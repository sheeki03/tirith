//! M13 ch4 — `tirith rule test|validate|explain` (the custom-rule DSL CLI).
//!
//! Operates on `.tirith/policy.yaml` `custom_rules:`, each carrying EITHER a
//! `pattern:` regex or a `when:` clause ([`tirith_core::custom_rule_dsl`]).
//!
//! * `test`    — evaluate one rule against `--input` and report FIRES /
//!   does-not-fire, using the SAME extraction the engine runs so it matches
//!   production.
//! * `validate`— check every rule (exactly-one-of pattern/when, well-formed
//!   predicates/regexes, declared `context:` covers the clause's trigger
//!   groups). Exit 0 if all valid, 1 otherwise.
//! * `explain` — print one rule's predicate tree, severity, action, context.
//!
//! Vs `tirith policy validate` (which checks the WHOLE policy file): this is the
//! focused custom-rule-DSL checker, reporting only those errors with rule-ids.

use tirith_core::custom_rule_dsl::{self, Reputation, WhenClause};
use tirith_core::extract::ScanContext;
use tirith_core::policy::{CustomRule, Policy};
use tirith_core::rules::custom::{compile_rules, CompiledMatcher};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::Action;

use super::write_json_stdout;

/// Resolve `--shell` to a [`ShellType`], defaulting to POSIX on an unknown
/// value (matching `tirith check`'s lenient shell handling).
fn resolve_shell(shell: &str) -> ShellType {
    shell.parse::<ShellType>().unwrap_or(ShellType::Posix)
}

/// Parse a rule's declared `context:` strings into [`ScanContext`]s.
fn declared_contexts(rule: &CustomRule) -> Vec<ScanContext> {
    rule.context
        .iter()
        .filter_map(|c| match c.as_str() {
            "exec" => Some(ScanContext::Exec),
            "paste" => Some(ScanContext::Paste),
            "file" => Some(ScanContext::FileScan),
            _ => None,
        })
        .collect()
}

/// The rule's COMPILED contexts in exec→paste→file order. `rule test` evaluates
/// in EACH and fires if any matches (R7-6): a multi-context rule (e.g.
/// `file.path_matches` declared `[exec, file]`) fires during FileScan, so
/// testing only exec wrongly reported not-firing. Using the compiled list keeps
/// `rule test` in step with the engine.
fn ordered_eval_contexts(contexts: &[ScanContext]) -> Vec<ScanContext> {
    [ScanContext::Exec, ScanContext::Paste, ScanContext::FileScan]
        .into_iter()
        .filter(|c| contexts.contains(c))
        .collect()
}

/// `tirith rule test --rule <id> --input <s>` — evaluate one rule and report
/// whether it FIRES.
///
/// Mirrors the engine: runs the rule through the SAME [`compile_rules`] step,
/// then evaluates only the COMPILED rule. A rule the engine would drop (bad
/// shape/regex, no valid context, an unsupported predicate, or an uncovered
/// trigger group) reports not-firing/invalid, never FIRES, so `test` and
/// `validate` agree (R9). Loads strictly so a broken policy surfaces a parse
/// error, not a misleading "no rule named …" (R10).
pub fn test(rule_id: &str, input: &str, shell: &str, json: bool) -> i32 {
    let (policy, _source) = match load_policy_strict("test", None, json) {
        Ok(pair) => pair,
        Err(code) => return code,
    };

    // Does the rule exist UNAMBIGUOUSLY? 0 → "unknown id"; >1 → ambiguous (R10-6,
    // don't silently pick the first); exactly 1 → proceed.
    let count = policy
        .custom_rules
        .iter()
        .filter(|r| r.id == rule_id)
        .count();
    if count == 0 {
        return emit_not_found("test", rule_id, &policy, json);
    }
    if count > 1 {
        return emit_duplicate_rule("test", rule_id, count, json);
    }

    // Compile as the engine does; absent from the compiled set → dropped as
    // invalid, report that rather than FIRES.
    let compiled = compile_rules(&policy.custom_rules);
    let rule = match compiled.iter().find(|r| r.id == rule_id) {
        Some(r) => r,
        None => {
            return emit_invalid_rule("test", rule_id, json);
        }
    };

    let shell_type = resolve_shell(shell);
    // Evaluate across ALL compiled contexts and fire if ANY matches (R7-6):
    // forcing a single context wrongly reported `file.path_matches` rules
    // not-firing. Iterating mirrors the engine.
    let kind = if rule.is_dsl() { "when" } else { "pattern" };
    let mut fires = false;
    // Context to REPORT: the one it fired in, else the first tried.
    let mut reported_context = None;
    for context in ordered_eval_contexts(&rule.contexts) {
        let matched = match &rule.matcher {
            CompiledMatcher::When(when) => {
                // Build the eval context exactly as the engine does for THIS
                // context (facts differ per context — e.g. file path only in FileScan).
                let backing =
                    tirith_core::engine::dsl_backing_for_input(input, shell_type, context);
                let cwd = std::env::current_dir()
                    .ok()
                    .map(|p| p.to_string_lossy().into_owned());
                let file_path = if context == ScanContext::FileScan {
                    // Normalize via the SAME helper the runtime FileScan uses so
                    // `file.path_matches` is byte-identical under test (F2).
                    tirith_core::util::normalize_path_separators(Some(std::path::Path::new(input)))
                } else {
                    None
                };
                let eval_ctx = backing.as_eval_context(cwd.as_deref(), file_path.as_deref());
                custom_rule_dsl::evaluate(when, &eval_ctx)
            }
            CompiledMatcher::Regex(re) => {
                // Match against the input (compiled+validated, context-independent).
                re.is_match(input)
            }
        };
        if reported_context.is_none() {
            reported_context = Some(context);
        }
        if matched {
            fires = true;
            reported_context = Some(context);
            break;
        }
    }
    // `compile_rules` guarantees a non-empty context set for any rule it kept, so
    // the loop always runs at least once; fall back to Exec only defensively.
    let context = reported_context.unwrap_or(ScanContext::Exec);

    if json {
        let v = serde_json::json!({
            "rule": rule_id,
            "kind": kind,
            "context": scan_context_name(context),
            "fires": fires,
        });
        if !write_json_stdout(&v, "tirith rule test: failed to write JSON output") {
            return 2;
        }
        return 0;
    }

    if fires {
        println!(
            "FIRES: rule '{rule_id}' matches the input ({kind}, context {}).",
            scan_context_name(context)
        );
    } else {
        println!(
            "does not fire: rule '{rule_id}' does not match the input ({kind}, context {}).",
            scan_context_name(context)
        );
    }
    0
}

/// `tirith rule validate [--path <file>]` — validate every custom rule.
///
/// Exit 0 when all custom rules are valid; 1 when any is invalid (with the
/// offending rule id + reason). Cross-references `tirith policy validate` for
/// whole-file checks.
pub fn validate(path: Option<&str>, json: bool) -> i32 {
    // Read the RAW YAML, not a strict Policy: the strict shape gate
    // (`try_parse_yaml`) would fail the whole parse on the first both/neither
    // rule, short-circuiting the per-rule validator below that is meant to
    // report it (with the rule id). `test`/`explain` use the strict loader;
    // `validate` runs its OWN lenient parse below (round-24).
    let (yaml, source) = match read_policy_source("validate", path, json) {
        Ok(pair) => pair,
        Err(code) => return code,
    };

    // Structural parse WITHOUT the shape gate so a both/neither rule reaches the
    // per-rule `validate_shape()` below; truly-malformed YAML still fails.
    let policy = match parse_policy_lenient(&yaml) {
        Ok(p) => p,
        Err(e) => {
            if json {
                let v = serde_json::json!({
                    "source": source,
                    "valid": false,
                    "error": e,
                });
                if !write_json_stdout(&v, "tirith rule validate: failed to write JSON output") {
                    return 2;
                }
                return 1;
            }
            eprintln!("tirith rule validate: {source}: {e}");
            return 1;
        }
    };

    let mut errors: Vec<RuleError> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for rule in &policy.custom_rules {
        if !seen.insert(rule.id.clone()) {
            errors.push(RuleError {
                rule: rule.id.clone(),
                message: "duplicate rule id".to_string(),
            });
        }

        // Exactly-one-of pattern/when.
        if let Err(e) = rule.validate_shape() {
            errors.push(RuleError {
                rule: rule.id.clone(),
                message: e.to_string(),
            });
            continue;
        }

        // Contexts must be known tokens. Track whether ANY was invalid so the
        // coverage check below doesn't double-report a dropped (unknown) token
        // as an unmet requirement. Mirrors `policy_validate` so both classify
        // identically (R3-9).
        let mut has_invalid_context = false;
        for c in &rule.context {
            if !matches!(c.as_str(), "exec" | "paste" | "file") {
                has_invalid_context = true;
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message: format!("unknown context '{c}' (valid: exec, paste, file)"),
                });
            }
        }

        if let Some(pattern) = &rule.pattern {
            // Mirror the three `compile_rules` drop conditions for a regex rule
            // so `validate` never passes a rule the engine drops (R7-7).
            //
            // (a) No valid contexts (a regex rule has no trigger-set fallback —
            // R7-2). Skipped when a token was invalid, already reported (R3-9).
            let parsed = declared_contexts(rule);
            if parsed.is_empty() && !has_invalid_context {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message:
                        "no valid contexts (regex rule needs at least one of: exec, paste, file)"
                            .to_string(),
                });
            }
            // (b) Pattern char cap (1024) — the engine's hard limit.
            if pattern.chars().count() > 1024 {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message: format!(
                        "pattern too long ({} chars, max 1024)",
                        pattern.chars().count()
                    ),
                });
            }
            // (c) Regex must compile.
            if let Err(e) = regex::Regex::new(pattern) {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message: format!("invalid regex: {e}"),
                });
            }
        }

        if let Some(when) = &rule.when {
            if let Err(e) = custom_rule_dsl::validate_regexes(when) {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message: e,
                });
            }
            // Reject a clause using a predicate no scan context satisfies
            // (`mcp.tool` R3-3, `agent.kind` R8-1 — use `agent_rules` instead).
            // Done FIRST so it never reaches the satisfiability check below
            // (whose set is empty by construction for these).
            let unsupported = custom_rule_dsl::clause_uses_unsupported_predicate(when);
            if let Some(reason) = unsupported {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message: reason.to_string(),
                });
            }
            // Per-clause satisfiability + coverage (R9-1), via the SAME
            // `satisfiable_contexts` the engine and `policy validate` use:
            //   (1) An EMPTY set means the clause mixes facts from contexts that
            //       never co-occur (e.g. `all(command.*, file.*)`) — reject as
            //       unsatisfiable. Skipped for an unsupported predicate (above).
            //   (2) Else the declared context must intersect the satisfiable set
            //       (only when tokens are valid — R3-9 — and predicate supported).
            let satisfiable = custom_rule_dsl::satisfiable_contexts(when);
            if unsupported.is_none() && satisfiable.is_empty() {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message: "when-clause needs facts from contexts that never co-occur in a \
                              single scan (e.g. command + file) — it can never match"
                        .to_string(),
                });
            } else if unsupported.is_none() && !has_invalid_context {
                // Via the SAME `resolve_runtime_contexts` (`declared ∩
                // satisfiable`) the engine uses, so all three classify
                // identically. An omitted `context:` defaults to `[exec, paste]`,
                // so a no-context `command.*` rule is ACCEPTED while a no-context
                // `file.path_matches` rule resolves empty and is REJECTED (an
                // explicit `context: []` is rejected too — finding D).
                let declared = declared_contexts(rule);
                if custom_rule_dsl::resolve_runtime_contexts(&declared, when).is_empty() {
                    errors.push(RuleError {
                        rule: rule.id.clone(),
                        message: format!(
                            "when-clause can only be evaluated in context [{}], not covered by declared context {:?}",
                            satisfiable.describe(),
                            rule.context
                        ),
                    });
                }
            }
        }
    }

    let total = policy.custom_rules.len();
    if json {
        let v = serde_json::json!({
            "source": source,
            "valid": errors.is_empty(),
            "rule_count": total,
            "error_count": errors.len(),
            "errors": errors.iter().map(|e| serde_json::json!({
                "rule": e.rule,
                "message": e.message,
            })).collect::<Vec<_>>(),
        });
        if !write_json_stdout(&v, "tirith rule validate: failed to write JSON output") {
            return 2;
        }
        return if errors.is_empty() { 0 } else { 1 };
    }

    if errors.is_empty() {
        eprintln!("tirith rule validate: {source} — {total} custom rule(s), all valid");
        0
    } else {
        eprintln!(
            "tirith rule validate: {source} — {} error(s) in {total} custom rule(s):",
            errors.len()
        );
        for e in &errors {
            eprintln!("  custom_rules.{}: {}", e.rule, e.message);
        }
        eprintln!();
        eprintln!("(for whole-policy-file checks, run `tirith policy validate`)");
        1
    }
}

/// `tirith rule explain --rule <id>` — print a rule's predicate tree, severity,
/// action and context. Loads strictly then delegates to [`explain_policy`];
/// splitting the load from the body (F2) lets a test drive the REAL path.
pub fn explain(rule_id: &str, json: bool) -> i32 {
    // Strict load so a broken policy surfaces a parse error instead of
    // warn-defaulting to "no custom rule named …" (R10).
    let (policy, _source) = match load_policy_strict("explain", None, json) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    explain_policy(&policy, rule_id, json)
}

/// The body of [`explain`] against a loaded [`Policy`]: ambiguity/not-found
/// checks, the `compile_rules` gate, and the JSON/human render. Separate from
/// the load step so tests drive the REAL gating+render wiring directly.
fn explain_policy(policy: &Policy, rule_id: &str, json: bool) -> i32 {
    // Reject ambiguity: duplicate ids would silently explain the first (R10-6).
    // 0 → not found; >1 → point at `validate`; exactly 1 → proceed.
    let count = policy
        .custom_rules
        .iter()
        .filter(|r| r.id == rule_id)
        .count();
    if count == 0 {
        return emit_not_found("explain", rule_id, policy, json);
    }
    if count > 1 {
        return emit_duplicate_rule("explain", rule_id, count, json);
    }
    // Gate through the SAME `compile_rules` step `test` uses (R20) so a rule the
    // engine would drop isn't described as live. Absent from the compiled set →
    // report invalid (like `test`), not the raw entry.
    let compiled = compile_rules(&policy.custom_rules);
    let compiled_rule = match compiled.iter().find(|r| r.id == rule_id) {
        Some(r) => r,
        None => return emit_invalid_rule("explain", rule_id, json),
    };
    let rule = match policy.custom_rules.iter().find(|r| r.id == rule_id) {
        Some(r) => r,
        None => {
            return emit_not_found("explain", rule_id, policy, json);
        }
    };

    // Report the CLAMPED runtime contexts (`declared ∩ satisfiable`), not the
    // declared list — else it advertises contexts the rule never runs in (round-21).
    // Ordered exec→paste→file like `rule test` so the two agree (round-22).
    let runtime_contexts: Vec<&'static str> = ordered_eval_contexts(&compiled_rule.contexts)
        .into_iter()
        .map(scan_context_name)
        .collect();

    // Declared `action:` is metadata; the engine derives the effective action
    // from severity. Report both so the operator sees what runs.
    let effective = action_for_severity(rule.severity);

    if json {
        let tree = rule.when.as_ref().map(clause_to_json);
        let v = serde_json::json!({
            "rule": rule.id,
            "kind": if rule.when.is_some() { "when" } else { "pattern" },
            "severity": rule.severity.to_string(),
            "declared_action": rule.action.map(action_name),
            "effective_action": action_name(effective),
            "context": runtime_contexts,
            "title": rule.title,
            "description": rule.description,
            "pattern": rule.pattern,
            "when": tree,
        });
        if !write_json_stdout(&v, "tirith rule explain: failed to write JSON output") {
            return 2;
        }
        return 0;
    }

    println!("Custom rule: {}", rule.id);
    println!("  title:    {}", rule.title);
    if !rule.description.is_empty() {
        println!("  detail:   {}", rule.description);
    }
    println!("  severity: {}", rule.severity);
    match rule.action {
        Some(a) => println!(
            "  action:   {} (declared) — effective {} (derived from severity)",
            action_name(a),
            action_name(effective)
        ),
        None => println!(
            "  action:   {} (derived from severity)",
            action_name(effective)
        ),
    }
    println!("  context:  {}", runtime_contexts.join(", "));
    println!();
    if let Some(pattern) = &rule.pattern {
        println!("  matcher:  regex");
        println!("    {pattern}");
    } else if let Some(when) = &rule.when {
        println!("  matcher:  when-clause (semantic predicates)");
        print_clause(when, 2);
    }
    0
}

// ---- shared helpers ----

struct RuleError {
    rule: String,
    message: String,
}

/// Emit a policy-load failure honoring the output mode; returns exit 1. In
/// `--json` mode MUST emit a structured `{ source, valid: false, error }` object
/// (same as `validate`'s parse-error path), never plain text — the JSON
/// contract: every byte of `--json` output is JSON (F1). A JSON write failure
/// (broken pipe) returns exit 2, matching the success paths.
fn emit_load_error(cmd: &str, source: &str, error: &str, json: bool) -> i32 {
    if json {
        let v = load_error_json(source, error);
        if !write_json_stdout(
            &v,
            &format!("tirith rule {cmd}: failed to write JSON output"),
        ) {
            return 2;
        }
        return 1;
    }
    eprintln!("tirith rule {cmd}: {source}: {error}");
    1
}

/// The structured `{ source, valid: false, error }` object for a `--json`
/// load-stage failure, factored out so its shape is unit-testable without stdout.
fn load_error_json(source: &str, error: &str) -> serde_json::Value {
    serde_json::json!({
        "source": source,
        "valid": false,
        "error": error,
    })
}

/// Resolve a `rule` subcommand's policy SOURCE — from `--path` or the discovered
/// local policy — as `(raw-yaml, source-label)`, or `Err(exit_code)` after a
/// file-read error. No parsing here (the caller picks strict vs lenient). A
/// missing file is NOT an error: empty document labeled `<no policy file>`.
fn read_policy_source(cmd: &str, path: Option<&str>, json: bool) -> Result<(String, String), i32> {
    if let Some(p) = path {
        match std::fs::read_to_string(p) {
            Ok(s) => Ok((s, p.to_string())),
            Err(e) => Err(emit_load_error(cmd, p, &format!("cannot read: {e}"), json)),
        }
    } else {
        match tirith_core::policy::discover_local_policy_path(None) {
            Some(found) => match std::fs::read_to_string(&found) {
                Ok(s) => Ok((s, found.display().to_string())),
                Err(e) => Err(emit_load_error(
                    cmd,
                    &found.display().to_string(),
                    &format!("cannot read: {e}"),
                    json,
                )),
            },
            None => Ok((String::new(), "<no policy file>".to_string())),
        }
    }
}

/// Load the policy STRICTLY for `test`/`explain` (full [`Policy::try_parse_yaml`]
/// with the shape gate). Unlike [`Policy::discover`] (which warn-defaults a
/// broken policy to empty, hiding the error), this surfaces a parse error as a
/// non-zero exit with the YAML location (R10). `validate` does NOT use this —
/// it needs its own per-rule validator, so it parses leniently (round-24).
fn load_policy_strict(cmd: &str, path: Option<&str>, json: bool) -> Result<(Policy, String), i32> {
    let (yaml, source) = read_policy_source(cmd, path, json)?;
    if yaml.is_empty() {
        return Ok((Policy::default(), source));
    }
    // try_parse_yaml surfaces a parse error (exit 1 + YAML location) rather than
    // warn-defaulting; in `--json` mode a structured object, not stderr (F1).
    match Policy::try_parse_yaml(&yaml) {
        Ok(policy) => Ok((policy, source)),
        Err(e) => Err(emit_load_error(cmd, &source, &e.to_string(), json)),
    }
}

/// Structurally parse policy YAML for `validate` WITHOUT the shape gate (the
/// migrate-then-deserialize half of [`Policy::try_parse_yaml`]). Dropping the
/// gate lets a both/neither rule deserialize so `validate`'s own per-rule loop
/// reports it with the rule id; truly-malformed YAML still returns `Err`
/// (round-24). An empty document → the default zero-rule policy.
fn parse_policy_lenient(yaml: &str) -> Result<Policy, String> {
    if yaml.is_empty() {
        return Ok(Policy::default());
    }
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(yaml).map_err(|e| format!("yaml parse error: {e}"))?;
    tirith_core::policy_migrations::migrate_forward(&mut value)
        .map_err(|e| format!("migration error: {e}"))?;
    serde_yaml::from_value::<Policy>(value).map_err(|e| format!("deserialize error: {e}"))
}

fn emit_not_found(cmd: &str, rule_id: &str, policy: &Policy, json: bool) -> i32 {
    if json {
        let v = serde_json::json!({
            "error": format!("no custom rule named '{rule_id}'"),
            "available": policy.custom_rules.iter().map(|r| &r.id).collect::<Vec<_>>(),
        });
        // Broken pipe → exit 2 (write failure), not 1 ("rule missing") — D5-5.
        if !write_json_stdout(
            &v,
            &format!("tirith rule {cmd}: failed to write JSON output"),
        ) {
            return 2;
        }
        return 1;
    }
    eprintln!("tirith rule {cmd}: no custom rule named '{rule_id}'");
    if policy.custom_rules.is_empty() {
        eprintln!("  (no custom_rules declared in policy; add one to .tirith/policy.yaml)");
    } else {
        eprintln!("  available rules:");
        for r in &policy.custom_rules {
            eprintln!("    {}", r.id);
        }
    }
    1
}

/// More than one custom rule with this id, so `test`/`explain` are ambiguous
/// (R10-6) — fail fast and point at `tirith rule validate`. Exit 1.
fn emit_duplicate_rule(cmd: &str, rule_id: &str, count: usize, json: bool) -> i32 {
    let msg = format!(
        "multiple custom rules named '{rule_id}' ({count} found); \
         the rule to {cmd} is ambiguous — run `tirith rule validate`"
    );
    if json {
        let v = serde_json::json!({
            "rule": rule_id,
            "error": msg,
            "duplicate_count": count,
        });
        // Broken pipe → exit 2 (write failure), not the duplicate-error 1.
        if !write_json_stdout(
            &v,
            &format!("tirith rule {cmd}: failed to write JSON output"),
        ) {
            return 2;
        }
        return 1;
    }
    eprintln!("tirith rule {cmd}: {msg}");
    1
}

/// The rule exists but `compile_rules` dropped it as invalid, so the engine
/// never runs it — report that rather than FIRES (R9). Points at
/// `tirith rule validate` for the reason. Exit 1.
fn emit_invalid_rule(cmd: &str, rule_id: &str, json: bool) -> i32 {
    let msg = format!(
        "rule '{rule_id}' is invalid and would be skipped by the engine (not evaluated); \
         run `tirith rule validate` for the reason"
    );
    if json {
        let v = serde_json::json!({
            "rule": rule_id,
            "valid": false,
            "fires": false,
            "error": msg,
        });
        // Broken pipe → exit 2 (write failure), not 1 ("rule invalid") — D5-5.
        if !write_json_stdout(
            &v,
            &format!("tirith rule {cmd}: failed to write JSON output"),
        ) {
            return 2;
        }
        return 1;
    }
    eprintln!("tirith rule {cmd}: {msg}");
    1
}

fn scan_context_name(c: ScanContext) -> &'static str {
    match c {
        ScanContext::Exec => "exec",
        ScanContext::Paste => "paste",
        ScanContext::FileScan => "file",
    }
}

fn action_name(a: Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        Action::Warn => "warn",
        Action::Block => "block",
        Action::WarnAck => "warn_ack",
    }
}

/// Mirror [`tirith_core::verdict::action_from_findings`]'s severity→action map
/// for a single finding (Critical/High → block, Medium/Low → warn, Info →
/// allow), so `explain` reports the action the rule drives. NOTE Low → Warn,
/// not Allow (Medium and Low share the Warn arm) — R7-8.
fn action_for_severity(sev: tirith_core::verdict::Severity) -> Action {
    use tirith_core::verdict::Severity;
    match sev {
        Severity::Critical | Severity::High => Action::Block,
        Severity::Medium | Severity::Low => Action::Warn,
        Severity::Info => Action::Allow,
    }
}

/// Pretty-print a `when:` clause as an indented predicate tree.
fn print_clause(clause: &WhenClause, indent: usize) {
    let pad = "  ".repeat(indent);
    match clause {
        WhenClause::All(cs) => {
            println!("{pad}all:");
            for c in cs {
                print_clause(c, indent + 1);
            }
        }
        WhenClause::Any(cs) => {
            println!("{pad}any:");
            for c in cs {
                print_clause(c, indent + 1);
            }
        }
        WhenClause::Not(c) => {
            println!("{pad}not:");
            print_clause(c, indent + 1);
        }
        leaf => println!("{pad}{}", leaf_to_line(leaf)),
    }
}

/// One-line rendering of a leaf predicate.
fn leaf_to_line(leaf: &WhenClause) -> String {
    let key = leaf.key();
    match leaf {
        WhenClause::CommandHasPipelineTo(v)
        | WhenClause::CommandCwdIn(v)
        | WhenClause::UrlDomainNotIn(v) => format!("{key}: [{}]", v.join(", ")),
        WhenClause::CommandUsesSudo(b) => format!("{key}: {b}"),
        WhenClause::UrlHost(s)
        | WhenClause::UrlHostMatches(s)
        | WhenClause::UrlScheme(s)
        | WhenClause::PackageEcosystem(s)
        | WhenClause::PackageNameMatches(s)
        | WhenClause::FilePathMatches(s)
        | WhenClause::AgentKind(s)
        | WhenClause::McpTool(s) => format!("{key}: {s}"),
        WhenClause::UrlReputation(r) | WhenClause::PackageReputation(r) => {
            format!("{key}: {}", reputation_name(r))
        }
        // All/Any/Not are handled by print_clause; render compactly if reached.
        WhenClause::All(_) | WhenClause::Any(_) | WhenClause::Not(_) => key.to_string(),
    }
}

fn reputation_name(r: &Reputation) -> &'static str {
    match r {
        Reputation::Known => "known",
        Reputation::Unknown => "unknown",
        Reputation::Malicious => "malicious",
    }
}

/// Recursively render a `when:` clause as JSON for `--json` explain.
fn clause_to_json(clause: &WhenClause) -> serde_json::Value {
    match clause {
        WhenClause::All(cs) => {
            serde_json::json!({ "all": cs.iter().map(clause_to_json).collect::<Vec<_>>() })
        }
        WhenClause::Any(cs) => {
            serde_json::json!({ "any": cs.iter().map(clause_to_json).collect::<Vec<_>>() })
        }
        WhenClause::Not(c) => serde_json::json!({ "not": clause_to_json(c) }),
        leaf => serde_json::json!({ leaf.key(): leaf_value_json(leaf) }),
    }
}

fn leaf_value_json(leaf: &WhenClause) -> serde_json::Value {
    match leaf {
        WhenClause::CommandHasPipelineTo(v)
        | WhenClause::CommandCwdIn(v)
        | WhenClause::UrlDomainNotIn(v) => serde_json::json!(v),
        WhenClause::CommandUsesSudo(b) => serde_json::json!(b),
        WhenClause::UrlHost(s)
        | WhenClause::UrlHostMatches(s)
        | WhenClause::UrlScheme(s)
        | WhenClause::PackageEcosystem(s)
        | WhenClause::PackageNameMatches(s)
        | WhenClause::FilePathMatches(s)
        | WhenClause::AgentKind(s)
        | WhenClause::McpTool(s) => serde_json::json!(s),
        WhenClause::UrlReputation(r) | WhenClause::PackageReputation(r) => {
            serde_json::json!(reputation_name(r))
        }
        WhenClause::All(_) | WhenClause::Any(_) | WhenClause::Not(_) => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::verdict::{Evidence, Finding, RuleId, Severity};

    /// Build a minimal finding carrying just a severity, for `action_from_findings`.
    fn finding(severity: Severity) -> Finding {
        Finding {
            rule_id: RuleId::CustomRuleMatch,
            severity,
            title: "t".into(),
            description: "d".into(),
            evidence: vec![Evidence::Text { detail: "x".into() }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: Some("r".into()),
        }
    }

    #[test]
    fn action_for_severity_low_is_warn() {
        // R7-8: Low → Warn (not Allow), matching `action_from_findings`.
        assert_eq!(action_for_severity(Severity::Low), Action::Warn);
        assert_eq!(action_for_severity(Severity::Info), Action::Allow);
    }

    #[test]
    fn action_for_severity_matches_action_from_findings() {
        // R7-8: this helper must agree with the engine's map for a single
        // finding of each severity.
        use tirith_core::verdict::action_from_findings;
        for sev in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(
                action_for_severity(sev),
                action_from_findings(&[finding(sev)]),
                "action_for_severity({sev:?}) must match action_from_findings for a single {sev:?} finding"
            );
        }
    }

    #[test]
    fn ordered_eval_contexts_preserves_preference_and_membership() {
        // R7-6: exec→paste→file, filtered to the rule's compiled contexts.
        assert_eq!(
            ordered_eval_contexts(&[ScanContext::FileScan, ScanContext::Exec]),
            vec![ScanContext::Exec, ScanContext::FileScan],
            "must keep exec-before-file order regardless of declared order"
        );
        assert_eq!(
            ordered_eval_contexts(&[ScanContext::Paste]),
            vec![ScanContext::Paste]
        );
        assert!(ordered_eval_contexts(&[]).is_empty());
    }

    /// Write `yaml` to a temp file and run `tirith rule validate` against it,
    /// returning the exit code (0 = all valid, 1 = at least one invalid).
    fn rule_validate_exit(yaml: &str) -> i32 {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(yaml.as_bytes()).expect("write yaml");
        let path = f.path().to_string_lossy().into_owned();
        // JSON path writes to stdout and returns the same exit code; the
        // non-JSON path prints diagnostics to stderr. Use non-JSON so the test's
        // stdout stays clean.
        super::validate(Some(&path), false)
    }

    /// Whether `tirith_core::policy_validate` reports a coverage error for the
    /// given rule id (the SAME classification `rule validate` must reach).
    fn policy_validate_has_coverage_error(yaml: &str, rule_id: &str) -> bool {
        tirith_core::policy_validate::validate(yaml)
            .iter()
            .any(|i| {
                matches!(i.level, tirith_core::policy_validate::IssueLevel::Error)
                    && i.message.contains(rule_id)
                    && i.message.contains("not covered by declared context")
            })
    }

    // round-24: `validate` must load LENIENTLY so a both-pattern-and-when rule is
    // reported by its per-rule validator (rule id, exit 1), not a generic
    // strict-parse error. `test`/`explain` keep the strict loader and must still
    // reject it up front.
    #[test]
    fn validate_both_pattern_and_when_reaches_per_rule_validator_not_strict_parse() {
        let yaml = "custom_rules:\n  - id: both\n    pattern: \"foo\"\n    when:\n      command.uses_sudo: true\n    title: \"has both pattern and when\"\n    context: [exec]\n";

        // The strict path (test/explain) still rejects it up front.
        assert!(
            Policy::try_parse_yaml(yaml).is_err(),
            "strict parse (test/explain) must still reject a both-pattern-and-when rule up front"
        );

        // The lenient path (validate) parses it structurally so the per-rule
        // validator can see it.
        let policy = parse_policy_lenient(yaml)
            .expect("lenient parse must SUCCEED on a both/neither rule so validate can report it");
        let rule = policy
            .custom_rules
            .iter()
            .find(|r| r.id == "both")
            .expect("the both/neither rule survives the lenient (gate-free) parse");
        // And the per-rule check gives a helpful rule-level message.
        let shape_err = rule
            .validate_shape()
            .expect_err("validate_shape must flag the both-pattern-and-when rule");
        assert!(
            shape_err.to_string().contains("exactly one of"),
            "the per-rule validator must give the friendly shape message, got: {shape_err}"
        );

        // End-to-end through the real `validate` command: exit 1, not 0.
        assert_eq!(
            rule_validate_exit(yaml),
            1,
            "rule validate must exit 1 on the both/neither rule, via its per-rule validator"
        );
        // `policy validate` must AGREE — it reports the same shape problem.
        assert!(
            tirith_core::policy_validate::validate(yaml)
                .iter()
                .any(|i| {
                    matches!(i.level, tirith_core::policy_validate::IssueLevel::Error)
                        && i.message.contains("both")
                }),
            "policy validate must AGREE: it reports the both-pattern-and-when rule as an error"
        );
    }

    /// F1: a `--json` load failure must emit a structured `{ source, valid:
    /// false, error }` object, not plain stderr. Pins that shape and proves it
    /// round-trips as valid JSON carrying the error field (verifying the value
    /// avoids an FD-capture race against the parallel harness).
    #[test]
    fn load_error_json_is_structured_and_carries_error_field() {
        let v = load_error_json("/no/such/policy.yaml", "cannot read: not found");
        // Round-trips as valid JSON (a string consumer could parse it).
        let s = serde_json::to_string(&v).expect("load-error JSON must serialize");
        let parsed: serde_json::Value =
            serde_json::from_str(&s).expect("load-error output must be parseable JSON, not text");
        assert_eq!(
            parsed["valid"],
            serde_json::Value::Bool(false),
            "a load failure must report valid: false"
        );
        assert!(
            parsed["error"].is_string(),
            "JSON load error must carry a string `error` field, got: {parsed}"
        );
        assert!(
            parsed["error"]
                .as_str()
                .is_some_and(|e| e.contains("cannot read")),
            "the `error` field must surface the read-failure detail, got: {parsed}"
        );
        assert!(
            parsed["source"].is_string(),
            "JSON load error must carry the `source` label, got: {parsed}"
        );
    }

    /// F1, end-to-end: `validate --json` on a MISSING `--path` must exit
    /// non-zero (exit code authoritative). Exit-code-only keeps it deterministic
    /// under the parallel harness.
    #[test]
    fn validate_json_missing_path_exits_nonzero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist-policy.yaml");
        let missing = missing.to_string_lossy().into_owned();
        assert_eq!(
            super::validate(Some(&missing), true),
            1,
            "validate --json on a missing path must exit non-zero (exit code authoritative)"
        );
    }

    /// F1, routing: both `emit_load_error` arms exit 1, but only the JSON arm
    /// produces the structured object — the race-free stand-in for capturing
    /// stdout.
    #[test]
    fn validate_json_missing_path_routes_through_load_error() {
        // JSON arm: exit 1 (object written to stdout).
        assert_eq!(
            emit_load_error(
                "validate",
                "/no/such/policy.yaml",
                "cannot read: nope",
                true
            ),
            1,
            "the JSON load-error arm must exit 1"
        );
        // Human arm: exit 1 (plain text to stderr) — kept for the non-JSON path.
        assert_eq!(
            emit_load_error(
                "validate",
                "/no/such/policy.yaml",
                "cannot read: nope",
                false
            ),
            1,
            "the human load-error arm must also exit 1"
        );
    }

    // round-24 companion: truly-malformed YAML must STILL exit non-zero —
    // lenient loading defers the shape gate, it doesn't swallow bad input.
    #[test]
    fn validate_truly_malformed_yaml_still_exits_nonzero() {
        let malformed = "custom_rules: [this is not valid yaml\n";
        assert!(
            parse_policy_lenient(malformed).is_err(),
            "lenient parse must still FAIL on structurally-broken YAML"
        );
        assert_eq!(
            rule_validate_exit(malformed),
            1,
            "rule validate must exit non-zero on truly-malformed YAML (no silent pass)"
        );
    }

    #[test]
    fn validate_no_context_command_rule_is_accepted() {
        // round-15: an omitted `context:` defaults to [exec, paste], so a
        // no-context `command.*` rule resolves non-empty and exits 0; `policy
        // validate` agrees.
        let yaml = "custom_rules:\n  - id: no-ctx-cmd\n    when:\n      command.uses_sudo: true\n    title: \"no-context command rule\"\n";
        assert_eq!(
            rule_validate_exit(yaml),
            0,
            "no-context command.* rule must validate OK (resolves to exec/paste)"
        );
        assert!(
            !policy_validate_has_coverage_error(yaml, "no-ctx-cmd"),
            "policy validate must AGREE: no coverage error for the command rule"
        );
    }

    #[test]
    fn validate_no_context_file_rule_is_rejected() {
        // Companion: a no-context `file.path_matches` rule resolves to [exec,
        // paste] ∩ {file} = ∅, so it can never fire — exit 1 (both validators
        // agree). Proves the default-then-clamp model, not a `!is_empty()` skip.
        let yaml = "custom_rules:\n  - id: no-ctx-file\n    when:\n      file.path_matches: '\\.env$'\n    title: \"no-context file rule\"\n";
        assert_eq!(
            rule_validate_exit(yaml),
            1,
            "no-context file.path_matches rule must be REJECTED (can never fire)"
        );
        assert!(
            policy_validate_has_coverage_error(yaml, "no-ctx-file"),
            "policy validate must AGREE: it reports the coverage error for the file rule"
        );
    }

    #[test]
    fn validate_multibyte_pattern_under_char_cap_accepted() {
        // round-27: the 1024 pattern cap counts CHARACTERS, not bytes. A
        // 600-char (1200-byte) pattern is under the cap and must be accepted (the
        // old `pattern.len()` byte check wrongly rejected it).
        let pat = "é".repeat(600); // 600 chars / 1200 bytes
        let yaml = format!(
            "custom_rules:\n  - id: mb-pat\n    pattern: \"{pat}\"\n    title: \"multibyte pattern\"\n    context: [exec]\n"
        );
        assert_eq!(
            rule_validate_exit(&yaml),
            0,
            "a <=1024-CHAR multibyte pattern (>1024 bytes) must validate OK"
        );

        // A pattern over 1024 CHARACTERS is still rejected.
        let too_long = "a".repeat(1025);
        let yaml2 = format!(
            "custom_rules:\n  - id: long-pat\n    pattern: \"{too_long}\"\n    title: \"too long\"\n    context: [exec]\n"
        );
        assert_eq!(
            rule_validate_exit(&yaml2),
            1,
            "a >1024-CHAR pattern must be rejected by rule validate"
        );
    }

    #[test]
    fn validate_explicit_file_context_file_rule_is_accepted() {
        // A `file.path_matches` rule that DECLARES `[file]` resolves to {file}
        // (non-empty) and must validate OK; both validators agree.
        let yaml = "custom_rules:\n  - id: file-ctx-file\n    when:\n      file.path_matches: '\\.env$'\n    title: \"explicit file context\"\n    context: [file]\n";
        assert_eq!(
            rule_validate_exit(yaml),
            0,
            "explicit [file] file rule must validate OK"
        );
        assert!(
            !policy_validate_has_coverage_error(yaml, "file-ctx-file"),
            "policy validate must AGREE: no coverage error for the explicit-[file] rule"
        );
    }

    // R20 + F2: `explain` must route through the SAME `compile_rules` gate as
    // `test`, so it never describes a rule the engine drops. Drives the REAL
    // `explain_policy` body (not in-isolation helpers). `agent.kind` is
    // unsupported → the policy compiles to the empty set, the reject condition.
    // Use the human path so a clean stdout proves the raw entry was NOT rendered.
    #[test]
    fn explain_rejects_unsupported_predicate_rule_via_real_path() {
        let yaml = "custom_rules:\n  - id: agent-kind-only\n    when:\n      agent.kind: aider\n    title: \"unsupported predicate rule\"\n";
        let policy = Policy::try_parse_yaml(yaml).expect("policy parses");
        // Sanity: `compile_rules` drops the `agent.kind` rule (the gate's trigger).
        let compiled = compile_rules(&policy.custom_rules);
        assert!(
            !compiled.iter().any(|r| r.id == "agent-kind-only"),
            "compile_rules must drop the agent.kind rule (unsupported predicate)"
        );
        // The REAL explain body: it must reject (non-zero), matching `test`, rather
        // than render a rule the engine would never run.
        let code = explain_policy(&policy, "agent-kind-only", false);
        assert_ne!(
            code, 0,
            "explain (real path) must reject an engine-dropped rule non-zero, matching `test`"
        );
    }

    // F2 (positive half): a VALID rule explains successfully (exit 0) through the
    // real path, covering the keep arm of the compile gate end-to-end.
    #[test]
    fn explain_valid_rule_via_real_path_exits_zero() {
        let yaml = "custom_rules:\n  - id: ok-rule\n    when:\n      command.uses_sudo: true\n    title: \"a valid command rule\"\n    context: [exec]\n";
        let policy = Policy::try_parse_yaml(yaml).expect("policy parses");
        assert_eq!(
            explain_policy(&policy, "ok-rule", false),
            0,
            "a valid rule must explain successfully (exit 0) through the real path"
        );
    }

    // F2: a not-found id and a duplicate id both exit 1 through the real
    // `explain_policy` body (not-found / ambiguity gates).
    #[test]
    fn explain_unknown_and_duplicate_ids_via_real_path_exit_one() {
        let single = "custom_rules:\n  - id: only-rule\n    when:\n      command.uses_sudo: true\n    title: \"t\"\n    context: [exec]\n";
        let policy = Policy::try_parse_yaml(single).expect("policy parses");
        assert_eq!(
            explain_policy(&policy, "no-such-rule", false),
            1,
            "an unknown rule id must exit 1 through the real explain path"
        );

        let dup = "custom_rules:\n  - id: dup\n    when:\n      url.scheme: http\n    title: \"a\"\n    context: [exec]\n  - id: dup\n    when:\n      url.scheme: https\n    title: \"b\"\n    context: [exec]\n";
        let dup_policy = Policy::try_parse_yaml(dup).expect("policy parses");
        assert_eq!(
            explain_policy(&dup_policy, "dup", false),
            1,
            "a duplicate rule id must exit 1 (ambiguous) through the real explain path"
        );
    }

    // round-21: `explain` must report the CLAMPED runtime contexts (declared ∩
    // satisfiable), not the declared list. A `file.path_matches` clause is
    // satisfiable only in FileScan, so `[exec, file]` clamps to `[file]` — a set
    // strictly smaller than declared.
    #[test]
    fn explain_reports_clamped_runtime_contexts_not_declared() {
        let yaml = "custom_rules:\n  - id: file-rule-broad-decl\n    when:\n      file.path_matches: '\\.env$'\n    title: \"file rule declared exec+file\"\n    context: [exec, file]\n";
        let policy = Policy::try_parse_yaml(yaml).expect("policy parses");

        // The rule as DECLARED carries both contexts.
        let declared = policy
            .custom_rules
            .iter()
            .find(|r| r.id == "file-rule-broad-decl")
            .expect("declared rule present");
        assert_eq!(
            declared.context,
            vec!["exec".to_string(), "file".to_string()],
            "fixture must declare both exec and file so the clamp is observable"
        );

        // The compiled rule (what `explain` renders) is clamped to {file}. Build
        // the reported list the SAME way `explain` does (ordered_eval_contexts + map).
        let compiled = compile_rules(&policy.custom_rules);
        let compiled_rule = compiled
            .iter()
            .find(|r| r.id == "file-rule-broad-decl")
            .expect("compile_rules must keep the file rule (it has a satisfiable context)");
        let runtime_contexts: Vec<&'static str> = ordered_eval_contexts(&compiled_rule.contexts)
            .into_iter()
            .map(scan_context_name)
            .collect();

        assert_eq!(
            runtime_contexts,
            vec!["file"],
            "explain must report the CLAMPED set [file], not the declared [exec, file]"
        );
        // And the clamped set is strictly smaller than the declared set.
        assert!(
            runtime_contexts.len() < declared.context.len(),
            "clamped runtime contexts ({runtime_contexts:?}) must be strictly smaller than \
             declared ({:?})",
            declared.context
        );
        assert!(
            !runtime_contexts.contains(&"exec"),
            "exec was declared but is not satisfiable for file.path_matches, so explain must \
             not advertise it"
        );
    }

    // round-22 F1: `explain` must render contexts in the SAME exec→paste→file
    // order `rule test` uses. A regex rule is the observable case: `compile_rules`
    // keeps its declared order verbatim, so `[file, exec]` would echo reversed
    // pre-F1; this pins that `explain` now normalizes to `[exec, file]`.
    #[test]
    fn explain_orders_contexts_exec_before_file() {
        let yaml = "custom_rules:\n  - id: regex-reversed-ctx\n    pattern: 'curl'\n    title: \"regex rule declared file then exec\"\n    context: [file, exec]\n";
        let policy = Policy::try_parse_yaml(yaml).expect("policy parses");

        // The compiled regex rule keeps the declared order (file, exec), so the
        // reorder is observable.
        let compiled = compile_rules(&policy.custom_rules);
        let compiled_rule = compiled
            .iter()
            .find(|r| r.id == "regex-reversed-ctx")
            .expect("compile_rules must keep the regex rule");
        assert_eq!(
            compiled_rule.contexts,
            vec![ScanContext::FileScan, ScanContext::Exec],
            "the compiled regex rule must carry the declared (reversed) order, so the F1 \
             reorder in explain is observable"
        );

        // What `explain` renders: contexts through `ordered_eval_contexts` → exec before file.
        let reported: Vec<&'static str> = ordered_eval_contexts(&compiled_rule.contexts)
            .into_iter()
            .map(scan_context_name)
            .collect();
        assert_eq!(
            reported,
            vec!["exec", "file"],
            "explain must normalize to exec→file order (matching `rule test`), not echo the \
             declared [file, exec]"
        );

        // And it must explain successfully through the real path (exit 0).
        assert_eq!(
            explain_policy(&policy, "regex-reversed-ctx", false),
            0,
            "a valid regex rule with reversed declared contexts must still explain (exit 0)"
        );
    }
}
