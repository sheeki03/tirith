//! M13 ch4 — `tirith rule test|validate|explain` (the custom-rule DSL CLI).
//!
//! These commands operate on the custom rules declared in `.tirith/policy.yaml`
//! (`custom_rules:`), which carry EITHER a `pattern:` regex or a `when:`
//! semantic-predicate clause (the M13 ch4 DSL — [`tirith_core::custom_rule_dsl`]).
//!
//! * `test`    — evaluate one named rule against a `--input` and report FIRES /
//!   does-not-fire. The DSL eval context is built from the SAME extraction the
//!   engine runs ([`tirith_core::engine::dsl_backing_for_input`]), so a test
//!   matches production.
//! * `validate`— check every custom rule: exactly-one-of pattern/when,
//!   well-formed predicates/regexes, and the tier-1 invariant (the declared
//!   `context:` must cover the clause's required trigger groups). Exit 0 if all
//!   valid, 1 otherwise.
//! * `explain` — print one rule's predicate tree, severity, action and context.
//!
//! Scope vs `tirith policy validate`: that command validates the WHOLE policy
//! FILE structure (every key, allowlist/blocklist coherence, …). `tirith rule
//! validate` is the focused custom-rule-DSL checker — it reports the same
//! custom-rule errors but only those, with rule-id locations.

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

/// The rule's COMPILED contexts in a deterministic preference order — exec,
/// then paste, then file (the order the engine would reach the rule in for a
/// typed command). `rule test` evaluates the rule in EACH of these and fires if
/// it matches in any (CodeRabbit M13 round-7 R7-6): a multi-context rule (e.g.
/// `file.path_matches` declared `[exec, file]`) fires during FileScan at
/// runtime, so testing only the single preferred context (exec) wrongly
/// reported not-firing. Operating on the COMPILED list (post-`compile_rules`)
/// keeps `rule test` in step with what the engine actually runs — a context the
/// rule declared but compilation dropped is not tried, and a context-agnostic
/// rule's synthesized executable set is honored.
fn ordered_eval_contexts(contexts: &[ScanContext]) -> Vec<ScanContext> {
    [ScanContext::Exec, ScanContext::Paste, ScanContext::FileScan]
        .into_iter()
        .filter(|c| contexts.contains(c))
        .collect()
}

/// `tirith rule test --rule <id> --input <s>` — evaluate one custom rule
/// against an input and report whether it FIRES.
///
/// Mirrors the engine: the named rule is run through the SAME
/// [`compile_rules`] step the engine uses, then evaluated only from the
/// COMPILED rule. A rule the engine would skip at compile time (invalid shape /
/// regex, no valid context, a DSL clause using an unsupported predicate —
/// `agent.kind`/`mcp.tool` — or a DSL clause whose required trigger groups the
/// declared `context:` doesn't cover) is reported as not-firing/invalid here
/// too — never FIRES — so `rule test` and `rule validate` agree. (CodeRabbit
/// M13 round-2 R9.) Loads the policy strictly so a broken
/// `.tirith/policy.yaml` surfaces a parse error, not a misleading "no rule
/// named …" (R10).
pub fn test(rule_id: &str, input: &str, shell: &str, json: bool) -> i32 {
    let (policy, _source) = match load_policy("test", None) {
        Ok(pair) => pair,
        Err(code) => return code,
    };

    // Does the rule exist in the policy at all? Distinguish "unknown id" from
    // "declared but dropped by compilation (invalid)".
    if !policy.custom_rules.iter().any(|r| r.id == rule_id) {
        return emit_not_found("test", rule_id, &policy, json);
    }

    // Compile exactly as the engine does, then locate the COMPILED rule. If it
    // isn't present, compilation dropped it as invalid — report that, not FIRES.
    let compiled = compile_rules(&policy.custom_rules);
    let rule = match compiled.iter().find(|r| r.id == rule_id) {
        Some(r) => r,
        None => {
            return emit_invalid_rule("test", rule_id, json);
        }
    };

    let shell_type = resolve_shell(shell);
    // Evaluate the rule across ALL of its compiled contexts and fire if it
    // matches in ANY (CodeRabbit M13 round-7 R7-6). The old code forced a single
    // preferred context (always exec when present), so a `file.path_matches`
    // rule declared `[exec, file]` was tested in Exec — where the engine never
    // populates the file path — and reported not-firing even though the engine
    // fires it during FileScan. Iterating the compiled contexts mirrors the
    // engine, which reaches the rule in each context it declares.
    let kind = if rule.is_dsl() { "when" } else { "pattern" };
    let mut fires = false;
    // The context to REPORT: the one the rule fired in, or — if it never fires —
    // the first context tried (deterministic preference order below).
    let mut reported_context = None;
    for context in ordered_eval_contexts(&rule.contexts) {
        let matched = match &rule.matcher {
            CompiledMatcher::When(when) => {
                // DSL rule: build the eval context exactly as the engine does
                // for THIS context (`build_dsl_backing` extracts different facts
                // per context — e.g. the file path only in FileScan).
                let backing =
                    tirith_core::engine::dsl_backing_for_input(input, shell_type, context);
                // `cwd_in` is evaluated against the process cwd (what the engine
                // sees); `file.path_matches` against `--input` treated as a path
                // in FileScan.
                let cwd = std::env::current_dir()
                    .ok()
                    .map(|p| p.to_string_lossy().into_owned());
                let file_path = if context == ScanContext::FileScan {
                    Some(input.to_string())
                } else {
                    None
                };
                let eval_ctx = backing.as_eval_context(cwd.as_deref(), file_path.as_deref());
                custom_rule_dsl::evaluate(when, &eval_ctx)
            }
            CompiledMatcher::Regex(re) => {
                // Regex rule: match against the input, mirroring the engine's
                // `rules::custom::check`. The regex is already compiled+validated
                // and context-independent, so any declared context matches alike.
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
    let (policy, source) = match load_policy("validate", path) {
        Ok(pair) => pair,
        Err(code) => return code,
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
        // coverage check below does not ALSO fire for a dropped token (the
        // unknown token vanishes from the parsed set, which would otherwise look
        // like an unmet requirement and double-report the same typo). This
        // mirrors `policy_validate::validate_custom_rules` exactly so `rule
        // validate` and `policy validate` classify the same rule identically
        // (CodeRabbit M13 round-3 R3-9).
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
            // Mirror `compile_rules` exactly so `rule validate` never passes a
            // rule the engine silently drops (CodeRabbit M13 round-7 R7-7).
            // compile_rules drops a regex rule for, in order: no valid context,
            // pattern over the 1024-char cap, or invalid regex syntax.
            //
            // (a) No valid contexts. A regex rule has no required-trigger notion
            // to synthesize an executable set from (that fallback is for
            // context-agnostic DSL rules — R7-2), so an empty parsed context set
            // is a dead rule and compile_rules drops it. We skip this when a
            // context token was INVALID: that is already reported above, and a
            // bogus-only context list would otherwise be double-reported (same
            // discipline as the DSL coverage check — R3-9).
            let parsed = declared_contexts(rule);
            if parsed.is_empty() && !has_invalid_context {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message:
                        "no valid contexts (regex rule needs at least one of: exec, paste, file)"
                            .to_string(),
                });
            }
            // (b) Pattern length cap (1024 chars) — the engine's hard limit.
            if pattern.len() > 1024 {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message: format!("pattern too long ({} chars, max 1024)", pattern.len()),
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
            // Reject a clause using a predicate no scan context can satisfy
            // (`mcp.tool` and `agent.kind` — neither signal is wired into the
            // scan context). Same rejection `policy validate` applies —
            // CodeRabbit M13 round-3 R3-3 (`mcp.tool`) + round-8 R8-1
            // (`agent.kind`; use `agent_rules` for per-agent control). Done FIRST
            // so an `agent.kind`/`mcp.tool` clause never reaches the
            // satisfiable-context check (its set is empty by construction).
            let unsupported = custom_rule_dsl::clause_uses_unsupported_predicate(when);
            if let Some(reason) = unsupported {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message: reason.to_string(),
                });
            }
            // Per-clause satisfiability + coverage (CodeRabbit M13 round-9 R9-1),
            // routed through the SAME `satisfiable_contexts` the engine's
            // `compile_rules` and `policy validate` use, so all three classify a
            // rule identically. `satisfiable_contexts` intersects children for
            // `all`, unions for `any`, and passes through `not`.
            //   (1) An EMPTY set means the clause mixes facts from contexts that
            //       never co-occur in a single scan (e.g. `all(command.*,
            //       file.*)`) — it can never match. Reject as unsatisfiable,
            //       independent of declared context. Skipped when the clause used
            //       an unsupported predicate (reported just above — its empty set
            //       would otherwise double-report).
            //   (2) Otherwise the declared context must intersect the satisfiable
            //       set. Only emit when context tokens are VALID (R3-9: a dropped
            //       bogus token would otherwise look like an uncovered context),
            //       and the predicate is supported.
            let satisfiable = custom_rule_dsl::satisfiable_contexts(when);
            if unsupported.is_none() && satisfiable.is_empty() {
                errors.push(RuleError {
                    rule: rule.id.clone(),
                    message: "when-clause needs facts from contexts that never co-occur in a \
                              single scan (e.g. command + file) — it can never match"
                        .to_string(),
                });
            } else if unsupported.is_none() && !has_invalid_context {
                let declared = declared_contexts(rule);
                if !satisfiable.intersects_declared(&declared) {
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
/// action and context.
pub fn explain(rule_id: &str, json: bool) -> i32 {
    // Strict load so a broken `.tirith/policy.yaml` surfaces a parse error
    // (non-zero exit) instead of warn-defaulting to an empty policy that would
    // misreport every rule as "no custom rule named …" (CodeRabbit M13 round-2
    // R10).
    let (policy, _source) = match load_policy("explain", None) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    let rule = match policy.custom_rules.iter().find(|r| r.id == rule_id) {
        Some(r) => r,
        None => {
            return emit_not_found("explain", rule_id, &policy, json);
        }
    };

    // Effective action: a rule's declared `action:` is recorded metadata; the
    // engine derives the effective action from `severity` (a Critical finding
    // blocks, Medium warns, …). Report both so the operator sees what runs.
    let effective = action_for_severity(rule.severity);

    if json {
        let tree = rule.when.as_ref().map(clause_to_json);
        let v = serde_json::json!({
            "rule": rule.id,
            "kind": if rule.when.is_some() { "when" } else { "pattern" },
            "severity": rule.severity.to_string(),
            "declared_action": rule.action.map(action_name),
            "effective_action": action_name(effective),
            "context": rule.context,
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
    println!("  context:  {}", rule.context.join(", "));
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

/// Load the policy STRICTLY for a `rule` subcommand: from `--path` (read the
/// file directly) or the discovered local policy. Returns `(policy,
/// source-label)`, or `Err(exit_code)` after printing a config-load error.
///
/// Unlike [`Policy::discover`] (which warn-defaults a broken local policy to a
/// fail-closed empty policy — hiding the parse error behind a misleading "no
/// custom rule" / empty result), this surfaces a parse error as a non-zero
/// exit with the YAML location. `cmd` names the subcommand for the message
/// (`test` / `validate` / `explain`). (CodeRabbit M13 round-2 R10.)
fn load_policy(cmd: &str, path: Option<&str>) -> Result<(Policy, String), i32> {
    if let Some(p) = path {
        let yaml = match std::fs::read_to_string(p) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("tirith rule {cmd}: cannot read {p}: {e}");
                return Err(1);
            }
        };
        // try_parse_yaml surfaces a parse error rather than warn-and-defaulting,
        // so a malformed `when:` is reported as exit 1 with the YAML location.
        match Policy::try_parse_yaml(&yaml) {
            Ok(policy) => Ok((policy, p.to_string())),
            Err(e) => {
                eprintln!("tirith rule {cmd}: {p}: {e}");
                Err(1)
            }
        }
    } else {
        match tirith_core::policy::discover_local_policy_path(None) {
            Some(found) => {
                let yaml = match std::fs::read_to_string(&found) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("tirith rule {cmd}: cannot read {}: {e}", found.display());
                        return Err(1);
                    }
                };
                match Policy::try_parse_yaml(&yaml) {
                    Ok(policy) => Ok((policy, found.display().to_string())),
                    Err(e) => {
                        eprintln!("tirith rule {cmd}: {}: {e}", found.display());
                        Err(1)
                    }
                }
            }
            // No policy file at all — the default policy has zero custom rules,
            // which is trivially valid (matches the shipping/no-policy case).
            None => Ok((Policy::default(), "<no policy file>".to_string())),
        }
    }
}

fn emit_not_found(cmd: &str, rule_id: &str, policy: &Policy, json: bool) -> i32 {
    if json {
        let v = serde_json::json!({
            "error": format!("no custom rule named '{rule_id}'"),
            "available": policy.custom_rules.iter().map(|r| &r.id).collect::<Vec<_>>(),
        });
        // A broken pipe must surface as a write failure (exit 2), consistent with
        // the success paths — not be misreported as "rule missing" (exit 1).
        // CodeRabbit M13 round-5 D5-5.
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

/// The named rule exists in the policy but `compile_rules` dropped it as
/// invalid (bad shape/regex, no valid context, or an uncovered DSL trigger
/// group) — so the engine would never run it. Report that rather than FIRES
/// (CodeRabbit M13 round-2 R9). Points to `tirith rule validate` for the exact
/// reason (it prints the per-rule diagnostic). Exit 1.
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
        // A broken pipe must surface as a write failure (exit 2), consistent with
        // the success paths — not be misreported as "rule invalid" (exit 1).
        // CodeRabbit M13 round-5 D5-5.
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
/// for a single finding's severity (Critical/High → block, Medium/Low → warn,
/// Info → allow), so `explain` reports the action the rule actually drives.
///
/// `Low` maps to `Warn`, NOT `Allow`: the engine's `action_from_findings`
/// treats a single `Low` finding as `Warn` (Medium and Low share the `Warn`
/// arm there). Returning `Allow` here previously understated low-severity rules
/// — `rule explain` would claim a Low rule allows when the engine actually
/// warns (CodeRabbit M13 round-7 R7-8).
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
        // CodeRabbit M13 round-7 R7-8: Low must map to Warn (not Allow), matching
        // the engine's `action_from_findings`.
        assert_eq!(action_for_severity(Severity::Low), Action::Warn);
        assert_eq!(action_for_severity(Severity::Info), Action::Allow);
    }

    #[test]
    fn action_for_severity_matches_action_from_findings() {
        // The whole point of R7-8: this helper must agree with the engine's
        // severity->action map for a SINGLE finding of each severity, so `rule
        // explain` reports the action the engine actually drives.
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
        // R7-6: the eval order is exec, paste, file — filtered to the rule's
        // compiled contexts (so a multi-context rule is tried in each).
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
}
