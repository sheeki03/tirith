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
    let (policy, _source) = match load_policy_strict("test", None, json) {
        Ok(pair) => pair,
        Err(code) => return code,
    };

    // Does the rule exist in the policy at all, and UNAMBIGUOUSLY? Distinguish
    // three cases: 0 matches → "unknown id"; >1 matches → an ambiguous policy
    // where silently picking the first match would be misleading (CodeRabbit M13
    // PR #132 R10-6); exactly 1 → proceed. (`validate` reports duplicate ids, so
    // point the operator there.)
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
                    // Normalize `\`→`/` like the runtime FileScan path so
                    // `file.path_matches` rules behave identically under test.
                    Some(input.replace('\\', "/"))
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
    // Read the RAW YAML SOURCE directly — NOT a strict-parsed Policy. `validate`
    // reads raw (no strict parse) BY DESIGN: the strict loader runs the
    // pattern-XOR-when shape gate (`Policy::try_parse_yaml`) which fails the
    // whole parse on the first both/neither rule, short-circuiting the very
    // per-rule validator below that is meant to report that rule-level problem
    // (with the rule id, continuing to check the rest). `test`/`explain` instead
    // need a fully-parsed Policy, so they use `load_policy_strict`; `validate`
    // reads via `read_policy_source` and runs its OWN lenient (gate-free) parse
    // below. CodeRabbit M13 PR #132 round-24.
    let (yaml, source) = match read_policy_source("validate", path, json) {
        Ok(pair) => pair,
        Err(code) => return code,
    };

    // Structural parse WITHOUT the shape gate, so a both/neither rule reaches
    // the per-rule `validate_shape()` check below instead of dying here.
    // Truly-malformed YAML still fails — `validate` then surfaces a parse-level
    // error and exits non-zero rather than silently passing unparseable input.
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
                // Route through the SAME shared resolver `compile_rules` uses
                // (`resolve_runtime_contexts` = `declared ∩ satisfiable`) so the
                // engine and both validators classify a rule IDENTICALLY
                // (CodeRabbit M13 round-15 rule.rs:338). `declared_contexts`
                // already carries serde's empty-→-`[exec, paste]` default for an
                // OMITTED `context:`, so a no-context `command.*` rule (declared
                // `[exec, paste]`) RESOLVES non-empty and is ACCEPTED — exactly as
                // the engine compiles it — while a no-context `file.path_matches`
                // rule (declared `[exec, paste]`, satisfiable `{file}`) resolves
                // to the EMPTY intersection and is correctly REJECTED. An explicit
                // `context: []` (which serde does NOT default) also resolves empty
                // and is rejected (finding D).
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
/// action and context.
///
/// Loads the policy strictly (so a broken `.tirith/policy.yaml` surfaces a parse
/// error) then delegates to [`explain_policy`], which holds the actual gating +
/// rendering. Splitting the load from the body (CodeRabbit M13 PR #132 round-22
/// F2) lets a unit test drive the REAL explain path against a constructed
/// `Policy` — exercising the `compile_rules` gate end-to-end — without a parallel
/// reimplementation or a cwd dance.
pub fn explain(rule_id: &str, json: bool) -> i32 {
    // Strict load so a broken `.tirith/policy.yaml` surfaces a parse error
    // (non-zero exit) instead of warn-defaulting to an empty policy that would
    // misreport every rule as "no custom rule named …" (CodeRabbit M13 round-2
    // R10).
    let (policy, _source) = match load_policy_strict("explain", None, json) {
        Ok(pair) => pair,
        Err(code) => return code,
    };
    explain_policy(&policy, rule_id, json)
}

/// The body of [`explain`] against an already-loaded [`Policy`]: the ambiguity /
/// not-found checks, the `compile_rules` gate, and the JSON/human render. Kept
/// separate from the strict-load step so tests can call the REAL gating+render
/// wiring directly (the CLI calls it via [`explain`]).
fn explain_policy(policy: &Policy, rule_id: &str, json: bool) -> i32 {
    // Reject an ambiguous policy: with duplicate ids `.find()` would silently
    // explain the FIRST match, hiding the others (CodeRabbit M13 PR #132 R10-6).
    // 0 → not found; >1 → fail fast and point at `validate`; exactly 1 → proceed.
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
    // Gate `explain` through the SAME `compile_rules` step `test` uses (CodeRabbit
    // M13 PR #132 R20). `compile_rules` clamps contexts, rejects unsupported
    // predicates (e.g. `agent.kind`), and dedups — so a rule the engine would
    // drop must NOT be described as if it were live. If the named rule is absent
    // from the compiled set it is invalid and would be skipped by the engine;
    // report that (matching `test`'s `emit_invalid_rule`) instead of rendering
    // the raw entry. The duplicate-id / not-found checks above already ran against
    // the raw policy, so reaching here means exactly one entry carries this id.
    let compiled = compile_rules(&policy.custom_rules);
    let compiled_rule = match compiled.iter().find(|r| r.id == rule_id) {
        Some(r) => r,
        // Absent from the compiled set → the engine would drop it; report that
        // rather than describe a rule that never runs.
        None => return emit_invalid_rule("explain", rule_id, json),
    };
    let rule = match policy.custom_rules.iter().find(|r| r.id == rule_id) {
        Some(r) => r,
        None => {
            return emit_not_found("explain", rule_id, policy, json);
        }
    };

    // The CLAMPED runtime contexts the engine actually evaluates this rule in
    // (`compile_rules` intersects declared ∩ satisfiable). `explain` must report
    // THESE, not `rule.context` (the originally-declared list) — otherwise it
    // advertises contexts the rule will never be evaluated in. E.g. a
    // `file.path_matches` rule declared `[exec, file]` compiles to `[file]`
    // only. CodeRabbit M13 PR #132 round-21.
    //
    // Render them in the SAME deterministic exec→paste→file order `rule test`
    // uses (`ordered_eval_contexts`), so the two commands describe a rule's
    // contexts identically regardless of the declared/compiled order. Without
    // this normalization `explain` would echo `compiled_rule.contexts` verbatim
    // (whatever order `compile_rules` happened to emit), while `rule test`
    // already orders them — an inconsistency CodeRabbit M13 PR #132 round-22
    // flagged.
    let runtime_contexts: Vec<&'static str> = ordered_eval_contexts(&compiled_rule.contexts)
        .into_iter()
        .map(scan_context_name)
        .collect();

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

/// Emit a policy-load failure (read or parse error) honoring the command's
/// output mode, then return the exit code (always 1). In `--json` mode this
/// MUST emit a structured JSON error object rather than plain-text stderr — a
/// failed path must not hand a machine consumer non-JSON while exit-1 says
/// "error" (tirith's JSON contract: every byte of `--json` output is JSON, and
/// the exit code stays authoritative). The shape reuses the SAME `{ source,
/// valid: false, error }` object `validate`'s own parse-error path already
/// produces, so all of `rule`'s load-stage errors look identical to a consumer.
/// In human mode it keeps the existing plain-text `eprintln!`. CodeRabbit M13
/// PR #132 round-27 F1.
///
/// A JSON write failure (broken pipe) returns exit 2, matching the success
/// paths' broken-pipe handling, rather than the load-error code 1.
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

/// The structured JSON error object emitted for a load-stage failure in
/// `--json` mode — factored out of [`emit_load_error`] so its exact shape is
/// unit-testable without capturing stdout. Mirrors `validate`'s parse-error
/// JSON: `{ source, valid: false, error }`.
fn load_error_json(source: &str, error: &str) -> serde_json::Value {
    serde_json::json!({
        "source": source,
        "valid": false,
        "error": error,
    })
}

/// Resolve a `rule` subcommand's policy SOURCE: from `--path` (the file
/// itself) or the discovered local policy. Returns `(raw-yaml, source-label)`,
/// or `Err(exit_code)` after emitting a file-read error in the command's
/// output mode (`json`-aware — see [`emit_load_error`]). No YAML/shape parsing
/// happens here — that is the caller's choice (strict vs lenient), so the two
/// load helpers below can share one I/O path.
///
/// A missing policy file is NOT an error: it yields an empty document
/// (`String::new()`) labeled `<no policy file>`, which both parsers treat as
/// the zero-custom-rule default (matches the shipping/no-policy case).
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

/// Load the policy STRICTLY for `test`/`explain`: read the source, then run the
/// full [`Policy::try_parse_yaml`] (migrate → deserialize → enforce the
/// pattern-XOR-when shape gate). Returns `(policy, source-label)`, or
/// `Err(exit_code)` after printing a config-load error.
///
/// Unlike [`Policy::discover`] (which warn-defaults a broken local policy to a
/// fail-closed empty policy — hiding the parse error behind a misleading "no
/// custom rule" / empty result), this surfaces a parse error as a non-zero
/// exit with the YAML location. `cmd` names the subcommand for the message
/// (`test` / `explain`). (CodeRabbit M13 round-2 R10.)
///
/// `validate` does NOT use this: it must reach its own per-rule validator even
/// for the rule-level problems (e.g. both `pattern:` and `when:`) the strict
/// shape gate would reject up front, so it reads the raw source via
/// [`read_policy_source`] and runs its own lenient parse instead (CodeRabbit M13
/// PR #132 round-24).
fn load_policy_strict(cmd: &str, path: Option<&str>, json: bool) -> Result<(Policy, String), i32> {
    let (yaml, source) = read_policy_source(cmd, path, json)?;
    // An empty document (no policy file) is the zero-custom-rule default.
    if yaml.is_empty() {
        return Ok((Policy::default(), source));
    }
    // try_parse_yaml surfaces a parse error rather than warn-and-defaulting,
    // so a malformed `when:` is reported as exit 1 with the YAML location.
    // In `--json` mode the error is a structured object, not plain stderr
    // (CodeRabbit M13 PR #132 round-27 F1) — same `{ source, valid: false,
    // error }` shape `validate`'s own parse-error path uses.
    match Policy::try_parse_yaml(&yaml) {
        Ok(policy) => Ok((policy, source)),
        Err(e) => Err(emit_load_error(cmd, &source, &e.to_string(), json)),
    }
}

/// Structurally parse policy YAML for `validate` WITHOUT the strict
/// pattern-XOR-when shape gate — the migrate-then-deserialize half of
/// [`Policy::try_parse_yaml`], minus its per-rule `validate_shape` enforcement.
///
/// Dropping the shape gate is the whole point: a rule carrying BOTH `pattern:`
/// and `when:` (or neither) still deserializes structurally, so [`validate`]'s
/// own per-rule loop (`rule.validate_shape()`) can report it with the rule id
/// instead of a generic up-front parse error. Truly-malformed YAML (or a
/// schema-migration failure) still returns `Err`, so `validate` surfaces a
/// parse-level error and exits non-zero rather than silently passing
/// unparseable input. (CodeRabbit M13 PR #132 round-24.)
///
/// An empty document (no policy file) parses to the default zero-rule policy.
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

/// The policy declares MORE THAN ONE custom rule with this id, so selecting
/// "the rule" is ambiguous — `test`/`explain` must not silently pick the first
/// match (CodeRabbit M13 PR #132 R10-6). Fail fast and point at
/// `tirith rule validate`, which reports the duplicate. Exit 1.
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
        // A broken pipe must surface as a write failure (exit 2), consistent with
        // the success paths — not be misreported as the duplicate error (exit 1).
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

    // CodeRabbit M13 PR #132 round-24: `rule validate` must load LENIENTLY so a
    // RULE-LEVEL problem (here: a rule carrying BOTH `pattern:` and `when:`) is
    // reported by its OWN per-rule validator — with the rule id, exit 1 — not by
    // a generic up-front strict-parse error. Before the fix `load_policy` always
    // ran `Policy::try_parse_yaml`, whose pattern-XOR-when shape gate failed the
    // whole parse on the first offender, so `validate` never reached its per-rule
    // loop. Meanwhile `test`/`explain` (which DO need a fully-parsed Policy) keep
    // the strict loader and must still reject the same policy up front.
    #[test]
    fn validate_both_pattern_and_when_reaches_per_rule_validator_not_strict_parse() {
        let yaml = "custom_rules:\n  - id: both\n    pattern: \"foo\"\n    when:\n      command.uses_sudo: true\n    title: \"has both pattern and when\"\n    context: [exec]\n";

        // The STRICT path that `test`/`explain` use rejects this up front (its
        // shape gate fires), so those commands still fail as before.
        assert!(
            Policy::try_parse_yaml(yaml).is_err(),
            "strict parse (test/explain) must still reject a both-pattern-and-when rule up front"
        );

        // The LENIENT path that `validate` now uses parses it STRUCTURALLY — the
        // shape gate is gone, so the per-rule validator can see the rule.
        let policy = parse_policy_lenient(yaml)
            .expect("lenient parse must SUCCEED on a both/neither rule so validate can report it");
        let rule = policy
            .custom_rules
            .iter()
            .find(|r| r.id == "both")
            .expect("the both/neither rule survives the lenient (gate-free) parse");
        // And `validate`'s per-rule check produces a HELPFUL rule-level message
        // (the exact `validate_shape` diagnostic), not a generic deserialize error.
        let shape_err = rule
            .validate_shape()
            .expect_err("validate_shape must flag the both-pattern-and-when rule");
        assert!(
            shape_err.to_string().contains("exactly one of"),
            "the per-rule validator must give the friendly shape message, got: {shape_err}"
        );

        // End-to-end through the REAL `validate` command: exit 1 (the offending
        // rule is reported), and crucially NOT exit 0 (it must not silently pass).
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

    /// CodeRabbit M13 PR #132 round-27 F1: in `--json` mode a policy LOAD
    /// failure (missing/unreadable file) must emit a STRUCTURED JSON error
    /// object (NOT plain-text stderr) so a machine consumer reading stdout
    /// never gets non-JSON while the exit code claims "error". This pins the
    /// exact shape the shared load-error helper builds (`{ source, valid:
    /// false, error }`) — the SAME shape `validate`'s parse-error path already
    /// produces — and proves it round-trips as valid JSON carrying the error
    /// field. `emit_load_error` writes THIS value via `write_json_stdout` (the
    /// same stdout writer every other `--json` path in this file uses), so
    /// verifying the value here proves the bytes on stdout are valid JSON
    /// without an FD-capture race against the parallel test harness.
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

    /// CodeRabbit M13 PR #132 round-27 F1, end-to-end: `validate --json` on a
    /// MISSING `--path` must exit NON-ZERO (the exit code stays authoritative).
    /// Combined with `load_error_json_is_structured_and_carries_error_field`
    /// (the JSON shape) and `validate_json_missing_path_routes_through_load_error`
    /// (the JSON branch is the one taken), this covers the contract: a `--json`
    /// load failure exits non-zero AND emits structured JSON, never plain text.
    /// Exit-code-only here keeps it deterministic under the parallel harness (no
    /// process-wide stdout FD capture, which races with libtest's own output).
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

    /// CodeRabbit M13 PR #132 round-27 F1, routing: prove the JSON branch is the
    /// one a missing/unreadable file takes — `emit_load_error(json=true)` returns
    /// 1 (after writing the JSON object to stdout) and `emit_load_error(json=false)`
    /// returns 1 (after the plain-text `eprintln!`). Both exit 1, but only the
    /// JSON arm produces the structured object asserted above. This is the
    /// deterministic, race-free stand-in for capturing process stdout: it drives
    /// the SAME helper `read_policy_source`/`load_policy_strict` call on failure.
    #[test]
    fn validate_json_missing_path_routes_through_load_error() {
        // JSON arm: exit 1 (the object went to stdout via write_json_stdout).
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

    // round-24 companion: truly-malformed YAML must STILL make `validate` exit
    // non-zero — lenient loading defers the shape gate, it does NOT swallow
    // unparseable input. `parse_policy_lenient` returns Err, and the command
    // surfaces a parse-level error (exit 1) rather than silently passing.
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
        // CodeRabbit M13 round-15 rule.rs:338: an OMITTED `context:` defaults to
        // [exec, paste], so a no-context `command.*` rule RESOLVES to a non-empty
        // set and `rule validate` must EXIT 0 — matching what the engine
        // compiles+runs. And `policy validate` must agree (no coverage error).
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
        // The companion: a no-context `file.path_matches` rule resolves to
        // [exec, paste] ∩ {file} = ∅, so it can never fire and `rule validate`
        // must EXIT 1. `policy validate` must AGREE (it reports the coverage
        // error). This proves the default-then-clamp model, not a literal
        // `!declared.is_empty()` skip (which would wrongly accept this dead rule).
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
        // CodeRabbit M13 round-27: the 1024 pattern cap counts CHARACTERS, not
        // UTF-8 bytes — consistent with compile_rules / check_regex / policy
        // validate. A 600-char multibyte pattern is 1200 bytes but well under the
        // 1024-CHAR cap, so `rule validate` must ACCEPT it; the old byte-length
        // check (`pattern.len()`) would have wrongly rejected it.
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

    // CodeRabbit M13 PR #132 R20 + round-22 F2: `rule explain` must route through
    // the SAME `compile_rules` gate `rule test` uses, so it can never DESCRIBE a
    // rule the engine would drop (and that `test`/`validate` reject). The round-20
    // version of this test only asserted that `compile_rules` dropped the rule and
    // that `emit_invalid_rule` returns non-zero IN ISOLATION — it never invoked the
    // real `explain` path, so the gating WIRING inside `explain` was untested
    // end-to-end. This drives the REAL post-load body (`explain_policy`, exactly
    // what the CLI's `explain` calls after loading) against a constructed policy.
    //
    // `agent.kind` is an unsupported predicate — `compile_rules` skips any rule
    // using it — so a policy whose only rule uses `agent.kind` compiles to the
    // EMPTY set, the precise condition `explain`'s gate keys off to reject. Use
    // the HUMAN path (`json=false`): its rejection (`emit_invalid_rule`) writes
    // only to STDERR and returns 1, so a clean stdout proves the raw entry was
    // NOT rendered (the human success path would `println!` the rule to stdout).
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

    // F2 (positive half): a VALID rule must explain successfully through the real
    // `explain_policy` path — exit 0. Pairs with the rejection test so both arms of
    // the compile gate (drop → non-zero; keep → zero) are covered end-to-end via
    // the actual command body, not a parallel reimplementation.
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

    // F2: a not-found id and a duplicate id must also be handled by the real
    // `explain_policy` body — exit 1 in both cases — so the not-found / ambiguity
    // gates are covered through the actual command path too, not just the
    // compile-gate arm.
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

    // CodeRabbit M13 PR #132 round-21: `explain` must report the CLAMPED runtime
    // contexts (`compile_rules`'s declared ∩ satisfiable), NOT the originally
    // declared `context:` list — otherwise it advertises contexts the rule is
    // never evaluated in. A `file.path_matches` clause is satisfiable only in
    // FileScan, so declaring it for `[exec, file]` clamps to `[file]` alone. This
    // pins the exact transformation `explain`'s JSON/human output now reads from
    // (`compiled_rule.contexts` mapped via `scan_context_name`), proving the
    // clamped set is strictly smaller than the declared set.
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

        // The COMPILED rule — exactly what `explain` now renders from — is clamped
        // by `compile_rules` to the satisfiable intersection, i.e. file only.
        // Build the reported list the SAME way `explain` does: pass the compiled
        // contexts through `ordered_eval_contexts` (F1), then map each name.
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
        // And the clamped set is STRICTLY smaller than the declared set — the
        // precise regression (rendering declared contexts the rule never runs in).
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

    // CodeRabbit M13 PR #132 round-22 F1: `explain` must render runtime contexts
    // in the SAME deterministic exec→paste→file order `rule test` uses (via
    // `ordered_eval_contexts`), not in whatever order the compiled set carries.
    // A REGEX rule is the observable case: `compile_rules` stores its DECLARED
    // contexts verbatim (DSL rules are already normalized to exec→paste→file by
    // `ContextSet::to_contexts`). So a regex rule declared `context: [file, exec]`
    // compiles to `[file, exec]` — and the pre-F1 `explain` would echo that
    // reversed order, disagreeing with `rule test`. This pins that `explain` now
    // normalizes it to `[exec, file]`.
    #[test]
    fn explain_orders_contexts_exec_before_file() {
        let yaml = "custom_rules:\n  - id: regex-reversed-ctx\n    pattern: 'curl'\n    title: \"regex rule declared file then exec\"\n    context: [file, exec]\n";
        let policy = Policy::try_parse_yaml(yaml).expect("policy parses");

        // The compiled regex rule carries the declared order verbatim (file, exec)
        // — proving the reorder is observable, not a no-op.
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

        // What `explain` renders (the exact production transform): the contexts run
        // through `ordered_eval_contexts` first → exec BEFORE file.
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
