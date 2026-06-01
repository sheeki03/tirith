use regex::Regex;

use crate::custom_rule_dsl::{self, DslEvalContext, WhenClause};
use crate::extract::ScanContext;
use crate::policy::CustomRule;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// The matcher half of a compiled custom rule: a regex (the original path) or a
/// semantic-predicate `when:` clause (M13 ch4 DSL). A rule carries exactly one.
pub enum CompiledMatcher {
    Regex(Regex),
    When(Box<WhenClause>),
}

/// A compiled custom rule ready for matching.
pub struct CompiledCustomRule {
    pub id: String,
    pub matcher: CompiledMatcher,
    pub contexts: Vec<ScanContext>,
    pub severity: Severity,
    pub title: String,
    pub description: String,
}

impl CompiledCustomRule {
    /// `true` when this rule's matcher is a `when:` clause (DSL rule).
    pub fn is_dsl(&self) -> bool {
        matches!(&self.matcher, CompiledMatcher::When(_))
    }
}

/// Parse a rule's declared `context:` strings into [`ScanContext`]s, warning on
/// unknown tokens. Shared by both the regex and DSL compile paths.
fn parse_contexts(rule: &CustomRule) -> Vec<ScanContext> {
    rule.context
        .iter()
        .filter_map(|c| match c.as_str() {
            "exec" => Some(ScanContext::Exec),
            "paste" => Some(ScanContext::Paste),
            "file" => Some(ScanContext::FileScan),
            other => {
                eprintln!(
                    "tirith: warning: custom rule '{}' has unknown context: {other}",
                    rule.id
                );
                None
            }
        })
        .collect()
}

/// Compile custom rules from policy. Invalid rules (bad shape, invalid regex,
/// pattern longer than the 1024-char cap, no valid contexts, a DSL clause using
/// an unsupported predicate, or — for DSL rules — predicates whose required
/// trigger groups aren't covered by the declared `context:`) are logged and
/// skipped. This keeps the hot path fail-open: a malformed rule never blocks the
/// user. Strict validation with non-zero exit lives in `tirith rule validate`,
/// which mirrors EXACTLY the drops below.
///
/// Unsupported-predicate handling (CodeRabbit M13 round-8 R8-1): a DSL clause
/// using `agent.kind` or `mcp.tool` is SKIPPED here — those predicates read a
/// [`custom_rule_dsl::DslEvalContext`] field the engine hard-codes to `None`, so
/// the rule could never match. Both validators reject such a rule outright, and
/// skipping here keeps the engine from pretending to run a dead rule. This
/// removed round-7's "context-agnostic clause → assign an executable context
/// set" branch: the ONLY clauses with empty required triggers were
/// `agent.kind`-only ones (`mcp.tool` requires FileScan), and those are now
/// skipped before context resolution, so the branch was unreachable. A regex
/// rule, or a DSL rule with required triggers, still needs a declared context
/// that covers its data; a DSL rule that resolves to no usable context is
/// dropped as a dead rule (matching the regex path and `tirith rule validate`).
pub fn compile_rules(rules: &[CustomRule]) -> Vec<CompiledCustomRule> {
    let mut compiled = Vec::new();
    for rule in rules {
        // Exactly-one-of pattern/when.
        if let Err(e) = rule.validate_shape() {
            eprintln!("tirith: warning: custom rule '{}' {e}, skipping", rule.id);
            continue;
        }

        let declared = parse_contexts(rule);

        // `contexts` is the executable context set for this rule and `matcher`
        // its compiled matcher, resolved together. Both the regex and DSL arms
        // use the rule's declared contexts directly (a rule that resolves to no
        // usable context is dropped as a dead rule in each arm).
        let (contexts, matcher) = if let Some(pattern) = &rule.pattern {
            // Regex rule: needs a declared context (it has no required-trigger
            // notion). Empty declared contexts -> dead rule, skip.
            if declared.is_empty() {
                eprintln!(
                    "tirith: warning: custom rule '{}' has no valid contexts, skipping",
                    rule.id
                );
                continue;
            }
            // Measure the cap in CHARACTERS, not UTF-8 BYTES: the limit and the
            // message both speak of "chars", so a multibyte pattern must not hit
            // the cap early or report a misleading byte count (CodeRabbit M13
            // round-26). `check_regex` in `custom_rule_dsl` applies the same
            // char-count cap so regex validation stays consistent.
            if pattern.chars().count() > 1024 {
                eprintln!(
                    "tirith: custom rule '{}' pattern too long ({} chars), skipping",
                    rule.id,
                    pattern.chars().count()
                );
                continue;
            }
            match Regex::new(pattern) {
                Ok(r) => (declared, CompiledMatcher::Regex(r)),
                Err(e) => {
                    eprintln!(
                        "tirith: warning: custom rule '{}' has invalid regex: {e}",
                        rule.id
                    );
                    continue;
                }
            }
        } else if let Some(when) = &rule.when {
            // Validate the clause's regexes up front so a bad inner regex is a
            // skip, not a per-input recompile failure.
            if let Err(e) = custom_rule_dsl::validate_regexes(when) {
                eprintln!(
                    "tirith: warning: custom rule '{}' has invalid when-clause: {e}",
                    rule.id
                );
                continue;
            }
            // Skip a clause that uses an unsupported predicate (`agent.kind` /
            // `mcp.tool`): the engine hard-codes their backing field to `None`,
            // so the rule could never match. Don't pretend to run a dead rule
            // (CodeRabbit M13 round-8 R8-1). Both validators reject it outright.
            // Done before the satisfiability check so an unsupported predicate's
            // empty satisfiable set isn't reported as an "unsatisfiable" clause.
            if let Some(reason) = custom_rule_dsl::clause_uses_unsupported_predicate(when) {
                eprintln!(
                    "tirith: warning: custom rule '{}' {reason}, skipping",
                    rule.id
                );
                continue;
            }
            // Per-clause satisfiability + coverage (CodeRabbit M13 round-9 R9-1).
            // `satisfiable_contexts` is the set of scan contexts in which the
            // WHOLE clause can be evaluated — `all` intersects children, `any`
            // unions, `not` is the child's set — so combinators stay sound.
            //
            // (1) An EMPTY satisfiable set means the clause mixes facts from
            //     contexts that never co-occur in a single scan (e.g. `all(
            //     command.*, file.*)`) — it can NEVER match. Drop it as a dead
            //     rule (fail-open on the hot path); both validators reject it.
            //     This also covers `declared.is_empty()` for any real predicate:
            //     an empty declared set has no intersection with a non-empty
            //     satisfiable set, so the coverage check below drops it.
            let satisfiable = custom_rule_dsl::satisfiable_contexts(when);
            if satisfiable.is_empty() {
                eprintln!(
                    "tirith: warning: custom rule '{}' when-clause needs facts from contexts that never co-occur in a single scan (e.g. command + file), skipping",
                    rule.id
                );
                continue;
            }
            // (2) The declared context must intersect the satisfiable set, or the
            //     predicates can never see their data in any context the rule
            //     runs. Skip (fail-open) on the hot path; `tirith rule validate`
            //     reports this as a hard error. An empty declared context here is
            //     a dead rule (no intersection) and is dropped, matching the regex
            //     path and `tirith rule validate`.
            //
            // Resolve the rule's RUNTIME contexts through the SINGLE shared model
            // (`resolve_runtime_contexts` = `declared ∩ satisfiable`) and store
            // THAT, not the full `declared` (CodeRabbit M13 round-15
            // custom.rs:172). Storing the full declared set let `check_dsl` run
            // the clause in a declared context where its facts are ABSENT — e.g.
            // `not(file.path_matches)` declared `[exec, file]` ran in Exec, where
            // `file_path` is `None` so `file.path_matches` is `false` and `not`
            // flips it to a FALSE POSITIVE. The clamp guarantees the clause is
            // only evaluated where every fact it reads is populated. A non-empty
            // resolved set is exactly the validity condition both validators use,
            // so all three agree.
            let runtime_contexts = custom_rule_dsl::resolve_runtime_contexts(&declared, when);
            if runtime_contexts.is_empty() {
                eprintln!(
                    "tirith: warning: custom rule '{}' when-clause can only be evaluated in context [{}] not covered by its declared context, skipping",
                    rule.id,
                    satisfiable.describe()
                );
                continue;
            }
            (
                runtime_contexts,
                CompiledMatcher::When(Box::new(when.clone())),
            )
        } else {
            // validate_shape already guaranteed one of the two arms above.
            unreachable!("validate_shape guarantees exactly one of pattern/when");
        };

        compiled.push(CompiledCustomRule {
            id: rule.id.clone(),
            matcher,
            contexts,
            severity: rule.severity,
            title: rule.title.clone(),
            description: rule.description.clone(),
        });
    }
    compiled
}

/// Build a [`Finding`] for a matched custom rule (regex or DSL). The
/// `match_detail` is the rule-specific evidence line.
fn make_finding(rule: &CompiledCustomRule, match_detail: String) -> Finding {
    Finding {
        rule_id: RuleId::CustomRuleMatch,
        severity: rule.severity,
        title: rule.title.clone(),
        description: if rule.description.is_empty() {
            format!("Custom rule '{}' matched", rule.id)
        } else {
            rule.description.clone()
        },
        evidence: vec![Evidence::Text {
            detail: match_detail,
        }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: Some(rule.id.clone()),
    }
}

/// Check input against compiled REGEX custom rules for a given context.
///
/// DSL (`when:`) rules are evaluated separately by [`check_dsl`] (they need the
/// richer extracted data, not a `&str`). A `when:` rule never matches here.
pub fn check(input: &str, context: ScanContext, compiled: &[CompiledCustomRule]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in compiled {
        if !rule.contexts.contains(&context) {
            continue;
        }
        let CompiledMatcher::Regex(regex) = &rule.matcher else {
            continue;
        };

        if let Some(m) = regex.find(input) {
            let matched_text = m.as_str();
            let preview: String = matched_text.chars().take(100).collect();
            findings.push(make_finding(rule, format!("Matched: \"{preview}\"")));
        }
    }

    findings
}

/// Evaluate compiled DSL (`when:`) custom rules against the extracted analysis
/// data for a given context. Regex rules are skipped here (see [`check`]).
///
/// A finding fires (reusing [`RuleId::CustomRuleMatch`], like the regex path)
/// when the clause matches AND `context` is in the rule's declared contexts.
pub fn check_dsl(
    ctx: &DslEvalContext,
    context: ScanContext,
    compiled: &[CompiledCustomRule],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in compiled {
        if !rule.contexts.contains(&context) {
            continue;
        }
        let CompiledMatcher::When(clause) = &rule.matcher else {
            continue;
        };

        if custom_rule_dsl::evaluate(clause, ctx) {
            findings.push(make_finding(
                rule,
                format!("when-clause matched (rule '{}')", rule.id),
            ));
        }
    }

    findings
}

/// `true` when any compiled rule is a DSL (`when:`) rule. Lets the engine skip
/// building a [`DslEvalContext`] entirely on the common regex-only path.
pub fn any_dsl_rules(compiled: &[CompiledCustomRule]) -> bool {
    compiled.iter().any(|r| r.is_dsl())
}

/// `true` when, FOR THE GIVEN scan context `ctx`, the policy carries at least one
/// DSL (`when:`) custom rule that (a) would actually COMPILE — it has a `when:`
/// clause and uses no unsupported predicate (`agent.kind` / `mcp.tool`, which
/// [`compile_rules`] always drops) — AND (b) keys on a SEMANTIC fact the tier-1
/// fast gate cannot observe ([`custom_rule_dsl::clause_has_tier1_invisible_predicate`])
/// — AND (c) WOULD ACTUALLY RUN in `ctx`, i.e. `ctx` is in the rule's resolved
/// runtime contexts (`declared ∩ satisfiable`), the SAME clamp `compile_rules`
/// stores as the rule's [`CompiledCustomRule::contexts`].
///
/// # The tier-1 gating bug this prevents (see CLAUDE.md)
///
/// The engine's tier-1 fast-exit early-returns "allow" when no regex/byte signal
/// fired. A DSL rule whose `when:` clause keys only on `command.uses_sudo`,
/// `command.has_pipeline_to`, `command.cwd_in`, `package.*`, `url.*`, … would
/// then be silently SKIPPED on input it should match (e.g. a bare `sudo whoami`,
/// which trips no tier-1 pattern) — the dotfile-overwrite gating bug class, for
/// DSL rules. The engine calls this BEFORE the fast-exit and, when it returns
/// `true`, forces past the early return so [`check_dsl`] runs for this input.
///
/// # Why CONTEXT-AWARE (CodeRabbit M13 PR #132)
///
/// The force-past only buys anything in the context where the rule can FIRE. A
/// FILE-scoped rule (`file.path_matches`, `context: [file]`) keys on a fact only
/// the FileScan path populates; `compile_rules` clamps its runtime contexts to
/// `{file}`, so [`check_dsl`] never evaluates it in Exec/Paste. A
/// context-AGNOSTIC gate would nonetheless force EVERY Exec/Paste command past
/// the fast-exit for such a rule — defeating the fast-exit for unrelated input
/// AND forcing continuation for a rule `compile_rules` would DROP from that
/// context. Restricting to rules whose resolved runtime contexts INCLUDE `ctx`
/// keeps the gate in exact lockstep with compile-time context dropping: the gate
/// forces continuation iff the rule both compiles AND would run in `ctx`.
///
/// # Performance
///
/// This runs on the sub-millisecond tier-1 hot path, so it does the CHEAPEST
/// possible work: an O(rules) scan over the (typically empty/tiny) raw
/// `custom_rules` list, recursing each `when:` clause tree, and SHORT-CIRCUITS on
/// the first forcing rule. It compiles NO regex and builds NO [`DslEvalContext`]
/// / backing — it only inspects the clause SHAPE plus the cheap context algebra.
/// A policy with no semantic DSL rule pays just the empty-slice scan, so the
/// common case is unchanged.
///
/// Operates on the RAW [`CustomRule`]s (not [`CompiledCustomRule`]s) so the
/// engine can consult it BEFORE the (more expensive) `compile_rules` pass that
/// today runs only past the fast-exit. Reusing [`parse_contexts`] +
/// [`custom_rule_dsl::resolve_runtime_contexts`] — the exact `declared` source and
/// clamp helper `compile_rules` uses — keeps it in lockstep with `compile_rules`:
/// a rule this returns `true` for is exactly one `compile_rules` would keep, run
/// in `ctx`, and `check_dsl` could fire — so the gate never forces continuation
/// for a rule that would be dropped (as dead, or as not running in `ctx`) anyway.
pub fn any_semantic_only_dsl_rules_for_context(rules: &[CustomRule], ctx: ScanContext) -> bool {
    rules.iter().any(|rule| match &rule.when {
        Some(clause) => {
            // (a) compiles (not a dead agent.kind / mcp.tool rule) AND
            // (b) keys on a tier-1-invisible fact AND
            // (c) actually runs in `ctx` — resolved through the SAME
            //     `parse_contexts` + `resolve_runtime_contexts` clamp
            //     `compile_rules` uses, so the gate can't drift from compile-time
            //     context dropping. Ordered cheapest-first; the clamp is last so a
            //     dead / tier-1-visible rule skips it.
            custom_rule_dsl::clause_uses_unsupported_predicate(clause).is_none()
                && clause_has_tier1_invisible_predicate(clause)
                && custom_rule_dsl::resolve_runtime_contexts(&parse_contexts(rule), clause)
                    .contains(&ctx)
        }
        None => false,
    })
}

/// `true` when a clause references AT LEAST ONE leaf predicate whose backing
/// fact the tier-1 fast gate cannot observe — i.e. a predicate that needs tier-2
/// extraction or tier-3 state to evaluate, so the engine MUST run the rules
/// rather than fast-exit.
///
/// # Why this exists (the tier-1 gating bug class, see CLAUDE.md)
///
/// The engine's tier-1 fast-exit ([`crate::engine::analyze`]) early-returns
/// "allow" when no regex/byte signal fired (no suspicious URL, no bidi /
/// zero-width / invisible bytes, …). A DSL `when:` rule whose clause keys only on
/// SEMANTIC facts the tier-1 gate never inspects — `command.uses_sudo`,
/// `command.has_pipeline_to`, `command.cwd_in`, `package.*`, `url.*` — would be
/// silently skipped on input it should match (e.g. a benign `whoami` under a
/// watched `command.cwd_in` directory, which trips no tier-1 pattern). The engine
/// consults this (via [`any_semantic_only_dsl_rules`]) to FORCE PAST the fast-exit
/// when a semantic-only DSL rule is loaded, exactly as it does for taint / canary
/// / exec-guard (the `*_triggered` flags).
///
/// # Which leaves are "tier-1-invisible"
///
/// EVERY real leaf predicate is treated as tier-1-invisible, because none of
/// their backing facts are guaranteed to coincide with a tier-1 trigger:
///
/// * `command.*` — command structure (sudo / pipeline / cwd) is not by itself a
///   reliable regex/byte signal; the leader/pipeline must be TOKENIZED first
///   (tier-2). (`sudo` happens to ALSO trip a tier-1 fragment, but `cwd_in` /
///   `has_pipeline_to` on a benign leader do not.)
/// * `url.*` / `package.*` — these read EXTRACTED URLs / packages (tier-2). A
///   benign URL (e.g. `https://company.com`) or install package trips no tier-1
///   suspicious-URL pattern, so the gate cannot see it; the data only exists
///   after extraction.
/// * `file.path_matches` — reads the scanned file path (FileScan). FileScan
///   never fast-exits ([`crate::extract::tier1_scan`] returns `true` for it), so
///   this is moot in practice, but it is still classified invisible: it is never
///   a tier-1 regex/byte trigger.
///
/// `agent.kind` / `mcp.tool` are dead predicates (their backing field is
/// hard-coded `None` and [`compile_rules`] never compiles a rule using them), so
/// on their own they contribute NOTHING here — a clause that is ONLY `agent.kind`
/// returns `false` and does not force continuation (the rule could never fire
/// anyway). A combinator returns `true` if ANY child does, so a real predicate
/// buried inside `all`/`any`/`not` still forces continuation.
///
/// This errs toward `true` (run the rules) per correctness-over-micro-
/// optimization: any clause carrying a real, evaluable predicate forces past the
/// fast-exit. The scan is O(clause nodes) over a usually-empty custom-rule list
/// and does NO regex work, so the common no-DSL-rule hot path is unchanged.
fn clause_has_tier1_invisible_predicate(clause: &WhenClause) -> bool {
    match clause {
        // Combinators: invisible if ANY child is (a single real leaf anywhere in
        // the tree means the rule needs tier-2/3 to decide).
        WhenClause::All(cs) | WhenClause::Any(cs) => {
            cs.iter().any(clause_has_tier1_invisible_predicate)
        }
        WhenClause::Not(c) => clause_has_tier1_invisible_predicate(c),

        // Dead predicates — never compiled, can never fire, so they do NOT on
        // their own justify forcing past the fast-exit.
        WhenClause::AgentKind(_) | WhenClause::McpTool(_) => false,

        // Every real leaf reads tier-2/3 data the tier-1 gate cannot observe.
        WhenClause::CommandHasPipelineTo(_)
        | WhenClause::CommandUsesSudo(_)
        | WhenClause::CommandCwdIn(_)
        | WhenClause::UrlHost(_)
        | WhenClause::UrlHostMatches(_)
        | WhenClause::UrlScheme(_)
        | WhenClause::UrlReputation(_)
        | WhenClause::UrlDomainNotIn(_)
        | WhenClause::PackageEcosystem(_)
        | WhenClause::PackageNameMatches(_)
        | WhenClause::PackageReputation(_)
        | WhenClause::FilePathMatches(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(id: &str, pattern: &str, contexts: &[&str]) -> CustomRule {
        CustomRule {
            id: id.to_string(),
            pattern: Some(pattern.to_string()),
            when: None,
            context: contexts.iter().map(|s| s.to_string()).collect(),
            severity: Severity::High,
            title: format!("Test rule: {id}"),
            description: String::new(),
            action: None,
        }
    }

    fn make_dsl_rule(id: &str, when: WhenClause, contexts: &[&str]) -> CustomRule {
        CustomRule {
            id: id.to_string(),
            pattern: None,
            when: Some(when),
            context: contexts.iter().map(|s| s.to_string()).collect(),
            severity: Severity::Critical,
            title: format!("DSL rule: {id}"),
            description: String::new(),
            action: None,
        }
    }

    #[test]
    fn test_compile_valid_rule() {
        let rules = vec![make_rule("test1", r"internal\.corp", &["exec"])];
        let compiled = compile_rules(&rules);
        assert_eq!(compiled.len(), 1);
        assert_eq!(compiled[0].id, "test1");
        assert!(!compiled[0].is_dsl());
    }

    #[test]
    fn test_compile_invalid_regex_skipped() {
        let rules = vec![make_rule("bad", r"(unclosed", &["exec"])];
        let compiled = compile_rules(&rules);
        assert_eq!(compiled.len(), 0);
    }

    #[test]
    fn test_check_matches_in_context() {
        let rules = vec![make_rule(
            "corp",
            r"internal\.corp\.example\.com",
            &["exec"],
        )];
        let compiled = compile_rules(&rules);

        let findings = check(
            "curl https://internal.corp.example.com/api",
            ScanContext::Exec,
            &compiled,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CustomRuleMatch);
        assert_eq!(findings[0].custom_rule_id.as_deref(), Some("corp"));
    }

    #[test]
    fn test_check_no_match_wrong_context() {
        let rules = vec![make_rule("corp", r"internal\.corp", &["exec"])];
        let compiled = compile_rules(&rules);

        let findings = check("internal.corp.example.com", ScanContext::Paste, &compiled);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_check_no_match_when_pattern_absent() {
        let rules = vec![make_rule("corp", r"internal\.corp", &["exec"])];
        let compiled = compile_rules(&rules);

        let findings = check("curl https://example.com", ScanContext::Exec, &compiled);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_compile_skips_rule_with_both_pattern_and_when() {
        let mut rule = make_rule("both", r"x", &["exec"]);
        rule.when = Some(WhenClause::CommandUsesSudo(true));
        let compiled = compile_rules(&[rule]);
        assert_eq!(
            compiled.len(),
            0,
            "rule with both pattern and when is skipped"
        );
    }

    #[test]
    fn test_compile_skips_rule_with_neither() {
        let mut rule = make_rule("neither", r"x", &["exec"]);
        rule.pattern = None;
        let compiled = compile_rules(&[rule]);
        assert_eq!(
            compiled.len(),
            0,
            "rule with neither pattern nor when is skipped"
        );
    }

    #[test]
    fn test_compile_dsl_rule() {
        let rule = make_dsl_rule("dsl1", WhenClause::CommandUsesSudo(true), &["exec"]);
        let compiled = compile_rules(&[rule]);
        assert_eq!(compiled.len(), 1);
        assert!(compiled[0].is_dsl());
        assert!(any_dsl_rules(&compiled));
    }

    #[test]
    fn test_any_semantic_only_dsl_rules_classification() {
        // Tier-1 gating guard (CodeRabbit M13 PR #132): the engine consults this
        // BEFORE the fast-exit to decide whether a semantic-only DSL rule must
        // force continuation IN THE CURRENT CONTEXT. This test fixes the context to
        // Exec and varies the clause; `test_any_semantic_only_dsl_rules_is_context_aware`
        // varies the context for a fixed clause.

        // A `command.uses_sudo` rule (declared `[exec]`) references a
        // tier-1-invisible predicate and runs in Exec -> true.
        let sudo = make_dsl_rule("sudo", WhenClause::CommandUsesSudo(true), &["exec"]);
        assert!(
            any_semantic_only_dsl_rules_for_context(&[sudo], ScanContext::Exec),
            "a command.uses_sudo DSL rule is semantic-only and must force continuation in Exec"
        );

        // A `file.path_matches` rule declared `[file]` is tier-1-invisible AND runs
        // in FileScan -> true when asked about FileScan.
        let file_rule = make_dsl_rule(
            "file",
            WhenClause::FilePathMatches(r"\.env$".into()),
            &["file"],
        );
        assert!(
            any_semantic_only_dsl_rules_for_context(&[file_rule], ScanContext::FileScan),
            "a file.path_matches DSL rule is semantic-only and runs in FileScan"
        );

        // A REGEX rule (no `when:`) is NOT a DSL rule -> false (regex matching runs
        // only past the gate; tier-1 already covers what regex rules need or not).
        let regex = make_rule("regex", r"internal\.corp", &["exec"]);
        assert!(
            !any_semantic_only_dsl_rules_for_context(&[regex], ScanContext::Exec),
            "a regex-only custom rule must not force continuation"
        );

        // An `agent.kind`-ONLY DSL rule is a dead rule `compile_rules` drops, so it
        // must NOT force continuation (it can never fire).
        let agent = make_dsl_rule(
            "agent",
            WhenClause::AgentKind("claude-code".into()),
            &["exec"],
        );
        assert!(
            !any_semantic_only_dsl_rules_for_context(&[agent], ScanContext::Exec),
            "an agent.kind-only DSL rule is dead and must not force continuation"
        );

        // A clause mixing a real predicate with a dead one inside `all:`. The
        // clause uses an unsupported predicate, so the helper returns FALSE (it
        // would be dropped by compile_rules anyway, keeping the gate in lockstep:
        // it never forces continuation for a rule that can't fire).
        let mixed = make_dsl_rule(
            "mixed",
            WhenClause::All(vec![
                WhenClause::CommandUsesSudo(true),
                WhenClause::AgentKind("claude-code".into()),
            ]),
            &["exec"],
        );
        assert!(
            !any_semantic_only_dsl_rules_for_context(&[mixed], ScanContext::Exec),
            "a clause containing an unsupported predicate is dropped by compile_rules, \
             so the gate must not force continuation for it"
        );

        // Empty rule set -> false (the common hot path).
        assert!(!any_semantic_only_dsl_rules_for_context(
            &[],
            ScanContext::Exec
        ));
    }

    /// CONTEXT-AWARENESS guard (CodeRabbit M13 PR #132). The SAME clause forces
    /// continuation ONLY in a context where the rule would actually RUN, i.e. the
    /// gate's per-rule decision matches the runtime contexts `compile_rules` clamps
    /// to (`declared` intersect `satisfiable`). A FILE-scoped `file.path_matches`
    /// rule must force continuation in FileScan but NOT in Exec/Paste (where
    /// `check_dsl` would never evaluate it), and a command rule declared `[exec]`
    /// must force in Exec but not Paste.
    #[test]
    fn test_any_semantic_only_dsl_rules_is_context_aware() {
        // A `file.path_matches` rule declared `[file]`. `compile_rules` clamps its
        // runtime contexts to {file}, so the gate must force only in FileScan.
        let file_rule = make_dsl_rule(
            "file-only",
            WhenClause::FilePathMatches(r"\.env$".into()),
            &["file"],
        );
        // Sanity: this is exactly what compile_rules stores as the rule's runtime
        // contexts, proving the gate reuses the same clamp helper. `parse_contexts`
        // turns the declared `["file"]` into `[FileScan]`, the same input
        // `compile_rules` feeds the clamp.
        assert_eq!(
            custom_rule_dsl::resolve_runtime_contexts(
                &parse_contexts(&file_rule),
                file_rule.when.as_ref().unwrap()
            ),
            vec![ScanContext::FileScan],
            "compile_rules clamps a [file] file.path_matches rule to FileScan only"
        );
        assert!(
            any_semantic_only_dsl_rules_for_context(
                std::slice::from_ref(&file_rule),
                ScanContext::FileScan
            ),
            "a [file] file.path_matches rule forces continuation in FileScan (it runs there)"
        );
        assert!(
            !any_semantic_only_dsl_rules_for_context(
                std::slice::from_ref(&file_rule),
                ScanContext::Exec
            ),
            "a [file] file.path_matches rule must NOT force continuation in Exec \
             (check_dsl never evaluates it there)"
        );
        assert!(
            !any_semantic_only_dsl_rules_for_context(
                std::slice::from_ref(&file_rule),
                ScanContext::Paste
            ),
            "a [file] file.path_matches rule must NOT force continuation in Paste"
        );

        // A `command.cwd_in` rule declared `[exec]` runs only in Exec.
        let cmd_exec = make_dsl_rule(
            "cwd-exec",
            WhenClause::CommandCwdIn(vec!["/tmp".to_string()]),
            &["exec"],
        );
        assert!(
            any_semantic_only_dsl_rules_for_context(
                std::slice::from_ref(&cmd_exec),
                ScanContext::Exec
            ),
            "an [exec] command.cwd_in rule forces continuation in Exec"
        );
        assert!(
            !any_semantic_only_dsl_rules_for_context(
                std::slice::from_ref(&cmd_exec),
                ScanContext::Paste
            ),
            "an [exec]-declared command.cwd_in rule must NOT force continuation in Paste \
             (it is not declared there)"
        );

        // A `command.cwd_in` rule declared `[exec, paste]` runs in BOTH.
        let cmd_both = make_dsl_rule(
            "cwd-both",
            WhenClause::CommandCwdIn(vec!["/tmp".to_string()]),
            &["exec", "paste"],
        );
        assert!(
            any_semantic_only_dsl_rules_for_context(
                std::slice::from_ref(&cmd_both),
                ScanContext::Exec
            ),
            "an [exec, paste] command.cwd_in rule forces continuation in Exec"
        );
        assert!(
            any_semantic_only_dsl_rules_for_context(
                std::slice::from_ref(&cmd_both),
                ScanContext::Paste
            ),
            "an [exec, paste] command.cwd_in rule forces continuation in Paste"
        );
    }

    #[test]
    fn test_clause_has_tier1_invisible_predicate() {
        use crate::custom_rule_dsl::Reputation;

        // Every REAL leaf reads tier-2/3 data the tier-1 fast gate cannot observe,
        // so each must be classified invisible (the engine forces past the
        // fast-exit for it).
        for leaf in [
            WhenClause::CommandUsesSudo(true),
            WhenClause::CommandHasPipelineTo(vec!["bash".into()]),
            WhenClause::CommandCwdIn(vec!["/tmp".into()]),
            WhenClause::UrlHost("example.com".into()),
            WhenClause::UrlHostMatches(".*".into()),
            WhenClause::UrlScheme("http".into()),
            WhenClause::UrlReputation(Reputation::Unknown),
            WhenClause::UrlDomainNotIn(vec!["company.com".into()]),
            WhenClause::PackageEcosystem("npm".into()),
            WhenClause::PackageNameMatches("^left-pad$".into()),
            WhenClause::PackageReputation(Reputation::Malicious),
            WhenClause::FilePathMatches(r"\.env$".into()),
        ] {
            assert!(
                clause_has_tier1_invisible_predicate(&leaf),
                "{} must be classified tier-1-invisible",
                leaf.key()
            );
        }

        // Dead predicates contribute nothing on their own (they can never fire, so
        // must NOT justify forcing past the fast-exit).
        assert!(!clause_has_tier1_invisible_predicate(
            &WhenClause::AgentKind("claude-code".into())
        ));
        assert!(!clause_has_tier1_invisible_predicate(&WhenClause::McpTool(
            "read_file".into()
        )));

        // Combinators: invisible if ANY child is.
        assert!(clause_has_tier1_invisible_predicate(&WhenClause::All(
            vec![
                WhenClause::AgentKind("claude-code".into()),
                WhenClause::CommandUsesSudo(true),
            ]
        )));
        assert!(clause_has_tier1_invisible_predicate(&WhenClause::Not(
            Box::new(WhenClause::FilePathMatches(r"\.env$".into()))
        )));
        // A combinator of ONLY dead predicates is not invisible.
        assert!(!clause_has_tier1_invisible_predicate(&WhenClause::Any(
            vec![
                WhenClause::AgentKind("a".into()),
                WhenClause::McpTool("b".into()),
            ]
        )));
        // Empty combinator: no real leaf -> not invisible.
        assert!(!clause_has_tier1_invisible_predicate(&WhenClause::All(
            vec![]
        )));
    }

    #[test]
    fn test_compile_dsl_rule_context_mismatch_skipped() {
        // command.* needs exec OR paste (round-3 R3-1), but the rule declares
        // only `file` — the FileScan path never extracts command facts, so the
        // predicate could never see its data and the rule is skipped.
        let rule = make_dsl_rule("mismatch", WhenClause::CommandUsesSudo(true), &["file"]);
        let compiled = compile_rules(&[rule]);
        assert_eq!(
            compiled.len(),
            0,
            "DSL rule needing exec/paste but declaring only file is skipped"
        );
    }

    #[test]
    fn test_compile_dsl_command_rule_paste_context_compiles() {
        // Regression (CodeRabbit M13 round-3 R3-1): a `command.*` rule declared
        // under `paste` must now COMPILE — `build_dsl_backing` fills command
        // facts for paste, so the predicate is live. The round-1/2 narrowing to
        // exec-only wrongly dropped it.
        let rule = make_dsl_rule("paste-cmd", WhenClause::CommandUsesSudo(true), &["paste"]);
        let compiled = compile_rules(&[rule]);
        assert_eq!(
            compiled.len(),
            1,
            "DSL command rule under paste must compile (round-3 R3-1)"
        );
        assert!(compiled[0].is_dsl());
    }

    #[test]
    fn test_compile_agent_kind_dsl_rule_is_skipped() {
        // CodeRabbit M13 round-8 R8-1: an `agent.kind` clause reads
        // `DslEvalContext::agent_kind`, which the engine hard-codes to `None`, so
        // the rule could never match. `compile_rules` must SKIP it (not pretend
        // to run a dead rule) — this replaced round-7's "context-agnostic clause
        // gets an executable set" behavior, since `agent.kind` was the only
        // empty-required predicate and it is now unsupported. Both an explicit
        // context and `context: []` are dropped alike.
        let with_ctx = make_dsl_rule(
            "agent-only-ctx",
            WhenClause::AgentKind("claude-code".into()),
            &["exec"],
        );
        let empty_ctx = make_dsl_rule(
            "agent-only-empty",
            WhenClause::AgentKind("claude-code".into()),
            &[],
        );
        assert_eq!(
            compile_rules(&[with_ctx]).len(),
            0,
            "agent.kind rule (with context) must be skipped — it can never match"
        );
        assert_eq!(
            compile_rules(&[empty_ctx]).len(),
            0,
            "agent.kind rule (empty context) must be skipped — it can never match"
        );
        // Buried inside an `all:` it must STILL be skipped.
        let nested = make_dsl_rule(
            "agent-nested",
            WhenClause::All(vec![
                WhenClause::CommandUsesSudo(true),
                WhenClause::AgentKind("claude-code".into()),
            ]),
            &["exec"],
        );
        assert_eq!(
            compile_rules(&[nested]).len(),
            0,
            "a clause containing agent.kind (even nested) must be skipped"
        );
    }

    #[test]
    fn test_compile_mcp_tool_dsl_rule_is_skipped() {
        // Companion to the agent.kind skip (R8-1) and the long-standing
        // `mcp.tool` rejection (round-3 R3-3): an `mcp.tool` clause is also an
        // unsupported predicate, so `compile_rules` must skip it rather than
        // compile a rule the engine can never fire.
        let rule = make_dsl_rule(
            "mcp-tool",
            WhenClause::McpTool("read_file".into()),
            &["file"],
        );
        assert_eq!(
            compile_rules(&[rule]).len(),
            0,
            "mcp.tool rule must be skipped — no scan context wires up the signal"
        );
    }

    #[test]
    fn test_compile_command_dsl_rule_empty_context_still_dropped() {
        // Coherence guard for R7-2: the executable-set fallback applies ONLY to
        // context-agnostic clauses. A `command.*` clause has a real required
        // trigger group ([exec, paste]); with `context: []` it cannot be
        // satisfied, so it must STILL be dropped (matching `rule validate`,
        // which rejects it).
        let rule = make_dsl_rule("cmd-no-ctx", WhenClause::CommandUsesSudo(true), &[]);
        let compiled = compile_rules(&[rule]);
        assert_eq!(
            compiled.len(),
            0,
            "command.* rule with empty context has unmet triggers and must be dropped"
        );
    }

    #[test]
    fn test_compile_all_command_and_file_is_dropped_as_unsatisfiable() {
        // CodeRabbit M13 round-9 R9-1: `all(command.*, file.*)` mixes facts from
        // contexts that never co-occur in a single scan, so the intersection of
        // its leaves' satisfiable sets is empty — the clause can never match.
        // `compile_rules` must DROP it even when BOTH contexts are declared
        // (the old leaf-flatten kept it for `[exec, file]`), matching `rule
        // validate`'s rejection.
        let rule = make_dsl_rule(
            "impossible-and",
            WhenClause::All(vec![
                WhenClause::CommandUsesSudo(true),
                WhenClause::FilePathMatches(r"\.env$".into()),
            ]),
            &["exec", "file"],
        );
        let compiled = compile_rules(&[rule]);
        assert_eq!(
            compiled.len(),
            0,
            "all(command, file) is unsatisfiable and must be dropped even with both contexts declared"
        );
    }

    #[test]
    fn test_compile_any_command_or_file_compiles_under_either_context() {
        // R9-1: `any(command.*, file.*)` is evaluable wherever EITHER branch is
        // (the union {exec, paste, file}), so it COMPILES under `[exec]` (command
        // branch) AND under `[file]` (file branch). The old leaf-flatten dropped
        // the `[exec]` case as "uncovered".
        for ctx in [&["exec"][..], &["file"][..]] {
            let rule = make_dsl_rule(
                "either-or",
                WhenClause::Any(vec![
                    WhenClause::CommandUsesSudo(true),
                    WhenClause::FilePathMatches(r"\.env$".into()),
                ]),
                ctx,
            );
            let compiled = compile_rules(&[rule]);
            assert_eq!(
                compiled.len(),
                1,
                "any(command, file) must compile under context {ctx:?} (R9-1)"
            );
            assert!(compiled[0].is_dsl());
        }
    }

    #[test]
    fn test_compile_clamps_union_any_to_declared_subset() {
        // The Any-union analogue of the not(file)-in-exec clamp
        // (`test_not_file_path_matches_no_false_positive_in_exec`): an
        // `any(command.*, file.*)` clause is satisfiable in {Exec, Paste,
        // FileScan} (the union of its branches), but `compile_rules` must clamp
        // the stored runtime contexts to `declared ∩ satisfiable`. So a rule
        // declared `[exec]` runs ONLY in Exec (not FileScan), and one declared
        // `[file]` runs ONLY in FileScan (not Exec) — even though the clause as a
        // whole is satisfiable in both.
        let make = |contexts: &[&str]| {
            make_dsl_rule(
                "any-clamp",
                WhenClause::Any(vec![
                    WhenClause::CommandUsesSudo(true),
                    WhenClause::FilePathMatches(r"\.env$".into()),
                ]),
                contexts,
            )
        };

        // Declared `[exec]`: clamps to {Exec}. The command branch is live in
        // Exec; the file branch's fact (file_path) is absent there but the union
        // still fires via the sudo branch. In FileScan the rule is clamped out.
        let exec_compiled = compile_rules(&[make(&["exec"])]);
        assert_eq!(exec_compiled.len(), 1, "any-union declared [exec] compiles");
        assert_eq!(
            exec_compiled[0].contexts,
            vec![ScanContext::Exec],
            "declared [exec] ∩ satisfiable {{exec, paste, file}} = {{exec}}"
        );
        let exec_ctx = DslEvalContext {
            uses_sudo: true,
            ..Default::default()
        };
        assert_eq!(
            check_dsl(&exec_ctx, ScanContext::Exec, &exec_compiled).len(),
            1,
            "any(command, file) declared [exec] must FIRE in Exec"
        );
        // Same backing, FileScan context: clamped out, so it must NOT fire even
        // though the file branch could be satisfiable in FileScan generally.
        let scan_env = DslEvalContext {
            file_path: Some("/repo/.env"),
            ..Default::default()
        };
        assert_eq!(
            check_dsl(&scan_env, ScanContext::FileScan, &exec_compiled).len(),
            0,
            "any(command, file) declared [exec] must be ABSENT in FileScan (clamped out)"
        );

        // Symmetric: declared `[file]` clamps to {FileScan}. Fires in FileScan
        // via the file branch; absent in Exec.
        let file_compiled = compile_rules(&[make(&["file"])]);
        assert_eq!(file_compiled.len(), 1, "any-union declared [file] compiles");
        assert_eq!(
            file_compiled[0].contexts,
            vec![ScanContext::FileScan],
            "declared [file] ∩ satisfiable {{exec, paste, file}} = {{file}}"
        );
        assert_eq!(
            check_dsl(&scan_env, ScanContext::FileScan, &file_compiled).len(),
            1,
            "any(command, file) declared [file] must FIRE in FileScan"
        );
        assert_eq!(
            check_dsl(&exec_ctx, ScanContext::Exec, &file_compiled).len(),
            0,
            "any(command, file) declared [file] must be ABSENT in Exec (clamped out)"
        );
    }

    #[test]
    fn test_compile_regex_rule_empty_context_dropped() {
        // Coherence guard for R7-2/R7-7: a REGEX rule with no valid contexts is
        // a dead rule (no required-trigger notion to synthesize a set from) and
        // must be dropped, matching `rule validate`.
        let rule = make_rule("regex-no-ctx", r"foo", &[]);
        let compiled = compile_rules(&[rule]);
        assert_eq!(
            compiled.len(),
            0,
            "regex rule with empty context must be dropped"
        );
    }

    #[test]
    fn test_compile_regex_rule_pattern_too_long_dropped() {
        // Coherence guard for R7-7: a regex `pattern` longer than the engine's
        // 1024-char cap is dropped by compile_rules, so `rule validate` must
        // flag it too.
        let long = "a".repeat(1025);
        let rule = make_rule("too-long", &long, &["exec"]);
        let compiled = compile_rules(&[rule]);
        assert_eq!(
            compiled.len(),
            0,
            "regex rule with pattern over the 1024-char cap must be dropped"
        );
    }

    #[test]
    fn test_compile_regex_pattern_cap_counts_chars_not_bytes() {
        // CodeRabbit M13 round-26: the 1024 cap (and its "{} chars" message) must
        // count CHARACTERS, not UTF-8 BYTES. A multibyte pattern that is <=1024
        // CHARS but >1024 BYTES used to hit the byte-length cap early and get
        // wrongly dropped; it must now be ACCEPTED.
        //
        // 'é' (U+00E9) is 2 bytes in UTF-8. 600 of them is 600 chars / 1200
        // bytes: well under the 1024-CHAR cap yet over a 1024-BYTE one. A
        // repeated literal is also a trivially-cheap, valid regex (keeps the
        // test fast — no pathological backtracking).
        let multibyte = "é".repeat(600);
        assert_eq!(multibyte.chars().count(), 600, "600 chars");
        assert!(multibyte.len() > 1024, "but >1024 bytes");
        let rule = make_rule("multibyte-ok", &multibyte, &["exec"]);
        let compiled = compile_rules(&[rule]);
        assert_eq!(
            compiled.len(),
            1,
            "a <=1024-CHAR pattern must be accepted even when its byte length exceeds 1024"
        );

        // And a pattern of >1024 CHARACTERS is still rejected (the cap holds; we
        // only changed how the input is measured). Use a single-byte char so the
        // rejection is unambiguously a CHAR-count, not a BYTE-count, trip.
        let over = "a".repeat(1025);
        assert_eq!(over.chars().count(), 1025, "1025 chars");
        let rule = make_rule("over-chars", &over, &["exec"]);
        assert_eq!(
            compile_rules(&[rule]).len(),
            0,
            "a >1024-CHAR pattern must be rejected by the char-count cap"
        );
    }

    #[test]
    fn test_check_dsl_fires_in_context() {
        let rule = make_dsl_rule("sudo-rule", WhenClause::CommandUsesSudo(true), &["exec"]);
        let compiled = compile_rules(&[rule]);

        let ctx = DslEvalContext {
            uses_sudo: true,
            ..Default::default()
        };
        let findings = check_dsl(&ctx, ScanContext::Exec, &compiled);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CustomRuleMatch);
        assert_eq!(findings[0].custom_rule_id.as_deref(), Some("sudo-rule"));

        // Wrong context -> no fire.
        let none = check_dsl(&ctx, ScanContext::Paste, &compiled);
        assert_eq!(none.len(), 0);
    }

    #[test]
    fn test_regex_check_ignores_dsl_rules() {
        let rule = make_dsl_rule("dsl-only", WhenClause::CommandUsesSudo(true), &["exec"]);
        let compiled = compile_rules(&[rule]);
        // The regex `check` path must never match a DSL rule.
        let findings = check("sudo anything", ScanContext::Exec, &compiled);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_compile_clamps_stored_contexts_to_satisfiable() {
        // CodeRabbit M13 round-15 custom.rs:172: `compile_rules` must STORE the
        // CLAMPED contexts (`declared ∩ satisfiable`), not the full declared set.
        // A `not(file.path_matches)` clause declared `context: [exec, file]` is
        // satisfiable only in FileScan ({file}); declaring [exec, file] must
        // resolve the stored runtime contexts to [file] alone.
        let rule = make_dsl_rule(
            "not-file",
            WhenClause::Not(Box::new(WhenClause::FilePathMatches(r"\.env$".into()))),
            &["exec", "file"],
        );
        let compiled = compile_rules(&[rule]);
        assert_eq!(compiled.len(), 1, "rule is satisfiable in file and kept");
        assert_eq!(
            compiled[0].contexts,
            vec![ScanContext::FileScan],
            "stored contexts must be clamped to declared ∩ satisfiable = {{file}}, not [exec, file]"
        );
    }

    #[test]
    fn test_not_file_path_matches_no_false_positive_in_exec() {
        // CodeRabbit M13 round-15 custom.rs:172 (the bug it guards): with the full
        // declared set stored, `not(file.path_matches)` declared `[exec, file]`
        // would run in the exec context — where `file_path` is `None`, so
        // `file.path_matches` is `false` and `not` flips it to `true` → a FALSE
        // POSITIVE. After the clamp the rule only runs in FileScan, so:
        //   * exec  (file_path absent) → does NOT fire (context clamped out).
        //   * FileScan with a NON-matching path → FIRES (inner false → not true).
        //   * FileScan with a MATCHING `.env` path → does NOT fire (inner true).
        let rule = make_dsl_rule(
            "not-env",
            WhenClause::Not(Box::new(WhenClause::FilePathMatches(r"\.env$".into()))),
            &["exec", "file"],
        );
        let compiled = compile_rules(&[rule]);

        // Exec context: the engine would build a backing with NO file path.
        // Before the fix this fired (false positive); after the clamp the exec
        // context is not a runtime context for this rule, so it is skipped.
        let exec_ctx = DslEvalContext {
            file_path: None,
            ..Default::default()
        };
        assert_eq!(
            check_dsl(&exec_ctx, ScanContext::Exec, &compiled).len(),
            0,
            "not(file.path_matches) must NOT fire in the exec context (file_path absent)"
        );

        // FileScan with a NON-`.env` path: `file.path_matches` is false, so
        // `not` is true and the rule legitimately FIRES (the clause works in the
        // context where its fact is populated).
        let scan_other = DslEvalContext {
            file_path: Some("/repo/src/main.rs"),
            ..Default::default()
        };
        assert_eq!(
            check_dsl(&scan_other, ScanContext::FileScan, &compiled).len(),
            1,
            "not(file.path_matches \\.env$) must FIRE in FileScan for a non-.env path"
        );

        // FileScan with a `.env` path: `file.path_matches` is true, `not` false,
        // so the rule does NOT fire — the clause still evaluates correctly.
        let scan_env = DslEvalContext {
            file_path: Some("/repo/.env"),
            ..Default::default()
        };
        assert_eq!(
            check_dsl(&scan_env, ScanContext::FileScan, &compiled).len(),
            0,
            "not(file.path_matches \\.env$) must NOT fire in FileScan for a .env path"
        );
    }
}
