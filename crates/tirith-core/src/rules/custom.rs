use regex::Regex;

use crate::custom_rule_dsl::{self, DslEvalContext, WhenClause};
use crate::extract::ScanContext;
use crate::policy::CustomRule;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// The matcher half of a compiled custom rule: a regex or a `when:` clause
/// (M13 ch4 DSL). A rule carries exactly one.
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
/// pattern over the 1024-char cap, no valid contexts, an unsupported DSL
/// predicate, or DSL triggers not covered by the declared `context:`) are
/// logged and skipped to keep the hot path fail-open. `tirith rule validate`
/// mirrors these drops exactly with a non-zero exit.
///
/// A DSL clause using `agent.kind` / `mcp.tool` is skipped (CodeRabbit M13
/// round-8 R8-1): those read a `DslEvalContext` field the engine hard-codes to
/// `None`, so the rule could never match. A DSL rule resolving to no usable
/// context is likewise dropped as dead.
pub fn compile_rules(rules: &[CustomRule]) -> Vec<CompiledCustomRule> {
    let mut compiled = Vec::new();
    for rule in rules {
        if let Err(e) = rule.validate_shape() {
            eprintln!("tirith: warning: custom rule '{}' {e}, skipping", rule.id);
            continue;
        }

        let declared = parse_contexts(rule);

        // Resolve the executable context set and the compiled matcher together;
        // a rule resolving to no usable context is dropped as dead in each arm.
        let (contexts, matcher) = if let Some(pattern) = &rule.pattern {
            // Regex rule: needs a declared context (no required-trigger notion).
            if declared.is_empty() {
                eprintln!(
                    "tirith: warning: custom rule '{}' has no valid contexts, skipping",
                    rule.id
                );
                continue;
            }
            // Cap in CHARACTERS, not bytes, so a multibyte pattern isn't dropped
            // early (CodeRabbit M13 round-26); `check_regex` uses the same cap.
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
            // Validate inner regexes up front so a bad one is a skip, not a
            // per-input recompile failure.
            if let Err(e) = custom_rule_dsl::validate_regexes(when) {
                eprintln!(
                    "tirith: warning: custom rule '{}' has invalid when-clause: {e}",
                    rule.id
                );
                continue;
            }
            // Skip an unsupported-predicate clause (`agent.kind` / `mcp.tool`):
            // their backing field is hard-coded `None`, so the rule can never
            // match (CodeRabbit M13 round-8 R8-1). Done before the satisfiability
            // check so it isn't misreported as "unsatisfiable".
            if let Some(reason) = custom_rule_dsl::clause_uses_unsupported_predicate(when) {
                eprintln!(
                    "tirith: warning: custom rule '{}' {reason}, skipping",
                    rule.id
                );
                continue;
            }
            // Per-clause satisfiability + coverage (CodeRabbit M13 round-9 R9-1).
            // `satisfiable_contexts` is where the WHOLE clause can evaluate (`all`
            // intersects, `any` unions, `not` is the child's set). An empty set
            // means it mixes contexts that never co-occur (e.g. command + file) —
            // drop it as a dead rule; both validators reject it.
            let satisfiable = custom_rule_dsl::satisfiable_contexts(when);
            if satisfiable.is_empty() {
                eprintln!(
                    "tirith: warning: custom rule '{}' when-clause needs facts from contexts that never co-occur in a single scan (e.g. command + file), skipping",
                    rule.id
                );
                continue;
            }
            // Store the RUNTIME contexts (`declared ∩ satisfiable`), NOT the full
            // declared set (CodeRabbit M13 round-15 custom.rs:172). Storing the
            // full set let `check_dsl` evaluate a clause where its facts are absent
            // — e.g. `not(file.path_matches)` declared `[exec, file]` ran in Exec
            // (file_path `None` → inner false → `not` true → FALSE POSITIVE). The
            // clamp ensures the clause only runs where every fact it reads exists;
            // an empty resolved set is dropped, matching both validators.
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

/// Build a [`Finding`] for a matched custom rule; `match_detail` is the
/// rule-specific evidence line.
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

/// Check input against compiled REGEX custom rules for a given context. DSL
/// (`when:`) rules are evaluated separately by [`check_dsl`].
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
/// data for a given context. A finding fires (reusing
/// [`RuleId::CustomRuleMatch`]) when the clause matches and `context` is in the
/// rule's contexts. Regex rules are skipped here (see [`check`]).
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

/// `true` when any compiled rule is a DSL (`when:`) rule, so the engine can skip
/// building a [`DslEvalContext`] on the regex-only path.
pub fn any_dsl_rules(compiled: &[CompiledCustomRule]) -> bool {
    compiled.iter().any(|r| r.is_dsl())
}

/// `true` when, for scan context `ctx`, the policy carries a DSL rule that (a)
/// would compile (no unsupported predicate), (b) keys on a SEMANTIC fact the
/// tier-1 fast gate cannot observe
/// ([`custom_rule_dsl::clause_has_tier1_invisible_predicate`]), and (c) would
/// actually run in `ctx` (`ctx` in `declared ∩ satisfiable`, the same clamp
/// `compile_rules` stores).
///
/// # The tier-1 gating bug this prevents (see CLAUDE.md)
///
/// The engine's tier-1 fast-exit returns "allow" when no regex/byte signal
/// fired. A DSL rule keying only on `command.uses_sudo`, `command.cwd_in`,
/// `package.*`, `url.*`, … would then be silently skipped on input it should
/// match (e.g. a bare `sudo whoami`) — the dotfile-overwrite bug class for DSL
/// rules. The engine calls this before the fast-exit and forces past it on
/// `true` so [`check_dsl`] runs.
///
/// CONTEXT-AWARE (CodeRabbit M13 PR #132): forcing only buys anything where the
/// rule can fire. A `[file]`-scoped rule clamps to `{file}`, so a context-agnostic
/// gate would wrongly force every Exec/Paste command. Restricting to `ctx ∈`
/// resolved runtime contexts keeps the gate in lockstep with compile-time
/// dropping.
///
/// Runs on the sub-millisecond hot path: an O(rules) scan over the raw
/// [`CustomRule`]s that compiles no regex and builds no [`DslEvalContext`],
/// short-circuiting on the first forcing rule. Operating on raw rules + reusing
/// [`parse_contexts`] / [`custom_rule_dsl::resolve_runtime_contexts`] keeps it in
/// lockstep with `compile_rules`.
pub fn any_semantic_only_dsl_rules_for_context(rules: &[CustomRule], ctx: ScanContext) -> bool {
    rules.iter().any(|rule| match &rule.when {
        Some(clause) => {
            // (a) compiles, (b) keys on a tier-1-invisible fact, (c) runs in
            // `ctx` — via the same clamp `compile_rules` uses. Cheapest-first;
            // the clamp is last so a dead/tier-1-visible rule skips it.
            custom_rule_dsl::clause_uses_unsupported_predicate(clause).is_none()
                && clause_has_tier1_invisible_predicate(clause)
                && custom_rule_dsl::resolve_runtime_contexts(&parse_contexts(rule), clause)
                    .contains(&ctx)
        }
        None => false,
    })
}

/// `true` when a clause references at least one leaf predicate whose backing
/// fact the tier-1 fast gate cannot observe (needs tier-2 extraction or tier-3
/// state), so the engine must run the rules rather than fast-exit.
///
/// Tier-1 gating bug class (see CLAUDE.md): the fast-exit returns "allow" when no
/// regex/byte signal fired, so a DSL rule keying only on semantic facts
/// (`command.*`, `url.*`, `package.*`) would be skipped on input it should match.
/// Consulted (via [`any_semantic_only_dsl_rules`]) to force past the fast-exit,
/// like taint/canary/exec-guard do.
///
/// Every real leaf is treated as invisible — none of their facts are guaranteed
/// to coincide with a tier-1 trigger: `command.*` needs tokenizing (tier-2),
/// `url.*` / `package.*` read extracted data (tier-2), `file.path_matches` reads
/// the FileScan path (which never fast-exits anyway). `agent.kind` / `mcp.tool`
/// are dead (never compiled), so alone they contribute nothing; a combinator is
/// invisible if ANY child is. Errs toward `true` (correctness over micro-opt).
fn clause_has_tier1_invisible_predicate(clause: &WhenClause) -> bool {
    match clause {
        // Combinators: invisible if ANY child is.
        WhenClause::All(cs) | WhenClause::Any(cs) => {
            cs.iter().any(clause_has_tier1_invisible_predicate)
        }
        WhenClause::Not(c) => clause_has_tier1_invisible_predicate(c),

        // Dead predicates — never compiled, so they don't force continuation.
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
        // Tier-1 gating guard (CodeRabbit M13 PR #132): fixes context to Exec and
        // varies the clause (the context-aware case is a separate test).

        // command.uses_sudo declared [exec] is tier-1-invisible and runs in Exec.
        let sudo = make_dsl_rule("sudo", WhenClause::CommandUsesSudo(true), &["exec"]);
        assert!(
            any_semantic_only_dsl_rules_for_context(&[sudo], ScanContext::Exec),
            "a command.uses_sudo DSL rule is semantic-only and must force continuation in Exec"
        );

        // file.path_matches declared [file] runs in FileScan.
        let file_rule = make_dsl_rule(
            "file",
            WhenClause::FilePathMatches(r"\.env$".into()),
            &["file"],
        );
        assert!(
            any_semantic_only_dsl_rules_for_context(&[file_rule], ScanContext::FileScan),
            "a file.path_matches DSL rule is semantic-only and runs in FileScan"
        );

        // A regex rule (no `when:`) is not a DSL rule -> false.
        let regex = make_rule("regex", r"internal\.corp", &["exec"]);
        assert!(
            !any_semantic_only_dsl_rules_for_context(&[regex], ScanContext::Exec),
            "a regex-only custom rule must not force continuation"
        );

        // An agent.kind-only DSL rule is dead (dropped by compile_rules) -> false.
        let agent = make_dsl_rule(
            "agent",
            WhenClause::AgentKind("claude-code".into()),
            &["exec"],
        );
        assert!(
            !any_semantic_only_dsl_rules_for_context(&[agent], ScanContext::Exec),
            "an agent.kind-only DSL rule is dead and must not force continuation"
        );

        // A real + dead predicate in `all:` uses an unsupported predicate, so
        // the helper returns false (compile_rules would drop it anyway).
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

        // Empty rule set -> false.
        assert!(!any_semantic_only_dsl_rules_for_context(
            &[],
            ScanContext::Exec
        ));
    }

    /// CONTEXT-AWARENESS guard (CodeRabbit M13 PR #132): the same clause forces
    /// continuation only where the rule would run (`declared ∩ satisfiable`). A
    /// `[file]` rule forces in FileScan but not Exec/Paste; an `[exec]` command
    /// rule forces in Exec but not Paste.
    #[test]
    fn test_any_semantic_only_dsl_rules_is_context_aware() {
        // [file] file.path_matches clamps to {file}: force only in FileScan.
        let file_rule = make_dsl_rule(
            "file-only",
            WhenClause::FilePathMatches(r"\.env$".into()),
            &["file"],
        );
        // Sanity: matches what compile_rules stores (same clamp helper).
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

        // [exec] command.cwd_in runs only in Exec.
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

        // [exec, paste] command.cwd_in runs in both.
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

        // Every real leaf reads tier-2/3 data, so each is classified invisible.
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

        // Dead predicates contribute nothing on their own.
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
        // command.* needs exec/paste (round-3 R3-1); declaring only `file` means
        // the predicate never sees its data, so the rule is skipped.
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
        // Regression (CodeRabbit M13 round-3 R3-1): a `command.*` rule under
        // `paste` must compile — paste fills command facts, so it's live.
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
        // CodeRabbit M13 round-8 R8-1: an `agent.kind` clause reads a field the
        // engine hard-codes to `None`, so it can never match — `compile_rules`
        // skips it. Both an explicit context and `context: []` are dropped.
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
        // Buried inside an `all:` it must still be skipped.
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
        // Companion to the agent.kind skip (R8-1 / round-3 R3-3): `mcp.tool` is
        // also unsupported, so compile_rules skips it.
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
        // Coherence guard for R7-2: a `command.*` clause with `context: []` has
        // unmet triggers and must still be dropped (matching `rule validate`).
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
        // CodeRabbit M13 round-9 R9-1: `all(command.*, file.*)` mixes contexts
        // that never co-occur (empty intersection), so it can never match and is
        // dropped even with both contexts declared.
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
        // R9-1: `any(command.*, file.*)` is evaluable wherever either branch is
        // (union {exec, paste, file}), so it compiles under [exec] and [file].
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
        // Any-union analogue of the not(file)-in-exec clamp: `any(command.*,
        // file.*)` is satisfiable in {Exec, Paste, FileScan}, but compile_rules
        // clamps stored contexts to `declared ∩ satisfiable` — so [exec] runs
        // only in Exec and [file] only in FileScan.
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

        // Declared [exec]: clamps to {Exec}; fires via the sudo branch.
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
        // Same backing, FileScan context: clamped out, so it must not fire.
        let scan_env = DslEvalContext {
            file_path: Some("/repo/.env"),
            ..Default::default()
        };
        assert_eq!(
            check_dsl(&scan_env, ScanContext::FileScan, &exec_compiled).len(),
            0,
            "any(command, file) declared [exec] must be ABSENT in FileScan (clamped out)"
        );

        // Symmetric: [file] clamps to {FileScan}; fires there, absent in Exec.
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
        // R7-2/R7-7: a regex rule with no valid contexts is dead and dropped.
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
        // R7-7: a regex pattern over the 1024-char cap is dropped.
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
        // CodeRabbit M13 round-26: the 1024 cap counts CHARACTERS, not bytes.
        // 'é' is 2 bytes; 600 of them = 600 chars / 1200 bytes — under the char
        // cap but over a byte cap, so it must be accepted.
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

        // A >1024-CHAR pattern (single-byte char) is still rejected.
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
        // CodeRabbit M13 round-15 custom.rs:172: compile_rules stores the clamped
        // contexts. `not(file.path_matches)` declared `[exec, file]` is
        // satisfiable only in FileScan, so the stored set is [file] alone.
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
        // CodeRabbit M13 round-15 custom.rs:172 (the bug guarded): without the
        // clamp, `not(file.path_matches)` declared `[exec, file]` ran in Exec
        // where file_path is `None` → inner false → `not` true → false positive.
        // After the clamp: Exec doesn't fire (clamped out); FileScan fires for a
        // non-.env path and doesn't for a .env path.
        let rule = make_dsl_rule(
            "not-env",
            WhenClause::Not(Box::new(WhenClause::FilePathMatches(r"\.env$".into()))),
            &["exec", "file"],
        );
        let compiled = compile_rules(&[rule]);

        // Exec context (no file path): clamped out, so skipped.
        let exec_ctx = DslEvalContext {
            file_path: None,
            ..Default::default()
        };
        assert_eq!(
            check_dsl(&exec_ctx, ScanContext::Exec, &compiled).len(),
            0,
            "not(file.path_matches) must NOT fire in the exec context (file_path absent)"
        );

        // FileScan, non-.env path: inner false → `not` true → fires.
        let scan_other = DslEvalContext {
            file_path: Some("/repo/src/main.rs"),
            ..Default::default()
        };
        assert_eq!(
            check_dsl(&scan_other, ScanContext::FileScan, &compiled).len(),
            1,
            "not(file.path_matches \\.env$) must FIRE in FileScan for a non-.env path"
        );

        // FileScan, .env path: inner true → `not` false → does not fire.
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
