//! Policy YAML validation — syntax, schema, and conflict checks.
//!
//! Separate from `policy.rs` (which handles loading and runtime matching).
//! Used by `tirith policy validate`.

use crate::verdict::{RuleId, Severity};

/// A single validation issue found in a policy file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyIssue {
    pub level: IssueLevel,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IssueLevel {
    Error,
    Warning,
}

impl std::fmt::Display for IssueLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssueLevel::Error => write!(f, "error"),
            IssueLevel::Warning => write!(f, "warning"),
        }
    }
}

/// Validate a policy YAML string. Returns a list of issues (empty = valid).
pub fn validate(yaml: &str) -> Vec<PolicyIssue> {
    let mut issues = Vec::new();

    // Use the runtime's parse → migrate/version-gate → deserialize pipeline.
    // Runtime-only invariants (notably custom-rule shape) remain below so this
    // validator can emit their focused field diagnostics.
    let crate::policy::ParsedPolicyDocument { migrated, policy } =
        match crate::policy::Policy::parse_document(yaml) {
            Ok(document) => document,
            Err(error) => {
                issues.push(policy_document_error_issue(error));
                return issues;
            }
        };

    validate_paranoia(&policy, &mut issues);
    validate_severity_overrides(&policy, &mut issues);
    validate_allowlist_blocklist_overlap(&policy, &mut issues);
    validate_custom_rules(&policy, &mut issues);
    validate_injection_seeds(&policy, &mut issues);
    validate_approval_rules(&policy, &mut issues);
    validate_fail_mode_fields(&policy, &mut issues);
    validate_scan_config(&policy, &mut issues);
    validate_network_entries(&policy, &mut issues);
    validate_action_overrides(&policy, &mut issues);
    validate_escalation_rules(&policy, &mut issues);
    validate_agent_rules(&policy, &mut issues);
    validate_package_policy(&policy, &mut issues);

    validate_schema_unknown_fields(&migrated, &mut issues);

    issues
}

fn policy_document_error_issue(error: crate::policy::PolicyDocumentError) -> PolicyIssue {
    match error {
        crate::policy::PolicyDocumentError::Yaml(error)
        | crate::policy::PolicyDocumentError::Deserialize(error) => PolicyIssue {
            level: IssueLevel::Error,
            message: format!("YAML parse error: {error}"),
            field: None,
        },
        crate::policy::PolicyDocumentError::Migration(error) => PolicyIssue {
            level: IssueLevel::Error,
            message: format!("Policy migration error: {error}"),
            field: Some("schema_version".to_string()),
        },
    }
}

fn validate_schema_unknown_fields(migrated: &serde_yaml::Value, issues: &mut Vec<PolicyIssue>) {
    let fields = match crate::policy_ignored::collect(migrated.clone()) {
        Ok(fields) => fields,
        Err(error) => {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!("policy schema inspection error: {error}"),
                field: None,
            });
            return;
        }
    };

    for field in fields {
        issues.push(PolicyIssue {
            level: IssueLevel::Warning,
            message: format!("unknown field '{field}'"),
            field: Some(field),
        });
    }
}

fn validate_paranoia(policy: &crate::policy::Policy, issues: &mut Vec<PolicyIssue>) {
    if policy.paranoia == 0 || policy.paranoia > 4 {
        issues.push(PolicyIssue {
            level: IssueLevel::Error,
            message: format!("paranoia must be 1-4, got {}", policy.paranoia),
            field: Some("paranoia".into()),
        });
    }
}

fn validate_severity_overrides(policy: &crate::policy::Policy, issues: &mut Vec<PolicyIssue>) {
    for key in policy.severity_overrides.keys() {
        let parsed: Result<RuleId, _> =
            serde_json::from_value(serde_json::Value::String(key.clone()));
        if parsed.is_err() {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!("severity_overrides: unknown rule ID '{key}'"),
                field: Some(format!("severity_overrides.{key}")),
            });
        }
    }
}

fn validate_allowlist_blocklist_overlap(
    policy: &crate::policy::Policy,
    issues: &mut Vec<PolicyIssue>,
) {
    for allow in &policy.allowlist {
        let allow_lower = allow.to_lowercase();
        for block in &policy.blocklist {
            if block.to_lowercase() == allow_lower {
                issues.push(PolicyIssue {
                    level: IssueLevel::Warning,
                    message: format!(
                        "pattern '{allow}' appears in both allowlist and blocklist \
                         (blocklist takes precedence)"
                    ),
                    field: Some("allowlist/blocklist".into()),
                });
            }
        }
    }
}

fn validate_custom_rules(policy: &crate::policy::Policy, issues: &mut Vec<PolicyIssue>) {
    let mut seen_ids = std::collections::HashSet::new();
    for rule in &policy.custom_rules {
        if !seen_ids.insert(&rule.id) {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!("custom_rules: duplicate id '{}'", rule.id),
                field: Some(format!("custom_rules.{}", rule.id)),
            });
        }

        // Exactly-one-of pattern/when (M13 ch4 DSL).
        if let Err(e) = rule.validate_shape() {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!("custom_rules.{}: {e}", rule.id),
                field: Some(format!("custom_rules.{}", rule.id)),
            });
        }

        // Validate contexts BEFORE the regex checks so `has_invalid_context` is
        // set and the empty-context check can skip a bogus-only list (avoids
        // double-reporting — same discipline as `rule validate`).
        let valid_contexts = ["exec", "paste", "file"];
        let mut has_invalid_context = false;
        for ctx in &rule.context {
            if !valid_contexts.contains(&ctx.as_str()) {
                has_invalid_context = true;
                issues.push(PolicyIssue {
                    level: IssueLevel::Error,
                    message: format!(
                        "custom_rules.{}: invalid context '{}' (valid: exec, paste, file)",
                        rule.id, ctx
                    ),
                    field: Some(format!("custom_rules.{}.context", rule.id)),
                });
            }
        }

        // Validate a REGEX rule by mirroring `compile_rules` EXACTLY in the SAME
        // ORDER, so `policy validate` never green-lights a rule the engine
        // silently DROPS (CodeRabbit M13). Drop order: (1) no valid contexts,
        // (2) pattern over the 1024-CHAR cap, (3) invalid regex.
        if let Some(pattern) = &rule.pattern {
            // (1) No valid contexts ⇒ dead rule. Skip when a token was invalid
            //     (reported above; avoids double-report).
            let parsed = parse_declared_contexts(&rule.context);
            if parsed.is_empty() {
                if !has_invalid_context {
                    issues.push(PolicyIssue {
                        level: IssueLevel::Error,
                        message: format!(
                            "custom_rules.{}: no valid contexts (regex rule needs at least one of: exec, paste, file)",
                            rule.id
                        ),
                        field: Some(format!("custom_rules.{}.context", rule.id)),
                    });
                }
                // No runnable contexts ⇒ engine drops the rule; skip the length +
                // regex checks (they'd redundantly error a rule that can't run).
                continue;
            }
            // (2) Length cap in CHARACTERS not BYTES (round-26: a multibyte
            //     pattern must not trip early). Round-28: the `else if`
            //     short-circuits `Regex::new` on cap failure — `compile_rules`
            //     also never compiles past the cap (avoids wasted work + a
            //     redundant second issue).
            let pattern_chars = pattern.chars().count();
            if pattern_chars > 1024 {
                issues.push(PolicyIssue {
                    level: IssueLevel::Error,
                    message: format!(
                        "custom_rules.{}: pattern too long ({pattern_chars} chars, max 1024)",
                        rule.id
                    ),
                    field: Some(format!("custom_rules.{}.pattern", rule.id)),
                });
            } else if let Err(e) = regex::Regex::new(pattern) {
                // (3) Regex must compile. LAST (after the cap), matching `compile_rules`.
                issues.push(PolicyIssue {
                    level: IssueLevel::Error,
                    message: format!("custom_rules.{}: invalid regex '{}': {e}", rule.id, pattern),
                    field: Some(format!("custom_rules.{}.pattern", rule.id)),
                });
            }
        }

        // Validate the `when:` clause (DSL): inner regexes compile and the
        // declared context covers the clause's required trigger groups (tier-1
        // invariant — predicates need their data extracted).
        if let Some(when) = &rule.when {
            if let Err(e) = crate::custom_rule_dsl::validate_regexes(when) {
                issues.push(PolicyIssue {
                    level: IssueLevel::Error,
                    message: format!("custom_rules.{}: invalid when-clause: {e}", rule.id),
                    field: Some(format!("custom_rules.{}.when", rule.id)),
                });
            }
            // Reject predicates no scan context can satisfy — `mcp.tool` (round-3
            // R3-3) and `agent.kind` (round-8 R8-1; use `agent_rules` instead);
            // neither signal is wired in. Done FIRST so such a clause never
            // reaches the (empty-set) satisfiable check below.
            let unsupported = crate::custom_rule_dsl::clause_uses_unsupported_predicate(when);
            if let Some(reason) = unsupported {
                issues.push(PolicyIssue {
                    level: IssueLevel::Error,
                    message: format!("custom_rules.{}: {reason}", rule.id),
                    field: Some(format!("custom_rules.{}.when", rule.id)),
                });
            }
            // Per-clause satisfiability + coverage (round-9 R9-1).
            // `satisfiable_contexts` = contexts where the WHOLE clause evaluates
            // (`all` intersects, `any` unions, `not` passes through). Two failures:
            //   (1) Empty satisfiable set ⇒ needs facts from contexts that never
            //       co-occur (e.g. command + file via `all`) — can never match.
            //       Skip when an unsupported predicate was used (reported above).
            //   (2) Else the declared context must intersect the satisfiable set;
            //       an empty `context: []` has no intersection (finding D). Skip
            //       when a context token was invalid (reported above).
            let satisfiable = crate::custom_rule_dsl::satisfiable_contexts(when);
            if unsupported.is_none() && satisfiable.is_empty() {
                issues.push(PolicyIssue {
                    level: IssueLevel::Error,
                    message: format!(
                        "custom_rules.{}: when-clause needs facts from contexts that never \
                         co-occur in a single scan (e.g. command + file) — it can never match",
                        rule.id
                    ),
                    field: Some(format!("custom_rules.{}.when", rule.id)),
                });
            } else if unsupported.is_none() && !has_invalid_context {
                // Route through the SAME `resolve_runtime_contexts` (= `declared ∩
                // satisfiable`) the engine and `rule validate` use, so all three
                // classify identically (round-15). An OMITTED `context:` carries
                // serde's `[exec, paste]` default, so a no-context `command.*`
                // rule is ACCEPTED but a no-context `file.*` rule is REJECTED
                // (`{exec,paste} ∩ {file}` = ∅); an explicit `context: []` also
                // resolves empty and is rejected (finding D).
                let declared = parse_declared_contexts(&rule.context);
                if crate::custom_rule_dsl::resolve_runtime_contexts(&declared, when).is_empty() {
                    issues.push(PolicyIssue {
                        level: IssueLevel::Error,
                        message: format!(
                            "custom_rules.{}: when-clause can only be evaluated in context [{}], not covered by declared context {:?}",
                            rule.id,
                            satisfiable.describe(),
                            rule.context
                        ),
                        field: Some(format!("custom_rules.{}.when", rule.id)),
                    });
                }
            }
        }
    }
}

/// Validate `injection_seeds_custom` entries (C5). Each entry is a prompt-injection
/// seed regex layered on top of the built-in corpus via `compile_seeds`. Error on an
/// empty pattern, a pattern over the 1024-CHAR cap, or one that fails to compile.
/// The compile check routes through `prompt_injection::validate_seed_pattern`, which
/// runs the EXACT `substitute_placeholders` + case-insensitive build that
/// `compile_seeds` uses — so `policy validate` can never green-light a seed the
/// engine then silently DROPS (the validate/compile divergence). Bad seeds are
/// SKIPPED at compile time (not a hard load error, see `policy.rs::try_parse_yaml`),
/// so this lenient `policy validate` path is where the operator is told about them.
/// A blank/`#`-comment line is a deliberate skip in `compile_seeds`, so it is not
/// flagged here either.
fn validate_injection_seeds(policy: &crate::policy::Policy, issues: &mut Vec<PolicyIssue>) {
    for (i, pattern) in policy.injection_seeds_custom.iter().enumerate() {
        let trimmed = pattern.trim();
        // Blank / comment lines are intentionally ignored by `compile_seeds`; do not
        // flag them. A pattern that is non-blank but whitespace-padded is validated
        // on its trimmed form (that is what `compile_seeds` compiles).
        if trimmed.is_empty() {
            if pattern.is_empty() {
                issues.push(PolicyIssue {
                    level: IssueLevel::Error,
                    message: format!("injection_seeds_custom[{i}]: empty seed pattern"),
                    field: Some(format!("injection_seeds_custom[{i}]")),
                });
            }
            continue;
        }
        if trimmed.starts_with('#') {
            continue;
        }
        // Length cap in CHARACTERS not BYTES, mirroring the custom-rule pattern cap.
        let pattern_chars = trimmed.chars().count();
        if pattern_chars > 1024 {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!(
                    "injection_seeds_custom[{i}]: seed too long ({pattern_chars} chars, max 1024)"
                ),
                field: Some(format!("injection_seeds_custom[{i}]")),
            });
        } else if crate::rules::prompt_injection::validate_seed_pattern(trimmed).is_err() {
            // Regex must compile (checked last, after the cap, like custom rules).
            // Use the SAME compile path `compile_seeds` uses (placeholder
            // substitution + case-insensitive build), NOT a raw `Regex::new`, so a
            // pattern that passes here can never be silently dropped at runtime.
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                // The regex compiler's Display text can echo the raw policy
                // pattern. Keep validation categorical/indexed just like the
                // runtime CLI/MCP warning boundary.
                message: format!(
                    "injection_seeds_custom[{i}]: invalid regex rejected by runtime compiler"
                ),
                field: Some(format!("injection_seeds_custom[{i}]")),
            });
        }
    }
}

/// Parse the declared `context:` strings into [`crate::extract::ScanContext`]s,
/// dropping unknown tokens (those are reported separately as their own issue).
fn parse_declared_contexts(context: &[String]) -> Vec<crate::extract::ScanContext> {
    use crate::extract::ScanContext;
    context
        .iter()
        .filter_map(|c| match c.as_str() {
            "exec" => Some(ScanContext::Exec),
            "paste" => Some(ScanContext::Paste),
            "file" => Some(ScanContext::FileScan),
            _ => None,
        })
        .collect()
}

fn validate_approval_rules(policy: &crate::policy::Policy, issues: &mut Vec<PolicyIssue>) {
    for (i, rule) in policy.approval_rules.iter().enumerate() {
        for rule_id_str in &rule.rule_ids {
            let parsed: Result<RuleId, _> =
                serde_json::from_value(serde_json::Value::String(rule_id_str.clone()));
            if parsed.is_err() {
                issues.push(PolicyIssue {
                    level: IssueLevel::Error,
                    message: format!("approval_rules[{i}]: unknown rule ID '{rule_id_str}'"),
                    field: Some(format!("approval_rules[{i}].rule_ids")),
                });
            }
        }

        let valid_fallbacks = ["block", "warn", "allow"];
        if !valid_fallbacks.contains(&rule.fallback.as_str()) {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!(
                    "approval_rules[{i}]: invalid fallback '{}' (valid: block, warn, allow)",
                    rule.fallback
                ),
                field: Some(format!("approval_rules[{i}].fallback")),
            });
        }
    }
}

/// M6 ch7 — range checks for the `package_policy` section.
fn validate_package_policy(policy: &crate::policy::Policy, issues: &mut Vec<PolicyIssue>) {
    let pp = &policy.package_policy;

    // CVSS must be in [0, 10]
    if let Some(cvss) = pp.block_osv_min_cvss {
        if !cvss.is_finite() || !(0.0..=10.0).contains(&cvss) {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!(
                    "package_policy.block_osv_min_cvss: must be in [0.0, 10.0], got {cvss}"
                ),
                field: Some("package_policy.block_osv_min_cvss".into()),
            });
        }
    }

    // Zero is meaningful for the block threshold: it blocks packages first
    // published today while allowing older packages to fall through to the
    // warning threshold. `None`, not zero, disables blocking by age.
    if let Some(d) = pp.warn_newer_than_days {
        if d == 0 {
            issues.push(PolicyIssue {
                level: IssueLevel::Warning,
                message: "package_policy.warn_newer_than_days: 0 only warns for packages \
                          published today; omit the field to retain the 30-day baseline"
                    .into(),
                field: Some("package_policy.warn_newer_than_days".into()),
            });
        }
    }

    // The Block age window must fit inside the effective Warn window, including
    // the shipped 30-day warning baseline when the warn field is omitted.
    if let Some(b) = pp.block_newer_than_days {
        let w = pp.warn_newer_than_days_effective();
        if b > w {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!(
                    "package_policy: block_newer_than_days ({b}) must be <= warn_newer_than_days ({w}); \
                     a Block age window cannot be wider than the Warn window"
                ),
                field: Some("package_policy.block_newer_than_days".into()),
            });
        }
    }

    // Aggregate-score thresholds: must be 0..=100
    if let Some(b) = pp.block_aggregate_score {
        if b > 100 {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!(
                    "package_policy.block_aggregate_score: must be in 0..=100, got {b}"
                ),
                field: Some("package_policy.block_aggregate_score".into()),
            });
        }
    }
    if let Some(w) = pp.warn_aggregate_score {
        if w > 100 {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!(
                    "package_policy.warn_aggregate_score: must be in 0..=100, got {w}"
                ),
                field: Some("package_policy.warn_aggregate_score".into()),
            });
        }
    }
    if let (Some(b), Some(w)) = (pp.block_aggregate_score, pp.warn_aggregate_score) {
        if w > b {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!(
                    "package_policy: warn_aggregate_score ({w}) must be <= block_aggregate_score ({b})"
                ),
                field: Some("package_policy.warn_aggregate_score".into()),
            });
        }
    }

    // Typosquat distance: 1..=10 is practical; 0 is useless, >10 matches all.
    if let Some(d) = pp.block_typosquat_distance {
        if d == 0 {
            issues.push(PolicyIssue {
                level: IssueLevel::Warning,
                message: "package_policy.block_typosquat_distance: 0 matches only exact \
                          known-popular names; this is almost never what you want — omit \
                          the field instead"
                    .into(),
                field: Some("package_policy.block_typosquat_distance".into()),
            });
        }
        if d > 10 {
            issues.push(PolicyIssue {
                level: IssueLevel::Warning,
                message: format!(
                    "package_policy.block_typosquat_distance: {d} is very wide; \
                     typical values are 1..=3"
                ),
                field: Some("package_policy.block_typosquat_distance".into()),
            });
        }
    }

    // Internal-package-names entries: name must be non-empty.
    for (i, spec) in pp.internal_package_names.iter().enumerate() {
        if spec.name.trim().is_empty() {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!(
                    "package_policy.internal_package_names[{i}]: name must not be empty"
                ),
                field: Some(format!("package_policy.internal_package_names[{i}].name")),
            });
        }
    }
}

fn validate_fail_mode_fields(policy: &crate::policy::Policy, issues: &mut Vec<PolicyIssue>) {
    if let Some(ref mode) = policy.policy_fetch_fail_mode {
        let valid = ["open", "closed", "cached"];
        if !valid.contains(&mode.as_str()) {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!(
                    "policy_fetch_fail_mode: invalid value '{mode}' (valid: open, closed, cached)"
                ),
                field: Some("policy_fetch_fail_mode".into()),
            });
        }
    }
}

fn validate_scan_config(policy: &crate::policy::Policy, issues: &mut Vec<PolicyIssue>) {
    if let Some(ref fail_on) = policy.scan.fail_on {
        let parsed: Result<Severity, _> =
            serde_json::from_value(serde_json::Value::String(fail_on.to_uppercase()));
        if parsed.is_err() {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!(
                    "scan.fail_on: invalid severity '{}' (valid: INFO, LOW, MEDIUM, HIGH, CRITICAL)",
                    fail_on
                ),
                field: Some("scan.fail_on".into()),
            });
        }
    }

    validate_custom_dlp_patterns("dlp_custom_patterns", &policy.dlp_custom_patterns, issues);
    validate_custom_dlp_patterns(
        "share.customer_id_patterns",
        &policy.share.customer_id_patterns,
        issues,
    );
}

fn validate_custom_dlp_patterns(field: &str, patterns: &[String], issues: &mut Vec<PolicyIssue>) {
    if patterns.len() > crate::redact::MAX_CUSTOM_DLP_PATTERNS {
        issues.push(PolicyIssue {
            level: IssueLevel::Error,
            message: format!(
                "{field}: too many patterns ({}, max {})",
                patterns.len(),
                crate::redact::MAX_CUSTOM_DLP_PATTERNS
            ),
            field: Some(field.to_string()),
        });
        return;
    }
    for (i, pattern) in patterns.iter().enumerate() {
        if let Err(error) = crate::redact::compile_custom_dlp_pattern(pattern) {
            let field = format!("{field}[{i}]");
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!("{field}: {error}"),
                field: Some(field),
            });
        }
    }
}

/// Validate CIDR/host entries in network_deny and network_allow.
fn validate_network_entries(policy: &crate::policy::Policy, issues: &mut Vec<PolicyIssue>) {
    for (field_name, entries) in [
        ("network_deny", &policy.network_deny),
        ("network_allow", &policy.network_allow),
    ] {
        for (i, entry) in entries.iter().enumerate() {
            if !is_valid_cidr_or_host(entry) {
                issues.push(PolicyIssue {
                    level: IssueLevel::Error,
                    message: format!(
                        "{field_name}[{i}]: '{entry}' is not a valid hostname or CIDR"
                    ),
                    field: Some(format!("{field_name}[{i}]")),
                });
            }
        }
    }
}

/// Check if a string is a valid hostname, IP, or CIDR notation.
fn is_valid_cidr_or_host(s: &str) -> bool {
    // CIDR: split on '/' for the prefix length.
    if let Some((ip_part, prefix)) = s.split_once('/') {
        let Ok(prefix_len) = prefix.parse::<u32>() else {
            return false;
        };
        // Runtime enforcement currently has an IPv4 CIDR matcher only. Use its
        // exact `Ipv4Addr` grammar rather than a parallel handwritten parser.
        return prefix_len <= 32 && ip_part.parse::<std::net::Ipv4Addr>().is_ok();
    }

    if s.contains('*') {
        return false;
    }

    // A leading dot is the runtime's explicit suffix-policy spelling. All
    // remaining hostname/IP grammar and normalization comes from the same
    // parser used by enforcement, so validation cannot approve an entry the
    // matcher will silently discard.
    let Some(canonical) = crate::rules::command::canonical_network_host(s.trim_start_matches('.'))
    else {
        return false;
    };
    if canonical.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    canonical.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

fn validate_action_overrides(policy: &crate::policy::Policy, issues: &mut Vec<PolicyIssue>) {
    for (key, value) in &policy.action_overrides {
        if value != "block" {
            let hint = match value.as_str() {
                "allow" | "warn" | "warn_ack" => {
                    " (use severity_overrides to change rule severity instead)"
                }
                _ => "",
            };
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!(
                    "action_overrides.{key}: invalid value '{value}' \
                     (only 'block' is supported){hint}"
                ),
                field: Some(format!("action_overrides.{key}")),
            });
        }

        let parsed: Result<RuleId, _> =
            serde_json::from_value(serde_json::Value::String(key.clone()));
        if parsed.is_err() {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!("action_overrides: unknown rule ID '{key}'"),
                field: Some(format!("action_overrides.{key}")),
            });
        }
    }
}

fn validate_escalation_rules(policy: &crate::policy::Policy, issues: &mut Vec<PolicyIssue>) {
    for (i, rule) in policy.escalation.iter().enumerate() {
        match rule {
            crate::escalation::EscalationRule::RepeatCount {
                rule_ids,
                threshold,
                ..
            } => {
                if *threshold == 0 {
                    issues.push(PolicyIssue {
                        level: IssueLevel::Error,
                        message: format!("escalation[{i}]: threshold must be > 0"),
                        field: Some(format!("escalation[{i}].threshold")),
                    });
                }
                for rule_id_str in rule_ids {
                    if rule_id_str == "*" {
                        continue; // wildcard is valid
                    }
                    let parsed: Result<RuleId, _> =
                        serde_json::from_value(serde_json::Value::String(rule_id_str.clone()));
                    if parsed.is_err() {
                        issues.push(PolicyIssue {
                            level: IssueLevel::Error,
                            message: format!("escalation[{i}]: unknown rule ID '{rule_id_str}'"),
                            field: Some(format!("escalation[{i}].rule_ids")),
                        });
                    }
                }
            }
            crate::escalation::EscalationRule::MultiMedium { min_findings, .. } => {
                if *min_findings == 0 {
                    issues.push(PolicyIssue {
                        level: IssueLevel::Error,
                        message: format!("escalation[{i}]: min_findings must be > 0"),
                        field: Some(format!("escalation[{i}].min_findings")),
                    });
                }
            }
        }
    }
}

/// Schema validation only for the agent governance block — flags matchers
/// shaped wrong, not whether one ever fires (the engine enforces at runtime via
/// [`crate::escalation::apply_agent_rules`]). Warns on: a `name` filter on a
/// payloadless kind (`human`/`gateway`) which matches nothing; and an empty
/// `name: ""` which the `AgentOrigin` constructors reject up-front.
fn validate_agent_rules(policy: &crate::policy::Policy, issues: &mut Vec<PolicyIssue>) {
    for (list_name, list) in [
        ("agent_rules.allow", &policy.agent_rules.allow),
        ("agent_rules.deny", &policy.agent_rules.deny),
    ] {
        for (i, matcher) in list.iter().enumerate() {
            // Payload filter on a payloadless kind.
            if matcher.name.is_some()
                && matches!(
                    matcher.kind,
                    crate::policy::AgentOriginKind::Human | crate::policy::AgentOriginKind::Gateway
                )
            {
                issues.push(PolicyIssue {
                    level: IssueLevel::Warning,
                    message: format!(
                        "{list_name}[{i}]: a `name` filter on `kind: {}` matches nothing — \
                         that variant carries no caller-claimed payload",
                        matcher.kind.as_str()
                    ),
                    field: Some(format!("{list_name}[{i}].name")),
                });
            }

            // Empty payload string.
            if matches!(matcher.name.as_deref(), Some("")) {
                issues.push(PolicyIssue {
                    level: IssueLevel::Warning,
                    message: format!(
                        "{list_name}[{i}]: `name: \"\"` matches nothing — the AgentOrigin \
                         constructors reject an empty caller-claimed payload"
                    ),
                    field: Some(format!("{list_name}[{i}].name")),
                });
            }

            // Unenforced semantic predicates (round-15). `filesystem_write` /
            // `network` / `secrets_access` load fine but `matcher_matches` keys
            // on `kind` + `name` ONLY, so such a predicate is silently dropped at
            // runtime — a conditional-LOOKING matcher that isn't. Warn (not
            // error: legal advisory metadata), one per present predicate.
            for (field, present) in [
                ("filesystem_write", matcher.filesystem_write.is_some()),
                ("network", matcher.network.is_some()),
                ("secrets_access", matcher.secrets_access.is_some()),
            ] {
                if present {
                    issues.push(PolicyIssue {
                        level: IssueLevel::Warning,
                        message: format!(
                            "{list_name}[{i}]: matcher predicate `{field}` is recognized but \
                             NOT enforced at runtime (agent matching uses `kind` and optional \
                             `name` only); this predicate has no effect"
                        ),
                        field: Some(format!("{list_name}[{i}].{field}")),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_day_zero_block_is_valid_and_meaningful() {
        let issues = validate("package_policy:\n  block_newer_than_days: 0\n");
        assert!(
            issues
                .iter()
                .all(|issue| issue.field.as_deref() != Some("package_policy.block_newer_than_days")),
            "day-zero package blocking must not be treated as disabled: {issues:?}"
        );
    }

    fn unknown_fields(yaml: &str) -> Vec<String> {
        let runtime = crate::policy::Policy::try_parse_yaml(yaml);
        assert!(
            runtime.is_ok(),
            "unknown-field fixture must remain runtime-loadable: {:?}",
            runtime.err()
        );

        let issues = validate(yaml);
        assert!(
            issues.iter().all(|issue| issue.level != IssueLevel::Error),
            "unknown-field fixture must remain validator-loadable: {issues:?}"
        );

        let mut fields: Vec<String> = issues
            .into_iter()
            .filter(|issue| {
                issue.level == IssueLevel::Warning && issue.message.starts_with("unknown field '")
            })
            .filter_map(|issue| issue.field)
            .collect();
        fields.sort();
        fields
    }

    fn assert_runtime_validator_parse_parity(name: &str, yaml: &str) {
        let runtime_accepts = crate::policy::Policy::try_parse_yaml(yaml).is_ok();
        let issues = validate(yaml);
        let validator_accepts = !issues.iter().any(|issue| issue.level == IssueLevel::Error);
        assert_eq!(
            validator_accepts, runtime_accepts,
            "runtime/validator parse parity failed for {name}: {issues:?}"
        );
    }

    #[test]
    fn test_valid_minimal_policy() {
        let yaml = "fail_mode: open\nparanoia: 1\n";
        let issues = validate(yaml);
        assert!(
            issues.is_empty(),
            "minimal policy should be valid: {issues:?}"
        );
    }

    #[test]
    fn test_invalid_yaml() {
        let yaml = "{{invalid yaml";
        let issues = validate(yaml);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].level, IssueLevel::Error);
        assert!(issues[0].message.contains("YAML parse error"));
    }

    #[test]
    fn validator_rejects_future_schema_version_like_runtime() {
        let yaml = format!(
            "schema_version: {}\nparanoia: 2\n",
            crate::policy_migrations::CURRENT_SCHEMA_VERSION + 1
        );
        assert!(crate::policy::Policy::try_parse_yaml(&yaml).is_err());

        let issues = validate(&yaml);
        let issue = issues.iter().find(|issue| {
            issue.level == IssueLevel::Error
                && issue.field.as_deref() == Some("schema_version")
                && issue.message.contains("newer tirith")
        });
        assert!(
            issue.is_some(),
            "future schema version must fail validation before fields are discarded: {issues:?}"
        );
    }

    #[test]
    fn validator_parse_acceptance_matches_runtime_across_document_versions() {
        let current = crate::policy_migrations::CURRENT_SCHEMA_VERSION;
        let cases = [
            ("versionless", "paranoia: 2\n".to_string()),
            (
                "explicit-v1",
                "schema_version: 1\nparanoia: 2\n".to_string(),
            ),
            (
                "v1-legacy",
                "schema_version: 1\ninternal_package_names: [internal-tool]\nparanoia: 2\n"
                    .to_string(),
            ),
            (
                "current",
                format!("schema_version: {current}\nparanoia: 2\n"),
            ),
            (
                "malformed-explicit-version-runtime-compat",
                "schema_version: not-a-number\nparanoia: 2\n".to_string(),
            ),
            ("malformed-field-type", "paranoia: nope\n".to_string()),
            ("malformed-yaml", "{{invalid yaml".to_string()),
        ];

        for (name, yaml) in cases {
            assert_runtime_validator_parse_parity(name, &yaml);
        }
    }

    #[test]
    fn validator_preserves_focused_custom_rule_shape_diagnostics() {
        let cases = [
            (
                "both-shape",
                r#"
custom_rules:
  - id: both-shape
    pattern: "blocked"
    when:
      command.uses_sudo: true
    title: "both"
    context: [exec]
"#,
                "has both",
            ),
            (
                "neither-shape",
                r#"
custom_rules:
  - id: neither-shape
    title: "neither"
    context: [exec]
"#,
                "has neither",
            ),
        ];

        for (id, yaml, detail) in cases {
            assert!(
                crate::policy::Policy::try_parse_yaml(yaml).is_err(),
                "runtime must keep its strict custom-rule shape gate"
            );
            let issues = validate(yaml);
            assert!(
                issues.iter().any(|issue| {
                    issue.level == IssueLevel::Error
                        && issue.field.as_deref() == Some(&format!("custom_rules.{id}"))
                        && issue.message.contains(detail)
                }),
                "validator must retain the focused {id} diagnostic: {issues:?}"
            );
        }
    }

    /// T2.10: the gap-action validator matches the LOWERCASE serde wire contract
    /// exactly (`#[serde(rename_all = "lowercase")]`), so a mixed-case `Warn` /
    /// `FAIL` is rejected through the same strict typed parse runtime uses.
    #[test]
    fn gap_action_rejects_mixed_case_in_policy_validate() {
        for v in ["Warn", "FAIL"] {
            let yaml = format!("scan:\n  oversized_file_action: {v}\n");

            // End-to-end: a mixed-case action is an Error (the wire contract
            // refuses it, here at the strict typed parse).
            let issues = validate(&yaml);
            assert!(
                issues.iter().any(|i| i.level == IssueLevel::Error),
                "mixed-case action '{v}' must be rejected by validate(): {issues:?}"
            );
        }
    }

    /// T2.10: a lowercase `warn` / `fail` is accepted by the validator and
    /// round-trips through serde, matching the wire contract.
    #[test]
    fn gap_action_lowercase_validates_and_round_trips() {
        for v in ["warn", "fail", "ignore"] {
            let yaml = format!("scan:\n  oversized_file_action: {v}\n");

            // No validation error at all for a valid lowercase action.
            let issues = validate(&yaml);
            assert!(
                issues.iter().all(|i| i.level != IssueLevel::Error),
                "lowercase action '{v}' must validate cleanly: {issues:?}"
            );

            // And it round-trips through the strict typed parse (the wire layer).
            let parsed: Result<crate::policy::Policy, _> = serde_yaml::from_str(&yaml);
            assert!(
                parsed.is_ok(),
                "lowercase action '{v}' must deserialize: {:?}",
                parsed.err()
            );
        }
    }

    #[test]
    fn test_paranoia_out_of_range() {
        let yaml = "paranoia: 5\n";
        let issues = validate(yaml);
        assert!(issues
            .iter()
            .any(|i| i.message.contains("paranoia must be 1-4")));
    }

    #[test]
    fn test_invalid_severity_override() {
        let yaml = "severity_overrides:\n  not_a_rule: HIGH\n";
        let issues = validate(yaml);
        assert!(issues
            .iter()
            .any(|i| i.message.contains("unknown rule ID 'not_a_rule'")));
    }

    #[test]
    fn test_allowlist_blocklist_overlap() {
        let yaml = "allowlist:\n  - example.com\nblocklist:\n  - example.com\n";
        let issues = validate(yaml);
        assert!(issues
            .iter()
            .any(|i| i.message.contains("both allowlist and blocklist")));
    }

    #[test]
    fn network_policy_rejects_unenforceable_wildcard_and_ipv6_cidr() {
        for entry in [
            "*.example.com",
            "2001:db8::/32",
            ".",
            "...",
            "bad host.example",
            "bad_host.example",
            "-bad.example",
            "bad-.example",
            "bad..example",
        ] {
            let yaml = format!("network_deny:\n  - '{entry}'\n");
            let issues = validate(&yaml);
            assert!(
                issues.iter().any(|issue| {
                    issue.level == IssueLevel::Error
                        && issue.field.as_deref() == Some("network_deny[0]")
                }),
                "validator accepted unenforceable network entry {entry}: {issues:?}"
            );
        }
    }

    #[test]
    fn network_policy_accepts_runtime_enforceable_forms() {
        let entries = [
            ("example.com", "sub.example.com"),
            (".example.net", "sub.example.net"),
            ("10.0.0.0/8", "10.2.3.4"),
            ("2001:db8::1", "2001:db8::1"),
        ];
        let yaml = format!(
            "network_deny:\n{}",
            entries
                .iter()
                .map(|(entry, _)| format!("  - '{entry}'\n"))
                .collect::<String>()
        );
        let issues = validate(&yaml);
        assert!(
            !issues.iter().any(|issue| {
                issue.level == IssueLevel::Error
                    && issue
                        .field
                        .as_deref()
                        .is_some_and(|field| field.starts_with("network_deny["))
            }),
            "validator rejected runtime-enforceable network entries: {issues:?}"
        );
        for (entry, host) in entries {
            assert!(
                crate::rules::command::matches_network_list(host, &[entry.to_string()]),
                "validation accepted {entry}, but runtime did not match {host}"
            );
        }
    }

    #[test]
    fn test_custom_rule_bad_regex() {
        let yaml = r#"
custom_rules:
  - id: test
    pattern: "[invalid"
    title: "Test rule"
"#;
        let issues = validate(yaml);
        assert!(issues.iter().any(|i| i.message.contains("invalid regex")));
    }

    #[test]
    fn custom_dlp_validation_matches_every_runtime_pattern_boundary() {
        let cases = [
            ("ascii-at-limit", "a".repeat(1024)),
            ("ascii-over-limit", "a".repeat(1025)),
            ("multibyte-at-limit", "é".repeat(512)),
            ("multibyte-over-limit", format!("{}a", "é".repeat(512))),
            ("invalid-regex", "(".to_string()),
            ("zero-width-empty", "".to_string()),
            ("zero-width-boundary", r"\b".to_string()),
            ("legitimate", r"PROJ-\d+".to_string()),
        ];

        for (name, pattern) in cases {
            let runtime_accepts = crate::redact::compile_custom_dlp_pattern(&pattern).is_ok();

            let yaml = format!("dlp_custom_patterns:\n  - '{pattern}'\n");
            let issues = validate(&yaml);
            let validator_accepts = !issues.iter().any(|issue| {
                issue.level == IssueLevel::Error
                    && issue.field.as_deref() == Some("dlp_custom_patterns[0]")
            });
            assert_eq!(
                validator_accepts, runtime_accepts,
                "dlp_custom_patterns parity failed for {name}: {issues:?}"
            );

            let yaml = format!("share:\n  customer_id_patterns:\n    - '{pattern}'\n");
            let issues = validate(&yaml);
            let validator_accepts = !issues.iter().any(|issue| {
                issue.level == IssueLevel::Error
                    && issue.field.as_deref() == Some("share.customer_id_patterns[0]")
            });
            assert_eq!(
                validator_accepts, runtime_accepts,
                "share.customer_id_patterns parity failed for {name}: {issues:?}"
            );
        }
    }

    #[test]
    fn custom_dlp_validation_matches_runtime_pattern_count_cap() {
        let count = crate::redact::MAX_CUSTOM_DLP_PATTERNS + 1;
        let rows = "  - 'never-match'\n".repeat(count);
        for (field, yaml) in [
            (
                "dlp_custom_patterns",
                format!("dlp_custom_patterns:\n{rows}"),
            ),
            (
                "share.customer_id_patterns",
                format!(
                    "share:\n  customer_id_patterns:\n{}",
                    rows.replace("  -", "    -")
                ),
            ),
        ] {
            let issues = validate(&yaml);
            assert!(
                issues.iter().any(|issue| {
                    issue.level == IssueLevel::Error
                        && issue.field.as_deref() == Some(field)
                        && issue.message.contains("too many patterns")
                }),
                "validator must reject the runtime-over-limit set for {field}: {issues:?}"
            );
        }
    }

    #[test]
    fn test_custom_regex_rule_empty_context_rejected() {
        // round-27: mirror `compile_rules`, which DROPS a regex rule with an
        // empty filtered context. An explicit `context: []` filters empty and
        // must be an Error (an OMITTED `context:` defaults to [exec,paste] and is
        // unaffected — see `test_custom_rule_bad_regex`).
        let yaml = r#"
custom_rules:
  - id: regex-empty-ctx
    pattern: "internal\\.corp"
    title: "Test rule"
    context: []
"#;
        let issues = validate(yaml);
        let issue = issues.iter().find(|i| {
            i.level == IssueLevel::Error
                && i.message.contains("regex-empty-ctx")
                && i.message.contains("no valid contexts")
        });
        assert!(
            issue.is_some(),
            "regex rule with empty context must be rejected (mirrors compile_rules): {issues:?}"
        );
        assert_eq!(
            issue.unwrap().field.as_deref(),
            Some("custom_rules.regex-empty-ctx.context"),
            "field must point at the rule's context: {issues:?}"
        );
    }

    #[test]
    fn test_empty_context_regex_rule_short_circuits_regex_validation() {
        // A no-context rule is dropped by `compile_rules`, so the empty-context
        // check short-circuits before the regex checks: an empty-context AND
        // invalid-regex rule must report ONLY "no valid contexts".
        let yaml = r#"
custom_rules:
  - id: empty-ctx-bad-regex
    pattern: "("
    title: "Test rule"
    context: []
"#;
        let issues = validate(yaml);
        let ours: Vec<_> = issues
            .iter()
            .filter(|i| i.message.contains("empty-ctx-bad-regex"))
            .collect();
        assert!(
            ours.iter().any(|i| i.message.contains("no valid contexts")),
            "must report the no-valid-contexts error: {issues:?}"
        );
        assert!(
            !ours.iter().any(|i| i.message.contains("invalid regex")),
            "must NOT also emit an invalid-regex error for a dropped no-context rule: {issues:?}"
        );
        assert_eq!(
            ours.len(),
            1,
            "exactly one issue (no valid contexts), not a redundant regex error: {issues:?}"
        );
    }

    #[test]
    fn test_custom_regex_rule_pattern_too_long_rejected() {
        // round-27: a pattern over the 1024-CHAR cap (chars, not bytes — round-26)
        // is an Error. round-28: the cap also short-circuits compilation. Using a
        // pattern that's over-cap AND invalid (`(` repeated) makes the short-
        // circuit observable: the ONLY issue must be the length error.
        let pattern = "(".repeat(1025);
        assert_eq!(pattern.chars().count(), 1025, "1025 chars (over the cap)");
        assert!(
            regex::Regex::new(&pattern).is_err(),
            "the over-cap pattern must ALSO be an invalid regex, so a fall-through \
             would add a second 'invalid regex' issue we can detect its absence of"
        );
        let yaml = format!(
            "custom_rules:\n  - id: too-long\n    pattern: \"{pattern}\"\n    title: \"Test rule\"\n    context: [exec]\n"
        );
        let issues = validate(&yaml);
        let issue = issues.iter().find(|i| {
            i.level == IssueLevel::Error
                && i.message.contains("too-long")
                && i.message.contains("pattern too long")
                && i.message.contains("1025 chars")
                && i.message.contains("max 1024")
        });
        assert!(
            issue.is_some(),
            "regex rule with a >1024-char pattern must be rejected: {issues:?}"
        );
        assert_eq!(
            issue.unwrap().field.as_deref(),
            Some("custom_rules.too-long.pattern"),
            "field must point at the rule's pattern: {issues:?}"
        );
        // The over-cap (and invalid) pattern must NOT also yield "invalid regex"
        // — exactly one issue proves `Regex::new` was skipped.
        assert!(
            !issues
                .iter()
                .any(|i| i.message.contains("too-long") && i.message.contains("invalid regex")),
            "overlong pattern must not ALSO be compiled (no 'invalid regex' issue): {issues:?}"
        );
        assert_eq!(
            issues
                .iter()
                .filter(|i| i.message.contains("too-long"))
                .count(),
            1,
            "an overlong pattern must yield exactly ONE issue (the length error), \
             proving compilation was short-circuited: {issues:?}"
        );
    }

    #[test]
    fn test_custom_regex_rule_multibyte_pattern_under_char_cap_accepted() {
        // round-26/27: the cap counts CHARS not BYTES. 600×'é' = 600 chars /
        // 1200 bytes — under the char cap, over a byte cap — must be ACCEPTED,
        // proving `pattern.chars().count()` is used like the engine.
        let pattern = "é".repeat(600);
        assert_eq!(pattern.chars().count(), 600, "600 chars");
        assert!(pattern.len() > 1024, "but >1024 bytes");
        let yaml = format!(
            "custom_rules:\n  - id: multibyte-ok\n    pattern: \"{pattern}\"\n    title: \"Test rule\"\n    context: [exec]\n"
        );
        let issues = validate(&yaml);
        assert!(
            !issues.iter().any(|i| i.message.contains("multibyte-ok")
                && (i.message.contains("pattern too long")
                    || i.message.contains("invalid regex")
                    || i.message.contains("no valid contexts"))),
            "a <=1024-CHAR multibyte pattern (>1024 bytes) must be ACCEPTED: {issues:?}"
        );
    }

    #[test]
    fn test_custom_regex_rule_valid_still_passes() {
        // Sanity: a valid regex rule with a real context and a sane pattern must
        // produce no error after the round-27 gating was added.
        let yaml = r#"
custom_rules:
  - id: valid-regex
    pattern: "internal\\.corp"
    title: "Test rule"
    context: [exec]
"#;
        let issues = validate(yaml);
        assert!(
            !issues.iter().any(|i| i.level == IssueLevel::Error),
            "a valid regex rule must produce no errors: {issues:?}"
        );
    }

    #[test]
    fn test_injection_seeds_custom_invalid_regex_rejected() {
        // C5: a bad `injection_seeds_custom` regex is reported by `policy validate`
        // (it is skipped, not hard-failed, at compile time). The two new keys must
        // ALSO be known top-level fields (no "unknown field" warning).
        let yaml = "injection_seeds_custom:\n  - \"(unclosed\"\nmcp_redact_injection: true\n";
        let issues = validate(yaml);
        assert!(
            issues.iter().any(|i| i.level == IssueLevel::Error
                && i.message.contains("injection_seeds_custom[0]")
                && i.message.contains("invalid regex")),
            "a bad injection_seeds_custom regex must produce a validation error: {issues:?}"
        );
        assert!(
            !issues
                .iter()
                .any(|i| i.message.contains("unknown field 'injection_seeds_custom'")),
            "injection_seeds_custom must be a known top-level field: {issues:?}"
        );
        assert!(
            !issues
                .iter()
                .any(|i| i.message.contains("unknown field 'mcp_redact_injection'")),
            "mcp_redact_injection must be a known top-level field: {issues:?}"
        );
    }

    #[test]
    fn test_injection_seeds_custom_validate_compile_parity() {
        // FIX 1: `policy validate` must use the SAME compile path as the engine
        // (`validate_seed_pattern` -> placeholder-substitution + case-insensitive
        // build), NOT a raw `Regex::new`. `(?P<name>x)` is a VALID raw regex (a
        // named capture group), so the OLD raw validator accepted it — but the
        // engine rewrites the `<name>` token to `\S+` (`(?P\S+x)`), which fails to
        // compile and is silently dropped at runtime. `policy validate` must now
        // REPORT it as invalid so the operator is not told OK while detection never
        // runs.
        let yaml = "injection_seeds_custom:\n  - \"(?P<name>x)\"\n";
        let issues = validate(yaml);
        assert!(
            issues.iter().any(|i| i.level == IssueLevel::Error
                && i.message.contains("injection_seeds_custom[0]")
                && i.message.contains("invalid regex")),
            "a seed valid raw but invalid after placeholder substitution must be \
             reported by policy validate (validate/compile parity): {issues:?}"
        );
        // Guard the premise: the raw pattern really is a valid regex, so this test
        // would have FAILED before the fix (the old raw `Regex::new` passed it).
        assert!(
            regex::Regex::new("(?P<name>x)").is_ok(),
            "premise: the raw pattern is a valid regex"
        );
    }

    #[test]
    fn test_injection_seeds_custom_valid_accepted() {
        // A valid seed regex and the bool flag produce no errors.
        let yaml =
            "injection_seeds_custom:\n  - \"my-secret-phrase\"\nmcp_redact_injection: false\n";
        let issues = validate(yaml);
        assert!(
            !issues.iter().any(|i| i.level == IssueLevel::Error),
            "a valid injection_seeds_custom entry must produce no errors: {issues:?}"
        );
    }

    #[test]
    fn test_unknown_field() {
        let yaml = "not_a_real_field: true\n";
        let issues = validate(yaml);
        assert!(issues.iter().any(|i| i.message.contains("unknown field")));
    }

    #[test]
    fn every_serialized_production_policy_field_is_known() {
        let yaml = serde_yaml::to_string(&crate::policy::Policy::default())
            .expect("default policy must serialize");
        let top_level_count = serde_yaml::from_str::<serde_yaml::Value>(&yaml)
            .expect("serialized policy must parse")
            .as_mapping()
            .expect("policy must serialize as a mapping")
            .len();
        assert!(
            top_level_count >= 35,
            "test must exercise the complete production Policy surface, got {top_level_count}"
        );
        assert_eq!(
            unknown_fields(&yaml),
            Vec::<String>::new(),
            "fields emitted by the production Policy serializer must be recognized"
        );
    }

    #[test]
    fn schema_derived_unknowns_include_nested_structs_and_sequence_elements() {
        let yaml = r#"
share:
  customer_id_patterns: []
  customer_id_patternz: []
scan:
  profiles:
    release:
      include: ["src/**"]
      incldue: ["tests/**"]
approval_rules:
  - rule_ids: []
    timeout_secondz: 30
webhooks:
  - url: "https://hooks.example.test/events"
    payload_temlate: "{}"
"#;

        assert_eq!(
            unknown_fields(yaml),
            vec![
                "approval_rules[0].timeout_secondz".to_string(),
                "scan.profiles.release.incldue".to_string(),
                "share.customer_id_patternz".to_string(),
                "webhooks[0].payload_temlate".to_string(),
            ]
        );
    }

    #[test]
    fn dynamic_map_keys_and_serde_aliases_are_not_unknown_fields() {
        let yaml = r#"
severity_overrides:
  curl_pipe_shell: HIGH
action_overrides:
  curl_pipe_shell: block
context_destructive_verbs:
  aws: [delete-stack]
scan:
  mcp_allowed_tools:
    server.alpha: [read_resource]
  profiles:
    release:
      include: ["src/**"]
webhooks:
  - url: "https://hooks.example.test/events"
    headers:
      X-Custom-Header: value
custom_rules:
  - id: alias-title
    pattern: "safe-pattern"
    message: "recognized title alias"
    context: [exec]
"#;

        assert_eq!(unknown_fields(yaml), Vec::<String>::new());
    }

    #[test]
    fn serde_skipped_policy_fields_are_reported_as_unknown() {
        let yaml = r#"
path: "/tmp/untrusted-policy.yaml"
scope: repo
context_labels:
  aws:prod: critical
ssh_host_labels:
  prod: critical
neutralized_fields: [allowlist]
"#;

        assert_eq!(
            unknown_fields(yaml),
            vec![
                "context_labels".to_string(),
                "neutralized_fields".to_string(),
                "path".to_string(),
                "scope".to_string(),
                "ssh_host_labels".to_string(),
            ]
        );
    }

    #[test]
    fn migrated_legacy_fields_are_checked_after_migration() {
        for yaml in [
            "internal_package_names: [internal-tool]\n",
            "schema_version: 1\ninternal_package_names: [internal-tool]\n",
        ] {
            let policy = crate::policy::Policy::try_parse_yaml(yaml)
                .expect("v1 legacy field must migrate into a loadable current policy");
            assert_eq!(policy.package_policy.internal_package_names.len(), 1);
            assert_eq!(
                policy.package_policy.internal_package_names[0].name,
                "internal-tool"
            );
            assert_eq!(
                unknown_fields(yaml),
                Vec::<String>::new(),
                "v1 legacy field must be consumed before unknown-field collection"
            );
        }

        let yaml = format!(
            "schema_version: {}\ninternal_package_names: [internal-tool]\n",
            crate::policy_migrations::CURRENT_SCHEMA_VERSION
        );
        assert_eq!(
            unknown_fields(&yaml),
            vec!["internal_package_names".to_string()],
            "the legacy key is unknown when a current-version policy bypasses migration"
        );
    }

    #[test]
    fn curated_policy_templates_have_no_unknown_fields() {
        let templates = [
            (
                "individual",
                include_str!("../../tirith/assets/policy_templates/individual.yaml"),
            ),
            (
                "startup",
                include_str!("../../tirith/assets/policy_templates/startup.yaml"),
            ),
            (
                "oss-maintainer",
                include_str!("../../tirith/assets/policy_templates/oss-maintainer.yaml"),
            ),
            (
                "ci-strict",
                include_str!("../../tirith/assets/policy_templates/ci-strict.yaml"),
            ),
            (
                "enterprise",
                include_str!("../../tirith/assets/policy_templates/enterprise.yaml"),
            ),
            (
                "ai-agent-heavy",
                include_str!("../../tirith/assets/policy_templates/ai-agent-heavy.yaml"),
            ),
            (
                "mcp-strict",
                include_str!("../../tirith/assets/policy_templates/mcp-strict.yaml"),
            ),
        ];

        for (name, yaml) in templates {
            assert_eq!(
                unknown_fields(yaml),
                Vec::<String>::new(),
                "curated template {name} must stay aligned with the production schema"
            );
        }
    }

    #[test]
    fn test_dsl_rule_empty_context_rejected() {
        // Finding D: an explicit `context: []` with a `command.*` predicate is a
        // silent no-op and must be rejected (the old `!declared.is_empty()` guard
        // let it pass).
        let yaml = r#"
custom_rules:
  - id: empty-context-noop
    when:
      command.uses_sudo: true
    title: "empty-context no-op"
    context: []
"#;
        let issues = validate(yaml);
        assert!(
            issues.iter().any(|i| i.level == IssueLevel::Error
                && i.message.contains("empty-context-noop")
                && i.message.contains("not covered by declared context")),
            "DSL rule with empty context must be rejected: {issues:?}"
        );
    }

    #[test]
    fn test_dsl_rule_empty_context_file_predicate_rejected() {
        // The coverage check must also reject an empty context for a file-family
        // predicate.
        let yaml = r#"
custom_rules:
  - id: empty-context-file
    when:
      file.path_matches: '\.env$'
    title: "empty-context file rule"
    context: []
"#;
        let issues = validate(yaml);
        assert!(
            issues.iter().any(|i| i.level == IssueLevel::Error
                && i.message.contains("empty-context-file")
                && i.message.contains("not covered by declared context")),
            "DSL file rule with empty context must be rejected: {issues:?}"
        );
    }

    #[test]
    fn test_dsl_rule_omitted_context_defaults_and_is_accepted() {
        // An OMITTED `context:` defaults to [exec, paste], so a url-family rule
        // is covered and accepted (finding D is about the EXPLICIT empty list).
        let yaml = r#"
custom_rules:
  - id: defaulted-context
    when:
      url.reputation: unknown
    title: "defaulted-context rule"
"#;
        let issues = validate(yaml);
        assert!(
            !issues
                .iter()
                .any(|i| i.message.contains("defaulted-context")
                    && i.message.contains("not covered by declared context")),
            "DSL rule with omitted context (defaults to exec/paste) must be accepted: {issues:?}"
        );
    }

    #[test]
    fn test_dsl_rule_no_context_command_accepted_file_rejected() {
        // round-15: an OMITTED `context:` resolves THROUGH the [exec,paste]
        // default, so a no-context `command.*` rule resolves to {exec,paste} and
        // is ACCEPTED while a no-context `file.*` rule resolves to ∅ and is
        // REJECTED — computed the same way `compile_rules` does.
        let cmd_yaml = r#"
custom_rules:
  - id: no-ctx-cmd
    when:
      command.uses_sudo: true
    title: "no-context command rule"
"#;
        let cmd_issues = validate(cmd_yaml);
        assert!(
            !cmd_issues.iter().any(|i| i.message.contains("no-ctx-cmd")
                && i.message.contains("not covered by declared context")),
            "no-context command.* rule (defaults to exec/paste) must be ACCEPTED: {cmd_issues:?}"
        );

        let file_yaml = r#"
custom_rules:
  - id: no-ctx-file
    when:
      file.path_matches: '\.env$'
    title: "no-context file rule"
"#;
        let file_issues = validate(file_yaml);
        assert!(
            file_issues.iter().any(|i| i.level == IssueLevel::Error
                && i.message.contains("no-ctx-file")
                && i.message.contains("not covered by declared context")),
            "no-context file.path_matches rule must be REJECTED (can never fire): {file_issues:?}"
        );
    }

    #[test]
    fn test_dsl_rule_explicit_file_context_file_predicate_accepted() {
        // The counterpart: a `file.path_matches` rule that DECLARES `[file]`
        // resolves to {file} (non-empty) and must be ACCEPTED.
        let yaml = r#"
custom_rules:
  - id: file-ctx-file
    when:
      file.path_matches: '\.env$'
    title: "explicit file context"
    context: [file]
"#;
        let issues = validate(yaml);
        assert!(
            !issues.iter().any(|i| i.message.contains("file-ctx-file")
                && (i.message.contains("not covered by declared context")
                    || i.message.contains("never co-occur"))),
            "explicit [file] file rule must be accepted: {issues:?}"
        );
    }

    #[test]
    fn test_agent_matcher_unenforced_predicate_warns() {
        // round-15: `filesystem_write` / `network` / `secrets_access` are
        // recognized but `matcher_matches` ignores them (kind+name only), so a
        // matcher carrying one must emit a WARNING (not error, not silence).
        let yaml = "agent_rules:\n  deny:\n    - kind: agent\n      network: block\n";
        let issues = validate(yaml);
        let warn = issues.iter().find(|i| {
            i.message.contains("network")
                && i.message.contains("NOT enforced at runtime")
                && i.message.contains("has no effect")
        });
        assert!(
            warn.is_some(),
            "agent matcher carrying `network` must produce an unenforced-predicate WARNING: {issues:?}"
        );
        assert_eq!(
            warn.unwrap().level,
            IssueLevel::Warning,
            "must be a Warning, not an Error"
        );
        // It must NOT be reported as an error (the field is legal advisory metadata).
        assert!(
            !issues.iter().any(|i| i.level == IssueLevel::Error
                && i.field.as_deref() == Some("agent_rules.deny[0].network")),
            "the unenforced predicate must not be an error: {issues:?}"
        );
    }

    #[test]
    fn test_agent_matcher_all_three_predicates_each_warn() {
        // Each of the three advisory predicates produces its own warning.
        let yaml = "agent_rules:\n  allow:\n    - kind: agent\n      filesystem_write: repo_only\n      network: allow\n      secrets_access: block\n";
        let issues = validate(yaml);
        for field in ["filesystem_write", "network", "secrets_access"] {
            assert!(
                issues.iter().any(|i| i.level == IssueLevel::Warning
                    && i.message.contains(field)
                    && i.message.contains("NOT enforced at runtime")),
                "predicate `{field}` must produce an unenforced WARNING: {issues:?}"
            );
        }
    }

    #[test]
    fn test_agent_matcher_no_predicates_no_unenforced_warning() {
        // A plain kind+name matcher must NOT trigger the unenforced-predicate warning.
        let yaml = "agent_rules:\n  deny:\n    - kind: agent\n      name: claude-code\n";
        let issues = validate(yaml);
        assert!(
            !issues
                .iter()
                .any(|i| i.message.contains("NOT enforced at runtime")),
            "a kind+name matcher must not warn about unenforced predicates: {issues:?}"
        );
    }

    #[test]
    fn test_dsl_rule_invalid_context_not_double_reported() {
        // An invalid context value is its own issue; we must NOT also emit a
        // coverage error for the dropped token. Exactly one error, the
        // invalid-context one.
        let yaml = r#"
custom_rules:
  - id: bogus-ctx
    when:
      command.uses_sudo: true
    title: "bogus context"
    context: [bogus]
"#;
        let issues = validate(yaml);
        let rule_errors: Vec<&PolicyIssue> = issues
            .iter()
            .filter(|i| i.level == IssueLevel::Error && i.message.contains("bogus-ctx"))
            .collect();
        assert!(
            rule_errors
                .iter()
                .any(|i| i.message.contains("invalid context")),
            "invalid context must be reported: {issues:?}"
        );
        assert!(
            !rule_errors
                .iter()
                .any(|i| i.message.contains("not covered by declared context")),
            "must NOT double-report a coverage error for the dropped token: {issues:?}"
        );
    }

    #[test]
    fn test_dsl_rule_valid_context_accepted() {
        // Sanity: a DSL rule whose declared context covers its predicates passes.
        let yaml = r#"
custom_rules:
  - id: ok-rule
    when:
      command.uses_sudo: true
    title: "ok rule"
    context: [exec]
"#;
        let issues = validate(yaml);
        assert!(
            !issues.iter().any(|i| i.message.contains("ok-rule")
                && i.message.contains("not covered by declared context")),
            "valid DSL rule must not produce a coverage error: {issues:?}"
        );
    }

    #[test]
    fn test_dsl_rule_agent_kind_rejected_as_unsupported() {
        // round-8 R8-1: an `agent.kind` clause reads a field the engine hard-codes
        // to `None`, so it can never match and must be REJECTED (like `mcp.tool`)
        // with a message pointing at `agent_rules`. Covers bare + nested-in-`all`.
        for (id, when_block) in [
            ("agent-bare", "      agent.kind: claude-code"),
            (
                "agent-nested",
                "      all:\n        - command.uses_sudo: true\n        - agent.kind: claude-code",
            ),
        ] {
            let yaml = format!(
                "custom_rules:\n  - id: {id}\n    when:\n{when_block}\n    title: \"agent rule\"\n    context: [exec]\n"
            );
            let issues = validate(&yaml);
            assert!(
                issues.iter().any(|i| i.level == IssueLevel::Error
                    && i.message.contains(id)
                    && i.message.contains("agent.kind")
                    && i.message.contains("not supported")
                    && i.message.contains("agent_rules")),
                "agent.kind rule '{id}' must be rejected with a clear message: {issues:?}"
            );
        }
    }

    #[test]
    fn test_dsl_rule_mcp_tool_rejected() {
        // round-3 R3-3: `mcp.tool` must be REJECTED — no scan context wires up an
        // MCP-tool signal, so the rule would load yet never match.
        let yaml = r#"
custom_rules:
  - id: mcp-tool-rule
    when:
      mcp.tool: read_file
    title: "mcp tool rule"
    context: [file]
"#;
        let issues = validate(yaml);
        assert!(
            issues.iter().any(|i| i.level == IssueLevel::Error
                && i.message.contains("mcp-tool-rule")
                && i.message.contains("mcp.tool")
                && i.message.contains("not supported")),
            "mcp.tool rule must be rejected with a clear message: {issues:?}"
        );
    }

    #[test]
    fn test_dsl_rule_paste_command_predicate_accepted() {
        // round-3 R3-1: a `command.*` predicate under `paste` is VALID (paste
        // fills command facts), so no coverage error.
        let yaml = r#"
custom_rules:
  - id: paste-cmd
    when:
      command.uses_sudo: true
    title: "paste command rule"
    context: [paste]
"#;
        let issues = validate(yaml);
        assert!(
            !issues.iter().any(|i| i.message.contains("paste-cmd")
                && i.message.contains("not covered by declared context")),
            "paste + command.* rule must be accepted (round-3 R3-1): {issues:?}"
        );
    }

    #[test]
    fn test_dsl_rule_all_command_and_file_is_unsatisfiable() {
        // round-9 R9-1: `all(command.*, file.*)` mixes contexts that never
        // co-occur, so its satisfiable set is ∅ — rejected with the dedicated
        // "never co-occur" message (not the generic coverage one), even with both
        // contexts declared.
        let yaml = r#"
custom_rules:
  - id: impossible-and
    when:
      all:
        - command.uses_sudo: true
        - file.path_matches: '\.env$'
    title: "command AND file"
    context: [exec, file]
"#;
        let issues = validate(yaml);
        assert!(
            issues.iter().any(|i| i.level == IssueLevel::Error
                && i.message.contains("impossible-and")
                && i.message.contains("never co-occur")),
            "all(command, file) must be rejected as unsatisfiable: {issues:?}"
        );
        // The dedicated message replaces the coverage message -- no double-report.
        assert!(
            !issues.iter().any(|i| i.message.contains("impossible-and")
                && i.message.contains("not covered by declared context")),
            "unsatisfiable clause must NOT also emit a coverage error: {issues:?}"
        );
    }

    #[test]
    fn test_dsl_rule_any_command_or_file_accepted_under_single_context() {
        // round-9 R9-1: `any(command.*, file.*)` is evaluable wherever EITHER
        // branch is (the union), so a single-context rule is covered and ACCEPTED.
        let yaml = r#"
custom_rules:
  - id: either-or
    when:
      any:
        - command.uses_sudo: true
        - file.path_matches: '\.env$'
    title: "command OR file"
    context: [paste]
"#;
        let issues = validate(yaml);
        assert!(
            !issues.iter().any(|i| i.message.contains("either-or")
                && (i.message.contains("not covered by declared context")
                    || i.message.contains("never co-occur"))),
            "any(command, file) under a single context must be accepted (R9-1): {issues:?}"
        );
    }

    #[test]
    fn test_nested_scan_profile_unknown_field() {
        let yaml = "scan:\n  profiles:\n    ci:\n      nope: true\n";
        let issues = validate(yaml);
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("scan.profiles.ci.nope")),
            "nested profile typo should be flagged: {issues:?}"
        );
    }

    // -----------------------------------------------------------------------
    // M4 item 8 chunk 2: agent_rules schema validation.
    // -----------------------------------------------------------------------

    #[test]
    fn test_agent_rules_valid_kinds_no_warnings() {
        let yaml = "agent_rules:\n  allow:\n    - kind: agent\n      name: claude-code\n    - kind: mcp\n  deny:\n    - kind: ci\n      name: github-actions\n";
        let issues = validate(yaml);
        assert!(
            issues.iter().all(|i| i.level != IssueLevel::Error),
            "valid agent_rules must produce no errors: {issues:?}"
        );
    }

    #[test]
    fn test_agent_rules_name_filter_on_human_warns() {
        let yaml = "agent_rules:\n  allow:\n    - kind: human\n      name: xyz\n";
        let issues = validate(yaml);
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("matches nothing") && i.message.contains("human")),
            "name filter on `kind: human` must warn: {issues:?}"
        );
    }

    #[test]
    fn test_agent_rules_name_filter_on_gateway_warns() {
        let yaml = "agent_rules:\n  deny:\n    - kind: gateway\n      name: anywhere\n";
        let issues = validate(yaml);
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("matches nothing") && i.message.contains("gateway")),
            "name filter on `kind: gateway` must warn: {issues:?}"
        );
    }

    #[test]
    fn test_agent_rules_empty_name_string_warns() {
        let yaml = "agent_rules:\n  allow:\n    - kind: agent\n      name: \"\"\n";
        let issues = validate(yaml);
        assert!(
            issues.iter().any(|i| i.message.contains("`name: \"\"`")),
            "empty name string must warn: {issues:?}"
        );
    }

    #[test]
    fn test_agent_rules_unknown_kind_is_yaml_parse_error() {
        // An unknown kind cannot deserialize — that's a structural YAML
        // error and we surface it through the parse path.
        let yaml = "agent_rules:\n  allow:\n    - kind: telepathy\n";
        let issues = validate(yaml);
        assert!(
            issues.iter().any(|i| i.level == IssueLevel::Error),
            "unknown kind must surface a parse error: {issues:?}"
        );
    }

    #[test]
    fn test_threat_intel_no_longer_unknown_field() {
        // Regression: a policy declaring threat_intel must NOT trigger the
        // "unknown field" warning.
        let yaml = "threat_intel:\n  osv_enabled: true\n";
        let issues = validate(yaml);
        assert!(
            !issues
                .iter()
                .any(|i| i.message.contains("unknown field 'threat_intel'")),
            "threat_intel must be a known top-level field: {issues:?}"
        );
    }

    #[test]
    fn test_agent_rules_no_longer_unknown_field() {
        let yaml = "agent_rules:\n  allow: []\n  deny: []\n";
        let issues = validate(yaml);
        assert!(
            !issues
                .iter()
                .any(|i| i.message.contains("unknown field 'agent_rules'")),
            "agent_rules must be a known top-level field: {issues:?}"
        );
    }

    // PR #121 fix-list item 10 — nested `agent_rules.*` unknown-field validation
    // (a typo on `allow`/`deny` or a matcher field used to be dropped silently).

    #[test]
    fn test_agent_rules_unknown_sub_key_warns() {
        // `denyy` instead of `deny` used to pass silently with the list dropped.
        let yaml = "agent_rules:\n  denyy:\n    - kind: agent\n      name: claude-code\n";
        let issues = validate(yaml);
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("agent_rules.denyy")),
            "typo on `agent_rules.deny` must produce an unknown-field warning: {issues:?}"
        );
    }

    #[test]
    fn test_agent_rules_unknown_matcher_field_warns() {
        // `namee` instead of `name` deserialized as `name: None` (matching every
        // Agent caller) and emitted zero warnings pre-fix.
        let yaml = "agent_rules:\n  deny:\n    - kind: agent\n      namee: claude-code\n";
        let issues = validate(yaml);
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("agent_rules.deny[0].namee")),
            "typo on a matcher field must produce an unknown-field warning: {issues:?}"
        );
    }

    #[test]
    fn test_agent_rules_valid_matcher_accepted() {
        // Sanity check — the valid shape produces no `agent_rules.*`
        // unknown-field warning. (Other warnings may still fire from
        // unrelated checks; we look specifically for the unknown-field
        // shape on this key.)
        let yaml = "agent_rules:\n  deny:\n    - kind: agent\n      name: claude-code\n";
        let issues = validate(yaml);
        assert!(
            !issues
                .iter()
                .any(|i| i.message.contains("unknown field 'agent_rules.")),
            "valid agent_rules matcher must not produce an unknown-field warning: {issues:?}"
        );
    }
}
