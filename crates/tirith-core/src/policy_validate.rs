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

    // Structural parse first — fail early if the YAML shape is wrong.
    let policy: crate::policy::Policy = match serde_yaml::from_str(yaml) {
        Ok(p) => p,
        Err(e) => {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!("YAML parse error: {e}"),
                field: None,
            });
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

    // Typo guard: flag fields that aren't part of the Policy schema.
    validate_unknown_fields(yaml, &mut issues);

    issues
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
        } else if let Err(e) = crate::rules::prompt_injection::validate_seed_pattern(trimmed) {
            // Regex must compile (checked last, after the cap, like custom rules).
            // Use the SAME compile path `compile_seeds` uses (placeholder
            // substitution + case-insensitive build), NOT a raw `Regex::new`, so a
            // pattern that passes here can never be silently dropped at runtime.
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!("injection_seeds_custom[{i}]: invalid regex '{trimmed}': {e}"),
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

    // Day-based thresholds: must be > 0 to be meaningful (0 disables the
    // signal in the same way `None` does, but is silently misleading)
    if let Some(d) = pp.block_newer_than_days {
        if d == 0 {
            issues.push(PolicyIssue {
                level: IssueLevel::Warning,
                message: "package_policy.block_newer_than_days: 0 disables the block path; \
                          omit the field instead for clarity"
                    .into(),
                field: Some("package_policy.block_newer_than_days".into()),
            });
        }
    }
    if let Some(d) = pp.warn_newer_than_days {
        if d == 0 {
            issues.push(PolicyIssue {
                level: IssueLevel::Warning,
                message: "package_policy.warn_newer_than_days: 0 disables the warn path; \
                          omit the field instead for clarity"
                    .into(),
                field: Some("package_policy.warn_newer_than_days".into()),
            });
        }
    }

    // If both set, the Block age window must be stricter (smaller) than Warn.
    if let (Some(b), Some(w)) = (pp.block_newer_than_days, pp.warn_newer_than_days) {
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

    // Validate DLP patterns compile
    for (i, pattern) in policy.dlp_custom_patterns.iter().enumerate() {
        if let Err(e) = regex::Regex::new(pattern) {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!("dlp_custom_patterns[{i}]: invalid regex '{pattern}': {e}"),
                field: Some(format!("dlp_custom_patterns[{i}]")),
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
    // Hostnames (domain-like strings).
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '*')
        && !s.is_empty()
    {
        return true;
    }

    // CIDR: split on '/' for the prefix length.
    if let Some((ip_part, prefix)) = s.split_once('/') {
        let Ok(prefix_len) = prefix.parse::<u32>() else {
            return false;
        };
        if ip_part.contains('.') {
            return prefix_len <= 32 && parse_ipv4(ip_part);
        }
        if ip_part.contains(':') {
            return prefix_len <= 128 && parse_ipv6(ip_part);
        }
        return false;
    }

    // Plain IP.
    if s.contains(':') {
        return parse_ipv6(s);
    }
    if s.contains('.') && s.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return parse_ipv4(s);
    }

    false
}

fn parse_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            p.parse::<u8>().is_ok() || (*p == "0" || p.parse::<u16>().is_ok_and(|n| n <= 255))
        })
}

fn parse_ipv6(s: &str) -> bool {
    // Basic IPv6 validation: 1-8 groups of hex, with :: allowed once
    let double_colon_count = s.matches("::").count();
    if double_colon_count > 1 {
        return false;
    }
    let groups: Vec<&str> = s.split(':').collect();
    if double_colon_count == 0 && groups.len() != 8 {
        return false;
    }
    if double_colon_count == 1 && groups.len() > 8 {
        return false;
    }
    groups
        .iter()
        .all(|g| g.is_empty() || (g.len() <= 4 && g.chars().all(|c| c.is_ascii_hexdigit())))
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

fn validate_unknown_fields(yaml: &str, issues: &mut Vec<PolicyIssue>) {
    let known_top_level = [
        "schema_version",
        "fail_mode",
        "allow_bypass_env",
        "allow_bypass_env_noninteractive",
        "paranoia",
        "severity_overrides",
        "additional_known_domains",
        "allowlist",
        "blocklist",
        "approval_rules",
        "network_deny",
        "network_allow",
        "webhooks",
        "checkpoints",
        "scan",
        "allowlist_rules",
        "custom_rules",
        "dlp_custom_patterns",
        "injection_seeds_custom",
        "mcp_redact_injection",
        "strict_warn",
        "action_overrides",
        "escalation",
        "policy_server_url",
        "policy_server_api_key",
        "policy_fetch_fail_mode",
        "enforce_fail_mode",
        "threat_intel",
        "agent_rules",
        "package_policy",
    ];

    // A typo here is load-bearing — a misspelled `block_newr_than_days` silently
    // disables the operator's intent — so flag unknown keys.
    let known_package_policy_fields = [
        "block_not_found",
        "block_newer_than_days",
        "warn_newer_than_days",
        "warn_low_downloads_below",
        "block_install_scripts_for_unknown_packages",
        "block_typosquat_distance",
        "block_aggregate_score",
        "warn_aggregate_score",
        "block_osv_min_cvss",
        "block_repo_mismatch",
        "warn_install_script_network_call",
        "block_dependency_confusion",
        "internal_package_names",
        "repo_mismatch_check_max_packages",
    ];
    let known_internal_package_spec_fields = ["ecosystem", "name"];

    let known_scan_fields = [
        "additional_config_files",
        "trusted_mcp_servers",
        "mcp_allowed_tools",
        "ignore_patterns",
        "fail_on",
        "profiles",
    ];
    let known_checkpoint_fields = ["max_count", "max_age_hours", "max_storage_bytes"];
    // PR #121 fix-list item 10 — the `allow`/`deny` children were never
    // validated, so `agent_rules: { denyy: [...] }` passed silently and the
    // intended block never fired. Lists mirror `policy.rs` AgentRules/AgentMatcher.
    let known_agent_rules_fields = ["allow", "deny"];
    // `kind` + `name` plus the optional semantic predicates.
    let known_agent_matcher_fields = [
        "kind",
        "name",
        "filesystem_write",
        "network",
        "secrets_access",
    ];

    if let Ok(serde_yaml::Value::Mapping(map)) = serde_yaml::from_str::<serde_yaml::Value>(yaml) {
        for (key, value) in &map {
            if let serde_yaml::Value::String(k) = key {
                if !known_top_level.contains(&k.as_str()) {
                    issues.push(PolicyIssue {
                        level: IssueLevel::Warning,
                        message: format!("unknown field '{k}'"),
                        field: Some(k.clone()),
                    });
                }

                if k == "scan" {
                    if let serde_yaml::Value::Mapping(sub_map) = value {
                        let known_profile_fields = ["include", "exclude", "fail_on", "ignore"];
                        for (sub_key, sub_val) in sub_map {
                            if let serde_yaml::Value::String(sk) = sub_key {
                                if !known_scan_fields.contains(&sk.as_str()) {
                                    issues.push(PolicyIssue {
                                        level: IssueLevel::Warning,
                                        message: format!("unknown field 'scan.{sk}'"),
                                        field: Some(format!("scan.{sk}")),
                                    });
                                }
                                if sk == "profiles" {
                                    if let serde_yaml::Value::Mapping(profiles) = sub_val {
                                        for (pname, pval) in profiles {
                                            let pname_str = match pname {
                                                serde_yaml::Value::String(s) => s.clone(),
                                                _ => continue,
                                            };
                                            if let serde_yaml::Value::Mapping(pfields) = pval {
                                                for pkey in pfields.keys() {
                                                    if let serde_yaml::Value::String(pk) = pkey {
                                                        if !known_profile_fields
                                                            .contains(&pk.as_str())
                                                        {
                                                            issues.push(PolicyIssue {
                                                                level: IssueLevel::Warning,
                                                                message: format!(
                                                                    "unknown field 'scan.profiles.{pname_str}.{pk}'"
                                                                ),
                                                                field: Some(format!(
                                                                    "scan.profiles.{pname_str}.{pk}"
                                                                )),
                                                            });
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if k == "checkpoints" {
                    if let serde_yaml::Value::Mapping(sub_map) = value {
                        for sub_key in sub_map.keys() {
                            if let serde_yaml::Value::String(sk) = sub_key {
                                if !known_checkpoint_fields.contains(&sk.as_str()) {
                                    issues.push(PolicyIssue {
                                        level: IssueLevel::Warning,
                                        message: format!("unknown field 'checkpoints.{sk}'"),
                                        field: Some(format!("checkpoints.{sk}")),
                                    });
                                }
                            }
                        }
                    }
                }

                if k == "package_policy" {
                    if let serde_yaml::Value::Mapping(sub_map) = value {
                        for (sub_key, sub_val) in sub_map {
                            let serde_yaml::Value::String(sk) = sub_key else {
                                continue;
                            };
                            if !known_package_policy_fields.contains(&sk.as_str()) {
                                issues.push(PolicyIssue {
                                    level: IssueLevel::Warning,
                                    message: format!("unknown field 'package_policy.{sk}'"),
                                    field: Some(format!("package_policy.{sk}")),
                                });
                                continue;
                            }
                            // Recurse into internal_package_names entries
                            // ({ecosystem, name}); a typo silently drops the entry.
                            if sk == "internal_package_names" {
                                if let serde_yaml::Value::Sequence(seq) = sub_val {
                                    for (i, item) in seq.iter().enumerate() {
                                        let serde_yaml::Value::Mapping(spec) = item else {
                                            continue;
                                        };
                                        for skey in spec.keys() {
                                            let serde_yaml::Value::String(sk2) = skey else {
                                                continue;
                                            };
                                            if !known_internal_package_spec_fields
                                                .contains(&sk2.as_str())
                                            {
                                                issues.push(PolicyIssue {
                                                    level: IssueLevel::Warning,
                                                    message: format!(
                                                        "unknown field 'package_policy.internal_package_names[{i}].{sk2}'"
                                                    ),
                                                    field: Some(format!(
                                                        "package_policy.internal_package_names[{i}].{sk2}"
                                                    )),
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // PR #121 fix-list item 10 — validate the nested
                // `agent_rules.{allow,deny}` keys and each matcher's keys; a typo
                // at either level used to be dropped silently (a no-op rule).
                if k == "agent_rules" {
                    if let serde_yaml::Value::Mapping(sub_map) = value {
                        for (sub_key, sub_val) in sub_map {
                            let serde_yaml::Value::String(sk) = sub_key else {
                                continue;
                            };
                            if !known_agent_rules_fields.contains(&sk.as_str()) {
                                issues.push(PolicyIssue {
                                    level: IssueLevel::Warning,
                                    message: format!("unknown field 'agent_rules.{sk}'"),
                                    field: Some(format!("agent_rules.{sk}")),
                                });
                                continue;
                            }
                            // Recurse into each matcher and flag unknown fields.
                            if let serde_yaml::Value::Sequence(seq) = sub_val {
                                for (i, item) in seq.iter().enumerate() {
                                    let serde_yaml::Value::Mapping(matcher) = item else {
                                        continue;
                                    };
                                    for mkey in matcher.keys() {
                                        let serde_yaml::Value::String(mk) = mkey else {
                                            continue;
                                        };
                                        if !known_agent_matcher_fields.contains(&mk.as_str()) {
                                            issues.push(PolicyIssue {
                                                level: IssueLevel::Warning,
                                                message: format!(
                                                    "unknown field 'agent_rules.{sk}[{i}].{mk}'"
                                                ),
                                                field: Some(format!("agent_rules.{sk}[{i}].{mk}")),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
