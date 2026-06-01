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
        // Check if the key is a valid RuleId
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

        // Validate contexts (shared by both rule shapes). Run BEFORE the regex
        // checks so `has_invalid_context` is set and the regex empty-context
        // check below can skip a list that only had bogus tokens (already
        // reported here) — same double-report discipline `rule validate` uses.
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

        // Validate a REGEX rule by mirroring `rules::custom::compile_rules`
        // EXACTLY, in the SAME ORDER, so `policy validate` never green-lights a
        // regex rule the engine silently DROPS at runtime (CodeRabbit M13). The
        // engine drops a regex rule for, in order: (1) no valid contexts after
        // filtering, (2) pattern over the 1024-CHAR cap, (3) invalid regex
        // syntax. The earlier "validate the regex compiles" block ran first and
        // checked only (3); (1) and (2) were missing, so a rule with an empty
        // context set or an over-cap pattern validated as "valid" yet never ran.
        if let Some(pattern) = &rule.pattern {
            // (1) No valid contexts. A regex rule has no required-trigger notion
            //     to synthesize an executable set from, so an empty filtered
            //     context set is a dead rule that `compile_rules` drops. Skip
            //     when a token was INVALID (already reported above; a bogus-only
            //     list would otherwise double-report — same discipline as the
            //     DSL coverage check and `rule validate`).
            let parsed = parse_declared_contexts(&rule.context);
            if parsed.is_empty() && !has_invalid_context {
                issues.push(PolicyIssue {
                    level: IssueLevel::Error,
                    message: format!(
                        "custom_rules.{}: no valid contexts (regex rule needs at least one of: exec, paste, file)",
                        rule.id
                    ),
                    field: Some(format!("custom_rules.{}.context", rule.id)),
                });
            }
            // (2) Pattern length cap. Measure in CHARACTERS, not UTF-8 BYTES, to
            //     mirror `compile_rules` / `check_regex` (CodeRabbit M13
            //     round-26): a multibyte pattern must not trip the cap early or
            //     report a misleading byte count.
            if pattern.chars().count() > 1024 {
                issues.push(PolicyIssue {
                    level: IssueLevel::Error,
                    message: format!(
                        "custom_rules.{}: pattern too long ({} chars, max 1024)",
                        rule.id,
                        pattern.chars().count()
                    ),
                    field: Some(format!("custom_rules.{}.pattern", rule.id)),
                });
            }
            // (3) Regex must compile. Done LAST (after the cap) so the same
            //     ordering as `compile_rules` is preserved.
            if let Err(e) = regex::Regex::new(pattern) {
                issues.push(PolicyIssue {
                    level: IssueLevel::Error,
                    message: format!("custom_rules.{}: invalid regex '{}': {e}", rule.id, pattern),
                    field: Some(format!("custom_rules.{}.pattern", rule.id)),
                });
            }
        }

        // Validate the `when:` clause (M13 ch4 DSL): inner regexes must compile
        // and the declared context must cover the clause's required trigger
        // groups (the tier-1 invariant — predicates need their data extracted).
        if let Some(when) = &rule.when {
            if let Err(e) = crate::custom_rule_dsl::validate_regexes(when) {
                issues.push(PolicyIssue {
                    level: IssueLevel::Error,
                    message: format!("custom_rules.{}: invalid when-clause: {e}", rule.id),
                    field: Some(format!("custom_rules.{}.when", rule.id)),
                });
            }
            // Reject a clause that uses a predicate no scan context can satisfy
            // (`mcp.tool` and `agent.kind` — neither signal is wired into the
            // scan context, so the rule would validate+load yet never match).
            // CodeRabbit M13 round-3 R3-3 (`mcp.tool`) + round-8 R8-1
            // (`agent.kind`; use `agent_rules` for per-agent control instead).
            // Done FIRST so an `agent.kind`/`mcp.tool` clause never reaches the
            // satisfiable-context check below (its set would be empty).
            let unsupported = crate::custom_rule_dsl::clause_uses_unsupported_predicate(when);
            if let Some(reason) = unsupported {
                issues.push(PolicyIssue {
                    level: IssueLevel::Error,
                    message: format!("custom_rules.{}: {reason}", rule.id),
                    field: Some(format!("custom_rules.{}.when", rule.id)),
                });
            }
            // Per-clause satisfiability + coverage (CodeRabbit M13 round-9 R9-1).
            // `satisfiable_contexts` computes the scan contexts in which the WHOLE
            // clause can be evaluated — `all` intersects children, `any` unions,
            // `not` is the child's set — so combinators keep their semantics. Two
            // independent failures:
            //   (1) An EMPTY satisfiable set means the clause needs facts from
            //       contexts that never co-occur in a single scan (e.g. command +
            //       file via `all`) — it can NEVER match. Reject as unsatisfiable,
            //       independent of the declared context. Skip only when the clause
            //       used an unsupported predicate (already reported just above;
            //       that predicate's empty set would otherwise double-report).
            //   (2) Otherwise the declared context must intersect the satisfiable
            //       set (`declared ∩ satisfiable ≠ ∅`) — at least one declared
            //       context can evaluate the clause. An empty `context: []` here
            //       has no intersection and is rejected (CodeRabbit M13 finding D).
            //       Skipped when a context token was INVALID (reported above; the
            //       dropped token would otherwise look like an uncovered context).
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
                // Route through the SAME shared resolver `compile_rules` and
                // `rule validate` use (`resolve_runtime_contexts` = `declared ∩
                // satisfiable`) so the engine and both validators classify a rule
                // IDENTICALLY (CodeRabbit M13 round-15). `parse_declared_contexts`
                // already carries serde's empty-→-`[exec, paste]` default for an
                // OMITTED `context:`, so a no-context `command.*` rule is ACCEPTED
                // (resolves to a non-empty `{exec, paste}`) while a no-context
                // `file.path_matches` rule is REJECTED (resolves to the empty
                // `{exec, paste} ∩ {file}`). An explicit `context: []` (which
                // serde does NOT default) likewise resolves empty and is rejected
                // (finding D).
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

    // Block must not be greater than Warn — if both are set, Block requires
    // a stricter (smaller) age window than Warn.
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

    // Typosquat distance: 1..=10 is the practical range; anything else is
    // either useless (0) or matches every package (>10).
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
    // Allow hostnames (domain-like strings)
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '*')
        && !s.is_empty()
    {
        return true;
    }

    // Allow IP/CIDR: split on '/' for CIDR prefix
    if let Some((ip_part, prefix)) = s.split_once('/') {
        // Validate prefix length
        let Ok(prefix_len) = prefix.parse::<u32>() else {
            return false;
        };
        // IPv4 CIDR
        if ip_part.contains('.') {
            return prefix_len <= 32 && parse_ipv4(ip_part);
        }
        // IPv6 CIDR
        if ip_part.contains(':') {
            return prefix_len <= 128 && parse_ipv6(ip_part);
        }
        return false;
    }

    // Plain IP
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
        // Validate value: only "block" is allowed
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

        // Validate key is a known RuleId
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

/// Sanity-check the agent governance block (M4 item 8). This is
/// **schema validation only** — the engine consumes `agent_rules` at
/// runtime via [`crate::escalation::apply_agent_rules`], but the
/// validator's job is limited to flagging matchers shaped wrong
/// (e.g. a `name` filter on a payloadless kind), not predicting whether
/// a matcher will ever fire in practice.
///
/// Diagnostics:
/// * A `name` filter on a payloadless kind (`human`, `gateway`) is a
///   warning — it matches nothing by construction. The decision helper
///   in `policy.rs` is deterministic about that, but the operator most
///   likely meant a different `kind` or no `name` filter at all.
/// * An empty `name` string (`name: ""`) is a warning — a zero-length
///   match accepts only a payload that itself sanitized to empty, which
///   the `AgentOrigin` constructors reject up-front.
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

            // Unenforced semantic predicates (CodeRabbit M13 round-15
            // policy_validate.rs:744). `filesystem_write` / `network` /
            // `secrets_access` are accepted as known matcher keys and load fine,
            // but `policy.rs::matcher_matches` decides on `kind` + `name` ONLY —
            // it never reads these. So a hand-written entry like
            // `agent_rules: { deny: [{ kind: agent, network: block }] }` LOOKS
            // conditional, yet the `network: block` predicate is silently dropped
            // at runtime (matching is still constrained by `kind` and any `name`).
            // Warn (not error: the field is legal advisory metadata an operator may
            // declare in policy YAML, and the round-12 `agent block` CLI gate is the
            // enforced path). Emit one warning per present predicate.
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
        "strict_warn",
        "action_overrides",
        "escalation",
        "policy_server_url",
        "policy_server_api_key",
        "policy_fetch_fail_mode",
        "enforce_fail_mode",
        "threat_intel",
        "agent_rules",
        // M6 ch7 — package-policy section
        "package_policy",
    ];

    // Known fields under package_policy (M6 ch7). A typo at this level is
    // load-bearing — a misspelled `block_newr_than_days` silently disables
    // the operator's intent — so flag unknown keys.
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

    // Known fields for nested objects
    let known_scan_fields = [
        "additional_config_files",
        "trusted_mcp_servers",
        "mcp_allowed_tools",
        "ignore_patterns",
        "fail_on",
        "profiles",
    ];
    let known_checkpoint_fields = ["max_count", "max_age_hours", "max_storage_bytes"];
    // PR #121 fix-list item 10 — `agent_rules` is in `known_top_level` but
    // its children (`allow`/`deny`) were never validated. A typo like
    // `agent_rules: { denyy: [...] }` then passed silently and the
    // operator's intended block never fired. The lists below mirror
    // `policy.rs::AgentRules` and `policy.rs::AgentMatcher`.
    let known_agent_rules_fields = ["allow", "deny"];
    // `kind` + `name` (pre-M13) plus the M13 ch5 optional semantic predicates.
    let known_agent_matcher_fields = [
        "kind",
        "name",
        "filesystem_write",
        "network",
        "secrets_access",
    ];

    // Parse as generic YAML value to check top-level keys
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

                // Check nested fields for known sub-objects
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
                                // Validate scan.profiles.<name>.* keys
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
                            // Recurse into internal_package_names entries —
                            // each is an `InternalPackageSpec { ecosystem, name }`
                            // map. A typo silently drops the entry, so flag.
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
                // `agent_rules.{allow,deny}` keys and each matcher object's
                // (`kind`, `name`) keys. A typo at either level was
                // silently dropped pre-fix, e.g.
                //   agent_rules: { denyy: [...] }                  (top key)
                //   agent_rules: { deny: [{ kind: agent, namee: x }] }  (matcher key)
                // both used to pass `validate`; the policy then loaded
                // with the typo'd field discarded and the operator never
                // knew their rule was a no-op.
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
                            // For known `allow` / `deny` lists, recurse
                            // into each matcher object and flag unknown
                            // matcher fields. The fields on
                            // `policy::AgentMatcher` are `kind` and `name`.
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
        // CodeRabbit M13 round-27 (outside-diff): `policy validate` must mirror
        // `compile_rules`, which DROPS a regex rule whose filtered context set is
        // empty. An explicit `context: []` (serde does NOT default it) filters to
        // the empty set, so the engine never runs the rule — `policy validate`
        // must report this as an Error instead of green-lighting it. (An OMITTED
        // `context:` defaults to [exec, paste] and is NOT affected — see
        // `test_custom_rule_bad_regex`, which omits context and only flags the
        // regex.)
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
    fn test_custom_regex_rule_pattern_too_long_rejected() {
        // CodeRabbit M13 round-27: `compile_rules` drops a regex `pattern` over
        // the 1024-CHAR cap, so `policy validate` must flag it as an Error.
        // 1025 single-byte chars trips the cap unambiguously (the engine uses
        // `pattern.chars().count()`, not byte length — round-26).
        let pattern = "a".repeat(1025);
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
    }

    #[test]
    fn test_custom_regex_rule_multibyte_pattern_under_char_cap_accepted() {
        // CodeRabbit M13 round-26 + round-27: the 1024 cap counts CHARACTERS, not
        // UTF-8 BYTES. A multibyte pattern that is <=1024 CHARS but >1024 BYTES
        // must be ACCEPTED (it would be wrongly dropped by a byte-length cap),
        // proving `policy validate` uses `pattern.chars().count()` like the
        // engine. 'é' (U+00E9) is 2 bytes; 600 of them is 600 chars / 1200 bytes
        // — under the 1024-CHAR cap, over a 1024-BYTE one. A repeated literal is
        // a cheap, valid regex (no pathological backtracking in debug).
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
    fn test_unknown_field() {
        let yaml = "not_a_real_field: true\n";
        let issues = validate(yaml);
        assert!(issues.iter().any(|i| i.message.contains("unknown field")));
    }

    #[test]
    fn test_dsl_rule_empty_context_rejected() {
        // Regression (CodeRabbit M13 finding D): a DSL rule with an explicitly
        // empty `context: []` and a `command.*` predicate is a silent no-op —
        // its predicates can never see the data they reference — and must be
        // rejected. The previous `!declared.is_empty()` guard let it pass.
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
        // The always-on coverage check must also reject an empty context for a
        // file-family predicate (a different required group than command/url).
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
        // When `context:` is OMITTED it defaults to [exec, paste] (NOT empty),
        // so a url-family rule is covered and accepted. This is the
        // counterpoint to the explicit `context: []` no-op above — finding D is
        // about the EXPLICIT empty list, not the defaulted one.
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
        // CodeRabbit M13 round-15 rule.rs:338 + policy_validate consistency: an
        // OMITTED `context:` defaults (via serde) to [exec, paste], so it must be
        // resolved THROUGH that default — not treated as raw-empty. A no-context
        // `command.*` rule therefore RESOLVES to {exec, paste} and is ACCEPTED
        // (the engine compiles+runs it), while a no-context `file.path_matches`
        // rule resolves to {exec, paste} ∩ {file} = ∅ and is correctly REJECTED
        // (it can never fire). Validity is computed the SAME way compile_rules
        // resolves+clamps, so all three agree.
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
        // CodeRabbit M13 round-15 policy_validate.rs:744: `filesystem_write` /
        // `network` / `secrets_access` are recognized matcher keys but
        // `matcher_matches` ignores them (matching is kind+name only). A
        // conditional-LOOKING matcher carrying one of them is an unconditional
        // allow/deny at runtime, so `policy validate` must emit a WARNING (not an
        // error, not silence).
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
        // A plain kind+name matcher carries no advisory predicates, so it must
        // NOT trigger the unenforced-predicate warning.
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
        // An invalid context value is reported as its own issue; we must NOT
        // also emit a trigger-coverage error for the same typo (the unknown
        // token is dropped, which would otherwise look like an unmet
        // requirement). Exactly one error mentions the rule, and it is the
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
        // CodeRabbit M13 round-8 R8-1: an `agent.kind` clause reads a
        // `DslEvalContext` field the engine hard-codes to `None`, so it can never
        // match — `policy validate` must REJECT it (like `mcp.tool`), with a
        // clear message that points at `agent_rules`. (Round-3 R3-9 had kept it
        // valid; that is reversed here.) Cover both a bare clause and one nested
        // in an `all:`.
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
        // CodeRabbit M13 round-3 R3-3: a `when:` clause using `mcp.tool` must be
        // REJECTED — no scan context wires up an MCP-tool signal, so the rule
        // would validate+load yet never match. The error must be clear.
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
        // CodeRabbit M13 round-3 R3-1: a `command.*` predicate under `paste`
        // context is now VALID (build_dsl_backing fills command facts for paste),
        // so it must NOT produce a coverage error. Agrees with `rule validate`.
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
        // CodeRabbit M13 round-9 R9-1: `all(command.*, file.*)` mixes facts from
        // contexts that never co-occur in a single scan (command -> exec/paste,
        // file -> FileScan), so its satisfiable set is the EMPTY intersection. It
        // can never match and must be rejected with the dedicated
        // "never co-occur" message -- NOT the generic coverage message -- even
        // though the rule declares BOTH contexts. The old leaf-flatten accepted
        // both-contexts here.
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
        // CodeRabbit M13 round-9 R9-1: `any(command.*, file.*)` is evaluable
        // wherever EITHER branch is (the UNION), so a single-context rule is
        // covered by whichever branch is live there and must be ACCEPTED. The old
        // leaf-flatten rejected it. Cover the command-branch context.
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

    // -----------------------------------------------------------------------
    // PR #121 fix-list item 10 — nested `agent_rules.*` unknown-field
    // validation. Pre-fix a typo on the `allow`/`deny` slot or on a matcher
    // field (`kind`/`name`) was silently dropped; the operator's intended
    // rule then never fired but no warning surfaced.
    // -----------------------------------------------------------------------

    #[test]
    fn test_agent_rules_unknown_sub_key_warns() {
        // `denyy` instead of `deny` — pre-fix this passed silently, the
        // matcher list was dropped, and the policy looked "valid".
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
        // A typo on the matcher object itself (`namee` instead of `name`)
        // — the matcher then deserialized as `{kind: agent, name: None}`,
        // matched every Agent caller, and the operator's intent was lost.
        // Note: a matcher with `name: None` does NOT trigger
        // "matches nothing" (that's only fired on Human/Gateway), so the
        // pre-fix path emitted zero warnings.
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
