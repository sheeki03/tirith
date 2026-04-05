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

    // Phase 1: serde structural parse
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

    // Phase 2: semantic validation
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

    // Phase 3: check for unknown top-level and nested fields
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

        // Validate regex compiles
        if let Err(e) = regex::Regex::new(&rule.pattern) {
            issues.push(PolicyIssue {
                level: IssueLevel::Error,
                message: format!(
                    "custom_rules.{}: invalid regex '{}': {e}",
                    rule.id, rule.pattern
                ),
                field: Some(format!("custom_rules.{}.pattern", rule.id)),
            });
        }

        // Validate contexts
        let valid_contexts = ["exec", "paste", "file"];
        for ctx in &rule.context {
            if !valid_contexts.contains(&ctx.as_str()) {
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
    }
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

fn validate_unknown_fields(yaml: &str, issues: &mut Vec<PolicyIssue>) {
    let known_top_level = [
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
    ];

    // Known fields for nested objects
    let known_scan_fields = [
        "additional_config_files",
        "trusted_mcp_servers",
        "ignore_patterns",
        "fail_on",
        "profiles",
    ];
    let known_checkpoint_fields = ["max_count", "max_age_hours", "max_storage_bytes"];

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
    fn test_unknown_field() {
        let yaml = "not_a_real_field: true\n";
        let issues = validate(yaml);
        assert!(issues.iter().any(|i| i.message.contains("unknown field")));
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
}
