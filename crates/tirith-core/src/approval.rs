use std::io::Write;
use std::path::PathBuf;

use crate::policy::{ApprovalRule, Policy};
use crate::verdict::Verdict;

/// Approval metadata extracted from a verdict + policy.
#[derive(Debug, Clone)]
pub struct ApprovalMetadata {
    pub requires_approval: bool,
    pub timeout_secs: u64,
    pub fallback: String,
    pub rule_id: String,
    pub description: String,
}

/// Check whether a verdict triggers any approval rules from the policy.
///
/// Returns `Some(ApprovalMetadata)` if approval is required, `None` otherwise.
/// This is a Team-tier feature: callers should gate on tier before calling.
pub fn check_approval(verdict: &Verdict, policy: &Policy) -> Option<ApprovalMetadata> {
    if policy.approval_rules.is_empty() {
        return None;
    }

    // Check each finding's rule_id against approval_rules
    for finding in &verdict.findings {
        let finding_rule_str = finding.rule_id.to_string();
        for approval_rule in &policy.approval_rules {
            if approval_rule_matches(&finding_rule_str, approval_rule) {
                let description = if finding.description.is_empty() {
                    finding.title.clone()
                } else {
                    finding.description.clone()
                };
                return Some(ApprovalMetadata {
                    requires_approval: true,
                    timeout_secs: approval_rule.timeout_secs,
                    fallback: approval_rule.fallback.clone(),
                    rule_id: finding_rule_str,
                    description: sanitize_description(&description),
                });
            }
        }
    }

    None
}

/// Apply approval metadata to a verdict (mutates in place).
pub fn apply_approval(verdict: &mut Verdict, metadata: &ApprovalMetadata) {
    verdict.requires_approval = Some(metadata.requires_approval);
    verdict.approval_timeout_secs = Some(metadata.timeout_secs);
    verdict.approval_fallback = Some(metadata.fallback.clone());
    verdict.approval_rule = Some(metadata.rule_id.clone());
    verdict.approval_description = Some(metadata.description.clone());
}

/// Write approval metadata to a secure temp file.
///
/// Returns the path to the temp file. The caller is responsible for printing
/// this path to stdout. The temp file is persisted (not auto-deleted) so
/// shell hooks can read it after tirith exits.
///
/// Per ADR-7: file is created with O_EXCL + O_CREAT (via tempfile crate),
/// mode 0600 on Unix, and `.keep()` is called before returning.
pub fn write_approval_file(metadata: &ApprovalMetadata) -> Result<PathBuf, std::io::Error> {
    let mut tmp = tempfile::Builder::new()
        .prefix("tirith-approval-")
        .suffix(".env")
        .tempfile()?;

    // Set permissions to 0600 on Unix before writing content
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(tmp.path(), perms)?;
    }

    // Write key=value pairs
    writeln!(
        tmp,
        "TIRITH_REQUIRES_APPROVAL={}",
        if metadata.requires_approval {
            "yes"
        } else {
            "no"
        }
    )?;
    writeln!(tmp, "TIRITH_APPROVAL_TIMEOUT={}", metadata.timeout_secs)?;
    writeln!(
        tmp,
        "TIRITH_APPROVAL_FALLBACK={}",
        sanitize_fallback(&metadata.fallback)
    )?;
    writeln!(
        tmp,
        "TIRITH_APPROVAL_RULE={}",
        sanitize_rule_id(&metadata.rule_id)
    )?;
    writeln!(
        tmp,
        "TIRITH_APPROVAL_DESCRIPTION={}",
        sanitize_description(&metadata.description)
    )?;

    tmp.flush()?;

    // Persist the file (prevent auto-delete on drop)
    let (_, path) = tmp.keep().map_err(|e| e.error)?;
    Ok(path)
}

/// Write a "no approval required" temp file for the common case.
pub fn write_no_approval_file() -> Result<PathBuf, std::io::Error> {
    let mut tmp = tempfile::Builder::new()
        .prefix("tirith-approval-")
        .suffix(".env")
        .tempfile()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(tmp.path(), perms)?;
    }

    writeln!(tmp, "TIRITH_REQUIRES_APPROVAL=no")?;
    tmp.flush()?;

    let (_, path) = tmp.keep().map_err(|e| e.error)?;
    Ok(path)
}

/// Check if a finding's rule_id string matches an approval rule.
fn approval_rule_matches(rule_id_str: &str, approval_rule: &ApprovalRule) -> bool {
    approval_rule.rule_ids.iter().any(|r| r == rule_id_str)
}

/// Sanitize a description string per ADR-7.
///
/// Allowlist: `[A-Za-z0-9 .,_:/()\-']`. All other characters stripped.
/// Consecutive spaces collapsed. Max 200 bytes, truncated with `...`.
pub fn sanitize_description(input: &str) -> String {
    let filtered: String = input
        .chars()
        .filter(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    ' ' | '.' | ',' | '_' | ':' | '/' | '(' | ')' | '-' | '\''
                )
        })
        .collect();

    // Collapse consecutive spaces
    let mut result = String::with_capacity(filtered.len());
    let mut prev_space = false;
    for c in filtered.chars() {
        if c == ' ' {
            if !prev_space {
                result.push(c);
            }
            prev_space = true;
        } else {
            result.push(c);
            prev_space = false;
        }
    }

    // Truncate to 200 bytes
    if result.len() > 200 {
        // Find a safe UTF-8 boundary
        let mut end = 197;
        while end > 0 && !result.is_char_boundary(end) {
            end -= 1;
        }
        result.truncate(end);
        result.push_str("...");
    }

    result
}

/// Sanitize the approval fallback value per ADR-7.
///
/// Only "block", "warn", and "allow" are valid. Any other value
/// (including values containing newlines, `=`, or shell metacharacters)
/// defaults to "block" for fail-closed safety.
fn sanitize_fallback(input: &str) -> &'static str {
    match input.trim().to_lowercase().as_str() {
        "block" => "block",
        "warn" => "warn",
        "allow" => "allow",
        _ => "block",
    }
}

/// Sanitize a rule_id to `[a-z_]+`, max 64 chars.
fn sanitize_rule_id(input: &str) -> String {
    let filtered: String = input
        .chars()
        .filter(|c| c.is_ascii_lowercase() || *c == '_')
        .take(64)
        .collect();
    filtered
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ApprovalRule;
    use crate::verdict::{Action, Evidence, Finding, RuleId, Severity, Timings, Verdict};

    fn make_verdict(rule_id: RuleId, severity: Severity) -> Verdict {
        Verdict {
            action: Action::Block,
            findings: vec![Finding {
                rule_id,
                severity,
                title: "Test finding".to_string(),
                description: "A test finding description".to_string(),
                evidence: vec![Evidence::Text {
                    detail: "test".to_string(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            tier_reached: 3,
            bypass_requested: false,
            bypass_honored: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: Timings::default(),
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
        }
    }

    fn make_policy_with_approval(rule_ids: &[&str]) -> Policy {
        let mut policy = Policy::default();
        policy.approval_rules.push(ApprovalRule {
            rule_ids: rule_ids.iter().map(|s| s.to_string()).collect(),
            timeout_secs: 30,
            fallback: "block".to_string(),
        });
        policy
    }

    #[test]
    fn test_check_approval_matches() {
        let verdict = make_verdict(RuleId::CurlPipeShell, Severity::High);
        let policy = make_policy_with_approval(&["curl_pipe_shell"]);

        let meta = check_approval(&verdict, &policy);
        assert!(meta.is_some());
        let meta = meta.unwrap();
        assert!(meta.requires_approval);
        assert_eq!(meta.timeout_secs, 30);
        assert_eq!(meta.fallback, "block");
        assert_eq!(meta.rule_id, "curl_pipe_shell");
    }

    #[test]
    fn test_check_approval_no_match() {
        let verdict = make_verdict(RuleId::NonAsciiHostname, Severity::Medium);
        let policy = make_policy_with_approval(&["curl_pipe_shell"]);

        let meta = check_approval(&verdict, &policy);
        assert!(meta.is_none());
    }

    #[test]
    fn test_check_approval_empty_rules() {
        let verdict = make_verdict(RuleId::CurlPipeShell, Severity::High);
        let policy = Policy::default(); // no approval_rules

        let meta = check_approval(&verdict, &policy);
        assert!(meta.is_none());
    }

    #[test]
    fn test_sanitize_description_basic() {
        assert_eq!(
            sanitize_description("Normal text with (parens) and 123"),
            "Normal text with (parens) and 123"
        );
    }

    #[test]
    fn test_sanitize_description_strips_dangerous() {
        assert_eq!(
            sanitize_description("echo $HOME; rm -rf /; `whoami`"),
            "echo HOME rm -rf / whoami"
        );
    }

    #[test]
    fn test_sanitize_description_collapses_spaces() {
        assert_eq!(
            sanitize_description("too   many    spaces"),
            "too many spaces"
        );
    }

    #[test]
    fn test_sanitize_description_truncates() {
        let long = "a".repeat(300);
        let result = sanitize_description(&long);
        assert!(result.len() <= 200);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_sanitize_rule_id() {
        // Normal snake_case (from serde serialization) passes through
        assert_eq!(sanitize_rule_id("curl_pipe_shell"), "curl_pipe_shell");
        // Uppercase letters are stripped (only [a-z_] allowed)
        assert_eq!(sanitize_rule_id("CurlPipeShell"), "urlipehell");
        // Truncates to 64 chars
        assert_eq!(sanitize_rule_id(&"a".repeat(100)), "a".repeat(64));
    }

    #[test]
    fn test_sanitize_fallback() {
        assert_eq!(sanitize_fallback("block"), "block");
        assert_eq!(sanitize_fallback("warn"), "warn");
        assert_eq!(sanitize_fallback("allow"), "allow");
        assert_eq!(sanitize_fallback("BLOCK"), "block");
        assert_eq!(sanitize_fallback("  warn  "), "warn");
        // Malicious values default to "block"
        assert_eq!(sanitize_fallback("block\nINJECTED=yes"), "block");
        assert_eq!(
            sanitize_fallback("allow\r\nTIRITH_REQUIRES_APPROVAL=no"),
            "block"
        );
        assert_eq!(sanitize_fallback(""), "block");
        assert_eq!(sanitize_fallback("invalid"), "block");
    }

    #[test]
    fn test_apply_approval() {
        let mut verdict = make_verdict(RuleId::CurlPipeShell, Severity::High);
        let meta = ApprovalMetadata {
            requires_approval: true,
            timeout_secs: 60,
            fallback: "warn".to_string(),
            rule_id: "curl_pipe_shell".to_string(),
            description: "Pipe to shell detected".to_string(),
        };
        apply_approval(&mut verdict, &meta);

        assert_eq!(verdict.requires_approval, Some(true));
        assert_eq!(verdict.approval_timeout_secs, Some(60));
        assert_eq!(verdict.approval_fallback.as_deref(), Some("warn"));
        assert_eq!(verdict.approval_rule.as_deref(), Some("curl_pipe_shell"));
    }

    #[test]
    fn test_write_approval_file() {
        let meta = ApprovalMetadata {
            requires_approval: true,
            timeout_secs: 30,
            fallback: "block".to_string(),
            rule_id: "curl_pipe_shell".to_string(),
            description: "Pipe to shell detected".to_string(),
        };

        let path = write_approval_file(&meta).expect("write should succeed");
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).expect("read should succeed");
        assert!(content.contains("TIRITH_REQUIRES_APPROVAL=yes"));
        assert!(content.contains("TIRITH_APPROVAL_TIMEOUT=30"));
        assert!(content.contains("TIRITH_APPROVAL_FALLBACK=block"));
        assert!(content.contains("TIRITH_APPROVAL_RULE=curl_pipe_shell"));
        assert!(content.contains("TIRITH_APPROVAL_DESCRIPTION=Pipe to shell detected"));

        // Verify file permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_write_no_approval_file() {
        let path = write_no_approval_file().expect("write should succeed");
        assert!(path.exists());

        let content = std::fs::read_to_string(&path).expect("read should succeed");
        assert!(content.contains("TIRITH_REQUIRES_APPROVAL=no"));
        assert!(!content.contains("TIRITH_APPROVAL_TIMEOUT"));

        let _ = std::fs::remove_file(&path);
    }
}
