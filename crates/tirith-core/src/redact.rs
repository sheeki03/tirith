use once_cell::sync::Lazy;
use regex::Regex;

/// Built-in redaction patterns: (label, regex).
static BUILTIN_PATTERNS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    vec![
        (
            "OpenAI API Key",
            Regex::new(r"sk-[A-Za-z0-9]{20,}").unwrap(),
        ),
        ("AWS Access Key", Regex::new(r"AKIA[A-Z0-9]{16}").unwrap()),
        ("GitHub PAT", Regex::new(r"ghp_[A-Za-z0-9]{36,}").unwrap()),
        (
            "GitHub Server Token",
            Regex::new(r"ghs_[A-Za-z0-9]{36,}").unwrap(),
        ),
        (
            "Anthropic API Key",
            Regex::new(r"sk-ant-[A-Za-z0-9\-]{20,}").unwrap(),
        ),
        (
            "Slack Token",
            Regex::new(r"xox[bprs]-[A-Za-z0-9\-]{10,}").unwrap(),
        ),
        (
            "Email Address",
            Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap(),
        ),
    ]
});

/// Redact sensitive content from a string using built-in patterns.
pub fn redact(input: &str) -> String {
    let mut result = input.to_string();
    for (label, regex) in BUILTIN_PATTERNS.iter() {
        result = regex
            .replace_all(&result, format!("[REDACTED:{label}]"))
            .into_owned();
    }
    result
}

/// Pre-compiled set of custom DLP patterns.
pub struct CompiledCustomPatterns {
    patterns: Vec<Regex>,
}

impl CompiledCustomPatterns {
    /// Compile custom DLP patterns once for reuse across multiple redaction calls.
    pub fn new(raw_patterns: &[String]) -> Self {
        let patterns = raw_patterns
            .iter()
            .filter_map(|pat_str| match Regex::new(pat_str) {
                Ok(re) => Some(re),
                Err(e) => {
                    eprintln!("tirith: warning: invalid custom DLP pattern '{pat_str}': {e}");
                    None
                }
            })
            .collect();
        Self { patterns }
    }
}

/// Redact using both built-in and custom patterns from policy.
pub fn redact_with_custom(input: &str, custom_patterns: &[String]) -> String {
    let mut result = redact(input);
    for pat_str in custom_patterns {
        if pat_str.len() > 1024 {
            eprintln!(
                "tirith: DLP pattern too long ({} chars), skipping",
                pat_str.len()
            );
            continue;
        }
        match Regex::new(pat_str) {
            Ok(re) => {
                result = re.replace_all(&result, "[REDACTED:custom]").into_owned();
            }
            Err(e) => {
                eprintln!("tirith: warning: invalid custom DLP pattern '{pat_str}': {e}");
            }
        }
    }
    result
}

/// Redact using built-in patterns and pre-compiled custom patterns (avoids per-call recompilation).
pub fn redact_with_compiled(input: &str, compiled: &CompiledCustomPatterns) -> String {
    let mut result = redact(input);
    for re in &compiled.patterns {
        result = re.replace_all(&result, "[REDACTED:custom]").into_owned();
    }
    result
}

/// Redact sensitive content from a Finding's string fields in-place.
pub fn redact_finding(finding: &mut crate::verdict::Finding, custom_patterns: &[String]) {
    finding.description = redact_with_custom(&finding.description, custom_patterns);
    if let Some(ref mut v) = finding.human_view {
        *v = redact_with_custom(v, custom_patterns);
    }
    if let Some(ref mut v) = finding.agent_view {
        *v = redact_with_custom(v, custom_patterns);
    }
    for ev in &mut finding.evidence {
        redact_evidence(ev, custom_patterns);
    }
}

fn redact_evidence(ev: &mut crate::verdict::Evidence, custom_patterns: &[String]) {
    use crate::verdict::Evidence;
    match ev {
        Evidence::Url { raw } => {
            *raw = redact_with_custom(raw, custom_patterns);
        }
        Evidence::CommandPattern { matched, .. } => {
            *matched = redact_with_custom(matched, custom_patterns);
        }
        Evidence::EnvVar { value_preview, .. } => {
            *value_preview = redact_with_custom(value_preview, custom_patterns);
        }
        Evidence::Text { detail } => {
            *detail = redact_with_custom(detail, custom_patterns);
        }
        Evidence::ByteSequence { description, .. } => {
            *description = redact_with_custom(description, custom_patterns);
        }
        // HostComparison and HomoglyphAnalysis contain domain names / char analysis, not user content
        _ => {}
    }
}

/// Redact all findings in a verdict in-place.
pub fn redact_verdict(verdict: &mut crate::verdict::Verdict, custom_patterns: &[String]) {
    for f in &mut verdict.findings {
        redact_finding(f, custom_patterns);
    }
}

/// Redact all findings in a slice in-place.
pub fn redact_findings(findings: &mut [crate::verdict::Finding], custom_patterns: &[String]) {
    for f in findings.iter_mut() {
        redact_finding(f, custom_patterns);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_openai_key() {
        let input = "export OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz12345678";
        let redacted = redact(input);
        assert!(!redacted.contains("sk-abcdef"));
        assert!(redacted.contains("[REDACTED:OpenAI API Key]"));
    }

    #[test]
    fn test_redact_aws_key() {
        let input = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let redacted = redact(input);
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(redacted.contains("[REDACTED:AWS Access Key]"));
    }

    #[test]
    fn test_redact_github_pat() {
        let input = "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";
        let redacted = redact(input);
        assert!(!redacted.contains("ghp_ABCDEF"));
        assert!(redacted.contains("[REDACTED:GitHub PAT]"));
    }

    #[test]
    fn test_redact_email() {
        let input = "contact: user@example.com for details";
        let redacted = redact(input);
        assert!(!redacted.contains("user@example.com"));
        assert!(redacted.contains("[REDACTED:Email Address]"));
    }

    #[test]
    fn test_redact_no_false_positive() {
        let input = "normal text without any secrets";
        let redacted = redact(input);
        assert_eq!(input, redacted);
    }

    #[test]
    fn test_redact_with_custom() {
        let input = "internal ref: PROJ-12345 in the system";
        let custom = vec![r"PROJ-\d+".to_string()];
        let redacted = redact_with_custom(input, &custom);
        assert!(!redacted.contains("PROJ-12345"));
        assert!(redacted.contains("[REDACTED:custom]"));
    }

    #[test]
    fn test_redact_anthropic_key() {
        let input = "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnop";
        let redacted = redact(input);
        assert!(!redacted.contains("sk-ant-api03"));
        assert!(redacted.contains("[REDACTED:Anthropic API Key]"));
    }

    #[test]
    fn test_redact_finding_covers_all_fields() {
        use crate::verdict::{Evidence, Finding, RuleId, Severity};

        let mut finding = Finding {
            rule_id: RuleId::SensitiveEnvExport,
            severity: Severity::High,
            title: "test".into(),
            description: "exports sk-abcdefghijklmnopqrstuvwxyz12345678".into(),
            evidence: vec![
                Evidence::EnvVar {
                    name: "OPENAI_API_KEY".into(),
                    value_preview: "sk-abcdefghijklmnopqrstuvwxyz12345678".into(),
                },
                Evidence::Text {
                    detail: "saw ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl".into(),
                },
                Evidence::CommandPattern {
                    pattern: "export".into(),
                    matched: "export OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz12345678".into(),
                },
            ],
            human_view: Some("key is sk-abcdefghijklmnopqrstuvwxyz12345678".into()),
            agent_view: Some("AKIAIOSFODNN7EXAMPLE exposed".into()),
            mitre_id: None,
            custom_rule_id: None,
        };

        redact_finding(&mut finding, &[]);

        // description redacted
        assert!(finding.description.contains("[REDACTED:OpenAI API Key]"));
        assert!(!finding.description.contains("sk-abcdef"));

        // evidence redacted
        match &finding.evidence[0] {
            Evidence::EnvVar { value_preview, .. } => {
                assert!(value_preview.contains("[REDACTED:OpenAI API Key]"));
            }
            _ => panic!("expected EnvVar"),
        }
        match &finding.evidence[1] {
            Evidence::Text { detail } => {
                assert!(detail.contains("[REDACTED:GitHub PAT]"));
            }
            _ => panic!("expected Text"),
        }
        match &finding.evidence[2] {
            Evidence::CommandPattern { matched, .. } => {
                assert!(matched.contains("[REDACTED:OpenAI API Key]"));
            }
            _ => panic!("expected CommandPattern"),
        }

        // human_view / agent_view redacted
        assert!(finding
            .human_view
            .as_ref()
            .unwrap()
            .contains("[REDACTED:OpenAI API Key]"));
        assert!(finding
            .agent_view
            .as_ref()
            .unwrap()
            .contains("[REDACTED:AWS Access Key]"));
    }
}
