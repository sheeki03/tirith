use crate::parse::UrlLike;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Run transport rules against a parsed URL.
pub fn check(url: &UrlLike, in_sink_context: bool) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_plain_http_to_sink(url, in_sink_context, &mut findings);
    check_shortened_url(url, &mut findings);

    if matches!(url, UrlLike::SchemelessHostPath { .. }) && in_sink_context {
        findings.push(Finding {
            rule_id: RuleId::SchemelessToSink,
            severity: Severity::Medium,
            title: "Schemeless URL in sink context".to_string(),
            description:
                "URL without explicit scheme passed to a command that downloads/executes content"
                    .to_string(),
            evidence: vec![Evidence::Url { raw: url.raw_str() }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    findings
}

fn is_loopback_host(host: &str) -> bool {
    matches!(
        host,
        "localhost" | "127.0.0.1" | "::1" | "[::1]" | "0.0.0.0"
    ) || host.starts_with("127.")
        || host.ends_with(".localhost")
}

fn check_plain_http_to_sink(url: &UrlLike, in_sink: bool, findings: &mut Vec<Finding>) {
    if let Some(scheme) = url.scheme() {
        if scheme == "http" && in_sink {
            // Loopback traffic never leaves the machine — no MITM risk.
            if let Some(host) = url.host() {
                if is_loopback_host(host) {
                    return;
                }
            }
            findings.push(Finding {
                rule_id: RuleId::PlainHttpToSink,
                severity: Severity::High,
                title: "Plain HTTP URL in execution context".to_string(),
                description: format!(
                    "URL '{}' uses unencrypted HTTP and is being passed to a command that downloads or executes content. An attacker on the network could modify the content.",
                    url.raw_str()
                ),
                evidence: vec![Evidence::Url { raw: url.raw_str() }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }
}

fn check_shortened_url(url: &UrlLike, findings: &mut Vec<Finding>) {
    let shorteners = [
        "bit.ly",
        "t.co",
        "tinyurl.com",
        "is.gd",
        "v.gd",
        "goo.gl",
        "ow.ly",
    ];

    if let Some(host) = url.host() {
        let host_lower = host.to_lowercase();
        if shorteners.iter().any(|s| host_lower == *s) {
            findings.push(Finding {
                rule_id: RuleId::ShortenedUrl,
                severity: Severity::Medium,
                title: "Shortened URL detected".to_string(),
                description: format!(
                    "URL uses shortener '{host}' which hides the actual destination"
                ),
                evidence: vec![Evidence::Url { raw: url.raw_str() }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }
}

fn strip_quotes_simple(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Check command arguments for insecure TLS flags.
pub fn check_insecure_flags(args: &[String], in_sink: bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    let insecure_flags = ["-k", "--insecure", "--no-check-certificate"];

    for arg in args {
        let clean = strip_quotes_simple(arg);
        if insecure_flags.contains(&clean.as_str()) {
            let severity = if in_sink {
                Severity::High
            } else {
                Severity::Medium
            };
            findings.push(Finding {
                rule_id: RuleId::InsecureTlsFlags,
                severity,
                title: "Insecure TLS flag detected".to_string(),
                description: format!(
                    "Flag '{arg}' disables TLS certificate verification, allowing MITM attacks"
                ),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "insecure TLS flag".to_string(),
                    matched: arg.to_string(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quoted_insecure_flags() {
        let args = vec!["\"-k\"".to_string(), "https://example.com".to_string()];
        let findings = check_insecure_flags(&args, true);
        assert!(!findings.is_empty(), "should detect -k even when quoted");
    }

    #[test]
    fn test_single_quoted_insecure_flags() {
        let args = vec!["'-k'".to_string()];
        let findings = check_insecure_flags(&args, true);
        assert!(
            !findings.is_empty(),
            "should detect -k even when single-quoted"
        );
    }

    #[test]
    fn test_unquoted_insecure_flags_still_work() {
        let args = vec!["-k".to_string()];
        let findings = check_insecure_flags(&args, true);
        assert!(!findings.is_empty());
    }
}
