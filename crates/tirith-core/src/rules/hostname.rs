use crate::homoglyph;
use crate::parse::UrlLike;
use crate::policy::Policy;
use crate::util::levenshtein;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Run all hostname rules against a parsed URL.
pub fn check(url: &UrlLike, _policy: &Policy) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Some(raw_host) = url.raw_host() {
        check_non_ascii_hostname(raw_host, &mut findings);
        check_mixed_script_in_label(raw_host, &mut findings);
        check_invalid_host_chars(raw_host, &mut findings);
        check_trailing_dot_whitespace(raw_host, &mut findings);
        check_confusable_domain(raw_host, &mut findings);
    }

    if let Some(host) = url.host() {
        check_punycode_domain(host, &mut findings);
        check_raw_ip(host, &mut findings);
        check_lookalike_tld(host, &mut findings);
    }

    check_userinfo_trick(url, &mut findings);

    if let Some(port) = url.port() {
        if let Some(host) = url.host() {
            check_non_standard_port(host, port, &mut findings);
        }
    }

    findings
}

fn check_non_ascii_hostname(raw_host: &str, findings: &mut Vec<Finding>) {
    if raw_host.bytes().any(|b| b > 0x7F) {
        // Generate detailed homoglyph analysis
        let homoglyph_evidence = homoglyph::analyze_hostname(raw_host);

        findings.push(Finding {
            rule_id: RuleId::NonAsciiHostname,
            severity: Severity::High,
            title: "Non-ASCII characters in hostname".to_string(),
            description: format!(
                "Hostname '{raw_host}' contains non-ASCII characters which may be a homograph attack"
            ),
            evidence: vec![homoglyph_evidence],
        });
    }
}

fn check_punycode_domain(host: &str, findings: &mut Vec<Finding>) {
    let labels: Vec<&str> = host.split('.').collect();
    for label in &labels {
        if label.starts_with("xn--") {
            findings.push(Finding {
                rule_id: RuleId::PunycodeDomain,
                severity: Severity::High,
                title: "Punycode domain detected".to_string(),
                description: format!(
                    "Domain contains punycode label '{label}' which may disguise the actual domain"
                ),
                evidence: vec![Evidence::Url {
                    raw: host.to_string(),
                }],
            });
            return;
        }
    }
}

fn check_mixed_script_in_label(raw_host: &str, findings: &mut Vec<Finding>) {
    use unicode_normalization::UnicodeNormalization;
    use unicode_script::{Script, UnicodeScript};

    let normalized: String = raw_host.nfc().collect();
    for label in normalized.split('.') {
        let mut scripts = std::collections::HashSet::new();
        for ch in label.chars() {
            if ch == '-' || ch.is_ascii_digit() {
                continue;
            }
            let script = ch.script();
            if script == Script::Common || script == Script::Inherited {
                continue;
            }
            scripts.insert(script);
        }
        if scripts.len() > 1 {
            findings.push(Finding {
                rule_id: RuleId::MixedScriptInLabel,
                severity: Severity::High,
                title: "Mixed scripts in hostname label".to_string(),
                description: format!(
                    "Label '{label}' mixes multiple Unicode scripts ({scripts:?}), potential homograph"
                ),
                evidence: vec![Evidence::Url {
                    raw: raw_host.to_string(),
                }],
            });
            return;
        }
    }
}

fn check_userinfo_trick(url: &UrlLike, findings: &mut Vec<Finding>) {
    if let Some(userinfo) = url.userinfo() {
        if userinfo.contains('.') {
            findings.push(Finding {
                rule_id: RuleId::UserinfoTrick,
                severity: Severity::High,
                title: "Domain-like userinfo in URL".to_string(),
                description: format!(
                    "URL userinfo '{userinfo}' contains a dot, suggesting domain impersonation (e.g., http://github.com@evil.com/)"
                ),
                evidence: vec![Evidence::Url {
                    raw: url.raw_str(),
                }],
            });
        }
    }
}

fn check_raw_ip(host: &str, findings: &mut Vec<Finding>) {
    // Check IPv4
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        findings.push(Finding {
            rule_id: RuleId::RawIpUrl,
            severity: Severity::Medium,
            title: "URL uses raw IP address".to_string(),
            description: format!("URL points to IP address {host} instead of a domain name"),
            evidence: vec![Evidence::Url {
                raw: host.to_string(),
            }],
        });
        return;
    }
    // Check IPv6 (strip brackets)
    let stripped = host.trim_start_matches('[').trim_end_matches(']');
    if stripped.parse::<std::net::Ipv6Addr>().is_ok() {
        findings.push(Finding {
            rule_id: RuleId::RawIpUrl,
            severity: Severity::Medium,
            title: "URL uses raw IPv6 address".to_string(),
            description: format!("URL points to IPv6 address {host} instead of a domain name"),
            evidence: vec![Evidence::Url {
                raw: host.to_string(),
            }],
        });
    }
}

fn check_non_standard_port(host: &str, port: u16, findings: &mut Vec<Finding>) {
    let standard_ports = [80, 443, 22, 9418];
    if !standard_ports.contains(&port) && is_known_domain(host) {
        findings.push(Finding {
            rule_id: RuleId::NonStandardPort,
            severity: Severity::Medium,
            title: "Non-standard port on known domain".to_string(),
            description: format!("Known domain '{host}' using non-standard port {port}"),
            evidence: vec![Evidence::Url {
                raw: format!("{host}:{port}"),
            }],
        });
    }
}

fn check_confusable_domain(raw_host: &str, findings: &mut Vec<Finding>) {
    let skeleton = crate::confusables::skeleton(&raw_host.to_lowercase());
    for known in crate::data::known_domains() {
        let known_lower = known.to_lowercase();
        if skeleton == known_lower && raw_host.to_lowercase() != known_lower {
            findings.push(Finding {
                rule_id: RuleId::ConfusableDomain,
                severity: Severity::High,
                title: "Confusable domain detected".to_string(),
                description: format!(
                    "Domain '{raw_host}' is visually similar to known domain '{known}'"
                ),
                evidence: vec![Evidence::HostComparison {
                    raw_host: raw_host.to_string(),
                    similar_to: known.to_string(),
                }],
            });
            return;
        }
        // Also check Levenshtein distance for typosquatting.
        // Only compare domains within 3 chars of the same length to avoid
        // false positives between unrelated short domains (e.g., ghcr.io vs gcr.io).
        // For short domains (< 8 chars), skip levenshtein entirely since
        // single-edit matches are too noisy.
        let host_lower = raw_host.to_lowercase();
        let len_diff = (host_lower.len() as isize - known_lower.len() as isize).unsigned_abs();
        if known_lower.len() >= 8
            && len_diff <= 3
            && levenshtein(&host_lower, &known_lower) <= 1
            && host_lower != known_lower
        {
            findings.push(Finding {
                rule_id: RuleId::ConfusableDomain,
                severity: Severity::Medium,
                title: "Domain similar to known domain".to_string(),
                description: format!(
                    "Domain '{raw_host}' is one edit away from known domain '{known}'"
                ),
                evidence: vec![Evidence::HostComparison {
                    raw_host: raw_host.to_string(),
                    similar_to: known.to_string(),
                }],
            });
            return;
        }
    }
}

fn check_invalid_host_chars(raw_host: &str, findings: &mut Vec<Finding>) {
    let invalid_chars: &[char] = &['%', '\\'];
    let has_invalid = raw_host.chars().any(|c| {
        invalid_chars.contains(&c)
            || c.is_ascii_control()
            || c.is_whitespace()
            || matches!(c, '\u{FF0E}' | '\u{3002}' | '\u{FF61}')
    });

    if has_invalid {
        findings.push(Finding {
            rule_id: RuleId::InvalidHostChars,
            severity: Severity::High,
            title: "Invalid characters in hostname".to_string(),
            description: format!(
                "Hostname '{raw_host}' contains characters that are never valid in DNS names"
            ),
            evidence: vec![Evidence::Url {
                raw: raw_host.to_string(),
            }],
        });
    }
}

fn check_trailing_dot_whitespace(raw_host: &str, findings: &mut Vec<Finding>) {
    if raw_host.ends_with('.') || raw_host.ends_with(char::is_whitespace) {
        findings.push(Finding {
            rule_id: RuleId::TrailingDotWhitespace,
            severity: Severity::Medium,
            title: "Trailing dot or whitespace in hostname".to_string(),
            description: format!("Hostname '{raw_host}' has trailing dot or whitespace"),
            evidence: vec![Evidence::Url {
                raw: raw_host.to_string(),
            }],
        });
    }
}

fn check_lookalike_tld(host: &str, findings: &mut Vec<Finding>) {
    let lookalike_tlds = ["zip", "mov", "app", "dev", "run"];
    if let Some(tld) = host.rsplit('.').next() {
        if lookalike_tlds.contains(&tld.to_lowercase().as_str()) {
            findings.push(Finding {
                rule_id: RuleId::LookalikeTld,
                severity: Severity::Medium,
                title: "Lookalike TLD detected".to_string(),
                description: format!(
                    "Domain uses '.{tld}' TLD which can be confused with file extensions"
                ),
                evidence: vec![Evidence::Url {
                    raw: host.to_string(),
                }],
            });
        }
    }
}

/// Check if a domain is in the known high-value targets list.
fn is_known_domain(host: &str) -> bool {
    crate::data::is_known_domain(host)
}
