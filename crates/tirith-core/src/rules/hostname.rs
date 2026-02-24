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
            human_view: None,
            agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
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
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
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
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
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
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }
}

fn check_raw_ip(host: &str, findings: &mut Vec<Finding>) {
    // Check IPv4
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        // Loopback (127.x) is benign local development — skip.
        if ip.octets()[0] == 127 {
            return;
        }
        findings.push(Finding {
            rule_id: RuleId::RawIpUrl,
            severity: Severity::Medium,
            title: "URL uses raw IP address".to_string(),
            description: format!("URL points to IP address {host} instead of a domain name"),
            evidence: vec![Evidence::Url {
                raw: host.to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
        return;
    }
    // Check IPv6 (strip brackets)
    let stripped = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = stripped.parse::<std::net::Ipv6Addr>() {
        // IPv6 loopback (::1) is benign local development — skip.
        if ip.is_loopback() {
            return;
        }
        findings.push(Finding {
            rule_id: RuleId::RawIpUrl,
            severity: Severity::Medium,
            title: "URL uses raw IPv6 address".to_string(),
            description: format!("URL points to IPv6 address {host} instead of a domain name"),
            evidence: vec![Evidence::Url {
                raw: host.to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
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
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
}

fn check_confusable_domain(raw_host: &str, findings: &mut Vec<Finding>) {
    let host_lower = raw_host.to_lowercase();
    let skeleton = crate::confusables::skeleton(&host_lower);
    let ocr_normalized = ocr_normalize(&host_lower);

    for known in crate::data::known_domains() {
        let known_lower = known.to_lowercase();
        if host_lower == known_lower {
            continue; // Exact match — not confusable
        }

        // Unicode skeleton check (existing)
        if skeleton == known_lower {
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
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
            return;
        }

        // OCR confusion check: apply OCR normalization and compare
        if ocr_normalized != host_lower && ocr_normalized == known_lower {
            findings.push(Finding {
                rule_id: RuleId::ConfusableDomain,
                severity: Severity::Medium,
                title: "OCR-confusable domain detected".to_string(),
                description: format!(
                    "Domain '{raw_host}' is visually similar to '{known}' via OCR confusion (e.g., rn→m, l→1)"
                ),
                evidence: vec![Evidence::HostComparison {
                    raw_host: raw_host.to_string(),
                    similar_to: known.to_string(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
            return;
        }

        // Levenshtein distance for typosquatting.
        // Only compare domains within 3 chars of the same length to avoid
        // false positives between unrelated short domains (e.g., ghcr.io vs gcr.io).
        // For short domains (< 8 chars), skip levenshtein entirely since
        // single-edit matches are too noisy.
        let len_diff = (host_lower.len() as isize - known_lower.len() as isize).unsigned_abs();
        if known_lower.len() >= 8 && len_diff <= 3 && levenshtein(&host_lower, &known_lower) <= 1 {
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
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
            return;
        }
    }
}

/// Apply OCR confusion normalization to a string.
/// Replaces visually confusable character sequences with their canonical forms
/// (e.g., "rn" → "m", "l" → "1"). Longest match applied first.
/// Constrained: max 3 consecutive substitutions per ADR-9.
fn ocr_normalize(input: &str) -> String {
    let confusions = crate::data::ocr_confusions();
    let mut result = String::with_capacity(input.len());
    let mut consecutive_subs = 0u32;
    let mut i = 0;
    let bytes = input.as_bytes();

    while i < bytes.len() {
        let mut matched = false;
        if consecutive_subs < 3 {
            // Try each confusion entry (already sorted by length descending)
            for &(confusable, canonical) in confusions {
                let conf_bytes = confusable.as_bytes();
                if i + conf_bytes.len() <= bytes.len()
                    && &bytes[i..i + conf_bytes.len()] == conf_bytes
                {
                    result.push_str(canonical);
                    i += conf_bytes.len();
                    consecutive_subs += 1;
                    matched = true;
                    break;
                }
            }
        }
        if !matched {
            // Reset consecutive counter on non-substitution
            consecutive_subs = 0;
            // Advance by one UTF-8 character to preserve multi-byte chars
            let remaining = &input[i..];
            if let Some(ch) = remaining.chars().next() {
                result.push(ch);
                i += ch.len_utf8();
            } else {
                i += 1;
            }
        }
    }
    result
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
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
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
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
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
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }
}

/// Check if a domain is in the known high-value targets list.
fn is_known_domain(host: &str) -> bool {
    crate::data::is_known_domain(host)
}
