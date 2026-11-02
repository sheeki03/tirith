use crate::normalize::NormalizedComponent;
use crate::parse::UrlLike;
use crate::util::levenshtein;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Run path rules against a parsed URL.
/// `raw_path` is the path from the original URL string (pre-percent-encoding by url crate).
pub fn check(
    _url: &UrlLike,
    normalized_path: Option<&NormalizedComponent>,
    raw_path: Option<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // The analysis subject: the raw (pre-encoding) path when available — the url
    // crate percent-encodes non-ASCII before we see it — else the normalized
    // component. Non-ASCII and homoglyph checks run against BOTH the literal
    // subject and its bounded, validated percent-decoded view (repo-0329): a
    // percent-encoded UTF-8 homoglyph stays ASCII in the literal text, and
    // `normalize_path` deliberately preserves percent-encoded non-ASCII bytes,
    // so scanning only one representation misses it. The original text is kept
    // for evidence and for the URL-semantics checks; the view is analysis-only.
    let subject = raw_path.or_else(|| normalized_path.map(|np| np.normalized.as_str()));
    let mut double_encoding_fired = false;
    if let Some(subject) = subject {
        let view = crate::normalize::percent_decoded_view(subject);
        let decoded_differs = view.decoded != subject;

        if !check_non_ascii_path(subject, subject, &mut findings) && decoded_differs {
            check_non_ascii_path(&view.decoded, subject, &mut findings);
        }
        if !check_homoglyph_in_path(subject, subject, &mut findings) && decoded_differs {
            check_homoglyph_in_path(&view.decoded, subject, &mut findings);
        }
        if view.repeated_encoded {
            check_double_encoding(subject, &mut findings);
            double_encoding_fired = true;
        }
    }

    if let Some(np) = normalized_path {
        if np.double_encoded && !double_encoding_fired {
            check_double_encoding(&np.raw, &mut findings);
        }
    }

    findings
}

/// Push a [`RuleId::NonAsciiPath`] finding when `scan` carries a non-ASCII byte,
/// attributing the evidence to `evidence_text` (the original path, when `scan`
/// is the percent-decoded analysis view). Returns whether a finding fired so
/// the caller scans the decoded view only when the literal text was clean.
fn check_non_ascii_path(scan: &str, evidence_text: &str, findings: &mut Vec<Finding>) -> bool {
    if scan.bytes().any(|b| b > 0x7F) {
        findings.push(Finding {
            rule_id: RuleId::NonAsciiPath,
            severity: Severity::Medium,
            title: "Non-ASCII characters in URL path".to_string(),
            description:
                "URL path contains non-ASCII characters which may indicate homoglyph substitution"
                    .to_string(),
            evidence: vec![Evidence::Url {
                raw: evidence_text.to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
        return true;
    }
    false
}

/// Push a [`RuleId::HomoglyphInPath`] finding for the first path segment of
/// `scan` that mixes ASCII and non-ASCII while resembling a well-known segment;
/// evidence attributes to `evidence_text`. Returns whether a finding fired.
fn check_homoglyph_in_path(scan: &str, evidence_text: &str, findings: &mut Vec<Finding>) -> bool {
    let known_paths = [
        "install", "setup", "init", "config", "login", "auth", "admin", "api", "token", "key",
        "secret", "password",
    ];

    for segment in scan.split('/') {
        if segment.is_empty() {
            continue;
        }
        let lower = segment.to_lowercase();

        // Mixed ASCII + non-ASCII in one segment is the homoglyph shape we care about.
        let has_ascii = segment.bytes().any(|b| b.is_ascii_alphabetic());
        let has_non_ascii = segment.bytes().any(|b| b > 0x7F);
        if has_ascii && has_non_ascii {
            for known in &known_paths {
                if levenshtein(&lower, known) <= 2 {
                    findings.push(Finding {
                        rule_id: RuleId::HomoglyphInPath,
                        severity: Severity::Medium,
                        title: "Potential homoglyph in URL path".to_string(),
                        description: format!(
                            "Path segment '{segment}' looks similar to '{known}' but contains non-ASCII characters"
                        ),
                        evidence: vec![Evidence::Url {
                            raw: evidence_text.to_string(),
                        }],
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                    return true;
                }
            }
        }
    }
    false
}

fn check_double_encoding(raw_path: &str, findings: &mut Vec<Finding>) {
    findings.push(Finding {
        rule_id: RuleId::DoubleEncoding,
        severity: Severity::Medium,
        title: "Double-encoded URL path detected".to_string(),
        description: "URL path contains percent-encoded percent signs (%25XX) indicating double encoding, which may be used to bypass security filters".to_string(),
        evidence: vec![Evidence::Url { raw: raw_path.to_string() }],
        human_view: None,
        agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::UrlLike;

    fn unparsed_url() -> UrlLike {
        UrlLike::Unparsed {
            raw: "https://example.invalid/x".to_string(),
            raw_host: Some("example.invalid".to_string()),
            raw_path: Some("/x".to_string()),
        }
    }

    fn normalized(raw: &str) -> NormalizedComponent {
        crate::normalize::normalize_path(raw)
    }

    #[test]
    fn percent_encoded_cyrillic_fires_non_ascii_path() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // repo-0329: %D0%B0 is Cyrillic small A; the raw path is pure ASCII, so
        // only the decoded view can see the non-ASCII content.
        let findings = check(&unparsed_url(), None, Some("/inst%D0%B0ll"));
        assert!(
            findings.iter().any(|f| f.rule_id == RuleId::NonAsciiPath),
            "expected NonAsciiPath, got {findings:?}"
        );
        // Evidence keeps the original (encoded) path.
        let finding = findings
            .iter()
            .find(|f| f.rule_id == RuleId::NonAsciiPath)
            .unwrap();
        match &finding.evidence[0] {
            Evidence::Url { raw } => assert_eq!(raw, "/inst%D0%B0ll"),
            other => panic!("unexpected evidence: {other:?}"),
        }
    }

    #[test]
    fn percent_encoded_homoglyph_fires_homoglyph_in_path() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // "login" with a percent-encoded Cyrillic o (U+043E): l%D0%BEgin.
        let findings = check(&unparsed_url(), None, Some("/l%D0%BEgin"));
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::HomoglyphInPath),
            "expected HomoglyphInPath, got {findings:?}"
        );
    }

    #[test]
    fn clean_ascii_path_fires_nothing() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let findings = check(&unparsed_url(), None, Some("/install/setup.sh"));
        assert!(findings.is_empty(), "got {findings:?}");
    }

    #[test]
    fn invalid_percent_utf8_is_conservatively_flagged() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A truncated UTF-8 sequence decodes to U+FFFD, which the non-ASCII
        // check sees: malformed encodings fail closed.
        let findings = check(&unparsed_url(), None, Some("/x%D0y"));
        assert!(
            findings.iter().any(|f| f.rule_id == RuleId::NonAsciiPath),
            "expected NonAsciiPath for invalid UTF-8, got {findings:?}"
        );
    }

    #[test]
    fn double_encoding_fires_once_from_raw_or_normalized() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // Raw-only: the view's repeated-encoding marker fires DoubleEncoding.
        let findings = check(&unparsed_url(), None, Some("/x%252Fy"));
        let count = findings
            .iter()
            .filter(|f| f.rule_id == RuleId::DoubleEncoding)
            .count();
        assert_eq!(count, 1, "got {findings:?}");

        // Raw AND a double-encoded normalized component: still one finding.
        let np = normalized("/x%252Fy");
        assert!(np.double_encoded, "test premise");
        let findings = check(&unparsed_url(), Some(&np), Some("/x%252Fy"));
        let count = findings
            .iter()
            .filter(|f| f.rule_id == RuleId::DoubleEncoding)
            .count();
        assert_eq!(
            count, 1,
            "double-encoding must not double-fire: {findings:?}"
        );
    }

    #[test]
    fn literal_non_ascii_still_fires_without_double_firing() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // A literal (unencoded) Cyrillic path fires once via the raw scan; the
        // identical decoded view adds nothing.
        let findings = check(&unparsed_url(), None, Some("/caf\u{00E9}"));
        let count = findings
            .iter()
            .filter(|f| f.rule_id == RuleId::NonAsciiPath)
            .count();
        assert_eq!(count, 1, "got {findings:?}");
    }
}
