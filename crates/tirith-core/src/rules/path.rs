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

    // Use raw_path for non-ASCII detection (url crate percent-encodes non-ASCII)
    if let Some(rp) = raw_path {
        check_non_ascii_path(rp, &mut findings);
        check_homoglyph_in_path(rp, &mut findings);
    } else if let Some(np) = normalized_path {
        check_non_ascii_path(&np.normalized, &mut findings);
        check_homoglyph_in_path(&np.normalized, &mut findings);
    }

    if let Some(np) = normalized_path {
        if np.double_encoded {
            check_double_encoding(&np.raw, &mut findings);
        }
    }

    findings
}

fn check_non_ascii_path(normalized: &str, findings: &mut Vec<Finding>) {
    if normalized.bytes().any(|b| b > 0x7F) {
        findings.push(Finding {
            rule_id: RuleId::NonAsciiPath,
            severity: Severity::Medium,
            title: "Non-ASCII characters in URL path".to_string(),
            description:
                "URL path contains non-ASCII characters which may indicate homoglyph substitution"
                    .to_string(),
            evidence: vec![Evidence::Url {
                raw: normalized.to_string(),
            }],
        });
    }
}

fn check_homoglyph_in_path(normalized: &str, findings: &mut Vec<Finding>) {
    // Check for confusable characters near known path patterns
    let known_paths = [
        "install", "setup", "init", "config", "login", "auth", "admin", "api", "token", "key",
        "secret", "password",
    ];

    for segment in normalized.split('/') {
        if segment.is_empty() {
            continue;
        }
        // Check if segment has mixed ASCII and non-ASCII suggesting homoglyphs
        let has_ascii = segment.bytes().any(|b| b.is_ascii_alphabetic());
        let has_non_ascii = segment.bytes().any(|b| b > 0x7F);
        if has_ascii && has_non_ascii {
            // Check proximity to known paths
            let lower = segment.to_lowercase();
            for known in &known_paths {
                if levenshtein(&lower, known) <= 2 {
                    findings.push(Finding {
                        rule_id: RuleId::HomoglyphInPath,
                        severity: Severity::Medium,
                        title: "Potential homoglyph in URL path".to_string(),
                        description: format!(
                            "Path segment '{segment}' looks similar to '{known}' but contains non-ASCII characters"
                        ),
                        evidence: vec![Evidence::Url { raw: segment.to_string() }],
                    });
                    return;
                }
            }
        }
    }
}

fn check_double_encoding(raw_path: &str, findings: &mut Vec<Finding>) {
    findings.push(Finding {
        rule_id: RuleId::DoubleEncoding,
        severity: Severity::Medium,
        title: "Double-encoded URL path detected".to_string(),
        description: "URL path contains percent-encoded percent signs (%25XX) indicating double encoding, which may be used to bypass security filters".to_string(),
        evidence: vec![Evidence::Url { raw: raw_path.to_string() }],
    });
}
