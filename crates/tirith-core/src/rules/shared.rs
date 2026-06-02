//! Shared constants and helpers used by multiple rule modules.

/// Sensitive-credential env var names. Used by `command.rs` (SensitiveEnvExport)
/// and `credential.rs` (dedup suppression).
pub const SENSITIVE_KEY_VARS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
];

/// Known URL-shortener hosts. Centralised so `transport.rs` (`ShortenedUrl`) and
/// `paste_provenance.rs` (host-mismatch escalation) can't drift (M12 ch1).
/// Matching is exact, case-insensitive at the call site.
pub const URL_SHORTENER_HOSTS: &[&str] = &[
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "is.gd",
    "v.gd",
    "goo.gl",
    "ow.ly",
];

/// `true` when `host` (any case) is a known URL shortener from
/// [`URL_SHORTENER_HOSTS`].
pub fn is_url_shortener(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    URL_SHORTENER_HOSTS.iter().any(|s| lower == *s)
}

/// Canonical "critical" criticality labels for the M8 context/SSH/IaC/container
/// rules; a label outside this set never fires. Centralised to avoid the
/// four-copy drift hazard (PR-127 review #7). Case-insensitive, whitespace-trimmed.
pub fn is_critical_label(label: &str) -> bool {
    let lower = label.trim().to_lowercase();
    matches!(
        lower.as_str(),
        "critical" | "production" | "prod" | "live" | "p0" | "p1"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_url_shortener_basic() {
        assert!(is_url_shortener("bit.ly"));
        assert!(is_url_shortener("T.CO"), "case-insensitive");
        assert!(is_url_shortener("tinyurl.com"));
        assert!(!is_url_shortener("github.com"));
        assert!(!is_url_shortener("bit.ly.evil.com"));
    }

    #[test]
    fn is_critical_label_basic() {
        for s in &["critical", "production", "prod", "live", "p0", "p1"] {
            assert!(is_critical_label(s), "should be critical: {s:?}");
        }
        // Case-insensitive.
        assert!(is_critical_label("Critical"));
        assert!(is_critical_label("PRODUCTION"));
        // Whitespace tolerance.
        assert!(is_critical_label("  prod  "));
        // Non-critical recognised values.
        assert!(!is_critical_label("staging"));
        assert!(!is_critical_label("dev"));
        assert!(!is_critical_label("test"));
        assert!(!is_critical_label("p2"));
        assert!(!is_critical_label(""));
    }
}
