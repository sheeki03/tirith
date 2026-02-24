// Embedded data from build.rs: known domains, popular repos, OCR confusions.

// Include generated data
include!(concat!(env!("OUT_DIR"), "/known_domains_gen.rs"));
include!(concat!(env!("OUT_DIR"), "/popular_repos_gen.rs"));
include!(concat!(env!("OUT_DIR"), "/psl_gen.rs"));
include!(concat!(env!("OUT_DIR"), "/ocr_confusions_gen.rs"));

/// Check if a domain is in the known high-value targets list.
pub fn is_known_domain(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    KNOWN_DOMAINS.iter().any(|d| *d == lower)
}

/// Check if a repo (owner/name) is in the popular repos list.
pub fn is_popular_repo(owner: &str, name: &str) -> bool {
    let owner_lower = owner.to_lowercase();
    let name_lower = name.to_lowercase();
    POPULAR_REPOS
        .iter()
        .any(|(o, n)| o.to_lowercase() == owner_lower && n.to_lowercase() == name_lower)
}

/// Get all known domains for confusable checking.
pub fn known_domains() -> &'static [&'static str] {
    KNOWN_DOMAINS
}

/// Get the OCR confusion table for confusable domain normalization.
pub fn ocr_confusions() -> &'static [(&'static str, &'static str)] {
    OCR_CONFUSIONS
}

/// Check if a suffix is in the public suffix list.
pub fn is_public_suffix(suffix: &str) -> bool {
    let lower = suffix.to_lowercase();
    PUBLIC_SUFFIXES.iter().any(|s| *s == lower)
}

/// Extract the registrable domain (eTLD+1) from a hostname.
/// Returns None if the entire hostname is a public suffix or has no suffix match.
pub fn registrable_domain(host: &str) -> Option<String> {
    let lower = host.to_lowercase().trim_end_matches('.').to_string();
    let labels: Vec<&str> = lower.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    // Try multi-part suffixes first (longest match)
    for i in 0..labels.len() {
        let suffix = labels[i..].join(".");
        if is_public_suffix(&suffix) {
            if i == 0 {
                // Entire hostname is a public suffix
                return None;
            }
            // eTLD+1 = one label before the suffix + suffix
            return Some(labels[i - 1..].join("."));
        }
    }
    // Fallback: treat last label as TLD
    if labels.len() >= 2 {
        Some(labels[labels.len() - 2..].join("."))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_domain() {
        assert!(is_known_domain("github.com"));
        assert!(is_known_domain("GitHub.com"));
        assert!(!is_known_domain("notaknowndomain.com"));
    }

    #[test]
    fn test_popular_repo() {
        assert!(is_popular_repo("torvalds", "linux"));
        assert!(!is_popular_repo("nobody", "nothing"));
    }
}
