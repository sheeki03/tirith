use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

/// Thread-safe cache: URL -> (resolved destination, insertion time).
static CACHE: Lazy<Mutex<HashMap<String, (String, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Cache entries expire after 5 minutes.
const CACHE_TTL: Duration = Duration::from_secs(300);

/// Maximum redirect hops before giving up.
const MAX_REDIRECTS: usize = 10;

/// Per-hop HTTP timeout.
const HOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Known URL shortener domains (lowercase).
const SHORTENER_DOMAINS: &[&str] = &[
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "is.gd",
    "v.gd",
    "goo.gl",
    "ow.ly",
    "buff.ly",
    "rb.gy",
];

/// Returns `true` if `url` is hosted on a known URL shortener domain.
pub fn is_shortened_url(url: &str) -> bool {
    extract_host(url)
        .map(|h| {
            let lower = h.to_lowercase();
            SHORTENER_DOMAINS.iter().any(|&s| lower == s)
        })
        .unwrap_or(false)
}

/// Follow redirects from a shortened URL and return the final destination.
///
/// Returns `None` when:
/// - The URL is not a known shortener
/// - Network errors prevent resolution
/// - The redirect chain exceeds [`MAX_REDIRECTS`]
///
/// Results are cached for [`CACHE_TTL`] to avoid redundant requests.
pub fn resolve_shortened_url(url: &str) -> Option<String> {
    if !is_shortened_url(url) {
        return None;
    }

    // Check cache first.
    if let Some(cached) = cache_get(url) {
        return Some(cached);
    }

    let resolved = follow_redirects(url)?;

    cache_put(url, &resolved);

    Some(resolved)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Extract the host portion from a URL string (cheap, no full parse).
fn extract_host(url: &str) -> Option<&str> {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("//"))?;

    // Host ends at `/`, `?`, `#`, or `:` (port).
    let end = after_scheme
        .find(['/', '?', '#', ':'])
        .unwrap_or(after_scheme.len());

    let host = &after_scheme[..end];
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Follow the `Location` header chain manually.
fn follow_redirects(start_url: &str) -> Option<String> {
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(HOP_TIMEOUT)
        .user_agent("tirith-security/0.1")
        .build()
        .ok()?;

    let mut current = start_url.to_string();

    for _ in 0..MAX_REDIRECTS {
        let resp = client.get(&current).send().ok()?;

        if !resp.status().is_redirection() {
            // Reached the final destination.
            return Some(current);
        }

        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)?
            .to_str()
            .ok()?;

        // Handle relative redirects.
        current = if location.starts_with("http://") || location.starts_with("https://") {
            location.to_string()
        } else if location.starts_with('/') {
            // Absolute path — reuse scheme+host from current URL.
            if let Some(origin) = extract_origin(&current) {
                format!("{origin}{location}")
            } else {
                return None;
            }
        } else {
            return None;
        };
    }

    // Exceeded redirect limit — return last URL we saw.
    Some(current)
}

/// Return "https://host" or "http://host:port" portion of a URL.
fn extract_origin(url: &str) -> Option<String> {
    let scheme_end = url.find("://")?;
    let after = &url[scheme_end + 3..];
    let host_end = after.find('/').unwrap_or(after.len());
    Some(url[..scheme_end + 3 + host_end].to_string())
}

fn cache_get(url: &str) -> Option<String> {
    let cache = CACHE.lock().ok()?;
    if let Some((resolved, ts)) = cache.get(url) {
        if ts.elapsed() < CACHE_TTL {
            return Some(resolved.clone());
        }
    }
    None
}

fn cache_put(url: &str, resolved: &str) {
    if let Ok(mut cache) = CACHE.lock() {
        // Evict expired entries when the cache grows large.
        if cache.len() > 1024 {
            cache.retain(|_, (_, ts)| ts.elapsed() < CACHE_TTL);
        }
        cache.insert(url.to_string(), (resolved.to_string(), Instant::now()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_shortened_url_known() {
        assert!(is_shortened_url("https://bit.ly/abc123"));
        assert!(is_shortened_url("https://t.co/xyz"));
        assert!(is_shortened_url("http://tinyurl.com/something"));
        assert!(is_shortened_url("https://is.gd/foo"));
        assert!(is_shortened_url("https://v.gd/bar"));
        assert!(is_shortened_url("https://goo.gl/maps"));
        assert!(is_shortened_url("https://ow.ly/test"));
        assert!(is_shortened_url("https://buff.ly/article"));
        assert!(is_shortened_url("https://rb.gy/short"));
    }

    #[test]
    fn test_is_shortened_url_negative() {
        assert!(!is_shortened_url("https://github.com/foo"));
        assert!(!is_shortened_url("https://example.com/bit.ly"));
        assert!(!is_shortened_url("not-a-url"));
    }

    #[test]
    fn test_is_shortened_url_case_insensitive() {
        assert!(is_shortened_url("https://BIT.LY/AbC"));
        assert!(is_shortened_url("https://T.CO/XyZ"));
    }

    #[test]
    fn test_extract_host_various() {
        assert_eq!(extract_host("https://bit.ly/abc"), Some("bit.ly"));
        assert_eq!(
            extract_host("http://example.com:8080/path"),
            Some("example.com")
        );
        assert_eq!(extract_host("https://host/"), Some("host"));
        assert_eq!(extract_host("//host/path"), Some("host"));
        assert_eq!(extract_host("no-scheme.com"), None);
    }

    #[test]
    fn test_extract_origin() {
        assert_eq!(
            extract_origin("https://bit.ly/abc"),
            Some("https://bit.ly".to_string())
        );
        assert_eq!(
            extract_origin("http://example.com:8080/path?q=1"),
            Some("http://example.com:8080".to_string())
        );
    }

    #[test]
    fn test_cache_roundtrip() {
        let url = "https://bit.ly/__test_cache__";
        cache_put(url, "https://example.com/final");
        assert_eq!(
            cache_get(url),
            Some("https://example.com/final".to_string())
        );
    }

    // Note: resolve_shortened_url does real HTTP and is not tested in unit tests.
    // Integration tests should be written separately against controlled servers.
}
