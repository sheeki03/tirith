use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

static CACHE: Lazy<Mutex<HashMap<String, (String, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const CACHE_TTL: Duration = Duration::from_secs(300);

const MAX_REDIRECTS: usize = 10;

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
/// `None` for a non-shortener, a network failure, a chain over [`MAX_REDIRECTS`],
/// or a redirect toward a non-public / forbidden destination (SSRF guard).
/// Results are cached for [`CACHE_TTL`].
pub fn resolve_shortened_url(url: &str) -> Option<String> {
    if !is_shortened_url(url) {
        return None;
    }

    if let Some(cached) = cache_get(url) {
        return Some(cached);
    }

    let resolved = follow_redirects(url)?;

    cache_put(url, &resolved);

    Some(resolved)
}

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

/// One step in a redirect chain: a terminal response, or a redirect carrying
/// the raw value of its `Location` header.
enum Hop {
    Final,
    Redirect(String),
}

/// Follow the `Location` chain, validating every URL — the initial one and each
/// hop — with [`crate::url_validate::validate_fetch_url`] before connecting, so
/// a shortener cannot steer us into an SSRF target (loopback / private /
/// link-local / cloud-metadata).
fn follow_redirects(start_url: &str) -> Option<String> {
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(HOP_TIMEOUT)
        .user_agent("tirith-security/0.1")
        .build()
        .ok()?;

    follow_redirects_with(
        start_url,
        |url| {
            let resp = client.get(url).send().ok()?;
            if resp.status().is_redirection() {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)?
                    .to_str()
                    .ok()?;
                Some(Hop::Redirect(location.to_string()))
            } else {
                Some(Hop::Final)
            }
        },
        |url| crate::url_validate::validate_fetch_url(url).map(|_| ()),
    )
}

/// Pure redirect-following control flow with injected `fetch` and `validate`
/// closures, so the SSRF guard, the over-limit case, and `Location` resolution
/// are unit-testable without real HTTP.
fn follow_redirects_with<F, V>(start_url: &str, fetch: F, validate: V) -> Option<String>
where
    F: Fn(&str) -> Option<Hop>,
    V: Fn(&str) -> Result<(), String>,
{
    let mut current = start_url.to_string();

    for _ in 0..MAX_REDIRECTS {
        // SSRF guard: refuse a forbidden destination before connecting. Applies
        // to the initial URL and every redirect hop.
        if validate(&current).is_err() {
            return None;
        }

        match fetch(&current)? {
            Hop::Final => return Some(current),
            Hop::Redirect(location) => current = resolve_location(&current, &location)?,
        }
    }

    // Exceeded the redirect limit without resolving. Per the documented
    // contract this is a failure (`None`) — the last hop was never fetched or
    // validated as a final destination, so we must not return it.
    None
}

/// Resolve a `Location` header against the URL it came from: absolute http(s) is
/// taken as-is, a leading-`/` path reuses the current origin, anything else
/// (including protocol-relative) is unsupported and gives up.
fn resolve_location(current: &str, location: &str) -> Option<String> {
    if location.starts_with("http://") || location.starts_with("https://") {
        Some(location.to_string())
    } else if location.starts_with('/') {
        extract_origin(current).map(|origin| format!("{origin}{location}"))
    } else {
        None
    }
}

/// Return the `scheme://host[:port]` origin portion of a URL.
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
    // The redirect-following control flow below IS tested via injected closures.

    #[test]
    fn test_follow_redirects_over_limit_returns_none() {
        // A chain that redirects forever must give up with None (#122), not
        // return the last unfetched hop.
        let result = follow_redirects_with(
            "https://bit.ly/loop",
            |url| Some(Hop::Redirect(format!("{url}/x"))),
            |_| Ok(()),
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_follow_redirects_initial_url_ssrf_blocked() {
        // Even the first URL is validated on the passive path.
        let result = follow_redirects_with(
            "http://127.0.0.1/x",
            |_| Some(Hop::Final),
            |url| {
                if url.contains("127.0.0.1") {
                    Err("forbidden".to_string())
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_follow_redirects_ssrf_hop_blocked() {
        // A shortener that redirects to a metadata endpoint is refused before
        // the GET; the fetcher's would-be Final for that host is never reached.
        let result = follow_redirects_with(
            "https://bit.ly/evil",
            |url| {
                if url.contains("169.254.169.254") {
                    Some(Hop::Final)
                } else {
                    Some(Hop::Redirect(
                        "http://169.254.169.254/latest/meta-data/".to_string(),
                    ))
                }
            },
            |url| {
                if url.contains("169.254.169.254") {
                    Err("forbidden".to_string())
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_follow_redirects_resolves_absolute() {
        let result = follow_redirects_with(
            "https://bit.ly/x",
            |url| {
                if url == "https://example.com/final" {
                    Some(Hop::Final)
                } else {
                    Some(Hop::Redirect("https://example.com/final".to_string()))
                }
            },
            |_| Ok(()),
        );
        assert_eq!(result, Some("https://example.com/final".to_string()));
    }

    #[test]
    fn test_follow_redirects_resolves_relative_path() {
        // `Location: /landing` reuses the origin of the current URL.
        let result = follow_redirects_with(
            "https://bit.ly/x",
            |url| {
                if url == "https://bit.ly/landing" {
                    Some(Hop::Final)
                } else {
                    Some(Hop::Redirect("/landing".to_string()))
                }
            },
            |_| Ok(()),
        );
        assert_eq!(result, Some("https://bit.ly/landing".to_string()));
    }
}
