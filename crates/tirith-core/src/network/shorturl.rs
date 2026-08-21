use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

static CACHE: Lazy<Mutex<HashMap<String, (String, Instant)>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const CACHE_TTL: Duration = Duration::from_secs(300);

const MAX_REDIRECTS: usize = 10;

const HOP_TIMEOUT: Duration = Duration::from_secs(5);

/// repo-0303: aggregate wall-clock budget across the whole redirect chain.
const AGGREGATE_TIMEOUT: Duration = Duration::from_secs(15);

/// Returns `true` if `url` is hosted on a known URL shortener domain.
pub fn is_shortened_url(url: &str) -> bool {
    // repo-0301: one canonical shortener list shared with the transport
    // detector (case- and trailing-dot-insensitive), so a host the rule flags
    // is always a host this resolver accepts.
    extract_host(url)
        .map(crate::rules::shared::is_url_shortener)
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
    let client = shorturl_client(crate::ssrf_guard::fetch_resolver()).ok()?;

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

/// The production short-URL client builder, split so the connect-time rebind
/// guard can be driven with a per-test resolver without mutable process DNS.
fn shorturl_client(
    resolver: std::sync::Arc<crate::ssrf_guard::SsrfGuardResolver>,
) -> Result<reqwest::blocking::Client, reqwest::Error> {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .dns_resolver(resolver)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(HOP_TIMEOUT)
        .user_agent("tirith-security/0.1")
        .build()
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
    // repo-0303: one AGGREGATE deadline for the whole chain. Ten hops at five
    // seconds each otherwise lets one short URL hold a blocking worker for
    // ~50s; the daemon enriches these sequentially.
    let deadline = std::time::Instant::now() + AGGREGATE_TIMEOUT;

    for _ in 0..MAX_REDIRECTS {
        if std::time::Instant::now() >= deadline {
            return None;
        }
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
    } else if let Some(rest) = location.strip_prefix("//") {
        // repo-0302: a `//host/path` Location is a NETWORK-PATH reference that
        // keeps only the SCHEME — it is not an origin-relative path. Resolving
        // it against the current origin would inspect a different destination
        // than the one a browser/curl actually follows.
        let scheme_end = current.find("://")?;
        let scheme = &current[..scheme_end];
        Some(format!("{scheme}://{rest}"))
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
        // repo-0303: HARD cap. The retain above only drops expired entries; an
        // attacker feeding unique cache-busting URLs inside the TTL window
        // otherwise grows the map without bound. Evict oldest first.
        while cache.len() >= 1024 {
            let oldest = cache
                .iter()
                .max_by_key(|(_, (_, ts))| ts.elapsed())
                .map(|(k, _)| k.clone());
            match oldest {
                Some(key) => {
                    cache.remove(&key);
                }
                None => break,
            }
        }
        cache.insert(url.to_string(), (resolved.to_string(), Instant::now()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    const AMBIENT_PROXY_PROBE_HOSTS: [&str; 3] = [
        "http-proxy-bypass.example.test",
        "https-proxy-bypass.example.test",
        "all-proxy-bypass.example.test",
    ];

    #[cfg(unix)]
    fn is_owned_ambient_proxy_probe(request: &[u8]) -> bool {
        let request = String::from_utf8_lossy(request);
        AMBIENT_PROXY_PROBE_HOSTS
            .iter()
            .any(|host| request.contains(host))
    }

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

    #[test]
    fn test_production_client_rejects_connect_time_private_rebind() {
        use std::error::Error as _;

        let url = "http://rebind.example.test/landing";
        let preflight =
            crate::url_validate::validate_fetch_url_with_resolver_for_test(url, &|host, _| {
                assert_eq!(host, "rebind.example.test");
                Ok(vec!["93.184.216.34".parse().unwrap()])
            });
        assert!(preflight.is_ok(), "the public preflight answer must pass");

        let resolver = crate::ssrf_guard::fetch_resolver_with_lookup_for_test(|host| {
            assert_eq!(host, "rebind.example.test");
            Ok(vec!["127.0.0.1:9".parse().unwrap()])
        });
        let client = shorturl_client(resolver).expect("build guarded short-URL client");
        let error = client
            .get(url)
            .send()
            .expect_err("connect-time private DNS answer must be refused");

        let mut messages = vec![error.to_string()];
        let mut source = error.source();
        while let Some(cause) = source {
            messages.push(cause.to_string());
            source = cause.source();
        }
        assert!(
            messages.iter().any(|message| {
                message.contains("ssrf_guard") && message.contains("non-public address")
            }),
            "failure must come from the guarded resolver, got: {messages:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn production_client_ignores_ambient_proxy_environment() {
        use std::error::Error as _;
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration, Instant};

        const PROXY_KEYS: [&str; 8] = [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
        ];

        let mut global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global short-URL state");

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local proxy trap");
        listener
            .set_nonblocking(true)
            .expect("make local proxy trap nonblocking");
        let proxy_url = format!(
            "http://{}",
            listener.local_addr().expect("read local proxy address")
        );
        let proxy_hit = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_hit = Arc::clone(&proxy_hit);
        let worker_stop = Arc::clone(&stop);
        let proxy_worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while !worker_stop.load(Ordering::Acquire) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                        let mut request = [0u8; 1024];
                        if let Ok(read) = stream.read(&mut request) {
                            if is_owned_ambient_proxy_probe(&request[..read]) {
                                worker_hit.store(true, Ordering::Release);
                            }
                        }
                        let _ = stream.write_all(
                            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        let mut outcomes = Vec::new();
        for (proxy_key, url, expected_host) in [
            (
                "HTTP_PROXY",
                "http://http-proxy-bypass.example.test/landing",
                "http-proxy-bypass.example.test",
            ),
            (
                "HTTPS_PROXY",
                "https://https-proxy-bypass.example.test/landing",
                "https-proxy-bypass.example.test",
            ),
            (
                "ALL_PROXY",
                "http://all-proxy-bypass.example.test/landing",
                "all-proxy-bypass.example.test",
            ),
        ] {
            for name in PROXY_KEYS {
                global.remove_env(name);
            }
            global.set_env(proxy_key, &proxy_url);

            let resolver = crate::ssrf_guard::fetch_resolver_with_lookup_for_test(move |host| {
                if host != expected_host {
                    return Err(format!(
                        "unexpected resolver host {host:?}; expected {expected_host:?}"
                    ));
                }
                Ok(vec!["127.0.0.1:9".parse().unwrap()])
            });
            let client = shorturl_client(resolver).expect("build guarded short-URL client");
            let outcome = match client.get(url).send() {
                Ok(response) => vec![format!(
                    "request unexpectedly reached a proxy and returned {}",
                    response.status()
                )],
                Err(error) => {
                    let mut messages = vec![error.to_string()];
                    let mut source = error.source();
                    while let Some(cause) = source {
                        messages.push(cause.to_string());
                        source = cause.source();
                    }
                    messages
                }
            };
            outcomes.push((proxy_key, outcome));
        }

        stop.store(true, Ordering::Release);
        proxy_worker.join().expect("join local proxy trap");

        assert!(
            !proxy_hit.load(Ordering::Acquire),
            "the short-URL client must bypass HTTP_PROXY, HTTPS_PROXY, and ALL_PROXY"
        );
        for (proxy_key, messages) in outcomes {
            assert!(
                messages.iter().any(|message| {
                    message.contains("ssrf_guard") && message.contains("non-public address")
                }),
                "{proxy_key} must not bypass the guarded resolver: {messages:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn ambient_proxy_fixture_attributes_only_owned_shorturl_requests() {
        assert!(is_owned_ambient_proxy_probe(
            b"GET http://http-proxy-bypass.example.test/landing HTTP/1.1\r\n"
        ));
        assert!(is_owned_ambient_proxy_probe(
            b"CONNECT https-proxy-bypass.example.test:443 HTTP/1.1\r\n"
        ));
        assert!(is_owned_ambient_proxy_probe(
            b"GET http://all-proxy-bypass.example.test/landing HTTP/1.1\r\n"
        ));
        assert!(!is_owned_ambient_proxy_probe(
            b"GET http://unrelated-full-suite-fixture.example.test/ HTTP/1.1\r\n"
        ));
    }

    // Redirect control flow remains hermetic via injected closures below.

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
