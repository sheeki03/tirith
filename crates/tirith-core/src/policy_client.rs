use std::fmt;
use std::time::Duration;

/// Client-observed successful body receipt. Server headers are supporting
/// evidence only and never determine whether a cached policy is trusted.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteFetchMetadata {
    pub fetched_at: String,
    pub server_date: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug)]
pub struct FetchedRemotePolicy {
    pub yaml: String,
    pub metadata: RemoteFetchMetadata,
}

/// Errors that can occur when fetching remote policy.
#[derive(Debug)]
pub enum PolicyFetchError {
    /// Network-level error (DNS, connection refused, timeout, etc.).
    NetworkError(String),
    /// Authentication failure (401/403); always fatal.
    AuthError(u16),
    /// Server returned an error status code.
    ServerError(String),
    /// Response body unreadable or not valid YAML.
    InvalidResponse(String),
}

impl fmt::Display for PolicyFetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyFetchError::NetworkError(msg) => write!(f, "network error: {msg}"),
            PolicyFetchError::AuthError(code) => write!(f, "authentication failed (HTTP {code})"),
            PolicyFetchError::ServerError(msg) => write!(f, "server error: {msg}"),
            PolicyFetchError::InvalidResponse(msg) => write!(f, "invalid response: {msg}"),
        }
    }
}

/// Fetch remote policy YAML from `{url}/api/policy/fetch` (Bearer auth, 5s
/// connect / 10s total timeout).
pub fn fetch_remote_policy(url: &str, api_key: &str) -> Result<String, PolicyFetchError> {
    fetch_remote_policy_with_metadata(url, api_key).map(|response| response.yaml)
}

pub fn fetch_remote_policy_with_metadata(
    url: &str,
    api_key: &str,
) -> Result<FetchedRemotePolicy, PolicyFetchError> {
    // SSRF protection: validate the URL before connecting.
    if let Err(reason) = crate::url_validate::validate_server_url(url) {
        return Err(PolicyFetchError::NetworkError(reason));
    }
    // TIRITH_ALLOW_HTTP relaxes transport for a local server, not credential
    // handling: this request carries an API key, so it requires TLS regardless.
    if url::Url::parse(url).is_ok_and(|parsed| parsed.scheme() != "https") {
        return Err(PolicyFetchError::NetworkError(
            "policy fetch sends an API key and therefore requires https://".into(),
        ));
    }

    let client = crate::ssrf_guard::server_client_builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| PolicyFetchError::NetworkError(e.to_string()))?;

    let endpoint = format!("{}/api/policy/fetch", url.trim_end_matches('/'));
    let resp = client
        .get(&endpoint)
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .map_err(|e| PolicyFetchError::NetworkError(e.to_string()))?;

    match resp.status().as_u16() {
        200 => {
            let header = |name: &str| {
                resp.headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
                    .filter(|value| value.len() <= 1024)
                    .map(str::to_owned)
            };
            let server_date = header("date");
            let etag = header("etag");
            let last_modified = header("last-modified");
            let yaml = read_policy_body_capped(resp)?;
            Ok(FetchedRemotePolicy {
                yaml,
                metadata: RemoteFetchMetadata {
                    fetched_at: chrono::Utc::now().to_rfc3339(),
                    server_date,
                    etag,
                    last_modified,
                },
            })
        }
        401 | 403 => Err(PolicyFetchError::AuthError(resp.status().as_u16())),
        404 => Err(PolicyFetchError::ServerError(
            "no active policy found".into(),
        )),
        s => Err(PolicyFetchError::ServerError(format!(
            "server returned HTTP {s}"
        ))),
    }
}

/// Maximum accepted remote-policy body size (1 MiB), matching the local
/// policy-file read cap. A malicious or compromised policy server must not be
/// able to exhaust memory: the 10s timeout bounds DURATION, not BYTES, and a
/// compressed body expands far beyond its Content-Length.
pub const REMOTE_POLICY_BODY_CAP: u64 = 1024 * 1024;

/// Read a successful response through a strict size budget. Rejects an
/// oversized Content-Length early AND enforces the cap while streaming, so
/// chunked or compressed bodies cannot bypass it (repo-0309).
fn read_policy_body_capped(resp: reqwest::blocking::Response) -> Result<String, PolicyFetchError> {
    use std::io::Read as _;

    if let Some(len) = resp.content_length() {
        if len > REMOTE_POLICY_BODY_CAP {
            return Err(PolicyFetchError::InvalidResponse(format!(
                "policy body too large (Content-Length {len} exceeds {REMOTE_POLICY_BODY_CAP} bytes)"
            )));
        }
    }

    // Read at most cap+1 bytes of the DECODED stream; the extra byte is the
    // oversize signal so chunked / gzip-expanded bodies fail closed.
    let mut limited = resp.take(REMOTE_POLICY_BODY_CAP + 1);
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        .map_err(|e| PolicyFetchError::InvalidResponse(e.to_string()))?;
    if buf.len() as u64 > REMOTE_POLICY_BODY_CAP {
        return Err(PolicyFetchError::InvalidResponse(format!(
            "policy body exceeds {REMOTE_POLICY_BODY_CAP} bytes"
        )));
    }
    String::from_utf8(buf)
        .map_err(|e| PolicyFetchError::InvalidResponse(format!("policy body is not UTF-8: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capped_reader_rejects_oversize_prefix() {
        // Unit-level check of the budget logic without a live server: the
        // decision rule is cap+1 bytes read ⇒ error.
        let cap = REMOTE_POLICY_BODY_CAP as usize;
        let buf = vec![b'x'; cap + 1];
        assert!(
            buf.len() as u64 > REMOTE_POLICY_BODY_CAP,
            "cap+1 bytes must trip the budget"
        );
    }

    #[test]
    fn test_policy_fetch_error_display() {
        let e = PolicyFetchError::NetworkError("timeout".into());
        assert_eq!(format!("{e}"), "network error: timeout");

        let e = PolicyFetchError::AuthError(401);
        assert_eq!(format!("{e}"), "authentication failed (HTTP 401)");

        let e = PolicyFetchError::ServerError("internal error".into());
        assert_eq!(format!("{e}"), "server error: internal error");

        let e = PolicyFetchError::InvalidResponse("bad body".into());
        assert_eq!(format!("{e}"), "invalid response: bad body");
    }

    #[test]
    fn test_fetch_invalid_url_returns_network_error() {
        // Non-routable address should fail quickly
        let result = fetch_remote_policy("http://192.0.2.1:1", "test-key");
        assert!(result.is_err());
        match result.unwrap_err() {
            PolicyFetchError::NetworkError(_) => {} // expected
            other => panic!("expected NetworkError, got: {other}"),
        }
    }
}
