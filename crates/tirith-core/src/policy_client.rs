use std::fmt;
use std::time::Duration;

/// Errors that can occur when fetching remote policy.
#[derive(Debug)]
pub enum PolicyFetchError {
    /// Network-level error (DNS, connection refused, timeout, etc.).
    NetworkError(String),
    /// Authentication failure (401/403). Always treated as fatal.
    AuthError(u16),
    /// Server returned an error status code.
    ServerError(String),
    /// Response body could not be read or is not valid YAML.
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

/// Fetch remote policy YAML from the policy server.
///
/// Uses 5s connect timeout and 10s total timeout. The server endpoint
/// is `{url}/api/policy/fetch` and requires Bearer token authentication.
#[cfg(unix)]
pub fn fetch_remote_policy(url: &str, api_key: &str) -> Result<String, PolicyFetchError> {
    // SSRF protection: validate the URL before connecting
    if let Err(reason) = crate::url_validate::validate_server_url(url) {
        return Err(PolicyFetchError::NetworkError(reason));
    }

    let client = reqwest::blocking::Client::builder()
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
        200 => resp
            .text()
            .map_err(|e| PolicyFetchError::InvalidResponse(e.to_string())),
        401 | 403 => Err(PolicyFetchError::AuthError(resp.status().as_u16())),
        404 => Err(PolicyFetchError::ServerError(
            "no active policy found".into(),
        )),
        s => Err(PolicyFetchError::ServerError(format!(
            "server returned HTTP {s}"
        ))),
    }
}

/// Stub for non-unix platforms where reqwest is not available.
#[cfg(not(unix))]
pub fn fetch_remote_policy(_url: &str, _api_key: &str) -> Result<String, PolicyFetchError> {
    Err(PolicyFetchError::NetworkError(
        "remote policy fetch is not supported on this platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
