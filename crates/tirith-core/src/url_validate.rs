/// URL validation for outbound HTTP requests (SSRF protection).
use std::net::IpAddr;

/// Validate that a server URL is safe for outbound requests.
///
/// Requires HTTPS and blocks private/loopback/link-local IP addresses.
/// Returns Ok(()) if the URL is safe, or Err(reason) if not.
pub fn validate_server_url(url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;

    // Require HTTPS unless explicitly opted out
    if parsed.scheme() != "https" {
        if std::env::var("TIRITH_ALLOW_HTTP").ok().as_deref() == Some("1") {
            eprintln!(
                "tirith: warning: connecting to server over plain HTTP (TIRITH_ALLOW_HTTP=1)"
            );
        } else {
            return Err(format!(
                "server URL must use HTTPS (got {}://). Set TIRITH_ALLOW_HTTP=1 to override.",
                parsed.scheme()
            ));
        }
    }

    // Block private/loopback/link-local addresses
    if let Some(host) = parsed.host_str() {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_private_ip(&ip) {
                return Err(format!("refusing to connect to private address: {host}"));
            }
        }
        // Block common metadata endpoints by hostname
        if host == "metadata.google.internal"
            || host == "metadata.google.com"
            || host.ends_with(".internal")
        {
            return Err(format!(
                "refusing to connect to cloud metadata endpoint: {host}"
            ));
        }
    }

    Ok(())
}

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                // AWS/cloud metadata: 169.254.169.254
                || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_http() {
        let result = validate_server_url("http://example.com/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTPS"));
    }

    #[test]
    fn test_accepts_https() {
        let result = validate_server_url("https://policy.tirith.dev/api");
        assert!(result.is_ok());
    }

    #[test]
    fn test_rejects_loopback() {
        let result = validate_server_url("https://127.0.0.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("private"));
    }

    #[test]
    fn test_rejects_private_10() {
        let result = validate_server_url("https://10.0.0.1/api");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_private_172() {
        let result = validate_server_url("https://172.16.0.1/api");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_private_192() {
        let result = validate_server_url("https://192.168.1.1/api");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_metadata() {
        let result = validate_server_url("https://169.254.169.254/latest/meta-data/");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_cloud_metadata_hostname() {
        let result = validate_server_url("https://metadata.google.internal/");
        assert!(result.is_err());
    }

    #[test]
    fn test_rejects_invalid_url() {
        let result = validate_server_url("not a url");
        assert!(result.is_err());
    }
}
