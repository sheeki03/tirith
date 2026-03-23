/// URL validation for outbound HTTP requests (SSRF protection).
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

type HostResolver = dyn Fn(&str, u16) -> Result<Vec<IpAddr>, String>;

#[derive(Clone, Copy)]
enum UrlValidationMode {
    Server,
    Fetch,
}

/// Validate that a server URL is safe for outbound requests.
///
/// Requires HTTPS unless `TIRITH_ALLOW_HTTP=1` is set, and blocks private,
/// loopback, link-local, metadata, documentation, and other non-public targets.
pub fn validate_server_url(url: &str) -> Result<(), String> {
    validate_outbound_url_with_resolver(url, UrlValidationMode::Server, &resolve_host).map(|_| ())
}

/// Validate that a fetch/cloaking URL is safe for outbound requests.
///
/// Allows `http` and `https`, but blocks embedded credentials and non-public
/// network destinations after DNS resolution.
pub fn validate_fetch_url(url: &str) -> Result<url::Url, String> {
    validate_outbound_url_with_resolver(url, UrlValidationMode::Fetch, &resolve_host)
}

fn validate_outbound_url_with_resolver(
    url: &str,
    mode: UrlValidationMode,
    resolver: &HostResolver,
) -> Result<url::Url, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    validate_parsed_url_with_resolver(&parsed, mode, resolver)?;
    Ok(parsed)
}

fn validate_parsed_url_with_resolver(
    parsed: &url::Url,
    mode: UrlValidationMode,
    resolver: &HostResolver,
) -> Result<(), String> {
    validate_scheme(parsed, mode)?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("refusing to connect to URLs with embedded credentials".to_string());
    }

    let host = parsed
        .host()
        .ok_or_else(|| "URL is missing a host".to_string())?;
    let host_label = parsed
        .host_str()
        .ok_or_else(|| "URL is missing a host".to_string())?
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if host_label == "localhost" || host_label.ends_with(".localhost") {
        return Err(format!(
            "refusing to connect to localhost destination: {host_label}"
        ));
    }

    if is_cloud_metadata_host(&host_label) {
        return Err(format!(
            "refusing to connect to cloud metadata endpoint: {host_label}"
        ));
    }

    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| format!("unsupported URL scheme: {}", parsed.scheme()))?;

    match host {
        url::Host::Ipv4(ip) => validate_resolved_ip(&host_label, &IpAddr::V4(ip))?,
        url::Host::Ipv6(ip) => validate_resolved_ip(&host_label, &IpAddr::V6(ip))?,
        url::Host::Domain(domain) => {
            let resolved = resolver(domain, port)?;
            if resolved.is_empty() {
                return Err(format!("failed to resolve host: {host_label}"));
            }
            for ip in resolved {
                validate_resolved_ip(&host_label, &ip)?;
            }
        }
    }

    Ok(())
}

fn validate_scheme(parsed: &url::Url, mode: UrlValidationMode) -> Result<(), String> {
    match mode {
        UrlValidationMode::Server => {
            if parsed.scheme() != "https" {
                if parsed.scheme() == "http"
                    && std::env::var("TIRITH_ALLOW_HTTP").ok().as_deref() == Some("1")
                {
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
        }
        UrlValidationMode::Fetch => {
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                return Err(format!(
                    "fetch URL must use http:// or https:// (got {}://)",
                    parsed.scheme()
                ));
            }
        }
    }

    Ok(())
}

fn resolve_host(host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve host {host}: {e}"))?;

    let mut ips = Vec::new();
    for addr in addrs {
        let ip = addr.ip();
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    Ok(ips)
}

fn validate_resolved_ip(host: &str, ip: &IpAddr) -> Result<(), String> {
    if is_forbidden_ip(ip) {
        Err(format!(
            "refusing to connect to non-public address: {host} -> {ip}"
        ))
    } else {
        Ok(())
    }
}

fn is_cloud_metadata_host(host: &str) -> bool {
    matches!(
        host,
        "metadata.google.internal"
            | "metadata.google.com"
            | "instance-data"
            | "instance-data.ec2.internal"
    )
}

fn is_forbidden_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 18)
                || (o[0] == 198 && o[1] == 19)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = embedded_ipv4_in_v6(v6) {
                return is_forbidden_ip(&IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || ((s[0] & 0xfe00) == 0xfc00)
                || ((s[0] & 0xffc0) == 0xfe80)
                || (s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}

fn embedded_ipv4_in_v6(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }

    let octets = v6.octets();
    if octets[..12].iter().all(|&b| b == 0) {
        return Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }

    const NAT64_WELL_KNOWN_PREFIX: [u8; 12] = [
        0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    if octets.starts_with(&NAT64_WELL_KNOWN_PREFIX) {
        return Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver_with(ip: IpAddr) -> impl Fn(&str, u16) -> Result<Vec<IpAddr>, String> {
        move |_, _| Ok(vec![ip])
    }

    #[test]
    fn test_rejects_http() {
        let result = validate_server_url("http://example.com/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTPS"));
    }

    #[test]
    fn test_accepts_https() {
        let result = validate_outbound_url_with_resolver(
            "https://policy.tirith.dev/api",
            UrlValidationMode::Server,
            &resolver_with("93.184.216.34".parse().unwrap()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_rejects_loopback() {
        let result = validate_server_url("https://127.0.0.1/api");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-public"));
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

    #[test]
    fn test_rejects_embedded_credentials() {
        let result = validate_outbound_url_with_resolver(
            "https://user:pass@example.com/path",
            UrlValidationMode::Fetch,
            &resolver_with("93.184.216.34".parse().unwrap()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("embedded credentials"));
    }

    #[test]
    fn test_rejects_localhost_name() {
        let result = validate_outbound_url_with_resolver(
            "https://localhost/path",
            UrlValidationMode::Fetch,
            &resolver_with("93.184.216.34".parse().unwrap()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("localhost"));
    }

    #[test]
    fn test_rejects_localhost_subdomain() {
        let result = validate_outbound_url_with_resolver(
            "https://api.localhost/path",
            UrlValidationMode::Fetch,
            &resolver_with("93.184.216.34".parse().unwrap()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("localhost"));
    }

    #[test]
    fn test_rejects_hostname_resolving_to_private_ip() {
        let result = validate_outbound_url_with_resolver(
            "https://example.com/path",
            UrlValidationMode::Server,
            &resolver_with("127.0.0.1".parse().unwrap()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("127.0.0.1"));
    }

    #[test]
    fn test_rejects_hostname_resolving_to_documentation_range() {
        let result = validate_outbound_url_with_resolver(
            "https://example.com/path",
            UrlValidationMode::Fetch,
            &resolver_with("203.0.113.10".parse().unwrap()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("203.0.113.10"));
    }

    #[test]
    fn test_fetch_allows_http_when_public() {
        let result = validate_outbound_url_with_resolver(
            "http://example.com/path",
            UrlValidationMode::Fetch,
            &resolver_with("93.184.216.34".parse().unwrap()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_fetch_rejects_non_http_scheme() {
        let result = validate_outbound_url_with_resolver(
            "ftp://example.com/file",
            UrlValidationMode::Fetch,
            &resolver_with("93.184.216.34".parse().unwrap()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("http:// or https://"));
    }

    #[test]
    fn test_accepts_public_ipv6_literal_without_dns_lookup() {
        let result = validate_outbound_url_with_resolver(
            "https://[2606:2800:220:1:248:1893:25c8:1946]",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_rejects_ipv4_mapped_ipv6_literal() {
        let result = validate_outbound_url_with_resolver(
            "https://[::ffff:127.0.0.1]/api",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-public"));
    }

    #[test]
    fn test_rejects_hostname_resolving_to_ipv4_mapped_ipv6() {
        let result = validate_outbound_url_with_resolver(
            "https://example.com/api",
            UrlValidationMode::Fetch,
            &resolver_with("::ffff:169.254.169.254".parse().unwrap()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("169.254.169.254"));
    }

    // -----------------------------------------------------------------------
    // Adversarial bypass attempts: embedded IPv4 / translated IPv6
    // -----------------------------------------------------------------------

    #[test]
    fn test_bypass_mapped_cloud_metadata() {
        // ::ffff:169.254.169.254 — AWS metadata endpoint via IPv4-mapped
        let result = validate_outbound_url_with_resolver(
            "https://[::ffff:169.254.169.254]/latest/meta-data/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "IPv4-mapped metadata must be blocked");
    }

    #[test]
    fn test_bypass_mapped_private_10() {
        let result = validate_outbound_url_with_resolver(
            "https://[::ffff:10.0.0.1]/admin",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "IPv4-mapped 10.x must be blocked");
    }

    #[test]
    fn test_bypass_mapped_private_192() {
        let result = validate_outbound_url_with_resolver(
            "https://[::ffff:192.168.1.1]/config",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "IPv4-mapped 192.168.x must be blocked");
    }

    #[test]
    fn test_bypass_mapped_private_172() {
        let result = validate_outbound_url_with_resolver(
            "https://[::ffff:172.16.0.1]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "IPv4-mapped 172.16.x must be blocked");
    }

    #[test]
    fn test_bypass_mapped_unspecified() {
        let result = validate_outbound_url_with_resolver(
            "https://[::ffff:0.0.0.0]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "IPv4-mapped 0.0.0.0 must be blocked");
    }

    #[test]
    fn test_bypass_mapped_broadcast() {
        let result = validate_outbound_url_with_resolver(
            "https://[::ffff:255.255.255.255]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "IPv4-mapped broadcast must be blocked");
    }

    #[test]
    fn test_bypass_resolved_mapped_loopback() {
        // DNS returns ::ffff:127.0.0.1 for a hostname
        let result = validate_outbound_url_with_resolver(
            "https://attacker.example.com/",
            UrlValidationMode::Server,
            &resolver_with("::ffff:127.0.0.1".parse().unwrap()),
        );
        assert!(
            result.is_err(),
            "Resolved IPv4-mapped loopback must be blocked"
        );
    }

    #[test]
    fn test_bypass_resolved_mapped_private() {
        // DNS returns ::ffff:10.0.0.1 for a hostname
        let result = validate_outbound_url_with_resolver(
            "https://attacker.example.com/api",
            UrlValidationMode::Fetch,
            &resolver_with("::ffff:10.0.0.1".parse().unwrap()),
        );
        assert!(
            result.is_err(),
            "Resolved IPv4-mapped private must be blocked"
        );
    }

    #[test]
    fn test_rejects_nat64_encoded_loopback() {
        let result = validate_outbound_url_with_resolver(
            "https://[64:ff9b::127.0.0.1]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "NAT64-encoded loopback must be blocked");
    }

    #[test]
    fn test_rejects_resolved_nat64_encoded_metadata() {
        let result = validate_outbound_url_with_resolver(
            "https://example.com/api",
            UrlValidationMode::Fetch,
            &resolver_with("64:ff9b::169.254.169.254".parse().unwrap()),
        );
        assert!(
            result.is_err(),
            "NAT64-encoded metadata address must be blocked"
        );
    }

    #[test]
    fn test_rejects_ipv4_compatible_loopback() {
        let result = validate_outbound_url_with_resolver(
            "https://[::127.0.0.1]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(
            result.is_err(),
            "IPv4-compatible loopback form must be blocked"
        );
    }

    #[test]
    fn test_allows_nat64_encoded_public_ipv4() {
        let result = validate_outbound_url_with_resolver(
            "https://[64:ff9b::0808:0808]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(
            result.is_ok(),
            "NAT64-encoded public IPv4 should be allowed"
        );
    }

    #[test]
    fn test_legitimate_public_ipv6_still_allowed() {
        // Google's public DNS — must NOT be blocked
        let result = validate_outbound_url_with_resolver(
            "https://[2607:f8b0:4004:800::200e]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_ok(), "Public IPv6 must be allowed");
    }

    #[test]
    fn test_legitimate_resolved_public_ipv6_allowed() {
        let result = validate_outbound_url_with_resolver(
            "https://example.com/api",
            UrlValidationMode::Server,
            &resolver_with("2607:f8b0:4004:800::200e".parse().unwrap()),
        );
        assert!(result.is_ok(), "Resolved public IPv6 must be allowed");
    }
}
