use std::net::ToSocketAddrs;

/// Known DNS-based blocklists for threat intelligence.
const DNS_BLOCKLISTS: &[(&str, &str)] = &[
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("dnsbl.sorbs.net", "SORBS"),
];

/// Check if a domain appears in DNS-based blocklists (DNSBLs).
///
/// This works by resolving the domain to its IP address(es), then querying each
/// DNSBL with the reversed-IP lookup format: `<d>.<c>.<b>.<a>.<blocklist-zone>`.
///
/// Returns a list of blocklist display names that returned a positive result.
/// Returns an empty list if the domain cannot be resolved or no blocklists match.
pub fn check_dns_blocklist(domain: &str) -> Vec<String> {
    let ips = match resolve_domain_ips(domain) {
        Some(ips) => ips,
        None => return Vec::new(),
    };

    let mut matches = Vec::new();

    for ip in &ips {
        let reversed = reverse_ipv4(ip);
        let reversed = match reversed {
            Some(r) => r,
            None => continue, // Skip non-IPv4 addresses
        };

        for &(zone, display_name) in DNS_BLOCKLISTS {
            let query = format!("{reversed}.{zone}");
            if dnsbl_lookup(&query) {
                let entry = display_name.to_string();
                if !matches.contains(&entry) {
                    matches.push(entry);
                }
            }
        }
    }

    matches
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Resolve a domain to its IPv4 addresses using the system resolver.
fn resolve_domain_ips(domain: &str) -> Option<Vec<String>> {
    // ToSocketAddrs requires a port; we use 0 as a dummy.
    let lookup = format!("{domain}:0");
    let addrs: Vec<String> = lookup
        .to_socket_addrs()
        .ok()?
        .filter_map(|addr| {
            if addr.is_ipv4() {
                Some(addr.ip().to_string())
            } else {
                None
            }
        })
        .collect();

    if addrs.is_empty() {
        None
    } else {
        Some(addrs)
    }
}

/// Reverse the octets of an IPv4 address string.
///
/// `"1.2.3.4"` -> `Some("4.3.2.1")`
fn reverse_ipv4(ip: &str) -> Option<String> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    // Validate each octet is a number in range.
    for part in &parts {
        part.parse::<u8>().ok()?;
    }
    Some(format!(
        "{}.{}.{}.{}",
        parts[3], parts[2], parts[1], parts[0]
    ))
}

/// Perform a DNSBL lookup by trying to resolve the query hostname.
///
/// A positive result is indicated by the DNS query resolving to any address
/// (typically `127.0.0.x`). A negative result means NXDOMAIN (resolution fails).
fn dnsbl_lookup(query: &str) -> bool {
    let lookup = format!("{query}:0");
    lookup.to_socket_addrs().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_ipv4_valid() {
        assert_eq!(reverse_ipv4("1.2.3.4"), Some("4.3.2.1".to_string()));
        assert_eq!(
            reverse_ipv4("192.168.1.100"),
            Some("100.1.168.192".to_string())
        );
        assert_eq!(reverse_ipv4("10.0.0.1"), Some("1.0.0.10".to_string()));
    }

    #[test]
    fn test_reverse_ipv4_invalid() {
        assert_eq!(reverse_ipv4("not-an-ip"), None);
        assert_eq!(reverse_ipv4("1.2.3"), None);
        assert_eq!(reverse_ipv4("1.2.3.4.5"), None);
        assert_eq!(reverse_ipv4("::1"), None);
        assert_eq!(reverse_ipv4("256.1.2.3"), None);
    }

    // DNS resolution tests are network-dependent and skipped in CI.
    // They should be run in integration test environments.
}
