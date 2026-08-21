//! URL validation for outbound HTTP requests — SSRF protection.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

type HostResolver<'a> = dyn Fn(&str, u16) -> Result<Vec<IpAddr>, String> + 'a;

#[cfg(any(test, feature = "test-network-seams"))]
#[doc(hidden)]
pub type TestHostResolver<'a> = dyn Fn(&str, u16) -> Result<Vec<IpAddr>, String> + 'a;

#[derive(Clone, Copy)]
enum UrlValidationMode {
    Server,
    Fetch,
}

/// Exact host/IP/CIDR exceptions for user-initiated fetches.
///
/// This intentionally is not a general "allow private networking" switch. A
/// policy can approve one hostname or a bounded private-use CIDR, while the
/// centralized address classifier still unconditionally refuses link-local,
/// cloud control-plane/credential, multicast, and other special-use space.
///
/// SCOPE OF A HOSTNAME ENTRY: a host approved by name is approved for WHATEVER
/// it resolves to within private-use and loopback space, including `127.0.0.1`
/// and the rest of RFC 1918. Name resolution is not part of the trust decision,
/// so whoever controls that name's DNS chooses the destination inside those
/// ranges. Use a CIDR entry when the intended destination is a fixed address
/// range; use a hostname entry only when the name itself is the thing being
/// trusted. The unconditional refusals above still apply either way.
#[derive(Clone, Debug, Default)]
pub(crate) struct PrivateFetchPolicy {
    hosts: Vec<String>,
    cidrs: Vec<IpCidr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressScope {
    Global,
    PrivateUse,
    Loopback,
    LinkLocal,
    CloudControlPlane,
    SpecialUse,
}

const PRIVATE_FETCH_ALLOW_ENV: &str = "TIRITH_PRIVATE_FETCH_ALLOW";

#[cfg(test)]
thread_local! {
    static TEST_PRIVATE_FETCH_POLICY: std::cell::RefCell<Option<Result<PrivateFetchPolicy, String>>> =
        const { std::cell::RefCell::new(None) };
}

/// Validate a server URL for outbound requests: HTTPS unless `TIRITH_ALLOW_HTTP=1`,
/// and block private / loopback / link-local / metadata / non-public targets.
pub fn validate_server_url(url: &str) -> Result<(), String> {
    validate_outbound_url_with_resolver(url, UrlValidationMode::Server, &resolve_host).map(|_| ())
}

/// Hermetic server-URL preflight seam for tests that must model the validation
/// DNS answer independently from the connect-time resolver answer.
#[cfg(test)]
#[doc(hidden)]
pub fn validate_server_url_with_resolver_for_test(
    url: &str,
    resolver: &TestHostResolver<'_>,
) -> Result<(), String> {
    let parsed = url::Url::parse(url).map_err(|_| "invalid URL".to_string())?;
    validate_parsed_url_with_resolver(&parsed, UrlValidationMode::Server, resolver, None)
}

/// Validate a fetch/cloaking URL: allows http/https but blocks embedded
/// credentials and non-public destinations (after DNS resolution).
pub fn validate_fetch_url(url: &str) -> Result<url::Url, String> {
    validate_outbound_url_with_resolver(url, UrlValidationMode::Fetch, &resolve_host)
}

/// Pure fetch-URL preflight used before consuming a one-shot authorization.
///
/// This validates every property available without name resolution: syntax,
/// scheme, credentials, host/port presence, cloud-metadata hostnames, and
/// literal-IP policy. Domain names are deliberately not resolved here. The
/// ordinary [`validate_fetch_url`] call remains mandatory after authorization
/// and immediately before constructing the network request.
pub fn validate_fetch_url_syntax(url: &str) -> Result<url::Url, String> {
    let parsed = url::Url::parse(url).map_err(|_| "invalid URL".to_string())?;
    validate_parsed_url_syntax(&parsed, UrlValidationMode::Fetch)?;

    let host_label = parsed
        .host_str()
        .ok_or_else(|| "URL is missing a host".to_string())?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let policy = private_fetch_policy_from_env()?;
    let literal = match parsed
        .host()
        .ok_or_else(|| "URL is missing a host".to_string())?
    {
        url::Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
        url::Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
        url::Host::Domain(_) => {
            if is_localhost_host(&host_label) && !policy.approves_host(&host_label) {
                return Err("refusing to connect to localhost destination".to_string());
            }
            None
        }
    };
    if let Some(ip) = literal {
        validate_resolved_destination(&host_label, &[ip], Some(&policy))?;
    }
    Ok(parsed)
}

/// Hermetic preflight seam for crate tests that need to model the first DNS
/// answer independently from the connect-time resolver answer.
#[cfg(any(test, feature = "test-network-seams"))]
#[doc(hidden)]
pub fn validate_fetch_url_with_resolver_for_test(
    url: &str,
    resolver: &TestHostResolver<'_>,
) -> Result<url::Url, String> {
    let parsed = url::Url::parse(url).map_err(|_| "invalid URL".to_string())?;
    let strict_policy = PrivateFetchPolicy::default();
    validate_parsed_url_with_resolver(
        &parsed,
        UrlValidationMode::Fetch,
        resolver,
        Some(&strict_policy),
    )?;
    Ok(parsed)
}

fn validate_outbound_url_with_resolver(
    url: &str,
    mode: UrlValidationMode,
    resolver: &HostResolver<'_>,
) -> Result<url::Url, String> {
    let parsed = url::Url::parse(url).map_err(|_| "invalid URL".to_string())?;
    validate_parsed_url_with_resolver(&parsed, mode, resolver, None)?;
    Ok(parsed)
}

fn validate_parsed_url_with_resolver(
    parsed: &url::Url,
    mode: UrlValidationMode,
    resolver: &HostResolver<'_>,
    fetch_policy_override: Option<&PrivateFetchPolicy>,
) -> Result<(), String> {
    validate_parsed_url_syntax(parsed, mode)?;

    let host = parsed
        .host()
        .ok_or_else(|| "URL is missing a host".to_string())?;
    let host_label = parsed
        .host_str()
        .ok_or_else(|| "URL is missing a host".to_string())?
        .trim_end_matches('.')
        .to_ascii_lowercase();

    let private_policy = match mode {
        UrlValidationMode::Server => None,
        UrlValidationMode::Fetch => Some(match fetch_policy_override {
            Some(policy) => policy.clone(),
            None => private_fetch_policy_from_env()?,
        }),
    };

    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "unsupported URL scheme".to_string())?;

    // Resolve the host (or take the literal IP) once, up front, so the metadata
    // and forbidden-IP screens below see the same address set.
    let addrs: Vec<IpAddr> = match host {
        url::Host::Ipv4(ip) => vec![IpAddr::V4(ip)],
        url::Host::Ipv6(ip) => vec![IpAddr::V6(ip)],
        url::Host::Domain(domain) => {
            let resolved = resolver(domain, port)
                .map_err(|_| "failed to resolve destination host".to_string())?;
            if resolved.is_empty() {
                return Err("failed to resolve destination host".to_string());
            }
            resolved
        }
    };

    validate_resolved_destination(&host_label, &addrs, private_policy.as_ref())
}

fn validate_parsed_url_syntax(parsed: &url::Url, mode: UrlValidationMode) -> Result<(), String> {
    validate_scheme(parsed, mode)?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("refusing to connect to URLs with embedded credentials".to_string());
    }
    let host_label = parsed
        .host_str()
        .ok_or_else(|| "URL is missing a host".to_string())?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if is_cloud_metadata_host(&host_label) {
        return Err("refusing to connect to cloud metadata endpoint".to_string());
    }
    parsed
        .port_or_known_default()
        .ok_or_else(|| "unsupported URL scheme".to_string())?;
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
                    return Err(
                        "server URL must use HTTPS. Set TIRITH_ALLOW_HTTP=1 to override."
                            .to_string(),
                    );
                }
            }
        }
        UrlValidationMode::Fetch => {
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                return Err("fetch URL must use http:// or https://".to_string());
            }
        }
    }

    Ok(())
}

fn resolve_host(host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|_| "failed to resolve destination host".to_string())?;

    let mut ips = Vec::new();
    for addr in addrs {
        let ip = addr.ip();
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    Ok(ips)
}

/// Whether a resolved socket address points at a routable, public destination.
///
/// [`classify_ip`] is the single source of truth for the IANA special-purpose
/// and cloud control-plane classification used here, by the URL validators, and
/// by the connect-time resolver.
pub fn is_public_addr(addr: &SocketAddr) -> bool {
    classify_ip(&addr.ip()) == AddressScope::Global
}

/// Whether a resolved socket address is a cloud-metadata (IMDS) endpoint.
///
/// `SocketAddr` adapter over the centralized cloud endpoint classifier.
pub fn is_cloud_metadata_addr(addr: &SocketAddr) -> bool {
    is_cloud_metadata_ip(&addr.ip())
}

/// Whether a non-empty, syntactically valid narrow private-fetch allowlist is
/// configured. `TIRITH_ALLOW_PRIVATE_FETCH=1` is deliberately no longer honored.
/// Callers must list exact hosts, IPs, or bounded private CIDRs in
/// `TIRITH_PRIVATE_FETCH_ALLOW`.
pub fn allow_private_fetch() -> bool {
    private_fetch_policy_from_env()
        .map(|policy| !policy.is_empty())
        .unwrap_or(false)
}

pub(crate) fn private_fetch_policy_from_env() -> Result<PrivateFetchPolicy, String> {
    #[cfg(test)]
    if let Some(policy) = TEST_PRIVATE_FETCH_POLICY.with(|slot| slot.borrow().clone()) {
        return policy;
    }

    let Some(raw) = std::env::var_os(PRIVATE_FETCH_ALLOW_ENV) else {
        return Ok(PrivateFetchPolicy::default());
    };
    let value = raw.into_string().map_err(|_| {
        format!("{PRIVATE_FETCH_ALLOW_ENV} must contain valid Unicode host/IP/CIDR entries")
    })?;
    PrivateFetchPolicy::parse(&value)
}

impl PrivateFetchPolicy {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        if value.trim().is_empty() {
            return Ok(Self::default());
        }

        let mut policy = Self::default();
        for (index, raw_entry) in value.split(',').enumerate() {
            let entry = raw_entry.trim();
            if entry.is_empty() {
                return Err(format!(
                    "invalid {PRIVATE_FETCH_ALLOW_ENV} entry {}: empty entries are not allowed",
                    index + 1
                ));
            }
            policy.add_entry(entry).map_err(|reason| {
                format!(
                    "invalid {PRIVATE_FETCH_ALLOW_ENV} entry {}: {reason}",
                    index + 1
                )
            })?;
        }
        Ok(policy)
    }

    fn add_entry(&mut self, entry: &str) -> Result<(), String> {
        if entry.contains('/') {
            let cidr = IpCidr::parse(entry)?;
            validate_private_fetch_cidr(&cidr)?;
            if !self.cidrs.contains(&cidr) {
                self.cidrs.push(cidr);
            }
            return Ok(());
        }

        if let Ok(ip) = entry.parse::<IpAddr>() {
            let cidr = IpCidr::single(ip);
            validate_private_fetch_cidr(&cidr)?;
            if !self.cidrs.contains(&cidr) {
                self.cidrs.push(cidr);
            }
            return Ok(());
        }

        if entry.contains('*') {
            return Err("wildcard hosts are not allowed".to_string());
        }

        match url::Host::parse(entry).map_err(|_| "expected an exact hostname, IP, or CIDR")? {
            url::Host::Domain(host) => {
                let host = host.trim_end_matches('.').to_ascii_lowercase();
                if host.is_empty() {
                    return Err("hostname is empty".to_string());
                }
                if is_cloud_metadata_host(&host) {
                    return Err("cloud metadata hostnames cannot be approved".to_string());
                }
                if !self.hosts.contains(&host) {
                    self.hosts.push(host);
                }
                Ok(())
            }
            url::Host::Ipv4(ip) => self.add_ip_host(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => self.add_ip_host(IpAddr::V6(ip)),
        }
    }

    fn add_ip_host(&mut self, ip: IpAddr) -> Result<(), String> {
        let cidr = IpCidr::single(ip);
        validate_private_fetch_cidr(&cidr)?;
        if !self.cidrs.contains(&cidr) {
            self.cidrs.push(cidr);
        }
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.cidrs.is_empty()
    }

    fn approves_host(&self, host: &str) -> bool {
        let normalized = host.trim_end_matches('.').to_ascii_lowercase();
        self.hosts.iter().any(|allowed| allowed == &normalized)
    }

    fn approves_ip(&self, ip: &IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(ip))
    }
}

impl IpCidr {
    fn parse(value: &str) -> Result<Self, String> {
        let (address, prefix) = value
            .split_once('/')
            .ok_or_else(|| "CIDR is missing a prefix length".to_string())?;
        if prefix.contains('/') {
            return Err("CIDR contains more than one prefix separator".to_string());
        }
        let address = address.trim();
        let address = if address.starts_with('[') || address.ends_with(']') {
            address
                .strip_prefix('[')
                .and_then(|value| value.strip_suffix(']'))
                .ok_or_else(|| "CIDR has mismatched IPv6 brackets".to_string())?
        } else {
            address
        };
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| "CIDR has an invalid IP address".to_string())?;
        let prefix = prefix
            .trim()
            .parse::<u8>()
            .map_err(|_| "CIDR has an invalid prefix length".to_string())?;
        let cidr = Self::new(address, prefix)?;
        if cidr.network != address {
            return Err("CIDR network address has host bits set".to_string());
        }
        Ok(cidr)
    }

    fn new(address: IpAddr, prefix: u8) -> Result<Self, String> {
        let network = match address {
            IpAddr::V4(ip) => {
                if prefix > 32 {
                    return Err("IPv4 CIDR prefix must be between 0 and 32".to_string());
                }
                IpAddr::V4(Ipv4Addr::from(u32::from(ip) & ipv4_mask(prefix)))
            }
            IpAddr::V6(ip) => {
                if prefix > 128 {
                    return Err("IPv6 CIDR prefix must be between 0 and 128".to_string());
                }
                IpAddr::V6(Ipv6Addr::from(u128::from(ip) & ipv6_mask(prefix)))
            }
        };
        Ok(Self { network, prefix })
    }

    fn single(ip: IpAddr) -> Self {
        Self {
            prefix: if ip.is_ipv4() { 32 } else { 128 },
            network: ip,
        }
    }

    fn contains(&self, address: &IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                u32::from(*address) & ipv4_mask(self.prefix) == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                u128::from(*address) & ipv6_mask(self.prefix) == u128::from(network)
            }
            _ => false,
        }
    }

    fn contains_cidr(&self, other: &Self) -> bool {
        self.network.is_ipv4() == other.network.is_ipv4()
            && self.prefix <= other.prefix
            && self.contains(&other.network)
    }

    fn overlaps(&self, other: &Self) -> bool {
        self.network.is_ipv4() == other.network.is_ipv4()
            && (self.contains(&other.network) || other.contains(&self.network))
    }
}

fn validate_private_fetch_cidr(cidr: &IpCidr) -> Result<(), String> {
    for immutable in immutable_cloud_cidrs() {
        if cidr.overlaps(&immutable) {
            return Err("CIDR overlaps a cloud control-plane or credential endpoint".to_string());
        }
    }

    let eligible = private_fetch_parent_cidrs()
        .iter()
        .any(|parent| parent.contains_cidr(cidr));
    if !eligible {
        return Err(
            "CIDRs must stay within RFC1918, shared-address, loopback, or IPv6 ULA space"
                .to_string(),
        );
    }

    // A site-sized ULA is narrow enough to express a real internal network;
    // accepting fc00::/7 would recreate the broad bypass this allowlist replaces.
    if cidr.network.is_ipv6() && cidr.prefix < 48 {
        return Err("IPv6 ULA CIDRs must use a /48 or narrower prefix".to_string());
    }
    Ok(())
}

fn private_fetch_parent_cidrs() -> [IpCidr; 7] {
    [
        IpCidr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).expect("valid CIDR"),
        IpCidr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)), 10).expect("valid CIDR"),
        IpCidr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8).expect("valid CIDR"),
        IpCidr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12).expect("valid CIDR"),
        IpCidr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 16).expect("valid CIDR"),
        IpCidr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128).expect("valid CIDR"),
        IpCidr::new(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7).expect("valid CIDR"),
    ]
}

fn immutable_cloud_cidrs() -> [IpCidr; 8] {
    [
        IpCidr::single(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))),
        IpCidr::single(IpAddr::V4(Ipv4Addr::new(169, 254, 170, 2))),
        IpCidr::single(IpAddr::V4(Ipv4Addr::new(169, 254, 170, 23))),
        IpCidr::single(IpAddr::V4(Ipv4Addr::new(169, 254, 0, 23))),
        IpCidr::single(IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200))),
        IpCidr::single(IpAddr::V4(Ipv4Addr::new(168, 63, 129, 16))),
        IpCidr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0)),
            64,
        )
        .expect("valid CIDR"),
        IpCidr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0)),
            64,
        )
        .expect("valid CIDR"),
    ]
}

/// Validate an entire DNS answer set using the same decision function used by
/// the preflight validator and the reqwest connect-time resolver. One forbidden
/// answer rejects the whole set; silently dropping a private answer would make
/// the two boundaries disagree and leave rebinding behavior resolver-dependent.
pub(crate) fn validate_resolved_destination(
    host: &str,
    addresses: &[IpAddr],
    private_policy: Option<&PrivateFetchPolicy>,
) -> Result<(), String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if is_cloud_metadata_host(&host) {
        return Err("refusing to connect to cloud metadata endpoint".to_string());
    }
    if addresses.is_empty() {
        return Err("failed to resolve destination host".to_string());
    }

    for ip in addresses {
        validate_destination_ip(&host, ip, private_policy)?;
    }
    Ok(())
}

fn validate_destination_ip(
    host: &str,
    ip: &IpAddr,
    private_policy: Option<&PrivateFetchPolicy>,
) -> Result<(), String> {
    let scope = classify_ip(ip);
    let host_approved = private_policy.is_some_and(|policy| policy.approves_host(host));
    let ip_approved = private_policy.is_some_and(|policy| policy.approves_ip(ip));

    match scope {
        AddressScope::Global if !is_localhost_host(host) || host_approved => Ok(()),
        AddressScope::Global => Err("refusing to connect to localhost destination".to_string()),
        AddressScope::PrivateUse | AddressScope::Loopback if host_approved || ip_approved => Ok(()),
        AddressScope::CloudControlPlane => {
            Err("refusing to connect to cloud metadata endpoint".to_string())
        }
        AddressScope::LinkLocal => Err("refusing to connect to link-local address".to_string()),
        AddressScope::PrivateUse | AddressScope::Loopback | AddressScope::SpecialUse => {
            Err("refusing to connect to non-public address".to_string())
        }
    }
}

fn is_localhost_host(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost")
}

/// Canonical cloud-metadata host names. Reused by both the URL validators and
/// the connect-time DNS guard so the carve-out can never reach a metadata host.
pub(crate) fn is_cloud_metadata_host(host: &str) -> bool {
    matches!(
        host.trim_end_matches('.').to_ascii_lowercase().as_str(),
        "metadata"
            | "metadata.google.internal"
            | "metadata.google.com"
            | "metadata.goog"
            | "instance-data"
            | "instance-data.ec2.internal"
    )
}

/// Cloud control-plane and credential-service addresses that must remain denied
/// even when an operator approves the surrounding private hostname or CIDR.
/// IPv4-mapped, well-known NAT64, 6to4, Teredo, and compatible encodings are
/// decoded so a textual address-family change cannot hide the endpoint.
pub(crate) fn is_cloud_metadata_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => matches!(
            v4.octets(),
            [169, 254, 169, 254] // AWS/GCP/Azure IMDS
                | [169, 254, 170, 2] // AWS ECS credentials/task metadata
                | [169, 254, 170, 23] // AWS EKS Pod Identity
                | [169, 254, 0, 23] // Tencent Cloud metadata
                | [100, 100, 100, 200] // Alibaba Cloud metadata
                | [168, 63, 129, 16] // Azure WireServer/platform virtual IP
        ),
        IpAddr::V6(v6) => {
            if let Some(v4) = embedded_ipv4_in_v6(v6) {
                return is_cloud_metadata_ip(&IpAddr::V4(v4));
            }
            // Deny the service subnets, not only today's terminal ::254, so the
            // exception cannot expose adjacent control-plane listeners.
            ipv6_in_prefix(*v6, Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0), 64)
                || ipv6_in_prefix(*v6, Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0), 64)
        }
    }
}

/// Classify an address against the IANA IPv4/IPv6 special-purpose registries
/// (registry revision 2025-10-09), plus explicit cloud control-plane endpoints.
/// This function is the only address-scope decision point for URL preflight and
/// connect-time DNS validation.
pub(crate) fn classify_ip(ip: &IpAddr) -> AddressScope {
    if is_cloud_metadata_ip(ip) {
        return AddressScope::CloudControlPlane;
    }

    match ip {
        IpAddr::V4(v4) => {
            if ipv4_in_prefix(*v4, [169, 254, 0, 0], 16) {
                AddressScope::LinkLocal
            } else if ipv4_in_prefix(*v4, [127, 0, 0, 0], 8) {
                AddressScope::Loopback
            } else if ipv4_in_prefix(*v4, [10, 0, 0, 0], 8)
                || ipv4_in_prefix(*v4, [100, 64, 0, 0], 10)
                || ipv4_in_prefix(*v4, [172, 16, 0, 0], 12)
                || ipv4_in_prefix(*v4, [192, 168, 0, 0], 16)
            {
                AddressScope::PrivateUse
            } else if is_globally_reachable_ipv4(*v4) {
                AddressScope::Global
            } else {
                AddressScope::SpecialUse
            }
        }
        IpAddr::V6(v6) => {
            if ipv6_in_prefix(*v6, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10) {
                AddressScope::LinkLocal
            } else if v6.is_loopback() {
                AddressScope::Loopback
            } else if ipv6_in_prefix(*v6, Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7) {
                AddressScope::PrivateUse
            } else if is_globally_reachable_ipv6(*v6) {
                AddressScope::Global
            } else {
                AddressScope::SpecialUse
            }
        }
    }
}

fn is_globally_reachable_ipv4(ip: Ipv4Addr) -> bool {
    // Globally reachable exceptions inside 192.0.0.0/24.
    if matches!(ip.octets(), [192, 0, 0, 9] | [192, 0, 0, 10]) {
        return true;
    }

    ![
        ([0, 0, 0, 0], 8),
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10),
        ([127, 0, 0, 0], 8),
        ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12),
        ([192, 0, 0, 0], 24),
        ([192, 0, 2, 0], 24),
        ([192, 88, 99, 0], 24),
        ([192, 168, 0, 0], 16),
        ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24),
        ([203, 0, 113, 0], 24),
        ([224, 0, 0, 0], 4),
        ([240, 0, 0, 0], 4),
    ]
    .iter()
    .any(|(network, prefix)| ipv4_in_prefix(ip, *network, *prefix))
}

fn is_globally_reachable_ipv6(ip: Ipv6Addr) -> bool {
    // The well-known NAT64 prefix is globally reachable only when its embedded
    // IPv4 destination is. The local-use 64:ff9b:1::/48 remains non-global.
    let octets = ip.octets();
    const NAT64_WELL_KNOWN_PREFIX: [u8; 12] = [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
    if octets.starts_with(&NAT64_WELL_KNOWN_PREFIX) {
        let embedded = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
        return classify_ip(&IpAddr::V4(embedded)) == AddressScope::Global;
    }

    // More-specific globally reachable registrations inside IETF's otherwise
    // non-global 2001::/23 protocol-assignment block.
    if ip == Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 1)
        || ip == Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 2)
        || ip == Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 3)
        || ipv6_in_prefix(ip, Ipv6Addr::new(0x2001, 3, 0, 0, 0, 0, 0, 0), 32)
        || ipv6_in_prefix(ip, Ipv6Addr::new(0x2001, 4, 0x0112, 0, 0, 0, 0, 0), 48)
        || ipv6_in_prefix(ip, Ipv6Addr::new(0x2001, 0x20, 0, 0, 0, 0, 0, 0), 28)
        || ipv6_in_prefix(ip, Ipv6Addr::new(0x2001, 0x30, 0, 0, 0, 0, 0, 0), 28)
    {
        return true;
    }

    // Default-deny unallocated/reserved IPv6 space: ordinary global unicast is
    // 2000::/3, less the current non-global special-purpose subranges.
    ipv6_in_prefix(ip, Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3)
        && !ipv6_in_prefix(ip, Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23)
        && !ipv6_in_prefix(ip, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)
        && !ipv6_in_prefix(ip, Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16)
        && !ipv6_in_prefix(ip, Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20)
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

fn ipv4_in_prefix(address: Ipv4Addr, network: [u8; 4], prefix: u8) -> bool {
    let address = u32::from(address);
    let network = u32::from_be_bytes(network);
    let mask = ipv4_mask(prefix);
    address & mask == network & mask
}

fn ipv6_in_prefix(address: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    let address = u128::from(address);
    let network = u128::from(network);
    let mask = ipv6_mask(prefix);
    address & mask == network & mask
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

    // 6to4 (`2002::/16`, RFC 3056): the embedded IPv4 is octets [2..6]. A
    // literal like `2002:7f00:1::` tunnels 127.0.0.1. Decode it so callers that
    // inspect embedded addresses cannot miss that identity; the global-address
    // classifier independently blanket-blocks the deprecated 2002::/16 range.
    if octets[0] == 0x20 && octets[1] == 0x02 {
        return Some(Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]));
    }

    // Teredo (`2001:0000::/32`, RFC 4380): the server (client external) IPv4 is
    // the LAST 4 octets, each XORed with 0xFF (obfuscated). Decode and apply the
    // same IPv4 check so a Teredo address embedding a private/loopback IPv4
    // can't be used as an SSRF bounce.
    if octets[0] == 0x20 && octets[1] == 0x01 && octets[2] == 0x00 && octets[3] == 0x00 {
        return Some(Ipv4Addr::new(
            octets[12] ^ 0xff,
            octets[13] ^ 0xff,
            octets[14] ^ 0xff,
            octets[15] ^ 0xff,
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

    fn resolver_with_many(ips: Vec<IpAddr>) -> impl Fn(&str, u16) -> Result<Vec<IpAddr>, String> {
        move |_, _| Ok(ips.clone())
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
        let error = result.unwrap_err();
        assert!(error.contains("non-public"));
        assert!(!error.contains("127.0.0.1"));
        assert!(!error.contains("example.com"));
    }

    #[test]
    fn test_rejects_hostname_resolving_to_documentation_range() {
        let result = validate_outbound_url_with_resolver(
            "https://example.com/path",
            UrlValidationMode::Fetch,
            &resolver_with("203.0.113.10".parse().unwrap()),
        );
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.contains("non-public"));
        assert!(!error.contains("203.0.113.10"));
        assert!(!error.contains("example.com"));
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
    fn fetch_syntax_preflight_accepts_a_domain_without_resolution() {
        let parsed = validate_fetch_url_syntax("https://does-not-resolve.invalid/script")
            .expect("pure preflight must not consult DNS for a domain name");
        assert_eq!(parsed.host_str(), Some("does-not-resolve.invalid"));

        let resolver_called = std::cell::Cell::new(false);
        let full = validate_outbound_url_with_resolver(
            parsed.as_str(),
            UrlValidationMode::Fetch,
            &|_, _| {
                resolver_called.set(true);
                Err("synthetic DNS failure".to_string())
            },
        );
        assert!(full.is_err());
        assert!(resolver_called.get());
    }

    #[test]
    fn fetch_syntax_preflight_rejects_literal_ssrf_and_malformed_inputs() {
        for input in [
            "not a URL",
            "ftp://example.com/script",
            "https://user:secret@example.com/script",
            "https://api.localhost/script",
            "https://169.254.169.254/latest/meta-data",
            "https://metadata.google.internal/computeMetadata/v1",
        ] {
            assert!(
                validate_fetch_url_syntax(input).is_err(),
                "accepted {input}"
            );
        }
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
        let error = result.unwrap_err();
        assert!(error.contains("cloud metadata endpoint"));
        assert!(!error.contains("169.254.169.254"));
    }

    // Adversarial bypass attempts: embedded IPv4 / translated IPv6.

    #[test]
    fn test_bypass_mapped_cloud_metadata() {
        // AWS metadata endpoint via IPv4-mapped IPv6.
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

    // 6to4 (2002::/16) and Teredo (2001:0000::/32) are no longer globally
    // reachable transition ranges. The server boundary rejects the entire
    // ranges rather than treating a public embedded IPv4 as sufficient.

    #[test]
    fn test_rejects_6to4_encoded_loopback() {
        // 2002:7f00:1:: is the 6to4 wrapping of 127.0.0.1.
        let result = validate_outbound_url_with_resolver(
            "https://[2002:7f00:1::]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "6to4-encoded loopback must be blocked");
        assert!(result.unwrap_err().contains("non-public"));
    }

    #[test]
    fn test_rejects_deprecated_6to4_even_with_public_ipv4() {
        // 2002:0808:0808:: wraps 8.8.8.8, but RFC 9637 makes 2002::/16
        // non-global regardless of the embedded address.
        let result = validate_outbound_url_with_resolver(
            "https://[2002:0808:0808::]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(result.is_err(), "deprecated 6to4 must be refused");
    }

    #[test]
    fn test_rejects_teredo_encoded_private_ipv4() {
        // Teredo address whose embedded server IPv4 is 192.168.1.1: the last 32
        // bits are the server IPv4 XOR 0xff per octet (0x3f57:fefe).
        let result = validate_outbound_url_with_resolver(
            "https://[2001:0:0:0:0:0:3f57:fefe]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(
            result.is_err(),
            "Teredo-encoded private IPv4 must be blocked"
        );
        assert!(result.unwrap_err().contains("non-public"));
    }

    #[test]
    fn test_normal_public_ipv6_still_allowed_after_carveout() {
        // A genuine public v6 (Cloudflare DNS) must not collide with the 6to4 or
        // Teredo prefixes added by the carve-out.
        let result = validate_outbound_url_with_resolver(
            "https://[2606:4700:4700::1111]/",
            UrlValidationMode::Server,
            &|_, _| Err("resolver should not be called".to_string()),
        );
        assert!(
            result.is_ok(),
            "Public IPv6 must still be allowed after the 6to4/Teredo carve-out"
        );
    }

    // F6: `validate_fetch_url` must reject IP-literal SSRF targets up front
    // (these are the fast-clear-error cases the runner pre-check relies on).

    #[test]
    fn test_fetch_rejects_loopback_literal() {
        let result = validate_fetch_url("http://127.0.0.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-public"));
    }

    #[test]
    fn test_fetch_rejects_metadata_literal() {
        let result = validate_fetch_url("http://169.254.169.254");
        assert!(result.is_err());
        // Metadata IPs are now rejected by the dedicated metadata gate (ahead of
        // the generic non-public check) so the error names the metadata endpoint.
        assert!(result.unwrap_err().contains("cloud metadata endpoint"));
    }

    #[test]
    fn test_fetch_rejects_ipv6_loopback_literal() {
        let result = validate_fetch_url("http://[::1]");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-public"));
    }

    #[test]
    fn test_fetch_rejects_private_10_literal() {
        let result = validate_fetch_url("http://10.0.0.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-public"));
    }

    // is_public_addr: the shared classifier reused by the DNS guard.

    fn sock(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 443)
    }

    #[test]
    fn test_is_public_addr_rejects_private() {
        assert!(!is_public_addr(&sock("10.0.0.1")));
        assert!(!is_public_addr(&sock("172.16.0.1")));
        assert!(!is_public_addr(&sock("192.168.1.1")));
    }

    #[test]
    fn test_is_public_addr_rejects_loopback() {
        assert!(!is_public_addr(&sock("127.0.0.1")));
        assert!(!is_public_addr(&sock("::1")));
    }

    #[test]
    fn test_is_public_addr_rejects_link_local() {
        assert!(!is_public_addr(&sock("169.254.1.1")));
        assert!(!is_public_addr(&sock("fe80::1")));
    }

    #[test]
    fn test_is_public_addr_rejects_metadata() {
        assert!(!is_public_addr(&sock("169.254.169.254")));
    }

    #[test]
    fn test_is_public_addr_rejects_mapped_ipv6() {
        assert!(!is_public_addr(&sock("::ffff:127.0.0.1")));
        assert!(!is_public_addr(&sock("::ffff:169.254.169.254")));
    }

    #[test]
    fn test_is_public_addr_accepts_public() {
        assert!(is_public_addr(&sock("93.184.216.34")));
        assert!(is_public_addr(&sock("8.8.8.8")));
        assert!(is_public_addr(&sock("2607:f8b0:4004:800::200e")));
    }

    #[test]
    fn test_is_public_addr_tracks_special_purpose_registries() {
        for address in [
            "192.0.0.1",
            "192.88.99.1",
            "192.88.99.2",
            "100::1",
            "100:0:0:1::1",
            "2001:2::1",
            "2001:db8::1",
            "2002:0808:0808::1",
            "3fff::1",
            "5f00::1",
            "64:ff9b:1::808:808",
            "fec0::1",
        ] {
            assert!(!is_public_addr(&sock(address)), "{address}");
        }
        for address in [
            "192.0.0.9",
            "192.0.0.10",
            "2001:1::1",
            "2001:1::2",
            "2001:1::3",
            "2001:3::1",
            "2001:4:112::1",
            "2001:20::1",
            "2001:30::1",
            "64:ff9b::808:808",
        ] {
            assert!(is_public_addr(&sock(address)), "{address}");
        }
    }

    // Explicit cloud control-plane and credential endpoints are classified
    // before IANA global/private scope.

    #[test]
    fn test_is_cloud_metadata_ip_matches_known_endpoints() {
        for address in [
            "169.254.169.254",
            "169.254.170.2",
            "169.254.170.23",
            "169.254.0.23",
            "100.100.100.200",
            "168.63.129.16",
            "fd00:ec2::254",
            "fd20:ce::254",
            "::ffff:168.63.129.16",
            "64:ff9b::169.254.170.2",
            "2002:a83f:8110::",
            "2001::57c0:7eef",
        ] {
            assert!(is_cloud_metadata_ip(&address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn test_is_cloud_metadata_ip_ignores_non_metadata() {
        // Nearby addresses outside explicit service subnets stay in their normal
        // IANA scope; link-local is independently immutable.
        assert!(!is_cloud_metadata_ip(&"169.254.1.1".parse().unwrap()));
        assert!(!is_cloud_metadata_ip(&"127.0.0.1".parse().unwrap()));
        assert!(!is_cloud_metadata_ip(&"10.0.0.1".parse().unwrap()));
        assert!(!is_cloud_metadata_ip(&"100.100.100.201".parse().unwrap()));
        assert!(!is_cloud_metadata_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_cloud_metadata_ip(&"fd01:ec2::254".parse().unwrap()));
    }

    // Narrow private-fetch policy. Unit tests use a thread-local policy snapshot
    // so parallel test threads cannot observe a process-wide environment race;
    // CLI integration tests cover the real environment boundary in a child.

    struct PrivatePolicyGuard {
        previous: Option<Result<PrivateFetchPolicy, String>>,
    }

    impl PrivatePolicyGuard {
        fn from_value(value: &str) -> Self {
            Self::install(PrivateFetchPolicy::parse(value))
        }

        fn disabled() -> Self {
            Self::install(Ok(PrivateFetchPolicy::default()))
        }

        fn install(policy: Result<PrivateFetchPolicy, String>) -> Self {
            let previous = TEST_PRIVATE_FETCH_POLICY.with(|slot| slot.replace(Some(policy)));
            Self { previous }
        }
    }

    impl Drop for PrivatePolicyGuard {
        fn drop(&mut self) {
            TEST_PRIVATE_FETCH_POLICY.with(|slot| {
                slot.replace(self.previous.take());
            });
        }
    }

    #[test]
    fn test_legacy_broad_private_fetch_flag_grants_nothing() {
        let _policy = PrivatePolicyGuard::disabled();

        assert!(validate_fetch_url("http://127.0.0.1/card.json").is_err());
        assert!(validate_fetch_url("http://10.0.0.1/card.json").is_err());
        assert!(!allow_private_fetch());
    }

    #[test]
    fn test_private_fetch_allowlist_accepts_only_exact_host_or_cidr() {
        let _policy = PrivatePolicyGuard::from_value("127.0.0.1/32,10.42.0.0/24,registry.internal");

        assert!(validate_fetch_url("http://127.0.0.1/card.json").is_ok());
        assert!(validate_fetch_url("http://10.42.0.8/card.json").is_ok());
        assert!(validate_fetch_url("http://10.42.1.8/card.json").is_err());

        let approved = validate_outbound_url_with_resolver(
            "http://registry.internal/card.json",
            UrlValidationMode::Fetch,
            &resolver_with("10.99.0.8".parse().unwrap()),
        );
        assert!(approved.is_ok());
        let sibling = validate_outbound_url_with_resolver(
            "http://sibling.internal/card.json",
            UrlValidationMode::Fetch,
            &resolver_with("10.99.0.8".parse().unwrap()),
        );
        assert!(sibling.is_err());
    }

    #[test]
    fn test_private_fetch_allowlist_rejects_cloud_endpoints_even_for_exact_host() {
        let _policy = PrivatePolicyGuard::from_value("registry.internal");

        for address in [
            "169.254.169.254",
            "169.254.170.2",
            "169.254.170.23",
            "169.254.0.23",
            "100.100.100.200",
            "168.63.129.16",
            "fd00:ec2::254",
            "fd20:ce::254",
            "::ffff:168.63.129.16",
            "64:ff9b::169.254.170.2",
        ] {
            let result = validate_outbound_url_with_resolver(
                "http://registry.internal/metadata",
                UrlValidationMode::Fetch,
                &resolver_with(address.parse().unwrap()),
            );
            assert!(result.is_err(), "{address} must remain denied");
            assert!(result.unwrap_err().contains("cloud metadata endpoint"));
        }
    }

    #[test]
    fn test_private_fetch_allowlist_never_relaxes_link_local_or_special_use() {
        let _policy = PrivatePolicyGuard::from_value("registry.internal");

        for address in [
            "169.254.1.1",
            "fe80::1",
            "fec0::1",
            "64:ff9b:1::808:808",
            "100::1",
            "5f00::1",
        ] {
            let result = validate_outbound_url_with_resolver(
                "http://registry.internal/data",
                UrlValidationMode::Fetch,
                &resolver_with(address.parse().unwrap()),
            );
            assert!(result.is_err(), "{address} must remain denied");
        }
    }

    #[test]
    fn test_private_fetch_rejects_mixed_dns_answer_set_unless_every_ip_is_allowed() {
        let _policy = PrivatePolicyGuard::from_value("10.42.0.0/24");

        let mixed = resolver_with_many(vec![
            "93.184.216.34".parse().unwrap(),
            "10.43.0.8".parse().unwrap(),
        ]);
        assert!(validate_outbound_url_with_resolver(
            "http://mixed.example/data",
            UrlValidationMode::Fetch,
            &mixed,
        )
        .is_err());

        let approved_mixed = resolver_with_many(vec![
            "93.184.216.34".parse().unwrap(),
            "10.42.0.8".parse().unwrap(),
        ]);
        assert!(validate_outbound_url_with_resolver(
            "http://mixed.example/data",
            UrlValidationMode::Fetch,
            &approved_mixed,
        )
        .is_ok());
    }

    #[test]
    fn test_private_fetch_policy_parser_fails_closed_on_broad_or_immutable_cidrs() {
        for policy in [
            "0.0.0.0/0",
            "169.254.0.0/16",
            "fe80::/64",
            "fc00::/7",
            "100.100.0.0/16",
            "fd00:ec2::/64",
            "fd20:ce::/64",
            "*.internal",
            "10.0.0.0/33",
            "10.0.0.1/8",
            "[[::1]]/128",
            "10.0.0.0/8,",
        ] {
            assert!(PrivateFetchPolicy::parse(policy).is_err(), "{policy}");
        }
    }

    #[test]
    fn test_invalid_private_fetch_env_fails_even_public_fetch_closed() {
        let _policy = PrivatePolicyGuard::from_value("0.0.0.0/0");
        let result = validate_outbound_url_with_resolver(
            "https://example.com/",
            UrlValidationMode::Fetch,
            &resolver_with("93.184.216.34".parse().unwrap()),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains(PRIVATE_FETCH_ALLOW_ENV));
    }

    #[test]
    fn test_private_fetch_policy_does_not_apply_to_server_urls() {
        let _policy = PrivatePolicyGuard::from_value("10.0.0.0/8");

        let result = validate_outbound_url_with_resolver(
            "https://registry.internal/data",
            UrlValidationMode::Server,
            &resolver_with("10.0.0.8".parse().unwrap()),
        );
        assert!(result.is_err(), "server URLs must ignore fetch exceptions");
    }
}
