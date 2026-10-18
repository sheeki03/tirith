//! Shared constants and helpers used by multiple rule modules.

/// Minimum length of a base64 run worth treating as an embedded payload (a short
/// run, like a hash or an id, is not interesting). Shared by `aifile.rs` and
/// `configfile.rs`.
pub const MIN_BASE64_BLOB_LEN: usize = 96;

/// Upper bound on how many bytes of a single candidate base64 run are actually
/// fed to the (up to four) decoders. An untrusted file can contain an enormous
/// base64-shaped blob (e.g. a 10 MB run); decoding it in full four times is a CPU
/// and allocation DoS, and pointless: a few KB is already conclusive that a run is a
/// real encoded payload. So a run longer than this cap is validated by decoding
/// only its leading `MAX_BASE64_VALIDATE_LEN` bytes (rounded DOWN to a multiple of
/// 4 so the prefix is itself well-formed base64). The detection is preserved for
/// real embedded secrets, which are far smaller than the cap; a giant blob still
/// matches (its prefix decodes) but bounds the work.
///
/// `pub(crate)` so `deobfuscate`'s short-blob decoder reuses the same upper bound
/// (it scans a much lower 16-char floor but must cap decode work identically).
pub(crate) const MAX_BASE64_VALIDATE_LEN: usize = 8 * 1024;

/// Stable compatibility view retained at its original public type and exact
/// values. Runtime classification uses `sensitive_assets`.
pub const SENSITIVE_KEY_VARS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
];

/// Stable compatibility view retained at its original public type and exact
/// values. Runtime bind classification uses `sensitive_assets`.
pub const SENSITIVE_BIND_PATHS: &[&str] = &[
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/podman/podman.sock",
    "~/.ssh",
    "~/.aws",
    "~/.kube",
    "~/.docker",
    "/etc",
    "/root/.ssh",
    "/root/.aws",
    "${env:HOME}/.ssh",
    "${env:HOME}/.aws",
    "${env:HOME}/.kube",
    "${env:HOME}/.docker",
    "${localEnv:HOME}/.ssh",
    "${localEnv:HOME}/.aws",
    "${localEnv:HOME}/.kube",
    "${localEnv:HOME}/.docker",
    "${env:USERPROFILE}/.ssh",
    "${env:USERPROFILE}/.aws",
    "${env:USERPROFILE}/.kube",
    "${env:USERPROFILE}/.docker",
    "${localEnv:USERPROFILE}/.ssh",
    "${localEnv:USERPROFILE}/.aws",
    "${localEnv:USERPROFILE}/.kube",
    "${localEnv:USERPROFILE}/.docker",
    "${env:HOMEDRIVE}${env:HOMEPATH}/.ssh",
    "${env:HOMEDRIVE}${env:HOMEPATH}/.aws",
    "${env:HOMEDRIVE}${env:HOMEPATH}/.kube",
    "${env:HOMEDRIVE}${env:HOMEPATH}/.docker",
    "${localEnv:HOMEDRIVE}${localEnv:HOMEPATH}/.ssh",
    "${localEnv:HOMEDRIVE}${localEnv:HOMEPATH}/.aws",
    "${localEnv:HOMEDRIVE}${localEnv:HOMEPATH}/.kube",
    "${localEnv:HOMEDRIVE}${localEnv:HOMEPATH}/.docker",
    "%USERPROFILE%/.ssh",
    "%USERPROFILE%/.aws",
    "%USERPROFILE%/.kube",
    "%USERPROFILE%/.docker",
    "%HOMEDRIVE%%HOMEPATH%/.ssh",
    "%HOMEDRIVE%%HOMEPATH%/.aws",
    "%HOMEDRIVE%%HOMEPATH%/.kube",
    "%HOMEDRIVE%%HOMEPATH%/.docker",
];

/// Whether `content` contains a long base64 run that actually decodes (standard
/// or URL-safe, padded or not): the shape of an encoded payload smuggled into a
/// text field. Returns the matched run passed through `truncate` when found.
///
/// The `truncate` parameter is the only thing that differs between call sites:
/// `aifile` truncates with a non-ASCII ellipsis, `configfile` truncates ASCII-
/// only so its evidence string never introduces non-ASCII bytes.
pub fn find_base64_blob_with(
    content: &str,
    truncate: impl Fn(&str, usize) -> String,
) -> Option<String> {
    use base64::Engine as _;
    let bytes = content.as_bytes();
    let is_b64 =
        |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'-' || b == b'_';
    let mut i = 0;
    while i < bytes.len() {
        if !is_b64(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_b64(bytes[i]) {
            i += 1;
        }
        // Tolerate trailing `=` padding.
        let mut end = i;
        while end < bytes.len() && bytes[end] == b'=' {
            end += 1;
        }
        let run = &content[start..end];
        if run.len() >= MIN_BASE64_BLOB_LEN {
            // Cap the bytes actually decoded so a giant base64-shaped blob cannot
            // force four full decodes (DoS). For an over-cap run, validate only a
            // leading prefix; cut on a byte boundary that is a multiple of 4 (and
            // BEFORE any `=` padding, which is only valid at the very end) so the
            // prefix is itself well-formed base64. `run` is ASCII base64-alphabet
            // bytes, so byte indices are char boundaries.
            let to_validate = if run.len() > MAX_BASE64_VALIDATE_LEN {
                &run[..MAX_BASE64_VALIDATE_LEN - (MAX_BASE64_VALIDATE_LEN % 4)]
            } else {
                run
            };
            let decodes = base64::engine::general_purpose::STANDARD
                .decode(to_validate)
                .is_ok()
                || base64::engine::general_purpose::URL_SAFE
                    .decode(to_validate)
                    .is_ok()
                || base64::engine::general_purpose::STANDARD_NO_PAD
                    .decode(to_validate)
                    .is_ok()
                || base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(to_validate)
                    .is_ok();
            if decodes {
                return Some(truncate(run, 64));
            }
        }
        i = end.max(i);
    }
    None
}

/// Known URL-shortener hosts. Centralised so `transport.rs` (`ShortenedUrl`) and
/// `paste_provenance.rs` (host-mismatch escalation) can't drift (M12 ch1).
/// Matching is exact, case-insensitive at the call site.
pub const URL_SHORTENER_HOSTS: &[&str] = &[
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

/// `true` when `host` (any case) is a known URL shortener from
/// [`URL_SHORTENER_HOSTS`].
pub fn is_url_shortener(host: &str) -> bool {
    // repo-0301: DNS names are case-insensitive and a trailing root dot is
    // semantically identical (`bit.ly.` == `bit.ly`).
    let lower = host.to_ascii_lowercase();
    let lower = lower.trim_end_matches('.');
    URL_SHORTENER_HOSTS.contains(&lower)
}

/// `true` when `host` is a loopback / local target that never leaves the
/// machine: `localhost`, the `127.0.0.0/8` loopback block (a real IPv4 loopback
/// address), IPv6 `::1` (bracketed or bare), the unspecified address `0.0.0.0`,
/// or any `*.localhost` name. Centralised so `transport.rs` (PlainHttpToSink) and
/// `escalation.rs` (W7 Network-event derivation) share one definition and cannot
/// drift. Matching is CASE-INSENSITIVE: the host is lowercased internally, so
/// callers may pass a raw host of any casing (`LOCALHOST`, `App.LocalHost`) and
/// need not pre-lowercase. This matters because `transport.rs` passes the raw host
/// straight from URL/SCP parsing (which does not lowercase), and an uppercase
/// loopback host must still be recognised so it does not falsely fire
/// `PlainHttpToSink`.
///
/// The 127.0.0.0/8 case is gated on actually parsing as an IPv4 address: a bare
/// `host.starts_with("127.")` would also match hostnames like `127.evil.example`,
/// marking a real REMOTE host as local and excluding it from network detection.
/// `Ipv4Addr::is_loopback` is true for the whole 127.0.0.0/8 block and false for
/// any non-address string.
pub fn is_loopback_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    matches!(
        host.as_str(),
        "localhost" | "127.0.0.1" | "::1" | "[::1]" | "0.0.0.0"
    ) || host
        .parse::<std::net::Ipv4Addr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
        || host.ends_with(".localhost")
}

/// A socket destination host that names this machine: `localhost`, an IPv4
/// loopback or unspecified address (`127.0.0.0/8`, `0.0.0.0`) in any spelling
/// the WHATWG host parser shares with `inet_aton` (`127.1`, `0x7f.1`), or IPv6
/// `::1` / `::` / an IPv4-mapped loopback, bracketed or bare. Narrower than
/// [`is_loopback_host`]: a `*.localhost` name and any other DNS name (including
/// `127.0.0.1.example`, which a resolver may map anywhere) are remote, because
/// the data-flow sinks that use this decide whether bytes can leave the host.
pub fn is_local_machine_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(address) = host.parse::<std::net::Ipv6Addr>() {
        return local_ipv6(address);
    }
    match url::Host::parse(host) {
        Ok(url::Host::Ipv4(address)) => address.is_loopback() || address.is_unspecified(),
        Ok(url::Host::Domain(domain)) => domain == "localhost",
        _ => false,
    }
}

fn local_ipv6(address: std::net::Ipv6Addr) -> bool {
    address.is_loopback()
        || address.is_unspecified()
        || address
            .to_ipv4_mapped()
            .is_some_and(|mapped| mapped.is_loopback() || mapped.is_unspecified())
}

/// A URL-client destination operand whose authority is spelled literally as
/// this machine: `localhost`, a dotted-quad `127.x.y.z` or `0.0.0.0`, or a
/// bracketed `[::1]` / `[::]` / IPv4-mapped loopback, with at most a numeric
/// port, after an optional `http`, `https`, `ftp`, `ftps`, `ws` or `wss`
/// scheme. The authority may hold nothing else (no userinfo, escapes,
/// backslashes or numeric shorthand), so curl, wget and the WHATWG parser all
/// read the same host and none of them can be steered elsewhere by syntax.
pub fn literal_loopback_destination(destination: &str) -> bool {
    let rest = match destination.split_once("://") {
        Some((scheme, rest)) => {
            if !["http", "https", "ftp", "ftps", "ws", "wss"]
                .iter()
                .any(|candidate| scheme.eq_ignore_ascii_case(candidate))
            {
                return false;
            }
            rest
        }
        None => destination,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty()
        || !authority
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'[' | b']'))
    {
        return false;
    }
    let numeric_port =
        |port: &str| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit());
    if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((inner, after)) = bracketed.split_once(']') else {
            return false;
        };
        if !(after.is_empty() || after.strip_prefix(':').is_some_and(numeric_port)) {
            return false;
        }
        return inner.parse::<std::net::Ipv6Addr>().is_ok_and(local_ipv6);
    }
    let host = match authority.split_once(':') {
        Some((host, port)) if numeric_port(port) => host,
        Some(_) => return false,
        None => authority,
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|address| address.is_loopback() || address.is_unspecified())
}

/// An RFC 1918 private IPv4 address in dotted-quad form (`10.0.0.0/8`,
/// `172.16.0.0/12`, `192.168.0.0/16`): a LAN host. Loopback, link-local
/// (`169.254.0.0/16`, where cloud metadata services live), IPv6 and every
/// other spelling of an address (`0xC0A80114`, `3232235796`) are not.
pub fn is_rfc1918_ipv4_host(host: &str) -> bool {
    host.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| {
        let octets = ip.octets();
        octets[0] == 10
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            || (octets[0] == 192 && octets[1] == 168)
    })
}

/// True when `raw` (a URL or a bare destination operand such as
/// `10.0.0.5:9200/x`) spells its host exactly as `host` (ASCII
/// case-insensitive). URL parsers normalize other spellings of an address
/// (`0xC0A80114`, `3232235796`, `0300.0250.1.24` all become `192.168.1.20`),
/// and those obfuscated spellings must not inherit the plain LAN treatment.
pub fn raw_destination_spells_host(raw: &str, host: &str) -> bool {
    let after_scheme = raw.split_once("://").map_or(raw, |(_, rest)| rest);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, rest)| rest);
    let spelled = match host_port.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => name,
        _ => host_port,
    };
    spelled.eq_ignore_ascii_case(host)
}

/// Canonical "critical" criticality labels for the M8 context/SSH/IaC/container
/// rules; a label outside this set never fires. Centralised to avoid the
/// four-copy drift hazard (PR-127 review #7). Case-insensitive, whitespace-trimmed.
pub fn is_critical_label(label: &str) -> bool {
    let lower = label.trim().to_lowercase();
    matches!(
        lower.as_str(),
        "critical" | "production" | "prod" | "live" | "p0" | "p1"
    )
}

/// Canonical key used by SSH host-label policy and runtime lookup. DNS names
/// and OpenSSH host aliases are case-insensitive, and a final DNS root dot is
/// semantically insignificant. The optional username remains byte-for-byte
/// significant so `Alice@host` cannot silently become `alice@host`.
pub fn canonicalize_ssh_label_key(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (user, host) = match raw.rsplit_once('@') {
        Some((user, host)) if !user.is_empty() => (Some(user), host),
        Some(_) => return None,
        None => (None, raw),
    };
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    let host = host.to_ascii_lowercase();
    Some(match user {
        Some(user) => format!("{user}@{host}"),
        None => host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_base64_blob_caps_giant_run() {
        // A multi-MB base64 run must NOT trigger four full decodes (DoS). The cap
        // validates only a bounded prefix, so this returns quickly AND still detects
        // the blob (a giant encoded payload is, if anything, more suspicious).
        let identity = |s: &str, _max: usize| s.to_string();
        let giant = "A".repeat(4 * 1024 * 1024); // 4 MiB of a valid base64 char
        let found = find_base64_blob_with(&giant, identity);
        assert!(
            found.is_some(),
            "a multi-MB base64 run must still be detected within the cap"
        );
        // A real, small embedded payload below the cap is still detected (the cap
        // does not weaken ordinary detection).
        use base64::Engine as _;
        let small = base64::engine::general_purpose::STANDARD.encode("x".repeat(120));
        assert!(
            find_base64_blob_with(&small, identity).is_some(),
            "a real small base64 payload must still match"
        );
        // A long run of NON-base64-alphabet bytes never forms a candidate run, so the
        // cap path is never even entered.
        let dots = ".".repeat(4 * 1024 * 1024);
        assert!(find_base64_blob_with(&dots, identity).is_none());
    }

    #[test]
    fn is_url_shortener_basic() {
        assert!(is_url_shortener("bit.ly"));
        assert!(is_url_shortener("T.CO"), "case-insensitive");
        assert!(is_url_shortener("tinyurl.com"));
        assert!(!is_url_shortener("github.com"));
        assert!(!is_url_shortener("bit.ly.evil.com"));
    }

    #[test]
    fn ssh_label_keys_fold_only_the_host_identity() {
        assert_eq!(
            canonicalize_ssh_label_key(" Alice@PROD.Example. ").as_deref(),
            Some("Alice@prod.example")
        );
        assert_eq!(
            canonicalize_ssh_label_key("alice@prod.example").as_deref(),
            Some("alice@prod.example")
        );
        assert!(canonicalize_ssh_label_key("@prod.example").is_none());
        assert!(canonicalize_ssh_label_key(".").is_none());
    }

    #[test]
    fn is_critical_label_basic() {
        for s in &["critical", "production", "prod", "live", "p0", "p1"] {
            assert!(is_critical_label(s), "should be critical: {s:?}");
        }
        // Case-insensitive.
        assert!(is_critical_label("Critical"));
        assert!(is_critical_label("PRODUCTION"));
        // Whitespace tolerance.
        assert!(is_critical_label("  prod  "));
        // Non-critical recognised values.
        assert!(!is_critical_label("staging"));
        assert!(!is_critical_label("dev"));
        assert!(!is_critical_label("test"));
        assert!(!is_critical_label("p2"));
        assert!(!is_critical_label(""));
    }

    #[test]
    fn is_loopback_host_only_matches_real_loopback() {
        // Named and IPv6 local targets.
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("app.localhost"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("0.0.0.0"));
        // The whole 127.0.0.0/8 block parses as an IPv4 loopback address.
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.1.2.3"));
        assert!(is_loopback_host("127.255.255.254"));
        // A hostname that merely STARTS WITH "127." is NOT loopback: it is a real
        // remote host and must stay in network detection (no evasion via prefix).
        assert!(!is_loopback_host("127.evil.example"));
        assert!(!is_loopback_host("127.0.0.1.evil.example"));
        // A non-loopback IPv4 address is not local.
        assert!(!is_loopback_host("10.0.0.1"));
        assert!(!is_loopback_host("128.0.0.1"));
    }

    #[test]
    fn local_machine_hosts_exclude_dns_names() {
        for host in [
            "localhost",
            "LocalHost",
            "127.0.0.1",
            "127.1",
            "0x7f.1",
            "2130706433",
            "0.0.0.0",
            "::1",
            "[::1]",
            "::",
            "[::ffff:127.0.0.1]",
        ] {
            assert!(is_local_machine_host(host), "{host}");
        }
        for host in [
            "",
            "localhost.",
            "app.localhost",
            "127.evil.example",
            "127.0.0.1.evil.example",
            "10.0.0.1",
            "[::2]",
            "evil.example",
        ] {
            assert!(!is_local_machine_host(host), "{host}");
        }
    }

    #[test]
    fn literal_loopback_destinations_are_plain_authorities() {
        for destination in [
            "http://localhost:3000/debug",
            "HTTP://LOCALHOST/x",
            "https://127.0.0.1:8443/",
            "http://127.0.0.1",
            "http://[::1]:3000/x?y#z",
            "http://[::ffff:127.0.0.1]/",
            "http://0.0.0.0:8080",
            "localhost:3000/debug",
            "127.0.0.1:8080/api",
            "localhost",
        ] {
            assert!(literal_loopback_destination(destination), "{destination}");
        }
        for destination in [
            "http://localhost@evil.example/",
            "http://localhost:80@evil.example/",
            r"http://localhost\@evil.example/",
            "http://evil.example#@localhost",
            "http://localhost.evil.example/",
            "http://127.0.0.1.evil.example/",
            "http://127.1/",
            "http://2130706433/",
            "http://0x7f000001/",
            "http://%6cocalhost/",
            "http://localhost:/",
            "http://localhost:3000:4000/",
            "http://[::2]/",
            "http://192.168.1.5/",
            "gopher://localhost/",
            "file://localhost/etc/passwd",
            "",
            "//localhost/",
        ] {
            assert!(!literal_loopback_destination(destination), "{destination}");
        }
    }

    #[test]
    fn rfc1918_hosts_are_only_dotted_private_ipv4() {
        for host in ["10.0.0.5", "172.16.0.1", "172.31.255.254", "192.168.1.20"] {
            assert!(is_rfc1918_ipv4_host(host), "{host}");
        }
        for host in [
            "169.254.169.254",
            "100.100.100.200",
            "127.0.0.1",
            "172.15.0.1",
            "172.32.0.1",
            "192.169.0.1",
            "8.8.8.8",
            "0xC0A80114",
            "3232235796",
            "fd00:ec2::254",
            "10.0.0.5.evil.example",
            "lan.example",
        ] {
            assert!(!is_rfc1918_ipv4_host(host), "{host}");
        }
    }

    #[test]
    fn raw_destination_spelling_must_match_the_host() {
        for raw in [
            "http://192.168.1.20/",
            "http://192.168.1.20:8080/health",
            "https://user@192.168.1.20/x?y#z",
            "192.168.1.20",
            "192.168.1.20:9200/_cat/indices",
            "HTTP://192.168.1.20",
        ] {
            assert!(raw_destination_spells_host(raw, "192.168.1.20"), "{raw}");
        }
        for raw in [
            "http://0xC0A80114/",
            "http://3232235796/",
            "http://0300.0250.1.24/",
            "http://192.168.1.020/",
            "http://192.168.1.20./",
            "http://192.168.1.20.evil.example/",
            "0xc0a80114/x",
        ] {
            assert!(!raw_destination_spells_host(raw, "192.168.1.20"), "{raw}");
        }
    }

    #[test]
    fn is_loopback_host_is_case_insensitive() {
        // The host is lowercased internally, so any casing of a loopback name is
        // recognised. This guards transport.rs, which passes the raw (un-lowercased)
        // host and would otherwise fire PlainHttpToSink for an uppercase loopback.
        assert!(is_loopback_host("LOCALHOST"));
        assert!(is_loopback_host("Localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("App.LocalHost"));
        // A real remote host is still not loopback regardless of casing.
        assert!(!is_loopback_host("Evil.example"));
    }
}
