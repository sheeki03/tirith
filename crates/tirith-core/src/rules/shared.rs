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

/// Sensitive-credential env var names. Used by `command.rs` (SensitiveEnvExport)
/// and `credential.rs` (dedup suppression).
pub const SENSITIVE_KEY_VARS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
];

/// Sensitive filesystem paths (credential directories, runtime sockets, and the
/// devcontainer `${env:HOME}` / `${localEnv:HOME}` variable forms) that a config
/// file should not bind-mount. Consumed by `configfile.rs` (bind-mount detection).
///
/// NOT shared with `exfil.rs`: the output-side read-and-send directive in
/// `exfil.rs` maintains its OWN sensitive-path list (a regex path-alternation of a
/// DIFFERENT shape, `~/.ssh` | `/etc/` | `.env` | `id_rsa` | …) inline in its
/// rule. The two lists are independent and must be updated together by hand when a
/// path class changes. They are not merged because their shapes differ (this exact
/// `&[&str]` of mount targets vs. a regex fragment).
///
/// This is ALSO distinct from `command.rs`'s private credential-FILE list
/// (`/etc/passwd`, `~/.ssh/id_rsa`), which drives the curl-exfil command rule;
/// those have different shapes on purpose and must not be merged either.
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
    "${env:HOME}/.docker",
    "${localEnv:HOME}/.ssh",
    "${localEnv:HOME}/.aws",
    "${localEnv:HOME}/.docker",
];

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
];

/// `true` when `host` (any case) is a known URL shortener from
/// [`URL_SHORTENER_HOSTS`].
pub fn is_url_shortener(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    URL_SHORTENER_HOSTS.iter().any(|s| lower == *s)
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
