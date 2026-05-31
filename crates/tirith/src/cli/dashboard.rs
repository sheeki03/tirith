//! `tirith dashboard export|serve` — M13 ch3.
//!
//! Builds a local-only security snapshot (via [`tirith_core::dashboard`]) and
//! either writes it as a self-contained HTML file (`export`) or serves it over a
//! loopback-only HTTP server guarded by an ephemeral token (`serve`).
//!
//! # Security posture
//!
//! This is the security-sensitive chunk: a local web server plus an HTML report
//! built from user-controlled audit bytes. The invariants:
//!
//! * **HTML escaping** — every interpolated value passes through
//!   `tirith_core::dashboard::html_escape`; there is no raw path. The escaping
//!   test lives in core.
//! * **Loopback only** — `serve` binds `127.0.0.1` exclusively, never `0.0.0.0`.
//! * **Ephemeral token** — a fresh random token (OS CSPRNG via `getrandom`, the
//!   same source the canary store uses) is generated per `serve` invocation and
//!   lives ONLY in process memory. It is printed in the URL and never written to
//!   `policy.yaml` or any file. The token also has a hard TTL ([`TOKEN_TTL`]):
//!   after it expires every request 401s even with the right token.
//! * **DNS-rebinding guard** — a request whose `Host:` header is not
//!   `127.0.0.1[:port]` / `localhost[:port]` is rejected 403. A rebinding
//!   attacker's browser sends the attacker hostname in `Host`.
//! * **Token mismatch / missing** — 401.
//! * **Zero telemetry, zero network** beyond the bound loopback port.
//!
//! The request-authorization decision is a PURE function ([`authorize`]) so all
//! of the above can be unit-tested without binding a socket. The accept loop is
//! a thin shell around it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use tirith_core::dashboard::{self, DashboardSnapshot, HookSummary};

/// Hard time-to-live for a `serve` token. After this elapses every request is
/// rejected 401 regardless of whether the token value matches — a browser tab
/// left open overnight cannot keep reading the dashboard.
const TOKEN_TTL: Duration = Duration::from_secs(60 * 60); // 1 hour

/// How long the accept loop blocks per `recv_timeout` before re-checking the
/// token TTL / shutdown. Keeps the loop responsive to TTL expiry without busy
/// polling.
const ACCEPT_POLL: Duration = Duration::from_millis(500);

/// The outcome of authorizing a single request. Maps directly to an HTTP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Authorized — serve the report (HTTP 200).
    Ok,
    /// Missing / wrong / expired token (HTTP 401).
    Unauthorized,
    /// Disallowed `Host` header — DNS-rebinding guard (HTTP 403).
    Forbidden,
}

/// Decide whether a single request is authorized. PURE — no sockets, no clock of
/// its own (the caller passes `now`), no globals. This is the security core of
/// `serve`; the accept loop is a thin wrapper that calls it.
///
/// Decision order (Host BEFORE token):
///   1. **Host check (DNS-rebinding guard).** If `host_header` is absent or is
///      not a loopback host (`127.0.0.1` / `localhost`, with an optional
///      `:port`), return [`Decision::Forbidden`]. Checking Host first means a
///      rebinding attacker — whose browser sends the attacker's hostname — is
///      rejected 403 before the token is even consulted, so a leaked token from
///      a different vector still cannot be replayed through a foreign Host.
///   2. **Token TTL.** If `now - issued_at >= TOKEN_TTL`, return
///      [`Decision::Unauthorized`] (the token has expired).
///   3. **Token value.** If `query_token` is absent or does not match
///      `expected_token` (compared in constant time), return
///      [`Decision::Unauthorized`].
///   4. Otherwise [`Decision::Ok`].
pub fn authorize(
    host_header: Option<&str>,
    query_token: Option<&str>,
    expected_token: &str,
    now: DateTime<Utc>,
    issued_at: DateTime<Utc>,
) -> Decision {
    // 1. DNS-rebinding guard — Host must be loopback.
    match host_header {
        Some(h) if is_loopback_host(h) => {}
        _ => return Decision::Forbidden,
    }

    // 2. TTL — an expired token is rejected even if the value matches.
    //    `now - issued_at` may be negative if clocks jump backwards; a negative
    //    age is treated as "not expired" (fail toward the live window — the hard
    //    upper bound is what matters for the leave-a-tab-open threat).
    let age = now.signed_duration_since(issued_at);
    // `from_std` only errors on an out-of-range duration; `TOKEN_TTL` is a fixed
    // 1h so it never does, but fall back to 1h rather than SKIPPING the expiry
    // check (a silent skip would let a stale token live forever).
    let ttl = chrono::Duration::from_std(TOKEN_TTL).unwrap_or_else(|_| chrono::Duration::hours(1));
    if age >= ttl {
        return Decision::Unauthorized;
    }

    // 3. Token value — constant-time compare to avoid a timing oracle.
    match query_token {
        Some(t) if constant_time_eq(t.as_bytes(), expected_token.as_bytes()) => Decision::Ok,
        _ => Decision::Unauthorized,
    }
}

/// `true` when `host` (a raw `Host:` header value) names a loopback target:
/// `127.0.0.1` or `localhost`, optionally followed by `:<port>`. Any other
/// host — including `0.0.0.0`, a LAN IP, or an attacker domain — is rejected.
///
/// We deliberately do NOT accept `::1` here: `serve` only ever binds an IPv4
/// loopback socket, so a request arriving with an IPv6 `Host` is not one we
/// issued and is safer to reject. (The bracketed-IPv6 `Host` form `[::1]:port`
/// is likewise rejected.)
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    // Split off an optional `:port`. A bare IPv6 literal would contain multiple
    // colons; we only accept the two known IPv4 loopback spellings, so a value
    // with more than one colon (or a leading `[`) can never match.
    let hostname = match host.rsplit_once(':') {
        Some((name, port)) => {
            // The port must be all-numeric; otherwise this is not `host:port`.
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            name
        }
        None => host,
    };
    hostname.eq_ignore_ascii_case("127.0.0.1") || hostname.eq_ignore_ascii_case("localhost")
}

/// Constant-time byte comparison. Avoids leaking how many leading bytes of the
/// token matched via response timing. A length mismatch returns `false`; for
/// equal lengths every byte is folded so the running time does not depend on the
/// position of the first differing byte. (The token is a fixed-length hex string,
/// so the length check itself reveals nothing useful.)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract the `token` query parameter from a request target like
/// `/?token=abc&x=1`. Returns the FIRST `token` value, percent-decoded for the
/// `%xx` and `+` forms a browser may emit. Returns `None` when absent.
fn token_from_target(target: &str) -> Option<String> {
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
    for pair in query.split('&') {
        let (key, val) = pair.split_once('=').unwrap_or((pair, ""));
        if key == "token" {
            return Some(percent_decode(val));
        }
    }
    None
}

/// Minimal application/x-www-form-urlencoded value decode (`+` → space, `%xx` →
/// byte). Good enough for a hex token; unknown escapes are passed through.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Build a snapshot for the current working directory, with the shell-hook state
/// resolved via the SAME read-only probe `tirith onboard` / `doctor` use (never
/// materializes hooks).
fn build_snapshot() -> DashboardSnapshot {
    let detected_shell = crate::cli::init::detect_shell().to_string();
    let (_profile, hook_installed) = crate::cli::doctor::check_shell_profile(&detected_shell);
    let hook = HookSummary {
        shell: detected_shell,
        installed: hook_installed,
    };

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cwd_str = cwd.display().to_string();
    dashboard::build_snapshot(None, Some(&cwd_str), hook)
}

/// A small machine-readable result for `export --json`.
#[derive(serde::Serialize)]
struct ExportJson<'a> {
    written: bool,
    path: String,
    bytes: usize,
    snapshot: &'a DashboardSnapshot,
}

/// `tirith dashboard export [--out <path>] [--json]`.
///
/// Default output path: `~/Documents/tirith-dashboard-<date>.html`. `--out .`
/// writes `./dashboard.html`; `--out <dir>` (an existing directory) writes
/// `<dir>/dashboard.html`; `--out <file>` writes exactly that file.
pub fn export(out: Option<&str>, json: bool) -> i32 {
    let snapshot = build_snapshot();
    let html = dashboard::render_html(&snapshot);

    let path = match resolve_export_path(out) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("tirith dashboard export: {e}");
            return 1;
        }
    };

    if let Err(e) = write_html_file(&path, &html) {
        eprintln!("tirith dashboard export: {e}");
        return 1;
    }

    if json {
        let result = ExportJson {
            written: true,
            path: path.display().to_string(),
            bytes: html.len(),
            snapshot: &snapshot,
        };
        if !crate::cli::write_json_stdout(
            &result,
            "tirith dashboard export: failed to write JSON output",
        ) {
            return 2;
        }
    } else {
        println!(
            "Wrote dashboard to {} ({} bytes).",
            path.display(),
            html.len()
        );
        println!("Open it in a browser — it is a self-contained local file with no network calls.");
    }
    0
}

/// Resolve the export output path from the optional `--out`.
///
/// * `None` → `~/Documents/tirith-dashboard-<YYYY-MM-DD>.html` (falls back to the
///   cwd if the home directory cannot be determined).
/// * `"."` or an existing directory → `<dir>/dashboard.html`.
/// * any other value → treated as the exact file path.
fn resolve_export_path(out: Option<&str>) -> Result<PathBuf, String> {
    match out {
        None => {
            let date = Utc::now().format("%Y-%m-%d").to_string();
            let filename = format!("tirith-dashboard-{date}.html");
            let dir = home::home_dir()
                .map(|h| h.join("Documents"))
                .unwrap_or_else(|| PathBuf::from("."));
            Ok(dir.join(filename))
        }
        Some(s) => {
            let p = Path::new(s);
            if s == "." || p.is_dir() {
                Ok(p.join("dashboard.html"))
            } else {
                Ok(p.to_path_buf())
            }
        }
    }
}

/// Write `html` to `path`, creating parent dirs, with 0600 perms on Unix (the
/// report may carry repo-internal hostnames / paths even after redaction —
/// mirrors `incident report --out`).
fn write_html_file(path: &Path, html: &str) -> Result<(), String> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    // Re-assert 0600 even when overwriting a pre-existing (possibly
    // world-readable) file: `mode()` only applies on CREATE. We chmod BEFORE the
    // body write so a chmod failure aborts before sensitive content lands in a
    // file we could not lock down (mirrors audit.rs / incident.rs).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 {}: {e}", path.display()))?;
    }
    f.write_all(html.as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))
}

/// `tirith dashboard serve [--port <p>] [--json]`.
///
/// Binds `127.0.0.1:<port>` (or an OS-assigned ephemeral port when `--port` is
/// omitted), prints the loopback URL carrying an ephemeral in-memory token, and
/// serves the rendered HTML at `/` for an authorized request until SIGINT.
pub fn serve(port: Option<u16>, json: bool) -> i32 {
    let token = match dashboard::generate_serve_token() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("tirith dashboard serve: {e}");
            return 1;
        }
    };

    // Loopback ONLY. The literal IP is never `0.0.0.0` — we never bind a
    // non-loopback interface.
    let bind_port = port.unwrap_or(0);
    let bind_addr = SocketAddr::from(([127, 0, 0, 1], bind_port));
    let server = match tiny_http::Server::http(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tirith dashboard serve: cannot bind 127.0.0.1:{bind_port}: {e}");
            return 1;
        }
    };

    // Read back the actual bound port (resolves the ephemeral `:0` case).
    let actual_port = match server.server_addr().to_ip() {
        Some(addr) => addr.port(),
        None => {
            eprintln!("tirith dashboard serve: bound socket has no IP address");
            return 1;
        }
    };

    let url = format!("http://127.0.0.1:{actual_port}/?token={token}");
    let issued_at = Utc::now();

    if json {
        #[derive(serde::Serialize)]
        struct ServeJson {
            url: String,
            host: String,
            port: u16,
            token_ttl_secs: u64,
        }
        // The token is part of `url`; we intentionally do not break it out as a
        // separate field, but it is fully present in `url` for a scripted opener.
        if !crate::cli::write_json_stdout(
            &ServeJson {
                url: url.clone(),
                host: "127.0.0.1".to_string(),
                port: actual_port,
                token_ttl_secs: TOKEN_TTL.as_secs(),
            },
            "tirith dashboard serve: failed to write JSON output",
        ) {
            return 2;
        }
    } else {
        println!("tirith dashboard — serving on loopback only (127.0.0.1).");
        println!();
        println!("  {url}");
        println!();
        println!(
            "Open the URL above. The token is ephemeral (in memory only, TTL {} min) and is",
            TOKEN_TTL.as_secs() / 60
        );
        println!("never written to disk. Press Ctrl-C to stop.");
    }

    serve_loop(&server, &token, issued_at);
    0
}

/// The blocking accept loop. Re-renders the snapshot per request (cheap; keeps
/// the served report fresh) and routes every request through [`authorize`].
///
/// `recv_timeout` is used so the loop wakes periodically: once the token TTL has
/// elapsed there is nothing useful left to serve, so the loop exits and the
/// process returns (the token can never be revived). SIGINT terminates the
/// process directly.
fn serve_loop(server: &tiny_http::Server, token: &str, issued_at: DateTime<Utc>) {
    let ttl = chrono::Duration::from_std(TOKEN_TTL).unwrap_or_else(|_| chrono::Duration::hours(1));
    loop {
        // Stop accepting once the token has expired — every request would 401.
        if Utc::now().signed_duration_since(issued_at) >= ttl {
            eprintln!("tirith dashboard serve: token expired; stopping.");
            return;
        }

        match server.recv_timeout(ACCEPT_POLL) {
            Ok(Some(request)) => handle_request(request, token, issued_at),
            Ok(None) => continue, // timeout tick — re-check TTL
            Err(e) => {
                eprintln!("tirith dashboard serve: accept error: {e}");
                return;
            }
        }
    }
}

/// Apply the response-hardening header set to `response` and return it.
///
/// Every response we emit — 200, 401, AND 403 — carries the same headers so the
/// hardening cannot drift between the success and error paths (M13 PR #132
/// finding D6-3). `Cache-Control: no-store` keeps even an unauthorized response
/// out of any browser/proxy cache; the strict CSP, `nosniff`, and
/// `no-referrer` apply browser hardening regardless of status.
///
/// `Header::from_bytes` only fails on a non-ASCII header name/value, which none
/// of these are, so the `if let Ok(..)` is best-effort and never drops a header
/// in practice.
fn with_security_headers(
    mut response: tiny_http::Response<std::io::Cursor<Vec<u8>>>,
) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    for (name, value) in [
        ("Content-Type", "text/html; charset=utf-8"),
        // Defense in depth for the report itself — it has no scripts, but
        // a strict CSP makes that explicit and blocks any injected one.
        (
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'",
        ),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Cache-Control", "no-store"),
    ] {
        if let Ok(h) = tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()) {
            response = response.with_header(h);
        }
    }
    response
}

/// Authorize + respond to one request. Pulls the `Host` header and `token` query
/// param, calls [`authorize`], and emits 200 (HTML) / 401 / 403 accordingly.
///
/// Authorization is decided BEFORE the request body is touched (M13 PR #132
/// finding K): the decision derives only from the `Host` header + the `token`
/// query parameter, so an unauthenticated client can never make us read (and
/// buffer) an unbounded body pre-auth. Only after a successful authorize do we
/// drain a BOUNDED amount of the body so the connection can be reused cleanly.
fn handle_request(mut request: tiny_http::Request, token: &str, issued_at: DateTime<Utc>) {
    let host_header = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Host"))
        .map(|h| h.value.as_str().to_string());
    let query_token = token_from_target(request.url());

    let decision = authorize(
        host_header.as_deref(),
        query_token.as_deref(),
        token,
        Utc::now(),
        issued_at,
    );

    // Reject unauthorized / forbidden requests immediately, WITHOUT reading the
    // body — a pre-auth client cannot grow our memory or keep the handler busy.
    // The error responses carry the SAME hardening headers as the 200 path (see
    // `with_security_headers`) so an unauthorized reply is never cacheable and
    // never misses the browser hardening.
    if decision != Decision::Ok {
        let response = match decision {
            Decision::Unauthorized => {
                tiny_http::Response::from_string("401 Unauthorized").with_status_code(401)
            }
            Decision::Forbidden => {
                tiny_http::Response::from_string("403 Forbidden").with_status_code(403)
            }
            Decision::Ok => unreachable!("handled above"),
        };
        let _ = request.respond(with_security_headers(response));
        return;
    }

    // Authorized: drain a BOUNDED slice of the body so the connection can be
    // reused cleanly. We ignore the contents entirely (this is a read-only GET
    // surface); the cap means even an authorized client cannot stream us an
    // unbounded body. Anything beyond the cap is left unread (the response is
    // sent regardless).
    const MAX_DRAIN: usize = 64 * 1024; // 64 KiB — generous for any legit GET body
    {
        // `as_reader()` yields `&mut dyn Read` (a trait object), so the `Sized`
        // combinators (`take`/`by_ref`) don't apply. Drain manually with a fixed
        // buffer, stopping at the cap, so even an authorized client can't stream
        // us an unbounded body. Anything past the cap is left unread; the
        // response is sent regardless.
        let reader = request.as_reader();
        let mut buf = [0u8; 8 * 1024];
        let mut drained = 0usize;
        while drained < MAX_DRAIN {
            match reader.read(&mut buf) {
                Ok(0) => break,        // EOF
                Ok(n) => drained += n, // discard the bytes; we only need to drain
                Err(_) => break,       // best-effort drain
            }
        }
    }

    // Authorized (Decision::Ok) — the only path that reaches here. Re-render
    // fresh each request so a long-lived tab reflects new activity. The render
    // escapes every value (see core).
    let snapshot = build_snapshot();
    let html = dashboard::render_html(&snapshot);
    // Same hardening header set as the 401/403 paths (see `with_security_headers`).
    let response = with_security_headers(tiny_http::Response::from_string(html));
    let _ = request.respond(response);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token() -> &'static str {
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    // -----------------------------------------------------------------------
    // Invariant G — authorize() is pure and every branch is unit-tested
    // WITHOUT binding a socket.
    // -----------------------------------------------------------------------

    #[test]
    fn authorize_ok_for_loopback_host_and_good_token() {
        let n = now();
        assert_eq!(
            authorize(Some("127.0.0.1:8080"), Some(token()), token(), n, n),
            Decision::Ok
        );
        // `localhost` and a bare host (no port) are also loopback.
        assert_eq!(
            authorize(Some("localhost:9000"), Some(token()), token(), n, n),
            Decision::Ok
        );
        assert_eq!(
            authorize(Some("127.0.0.1"), Some(token()), token(), n, n),
            Decision::Ok
        );
        assert_eq!(
            authorize(Some("LOCALHOST"), Some(token()), token(), n, n),
            Decision::Ok,
            "host comparison is case-insensitive"
        );
    }

    #[test]
    fn authorize_forbids_foreign_host_dns_rebinding() {
        let n = now();
        // A DNS-rebinding attacker's browser sends the attacker hostname in Host.
        assert_eq!(
            authorize(Some("evil.example.com"), Some(token()), token(), n, n),
            Decision::Forbidden
        );
        // Even WITH the correct token, a foreign Host is rejected (Host is checked
        // first, so a leaked token cannot be replayed through a foreign Host).
        assert_eq!(
            authorize(Some("attacker.test:8080"), Some(token()), token(), n, n),
            Decision::Forbidden
        );
        // 0.0.0.0 is NOT loopback.
        assert_eq!(
            authorize(Some("0.0.0.0:8080"), Some(token()), token(), n, n),
            Decision::Forbidden
        );
        // A LAN IP that merely starts with 127-looking text is rejected.
        assert_eq!(
            authorize(Some("127.0.0.1.evil.com"), Some(token()), token(), n, n),
            Decision::Forbidden
        );
        // An absent Host header (HTTP/1.0 style) is rejected.
        assert_eq!(
            authorize(None, Some(token()), token(), n, n),
            Decision::Forbidden
        );
        // IPv6 loopback is rejected (we only bind IPv4 loopback).
        assert_eq!(
            authorize(Some("[::1]:8080"), Some(token()), token(), n, n),
            Decision::Forbidden
        );
    }

    #[test]
    fn authorize_unauthorized_for_missing_or_wrong_token() {
        let n = now();
        // Missing token.
        assert_eq!(
            authorize(Some("127.0.0.1:8080"), None, token(), n, n),
            Decision::Unauthorized
        );
        // Wrong token.
        assert_eq!(
            authorize(Some("127.0.0.1:8080"), Some("nope"), token(), n, n),
            Decision::Unauthorized
        );
        // Right length, one byte off.
        let mut wrong = token().to_string();
        wrong.replace_range(0..1, "0");
        assert_eq!(
            authorize(Some("127.0.0.1:8080"), Some(&wrong), token(), n, n),
            Decision::Unauthorized
        );
        // Empty token string.
        assert_eq!(
            authorize(Some("127.0.0.1:8080"), Some(""), token(), n, n),
            Decision::Unauthorized
        );
    }

    #[test]
    fn authorize_unauthorized_when_token_expired() {
        let issued = Utc::now() - chrono::Duration::hours(2); // older than TTL
        let n = Utc::now();
        // Correct Host AND correct token, but the token has aged out → 401.
        assert_eq!(
            authorize(Some("127.0.0.1:8080"), Some(token()), token(), n, issued),
            Decision::Unauthorized
        );
        // Just inside the TTL is still OK.
        let fresh = n - chrono::Duration::minutes(59);
        assert_eq!(
            authorize(Some("127.0.0.1:8080"), Some(token()), token(), n, fresh),
            Decision::Ok
        );
    }

    #[test]
    fn authorize_host_checked_before_ttl_and_token() {
        // A foreign Host with an expired token + wrong token still reports 403
        // (Forbidden), proving Host is evaluated first.
        let issued = Utc::now() - chrono::Duration::hours(5);
        let n = Utc::now();
        assert_eq!(
            authorize(Some("evil.com"), Some("wrong"), token(), n, issued),
            Decision::Forbidden
        );
    }

    // -----------------------------------------------------------------------
    // is_loopback_host unit coverage
    // -----------------------------------------------------------------------

    #[test]
    fn loopback_host_accepts_only_known_loopback_spellings() {
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.0.0.1:8080"));
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("localhost:65535"));
        assert!(is_loopback_host("  localhost:3000  ")); // trimmed

        assert!(!is_loopback_host("0.0.0.0"));
        assert!(!is_loopback_host("example.com"));
        assert!(!is_loopback_host("127.0.0.1:notaport"));
        assert!(!is_loopback_host("127.0.0.1:"));
        assert!(!is_loopback_host("[::1]"));
        assert!(!is_loopback_host("::1"));
        assert!(!is_loopback_host("localhost.evil.com"));
        assert!(!is_loopback_host(""));
    }

    // -----------------------------------------------------------------------
    // token query parsing
    // -----------------------------------------------------------------------

    #[test]
    fn token_from_target_extracts_and_decodes() {
        assert_eq!(token_from_target("/?token=abc"), Some("abc".to_string()));
        assert_eq!(
            token_from_target("/?token=abc&x=1"),
            Some("abc".to_string())
        );
        assert_eq!(
            token_from_target("/?x=1&token=def"),
            Some("def".to_string())
        );
        // No token param.
        assert_eq!(token_from_target("/"), None);
        assert_eq!(token_from_target("/?x=1"), None);
        // Percent / plus decode.
        assert_eq!(token_from_target("/?token=a%2Bb"), Some("a+b".to_string()));
        assert_eq!(token_from_target("/?token=a+b"), Some("a b".to_string()));
    }

    #[test]
    fn constant_time_eq_matches_only_equal_bytes() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn resolve_export_path_variants() {
        // `--out .` → ./dashboard.html
        let p = resolve_export_path(Some(".")).unwrap();
        assert_eq!(p, Path::new("./dashboard.html"));

        // explicit file path is honored verbatim
        let p = resolve_export_path(Some("/tmp/x/report.html")).unwrap();
        assert_eq!(p, Path::new("/tmp/x/report.html"));

        // default → ~/Documents/tirith-dashboard-<date>.html (or ./ fallback)
        let p = resolve_export_path(None).unwrap();
        let name = p.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("tirith-dashboard-"));
        assert!(name.ends_with(".html"));
    }

    #[test]
    fn resolve_export_path_existing_dir_gets_dashboard_html() {
        let dir = tempfile::tempdir().unwrap();
        let p = resolve_export_path(Some(dir.path().to_str().unwrap())).unwrap();
        assert_eq!(p, dir.path().join("dashboard.html"));
    }

    // -----------------------------------------------------------------------
    // Light integration test (invariant B/D/E end-to-end over a REAL socket).
    //
    // The security LOGIC coverage lives in the pure `authorize` tests above;
    // this binds 127.0.0.1:0 and pushes three forged raw HTTP/1.1 requests
    // through the actual `handle_request` path to confirm the bound server
    // wires the decision to the right status code. We forge the `Host` header
    // by hand (a normal HTTP client would set it to the request authority),
    // which is exactly what a DNS-rebinding attacker's browser does.
    // -----------------------------------------------------------------------

    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;

    /// Send a raw HTTP/1.1 GET with an explicit `Host` header and read the FULL
    /// response back as `(status_code, raw_text)`. The raw text includes the
    /// header block so a caller can assert on response headers.
    fn raw_get_response(port: u16, target: &str, host: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let req = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).expect("write request");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).expect("read response");
        let text = String::from_utf8_lossy(&buf).into_owned();
        // Status line: "HTTP/1.1 <code> <reason>".
        let status = text
            .lines()
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        (status, text)
    }

    /// Convenience wrapper that returns just the numeric status code.
    fn raw_get_status(port: u16, target: &str, host: &str) -> u16 {
        raw_get_response(port, target, host).0
    }

    #[test]
    fn serve_loopback_authorizes_real_requests() {
        // A fixed token + fresh issue time so the TTL never expires mid-test.
        let token = "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface";
        let issued = Utc::now();

        let server = tiny_http::Server::http(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("bind 127.0.0.1:0");
        let addr = server.server_addr().to_ip().expect("ip addr");
        // INVARIANT B: the bound address is loopback, never 0.0.0.0.
        assert!(addr.ip().is_loopback(), "must bind a loopback address");
        let port = addr.port();

        // Handle exactly three requests on a worker thread, then drop the server.
        let tok = token.to_string();
        let handle = std::thread::spawn(move || {
            for _ in 0..3 {
                match server.recv() {
                    Ok(req) => handle_request(req, &tok, issued),
                    Err(_) => break,
                }
            }
        });

        // 1. Good loopback Host + good token → 200.
        assert_eq!(
            raw_get_status(
                port,
                &format!("/?token={token}"),
                &format!("127.0.0.1:{port}")
            ),
            200,
            "loopback Host + valid token must serve 200"
        );

        // 2. INVARIANT D: foreign Host (DNS-rebinding) → 403, even with a good token.
        assert_eq!(
            raw_get_status(port, &format!("/?token={token}"), "evil.example.com"),
            403,
            "a non-loopback Host must be refused 403"
        );

        // 3. INVARIANT E: loopback Host, wrong token → 401.
        assert_eq!(
            raw_get_status(port, "/?token=wrong", &format!("127.0.0.1:{port}")),
            401,
            "a wrong token must be rejected 401"
        );

        handle.join().expect("server thread");
    }

    // -----------------------------------------------------------------------
    // M13 PR #132 finding D6-3 — the hardening header set is applied to the
    // 401 (wrong token) and 403 (foreign Host) responses too, not just 200.
    // An unauthorized response must still be uncacheable (`Cache-Control:
    // no-store`) and carry the strict CSP / nosniff / no-referrer headers so
    // the hardening cannot drift between the success and error paths.
    // -----------------------------------------------------------------------
    #[test]
    fn unauthorized_responses_carry_hardening_headers() {
        let token = "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface";
        let issued = Utc::now();

        let server = tiny_http::Server::http(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("bind 127.0.0.1:0");
        let port = server.server_addr().to_ip().expect("ip addr").port();

        // Handle exactly two requests: one 401, one 403.
        let tok = token.to_string();
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                match server.recv() {
                    Ok(req) => handle_request(req, &tok, issued),
                    Err(_) => break,
                }
            }
        });

        // Assert a response's header block carries every hardening header,
        // case-insensitively (HTTP header names are case-insensitive).
        fn assert_hardened(status: u16, text: &str, expected_status: u16, label: &str) {
            assert_eq!(status, expected_status, "{label}: wrong status");
            let lower = text.to_ascii_lowercase();
            for needle in [
                "cache-control: no-store",
                "content-security-policy: default-src 'none'; style-src 'unsafe-inline'",
                "x-content-type-options: nosniff",
                "referrer-policy: no-referrer",
            ] {
                assert!(
                    lower.contains(needle),
                    "{label}: response missing header `{needle}`\nfull response: {text:?}"
                );
            }
        }

        // 401 — loopback Host, wrong token.
        let (status, text) = raw_get_response(port, "/?token=wrong", &format!("127.0.0.1:{port}"));
        assert_hardened(status, &text, 401, "401 wrong-token response");

        // 403 — foreign Host (DNS-rebinding guard), even with a good token.
        let (status, text) =
            raw_get_response(port, &format!("/?token={token}"), "evil.example.com");
        assert_hardened(status, &text, 403, "403 foreign-Host response");

        handle.join().expect("server thread");
    }

    // -----------------------------------------------------------------------
    // M13 PR #132 finding K — authorization happens BEFORE we read the body.
    //
    // `handle_request` now decides `authorize()` from the Host header + the
    // `token` query param and EARLY-RETURNS 401/403 before entering the body
    // drain. We can't reliably observe "didn't read the body" over a real
    // socket because `tiny_http::Request::respond()` itself drains any unread
    // body to keep HTTP framing intact. Instead we assert the observable
    // contract that the reordering guarantees: a POST carrying a non-trivial
    // body, sent with a FORBIDDEN (foreign) Host, is rejected 403 — the auth
    // verdict never depends on the request body. (The pure `authorize` tests
    // above pin the decision order; this end-to-end test pins that the bound
    // server reaches that verdict for a body-bearing request.)
    // -----------------------------------------------------------------------
    #[test]
    fn unauthorized_body_bearing_request_is_rejected_by_auth() {
        use std::time::Duration as StdDuration;

        let token = "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface";
        let issued = Utc::now();

        let server = tiny_http::Server::http(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("bind 127.0.0.1:0");
        let port = server.server_addr().to_ip().expect("ip addr").port();

        let tok = token.to_string();
        let handle = std::thread::spawn(move || {
            if let Ok(req) = server.recv() {
                handle_request(req, &tok, issued);
            }
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        // Foreign Host + a COMPLETE (Content-Length-matching) body. The body is
        // present so the auth verdict provably does not require its absence; the
        // verdict must still be 403 (Host fails the rebinding guard).
        let body = "x".repeat(2048);
        let req = format!(
            "POST /?token=wrong HTTP/1.1\r\n\
             Host: evil.example.com\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {body}",
            body.len()
        );
        stream.write_all(req.as_bytes()).expect("write request");
        stream.flush().expect("flush");
        // Bounded read timeout so a regression can't hang the suite indefinitely.
        stream
            .set_read_timeout(Some(StdDuration::from_secs(10)))
            .expect("set read timeout");

        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf);
        let text = String::from_utf8_lossy(&buf);
        let status: u16 = text
            .lines()
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);

        assert_eq!(
            status, 403,
            "a foreign-Host request must be refused 403 regardless of its body; \
             got status {status} (response: {text:?})"
        );

        handle.join().expect("server thread");
    }
}
