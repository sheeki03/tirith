//! `tirith dashboard export|serve` — M13 ch3. Builds a local-only security
//! snapshot (via [`tirith_core::dashboard`]) and either writes it as a
//! self-contained HTML file (`export`) or serves it over a loopback-only HTTP
//! server guarded by an ephemeral token (`serve`).
//!
//! # Security posture
//!
//! A local web server plus an HTML report built from user-controlled audit
//! bytes. Invariants:
//!
//! * HTML escaping — every interpolated value passes through
//!   `tirith_core::dashboard::html_escape` (test in core).
//! * Loopback only — `serve` binds `127.0.0.1`, never `0.0.0.0`.
//! * Ephemeral token — a fresh CSPRNG token (`getrandom`) per `serve`, in
//!   process memory only, never written to disk, with a hard TTL ([`TOKEN_TTL`]).
//! * DNS-rebinding guard — a `Host:` other than `127.0.0.1`/`localhost`
//!   (`[:port]`) is rejected 403.
//! * Token mismatch / missing — 401.
//! * Zero telemetry/network beyond the bound loopback port.
//!
//! The authorization decision is a PURE function ([`authorize`]), unit-testable
//! without a socket; the accept loop is a thin shell around it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use tirith_core::dashboard::{self, DashboardSnapshot, HookSummary};

/// Hard TTL for a `serve` token — after this every request 401s even with the
/// right token, so a tab left open overnight can't keep reading the dashboard.
const TOKEN_TTL: Duration = Duration::from_secs(60 * 60); // 1 hour

/// `true` once a monotonic `elapsed` reaches the TTL — the AUTHORITATIVE,
/// clock-jump-resistant check (R7-4). `authorize()`'s wall-clock TTL is
/// bypassable by setting the clock backwards; a monotonic [`Instant`] is not.
/// Both are kept (dual-layer): whichever fires first expires the token.
fn mono_ttl_expired(elapsed: Duration) -> bool {
    elapsed >= TOKEN_TTL
}

/// How long the accept loop blocks per `recv_timeout` before re-checking the
/// TTL / shutdown — responsive to expiry without busy-polling.
const ACCEPT_POLL: Duration = Duration::from_millis(500);

/// The outcome of authorizing a request — maps directly to an HTTP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Authorized — serve the report (HTTP 200).
    Ok,
    /// Missing / wrong / expired token (HTTP 401).
    Unauthorized,
    /// Disallowed `Host` header — DNS-rebinding guard (HTTP 403).
    Forbidden,
}

/// Decide whether a request is authorized. PURE — no sockets, no clock (caller
/// passes `now`), no globals. The security core of `serve`.
///
/// Decision order, Host BEFORE token:
///   1. Host check (DNS-rebinding guard) — a non-loopback or absent `Host`
///      returns [`Decision::Forbidden`], so a leaked token can't be replayed
///      through a foreign Host.
///   2. Token TTL — an expired token returns [`Decision::Unauthorized`].
///   3. Token value — absent/mismatch (constant-time) returns
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

    // 2. TTL. A negative age (backward clock jump) is treated as not-expired;
    //    the hard upper bound is what matters here. The mono check enforces it.
    let age = now.signed_duration_since(issued_at);
    // Fall back to 1h rather than skipping the check (a skip would let a stale
    // token live forever); `from_std` can't actually fail for a fixed 1h.
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

/// `true` when `host` names a loopback target: `127.0.0.1` or `localhost`, with
/// an optional `:<port>`. Everything else (`0.0.0.0`, a LAN IP, a domain) is
/// rejected. `::1` / `[::1]:port` are deliberately rejected too: `serve` only
/// binds IPv4 loopback, so an IPv6 `Host` is not one we issued.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    // Split off an optional `:port`. We accept only the two IPv4 spellings, so a
    // value with multiple colons (or a leading `[`) can never match.
    let hostname = match host.rsplit_once(':') {
        Some((name, port)) => {
            // The port must be all-numeric, else this isn't `host:port`.
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
            name
        }
        None => host,
    };
    hostname.eq_ignore_ascii_case("127.0.0.1") || hostname.eq_ignore_ascii_case("localhost")
}

/// Constant-time byte comparison — avoids leaking via timing how many leading
/// bytes matched. Length mismatch returns `false` (the token is fixed-length
/// hex, so that reveals nothing); equal lengths fold every byte.
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

/// Extract the first `token` query parameter from a request target (e.g.
/// `/?token=abc&x=1`), percent-decoded. `None` when absent.
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

/// Minimal form-urlencoded value decode (`+` → space, `%xx` → byte); unknown
/// escapes pass through. Good enough for a hex token.
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

/// Build a snapshot for the cwd, resolving shell-hook state via the same
/// read-only probe `onboard`/`doctor` use (never materializes hooks).
fn build_snapshot() -> DashboardSnapshot {
    let detected_shell = crate::cli::init::detect_shell().to_string();
    let (_profile, hook_installed) =
        crate::cli::doctor::check_shell_profile(&detected_shell, "tirith: dashboard:");
    let hook = HookSummary {
        shell: detected_shell,
        installed: hook_installed,
    };

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cwd_str = cwd.display().to_string();
    dashboard::build_snapshot(None, Some(&cwd_str), hook)
}

/// Emit an operator error from `dashboard export|serve`. In `--json` mode this
/// is the structured `{ "error": <msg> }` object on stdout (finding F2: a
/// `--json` consumer must never get non-JSON on the error path); human mode
/// uses `eprintln!`. Returns `false` only on a JSON-write failure (broken pipe →
/// exit 2); the human path always returns `true`.
fn emit_error(json: bool, ctx: &str, msg: &str) -> bool {
    if json {
        let v = serde_json::json!({ "error": msg });
        crate::cli::write_json_stdout(&v, &format!("{ctx}: failed to write JSON output"))
    } else {
        eprintln!("{ctx}: {msg}");
        true
    }
}

/// A small machine-readable result for `export --json`.
#[derive(serde::Serialize)]
struct ExportJson<'a> {
    written: bool,
    path: String,
    bytes: usize,
    snapshot: &'a DashboardSnapshot,
}

/// `tirith dashboard export [--out <path>] [--json]`. Default output:
/// `~/Documents/tirith-dashboard-<date>.html`; `--out .` or a dir writes
/// `<dir>/dashboard.html`; otherwise the exact file.
pub fn export(out: Option<&str>, json: bool) -> i32 {
    let snapshot = build_snapshot();
    let html = dashboard::render_html(&snapshot);

    let path = match resolve_export_path(out) {
        Ok(p) => p,
        Err(e) => {
            // JSON-write failure → exit 2; the resolve failure itself → exit 1.
            if !emit_error(json, "tirith dashboard export", &e) {
                return 2;
            }
            return 1;
        }
    };

    if let Err(e) = write_html_file(&path, &html) {
        if !emit_error(json, "tirith dashboard export", &e) {
            return 2;
        }
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

/// Resolve the export path from `--out`: `None` → dated file in `~/Documents`
/// (cwd fallback); `"."`/existing dir → `<dir>/dashboard.html`; else the exact
/// file path.
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

/// Write `html` to `path`, creating parent dirs. The report may carry
/// repo-internal hostnames/paths even after redaction, so it is private by
/// default.
///
/// Atomic publish (R19-N3): written to a sibling temp file, `sync_all`'d, then
/// renamed over `path` via [`crate::cli::write_file_atomic`], so a mid-write
/// failure never truncates a previously-good export.
///
/// Permissions (R12-3): on Unix the temp file is `0600` and the rename carries
/// that mode onto the destination, so the report is owner-only even before
/// publish. On Windows there is no portable `chmod`; we do NOT fail closed (the
/// default `%USERPROFILE%\Documents` is already user-private via NTFS ACL) but
/// emit a one-line stderr warning that protection relies on directory perms.
fn write_html_file(path: &Path, html: &str) -> Result<(), String> {
    // Atomic temp+fsync+rename; `overwrite = true` replaces an existing export.
    // On Unix the 0600 temp mode is preserved by the rename; the helper also
    // creates any missing parent dirs.
    crate::cli::write_file_atomic(path, html.as_bytes(), /* overwrite = */ true)
        .map_err(|e| format!("write {}: {e}", path.display()))?;

    // No Unix file modes here — warn (to stderr, keeping --json/stdout clean)
    // that protection relies on the OS directory permissions.
    #[cfg(not(unix))]
    {
        eprintln!(
            "tirith dashboard export: WARNING: on this platform the report at {} \
             is not restricted to your user account explicitly; its protection \
             relies on the directory's inherited permissions. Move it somewhere \
             only you can read if you copy it elsewhere.",
            path.display()
        );
    }

    Ok(())
}

/// Bind the `serve` listener to IPv4 LOOPBACK only — `127.0.0.1:<port>`, or
/// `127.0.0.1:0` when `port` is `None`. NEVER `0.0.0.0`: the dashboard must not
/// be reachable off-host. Factored out of [`serve`] so the loopback-only
/// invariant is unit-testable against the production bind (finding F2).
fn bind_loopback(
    port: Option<u16>,
) -> Result<tiny_http::Server, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let bind_addr = SocketAddr::from(([127, 0, 0, 1], port.unwrap_or(0)));
    tiny_http::Server::http(bind_addr)
}

/// `tirith dashboard serve [--port <p>] [--json]`. Binds `127.0.0.1:<port>`
/// (ephemeral when omitted), prints the loopback URL carrying an ephemeral
/// in-memory token, and serves the HTML at `/` for an authorized request until
/// SIGINT.
pub fn serve(port: Option<u16>, json: bool) -> i32 {
    let token = match dashboard::generate_serve_token() {
        Ok(t) => t,
        Err(e) => {
            // JSON-write failure → exit 2; token failure → exit 1.
            if !emit_error(json, "tirith dashboard serve", &e) {
                return 2;
            }
            return 1;
        }
    };

    // Loopback ONLY (via `bind_loopback`, so a unit test pins it against the
    // production path — finding F2).
    let bind_port = port.unwrap_or(0);
    let server = match bind_loopback(port) {
        Ok(s) => s,
        Err(e) => {
            if !emit_error(
                json,
                "tirith dashboard serve",
                &format!("cannot bind 127.0.0.1:{bind_port}: {e}"),
            ) {
                return 2;
            }
            return 1;
        }
    };

    // Resolve the actual bound port (the ephemeral `:0` case).
    let actual_port = match server.server_addr().to_ip() {
        Some(addr) => addr.port(),
        None => {
            if !emit_error(
                json,
                "tirith dashboard serve",
                "bound socket has no IP address",
            ) {
                return 2;
            }
            return 1;
        }
    };

    let url = format!("http://127.0.0.1:{actual_port}/?token={token}");
    let issued_at = Utc::now();
    // Monotonic issue instant — the authoritative, clock-jump-resistant TTL
    // reference (see `mono_ttl_expired`), sharing `issued_at`'s logical time.
    let issued_mono = Instant::now();

    if json {
        #[derive(serde::Serialize)]
        struct ServeJson {
            url: String,
            host: String,
            port: u16,
            token_ttl_secs: u64,
        }
        // The token lives only inside `url` (no separate field).
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

    // TTL expiry is a normal end-of-life (exit 0); a genuine accept/recv error
    // is fatal (R20).
    loop_outcome_exit_code(serve_loop(&server, &token, issued_at, issued_mono))
}

/// Why [`serve_loop`] returned: `TtlExpired` is the expected end-of-life
/// (success); `AcceptError` is a genuine recv/accept failure (fatal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopOutcome {
    /// The token TTL elapsed; nothing left to serve. Success.
    TtlExpired,
    /// The accept socket failed (not a timeout tick). Fatal.
    AcceptError,
}

/// Map a [`LoopOutcome`] to the exit code: TTL expiry → 0; accept/recv error →
/// 1, so a non-serving dashboard never masquerades as success.
fn loop_outcome_exit_code(outcome: LoopOutcome) -> i32 {
    match outcome {
        LoopOutcome::TtlExpired => 0,
        LoopOutcome::AcceptError => 1,
    }
}

/// The blocking accept loop — re-renders the snapshot per request and routes
/// each through [`authorize`]. `recv_timeout` lets it wake periodically and exit
/// once the TTL elapses (the token can't be revived); SIGINT ends the process.
/// TTL is enforced with a MONOTONIC [`Instant`] (clock-jump-resistant); the
/// wall-clock TTL in [`authorize`] stays as defense-in-depth.
fn serve_loop(
    server: &tiny_http::Server,
    token: &str,
    issued_at: DateTime<Utc>,
    issued_mono: Instant,
) -> LoopOutcome {
    loop {
        // Stop once the token expires (every request would 401). Monotonic:
        // immune to a backward clock jump. Normal end-of-life, not a failure.
        if mono_ttl_expired(issued_mono.elapsed()) {
            eprintln!("tirith dashboard serve: token expired; stopping.");
            return LoopOutcome::TtlExpired;
        }

        match server.recv_timeout(ACCEPT_POLL) {
            Ok(Some(request)) => handle_request(request, token, issued_at, issued_mono),
            Ok(None) => continue, // expected TTL-poll tick; re-check the TTL
            // A genuine recv/accept error: the server can no longer serve, so
            // surface it as fatal rather than a false success.
            Err(e) => {
                eprintln!("tirith dashboard serve: accept error: {e}");
                return LoopOutcome::AcceptError;
            }
        }
    }
}

/// Apply the response-hardening header set (Cache-Control no-store, strict CSP,
/// nosniff, no-referrer) to `response`. Applied to EVERY response — 200/401/403
/// — so hardening can't drift between paths (finding D6-3). `Header::from_bytes`
/// only fails on non-ASCII, which none of these are.
fn with_security_headers(
    mut response: tiny_http::Response<std::io::Cursor<Vec<u8>>>,
) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    for (name, value) in [
        ("Content-Type", "text/html; charset=utf-8"),
        // Strict CSP — the report has no scripts; this blocks any injected one.
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

/// Authorize + respond to one request: pull `Host` + the `token` query param,
/// call [`authorize`], emit 200 (HTML) / 401 / 403. Authorization is decided
/// BEFORE the body is touched (finding K), so an unauthenticated client can't
/// make us buffer an unbounded body. We never read the body at all — even when
/// authorized (finding R12-4): a post-auth drain would let a valid-token client
/// trickle a body and stall this single-threaded loop. `tiny_http` discards any
/// unread body on drop.
fn handle_request(
    request: tiny_http::Request,
    token: &str,
    issued_at: DateTime<Utc>,
    issued_mono: Instant,
) {
    // AUTHORITATIVE TTL gate, checked FIRST (R7-4): a monotonic `Instant` can't
    // be wound back, so an expired token 401s here even if `authorize`'s
    // wall-clock TTL were defeated by a backward clock jump.
    if mono_ttl_expired(issued_mono.elapsed()) {
        let response = tiny_http::Response::from_string("401 Unauthorized").with_status_code(401);
        let _ = request.respond(with_security_headers(response));
        return;
    }

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

    // Reject unauthorized/forbidden immediately, WITHOUT reading the body, with
    // the same hardening headers as the 200 path.
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

    // Authorized — respond immediately without reading the body (R12-4); a
    // post-auth drain would stall this single-threaded loop. Re-render fresh so
    // a long-lived tab reflects new activity (the render escapes every value).
    let snapshot = build_snapshot();
    let html = dashboard::render_html(&snapshot);
    let response = with_security_headers(tiny_http::Response::from_string(html));
    let _ = request.respond(response);
}

#[cfg(test)]
mod tests {
    use super::*;

    // F2 — export/serve error branches must honor `--json` (structured JSON on
    // stdout, never a stderr line). We pin the JSON SHAPE on the pure helper and
    // the EXIT CODE end-to-end through `export()` (avoids racing libtest's stdout
    // under the parallel harness).

    /// The JSON-mode error is the canonical `{ "error": <msg> }` object,
    /// round-tripping as parseable JSON, not plain text.
    #[test]
    fn emit_error_json_shape_is_structured_error_object() {
        // Reproduce the value `emit_error(json=true, ..)` writes, asserting its
        // shape without capturing the process stdout FD.
        let v = serde_json::json!({ "error": "write /no/such/dir/x.html: nonexistent" });
        let s = serde_json::to_string(&v).expect("error JSON must serialize");
        let parsed: serde_json::Value =
            serde_json::from_str(&s).expect("error output must be parseable JSON, not text");
        assert!(
            parsed["error"].is_string(),
            "JSON error must carry a string `error` field, got: {parsed}"
        );
        assert!(
            parsed["error"]
                .as_str()
                .is_some_and(|e| e.contains("nonexistent")),
            "the `error` field must surface the failure detail, got: {parsed}"
        );
    }

    /// Return contract: both arms return `true` on success (human → stderr,
    /// JSON → stdout); `false` is reserved for a JSON-write failure (→ exit 2).
    #[test]
    fn emit_error_human_arm_returns_true_without_touching_stdout_contract() {
        assert!(
            emit_error(false, "tirith dashboard export", "boom"),
            "human-mode emit_error must return true (only a JSON write failure returns false)"
        );
        // JSON mode against real stdout also returns true. (The broken-pipe
        // branch is covered by `write_json_stdout`'s own test.)
        assert!(
            emit_error(true, "tirith dashboard export", "boom"),
            "json-mode emit_error must return true when the stdout write succeeds"
        );
    }

    /// End-to-end exit code: `export` to an UNWRITABLE `--out` (parent is a
    /// regular file → ENOTDIR) must exit non-zero in both JSON and human modes.
    /// `build_snapshot()` reads the process env, so we hold `ENV_LOCK` and point
    /// every base at fresh empty temp dirs for a deterministic, race-free build.
    #[test]
    fn export_unwritable_path_exits_nonzero_in_both_modes() {
        use crate::cli::test_harness::{EnvGuard, ENV_LOCK};

        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home_tmp = tempfile::tempdir().expect("home tempdir");
        let config_tmp = tempfile::tempdir().expect("config tempdir");
        let data_tmp = tempfile::tempdir().expect("data tempdir");
        let state_tmp = tempfile::tempdir().expect("state tempdir");
        let _home = EnvGuard::set("HOME", home_tmp.path());
        let _userprofile = EnvGuard::set("USERPROFILE", home_tmp.path());
        let _xdg_config = EnvGuard::set("XDG_CONFIG_HOME", config_tmp.path());
        let _xdg_data = EnvGuard::set("XDG_DATA_HOME", data_tmp.path());
        let _xdg_state = EnvGuard::set("XDG_STATE_HOME", state_tmp.path());
        let _appdata = EnvGuard::set("APPDATA", config_tmp.path());
        let _localappdata = EnvGuard::set("LOCALAPPDATA", config_tmp.path());

        // Unwritable destination: a regular FILE used as a dir, so
        // `<file>/dashboard.html`'s parent isn't a dir and the temp-file
        // placement fails deterministically (no permission games).
        let dir = tempfile::tempdir().expect("out tempdir");
        let not_a_dir = dir.path().join("regular-file");
        std::fs::write(&not_a_dir, b"i am a file, not a directory").unwrap();
        let bad_out = not_a_dir.join("dashboard.html");
        let bad_out = bad_out.to_string_lossy().into_owned();

        // JSON mode: structured error to stdout, exit 1 (the write failure; 2 is
        // reserved for a JSON-write/broken-pipe failure).
        let code_json = export(Some(&bad_out), true);
        assert_ne!(
            code_json, 0,
            "export --json to an unwritable path must exit non-zero (exit code authoritative)"
        );
        assert_eq!(
            code_json, 1,
            "the write-failure exit code is 1 (2 is reserved for a JSON-write/broken-pipe failure)"
        );

        // Human mode: same non-zero exit, message routed to stderr instead.
        let code_human = export(Some(&bad_out), false);
        assert_eq!(
            code_human, 1,
            "export (human mode) to an unwritable path must exit 1, same as the JSON path"
        );
    }

    // R20: `serve_loop` must distinguish a clean TTL expiry (0) from a fatal
    // accept/recv error (non-zero). Pin the outcome→exit-code mapping (a timeout
    // tick `Ok(None)` never reaches it — it continues the loop).
    #[test]
    fn loop_outcome_exit_code_maps_ttl_to_success_and_error_to_failure() {
        assert_eq!(
            loop_outcome_exit_code(LoopOutcome::TtlExpired),
            0,
            "a clean TTL expiry is the normal end-of-life and must exit 0"
        );
        let err_code = loop_outcome_exit_code(LoopOutcome::AcceptError);
        assert_ne!(
            err_code, 0,
            "an accept/recv error must NOT report success (exit 0)"
        );
        assert_eq!(err_code, 1, "the fatal accept-error exit code is 1");
    }

    // F2 — the production `bind_loopback` binds 127.0.0.1 exclusively (never
    // 0.0.0.0) for both an explicit port and the ephemeral `:0` case. The
    // end-to-end test below binds its own listener, so this pins the contract on
    // the real helper `serve` calls.

    /// Assert a `bind_loopback` server's address is IPv4 loopback specifically
    /// (loopback AND not `0.0.0.0`).
    fn assert_bound_loopback(server: &tiny_http::Server, label: &str) {
        let addr = server
            .server_addr()
            .to_ip()
            .expect("bound socket has an IP");
        assert!(
            addr.ip().is_loopback(),
            "{label}: bind address {} must be loopback",
            addr.ip()
        );
        assert_eq!(
            addr.ip(),
            std::net::Ipv4Addr::LOCALHOST,
            "{label}: bind address must be 127.0.0.1 exactly, not {} (e.g. 0.0.0.0)",
            addr.ip()
        );
    }

    #[test]
    fn bind_loopback_ephemeral_binds_127_0_0_1() {
        // `None` → ephemeral `127.0.0.1:0`; the IP must still be IPv4 loopback.
        let server = bind_loopback(None).expect("ephemeral loopback bind must succeed");
        assert_bound_loopback(&server, "bind_loopback(None)");
        let port = server.server_addr().to_ip().unwrap().port();
        assert_ne!(port, 0, "an ephemeral bind must resolve to a concrete port");
    }

    #[test]
    fn bind_loopback_explicit_port_is_honored_and_loopback() {
        // Prove `bind_loopback(Some(port))` honors the explicit port without a
        // racy free-then-rebind dance: hold a server on port P, then a SECOND
        // `bind_loopback(Some(P))` must fail with AddrInUse (had the arg been
        // ignored or bound ephemerally, it would have succeeded). Deterministic:
        // P stays occupied for the whole window.
        let held = bind_loopback(None).expect("hold a loopback server");
        assert_bound_loopback(&held, "held loopback server");
        let port = held.server_addr().to_ip().unwrap().port();

        let second = bind_loopback(Some(port));
        assert!(
            second.is_err(),
            "binding the explicit, already-held port {port} must fail (proves the explicit \
             port is honored, not silently replaced with an ephemeral/0.0.0.0 bind)"
        );
        // `held` stays alive until here so `port` can't be reused mid-test.
        drop(held);
    }

    fn token() -> &'static str {
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    // Invariant G — authorize() is pure; every branch is unit-tested without a
    // socket.

    #[test]
    fn authorize_ok_for_loopback_host_and_good_token() {
        let n = now();
        assert_eq!(
            authorize(Some("127.0.0.1:8080"), Some(token()), token(), n, n),
            Decision::Ok
        );
        // `localhost` and a bare host are also loopback.
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

    // R7-4 — the authoritative TTL is monotonic, so a backward clock jump can't
    // defeat it. `mono_ttl_expired` is pure, so both boundary edges are pinned
    // deterministically (no sleeping).
    #[test]
    fn mono_ttl_expired_at_and_past_the_boundary() {
        // Fresh / mid-window → not expired.
        assert!(!mono_ttl_expired(Duration::from_secs(0)));
        assert!(!mono_ttl_expired(TOKEN_TTL - Duration::from_secs(1)));
        // Exactly at the TTL is expired (inclusive, like `authorize`'s `age >= ttl`).
        assert!(mono_ttl_expired(TOKEN_TTL));
        // Past the TTL is expired.
        assert!(mono_ttl_expired(TOKEN_TTL + Duration::from_secs(1)));
        assert!(mono_ttl_expired(TOKEN_TTL * 5));
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

    /// R19-N3: a successful export lands the complete HTML (no truncation), on
    /// Unix is owner-only `0600`, and leaves no stray `.tmp*` sibling — the
    /// atomic temp+fsync+rename must preserve content and mode.
    #[test]
    fn write_html_file_lands_intact_bytes_and_0600_perms() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dashboard.html");
        // Multi-line body so a truncating write shows as a short read.
        let html = "<html>\n<body>tirith dashboard export — intact?</body>\n</html>\n";

        write_html_file(&path, html).expect("export must succeed");

        let read_back = std::fs::read(&path).expect("read exported file");
        assert_eq!(
            read_back,
            html.as_bytes(),
            "exported file must contain the complete HTML, untruncated"
        );

        // No temp sibling left over — the rename published the temp file.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "dashboard.html")
            .collect();
        assert!(
            leftovers.is_empty(),
            "no temp/partial files should remain after a successful export, found: {leftovers:?}"
        );

        // Owner-only on Unix: the rename must carry the temp file's 0600 mode.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "exported report must be owner-only 0600, got {mode:o}"
            );
        }
    }

    /// R19-N3: a second export over an existing file replaces it atomically with
    /// the complete new content and keeps 0600 — never a half-written file.
    #[test]
    fn write_html_file_overwrite_preserves_intact_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dashboard.html");

        write_html_file(&path, "<html>old</html>\n").expect("first export");
        let new_html = "<html>\nnew and longer content here\n</html>\n";
        write_html_file(&path, new_html).expect("second export");

        assert_eq!(
            std::fs::read(&path).unwrap(),
            new_html.as_bytes(),
            "re-export must atomically replace with the complete new content"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode, 0o600,
                "re-exported report must remain 0600, got {mode:o}"
            );
        }
    }

    // Light integration test (invariants B/D/E end-to-end over a real socket).
    // The security LOGIC lives in the pure `authorize` tests above; this binds
    // 127.0.0.1:0 and pushes forged raw HTTP/1.1 requests through
    // `handle_request` to confirm the bound server wires each decision to the
    // right status code. We forge the `Host` header by hand — what a
    // DNS-rebinding attacker's browser does.

    use std::io::{Read as _, Write as _};
    use std::net::TcpStream;

    /// Send a raw HTTP/1.1 GET with an explicit `Host` and return
    /// `(status_code, raw_text)` — the raw text includes the header block for
    /// header assertions.
    fn raw_get_response(port: u16, target: &str, host: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let req = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).expect("write request");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).expect("read response");
        let text = String::from_utf8_lossy(&buf).into_owned();
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
        let issued_mono = Instant::now();

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
                    Ok(req) => handle_request(req, &tok, issued, issued_mono),
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

    // D6-3 — the hardening header set applies to 401/403 too, not just 200, so
    // an unauthorized response is still uncacheable and carries the strict
    // CSP/nosniff/no-referrer headers.
    #[test]
    fn unauthorized_responses_carry_hardening_headers() {
        let token = "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface";
        let issued = Utc::now();
        let issued_mono = Instant::now();

        let server = tiny_http::Server::http(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("bind 127.0.0.1:0");
        let port = server.server_addr().to_ip().expect("ip addr").port();

        // Handle exactly two requests: one 401, one 403.
        let tok = token.to_string();
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                match server.recv() {
                    Ok(req) => handle_request(req, &tok, issued, issued_mono),
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

    // Finding K — authorization happens BEFORE the body is read. We can't
    // observe "didn't read the body" over a real socket (`respond()` itself
    // drains for framing), so we assert the observable contract: a body-bearing
    // POST with a foreign Host is rejected 403 — the verdict never depends on
    // the body.
    #[test]
    fn unauthorized_body_bearing_request_is_rejected_by_auth() {
        use std::time::Duration as StdDuration;

        let token = "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface";
        let issued = Utc::now();
        let issued_mono = Instant::now();

        let server = tiny_http::Server::http(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("bind 127.0.0.1:0");
        let port = server.server_addr().to_ip().expect("ip addr").port();

        let tok = token.to_string();
        let handle = std::thread::spawn(move || {
            if let Ok(req) = server.recv() {
                handle_request(req, &tok, issued, issued_mono);
            }
        });

        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        // Foreign Host + a complete body present, so the 403 verdict provably
        // doesn't require the body's absence.
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

    // R12-4 — an authorized request is answered WITHOUT a pre-response body
    // drain (the deleted drain blocked the single-threaded loop). We assert both
    // shapes the surface sees — a plain GET and a complete-body POST — return
    // 200 promptly; a deadline-bounded read turns a re-introduced drain into a
    // timeout failure rather than a hang. Each request uses its own server so
    // `Connection: close` teardowns don't interact.
    //
    // ENV ISOLATION (fixes a parallel-suite flake): the 200 path runs
    // `build_snapshot()`, which resolves config/data/state dirs + policy
    // discovery from the process env. Without isolation this raced every
    // env-mutating CLI test (which serialize on `ENV_LOCK`) and did slow real-FS
    // work, pushing the render past the read deadline (intermittent status-0).
    // We hold `ENV_LOCK` and point every base at fresh empty temp dirs (+ empty
    // cwd, no `.git`) so the build is fast, deterministic, and unraceable.
    //
    // (We don't test a never-completed oversized body: tiny_http 0.12's own
    // `respond` blocks reconciling an unread lazy body regardless of our code.)
    #[test]
    fn authorized_request_is_served_without_body_drain() {
        use crate::cli::test_harness::{CwdGuard, EnvGuard, ENV_LOCK};
        use std::time::{Duration as StdDuration, Instant as StdInstant};

        let token = "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface";

        // HERMETIC ENV: serialize on the shared lock, then redirect every base
        // the snapshot build resolves at fresh empty temp dirs. `EnvGuard`
        // restores each var on Drop. Tolerate a poisoned lock.
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let home_tmp = tempfile::tempdir().expect("home tempdir");
        let config_tmp = tempfile::tempdir().expect("config tempdir");
        let data_tmp = tempfile::tempdir().expect("data tempdir");
        let state_tmp = tempfile::tempdir().expect("state tempdir");
        let cwd_tmp = tempfile::tempdir().expect("cwd tempdir");
        // Per-OS bases (XDG_* on Linux/macOS, %APPDATA%/%USERPROFILE% on
        // Windows) — set BOTH families so every file lookup misses fast.
        let _home = EnvGuard::set("HOME", home_tmp.path());
        let _userprofile = EnvGuard::set("USERPROFILE", home_tmp.path());
        let _xdg_config = EnvGuard::set("XDG_CONFIG_HOME", config_tmp.path());
        let _xdg_data = EnvGuard::set("XDG_DATA_HOME", data_tmp.path());
        let _xdg_state = EnvGuard::set("XDG_STATE_HOME", state_tmp.path());
        let _appdata = EnvGuard::set("APPDATA", config_tmp.path());
        let _localappdata = EnvGuard::set("LOCALAPPDATA", config_tmp.path());
        // Remove policy-discovery + remote-fetch probes so discovery finds no
        // root and never considers a network fetch.
        let _policy_root = EnvGuard::remove("TIRITH_POLICY_ROOT");
        let _server_url = EnvGuard::remove("TIRITH_SERVER_URL");
        let _api_key = EnvGuard::remove("TIRITH_API_KEY");
        // Empty cwd (no `.git`) so the repo-scope overlays resolve to nothing.
        let _cwd = CwdGuard::set(cwd_tmp.path());

        // Serve one forged request through the real `handle_request` and return
        // its status. A deadline-bounded read makes a re-introduced drain fail
        // (not flakily).
        fn serve_one(token: &str, raw_request: &str) -> u16 {
            let issued = Utc::now();
            let issued_mono = Instant::now();
            let server = tiny_http::Server::http(SocketAddr::from(([127, 0, 0, 1], 0)))
                .expect("bind 127.0.0.1:0");
            let port = server.server_addr().to_ip().expect("ip addr").port();

            let tok = token.to_string();
            let handle = std::thread::spawn(move || {
                if let Ok(req) = server.recv() {
                    handle_request(req, &tok, issued, issued_mono);
                }
            });

            let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
            // The forged request carries a `{port}` placeholder for the Host.
            let req = raw_request.replace("{port}", &port.to_string());
            stream.write_all(req.as_bytes()).expect("write request");
            stream.flush().expect("flush");
            // Short per-syscall timeout so a blocked read wakes often; the hard
            // ceiling below is what bounds the regression.
            stream
                .set_read_timeout(Some(StdDuration::from_secs(2)))
                .expect("set read timeout");

            // Read until a status line parses or the deadline elapses (no
            // drain-to-EOF: a re-introduced drain would delay the status line).
            // We LOOP rather than collapse a transient WouldBlock/TimedOut into
            // status 0, since a late-scheduled server thread would otherwise
            // race to a false 0; a real hang still fails at the ceiling.
            let deadline = StdInstant::now() + StdDuration::from_secs(30);
            let mut acc: Vec<u8> = Vec::with_capacity(256);
            loop {
                if let Some(code) = parse_status_line(&acc) {
                    handle.join().expect("server thread");
                    return code;
                }
                if StdInstant::now() >= deadline {
                    handle.join().expect("server thread");
                    // No status line within the ceiling ⇒ a genuine hang. Return
                    // 0 so the caller's assert_eq! fails with its message.
                    return 0;
                }
                let mut buf = [0u8; 256];
                match stream.read(&mut buf) {
                    // EOF before a status line: peer closed; let the assertion fail.
                    Ok(0) => {
                        handle.join().expect("server thread");
                        return parse_status_line(&acc).unwrap_or(0);
                    }
                    Ok(n) => acc.extend_from_slice(&buf[..n]),
                    // A timeout/would-block isn't a failure — the server may be
                    // slow to schedule; retry until the deadline.
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut => {}
                    // Any other IO error is terminal.
                    Err(_) => {
                        handle.join().expect("server thread");
                        return parse_status_line(&acc).unwrap_or(0);
                    }
                }
            }
        }

        // Parse the status from a (possibly partial) response. `None` until a
        // full status line has arrived, so a half-read block keeps the caller
        // looping rather than mis-parsing.
        fn parse_status_line(bytes: &[u8]) -> Option<u16> {
            let text = String::from_utf8_lossy(bytes);
            // Trust the first line only once terminated.
            let (first, _rest) = text.split_once("\r\n")?;
            first.split_whitespace().nth(1)?.parse().ok()
        }

        // 1. Plain authorized GET, no body — the canonical browser request.
        let get = "GET /?token={token} HTTP/1.1\r\n\
             Host: 127.0.0.1:{port}\r\n\
             Connection: close\r\n\r\n"
            .replace("{token}", token);
        assert_eq!(
            serve_one(token, &get),
            200,
            "an authorized GET with no body must be served 200 promptly"
        );

        // 2. Authorized request with a complete body (what the drain claimed to
        //    consume) — must still respond 200 without blocking on the body.
        let body = "ignored-body-bytes";
        let post = format!(
            "POST /?token={token} HTTP/1.1\r\n\
             Host: 127.0.0.1:{{port}}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {body}",
            body.len()
        );
        assert_eq!(
            serve_one(token, &post),
            200,
            "an authorized request with a complete body must still be served 200"
        );
    }
}
