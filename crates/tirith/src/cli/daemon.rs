use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[cfg(unix)]
use std::io::Read as _;
#[cfg(unix)]
use std::time::Instant;
#[cfg(unix)]
use tokio::io::AsyncReadExt as _;

use tirith_core::verdict::{Action, Finding};

#[cfg(unix)]
use tirith_core::engine::{self, AnalysisContext};
#[cfg(unix)]
use tirith_core::extract::ScanContext;
#[cfg(unix)]
use tirith_core::network;
#[cfg(unix)]
use tirith_core::threatdb_api::RuntimeThreatMode;
#[cfg(unix)]
use tirith_core::tokenize::ShellType;
#[cfg(unix)]
use tirith_core::verdict::{upgraded_action_from_findings, Evidence, RuleId, Severity};

/// Directory that holds the daemon's runtime files (socket + PID).
///
/// Resolution order (first that yields a path wins):
///   1. `state_dir()` (`$XDG_STATE_HOME/tirith` or `~/.local/state/tirith`).
///   2. `$XDG_RUNTIME_DIR/tirith` — already a per-user, `0700`, OS-managed dir.
///   3. `/run/user/<euid>/tirith`, but only when `/run/user/<euid>` exists and is
///      owned by the euid (the standard systemd per-user runtime dir).
///   4. Last resort: a *per-uid* `/tmp/tirith-<uid>` directory.
///
/// The earlier options are per-user runtime dirs that are already `0700`; the
/// `/tmp` fallback shares the world-writable, sticky tempdir, so the bare
/// `/tmp/daemon.sock` path used to let any same-host user pre-bind the socket and
/// feed the hook path forged verdicts (F19). A uid-scoped subdir keeps the path
/// predictable for both client and server while denying other users write access.
///
/// Whatever dir is chosen, `ensure_private_dir` is the gate that actually makes
/// it safe to bind inside: it materializes the dir at `0700`, then STATs it and
/// refuses (fail-closed) if it is a symlink, not owned by the euid, or not exactly
/// `0700`. A deterministic `/tmp` path another user pre-created is therefore
/// rejected rather than reused or chmod-coerced.
#[cfg(unix)]
fn runtime_dir() -> PathBuf {
    if let Some(state) = tirith_core::policy::state_dir() {
        return state;
    }

    let euid = unsafe { libc::geteuid() };

    // `$XDG_RUNTIME_DIR` is a per-user 0700 dir on most modern Linux desktops.
    // Treat empty as unset (matches shell `${VAR:-fallback}` semantics). Only use
    // it when the BASE is a real dir we own that is not group/other-writable —
    // otherwise another user could swap the leaf dir or socket from the parent.
    if let Ok(rt) = std::env::var("XDG_RUNTIME_DIR") {
        let trimmed = rt.trim();
        if !trimmed.is_empty() {
            let base = PathBuf::from(trimmed);
            if dir_owned_by_euid(&base, euid) {
                return base.join("tirith");
            }
        }
    }

    // `/run/user/<euid>` is the systemd-managed per-user runtime dir. Only use it
    // when it already exists AND is a safe per-user base (owned, not group/other-
    // writable) — otherwise fall through to the uid-scoped tempdir.
    // `ensure_private_dir` re-verifies the `tirith` subdir.
    let run_user = PathBuf::from(format!("/run/user/{euid}"));
    if dir_owned_by_euid(&run_user, euid) {
        return run_user.join("tirith");
    }

    std::env::temp_dir().join(format!("tirith-{euid}"))
}

/// `true` when `path` is a real directory (not a symlink), owned by `euid`, and
/// NOT writable by group or other. Used to decide whether a per-user runtime base
/// (`$XDG_RUNTIME_DIR`, `/run/user/<euid>`) is safe to bind under: a group/other-
/// writable base would let another local user remove or replace the leaf dir or
/// the socket. `symlink_metadata` (lstat) so a symlinked entry pointing at a
/// victim dir is rejected rather than followed.
#[cfg(unix)]
fn dir_owned_by_euid(path: &std::path::Path, euid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            meta.is_dir()
                && !meta.file_type().is_symlink()
                && meta.uid() == euid
                && (meta.mode() & 0o022) == 0
        }
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn runtime_dir() -> PathBuf {
    tirith_core::policy::state_dir().unwrap_or_else(|| PathBuf::from("/tmp").join("tirith"))
}

fn socket_path() -> PathBuf {
    runtime_dir().join("daemon.sock")
}

fn pid_path() -> PathBuf {
    runtime_dir().join("daemon.pid")
}

/// Create `dir` (and parents) with mode `0700`, then PROVE it is safe to bind
/// inside before returning. This is the gate that defeats a same-host squatter:
/// when `runtime_dir()` falls back to a deterministic path in the world-writable,
/// sticky tempdir (`/tmp/tirith-<uid>`), another local user can `mkdir` it first.
/// Re-asserting `0700` is not enough — an attacker-owned dir would let the daemon
/// bind its socket inside a directory it does not control. So after materializing
/// the dir we STAT it (`symlink_metadata`, lstat — never follow a symlinked dir)
/// and FAIL CLOSED unless ALL hold:
///   * it is a real directory, not a symlink, and
///   * it is owned by our effective uid, and
///   * its permission bits are exactly `0700` (no group/other access).
///
/// A pre-created attacker-owned or loosened/symlinked path is rejected (the daemon
/// refuses to start) rather than reused or chmod-coerced. Owner-by-us tightening
/// stays: a dir WE pre-created world-writable is pulled back to `0700` and then
/// passes the re-stat.
#[cfg(unix)]
fn ensure_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    // Create (then verify) as atomically as practical. `recursive(true)` is
    // idempotent if the path already exists; the stat gate below — not this
    // call — is what decides whether an extant entry is trustworthy.
    std::fs::DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(dir)?;

    let euid = unsafe { libc::geteuid() };

    // lstat first so a symlink the squatter dropped in our place is caught BEFORE
    // any `set_permissions` (which follows symlinks and would chmod the target).
    let meta = std::fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(Error::other(format!(
            "runtime dir {} is a symlink or not a directory; refusing to use it",
            dir.display()
        )));
    }
    if meta.uid() != euid {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "runtime dir {} is owned by uid {}, not {euid}; refusing to use a \
                 directory another user controls",
                dir.display(),
                meta.uid()
            ),
        ));
    }

    // We own it and it is a real dir: safe to tighten a pre-existing looser mode
    // (`recursive(true)` leaves an extant dir's mode untouched).
    if meta.mode() & 0o777 != 0o700 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }

    // Re-stat and require exactly 0700 (no group/other bits). Closes the window
    // between the chmod and now, and rejects any setuid/setgid/sticky variation
    // we did not intend.
    let meta = std::fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() || !meta.is_dir() || meta.uid() != euid {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "runtime dir {} changed identity under us; refusing to use it",
                dir.display()
            ),
        ));
    }
    if meta.mode() & 0o777 != 0o700 {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "runtime dir {} is mode {:#o} after tightening, not 0700; refusing \
                 to bind inside a group/other-accessible directory",
                dir.display(),
                meta.mode() & 0o777
            ),
        ));
    }

    Ok(())
}

/// Restrict the bound socket to owner read/write only (`0600`), so no other user
/// can `connect()` to it even if they can reach the directory. Called right after
/// `UnixListener::bind`.
#[cfg(unix)]
fn set_socket_perms(sock: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))
}

/// Return the effective uid of the process on the other end of `fd`, or `None`
/// if the kernel could not supply peer credentials (e.g. the fd is not a
/// connected `AF_UNIX` socket). Used to reject cross-user connections so a same-
/// host attacker cannot drive the daemon (which the hook path trusts).
///
/// Platform notes for integrators:
/// - Linux: `getsockopt(SOL_SOCKET, SO_PEERCRED)` filling `libc::ucred`; read
///   `ucred.uid` (the peer's *effective* uid at `connect()` time).
/// - macOS/BSD: `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)` filling `libc::xucred`;
///   read `xucred.cr_uid`. NOTE: `libc` (0.2.x) does NOT export `getpeereuid`,
///   so we use `LOCAL_PEERCRED`/`xucred` instead of the `getpeereuid(3)` the
///   task hint mentioned. Verify `cr_version == XUCRED_VERSION` before trusting.
#[cfg(target_os = "linux")]
fn peer_euid(fd: std::os::unix::io::RawFd) -> Option<u32> {
    let mut cred = std::mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            cred.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 || len as usize != std::mem::size_of::<libc::ucred>() {
        return None;
    }
    // SAFETY: getsockopt returned 0 and filled the full struct.
    Some(unsafe { cred.assume_init() }.uid)
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
))]
fn peer_euid(fd: std::os::unix::io::RawFd) -> Option<u32> {
    let mut cred = std::mem::MaybeUninit::<libc::xucred>::zeroed();
    let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERCRED,
            cred.as_mut_ptr() as *mut libc::c_void,
            &mut len,
        )
    };
    // The kernel may report a length shorter than the full struct (fewer
    // groups), so require only that it covered through `cr_uid` rather than an
    // exact match — an over-strict equality would spuriously reject legitimate
    // same-uid peers.
    let min_len = std::mem::offset_of!(libc::xucred, cr_uid) + std::mem::size_of::<libc::uid_t>();
    if rc != 0 || (len as usize) < min_len {
        return None;
    }
    // SAFETY: getsockopt returned 0 and filled at least through `cr_uid`. The
    // backing buffer was zero-initialized, so any unfilled trailing groups read
    // as 0 rather than uninitialized memory.
    let cred = unsafe { cred.assume_init() };
    if cred.cr_version != libc::XUCRED_VERSION {
        return None;
    }
    Some(cred.cr_uid)
}

/// Fallback for Unix platforms we don't have a peer-credential path for: fail
/// closed by returning `None` so the caller drops the connection.
#[cfg(all(
    unix,
    not(target_os = "linux"),
    not(target_os = "macos"),
    not(target_os = "ios"),
    not(target_os = "freebsd"),
    not(target_os = "dragonfly"),
))]
fn peer_euid(_fd: std::os::unix::io::RawFd) -> Option<u32> {
    None
}

/// Wire protocol: one DaemonRequest per newline-delimited JSON line.
#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonRequest {
    pub command: String,
    pub input: String,
    #[serde(default = "default_context")]
    pub context: String,
    pub cwd: Option<String>,
    pub shell: Option<String>,
    #[serde(default)]
    pub interactive: bool,
    /// Client-side TIRITH=0 bypass request from the invoking env.
    #[serde(default)]
    pub bypass_requested: bool,
}

fn default_context() -> String {
    "exec".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DaemonResponse {
    pub action: Action,
    pub findings: Vec<Finding>,
    pub exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub bypass_honored: bool,
    #[serde(default)]
    pub bypass_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_path_used: Option<String>,
    #[serde(default)]
    pub timings_ms: tirith_core::verdict::Timings,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls_extracted_count: Option<usize>,
    #[serde(default)]
    pub tier_reached: u8,
    /// All findings AFTER enrichment but BEFORE paranoia filtering.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub raw_findings: Option<Vec<Finding>>,
    /// Action AFTER enrichment but BEFORE paranoia.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub raw_action: Option<String>,
    /// M11 ch2 — the manifest `allowed[]` entry this command matched, for the
    /// client's audit context. The daemon runs the full `engine::analyze`, so
    /// this is populated from the verdict.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub manifest_allowed_match: Option<String>,
}

/// Connect to the daemon and run a check; `None` if unavailable (caller falls
/// back to local analysis).
#[cfg(unix)]
pub fn try_daemon_check(
    input: &str,
    shell: &str,
    cwd: Option<&str>,
    interactive: bool,
) -> Option<DaemonResponse> {
    let sock = socket_path();
    if !sock.exists() {
        return None;
    }

    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let stream = UnixStream::connect(&sock).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .ok()?;

    let bypass_requested = std::env::var("TIRITH")
        .ok()
        .map(|v| v == "0")
        .unwrap_or(false);

    let req = DaemonRequest {
        command: "check".to_string(),
        input: input.to_string(),
        context: "exec".to_string(),
        cwd: cwd.map(|s| s.to_string()),
        shell: Some(shell.to_string()),
        interactive,
        bypass_requested,
    };

    let mut payload = serde_json::to_string(&req).ok()?;
    payload.push('\n');

    let mut stream_w = stream.try_clone().ok()?;
    stream_w.write_all(payload.as_bytes()).ok()?;
    stream_w.flush().ok()?;

    let reader = BufReader::new(stream);
    let mut line = String::new();
    reader.take(1024 * 1024).read_line(&mut line).ok()?;

    serde_json::from_str::<DaemonResponse>(line.trim()).ok()
}

#[cfg(not(unix))]
pub fn try_daemon_check(
    _input: &str,
    _shell: &str,
    _cwd: Option<&str>,
    _interactive: bool,
) -> Option<DaemonResponse> {
    None
}

#[cfg(unix)]
fn handle_request(req: &DaemonRequest) -> DaemonResponse {
    let empty_resp = |error: Option<String>, code: i32| DaemonResponse {
        action: Action::Allow,
        findings: vec![],
        exit_code: code,
        error,
        bypass_honored: false,
        bypass_available: false,
        policy_path_used: None,
        timings_ms: Default::default(),
        urls_extracted_count: None,
        tier_reached: 0,
        raw_findings: None,
        raw_action: None,
        manifest_allowed_match: None,
    };

    if req.command == "ping" {
        return empty_resp(None, 0);
    }

    if req.command != "check" {
        return empty_resp(Some(format!("unknown command: {}", req.command)), 1);
    }

    let shell_type = req
        .shell
        .as_deref()
        .and_then(|s| s.parse::<ShellType>().ok())
        .unwrap_or(ShellType::Posix);

    let scan_ctx = match req.context.as_str() {
        "paste" => ScanContext::Paste,
        _ => ScanContext::Exec,
    };

    // Match the local engine fast-path: an honored bypass short-circuits at
    // tier 2 with no findings/URLs and zero timings.
    if req.bypass_requested {
        let policy = tirith_core::policy::Policy::discover(req.cwd.as_deref());
        let bypass_allowed = if req.interactive {
            policy.allow_bypass_env
        } else {
            policy.allow_bypass_env_noninteractive
        };
        if bypass_allowed {
            return DaemonResponse {
                action: Action::Allow,
                findings: vec![],
                exit_code: 0,
                error: None,
                bypass_honored: true,
                bypass_available: true,
                policy_path_used: policy.path,
                timings_ms: tirith_core::verdict::Timings {
                    tier0_ms: 0.0,
                    tier1_ms: 0.0,
                    tier2_ms: Some(0.0),
                    tier3_ms: None,
                    total_ms: 0.0,
                },
                urls_extracted_count: None,
                tier_reached: 2,
                raw_findings: None,
                raw_action: None,
                manifest_allowed_match: None,
            };
        }
    }

    let ctx = AnalysisContext {
        input: req.input.clone(),
        shell: shell_type,
        scan_context: scan_ctx,
        raw_bytes: None,
        interactive: req.interactive,
        cwd: req.cwd.clone(),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
    };

    let mut verdict = engine::analyze(&ctx);
    let policy = tirith_core::policy::Policy::discover(ctx.cwd.as_deref());

    let runtime_findings = tirith_core::threatdb_api::enrich_command(
        &req.input,
        shell_type,
        &policy.threat_intel,
        RuntimeThreatMode::Daemon,
    );
    verdict.findings.extend(runtime_findings);

    // Daemon-only: network-aware enrichment is too slow for the sync path.
    enrich_with_network_checks(&mut verdict.findings);

    // Enrichment may add higher-severity findings; recompute the action.
    verdict.action = upgraded_action_from_findings(&verdict.findings, verdict.action);

    // Snapshot after enrichment, before paranoia filtering (ADR-13).
    let raw_findings = Some(verdict.findings.clone());
    let raw_action_str = Some(format!("{:?}", verdict.action));

    engine::filter_findings_by_paranoia(&mut verdict, policy.paranoia);

    // Capture before `verdict.findings` is moved below.
    let manifest_allowed_match = verdict.manifest_allowed_match.clone();

    DaemonResponse {
        action: verdict.action,
        findings: verdict.findings,
        exit_code: verdict.action.exit_code(),
        error: None,
        bypass_honored: verdict.bypass_honored,
        bypass_available: verdict.bypass_available,
        policy_path_used: verdict.policy_path_used,
        timings_ms: verdict.timings_ms,
        urls_extracted_count: verdict.urls_extracted_count,
        tier_reached: verdict.tier_reached,
        raw_findings,
        raw_action: raw_action_str,
        manifest_allowed_match,
    }
}

/// Run network checks on URL-referencing findings (daemon path only, where
/// latency is acceptable).
#[cfg(unix)]
fn enrich_with_network_checks(findings: &mut Vec<Finding>) {
    let mut new_findings = Vec::new();

    // Resolve shortened URLs and surface blocklist hits on destinations.
    for finding in findings.iter_mut() {
        if finding.rule_id != RuleId::ShortenedUrl {
            continue;
        }

        let url = finding.evidence.iter().find_map(|e| match e {
            Evidence::Url { raw } => Some(raw.clone()),
            _ => None,
        });

        if let Some(url) = url {
            if let Some(resolved) = network::resolve_shortened_url(&url) {
                finding.description =
                    format!("{} — resolves to: {}", finding.description, resolved);

                // DNS blocklist on the resolved destination's host.
                if let Some(host) = extract_host_from_url(&resolved) {
                    let blocklist_hits = network::check_dns_blocklist(&host);
                    if !blocklist_hits.is_empty() {
                        new_findings.push(Finding {
                            rule_id: RuleId::ShortenedUrl,
                            severity: Severity::High,
                            title: "Shortened URL destination on DNS blocklist".to_string(),
                            description: format!(
                                "Resolved destination '{}' appears on: {}",
                                resolved,
                                blocklist_hits.join(", ")
                            ),
                            evidence: vec![Evidence::Url { raw: resolved }],
                            human_view: None,
                            agent_view: None,
                            mitre_id: None,
                            custom_rule_id: None,
                        });
                    }
                }
            }
        }
    }

    // DNS blocklist on every URL host in any finding.
    let mut checked_hosts = std::collections::HashSet::new();
    for finding in findings.iter() {
        for evidence in &finding.evidence {
            if let Evidence::Url { raw } = evidence {
                if let Some(host) = extract_host_from_url(raw) {
                    if checked_hosts.insert(host.clone()) {
                        let hits = network::check_dns_blocklist(&host);
                        if !hits.is_empty() {
                            new_findings.push(Finding {
                                rule_id: finding.rule_id,
                                severity: Severity::High,
                                title: "URL host on DNS blocklist".to_string(),
                                description: format!(
                                    "Host '{}' appears on: {}",
                                    host,
                                    hits.join(", ")
                                ),
                                evidence: vec![Evidence::Url { raw: raw.clone() }],
                                human_view: None,
                                agent_view: None,
                                mitre_id: None,
                                custom_rule_id: None,
                            });
                        }
                    }
                }
            }
        }
    }

    findings.extend(new_findings);
}

/// Extract the host portion from a URL string.
fn extract_host_from_url(url: &str) -> Option<String> {
    let after_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .or_else(|| url.strip_prefix("//"))?;

    let end = after_scheme
        .find(['/', '?', '#', ':'])
        .unwrap_or(after_scheme.len());

    let host = &after_scheme[..end];
    if host.is_empty() {
        None
    } else {
        Some(host.to_lowercase())
    }
}

#[cfg(unix)]
fn run_server(sock: &std::path::Path, pid: &std::path::Path) -> i32 {
    if let Some(parent) = sock.parent() {
        // 0700, owned-by-us, non-symlink so no other user can drop a same-named
        // socket beside ours, read the directory, or pre-squat the path (F19).
        // Refuse to start if `ensure_private_dir` can't prove all of that.
        if let Err(e) = ensure_private_dir(parent) {
            eprintln!(
                "tirith: refusing to start — runtime dir {} is not a private \
                 owner-only directory: {e}",
                parent.display()
            );
            return 1;
        }
    }

    // Clean up a stale socket from a previous unclean shutdown.
    let _ = std::fs::remove_file(sock);

    if let Err(e) = std::fs::write(pid, std::process::id().to_string()) {
        eprintln!("tirith: failed to write PID file: {e}");
        return 1;
    }

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("tirith: failed to create tokio runtime: {e}");
            return 1;
        }
    };

    let exit = rt.block_on(async {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixListener;

        let listener = match UnixListener::bind(sock) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("tirith: failed to bind socket {}: {e}", sock.display());
                return 1;
            }
        };

        // Restrict the socket to owner-only (0600) immediately after bind so no
        // other user can connect (F19). Bail if we can't, rather than serve an
        // over-permissive socket.
        if let Err(e) = set_socket_perms(sock) {
            eprintln!(
                "tirith: failed to set 0600 perms on socket {}: {e}",
                sock.display()
            );
            return 1;
        }

        eprintln!(
            "tirith: daemon listening on {} (PID {})",
            sock.display(),
            std::process::id()
        );

        let shutdown = async {
            #[cfg(unix)]
            {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("failed to install SIGTERM handler");
                let mut sigint =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                        .expect("failed to install SIGINT handler");
                tokio::select! {
                    _ = sigterm.recv() => {},
                    _ = sigint.recv() => {},
                }
            }
            #[cfg(not(unix))]
            {
                tokio::signal::ctrl_c().await.ok();
            }
        };

        tokio::pin!(shutdown);

        // Periodic threat DB update: own timer, coordinating with concurrent
        // `tirith check` processes via the same lockfile + next-check-at state.
        let threatdb_update_handle = tokio::spawn(async {
            // Initial delay so the daemon stabilizes first.
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            loop {
                // spawn_blocking — the check does filesystem I/O.
                let should_spawn =
                    tokio::task::spawn_blocking(daemon_should_spawn_update)
                        .await
                        .unwrap_or(false);

                if should_spawn {
                    // Detached child so the daemon doesn't block on the download.
                    let _ = tokio::task::spawn_blocking(|| {
                        if let Ok(exe) = std::env::current_exe() {
                            let _ = std::process::Command::new(exe)
                                .args(["threat-db", "update", "--background"])
                                .stdin(std::process::Stdio::null())
                                .stdout(std::process::Stdio::null())
                                .stderr(std::process::Stdio::null())
                                .spawn();
                        }
                    })
                    .await;
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(15 * 60)).await;
            }
        });

        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    threatdb_update_handle.abort();
                    eprintln!("tirith: daemon shutting down");
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((stream, _addr)) => {
                            tokio::spawn(async move {
                                // Reject cross-user peers: the hook path trusts
                                // the daemon's verdict, so only the owning uid may
                                // connect (F19). Drop silently on mismatch or when
                                // peer creds are unavailable (fail closed).
                                {
                                    use std::os::unix::io::AsRawFd;
                                    let fd = stream.as_raw_fd();
                                    let me = unsafe { libc::geteuid() };
                                    match peer_euid(fd) {
                                        Some(uid) if uid == me => {}
                                        _ => return,
                                    }
                                }

                                let (reader, mut writer) = stream.into_split();
                                // Cap request size to 1 MiB (OOM guard).
                                let mut buf_reader = BufReader::new(reader.take(1024 * 1024));
                                let mut line = String::new();

                                match buf_reader.read_line(&mut line).await {
                                    Ok(0) => return,
                                    Err(_) => return,
                                    Ok(_) => {}
                                }

                                let resp = match serde_json::from_str::<DaemonRequest>(line.trim()) {
                                    Ok(req) => {
                                        // Engine + network checks block — offload so
                                        // the accept loop stays responsive.
                                        tokio::task::spawn_blocking(move || handle_request(&req))
                                            .await
                                            .unwrap_or_else(|_| DaemonResponse {
                                                action: Action::Allow, findings: vec![], exit_code: 1,
                                                error: Some("internal error".to_string()),
                                                bypass_honored: false, bypass_available: false,
                                                policy_path_used: None, timings_ms: Default::default(),
                                                urls_extracted_count: None, tier_reached: 0,
                                                raw_findings: None, raw_action: None,
                                                manifest_allowed_match: None,
                                            })
                                    }
                                    Err(e) => DaemonResponse {
                                        action: Action::Allow, findings: vec![], exit_code: 1,
                                        error: Some(format!("invalid request: {e}")),
                                        bypass_honored: false, bypass_available: false,
                                        policy_path_used: None, timings_ms: Default::default(),
                                        urls_extracted_count: None, tier_reached: 0,
                                        raw_findings: None, raw_action: None,
                                        manifest_allowed_match: None,
                                    },
                                };

                                if let Ok(mut payload) = serde_json::to_string(&resp) {
                                    payload.push('\n');
                                    let _ = writer.write_all(payload.as_bytes()).await;
                                    let _ = writer.flush().await;
                                }
                            });
                        }
                        Err(e) => {
                            eprintln!("tirith: accept error: {e}");
                        }
                    }
                }
            }
        }

        0
    });

    let _ = std::fs::remove_file(sock);
    let _ = std::fs::remove_file(pid);

    exit
}

/// Whether a background threat DB update should be spawned (called from the
/// daemon's periodic timer, blocking context).
#[cfg(unix)]
fn daemon_should_spawn_update() -> bool {
    let policy = tirith_core::policy::Policy::discover(None);
    if policy.threat_intel.auto_update_hours == 0 {
        return false;
    }

    let state = match tirith_core::policy::state_dir() {
        Some(d) => d,
        None => return false,
    };

    let next_check_path = state.join("threatdb-next-check-at");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if let Ok(content) = std::fs::read_to_string(&next_check_path) {
        if let Ok(next_ts) = content.trim().parse::<u64>() {
            if now < next_ts {
                return false;
            }
        }
    }

    // Dedup against recent spawns from other processes (30s).
    let spawned_at_path = state.join("threatdb-spawned-at");
    if let Ok(content) = std::fs::read_to_string(&spawned_at_path) {
        if let Ok(spawned_ts) = content.trim().parse::<u64>() {
            if now.saturating_sub(spawned_ts) < 30 {
                return false;
            }
        }
    }

    let _ = std::fs::create_dir_all(&state);
    let _ = std::fs::write(&spawned_at_path, now.to_string());

    true
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    // kill(pid, 0) probes existence without sending a signal.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    // Conservatively assume alive (Windows should use OpenProcess).
    true
}

#[cfg(unix)]
fn kill_process(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) == 0 }
}

#[cfg(unix)]
pub fn start(detach: bool) -> i32 {
    if detach {
        return start_detached();
    }

    let sock = socket_path();
    let pid = pid_path();

    if pid.exists() {
        if let Ok(content) = std::fs::read_to_string(&pid) {
            if let Ok(pid_num) = content.trim().parse::<u32>() {
                if process_alive(pid_num) {
                    eprintln!("tirith: daemon already running (PID {pid_num})");
                    return 1;
                }
            }
        }
        // Stale PID — previous daemon died without cleaning up.
        let _ = std::fs::remove_file(&pid);
        let _ = std::fs::remove_file(&sock);
    }

    eprintln!("tirith: starting daemon on {}", sock.display());

    // Foreground; production relies on a supervisor (systemd/launchd).
    run_server(&sock, &pid)
}

/// Re-spawn `tirith daemon start` (no `--detach`, so the child runs the
/// foreground path that binds the socket and writes the PID file) detached from
/// this process, then VERIFY it actually came up before reporting success.
///
/// FIX S1: never report "started" blindly. After spawning we poll for up to ~2s
/// for the socket to appear while confirming the child is still alive
/// (`try_wait() == Ok(None)`). Three outcomes:
///   * socket appears, child alive → success (return 0);
///   * child exits early (`try_wait()` yields a status) → the foreground path
///     refused/failed (e.g. already-running, runtime-dir gate, bind error);
///     report it and return 1;
///   * timeout with no socket → report failure, best-effort kill the orphaned
///     child, return 1.
#[cfg(unix)]
fn start_detached() -> i32 {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("tirith: cannot determine current executable to detach: {e}");
            return 1;
        }
    };

    let sock = socket_path();

    // Mirror the detached-spawn idiom used by the periodic threat-DB updater:
    // null all stdio so the background daemon holds no terminal fds, and
    // `setsid()` in the forked child so it leaves the controlling TTY and
    // becomes a session/group leader (it won't die on terminal close / Ctrl-C).
    let mut cmd = Command::new(&exe);
    cmd.args(["daemon", "start"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: `setsid` is async-signal-safe and is the only call in the forked
    // child before exec; it detaches the child from the controlling terminal.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tirith: failed to spawn background daemon: {e}");
            return 1;
        }
    };

    // FIX S1: verify the daemon actually bound before reporting success. Poll up
    // to ~2s (20 × 100ms) for the socket, bailing early if the child exits.
    let child_id = child.id();
    match poll_startup(&mut child, &sock, 20, std::time::Duration::from_millis(100)) {
        StartupOutcome::SocketUp => {
            eprintln!("tirith: daemon started in background (PID {child_id})");
            0
        }
        StartupOutcome::ChildExited(status) => {
            // The foreground child exited before binding — surface its status.
            eprintln!("tirith: daemon failed to start (exited {status})");
            1
        }
        StartupOutcome::PollError(e) => {
            eprintln!("tirith: failed to poll background daemon: {e}");
            let _ = child.kill();
            let _ = child.wait();
            1
        }
        StartupOutcome::TimedOut => {
            // The child may be wedged — best-effort kill so we don't leave an
            // orphan, then report failure.
            eprintln!(
                "tirith: daemon did not come up within 2s (no socket at {})",
                sock.display()
            );
            let _ = child.kill();
            let _ = child.wait();
            1
        }
    }
}

/// Result of polling a freshly spawned detached daemon for startup (FIX S1).
#[cfg(unix)]
#[derive(Debug)]
enum StartupOutcome {
    /// The socket appeared while the child was still alive — daemon is up.
    SocketUp,
    /// The child exited before the socket appeared, carrying its exit status.
    ChildExited(std::process::ExitStatus),
    /// `try_wait()` itself errored.
    PollError(std::io::Error),
    /// The attempt budget elapsed with no socket and the child still running.
    TimedOut,
}

/// Poll `child` up to `attempts` times (sleeping `delay` between attempts) for
/// `sock` to exist, treating early child exit as failure.
///
/// On each attempt: if `try_wait()` shows the child EXITED, return
/// [`StartupOutcome::ChildExited`] (the foreground daemon refused/crashed before
/// binding). If the child is still alive AND the socket now exists, return
/// [`StartupOutcome::SocketUp`]. If `try_wait()` errors, return
/// [`StartupOutcome::PollError`]. If the budget is exhausted with neither, return
/// [`StartupOutcome::TimedOut`]. The socket is checked only while the child is
/// confirmed alive so a stale socket from a crashed child is never mistaken for a
/// successful start.
#[cfg(unix)]
fn poll_startup(
    child: &mut std::process::Child,
    sock: &std::path::Path,
    attempts: u32,
    delay: std::time::Duration,
) -> StartupOutcome {
    for _ in 0..attempts {
        match child.try_wait() {
            Ok(Some(status)) => return StartupOutcome::ChildExited(status),
            Ok(None) => {
                if sock.exists() {
                    return StartupOutcome::SocketUp;
                }
            }
            Err(e) => return StartupOutcome::PollError(e),
        }
        std::thread::sleep(delay);
    }
    StartupOutcome::TimedOut
}

#[cfg(not(unix))]
pub fn start(_detach: bool) -> i32 {
    eprintln!("tirith: daemon requires Unix; Windows named pipe support coming soon");
    1
}

#[cfg(unix)]
pub fn stop() -> i32 {
    let pid = pid_path();
    let sock = socket_path();

    let content = match std::fs::read_to_string(&pid) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("tirith: no PID file found — daemon not running?");
            return 1;
        }
    };

    let pid_num: u32 = match content.trim().parse() {
        Ok(n) => n,
        Err(_) => {
            eprintln!("tirith: invalid PID file");
            let _ = std::fs::remove_file(&pid);
            return 1;
        }
    };

    if !process_alive(pid_num) {
        eprintln!("tirith: daemon (PID {pid_num}) not running — cleaning up stale files");
        let _ = std::fs::remove_file(&pid);
        let _ = std::fs::remove_file(&sock);
        return 0;
    }

    if kill_process(pid_num) {
        eprintln!("tirith: sent SIGTERM to daemon (PID {pid_num})");
        std::thread::sleep(std::time::Duration::from_millis(200));
        let _ = std::fs::remove_file(&pid);
        let _ = std::fs::remove_file(&sock);
        0
    } else {
        eprintln!("tirith: failed to stop daemon (PID {pid_num})");
        1
    }
}

#[cfg(not(unix))]
pub fn stop() -> i32 {
    eprintln!("tirith: daemon stop is not yet supported on this platform");
    1
}

#[cfg(unix)]
pub fn status() -> i32 {
    let sock = socket_path();
    let pid = pid_path();

    let pid_num = if pid.exists() {
        match std::fs::read_to_string(&pid)
            .ok()
            .and_then(|c| c.trim().parse::<u32>().ok())
        {
            Some(n) if process_alive(n) => Some(n),
            Some(_) => {
                eprintln!("tirith: stale PID file (process not running)");
                None
            }
            None => None,
        }
    } else {
        None
    };

    if pid_num.is_none() {
        eprintln!("tirith: daemon is not running");
        return 1;
    }

    let pid_num = pid_num.unwrap();

    if !sock.exists() {
        eprintln!(
            "tirith: daemon running (PID {pid_num}) but socket missing at {}",
            sock.display()
        );
        return 1;
    }

    let start = Instant::now();
    let ping_req = DaemonRequest {
        command: "ping".to_string(),
        input: String::new(),
        context: "exec".to_string(),
        cwd: None,
        shell: None,
        interactive: false,
        bypass_requested: false,
    };

    let ok = (|| -> Option<()> {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixStream;
        use std::time::Duration;

        let stream = UnixStream::connect(&sock).ok()?;
        stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .ok()?;

        let mut payload = serde_json::to_string(&ping_req).ok()?;
        payload.push('\n');

        let mut sw = stream.try_clone().ok()?;
        sw.write_all(payload.as_bytes()).ok()?;
        sw.flush().ok()?;

        let reader = BufReader::new(stream);
        let mut line = String::new();
        reader.take(4096).read_line(&mut line).ok()?;

        serde_json::from_str::<DaemonResponse>(line.trim()).ok()?;
        Some(())
    })();

    let latency = start.elapsed();

    if ok.is_some() {
        eprintln!(
            "tirith: daemon running (PID {pid_num}), latency {:.1}ms",
            latency.as_secs_f64() * 1000.0
        );
        0
    } else {
        eprintln!("tirith: daemon running (PID {pid_num}) but not responding on socket");
        1
    }
}

#[cfg(not(unix))]
pub fn status() -> i32 {
    eprintln!("tirith: daemon status is not yet supported on this platform");
    1
}

#[cfg(test)]
mod tests {
    use super::DaemonResponse;
    use tirith_core::verdict::Action;

    fn base_response() -> DaemonResponse {
        DaemonResponse {
            action: Action::Allow,
            findings: vec![],
            exit_code: 0,
            error: None,
            bypass_honored: false,
            bypass_available: false,
            policy_path_used: None,
            timings_ms: Default::default(),
            urls_extracted_count: None,
            tier_reached: 0,
            raw_findings: None,
            raw_action: None,
            manifest_allowed_match: None,
        }
    }

    /// CodeRabbit R3 #4: the matched `allowed[]` entry must survive the
    /// daemon→client serde boundary (previously `check.rs` hardcoded `None`).
    #[test]
    fn daemon_response_round_trips_manifest_allowed_match() {
        let resp = DaemonResponse {
            manifest_allowed_match: Some("deploy".to_string()),
            ..base_response()
        };
        let wire = serde_json::to_string(&resp).expect("serialize");
        assert!(
            wire.contains("manifest_allowed_match"),
            "the field must be on the wire when Some, got: {wire}"
        );
        let back: DaemonResponse = serde_json::from_str(&wire).expect("deserialize");
        assert_eq!(back.manifest_allowed_match.as_deref(), Some("deploy"));
    }

    /// `None` is omitted on the wire and a pre-upgrade payload without the field
    /// deserializes to `None` — backward-compatible.
    #[test]
    fn daemon_response_omits_and_defaults_manifest_allowed_match() {
        // None => omitted on the wire.
        let resp = base_response();
        let wire = serde_json::to_string(&resp).expect("serialize");
        assert!(
            !wire.contains("manifest_allowed_match"),
            "None must be omitted (skip_serializing_if), got: {wire}"
        );
        // A pre-upgrade payload with no such key still parses, defaulting to None.
        let legacy = r#"{"action":"allow","findings":[],"exit_code":0}"#;
        let back: DaemonResponse = serde_json::from_str(legacy).expect("deserialize legacy");
        assert!(
            back.manifest_allowed_match.is_none(),
            "a payload without the field must default to None"
        );
    }

    // ---- F19: Unix socket auth / permission hardening ----

    /// Unique temp dir under the system tempdir for a single test, removed on
    /// drop. Avoids a hard dep on `tempfile` in the test path.
    #[cfg(unix)]
    struct TmpDir(std::path::PathBuf);

    #[cfg(unix)]
    impl TmpDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static CTR: AtomicU64 = AtomicU64::new(0);
            let n = CTR.fetch_add(1, Ordering::Relaxed);
            let p =
                std::env::temp_dir().join(format!("tirith-f19-{tag}-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            Self(p)
        }
    }

    #[cfg(unix)]
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(unix)]
    fn mode_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    /// `ensure_private_dir` creates the runtime dir (and parents) at mode 0700.
    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_creates_0700() {
        let tmp = TmpDir::new("mkdir");
        let nested = tmp.0.join("a").join("b");
        super::ensure_private_dir(&nested).expect("create private dir");
        assert!(nested.is_dir());
        assert_eq!(mode_of(&nested), 0o700, "leaf dir must be 0700");
        // The intermediate dir we created is locked down too.
        assert_eq!(mode_of(&tmp.0.join("a")), 0o700, "parent dir must be 0700");
    }

    /// A pre-existing, looser-permission dir is tightened back to 0700 (closes a
    /// peer pre-creating the path world-writable before the daemon starts).
    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_tightens_existing_loose_dir() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TmpDir::new("tighten");
        std::fs::create_dir_all(&tmp.0).expect("pre-create");
        std::fs::set_permissions(&tmp.0, std::fs::Permissions::from_mode(0o777)).expect("loosen");
        assert_eq!(mode_of(&tmp.0), 0o777, "precondition: world-writable");
        super::ensure_private_dir(&tmp.0).expect("tighten");
        assert_eq!(mode_of(&tmp.0), 0o700, "must be re-tightened to 0700");
    }

    /// After binding a real listener, `set_socket_perms` leaves the socket file
    /// at mode 0600 (mirrors `run_server`'s post-bind step).
    #[cfg(unix)]
    #[test]
    fn set_socket_perms_makes_socket_0600() {
        let tmp = TmpDir::new("sock");
        super::ensure_private_dir(&tmp.0).expect("dir");
        let sock = tmp.0.join("daemon.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
        super::set_socket_perms(&sock).expect("chmod socket");
        assert_eq!(mode_of(&sock), 0o600, "socket must be owner-only 0600");
        // And the containing runtime dir is 0700.
        assert_eq!(mode_of(&tmp.0), 0o700, "runtime dir must be 0700");
    }

    /// `peer_euid` on a self-connected socket pair reports our own euid, and the
    /// daemon's accept-time comparison (`uid == geteuid()`) accepts it. A forged
    /// non-matching uid is rejected by the same comparison.
    #[cfg(unix)]
    #[test]
    fn peer_euid_matches_self_and_rejects_other() {
        use std::os::unix::io::AsRawFd;
        let (a, _b) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let me = unsafe { libc::geteuid() };

        let peer = super::peer_euid(a.as_raw_fd());
        // On Linux/macOS we expect a concrete answer equal to our own euid.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let peer = peer.expect("peer_euid should resolve on linux/macos");
            assert_eq!(peer, me, "a self-connected pair must report our euid");
        }

        // The accept-loop decision: accept iff Some(uid) == me. A mismatching
        // uid (here me+1) must be rejected regardless of platform.
        let accepts = |p: Option<u32>| matches!(p, Some(uid) if uid == me);
        if peer.is_some() {
            assert!(accepts(peer), "matching euid must be accepted");
        }
        assert!(
            !accepts(Some(me.wrapping_add(1))),
            "a non-matching euid must be rejected"
        );
        assert!(
            !accepts(None),
            "missing peer creds must be rejected (fail closed)"
        );
    }

    /// The runtime dir is the state dir when available, and `socket_path` /
    /// `pid_path` sit directly inside it (no bare-`/tmp` join).
    #[cfg(unix)]
    #[test]
    fn runtime_dir_drives_socket_and_pid_paths() {
        let dir = super::runtime_dir();
        if let Some(state) = tirith_core::policy::state_dir() {
            assert_eq!(dir, state, "runtime dir should prefer state_dir when set");
        }
        assert_eq!(super::socket_path(), dir.join("daemon.sock"));
        assert_eq!(super::pid_path(), dir.join("daemon.pid"));
        // Whatever the runtime dir is, it is never the shared, world-writable
        // tempdir itself (F19): a fallback must be a uid-scoped *subdir*.
        assert_ne!(
            dir,
            std::env::temp_dir(),
            "runtime dir must never be the bare tempdir"
        );
    }

    /// The `/tmp` fallback (used only when `state_dir()` is `None`) is a
    /// uid-scoped `tirith-<uid>` subdirectory of the tempdir, not bare `/tmp`.
    /// Verified by replicating the fallback construction so the test never has to
    /// mutate process-global `HOME` / `XDG_STATE_HOME` (which would race other
    /// parallel tests in this binary).
    #[cfg(unix)]
    #[test]
    fn tmp_fallback_dir_is_uid_scoped() {
        let uid = unsafe { libc::geteuid() };
        let fallback = std::env::temp_dir().join(format!("tirith-{uid}"));
        let tmp = std::env::temp_dir();
        assert!(
            fallback.starts_with(&tmp) && fallback != tmp,
            "fallback must be a subdir of the tempdir, got {}",
            fallback.display()
        );
        let name = fallback.file_name().and_then(|s| s.to_str()).unwrap_or("");
        assert_eq!(name, format!("tirith-{uid}"), "fallback must be uid-scoped");
        // `ensure_private_dir` (the helper run_server uses on this path)
        // materializes any such dir at 0700 — proven by
        // `ensure_private_dir_creates_0700`, so we don't touch the shared
        // production fallback path here.
    }

    /// A pre-existing fallback dir owned by us at exactly mode 0700 is accepted
    /// (the common case: our own prior run, or a freshly created dir).
    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_accepts_owned_0700() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TmpDir::new("accept0700");
        std::fs::create_dir_all(&tmp.0).expect("pre-create");
        std::fs::set_permissions(&tmp.0, std::fs::Permissions::from_mode(0o700)).expect("0700");
        // Owned by us (this process created it) and exactly 0700 → accepted.
        super::ensure_private_dir(&tmp.0).expect("owned 0700 dir must be accepted");
        assert_eq!(mode_of(&tmp.0), 0o700, "still 0700 after the gate");
    }

    /// A fallback dir with loose perms (0777) that WE own is tightened to 0700 and
    /// then accepted — the gate coerces our own loosened dir but never an
    /// attacker-owned one (that path fails the ownership check, which we can't
    /// simulate without root).
    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_tightens_loose_owned_dir() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TmpDir::new("loose0777");
        std::fs::create_dir_all(&tmp.0).expect("pre-create");
        std::fs::set_permissions(&tmp.0, std::fs::Permissions::from_mode(0o777)).expect("loosen");
        assert_eq!(mode_of(&tmp.0), 0o777, "precondition: world-writable");
        // We own it, so the gate tightens 0777 → 0700 and the re-stat passes.
        super::ensure_private_dir(&tmp.0).expect("owned loose dir must be tightened, not rejected");
        assert_eq!(mode_of(&tmp.0), 0o700, "must be re-tightened to 0700");
    }

    /// A runtime dir that is a SYMLINK (even to a directory we own) is rejected:
    /// `ensure_private_dir` lstat-refuses it rather than binding through the link.
    /// This exercises the same fail-closed gate that rejects an attacker-owned
    /// pre-created `/tmp/tirith-<uid>` (which we cannot simulate without root).
    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_rejects_symlinked_dir() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TmpDir::new("symlink");
        // A real target dir we own, locked down to 0700 so ONLY the symlink-ness
        // (not perms/ownership) is what the gate rejects.
        let target = tmp.0.join("real-target");
        std::fs::create_dir_all(&target).expect("create target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).expect("0700");

        let link = tmp.0.join("link-to-target");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let err = super::ensure_private_dir(&link)
            .expect_err("a symlinked runtime dir must be rejected (fail closed)");
        let msg = err.to_string();
        assert!(
            msg.contains("symlink") || msg.contains("not a directory"),
            "rejection must cite the symlink, got: {msg}"
        );
        // The target's mode was NOT coerced through the link.
        assert_eq!(
            mode_of(&target),
            0o700,
            "gate must not chmod through the link"
        );
    }

    /// `dir_owned_by_euid` is true for a real dir we own and false for a symlink
    /// (even one pointing at a dir we own) — the predicate that decides whether
    /// `/run/user/<euid>` is a usable runtime base.
    #[cfg(unix)]
    #[test]
    fn dir_owned_by_euid_rejects_symlink() {
        let tmp = TmpDir::new("ownedby");
        let euid = unsafe { libc::geteuid() };
        let target = tmp.0.join("d");
        std::fs::create_dir_all(&target).expect("create dir");
        assert!(
            super::dir_owned_by_euid(&target, euid),
            "a real dir we own must be accepted"
        );

        let link = tmp.0.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(
            !super::dir_owned_by_euid(&link, euid),
            "a symlink must be rejected even when its target is owned by us"
        );

        // A non-existent path is not a usable base.
        assert!(
            !super::dir_owned_by_euid(&tmp.0.join("missing"), euid),
            "a missing path must be rejected"
        );
    }

    #[cfg(unix)]
    #[test]
    fn dir_owned_by_euid_rejects_group_or_other_writable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TmpDir::new("loosebase");
        let euid = unsafe { libc::geteuid() };
        let dir = tmp.0.join("d");
        std::fs::create_dir_all(&dir).expect("create dir");
        // A base we own but that is group/other-writable lets another user swap the
        // leaf dir or socket from the parent, so it must be rejected.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        assert!(
            !super::dir_owned_by_euid(&dir, euid),
            "a group/other-writable base must be rejected even when we own it"
        );
        // Tightening to 0700 makes it acceptable again.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        assert!(
            super::dir_owned_by_euid(&dir, euid),
            "an owned 0700 base must be accepted"
        );
    }

    /// `runtime_dir()` honors `XDG_RUNTIME_DIR` (as `<dir>/tirith`) when
    /// `state_dir()` is unset. Mutates a process-global env var, so it is marked
    /// `#[ignore]` to avoid racing the other parallel tests in this binary that
    /// read env; run explicitly with `--ignored` (or in isolation) to verify.
    #[cfg(unix)]
    #[test]
    #[ignore = "mutates process-global XDG env; run with --ignored in isolation"]
    fn runtime_dir_prefers_xdg_runtime_dir_when_no_state_dir() {
        let tmp = TmpDir::new("xdgrt");
        std::fs::create_dir_all(&tmp.0).expect("create");
        // Clear state-dir inputs so resolution falls past option (1).
        std::env::remove_var("XDG_STATE_HOME");
        std::env::remove_var("HOME");
        std::env::set_var("XDG_RUNTIME_DIR", &tmp.0);
        let dir = super::runtime_dir();
        assert_eq!(
            dir,
            tmp.0.join("tirith"),
            "with no state_dir, XDG_RUNTIME_DIR/tirith should win"
        );
        std::env::remove_var("XDG_RUNTIME_DIR");
    }

    // ---- D: `daemon start --detach` startup verification (FIX S1) ----

    /// Spawn a real, long-lived child so `poll_startup` can observe it as alive.
    /// Killed on drop so a passing/failing test never leaks a process.
    #[cfg(unix)]
    struct LiveChild(std::process::Child);

    #[cfg(unix)]
    impl LiveChild {
        /// A process that stays alive well past the poll budget.
        fn sleeping() -> Self {
            let child = std::process::Command::new("sleep")
                .arg("30")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn `sleep 30`");
            Self(child)
        }
    }

    #[cfg(unix)]
    impl Drop for LiveChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// When the socket appears while the child is still alive, `poll_startup`
    /// reports `SocketUp` — the success path of FIX S1.
    #[cfg(unix)]
    #[test]
    fn poll_startup_reports_socket_up_when_socket_appears() {
        let tmp = TmpDir::new("poll-up");
        std::fs::create_dir_all(&tmp.0).expect("dir");
        let sock = tmp.0.join("daemon.sock");
        // Create the "socket" file up front; the live child never touches it, so
        // this isolates the socket-appeared decision from any real daemon.
        std::fs::write(&sock, b"").expect("create sock placeholder");

        let mut live = LiveChild::sleeping();
        let outcome =
            super::poll_startup(&mut live.0, &sock, 20, std::time::Duration::from_millis(5));
        assert!(
            matches!(outcome, super::StartupOutcome::SocketUp),
            "socket present + child alive must yield SocketUp, got {outcome:?}"
        );
    }

    /// When the child exits before the socket appears, `poll_startup` reports
    /// `ChildExited` (carrying the status) instead of blindly succeeding — the
    /// core of FIX S1.
    #[cfg(unix)]
    #[test]
    fn poll_startup_reports_child_exited_when_child_dies() {
        let tmp = TmpDir::new("poll-exit");
        std::fs::create_dir_all(&tmp.0).expect("dir");
        // No socket is ever created.
        let sock = tmp.0.join("daemon.sock");

        // `true` exits 0 immediately; wait for it so the first `try_wait()` in
        // `poll_startup` observes the exit deterministically.
        let mut child = std::process::Command::new("true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn `true`");
        let _ = child.wait();

        let outcome =
            super::poll_startup(&mut child, &sock, 20, std::time::Duration::from_millis(5));
        match outcome {
            super::StartupOutcome::ChildExited(status) => {
                assert!(status.success(), "`true` exits 0");
            }
            other => panic!("an early-exiting child must yield ChildExited, got {other:?}"),
        }
        assert!(!sock.exists(), "no socket should have been created");
    }

    /// When the child stays alive but the socket never appears, `poll_startup`
    /// reports `TimedOut` after exhausting its attempt budget.
    #[cfg(unix)]
    #[test]
    fn poll_startup_times_out_when_no_socket() {
        let tmp = TmpDir::new("poll-timeout");
        std::fs::create_dir_all(&tmp.0).expect("dir");
        let sock = tmp.0.join("daemon.sock"); // never created

        let mut live = LiveChild::sleeping();
        let outcome = super::poll_startup(
            &mut live.0,
            &sock,
            3, // tiny budget so the test is fast
            std::time::Duration::from_millis(5),
        );
        assert!(
            matches!(outcome, super::StartupOutcome::TimedOut),
            "alive child + no socket must time out, got {outcome:?}"
        );
    }

    /// End-to-end: `start(true)` spawns a detached daemon, the socket appears,
    /// the daemon is reachable (`status()` pings it successfully), then `stop()`
    /// tears it down.
    ///
    /// `#[ignore]` because it points process-global `XDG_STATE_HOME` at a temp
    /// dir (so the detached child resolves an isolated runtime dir) and actually
    /// binds a socket — mutating that env races the other parallel env-reading
    /// tests in this binary. Run with `--ignored` in isolation.
    #[cfg(unix)]
    #[test]
    #[ignore = "mutates process-global XDG_STATE_HOME and binds a real socket; run with --ignored in isolation"]
    fn start_detach_spawns_verifies_and_stops() {
        let tmp = TmpDir::new("detach-e2e");
        std::fs::create_dir_all(&tmp.0).expect("create state dir");
        std::env::set_var("XDG_STATE_HOME", &tmp.0);

        // Ensure a clean slate (no leftover pid/sock from a prior run).
        let _ = super::stop();

        let code = super::start(true);
        assert_eq!(code, 0, "start(true) must verify startup and return 0");

        // The detached child's foreground `run_server` bound the socket and wrote
        // the PID file; `status()` connects + pings to confirm reachability.
        assert!(
            super::socket_path().exists(),
            "socket must exist after start"
        );
        assert_eq!(super::status(), 0, "daemon must be reachable via ping");

        assert_eq!(super::stop(), 0, "stop() must shut the daemon down");

        std::env::remove_var("XDG_STATE_HOME");
    }
}
