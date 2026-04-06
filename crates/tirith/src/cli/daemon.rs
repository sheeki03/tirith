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
use tirith_core::tokenize::ShellType;
#[cfg(unix)]
use tirith_core::verdict::{Evidence, RuleId, Severity};

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn socket_path() -> PathBuf {
    tirith_core::policy::state_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("daemon.sock")
}

fn pid_path() -> PathBuf {
    tirith_core::policy::state_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("daemon.pid")
}

// ---------------------------------------------------------------------------
// Wire protocol (newline-delimited JSON)
// ---------------------------------------------------------------------------

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
    /// Client-side TIRITH=0 bypass request (carried from the invoking env).
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
    // Verdict metadata for faithful JSON reconstruction
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
}

// ---------------------------------------------------------------------------
// Client helper — used by check.rs to delegate to the daemon
// ---------------------------------------------------------------------------

/// Try to connect to the daemon and run a check. Returns `None` if the daemon
/// is unavailable (caller should fall back to local analysis).
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
    None // Daemon not yet supported on this platform
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

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

    // Honor client-side bypass BEFORE analysis — matches the local engine
    // fast-path that returns at tier 2 with no findings or extracted URLs.
    if req.bypass_requested {
        let policy = tirith_core::policy::Policy::discover(req.cwd.as_deref());
        let bypass_allowed = if req.interactive {
            policy.allow_bypass_env
        } else {
            policy.allow_bypass_env_noninteractive
        };
        if bypass_allowed {
            // Match the local fast-bypass Verdict shape: tier 0/1/2 reached,
            // tier3 absent, with zero timings (daemon didn't run analysis).
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
    };

    let mut verdict = engine::analyze(&ctx);

    // --- Network-aware enrichment (daemon-only, too slow for sync path) ---
    enrich_with_network_checks(&mut verdict.findings);

    // Recalculate action after enrichment may have added higher-severity findings.
    let max_severity = verdict
        .findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);
    let new_action = match max_severity {
        Severity::Critical | Severity::High => Action::Block,
        Severity::Medium | Severity::Low => Action::Warn,
        Severity::Info => Action::Allow,
    };
    let action_rank = |a: Action| match a {
        Action::Allow => 0,
        Action::Warn | Action::WarnAck => 1,
        Action::Block => 2,
    };
    if action_rank(new_action) > action_rank(verdict.action) {
        verdict.action = new_action;
    }

    // Snapshot raw findings/action AFTER enrichment but BEFORE paranoia filtering.
    let raw_findings = Some(verdict.findings.clone());
    let raw_action_str = Some(format!("{:?}", verdict.action));

    // Apply paranoia filter
    let policy = tirith_core::policy::Policy::discover(ctx.cwd.as_deref());
    engine::filter_findings_by_paranoia(&mut verdict, policy.paranoia);

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
    }
}

/// Run network checks on findings that reference URLs and add enrichment.
///
/// This is only called in the daemon path where latency is acceptable.
#[cfg(unix)]
fn enrich_with_network_checks(findings: &mut Vec<Finding>) {
    let mut new_findings = Vec::new();

    // 1. Resolve shortened URLs and update the finding description.
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

                // Run DNS blocklist on the resolved destination's host.
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

    // 2. DNS blocklist check on all URL hosts in findings (non-shortened too).
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
    // Ensure parent directory exists
    if let Some(parent) = sock.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Remove stale socket
    let _ = std::fs::remove_file(sock);

    // Write PID file
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

        eprintln!(
            "tirith: daemon listening on {} (PID {})",
            sock.display(),
            std::process::id()
        );

        // Spawn a signal handler for graceful shutdown
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

        // Spawn periodic threat DB update task.
        // Uses its own timer independent of the per-CLI-process UPDATE_ATTEMPTED guard.
        // Coordinates with concurrent `tirith check` processes via the same lockfile
        // and next-check-at state file.
        let threatdb_update_handle = tokio::spawn(async {
            // Initial delay: wait 60s before first check to let daemon stabilize
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            loop {
                // Check if update is due (on a blocking thread since it does I/O)
                let should_spawn =
                    tokio::task::spawn_blocking(daemon_should_spawn_update)
                        .await
                        .unwrap_or(false);

                if should_spawn {
                    // Spawn as a detached child process (same as check.rs path)
                    // so the daemon doesn't block on download.
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

                // Re-check every 15 minutes
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
                                let (reader, mut writer) = stream.into_split();
                                // Cap request size to 1 MiB to prevent OOM from malicious clients
                                let mut buf_reader = BufReader::new(reader.take(1024 * 1024));
                                let mut line = String::new();

                                match buf_reader.read_line(&mut line).await {
                                    Ok(0) => return, // EOF
                                    Err(_) => return,
                                    Ok(_) => {}
                                }

                                let resp = match serde_json::from_str::<DaemonRequest>(line.trim()) {
                                    Ok(req) => {
                                        // Run blocking analysis on a dedicated thread to avoid
                                        // stalling the accept loop (engine + network checks block).
                                        tokio::task::spawn_blocking(move || handle_request(&req))
                                            .await
                                            .unwrap_or_else(|_| DaemonResponse {
                                                action: Action::Allow, findings: vec![], exit_code: 1,
                                                error: Some("internal error".to_string()),
                                                bypass_honored: false, bypass_available: false,
                                                policy_path_used: None, timings_ms: Default::default(),
                                                urls_extracted_count: None, tier_reached: 0,
                                                raw_findings: None, raw_action: None,
                                            })
                                    }
                                    Err(e) => DaemonResponse {
                                        action: Action::Allow, findings: vec![], exit_code: 1,
                                        error: Some(format!("invalid request: {e}")),
                                        bypass_honored: false, bypass_available: false,
                                        policy_path_used: None, timings_ms: Default::default(),
                                        urls_extracted_count: None, tier_reached: 0,
                                        raw_findings: None, raw_action: None,
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

    // Cleanup
    let _ = std::fs::remove_file(sock);
    let _ = std::fs::remove_file(pid);

    exit
}

// ---------------------------------------------------------------------------
// Threat DB periodic update (daemon-only)
// ---------------------------------------------------------------------------

/// Check whether a background threat DB update should be spawned.
/// Called from the daemon's periodic timer task (blocking context).
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
                return false; // not yet due
            }
        }
    }

    // Check spawned-at dedup (same as check.rs path)
    let spawned_at_path = state.join("threatdb-spawned-at");
    if let Ok(content) = std::fs::read_to_string(&spawned_at_path) {
        if let Ok(spawned_ts) = content.trim().parse::<u64>() {
            if now.saturating_sub(spawned_ts) < 30 {
                return false; // another process spawned recently
            }
        }
    }

    // Write spawned-at
    let _ = std::fs::create_dir_all(&state);
    let _ = std::fs::write(&spawned_at_path, now.to_string());

    true
}

// ---------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    // kill(pid, 0) checks if the process exists without sending a signal
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    // On non-Unix, conservatively assume alive if PID file exists.
    // A more robust check would use OpenProcess on Windows.
    true
}

#[cfg(unix)]
fn kill_process(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) == 0 }
}

// ---------------------------------------------------------------------------
// CLI subcommands
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub fn start() -> i32 {
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
        // Stale PID file — clean up
        let _ = std::fs::remove_file(&pid);
        let _ = std::fs::remove_file(&sock);
    }

    eprintln!("tirith: starting daemon on {}", sock.display());

    // Run the server in the foreground. In production a process supervisor
    // (systemd, launchd, etc.) handles daemonisation; we keep the code simple.
    run_server(&sock, &pid)
}

#[cfg(not(unix))]
pub fn start() -> i32 {
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
        // Give it a moment to clean up
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
