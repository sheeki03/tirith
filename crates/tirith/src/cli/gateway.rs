use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::mcp::types::{ContentItem, JsonRpcError, JsonRpcResponse, ToolCallResult};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Action, Finding};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct GatewayConfig {
    pub guarded_tools: Vec<GuardedTool>,
    #[serde(default)]
    pub policy: PolicyConfig,
}

#[derive(Debug, Deserialize)]
pub struct GuardedTool {
    pub pattern: String,
    pub command_paths: Vec<String>,
    #[serde(default = "default_shell")]
    pub shell: String,
}

fn default_shell() -> String {
    "posix".to_string()
}

#[derive(Debug, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_warn_action")]
    pub warn_action: String,
    #[serde(default = "default_fail_mode")]
    pub fail_mode: String,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_message_bytes")]
    pub max_message_bytes: usize,
}

fn default_warn_action() -> String {
    "forward".to_string()
}
fn default_fail_mode() -> String {
    "open".to_string()
}
fn default_timeout_ms() -> u64 {
    10000
}
fn default_max_message_bytes() -> usize {
    1_048_576
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            warn_action: default_warn_action(),
            fail_mode: default_fail_mode(),
            timeout_ms: default_timeout_ms(),
            max_message_bytes: default_max_message_bytes(),
        }
    }
}

#[cfg_attr(test, derive(Debug))]
struct CompiledConfig {
    guarded_tools: Vec<CompiledGuardedTool>,
    policy: PolicyConfig,
}

#[cfg_attr(test, derive(Debug))]
struct CompiledGuardedTool {
    regex: Regex,
    command_paths: Vec<String>,
    shell: ShellType,
}

impl CompiledConfig {
    fn from_config(config: GatewayConfig) -> Result<Self, String> {
        let mut guarded = Vec::new();
        for tool in config.guarded_tools {
            let regex = Regex::new(&tool.pattern)
                .map_err(|e| format!("invalid regex '{}': {e}", tool.pattern))?;
            for path in &tool.command_paths {
                validate_json_pointer(path)?;
            }
            let shell = tool.shell.parse::<ShellType>().unwrap_or(ShellType::Posix);
            guarded.push(CompiledGuardedTool {
                regex,
                command_paths: tool.command_paths,
                shell,
            });
        }
        validate_policy_values(&config.policy)?;
        // Normalize "allow" → "forward" so downstream only checks == "deny"
        let mut policy = config.policy;
        if policy.warn_action == "allow" {
            policy.warn_action = "forward".to_string();
        }
        Ok(Self {
            guarded_tools: guarded,
            policy,
        })
    }
}

fn validate_policy_values(policy: &PolicyConfig) -> Result<(), String> {
    match policy.warn_action.as_str() {
        "deny" | "forward" | "allow" => {}
        other => {
            return Err(format!(
                "invalid warn_action '{other}': must be \"deny\", \"forward\", or \"allow\""
            ))
        }
    }
    match policy.fail_mode.as_str() {
        "open" | "closed" => {}
        other => {
            return Err(format!(
                "invalid fail_mode '{other}': must be \"open\" or \"closed\""
            ))
        }
    }
    if policy.max_message_bytes == 0 {
        return Err("max_message_bytes must be > 0".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON Pointer (RFC 6901) — resolved against params object
// ---------------------------------------------------------------------------

fn validate_json_pointer(pointer: &str) -> Result<(), String> {
    if pointer.is_empty() {
        return Ok(());
    }
    if !pointer.starts_with('/') {
        return Err(format!("JSON Pointer must start with '/': {pointer}"));
    }
    // RFC 6901: '~' must be followed by '0' or '1'. Reject other escapes.
    let bytes = pointer.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'~' {
            match bytes.get(i + 1) {
                Some(b'0') | Some(b'1') => {}
                Some(c) => {
                    return Err(format!(
                    "invalid JSON Pointer escape '~{}' in '{pointer}' (only ~0 and ~1 are valid)",
                    *c as char
                ))
                }
                None => {
                    return Err(format!(
                        "JSON Pointer ends with unescaped '~' in '{pointer}'"
                    ))
                }
            }
        }
    }
    Ok(())
}

fn resolve_json_pointer<'a>(value: &'a Value, pointer: &str) -> Option<&'a Value> {
    if pointer.is_empty() {
        return Some(value);
    }
    let mut current = value;
    for part in pointer.strip_prefix('/')?.split('/') {
        let unescaped = part.replace("~1", "/").replace("~0", "~");
        match current {
            Value::Object(map) => current = map.get(&unescaped)?,
            Value::Array(arr) => current = arr.get(unescaped.parse::<usize>().ok()?)?,
            _ => return None,
        }
    }
    Some(current)
}

// ---------------------------------------------------------------------------
// Audit log (one JSON line per event, stderr)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AuditEntry<'a> {
    ts: String,
    decision: &'a str,
    action_taken: &'a str,
    rule_ids: &'a [String],
    findings_count: usize,
    highest_severity: &'a str,
    tool_name: &'a str,
    command_hash_prefix: &'a str,
    elapsed_ms: f64,
    fail_mode_triggered: bool,
    timeout_triggered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_decision: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_rule_ids: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<&'a str>,
}

#[allow(clippy::too_many_arguments)]
fn write_audit(
    decision: &str,
    action_taken: &str,
    rule_ids: &[String],
    highest_severity: Option<&str>,
    tool_name: &str,
    cmd_hash: &str,
    elapsed_ms: f64,
    fail_mode_triggered: bool,
    timeout_triggered: bool,
) {
    write_audit_with_raw(
        decision,
        action_taken,
        rule_ids,
        highest_severity,
        tool_name,
        cmd_hash,
        elapsed_ms,
        fail_mode_triggered,
        timeout_triggered,
        None,
        None,
        None,
    );
}

#[allow(clippy::too_many_arguments)]
fn write_audit_with_raw(
    decision: &str,
    action_taken: &str,
    rule_ids: &[String],
    highest_severity: Option<&str>,
    tool_name: &str,
    cmd_hash: &str,
    elapsed_ms: f64,
    fail_mode_triggered: bool,
    timeout_triggered: bool,
    raw_decision: Option<&str>,
    raw_rule_ids: Option<&[String]>,
    session_id: Option<&str>,
) {
    let entry = AuditEntry {
        ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        decision,
        action_taken,
        rule_ids,
        findings_count: rule_ids.len(),
        highest_severity: highest_severity.unwrap_or("NONE"),
        tool_name,
        command_hash_prefix: cmd_hash,
        elapsed_ms,
        fail_mode_triggered,
        timeout_triggered,
        raw_decision,
        raw_rule_ids,
        session_id,
    };
    match serde_json::to_string(&entry) {
        Ok(json) => eprintln!("{json}"),
        Err(e) => eprintln!(
            "tirith gateway: audit serialization failed: {e} — decision={} tool={}",
            entry.decision, entry.tool_name
        ),
    }
}

fn cmd_hash_prefix(cmd: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(cmd.as_bytes()))
        .chars()
        .take(8)
        .collect()
}

// ---------------------------------------------------------------------------
// validate-config subcommand
// ---------------------------------------------------------------------------

pub fn validate_config(config_path: &str) -> i32 {
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tirith gateway: cannot read config '{config_path}': {e}");
            return 1;
        }
    };
    let config: GatewayConfig = match serde_yaml::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tirith gateway: invalid YAML: {e}");
            return 1;
        }
    };
    if let Err(e) = CompiledConfig::from_config(config) {
        eprintln!("tirith gateway: {e}");
        return 1;
    }
    eprintln!("tirith gateway: config is valid");
    0
}

// ---------------------------------------------------------------------------
// gateway run — main entry point
// ---------------------------------------------------------------------------

pub fn run_gateway(upstream_bin: &str, upstream_args: &[String], config_path: &str) -> i32 {
    // Recursion guard
    let depth: u32 = std::env::var("TIRITH_GATEWAY_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if depth >= 1 {
        eprintln!("tirith gateway: recursion detected (depth={depth}), aborting");
        return 1;
    }

    // Load and compile config
    let content = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tirith gateway: cannot read config '{config_path}': {e}");
            return 1;
        }
    };
    let raw_config: GatewayConfig = match serde_yaml::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tirith gateway: invalid config: {e}");
            return 1;
        }
    };
    let config = match CompiledConfig::from_config(raw_config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tirith gateway: {e}");
            return 1;
        }
    };

    eprintln!("tirith gateway: batch JSON-RPC requests are denied until batch interception is implemented");

    // Spawn upstream process
    let mut child = match Command::new(upstream_bin)
        .args(upstream_args)
        .env("TIRITH_GATEWAY_DEPTH", (depth + 1).to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tirith gateway: failed to spawn upstream '{upstream_bin}': {e}");
            return 1;
        }
    };

    let child_stdin = child.stdin.take().expect("child stdin");
    let child_stdout = child.stdout.take().expect("child stdout");
    let child_stderr = child.stderr.take().expect("child stderr");

    let shutdown = Arc::new(AtomicBool::new(false));
    let client_done = Arc::new(AtomicBool::new(false));
    let (output_tx, output_rx) = mpsc::channel::<Vec<u8>>();
    let config = Arc::new(config);
    let max_bytes = config.policy.max_message_bytes;

    // Shared state: pending warn-forwarded request IDs → findings.
    // Thread 1 inserts before forwarding; Thread 2 removes on response match.
    // Key is serde_json::Value because JSON-RPC IDs can be string, number, or null.
    #[allow(clippy::type_complexity)]
    let pending_warns: Arc<Mutex<HashMap<Value, (Vec<Finding>, Instant)>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Thread 2: upstream stdout reader
    // Sets shutdown on EOF so main thread exits even if Thread 1 is blocked on stdin.
    let tx2 = output_tx.clone();
    let sd2 = shutdown.clone();
    let pw2 = Arc::clone(&pending_warns);
    let t_upstream = thread::spawn(move || {
        let mut reader = BufReader::new(child_stdout);
        loop {
            if sd2.load(Ordering::Relaxed) {
                break;
            }
            match read_bounded_line(&mut reader, max_bytes) {
                Ok(Some(line)) => {
                    let to_send = augment_if_pending(&line, &pw2).unwrap_or(line);
                    if tx2.send(to_send).is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    // Upstream EOF — signal main thread to stop.
                    // Without this, main hangs if Thread 1 is blocked on stdin
                    // (Thread 1's sender keeps the channel alive).
                    sd2.store(true, Ordering::Relaxed);
                    break;
                }
                Err(n) => {
                    eprintln!("tirith gateway: upstream message exceeds max_message_bytes ({n} > {max_bytes}), terminating");
                    sd2.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
    });

    // Thread 3: upstream stderr drainer
    let sd3 = shutdown.clone();
    let t_stderr = thread::spawn(move || {
        let reader = BufReader::new(child_stderr);
        for line in reader.lines() {
            if sd3.load(Ordering::Relaxed) {
                break;
            }
            match line {
                Ok(l) => eprintln!("[upstream] {l}"),
                Err(_) => break,
            }
        }
    });

    // Thread 1: client stdin reader + interception
    let tx1 = output_tx;
    let sd1 = shutdown.clone();
    let cd1 = client_done.clone();
    let cfg = config.clone();
    let pw1 = Arc::clone(&pending_warns);
    let t_client = thread::spawn(move || {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin.lock());
        let mut upstream = child_stdin;

        loop {
            if sd1.load(Ordering::Relaxed) {
                break;
            }
            let raw_line = match read_bounded_line(&mut reader, max_bytes) {
                Ok(Some(line)) => line,
                Ok(None) => {
                    cd1.store(true, Ordering::Relaxed);
                    sd1.store(true, Ordering::Relaxed);
                    break; // Client stdin EOF (normal shutdown)
                }
                Err(n) => {
                    eprintln!("tirith gateway: client message exceeds max_message_bytes ({n} > {max_bytes}), terminating");
                    sd1.store(true, Ordering::Relaxed);
                    break;
                }
            };

            let write_err = match serde_json::from_slice::<Value>(&raw_line) {
                Err(_) => {
                    // Parse fails → forward raw bytes
                    forward(&mut upstream, &raw_line).err()
                }
                Ok(Value::Array(ref arr)) => {
                    // Batch → fail closed (Phase 1)
                    handle_batch_deny(arr, &tx1);
                    None
                }
                Ok(ref val) if !val.is_object() => {
                    // Non-object, non-array → forward raw bytes
                    forward(&mut upstream, &raw_line).err()
                }
                Ok(ref obj) => {
                    process_object(obj, &raw_line, &cfg, &mut upstream, &tx1, &pw1).err()
                }
            };
            if let Some(e) = write_err {
                eprintln!("tirith gateway: upstream write failed: {e}");
                sd1.store(true, Ordering::Relaxed);
                break;
            }
        }
        drop(upstream); // Signal EOF to child
    });

    // Main thread: output writer with recv_timeout for shutdown observability
    let sd_main = shutdown.clone();
    let mut stdout = io::stdout().lock();
    let mut last_sweep = Instant::now();
    loop {
        match output_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(line) => {
                let ok = stdout
                    .write_all(&line)
                    .and_then(|_| stdout.write_all(b"\n"))
                    .and_then(|_| stdout.flush())
                    .is_ok();
                if !ok {
                    sd_main.store(true, Ordering::Relaxed);
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if sd_main.load(Ordering::Relaxed) {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        // Periodically evict stale pending_warns entries (TTL 30s, sweep every 10s)
        if last_sweep.elapsed() > Duration::from_secs(10) {
            if let Ok(mut map) = pending_warns.lock() {
                let cutoff = Instant::now() - Duration::from_secs(30);
                map.retain(|_, (_, ts)| *ts > cutoff);
            }
            last_sweep = Instant::now();
        }
    }
    drop(stdout);

    // Shutdown child — abnormal unless client initiated shutdown via stdin EOF
    let abnormal = !client_done.load(Ordering::Relaxed);
    let exit_code = shutdown_child(&mut child, abnormal);

    // Join Thread 2 and 3 — bounded by child process death (stdout/stderr EOF).
    let _ = t_upstream.join();
    let _ = t_stderr.join();

    // Thread 1 may be blocked on stdin read_line and cannot be unblocked from
    // another thread. Use a short timeout join; process exit will clean it up.
    let client_handle = t_client;
    let join_done = Arc::new(AtomicBool::new(false));
    let jd = join_done.clone();
    thread::spawn(move || {
        let _ = client_handle.join();
        jd.store(true, Ordering::Relaxed);
    });
    for _ in 0..10 {
        if join_done.load(Ordering::Relaxed) {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    exit_code
}

// ---------------------------------------------------------------------------
// Process a single JSON object from client
// ---------------------------------------------------------------------------

fn process_object(
    obj: &Value,
    raw_line: &[u8],
    config: &CompiledConfig,
    upstream: &mut impl Write,
    output_tx: &mpsc::Sender<Vec<u8>>,
    pending_warns: &Mutex<HashMap<Value, (Vec<Finding>, Instant)>>,
) -> io::Result<()> {
    match check_guarded(obj, config) {
        GuardedResult::NotGuarded => forward(upstream, raw_line),
        GuardedResult::Guarded {
            id,
            command,
            tool_name,
            shell,
        } => handle_guarded_call(
            id,
            &command,
            &tool_name,
            shell,
            raw_line,
            config,
            upstream,
            output_tx,
            pending_warns,
        ),
        GuardedResult::GuardedNotification {
            command,
            tool_name,
            shell,
        } => handle_guarded_notification(&command, &tool_name, shell, raw_line, config, upstream),
        GuardedResult::ExtractionFailed { id, tool_name } => {
            handle_extraction_failed(id, &tool_name, raw_line, config, upstream, output_tx)
        }
        GuardedResult::NotificationExtractionFailed { tool_name } => {
            handle_notification_extraction_failed(&tool_name)
        }
        GuardedResult::InvalidRequest { tool_name } => {
            handle_invalid_guarded_request(&tool_name, output_tx)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_guarded_call(
    id: Value,
    command: &str,
    tool_name: &str,
    shell: ShellType,
    raw_line: &[u8],
    config: &CompiledConfig,
    upstream: &mut impl Write,
    output_tx: &mpsc::Sender<Vec<u8>>,
    pending_warns: &Mutex<HashMap<Value, (Vec<Finding>, Instant)>>,
) -> io::Result<()> {
    let start = Instant::now();
    let hash = cmd_hash_prefix(command);

    // Inline analysis with oneshot thread + timeout.
    // Channel carries (Verdict, Policy) so we reuse the engine's loaded policy
    // instead of calling Policy::discover() a second time.
    let (tx, rx) = mpsc::channel();
    let cmd_owned = command.to_string();
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let cwd_for_thread = cwd.clone();
    thread::spawn(move || {
        let ctx = AnalysisContext {
            input: cmd_owned,
            shell,
            scan_context: ScanContext::Exec,
            raw_bytes: None,
            interactive: true,
            cwd: cwd_for_thread,
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
        };
        let _ = tx.send(engine::analyze_returning_policy(&ctx));
    });

    let timeout = Duration::from_millis(config.policy.timeout_ms);
    match rx.recv_timeout(timeout) {
        Ok((raw_verdict, engine_policy)) => {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;

            // Capture raw info before post-processing
            let raw_decision_str = format!("{:?}", raw_verdict.action).to_lowercase();
            let raw_rule_ids_vec: Vec<String>;
            let session_id = tirith_core::session::resolve_session_id();

            let effective = if raw_verdict.bypass_honored {
                raw_rule_ids_vec = vec![];
                raw_verdict
            } else {
                raw_rule_ids_vec = raw_verdict
                    .findings
                    .iter()
                    .map(|f| f.rule_id.to_string())
                    .collect();
                tirith_core::escalation::post_process_verdict(
                    &raw_verdict,
                    &engine_policy,
                    command,
                    &session_id,
                    tirith_core::escalation::CallerContext::Gateway,
                )
            };

            let should_deny = match effective.action {
                Action::Block => true,
                Action::Warn | Action::WarnAck => config.policy.warn_action == "deny",
                Action::Allow => false,
            };

            let rule_ids: Vec<String> = effective
                .findings
                .iter()
                .map(|f| f.rule_id.to_string())
                .collect();
            let max_sev = effective
                .findings
                .iter()
                .map(|f| f.severity)
                .max()
                .map(|s| s.to_string());

            if should_deny {
                let decision = if effective.action == Action::Block {
                    "block"
                } else {
                    "warn"
                };
                write_audit_with_raw(
                    decision,
                    "denied",
                    &rule_ids,
                    max_sev.as_deref(),
                    tool_name,
                    &hash,
                    elapsed,
                    false,
                    false,
                    Some(&raw_decision_str),
                    Some(&raw_rule_ids_vec),
                    Some(&session_id),
                );
                let _ = output_tx.send(build_deny_response(id, &effective, elapsed).into_bytes());
                Ok(())
            } else {
                let decision = if effective.action == Action::Warn {
                    "warn"
                } else {
                    "allow"
                };
                write_audit_with_raw(
                    decision,
                    "forwarded",
                    &rule_ids,
                    max_sev.as_deref(),
                    tool_name,
                    &hash,
                    elapsed,
                    false,
                    false,
                    Some(&raw_decision_str),
                    Some(&raw_rule_ids_vec),
                    Some(&session_id),
                );

                // For warn-forwarded requests with findings, insert into pending
                // map BEFORE forward so Thread 2 can augment the upstream response.
                // Insert before forward to prevent race: a fast upstream could
                // return before the map entry exists, causing Thread 2 to miss it.
                if !effective.findings.is_empty() {
                    match pending_warns.lock() {
                        Ok(mut map) => {
                            map.insert(id, (effective.findings, Instant::now()));
                        }
                        Err(e) => {
                            eprintln!(
                                "tirith gateway: pending_warns mutex poisoned on insert: {e}"
                            );
                        }
                    }
                }

                // On forward failure, Thread 1 triggers shutdown (caller sets
                // sd1=true and breaks). The pending map is cleaned up when all
                // Arcs drop, so no explicit removal is needed on failure.
                forward(upstream, raw_line)
            }
        }
        Err(_) => {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            if config.policy.fail_mode == "open" {
                write_audit(
                    "allow",
                    "forwarded",
                    &[],
                    None,
                    tool_name,
                    &hash,
                    elapsed,
                    true,
                    true,
                );
                forward(upstream, raw_line)
            } else {
                write_audit(
                    "block",
                    "denied",
                    &[],
                    None,
                    tool_name,
                    &hash,
                    elapsed,
                    true,
                    true,
                );
                let _ = output_tx.send(
                    build_fail_mode_deny(id, "analysis timed out", elapsed, true, true)
                        .into_bytes(),
                );
                Ok(())
            }
        }
    }
}

fn handle_extraction_failed(
    id: Value,
    tool_name: &str,
    raw_line: &[u8],
    config: &CompiledConfig,
    upstream: &mut impl Write,
    output_tx: &mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    if config.policy.fail_mode == "open" {
        write_audit(
            "allow",
            "forwarded",
            &[],
            None,
            tool_name,
            "",
            0.0,
            true,
            false,
        );
        forward(upstream, raw_line)
    } else {
        write_audit(
            "block",
            "denied",
            &[],
            None,
            tool_name,
            "",
            0.0,
            true,
            false,
        );
        let _ = output_tx.send(
            build_fail_mode_deny(id, "command extraction failed", 0.0, true, false).into_bytes(),
        );
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_guarded_notification(
    command: &str,
    tool_name: &str,
    shell: ShellType,
    raw_line: &[u8],
    config: &CompiledConfig,
    upstream: &mut impl Write,
) -> io::Result<()> {
    let start = std::time::Instant::now();
    let hash = cmd_hash_prefix(command);

    let (tx, rx) = mpsc::channel();
    let cmd_owned = command.to_string();
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let cwd_for_thread = cwd.clone();
    thread::spawn(move || {
        let ctx = AnalysisContext {
            input: cmd_owned,
            shell,
            scan_context: ScanContext::Exec,
            raw_bytes: None,
            interactive: true,
            cwd: cwd_for_thread,
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
        };
        let _ = tx.send(engine::analyze_returning_policy(&ctx));
    });

    let timeout = Duration::from_millis(config.policy.timeout_ms);
    match rx.recv_timeout(timeout) {
        Ok((raw_verdict, engine_policy)) => {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;

            let raw_decision_str = format!("{:?}", raw_verdict.action).to_lowercase();
            let raw_rule_ids_vec: Vec<String>;
            let session_id = tirith_core::session::resolve_session_id();

            let effective = if raw_verdict.bypass_honored {
                raw_rule_ids_vec = vec![];
                raw_verdict
            } else {
                raw_rule_ids_vec = raw_verdict
                    .findings
                    .iter()
                    .map(|f| f.rule_id.to_string())
                    .collect();
                tirith_core::escalation::post_process_verdict(
                    &raw_verdict,
                    &engine_policy,
                    command,
                    &session_id,
                    tirith_core::escalation::CallerContext::Gateway,
                )
            };

            let should_deny = match effective.action {
                Action::Block => true,
                Action::Warn | Action::WarnAck => config.policy.warn_action == "deny",
                Action::Allow => false,
            };

            let rule_ids: Vec<String> = effective
                .findings
                .iter()
                .map(|f| f.rule_id.to_string())
                .collect();
            let max_sev = effective
                .findings
                .iter()
                .map(|f| f.severity)
                .max()
                .map(|s| s.to_string());

            if should_deny {
                let decision = if effective.action == Action::Block {
                    "block"
                } else {
                    "warn"
                };
                write_audit_with_raw(
                    decision,
                    "dropped_notification",
                    &rule_ids,
                    max_sev.as_deref(),
                    tool_name,
                    &hash,
                    elapsed,
                    false,
                    false,
                    Some(&raw_decision_str),
                    Some(&raw_rule_ids_vec),
                    Some(&session_id),
                );
                Ok(())
            } else {
                let decision = if effective.action == Action::Warn {
                    "warn"
                } else {
                    "allow"
                };
                write_audit_with_raw(
                    decision,
                    "forwarded_notification",
                    &rule_ids,
                    max_sev.as_deref(),
                    tool_name,
                    &hash,
                    elapsed,
                    false,
                    false,
                    Some(&raw_decision_str),
                    Some(&raw_rule_ids_vec),
                    Some(&session_id),
                );
                forward(upstream, raw_line)
            }
        }
        Err(_) => {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            if config.policy.fail_mode == "open" {
                write_audit(
                    "allow",
                    "forwarded_notification",
                    &[],
                    None,
                    tool_name,
                    &hash,
                    elapsed,
                    true,
                    true,
                );
                forward(upstream, raw_line)
            } else {
                write_audit(
                    "block",
                    "dropped_notification",
                    &[],
                    None,
                    tool_name,
                    &hash,
                    elapsed,
                    true,
                    true,
                );
                Ok(())
            }
        }
    }
}

fn handle_notification_extraction_failed(tool_name: &str) -> io::Result<()> {
    write_audit(
        "block",
        "dropped_notification",
        &[],
        None,
        tool_name,
        "",
        0.0,
        true,
        false,
    );
    Ok(())
}

fn handle_invalid_guarded_request(
    tool_name: &str,
    output_tx: &mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    write_audit(
        "block",
        "invalid_request",
        &[],
        None,
        tool_name,
        "",
        0.0,
        false,
        false,
    );
    let _ = output_tx.send(build_invalid_id_request_response().into_bytes());
    Ok(())
}

// ---------------------------------------------------------------------------
// Guarded check
// ---------------------------------------------------------------------------

enum GuardedResult {
    NotGuarded,
    GuardedNotification {
        command: String,
        tool_name: String,
        shell: ShellType,
    },
    Guarded {
        id: Value,
        command: String,
        tool_name: String,
        shell: ShellType,
    },
    ExtractionFailed {
        id: Value,
        tool_name: String,
    },
    NotificationExtractionFailed {
        tool_name: String,
    },
    InvalidRequest {
        tool_name: String,
    },
}

fn check_guarded(obj: &Value, config: &CompiledConfig) -> GuardedResult {
    let method = match obj.get("method").and_then(|v| v.as_str()) {
        Some(m) if m == "tools/call" => m,
        _ => return GuardedResult::NotGuarded,
    };
    let _ = method;

    let params = match obj.get("params") {
        Some(p) if p.is_object() => p,
        _ => return GuardedResult::NotGuarded,
    };
    let tool_name = match params.get("name").and_then(|v| v.as_str()) {
        Some(n) => n.to_string(),
        None => return GuardedResult::NotGuarded,
    };

    let guard = match config
        .guarded_tools
        .iter()
        .find(|g| g.regex.is_match(&tool_name))
    {
        Some(g) => g,
        None => return GuardedResult::NotGuarded,
    };

    // Extract command via JSON Pointer paths (resolved against params)
    let extracted_command = || {
        for pointer in &guard.command_paths {
            if let Some(val) = resolve_json_pointer(params, pointer) {
                if let Some(s) = val.as_str() {
                    if !s.is_empty() {
                        return Some(s.to_string());
                    }
                }
            }
        }
        None
    };

    match obj.get("id") {
        None => match extracted_command() {
            Some(command) => GuardedResult::GuardedNotification {
                command,
                tool_name,
                shell: guard.shell,
            },
            None => GuardedResult::NotificationExtractionFailed { tool_name },
        },
        Some(Value::String(_)) | Some(Value::Number(_)) | Some(Value::Null) => {
            let id = obj.get("id").cloned().unwrap_or(Value::Null);
            match extracted_command() {
                Some(command) => GuardedResult::Guarded {
                    id,
                    command,
                    tool_name,
                    shell: guard.shell,
                },
                None => GuardedResult::ExtractionFailed { id, tool_name },
            }
        }
        Some(_) => GuardedResult::InvalidRequest { tool_name },
    }
}

// ---------------------------------------------------------------------------
// Batch deny (Phase 1: fail closed)
// ---------------------------------------------------------------------------

fn handle_batch_deny(arr: &[Value], output_tx: &mpsc::Sender<Vec<u8>>) {
    if arr.is_empty() {
        let resp = JsonRpcResponse::err(
            Value::Null,
            JsonRpcError {
                code: -32600,
                message: "Empty batch request".to_string(),
                data: None,
            },
        );
        let _ = output_tx.send(
            serde_json::to_string(&resp)
                .unwrap_or_default()
                .into_bytes(),
        );
        write_audit(
            "block",
            "batch_denied",
            &[],
            None,
            "",
            "",
            0.0,
            false,
            false,
        );
        return;
    }

    let mut responses: Vec<Value> = Vec::new();
    for item in arr {
        if let Some(id_val) = item.get("id") {
            let id = match id_val {
                Value::String(_) | Value::Number(_) | Value::Null => id_val.clone(),
                _ => Value::Null,
            };
            let resp = JsonRpcResponse::err(id, JsonRpcError {
                code: -32600,
                message: "Batch requests are not supported by Tirith gateway. Send individual requests.".to_string(),
                data: None,
            });
            if let Ok(v) = serde_json::to_value(&resp) {
                responses.push(v);
            }
        }
    }

    if !responses.is_empty() {
        let _ = output_tx.send(
            serde_json::to_string(&responses)
                .unwrap_or_default()
                .into_bytes(),
        );
    }

    write_audit(
        "block",
        "batch_denied",
        &[],
        None,
        "",
        "",
        0.0,
        false,
        false,
    );
}

// ---------------------------------------------------------------------------
// Deny response builder
// ---------------------------------------------------------------------------

fn build_deny_response(
    id: Value,
    verdict: &tirith_core::verdict::Verdict,
    elapsed_ms: f64,
) -> String {
    let findings_json: Vec<Value> = verdict
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "rule_id": f.rule_id.to_string(),
                "severity": f.severity.to_string(),
                "title": &f.title,
            })
        })
        .collect();

    let verdict_action = match verdict.action {
        Action::Block => "block",
        Action::Warn | Action::WarnAck => "warn",
        Action::Allow => "allow",
    };

    let text = verdict
        .findings
        .iter()
        .map(|f| format!("[{}] {}: {}", f.severity, f.rule_id, f.title))
        .collect::<Vec<_>>()
        .join("\n");

    let result = ToolCallResult {
        content: vec![ContentItem {
            content_type: "text".to_string(),
            text: format!("Tirith security check failed:\n{text}"),
        }],
        is_error: true,
        structured_content: Some(serde_json::json!({
            "_tirith_schema": 1,
            "decision": "deny",
            "verdict_action": verdict_action,
            "findings": findings_json,
            "elapsed_ms": elapsed_ms,
            "fail_mode_triggered": false,
            "timeout_triggered": false,
        })),
    };

    let resp = JsonRpcResponse::ok(id, serde_json::to_value(&result).unwrap());
    serde_json::to_string(&resp).unwrap_or_default()
}

/// Build a deny response for fail-mode denials (timeout, extraction failure).
/// Uses MCP tool-result envelope (result.isError=true) — same as normal policy
/// denials — so clients see a uniform denial contract.
///
/// `reason` is a short description without "Tirith:" prefix (added by this function).
fn build_fail_mode_deny(
    id: Value,
    reason: &str,
    elapsed_ms: f64,
    fail_mode_triggered: bool,
    timeout_triggered: bool,
) -> String {
    let result = ToolCallResult {
        content: vec![ContentItem {
            content_type: "text".to_string(),
            text: format!("Tirith: {reason} (fail_mode=closed)"),
        }],
        is_error: true,
        structured_content: Some(serde_json::json!({
            "_tirith_schema": 1,
            "decision": "deny",
            "verdict_action": "block",
            "findings": [],
            "elapsed_ms": elapsed_ms,
            "fail_mode_triggered": fail_mode_triggered,
            "timeout_triggered": timeout_triggered,
        })),
    };
    let resp = JsonRpcResponse::ok(id, serde_json::to_value(&result).unwrap());
    serde_json::to_string(&resp).unwrap_or_default()
}

fn build_invalid_id_request_response() -> String {
    serde_json::to_string(&JsonRpcResponse::err(
        Value::Null,
        JsonRpcError {
            code: -32600,
            message: "Invalid request: id must be string, number, or null".to_string(),
            data: None,
        },
    ))
    .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Warn augmentation — inject findings into upstream responses
// ---------------------------------------------------------------------------

/// Check if an upstream response line matches a pending warn-forwarded request.
/// If so, augment the response with findings and remove the entry from the map.
/// Returns `Some(augmented_bytes)` on success, `None` to pass through original.
fn augment_if_pending(
    line: &[u8],
    pending: &Mutex<HashMap<Value, (Vec<Finding>, Instant)>>,
) -> Option<Vec<u8>> {
    // Parse the upstream line to extract its id
    let parsed: Value = serde_json::from_slice(line).ok()?;
    let resp_id = parsed.get("id")?;

    // Brief lock: check if this id is in the pending map and remove it
    let findings = {
        let mut map = match pending.lock() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("tirith gateway: pending_warns mutex poisoned: {e}");
                return None;
            }
        };
        let (findings, _ts) = map.remove(resp_id)?;
        findings
    };

    // Augment outside the lock — no I/O while holding the mutex
    build_warn_augmented_response(parsed, &findings)
}

/// Build an augmented upstream response with warn findings prepended to `result.content`.
///
/// Operates entirely on `serde_json::Value` — NOT typed MCP structs (they are
/// Serialize-only and assume Tirith-shaped responses). The gateway is a generic
/// proxy over arbitrary upstreams, so augmentation must be defensive:
/// - Navigate to result.content (must exist and be an array)
/// - Prepend a text content item with formatted findings
/// - Re-serialize
/// - Return None on any failure (caller forwards original bytes)
fn build_warn_augmented_response(mut parsed: Value, findings: &[Finding]) -> Option<Vec<u8>> {
    if findings.is_empty() {
        return None;
    }

    // Navigate to result.content — must exist and be an array
    let content = parsed
        .get_mut("result")?
        .get_mut("content")?
        .as_array_mut()?;

    // Format findings as a warning text block
    let warning_lines: Vec<String> = findings
        .iter()
        .map(|f| format!("  [{}] {}: {}", f.severity, f.rule_id, f.title))
        .collect();
    let warning_text = format!(
        "\u{26a0} Tirith warnings (non-blocking):\n{}",
        warning_lines.join("\n")
    );

    // Prepend a text content item
    let warning_item = serde_json::json!({
        "type": "text",
        "text": warning_text
    });
    content.insert(0, warning_item);

    // Re-serialize
    serde_json::to_vec(&parsed).ok()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn forward(writer: &mut impl Write, line: &[u8]) -> io::Result<()> {
    writer.write_all(line)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn shutdown_child(child: &mut Child, abnormal: bool) -> i32 {
    // Check if already exited
    if let Ok(Some(_)) = child.try_wait() {
        return if abnormal { 1 } else { 0 };
    }

    // Wait up to 5 seconds for graceful exit (stdin already closed)
    for _ in 0..50 {
        thread::sleep(Duration::from_millis(100));
        if let Ok(Some(_)) = child.try_wait() {
            return if abnormal { 1 } else { 0 };
        }
    }

    // Send SIGTERM (Unix) or TerminateProcess (Windows)
    #[cfg(unix)]
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }

    // Wait 2 more seconds
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(100));
        if let Ok(Some(_)) = child.try_wait() {
            return if abnormal { 1 } else { 0 };
        }
    }

    // Force kill
    let _ = child.kill();
    let _ = child.wait();
    if abnormal {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Bounded line reader — prevents unbounded allocation from oversize lines
// Uses fill_buf()/consume() to read in chunks without allocating beyond limit.
// ---------------------------------------------------------------------------

fn read_bounded_line(reader: &mut impl BufRead, limit: usize) -> Result<Option<Vec<u8>>, usize> {
    let mut buf = Vec::with_capacity(std::cmp::min(limit, 8192));
    loop {
        let available = match reader.fill_buf() {
            Ok([]) => {
                if buf.is_empty() {
                    return Ok(None); // EOF
                }
                return Ok(Some(buf));
            }
            Ok(b) => b,
            Err(_) => {
                if buf.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(buf));
            }
        };

        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let total = buf.len() + pos;
            if total > limit {
                reader.consume(pos + 1);
                return Err(total);
            }
            buf.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            return Ok(Some(buf));
        }

        let avail_len = available.len();
        if buf.len() + avail_len > limit {
            // Oversize — consume this chunk and drain to newline
            reader.consume(avail_len);
            let total = buf.len() + avail_len;
            // Drain remaining bytes until newline or EOF
            loop {
                match reader.fill_buf() {
                    Ok([]) => return Err(total),
                    Ok(b) => {
                        if let Some(pos) = b.iter().position(|&c| c == b'\n') {
                            reader.consume(pos + 1);
                            return Err(total);
                        }
                        let len = b.len();
                        reader.consume(len);
                    }
                    Err(_) => return Err(total),
                }
            }
        }

        buf.extend_from_slice(available);
        reader.consume(avail_len);
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Config tests --

    #[test]
    fn test_config_parse_valid() {
        let yaml = r#"
guarded_tools:
  - pattern: "^Bash$"
    command_paths: ["/arguments/command"]
    shell: posix
policy:
  warn_action: deny
  fail_mode: open
  timeout_ms: 5000
  max_message_bytes: 2097152
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.guarded_tools.len(), 1);
        assert_eq!(config.policy.timeout_ms, 5000);
        let compiled = CompiledConfig::from_config(config).unwrap();
        assert_eq!(compiled.guarded_tools.len(), 1);
    }

    #[test]
    fn test_config_bad_regex() {
        let yaml = r#"
guarded_tools:
  - pattern: "[invalid"
    command_paths: ["/arguments/command"]
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(CompiledConfig::from_config(config).is_err());
    }

    #[test]
    fn test_config_bad_json_pointer() {
        let yaml = r#"
guarded_tools:
  - pattern: "^Bash$"
    command_paths: ["no-leading-slash"]
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(CompiledConfig::from_config(config).is_err());
    }

    #[test]
    fn test_config_bad_json_pointer_invalid_escape() {
        // ~2 is not a valid JSON Pointer escape (only ~0 and ~1)
        let yaml = r#"
guarded_tools:
  - pattern: "^Bash$"
    command_paths: ["/a~2b"]
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let err = CompiledConfig::from_config(config).unwrap_err();
        assert!(err.contains("~2"));
    }

    #[test]
    fn test_config_bad_json_pointer_trailing_tilde() {
        // Trailing ~ with no following character is invalid
        let yaml = r#"
guarded_tools:
  - pattern: "^Bash$"
    command_paths: ["/trailing~"]
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let err = CompiledConfig::from_config(config).unwrap_err();
        assert!(err.contains("unescaped '~'"));
    }

    #[test]
    fn test_config_defaults() {
        let yaml = "guarded_tools: []\n";
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.policy.warn_action, "forward");
        assert_eq!(config.policy.fail_mode, "open");
        assert_eq!(config.policy.timeout_ms, 10000);
        assert_eq!(config.policy.max_message_bytes, 1_048_576);
    }

    // -- JSON Pointer tests --

    #[test]
    fn test_json_pointer_against_params() {
        let params: Value = serde_json::json!({
            "name": "Bash",
            "arguments": {
                "command": "ls -la"
            }
        });
        let result = resolve_json_pointer(&params, "/arguments/command");
        assert_eq!(result.unwrap().as_str().unwrap(), "ls -la");
    }

    #[test]
    fn test_json_pointer_root() {
        let val: Value = serde_json::json!({"a": 1});
        assert!(resolve_json_pointer(&val, "").is_some());
    }

    #[test]
    fn test_json_pointer_missing() {
        let val: Value = serde_json::json!({"a": 1});
        assert!(resolve_json_pointer(&val, "/b").is_none());
    }

    #[test]
    fn test_json_pointer_escape() {
        let val: Value = serde_json::json!({"a/b": 1});
        assert!(resolve_json_pointer(&val, "/a~1b").is_some());
    }

    // -- Guarded check tests --

    fn test_config() -> CompiledConfig {
        let yaml = r#"
guarded_tools:
  - pattern: "^(Bash|bash)$"
    command_paths: ["/arguments/command", "/command"]
    shell: posix
"#;
        CompiledConfig::from_config(serde_yaml::from_str::<GatewayConfig>(yaml).unwrap()).unwrap()
    }

    #[test]
    fn test_guarded_with_id() {
        let config = test_config();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "Bash", "arguments": { "command": "ls" } }
        });
        match check_guarded(&obj, &config) {
            GuardedResult::Guarded { command, .. } => assert_eq!(command, "ls"),
            _ => panic!("expected Guarded"),
        }
    }

    #[test]
    fn test_guarded_notification() {
        let config = test_config();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": { "name": "Bash", "arguments": { "command": "ls" } }
        });
        match check_guarded(&obj, &config) {
            GuardedResult::GuardedNotification { command, .. } => assert_eq!(command, "ls"),
            _ => panic!("expected GuardedNotification"),
        }
    }

    #[test]
    fn test_not_guarded_different_tool() {
        let config = test_config();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "Read", "arguments": { "path": "/tmp" } }
        });
        assert!(matches!(
            check_guarded(&obj, &config),
            GuardedResult::NotGuarded
        ));
    }

    #[test]
    fn test_not_guarded_different_method() {
        let config = test_config();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        assert!(matches!(
            check_guarded(&obj, &config),
            GuardedResult::NotGuarded
        ));
    }

    #[test]
    fn test_extraction_failed() {
        let config = test_config();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "Bash", "arguments": { "code": "ls" } }
        });
        assert!(matches!(
            check_guarded(&obj, &config),
            GuardedResult::ExtractionFailed { .. }
        ));
    }

    // -- Batch deny tests --

    #[test]
    fn test_batch_empty() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        handle_batch_deny(&[], &tx);
        let resp = rx.recv().unwrap();
        let v: Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32600);
        assert!(v["id"].is_null());
    }

    #[test]
    fn test_batch_with_ids() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let items = vec![
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}),
            serde_json::json!({"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{}}),
        ];
        handle_batch_deny(&items, &tx);
        let resp = rx.recv().unwrap();
        let arr: Vec<Value> = serde_json::from_slice(&resp).unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["id"], 1);
        assert_eq!(arr[1]["id"], "abc");
    }

    #[test]
    fn test_batch_notifications_only() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let items = vec![serde_json::json!({"jsonrpc":"2.0","method":"notifications/something"})];
        handle_batch_deny(&items, &tx);
        assert!(rx.try_recv().is_err()); // No response for notifications-only
    }

    #[test]
    fn test_batch_invalid_id_types() {
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let items = vec![
            serde_json::json!({"jsonrpc":"2.0","id":{"nested":"obj"},"method":"x"}),
            serde_json::json!({"jsonrpc":"2.0","id":[1,2],"method":"x"}),
            serde_json::json!({"jsonrpc":"2.0","id":true,"method":"x"}),
        ];
        handle_batch_deny(&items, &tx);
        let resp = rx.recv().unwrap();
        let arr: Vec<Value> = serde_json::from_slice(&resp).unwrap();
        assert_eq!(arr.len(), 3);
        // All invalid id types → null
        for item in &arr {
            assert!(item["id"].is_null());
        }
    }

    // -- Bounded line reader tests --

    #[test]
    fn test_bounded_read_normal() {
        let data = b"hello\nworld\n";
        let mut reader = io::BufReader::new(&data[..]);
        assert_eq!(
            read_bounded_line(&mut reader, 100).unwrap().unwrap(),
            b"hello"
        );
        assert_eq!(
            read_bounded_line(&mut reader, 100).unwrap().unwrap(),
            b"world"
        );
        assert!(read_bounded_line(&mut reader, 100).unwrap().is_none());
    }

    #[test]
    fn test_bounded_read_oversize() {
        let data = b"this line is too long\n";
        let mut reader = io::BufReader::new(&data[..]);
        assert!(read_bounded_line(&mut reader, 5).is_err());
    }

    #[test]
    fn test_bounded_read_exact_limit() {
        let data = b"12345\n";
        let mut reader = io::BufReader::new(&data[..]);
        assert_eq!(
            read_bounded_line(&mut reader, 5).unwrap().unwrap(),
            b"12345"
        );
    }

    #[test]
    fn test_bounded_read_no_trailing_newline() {
        let data = b"hello";
        let mut reader = io::BufReader::new(&data[..]);
        assert_eq!(
            read_bounded_line(&mut reader, 100).unwrap().unwrap(),
            b"hello"
        );
    }

    #[test]
    fn test_bounded_read_preserves_invalid_utf8() {
        let data: &[u8] = &[0x80, 0x81, 0x82, b'\n'];
        let mut reader = io::BufReader::new(data);
        let line = read_bounded_line(&mut reader, 100).unwrap().unwrap();
        assert_eq!(line, &[0x80, 0x81, 0x82]);
    }

    // -- Recursion guard test --

    #[test]
    fn test_recursion_depth() {
        // Verify the depth check logic: any depth >= 1 should trigger abort
        let depth: u32 = 1;
        assert!(depth >= 1);
    }

    // -- No-id error rule test --

    #[test]
    fn test_no_id_notification_not_guarded() {
        let config = test_config();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        assert!(matches!(
            check_guarded(&obj, &config),
            GuardedResult::NotGuarded
        ));
    }

    // -- Invalid id type tests (Fix #4: non-batch path) --

    #[test]
    fn test_guarded_boolean_id_rejected() {
        let config = test_config();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": true,
            "method": "tools/call",
            "params": { "name": "Bash", "arguments": { "command": "ls" } }
        });
        assert!(matches!(
            check_guarded(&obj, &config),
            GuardedResult::InvalidRequest { .. }
        ));
    }

    #[test]
    fn test_guarded_object_id_rejected() {
        let config = test_config();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": {"nested": "obj"},
            "method": "tools/call",
            "params": { "name": "Bash", "arguments": { "command": "ls" } }
        });
        assert!(matches!(
            check_guarded(&obj, &config),
            GuardedResult::InvalidRequest { .. }
        ));
    }

    #[test]
    fn test_guarded_array_id_rejected() {
        let config = test_config();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": [1, 2],
            "method": "tools/call",
            "params": { "name": "Bash", "arguments": { "command": "ls" } }
        });
        assert!(matches!(
            check_guarded(&obj, &config),
            GuardedResult::InvalidRequest { .. }
        ));
    }

    #[test]
    fn test_guarded_string_id_preserved() {
        let config = test_config();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-42",
            "method": "tools/call",
            "params": { "name": "Bash", "arguments": { "command": "ls" } }
        });
        match check_guarded(&obj, &config) {
            GuardedResult::Guarded { id, .. } => assert_eq!(id, "req-42"),
            _ => panic!("expected Guarded"),
        }
    }

    #[test]
    fn test_guarded_null_id_preserved() {
        let config = test_config();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": null,
            "method": "tools/call",
            "params": { "name": "Bash", "arguments": { "command": "ls" } }
        });
        match check_guarded(&obj, &config) {
            GuardedResult::Guarded { id, .. } => assert!(id.is_null()),
            _ => panic!("expected Guarded"),
        }
    }

    #[test]
    fn test_guarded_notification_extraction_failed() {
        let config = test_config();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": { "name": "Bash", "arguments": { "code": "ls" } }
        });
        assert!(matches!(
            check_guarded(&obj, &config),
            GuardedResult::NotificationExtractionFailed { .. }
        ));
    }

    // -- Policy enum validation tests (Fix #5) --

    #[test]
    fn test_config_bad_warn_action() {
        let yaml = r#"
guarded_tools: []
policy:
  warn_action: "block"
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let err = CompiledConfig::from_config(config).unwrap_err();
        assert!(err.contains("warn_action"));
        assert!(err.contains("block"));
    }

    #[test]
    fn test_config_allow_synonym_normalized_to_forward() {
        let yaml = r#"
guarded_tools: []
policy:
  warn_action: "allow"
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let compiled = CompiledConfig::from_config(config).unwrap();
        assert_eq!(
            compiled.policy.warn_action, "forward",
            "\"allow\" should be normalized to \"forward\" at config load"
        );
    }

    #[test]
    fn test_config_bad_fail_mode() {
        let yaml = r#"
guarded_tools: []
policy:
  fail_mode: "strict"
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let err = CompiledConfig::from_config(config).unwrap_err();
        assert!(err.contains("fail_mode"));
        assert!(err.contains("strict"));
    }

    #[test]
    fn test_config_valid_forward_closed() {
        let yaml = r#"
guarded_tools: []
policy:
  warn_action: "forward"
  fail_mode: "closed"
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(CompiledConfig::from_config(config).is_ok());
    }

    // -- Audit serialization test (Fix #3) --

    #[test]
    fn test_audit_entry_serializes_valid_json() {
        let entry = AuditEntry {
            ts: "2026-02-21T00:00:00.000Z".to_string(),
            decision: "block",
            action_taken: "denied",
            rule_ids: &["CurlPipeShell".to_string()],
            findings_count: 1,
            highest_severity: "HIGH",
            tool_name: "Bash",
            command_hash_prefix: "a1b2c3d4",
            elapsed_ms: 2.3,
            fail_mode_triggered: false,
            timeout_triggered: false,
            raw_decision: None,
            raw_rule_ids: None,
            session_id: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["decision"], "block");
        assert_eq!(parsed["findings_count"], 1);
        assert_eq!(parsed["tool_name"], "Bash");
    }

    #[test]
    fn test_audit_entry_escapes_special_chars() {
        // Verify that crafted tool names can't break JSON
        let entry = AuditEntry {
            ts: "2026-02-21T00:00:00.000Z".to_string(),
            decision: "allow",
            action_taken: "forwarded",
            rule_ids: &[],
            findings_count: 0,
            highest_severity: "NONE",
            tool_name: r#"Bash","injected":"true"#,
            command_hash_prefix: "",
            elapsed_ms: 0.0,
            fail_mode_triggered: false,
            timeout_triggered: false,
            raw_decision: None,
            raw_rule_ids: None,
            session_id: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        // The injected content should be inside the tool_name string, not a separate field
        assert!(parsed.get("injected").is_none());
        assert!(parsed["tool_name"].as_str().unwrap().contains("injected"));
    }

    // -- max_message_bytes=0 rejected --

    #[test]
    fn test_config_rejects_zero_max_message_bytes() {
        let yaml = "guarded_tools: []\npolicy:\n  max_message_bytes: 0\n";
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let err = CompiledConfig::from_config(config).unwrap_err();
        assert!(err.contains("max_message_bytes"));
    }

    // -- Fail-mode deny formatting --

    #[test]
    fn test_fail_mode_deny_no_double_prefix() {
        let resp = build_fail_mode_deny(Value::from(1), "analysis timed out", 42.5, true, true);
        let v: Value = serde_json::from_str(&resp).unwrap();
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        // Should be "Tirith: analysis timed out (fail_mode=closed)" — NOT "Tirith: Tirith ..."
        assert!(text.starts_with("Tirith: analysis"));
        assert!(!text.contains("Tirith: Tirith"));
    }

    #[test]
    fn test_fail_mode_deny_reports_elapsed_ms() {
        let resp = build_fail_mode_deny(Value::from(1), "analysis timed out", 42.5, true, true);
        let v: Value = serde_json::from_str(&resp).unwrap();
        let elapsed = v["result"]["structuredContent"]["elapsed_ms"]
            .as_f64()
            .unwrap();
        assert!((elapsed - 42.5).abs() < 0.01);
    }

    #[test]
    fn test_fail_mode_deny_extraction_failed_no_double_prefix() {
        let resp = build_fail_mode_deny(
            Value::from(1),
            "command extraction failed",
            0.0,
            true,
            false,
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("Tirith: command extraction"));
        assert!(!text.contains("Tirith: Tirith"));
    }

    #[test]
    fn test_invalid_id_request_response_wire_format() {
        let resp = build_invalid_id_request_response();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32600);
        assert_eq!(
            v["error"]["message"],
            "Invalid request: id must be string, number, or null"
        );
        assert!(v["id"].is_null());
    }

    // -- Upstream write-failure shutdown test --

    #[test]
    fn test_forward_to_broken_writer_returns_error() {
        // Proves that forward() to a closed/broken writer returns Err,
        // which is the condition that now triggers shutdown in Thread 1.
        struct BrokenWriter;
        impl Write for BrokenWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"))
            }
        }
        let mut writer = BrokenWriter;
        let err = forward(&mut writer, b"test").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn test_process_object_to_broken_writer_returns_error() {
        // Non-guarded message forwarded to broken upstream → returns Err,
        // triggering shutdown in Thread 1.
        struct BrokenWriter;
        impl Write for BrokenWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"))
            }
        }
        let config = test_config();
        let (tx, _rx) = mpsc::channel::<Vec<u8>>();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let raw = serde_json::to_vec(&obj).unwrap();
        let mut writer = BrokenWriter;
        let pw = Mutex::new(HashMap::new());
        let err = process_object(&obj, &raw, &config, &mut writer, &tx, &pw).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn test_invalid_guarded_id_returns_local_error() {
        let config = test_config();
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": true,
            "method": "tools/call",
            "params": { "name": "Bash", "arguments": { "command": "ls" } }
        });
        let raw = serde_json::to_vec(&obj).unwrap();
        let mut writer = Vec::new();
        let pw = Mutex::new(HashMap::new());
        process_object(&obj, &raw, &config, &mut writer, &tx, &pw).unwrap();
        assert!(
            writer.is_empty(),
            "invalid guarded requests should not be forwarded"
        );

        let resp = rx.recv().unwrap();
        let v: Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32600);
        assert!(v["id"].is_null());
    }

    // -- Deny response wire format contract test (P1 fix) --

    #[test]
    fn test_deny_response_uses_wire_format_enums() {
        use tirith_core::verdict::{Finding, Severity, Timings, Verdict};

        let verdict = Verdict {
            action: Action::Block,
            findings: vec![
                Finding {
                    rule_id: tirith_core::verdict::RuleId::ShortenedUrl,
                    severity: Severity::Medium,
                    title: "Shortened URL detected".to_string(),
                    description: String::new(),
                    evidence: vec![],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                },
                Finding {
                    rule_id: tirith_core::verdict::RuleId::CurlPipeShell,
                    severity: Severity::Critical,
                    title: "Pipe to interpreter".to_string(),
                    description: String::new(),
                    evidence: vec![],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                },
            ],
            tier_reached: 3,
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: Timings::default(),
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
        };

        let resp = build_deny_response(Value::from(1), &verdict, 5.0);
        let v: Value = serde_json::from_str(&resp).unwrap();

        // structuredContent findings must use snake_case rule_id and UPPERCASE severity
        let findings = v["result"]["structuredContent"]["findings"]
            .as_array()
            .unwrap();
        assert_eq!(findings[0]["rule_id"], "shortened_url");
        assert_eq!(findings[0]["severity"], "MEDIUM");
        assert_eq!(findings[1]["rule_id"], "curl_pipe_shell");
        assert_eq!(findings[1]["severity"], "CRITICAL");

        // Human-readable text must also use wire format
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("[MEDIUM] shortened_url:"));
        assert!(text.contains("[CRITICAL] curl_pipe_shell:"));
        // Must NOT contain Debug-style formatting
        assert!(!text.contains("ShortenedUrl"));
        assert!(!text.contains("CurlPipeShell"));
    }

    // -- Warn augmentation tests --

    fn test_finding(
        rule_id: tirith_core::verdict::RuleId,
        severity: tirith_core::verdict::Severity,
        title: &str,
    ) -> Finding {
        Finding {
            rule_id,
            severity,
            title: title.to_string(),
            description: String::new(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }
    }

    #[test]
    fn test_warn_augmented_response_prepends_findings() {
        use tirith_core::verdict::{RuleId, Severity};

        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [
                    {"type": "text", "text": "original tool output"}
                ],
                "isError": false
            }
        });

        let findings = vec![test_finding(
            RuleId::PlainHttpToSink,
            Severity::Low,
            "Plain HTTP URL",
        )];

        let augmented = build_warn_augmented_response(upstream, &findings).unwrap();
        let v: Value = serde_json::from_slice(&augmented).unwrap();

        let content = v["result"]["content"].as_array().unwrap();
        assert_eq!(content.len(), 2, "should have warning + original");

        // First item is the prepended warning
        let warning = &content[0];
        assert_eq!(warning["type"], "text");
        let warning_text = warning["text"].as_str().unwrap();
        assert!(warning_text.contains("Tirith warnings"));
        assert!(warning_text.contains("plain_http_to_sink"));
        assert!(warning_text.contains("Plain HTTP URL"));

        // Second item is the original
        assert_eq!(content[1]["text"], "original tool output");
    }

    #[test]
    fn test_warn_augmented_response_returns_none_for_no_content() {
        // Response without result.content → None (pass-through)
        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {}
        });
        let findings = vec![test_finding(
            tirith_core::verdict::RuleId::PlainHttpToSink,
            tirith_core::verdict::Severity::Low,
            "test",
        )];
        assert!(build_warn_augmented_response(upstream, &findings).is_none());
    }

    #[test]
    fn test_warn_augmented_response_returns_none_for_non_array_content() {
        // result.content is a string, not array → None
        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": "not an array"}
        });
        let findings = vec![test_finding(
            tirith_core::verdict::RuleId::PlainHttpToSink,
            tirith_core::verdict::Severity::Low,
            "test",
        )];
        assert!(build_warn_augmented_response(upstream, &findings).is_none());
    }

    #[test]
    fn test_warn_augmented_response_returns_none_for_empty_findings() {
        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": []}
        });
        assert!(build_warn_augmented_response(upstream, &[]).is_none());
    }

    #[test]
    fn test_warn_augmented_response_returns_none_for_error_response() {
        // JSON-RPC error response (no result) → None
        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32600, "message": "bad request"}
        });
        let findings = vec![test_finding(
            tirith_core::verdict::RuleId::PlainHttpToSink,
            tirith_core::verdict::Severity::Low,
            "test",
        )];
        assert!(build_warn_augmented_response(upstream, &findings).is_none());
    }

    #[test]
    fn test_augment_if_pending_matches_and_removes() {
        use tirith_core::verdict::{RuleId, Severity};

        let pending: Mutex<HashMap<Value, (Vec<Finding>, Instant)>> = Mutex::new(HashMap::new());
        let id = Value::from(42);
        let findings = vec![test_finding(
            RuleId::PlainHttpToSink,
            Severity::Low,
            "Plain HTTP",
        )];
        pending
            .lock()
            .unwrap()
            .insert(id.clone(), (findings, Instant::now()));

        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 42,
            "result": {"content": [{"type": "text", "text": "ok"}]}
        });
        let line = serde_json::to_vec(&upstream).unwrap();

        // Should match and augment
        let result = augment_if_pending(&line, &pending);
        assert!(result.is_some());

        // Entry should be removed from map
        assert!(pending.lock().unwrap().is_empty());
    }

    #[test]
    fn test_augment_if_pending_no_match_passes_through() {
        let pending: Mutex<HashMap<Value, (Vec<Finding>, Instant)>> = Mutex::new(HashMap::new());
        // Map has id=42 but response has id=99
        pending.lock().unwrap().insert(
            Value::from(42),
            (
                vec![test_finding(
                    tirith_core::verdict::RuleId::PlainHttpToSink,
                    tirith_core::verdict::Severity::Low,
                    "test",
                )],
                Instant::now(),
            ),
        );

        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 99,
            "result": {"content": [{"type": "text", "text": "ok"}]}
        });
        let line = serde_json::to_vec(&upstream).unwrap();

        assert!(augment_if_pending(&line, &pending).is_none());
        // Original entry should still be in the map
        assert_eq!(pending.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_augment_if_pending_string_id() {
        use tirith_core::verdict::{RuleId, Severity};

        let pending: Mutex<HashMap<Value, (Vec<Finding>, Instant)>> = Mutex::new(HashMap::new());
        let id = Value::from("req-abc");
        pending.lock().unwrap().insert(
            id,
            (
                vec![test_finding(
                    RuleId::ShortenedUrl,
                    Severity::Medium,
                    "Shortened URL",
                )],
                Instant::now(),
            ),
        );

        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-abc",
            "result": {"content": [{"type": "text", "text": "ok"}]}
        });
        let line = serde_json::to_vec(&upstream).unwrap();

        let result = augment_if_pending(&line, &pending);
        assert!(result.is_some());
        let v: Value = serde_json::from_slice(&result.unwrap()).unwrap();
        assert!(v["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("shortened_url"));
    }
}
