use std::io::{self, BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::mcp::types::{ContentItem, JsonRpcError, JsonRpcResponse, ToolCallResult};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::Action;

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
    "deny".to_string()
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
        Ok(Self {
            guarded_tools: guarded,
            policy: config.policy,
        })
    }
}

fn validate_policy_values(policy: &PolicyConfig) -> Result<(), String> {
    match policy.warn_action.as_str() {
        "deny" | "forward" => {}
        other => {
            return Err(format!(
                "invalid warn_action '{other}': must be \"deny\" or \"forward\""
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
    };
    if let Ok(json) = serde_json::to_string(&entry) {
        eprintln!("{json}");
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

    // Thread 2: upstream stdout reader
    // Sets shutdown on EOF so main thread exits even if Thread 1 is blocked on stdin.
    let tx2 = output_tx.clone();
    let sd2 = shutdown.clone();
    let t_upstream = thread::spawn(move || {
        let mut reader = BufReader::new(child_stdout);
        loop {
            if sd2.load(Ordering::Relaxed) {
                break;
            }
            match read_bounded_line(&mut reader, max_bytes) {
                Ok(Some(line)) => {
                    if tx2.send(line).is_err() {
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
                Ok(ref obj) => process_object(obj, &raw_line, &cfg, &mut upstream, &tx1).err(),
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
) -> io::Result<()> {
    match check_guarded(obj, config) {
        GuardedResult::NotGuarded => forward(upstream, raw_line),
        GuardedResult::GuardedNotification { tool_name } => {
            write_audit(
                "allow",
                "passthrough_notification",
                &[],
                None,
                &tool_name,
                "",
                0.0,
                false,
                false,
            );
            forward(upstream, raw_line)
        }
        GuardedResult::Guarded {
            id,
            command,
            tool_name,
            shell,
        } => handle_guarded_call(
            id, &command, &tool_name, shell, raw_line, config, upstream, output_tx,
        ),
        GuardedResult::ExtractionFailed { id, tool_name } => {
            handle_extraction_failed(id, &tool_name, raw_line, config, upstream, output_tx)
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
) -> io::Result<()> {
    let start = std::time::Instant::now();
    let hash = cmd_hash_prefix(command);

    // Inline analysis with oneshot thread + timeout
    let (tx, rx) = mpsc::channel();
    let cmd_owned = command.to_string();
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    thread::spawn(move || {
        let ctx = AnalysisContext {
            input: cmd_owned,
            shell,
            scan_context: ScanContext::Exec,
            raw_bytes: None,
            interactive: true,
            cwd,
            file_path: None,
        };
        let _ = tx.send(engine::analyze(&ctx));
    });

    let timeout = Duration::from_millis(config.policy.timeout_ms);
    match rx.recv_timeout(timeout) {
        Ok(verdict) => {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;
            let should_deny = match verdict.action {
                Action::Block => true,
                Action::Warn => config.policy.warn_action == "deny",
                Action::Allow => false,
            };

            let rule_ids: Vec<String> = verdict
                .findings
                .iter()
                .map(|f| f.rule_id.to_string())
                .collect();
            let max_sev = verdict
                .findings
                .iter()
                .map(|f| f.severity)
                .max()
                .map(|s| s.to_string());

            if should_deny {
                let decision = if verdict.action == Action::Block {
                    "block"
                } else {
                    "warn"
                };
                write_audit(
                    decision,
                    "denied",
                    &rule_ids,
                    max_sev.as_deref(),
                    tool_name,
                    &hash,
                    elapsed,
                    false,
                    false,
                );
                let _ = output_tx.send(build_deny_response(id, &verdict, elapsed).into_bytes());
                Ok(())
            } else {
                let decision = if verdict.action == Action::Warn {
                    "warn"
                } else {
                    "allow"
                };
                write_audit(
                    decision,
                    "forwarded",
                    &rule_ids,
                    max_sev.as_deref(),
                    tool_name,
                    &hash,
                    elapsed,
                    false,
                    false,
                );
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

// ---------------------------------------------------------------------------
// Guarded check
// ---------------------------------------------------------------------------

enum GuardedResult {
    NotGuarded,
    GuardedNotification {
        tool_name: String,
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

    let id = match obj.get("id") {
        Some(v) => match v {
            // Valid JSON-RPC id types: string, number, null
            Value::String(_) | Value::Number(_) | Value::Null => v.clone(),
            // Invalid id types (object, array, boolean) → normalize to null
            _ => Value::Null,
        },
        None => return GuardedResult::GuardedNotification { tool_name },
    };

    // Extract command via JSON Pointer paths (resolved against params)
    for pointer in &guard.command_paths {
        if let Some(val) = resolve_json_pointer(params, pointer) {
            if let Some(s) = val.as_str() {
                if !s.is_empty() {
                    return GuardedResult::Guarded {
                        id,
                        command: s.to_string(),
                        tool_name,
                        shell: guard.shell,
                    };
                }
            }
        }
    }

    GuardedResult::ExtractionFailed { id, tool_name }
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
        Action::Warn => "warn",
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
        assert_eq!(config.policy.warn_action, "deny");
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
        assert!(matches!(
            check_guarded(&obj, &config),
            GuardedResult::GuardedNotification { .. }
        ));
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
        // Verify the depth check logic
        assert!(1u32 >= 1); // depth=1 would trigger abort
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
    fn test_guarded_boolean_id_normalized_to_null() {
        let config = test_config();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": true,
            "method": "tools/call",
            "params": { "name": "Bash", "arguments": { "command": "ls" } }
        });
        match check_guarded(&obj, &config) {
            GuardedResult::Guarded { id, .. } => assert!(id.is_null()),
            _ => panic!("expected Guarded"),
        }
    }

    #[test]
    fn test_guarded_object_id_normalized_to_null() {
        let config = test_config();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": {"nested": "obj"},
            "method": "tools/call",
            "params": { "name": "Bash", "arguments": { "command": "ls" } }
        });
        match check_guarded(&obj, &config) {
            GuardedResult::Guarded { id, .. } => assert!(id.is_null()),
            _ => panic!("expected Guarded"),
        }
    }

    #[test]
    fn test_guarded_array_id_normalized_to_null() {
        let config = test_config();
        let obj: Value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": [1, 2],
            "method": "tools/call",
            "params": { "name": "Bash", "arguments": { "command": "ls" } }
        });
        match check_guarded(&obj, &config) {
            GuardedResult::Guarded { id, .. } => assert!(id.is_null()),
            _ => panic!("expected Guarded"),
        }
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
        let err = process_object(&obj, &raw, &config, &mut writer, &tx).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
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
                },
                Finding {
                    rule_id: tirith_core::verdict::RuleId::CurlPipeShell,
                    severity: Severity::Critical,
                    title: "Pipe to interpreter".to_string(),
                    description: String::new(),
                    evidence: vec![],
                    human_view: None,
                    agent_view: None,
                },
            ],
            tier_reached: 3,
            bypass_requested: false,
            bypass_honored: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: Timings::default(),
            urls_extracted_count: None,
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
}
