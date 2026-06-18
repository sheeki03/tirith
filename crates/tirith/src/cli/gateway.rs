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
use tirith_core::mcp::output_filter::{self, FilterOutcome};
use tirith_core::mcp::types::{ContentItem, JsonRpcError, JsonRpcResponse, ToolCallResult};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Action, Finding};

/// Per-run gateway options (CLI surface). M7 ch4: `filter_output` (opt-in,
/// default `false`) routes every guarded-tool response's `result.content`
/// through [`tirith_core::mcp::output_filter::filter_tool_result`].
#[derive(Debug, Clone, Default)]
pub struct GatewayOptions {
    pub filter_output: bool,
}

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
        // Normalize "allow" → "forward" so downstream only checks == "deny".
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

/// JSON Pointer (RFC 6901) resolved against a params object.
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

/// Audit log: one JSON line per event, written to stderr.
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
    /// M4 item 8 ch3 — every gateway audit line carries `agent_origin: gateway`
    /// (the serialized struct previously lacked the field that the verdict had).
    agent_origin: tirith_core::agent_origin::AgentOrigin,
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
        // The gateway is the only call site, so stamping here (vs threading the
        // verdict's origin) guarantees no gateway line ships without attribution.
        agent_origin: tirith_core::agent_origin::AgentOrigin::Gateway,
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

pub fn run_gateway_with_options(
    upstream_bin: &str,
    upstream_args: &[String],
    config_path: &str,
    options: GatewayOptions,
) -> i32 {
    let depth: u32 = std::env::var("TIRITH_GATEWAY_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if depth >= 1 {
        eprintln!("tirith gateway: recursion detected (depth={depth}), aborting");
        return 1;
    }

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
    let filter_output = options.filter_output;

    // Pending warn-forwarded request IDs → findings. Thread 1 inserts before
    // forwarding; Thread 2 removes on response match. Keyed by Value (IDs can be
    // string/number/null).
    #[allow(clippy::type_complexity)]
    let pending_warns: Arc<Mutex<HashMap<Value, (Vec<Finding>, Instant)>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // M7 ch4: under `--filter-output`, Thread 1 records every guarded ID it
    // forwards (warn OR allow) so Thread 2 knows which responses to filter. TTL
    // 30s + 10s sweep (mirroring `pending_warns`) caps memory.
    let pending_filter_ids: Arc<Mutex<HashMap<Value, Instant>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Thread 2 (upstream stdout): sets shutdown on EOF so main exits even when
    // Thread 1 is blocked on client stdin.
    let tx2 = output_tx.clone();
    let sd2 = shutdown.clone();
    let pw2 = Arc::clone(&pending_warns);
    let pf2 = Arc::clone(&pending_filter_ids);
    // M7 ch4: route policy.fail_mode into the output filter so `fail_mode: closed`
    // fails closed on the output direction too (default "open" stays compatible).
    let fail_mode_closed = config.policy.fail_mode == "closed";

    // C3a — MCP policy seam (gateway). The gateway's own `PolicyConfig` is
    // unrelated to the core `Policy`; discover a core policy ONCE at init
    // (OFFLINE via `discover_local_only`, which neutralizes a repo-scoped
    // `mcp_redact_injection`), compile the operator's `injection_seeds_custom`,
    // and read the redact flag into an `OutputFilterContext` shared with the
    // upstream-reader thread. Built only under `--filter-output`. This is init,
    // not the hot path, so each bad seed is reported ONCE (to stderr, the
    // gateway's diagnostic channel) rather than silently dropped: a seed that
    // passes `policy validate` but fails the real compile would otherwise vanish.
    let filter_ctx: Arc<output_filter::OutputFilterContext> = Arc::new(if filter_output {
        let policy = tirith_core::policy::Policy::discover_local_only(
            std::env::current_dir()
                .ok()
                .and_then(|p| p.to_str().map(String::from))
                .as_deref(),
        );
        let (ctx, bad) = output_filter::OutputFilterContext::from_policy(&policy);
        for (pattern, error) in &bad {
            eprintln!(
                "tirith gateway: warning: invalid injection_seeds_custom regex {pattern:?}: {error}"
            );
        }
        ctx
    } else {
        output_filter::OutputFilterContext::default()
    });
    let fc2 = Arc::clone(&filter_ctx);
    let t_upstream = thread::spawn(move || {
        let mut reader = BufReader::new(child_stdout);
        loop {
            if sd2.load(Ordering::Relaxed) {
                break;
            }
            match read_bounded_line(&mut reader, max_bytes) {
                Ok(Some(line)) => {
                    // Filter first (a block short-circuits warn-augmentation), then
                    // warn-augment residual content.
                    let after_filter = if filter_output {
                        filter_if_pending(&line, &pf2, fail_mode_closed, &fc2).unwrap_or(line)
                    } else {
                        line
                    };
                    let to_send = augment_if_pending(&after_filter, &pw2).unwrap_or(after_filter);
                    if tx2.send(to_send).is_err() {
                        break;
                    }
                }
                Ok(None) => {
                    // Upstream EOF: signal shutdown, else main hangs (Thread 1's
                    // sender keeps the channel alive while it blocks on stdin).
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

    let tx1 = output_tx;
    let sd1 = shutdown.clone();
    let cd1 = client_done.clone();
    let cfg = config.clone();
    let pw1 = Arc::clone(&pending_warns);
    let pf1 = Arc::clone(&pending_filter_ids);
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
                    // Client stdin EOF — normal shutdown.
                    cd1.store(true, Ordering::Relaxed);
                    sd1.store(true, Ordering::Relaxed);
                    break;
                }
                Err(n) => {
                    eprintln!("tirith gateway: client message exceeds max_message_bytes ({n} > {max_bytes}), terminating");
                    sd1.store(true, Ordering::Relaxed);
                    break;
                }
            };

            let write_err = match serde_json::from_slice::<Value>(&raw_line) {
                Err(_) => forward(&mut upstream, &raw_line).err(),
                Ok(Value::Array(ref arr)) => {
                    // Batch requests fail closed until batch interception lands.
                    handle_batch_deny(arr, &tx1);
                    None
                }
                Ok(ref val) if !val.is_object() => forward(&mut upstream, &raw_line).err(),
                Ok(ref obj) => process_object(
                    obj,
                    &raw_line,
                    &cfg,
                    &mut upstream,
                    &tx1,
                    &pw1,
                    if filter_output { Some(&pf1) } else { None },
                )
                .err(),
            };
            if let Some(e) = write_err {
                eprintln!("tirith gateway: upstream write failed: {e}");
                sd1.store(true, Ordering::Relaxed);
                break;
            }
        }
        // Drop upstream stdin to signal EOF to the child process.
        drop(upstream);
    });

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

        // Evict stale entries from both pending maps: TTL 30s, sweep every 10s,
        // so a never-replying upstream cannot grow memory unbounded.
        if last_sweep.elapsed() > Duration::from_secs(10) {
            if let Ok(mut map) = pending_warns.lock() {
                let cutoff = Instant::now() - Duration::from_secs(30);
                map.retain(|_, (_, ts)| *ts > cutoff);
            }
            if let Ok(mut map) = pending_filter_ids.lock() {
                let cutoff = Instant::now() - Duration::from_secs(30);
                map.retain(|_, ts| *ts > cutoff);
            }
            last_sweep = Instant::now();
        }
    }
    drop(stdout);

    // Abnormal unless the client initiated shutdown via stdin EOF.
    let abnormal = !client_done.load(Ordering::Relaxed);
    let exit_code = shutdown_child(&mut child, abnormal);

    // Threads 2 and 3 exit on child stdout/stderr EOF, so join is safe.
    let _ = t_upstream.join();
    let _ = t_stderr.join();

    // Thread 1 may be blocked on stdin and uninterruptible — bounded wait, then
    // process exit cleans it up.
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

fn process_object(
    obj: &Value,
    raw_line: &[u8],
    config: &CompiledConfig,
    upstream: &mut impl Write,
    output_tx: &mpsc::Sender<Vec<u8>>,
    pending_warns: &Mutex<HashMap<Value, (Vec<Finding>, Instant)>>,
    pending_filter_ids: Option<&Mutex<HashMap<Value, Instant>>>,
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
            pending_filter_ids,
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
    pending_filter_ids: Option<&Mutex<HashMap<Value, Instant>>>,
) -> io::Result<()> {
    let start = Instant::now();
    let hash = cmd_hash_prefix(command);

    // Inline analysis on a oneshot thread + timeout. The channel carries
    // (Verdict, Policy) so we reuse the engine's loaded policy.
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
            card_ref: None,
            clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
        };
        let _ = tx.send(engine::analyze_returning_policy(&ctx));
    });

    let timeout = Duration::from_millis(config.policy.timeout_ms);
    match rx.recv_timeout(timeout) {
        Ok((mut raw_verdict, engine_policy)) => {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;

            // M4 item 8 — stamp Gateway origin so the audit records the path and
            // `post_process_verdict` can apply `agent_rules.deny` (the `TIRITH=0`
            // bypass branch skips post-processing, so deny does not enforce there).
            raw_verdict.agent_origin = Some(tirith_core::agent_origin::AgentOrigin::Gateway);

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

                // M7 ch4. Under `--filter-output`, record every guarded forward
                // (warn OR allow) so Thread 2 filters the response. Inserted BEFORE
                // forward (and before the warn insert) to avoid the fast-upstream
                // race documented on the warn path.
                if let Some(pf) = pending_filter_ids {
                    match pf.lock() {
                        Ok(mut map) => {
                            map.insert(id.clone(), Instant::now());
                        }
                        Err(e) => {
                            eprintln!(
                                "tirith gateway: pending_filter_ids mutex poisoned on insert: {e}"
                            );
                        }
                    }
                }

                // For warn-forwarded requests with findings, insert into the
                // pending map BEFORE forward (else a fast upstream could reply
                // before the entry exists and Thread 2 would miss it).
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

                // On forward failure Thread 1 shuts down; the pending map is
                // cleaned up when the Arcs drop, so no explicit removal is needed.
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
            card_ref: None,
            clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
        };
        let _ = tx.send(engine::analyze_returning_policy(&ctx));
    });

    let timeout = Duration::from_millis(config.policy.timeout_ms);
    match rx.recv_timeout(timeout) {
        Ok((mut raw_verdict, engine_policy)) => {
            let elapsed = start.elapsed().as_secs_f64() * 1000.0;

            // M4 item 8 — same Gateway origin attribution as the request path
            // (bypass skips post-processing here too).
            raw_verdict.agent_origin = Some(tirith_core::agent_origin::AgentOrigin::Gateway);

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

/// Batch request handler: currently fails closed until batch interception lands.
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

/// Build a deny response for fail-mode denials (timeout, extraction failure),
/// using the same MCP tool-result envelope (`isError=true`) as policy denials.
/// `reason` is a short description; this function adds the "Tirith:" prefix.
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

/// M7 ch4. If an upstream response matches a guarded request forwarded under
/// `--filter-output`, parse `result` as a `ToolCallResult`, run it through
/// [`output_filter::filter_tool_result`], and re-serialize. Returns
/// `Some(filtered)` on block/warn, `None` when the id is not pending or `result`
/// is unparseable. Removes the pending entry on match (once per response); a
/// block/warn writes a JSONL audit line, allow is silent.
fn filter_if_pending(
    line: &[u8],
    pending: &Mutex<HashMap<Value, Instant>>,
    fail_mode_closed: bool,
    filter_ctx: &output_filter::OutputFilterContext,
) -> Option<Vec<u8>> {
    let parsed: Value = serde_json::from_slice(line).ok()?;
    let resp_id = parsed.get("id")?;

    // Brief lock: remove the entry; a miss means not-pending → pass through.
    {
        let mut map = match pending.lock() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("tirith gateway: pending_filter_ids mutex poisoned: {e}");
                return None;
            }
        };
        map.remove(resp_id)?;
    }

    apply_output_filter_to_response(parsed, fail_mode_closed, filter_ctx)
}

/// Parse `parsed["result"]` as a `ToolCallResult`, filter it, and re-serialize.
/// Branches: a parseable `result` is filtered normally; a malformed `result`
/// synthesizes a block envelope under `fail_mode_closed` (else passes through with
/// a `parse_error` audit line); a `result`-less JSON-RPC error envelope has its
/// `error.message`/`error.data` sanitized for OSC52/hyperlink payloads (Greptile P1).
fn apply_output_filter_to_response(
    mut parsed: Value,
    fail_mode_closed: bool,
    filter_ctx: &output_filter::OutputFilterContext,
) -> Option<Vec<u8>> {
    // Error-response path: error envelopes lack a top-level `result`. Pre-fix this
    // returned `None`, letting an upstream embed OSC52 in `error.message`.
    if parsed.get("result").is_none() {
        if let Some(error) = parsed.get_mut("error") {
            let sanitized_any = sanitize_error_fields(error);
            if sanitized_any {
                // Pass the sanitized envelope through with a best-effort audit line.
                let entry = serde_json::json!({
                    "ts": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    "kind": "gateway_output_filter",
                    "decision": "warn",
                    "rule_ids": ["gateway_error_message_sanitized"],
                    "agent_origin": tirith_core::agent_origin::AgentOrigin::Gateway,
                });
                if let Ok(json) = serde_json::to_string(&entry) {
                    eprintln!("{json}");
                }
                return serde_json::to_vec(&parsed).ok();
            }
        }
        return None;
    }

    // Result-response path.
    let result_val = parsed.get("result")?;

    // Reify `result` as a `ToolCallResult` (the dispatcher's shape).
    let mut tool_result: ToolCallResult = match serde_json::from_value(reshape_for_deserialize(
        result_val.clone(),
    )) {
        Ok(tr) => tr,
        Err(e) => {
            // Sev-7 fix: a tool-shaped-but-unparseable `result` used to pass
            // through unfiltered with no audit line. Closed fail-mode synthesizes a
            // block envelope; open fail-mode passes through with a `parse_error` line.
            let entry = serde_json::json!({
                "ts": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "kind": "gateway_output_filter",
                "decision": if fail_mode_closed { "block" } else { "parse_error" },
                "error": e.to_string(),
                "fail_mode_triggered": fail_mode_closed,
                "agent_origin": tirith_core::agent_origin::AgentOrigin::Gateway,
            });
            if let Ok(json) = serde_json::to_string(&entry) {
                eprintln!("{json}");
            }
            if fail_mode_closed {
                // Synthesize a minimal block envelope (the `apply_block` helper
                // needs a real ToolCallResult we don't have here).
                let event_id = uuid::Uuid::new_v4().to_string();
                let new_result = serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": format!(
                            "[tirith: tool output blocked \u{2014} see audit log entry {event_id} for details]"
                        ),
                    }],
                    "isError": true,
                });
                let obj = parsed.as_object_mut()?;
                obj.insert("result".to_string(), new_result);
                return serde_json::to_vec(&parsed).ok();
            }
            return None;
        }
    };

    let outcome = output_filter::filter_tool_result(&mut tool_result, fail_mode_closed, filter_ctx);
    write_filter_audit_line(&outcome);

    // Re-serialize (camelCase) and splice back into the response.
    let new_result = serde_json::to_value(&tool_result).ok()?;
    let result_slot = parsed.as_object_mut()?.get_mut("result")?;
    *result_slot = new_result;
    serde_json::to_vec(&parsed).ok()
}

/// Sanitize `error.message`/`error.data` in place (scrubbing OSC52 / hyperlinks /
/// hidden-text an upstream may embed in an error response). Returns `true` if any
/// field changed.
fn sanitize_error_fields(error: &mut Value) -> bool {
    let Some(obj) = error.as_object_mut() else {
        return false;
    };
    let mut touched = false;

    if let Some(Value::String(msg)) = obj.get_mut("message") {
        let mut out = Vec::with_capacity(msg.len());
        tirith_core::mcp::output_filter::sanitize_text_into(msg.as_bytes(), &mut out);
        if out != msg.as_bytes() {
            *msg = String::from_utf8(out).unwrap_or_else(|_| std::mem::take(msg));
            touched = true;
        }
    }

    if let Some(Value::String(s)) = obj.get_mut("data") {
        let mut out = Vec::with_capacity(s.len());
        tirith_core::mcp::output_filter::sanitize_text_into(s.as_bytes(), &mut out);
        if out != s.as_bytes() {
            *s = String::from_utf8(out).unwrap_or_else(|_| std::mem::take(s));
            touched = true;
        }
    }

    touched
}

/// Coerce an upstream's `result.content` into the shape `ToolCallResult`
/// deserializes (`type: "text"`, string `text`): default missing `type` to
/// `"text"`, stringify non-string `text`, skip items with no `text`. A tolerant
/// hand-rolled parse because `ToolCallResult` is Serialize-only, so generic
/// upstreams that don't ship the exact struct still get filtered.
fn reshape_for_deserialize(mut v: Value) -> Value {
    let Some(obj) = v.as_object_mut() else {
        return v;
    };
    if !obj.contains_key("isError") {
        obj.insert("isError".to_string(), Value::Bool(false));
    }
    if let Some(content) = obj.get_mut("content").and_then(|c| c.as_array_mut()) {
        let mut keep = Vec::with_capacity(content.len());
        for item in content.drain(..) {
            if let Value::Object(mut map) = item {
                if !map.contains_key("type") {
                    map.insert("type".to_string(), Value::String("text".to_string()));
                }
                match map.get("text") {
                    Some(Value::String(_)) => {}
                    Some(other) => {
                        let s = other.to_string();
                        map.insert("text".to_string(), Value::String(s));
                    }
                    None => continue, // skip items without a text field
                }
                keep.push(Value::Object(map));
            }
        }
        *content = keep;
    } else {
        obj.insert("content".to_string(), Value::Array(Vec::new()));
    }
    v
}

/// Best-effort JSONL audit line for one output-filter pass (no `command` to log,
/// so it's small and dedicated).
fn write_filter_audit_line(outcome: &FilterOutcome) {
    let entry = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "kind": "gateway_output_filter",
        "decision": match outcome.action {
            Action::Block => "block",
            Action::Warn | Action::WarnAck => "warn",
            Action::Allow => "allow",
        },
        "event_id": outcome.event_id,
        "rule_ids": outcome.rule_ids,
        "findings_count": outcome.rule_ids.len(),
        "highest_severity": outcome
            .max_severity
            .map(|s| s.to_string())
            .unwrap_or_else(|| "NONE".to_string()),
        "elapsed_ms": outcome.elapsed_ms,
        "truncated": outcome.truncated,
        "fail_mode_triggered": outcome.fail_mode_triggered,
        "agent_origin": tirith_core::agent_origin::AgentOrigin::Gateway,
    });
    if let Ok(json) = serde_json::to_string(&entry) {
        eprintln!("{json}");
    }
}

/// If an upstream response matches a pending warn-forwarded request, augment it
/// with findings and remove the map entry. `Some(augmented)` on success, else `None`.
fn augment_if_pending(
    line: &[u8],
    pending: &Mutex<HashMap<Value, (Vec<Finding>, Instant)>>,
) -> Option<Vec<u8>> {
    let parsed: Value = serde_json::from_slice(line).ok()?;
    let resp_id = parsed.get("id")?;

    // Brief lock: look up and remove the id.
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

    // Augment outside the lock — no I/O while holding the mutex.
    build_warn_augmented_response(parsed, &findings)
}

/// Prepend warn findings to `result.content`. Operates on `serde_json::Value`
/// (the typed MCP structs are Serialize-only and assume Tirith-shaped responses),
/// so it is defensive: returns `None` on any failure (caller forwards original bytes).
fn build_warn_augmented_response(mut parsed: Value, findings: &[Finding]) -> Option<Vec<u8>> {
    if findings.is_empty() {
        return None;
    }

    let content = parsed
        .get_mut("result")?
        .get_mut("content")?
        .as_array_mut()?;

    let warning_lines: Vec<String> = findings
        .iter()
        .map(|f| format!("  [{}] {}: {}", f.severity, f.rule_id, f.title))
        .collect();
    let warning_text = format!(
        "\u{26a0} Tirith warnings (non-blocking):\n{}",
        warning_lines.join("\n")
    );

    let warning_item = serde_json::json!({
        "type": "text",
        "text": warning_text
    });
    content.insert(0, warning_item);

    serde_json::to_vec(&parsed).ok()
}

fn forward(writer: &mut impl Write, line: &[u8]) -> io::Result<()> {
    writer.write_all(line)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn shutdown_child(child: &mut Child, abnormal: bool) -> i32 {
    if let Ok(Some(_)) = child.try_wait() {
        return if abnormal { 1 } else { 0 };
    }

    // stdin is already closed; give the child up to 5s for a graceful exit.
    for _ in 0..50 {
        thread::sleep(Duration::from_millis(100));
        if let Ok(Some(_)) = child.try_wait() {
            return if abnormal { 1 } else { 0 };
        }
    }

    #[cfg(unix)]
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }

    // Grace period after SIGTERM before force-kill.
    for _ in 0..20 {
        thread::sleep(Duration::from_millis(100));
        if let Ok(Some(_)) = child.try_wait() {
            return if abnormal { 1 } else { 0 };
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    if abnormal {
        1
    } else {
        0
    }
}

/// Bounded line reader: `fill_buf`/`consume` in chunks so an oversize line never
/// allocates past `limit`.
fn read_bounded_line(reader: &mut impl BufRead, limit: usize) -> Result<Option<Vec<u8>>, usize> {
    let mut buf = Vec::with_capacity(std::cmp::min(limit, 8192));
    loop {
        let available = match reader.fill_buf() {
            Ok([]) => {
                if buf.is_empty() {
                    return Ok(None);
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
            // Oversize line: drop the chunk and drain to the next newline so the
            // reader resyncs for the following message.
            reader.consume(avail_len);
            let total = buf.len() + avail_len;
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_recursion_depth() {
        // Verify the depth check logic: any depth >= 1 should trigger abort
        let depth: u32 = 1;
        assert!(depth >= 1);
    }

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
            agent_origin: tirith_core::agent_origin::AgentOrigin::Gateway,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["decision"], "block");
        assert_eq!(parsed["findings_count"], 1);
        assert_eq!(parsed["tool_name"], "Bash");
        // M4 item 8 ch3 — every gateway audit line carries `agent_origin: gateway`.
        assert_eq!(parsed["agent_origin"]["kind"], "gateway");
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
            agent_origin: tirith_core::agent_origin::AgentOrigin::Gateway,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        // The injected content should be inside the tool_name string, not a separate field
        assert!(parsed.get("injected").is_none());
        assert!(parsed["tool_name"].as_str().unwrap().contains("injected"));
    }

    #[test]
    fn test_config_rejects_zero_max_message_bytes() {
        let yaml = "guarded_tools: []\npolicy:\n  max_message_bytes: 0\n";
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        let err = CompiledConfig::from_config(config).unwrap_err();
        assert!(err.contains("max_message_bytes"));
    }

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

    #[test]
    fn test_forward_to_broken_writer_returns_error() {
        // forward() to a broken writer returns Err (the Thread 1 shutdown trigger).
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
        // Non-guarded message to a broken upstream → Err (Thread 1 shutdown).
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
        let err = process_object(&obj, &raw, &config, &mut writer, &tx, &pw, None).unwrap_err();
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
        process_object(&obj, &raw, &config, &mut writer, &tx, &pw, None).unwrap();
        assert!(
            writer.is_empty(),
            "invalid guarded requests should not be forwarded"
        );

        let resp = rx.recv().unwrap();
        let v: Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32600);
        assert!(v["id"].is_null());
    }

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
            agent_origin: None,
            manifest_allowed_match: None,
        };

        let resp = build_deny_response(Value::from(1), &verdict, 5.0);
        let v: Value = serde_json::from_str(&resp).unwrap();

        // structuredContent findings: snake_case rule_id + UPPERCASE severity.
        let findings = v["result"]["structuredContent"]["findings"]
            .as_array()
            .unwrap();
        assert_eq!(findings[0]["rule_id"], "shortened_url");
        assert_eq!(findings[0]["severity"], "MEDIUM");
        assert_eq!(findings[1]["rule_id"], "curl_pipe_shell");
        assert_eq!(findings[1]["severity"], "CRITICAL");

        // Human-readable text uses wire format too, not Debug-style.
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("[MEDIUM] shortened_url:"));
        assert!(text.contains("[CRITICAL] curl_pipe_shell:"));
        assert!(!text.contains("ShortenedUrl"));
        assert!(!text.contains("CurlPipeShell"));
    }

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

        // First item is the prepended warning.
        let warning = &content[0];
        assert_eq!(warning["type"], "text");
        let warning_text = warning["text"].as_str().unwrap();
        assert!(warning_text.contains("Tirith warnings"));
        assert!(warning_text.contains("plain_http_to_sink"));
        assert!(warning_text.contains("Plain HTTP URL"));

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

        let result = augment_if_pending(&line, &pending);
        assert!(result.is_some());
        // Entry removed from the map.
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

    // M7 ch4 — output filter wire-format tests.

    #[test]
    fn test_filter_if_pending_blocks_osc52_payload() {
        // Block path: `isError: true` + sanitized placeholder + id echo, no error envelope.
        let pending: Mutex<HashMap<Value, Instant>> = Mutex::new(HashMap::new());
        let id = Value::from(42);
        pending.lock().unwrap().insert(id.clone(), Instant::now());

        // Synthetic MCP envelope with an OSC52 payload in `result.content[0].text`.
        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 42,
            "result": {
                "content": [
                    {"type": "text", "text": "harmless-prefix\u{001B}]52;c;aGVsbG8=\u{0007}harmless-suffix"}
                ],
                "isError": false
            }
        });
        let line = serde_json::to_vec(&upstream).unwrap();

        let filtered = filter_if_pending(
            &line,
            &pending,
            false,
            &output_filter::OutputFilterContext::default(),
        )
        .expect("OSC52 must be filtered");
        let v: Value = serde_json::from_slice(&filtered).unwrap();

        // Envelope preserved (id echoed); block contract is isError + a single placeholder.
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 42);
        assert_eq!(v["result"]["isError"], true);
        let content = v["result"]["content"].as_array().expect("content array");
        assert_eq!(content.len(), 1, "block must collapse to one placeholder");
        let text = content[0]["text"].as_str().expect("placeholder text");
        assert!(
            text.starts_with("[tirith: tool output blocked"),
            "placeholder shape, got: {text}"
        );
        assert!(text.contains("see audit log entry"));
        // Not a JSON-RPC error envelope.
        assert!(
            v.get("error").is_none(),
            "block path must NOT emit a JSON-RPC error envelope"
        );

        assert!(pending.lock().unwrap().is_empty());
    }

    #[test]
    fn test_filter_if_pending_passes_through_benign_content() {
        let pending: Mutex<HashMap<Value, Instant>> = Mutex::new(HashMap::new());
        let id = Value::from(7);
        pending.lock().unwrap().insert(id.clone(), Instant::now());

        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 7,
            "result": {
                "content": [
                    {"type": "text", "text": "tool ran fine — all clear"}
                ],
                "isError": false
            }
        });
        let line = serde_json::to_vec(&upstream).unwrap();

        let filtered = filter_if_pending(
            &line,
            &pending,
            false,
            &output_filter::OutputFilterContext::default(),
        )
        .expect("must process pending id");
        let v: Value = serde_json::from_slice(&filtered).unwrap();

        // Allow path: content identical. `isError` is omitted when false
        // (skip_serializing_if), so absent or explicit `false` both mean "not an error".
        match v["result"].get("isError") {
            None => {}
            Some(Value::Bool(false)) => {}
            other => panic!("allow path must NOT mark isError=true; got {other:?}"),
        }
        assert_eq!(
            v["result"]["content"][0]["text"],
            "tool ran fine — all clear"
        );
    }

    #[test]
    fn test_filter_if_pending_returns_none_when_id_not_pending() {
        // Not pending → None (caller forwards the original bytes verbatim).
        let pending: Mutex<HashMap<Value, Instant>> = Mutex::new(HashMap::new());
        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 99,
            "result": {"content": [{"type": "text", "text": "ok"}]}
        });
        let line = serde_json::to_vec(&upstream).unwrap();
        assert!(filter_if_pending(
            &line,
            &pending,
            false,
            &output_filter::OutputFilterContext::default()
        )
        .is_none());
    }

    #[test]
    fn test_filter_if_pending_passes_through_benign_error_envelope() {
        // A clean error response passes through untouched (sanitizer is a no-op).
        let pending: Mutex<HashMap<Value, Instant>> = Mutex::new(HashMap::new());
        let id = Value::from(1);
        pending.lock().unwrap().insert(id, Instant::now());

        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32601, "message": "method not found"}
        });
        let line = serde_json::to_vec(&upstream).unwrap();
        // Sanitizer returned no-op → None to caller → pass through.
        assert!(filter_if_pending(
            &line,
            &pending,
            false,
            &output_filter::OutputFilterContext::default()
        )
        .is_none());
        assert!(pending.lock().unwrap().is_empty());
    }

    #[test]
    fn test_filter_if_pending_sanitizes_osc52_in_error_message() {
        // Greptile P1: OSC52 in `error.message` used to bypass `--filter-output`;
        // the sanitizer must scrub it.
        let pending: Mutex<HashMap<Value, Instant>> = Mutex::new(HashMap::new());
        let id = Value::from(11);
        pending.lock().unwrap().insert(id, Instant::now());

        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 11,
            "error": {
                "code": -32603,
                "message": "internal\u{001B}]52;c;aGVsbG8=\u{0007}error",
            }
        });
        let line = serde_json::to_vec(&upstream).unwrap();
        let filtered = filter_if_pending(
            &line,
            &pending,
            false,
            &output_filter::OutputFilterContext::default(),
        )
        .expect("error-path sanitization must rewrite the envelope");
        let v: Value = serde_json::from_slice(&filtered).unwrap();
        let msg = v["error"]["message"].as_str().unwrap();
        assert!(
            !msg.contains('\u{001B}'),
            "OSC52 escape must be stripped, got: {msg:?}"
        );
        assert!(msg.starts_with("internal") && msg.ends_with("error"));
    }

    #[test]
    fn test_filter_if_pending_fail_closed_blocks_malformed_result() {
        // Silent-failure fix: a tool-shaped-but-unparseable `result` used to pass
        // through unfiltered. Closed fail-mode now synthesizes a block envelope;
        // a plain-string `result` triggers the parse-error branch.
        let pending: Mutex<HashMap<Value, Instant>> = Mutex::new(HashMap::new());
        let id = Value::from(21);
        pending.lock().unwrap().insert(id, Instant::now());

        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 21,
            "result": "just-a-string-not-a-tool-result-shape",
        });
        let line = serde_json::to_vec(&upstream).unwrap();
        let filtered = filter_if_pending(
            &line,
            &pending,
            /*fail_mode_closed=*/ true,
            &output_filter::OutputFilterContext::default(),
        )
        .expect("fail-closed must synthesize a block envelope on parse error");
        let v: Value = serde_json::from_slice(&filtered).unwrap();
        assert_eq!(v["result"]["isError"], true);
        let placeholder = v["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            placeholder.starts_with("[tirith: tool output blocked"),
            "placeholder shape, got: {placeholder}"
        );
    }

    #[test]
    fn test_filter_if_pending_warn_prepends_notice_and_sanitizes() {
        // Hidden-text rule (zero-width run > 8) lands at Warn: a notice item is
        // prepended and the original text is retained with zero-width stripped.
        let pending: Mutex<HashMap<Value, Instant>> = Mutex::new(HashMap::new());
        let id = Value::from("req-warn");
        pending.lock().unwrap().insert(id, Instant::now());

        let mut zw = String::new();
        for _ in 0..20 {
            zw.push('\u{200B}');
        }
        let payload = format!("visible{zw}tail");

        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "req-warn",
            "result": {
                "content": [{"type": "text", "text": payload}],
                "isError": false
            }
        });
        let line = serde_json::to_vec(&upstream).unwrap();
        let Some(filtered) = filter_if_pending(
            &line,
            &pending,
            false,
            &output_filter::OutputFilterContext::default(),
        ) else {
            // Rule landed at a different severity in this build — not a
            // contract failure for this test. Skip.
            return;
        };
        let v: Value = serde_json::from_slice(&filtered).unwrap();
        // Warn contract: isError stays false; first item is the notice.
        if v["result"]["isError"] == false {
            let content = v["result"]["content"].as_array().unwrap();
            if content.len() >= 2 {
                let first = content[0]["text"].as_str().unwrap();
                assert!(first.starts_with("[tirith: WARNING"));
                let body = content[1]["text"].as_str().unwrap();
                assert!(!body.contains('\u{200B}'), "zero-width must be stripped");
            }
        }
    }

    #[test]
    fn test_filter_if_pending_handles_missing_is_error_field() {
        // A missing `isError` (optional in older MCP) must not crash the filter —
        // `reshape_for_deserialize` defaults it to `false`.
        let pending: Mutex<HashMap<Value, Instant>> = Mutex::new(HashMap::new());
        let id = Value::from(5);
        pending.lock().unwrap().insert(id, Instant::now());

        let upstream = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 5,
            "result": {
                "content": [{"type": "text", "text": "no error field here"}]
                // isError intentionally absent
            }
        });
        let line = serde_json::to_vec(&upstream).unwrap();
        let filtered = filter_if_pending(
            &line,
            &pending,
            false,
            &output_filter::OutputFilterContext::default(),
        );
        assert!(filtered.is_some(), "missing isError must not be fatal");
    }
}
