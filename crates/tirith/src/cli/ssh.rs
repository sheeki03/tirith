//! `tirith ssh guard|label` (M8 ch2).
//!
//! * **`guard on|off|status`** — flips `policy.context_guard_enabled` (the same
//!   M8 ch1 switch, so there's no second policy field to discover; the off
//!   state silences SSH host-label findings too).
//! * **`label <host> <criticality> [--scope user|repo]`** — writes one entry to
//!   the SSH host-labels file. `~/.ssh/config` aliases are resolved at label
//!   time via `ssh -G <host>` so the file stores the FINAL host string (the
//!   rule then matches `ssh shortname` without re-resolving; 5s TTL cache).
//!
//! `bootstrap` is DEFERRED to M8.1: the stub exits 2 with a pointer, so the
//! documented command gives a real error rather than "command not found".

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tirith_core::policy::{self as policy_mod, Policy};

/// Allowed criticality values, shared with `cli::context::ALLOWED_CRITICALITIES`.
const ALLOWED_CRITICALITIES: &[&str] = &[
    "critical",
    "production",
    "prod",
    "live",
    "p0",
    "p1",
    "p2",
    "staging",
    "dev",
    "test",
];

/// Scope for `tirith ssh label` writes (mirrors `cli::context::LabelScope`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelScope {
    User,
    Repo,
}

impl LabelScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Repo => "repo",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "user" => Some(Self::User),
            "repo" | "project" | "workspace" => Some(Self::Repo),
            _ => None,
        }
    }
}

// ─── guard ─────────────────────────────────────────────────────────────────

/// `tirith ssh guard on|off|status` — flip the M8 ch1 `context_guard_enabled`
/// field (`ssh guard` vs `context guard` is one switch under the hood).
pub fn guard(action: &str, json: bool) -> i32 {
    let enable = match action {
        "on" | "enable" | "true" => true,
        "off" | "disable" | "false" => false,
        "status" => return guard_status(json),
        other => {
            eprintln!("tirith ssh guard: unknown action '{other}' (expected on|off|status)");
            return 2;
        }
    };

    let target_path = match resolve_policy_path_for_guard() {
        Ok(p) => p,
        Err(code) => return code,
    };

    if let Err(e) = update_policy_guard_key(&target_path, enable) {
        eprintln!(
            "tirith ssh guard: failed to update {}: {e}",
            target_path.display()
        );
        return 1;
    }

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "guard_enabled": enable,
            "policy_path": target_path.display().to_string(),
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else {
        eprintln!(
            "tirith ssh guard: {} (written to {})",
            if enable { "ON" } else { "OFF" },
            target_path.display(),
        );
    }
    0
}

fn guard_status(json: bool) -> i32 {
    let policy = Policy::discover_partial(None);
    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "guard_enabled": policy.context_guard_enabled,
            "policy_path": policy.path,
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else {
        eprintln!(
            "tirith ssh guard: {}",
            if policy.context_guard_enabled {
                "ON"
            } else {
                "OFF"
            }
        );
    }
    0
}

fn resolve_policy_path_for_guard() -> Result<PathBuf, i32> {
    if let Some(existing) = policy_mod::discover_local_policy_path(None) {
        return Ok(existing);
    }
    let user = policy_mod::config_dir().ok_or_else(|| {
        eprintln!("tirith ssh guard: could not resolve user config dir");
        1
    })?;
    Ok(user.join("policy.yaml"))
}

/// Idempotently set the `context_guard_enabled` line (append-or-rewrite, never
/// touching other lines).
fn update_policy_guard_key(path: &std::path::Path, enable: bool) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let new_line = format!("context_guard_enabled: {enable}");

    let mut out = String::new();
    let mut replaced = false;
    for line in existing.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("context_guard_enabled:") {
            out.push_str(&new_line);
            out.push('\n');
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&new_line);
        out.push('\n');
    }

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    use std::io::Write as _;
    f.write_all(out.as_bytes())
}

// ─── label ─────────────────────────────────────────────────────────────────

/// `tirith ssh label <host> <criticality> [--scope user|repo]`. Resolves
/// `~/.ssh/config` aliases via `ssh -G <host>` and stores BOTH the raw input
/// AND the resolved hostname when they differ (the runtime rule sees only the
/// literal the user typed, so the raw key must round-trip).
pub fn label(host: &str, criticality: &str, scope: LabelScope, json: bool) -> i32 {
    if host.trim().is_empty() {
        eprintln!("tirith ssh label: host is empty");
        return 2;
    }

    let criticality_norm = criticality.trim().to_lowercase();
    if !ALLOWED_CRITICALITIES.iter().any(|c| *c == criticality_norm) {
        eprintln!(
            "tirith ssh label: '{criticality}' is not a known criticality (expected one of: {}; case-insensitive)",
            ALLOWED_CRITICALITIES.join(", "),
        );
        return 2;
    }

    let resolved_host = resolve_ssh_alias(host).unwrap_or_else(|| {
        // Resolution failed: warn that an alias may not match its DNS name, but
        // still proceed — labeling the raw string is more conservative than nothing.
        eprintln!(
            "tirith ssh label: warning: `ssh -G {host}` failed (binary missing, timeout, or no hostname line); labeling raw input only — if {host} is an alias, runs against the resolved name will not match"
        );
        host.to_string()
    });

    let target_path = match scope {
        LabelScope::User => match policy_mod::user_ssh_host_labels_path() {
            Some(p) => p,
            None => {
                eprintln!("tirith ssh label: could not resolve user config dir");
                return 1;
            }
        },
        LabelScope::Repo => match policy_mod::repo_ssh_host_labels_path(None) {
            Some(p) => p,
            None => {
                eprintln!("tirith ssh label: --scope repo requires running inside a git repo");
                return 1;
            }
        },
    };

    // Write the RAW host input first (the runtime rule looks up the literal
    // typed string); add the resolved form below when it differs, so labeling an
    // alias also matches the DNS name. Same flat-YAML format as context labels.
    if let Err(e) = policy_mod::write_context_label(&target_path, host, criticality) {
        eprintln!(
            "tirith ssh label: failed to write {}: {e}",
            target_path.display()
        );
        return 1;
    }
    if resolved_host != host {
        if let Err(e) = policy_mod::write_context_label(&target_path, &resolved_host, criticality) {
            eprintln!(
                "tirith ssh label: failed to write resolved-host entry to {}: {e}",
                target_path.display()
            );
            return 1;
        }
    }

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "scope": scope.as_str(),
            "path": target_path.display().to_string(),
            "host_input": host,
            "host_resolved": resolved_host,
            "criticality": criticality,
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else if resolved_host == host {
        eprintln!(
            "tirith ssh label: {host} -> {criticality} (scope={}, file={})",
            scope.as_str(),
            target_path.display(),
        );
    } else {
        eprintln!(
            "tirith ssh label: {host} (resolved: {resolved_host}) -> {criticality} (scope={}, file={})",
            scope.as_str(),
            target_path.display(),
        );
    }
    0
}

// ─── bootstrap (M8.1 stub) ─────────────────────────────────────────────────

/// `tirith ssh bootstrap user@host` — DEFERRED to M8.1 (cross-host binary
/// deploy has too many failure modes for this PR); exits 2 with a pointer.
pub fn bootstrap_stub(_target: &str, json: bool) -> i32 {
    let msg = "tirith ssh bootstrap: DEFERRED to M8.1 follow-up PR. \
               Run `tirith ssh label <host> <criticality>` for now; \
               cross-host binary deploy lands once `ssh guard|label` has \
               field validation.";
    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "error": "deferred",
            "milestone": "M8.1",
            "message": msg,
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else {
        eprintln!("{msg}");
    }
    2
}

// ─── ssh -G alias resolution (with 5s cache) ───────────────────────────────

/// Cached `ssh -G` outputs (5s TTL, matching `context_detect::CACHE_TTL_SECS`)
/// to avoid re-shelling on every label write in a scripted run.
static SSH_G_CACHE: Mutex<Option<SshGCache>> = Mutex::new(None);

struct SshGCache {
    captured_at: Instant,
    entries: std::collections::HashMap<String, String>,
}

const SSH_G_TTL: Duration = Duration::from_secs(5);
const SSH_G_TIMEOUT: Duration = Duration::from_millis(1500);

/// Resolve a `~/.ssh/config` alias via `ssh -G <host>`'s `hostname` line.
/// `None` when `ssh` is missing, the call exceeds [`SSH_G_TIMEOUT`], or there's
/// no `hostname` line (the caller then keeps the raw host string).
fn resolve_ssh_alias(input: &str) -> Option<String> {
    // Strip any `user@` prefix for the cache key, re-attaching at return time.
    let (user_prefix, host_only) = match input.split_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, input),
    };

    if let Some(cached) = check_cache(host_only) {
        return Some(reattach_user(user_prefix, &cached));
    }

    let resolved = run_ssh_g(host_only)?;
    insert_cache(host_only, &resolved);
    Some(reattach_user(user_prefix, &resolved))
}

fn reattach_user(user_prefix: Option<&str>, host: &str) -> String {
    // Defensive: don't double-prefix if `host` already carries a `user@`.
    if host.contains('@') {
        return host.to_string();
    }
    match user_prefix {
        Some(u) => format!("{u}@{host}"),
        None => host.to_string(),
    }
}

fn check_cache(host: &str) -> Option<String> {
    let mut guard = SSH_G_CACHE.lock().unwrap_or_else(|p| p.into_inner());
    let cache = guard.as_mut()?;
    if cache.captured_at.elapsed() > SSH_G_TTL {
        *guard = None;
        return None;
    }
    cache.entries.get(host).cloned()
}

fn insert_cache(host: &str, resolved: &str) {
    let mut guard = SSH_G_CACHE.lock().unwrap_or_else(|p| p.into_inner());
    let cache = guard.get_or_insert_with(|| SshGCache {
        captured_at: Instant::now(),
        entries: std::collections::HashMap::new(),
    });
    if cache.captured_at.elapsed() > SSH_G_TTL {
        *cache = SshGCache {
            captured_at: Instant::now(),
            entries: std::collections::HashMap::new(),
        };
    }
    cache.entries.insert(host.to_string(), resolved.to_string());
}

fn run_ssh_g(host: &str) -> Option<String> {
    let mut cmd = Command::new("ssh");
    cmd.arg("-G")
        .arg(host)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    let mut child = cmd.spawn().ok()?;

    // Stream stdout on a helper thread so the pipe can't fill.
    let stdout_handle = child.stdout.take().map(|mut s| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            use std::io::Read as _;
            let _ = s.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + SSH_G_TIMEOUT;
    let poll = Duration::from_millis(25);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return None;
                }
                let buf = stdout_handle
                    .and_then(|h| h.join().ok())
                    .unwrap_or_default();
                let out = String::from_utf8_lossy(&buf);
                return out
                    .lines()
                    .find_map(|l| l.strip_prefix("hostname "))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(h) = stdout_handle {
                        let _ = h.join();
                    }
                    return None;
                }
                std::thread::sleep(poll);
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                if let Some(h) = stdout_handle {
                    let _ = h.join();
                }
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn label_scope_parse() {
        assert_eq!(LabelScope::parse("user"), Some(LabelScope::User));
        assert_eq!(LabelScope::parse("USER"), Some(LabelScope::User));
        assert_eq!(LabelScope::parse("repo"), Some(LabelScope::Repo));
        assert_eq!(LabelScope::parse("workspace"), Some(LabelScope::Repo));
        assert_eq!(LabelScope::parse("invalid"), None);
    }

    #[test]
    fn update_policy_guard_key_creates_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        update_policy_guard_key(&path, true).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("context_guard_enabled: true"));
    }

    #[test]
    fn update_policy_guard_key_replaces_existing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            "paranoia: 2\ncontext_guard_enabled: true\nfail_mode: open\n",
        )
        .unwrap();
        update_policy_guard_key(&path, false).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("context_guard_enabled: false"));
        assert!(content.contains("paranoia: 2"));
        assert!(content.contains("fail_mode: open"));
        assert!(!content.contains("context_guard_enabled: true"));
    }

    #[test]
    fn reattach_user_with_prefix() {
        assert_eq!(
            reattach_user(Some("root"), "host.example.com"),
            "root@host.example.com"
        );
        assert_eq!(reattach_user(None, "host.example.com"), "host.example.com");
        // Already prefixed — don't double-prefix.
        assert_eq!(
            reattach_user(Some("root"), "alice@host.example.com"),
            "alice@host.example.com"
        );
    }
}
