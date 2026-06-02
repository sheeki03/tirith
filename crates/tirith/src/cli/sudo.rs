//! `tirith sudo guard|session|require-reason` (M8 ch4). Three operator surfaces:
//! `guard` flips the shared `policy.context_guard_enabled`; `session
//! start|end|status` manages `state_dir()/sudo-session.json` (an active session
//! downgrades the five sudo rules High→Medium when `sudo_require_reason` is on);
//! `require-reason` flips `policy.sudo_require_reason` (off by default).

use std::io::Write;
use std::path::{Path, PathBuf};

use tirith_core::policy::{self as policy_mod, Policy};
use tirith_core::sudo_session::{self, SudoSession};

/// `tirith sudo guard on|off|status` — flip the shared operational-context switch.
pub fn guard(action: &str, json: bool) -> i32 {
    let enable = match action {
        "on" | "enable" | "true" => true,
        "off" | "disable" | "false" => false,
        "status" => return guard_status(json),
        other => {
            eprintln!("tirith sudo guard: unknown action '{other}' (expected on|off|status)");
            return 2;
        }
    };

    let target_path = match resolve_policy_path() {
        Ok(p) => p,
        Err(code) => return code,
    };

    if let Err(e) = update_policy_key(&target_path, "context_guard_enabled", &enable.to_string()) {
        eprintln!(
            "tirith sudo guard: failed to update {}: {e}",
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
            "tirith sudo guard: {} (written to {})",
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
            "tirith sudo guard: {}",
            if policy.context_guard_enabled {
                "ON"
            } else {
                "OFF"
            }
        );
    }
    0
}

/// `tirith sudo require-reason on|off|status`.
pub fn require_reason(action: &str, json: bool) -> i32 {
    let enable = match action {
        "on" | "enable" | "true" => true,
        "off" | "disable" | "false" => false,
        "status" => return require_reason_status(json),
        other => {
            eprintln!(
                "tirith sudo require-reason: unknown action '{other}' (expected on|off|status)"
            );
            return 2;
        }
    };

    let target_path = match resolve_policy_path() {
        Ok(p) => p,
        Err(code) => return code,
    };

    if let Err(e) = update_policy_key(&target_path, "sudo_require_reason", &enable.to_string()) {
        eprintln!(
            "tirith sudo require-reason: failed to update {}: {e}",
            target_path.display()
        );
        return 1;
    }

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "sudo_require_reason": enable,
            "policy_path": target_path.display().to_string(),
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else {
        eprintln!(
            "tirith sudo require-reason: {} (written to {})",
            if enable { "ON" } else { "OFF" },
            target_path.display(),
        );
    }
    0
}

fn require_reason_status(json: bool) -> i32 {
    let policy = Policy::discover_partial(None);
    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "sudo_require_reason": policy.sudo_require_reason,
            "policy_path": policy.path,
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else {
        eprintln!(
            "tirith sudo require-reason: {}",
            if policy.sudo_require_reason {
                "ON"
            } else {
                "OFF"
            }
        );
    }
    0
}

/// `tirith sudo session start [--ttl 30m] [--reason "…"]`.
pub fn session_start(ttl_str: Option<&str>, reason: Option<&str>, json: bool) -> i32 {
    let policy = Policy::discover_partial(None);
    let ttl_secs = match ttl_str {
        Some(s) => match sudo_session::parse_ttl(s) {
            Some(v) => v,
            None => {
                eprintln!(
                    "tirith sudo session start: invalid --ttl '{s}' (expected formats: 90s, 5m, 2h, 1d)"
                );
                return 2;
            }
        },
        None => policy
            .sudo_session_ttl
            .unwrap_or(sudo_session::DEFAULT_SESSION_TTL_SECS),
    };
    if policy.sudo_require_reason && reason.unwrap_or("").trim().is_empty() {
        eprintln!(
            "tirith sudo session start: --reason is required when policy.sudo_require_reason is on"
        );
        return 2;
    }
    let session = SudoSession::now(ttl_secs, reason.unwrap_or(""));
    let path = match sudo_session::write_session(&session) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("tirith sudo session start: failed to write session file: {e}");
            return 1;
        }
    };

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "started_at": session.started_at,
            "ttl_secs": session.ttl_secs,
            "ttl": sudo_session::format_ttl(session.ttl_secs),
            "reason": session.reason,
            "session_path": path.display().to_string(),
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else {
        eprintln!(
            "tirith sudo session start: ttl={} reason={:?} ({})",
            sudo_session::format_ttl(session.ttl_secs),
            session.reason,
            path.display(),
        );
    }
    0
}

/// `tirith sudo session end`.
pub fn session_end(json: bool) -> i32 {
    if let Err(e) = sudo_session::remove_session() {
        eprintln!("tirith sudo session end: {e}");
        return 1;
    }
    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "active": false,
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else {
        eprintln!("tirith sudo session end: cleared");
    }
    0
}

/// `tirith sudo session status`.
pub fn session_status(json: bool) -> i32 {
    let session = sudo_session::read_active_session();
    if json {
        let payload = match session {
            Some(ref s) => serde_json::json!({
                "schema_version": 1,
                "active": true,
                "started_at": s.started_at,
                "ttl_secs": s.ttl_secs,
                "remaining_secs": s.remaining_secs(),
                "reason": s.reason,
                "session_path": sudo_session::sudo_session_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "<unresolved>".to_string()),
            }),
            None => serde_json::json!({
                "schema_version": 1,
                "active": false,
            }),
        };
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &payload).is_err() || writeln!(stdout).is_err()
        {
            return 1;
        }
    } else {
        match session {
            Some(s) => eprintln!(
                "tirith sudo session: ACTIVE  remaining={}  reason={:?}",
                sudo_session::format_ttl(s.remaining_secs()),
                s.reason,
            ),
            None => eprintln!("tirith sudo session: inactive"),
        }
    }
    0
}

fn resolve_policy_path() -> Result<PathBuf, i32> {
    if let Some(existing) = policy_mod::discover_local_policy_path(None) {
        return Ok(existing);
    }
    let user = policy_mod::config_dir().ok_or_else(|| {
        eprintln!("tirith sudo: could not resolve user config dir");
        1
    })?;
    Ok(user.join("policy.yaml"))
}

/// Idempotent append-or-rewrite of a single policy key. Mirrors the
/// helper used by `cli::ssh` / `cli::context` / `cli::iac`.
fn update_policy_key(path: &Path, key: &str, value: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let new_line = format!("{key}: {value}");

    let prefix = format!("{key}:");

    let mut out = String::new();
    let mut replaced = false;
    for line in existing.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(&prefix) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn update_policy_key_creates_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        update_policy_key(&path, "sudo_require_reason", "true").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("sudo_require_reason: true"));
    }

    #[test]
    fn update_policy_key_replaces_existing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            "paranoia: 2\nsudo_require_reason: true\nfail_mode: open\n",
        )
        .unwrap();
        update_policy_key(&path, "sudo_require_reason", "false").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("sudo_require_reason: false"));
        assert!(content.contains("paranoia: 2"));
        assert!(!content.contains("sudo_require_reason: true"));
    }

    #[test]
    fn update_policy_key_distinct_keys_dont_collide() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            "context_guard_enabled: false\nsudo_require_reason: false\n",
        )
        .unwrap();
        update_policy_key(&path, "sudo_require_reason", "true").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("context_guard_enabled: false"));
        assert!(content.contains("sudo_require_reason: true"));
    }
}
