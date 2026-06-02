//! `tirith devcontainer guard|inject` (M8 ch5).
//!
//! 1. `guard on|off|status` — flips `policy.context_guard_enabled` (the shared
//!    M8 switch); when OFF the M8 ch5 container rules silence with ch1..ch4.
//! 2. `inject [--path <dir>]` — locates the devcontainer.json under `<dir>` and
//!    appends a tirith `postCreateCommand` + `TIRITH_DEVCONTAINER=1`. Idempotent.

use std::io::Write;
use std::path::{Path, PathBuf};

use tirith_core::devcontainer_writer::{
    self, default_devcontainer_json, find_devcontainer_json, inject_tirith_hook, InjectOutcome,
};
use tirith_core::policy::{self as policy_mod, Policy};

// ─── guard ─────────────────────────────────────────────────────────────────

/// `tirith devcontainer guard on|off|status` — flip the shared
/// operational-context switch.
pub fn guard(action: &str, json: bool) -> i32 {
    let enable = match action {
        "on" | "enable" | "true" => true,
        "off" | "disable" | "false" => false,
        "status" => return guard_status(json),
        other => {
            eprintln!(
                "tirith devcontainer guard: unknown action '{other}' (expected on|off|status)"
            );
            return 2;
        }
    };

    let target_path = match resolve_policy_path() {
        Ok(p) => p,
        Err(code) => return code,
    };

    if let Err(e) = update_policy_key(&target_path, "context_guard_enabled", &enable.to_string()) {
        eprintln!(
            "tirith devcontainer guard: failed to update {}: {e}",
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
            "tirith devcontainer guard: {} (written to {})",
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
            "tirith devcontainer guard: {}",
            if policy.context_guard_enabled {
                "ON"
            } else {
                "OFF"
            }
        );
    }
    0
}

// ─── inject ───────────────────────────────────────────────────────────────

/// `tirith devcontainer inject [--path <dir>] [--create]` — locate the
/// devcontainer.json under `<dir>` (or cwd) and add the tirith hook
/// (idempotent). `create` controls whether a missing file is created; without
/// it a missing file is an error.
pub fn inject(path: Option<&Path>, create: bool, json: bool) -> i32 {
    let cwd = match path {
        Some(p) => p.to_path_buf(),
        None => match std::env::current_dir() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("tirith devcontainer inject: cannot resolve cwd: {e}");
                return 1;
            }
        },
    };

    let target = find_devcontainer_json(&cwd).unwrap_or_else(|| default_devcontainer_json(&cwd));
    let outcome = inject_tirith_hook(&target, create);
    report_outcome("devcontainer inject", &outcome, json)
}

pub(crate) fn report_outcome(label: &str, outcome: &InjectOutcome, json: bool) -> i32 {
    match outcome {
        InjectOutcome::Created(p) => {
            emit_outcome(label, "created", p, json);
            0
        }
        InjectOutcome::Updated(p) => {
            emit_outcome(label, "updated", p, json);
            0
        }
        InjectOutcome::AlreadyInjected(p) => {
            emit_outcome(label, "already_injected", p, json);
            0
        }
        InjectOutcome::NotFound(p) => {
            if json {
                let out = serde_json::json!({
                    "schema_version": 1,
                    "status": "not_found",
                    "path": p.display().to_string(),
                });
                let mut stdout = std::io::stdout().lock();
                let _ = serde_json::to_writer_pretty(&mut stdout, &out);
                let _ = writeln!(stdout);
            } else {
                eprintln!(
                    "tirith {label}: no devcontainer.json under {}. \
                     Pass --create to scaffold one with the tirith hook wired in.",
                    p.display()
                );
            }
            1
        }
        InjectOutcome::ParseError(p, msg) => {
            if json {
                let out = serde_json::json!({
                    "schema_version": 1,
                    "status": "error",
                    "path": p.display().to_string(),
                    "error": msg,
                });
                let mut stdout = std::io::stdout().lock();
                let _ = serde_json::to_writer_pretty(&mut stdout, &out);
                let _ = writeln!(stdout);
            } else {
                eprintln!("tirith {label}: could not update {}: {msg}", p.display());
            }
            1
        }
    }
}

fn emit_outcome(label: &str, status: &str, path: &Path, json: bool) {
    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "status": status,
            "path": path.display().to_string(),
            "marker": devcontainer_writer::TIRITH_HOOK_MARKER,
        });
        let mut stdout = std::io::stdout().lock();
        let _ = serde_json::to_writer_pretty(&mut stdout, &out);
        let _ = writeln!(stdout);
    } else {
        eprintln!(
            "tirith {label}: {status} {} (postCreateCommand contains '{}')",
            path.display(),
            devcontainer_writer::TIRITH_HOOK_MARKER
        );
    }
}

// ─── shared helpers ────────────────────────────────────────────────────────

fn resolve_policy_path() -> Result<PathBuf, i32> {
    if let Some(existing) = policy_mod::discover_local_policy_path(None) {
        return Ok(existing);
    }
    let user = policy_mod::config_dir().ok_or_else(|| {
        eprintln!("tirith devcontainer: could not resolve user config dir");
        1
    })?;
    Ok(user.join("policy.yaml"))
}

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
        update_policy_key(&path, "context_guard_enabled", "true").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("context_guard_enabled: true"));
    }
}
