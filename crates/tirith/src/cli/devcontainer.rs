//! `tirith devcontainer guard|inject` (M8 ch5).
//!
//! 1. `guard on|off|status` — flips `policy.context_guard_enabled` (the shared
//!    M8 switch); when OFF the M8 ch5 container rules silence with ch1..ch4.
//! 2. `inject [--path <dir>]` — locates the devcontainer.json under `<dir>` and
//!    appends a tirith `postCreateCommand` + `TIRITH_DEVCONTAINER=1`. Idempotent.

use std::io::Write;
use std::path::{Path, PathBuf};

use tirith_core::devcontainer_writer::{
    self, default_devcontainer_json, find_devcontainer_json, InjectOutcome,
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
    // Containment is proven against the canonical workspace root (repo-0376).
    let cwd = std::fs::canonicalize(&cwd).unwrap_or(cwd);

    let target = find_devcontainer_json(&cwd).unwrap_or_else(|| default_devcontainer_json(&cwd));
    let policy = Policy::discover_local_only(cwd.to_str());
    let outcome = inject_tirith_hook_permitted(&target, &cwd, create, &policy);
    report_outcome("devcontainer inject", &outcome, json)
}

pub(crate) fn inject_tirith_hook_permitted(
    path: &Path,
    root: &Path,
    create_if_missing: bool,
    policy: &Policy,
) -> InjectOutcome {
    const CONFIG_READ_CAP: u64 = 1024 * 1024;
    let prepared = match super::prepare_config_destination_permitted(
        root,
        path,
        true,
        policy,
        false,
        create_if_missing,
    ) {
        Ok(prepared) => prepared,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create_if_missing => {
            return InjectOutcome::NotFound(path.to_path_buf());
        }
        Err(error) => {
            return InjectOutcome::ParseError(
                path.to_path_buf(),
                format!("refusing unsafe devcontainer destination: {error}"),
            );
        }
    };
    let (contents, created) = match prepared.read_capped(CONFIG_READ_CAP) {
        Ok(bytes) => {
            let content = match String::from_utf8(bytes) {
                Ok(content) => content,
                Err(_) => {
                    return InjectOutcome::ParseError(
                        path.to_path_buf(),
                        "devcontainer.json is not UTF-8".to_string(),
                    );
                }
            };
            let rendered = match devcontainer_writer::render_tirith_hook_jsonc(&content) {
                Ok(Some(rendered)) => rendered,
                Ok(None) => return InjectOutcome::AlreadyInjected(path.to_path_buf()),
                Err(error) => {
                    return InjectOutcome::ParseError(path.to_path_buf(), error);
                }
            };
            (rendered, false)
        }
        Err(tirith_core::util::OpenRegularError::NotFound) if !create_if_missing => {
            return InjectOutcome::NotFound(path.to_path_buf());
        }
        Err(tirith_core::util::OpenRegularError::NotFound) => {
            let seed = serde_json::json!({
                "name": "tirith-protected devcontainer",
                "postCreateCommand": {
                    "tirith-init": ["tirith", "init", "--shell", "auto"],
                },
                "containerEnv": { "TIRITH_DEVCONTAINER": "1" },
            });
            let mut contents = match serde_json::to_string_pretty(&seed) {
                Ok(contents) => contents,
                Err(error) => {
                    return InjectOutcome::ParseError(
                        path.to_path_buf(),
                        format!("serialize devcontainer.json: {error}"),
                    );
                }
            };
            contents.push('\n');
            (contents, true)
        }
        Err(error) => {
            return InjectOutcome::ParseError(
                path.to_path_buf(),
                format!("refusing unsafe devcontainer source: {error:?}"),
            );
        }
    };

    if let Err(error) = super::write_prepared_config_file_permitted(
        root,
        path,
        prepared,
        contents.as_bytes(),
        true,
        policy,
        false,
    ) {
        return InjectOutcome::ParseError(path.to_path_buf(), format!("atomic write: {error}"));
    }
    if created {
        InjectOutcome::Created(path.to_path_buf())
    } else {
        InjectOutcome::Updated(path.to_path_buf())
    }
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

pub(super) fn update_policy_key(path: &Path, key: &str, value: &str) -> std::io::Result<()> {
    // Confine the read-modify-write beneath the policy file's own directory
    // (the repository `.tirith` directory or the user config dir): the
    // contained writer refuses a symlinked final component AND any symlinked
    // intermediate directory, and publishes atomically through a
    // same-directory temporary file (repo-0376). A repository-planted symlink
    // at `.tirith/policy.yaml` is refused instead of truncated, and an
    // unreadable file is no longer silently treated as empty (which would
    // have clobbered its real contents).
    let root = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "policy path has no parent directory",
            )
        })?;
    let policy = Policy::discover_local_only(root.to_str());
    let prepared =
        super::prepare_config_destination_permitted(root, path, true, &policy, true, true)?;
    let existing = match prepared.read_capped(1024 * 1024) {
        Ok(bytes) => String::from_utf8(bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "policy file is not UTF-8; refusing to rewrite it",
            )
        })?,
        Err(tirith_core::util::OpenRegularError::NotFound) => String::new(),
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("refusing to read unsafe policy file: {e:?}"),
            ))
        }
    };
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

    super::write_prepared_config_file_permitted(
        root,
        path,
        prepared,
        out.as_bytes(),
        true,
        &policy,
        true,
    )
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

    #[test]
    fn inject_requires_an_exact_independent_lifecycle_entry() {
        for (label, command, preserved_key, preserved_value) in [
            (
                "decoy substring",
                serde_json::json!("echo 'tirith init --shell auto'"),
                "existing",
                serde_json::json!("echo 'tirith init --shell auto'"),
            ),
            (
                "argv lifecycle",
                serde_json::json!(["npm", "ci"]),
                "existing",
                serde_json::json!(["npm", "ci"]),
            ),
            (
                "object lifecycle",
                serde_json::json!({"setup": ["npm", "ci"]}),
                "setup",
                serde_json::json!(["npm", "ci"]),
            ),
        ] {
            let repo = tempdir().unwrap();
            let devcontainer_dir = repo.path().join(".devcontainer");
            std::fs::create_dir_all(&devcontainer_dir).unwrap();
            let config_path = devcontainer_dir.join("devcontainer.json");
            let initial = serde_json::json!({
                "postCreateCommand": command,
                "containerEnv": {"TIRITH_DEVCONTAINER": "1"}
            });
            std::fs::write(&config_path, serde_json::to_vec_pretty(&initial).unwrap()).unwrap();

            assert_eq!(
                inject(Some(repo.path()), false, false),
                0,
                "{label} must be updated through the CLI outcome path"
            );
            let updated_bytes = std::fs::read(&config_path).unwrap();
            let updated: serde_json::Value = serde_json::from_slice(&updated_bytes).unwrap();
            assert_eq!(
                updated["postCreateCommand"][devcontainer_writer::TIRITH_HOOK_KEY],
                serde_json::json!(["tirith", "init", "--shell", "auto"]),
                "{label} must gain Tirith's exact reserved argv entry"
            );
            assert_eq!(
                updated["postCreateCommand"][preserved_key], preserved_value,
                "{label} must be preserved as an independent lifecycle command"
            );
            assert_eq!(updated["containerEnv"]["TIRITH_DEVCONTAINER"], "1");

            assert_eq!(inject(Some(repo.path()), false, false), 0);
            assert_eq!(
                std::fs::read(&config_path).unwrap(),
                updated_bytes,
                "only the structurally exact hook may trigger idempotent success"
            );
        }
    }
}
