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

    // repo-0498: a repo-scoped policy is sanitized on load — the weakening key
    // never takes effect there, so refuse instead of reporting a false OFF.
    if !enable {
        if let Some((path, scope)) = policy_mod::discover_local_policy_path_scoped(None) {
            if path == target_path && scope == policy_mod::PolicyScope::Repo {
                eprintln!(
                    "tirith sudo guard: cannot disable via a repository policy ({}) — repo policies are sanitized on load and the guard would stay ON. Use your user config: ~/.config/tirith/policy.yaml",
                    path.display()
                );
                return 1;
            }
        }
    }

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

/// Largest policy file we will read-modify-write for a policy-key toggle. A
/// policy YAML is hand-authored and tiny; 1 MiB bounds a hostile or
/// symlinked-to-huge target so the read cannot be turned into an unbounded
/// slurp.
const MAX_POLICY_SIZE: u64 = 1024 * 1024;

/// Idempotent append-or-rewrite of a single policy key. Mirrors the
/// helper used by `cli::ssh` / `cli::context` / `cli::iac`.
///
/// Symlink-hardened (repo-0437, mirrors the F16 pattern in
/// `cli::exec::update_policy_guard_key`): the policy path is a repo-discovered
/// `<repo>/.tirith/policy.yaml` (or `<config>/tirith/policy.yaml`), so an
/// attacker who can plant a symlink there could otherwise redirect this
/// truncating write onto an arbitrary file. A retained directory capability is
/// traversed from the trusted grandparent without following repo-controlled
/// symlinks, then used for both the bounded read and atomic 0600 publication.
/// Any read error other than genuine absence aborts rather than becoming an
/// empty baseline.
pub(super) fn update_policy_key(path: &Path, key: &str, value: &str) -> std::io::Result<()> {
    // The containment root is the grandparent: <repo>/.tirith/policy.yaml →
    // <repo>, <config>/tirith/policy.yaml → <config>. A policy path is always
    // at least three components deep; refuse a malformed shallower path rather
    // than guess.
    let containment_root = path.parent().and_then(|p| p.parent()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "policy path must be <root>/<dir>/policy.yaml",
        )
    })?;

    let policy = Policy::discover_local_only(containment_root.to_str());
    let contained = super::prepare_config_destination_permitted(
        containment_root,
        path,
        true,
        &policy,
        true,
        true,
    )?;

    // Read the current contents WITHOUT following a symlinked final component.
    // An absent file is an empty baseline (the key is then appended); any other
    // read failure (symlinked, oversized, I/O) aborts rather than clobbering
    // blind.
    let existing = match contained.read_capped(MAX_POLICY_SIZE) {
        Ok(bytes) => String::from_utf8(bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "policy file is not UTF-8; refusing to rewrite it",
            )
        })?,
        Err(tirith_core::util::OpenRegularError::NotFound) => String::new(),
        Err(e) => return Err(open_regular_io_error(e)),
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
        containment_root,
        path,
        contained,
        out.as_bytes(),
        true,
        &policy,
        true,
    )
}

/// Map an `OpenRegularError` from the no-follow policy read onto an `io::Error`
/// so the policy-key read-modify-write surfaces a single failure type to the
/// caller.
fn open_regular_io_error(e: tirith_core::util::OpenRegularError) -> std::io::Error {
    match e {
        tirith_core::util::OpenRegularError::Io(io) => io,
        tirith_core::util::OpenRegularError::NotRegularFile => std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "policy path is not a regular file (symlink or special file)",
        ),
        tirith_core::util::OpenRegularError::TooLarge => std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "policy file exceeds the size cap",
        ),
        tirith_core::util::OpenRegularError::NotFound => {
            std::io::Error::new(std::io::ErrorKind::NotFound, "policy file not found")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn update_policy_key_creates_file() {
        let _global = crate::cli::test_harness::ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
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

    /// repo-0437: a symlinked containing directory (planted `.tirith`) that
    /// escapes the repo must abort the update BEFORE any read/write, and the
    /// external target must stay untouched.
    #[cfg(unix)]
    #[test]
    fn update_policy_key_refuses_symlinked_containing_dir() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::os::unix::fs::symlink(outside.path(), repo.join(".tirith")).unwrap();

        let path = repo.join(".tirith").join("policy.yaml");
        let err = update_policy_key(&path, "sudo_require_reason", "true").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert!(
            !outside.path().join("policy.yaml").exists(),
            "no policy file may be created outside the repo"
        );
    }

    /// repo-0437: a symlinked FINAL component must be refused; the link
    /// target's bytes must be preserved (the old code truncated it blind via
    /// `unwrap_or_default` + a following write).
    #[cfg(unix)]
    #[test]
    fn update_policy_key_refuses_symlinked_final_component() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let victim = outside.path().join("victim.yaml");
        std::fs::write(&victim, "SENTINEL: do not truncate\n").unwrap();
        let dir = root.path().join("repo").join(".tirith");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.yaml");
        std::os::unix::fs::symlink(&victim, &path).unwrap();

        assert!(update_policy_key(&path, "sudo_require_reason", "true").is_err());
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "SENTINEL: do not truncate\n",
            "symlink target must not be read-modify-written"
        );
    }

    /// repo-0437: a non-regular target is rejected by fstat of the OPEN handle
    /// (identity, not a re-checkable path); the update aborts rather than
    /// truncating through an empty baseline.
    #[cfg(unix)]
    #[test]
    fn update_policy_key_aborts_on_non_regular_policy() {
        let root = tempdir().unwrap();
        let dir = root.path().join("repo").join(".tirith");
        let path = dir.join("policy.yaml");
        std::fs::create_dir_all(&path).unwrap();

        assert!(update_policy_key(&path, "sudo_require_reason", "true").is_err());
        assert!(path.is_dir(), "the directory must remain, not be replaced");
    }
}
