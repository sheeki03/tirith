//! `tirith env guard|diff|explain` (M9 ch4). Thin presenter over
//! [`tirith_core::env_guard`] — output, snapshot persistence, and the
//! `policy.env_guard_enabled` toggle; the list/snapshot/diff/scan logic lives
//! in the library. **Variable VALUES are never read into argv or printed**
//! anywhere here.
//!
//! - `guard on|off|status`: flip / report `policy.env_guard_enabled` (when ON,
//!   the two exec-path env-guard rules fire from `engine::analyze`).
//! - `diff [--reset]`: compare sensitive vars set now vs the shell-start
//!   snapshot at `state_dir()/env_snapshot.json` (names/deltas only); `--reset`
//!   re-baselines.
//! - `explain <VAR>`: locate where `<VAR>` is exported (file + line), value
//!   MASKED to `****`.
//! - `_snapshot` (hidden): the shell hook execs this child once per session; it
//!   reads its OWN environment and stores NAMES + 8-char value-hash prefixes.

use std::path::PathBuf;

use tirith_core::env_guard::{self, EnvSnapshot};
use tirith_core::policy::{self as policy_mod, Policy};

use super::write_json_stdout;

/// `tirith env guard on|off|status` — flip / report `policy.env_guard_enabled`.
pub fn guard(action: &str, json: bool) -> i32 {
    let enable = match action {
        "on" | "enable" | "true" => true,
        "off" | "disable" | "false" => false,
        "status" => return guard_status(json),
        other => {
            eprintln!("tirith env guard: unknown action '{other}' (expected on|off|status)");
            return 2;
        }
    };

    let target_path = match resolve_policy_path_for_guard() {
        Ok(p) => p,
        Err(code) => return code,
    };

    if let Err(e) = update_policy_guard_key(&target_path, enable) {
        eprintln!(
            "tirith env guard: failed to update {}: {e}",
            target_path.display()
        );
        return 1;
    }

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "env_guard_enabled": enable,
            "policy_path": target_path.display().to_string(),
        });
        if !write_json_stdout(&out, "tirith env guard: failed to write JSON output") {
            return 1;
        }
    } else {
        eprintln!(
            "tirith env guard: {} (written to {})",
            if enable { "ON" } else { "OFF" },
            target_path.display(),
        );
    }
    0
}

fn guard_status(json: bool) -> i32 {
    let policy = Policy::discover_partial(None);
    let sensitive = env_guard::effective_sensitive_vars(&policy.env_guard_sensitive_vars);
    // Producer for RuleId::EnvSensitivePersistedInShellRc (values masked).
    let rc_findings =
        env_guard::scan_rc_for_sensitive_exports(&sensitive, home::home_dir().as_deref());

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "env_guard_enabled": policy.env_guard_enabled,
            "policy_path": policy.path,
            "persisted_secret_count": rc_findings.len(),
            "persisted_secrets": rc_findings,
        });
        if !write_json_stdout(&out, "tirith env guard: failed to write JSON output") {
            return 1;
        }
    } else {
        eprintln!(
            "tirith env guard: {}",
            if policy.env_guard_enabled {
                "ON"
            } else {
                "OFF"
            }
        );
        if rc_findings.is_empty() {
            eprintln!("  no sensitive env vars exported in your rc/profile files.");
        } else {
            eprintln!(
                "  {} sensitive env var(s) exported in rc/profile files (HIGH — value masked):",
                rc_findings.len()
            );
            for f in &rc_findings {
                if let Some(tirith_core::verdict::Evidence::Text { detail }) = f.evidence.first() {
                    // detail embeds the rc-file-derived var name (attacker-influenced).
                    eprintln!("    {}", super::sanitize_for_human_output(detail, false));
                }
            }
            eprintln!(
                "  Load these on demand (secrets manager / keychain) instead of exporting them."
            );
        }
    }
    // Exit 1 on a persisted secret so a script / CI can gate on it.
    if rc_findings.is_empty() {
        0
    } else {
        1
    }
}

fn resolve_policy_path_for_guard() -> Result<PathBuf, i32> {
    if let Some(existing) = policy_mod::discover_local_policy_path(None) {
        return Ok(existing);
    }
    let user = policy_mod::config_dir().ok_or_else(|| {
        eprintln!("tirith env guard: could not resolve user config dir");
        1
    })?;
    Ok(user.join("policy.yaml"))
}

/// Largest policy file we will read-modify-write for a guard toggle. A policy
/// YAML is hand-authored and tiny; 1 MiB bounds a hostile or symlinked-to-huge
/// target so the read cannot be turned into an unbounded slurp.
const MAX_POLICY_SIZE: u64 = 1024 * 1024;

/// Idempotently append-or-rewrite the `env_guard_enabled` line in a policy YAML,
/// never touching other lines (mirrors `cli::context::update_policy_guard_key`).
///
/// Symlink-hardened (repo-0383, mirrors the F16 pattern in
/// `cli::exec::update_policy_guard_key`): the policy path is a repo-discovered
/// `<repo>/.tirith/policy.yaml` (or `<config>/tirith/policy.yaml`), so an
/// attacker who can plant a symlink there could otherwise redirect this
/// truncating write onto an arbitrary file. A retained directory capability is
/// traversed from the trusted grandparent without following repo-controlled
/// symlinks, then used for both the bounded read and atomic 0600 publication.
///
/// The grandparent is the right containment root because the policy path is
/// always at least three components deep (`<root>/.tirith/policy.yaml`); a
/// malformed path with no grandparent is rejected rather than written.
fn update_policy_guard_key(path: &std::path::Path, enable: bool) -> std::io::Result<()> {
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

    let contained = tirith_core::util::ContainedAtomicFile::prepare(containment_root, path, true)?;

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
    let new_line = format!("env_guard_enabled: {enable}");

    let mut out = String::new();
    let mut replaced = false;
    for line in existing.lines() {
        if line.trim_start().starts_with("env_guard_enabled:") {
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

    // Atomic publish (temp + fsync + rename) through the retained parent
    // capability: a crash or full disk leaves the previous policy intact.
    contained.write_atomic(out.as_bytes(), true)
}

/// Map an `OpenRegularError` from the no-follow policy read onto an `io::Error`
/// so the guard read-modify-write surfaces a single failure type to the caller.
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

/// `tirith env diff [--reset]` — show sensitive vars set/changed since shell
/// start. Exit 1 if any newly appeared (worth a non-zero exit for scripting),
/// else 0. `--reset` re-baselines and exits 0.
pub fn diff(reset: bool, json: bool) -> i32 {
    let policy = Policy::discover_partial(None);
    let sensitive = env_guard::effective_sensitive_vars(&policy.env_guard_sensitive_vars);

    if reset {
        return reset_snapshot(json);
    }

    let snap_path = match env_guard::snapshot_path() {
        Some(p) => p,
        None => {
            eprintln!("tirith env diff: could not resolve state dir for the snapshot");
            return 1;
        }
    };
    let snapshot = env_guard::load_snapshot(&snap_path);
    let snapshot_present = snap_path.exists();
    let current = env_guard::current_sensitive_in_process(&sensitive);
    let entries = env_guard::diff_sensitive(&snapshot, &current, &sensitive);

    if json {
        let body = serde_json::json!({
            "schema_version": 1,
            "snapshot_path": snap_path.display().to_string(),
            "snapshot_present": snapshot_present,
            "changed_count": entries.len(),
            "changes": entries,
        });
        if !write_json_stdout(&body, "tirith env diff: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_diff(&snap_path, snapshot_present, &entries);
    }

    let any_newly_set = entries
        .iter()
        .any(|e| e.delta == env_guard::EnvDelta::NewlySet);
    if any_newly_set {
        1
    } else {
        0
    }
}

fn print_human_diff(
    snap_path: &std::path::Path,
    snapshot_present: bool,
    entries: &[env_guard::EnvDiffEntry],
) {
    if !snapshot_present {
        eprintln!(
            "tirith env diff: no shell-start snapshot found at {}.",
            snap_path.display()
        );
        eprintln!(
            "  The shell hook records one at shell start; run `tirith env diff --reset` to \
             baseline now, or open a new shell with the hook installed."
        );
        // Still report what's currently set (vs the empty baseline) so the
        // command is useful without a snapshot.
    }
    if entries.is_empty() {
        eprintln!("tirith env diff: no sensitive environment variables set since shell start.");
        return;
    }
    eprintln!(
        "tirith env diff: {} sensitive variable(s) changed since shell start (values never shown):\n",
        entries.len()
    );
    for e in entries {
        let label = match e.delta {
            env_guard::EnvDelta::NewlySet => "newly set",
            env_guard::EnvDelta::ValueChanged => "value changed",
        };
        eprintln!("  {:<28} [{label}]", e.name);
    }
    eprintln!("\nRun `tirith env explain <VAR>` to see where a variable is set (value masked).");
}

/// `tirith env diff --reset` — re-baseline from the current environment
/// (NAMES + 8-char value-hash prefixes only).
fn reset_snapshot(json: bool) -> i32 {
    let snap_path = match env_guard::snapshot_path() {
        Some(p) => p,
        None => {
            eprintln!("tirith env diff --reset: could not resolve state dir");
            return 1;
        }
    };
    let snapshot = EnvSnapshot::from_current_process();
    if let Err(e) = env_guard::save_snapshot(&snap_path, &snapshot) {
        eprintln!(
            "tirith env diff --reset: failed to write snapshot {}: {e}",
            snap_path.display()
        );
        return 1;
    }
    if json {
        let body = serde_json::json!({
            "schema_version": 1,
            "snapshot_path": snap_path.display().to_string(),
            "recorded_vars": snapshot.vars.len(),
            "reset": true,
        });
        if !write_json_stdout(
            &body,
            "tirith env diff --reset: failed to write JSON output",
        ) {
            return 1;
        }
    } else {
        eprintln!(
            "tirith env diff: snapshot re-baselined ({} variables recorded, names + 8-char \
             hashes only) at {}.",
            snapshot.vars.len(),
            snap_path.display()
        );
    }
    0
}

/// `tirith env explain <VAR>` — show where a variable is set (value masked).
/// Exit 0, except 2 when the var is neither set in the process nor in any rc
/// file, so a script can tell "not configured anywhere" from "found".
pub fn explain(var: &str, json: bool) -> i32 {
    let ex = env_guard::explain_var(var);

    if json {
        if !write_json_stdout(&ex, "tirith env explain: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_explain(&ex);
    }

    if !ex.set_in_process && ex.sources.is_empty() {
        2
    } else {
        0
    }
}

fn print_human_explain(ex: &env_guard::EnvExplain) {
    eprintln!("tirith env explain `{}`:", ex.name);
    eprintln!(
        "  currently set in this process: {}",
        if ex.set_in_process { "yes" } else { "no" }
    );
    if ex.sources.is_empty() {
        eprintln!("  not found in any rc/profile file scanned.");
        if ex.set_in_process {
            eprintln!(
                "  (it is set in the process — likely exported inline, inherited from a parent, \
                 or set by a tool not in your rc files.)"
            );
        }
        return;
    }
    eprintln!("  exported in:");
    for src in &ex.sources {
        // masked_line already has the value replaced with ****.
        eprintln!("    {}:{}  {}", src.file, src.line, src.masked_line);
    }
    eprintln!("\nThe value is never read or printed — only the location and a masked placeholder.");
}

/// `tirith env _snapshot` — write the shell-start snapshot from THIS process's
/// inherited environment (NAMES + 8-char value-hash prefixes only; no value
/// crosses argv). Invoked by the hook once per session; always exits 0 so a
/// write failure never disrupts the shell.
pub fn snapshot_write() -> i32 {
    if let Some(path) = env_guard::snapshot_path() {
        let snapshot = EnvSnapshot::from_current_process();
        let _ = env_guard::save_snapshot(&path, &snapshot);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_policy_guard_key_appends_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.yaml");
        std::fs::write(&path, "paranoia: 2\nfail_mode: open\n").unwrap();

        update_policy_guard_key(&path, true).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("env_guard_enabled: true"), "{content}");
        assert!(content.contains("paranoia: 2"), "other lines preserved");

        // Flip off — must REPLACE the existing line, not duplicate it.
        update_policy_guard_key(&path, false).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("env_guard_enabled: false"), "{content}");
        assert!(!content.contains("env_guard_enabled: true"), "{content}");
        assert_eq!(
            content.matches("env_guard_enabled:").count(),
            1,
            "must not duplicate the key"
        );
    }

    #[test]
    fn guard_unknown_action_returns_2() {
        assert_eq!(guard("bogus", false), 2);
    }

    /// repo-0383: a symlinked containing directory (planted `.tirith`) that
    /// escapes the repo must abort the update BEFORE any read/write, and the
    /// external target must stay untouched.
    #[cfg(unix)]
    #[test]
    fn update_policy_guard_key_refuses_symlinked_containing_dir() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        std::os::unix::fs::symlink(outside.path(), repo.join(".tirith")).unwrap();

        let path = repo.join(".tirith").join("policy.yaml");
        let err = update_policy_guard_key(&path, true).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        assert!(
            !outside.path().join("policy.yaml").exists(),
            "no policy file may be created outside the repo"
        );
    }

    /// repo-0383: a symlinked FINAL component must be refused on both the read
    /// and the write; the link target's bytes must be preserved.
    #[cfg(unix)]
    #[test]
    fn update_policy_guard_key_refuses_symlinked_final_component() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim.yaml");
        std::fs::write(&victim, "SENTINEL: do not truncate\n").unwrap();
        let dir = root.path().join("repo").join(".tirith");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.yaml");
        std::os::unix::fs::symlink(&victim, &path).unwrap();

        assert!(update_policy_guard_key(&path, true).is_err());
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "SENTINEL: do not truncate\n",
            "symlink target must not be read-modify-written"
        );
    }

    /// repo-0383: a non-regular target (a directory named `policy.yaml`)
    /// surfaces a read error other than NotFound, so the update must abort
    /// rather than truncate-through an empty baseline.
    #[cfg(unix)]
    #[test]
    fn update_policy_guard_key_aborts_on_non_regular_policy() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("repo").join(".tirith");
        let path = dir.join("policy.yaml");
        std::fs::create_dir_all(&path).unwrap();

        assert!(update_policy_guard_key(&path, true).is_err());
        assert!(path.is_dir(), "the directory must remain, not be replaced");
    }
}
