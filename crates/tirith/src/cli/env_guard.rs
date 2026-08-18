//! `tirith env guard|diff|explain` (M9 ch4). Thin presenter over
//! [`tirith_core::env_guard`] — output, snapshot persistence, and the
//! `policy.env_guard_enabled` toggle; the list/snapshot/diff/scan logic lives
//! in the library. **Variable VALUES are never read into argv or printed**
//! anywhere here.
//!
//! - `guard on|off|status`: flip / report `policy.env_guard_enabled` (when ON,
//!   the two exec-path env-guard rules fire from `engine::analyze`).
//! - `diff [--reset]`: compare sensitive vars set now vs the shell-start
//!   snapshot at `state_dir()/env_snapshot.json` (names/deltas only); persisted
//!   presence-only baselines explicitly report unavailable value comparison;
//!   `--reset` re-baselines.
//! - `explain <VAR>`: locate where `<VAR>` is exported (file + line), value
//!   MASKED to `****`.
//! - `_snapshot` (hidden): the shell hook execs this child once per session; it
//!   reads its OWN environment and stores variable NAMES categorically, never
//!   value-derived hashes or raw values.

use std::path::PathBuf;

use tirith_core::env_guard::{self, EnvSnapshot};
use tirith_core::policy::{self as policy_mod, Policy};

use super::write_json_stdout;

/// Env-guard output carries caller/policy-controlled names and local paths.
/// Apply the public-paste projection plus the conservative durable projection
/// before any JSON or human presenter extracts those fields.
fn project_env_cli_text(value: &str) -> String {
    let share_safe = tirith_core::redact::redact_for_audience(
        value,
        tirith_core::redact::ShareAudience::PublicPaste,
    )
    .redacted_content;
    tirith_core::redact::redact_blocked_output(&share_safe)
}

fn project_env_cli_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(text) => *text = project_env_cli_text(text),
        serde_json::Value::Array(values) => {
            for value in values {
                project_env_cli_json(value);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                project_env_cli_json(value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn write_env_json<T: serde::Serialize>(value: &T, context: &str) -> bool {
    let Ok(mut value) = serde_json::to_value(value) else {
        eprintln!("{context}");
        return false;
    };
    project_env_cli_json(&mut value);
    write_json_stdout(&value, context)
}

/// `tirith env guard on|off|status` — flip / report `policy.env_guard_enabled`.
pub fn guard(action: &str, json: bool) -> i32 {
    let enable = match action {
        "on" | "enable" | "true" => true,
        "off" | "disable" | "false" => false,
        "status" => return guard_status(json),
        other => {
            let other = super::sanitize_for_human_output(&project_env_cli_text(other), false);
            eprintln!("tirith env guard: unknown action '{other}' (expected on|off|status)");
            return 2;
        }
    };

    let target_path = match resolve_policy_path_for_guard() {
        Ok(p) => p,
        Err(code) => return code,
    };

    if let Err(e) = update_policy_guard_key(&target_path, enable) {
        let path = super::sanitize_for_human_output(
            &project_env_cli_text(&target_path.display().to_string()),
            false,
        );
        let error = super::sanitize_for_human_output(&project_env_cli_text(&e.to_string()), true);
        eprintln!("tirith env guard: failed to update {path}: {error}");
        return 1;
    }

    if json {
        let out = serde_json::json!({
            "schema_version": 1,
            "env_guard_enabled": enable,
            "policy_path": target_path.display().to_string(),
        });
        if !write_env_json(&out, "tirith env guard: failed to write JSON output") {
            return 1;
        }
    } else {
        let path = super::sanitize_for_human_output(
            &project_env_cli_text(&target_path.display().to_string()),
            false,
        );
        eprintln!(
            "tirith env guard: {} (written to {})",
            if enable { "ON" } else { "OFF" },
            path,
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
        if !write_env_json(&out, "tirith env guard: failed to write JSON output") {
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
                    let detail = project_env_cli_text(detail);
                    eprintln!("    {}", super::sanitize_for_human_output(&detail, false));
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
/// symlinks, then held under the parent mutation lock for the bounded read,
/// exact typed authorization, preimage recheck, and atomic 0600 publication.
///
/// The grandparent is the right containment root because the policy path is
/// always at least three components deep (`<root>/.tirith/policy.yaml`); a
/// malformed path with no grandparent is rejected rather than written.
pub(super) fn update_policy_guard_key(path: &std::path::Path, enable: bool) -> std::io::Result<()> {
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
                "policy file is not valid UTF-8; refusing to rewrite it",
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

/// `tirith env diff [--reset]` — show sensitive vars newly set, changed, or not
/// safely comparable since shell start. Exit 1 for any reported entry (including
/// an unresolved comparison) so scripting fails conservatively. `--reset`
/// re-baselines and exits 0.
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
    let snapshot_present = snap_path.exists();
    let snapshot = match load_snapshot_for_diff(&snap_path, &sensitive) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let path = super::sanitize_for_human_output(
                &project_env_cli_text(&snap_path.display().to_string()),
                false,
            );
            let error =
                super::sanitize_for_human_output(&project_env_cli_text(&error.to_string()), true);
            eprintln!("tirith env diff: failed to load or migrate snapshot {path}: {error}");
            return 1;
        }
    };
    let current = env_guard::current_sensitive_in_process(&sensitive);
    let entries = env_guard::diff_sensitive(&snapshot, &current, &sensitive);

    if json {
        let body = diff_json_body(&snap_path, snapshot_present, &entries);
        if !write_env_json(&body, "tirith env diff: failed to write JSON output") {
            return 1;
        }
    } else {
        print_human_diff(&snap_path, snapshot_present, &entries);
    }

    if entries.is_empty() {
        0
    } else {
        1
    }
}

fn diff_json_body(
    snap_path: &std::path::Path,
    snapshot_present: bool,
    entries: &[env_guard::EnvDiffEntry],
) -> serde_json::Value {
    let unavailable_count = entries
        .iter()
        .filter(|entry| entry.delta == env_guard::EnvDelta::ValueComparisonUnavailable)
        .count();
    serde_json::json!({
        "schema_version": 1,
        "snapshot_path": snap_path.display().to_string(),
        "snapshot_present": snapshot_present,
        "changed_count": entries.len(),
        "value_comparison_complete": unavailable_count == 0,
        "value_comparison_unavailable_count": unavailable_count,
        "changes": entries,
    })
}

fn load_snapshot_for_diff(
    path: &std::path::Path,
    sensitive: &[String],
) -> std::io::Result<EnvSnapshot> {
    env_guard::load_snapshot_and_migrate(path, sensitive)
}

fn print_human_diff(
    snap_path: &std::path::Path,
    snapshot_present: bool,
    entries: &[env_guard::EnvDiffEntry],
) {
    let snap_path = super::sanitize_for_human_output(
        &project_env_cli_text(&snap_path.display().to_string()),
        false,
    );
    if !snapshot_present {
        eprintln!("tirith env diff: no shell-start snapshot found at {snap_path}.");
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
        "tirith env diff: {} sensitive variable(s) reported since shell start (values never shown):\n",
        entries.len()
    );
    for e in entries {
        let label = match e.delta {
            env_guard::EnvDelta::NewlySet => "newly set",
            env_guard::EnvDelta::ValueChanged => "value changed",
            env_guard::EnvDelta::ValueComparisonUnavailable => "value comparison unavailable",
        };
        let name = super::sanitize_for_human_output(&project_env_cli_text(&e.name), false);
        eprintln!("  {name:<28} [{label}]");
    }
    if entries
        .iter()
        .any(|entry| entry.delta == env_guard::EnvDelta::ValueComparisonUnavailable)
    {
        eprintln!(
            "\n  A persisted baseline contains variable-name presence only. Tirith cannot safely \
             claim that a still-present secret is unchanged without retaining a durable \
             secret-derived identifier."
        );
    }
    eprintln!("\nRun `tirith env explain <VAR>` to see where a variable is set (value masked).");
}

/// `tirith env diff --reset` — re-baseline from the current environment.
/// Every persisted entry is presence-only; no value or comparison marker is
/// written to the snapshot.
fn reset_snapshot(json: bool) -> i32 {
    let snap_path = match env_guard::snapshot_path() {
        Some(p) => p,
        None => {
            eprintln!("tirith env diff --reset: could not resolve state dir");
            return 1;
        }
    };
    let policy = Policy::discover_partial(None);
    let sensitive = env_guard::effective_sensitive_vars(&policy.env_guard_sensitive_vars);
    let snapshot = EnvSnapshot::from_current_process_with_sensitive(&sensitive);
    if let Err(e) = env_guard::save_snapshot_with_sensitive(&snap_path, &snapshot, &sensitive) {
        let path = super::sanitize_for_human_output(
            &project_env_cli_text(&snap_path.display().to_string()),
            false,
        );
        let error = super::sanitize_for_human_output(&project_env_cli_text(&e.to_string()), true);
        eprintln!("tirith env diff --reset: failed to write snapshot {path}: {error}");
        return 1;
    }
    if json {
        let body = serde_json::json!({
            "schema_version": 1,
            "snapshot_path": snap_path.display().to_string(),
            "recorded_vars": snapshot.vars.len(),
            "reset": true,
        });
        if !write_env_json(
            &body,
            "tirith env diff --reset: failed to write JSON output",
        ) {
            return 1;
        }
    } else {
        let path = super::sanitize_for_human_output(
            &project_env_cli_text(&snap_path.display().to_string()),
            false,
        );
        eprintln!(
            "tirith env diff: snapshot re-baselined ({} variable names recorded; all values \
             presence-only) at {}.",
            snapshot.vars.len(),
            path
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
        if !write_env_json(&ex, "tirith env explain: failed to write JSON output") {
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
    let name = super::sanitize_for_human_output(&project_env_cli_text(&ex.name), false);
    eprintln!("tirith env explain `{name}`:");
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
        let file = super::sanitize_for_human_output(&project_env_cli_text(&src.file), false);
        let masked_line =
            super::sanitize_for_human_output(&project_env_cli_text(&src.masked_line), false);
        eprintln!("    {file}:{}  {masked_line}", src.line);
    }
    eprintln!("\nThe value is never read or printed — only the location and a masked placeholder.");
}

/// `tirith env _snapshot` — write the shell-start snapshot from THIS process's
/// inherited environment (variable names only; no value-derived hash/value
/// crosses argv or persistence). Invoked by the hook once per session; always
/// exits 0 so a write failure never disrupts the shell.
pub fn snapshot_write() -> i32 {
    if let Some(path) = env_guard::snapshot_path() {
        let policy = Policy::discover_partial(None);
        let sensitive = env_guard::effective_sensitive_vars(&policy.env_guard_sensitive_vars);
        let snapshot = EnvSnapshot::from_current_process_with_sensitive(&sensitive);
        let _ = env_guard::save_snapshot_with_sensitive(&path, &snapshot, &sensitive);
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_cli_projection_covers_names_paths_and_nested_json() {
        let secret = format!("ghp_{}", "N".repeat(36));
        let mut value = serde_json::json!({
            "snapshot_path": format!("/Users/alice/private/{secret}/env.json"),
            "changes": [{ "name": secret.clone() }],
            "sources": [{ "file": format!("/Users/alice/{secret}/.zshrc") }],
        });
        project_env_cli_json(&mut value);
        let rendered = value.to_string();
        assert!(!rendered.contains(&secret), "{rendered}");
        assert!(!rendered.contains("/Users/alice"), "{rendered}");
        assert!(rendered.contains("REDACTED"), "{rendered}");
        assert_eq!(
            project_env_cli_text("AWS_SECRET_ACCESS_KEY"),
            "AWS_SECRET_ACCESS_KEY"
        );
    }

    #[test]
    fn env_diff_json_explicitly_surfaces_presence_only_comparison_gap() {
        let entries = vec![env_guard::EnvDiffEntry {
            name: "WALLET_PRIVATE_KEY".to_string(),
            delta: env_guard::EnvDelta::ValueComparisonUnavailable,
        }];
        let body = diff_json_body(
            std::path::Path::new("/tmp/env_snapshot.json"),
            true,
            &entries,
        );
        assert_eq!(body["changed_count"], 1);
        assert_eq!(body["value_comparison_complete"], false);
        assert_eq!(body["value_comparison_unavailable_count"], 1);
        assert_eq!(body["changes"][0]["delta"], "value_comparison_unavailable");
    }

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

    #[test]
    fn normal_diff_loader_atomically_persists_presence_only_migration_for_all_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env_snapshot.json");
        std::fs::write(
            &path,
            r#"{
                "schema_version": 1,
                "taken_at": 9,
                "vars": {
                    "AWS_SECRET_CUSTOM": {"name":"AWS_SECRET_CUSTOM","value_hash8":"deadbeef"},
                    "MY_POLICY_SECRET": {"name":"MY_POLICY_SECRET","value_hash8":"cafebabe"},
                    "LANG": {"name":"LANG","value_hash8":"12345678"}
                }
            }"#,
        )
        .unwrap();

        let snapshot = load_snapshot_for_diff(&path, &["MY_POLICY_SECRET".to_string()]).unwrap();
        assert_eq!(snapshot.schema_version, 3);
        assert_eq!(snapshot.vars["AWS_SECRET_CUSTOM"].value_hash8, "");
        assert_eq!(snapshot.vars["MY_POLICY_SECRET"].value_hash8, "");
        assert_eq!(snapshot.vars["LANG"].value_hash8, "");
        let persisted = std::fs::read_to_string(&path).unwrap();
        assert!(!persisted.contains("deadbeef"), "{persisted}");
        assert!(!persisted.contains("cafebabe"), "{persisted}");
        assert!(!persisted.contains("12345678"), "{persisted}");
        assert!(persisted.contains("\"schema_version\": 3"), "{persisted}");
    }

    #[test]
    fn normal_diff_loader_fails_safely_without_overwriting_invalid_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("env_snapshot.json");
        let invalid = "{not valid snapshot json";
        std::fs::write(&path, invalid).unwrap();
        assert!(load_snapshot_for_diff(&path, &[]).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), invalid);
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
