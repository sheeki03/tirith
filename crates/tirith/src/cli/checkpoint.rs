use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use tirith_core::checkpoint::{self, PostRunState};
use tirith_core::verdict::{action_from_findings, Action, Finding};

pub fn list_checkpoints(json: bool) -> i32 {
    match checkpoint::list() {
        Ok(entries) => {
            if json {
                let json_val = serde_json::json!({
                    "checkpoints": entries,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_val).unwrap_or_else(|e| {
                        eprintln!("tirith: checkpoint: JSON serialization failed: {e}");
                        "{}".to_string()
                    })
                );
            } else {
                if entries.is_empty() {
                    println!("No checkpoints found.");
                } else {
                    println!(
                        "{id:<38} {created:<26} {files:<8} {size:<12} Trigger",
                        id = "ID",
                        created = "Created",
                        files = "Files",
                        size = "Size"
                    );
                    println!("{}", "-".repeat(100));
                    for e in &entries {
                        let size = format_bytes(e.total_bytes);
                        let trigger = e
                            .trigger_command
                            .as_deref()
                            .unwrap_or("-")
                            .chars()
                            .take(30)
                            .collect::<String>();
                        println!(
                            "{:<38} {:<26} {:<8} {:<12} {}",
                            e.id, e.created_at, e.file_count, size, trigger
                        );
                    }
                    println!("\n{} checkpoint(s)", entries.len());
                }
            }
            0
        }
        Err(e) => {
            eprintln!("tirith checkpoint list: {e}");
            2
        }
    }
}

pub fn restore_checkpoint(id: &str, json: bool) -> i32 {
    match checkpoint::restore_reported(id) {
        Ok(report) => {
            let restored_n = report.restored.len();
            if json {
                let json_val = serde_json::json!({
                    "checkpoint_id": report.checkpoint_id,
                    "attempted": report.attempted,
                    "restored": report.restored,
                    "missing": report.missing,
                    "corrupt": report.corrupt,
                    "errors": report.errors,
                    "count": restored_n,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_val).unwrap_or_else(|e| {
                        eprintln!("tirith: checkpoint: JSON serialization failed: {e}");
                        "{}".to_string()
                    })
                );
            } else {
                println!("Restored {restored_n} file(s):");
                for path in &report.restored {
                    println!("  {path}");
                }
                if !report.missing.is_empty() {
                    println!("Missing backup data ({}):", report.missing.len());
                    for path in &report.missing {
                        println!("  {path}");
                    }
                }
                if !report.corrupt.is_empty() {
                    println!("Corrupt backup data, skipped ({}):", report.corrupt.len());
                    for path in &report.corrupt {
                        println!("  {path}");
                    }
                }
                if !report.errors.is_empty() {
                    println!("Errors ({}):", report.errors.len());
                    for (path, err) in &report.errors {
                        println!("  {path}: {err}");
                    }
                }
                println!(
                    "Restored {restored_n} files. Database, cloud, and API side effects are not covered by checkpoint restore."
                );
            }
            // A partial/failed restore (any blob missing, corrupt, or a copy
            // error) must NOT report success: scripts gate on the exit code, and
            // returning 0 here would make a half-restored state look complete. The
            // full per-bucket report is still printed above; we only flip the exit
            // status. 1 == restore completed with failures (distinct from 2, an
            // operational error that aborted the restore entirely).
            if !report.missing.is_empty() || !report.corrupt.is_empty() || !report.errors.is_empty()
            {
                1
            } else {
                0
            }
        }
        Err(e) => {
            eprintln!("tirith checkpoint restore: {e}");
            2
        }
    }
}

pub fn diff_checkpoint(id: &str, json: bool) -> i32 {
    match checkpoint::diff(id) {
        Ok(diffs) => {
            if json {
                let json_val = serde_json::json!({
                    "diffs": diffs,
                    "count": diffs.len(),
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_val).unwrap_or_else(|e| {
                        eprintln!("tirith: checkpoint: JSON serialization failed: {e}");
                        "{}".to_string()
                    })
                );
            } else if diffs.is_empty() {
                println!("No differences found — all files match checkpoint.");
            } else {
                for d in &diffs {
                    let s = tirith_core::style::Stream::Stdout;
                    let status = match d.status {
                        checkpoint::DiffStatus::Deleted => tirith_core::style::red("deleted", s),
                        checkpoint::DiffStatus::Modified => {
                            tirith_core::style::yellow("modified", s)
                        }
                        checkpoint::DiffStatus::BackupCorrupt => {
                            tirith_core::style::red("corrupt", s)
                        }
                    };
                    println!("  {status:>18}  {}", d.path);
                }
                println!("\n{} difference(s)", diffs.len());
            }
            0
        }
        Err(e) => {
            eprintln!("tirith checkpoint diff: {e}");
            2
        }
    }
}

pub fn purge_checkpoints(json: bool) -> i32 {
    let config = checkpoint::CheckpointConfig::default();
    match checkpoint::purge(&config) {
        Ok(result) => {
            if json {
                let json_val = serde_json::json!(result);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_val).unwrap_or_else(|e| {
                        eprintln!("tirith: checkpoint: JSON serialization failed: {e}");
                        "{}".to_string()
                    })
                );
            } else if result.removed_count == 0 {
                println!("No checkpoints needed purging.");
            } else {
                println!(
                    "Purged {} checkpoint(s), freed {}",
                    result.removed_count,
                    format_bytes(result.freed_bytes)
                );
            }
            0
        }
        Err(e) => {
            eprintln!("tirith checkpoint purge: {e}");
            2
        }
    }
}

pub fn create_checkpoint(paths: &[String], trigger: Option<&str>, json: bool) -> i32 {
    let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
    match checkpoint::create(&path_refs, trigger) {
        Ok(meta) => {
            if json {
                let json_val = serde_json::json!(meta);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_val).unwrap_or_else(|e| {
                        eprintln!("tirith: checkpoint: JSON serialization failed: {e}");
                        "{}".to_string()
                    })
                );
            } else {
                println!("Checkpoint created: {}", meta.id);
                println!(
                    "  {} file(s), {}",
                    meta.file_count,
                    format_bytes(meta.total_bytes)
                );
            }
            0
        }
        Err(e) => {
            eprintln!("tirith checkpoint create: {e}");
            2
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// `tirith watch -- <cmd>` — snapshot → run → snapshot → diff (M10 ch2).
///
/// Snapshots files (cwd + `--paths`) and runtime state (env names, `$PATH`,
/// shell-rc hashes), runs the command, re-snapshots, and reports new/modified
/// files, `$PATH` additions, and shell-rc changes (a changed rc fires High
/// `PostRunShellRcModified`). Observability AFTER the fact — it does NOT sandbox
/// or gate; the command runs with full privileges. Exit code is the CHILD's
/// (usage/spawn errors are 2); findings never override it — `watch` is a lens.
///
/// `with_net_hints` opts into an EXPERIMENTAL resolver-cache mtime heuristic; it
/// misses QUIC/UDP/direct-IP and is not a network monitor or security boundary.
pub fn watch(command: &[String], paths: &[String], with_net_hints: bool, json: bool) -> i32 {
    let command_str = command.join(" ");
    if command_str.trim().is_empty() {
        eprintln!(
            "tirith watch: no command given \
             (usage: tirith watch -- npm install <pkg>)"
        );
        return 2;
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let home = match home_dir() {
        Some(h) => h,
        None => {
            eprintln!("tirith watch: cannot resolve home directory; shell-rc diff unavailable");
            cwd.clone()
        }
    };

    // Snapshot roots: cwd + user paths. Capped to these — never all of $HOME
    // (perf + privacy).
    let mut snapshot_paths: Vec<String> = vec![cwd.to_string_lossy().into_owned()];
    snapshot_paths.extend(paths.iter().cloned());

    // --- BEFORE: file inventory + runtime state ---
    let files_before = inventory_files(&snapshot_paths);
    let rt_before = checkpoint::capture_runtime_state(&home);
    let net_before = if with_net_hints {
        Some(net_hint_sources(&home))
    } else {
        None
    };

    // F1: keep tirith alive across Ctrl-C so the AFTER snapshot + diff always run
    // (child is in its own process group, see `run_command`).
    install_watch_sigint_handler();

    // --- RUN the command with the user's full privileges (no isolation) ---
    let run_status = run_command(&command_str);
    let exit_code = match run_status {
        Ok(code) => code,
        Err(e) => {
            eprintln!("tirith watch: failed to run command: {e}");
            return 2;
        }
    };
    let interrupted = WATCH_INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed);

    // --- AFTER: re-inventory + re-capture (ALWAYS, even after an interrupt) ---
    let files_after = inventory_files(&snapshot_paths);
    let rt_after = checkpoint::capture_runtime_state(&home);

    let (mut post_run_state, modified_rc) = checkpoint::diff_runtime_state(&rt_before, &rt_after);

    if let Some(before_sources) = net_before {
        post_run_state.domains_contacted = net_hints_changed(&before_sources, &home);
    }

    // New / modified files from the before/after inventory.
    let new_files: Vec<String> = files_after
        .keys()
        .filter(|p| !files_before.contains_key(*p))
        .cloned()
        .collect();
    let mut new_files = new_files;
    new_files.sort();

    let mut modified_files: Vec<String> = files_after
        .iter()
        .filter_map(|(p, mtime_after)| {
            files_before
                .get(p)
                .filter(|mtime_before| *mtime_before != mtime_after)
                .map(|_| p.clone())
        })
        .collect();
    modified_files.sort();

    let findings = checkpoint::findings_for_modified_rc(&modified_rc);
    let action = action_from_findings(&findings);

    if json {
        emit_watch_json(
            &command_str,
            exit_code,
            &new_files,
            &modified_files,
            &modified_rc,
            &post_run_state,
            with_net_hints,
            &findings,
            action,
            interrupted,
        );
    } else {
        print_watch_human(
            &command_str,
            exit_code,
            &new_files,
            &modified_files,
            &modified_rc,
            &post_run_state,
            with_net_hints,
            &findings,
            interrupted,
        );
    }

    // `watch` reports, never gates: surface the child's exit code for scripts.
    exit_code
}

/// Resolve home without mutating env (`$HOME` / `%USERPROFILE%`); mirrors
/// `tirith_core::policy`.
fn home_dir() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    #[cfg(not(unix))]
    {
        std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
    }
}

/// Run the watched command through the platform shell (pipelines/redirects
/// behave as typed). Returns the child's exit code (128 if signal-killed). NOT
/// isolation — runs with full privileges.
///
/// F1: on Unix the child gets its OWN process group (`setpgid(0,0)` via
/// `pre_exec`) so a terminal SIGINT hits only the child, not tirith — otherwise
/// Ctrl-C would kill tirith before the AFTER snapshot + diff (and a half-finished
/// installer's `.zshrc` persistence line would go unreported). The child still
/// observes the interrupt; this only keeps tirith alive long enough to report.
fn run_command(command_str: &str) -> std::io::Result<i32> {
    use std::process::Command;
    let mut cmd = if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command_str);
        c
    } else {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let mut c = Command::new(shell);
        c.arg("-c").arg(command_str);
        c
    };
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: `setpgid` is async-signal-safe and the only call in the forked
        // child before exec; it puts the child in its own process group.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let status = cmd.status()?;
    Ok(status.code().unwrap_or(128))
}

// ─── SIGINT handling (F1) ────────────────────────────────────────────────────

/// Set by the watch SIGINT handler so the run path can note that the command was
/// interrupted and still report an honest (possibly incomplete) diff.
static WATCH_INTERRUPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Install a SIGINT handler that flips [`WATCH_INTERRUPTED`] instead of letting
/// the default action kill tirith. The child takes the terminal's SIGINT (own
/// process group, see [`run_command`]); this only keeps the parent alive to run
/// the after-snapshot + diff. The handler does one async-signal-safe atomic store.
#[cfg(unix)]
fn install_watch_sigint_handler() {
    extern "C" fn handle(_sig: libc::c_int) {
        WATCH_INTERRUPTED.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    // SAFETY: `handle` only does an async-signal-safe atomic store.
    unsafe {
        libc::signal(libc::SIGINT, handle as *const () as libc::sighandler_t);
    }
}

/// Non-Unix: Ctrl-C uses default behavior (the process-group nuance is Unix-only).
#[cfg(not(unix))]
fn install_watch_sigint_handler() {}

/// Inventory files under `roots` as a `path -> mtime` map (capped). Symlinks are
/// recorded by their own metadata (not followed); hidden dirs (`.git`, …) skipped.
fn inventory_files(roots: &[String]) -> std::collections::BTreeMap<String, SystemTime> {
    const MAX_FILES: usize = 100_000;
    let mut out = std::collections::BTreeMap::new();
    for root in roots {
        let path = Path::new(root);
        if path.is_file() {
            if let Some(mtime) = file_mtime(path) {
                out.insert(path.to_string_lossy().into_owned(), mtime);
            }
        } else if path.is_dir() {
            inventory_dir(path, &mut out, MAX_FILES);
        }
    }
    out
}

fn inventory_dir(
    dir: &Path,
    out: &mut std::collections::BTreeMap<String, SystemTime>,
    max_files: usize,
) {
    if out.len() >= max_files {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        if out.len() >= max_files {
            break;
        }
        let p = entry.path();
        let meta = match p.symlink_metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            // Record the link itself; don't follow (avoids escaping the tree).
            if let Ok(mt) = meta.modified() {
                out.insert(p.to_string_lossy().into_owned(), mt);
            }
            continue;
        }
        if meta.is_file() {
            if let Ok(mt) = meta.modified() {
                out.insert(p.to_string_lossy().into_owned(), mt);
            }
        } else if meta.is_dir() {
            // Skip dotdirs (.git, …): they dominate the count, rarely the point.
            let is_dot = p
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with('.'))
                .unwrap_or(false);
            if !is_dot {
                inventory_dir(&p, out, max_files);
            }
        }
    }
}

fn file_mtime(path: &Path) -> Option<SystemTime> {
    path.metadata().ok().and_then(|m| m.modified().ok())
}

/// EXPERIMENTAL candidate network-hint sources (resolver-cache/log files whose
/// mtime delta *might* indicate DNS activity); [`net_hints_changed`] re-stats them.
/// NOT a network monitor — misses QUIC/UDP/direct-IP.
fn net_hint_sources(home: &Path) -> std::collections::BTreeMap<String, Option<SystemTime>> {
    let mut candidates: Vec<PathBuf> = vec![
        PathBuf::from("/var/log/system.log"),
        PathBuf::from("/var/log/syslog"),
    ];
    candidates.push(home.join(".cache/mDNSResponder"));
    let mut out = std::collections::BTreeMap::new();
    for c in candidates {
        let mtime = file_mtime(&c);
        out.insert(c.to_string_lossy().into_owned(), mtime);
    }
    out
}

/// Re-stat the candidate sources, returning a hint per source whose mtime
/// advanced. Each is prefixed (`activity-near:`) so it can't be mistaken for a
/// resolved hostname.
fn net_hints_changed(
    before: &std::collections::BTreeMap<String, Option<SystemTime>>,
    home: &Path,
) -> Vec<String> {
    let after = net_hint_sources(home);
    let mut hints = Vec::new();
    for (src, after_mtime) in &after {
        let before_mtime = before.get(src).cloned().flatten();
        if after_mtime.is_some() && *after_mtime != before_mtime {
            hints.push(format!("activity-near:{src}"));
        }
    }
    hints.sort();
    hints
}

#[allow(clippy::too_many_arguments)]
fn print_watch_human(
    command: &str,
    exit_code: i32,
    new_files: &[String],
    modified_files: &[String],
    modified_rc: &[String],
    state: &PostRunState,
    with_net_hints: bool,
    findings: &[Finding],
    interrupted: bool,
) {
    let s = tirith_core::style::Stream::Stdout;
    println!("{} {command}", tirith_core::style::bold("watched:", s));
    println!("  exit code: {exit_code}");
    if interrupted {
        let note = tirith_core::style::yellow(
            "interrupted (Ctrl-C): the command may not have finished, but the \
             after-snapshot below still ran",
            s,
        );
        println!("  {note}");
    }

    print_list_section("new files", new_files, false);
    print_list_section("modified files", modified_files, false);
    print_list_section("$PATH additions", &state.path_dirs_added, false);
    print_list_section("env vars added", &state.env_vars_added, false);

    if !modified_rc.is_empty() {
        let label = tirith_core::style::red("shell-rc modified", s);
        println!("\n  {label}:");
        for f in modified_rc {
            println!("    {f}");
        }
    } else {
        println!("\n  shell-rc modified: none");
    }

    if with_net_hints {
        println!(
            "\n  network hints (EXPERIMENTAL — best-effort only, may miss \
             QUIC/UDP/direct-IP; NOT a network monitor, not a security boundary):"
        );
        if state.domains_contacted.is_empty() {
            println!("    none observed (does NOT mean no network activity)");
        } else {
            for d in &state.domains_contacted {
                println!("    {d}");
            }
        }
    }

    if !findings.is_empty() {
        println!();
        for f in findings {
            let sev = tirith_core::style::severity_label(&f.severity, s);
            println!("  [{sev}] {}", f.title);
            println!("        {}", f.description);
        }
    }
}

fn print_list_section(label: &str, items: &[String], _force: bool) {
    if items.is_empty() {
        println!("\n  {label}: none");
    } else {
        println!("\n  {label} ({}):", items.len());
        for i in items {
            println!("    {i}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_watch_json(
    command: &str,
    exit_code: i32,
    new_files: &[String],
    modified_files: &[String],
    modified_rc: &[String],
    state: &PostRunState,
    with_net_hints: bool,
    findings: &[Finding],
    action: Action,
    interrupted: bool,
) {
    // `net_hints` is null unless the experimental flag is set, so a consumer
    // never reads an empty array as "no network activity".
    let net_hints = if with_net_hints {
        serde_json::json!({
            "experimental": true,
            "best_effort": true,
            "not_a_network_monitor": true,
            "domains_contacted": state.domains_contacted,
        })
    } else {
        serde_json::Value::Null
    };

    let dedup_rc: BTreeSet<&String> = modified_rc.iter().collect();

    let json_val = serde_json::json!({
        "command": command,
        "exit_code": exit_code,
        // True if tirith caught a SIGINT: the after-snapshot ran but the command
        // may not have finished — treat the diff as a lower bound.
        "interrupted": interrupted,
        "new_files": new_files,
        "modified_files": modified_files,
        "shell_rc_modified": dedup_rc,
        "path_dirs_added": state.path_dirs_added,
        "env_vars_added": state.env_vars_added,
        "net_hints": net_hints,
        "action": action,
        "findings": findings,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&json_val).unwrap_or_else(|e| {
            eprintln!("tirith: watch: JSON serialization failed: {e}");
            "{}".to_string()
        })
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tirith_core::checkpoint::{self, ManifestEntry};

    // Local env lock (tirith_core::TEST_ENV_LOCK is pub(crate), unreachable here).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// F2: a partial/failed restore (any blob missing/corrupt, or a copy error)
    /// must return a NON-ZERO exit code so scripts don't mistake a half-restored
    /// state for success. A fully clean restore returns 0.
    #[cfg(unix)]
    #[test]
    fn restore_checkpoint_nonzero_on_partial_failure() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        let tmpdir = tempfile::tempdir().unwrap();
        let workdir = tmpdir.path().join("project");
        std::fs::create_dir_all(&workdir).unwrap();
        let state_dir = tmpdir.path().join("state");

        let prev_state = std::env::var("XDG_STATE_HOME").ok();
        let prev_log = std::env::var("TIRITH_LOG").ok();
        let prev_cwd = std::env::current_dir().ok();
        // SAFETY: serialized via ENV_LOCK. state_dir() honors XDG_STATE_HOME on all
        // unix (it is resolved manually, not via etcetera), so this is portable.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", &state_dir);
            std::env::set_var("TIRITH_LOG", "0");
        }

        let name = "a.txt";
        let run = || -> Result<(i32, i32), String> {
            std::env::set_current_dir(&workdir).map_err(|e| format!("chdir: {e}"))?;
            std::fs::write(name, "alpha").map_err(|e| format!("write: {e}"))?;
            let meta = checkpoint::create(&[name], Some("rm -rf project"))?;

            // Clean restore first: nothing tampered, must exit 0.
            let clean_code = super::restore_checkpoint(&meta.id, true);

            // Now delete the backup blob so the next restore buckets into
            // `missing`, which must flip the exit code to non-zero.
            let cp_dir = checkpoint::checkpoints_dir().join(&meta.id);
            let manifest_str = std::fs::read_to_string(cp_dir.join("manifest.json"))
                .map_err(|e| format!("read manifest: {e}"))?;
            let manifest: Vec<ManifestEntry> =
                serde_json::from_str(&manifest_str).map_err(|e| format!("parse: {e}"))?;
            let sha = manifest
                .iter()
                .find(|m| m.original_path == name)
                .map(|m| m.sha256.clone())
                .ok_or("no manifest entry")?;
            std::fs::remove_file(cp_dir.join("files").join(&sha))
                .map_err(|e| format!("rm blob: {e}"))?;

            let partial_code = super::restore_checkpoint(&meta.id, true);
            Ok((clean_code, partial_code))
        };

        let result = run();

        // Restore cwd + env before assertions so cleanup runs even on failure.
        if let Some(dir) = prev_cwd {
            let _ = std::env::set_current_dir(dir);
        }
        unsafe {
            match prev_state {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
            match prev_log {
                Some(v) => std::env::set_var("TIRITH_LOG", v),
                None => std::env::remove_var("TIRITH_LOG"),
            }
        }

        let (clean_code, partial_code) = result.expect("restore flow should run");
        assert_eq!(clean_code, 0, "a fully clean restore must exit 0");
        assert_eq!(
            partial_code, 1,
            "a restore with a missing backup blob must exit non-zero"
        );
    }
}
