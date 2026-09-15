//! `tirith pending`: list, resolve, and export pending decisions.
//!
//! This is a thin CLI over `tirith_core::pending`. It never runs a restore:
//! for a rollback it marks the entry and prints the exact
//! `tirith checkpoint restore <id>` command for the operator to run.

use std::path::PathBuf;

use tirith_core::pending::{self, PendingStatus};

/// Default retention window before a still-`Pending` decision ages out to
/// `Expired` (30 days). Applied on the read path so the store self-trims rather
/// than growing unbounded; matches the "configured retention window" the
/// `PendingStatus::Expired` doc-comment promises.
const PENDING_RETENTION_SECS: i64 = 30 * 24 * 60 * 60;

/// List unresolved pending decisions as a human table or JSON.
pub fn list(format_json: bool) -> i32 {
    // Age out stale entries first so they drop off the unresolved list and the
    // store does not accumulate forever (best-effort; an error here is non-fatal
    // to listing).
    let _ = pending::expire_older_than(PENDING_RETENTION_SECS);
    let entries = match pending::list_unresolved() {
        Ok(e) => e,
        // A real-but-unreadable store must surface as an error, not an empty list.
        Err(e) => {
            eprintln!("tirith pending list: {e}");
            return 2;
        }
    };
    if format_json {
        // Serialize through the shared helper so a broken pipe (EPIPE) returns a
        // non-zero exit instead of panicking, and the exit code follows the write.
        if super::write_json_stdout(&entries, "tirith pending list: failed to write JSON output") {
            0
        } else {
            2
        }
    } else {
        if entries.is_empty() {
            println!("No pending decisions.");
            return 0;
        }
        println!(
            "{id:<10} {created:<26} {source:<11} {severity:<9} Command",
            id = "ID",
            created = "Created",
            source = "Source",
            severity = "Severity"
        );
        println!("{}", "-".repeat(90));
        for e in &entries {
            let source = format!("{:?}", e.source).to_lowercase();
            // repo-0405: the persisted preview is attacker-derived — redaction
            // strips secrets, not ANSI/OSC/bidi/newlines. Sanitize before print.
            let command = super::sanitize_for_human_output(
                &e.command_redacted.chars().take(32).collect::<String>(),
                false,
            );
            println!(
                "{:<10} {:<26} {:<11} {:<9} {}",
                e.id, e.created_at, source, e.severity, command
            );
        }
        println!("\n{} pending decision(s)", entries.len());
        0
    }
}

/// Resolve a pending decision. `action` is one of keep|rollback|approve|deny.
///
/// For `rollback`, the entry is marked `RolledBack` and, if a
/// `refs.checkpoint_id` is present, the exact restore command is printed for
/// the operator to run. This handler never performs the restore itself.
pub fn resolve(id: &str, action: &str, reason: Option<String>) -> i32 {
    let status = match action {
        "keep" => PendingStatus::Kept,
        "rollback" => PendingStatus::RolledBack,
        "approve" => PendingStatus::Approved,
        "deny" => PendingStatus::Denied,
        other => {
            eprintln!(
                "tirith pending resolve: unknown action '{other}' (expected keep|rollback|approve|deny)"
            );
            return 2;
        }
    };

    // For rollback, surface the restore command (if any) before mutating, so
    // the operator sees it even when the entry is already resolved.
    // Best-effort lookup of the restore-command hint. If the store cannot be read
    // here, the authoritative `pending::resolve` call below still fails closed; we
    // just cannot surface the checkpoint id, so fall back to no hint.
    let checkpoint_id = if action == "rollback" {
        pending::load_all()
            .unwrap_or_default()
            .into_iter()
            .find(|d| d.id == id)
            .and_then(|d| d.refs.get("checkpoint_id").cloned())
    } else {
        None
    };

    // The restore-command guidance is independent of whether THIS call flipped
    // the status: for a rollback it must surface even when the entry was already
    // resolved, so an operator re-running the command still sees how to restore.
    let print_rollback_hint = || {
        if action == "rollback" {
            match &checkpoint_id {
                Some(cp) => {
                    println!("To roll back, run:");
                    println!("  tirith checkpoint restore {cp}");
                }
                None => {
                    println!("No checkpoint reference recorded; nothing to restore automatically.");
                }
            }
        }
    };

    match pending::resolve(id, status, reason, Some("cli".to_string())) {
        Ok(true) => {
            println!("Resolved {id} ({action}).");
            if action == "approve" {
                println!("This records a review decision only. It grants no execution permission; retry the original command through its supported execution boundary for a fresh policy check.");
            }
            print_rollback_hint();
            0
        }
        Ok(false) => {
            eprintln!("tirith pending resolve: '{id}' not found or already resolved.");
            // Still emit the rollback guidance: an already-resolved rollback whose
            // checkpoint reference is known should not drop the restore command.
            print_rollback_hint();
            1
        }
        Err(e) => {
            eprintln!("tirith pending resolve: {e}");
            2
        }
    }
}

/// Export all pending decisions as pretty JSON to a file or stdout.
pub fn export(output: Option<PathBuf>) -> i32 {
    let all = match pending::load_all() {
        Ok(a) => a,
        // Surface "cannot read store" rather than exporting an empty list that
        // could be mistaken for a genuinely empty store.
        Err(e) => {
            eprintln!("tirith pending export: {e}");
            return 2;
        }
    };

    match output {
        Some(path) => {
            // repo-0406: a repository can pre-plant the chosen export name as a
            // symlink to a writable external file; write_file_atomic resolves
            // symlinks deliberately, so refuse a symlinked destination here.
            if std::fs::symlink_metadata(&path)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false)
            {
                eprintln!(
                    "tirith pending export: refusing to write through symlink {}",
                    path.display()
                );
                return 2;
            }
            // The file path still pre-serializes (the bytes are written to a file,
            // not stdout, so the EPIPE concern does not apply here).
            let json = match serde_json::to_string_pretty(&all) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("tirith pending export: JSON serialization failed: {e}");
                    return 2;
                }
            };
            // Write atomically (temp + fsync + rename) so a crash/ENOSPC mid-write
            // cannot leave a half-written export at `path`; a reader sees either the
            // old file or the complete new one. `overwrite = true`: export replaces.
            match super::write_file_atomic(&path, json.as_bytes(), true) {
                Ok(()) => {
                    println!(
                        "Wrote {} pending decision(s) to {}",
                        all.len(),
                        path.display()
                    );
                    0
                }
                Err(e) => {
                    eprintln!("tirith pending export: write {}: {e}", path.display());
                    2
                }
            }
        }
        // Stdout export goes through the shared helper: pass the object directly
        // (the helper serializes) so a broken pipe returns non-zero rather than
        // panicking, and the exit code follows the write.
        None => {
            if super::write_json_stdout(&all, "tirith pending export: failed to write JSON output")
            {
                0
            } else {
                2
            }
        }
    }
}
