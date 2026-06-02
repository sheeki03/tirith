//! `tirith persistence scan|watch|diff` (M9 ch2). Thin presenter over
//! [`tirith_core::persistence`]; inventory + diff logic lives in the library.
//!
//! `scan` inventories every watched persistence surface (rc/profile files,
//! ssh, gitconfig, crontab, systemd-user, LaunchAgents, etc.), prints each
//! location + sha256, and records the baseline snapshot at
//! `state_dir()/persistence_snapshot.json`. `diff` compares the live inventory
//! against that snapshot and prints only credential-redacted ADDED lines (exit
//! 1 on any High/Critical); it does not re-baseline. `watch` polls every
//! `--interval` seconds until SIGINT, diffing then re-baselining each poll.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tirith_core::persistence::{self, PersistenceEntry, PersistenceFinding, PersistenceSnapshot};
use tirith_core::verdict::Severity;

use super::write_json_stdout;

/// `tirith persistence scan` — inventory every surface, print location + sha256,
/// and record the baseline snapshot. Always exits 0.
pub fn scan(json: bool) -> i32 {
    let entries = persistence::scan();

    let snapshot = PersistenceSnapshot::from_entries(&entries);
    let snapshot_note = persist_snapshot(&snapshot);

    if json {
        let body = scan_json_body(&entries, &snapshot_note);
        if !write_json_stdout(
            &body,
            "tirith persistence scan: failed to write JSON output",
        ) {
            return 1;
        }
    } else {
        print_human_scan(&entries, &snapshot_note);
    }
    0
}

/// `tirith persistence diff` — diff the live inventory against the recorded
/// snapshot, printing added-lines only. Exit 1 if any High/Critical finding.
pub fn diff(json: bool) -> i32 {
    let path = match persistence::snapshot_path() {
        Some(p) => p,
        None => {
            eprintln!(
                "tirith persistence diff: cannot resolve state dir (no HOME / XDG_STATE_HOME)."
            );
            return 1;
        }
    };
    let snapshot = persistence::load_snapshot(&path);
    let has_baseline = !snapshot.entries.is_empty();

    let findings = run_diff(&snapshot);
    let any_high = findings.iter().any(PersistenceFinding::is_high);

    if json {
        let body = diff_json_body(&findings, has_baseline);
        if !write_json_stdout(
            &body,
            "tirith persistence diff: failed to write JSON output",
        ) {
            return 1;
        }
    } else {
        print_human_diff(&findings, has_baseline, &path);
    }

    if any_high {
        1
    } else {
        0
    }
}

/// `tirith persistence watch` — poll every `interval` seconds until SIGINT,
/// diffing against the last-saved snapshot and re-baselining each poll so only
/// incremental changes surface. Exits 0 on SIGINT.
pub fn watch(interval: u64, json: bool) -> i32 {
    let path = match persistence::snapshot_path() {
        Some(p) => p,
        None => {
            eprintln!(
                "tirith persistence watch: cannot resolve state dir (no HOME / XDG_STATE_HOME)."
            );
            return 1;
        }
    };

    // Clamp so `--interval 0` doesn't busy-spin.
    let interval = interval.max(1);
    install_sigint_handler();

    if !json {
        eprintln!(
            "tirith persistence watch: polling every {interval}s (Ctrl-C to stop). \
             Baseline: {}",
            path.display()
        );
    }

    // Seed the baseline if none exists so the first poll doesn't report every
    // present surface as "new".
    let mut snapshot = persistence::load_snapshot(&path);
    if snapshot.entries.is_empty() {
        snapshot = PersistenceSnapshot::from_entries(&persistence::scan());
        let _ = persistence::save_snapshot(&path, &snapshot);
    }

    let mut polls: u64 = 0;
    while !STOP.load(Ordering::Relaxed) {
        // Sleep in 200ms slices so Ctrl-C stays responsive on a long interval.
        let mut slept = Duration::ZERO;
        let step = Duration::from_millis(200);
        let target = Duration::from_secs(interval);
        while slept < target && !STOP.load(Ordering::Relaxed) {
            std::thread::sleep(step);
            slept += step;
        }
        if STOP.load(Ordering::Relaxed) {
            break;
        }

        polls += 1;
        let current = persistence::scan();
        let findings = persistence::diff_entries(&current, &snapshot);

        // A change must not be silently dropped: if the --json stdout write
        // fails, skip the re-baseline below so the change re-surfaces next poll.
        let mut emitted = true;
        if !findings.is_empty() {
            if json {
                let body = watch_poll_json_body(polls, &findings);
                emitted =
                    write_json_stdout(&body, "tirith persistence watch: failed to write JSON");
            } else {
                print_human_watch_poll(polls, &findings);
            }
        }

        // Re-baseline only when the change was emitted; on a delivery failure
        // keep the prior baseline so the change is reported again.
        if emitted {
            snapshot = PersistenceSnapshot::from_entries(&current);
            let _ = persistence::save_snapshot(&path, &snapshot);
        }
    }

    if !json {
        eprintln!("\ntirith persistence watch: stopped after {polls} poll(s).");
    }
    0
}

/// Persist `snapshot` to the default state path. Returns a human-readable note
/// describing the outcome (used in scan output).
fn persist_snapshot(snapshot: &PersistenceSnapshot) -> String {
    match persistence::snapshot_path() {
        Some(path) => match persistence::save_snapshot(&path, snapshot) {
            Ok(()) => format!("baseline recorded at {}", path.display()),
            Err(e) => format!(
                "WARNING: failed to record baseline at {}: {e}",
                path.display()
            ),
        },
        None => {
            "WARNING: no state dir resolvable (no HOME / XDG_STATE_HOME); baseline not recorded"
                .to_string()
        }
    }
}

/// Run a diff against `snapshot` using the live inventory.
fn run_diff(snapshot: &PersistenceSnapshot) -> Vec<PersistenceFinding> {
    let current = persistence::scan();
    persistence::diff_entries(&current, snapshot)
}

/// Set by the SIGINT handler to break the `watch` poll loop for a clean exit.
static STOP: AtomicBool = AtomicBool::new(false);

/// Install a minimal SIGINT handler that flips [`STOP`] via `libc::signal`.
#[cfg(unix)]
fn install_sigint_handler() {
    extern "C" fn handle(_sig: libc::c_int) {
        STOP.store(true, Ordering::Relaxed);
    }
    // SAFETY: `handle` only does an async-signal-safe atomic store; the double
    // cast (fn item → ptr → sighandler_t) is what `libc` expects.
    unsafe {
        libc::signal(libc::SIGINT, handle as *const () as libc::sighandler_t);
    }
}

/// Non-Unix: default SIGINT behavior; the poll loop honors [`STOP`] (stays false).
#[cfg(not(unix))]
fn install_sigint_handler() {}

fn print_human_scan(entries: &[PersistenceEntry], snapshot_note: &str) {
    let present = entries.iter().filter(|e| e.present).count();
    eprintln!(
        "tirith persistence: {} surface(s) inventoried ({present} present).\n",
        entries.len()
    );
    for e in entries {
        let state = if e.present { "present" } else { "absent " };
        eprintln!(
            "  [{state}] {:<16} {}\n             sha256: {}",
            e.kind.as_str(),
            e.location,
            e.sha256,
        );
    }
    eprintln!("\n{snapshot_note}");
    eprintln!("Run `tirith persistence diff` later to see what changed since this baseline.");
}

fn print_human_diff(findings: &[PersistenceFinding], has_baseline: bool, path: &Path) {
    if !has_baseline {
        eprintln!(
            "tirith persistence diff: no baseline snapshot found at {}.\n\
             Run `tirith persistence scan` first to record one.",
            path.display()
        );
        return;
    }
    if findings.is_empty() {
        eprintln!("tirith persistence: no changes since the recorded baseline.");
        return;
    }

    let high = findings.iter().filter(|f| f.is_high()).count();
    eprintln!(
        "tirith persistence: {} change(s) since baseline ({high} high).\n",
        findings.len()
    );
    for f in findings {
        print_one_finding(f);
    }
    eprintln!("Re-run `tirith persistence scan` to accept the current state as the new baseline.");
}

fn print_human_watch_poll(poll: u64, findings: &[PersistenceFinding]) {
    eprintln!("\n[poll #{poll}] {} change(s) detected:", findings.len());
    for f in findings {
        print_one_finding(f);
    }
}

fn print_one_finding(f: &PersistenceFinding) {
    eprintln!(
        "  [{}] {}  ({})\n      surface: {}\n      change:  {}",
        severity_label(f.severity),
        f.rule_id,
        f.kind.as_str(),
        f.location,
        f.change,
    );
    if f.added_lines.is_empty() {
        eprintln!("      added:   (no line content — tracked by hash)\n");
    } else {
        eprintln!("      added lines (credential-redacted):");
        for line in &f.added_lines {
            eprintln!("        + {line}");
        }
        eprintln!();
    }
}

fn severity_label(sev: Severity) -> &'static str {
    match sev {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
        Severity::Critical => "CRITICAL",
    }
}

fn scan_json_body(entries: &[PersistenceEntry], snapshot_note: &str) -> serde_json::Value {
    // Fingerprint-only rows (NOT raw content) so --json never leaks verbatim
    // rc/authorized_keys content.
    let rows: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "key": e.key,
                "kind": e.kind.as_str(),
                "location": e.location,
                "present": e.present,
                "sha256": e.sha256,
                "size": e.size,
            })
        })
        .collect();
    serde_json::json!({
        "schema_version": 1,
        "total": entries.len(),
        "present": entries.iter().filter(|e| e.present).count(),
        "surfaces": rows,
        "baseline": snapshot_note,
    })
}

fn diff_json_body(findings: &[PersistenceFinding], has_baseline: bool) -> serde_json::Value {
    let high = findings.iter().filter(|f| f.is_high()).count();
    serde_json::json!({
        "schema_version": 1,
        "has_baseline": has_baseline,
        "total": findings.len(),
        "high_or_critical": high,
        "findings": findings,
    })
}

fn watch_poll_json_body(poll: u64, findings: &[PersistenceFinding]) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "event": "poll",
        "poll": poll,
        "total": findings.len(),
        "findings": findings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_json_body_emits_fingerprint_only() {
        let entries = vec![PersistenceEntry {
            key: "shell_rc:.zshrc".to_string(),
            kind: tirith_core::persistence::PersistenceKind::ShellRc,
            location: "/home/u/.zshrc".to_string(),
            present: true,
            sha256: "abc".to_string(),
            size: 10,
            content: "export SECRET=hunter2\n".to_string(),
        }];
        let body = scan_json_body(&entries, "baseline recorded");
        assert_eq!(body["total"], 1);
        assert_eq!(body["present"], 1);
        let surfaces = body["surfaces"].as_array().unwrap();
        let row = &surfaces[0];
        assert_eq!(row["sha256"], "abc");
        // Raw content key absent and the secret must not appear in the JSON.
        assert!(row.get("content").is_none());
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains("hunter2"));
    }

    #[test]
    fn diff_json_body_counts_high() {
        let body = diff_json_body(&[], true);
        assert_eq!(body["total"], 0);
        assert_eq!(body["high_or_critical"], 0);
        assert_eq!(body["has_baseline"], true);
        assert!(body["findings"].is_array());
    }

    #[test]
    fn watch_poll_json_body_shape() {
        let body = watch_poll_json_body(3, &[]);
        assert_eq!(body["event"], "poll");
        assert_eq!(body["poll"], 3);
        assert!(body["findings"].is_array());
    }
}
