//! M11 ch5 — `tirith incident start|stop|status|report` (L2 #21).
//!
//! Incident mode is a manually-declared "we may be under attack" posture that
//! forces the runtime policy fail-closed, disables the `TIRITH=0` bypass, and
//! elevates a curated rule set (see [`tirith_core::incident`]). State + override
//! logic lives in the library; this module is the CLI presenter + `report` writer.
//!
//! # Lockout safety (CRITICAL)
//!
//! `stop` is a DIRECT deletion of the flag file, NOT gated by the incident's own
//! fail-closed policy, so it can ALWAYS recover a stuck incident even with
//! `allow_bypass_env: false`. The CLI integration test `incident_*` pins this.
//!
//! # Report privacy
//!
//! `report` copies the audit log's already-redacted `command_redacted` preview
//! verbatim and NEVER reconstructs a full command.

use std::io::Write as _;
use std::path::PathBuf;

use tirith_core::incident::{self, IncidentState, StartError};

use super::{confirm, write_json_stdout};

/// Emit a fatal operator error as `{"error": ...}` JSON on stdout (`--json`) or
/// a human stderr line, keeping the `--json` surface parseable on fatal branches.
/// Returns `false` when the JSON write itself failed so the caller can use a
/// distinct write-failure exit; human mode always returns `true` (best-effort).
fn emit_error(json: bool, ctx: &str, msg: &str) -> bool {
    if json {
        let v = serde_json::json!({ "error": msg });
        write_json_stdout(&v, &format!("{ctx}: failed to write JSON output"))
    } else {
        eprintln!("{ctx}: {msg}");
        true
    }
}

/// `tirith incident start [--reason "…"]` — declare an incident (fail-closed +
/// `TIRITH=0` disabled). A second `start` fails (exit 1) without overwriting the
/// original reason / start time.
pub fn start(reason: Option<String>, json: bool) -> i32 {
    let reason = reason.unwrap_or_default();
    match incident::start(reason) {
        Ok(state) => {
            if json {
                if !write_json_stdout(
                    &StartedOut::from(&state),
                    "tirith incident start: failed to write JSON output",
                ) {
                    return 2;
                }
                return 0;
            }
            println!("Incident mode ACTIVE.");
            println!();
            println!("  started_at: {}", state.started_at_display());
            println!("  started_by: {}", state.started_by);
            println!(
                "  reason:     {}",
                if state.reason.is_empty() {
                    "<none>"
                } else {
                    &state.reason
                }
            );
            println!();
            println!("While active, tirith is FAIL-CLOSED and the TIRITH=0 bypass is DISABLED");
            println!("(interactive and non-interactive). A curated set of credential / payload /");
            println!("exec-provenance rules is elevated. Subsequent `tirith check` runs will");
            println!("block on these even with TIRITH=0 set.");
            println!();
            println!("End the incident with:  tirith incident stop");
            println!("(stop is ALWAYS available — it is never gated by the fail-closed policy.)");
            0
        }
        Err(StartError::AlreadyActive(existing)) => {
            if json {
                #[derive(serde::Serialize)]
                struct AlreadyOut<'a> {
                    started: bool,
                    already_active: bool,
                    started_at: u64,
                    started_at_display: String,
                    reason: &'a str,
                }
                // A failed JSON write returns exit 2 (write-failure), distinct
                // from the "already active" exit 1, so a piped consumer never
                // reads a clean record from truncated JSON.
                if !write_json_stdout(
                    &AlreadyOut {
                        started: false,
                        already_active: true,
                        started_at: existing.started_at,
                        started_at_display: existing.started_at_display(),
                        reason: &existing.reason,
                    },
                    "tirith incident start: failed to write JSON output",
                ) {
                    return 2;
                }
                return 1;
            }
            eprintln!(
                "tirith incident start: an incident is already active since {} (reason: {}).",
                existing.started_at_display(),
                if existing.reason.is_empty() {
                    "<none>"
                } else {
                    &existing.reason
                }
            );
            eprintln!("Run `tirith incident stop` to end it before starting a new one.");
            1
        }
        Err(e) => {
            // Failed JSON write → write-failure exit 2, distinct from fatal exit 1.
            if !emit_error(json, "tirith incident start", &e.to_string()) {
                return 2;
            }
            1
        }
    }
}

/// `tirith incident stop [--yes]` — end the active incident (delete the flag,
/// restore the policy, audit-log it). Prompts unless `--yes`.
///
/// LOCKOUT SAFETY: a plain filesystem deletion via [`tirith_core::incident::stop`]
/// with NO `check` and NO policy gating, so it works even when fail-closed.
pub fn stop(yes: bool, json: bool) -> i32 {
    let existing = incident::read_state();
    if existing.is_none() {
        if json {
            // Failed JSON write → non-zero, so a consumer never pairs truncated
            // JSON with a success exit.
            if !write_json_stdout(
                &StoppedOut {
                    stopped: false,
                    was_active: false,
                },
                "tirith incident stop: failed to write JSON output",
            ) {
                return 2;
            }
        } else {
            println!("No incident is active — nothing to stop.");
        }
        return 0;
    }

    // Confirmation. In JSON mode require --yes (no prompt on a machine surface).
    if json {
        if !yes {
            // Route "--yes required" through the JSON-error path so `--json` stays
            // parseable. Exit 2 either way (the bool is moot here).
            let _ = emit_error(
                json,
                "tirith incident stop",
                "--yes required in JSON mode to confirm",
            );
            return 2;
        }
    } else if !confirm(
        "End the active incident and restore the normal policy?",
        yes,
    ) {
        println!("Aborted — incident left active.");
        return 0;
    }

    match incident::stop() {
        Ok(removed) => {
            // RACE (CodeRabbit R18 #3): `read_state()` saw an active incident but
            // `stop()` returns `removed == false` when a concurrent process cleared
            // the flag first. Exit stays 0 (posture IS inactive), but the audit
            // event + message must report the already-cleared outcome, not claim
            // this call restored the policy.
            let (audit_event, detail) =
                stop_outcome(removed, existing.as_ref().map(|s| s.started_at_display()));
            // Best-effort audit trail (non-blocking; never gates).
            tirith_core::audit::log_hook_event(
                "incident",
                "stop",
                audit_event,
                None,
                Some(&detail),
            );

            if json {
                // `stopped` reflects whether THIS call removed the flag (false on
                // the race), so a consumer can tell a real stop from a no-op.
                if !write_json_stdout(
                    &StoppedOut {
                        stopped: removed,
                        was_active: true,
                    },
                    "tirith incident stop: failed to write JSON output",
                ) {
                    return 2;
                }
                return 0;
            }
            if removed {
                println!("Incident ended — normal policy restored.");
                println!("The TIRITH=0 bypass and your configured fail_mode are in effect again.");
            } else {
                // Cleared by a racing process — do NOT claim this call restored it.
                println!(
                    "Incident was already inactive — cleared by another process; nothing to stop."
                );
            }
            0
        }
        Err(e) => {
            // Failed JSON write → write-failure exit 2, distinct from fatal exit 1.
            if !emit_error(json, "tirith incident stop", &e) {
                return 2;
            }
            1
        }
    }
}

/// Select the audit `(event, detail)` for an `incident stop`. `removed == true`
/// → THIS call cleared the flag (`incident_stopped`); `removed == false` → a
/// racing process cleared it first (CodeRabbit R18 #3), so we record
/// `incident_already_inactive` rather than a false stop. Pure, so the
/// race-vs-normal selection is unit-testable without forcing the TOCTOU window.
fn stop_outcome(removed: bool, started_at_display: Option<String>) -> (&'static str, String) {
    if removed {
        let detail = started_at_display
            .map(|d| format!("incident stopped (was active since {d})"))
            .unwrap_or_else(|| "incident stopped".to_string());
        ("incident_stopped", detail)
    } else {
        (
            "incident_already_inactive",
            "incident already cleared by another process before this stop".to_string(),
        )
    }
}

/// `tirith incident status` — show whether an incident is active (and its
/// reason + start time if so).
pub fn status(json: bool) -> i32 {
    let state = incident::read_state();
    let flag = incident::flag_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<unresolved>".to_string());

    if json {
        #[derive(serde::Serialize)]
        struct StatusOut {
            active: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            started_at: Option<u64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            started_at_display: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            started_by: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            reason: Option<String>,
            flag_path: String,
        }
        let out = match &state {
            Some(s) => StatusOut {
                active: true,
                started_at: Some(s.started_at),
                started_at_display: Some(s.started_at_display()),
                started_by: Some(s.started_by.clone()),
                reason: Some(s.reason.clone()),
                flag_path: flag,
            },
            None => StatusOut {
                active: false,
                started_at: None,
                started_at_display: None,
                started_by: None,
                reason: None,
                flag_path: flag,
            },
        };
        if !write_json_stdout(&out, "tirith incident status: failed to write JSON output") {
            return 2;
        }
        return 0;
    }

    match state {
        Some(s) => {
            println!("Incident status: ACTIVE");
            println!("  started_at: {}", s.started_at_display());
            println!("  started_by: {}", s.started_by);
            println!(
                "  reason:     {}",
                if s.reason.is_empty() {
                    "<none>"
                } else {
                    &s.reason
                }
            );
            println!("  flag:       {flag}");
            println!();
            println!("Runtime policy is FAIL-CLOSED and the TIRITH=0 bypass is DISABLED.");
            println!("End with:  tirith incident stop");
        }
        None => {
            println!("Incident status: inactive");
            println!("  flag: {flag}");
            println!();
            println!("Declare one with:  tirith incident start --reason \"…\"");
        }
    }
    0
}

/// `tirith incident report [--out <path>]` — write (or print) a markdown report:
/// timeline since the incident started, live persistence/env/path/hook/canary
/// state, top recent findings, and an operator "actions taken" section. All
/// embedded command text comes from the already-redacted audit field.
pub fn report(out: Option<PathBuf>, json: bool) -> i32 {
    let state = incident::read_state();
    let body = build_report(state.as_ref());

    match out {
        Some(path) => match write_report_file(&path, &body) {
            Ok(()) => {
                if json {
                    #[derive(serde::Serialize)]
                    struct ReportOut {
                        written: bool,
                        path: String,
                        bytes: usize,
                    }
                    if !write_json_stdout(
                        &ReportOut {
                            written: true,
                            path: path.display().to_string(),
                            bytes: body.len(),
                        },
                        "tirith incident report: failed to write JSON output",
                    ) {
                        return 2;
                    }
                } else {
                    println!(
                        "Wrote incident report to {} ({} bytes).",
                        path.display(),
                        body.len()
                    );
                    println!("Fill in the \"Actions taken\" section before sharing.");
                }
                0
            }
            Err(e) => {
                // Failed JSON write → write-failure exit 2, distinct from fatal 1.
                if !emit_error(json, "tirith incident report", &e) {
                    return 2;
                }
                1
            }
        },
        None => {
            // No --out: `--json` carries the markdown as a string field (never
            // raw Markdown on a JSON surface); otherwise print raw for piping.
            if json {
                #[derive(serde::Serialize)]
                struct ReportStdoutOut {
                    report_markdown: String,
                    bytes: usize,
                }
                if !write_json_stdout(
                    &ReportStdoutOut {
                        report_markdown: body.clone(),
                        bytes: body.len(),
                    },
                    "tirith incident report: failed to write JSON output",
                ) {
                    return 2;
                }
            } else {
                print!("{body}");
            }
            0
        }
    }
}

/// Write the report to `path` with `0o600` perms on Unix (it may contain
/// repo-internal hostnames / paths even after redaction).
fn write_report_file(path: &std::path::Path, body: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    // `mode(0o600)` only applies on CREATE; a pre-existing `--out` file keeps its
    // old (possibly world-readable) mode. Re-assert 0600 BEFORE writing the body
    // and PROPAGATE the error (CodeRabbit R11 #7) so a chmod failure aborts the
    // write — sensitive repo-internal paths/hostnames are never left readable.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod 0600 {}: {e}", path.display()))?;
    }
    f.write_all(body.as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))
}

/// How many recent findings the report surfaces under "Top findings".
const REPORT_TOP_FINDINGS: usize = 25;
/// How many timeline rows the report surfaces.
const REPORT_TIMELINE_ROWS: usize = 50;

/// Escape a single-line value for safe inline embedding in the Markdown report.
/// Neutralizes two hazards: STRUCTURE — CR/LF collapse to a space so a
/// multi-line value (e.g. a `--reason` with a newline) can't break its list item
/// or inject a `#` heading (the load-bearing fix); RENDERING — inline
/// Markdown-significant chars (`` ` `` `*` `_` `[` `]` `<` `>` `\` `#` `|`) are
/// backslash-escaped.
fn md_inline_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            // Collapse line breaks to a space (a `\r\n` → two spaces, harmless).
            '\n' | '\r' => out.push(' '),
            '`' | '*' | '_' | '[' | ']' | '<' | '>' | '\\' | '#' | '|' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

/// Assemble the full markdown report; each section is best-effort (degrades to
/// a one-line "unavailable" note rather than aborting).
fn build_report(state: Option<&IncidentState>) -> String {
    let mut s = String::new();
    let now = chrono::Utc::now().to_rfc3339();

    s.push_str("# Tirith Incident Report\n\n");
    s.push_str(&format!("Generated: {now}\n\n"));

    match state {
        Some(st) => {
            s.push_str("Status: **ACTIVE**\n\n");
            s.push_str(&format!("- Started at: {}\n", st.started_at_display()));
            // `started_by` and `reason` are operator/env-controlled — escape them
            // so a newline can't break the list or inject a Markdown heading.
            s.push_str(&format!(
                "- Started by: {}\n",
                md_inline_escape(&st.started_by)
            ));
            s.push_str(&format!(
                "- Reason: {}\n\n",
                if st.reason.is_empty() {
                    "<none>".to_string()
                } else {
                    md_inline_escape(&st.reason)
                }
            ));
        }
        None => {
            s.push_str("Status: inactive (no incident flag present at report time)\n\n");
            s.push_str("This report reflects the CURRENT machine state. Timeline rows are not\n");
            s.push_str("bounded to an incident window because no `started_at` is recorded.\n\n");
        }
    }

    let since = state.map(|st| st.started_at);
    append_timeline(&mut s, since);
    append_top_findings(&mut s, since);
    append_persistence(&mut s);
    append_env(&mut s);
    append_path(&mut s);
    append_hooks(&mut s);
    append_canaries(&mut s);
    append_actions_taken(&mut s);
    s
}

/// Parse an RFC-3339 audit timestamp to unix epoch seconds. `None` on failure.
fn ts_to_epoch(ts: &str) -> Option<u64> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.timestamp().max(0) as u64)
}

/// Audit timeline: every audit record whose timestamp is at or after `since`
/// (or all recent records when `since` is `None`), newest first.
fn append_timeline(s: &mut String, since: Option<u64>) {
    s.push_str("## Timeline\n\n");
    let Some(path) = tirith_core::audit::audit_log_path() else {
        s.push_str("_Audit log path unavailable._\n\n");
        return;
    };
    if !path.exists() {
        s.push_str("_No audit log on this machine yet._\n\n");
        return;
    }
    let records = match tirith_core::audit_aggregator::read_log(&path) {
        Ok(r) => r.records,
        Err(e) => {
            s.push_str(&format!("_Could not read audit log: {e}_\n\n"));
            return;
        }
    };

    // Filter to the incident window, newest first.
    let mut rows: Vec<&tirith_core::audit_aggregator::AuditRecord> = records
        .iter()
        .filter(|r| match since {
            Some(start) => ts_to_epoch(&r.timestamp)
                .map(|e| e >= start)
                .unwrap_or(true),
            None => true,
        })
        .collect();
    rows.reverse();

    if rows.is_empty() {
        // CodeRabbit R9 #K: only call it an "incident window" when there is one.
        if since.is_some() {
            s.push_str("_No audit entries in the incident window._\n\n");
        } else {
            s.push_str("_No recent audit entries._\n\n");
        }
        return;
    }

    let shown = rows.len().min(REPORT_TIMELINE_ROWS);
    // No active incident → "recent entries", not "since incident start".
    let plural = if rows.len() == 1 { "y" } else { "ies" };
    if since.is_some() {
        s.push_str(&format!(
            "{} entr{plural} since incident start (showing {shown}):\n\n",
            rows.len(),
        ));
    } else {
        s.push_str(&format!(
            "{} recent entr{plural} (showing {shown}):\n\n",
            rows.len(),
        ));
    }
    s.push_str("| time | action | rules | command (redacted) |\n");
    s.push_str("| --- | --- | --- | --- |\n");
    for r in rows.into_iter().take(REPORT_TIMELINE_ROWS) {
        let rules = if r.rule_ids.is_empty() {
            "-".to_string()
        } else {
            r.rule_ids.join(", ")
        };
        s.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            md_cell(&r.timestamp),
            md_cell(&r.action),
            md_cell(&rules),
            md_cell(&redact_preview(&r.command_redacted)),
        ));
    }
    s.push('\n');
}

/// Re-run the shipping credential redactor over an audit `command_redacted`
/// field before embedding. The write-time redaction scrubs DLP patterns + URL
/// userinfo but NOT shell-assignment values (`AWS_SECRET_ACCESS_KEY=…`);
/// `redact_command_text` scrubs those first, then the DLP patterns. Idempotent.
fn redact_preview(already_redacted: &str) -> String {
    tirith_core::redact::redact_command_text(already_redacted, &[])
}

/// Top recent findings by rule_id frequency within the window.
fn append_top_findings(s: &mut String, since: Option<u64>) {
    s.push_str("## Top findings\n\n");
    let Some(path) = tirith_core::audit::audit_log_path() else {
        s.push_str("_Audit log path unavailable._\n\n");
        return;
    };
    if !path.exists() {
        s.push_str("_No audit log on this machine yet._\n\n");
        return;
    }
    let records = match tirith_core::audit_aggregator::read_log(&path) {
        Ok(r) => r.records,
        Err(e) => {
            s.push_str(&format!("_Could not read audit log: {e}_\n\n"));
            return;
        }
    };

    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for r in &records {
        let in_window = match since {
            Some(start) => ts_to_epoch(&r.timestamp)
                .map(|e| e >= start)
                .unwrap_or(true),
            None => true,
        };
        if !in_window {
            continue;
        }
        for rule in &r.rule_ids {
            *counts.entry(rule.clone()).or_insert(0) += 1;
        }
    }
    if counts.is_empty() {
        if since.is_some() {
            s.push_str("_No findings recorded in the incident window._\n\n");
        } else {
            s.push_str("_No findings recorded recently._\n\n");
        }
        return;
    }
    let mut ranked: Vec<(String, usize)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    s.push_str("| count | rule_id |\n");
    s.push_str("| --- | --- |\n");
    for (rule, count) in ranked.into_iter().take(REPORT_TOP_FINDINGS) {
        s.push_str(&format!("| {count} | {} |\n", md_cell(&rule)));
    }
    s.push('\n');
}

/// Live persistence surfaces (crontab, shell rc, launch agents, .envrc, …) —
/// current inventory only; "added lines" diffing needs a prior snapshot.
fn append_persistence(s: &mut String) {
    s.push_str("## Persistence surfaces\n\n");
    let entries = tirith_core::persistence::scan();
    let present: Vec<_> = entries.iter().filter(|e| e.present).collect();
    if present.is_empty() {
        s.push_str("_No watched persistence surfaces present._\n\n");
        return;
    }
    s.push_str("Current inventory (compare against `tirith persistence diff` if you have a\n");
    s.push_str("pre-incident snapshot):\n\n");
    s.push_str("| surface | location | size |\n");
    s.push_str("| --- | --- | --- |\n");
    for e in present {
        s.push_str(&format!(
            "| {} | {} | {} |\n",
            md_cell(&e.key),
            md_cell(&e.location),
            e.size,
        ));
    }
    s.push('\n');
}

/// Sensitive env-var diff (current process vs the saved snapshot, if any).
fn append_env(s: &mut String) {
    s.push_str("## Environment\n\n");
    let sensitive = tirith_core::env_guard::effective_sensitive_vars(&[]);
    let set_now = tirith_core::env_guard::sensitive_env_set_in_process(&sensitive);
    if set_now.is_empty() {
        s.push_str("_No sensitive environment variables set in this process._\n\n");
    } else {
        s.push_str(&format!(
            "{} sensitive variable(s) currently set in this process (names only, values\n",
            set_now.len()
        ));
        s.push_str("never recorded):\n\n");
        for name in &set_now {
            s.push_str(&format!("- `{}`\n", md_inline(name)));
        }
        s.push('\n');
    }
    s.push_str("Run `tirith env diff` for a full snapshot comparison.\n\n");
}

/// Exec-PATH audit of the current `$PATH` (writable-before-system dirs, etc.).
fn append_path(s: &mut String) {
    s.push_str("## PATH audit\n\n");
    let path_value = std::env::var("PATH").unwrap_or_default();
    if path_value.is_empty() {
        s.push_str("_No PATH set in this process._\n\n");
        return;
    }
    let dirs = tirith_core::path_audit::split_path(&path_value);
    let mut flagged = Vec::new();
    for (idx, dir) in dirs.iter().enumerate() {
        if tirith_core::path_audit::is_system_path(dir) {
            continue;
        }
        // A non-system dir before a later system dir is the classic
        // writable-before-system shadow risk.
        let precedes_system = dirs
            .iter()
            .skip(idx + 1)
            .any(|d| tirith_core::path_audit::is_system_path(d));
        if precedes_system {
            flagged.push(dir.display().to_string());
        }
    }
    if flagged.is_empty() {
        s.push_str("_No non-system PATH entries precede a system directory._\n\n");
        return;
    }
    s.push_str("Non-system PATH entries that precede a system directory (potential shadowing\n");
    s.push_str("— run `tirith path audit` for the full provenance check):\n\n");
    for d in flagged {
        s.push_str(&format!("- `{}`\n", md_inline(&d)));
    }
    s.push('\n');
}

/// Repo-hook / automation scan for the current repo.
fn append_hooks(s: &mut String) {
    s.push_str("## Repo hooks\n\n");
    let scan = tirith_core::repo_hooks::scan_for_cwd();
    match &scan.repo_root {
        Some(root) => s.push_str(&format!("Repo: `{}`\n\n", md_inline(root))),
        None => {
            s.push_str("_Not inside a git repo — no hook scan._\n\n");
            return;
        }
    }
    let findings = scan.all_findings();
    if findings.is_empty() {
        s.push_str("_No hook/automation findings._\n\n");
        return;
    }
    s.push_str("| severity | rule | detail |\n");
    s.push_str("| --- | --- | --- |\n");
    for f in findings {
        s.push_str(&format!(
            "| {} | {} | {} |\n",
            f.severity,
            md_cell(&format!("{:?}", f.rule_id)),
            md_cell(&f.detail),
        ));
    }
    s.push('\n');
}

/// Canary inventory + how many are local-only vs callback.
fn append_canaries(s: &mut String) {
    s.push_str("## Canary status\n\n");
    let entries = tirith_core::canary::list();
    if entries.is_empty() {
        s.push_str("_No canary tokens registered._\n\n");
        return;
    }
    let with_callback = entries.iter().filter(|e| e.callback_url.is_some()).count();
    s.push_str(&format!(
        "{} canary token(s) registered ({} local-only, {} with opt-in callback). Token\n",
        entries.len(),
        entries.len() - with_callback,
        with_callback
    ));
    s.push_str("values are NOT included in this report.\n\n");
    s.push_str("| id | kind | created |\n");
    s.push_str("| --- | --- | --- |\n");
    for e in &entries {
        s.push_str(&format!(
            "| {} | {} | {} |\n",
            md_cell(&e.id),
            md_cell(&e.kind),
            md_cell(&e.created_at),
        ));
    }
    s.push('\n');
}

/// The operator-fills-this-in section.
fn append_actions_taken(s: &mut String) {
    s.push_str("## Actions taken\n\n");
    s.push_str("_Fill this in as you respond. Suggested checklist:_\n\n");
    s.push_str("- [ ] Rotated exposed credentials (`tirith secret triage`)\n");
    s.push_str("- [ ] Reviewed new/changed persistence surfaces\n");
    s.push_str("- [ ] Reviewed PATH for shadowing binaries\n");
    s.push_str("- [ ] Reviewed repo hooks / automation\n");
    s.push_str("- [ ] Confirmed no canary tokens were touched\n");
    s.push_str("- [ ] Ended incident mode (`tirith incident stop`)\n");
    s.push('\n');
    s.push_str("### Notes\n\n");
    s.push_str("_(your notes here)_\n");
}

/// Escape a Markdown table cell: collapse newlines, escape `|` so the row holds.
fn md_cell(raw: &str) -> String {
    let collapsed: String = raw
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    collapsed.replace('|', "\\|").trim().to_string()
}

/// Escape a value for inline Markdown code: backticks would break the span.
fn md_inline(raw: &str) -> String {
    raw.replace('`', "'")
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect()
}

// ---- JSON output shapes ----------------------------------------------------

#[derive(serde::Serialize)]
struct StartedOut {
    started: bool,
    started_at: u64,
    started_at_display: String,
    started_by: String,
    reason: String,
}

impl From<&IncidentState> for StartedOut {
    fn from(s: &IncidentState) -> Self {
        StartedOut {
            started: true,
            started_at: s.started_at,
            started_at_display: s.started_at_display(),
            started_by: s.started_by.clone(),
            reason: s.reason.clone(),
        }
    }
}

#[derive(serde::Serialize)]
struct StoppedOut {
    stopped: bool,
    was_active: bool,
}

#[cfg(test)]
mod tests {
    use super::{build_report, md_inline_escape, stop_outcome};
    use tirith_core::incident::IncidentState;

    /// CodeRabbit R18 #3: a `removed == false` stop (racing process cleared the
    /// flag first) must report the already-cleared outcome, not a false stop.
    #[test]
    fn stop_outcome_distinguishes_real_stop_from_race() {
        // Real stop: removed → `incident_stopped` + detail naming the start time.
        let (event, detail) = stop_outcome(true, Some("2026-05-30T00:00:00+00:00".to_string()));
        assert_eq!(event, "incident_stopped");
        assert!(
            detail.contains("incident stopped") && detail.contains("2026-05-30T00:00:00+00:00"),
            "a real stop must record the stopped event with the start time, got: {detail}"
        );

        // Race: flag already gone → distinct already-inactive event; detail must
        // NOT claim this call stopped anything.
        let (event, detail) = stop_outcome(false, Some("2026-05-30T00:00:00+00:00".to_string()));
        assert_eq!(
            event, "incident_already_inactive",
            "a racing already-cleared stop must not be logged as incident_stopped"
        );
        assert!(
            detail.contains("already cleared by another process"),
            "the race detail must report the already-cleared outcome, got: {detail}"
        );
        assert!(
            !detail.contains("incident stopped"),
            "the race detail must NOT falsely claim this call stopped the incident, got: {detail}"
        );
    }

    #[test]
    fn md_inline_escape_neutralizes_newlines_and_markdown() {
        // Newlines collapse to spaces (so structure can't break); a leading `#`
        // is backslash-escaped so it can't become a heading even mid-line.
        assert_eq!(md_inline_escape("a\nb"), "a b");
        assert_eq!(md_inline_escape("a\r\nb"), "a  b");
        assert_eq!(md_inline_escape("# heading"), "\\# heading");
        assert_eq!(md_inline_escape("a*b_c`d"), "a\\*b\\_c\\`d");
        // A clean value is unchanged.
        assert_eq!(md_inline_escape("alice"), "alice");
    }

    #[test]
    fn report_escapes_reason_with_newline_and_heading_injection() {
        // CodeRabbit R6 #11: a `--reason` with a newline + `#` must NOT break the
        // report structure or inject a heading.
        let state = IncidentState {
            started_at: 1_700_000_000,
            started_by: "alice\n# Injected Heading".to_string(),
            reason: "real reason\n# Pwned\n- fake bullet".to_string(),
        };

        let report = build_report(Some(&state));

        // The injected newlines are gone from the metadata lines: no line in the
        // report is a bare `# Pwned` / `# Injected Heading` heading.
        for line in report.lines() {
            assert_ne!(line.trim_start(), "# Pwned", "reason injected a heading");
            assert_ne!(
                line.trim_start(),
                "# Injected Heading",
                "started_by injected a heading"
            );
        }
        // The escaped forms ARE present on their single metadata lines.
        assert!(
            report.contains("- Reason: real reason \\# Pwned - fake bullet"),
            "reason must be newline-collapsed and Markdown-escaped, got:\n{report}"
        );
        assert!(
            report.contains("- Started by: alice \\# Injected Heading"),
            "started_by must be newline-collapsed and Markdown-escaped, got:\n{report}"
        );
    }
}
