use std::io::IsTerminal;

use crate::cli::last_trigger;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::escalation::CallerContext;
use tirith_core::extract::ScanContext;
use tirith_core::output;
use tirith_core::threatdb_api::RuntimeThreatMode;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{action_from_findings, upgraded_action_from_findings, Action, Verdict};

/// W6: build a DISPLAY-ONLY clone of `effective` whose repeated Warn / WarnAck
/// findings (already surfaced earlier this session) are collapsed, and return how
/// many findings were hidden.
///
/// This is strictly an output-layer transform: the caller passes the returned
/// clone ONLY to `write_human` / `write_human_auto`. The unmodified `effective`
/// verdict still drives the action, exit code, audit log, ack / approval files,
/// `last_trigger`, the webhook, and session accounting (`record_*`). Nothing
/// about the verdict itself changes here.
///
/// Suppression NEVER touches a finding that drives a block: a finding is a
/// candidate only when, classified ALONE, it maps to [`Action::Warn`] /
/// [`Action::WarnAck`] (i.e. Medium / Low severity). High / Critical (Block) and
/// Info (Allow) findings are always kept. For each DISTINCT `(rule_id, target)`
/// pair among the candidates, [`tirith_core::session_warnings::suppress_check`] is
/// called EXACTLY once (it mutates session cooldown state and, on a suppressed
/// hit, emits the `finding_suppressed` audit rollup so a collapsed warning is
/// never dropped silently).
fn build_display_verdict(
    effective: &Verdict,
    session_id: &str,
    cooldown_secs: u64,
) -> (Verdict, usize) {
    // Suppression applies ONLY to an overall Warn/WarnAck verdict. If the command
    // is Blocked (including a Warn escalated to Block by policy override,
    // correlation, or deferral) the full finding set is always shown so the user
    // sees WHY it was blocked, even on a repeat. This also keeps suppress_check
    // (and its cooldown side effect) out of the Block path entirely.
    if !matches!(effective.action, Action::Warn | Action::WarnAck) {
        return (effective.clone(), 0);
    }
    // Distinct (rule_id, target) pairs whose action-class is Warn/WarnAck only.
    // Order-preserving so suppress_check is invoked deterministically.
    let mut pairs: Vec<(String, Option<String>)> = Vec::new();
    for f in &effective.findings {
        // Classify the finding ALONE: only Warn/WarnAck-class findings are
        // candidates. High/Critical (Block) and Info (Allow) are never suppressed.
        if !matches!(
            action_from_findings(std::slice::from_ref(f)),
            Action::Warn | Action::WarnAck
        ) {
            continue;
        }
        let rule_id = f.rule_id.to_string();
        // Primary target/domain if one is readily available on the finding's
        // evidence (scopes the cooldown per-domain, matching `cooldown_key`).
        let target = tirith_core::session_warnings::extract_domains_from_evidence(&f.evidence)
            .into_iter()
            .next();
        if !pairs.iter().any(|(r, t)| r == &rule_id && t == &target) {
            pairs.push((rule_id, target));
        }
    }

    // Call suppress_check ONCE per distinct pair (it mutates session state), and
    // remember which pairs are now suppressed.
    let mut suppressed: Vec<(String, Option<String>)> = Vec::new();
    for (rule_id, target) in &pairs {
        if tirith_core::session_warnings::suppress_check(
            session_id,
            rule_id,
            target.as_deref(),
            cooldown_secs,
        ) {
            suppressed.push((rule_id.clone(), target.clone()));
        }
    }

    // Fast path: nothing suppressed, so hand back a clone unchanged.
    if suppressed.is_empty() {
        return (effective.clone(), 0);
    }

    let mut display = effective.clone();
    let before = display.findings.len();
    display.findings.retain(|f| {
        // Keep everything that is not a suppressed Warn/WarnAck candidate. A
        // Block/Critical/Info finding is never in `suppressed`, so it always stays.
        if !matches!(
            action_from_findings(std::slice::from_ref(f)),
            Action::Warn | Action::WarnAck
        ) {
            return true;
        }
        let rule_id = f.rule_id.to_string();
        let target = tirith_core::session_warnings::extract_domains_from_evidence(&f.evidence)
            .into_iter()
            .next();
        !suppressed
            .iter()
            .any(|(r, t)| r == &rule_id && t == &target)
    });
    let hidden = before - display.findings.len();
    (display, hidden)
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    cmd: &str,
    shell: &str,
    json: bool,
    non_interactive: bool,
    interactive_flag: bool,
    approval_check: bool,
    strict_warn: bool,
    no_daemon: bool,
    warn_only: bool,
    defer: bool,
    offline: bool,
    suggest_safe_command: bool,
    card: Option<String>,
) -> i32 {
    // When clap left the positional empty and this is NOT the `--approval-check`
    // path (which has its own no-input contract below), accept the command from
    // piped stdin so `echo 'curl x | bash' | tirith check` works. Only read when
    // stdin is NOT a terminal, so an interactive `tirith check` with no argv still
    // returns silently rather than blocking on a TTY. Mirrors paste.rs's 1 MiB cap.
    let stdin_cmd: String;
    let cmd: &str = if cmd.trim().is_empty() && !approval_check && !std::io::stdin().is_terminal() {
        match crate::cli::read_stdin_capped(1024 * 1024) {
            Ok(bytes) => {
                stdin_cmd = String::from_utf8_lossy(&bytes).into_owned();
                &stdin_cmd
            }
            Err(e) => {
                // Fail CLOSED: an unreadable or OVER-LIMIT stream must never fall
                // through to a clean "no issues" verdict on a truncated command.
                eprintln!("tirith: cannot analyze piped input: {e}");
                return 1;
            }
        }
    } else {
        cmd
    };

    if cmd.trim().is_empty() {
        if approval_check {
            match tirith_core::approval::write_no_approval_file() {
                Ok(path) => {
                    println!("{}", path.display());
                    return 0;
                }
                Err(e) => {
                    eprintln!("tirith: failed to write approval file: {e}");
                    return 1;
                }
            }
        }
        return 0;
    }

    let shell_type = match shell.parse::<ShellType>() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("tirith: warning: unknown shell '{shell}', falling back to posix");
            ShellType::Posix
        }
    };

    let interactive = if interactive_flag {
        true
    } else if non_interactive {
        false
    } else if let Ok(val) = std::env::var("TIRITH_INTERACTIVE") {
        val == "1"
    } else {
        is_terminal::is_terminal(std::io::stderr())
    };

    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());

    // Check TIRITH=0 bypass early so it works regardless of daemon/local path.
    let bypass_requested = std::env::var("TIRITH")
        .ok()
        .map(|v| v == "0")
        .unwrap_or(false);

    // Must run before any early return so hooks calling `--approval-check` still
    // trigger updates. `--offline`/`TIRITH_OFFLINE` makes this a guaranteed no-op.
    crate::cli::threatdb_cmd::maybe_background_update(offline);

    let session_id = tirith_core::session::resolve_session_id();

    // M4 item 8: best-effort origin attribution, stamped on the verdict so
    // post-processing and audit agree. Consulted via `apply_agent_rules` against
    // `agent_rules.deny`. NOTE: the `TIRITH=0` bypass branch below skips
    // `post_process_verdict`, so `agent_rules.deny` does not enforce under bypass.
    let origin = tirith_core::agent_origin::resolve_cli_origin(interactive);

    // M11 ch1 — a `--card <path>` sidecar is daemon-unsupported (v1), so it forces
    // the local analysis path just like `--no-daemon`.
    let use_daemon = !approval_check && !no_daemon && card.is_none();

    // Local paths return the engine's policy to avoid a redundant
    // Policy::discover(); the daemon path returns None (analysis was server-side).
    let (mut raw_verdict, engine_policy) = if use_daemon {
        if let Some(resp) =
            crate::cli::daemon::try_daemon_check(cmd, shell, cwd.as_deref(), interactive)
        {
            if let Some(ref raw_findings) = resp.raw_findings {
                let raw_action_parsed = resp
                    .raw_action
                    .as_deref()
                    .and_then(parse_action)
                    .unwrap_or(resp.action);
                (
                    tirith_core::verdict::Verdict {
                        action: raw_action_parsed,
                        findings: raw_findings.clone(),
                        tier_reached: resp.tier_reached,
                        bypass_requested,
                        bypass_honored: resp.bypass_honored,
                        bypass_available: resp.bypass_available,
                        interactive_detected: interactive,
                        policy_path_used: resp.policy_path_used,
                        timings_ms: resp.timings_ms,
                        urls_extracted_count: resp.urls_extracted_count,
                        requires_approval: None,
                        approval_timeout_secs: None,
                        approval_fallback: None,
                        approval_rule: None,
                        approval_description: None,
                        escalation_reason: None,
                        agent_origin: None,
                        // M11 ch2 — matched `allowed[]` name carried across the
                        // daemon boundary so the audit annotation survives. A
                        // pre-upgrade daemon omits it; serde defaults to None.
                        manifest_allowed_match: resp.manifest_allowed_match.clone(),
                    },
                    None,
                )
            } else {
                // Pre-upgrade daemon without raw-findings support — run locally.
                eprintln!(
                    "tirith: daemon does not support raw findings — falling back to local analysis"
                );
                let ctx = AnalysisContext {
                    input: cmd.to_string(),
                    shell: shell_type,
                    scan_context: ScanContext::Exec,
                    raw_bytes: None,
                    interactive,
                    cwd: cwd.clone(),
                    file_path: None,
                    repo_root: None,
                    is_config_override: false,
                    clipboard_html: None,
                    card_ref: card.clone(),
                    clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
                };
                let (v, p) = engine::analyze_returning_policy(&ctx);
                (v, Some(p))
            }
        } else {
            let ctx = AnalysisContext {
                input: cmd.to_string(),
                shell: shell_type,
                scan_context: ScanContext::Exec,
                raw_bytes: None,
                interactive,
                cwd: cwd.clone(),
                file_path: None,
                repo_root: None,
                is_config_override: false,
                clipboard_html: None,
                card_ref: card.clone(),
                clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
            };
            let (v, p) = engine::analyze_returning_policy(&ctx);
            (v, Some(p))
        }
    } else {
        let ctx = AnalysisContext {
            input: cmd.to_string(),
            shell: shell_type,
            scan_context: ScanContext::Exec,
            raw_bytes: None,
            interactive,
            cwd: cwd.clone(),
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
            card_ref: card.clone(),
            clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
        };
        let (v, p) = engine::analyze_returning_policy(&ctx);
        (v, Some(p))
    };

    // Stamp the resolved origin so every later step sees it; `engine::analyze`
    // does not know the caller's identity by design, the CLI does.
    raw_verdict.agent_origin = Some(origin);

    // Bypass path audits and returns without post-processing.
    if raw_verdict.bypass_honored {
        let policy =
            engine_policy.unwrap_or_else(|| tirith_core::policy::Policy::discover(cwd.as_deref()));
        let event_id = uuid::Uuid::new_v4().to_string();
        // Best-effort audit: a write failure must not change the exit code.
        let _ = tirith_core::audit::log_verdict(
            &raw_verdict,
            cmd,
            None,
            Some(event_id),
            &policy.dlp_custom_patterns,
        );
        return 0;
    }

    let ran_locally = engine_policy.is_some();
    let policy =
        engine_policy.unwrap_or_else(|| tirith_core::policy::Policy::discover(cwd.as_deref()));
    crate::cli::warn_repo_policy_neutralized(&policy);

    if ran_locally {
        // Surface a bad `injection_seeds_custom` regex the local engine compiled
        // and dropped here (the daemon path surfaces its own at the server side).
        crate::cli::warn_bad_injection_seeds(&policy);
        let runtime_findings = tirith_core::threatdb_api::enrich_command(
            cmd,
            shell_type,
            &policy.threat_intel,
            RuntimeThreatMode::Inline,
        );
        if !runtime_findings.is_empty() {
            raw_verdict.findings.extend(runtime_findings);
            raw_verdict.action =
                upgraded_action_from_findings(&raw_verdict.findings, raw_verdict.action);
        }
    }

    // Snapshot raw action + rule ids before post-processing so the audit log
    // can record both raw and effective verdicts (for policy-override visibility).
    let raw_action_str = format!("{:?}", raw_verdict.action);
    let raw_rule_ids: Vec<String> = raw_verdict
        .findings
        .iter()
        .map(|f| f.rule_id.to_string())
        .collect();

    let effective = tirith_core::escalation::post_process_verdict(
        &raw_verdict,
        &policy,
        cmd,
        &session_id,
        CallerContext::Cli,
    );

    let event_id = uuid::Uuid::new_v4().to_string();
    // Best-effort audit: a write failure must not change the exit code.
    let _ = tirith_core::audit::log_verdict_with_raw(
        &effective,
        cmd,
        None,
        Some(event_id),
        &policy.dlp_custom_patterns,
        Some(raw_action_str),
        Some(raw_rule_ids),
    );

    // Reconstruct ApprovalMetadata from verdict fields set by apply_approval — do
    // NOT re-call check_approval on filtered findings (paranoia filtering may have
    // removed the causal finding).
    if approval_check {
        if effective.requires_approval == Some(true) {
            let meta = tirith_core::approval::ApprovalMetadata {
                requires_approval: true,
                timeout_secs: effective.approval_timeout_secs.unwrap_or(0),
                fallback: effective
                    .approval_fallback
                    .clone()
                    .unwrap_or_else(|| "block".to_string()),
                rule_id: effective
                    .approval_rule
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                description: effective.approval_description.clone().unwrap_or_default(),
            };
            match tirith_core::approval::write_approval_file(&meta) {
                Ok(path) => {
                    println!("{}", path.display());
                }
                Err(e) => {
                    eprintln!("tirith: failed to write approval file: {e}");
                    return 1;
                }
            }
        } else {
            match tirith_core::approval::write_no_approval_file() {
                Ok(path) => {
                    println!("{}", path.display());
                }
                Err(e) => {
                    eprintln!("tirith: failed to write approval file: {e}");
                    return 1;
                }
            }
        }
    }

    // Skip auto-checkpoint when non-interactive: checkpoint::create() synchronously
    // traverses the whole cwd (seconds on large dirs) and hooks need fast responses.
    if interactive
        && effective.action != Action::Block
        && tirith_core::checkpoint::should_auto_checkpoint(cmd)
    {
        if let Some(cwd_val) = &cwd {
            let cwd_owned = cwd_val.clone();
            let cmd_owned = cmd.to_string();
            std::thread::spawn(move || {
                if let Err(e) =
                    tirith_core::checkpoint::create(&[cwd_owned.as_str()], Some(&cmd_owned))
                {
                    eprintln!("tirith: auto-checkpoint failed (non-fatal): {e}");
                } else {
                    // Purge old checkpoints to prevent unbounded disk growth.
                    let config = tirith_core::checkpoint::CheckpointConfig::default();
                    if let Err(e) = tirith_core::checkpoint::purge(&config) {
                        eprintln!("tirith: checkpoint purge failed (non-fatal): {e}");
                    }
                }
            });
        }
    }

    if effective.action != Action::Allow {
        last_trigger::write_last_trigger(&effective, cmd, &policy.dlp_custom_patterns);
    }

    if !policy.webhooks.is_empty() {
        tirith_core::webhook::dispatch(
            &effective,
            cmd,
            &policy.webhooks,
            &policy.dlp_custom_patterns,
        );
    }

    // In --approval-check mode, stdout holds ONLY the temp-file path(s) so
    // hooks can parse it line-by-line. Human output must go to stderr.
    if approval_check {
        // W6: collapse repeated Warn/WarnAck findings in the DISPLAY only. The
        // full `effective` verdict above already drove the action, exit code,
        // audit log, ack file, last_trigger, and webhook; only this rendering is
        // filtered. No per-rule cooldown field exists on Policy, so all rules use
        // the default window.
        let (display, suppressed_count) = build_display_verdict(
            &effective,
            &session_id,
            tirith_core::suppression::DEFAULT_COOLDOWN_SECS,
        );
        if output::write_human(&display, warn_only, std::io::stderr().lock()).is_err() {
            eprintln!("tirith: failed to write approval output");
        }
        // If every displayable warning was collapsed, surface one compact notice
        // (same stream `write_human` used here: stderr in approval-check mode).
        if display.findings.is_empty() && suppressed_count > 0 {
            eprintln!(
                "tirith: {suppressed_count} repeated warning(s) suppressed this session (run `tirith warnings`)"
            );
        }

        // Mode B (hook-driven strict_warn): write warn-ack temp file and exit 3.
        // Old hooks without warn-ack support treat rc=3 as "unexpected" → fail open.
        if effective.action == Action::Warn && (strict_warn || policy.strict_warn) {
            let max_sev = effective
                .findings
                .iter()
                .map(|f| f.severity)
                .max()
                .unwrap_or(tirith_core::verdict::Severity::Low);
            match tirith_core::approval::write_warn_ack_file(effective.findings.len(), &max_sev) {
                Ok(path) => {
                    // Warn-ack path goes on a NEW line after the approval path
                    // already printed; hooks read line 1 = approval, line 2 = warn-ack.
                    println!("{}", path.display());
                }
                Err(e) => {
                    eprintln!("tirith: failed to write warn-ack file: {e}");
                    return 1;
                }
            }
            return tirith_core::verdict::Action::WarnAck.exit_code();
        }

        return effective.action.exit_code();
    }

    // Safe-command suggestions are advisory only: computed when opted-in AND the
    // verdict flagged something; they never influence the action or exit code.
    let safe_suggestions: Vec<tirith_core::safe_command::SafeSuggestion> =
        if suggest_safe_command && effective.action != Action::Allow {
            tirith_core::safe_command::suggest(cmd, shell_type, &effective)
        } else {
            Vec::new()
        };

    if json {
        let suggestions_opt = if suggest_safe_command {
            Some(safe_suggestions.as_slice())
        } else {
            None
        };
        if output::write_json_with_suggestions(
            &effective,
            &policy.dlp_custom_patterns,
            suggestions_opt,
            std::io::stdout().lock(),
        )
        .is_err()
        {
            eprintln!("tirith: failed to write JSON output");
        }
    } else {
        // W6: collapse repeated Warn/WarnAck findings in the DISPLAY only; the
        // full `effective` verdict already drove every enforcement side effect
        // above. `write_human_auto` writes the human verdict to stderr.
        let (display, suppressed_count) = build_display_verdict(
            &effective,
            &session_id,
            tirith_core::suppression::DEFAULT_COOLDOWN_SECS,
        );
        if output::write_human_auto(&display, warn_only).is_err() {
            eprintln!("tirith: failed to write output");
        }
        // If every displayable warning was collapsed, surface one compact notice
        // on the same stream `write_human_auto` used (stderr).
        if display.findings.is_empty() && suppressed_count > 0 {
            eprintln!(
                "tirith: {suppressed_count} repeated warning(s) suppressed this session (run `tirith warnings`)"
            );
        }
        if output::write_safe_suggestions(&safe_suggestions, std::io::stderr().lock()).is_err() {
            eprintln!("tirith: failed to write safe-command suggestions");
        }
        // On a clean human verdict from DIRECT CLI use, confirm nothing was found
        // (`write_human_auto` is silent on no findings). Gated OFF for hook
        // invocations — a per-keystroke "no issues" would be noise — detected via
        // the `_TIRITH_HOOK` / `_TIRITH_BASH_INTERNAL` markers the shell hooks set.
        // `note` is already `--quiet`-aware. Never emitted in the JSON branch.
        if effective.findings.is_empty()
            && std::env::var("_TIRITH_HOOK").is_err()
            && std::env::var("_TIRITH_BASH_INTERNAL").is_err()
        {
            crate::cli::note("tirith: no issues");
        }
    }

    let exit_code = effective.action.exit_code();

    // W8 deferred outcome (opt-in via --defer or TIRITH_DEFER=1): in a no-TTY /
    // no-approval context, a NON-critical block is recorded in the pending
    // registry and returns exit 4 ("blocked, pending review") instead of a hard
    // exit-1 block. CRITICAL always hard-blocks. Default behavior is unchanged.
    let deferred_opt_in = defer || std::env::var("TIRITH_DEFER").ok().as_deref() == Some("1");
    if deferred_opt_in && !effective.interactive_detected && exit_code == Action::Block.exit_code()
    {
        let max_sev = effective.findings.iter().map(|f| f.severity).max();
        if max_sev != Some(tirith_core::verdict::Severity::Critical) {
            let decision = tirith_core::pending::PendingDecision {
                id: String::new(),
                created_at: chrono::Utc::now().to_rfc3339(),
                source: tirith_core::pending::PendingSource::Deferred,
                rule_ids: effective
                    .findings
                    .iter()
                    .map(|f| f.rule_id.to_string())
                    .collect(),
                // Documented as a lowercase string (pending.rs); Severity::Display
                // renders UPPERCASE, so lowercase it here at the sole producer.
                severity: max_sev
                    .map(|s| s.to_string().to_lowercase())
                    .unwrap_or_default(),
                // SECURITY: this is persisted to state_dir()/pending.json and
                // later surfaced verbatim by `tirith pending list` / `export`, so
                // a raw truncation would leak any token/credential in the command.
                // Apply the SAME DLP redaction the audit log uses (built-in +
                // policy custom patterns) on the FULL command, THEN truncate, so a
                // secret straddling the 120-char boundary is still scrubbed.
                command_redacted: tirith_core::util::truncate_bytes(
                    &tirith_core::redact::redact_command_text(cmd, &policy.dlp_custom_patterns),
                    120,
                ),
                status: tirith_core::pending::PendingStatus::Pending,
                resolved_at: None,
                resolved_by: None,
                reason: None,
                refs: std::collections::BTreeMap::new(),
            };
            // Fail CLOSED: only downgrade the hard block to a soft exit-4 pending
            // outcome when the pending entry actually persisted. If register fails
            // (no state dir, read-only FS, disk full, serialize error) the block
            // must STAND at exit 1, never a click-through exit 4 that points the
            // user at a pending entry that was never recorded.
            match tirith_core::pending::register(decision) {
                Ok(_) => {
                    tirith_core::audit::log_hook_event(
                        "check",
                        "defer",
                        "deferred_block",
                        None,
                        Some("exit=4"),
                    );
                    if !json {
                        eprintln!(
                            "tirith: blocked, pending review (deferred). Resolve with `tirith pending`."
                        );
                    }
                    return 4;
                }
                Err(e) => {
                    tirith_core::audit::log_hook_event(
                        "check",
                        "defer",
                        "deferred_block_failed",
                        None,
                        Some("exit=1"),
                    );
                    eprintln!("tirith: defer failed to record pending entry ({e}); hard-blocking.");
                    // Fall through to the normal block exit path below.
                }
            }
        }
    }

    // Mode A (direct CLI strict_warn): prompt interactively. In non-interactive
    // mode we fall through to exit code 2 for backward compatibility.
    if exit_code == 2 && (strict_warn || policy.strict_warn) && interactive {
        eprint!(
            "tirith: proceed with {} warning(s)? [y/N] ",
            effective.findings.len()
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        if matches!(input.trim(), "y" | "Y" | "yes" | "Yes") {
            return 0;
        }
        return 1;
    }

    exit_code
}

/// Parse a debug-formatted Action string back into an Action.
fn parse_action(s: &str) -> Option<Action> {
    match s {
        "Allow" => Some(Action::Allow),
        "Warn" => Some(Action::Warn),
        "WarnAck" => Some(Action::WarnAck),
        "Block" => Some(Action::Block),
        _ => None,
    }
}
