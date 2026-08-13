use std::io::{IsTerminal, Write as _};
use std::time::Duration;

#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::fd::{AsRawFd as _, FromRawFd as _, RawFd};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
#[cfg(unix)]
use std::sync::{Mutex, MutexGuard, OnceLock};
#[cfg(unix)]
use std::time::Instant;

use crate::cli::last_trigger;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::escalation::CallerContext;
use tirith_core::execution_state::{
    self, PreparedExecution, ShellApprovalOutcome, ShellReceiptChannel, ShellReceiptContext,
};
use tirith_core::extract::ScanContext;
use tirith_core::output;
use tirith_core::threatdb_api::RuntimeThreatMode;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{action_from_findings, upgraded_action_from_findings, Action, Verdict};

/// Once a check dispatches webhooks, every return path waits for their bounded
/// best-effort delivery. A lexical guard avoids missing protocol/approval/
/// deferral early returns as new branches are added.
struct PendingWebhookGuard;

impl Drop for PendingWebhookGuard {
    fn drop(&mut self) {
        tirith_core::webhook::wait_for_pending_webhooks(Duration::from_secs(5));
    }
}

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
    shell_type: ShellType,
    json: bool,
    non_interactive: bool,
    interactive_flag: bool,
    approval_check: bool,
    execution_receipt: Option<ShellReceiptChannel>,
    strict_warn: bool,
    no_daemon: bool,
    warn_only: bool,
    defer: bool,
    offline: bool,
    suggest_safe_command: bool,
    card: Option<String>,
) -> i32 {
    let shell_name = match shell_type {
        ShellType::Posix => "posix",
        ShellType::Fish => "fish",
        ShellType::PowerShell => "powershell",
        ShellType::Cmd => "cmd",
    };
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
        if approval_check && execution_receipt.is_none() {
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
        if execution_receipt.is_some() {
            eprintln!("tirith: shell execution receipt command is empty; command blocked");
            return 1;
        }
        return 0;
    }

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
    // the local analysis path just like `--no-daemon`. Safe-command suggestions
    // also force local analysis: candidate verification must reuse the exact
    // policy snapshot returned with the original verdict, never combine a daemon
    // verdict with a separately discovered client policy.
    let use_daemon = !approval_check && !no_daemon && card.is_none() && !suggest_safe_command;

    // Local paths return the engine's policy to avoid a redundant
    // Policy::discover(); the daemon path returns None (analysis was server-side).
    let (mut raw_verdict, engine_policy) = if use_daemon {
        if let Some(resp) = crate::cli::daemon::try_daemon_check(
            cmd,
            shell_name,
            cwd.as_deref(),
            interactive,
            offline,
        ) {
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
        let (v, p) = if execution_receipt.is_some() {
            // A durable receipt must freeze every effective policy overlay even
            // for a clean command that the ordinary hot path could return at
            // tier 1. Consumption performs the same complete re-analysis.
            engine::analyze_force_full_returning_policy(&ctx)
        } else {
            engine::analyze_returning_policy(&ctx)
        };
        (v, Some(p))
    };

    // Stamp the resolved origin so every later step sees it; `engine::analyze`
    // does not know the caller's identity by design, the CLI does.
    raw_verdict.agent_origin = Some(origin);

    // Bypass path audits and returns without post-processing.
    if raw_verdict.bypass_honored && execution_receipt.is_none() {
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
    // Surface an invalid `injection_seeds_custom` regex (compiled and silently
    // dropped during analysis) to the operator. UNCONDITIONAL by design: on the
    // local path `policy` is the engine's; on the daemon path it is the client-side
    // `Policy::discover` resolved just above (the daemon server does NOT surface bad
    // seeds), so the operator sees the warning on either path. Cheap: few seeds.
    crate::cli::warn_bad_injection_seeds(&policy);

    if ran_locally {
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

    let mut receipt_prepared: Option<PreparedExecution> = None;
    let effective = if execution_receipt.is_some() {
        // The receipt path must retain a proof-carrying draft rather than the
        // diagnostic compatibility wrapper. A CLI --strict-warn override is
        // folded into this exact policy snapshot so the receipt independently
        // freezes and later requires the acknowledgement.
        let mut execution_policy = policy.clone();
        if strict_warn {
            execution_policy.strict_warn = true;
        }
        let prepared = match execution_state::prepare_execution(
            &raw_verdict,
            &execution_policy,
            cmd,
            &session_id,
            CallerContext::Cli,
            shell_type,
            execution_state::DEFAULT_DRAFT_TTL,
            execution_state::DEFAULT_GATE_LOCK_TIMEOUT,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                eprintln!("tirith: failed to prepare shell execution receipt: {error}");
                return 1;
            }
        };
        let effective = prepared.verdict().clone();
        receipt_prepared = Some(prepared);
        effective
    } else {
        tirith_core::escalation::post_process_verdict(
            &raw_verdict,
            &policy,
            cmd,
            &session_id,
            CallerContext::Cli,
        )
    };
    // `tirith check` is a preflight/diagnostic boundary: a zero exit only permits
    // the shell or caller to execute later, and this process never observes that
    // outcome. Do not call `record_executed_verdict_events` here.

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

    let receipt_token = if let Some(channel) = execution_receipt {
        let approval_wait = effective.approval_timeout_secs.unwrap_or(0);
        // Zero means an indefinite approval prompt in the legacy metadata. The
        // durable receipt remains bounded: ten minutes for an indefinite/no
        // timeout interaction, otherwise the frozen timeout plus one minute,
        // capped at the core's one-hour limit.
        let ttl_secs = if approval_wait == 0 {
            10 * 60
        } else {
            approval_wait.saturating_add(60).clamp(5 * 60, 60 * 60)
        };
        let prepared = receipt_prepared
            .as_ref()
            .ok_or_else(|| "shell receipt draft was not retained".to_string());
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                eprintln!("tirith: failed to prepare shell execution receipt: {error}");
                return 1;
            }
        };
        match execution_state::create_shell_execution_receipt(
            prepared,
            channel,
            interactive,
            strict_warn,
            Duration::from_secs(ttl_secs),
        ) {
            Ok(token) => Some(token),
            Err(error) => {
                eprintln!("tirith: failed to create shell execution receipt: {error}");
                return 1;
            }
        }
    } else {
        None
    };

    // Reconstruct ApprovalMetadata from verdict fields set by apply_approval — do
    // NOT re-call check_approval on filtered findings (paranoia filtering may have
    // removed the causal finding).
    if approval_check && execution_receipt.is_none() {
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
            // repo-0214: checkpoint creation must finish before this process
            // returns an executable verdict. A detached worker is terminated at
            // process exit, while a timed wait cannot cancel it safely; either
            // shape could let the destructive command run without a published
            // checkpoint. This path is interactive-only, and creation itself is
            // bounded by the checkpoint entry/file/total-byte budgets.
            match tirith_core::checkpoint::create(&[cwd_val.as_str()], Some(cmd)) {
                Err(e) => eprintln!("tirith: auto-checkpoint failed (non-fatal): {e}"),
                Ok(meta) => {
                    if meta.incomplete {
                        eprintln!(
                            "tirith: auto-checkpoint is incomplete; the destructive command may proceed without a complete snapshot"
                        );
                    }
                    // Purge old checkpoints to prevent unbounded disk growth.
                    let config = tirith_core::checkpoint::CheckpointConfig::default();
                    if let Err(e) = tirith_core::checkpoint::purge(&config) {
                        eprintln!("tirith: checkpoint purge failed (non-fatal): {e}");
                    }
                }
            }
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
    let _pending_webhook_guard = PendingWebhookGuard;

    // Protocol v3 owns every approval / warning-ack interaction in this process.
    // The shell receives only an already-armed receipt token; it never reports a
    // human decision back to Tirith. Legacy --approval-check callers without an
    // execution receipt keep the temp-file stdout contract below unchanged.
    if let (Some(channel), Some(token)) = (execution_receipt, receipt_token.as_deref()) {
        let requires_warn_ack = effective.action == Action::WarnAck
            || (effective.action == Action::Warn && (strict_warn || policy.strict_warn));
        return complete_owned_receipt_check(
            &effective,
            &session_id,
            token,
            channel,
            requires_warn_ack,
            warn_only,
        );
    }

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
            let suggestion_ctx = AnalysisContext {
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
            if ran_locally {
                tirith_core::safe_command::suggest_verified_for_cli_inline_with_policy_and_session(
                    &suggestion_ctx,
                    &policy,
                    &session_id,
                )
            } else {
                // A daemon verdict may include its longer-budget/private-network
                // enrichment. Never replace that producer profile with a local
                // Inline re-analysis at an executable-output boundary.
                tirith_core::safe_command::suggest_verified_with_policy(
                    &suggestion_ctx,
                    &effective,
                    &policy,
                )
            }
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
        if output::write_safe_suggestions(
            &safe_suggestions,
            &policy.dlp_custom_patterns,
            std::io::stderr().lock(),
        )
        .is_err()
        {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptAnswer {
    Accepted,
    Rejected,
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalFallback {
    Allow,
    Warn,
    Block,
}

impl ApprovalFallback {
    fn parse(value: Option<&str>) -> Self {
        match value {
            Some("allow") => Self::Allow,
            Some("warn") => Self::Warn,
            // Missing and malformed frozen metadata must fail closed. Receipt
            // creation independently rejects malformed values, but keeping this
            // boundary conservative prevents a future caller from widening it.
            _ => Self::Block,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }

    fn permits_execution(self) -> bool {
        matches!(self, Self::Allow | Self::Warn)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ApprovalPrompt<'a> {
    timeout: Option<Duration>,
    fallback: ApprovalFallback,
    rule: &'a str,
    description: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiptInteractionRequirements<'a> {
    approval: Option<ApprovalPrompt<'a>>,
    warn_ack_findings: Option<usize>,
}

impl ReceiptInteractionRequirements<'_> {
    fn is_empty(&self) -> bool {
        self.approval.is_none() && self.warn_ack_findings.is_none()
    }
}

fn channel_can_own_interactions(channel: ShellReceiptChannel) -> bool {
    channel != ShellReceiptChannel::BashPreexec
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnedInteractionResolution {
    Authorized {
        approval: Option<ShellApprovalOutcome>,
        warn_acknowledged: bool,
    },
    Blocked,
}

trait ReceiptInteractionIo {
    fn notify(&mut self, message: &str) -> Result<(), String>;
    fn prompt(&mut self, prompt: &str, timeout: Option<Duration>) -> Result<PromptAnswer, String>;
}

fn receipt_interaction_requirements(
    effective: &Verdict,
    requires_warn_ack: bool,
) -> ReceiptInteractionRequirements<'_> {
    let approval = (effective.requires_approval == Some(true)).then(|| ApprovalPrompt {
        timeout: effective
            .approval_timeout_secs
            .filter(|timeout| *timeout > 0)
            .map(Duration::from_secs),
        fallback: ApprovalFallback::parse(effective.approval_fallback.as_deref()),
        rule: effective.approval_rule.as_deref().unwrap_or("unknown"),
        description: effective
            .approval_description
            .as_deref()
            .unwrap_or_default(),
    });
    ReceiptInteractionRequirements {
        approval,
        warn_ack_findings: requires_warn_ack.then_some(effective.findings.len()),
    }
}

fn resolve_owned_interactions(
    requirements: &ReceiptInteractionRequirements<'_>,
    io: &mut impl ReceiptInteractionIo,
) -> Result<OwnedInteractionResolution, String> {
    let mut approval_outcome = None;
    if let Some(approval) = &requirements.approval {
        let rule = crate::cli::sanitize_for_human_output(approval.rule, false);
        io.notify(&format!("tirith: approval required for {rule}"))?;
        if !approval.description.is_empty() {
            let description = crate::cli::sanitize_for_human_output(approval.description, false);
            io.notify(&format!("  {description}"))?;
        }
        let prompt = approval
            .timeout
            .map(|timeout| format!("Approve? ({}s timeout) [y/N] ", timeout.as_secs()))
            .unwrap_or_else(|| "Approve? [y/N] ".to_string());
        let answer = io.prompt(&prompt, approval.timeout)?;
        approval_outcome = Some(match answer {
            PromptAnswer::Accepted => ShellApprovalOutcome::Granted,
            PromptAnswer::Rejected => ShellApprovalOutcome::Rejected,
            PromptAnswer::TimedOut => ShellApprovalOutcome::TimedOut,
        });
        if !matches!(answer, PromptAnswer::Accepted) {
            io.notify(&format!(
                "tirith: approval not granted — fallback: {}",
                approval.fallback.label()
            ))?;
            if !approval.fallback.permits_execution() {
                return Ok(OwnedInteractionResolution::Blocked);
            }
        }
    }

    let mut warn_acknowledged = false;
    if let Some(finding_count) = requirements.warn_ack_findings {
        let answer = io.prompt(
            &format!("tirith: proceed with {finding_count} warning(s)? [y/N] "),
            None,
        )?;
        if !matches!(answer, PromptAnswer::Accepted) {
            io.notify("tirith: warnings not acknowledged — command blocked")?;
            return Ok(OwnedInteractionResolution::Blocked);
        }
        warn_acknowledged = true;
    }

    Ok(OwnedInteractionResolution::Authorized {
        approval: approval_outcome,
        warn_acknowledged,
    })
}

fn render_receipt_display(
    effective: &Verdict,
    session_id: &str,
    warn_only: bool,
    mut writer: impl std::io::Write,
) -> Result<(), String> {
    let (display, suppressed_count) = build_display_verdict(
        effective,
        session_id,
        tirith_core::suppression::DEFAULT_COOLDOWN_SECS,
    );
    output::write_human(&display, warn_only, &mut writer)
        .map_err(|error| format!("write shell receipt verdict: {error}"))?;
    if display.findings.is_empty() && suppressed_count > 0 {
        writeln!(
            writer,
            "tirith: {suppressed_count} repeated warning(s) suppressed this session (run `tirith warnings`)"
        )
        .map_err(|error| format!("write shell receipt suppression notice: {error}"))?;
    }
    writer
        .flush()
        .map_err(|error| format!("flush shell receipt verdict: {error}"))
}

fn discard_receipt_best_effort(token: &str, channel: ShellReceiptChannel) {
    if let Err(error) = execution_state::discard_shell_execution_receipt(token, channel) {
        eprintln!("tirith: failed to discard shell execution receipt: {error}");
    }
}

fn armed_receipt_exit_code(
    effective: &Verdict,
    requires_warn_ack: bool,
    _approval: Option<ShellApprovalOutcome>,
) -> i32 {
    if effective.bypass_honored || requires_warn_ack {
        return 0;
    }
    // Approval is an additional gate; satisfying it does not erase an advisory
    // warning. Preserve exit 2 for an executable Warn decision so hooks can keep
    // their warning-specific behavior without owning the interaction.
    match effective.action {
        Action::Allow => 0,
        Action::Warn => 2,
        // WarnAck is represented by requires_warn_ack above. A non-bypassed
        // Block is rejected before arming. Keep impossible states fail closed.
        Action::Block | Action::WarnAck => 1,
    }
}

fn publish_armed_receipt(
    effective: &Verdict,
    token: &str,
    channel: ShellReceiptChannel,
    requires_warn_ack: bool,
    approval: Option<ShellApprovalOutcome>,
    warn_acknowledged: bool,
) -> i32 {
    let exit_code = armed_receipt_exit_code(effective, requires_warn_ack, approval);
    if !matches!(exit_code, 0 | 2) {
        eprintln!("tirith: shell execution receipt reached an inconsistent executable decision");
        discard_receipt_best_effort(token, channel);
        return 1;
    }
    if let Err(error) =
        execution_state::arm_shell_execution_receipt(token, channel, approval, warn_acknowledged)
    {
        eprintln!("tirith: failed to arm shell execution receipt: {error}");
        discard_receipt_best_effort(token, channel);
        return 1;
    }

    let frame = format!("TIRITH_EXECUTION_RECEIPT={token}");
    if let Err(error) = write_stdout_line_with_rollback(&frame, || {
        execution_state::discard_shell_execution_receipt(token, channel)
    }) {
        // An armed bearer that the hook did not receive must not remain live.
        // The helper rolls it back while SIGPIPE is still blocked, before this
        // diagnostic can encounter the same closed output pipe.
        eprintln!("tirith: failed to publish armed shell execution receipt: {error}");
        return 1;
    }
    exit_code
}

fn complete_owned_receipt_check(
    effective: &Verdict,
    session_id: &str,
    token: &str,
    channel: ShellReceiptChannel,
    requires_warn_ack: bool,
    warn_only: bool,
) -> i32 {
    if effective.action == Action::Block && !effective.bypass_honored {
        if let Err(error) =
            render_receipt_display(effective, session_id, warn_only, std::io::stderr().lock())
        {
            eprintln!("tirith: {error}");
        }
        discard_receipt_best_effort(token, channel);
        return 1;
    }

    let requirements = receipt_interaction_requirements(effective, requires_warn_ack);
    if !channel_can_own_interactions(channel) && !requirements.is_empty() {
        if let Err(error) =
            render_receipt_display(effective, session_id, warn_only, std::io::stderr().lock())
        {
            eprintln!("tirith: {error}");
        }
        eprintln!(
            "tirith: Bash preexec cannot safely own approval or warning acknowledgement; command blocked"
        );
        discard_receipt_best_effort(token, channel);
        return 1;
    }

    if requirements.is_empty() {
        if let Err(error) =
            render_receipt_display(effective, session_id, warn_only, std::io::stderr().lock())
        {
            eprintln!("tirith: {error}");
            discard_receipt_best_effort(token, channel);
            return 1;
        }
        return publish_armed_receipt(effective, token, channel, false, None, false);
    }

    #[cfg(unix)]
    let resolution = with_controlling_tty(|tty| {
        render_receipt_display(effective, session_id, warn_only, &mut *tty)?;
        resolve_owned_interactions(&requirements, tty)
    });

    #[cfg(not(unix))]
    let resolution: Result<OwnedInteractionResolution, String> =
        Err("controlling-terminal approval is unsupported on this platform".to_string());

    match resolution {
        Ok(OwnedInteractionResolution::Authorized {
            approval,
            warn_acknowledged,
        }) => publish_armed_receipt(
            effective,
            token,
            channel,
            requires_warn_ack,
            approval,
            warn_acknowledged,
        ),
        Ok(OwnedInteractionResolution::Blocked) => {
            discard_receipt_best_effort(token, channel);
            1
        }
        Err(error) => {
            eprintln!("tirith: shell receipt interaction failed: {error}; command blocked");
            discard_receipt_best_effort(token, channel);
            1
        }
    }
}

#[cfg(unix)]
const OWNED_PROMPT_SIGNALS: [libc::c_int; 5] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGQUIT,
    libc::SIGTSTP,
];

#[cfg(unix)]
static OWNED_PROMPT_SIGNAL_SCOPE: Mutex<()> = Mutex::new(());

#[cfg(unix)]
static OWNED_PROMPT_SIGNAL_PIPE: OnceLock<Result<PromptSignalPipe, String>> = OnceLock::new();

// Set exactly once, before any owned-prompt handler is installed, and never
// changed or closed for the process lifetime. A permanent descriptor avoids a
// handler-vs-close race while process-wide dispositions are being restored.
#[cfg(unix)]
static mut OWNED_PROMPT_SIGNAL_WRITE_FD: libc::c_int = -1;

#[cfg(unix)]
fn prompt_signal_code(signal: libc::c_int) -> Option<u8> {
    match signal {
        libc::SIGINT => Some(1),
        libc::SIGTERM => Some(2),
        libc::SIGHUP => Some(3),
        libc::SIGQUIT => Some(4),
        libc::SIGTSTP => Some(5),
        _ => None,
    }
}

#[cfg(unix)]
fn prompt_signal_from_code(code: u8) -> Option<libc::c_int> {
    match code {
        1 => Some(libc::SIGINT),
        2 => Some(libc::SIGTERM),
        3 => Some(libc::SIGHUP),
        4 => Some(libc::SIGQUIT),
        5 => Some(libc::SIGTSTP),
        _ => None,
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe fn prompt_errno_location() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
))]
unsafe fn prompt_errno_location() -> *mut libc::c_int {
    unsafe { libc::__error() }
}

/// Async-signal-safe relay: encode one managed signal and write one byte to the
/// permanent nonblocking pipe. No allocation, formatting, locking, terminal I/O,
/// or other non-signal-safe work happens here.
#[cfg(unix)]
extern "C" fn owned_prompt_signal_handler(signal: libc::c_int) {
    let Some(code) = prompt_signal_code(signal) else {
        return;
    };
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    let saved_errno = unsafe { *prompt_errno_location() };
    let fd = unsafe { std::ptr::read_volatile(&raw const OWNED_PROMPT_SIGNAL_WRITE_FD) };
    if fd >= 0 {
        let _ = unsafe { libc::write(fd, (&raw const code).cast(), 1) };
    }
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    unsafe {
        *prompt_errno_location() = saved_errno;
    }
}

#[cfg(unix)]
struct PromptSignalPipe {
    reader: File,
    // Kept open permanently. The handler uses the same descriptor number from
    // `OWNED_PROMPT_SIGNAL_WRITE_FD`; this owner prevents its reuse.
    _writer: File,
}

#[cfg(unix)]
impl PromptSignalPipe {
    fn create() -> Result<Self, String> {
        let mut descriptors = [-1; 2];
        if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
            return Err(format!(
                "create owned-prompt signal pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let configure = |fd: RawFd| -> std::io::Result<()> {
            let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if descriptor_flags < 0
                || unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) }
                    < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let status_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if status_flags < 0
                || unsafe { libc::fcntl(fd, libc::F_SETFL, status_flags | libc::O_NONBLOCK) } < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        };
        if let Err(error) = configure(descriptors[0]).and_then(|()| configure(descriptors[1])) {
            unsafe {
                libc::close(descriptors[0]);
                libc::close(descriptors[1]);
            }
            return Err(format!("configure owned-prompt signal pipe: {error}"));
        }
        let reader = unsafe { File::from_raw_fd(descriptors[0]) };
        let writer = unsafe { File::from_raw_fd(descriptors[1]) };
        unsafe {
            std::ptr::write_volatile(&raw mut OWNED_PROMPT_SIGNAL_WRITE_FD, writer.as_raw_fd());
        }
        Ok(Self {
            reader,
            _writer: writer,
        })
    }

    fn global() -> Result<&'static Self, String> {
        OWNED_PROMPT_SIGNAL_PIPE
            .get_or_init(Self::create)
            .as_ref()
            .map_err(Clone::clone)
    }

    fn reader_fd(&self) -> RawFd {
        self.reader.as_raw_fd()
    }

    fn drain(&self) -> Result<Option<libc::c_int>, String> {
        let mut first = None;
        let mut buffer = [0u8; 64];
        loop {
            let read = unsafe {
                libc::read(
                    self.reader.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if read > 0 {
                for code in &buffer[..read as usize] {
                    let signal = prompt_signal_from_code(*code).ok_or_else(|| {
                        "owned-prompt signal pipe contained an invalid frame".to_string()
                    })?;
                    first.get_or_insert(signal);
                }
                continue;
            }
            if read == 0 {
                return Err("owned-prompt signal pipe closed unexpectedly".to_string());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(first);
            }
            return Err(format!("read owned-prompt signal pipe: {error}"));
        }
    }
}

#[cfg(unix)]
struct ThreadSignalMask {
    previous: libc::sigset_t,
    active: bool,
}

#[cfg(unix)]
impl ThreadSignalMask {
    fn block(signals: &[libc::c_int]) -> Result<Self, String> {
        let mut blocked = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        if unsafe { libc::sigemptyset(&mut blocked) } != 0 {
            return Err(format!(
                "initialize signal mask: {}",
                std::io::Error::last_os_error()
            ));
        }
        for signal in signals {
            if unsafe { libc::sigaddset(&mut blocked, *signal) } != 0 {
                return Err(format!(
                    "add signal to mask: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let result = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous) };
        if result != 0 {
            return Err(format!(
                "block owned-prompt signals: {}",
                std::io::Error::from_raw_os_error(result)
            ));
        }
        Ok(Self {
            previous,
            active: true,
        })
    }

    fn restore(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        let result = unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut())
        };
        if result != 0 {
            return Err(format!(
                "restore signal mask: {}",
                std::io::Error::from_raw_os_error(result)
            ));
        }
        self.active = false;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for ThreadSignalMask {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(all(unix, any(test, not(target_os = "macos"))))]
fn signal_is_pending(signal: libc::c_int) -> Result<bool, String> {
    let mut pending = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    if unsafe { libc::sigpending(&mut pending) } != 0 {
        return Err(format!(
            "inspect pending signals: {}",
            std::io::Error::last_os_error()
        ));
    }
    let member = unsafe { libc::sigismember(&pending, signal) };
    match member {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(format!(
            "inspect pending signal membership: {}",
            std::io::Error::last_os_error()
        )),
    }
}

/// Linux/Unix thread-local SIGPIPE suppression for one stdout publication.
/// Blocking makes a closed pipe surface as EPIPE instead of terminating between
/// arming state and rollback. Darwin can deliver pipe SIGPIPE to another
/// unblocked thread, so macOS uses the descriptor-scoped guard below instead.
#[cfg(all(unix, not(target_os = "macos")))]
struct SigpipeDeliveryGuard {
    mask: ThreadSignalMask,
    pending_before: bool,
}

#[cfg(all(unix, not(target_os = "macos")))]
impl SigpipeDeliveryGuard {
    fn begin(_fd: RawFd) -> Result<Self, String> {
        let mask = ThreadSignalMask::block(&[libc::SIGPIPE])?;
        let pending_before = signal_is_pending(libc::SIGPIPE)?;
        Ok(Self {
            mask,
            pending_before,
        })
    }

    fn finish(&mut self) -> Result<(), String> {
        let pending_after = signal_is_pending(libc::SIGPIPE)?;
        if pending_after && !self.pending_before {
            let mut set = unsafe { std::mem::zeroed::<libc::sigset_t>() };
            if unsafe { libc::sigemptyset(&mut set) } != 0
                || unsafe { libc::sigaddset(&mut set, libc::SIGPIPE) } != 0
            {
                return Err(format!(
                    "prepare pending SIGPIPE consumption: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut received = 0;
            let waited = unsafe { libc::sigwait(&set, &mut received) };
            if waited != 0 || received != libc::SIGPIPE {
                return Err(if waited != 0 {
                    format!(
                        "consume delivery SIGPIPE: {}",
                        std::io::Error::from_raw_os_error(waited)
                    )
                } else {
                    format!("consume delivery SIGPIPE returned signal {received}")
                });
            }
        }
        self.mask.restore()
    }
}

// Darwin's F_SETNOSIGPIPE/F_GETNOSIGPIPE values from <sys/fcntl.h>. The libc
// crate does not currently expose them for Apple targets.
#[cfg(target_os = "macos")]
const DARWIN_F_SETNOSIGPIPE: libc::c_int = 73;
#[cfg(target_os = "macos")]
const DARWIN_F_GETNOSIGPIPE: libc::c_int = 74;

#[cfg(target_os = "macos")]
static SIGPIPE_DESCRIPTOR_SCOPE: Mutex<()> = Mutex::new(());

/// Descriptor-scoped SIGPIPE suppression for Darwin. Unlike a thread signal
/// mask, F_SETNOSIGPIPE prevents a failed write from generating a process-wide
/// signal that the kernel may deliver to another runtime/test thread.
#[cfg(target_os = "macos")]
struct SigpipeDescriptorGuard {
    fd: RawFd,
    previous: libc::c_int,
    active: bool,
    _scope: MutexGuard<'static, ()>,
}

#[cfg(target_os = "macos")]
impl SigpipeDescriptorGuard {
    fn begin(fd: RawFd) -> Result<Self, String> {
        if fd < 0 {
            return Err("SIGPIPE suppression descriptor is negative".to_string());
        }
        let scope = SIGPIPE_DESCRIPTOR_SCOPE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = unsafe { libc::fcntl(fd, DARWIN_F_GETNOSIGPIPE) };
        if previous < 0 {
            return Err(format!(
                "inspect descriptor SIGPIPE policy: {}",
                std::io::Error::last_os_error()
            ));
        }
        if unsafe { libc::fcntl(fd, DARWIN_F_SETNOSIGPIPE, 1) } < 0 {
            return Err(format!(
                "suppress descriptor SIGPIPE: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            fd,
            previous,
            active: true,
            _scope: scope,
        })
    }

    fn finish(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        if unsafe { libc::fcntl(self.fd, DARWIN_F_SETNOSIGPIPE, self.previous) } < 0 {
            return Err(format!(
                "restore descriptor SIGPIPE policy: {}",
                std::io::Error::last_os_error()
            ));
        }
        self.active = false;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Drop for SigpipeDescriptorGuard {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
type SigpipePublicationGuard = SigpipeDeliveryGuard;
#[cfg(target_os = "macos")]
type SigpipePublicationGuard = SigpipeDescriptorGuard;

#[cfg(unix)]
fn write_stdout_line_sigpipe_safe(line: &str) -> Result<(), String> {
    let mut guard = SigpipePublicationGuard::begin(libc::STDOUT_FILENO)?;
    let write_result = {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{line}").and_then(|()| stdout.flush())
    };
    let finish_result = guard.finish();
    match (write_result, finish_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(format!("publish stdout frame: {error}")),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(signal_error)) => {
            Err(format!("publish stdout frame: {error}; {signal_error}"))
        }
    }
}

#[cfg(not(unix))]
fn write_stdout_line_sigpipe_safe(line: &str) -> Result<(), String> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{line}")
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("publish stdout frame: {error}"))
}

#[cfg(unix)]
fn publish_with_sigpipe_rollback(
    fd: RawFd,
    publish: impl FnOnce() -> std::io::Result<()>,
    rollback: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let mut rollback = Some(rollback);
    let mut guard = match SigpipePublicationGuard::begin(fd) {
        Ok(guard) => guard,
        Err(mask_error) => {
            let rollback_result = rollback
                .take()
                .expect("stdout rollback is available before publication")(
            );
            return match rollback_result {
                Ok(()) => Err(mask_error),
                Err(rollback_error) => Err(format!("{mask_error}; rollback: {rollback_error}")),
            };
        }
    };
    let write_result = publish();
    let mut rollback_result = if write_result.is_err() {
        Some(rollback
            .take()
            .expect("stdout rollback is available after a write failure")(
        ))
    } else {
        None
    };
    // On EPIPE, rollback above runs while SIGPIPE is still blocked and before
    // any diagnostic is attempted. Only then consume this write's pending
    // SIGPIPE and restore the caller's exact mask.
    let finish_result = guard.finish();
    if finish_result.is_err() && rollback_result.is_none() {
        rollback_result = Some(rollback
            .take()
            .expect("stdout rollback is available after signal cleanup failure")(
        ));
    }
    match (write_result, rollback_result, finish_result) {
        (Ok(()), None, Ok(())) => Ok(()),
        (Err(write_error), Some(Ok(())), Ok(())) => {
            Err(format!("publish stdout frame: {write_error}"))
        }
        (Err(write_error), Some(Err(rollback_error)), Ok(())) => Err(format!(
            "publish stdout frame: {write_error}; rollback: {rollback_error}"
        )),
        (Ok(()), Some(Ok(())), Err(signal_error)) => Err(signal_error),
        (Ok(()), Some(Err(rollback_error)), Err(signal_error)) => {
            Err(format!("{signal_error}; rollback: {rollback_error}"))
        }
        (Err(write_error), Some(Ok(())), Err(signal_error)) => Err(format!(
            "publish stdout frame: {write_error}; {signal_error}"
        )),
        (Err(write_error), Some(Err(rollback_error)), Err(signal_error)) => Err(format!(
            "publish stdout frame: {write_error}; rollback: {rollback_error}; {signal_error}"
        )),
        _ => Err("stdout publication reached an invalid rollback state".to_string()),
    }
}

#[cfg(unix)]
fn write_stdout_line_with_rollback(
    line: &str,
    rollback: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    publish_with_sigpipe_rollback(
        libc::STDOUT_FILENO,
        || {
            let mut stdout = std::io::stdout().lock();
            writeln!(stdout, "{line}").and_then(|()| stdout.flush())
        },
        rollback,
    )
}

#[cfg(not(unix))]
fn write_stdout_line_with_rollback(
    line: &str,
    rollback: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    match write_stdout_line_sigpipe_safe(line) {
        Ok(()) => Ok(()),
        Err(error) => match rollback() {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(format!("{error}; rollback: {rollback_error}")),
        },
    }
}

#[cfg(unix)]
struct ScopedPromptSignals {
    _scope: MutexGuard<'static, ()>,
    previous_actions: Vec<(libc::c_int, libc::sigaction)>,
    pending_signal: Option<libc::c_int>,
    active: bool,
}

#[cfg(unix)]
impl ScopedPromptSignals {
    fn install() -> Result<Self, String> {
        let scope = OWNED_PROMPT_SIGNAL_SCOPE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let pipe = PromptSignalPipe::global()?;
        let mut masked = ThreadSignalMask::block(&OWNED_PROMPT_SIGNALS)?;
        let pending_signal = pipe.drain()?;

        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = owned_prompt_signal_handler as *const () as usize;
        action.sa_flags = 0;
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
            return Err(format!(
                "initialize owned-prompt handler mask: {}",
                std::io::Error::last_os_error()
            ));
        }
        for signal in OWNED_PROMPT_SIGNALS {
            if unsafe { libc::sigaddset(&mut action.sa_mask, signal) } != 0 {
                return Err(format!(
                    "populate owned-prompt handler mask: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }

        let mut previous_actions = Vec::with_capacity(OWNED_PROMPT_SIGNALS.len());
        for signal in OWNED_PROMPT_SIGNALS {
            let mut previous = unsafe { std::mem::zeroed::<libc::sigaction>() };
            if unsafe { libc::sigaction(signal, &action, &mut previous) } != 0 {
                let error = std::io::Error::last_os_error();
                for (installed, prior) in previous_actions.iter().rev() {
                    unsafe {
                        libc::sigaction(*installed, prior, std::ptr::null_mut());
                    }
                }
                return Err(format!("install owned-prompt signal handler: {error}"));
            }
            previous_actions.push((signal, previous));
        }
        if let Err(error) = masked.restore() {
            for (signal, previous) in previous_actions.iter().rev() {
                unsafe {
                    libc::sigaction(*signal, previous, std::ptr::null_mut());
                }
            }
            return Err(error);
        }
        Ok(Self {
            _scope: scope,
            previous_actions,
            pending_signal,
            active: true,
        })
    }

    fn reader_fd(&self) -> RawFd {
        PromptSignalPipe::global()
            .expect("installed prompt signal scope owns an initialized pipe")
            .reader_fd()
    }

    fn take_pending(&mut self) -> Result<Option<libc::c_int>, String> {
        let relayed = PromptSignalPipe::global()?.drain()?;
        Ok(self.pending_signal.take().or(relayed))
    }

    /// Restore every prior disposition while the current thread blocks the
    /// managed set. The caller restores termios before invoking this function.
    fn finish(&mut self) -> Result<Option<libc::c_int>, String> {
        if !self.active {
            return Ok(self.pending_signal.take());
        }
        let mut masked = ThreadSignalMask::block(&OWNED_PROMPT_SIGNALS)?;
        let pending = self.take_pending()?;
        let mut restore_error = None;
        for (signal, previous) in self.previous_actions.iter().rev() {
            if unsafe { libc::sigaction(*signal, previous, std::ptr::null_mut()) } != 0
                && restore_error.is_none()
            {
                restore_error = Some(format!(
                    "restore signal {signal} disposition: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        if restore_error.is_none() {
            self.active = false;
        }
        let mask_result = masked.restore();
        match (restore_error, mask_result) {
            (None, Ok(())) => Ok(pending),
            (Some(error), Ok(())) | (None, Err(error)) => Err(error),
            (Some(error), Err(mask_error)) => Err(format!("{error}; {mask_error}")),
        }
    }

    fn propagate<T>(signal: libc::c_int) -> Result<T, String> {
        // Deliver to this exact thread. Darwin's process-directed `raise`
        // implementation can select another runtime thread whose inherited
        // mask still blocks the signal, making propagation nondeterministic.
        // The prompt thread's original mask was restored immediately above.
        let delivered = unsafe { libc::pthread_kill(libc::pthread_self(), signal) };
        if delivered != 0 {
            return Err(format!(
                "re-raise signal {signal}: {}",
                std::io::Error::from_raw_os_error(delivered)
            ));
        }
        Err(format!(
            "controlling-terminal prompt interrupted by signal {signal}"
        ))
    }
}

#[cfg(unix)]
impl Drop for ScopedPromptSignals {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[cfg(unix)]
struct TerminalModeGuard {
    fd: RawFd,
    original: libc::termios,
    active: bool,
}

#[cfg(unix)]
impl TerminalModeGuard {
    fn activate(fd: RawFd) -> Result<Self, String> {
        let original = tcgetattr_retry(fd)
            .map_err(|error| format!("read controlling-terminal mode: {error}"))?;
        let mut interactive = original;
        interactive.c_lflag |= libc::ICANON | libc::ECHO;
        tcsetattr_retry(fd, &interactive)
            .map_err(|error| format!("set controlling-terminal interaction mode: {error}"))?;
        Ok(Self {
            fd,
            original,
            active: true,
        })
    }

    fn restore(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        tcsetattr_retry(self.fd, &self.original)
            .map_err(|error| format!("restore controlling-terminal mode: {error}"))?;
        self.active = false;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for TerminalModeGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(unix)]
fn tcgetattr_retry(fd: RawFd) -> std::io::Result<libc::termios> {
    loop {
        let mut mode = std::mem::MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(fd, mode.as_mut_ptr()) } == 0 {
            return Ok(unsafe { mode.assume_init() });
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn tcsetattr_retry(fd: RawFd, mode: &libc::termios) -> std::io::Result<()> {
    loop {
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, mode) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
struct ControllingTty {
    file: File,
    mode: TerminalModeGuard,
    signals: ScopedPromptSignals,
}

#[cfg(unix)]
impl ControllingTty {
    fn open() -> Result<Self, String> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NOFOLLOW)
            .open("/dev/tty")
            .map_err(|error| format!("open controlling terminal: {error}"))?;
        let fd = file.as_raw_fd();
        if unsafe { libc::isatty(fd) } != 1 {
            return Err("controlling-terminal descriptor is not a terminal".to_string());
        }
        let foreground = tcgetpgrp_retry(fd).map_err(|error| {
            format!("read controlling-terminal foreground process group: {error}")
        })?;
        let process_group = unsafe { libc::getpgrp() };
        if foreground != process_group {
            return Err(
                "tirith is not in the controlling terminal foreground process group".into(),
            );
        }
        // Install the relay while the original terminal mode is still active.
        // A signal before this point follows the caller's original disposition;
        // a signal after it is relayed until `with_controlling_tty` has restored
        // the exact mode and prior dispositions.
        let signals = ScopedPromptSignals::install()?;
        let mode = TerminalModeGuard::activate(fd)?;
        Ok(Self {
            file,
            mode,
            signals,
        })
    }

    fn restore(&mut self) -> Result<(), String> {
        let flush = self
            .file
            .flush()
            .map_err(|error| format!("flush controlling terminal: {error}"));
        let restore = self.mode.restore();
        match (flush, restore) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(error), Err(restore_error)) => Err(format!("{error}; {restore_error}")),
        }
    }
}

#[cfg(unix)]
fn tcgetpgrp_retry(fd: RawFd) -> std::io::Result<libc::pid_t> {
    loop {
        let process_group = unsafe { libc::tcgetpgrp(fd) };
        if process_group >= 0 {
            return Ok(process_group);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
impl std::io::Write for ControllingTty {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.file.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[cfg(unix)]
impl ReceiptInteractionIo for ControllingTty {
    fn notify(&mut self, message: &str) -> Result<(), String> {
        writeln!(self.file, "{message}")
            .and_then(|()| self.file.flush())
            .map_err(|error| format!("write controlling-terminal interaction: {error}"))
    }

    fn prompt(&mut self, prompt: &str, timeout: Option<Duration>) -> Result<PromptAnswer, String> {
        // Discard type-ahead immediately before every security decision. Without
        // this, bytes queued after the shell's Enter press could be mistaken for
        // an approval response that the user never gave to this prompt.
        flush_terminal_input(self.file.as_raw_fd())
            .map_err(|error| format!("flush queued controlling-terminal input: {error}"))?;
        write!(self.file, "{prompt}")
            .and_then(|()| self.file.flush())
            .map_err(|error| format!("write controlling-terminal prompt: {error}"))?;
        let answer = read_prompt_answer(self.file.as_raw_fd(), self.signals.reader_fd(), timeout)?;
        if answer == PromptAnswer::TimedOut {
            writeln!(self.file)
                .and_then(|()| self.file.flush())
                .map_err(|error| format!("finish timed-out terminal prompt: {error}"))?;
        }
        Ok(answer)
    }
}

#[cfg(unix)]
fn with_controlling_tty<T>(
    operation: impl FnOnce(&mut ControllingTty) -> Result<T, String>,
) -> Result<T, String> {
    let mut tty = ControllingTty::open()?;
    let result = operation(&mut tty);
    let restore = tty.restore();
    let signal = tty.signals.finish();
    let signal = match signal {
        Ok(signal) => signal,
        Err(signal_error) => {
            return match (result, restore) {
                (Err(error), Err(restore_error)) => Err(format!(
                    "{error}; additionally failed to {restore_error}; {signal_error}"
                )),
                (Err(error), Ok(())) => Err(format!("{error}; {signal_error}")),
                (Ok(_), Err(restore_error)) => Err(format!("{restore_error}; {signal_error}")),
                (Ok(_), Ok(())) => Err(signal_error),
            };
        }
    };
    if let Some(signal) = signal {
        // Termios and every prior sigaction/mask are restored before the
        // original signal is delivered again. Default SIGINT/TERM/HUP/QUIT now
        // terminates normally; default SIGTSTP stops and, after SIGCONT, this
        // path still returns an error so no receipt token can be emitted.
        return ScopedPromptSignals::propagate(signal);
    }
    match (result, restore) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(restore_error)) => Err(restore_error),
        (Err(error), Err(restore_error)) => {
            Err(format!("{error}; additionally failed to {restore_error}"))
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptWaitOutcome {
    Input,
    TimedOut,
    Signal,
}

#[cfg(unix)]
fn poll_timeout_ms(deadline: Option<Instant>) -> Option<i32> {
    let deadline = deadline?;
    let now = Instant::now();
    if now >= deadline {
        return Some(0);
    }
    let remaining = deadline.duration_since(now);
    let millis = remaining.as_millis();
    let rounded_up = millis.saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0));
    Some(rounded_up.clamp(1, i32::MAX as u128) as i32)
}

#[cfg(unix)]
fn wait_for_prompt_input_with(
    deadline: Option<Instant>,
    mut poll_once: impl FnMut(i32) -> std::io::Result<PromptWaitOutcome>,
) -> std::io::Result<PromptWaitOutcome> {
    loop {
        let timeout_ms = poll_timeout_ms(deadline).unwrap_or(-1);
        if timeout_ms == 0 {
            return Ok(PromptWaitOutcome::TimedOut);
        }
        match poll_once(timeout_ms) {
            Ok(PromptWaitOutcome::Input) => return Ok(PromptWaitOutcome::Input),
            Ok(PromptWaitOutcome::Signal) => return Ok(PromptWaitOutcome::Signal),
            Ok(PromptWaitOutcome::TimedOut) => {
                // A deadline farther away than i32::MAX milliseconds is polled
                // in bounded chunks. Recompute against the original Instant;
                // never treat the end of one chunk as the policy timeout.
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Ok(PromptWaitOutcome::TimedOut);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(unix)]
fn wait_for_prompt_input(
    fd: RawFd,
    signal_fd: RawFd,
    deadline: Option<Instant>,
) -> std::io::Result<PromptWaitOutcome> {
    let mut transient_valid_nvals = 0_u8;
    wait_for_prompt_input_with(deadline, |timeout_ms| {
        let mut descriptors = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: signal_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, timeout_ms) };
        if result < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if result == 0 {
            return Ok(PromptWaitOutcome::TimedOut);
        }
        if descriptors[1].revents & libc::POLLNVAL != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "owned-prompt signal descriptor became invalid",
            ));
        }
        if descriptors[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            // Leave the byte queued. `with_controlling_tty` drains it only after
            // restoring termios, then restores the prior disposition and raises
            // the original signal.
            return Ok(PromptWaitOutcome::Signal);
        }
        if descriptors[0].revents & libc::POLLNVAL != 0 {
            let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            let is_tty = descriptor_flags >= 0 && unsafe { libc::isatty(fd) } == 1;
            if is_tty && transient_valid_nvals < 32 {
                // Darwin PTYs can transiently report POLLNVAL while the
                // controlling session settles even though the descriptor is
                // still open and isatty succeeds. Revalidate and retry with a
                // hard cap; never spin forever or accept a replaced/non-TTY fd.
                transient_valid_nvals += 1;
                std::thread::sleep(Duration::from_millis(1));
                return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
            }
            let descriptor_state = if descriptor_flags >= 0 {
                format!("open with flags {descriptor_flags:#x}, isatty={is_tty}")
            } else {
                format!("closed: {}", std::io::Error::last_os_error())
            };
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("controlling-terminal descriptor became invalid ({descriptor_state})"),
            ));
        }
        transient_valid_nvals = 0;
        if descriptors[0].revents & libc::POLLIN != 0 {
            return Ok(PromptWaitOutcome::Input);
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "controlling terminal closed before a response was entered",
        ))
    })
}

#[cfg(unix)]
fn flush_terminal_input(fd: RawFd) -> std::io::Result<()> {
    loop {
        if unsafe { libc::tcflush(fd, libc::TCIFLUSH) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn classify_prompt_response(response: &[u8]) -> Result<PromptAnswer, String> {
    let response = std::str::from_utf8(response)
        .map_err(|_| "controlling-terminal response was not UTF-8".to_string())?;
    let response = response.trim_matches(|character: char| character.is_ascii_whitespace());
    if response.eq_ignore_ascii_case("y") || response.eq_ignore_ascii_case("yes") {
        Ok(PromptAnswer::Accepted)
    } else {
        Ok(PromptAnswer::Rejected)
    }
}

#[cfg(unix)]
fn read_prompt_answer(
    fd: RawFd,
    signal_fd: RawFd,
    timeout: Option<Duration>,
) -> Result<PromptAnswer, String> {
    const RESPONSE_CAP: usize = 64;
    let deadline = match timeout {
        Some(timeout) => Some(
            Instant::now()
                .checked_add(timeout)
                .ok_or_else(|| "controlling-terminal prompt deadline overflowed".to_string())?,
        ),
        None => None,
    };
    let mut response = Vec::with_capacity(8);
    loop {
        let ready = wait_for_prompt_input(fd, signal_fd, deadline)
            .map_err(|error| format!("wait for controlling-terminal response: {error}"))?;
        match ready {
            PromptWaitOutcome::TimedOut => {
                flush_terminal_input(fd)
                    .map_err(|error| format!("flush timed-out terminal response: {error}"))?;
                return Ok(PromptAnswer::TimedOut);
            }
            PromptWaitOutcome::Signal => {
                return Err("controlling-terminal prompt interrupted by a signal".to_string())
            }
            PromptWaitOutcome::Input => {}
        }
        let mut byte = [0_u8; 1];
        let read = loop {
            let read = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), byte.len()) };
            if read >= 0 {
                break read;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(format!("read controlling-terminal response: {error}"));
            }
        };
        if read == 0 {
            return Err("controlling terminal closed before a response was entered".to_string());
        }
        if matches!(byte[0], b'\n' | b'\r') {
            break;
        }
        if response.len() == RESPONSE_CAP {
            let flush_error = flush_terminal_input(fd).err();
            if let Some(error) = flush_error {
                return Err(format!(
                    "controlling-terminal response exceeded 64 bytes and could not be flushed: {error}"
                ));
            }
            return Err("controlling-terminal response exceeded 64 bytes".to_string());
        }
        response.push(byte[0]);
    }
    classify_prompt_response(&response)
}

const RECEIPT_STDIN_CAP: u64 = 1024 * 1024;

fn read_receipt_stdin() -> Result<Vec<u8>, String> {
    crate::cli::read_stdin_capped(RECEIPT_STDIN_CAP)
        .map_err(|error| format!("read shell receipt frame: {error}"))
}

fn parse_receipt_token_frame(bytes: &[u8]) -> Result<&str, String> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        return Err("shell receipt token frame contains extra data".to_string());
    }
    std::str::from_utf8(bytes).map_err(|_| "shell receipt token is not UTF-8".to_string())
}

fn parse_receipt_consume_frame(bytes: &[u8]) -> Result<(&str, &str), String> {
    let separator = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .ok_or_else(|| "shell receipt consume frame lacks its command separator".to_string())?;
    let token_bytes = bytes[..separator]
        .strip_suffix(b"\r")
        .unwrap_or(&bytes[..separator]);
    let token = std::str::from_utf8(token_bytes)
        .map_err(|_| "shell receipt token is not UTF-8".to_string())?;
    let command = std::str::from_utf8(&bytes[separator + 1..])
        .map_err(|_| "shell receipt command is not UTF-8".to_string())?;
    if command.is_empty() {
        return Err("shell receipt consume frame has an empty command".to_string());
    }
    Ok((token, command))
}

pub fn receipt_capability() -> i32 {
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        println!("TIRITH_EXECUTION_RECEIPT_PROTOCOL=3");
        0
    } else {
        eprintln!("tirith: strict shell execution receipts are unsupported on this platform");
        1
    }
}

pub fn register_receipt_instance(shell_pid: u32, family: execution_state::ShellHookFamily) -> i32 {
    let session_id = tirith_core::session::resolve_session_id();
    match execution_state::register_shell_hook_instance_with_delivery(
        shell_pid,
        family,
        &session_id,
        write_stdout_line_sigpipe_safe,
    ) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("tirith: failed to register shell receipt hook: {error}");
            1
        }
    }
}

pub fn new_receipt_instance() -> i32 {
    // Protocol v1 minted an unregistered bearer here. Keep the hidden command
    // as a fail-closed compatibility tombstone: protocol v3 requires a live,
    // direct-parent registration and must never disclose an unbound secret.
    eprintln!(
        "tirith: unregistered shell receipt instances are disabled; use protocol-v3 registration"
    );
    1
}

pub fn arm_receipt(
    _channel: ShellReceiptChannel,
    _approval: Option<ShellApprovalOutcome>,
    _warn_acknowledged: bool,
) -> i32 {
    // Protocol v3 deliberately leaves this clap surface as a compatibility
    // tombstone. In particular, do not read stdin: a caller cannot even present
    // a bearer here, let alone attach caller-supplied interaction outcomes to it.
    eprintln!(
        "tirith: external shell receipt arming is disabled in protocol v3; use `tirith check`"
    );
    1
}

pub fn discard_receipt(channel: ShellReceiptChannel) -> i32 {
    let bytes = match read_receipt_stdin() {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("tirith: {error}");
            return 1;
        }
    };
    let token = match parse_receipt_token_frame(&bytes) {
        Ok(token) => token,
        Err(error) => {
            eprintln!("tirith: {error}");
            return 1;
        }
    };
    match execution_state::discard_shell_execution_receipt(token, channel) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("tirith: failed to discard shell execution receipt: {error}");
            1
        }
    }
}

pub fn reconcile_receipt(channel: ShellReceiptChannel) -> i32 {
    let bytes = match read_receipt_stdin() {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("tirith: {error}");
            return 1;
        }
    };
    let token = match parse_receipt_token_frame(&bytes) {
        Ok(token) => token,
        Err(error) => {
            eprintln!("tirith: {error}");
            return 1;
        }
    };
    match execution_state::reconcile_shell_execution_receipt(
        token,
        channel,
        execution_state::DEFAULT_GATE_LOCK_TIMEOUT,
    ) {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(error) => {
            eprintln!("tirith: failed to reconcile shell execution receipt: {error}");
            1
        }
    }
}

fn prepare_receipt_consumption(
    command: &str,
    context: &ShellReceiptContext,
) -> Result<PreparedExecution, String> {
    let cwd = std::env::current_dir()
        .map_err(|error| format!("resolve shell receipt working directory: {error}"))?;
    let cwd_string = cwd.display().to_string();
    let analysis = AnalysisContext {
        input: command.to_string(),
        shell: context.shell(),
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: context.interactive(),
        cwd: Some(cwd_string.clone()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
    };
    let (mut raw_verdict, mut policy) = engine::analyze_force_full_returning_policy(&analysis);
    raw_verdict.agent_origin = Some(tirith_core::agent_origin::resolve_cli_origin(true));
    let runtime_findings = tirith_core::threatdb_api::enrich_command(
        command,
        context.shell(),
        &policy.threat_intel,
        RuntimeThreatMode::Inline,
    );
    if !runtime_findings.is_empty() {
        raw_verdict.findings.extend(runtime_findings);
        raw_verdict.action =
            upgraded_action_from_findings(&raw_verdict.findings, raw_verdict.action);
    }
    if context.strict_warn_override() {
        policy.strict_warn = true;
    }
    execution_state::prepare_execution(
        &raw_verdict,
        &policy,
        command,
        context.session_id(),
        CallerContext::Cli,
        context.shell(),
        execution_state::DEFAULT_DRAFT_TTL,
        execution_state::DEFAULT_GATE_LOCK_TIMEOUT,
    )
}

pub fn consume_receipt(channel: ShellReceiptChannel) -> i32 {
    let bytes = match read_receipt_stdin() {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("tirith: {error}");
            return 1;
        }
    };
    let (token, command) = match parse_receipt_consume_frame(&bytes) {
        Ok(frame) => frame,
        Err(error) => {
            eprintln!("tirith: {error}");
            return 1;
        }
    };
    let context = match execution_state::shell_execution_receipt_context(token, channel) {
        Ok(context) => context,
        Err(error) => {
            eprintln!("tirith: failed to open shell execution receipt: {error}");
            return 1;
        }
    };
    let prepared = match prepare_receipt_consumption(command, &context) {
        Ok(prepared) => prepared,
        Err(error) => {
            eprintln!("tirith: failed to refresh shell execution decision: {error}");
            return 1;
        }
    };
    match execution_state::consume_shell_execution_receipt(
        token,
        channel,
        command,
        prepared,
        execution_state::DEFAULT_GATE_LOCK_TIMEOUT,
    ) {
        Ok(_) => 0,
        Err(error) => {
            eprintln!("tirith: failed to consume shell execution receipt: {error}");
            1
        }
    }
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

#[cfg(test)]
mod receipt_interaction_tests {
    use super::*;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct FakeInteractionIo {
        answers: VecDeque<Result<PromptAnswer, String>>,
        notifications: Vec<String>,
        prompts: Vec<(String, Option<Duration>)>,
    }

    impl FakeInteractionIo {
        fn answering(answers: impl IntoIterator<Item = Result<PromptAnswer, String>>) -> Self {
            Self {
                answers: answers.into_iter().collect(),
                ..Self::default()
            }
        }
    }

    impl ReceiptInteractionIo for FakeInteractionIo {
        fn notify(&mut self, message: &str) -> Result<(), String> {
            self.notifications.push(message.to_string());
            Ok(())
        }

        fn prompt(
            &mut self,
            prompt: &str,
            timeout: Option<Duration>,
        ) -> Result<PromptAnswer, String> {
            self.prompts.push((prompt.to_string(), timeout));
            self.answers
                .pop_front()
                .unwrap_or_else(|| Err("test prompt had no response".to_string()))
        }
    }

    fn approval_requirements(
        fallback: ApprovalFallback,
        timeout: Option<Duration>,
        warn_ack_findings: Option<usize>,
    ) -> ReceiptInteractionRequirements<'static> {
        ReceiptInteractionRequirements {
            approval: Some(ApprovalPrompt {
                timeout,
                fallback,
                rule: "curl_pipe_shell",
                description: "remote content reaches a shell",
            }),
            warn_ack_findings,
        }
    }

    #[test]
    fn owned_approval_grant_authorizes_without_inventing_warn_ack() {
        let requirements = approval_requirements(ApprovalFallback::Block, None, None);
        let mut io = FakeInteractionIo::answering([Ok(PromptAnswer::Accepted)]);

        let resolution = resolve_owned_interactions(&requirements, &mut io).unwrap();

        assert_eq!(
            resolution,
            OwnedInteractionResolution::Authorized {
                approval: Some(ShellApprovalOutcome::Granted),
                warn_acknowledged: false,
            }
        );
        assert_eq!(io.prompts.len(), 1);
        assert_eq!(io.prompts[0].1, None);
    }

    #[test]
    fn owned_timeout_uses_frozen_warn_fallback_then_requires_warn_ack() {
        let timeout = Duration::from_secs(7);
        let requirements = approval_requirements(ApprovalFallback::Warn, Some(timeout), Some(2));
        let mut io =
            FakeInteractionIo::answering([Ok(PromptAnswer::TimedOut), Ok(PromptAnswer::Accepted)]);

        let resolution = resolve_owned_interactions(&requirements, &mut io).unwrap();

        assert_eq!(
            resolution,
            OwnedInteractionResolution::Authorized {
                approval: Some(ShellApprovalOutcome::TimedOut),
                warn_acknowledged: true,
            }
        );
        assert_eq!(io.prompts.len(), 2);
        assert_eq!(io.prompts[0].1, Some(timeout));
        assert_eq!(io.prompts[1].1, None);
        assert!(io
            .notifications
            .iter()
            .any(|message| message.ends_with("fallback: warn")));
    }

    #[test]
    fn block_fallback_stops_before_warning_ack() {
        let requirements = approval_requirements(ApprovalFallback::Block, None, Some(3));
        let mut io = FakeInteractionIo::answering([Ok(PromptAnswer::Rejected)]);

        let resolution = resolve_owned_interactions(&requirements, &mut io).unwrap();

        assert_eq!(resolution, OwnedInteractionResolution::Blocked);
        assert_eq!(io.prompts.len(), 1, "warn acknowledgement must not run");
        assert!(io
            .notifications
            .iter()
            .any(|message| message.ends_with("fallback: block")));
    }

    #[test]
    fn prompt_error_never_activates_permissive_fallback() {
        let requirements = approval_requirements(ApprovalFallback::Allow, None, None);
        let mut io = FakeInteractionIo::answering([Err("tty read failed".to_string())]);

        let error = resolve_owned_interactions(&requirements, &mut io).unwrap_err();

        assert_eq!(error, "tty read failed");
        assert!(io
            .notifications
            .iter()
            .all(|message| !message.contains("fallback:")));
    }

    #[test]
    fn warning_ack_rejection_blocks_without_approval_metadata() {
        let requirements = ReceiptInteractionRequirements {
            approval: None,
            warn_ack_findings: Some(1),
        };
        let mut io = FakeInteractionIo::answering([Ok(PromptAnswer::Rejected)]);

        let resolution = resolve_owned_interactions(&requirements, &mut io).unwrap();

        assert_eq!(resolution, OwnedInteractionResolution::Blocked);
        assert_eq!(io.prompts.len(), 1);
        assert_eq!(
            io.notifications.last().map(String::as_str),
            Some("tirith: warnings not acknowledged — command blocked")
        );
    }

    #[test]
    fn bash_preexec_is_the_only_channel_that_cannot_prompt() {
        assert!(!channel_can_own_interactions(
            ShellReceiptChannel::BashPreexec
        ));
        for channel in [
            ShellReceiptChannel::Zsh,
            ShellReceiptChannel::Fish,
            ShellReceiptChannel::BashEnter,
            ShellReceiptChannel::PowerShell,
        ] {
            assert!(channel_can_own_interactions(channel));
        }
    }

    #[test]
    fn armed_exit_contract_has_no_protocol_v2_exit_three() {
        let mut verdict = Verdict::allow_fast(0, Default::default());
        assert_eq!(armed_receipt_exit_code(&verdict, false, None), 0);

        verdict.action = Action::Warn;
        assert_eq!(armed_receipt_exit_code(&verdict, false, None), 2);
        assert_eq!(
            armed_receipt_exit_code(&verdict, false, Some(ShellApprovalOutcome::Granted)),
            2,
            "approval does not erase an advisory warning"
        );
        assert_eq!(armed_receipt_exit_code(&verdict, true, None), 0);

        verdict.action = Action::WarnAck;
        assert_eq!(armed_receipt_exit_code(&verdict, true, None), 0);
        assert_eq!(armed_receipt_exit_code(&verdict, false, None), 1);

        verdict.action = Action::Block;
        assert_eq!(armed_receipt_exit_code(&verdict, false, None), 1);
        verdict.bypass_honored = true;
        assert_eq!(armed_receipt_exit_code(&verdict, false, None), 0);
    }

    #[cfg(unix)]
    #[test]
    fn poll_eintr_reuses_one_monotonic_deadline() {
        let deadline = Instant::now().checked_add(Duration::from_secs(1)).unwrap();
        let mut timeouts = Vec::new();

        let ready = wait_for_prompt_input_with(Some(deadline), |timeout_ms| {
            timeouts.push(timeout_ms);
            if timeouts.len() == 1 {
                Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
            } else {
                Ok(PromptWaitOutcome::Input)
            }
        })
        .unwrap();

        assert_eq!(ready, PromptWaitOutcome::Input);
        assert_eq!(timeouts.len(), 2);
        assert!(timeouts[1] <= timeouts[0], "EINTR must not reset timeout");
        assert!(timeouts.iter().all(|timeout| *timeout > 0));
    }

    #[cfg(unix)]
    #[test]
    fn poll_chunk_timeout_rechecks_the_original_deadline() {
        let deadline = Instant::now().checked_add(Duration::from_secs(1)).unwrap();
        let mut calls = 0;
        let ready = wait_for_prompt_input_with(Some(deadline), |_| {
            calls += 1;
            Ok(if calls > 1 {
                PromptWaitOutcome::Input
            } else {
                PromptWaitOutcome::TimedOut
            })
        })
        .unwrap();

        assert_eq!(ready, PromptWaitOutcome::Input);
        assert_eq!(calls, 2);
    }

    #[cfg(unix)]
    #[test]
    fn expired_prompt_deadline_never_polls() {
        let deadline = Instant::now();
        let ready = wait_for_prompt_input_with(Some(deadline), |_| {
            panic!("expired deadline must not invoke poll")
        })
        .unwrap();
        assert_eq!(ready, PromptWaitOutcome::TimedOut);
    }

    #[cfg(unix)]
    #[test]
    fn prompt_response_accepts_only_trimmed_y_or_yes() {
        for accepted in [b"y".as_slice(), b" Y ", b"yes", b"YeS"] {
            assert_eq!(
                classify_prompt_response(accepted).unwrap(),
                PromptAnswer::Accepted
            );
        }
        for rejected in [b"".as_slice(), b"n", b"yep", b"yes please"] {
            assert_eq!(
                classify_prompt_response(rejected).unwrap(),
                PromptAnswer::Rejected
            );
        }
        assert!(classify_prompt_response(&[0xff]).is_err());
    }

    #[cfg(unix)]
    fn assert_same_terminal_mode(actual: &libc::termios, expected: &libc::termios) {
        assert_eq!(actual.c_iflag, expected.c_iflag);
        assert_eq!(actual.c_oflag, expected.c_oflag);
        assert_eq!(actual.c_cflag, expected.c_cflag);
        assert_eq!(actual.c_lflag, expected.c_lflag);
        assert_eq!(actual.c_cc, expected.c_cc);
        assert_eq!(unsafe { libc::cfgetispeed(actual) }, unsafe {
            libc::cfgetispeed(expected)
        });
        assert_eq!(unsafe { libc::cfgetospeed(actual) }, unsafe {
            libc::cfgetospeed(expected)
        });
    }

    #[cfg(unix)]
    #[test]
    fn terminal_mode_guard_restores_full_mode_on_restore_and_unwind() {
        use std::os::fd::FromRawFd as _;

        let mut master = -1;
        let mut slave = -1;
        let opened = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            opened,
            0,
            "openpty failed: {}",
            std::io::Error::last_os_error()
        );
        let _master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let fd = slave.as_raw_fd();

        let mut noncanonical = tcgetattr_retry(fd).unwrap();
        noncanonical.c_lflag &= !(libc::ICANON | libc::ECHO);
        tcsetattr_retry(fd, &noncanonical).unwrap();
        let original = tcgetattr_retry(fd).unwrap();

        let mut guard = TerminalModeGuard::activate(fd).unwrap();
        let active = tcgetattr_retry(fd).unwrap();
        assert_eq!(
            active.c_lflag & (libc::ICANON | libc::ECHO),
            libc::ICANON | libc::ECHO
        );
        guard.restore().unwrap();
        assert_same_terminal_mode(&tcgetattr_retry(fd).unwrap(), &original);

        let unwound = std::panic::catch_unwind(|| {
            let _guard = TerminalModeGuard::activate(fd).unwrap();
            panic!("exercise terminal-mode Drop during unwind");
        });
        assert!(unwound.is_err());
        assert_same_terminal_mode(&tcgetattr_retry(fd).unwrap(), &original);
    }

    #[cfg(unix)]
    fn reset_signal_to_default(signal: libc::c_int) -> Result<(), String> {
        let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
        action.sa_sigaction = libc::SIG_DFL;
        if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
            || unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0
        {
            return Err(format!(
                "reset signal {signal} disposition: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut set = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        if unsafe { libc::sigemptyset(&mut set) } != 0
            || unsafe { libc::sigaddset(&mut set, signal) } != 0
        {
            return Err(format!(
                "prepare signal {signal} unmask: {}",
                std::io::Error::last_os_error()
            ));
        }
        let unmasked =
            unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()) };
        if unmasked != 0 {
            return Err(format!(
                "unblock signal {signal}: {}",
                std::io::Error::from_raw_os_error(unmasked)
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn wait_for_child_exit(
        child: &mut std::process::Child,
        timeout: Duration,
    ) -> Result<std::process::ExitStatus, String> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| "child wait deadline overflowed".to_string())?;
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("poll child status: {error}"))?
            {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(format!("child did not exit within {timeout:?}"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(unix)]
    fn force_kill_and_reap_child(child: &mut std::process::Child) -> Result<(), String> {
        if child
            .try_wait()
            .map_err(|error| format!("poll child before forced cleanup: {error}"))?
            .is_some()
        {
            return Ok(());
        }
        if unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGKILL) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(format!("force-kill prompt child: {error}"));
            }
        }
        wait_for_child_exit(child, Duration::from_secs(5)).map(|_| ())
    }

    #[cfg(unix)]
    fn reap_after_pty_close_or_force(child: &mut std::process::Child) -> String {
        match wait_for_child_exit(child, Duration::from_millis(250)) {
            Ok(status) => format!("child exited after PTY close with {status}"),
            Err(wait_error) => {
                let cleanup = force_kill_and_reap_child(child);
                format!("{wait_error}; forced cleanup: {cleanup:?}")
            }
        }
    }

    #[cfg(unix)]
    fn take_child_stderr(child: &mut std::process::Child) -> String {
        use std::io::Read as _;

        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            if let Err(error) = pipe.read_to_string(&mut stderr) {
                return format!("<failed to read child stderr: {error}>");
            }
        }
        stderr
    }

    #[cfg(unix)]
    fn wait_for_terminal_flags(
        fd: RawFd,
        child: &mut std::process::Child,
        required: libc::tcflag_t,
        timeout: Duration,
    ) -> Result<libc::termios, String> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| "terminal-mode wait deadline overflowed".to_string())?;
        loop {
            let mode =
                tcgetattr_retry(fd).map_err(|error| format!("read PTY terminal mode: {error}"))?;
            if mode.c_lflag & required == required {
                return Ok(mode);
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("poll prompt child status: {error}"))?
            {
                return Err(format!(
                    "prompt child exited with {status} before terminal flags {required:#x} became active; last flags={:#x}",
                    mode.c_lflag
                ));
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "terminal flags {required:#x} did not become active within {timeout:?}; last flags={:#x}",
                    mode.c_lflag
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[cfg(unix)]
    fn wait_for_pty_marker(
        master: &mut File,
        child: &mut std::process::Child,
        marker: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        use std::io::Read as _;

        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| "PTY marker deadline overflowed".to_string())?;
        let mut transcript = Vec::new();
        loop {
            if transcript
                .windows(marker.len())
                .any(|window| window == marker)
            {
                return Ok(transcript);
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("poll prompt child status: {error}"))?
            {
                return Err(format!(
                    "prompt child exited before marker with {status}; PTY output: {}",
                    String::from_utf8_lossy(&transcript)
                ));
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(format!(
                    "PTY marker was not observed within {timeout:?}; output: {}",
                    String::from_utf8_lossy(&transcript)
                ));
            }
            let remaining = deadline.duration_since(now);
            let timeout_ms = remaining.as_millis().clamp(1, 100) as libc::c_int;
            let mut descriptor = libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let polled = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
            if polled < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(format!("poll PTY master: {error}"));
            }
            if polled == 0 {
                continue;
            }
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err("PTY master descriptor became invalid".to_string());
            }
            if descriptor.revents & libc::POLLIN != 0 {
                let mut buffer = [0u8; 512];
                match master.read(&mut buffer) {
                    Ok(0) => return Err("PTY master closed before marker".to_string()),
                    Ok(read) => transcript.extend_from_slice(&buffer[..read]),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(format!("read PTY master: {error}")),
                }
                continue;
            }
            if descriptor.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                return Err(format!(
                    "PTY master closed before marker; output: {}",
                    String::from_utf8_lossy(&transcript)
                ));
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn signal_during_owned_prompt_restores_exact_terminal_mode_before_propagation() {
        const CHILD_ENV: &str = "TIRITH_TEST_OWNED_PROMPT_SIGNAL_CHILD";
        const READY_MARKER: &str = "TIRITH_SIGNAL_PROMPT_READY";
        const TEST_NAME: &str = "cli::check::receipt_interaction_tests::signal_during_owned_prompt_restores_exact_terminal_mode_before_propagation";

        if std::env::var_os(CHILD_ENV).is_some() {
            reset_signal_to_default(libc::SIGTERM).expect("prepare default SIGTERM disposition");
            let resolution = with_controlling_tty(|tty| {
                tty.prompt(&format!("{READY_MARKER} [y/N] "), None)
                    .map(|_| ())
            });
            if resolution.is_ok() {
                println!("TIRITH_EXECUTION_RECEIPT=must-not-be-emitted");
            }
            panic!("owned prompt returned instead of propagating SIGTERM: {resolution:?}");
        }

        use std::io::Read as _;
        use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
        use std::process::{Command, Stdio};

        let mut master_fd = -1;
        let mut slave_fd = -1;
        let opened = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(
            opened,
            0,
            "openpty failed: {}",
            std::io::Error::last_os_error()
        );
        let mut master = unsafe { File::from_raw_fd(master_fd) };
        let slave = unsafe { File::from_raw_fd(slave_fd) };
        for fd in [master.as_raw_fd(), slave.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(
                flags >= 0
                    && unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == 0,
                "set PTY close-on-exec: {}",
                std::io::Error::last_os_error()
            );
        }

        let mut noncanonical = tcgetattr_retry(slave.as_raw_fd()).unwrap();
        noncanonical.c_lflag &= !(libc::ICANON | libc::ECHO);
        noncanonical.c_cc[libc::VMIN] = 3;
        noncanonical.c_cc[libc::VTIME] = 2;
        tcsetattr_retry(slave.as_raw_fd(), &noncanonical).unwrap();
        // The PTY attributes are shared, while Darwin may invalidate the
        // retained slave endpoint after its controlling session leader exits.
        // Sample and verify the durable master endpoint on both sides.
        let original = tcgetattr_retry(master.as_raw_fd()).unwrap();

        let child_stdin = slave.try_clone().expect("clone PTY slave for stdin");
        let mut command =
            Command::new(std::env::current_exe().expect("locate current unit-test executable"));
        command
            .args(["--exact", TEST_NAME, "--test-threads=1", "--nocapture"])
            .env(CHILD_ENV, "1")
            .stdin(Stdio::from(child_stdin))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as libc::c_ulong, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::tcsetpgrp(libc::STDIN_FILENO, libc::getpgrp()) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().expect("spawn owned-prompt signal child");
        // The child owns the slave side after spawn. Keep only the master in
        // the parent so Darwin cannot observe a competing retained slave
        // endpoint while the child establishes and tears down its session.
        drop(slave);
        let transcript = match wait_for_pty_marker(
            &mut master,
            &mut child,
            READY_MARKER.as_bytes(),
            Duration::from_secs(5),
        ) {
            Ok(transcript) => transcript,
            Err(error) => {
                drop(master);
                let cleanup = reap_after_pty_close_or_force(&mut child);
                let stderr = take_child_stderr(&mut child);
                panic!("{error}; cleanup state: {cleanup}; child stderr: {stderr}");
            }
        };
        let active = match wait_for_terminal_flags(
            master.as_raw_fd(),
            &mut child,
            libc::ICANON | libc::ECHO,
            Duration::from_secs(1),
        ) {
            Ok(active) => active,
            Err(error) => {
                let trailing = wait_for_pty_marker(
                    &mut master,
                    &mut child,
                    b"TIRITH_UNREACHABLE_DIAGNOSTIC_MARKER",
                    Duration::from_millis(100),
                )
                .expect_err("diagnostic marker must remain absent");
                drop(master);
                let cleanup = reap_after_pty_close_or_force(&mut child);
                let stderr = take_child_stderr(&mut child);
                panic!(
                    "{error}; PTY output: {}; trailing state: {trailing}; cleanup state: {cleanup}; child stderr: {stderr}",
                    String::from_utf8_lossy(&transcript),
                );
            }
        };
        assert_eq!(
            active.c_lflag & (libc::ICANON | libc::ECHO),
            libc::ICANON | libc::ECHO
        );

        assert_eq!(
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
            0,
            "send SIGTERM to prompt child: {}",
            std::io::Error::last_os_error()
        );
        let status = match wait_for_child_exit(&mut child, Duration::from_secs(5)) {
            Ok(status) => status,
            Err(error) => {
                let mode = tcgetattr_retry(master.as_raw_fd())
                    .map(|mode| format!("{:#x}", mode.c_lflag))
                    .unwrap_or_else(|mode_error| format!("unavailable ({mode_error})"));
                let trailing = wait_for_pty_marker(
                    &mut master,
                    &mut child,
                    b"TIRITH_UNREACHABLE_DIAGNOSTIC_MARKER",
                    Duration::from_millis(100),
                )
                .expect_err("diagnostic marker must remain absent");
                drop(master);
                let cleanup = reap_after_pty_close_or_force(&mut child);
                let stderr = take_child_stderr(&mut child);
                panic!(
                    "{error}; terminal flags after SIGTERM={mode}; trailing state: {trailing}; cleanup state: {cleanup}; child stderr: {stderr}"
                );
            }
        };
        let mut stdout = String::new();
        child
            .stdout
            .take()
            .expect("prompt child stdout")
            .read_to_string(&mut stdout)
            .expect("read prompt child stdout");
        let stderr = take_child_stderr(&mut child);

        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "child did not propagate SIGTERM; status={status}, stdout={stdout}, stderr={stderr}, PTY output={}",
            String::from_utf8_lossy(&transcript)
        );
        assert_same_terminal_mode(&tcgetattr_retry(master.as_raw_fd()).unwrap(), &original);
        assert!(
            !stdout.contains("TIRITH_EXECUTION_RECEIPT="),
            "signal path emitted a receipt token: {stdout}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn closed_stdout_rolls_back_without_default_sigpipe_termination() {
        const CHILD_ENV: &str = "TIRITH_TEST_RECEIPT_SIGPIPE_CHILD";
        const TEST_NAME: &str = "cli::check::receipt_interaction_tests::closed_stdout_rolls_back_without_default_sigpipe_termination";

        if std::env::var_os(CHILD_ENV).is_some() {
            reset_signal_to_default(libc::SIGPIPE).expect("prepare default SIGPIPE disposition");
            let mut pipe = [-1; 2];
            assert_eq!(
                unsafe { libc::pipe(pipe.as_mut_ptr()) },
                0,
                "create broken pipe"
            );
            unsafe {
                libc::close(pipe[0]);
            }
            let mut broken_pipe = unsafe { File::from_raw_fd(pipe[1]) };
            let broken_pipe_fd = broken_pipe.as_raw_fd();

            let mut rolled_back = false;
            let mut suppressed_during_rollback = false;
            let result = publish_with_sigpipe_rollback(
                broken_pipe_fd,
                || writeln!(broken_pipe, "receipt-bearer").and_then(|()| broken_pipe.flush()),
                || {
                    #[cfg(target_os = "macos")]
                    {
                        suppressed_during_rollback =
                            unsafe { libc::fcntl(broken_pipe_fd, DARWIN_F_GETNOSIGPIPE) } == 1;
                    }
                    #[cfg(not(target_os = "macos"))]
                    {
                        let mut current = unsafe { std::mem::zeroed::<libc::sigset_t>() };
                        let inspected = unsafe {
                            libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut current)
                        };
                        if inspected != 0 {
                            return Err(format!(
                                "inspect rollback signal mask: {}",
                                std::io::Error::from_raw_os_error(inspected)
                            ));
                        }
                        suppressed_during_rollback =
                            unsafe { libc::sigismember(&current, libc::SIGPIPE) } == 1;
                    }
                    rolled_back = true;
                    Ok(())
                },
            );
            assert!(result.is_err(), "broken stdout must fail publication");
            assert!(rolled_back, "publication failure did not invoke rollback");
            assert!(
                suppressed_during_rollback,
                "rollback ran without active SIGPIPE suppression"
            );
            assert!(
                !signal_is_pending(libc::SIGPIPE).expect("inspect final SIGPIPE state"),
                "publication left its generated SIGPIPE pending"
            );
            return;
        }

        use std::process::{Command, Stdio};

        let output =
            Command::new(std::env::current_exe().expect("locate current unit-test executable"))
                .args(["--exact", TEST_NAME, "--test-threads=1", "--nocapture"])
                .env(CHILD_ENV, "1")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .expect("spawn closed-stdout publication child");
        assert!(
            output.status.success(),
            "closed-stdout publication child failed with {}; stdout: {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
