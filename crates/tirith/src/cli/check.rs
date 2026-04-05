use crate::cli::last_trigger;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::escalation::CallerContext;
use tirith_core::extract::ScanContext;
use tirith_core::output;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::Action;

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
) -> i32 {
    if cmd.trim().is_empty() {
        if approval_check {
            // Empty command — no approval needed, write no-approval file
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

    // Resolve session ID for post-processing and audit
    let session_id = tirith_core::session::resolve_session_id();

    // Try daemon delegation: skip for --approval-check (requires local policy
    // + approval file writes) and --no-daemon (explicit opt-out).
    //
    // Returns (verdict, Option<Policy>). Local analysis paths return the policy
    // from the engine to avoid a redundant Policy::discover() call. The daemon
    // path returns None because analysis already happened server-side.
    let (raw_verdict, engine_policy) = if !approval_check && !no_daemon {
        if let Some(resp) =
            crate::cli::daemon::try_daemon_check(cmd, shell, cwd.as_deref(), interactive)
        {
            // If daemon provides raw_findings, reconstruct a raw verdict for post-processing.
            // Otherwise fall back to local analysis.
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
                    },
                    None,
                )
            } else {
                // Pre-upgrade daemon: fall back to local analysis
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
                };
                let (v, p) = engine::analyze_returning_policy(&ctx);
                (v, Some(p))
            }
        } else {
            // Daemon unavailable — fall through to local analysis
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
        };
        let (v, p) = engine::analyze_returning_policy(&ctx);
        (v, Some(p))
    };

    // If bypass was honored, skip post-processing — audit bypass and return early
    if raw_verdict.bypass_honored {
        let policy =
            engine_policy.unwrap_or_else(|| tirith_core::policy::Policy::discover(cwd.as_deref()));
        let event_id = uuid::Uuid::new_v4().to_string();
        tirith_core::audit::log_verdict(
            &raw_verdict,
            cmd,
            None,
            Some(event_id),
            &policy.dlp_custom_patterns,
        );
        return 0;
    }

    // Use policy from engine when available, otherwise load it (daemon path only)
    let policy =
        engine_policy.unwrap_or_else(|| tirith_core::policy::Policy::discover(cwd.as_deref()));

    // Capture raw info for audit BEFORE post-processing
    let raw_action_str = format!("{:?}", raw_verdict.action);
    let raw_rule_ids: Vec<String> = raw_verdict
        .findings
        .iter()
        .map(|f| f.rule_id.to_string())
        .collect();

    // post_process_verdict handles: action overrides, approval detection,
    // paranoia filtering, escalation, and session warning recording.
    let effective = tirith_core::escalation::post_process_verdict(
        &raw_verdict,
        &policy,
        cmd,
        &session_id,
        CallerContext::Cli,
    );

    // Log audit with BOTH raw and effective info
    let event_id = uuid::Uuid::new_v4().to_string();
    tirith_core::audit::log_verdict_with_raw(
        &effective,
        cmd,
        None,
        Some(event_id),
        &policy.dlp_custom_patterns,
        Some(raw_action_str),
        Some(raw_rule_ids),
    );

    // Approval file writing (post_process_verdict handled check_approval + apply_approval
    // internally, but write_approval_file must still be done here).
    // Reconstruct ApprovalMetadata from the verdict fields set by apply_approval —
    // do NOT re-call check_approval on the filtered findings, as paranoia filtering
    // may have removed the causal finding.
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
            // No approval needed
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

    // Auto-checkpoint before destructive commands.
    // Skip in non-interactive mode: hooks and scripts need fast responses, and
    // checkpoint::create() synchronously traverses the entire cwd which can take
    // seconds on large directories.
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
                    // Purge old checkpoints to prevent unbounded disk growth (#61)
                    let config = tirith_core::checkpoint::CheckpointConfig::default();
                    if let Err(e) = tirith_core::checkpoint::purge(&config) {
                        eprintln!("tirith: checkpoint purge failed (non-fatal): {e}");
                    }
                }
            });
        }
    }

    // Write last_trigger.json for non-allow verdicts
    if effective.action != Action::Allow {
        last_trigger::write_last_trigger(&effective, cmd, &policy.dlp_custom_patterns);
    }

    // Webhook dispatch (non-blocking background thread)
    if !policy.webhooks.is_empty() {
        tirith_core::webhook::dispatch(
            &effective,
            cmd,
            &policy.webhooks,
            &policy.dlp_custom_patterns,
        );
    }

    // For --approval-check mode, stdout has ONLY the temp-file path.
    // Write human-readable output to stderr so hooks can display it.
    if approval_check {
        if output::write_human(&effective, std::io::stderr().lock()).is_err() {
            eprintln!("tirith: failed to write approval output");
        }

        // Mode B: hook-driven strict_warn — write warn-ack temp file and exit 3.
        // Shell hooks handle the interactive prompt. Exit code 3 is fail-open on
        // old hooks (they fall through to "unexpected rc" path).
        // NOTE: Hook version gating is a follow-up — exit code 3 is safe as-is.
        if effective.action == Action::Warn && (strict_warn || policy.strict_warn) {
            let max_sev = effective
                .findings
                .iter()
                .map(|f| f.severity)
                .max()
                .unwrap_or(tirith_core::verdict::Severity::Low);
            match tirith_core::approval::write_warn_ack_file(effective.findings.len(), &max_sev) {
                Ok(path) => {
                    // Print warn-ack file path on a NEW line after the approval path
                    // already on stdout. Hooks read line 1 = approval, line 2 = warn-ack.
                    println!("{}", path.display());
                }
                Err(e) => {
                    eprintln!("tirith: failed to write warn-ack file: {e}");
                    return 1;
                }
            }
            return tirith_core::verdict::Action::WarnAck.exit_code(); // exit 3
        }

        return effective.action.exit_code();
    }

    // Output
    if json {
        if output::write_json(
            &effective,
            &policy.dlp_custom_patterns,
            std::io::stdout().lock(),
        )
        .is_err()
        {
            eprintln!("tirith: failed to write JSON output");
        }
    } else if output::write_human_auto(&effective).is_err() {
        eprintln!("tirith: failed to write output");
    }

    // strict_warn promotion: prompt user in interactive mode (Mode A: direct CLI)
    let exit_code = effective.action.exit_code();
    if exit_code == 2 && (strict_warn || policy.strict_warn) && interactive {
        // Mode A: direct CLI — prompt the user interactively
        eprint!(
            "tirith: proceed with {} warning(s)? [y/N] ",
            effective.findings.len()
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        if matches!(input.trim(), "y" | "Y" | "yes" | "Yes") {
            return 0; // user acknowledged
        }
        return 1; // user declined
    }
    // strict_warn + non-interactive: return exit code 2 (backward-compatible Warn)

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
