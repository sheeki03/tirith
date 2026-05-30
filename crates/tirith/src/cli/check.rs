use crate::cli::last_trigger;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::escalation::CallerContext;
use tirith_core::extract::ScanContext;
use tirith_core::output;
use tirith_core::threatdb_api::RuntimeThreatMode;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{upgraded_action_from_findings, Action};

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
    offline: bool,
    suggest_safe_command: bool,
    card: Option<String>,
) -> i32 {
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

    // Must run before any early return (--approval-check, daemon path, etc.)
    // so hooks calling `tirith check --approval-check` still trigger updates.
    // `--offline` (or TIRITH_OFFLINE) makes this a guaranteed no-op — analysis
    // then stays purely local with zero network attempts.
    crate::cli::threatdb_cmd::maybe_background_update(offline);

    let session_id = tirith_core::session::resolve_session_id();

    // M4 item 8: best-effort origin attribution. Computed once from the
    // current process env + the interactive flag tirith already derived,
    // and stamped on the verdict so post-processing and the audit entry
    // both see the same value. `post_process_verdict` consults this via
    // `escalation::apply_agent_rules` against the active policy's
    // `agent_rules.deny` (note: the `TIRITH=0` bypass branch below skips
    // `post_process_verdict`, so `agent_rules.deny` does not currently
    // enforce under bypass — to be addressed separately).
    let origin = tirith_core::agent_origin::resolve_cli_origin(interactive);

    // M11 ch1 — a `--card <path>` sidecar must be honored by the LOCAL engine
    // (the daemon protocol carries no card field in v1), so a card forces the
    // local analysis path just like `--no-daemon`.
    let use_daemon = !approval_check && !no_daemon && card.is_none();

    // Daemon delegation skipped for --approval-check (needs local policy +
    // approval file writes), --no-daemon, and --card. Local paths return the
    // policy from the engine to avoid a redundant Policy::discover() call;
    // daemon path returns None because analysis happened server-side.
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
                        // M11 ch2 — the daemon evaluates the full manifest
                        // (`engine::analyze`) and now carries the matched
                        // `allowed[]` entry name across the boundary, so the
                        // audit-context annotation survives the daemon path.
                        // (A pre-upgrade daemon omits the field; serde defaults
                        // it to None.)
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
                    clipboard_source: None,
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
                clipboard_source: None,
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
            clipboard_source: None,
        };
        let (v, p) = engine::analyze_returning_policy(&ctx);
        (v, Some(p))
    };

    // Stamp the resolved origin on the raw verdict so every later step
    // (post-processing → effective → audit) sees it. `engine::analyze` does
    // not know the caller's identity by design; the CLI does.
    raw_verdict.agent_origin = Some(origin);

    // Bypass path audits and returns without post-processing.
    if raw_verdict.bypass_honored {
        let policy =
            engine_policy.unwrap_or_else(|| tirith_core::policy::Policy::discover(cwd.as_deref()));
        let event_id = uuid::Uuid::new_v4().to_string();
        // Best-effort audit on the `check` hot path — a write failure must not
        // change the exit code, so the Result is intentionally dropped.
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

    let effective = tirith_core::escalation::post_process_verdict(
        &raw_verdict,
        &policy,
        cmd,
        &session_id,
        CallerContext::Cli,
    );

    let event_id = uuid::Uuid::new_v4().to_string();
    // Best-effort audit on the `check` hot path — a write failure must not
    // change the exit code, so the Result is intentionally dropped.
    let _ = tirith_core::audit::log_verdict_with_raw(
        &effective,
        cmd,
        None,
        Some(event_id),
        &policy.dlp_custom_patterns,
        Some(raw_action_str),
        Some(raw_rule_ids),
    );

    // Reconstruct ApprovalMetadata from verdict fields set by apply_approval —
    // do NOT re-call check_approval on the filtered findings, as paranoia
    // filtering may have removed the causal finding.
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

    // Skip auto-checkpoint in non-interactive mode: hooks and scripts need
    // fast responses, and checkpoint::create() synchronously traverses the
    // entire cwd which can take seconds on large directories.
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
        if output::write_human(&effective, warn_only, std::io::stderr().lock()).is_err() {
            eprintln!("tirith: failed to write approval output");
        }

        // Mode B (hook-driven strict_warn): write warn-ack temp file and exit 3.
        // Old hooks without warn-ack support treat rc=3 as "unexpected" and
        // fail open, so this is backward-compatible.
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

    // Safe-command suggestions are advisory only — computed solely when the
    // user opted in AND the verdict actually flagged something (Allow needs no
    // alternative). They never influence `effective.action` or the exit code.
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
        if output::write_human_auto(&effective, warn_only).is_err() {
            eprintln!("tirith: failed to write output");
        }
        if output::write_safe_suggestions(&safe_suggestions, std::io::stderr().lock()).is_err() {
            eprintln!("tirith: failed to write safe-command suggestions");
        }
    }

    // Mode A (direct CLI strict_warn): prompt interactively. In non-interactive
    // mode we fall through to exit code 2 for backward compatibility.
    let exit_code = effective.action.exit_code();
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
