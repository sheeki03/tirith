use crate::cli::last_trigger;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::output;
use tirith_core::tokenize::ShellType;

pub fn run(
    cmd: &str,
    shell: &str,
    json: bool,
    non_interactive: bool,
    interactive_flag: bool,
    approval_check: bool,
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

    let ctx = AnalysisContext {
        input: cmd.to_string(),
        shell: shell_type,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive,
        cwd: std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
    };

    let mut verdict = engine::analyze(&ctx);

    // Apply paranoia filter (suppress Info/Low findings based on policy + tier)
    let policy = tirith_core::policy::Policy::discover(ctx.cwd.as_deref());

    // Log to audit BEFORE paranoia filtering so the audit captures full detection
    // (ADR-13: engine always detects everything; paranoia is an output-layer filter).
    // Skip if bypass was honored — analyze() already logged it.
    if !verdict.bypass_honored {
        let event_id = uuid::Uuid::new_v4().to_string();
        tirith_core::audit::log_verdict(
            &verdict,
            cmd,
            None,
            Some(event_id),
            &policy.dlp_custom_patterns,
        );
    }

    engine::filter_findings_by_paranoia(&mut verdict, policy.paranoia);

    // Approval workflow (Team feature)
    if tirith_core::license::current_tier() >= tirith_core::license::Tier::Team {
        if let Some(meta) = tirith_core::approval::check_approval(&verdict, &policy) {
            tirith_core::approval::apply_approval(&mut verdict, &meta);

            if approval_check {
                match tirith_core::approval::write_approval_file(&meta) {
                    Ok(path) => {
                        println!("{}", path.display());
                    }
                    Err(e) => {
                        eprintln!("tirith: failed to write approval file: {e}");
                        return 1;
                    }
                }
                return verdict.action.exit_code();
            }
        } else if approval_check {
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
    } else if approval_check {
        // Not Team tier — no approval workflow, write no-approval
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

    // Auto-checkpoint before destructive commands (Pro feature).
    // Skip in non-interactive mode: hooks and scripts need fast responses, and
    // checkpoint::create() synchronously traverses the entire cwd which can take
    // seconds on large directories.
    if interactive
        && verdict.action != tirith_core::verdict::Action::Block
        && tirith_core::license::current_tier() >= tirith_core::license::Tier::Pro
        && tirith_core::checkpoint::should_auto_checkpoint(cmd)
    {
        if let Some(cwd) = &ctx.cwd {
            let cwd_owned = cwd.clone();
            let cmd_owned = cmd.to_string();
            std::thread::spawn(move || {
                if let Err(e) =
                    tirith_core::checkpoint::create(&[cwd_owned.as_str()], Some(&cmd_owned))
                {
                    eprintln!("tirith: auto-checkpoint failed (non-fatal): {e}");
                }
            });
        }
    }

    // Write last_trigger.json for non-allow verdicts
    if verdict.action != tirith_core::verdict::Action::Allow {
        last_trigger::write_last_trigger(&verdict, cmd);
    }

    // Webhook dispatch (Team feature, non-blocking background thread)
    if tirith_core::license::current_tier() >= tirith_core::license::Tier::Team
        && !policy.webhooks.is_empty()
    {
        tirith_core::webhook::dispatch(
            &verdict,
            cmd,
            &policy.webhooks,
            &policy.dlp_custom_patterns,
        );
    }

    // For --approval-check mode, stdout has ONLY the temp-file path.
    // Write human-readable output to stderr so hooks can display it.
    if approval_check {
        if output::write_human(&verdict, std::io::stderr().lock()).is_err() {
            eprintln!("tirith: failed to write approval output");
        }
        return verdict.action.exit_code();
    }

    // Output
    if json {
        if output::write_json(&verdict, std::io::stdout().lock()).is_err() {
            eprintln!("tirith: failed to write JSON output");
        }
    } else if output::write_human_auto(&verdict).is_err() {
        eprintln!("tirith: failed to write output");
    }

    // Warn if license is expiring soon (Pro+ only)
    crate::cli::license_cmd::warn_if_expiring_soon();

    verdict.action.exit_code()
}
