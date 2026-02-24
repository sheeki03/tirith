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
) -> i32 {
    if cmd.trim().is_empty() {
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
        clipboard_html: None,
    };

    let mut verdict = engine::analyze(&ctx);

    // Apply paranoia filter (suppress Info/Low findings based on policy + tier)
    let policy = tirith_core::policy::Policy::discover(ctx.cwd.as_deref());
    engine::filter_findings_by_paranoia(&mut verdict, policy.paranoia);

    // Auto-checkpoint before destructive commands (Pro feature, non-blocking)
    if verdict.action != tirith_core::verdict::Action::Block
        && tirith_core::license::current_tier() >= tirith_core::license::Tier::Pro
        && tirith_core::checkpoint::should_auto_checkpoint(cmd)
    {
        if let Some(cwd) = &ctx.cwd {
            let cwd_str = cwd.as_str();
            if let Err(e) = tirith_core::checkpoint::create(&[cwd_str], Some(cmd)) {
                eprintln!("tirith: auto-checkpoint failed (non-fatal): {e}");
            }
        }
    }

    // Write last_trigger.json for non-allow verdicts
    if verdict.action != tirith_core::verdict::Action::Allow {
        last_trigger::write_last_trigger(&verdict, cmd);
    }

    // Log to audit (skip if bypass was honored — analyze() already logged it)
    if !verdict.bypass_honored {
        let event_id = uuid::Uuid::new_v4().to_string();
        tirith_core::audit::log_verdict(&verdict, cmd, None, Some(event_id));
    }

    // Output
    if json {
        if let Err(e) = output::write_json(&verdict, std::io::stdout().lock()) {
            eprintln!("tirith: write output: {e}");
        }
    } else if let Err(e) = output::write_human_auto(&verdict) {
        eprintln!("tirith: write output: {e}");
    }

    verdict.action.exit_code()
}
