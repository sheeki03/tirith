use std::io::Read;

use crate::cli::last_trigger;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::output;
use tirith_core::tokenize::ShellType;

pub fn run(shell: &str, json: bool) -> i32 {
    // Read raw bytes from stdin with 1 MiB cap
    const MAX_PASTE: u64 = 1024 * 1024; // 1 MiB

    let mut raw_bytes = Vec::new();
    if let Err(e) = std::io::stdin()
        .take(MAX_PASTE + 1)
        .read_to_end(&mut raw_bytes)
    {
        eprintln!("tirith: failed to read stdin: {e}");
        return 1;
    }
    if raw_bytes.len() as u64 > MAX_PASTE {
        eprintln!("tirith: paste input exceeds 1 MiB limit");
        return 1;
    }

    if raw_bytes.is_empty() {
        return 0;
    }

    let shell_type = match shell.parse::<ShellType>() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("tirith: warning: unknown shell '{shell}', falling back to posix");
            ShellType::Posix
        }
    };

    // Decode to string (lossy for URL extraction)
    let input = String::from_utf8_lossy(&raw_bytes).into_owned();

    let interactive = is_terminal::is_terminal(std::io::stderr());

    let ctx = AnalysisContext {
        input,
        shell: shell_type,
        scan_context: ScanContext::Paste,
        raw_bytes: Some(raw_bytes),
        interactive,
        cwd: std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string()),
    };

    let verdict = engine::analyze(&ctx);

    // Write last_trigger.json for non-allow verdicts
    if verdict.action != tirith_core::verdict::Action::Allow {
        last_trigger::write_last_trigger(&verdict, &ctx.input);
    }

    // Log to audit
    let event_id = uuid::Uuid::new_v4().to_string();
    tirith_core::audit::log_verdict(&verdict, &ctx.input, None, Some(event_id));

    if json {
        let _ = output::write_json(&verdict, std::io::stdout().lock());
    } else {
        let _ = output::write_human_auto(&verdict);
    }

    verdict.action.exit_code()
}
