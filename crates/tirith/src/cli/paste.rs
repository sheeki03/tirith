use std::io::Read;

use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::output;
use tirith_core::tokenize::ShellType;

pub fn run(shell: &str, json: bool) -> i32 {
    // Read raw bytes from stdin
    let mut raw_bytes = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut raw_bytes) {
        eprintln!("tirith: failed to read stdin: {e}");
        return 1;
    }

    if raw_bytes.is_empty() {
        return 0;
    }

    let shell_type = shell.parse::<ShellType>().unwrap_or(ShellType::Posix);

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
        write_last_trigger(&verdict, &ctx.input);
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

fn write_last_trigger(verdict: &tirith_core::verdict::Verdict, cmd: &str) {
    if let Some(dir) = tirith_core::policy::data_dir() {
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("last_trigger.json");
        let tmp = dir.join(".last_trigger.json.tmp");

        #[derive(serde::Serialize)]
        struct LastTrigger<'a> {
            rule_ids: Vec<String>,
            severity: String,
            command_redacted: String,
            findings: &'a [tirith_core::verdict::Finding],
            timestamp: String,
        }

        let trigger = LastTrigger {
            rule_ids: verdict
                .findings
                .iter()
                .map(|f| f.rule_id.to_string())
                .collect(),
            severity: verdict
                .findings
                .iter()
                .map(|f| f.severity)
                .max()
                .map(|s| format!("{s}"))
                .unwrap_or_default(),
            command_redacted: if cmd.len() > 80 {
                format!("{}...", &cmd[..80])
            } else {
                cmd.to_string()
            },
            findings: &verdict.findings,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        if let Ok(json) = serde_json::to_string_pretty(&trigger) {
            let _ = std::fs::write(&tmp, &json);
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}
