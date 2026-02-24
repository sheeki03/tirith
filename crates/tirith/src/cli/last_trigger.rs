use tirith_core::util::truncate_bytes;

pub fn write_last_trigger(verdict: &tirith_core::verdict::Verdict, cmd: &str) {
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
            command_redacted: redact_command(cmd),
            findings: &verdict.findings,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        if let Ok(json) = serde_json::to_string_pretty(&trigger) {
            {
                use std::io::Write;
                let mut opts = std::fs::OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600);
                }
                if let Ok(mut f) = opts.open(&tmp) {
                    let _ = f.write_all(json.as_bytes());
                }
            }
            let _ = std::fs::rename(&tmp, &path);
        }
    }
}

fn redact_command(cmd: &str) -> String {
    let prefix = truncate_bytes(cmd, 80);
    if prefix.len() == cmd.len() {
        cmd.to_string()
    } else {
        format!("{prefix}...")
    }
}
