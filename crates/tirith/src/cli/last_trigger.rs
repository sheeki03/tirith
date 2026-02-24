use tirith_core::util::truncate_bytes;

pub fn write_last_trigger(verdict: &tirith_core::verdict::Verdict, cmd: &str) {
    if let Some(dir) = tirith_core::policy::data_dir() {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!(
                "tirith: warning: cannot create data dir {}: {e}",
                dir.display()
            );
            return;
        }
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

        let json = match serde_json::to_string_pretty(&trigger) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("tirith: warning: failed to serialize last trigger: {e}");
                return;
            }
        };

        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            match opts.open(&tmp) {
                Ok(mut f) => {
                    if f.write_all(json.as_bytes()).is_ok() && f.sync_all().is_ok() {
                        if let Err(e) = std::fs::rename(&tmp, &path) {
                            eprintln!("tirith: warning: failed to rename last trigger file: {e}");
                            let _ = std::fs::remove_file(&tmp);
                        }
                    } else {
                        eprintln!("tirith: warning: failed to write last trigger data");
                        let _ = std::fs::remove_file(&tmp);
                    }
                }
                Err(e) => {
                    eprintln!("tirith: warning: failed to open last trigger temp file: {e}");
                }
            }
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
