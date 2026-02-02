use std::fs;

pub fn run(json: bool) -> i32 {
    let path = match tirith_core::policy::data_dir() {
        Some(d) => d.join("last_trigger.json"),
        None => {
            eprintln!("tirith: cannot determine data directory");
            return 1;
        }
    };

    if !path.exists() {
        eprintln!("tirith: no recent trigger found");
        return 1;
    }

    let content = match fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tirith: failed to read last trigger: {e}");
            return 1;
        }
    };

    if json {
        // Pass through JSON directly
        println!("{content}");
        return 0;
    }

    // Parse and display human-readable
    let val: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("tirith: failed to parse last trigger: {e}");
            return 1;
        }
    };

    eprintln!("tirith: last trigger");
    if let Some(ts) = val.get("timestamp").and_then(|v| v.as_str()) {
        eprintln!("  when: {ts}");
    }
    if let Some(cmd) = val.get("command_redacted").and_then(|v| v.as_str()) {
        eprintln!("  command: {cmd}");
    }
    if let Some(severity) = val.get("severity").and_then(|v| v.as_str()) {
        eprintln!("  severity: {severity}");
    }
    if let Some(rules) = val.get("rule_ids").and_then(|v| v.as_array()) {
        for rule in rules {
            if let Some(r) = rule.as_str() {
                eprintln!("  rule: {r}");
            }
        }
    }
    if let Some(findings) = val.get("findings").and_then(|v| v.as_array()) {
        for finding in findings {
            if let Some(title) = finding.get("title").and_then(|v| v.as_str()) {
                eprintln!("  - {title}");
            }
            if let Some(desc) = finding.get("description").and_then(|v| v.as_str()) {
                eprintln!("    {desc}");
            }
        }
    }

    0
}
