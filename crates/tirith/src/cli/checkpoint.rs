use tirith_core::checkpoint;

pub fn list_checkpoints(json: bool) -> i32 {
    match checkpoint::list() {
        Ok(entries) => {
            if json {
                let json_val = serde_json::json!({
                    "checkpoints": entries,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_val).unwrap_or_else(|e| {
                        eprintln!("tirith: checkpoint: JSON serialization failed: {e}");
                        "{}".to_string()
                    })
                );
            } else {
                if entries.is_empty() {
                    println!("No checkpoints found.");
                } else {
                    println!(
                        "{id:<38} {created:<26} {files:<8} {size:<12} Trigger",
                        id = "ID",
                        created = "Created",
                        files = "Files",
                        size = "Size"
                    );
                    println!("{}", "-".repeat(100));
                    for e in &entries {
                        let size = format_bytes(e.total_bytes);
                        let trigger = e
                            .trigger_command
                            .as_deref()
                            .unwrap_or("-")
                            .chars()
                            .take(30)
                            .collect::<String>();
                        println!(
                            "{:<38} {:<26} {:<8} {:<12} {}",
                            e.id, e.created_at, e.file_count, size, trigger
                        );
                    }
                    println!("\n{} checkpoint(s)", entries.len());
                }
            }
            0
        }
        Err(e) => {
            eprintln!("tirith checkpoint list: {e}");
            2
        }
    }
}

pub fn restore_checkpoint(id: &str, json: bool) -> i32 {
    match checkpoint::restore(id) {
        Ok(restored) => {
            if json {
                let json_val = serde_json::json!({
                    "restored": restored,
                    "count": restored.len(),
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_val).unwrap_or_else(|e| {
                        eprintln!("tirith: checkpoint: JSON serialization failed: {e}");
                        "{}".to_string()
                    })
                );
            } else {
                println!("Restored {} file(s):", restored.len());
                for path in &restored {
                    println!("  {path}");
                }
            }
            0
        }
        Err(e) => {
            eprintln!("tirith checkpoint restore: {e}");
            2
        }
    }
}

pub fn diff_checkpoint(id: &str, json: bool) -> i32 {
    match checkpoint::diff(id) {
        Ok(diffs) => {
            if json {
                let json_val = serde_json::json!({
                    "diffs": diffs,
                    "count": diffs.len(),
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_val).unwrap_or_else(|e| {
                        eprintln!("tirith: checkpoint: JSON serialization failed: {e}");
                        "{}".to_string()
                    })
                );
            } else if diffs.is_empty() {
                println!("No differences found — all files match checkpoint.");
            } else {
                for d in &diffs {
                    let s = tirith_core::style::Stream::Stdout;
                    let status = match d.status {
                        checkpoint::DiffStatus::Deleted => tirith_core::style::red("deleted", s),
                        checkpoint::DiffStatus::Modified => {
                            tirith_core::style::yellow("modified", s)
                        }
                        checkpoint::DiffStatus::BackupCorrupt => {
                            tirith_core::style::red("corrupt", s)
                        }
                    };
                    println!("  {status:>18}  {}", d.path);
                }
                println!("\n{} difference(s)", diffs.len());
            }
            0
        }
        Err(e) => {
            eprintln!("tirith checkpoint diff: {e}");
            2
        }
    }
}

pub fn purge_checkpoints(json: bool) -> i32 {
    let config = checkpoint::CheckpointConfig::default();
    match checkpoint::purge(&config) {
        Ok(result) => {
            if json {
                let json_val = serde_json::json!(result);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_val).unwrap_or_else(|e| {
                        eprintln!("tirith: checkpoint: JSON serialization failed: {e}");
                        "{}".to_string()
                    })
                );
            } else if result.removed_count == 0 {
                println!("No checkpoints needed purging.");
            } else {
                println!(
                    "Purged {} checkpoint(s), freed {}",
                    result.removed_count,
                    format_bytes(result.freed_bytes)
                );
            }
            0
        }
        Err(e) => {
            eprintln!("tirith checkpoint purge: {e}");
            2
        }
    }
}

pub fn create_checkpoint(paths: &[String], trigger: Option<&str>, json: bool) -> i32 {
    let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
    match checkpoint::create(&path_refs, trigger) {
        Ok(meta) => {
            if json {
                let json_val = serde_json::json!(meta);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json_val).unwrap_or_else(|e| {
                        eprintln!("tirith: checkpoint: JSON serialization failed: {e}");
                        "{}".to_string()
                    })
                );
            } else {
                println!("Checkpoint created: {}", meta.id);
                println!(
                    "  {} file(s), {}",
                    meta.file_count,
                    format_bytes(meta.total_bytes)
                );
            }
            0
        }
        Err(e) => {
            eprintln!("tirith checkpoint create: {e}");
            2
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
