use std::path::Path;

use tirith_core::rules::cloaking;

/// `tirith fetch --save <path> <url>` — download `url` to `path` (no execution)
/// and mark `path` tainted, so a later `bash <path>` / `source <path>` fires the
/// engine's tainted-file rule. Unlike `tirith run`, nothing is executed.
pub fn save(url: &str, save_path: &str, sha256: Option<String>, json: bool) -> i32 {
    let dest = Path::new(save_path);

    let result = match tirith_core::runner::download_to_path(url, dest, sha256.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            if json {
                let err = serde_json::json!({ "error": e });
                // CodeRabbit R16 #4: on a broken `--json` write, exit 2 (JSON-write
                // failure), not 1 (download failure) — the JSON never arrived.
                if !super::write_json_stdout(
                    &err,
                    "tirith fetch --save: failed to write JSON output",
                ) {
                    return 2;
                }
            } else {
                eprintln!("tirith fetch --save: {e}");
            }
            return 1;
        }
    };

    // Mark the saved path tainted. The source is the (final, post-redirect) URL.
    let mark = tirith_core::taint::mark_tainted(
        dest,
        "fetch --save",
        Some(result.final_url.clone()),
        None,
    );

    match mark {
        Ok(entry) => {
            if json {
                #[derive(serde::Serialize)]
                struct SaveOut<'a> {
                    saved_path: String,
                    sha256: &'a str,
                    final_url: &'a str,
                    size: u64,
                    interpreter: &'a str,
                    tainted: bool,
                    taint_entry: &'a tirith_core::taint::TaintEntry,
                }
                let out = SaveOut {
                    saved_path: entry.path.clone(),
                    sha256: &result.sha256,
                    final_url: &result.final_url,
                    size: result.size,
                    interpreter: &result.interpreter,
                    tainted: true,
                    taint_entry: &entry,
                };
                if !super::write_json_stdout(
                    &out,
                    "tirith fetch --save: failed to write JSON output",
                ) {
                    return 2;
                }
            } else {
                println!(
                    "Saved {} bytes to {} (SHA256: {})",
                    result.size,
                    save_path,
                    tirith_core::receipt::short_hash(&result.sha256)
                );
                println!(
                    "Marked TAINTED (origin: fetch --save, source: {}).",
                    result.final_url
                );
                println!();
                println!("This file was NOT executed. A later `bash {save_path}` or `source {save_path}`");
                println!("will be flagged by tirith. Review it first; once you trust it:");
                println!("  tirith taint clear {save_path}");
            }
            0
        }
        Err(e) => {
            // The file downloaded but the taint mark failed — report honestly so
            // the user knows the file is on disk but UNtracked.
            eprintln!(
                "tirith fetch --save: downloaded to {save_path} but failed to mark tainted: {e}"
            );
            1
        }
    }
}

pub fn run(url: &str, json: bool) -> i32 {
    match cloaking::check(url) {
        Ok(result) => {
            if json {
                print_json(&result);
            } else {
                print_human(&result);
            }
            if result.cloaking_detected {
                1
            } else {
                0
            }
        }
        Err(e) => {
            eprintln!("tirith fetch: {e}");
            2
        }
    }
}

fn print_json(result: &cloaking::CloakingResult) {
    let json = result.to_json(true);
    println!(
        "{}",
        serde_json::to_string_pretty(&json).unwrap_or_else(|e| {
            eprintln!("tirith: fetch: JSON serialization failed: {e}");
            "{}".to_string()
        })
    );
}

fn print_human(result: &cloaking::CloakingResult) {
    println!("Cloaking check: {}", result.url);
    println!();

    for agent in &result.agent_responses {
        let status = if agent.status_code == 0 {
            "FAILED".to_string()
        } else {
            agent.status_code.to_string()
        };
        println!(
            "  {:<14} status={:<6} length={}",
            agent.agent_name, status, agent.content_length
        );
    }

    println!();

    if result.cloaking_detected {
        println!(
            "{}",
            tirith_core::style::bold_red("Cloaking detected!", tirith_core::style::Stream::Stdout)
        );
        for diff in &result.diff_pairs {
            println!(
                "  {} vs {}: {} chars different",
                diff.agent_a, diff.agent_b, diff.diff_chars
            );
            if let Some(ref text) = diff.diff_text {
                println!("    {text}");
            }
        }
    } else {
        println!(
            "{}",
            tirith_core::style::green("No cloaking detected.", tirith_core::style::Stream::Stdout)
        );
    }
}
