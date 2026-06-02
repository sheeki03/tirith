//! `tirith taint list|explain|clear` (M10 ch3) — thin presenter over
//! [`tirith_core::taint`]; the store and all logic live in the library.
//!
//! A file becomes tainted via `tirith fetch --save <path> <url>`; a later
//! `bash <path>` fires `ExecOfTaintedFile` from the engine.

use std::path::Path;

use tirith_core::taint::{self, TaintEntry};

use super::{confirm, write_json_stdout};

/// `tirith taint list` — print every recorded taint.
pub fn list(json: bool) -> i32 {
    let entries = taint::list_taints();

    if json {
        if !write_json_stdout(&entries, "tirith taint list: failed to write JSON output") {
            return 2;
        }
        return 0;
    }

    if entries.is_empty() {
        println!("No tainted files recorded.");
        println!();
        println!("A file becomes tainted when you download-and-keep it, e.g.:");
        println!("  tirith fetch --save ./install.sh https://untrusted.example/install.sh");
        return 0;
    }

    println!("Tainted files ({}):", entries.len());
    println!();
    for entry in &entries {
        print_entry_human(entry);
        println!();
    }
    println!("Run `tirith taint clear <file>` to remove a mark once you trust the file.");
    0
}

/// `tirith taint explain <file>` — print the recorded mark for one file.
pub fn explain(file: &str, json: bool) -> i32 {
    let entry = taint::is_tainted(Path::new(file), None);

    if json {
        #[derive(serde::Serialize)]
        struct ExplainOut<'a> {
            file: &'a str,
            tainted: bool,
            #[serde(skip_serializing_if = "Option::is_none")]
            entry: Option<&'a TaintEntry>,
        }
        let out = ExplainOut {
            file,
            tainted: entry.is_some(),
            entry: entry.as_ref(),
        };
        if !write_json_stdout(&out, "tirith taint explain: failed to write JSON output") {
            return 2;
        }
        // Exit 1 when the file IS tainted, mirroring the engine's "block"
        // posture for an exec of a tainted file; 0 when clean.
        return if entry.is_some() { 1 } else { 0 };
    }

    match entry {
        Some(e) => {
            println!("{file}: TAINTED");
            println!();
            print_entry_human(&e);
            println!();
            println!("This file was downloaded from a risky source. Review it before running it.");
            println!("Once you trust it: tirith taint clear {file}");
            1
        }
        None => {
            println!("{file}: not tainted");
            0
        }
    }
}

/// `tirith taint clear <file>` — remove the mark for one file. Prompts for
/// confirmation unless `--yes`. Non-interactive without `--yes` refuses.
pub fn clear(file: &str, yes: bool, json: bool) -> i32 {
    let existing = taint::is_tainted(Path::new(file), None);
    if existing.is_none() {
        if json {
            #[derive(serde::Serialize)]
            struct ClearOut<'a> {
                file: &'a str,
                cleared: bool,
                removed: usize,
            }
            let out = ClearOut {
                file,
                cleared: false,
                removed: 0,
            };
            if !write_json_stdout(&out, "tirith taint clear: failed to write JSON output") {
                return 2;
            }
        } else {
            println!("{file}: not tainted — nothing to clear.");
        }
        return 0;
    }

    if !json && !confirm(&format!("Clear taint mark for {file}?"), yes) {
        println!("Aborted — taint mark left in place.");
        return 0;
    }
    // JSON mode requires `--yes`: refuse rather than silently clear with no prompt.
    if json && !yes {
        eprintln!("tirith taint clear: --yes required in JSON mode to confirm removal");
        return 2;
    }

    match taint::clear_taint(Path::new(file), None) {
        Ok(removed) => {
            if json {
                #[derive(serde::Serialize)]
                struct ClearOut<'a> {
                    file: &'a str,
                    cleared: bool,
                    removed: usize,
                }
                let out = ClearOut {
                    file,
                    cleared: removed > 0,
                    removed,
                };
                if !write_json_stdout(&out, "tirith taint clear: failed to write JSON output") {
                    return 2;
                }
            } else {
                println!(
                    "Cleared taint mark for {file} ({removed} entr{}).",
                    if removed == 1 { "y" } else { "ies" }
                );
            }
            0
        }
        Err(e) => {
            eprintln!("tirith taint clear: {e}");
            2
        }
    }
}

/// Render one taint entry as indented human output.
fn print_entry_human(entry: &TaintEntry) {
    println!("  {}", entry.path);
    println!("    origin:    {}", entry.origin);
    println!("    marked_at: {}", entry.marked_at);
    if let Some(ref url) = entry.source_url {
        println!("    source_url:  {url}");
    }
    if let Some(ref repo) = entry.source_repo {
        println!("    source_repo: {repo}");
    }
}
