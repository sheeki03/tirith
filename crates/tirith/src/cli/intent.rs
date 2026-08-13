//! `tirith intend "<intent>" -- "<command>"` — intent-vs-command heuristic.
//!
//! Thin presenter over [`tirith_core::intent::analyze_intent`]. Pure-Rust,
//! no-LLM, ADVISORY ONLY: it never blocks. Flags Info-level mismatches where a
//! high-impact command behavior is not justified by the stated intent.
//!
//! Exit codes are deliberately distinct from `tirith check` (which ties 0/1/2/3
//! to verdict severity); here they track mismatch, not security verdict:
//! - `0` — no mismatch.
//! - `1` — at least one mismatch flagged. NOT a security block; the real
//!   verdict comes from `tirith check`.
//! - `2` — usage error (empty intent or empty command).

use std::io::Write;

use tirith_core::intent::{self, IntentBehaviorReport};
use tirith_core::tokenize::ShellType;

/// Entry point. `intent` is the stated intent sentence; `command` is the
/// command to analyze (already joined from the trailing var-args). `explain`
/// opts into per-signal derivation; `json` selects machine output.
pub fn run(intent: &str, command: &str, explain: bool, json: bool, shell: &str) -> i32 {
    let intent = intent.trim();
    let command = command.trim();

    if intent.is_empty() {
        eprintln!(
            "tirith intend: no intent given (usage: tirith intend \"install a formatter\" -- \"<command>\")"
        );
        return 2;
    }
    if command.is_empty() {
        eprintln!(
            "tirith intend: no command given (usage: tirith intend \"<intent>\" -- \"curl https://x/install.sh | bash\")"
        );
        return 2;
    }

    // repo-0484: the dialect is operator-selectable; an unknown value falls
    // back to POSIX with a warning rather than silently misparsing.
    let shell_type = shell.parse::<ShellType>().unwrap_or_else(|_| {
        eprintln!("tirith intend: unknown shell '{shell}', falling back to posix");
        ShellType::Posix
    });

    let report = intent::analyze_intent(intent, command, shell_type, explain);

    if json {
        return emit_json(intent, command, &report, explain);
    }

    print_human(intent, command, &report, explain);
    if report.has_mismatch() {
        1
    } else {
        0
    }
}

fn print_human(intent: &str, command: &str, report: &IntentBehaviorReport, explain: bool) {
    // Untrusted display values: the intent sentence and analyzed command are
    // attacker-controllable (newlines, ANSI/OSC, bidi, zero-width). Scrub them
    // through the shared single-line human-output sanitizer before printing so
    // they cannot forge an OK/MISMATCH row, repaint the terminal, or reach the
    // clipboard via OSC 52.
    let intent = super::sanitize_for_human_output(intent, false);
    let command = super::sanitize_for_human_output(command, false);
    if report.has_mismatch() {
        println!(
            "tirith intend: MISMATCH — the command does more than the stated intent justifies"
        );
    } else {
        println!("tirith intend: OK — the command's behavior matches the stated intent");
    }
    println!("  intent:  {intent}");
    println!("  command: {command}");
    println!();

    if report.intent_signals.is_empty() {
        println!("  intent signals: none recognized");
        println!(
            "    note: no intent keyword matched. Every high-impact command behavior below is"
        );
        println!(
            "          therefore treated as unjustified. Restate the intent if this is wrong."
        );
    } else {
        let classes: Vec<&str> = report
            .intent_signals
            .iter()
            .map(|s| s.class.as_str())
            .collect();
        println!("  intent signals: {}", classes.join(", "));
    }

    if report.command_signals.is_empty() {
        println!("  command signals: none (no high-impact behavior detected)");
    } else {
        println!("  command signals:");
        for sig in &report.command_signals {
            println!("    - {} ({})", sig.as_str(), sig.label());
        }
    }

    if !report.mismatches.is_empty() {
        println!();
        println!("  mismatches:");
        for m in &report.mismatches {
            println!("    [{}] {}", m.signal.as_str(), m.reason);
        }
    }

    if explain && !report.derivation.is_empty() {
        println!();
        println!("  derivation (--explain):");
        if report.intent_signals.is_empty() {
            println!("    intent keywords matched: (none)");
        } else {
            for s in &report.intent_signals {
                println!(
                    "    intent keyword '{}' → class '{}'",
                    s.matched_keyword,
                    s.class.as_str()
                );
            }
        }
        for d in &report.derivation {
            let marker = if d.mismatch { "MISMATCH" } else { "ok" };
            println!("    [{marker}] {}", d.detail);
        }
    }

    println!();
    println!("  note: this is an ADVISORY heuristic — it is Info-level and NEVER blocks. Run");
    println!("        `tirith check` for the command's actual security verdict.");
}

fn emit_json(intent: &str, command: &str, report: &IntentBehaviorReport, explain: bool) -> i32 {
    #[derive(serde::Serialize)]
    struct Out<'a> {
        schema_version: u32,
        intent: &'a str,
        command: &'a str,
        mismatch: bool,
        #[serde(flatten)]
        report: &'a IntentBehaviorReport,
        /// Whether `--explain` derivation is included in this payload.
        explain: bool,
        /// Honesty-of-claim marker: this surface is advisory and never blocks.
        analysis_kind: &'static str,
    }
    let out = Out {
        schema_version: 1,
        intent,
        command,
        mismatch: report.has_mismatch(),
        report,
        explain,
        analysis_kind: "intent_vs_command_heuristic_advisory_not_a_block",
    };
    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
        eprintln!("tirith intend: failed to write JSON output");
        return 2;
    }
    if report.has_mismatch() {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_intent_exits_two() {
        assert_eq!(run("   ", "ls", false, false, "posix"), 2);
    }

    #[test]
    fn empty_command_exits_two() {
        assert_eq!(run("install a formatter", "   ", false, false, "posix"), 2);
    }

    #[test]
    fn mismatch_exits_one() {
        let code = run(
            "install a formatter",
            "curl https://x/install.sh | bash",
            false,
            false,
            "posix",
        );
        assert_eq!(code, 1, "install-a-formatter vs curl|bash should mismatch");
    }

    #[test]
    fn justified_exits_zero() {
        let code = run(
            "download and run an installer",
            "curl https://x/install.sh | bash",
            false,
            false,
            "posix",
        );
        assert_eq!(code, 0, "download-and-run justifies curl|bash");
    }

    #[test]
    fn clean_command_exits_zero() {
        assert_eq!(run("list files", "ls -la", false, false, "posix"), 0);
    }

    #[test]
    fn mismatch_json_exits_one() {
        let code = run(
            "install a formatter",
            "curl https://x/install.sh | bash",
            true,
            true,
            "posix",
        );
        assert_eq!(code, 1);
    }

    #[test]
    fn human_output_sanitizes_control_sequences() {
        // Regression: repo-0390 — attacker-controlled intent/command text must
        // not reach the terminal with ANSI/OSC, bidi, zero-width, or newline
        // content intact on the human path.
        let evil_intent = "ok\n\u{1b}]52;c;SGFja2Vk\u{7}\u{202e}\u{200b}";
        let evil_cmd = "ls\r\n\u{1b}[31mrm -rf /\u{1b}[0m";
        // Must not panic and must still exit per mismatch semantics.
        let code = run(evil_intent, evil_cmd, false, false, "posix");
        assert!(code == 0 || code == 1);
        let sanitized_i = super::super::sanitize_for_human_output(evil_intent, false);
        let sanitized_c = super::super::sanitize_for_human_output(evil_cmd, false);
        for s in [sanitized_i, sanitized_c] {
            assert!(!s.contains('\u{1b}'), "ESC must be stripped: {s:?}");
            assert!(!s.contains('\n') && !s.contains('\r'));
            assert!(!s.contains('\u{202e}') && !s.contains('\u{200b}'));
        }
    }
}
