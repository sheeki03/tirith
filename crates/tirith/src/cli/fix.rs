//! `tirith fix` — interactive presenter over `tirith_core::safe_command::suggest`.
//!
//! Thin shim: tokenize → `engine::analyze` → `safe_command::suggest` → present.
//! Detection lives in `tirith-core`; this module is presentation + one-keystroke
//! acceptance only. Never invents a rewrite — a finding whose `safe_command` is
//! `None` is rendered as honest guidance from its `remediation` field.
//!
//! ## Exit codes (deliberately distinct from `tirith check`)
//!
//! | code | meaning                                                                                  |
//! |------|------------------------------------------------------------------------------------------|
//! | 0    | no fix needed (verdict was Allow) OR user accepted a rewrite                             |
//! | 1    | findings exist but no mechanical rewrite is available                                    |
//! | 2    | user rejected, JSON write failed, stdin/stderr is not a TTY, OR --non-interactive run    |
//! |      | with rewrites present (the JSON IS the deliverable, but it can't be auto-applied)        |
//!
//! `check` uses 0/1/2/3 (allow/block/warn/warn-ack), tied to *verdict
//! severity*; `fix`'s codes are tied to *whether a rewrite was applied*. The two
//! are deliberately different surfaces (documented in `main.rs`'s after-help).
//!
//! ## TTY gating
//!
//! Interactive mode requires BOTH `stdin` and `stderr` to be a TTY. Stdout is
//! reserved for the chosen `safe_command` so users can wrap the call with
//! `$(tirith fix …)` / `eval "$(tirith fix …)"`. A `--non-interactive` flag or a
//! non-TTY stdin/stderr pair forces JSON-emit-and-exit behavior.
//!
//! ## JSON shape (`--json` / `--non-interactive`)
//!
//! Two shapes, distinguished by whether the verdict had findings:
//!
//! - **No findings** (verdict was Allow) → object envelope:
//!   ```text
//!   { "applied": false, "reason": "no_findings", "verdict": "allow",
//!     "command": "<original>" }
//!   ```
//! - **Findings present** → plain JSON array of `SafeSuggestion`:
//!   ```text
//!   [ { "rule_id": "...", "safe_command": "..." | null,
//!       "rationale": "...", "remediation": "..." }, ... ]
//!   ```
//!
//! The array shape is the M6 acceptance criterion; the envelope is the honest
//! negative case so a parser doesn't read an empty `[]` as "nothing was wrong".

use std::io::{self, BufRead, Write};

use serde::Serialize;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::safe_command::{self, SafeSuggestion};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::Action;

/// Public entry point for the `tirith fix` subcommand.
///
/// `command_parts` are space-joined (mirroring `tirith check`). `shell` accepts
/// the same tokens as `tirith check --shell`; unknown values fall back to
/// `ShellType::Posix` with a stderr warning. `non_interactive`/`json` force
/// JSON-emit behavior even on a TTY. Returns the exit code per the module table.
pub fn run(command_parts: &[String], shell: &str, non_interactive: bool, json: bool) -> i32 {
    // Empty command is a no-op (mirrors `tirith check`).
    let cmd = command_parts.join(" ");
    if cmd.trim().is_empty() {
        if json || non_interactive {
            // A JSON write failure exits 2: a piped consumer must not read
            // truncated output as the `applied:false / no_findings` envelope.
            if !emit_no_findings_envelope(&FixEnvelope {
                applied: false,
                reason: "no_findings",
                verdict: "allow",
                command: "",
            }) {
                return 2;
            }
        } else {
            println!("no fix needed");
        }
        return 0;
    }

    let shell_type = match shell.parse::<ShellType>() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("tirith fix: warning: unknown shell '{shell}', falling back to posix");
            ShellType::Posix
        }
    };

    // Use `analyze` (not `analyze_returning_policy`): fix is advisory, never
    // gates on policy, and does not audit log.
    let ctx = AnalysisContext {
        input: cmd.clone(),
        shell: shell_type,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: false,
        cwd: std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
    };
    let verdict = engine::analyze(&ctx);

    // Allow path: nothing to fix.
    if verdict.action == Action::Allow {
        if json || non_interactive {
            if !emit_no_findings_envelope(&FixEnvelope {
                applied: false,
                reason: "no_findings",
                verdict: action_str(verdict.action),
                command: &cmd,
            }) {
                return 2;
            }
        } else {
            println!("no fix needed");
        }
        return 0;
    }

    // Verdict has findings — ask the library for safe-command suggestions.
    let suggestions = safe_command::suggest(&cmd, shell_type, &verdict);

    // JSON / non-interactive path: emit a plain JSON array, never prompt. Exit
    // 1 if no mechanical rewrite exists (guidance-only); 2 if rewrites are
    // present but we can't get an accept signal.
    if json || non_interactive {
        let has_rewrite = suggestions.iter().any(|s| s.safe_command.is_some());
        if !emit_suggestions_array(&suggestions) {
            return 2;
        }
        return if has_rewrite { 2 } else { 1 };
    }

    // Partition into applyable vs guidance-only.
    let (with_rewrite, guidance_only): (Vec<&SafeSuggestion>, Vec<&SafeSuggestion>) =
        suggestions.iter().partition(|s| s.safe_command.is_some());

    // No mechanical rewrite anywhere — print every remediation and exit 1.
    // Never invent a rewrite (Risk #2 in the spec).
    if with_rewrite.is_empty() {
        eprintln!(
            "tirith fix: no mechanical rewrite available — see guidance below ({} finding(s))",
            verdict.findings.len()
        );
        for s in &guidance_only {
            eprintln!("  rule={}", s.rule_id);
            eprintln!("    rationale:   {}", s.rationale);
            eprintln!("    remediation: {}", s.remediation);
        }
        return 1;
    }

    // Interactive mode requires BOTH stdin and stderr to be TTYs (see
    // `is_tty_pair` for why stderr, not stdout).
    if !is_tty_pair() {
        // Surface what the user would have seen, then refuse to apply. Exit 2 =
        // "rewrite available but no accept signal", distinct from exit 1 above.
        eprintln!(
            "tirith fix: stdin/stdout is not a TTY — re-run with --non-interactive --json \
             to capture suggestions, or attach a TTY to apply one."
        );
        for (i, s) in with_rewrite.iter().enumerate() {
            eprintln!(
                "  [{}] rule={} rewrite={} — {}",
                i + 1,
                s.rule_id,
                s.safe_command.as_deref().unwrap_or(""),
                s.rationale
            );
        }
        return 2;
    }

    // Interactive presenter. Prompt + suggestion list go to stderr so stdout
    // stays clean for the chosen `safe_command` (the `$(tirith fix …)` contract).
    eprintln!("tirith fix: {} finding(s) in:", verdict.findings.len());
    eprintln!("  {cmd}");
    eprintln!("verdict: {}", action_str(verdict.action));
    eprintln!();
    eprintln!("Suggestions:");
    for (i, s) in with_rewrite.iter().enumerate() {
        let sc = s.safe_command.as_deref().unwrap_or("");
        eprintln!(
            "  [{}] rule={} rewrite={} — {}",
            i + 1,
            s.rule_id,
            sc,
            s.rationale
        );
    }
    // Surface guidance-only entries too (unnumbered — they can't be applied).
    if !guidance_only.is_empty() {
        eprintln!();
        eprintln!("Guidance (no mechanical rewrite):");
        for s in &guidance_only {
            eprintln!("  rule={} — {}", s.rule_id, s.remediation);
        }
    }

    let n = with_rewrite.len();
    eprint!("\nApply (1-{n})? [n] ");
    let _ = io::stderr().flush();

    let stdin = io::stdin();
    let mut handle = stdin.lock();
    let mut buf = String::new();
    match handle.read_line(&mut buf) {
        Ok(0) => {
            // EOF before input — treat as reject.
            eprintln!("tirith fix: no input (EOF) — declining to apply");
            2
        }
        Err(e) => {
            eprintln!("tirith fix: stdin read failed: {e}");
            2
        }
        Ok(_) => {
            let trimmed = buf.trim();
            // `n`/`N`/`no`/empty → reject; any digit → try to apply.
            if trimmed.is_empty() || matches!(trimmed, "n" | "N" | "no" | "No") {
                eprintln!("tirith fix: declined");
                return 2;
            }
            match trimmed.parse::<usize>() {
                Ok(choice) if choice >= 1 && choice <= n => {
                    let sc = with_rewrite[choice - 1]
                        .safe_command
                        .as_deref()
                        .expect("partition guarantees safe_command is Some");
                    // The chosen rewrite goes to stdout (the `$(tirith fix …)` contract).
                    println!("{sc}");
                    0
                }
                _ => {
                    eprintln!("tirith fix: invalid choice '{trimmed}' — declined");
                    2
                }
            }
        }
    }
}

/// Map `Verdict::action` to the lowercase JSON token used in our envelope.
fn action_str(a: Action) -> &'static str {
    match a {
        Action::Allow => "allow",
        // WarnAck collapses to "warn" in the JSON view (mirrors lab.rs).
        Action::Warn | Action::WarnAck => "warn",
        Action::Block => "block",
    }
}

/// Interactive mode requires BOTH stdin and STDERR to be a TTY. We gate on
/// stderr, not stdout: the prompt goes to stderr so stdout stays clean for the
/// `$(tirith fix …)` capture contract, so gating on stdout would reject the
/// documented `eval "$(tirith fix ...)"` flow.
fn is_tty_pair() -> bool {
    is_terminal::is_terminal(std::io::stdin()) && is_terminal::is_terminal(std::io::stderr())
}

/// Stable JSON envelope for the no-findings case only (Allow under `--json` /
/// `--non-interactive`). Findings-present output is a plain JSON array of
/// [`SafeSuggestion`]. `applied` is always `false` here but kept so parsers can
/// branch on it uniformly across both shapes.
#[derive(Serialize)]
struct FixEnvelope<'a> {
    applied: bool,
    reason: &'a str,
    verdict: &'a str,
    command: &'a str,
}

fn emit_no_findings_envelope(envelope: &FixEnvelope<'_>) -> bool {
    let mut out = io::stdout().lock();
    if serde_json::to_writer_pretty(&mut out, envelope).is_err() || writeln!(out).is_err() {
        eprintln!("tirith fix: failed to write JSON output");
        return false;
    }
    true
}

fn emit_suggestions_array(suggestions: &[SafeSuggestion]) -> bool {
    let mut out = io::stdout().lock();
    if serde_json::to_writer_pretty(&mut out, suggestions).is_err() || writeln!(out).is_err() {
        eprintln!("tirith fix: failed to write JSON output");
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_str_collapses_warn_ack() {
        assert_eq!(action_str(Action::Allow), "allow");
        assert_eq!(action_str(Action::Warn), "warn");
        assert_eq!(action_str(Action::WarnAck), "warn");
        assert_eq!(action_str(Action::Block), "block");
    }

    #[test]
    fn no_findings_envelope_serializes_with_stable_keys() {
        // Public JSON contract for the no-findings case — pin keys + types so a
        // field rename/reorder trips CI.
        let envelope = FixEnvelope {
            applied: false,
            reason: "no_findings",
            verdict: "allow",
            command: "ls",
        };
        let json = serde_json::to_value(&envelope).unwrap();
        assert_eq!(json["applied"], serde_json::Value::Bool(false));
        assert_eq!(json["reason"], "no_findings");
        assert_eq!(json["verdict"], "allow");
        assert_eq!(json["command"], "ls");
    }
}
