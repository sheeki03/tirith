//! `tirith fix` — interactive presenter over `tirith_core::safe_command::suggest`.
//!
//! Thin shim: tokenize → `engine::analyze` → `safe_command::suggest` → present.
//! Detection lives entirely in `tirith-core`; this module is presentation +
//! one-keystroke acceptance only. Never invents a rewrite — a finding whose
//! `safe_command` is `None` is rendered as honest guidance from its
//! `remediation` field, never fabricated into a synthetic command.
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
//! `check` uses 0/1/2/3 (allow/block/warn/warn-ack) — those codes are tied to
//! *verdict severity*. `fix`'s codes are tied to *whether a rewrite was
//! applied*. The two are deliberately different surfaces; the `--help`
//! after-help block in `main.rs` documents this.
//!
//! ## TTY gating
//!
//! Interactive mode requires BOTH `stdin` and `stderr` to be a TTY. Reading
//! from a redirected stdin or writing a prompt into a pipe is a footgun.
//! Stdout is intentionally reserved for the chosen `safe_command` so users
//! can wrap the call with `$(tirith fix …)` / `eval "$(tirith fix …)"` and
//! capture the rewrite. A `--non-interactive` flag or a non-TTY stdin/stderr
//! pair forces JSON-emit-and-exit behavior.
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
//! The acceptance criterion in the M6 plan ("emits valid JSON array") locks
//! the second shape. The first is the documented honest negative case so a
//! parser doesn't see an empty `[]` and miss the "nothing was wrong" signal.

use std::io::{self, BufRead, Write};

use serde::Serialize;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::safe_command::{self, SafeSuggestion};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::Action;

/// Public entry point for the `tirith fix` subcommand.
///
/// `command_parts` are joined with a single space to form the command text
/// (mirroring `tirith check`). `shell` accepts the same tokens as
/// `tirith check --shell` (e.g. `posix`, `bash`, `zsh`, `fish`, `powershell`,
/// `cmd`) — unknown values fall back to `ShellType::Posix` with a stderr
/// warning, matching `check`'s shape.
///
/// `non_interactive` forces JSON-emit behavior even on a TTY. `json` is the
/// strict superset of `non_interactive` — under either, the output is a
/// single JSON object on stdout and exit reflects the *content* of the
/// envelope (0 = no findings, 1 = guidance-only, 2 = rejected/no-TTY-with-rewrites).
///
/// Returns the process exit code per the table at the top of this module.
pub fn run(command_parts: &[String], shell: &str, non_interactive: bool, json: bool) -> i32 {
    // Empty command is a no-op (mirrors `tirith check`).
    let cmd = command_parts.join(" ");
    if cmd.trim().is_empty() {
        if json || non_interactive {
            // Surface JSON write failures (broken pipe, truncated output)
            // via exit code 2 — a piped consumer must not treat truncated
            // JSON as the documented `applied:false / no_findings` envelope.
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

    // `engine::analyze` is the same hot-path the check command runs. We
    // intentionally use `analyze` (not `analyze_returning_policy`) — fix is
    // advisory, never gates on policy decisions, and we don't audit log.
    let ctx = AnalysisContext {
        input: cmd.clone(),
        shell: shell_type,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        // We don't drive an interactive analysis branch; fix is a presenter.
        interactive: false,
        cwd: std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
    };
    let verdict = engine::analyze(&ctx);

    // Allow path: nothing to fix. Emit shape per output mode.
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

    // JSON / non-interactive path: emit a plain JSON array of every
    // suggestion. Never prompt. Exit code reflects content: 1 if no
    // mechanical rewrite exists (guidance-only); 2 if rewrites are present
    // but we can't get an accept signal — the plan's acceptance test
    // (`tirith fix --non-interactive -- "echo nope" </dev/null` → 2) pins
    // the latter for the common `--non-interactive` flow.
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

    // No mechanical rewrite anywhere — print every remediation honestly and
    // exit 1. Never invent a rewrite (Risk #2 in the spec).
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

    // Interactive mode requires BOTH stdin and stderr to be TTYs. Without
    // that, we can't honestly prompt — see `is_tty_pair` below for why
    // we gate on stderr (not stdout, which is the `$(tirith fix …)` capture
    // surface).
    if !is_tty_pair() {
        // Surface what the user would have seen, then refuse to apply. Exit 2
        // signals "rewrite was available but I couldn't get an accept signal"
        // — distinct from the "no rewrite" exit 1 above.
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

    // Interactive presenter. The prompt and the suggestion list go to stderr
    // so that stdout stays clean — accepting [N] prints exactly the chosen
    // `safe_command` to stdout on its own line, so users can wrap with
    // `$(tirith fix …)`.
    eprintln!("tirith fix: {} finding(s) in:", verdict.findings.len());
    eprintln!("  {cmd}");
    eprintln!("verdict: {}", action_str(verdict.action));
    eprintln!();
    eprintln!("Suggestions:");
    for (i, s) in with_rewrite.iter().enumerate() {
        // Sanitize the rewrite display: the library already does this
        // (`sanitize_for_display`) but mention the rule + rationale here.
        let sc = s.safe_command.as_deref().unwrap_or("");
        eprintln!(
            "  [{}] rule={} rewrite={} — {}",
            i + 1,
            s.rule_id,
            sc,
            s.rationale
        );
    }
    // Surface guidance-only entries too, so the user sees the full picture
    // (but they aren't numbered — they can't be applied).
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
            // EOF before any input. Treat like reject.
            eprintln!("tirith fix: no input (EOF) — declining to apply");
            2
        }
        Err(e) => {
            eprintln!("tirith fix: stdin read failed: {e}");
            2
        }
        Ok(_) => {
            let trimmed = buf.trim();
            // `n`/`N`/`no`/empty → reject. Any digit → try to apply.
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
                    // The chosen rewrite goes to stdout on its own line. This
                    // is the contract for `$(tirith fix …)` capture.
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
        // Collapse WarnAck → "warn" in the JSON view (mirrors lab.rs).
        Action::Warn | Action::WarnAck => "warn",
        Action::Block => "block",
    }
}

/// Helper kept local (the spec explicitly says to mirror lab.rs's pattern).
///
/// Interactive mode requires BOTH stdin and STDERR to be a TTY. The prompt
/// goes to stderr (so stdout stays clean for the `$(tirith fix …)` capture
/// contract — accepting a rewrite prints exactly the chosen `safe_command`
/// to stdout on its own line), so gating on stdout being a TTY would reject
/// the documented `eval "$(tirith fix ...)"` interactive flow. We check
/// stderr instead — that's the surface we actually need a TTY for.
fn is_tty_pair() -> bool {
    is_terminal::is_terminal(std::io::stdin()) && is_terminal::is_terminal(std::io::stderr())
}

/// Stable JSON envelope used ONLY for the no-findings case (verdict was
/// Allow under `--json` / `--non-interactive`). Findings-present output is a
/// plain JSON array of [`SafeSuggestion`], not this envelope — see the
/// module-level doc.
///
/// Field order is fixed via the struct definition so downstream consumers
/// can rely on shape stability. `applied` is always `false` in the
/// no-findings case; the field is kept so parsers can branch on it
/// uniformly across both shapes.
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
        // This envelope is the public JSON contract for the no-findings
        // case under `tirith fix --json`. A field rename or reorder here
        // breaks downstream parsers — pin the keys + types so a refactor
        // trips CI. (The findings-present case is just a JSON array of
        // SafeSuggestion, which is locked by `safe_command.rs`.)
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
