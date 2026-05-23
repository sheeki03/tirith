//! PowerShell-specific detection rules.
//!
//! Complements [`super::command`]'s shell-agnostic command rules with three
//! Windows / PowerShell-only patterns that the existing rules do not cover:
//!
//! 1. **`Set-ExecutionPolicy Bypass`** (cmdlet form *and* `powershell -ExecutionPolicy Bypass`
//!    flag form) — [`RuleId::PsSetExecutionPolicyBypass`].
//! 2. **`Add-MpPreference -ExclusionPath|-ExclusionProcess`** — [`RuleId::PsDefenderExclusion`].
//! 3. **Inline `iex (iwr https://...)`** where `iex` / `invoke-expression`
//!    is the *leading* command (not a pipe RHS) — [`RuleId::PsInlineDownloadExecute`].
//!
//! ## Scope boundary with `command.rs`
//!
//! The pipe form `iwr url | iex` (and `irm url | iex`) is **intentionally not**
//! covered here. It is already caught by [`crate::rules::command::check`]'s
//! `check_pipe_to_interpreter` via the `pipe_to_interpreter` PATTERN_TABLE
//! entry (which lists `iex` and `invoke-expression` as recognized pipe-RHS
//! interpreters). Double-firing would noise up the verdict and confuse
//! downstream policy.
//!
//! The negative fixture `ps_iex_pipe_already_covered_not_double` in
//! `tests/fixtures/command.toml` pins this boundary — its `preceding_separator`
//! is `Some("|")`, so `check_inline_download_execute` correctly skips it.
//!
//! ## Engine wiring
//!
//! These rules only run when `ctx.shell == ShellType::PowerShell`. POSIX
//! input never reaches this module — the gate lives in `engine.rs`.

use crate::redact;
use crate::rules::command::{normalize_cmd_base, normalize_shell_token};
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Run PowerShell-specific detection rules against `input`.
///
/// Callers must ensure `shell == ShellType::PowerShell` before invoking this —
/// the gate lives at the call site in `engine.rs` (`if ctx.shell == ShellType::PowerShell`).
/// Tier-1 patterns are still required so the fast gate doesn't filter the
/// input out before reaching this function; the corresponding `PATTERN_TABLE`
/// entries in `build.rs` are `ps_set_execution_policy`, `ps_defender_exclusion`,
/// and `ps_iex_inline`.
pub fn check(input: &str, shell: ShellType) -> Vec<Finding> {
    let mut findings = Vec::new();
    let segments = tokenize::tokenize(input, shell);

    check_set_execution_policy(&segments, shell, &mut findings);
    check_defender_exclusion(&segments, shell, &mut findings);
    check_inline_download_execute(&segments, shell, &mut findings);

    findings
}

/// Detect both shapes of `Set-ExecutionPolicy Bypass`:
///
/// 1. Cmdlet form — leading command `set-executionpolicy` (or alias `sep`)
///    with `bypass` somewhere in the args (case-insensitive after normalize).
/// 2. Flag form — leading command `powershell` (or `pwsh`) with both
///    `-executionpolicy` and `bypass` in the args.
fn check_set_execution_policy(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    for seg in segments {
        let Some(ref cmd) = seg.command else { continue };
        let cmd_base = normalize_cmd_base(cmd, shell);

        let cmdlet_path = matches!(cmd_base.as_str(), "set-executionpolicy" | "sep");
        let flag_path = matches!(cmd_base.as_str(), "powershell" | "pwsh");
        if !cmdlet_path && !flag_path {
            continue;
        }

        // Cmdlet form: first non-flag arg is the policy value.
        if cmdlet_path {
            let mentions_bypass = seg.args.iter().any(|a| {
                let n = normalize_shell_token(a.trim(), shell);
                n.eq_ignore_ascii_case("bypass")
            });
            if mentions_bypass {
                findings.push(Finding {
                    rule_id: RuleId::PsSetExecutionPolicyBypass,
                    severity: Severity::High,
                    title: "PowerShell ExecutionPolicy set to Bypass".to_string(),
                    description: "Set-ExecutionPolicy Bypass disables script signing \
                                  enforcement, allowing unsigned scripts (including any \
                                  fetched from the network) to run in the affected scope. \
                                  This is a common malware install step."
                        .to_string(),
                    evidence: vec![Evidence::CommandPattern {
                        pattern: "Set-ExecutionPolicy Bypass".to_string(),
                        matched: redact::redact_shell_assignments(&seg.raw),
                    }],
                    human_view: None,
                    agent_view: None,
                    mitre_id: None,
                    custom_rule_id: None,
                });
                continue;
            }
        }

        // Flag form: -ExecutionPolicy Bypass somewhere in args.
        if flag_path && has_execution_policy_bypass_flag(&seg.args, shell) {
            findings.push(Finding {
                rule_id: RuleId::PsSetExecutionPolicyBypass,
                severity: Severity::High,
                title: "PowerShell launched with -ExecutionPolicy Bypass".to_string(),
                description: "powershell.exe -ExecutionPolicy Bypass disables script \
                              signing enforcement for the spawned process. Often paired \
                              with -Command and an inline `iex (iwr ...)` to download \
                              and execute a remote payload without inspection."
                    .to_string(),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "powershell -ExecutionPolicy Bypass".to_string(),
                    matched: redact::redact_shell_assignments(&seg.raw),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }
}

/// Return true if `args` contains both a `-ExecutionPolicy`-style flag and a
/// `Bypass` value, in either of the standard forms:
///
/// * `-ExecutionPolicy Bypass`  (separate tokens)
/// * `-ExecutionPolicy=Bypass`  (joined)
/// * `-ep Bypass` / `-ep=Bypass` (short alias)
fn has_execution_policy_bypass_flag(args: &[String], shell: ShellType) -> bool {
    for (i, arg) in args.iter().enumerate() {
        let n = normalize_shell_token(arg.trim(), shell);
        let lower = n.to_ascii_lowercase();

        // Joined form: -executionpolicy=bypass / -ep=bypass
        if let Some(value) = lower
            .strip_prefix("-executionpolicy=")
            .or_else(|| lower.strip_prefix("-ep="))
        {
            if value.trim_matches(|c: char| c == '"' || c == '\'') == "bypass" {
                return true;
            }
        }

        // Separated form: -executionpolicy bypass / -ep bypass
        if lower == "-executionpolicy" || lower == "-ep" {
            if let Some(next) = args.get(i + 1) {
                let next_n = normalize_shell_token(next.trim(), shell);
                if next_n.eq_ignore_ascii_case("bypass") {
                    return true;
                }
            }
        }
    }
    false
}

/// Detect `Add-MpPreference -ExclusionPath <path>` or
/// `Add-MpPreference -ExclusionProcess <process>`. Both shapes whitelist
/// the target from Defender real-time scanning, a documented evasion step.
fn check_defender_exclusion(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    for seg in segments {
        let Some(ref cmd) = seg.command else { continue };
        let cmd_base = normalize_cmd_base(cmd, shell);
        if cmd_base != "add-mppreference" {
            continue;
        }

        let mentions_exclusion = seg.args.iter().any(|a| {
            let n = normalize_shell_token(a.trim(), shell).to_ascii_lowercase();
            // Match both bare flag and joined `-flag=value` (PowerShell allows both).
            n == "-exclusionpath"
                || n == "-exclusionprocess"
                || n.starts_with("-exclusionpath=")
                || n.starts_with("-exclusionprocess=")
        });
        if !mentions_exclusion {
            continue;
        }

        findings.push(Finding {
            rule_id: RuleId::PsDefenderExclusion,
            severity: Severity::High,
            title: "Windows Defender exclusion added via Add-MpPreference".to_string(),
            description: "Add-MpPreference -ExclusionPath/-ExclusionProcess disables \
                          Defender real-time scanning for the target. Malware uses \
                          this to persist undetected — investigate any payload that \
                          will appear in the excluded path."
                .to_string(),
            evidence: vec![Evidence::CommandPattern {
                pattern: "Add-MpPreference exclusion".to_string(),
                matched: redact::redact_shell_assignments(&seg.raw),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
}

/// Detect the inline `iex (iwr https://...)` form, where `iex` /
/// `invoke-expression` is the **leading** command for the segment and at
/// least one arg contains `://`.
///
/// **Boundary with `pipe_to_interpreter`:** the pipe form
/// `iwr https://… | iex` already fires `pipe_to_interpreter`. To avoid
/// double-firing we require `seg.preceding_separator.is_none()` — i.e. this
/// segment is the *start* of a sequence, not the RHS of a `|`.
fn check_inline_download_execute(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    for seg in segments {
        // Pipe RHS is already covered by pipe_to_interpreter — skip it.
        if seg.preceding_separator.is_some() {
            continue;
        }

        let Some(ref cmd) = seg.command else { continue };
        let cmd_base = normalize_cmd_base(cmd, shell);
        if cmd_base != "iex" && cmd_base != "invoke-expression" {
            continue;
        }

        let has_url_arg = seg.args.iter().any(|a| {
            let n = normalize_shell_token(a.trim(), shell);
            n.contains("://")
        });
        if !has_url_arg {
            continue;
        }

        findings.push(Finding {
            rule_id: RuleId::PsInlineDownloadExecute,
            severity: Severity::High,
            title: "PowerShell inline download-and-execute (iex with URL)".to_string(),
            description: "iex / Invoke-Expression is the leading command and one of \
                          its arguments contains a URL. The fetched content will be \
                          executed without inspection. Save the script with -OutFile \
                          and review it before running."
                .to_string(),
            evidence: vec![Evidence::CommandPattern {
                pattern: "iex (iwr <url>)".to_string(),
                matched: redact::redact_shell_assignments(&seg.raw),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
}
