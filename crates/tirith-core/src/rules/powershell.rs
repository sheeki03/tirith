//! PowerShell-specific detection rules.
//!
//! Three Windows/PowerShell-only patterns `command.rs` doesn't cover:
//! 1. `Set-ExecutionPolicy Bypass` (cmdlet + `powershell -ExecutionPolicy Bypass`
//!    flag forms) — [`RuleId::PsSetExecutionPolicyBypass`].
//! 2. `Add-MpPreference -ExclusionPath|-ExclusionProcess` — [`RuleId::PsDefenderExclusion`].
//! 3. Inline `iex (iwr https://...)` with `iex`/`invoke-expression` LEADING (not a
//!    pipe RHS) — [`RuleId::PsInlineDownloadExecute`].
//!
//! Scope boundary with `command.rs`: the pipe form `iwr url | iex` is NOT covered
//! here — `command::check`'s `check_pipe_to_interpreter` already catches it (via
//! the `pipe_to_interpreter` PATTERN_TABLE entry), and double-firing would noise
//! the verdict. So `is_pipe_separator` skips only `|` / `|&`; other PS separators
//! (`;`, `\n`, `-and`, `-or`, `&&`, `||`) start fresh commands that
//! `pipe_to_interpreter` does NOT match, where `check_inline_download_execute`
//! still fires (e.g. `true; iex (iwr url)`). PS 5.1 lacks `&&`/`||`, but tirith
//! scans the input string before that parse, so chained `iex` is still flagged.
//!
//! Fixtures: `ps_iex_pipe_already_covered_not_double` pins the pipe boundary;
//! `ps_iex_inline_after_{semicolon,and,or}_chained` pin the chained cases.
//!
//! Engine wiring: these rules run only when `ctx.shell == ShellType::PowerShell`
//! — the gate lives in `engine.rs`.

use crate::redact;
use crate::rules::command::{normalize_cmd_base, normalize_shell_token};
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Run PowerShell-specific detection rules against `input`. Caller must ensure
/// `shell == ShellType::PowerShell` (gated in `engine.rs`). Tier-1 patterns are
/// still required so the fast gate doesn't filter the input out first — the
/// `build.rs` PATTERN_TABLE entries are `ps_set_execution_policy`,
/// `ps_defender_exclusion`, `ps_iex_inline`.
pub fn check(input: &str, shell: ShellType) -> Vec<Finding> {
    let mut findings = Vec::new();
    let segments = tokenize::tokenize(input, shell);

    check_set_execution_policy(&segments, shell, &mut findings);
    check_defender_exclusion(&segments, shell, &mut findings);
    check_inline_download_execute(&segments, shell, &mut findings);

    findings
}

/// Detect both shapes of `Set-ExecutionPolicy Bypass`:
/// 1. Cmdlet form — leader `set-executionpolicy` with `bypass` in the args.
///    Note: `sep` is NOT matched — it is not a default alias (`Get-Alias sep`
///    is empty), and including it caused tier-1 false-positives on benign
///    `$sep = ","`.
/// 2. Flag form — leader `powershell`/`pwsh` with both `-executionpolicy` and
///    `bypass` in the args.
fn check_set_execution_policy(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    for seg in segments {
        let Some(ref cmd) = seg.command else { continue };
        let cmd_base = normalize_cmd_base(cmd, shell);

        let cmdlet_path = cmd_base.as_str() == "set-executionpolicy";
        let flag_path = matches!(cmd_base.as_str(), "powershell" | "pwsh");
        if !cmdlet_path && !flag_path {
            continue;
        }

        // Cmdlet form: the value may be positional (`Set-ExecutionPolicy Bypass`)
        // or named, separated or joined with `=`/`:`. PR #121 item 12: the
        // colon-joined form was the pre-fix gap. `has_execution_policy_bypass_flag`
        // covers all named forms; the positional check below covers the rest.
        if cmdlet_path {
            let mentions_bypass = seg.args.iter().any(|a| {
                let n = normalize_shell_token(a.trim(), shell);
                n.eq_ignore_ascii_case("bypass")
            }) || has_execution_policy_bypass_flag(&seg.args, shell);
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

/// True if `args` has both a `-ExecutionPolicy`-style flag and a `Bypass` value,
/// in any binding form: separated (`-ExecutionPolicy Bypass`) or joined with
/// `=`/`:` (PR #121 item 12), and the `-ep` / `-ex` aliases (PS accepts any
/// unambiguous prefix; `-ex` appears in published payloads).
fn has_execution_policy_bypass_flag(args: &[String], shell: ShellType) -> bool {
    // Constant array (not chained `strip_prefix`) so the joined- and
    // separated-form branches share the same names.
    const FLAG_NAMES: &[&str] = &["-executionpolicy", "-ep", "-ex"];

    for (i, arg) in args.iter().enumerate() {
        let n = normalize_shell_token(arg.trim(), shell);
        let lower = n.to_ascii_lowercase();

        // Joined form `-<flag>=Bypass` / `-<flag>:Bypass`: PS treats `:` and `=`
        // as equivalent. The colon form is favored in payloads because some
        // detectors only check `=` (PR #121 item 12 mandates both).
        for flag in FLAG_NAMES {
            for sep in ['=', ':'] {
                let prefix = format!("{flag}{sep}");
                if let Some(value) = lower.strip_prefix(&prefix) {
                    if value.trim_matches(|c: char| c == '"' || c == '\'') == "bypass" {
                        return true;
                    }
                }
            }
        }

        // Separated form `-<flag> Bypass` (value in args[i+1]).
        if FLAG_NAMES.contains(&lower.as_str()) {
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

/// Detect `Add-MpPreference -ExclusionPath|-ExclusionProcess|-ExclusionExtension`
/// — all whitelist the target from Defender scanning, a documented evasion step.
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
            // Bare flag plus joined `=`/`:` forms. PR #121 item 12 adds the colon
            // form (`-ExclusionPath:C:\...`), a payload shape that previously
            // passed tier-3 with no finding.
            const FLAGS: &[&str] = &["-exclusionpath", "-exclusionprocess", "-exclusionextension"];
            FLAGS.iter().any(|f| {
                n == *f || n.starts_with(&format!("{f}=")) || n.starts_with(&format!("{f}:"))
            })
        });
        if !mentions_exclusion {
            continue;
        }

        findings.push(Finding {
            rule_id: RuleId::PsDefenderExclusion,
            severity: Severity::High,
            title: "Windows Defender exclusion added via Add-MpPreference".to_string(),
            description: "Add-MpPreference -ExclusionPath/-ExclusionProcess/-ExclusionExtension \
                          disables Defender real-time scanning for the target. Malware uses \
                          this to persist undetected — investigate any payload that \
                          will appear in the excluded path / process / file type."
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

/// Detect inline `iex (iwr https://...)` where `iex`/`invoke-expression` LEADS
/// the segment and an arg contains `://`.
///
/// Boundary with `pipe_to_interpreter`: the pipe form `iwr url | iex` already
/// fires it, so skip pipe-preceded segments (`|`/`|&`). Other separators (`;`,
/// `\n`, `-and`, `-or`, `&&`, `||`) start independent commands it does NOT cover,
/// so this rule still fires there (e.g. `true; iex (iwr url)`).
fn check_inline_download_execute(
    segments: &[tokenize::Segment],
    shell: ShellType,
    findings: &mut Vec<Finding>,
) {
    for seg in segments {
        // Pipe RHS is already covered by pipe_to_interpreter — skip. Non-pipe
        // separators start fresh commands it does NOT match, so keep checking.
        if let Some(sep) = seg.preceding_separator.as_deref() {
            if is_pipe_separator(sep) {
                continue;
            }
        }

        let Some(ref cmd) = seg.command else { continue };
        let cmd_base = normalize_cmd_base(cmd, shell);
        // Match `iex (iwr ...)` (space before `(` → clean `iex` + arg) and
        // `iex(iwr ...)` (no space → the tokenizer pulls `(` into the command
        // token, e.g. `iex(iwr`). Both are identical to PowerShell.
        let is_iex_leading = cmd_base == "iex"
            || cmd_base == "invoke-expression"
            || cmd_base.starts_with("iex(")
            || cmd_base.starts_with("invoke-expression(");
        if !is_iex_leading {
            continue;
        }

        // The URL may be in the args (whitespace form) or in the command token
        // itself (e.g. `iex(iwr,https://...)` pulls `://` into it). Scan both.
        let has_url_arg = cmd_base.contains("://")
            || seg.args.iter().any(|a| {
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

/// True if `sep` is a pipe separator `pipe_to_interpreter` already handles.
/// `tokenize.rs` encodes pipes as `"|"` and `"|&"`; all other separators start
/// fresh commands that rule does NOT cover, so this one must still run on them.
fn is_pipe_separator(sep: &str) -> bool {
    sep == "|" || sep == "|&"
}
