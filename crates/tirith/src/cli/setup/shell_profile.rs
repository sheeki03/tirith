//! Install `eval "$(tirith init)"` into the user's shell profile.
//!
//! Manages a BEGIN/END marker block in the shell's rc file (zsh/bash/fish/
//! nushell/PowerShell) so the hook installs idempotently and updates/removes
//! without corrupting user content.

use std::fs;
use std::path::PathBuf;

const BEGIN_MARKER: &str = "# BEGIN tirith-hook v1";
const END_MARKER: &str = "# END tirith-hook";
const BEGIN_PREFIX: &str = "# BEGIN tirith-hook";

/// Check whether a binary path needs quoting for shell interpolation.
fn needs_quoting(s: &str) -> bool {
    s.bytes().any(|b| {
        matches!(
            b,
            b' ' | b'\''
                | b'"'
                | b'\t'
                | b'\n'
                | b'\r'
                | b'$'
                | b'\\'
                | b'`'
                | b'('
                | b')'
                | b'!'
                | b'&'
                | b'|'
                | b';'
                | b'<'
                | b'>'
                | b'*'
                | b'?'
                | b'['
                | b']'
                | b'{'
                | b'}'
                | b'~'
        )
    })
}

/// Single-quote a path for safe shell interpolation (per-shell escaping for an
/// embedded `'`). Returned unchanged when no special characters.
pub(crate) fn shell_quote(path: &str, shell: &str) -> String {
    if !needs_quoting(path) {
        return path.to_string();
    }
    match shell {
        // PowerShell doubles a literal ' to escape; POSIX/fish break out of the quote.
        "powershell" => format!("'{}'", path.replace('\'', "''")),
        _ => format!("'{}'", path.replace('\'', "'\\''")),
    }
}

/// Detect the user's default shell and return its profile file path.
fn detect_shell_profile() -> Option<(&'static str, PathBuf)> {
    let home = home::home_dir()?;
    let shell = crate::cli::init::detect_shell();

    let profile = match shell {
        "zsh" => home.join(".zshrc"),
        "bash" => {
            // .bashrc preferred; fall back to .bash_profile, else create .bashrc.
            let bashrc = home.join(".bashrc");
            let bash_profile = home.join(".bash_profile");
            if bashrc.exists() {
                bashrc
            } else if bash_profile.exists() {
                bash_profile
            } else {
                bashrc
            }
        }
        "fish" => home.join(".config").join("fish").join("config.fish"),
        "nushell" => {
            let config = home.join(".config").join("nushell").join("config.nu");
            // Only offer if the user already has a nushell config directory.
            if config.exists() || config.parent().map(|p| p.exists()).unwrap_or(false) {
                config
            } else {
                return None;
            }
        }
        "powershell" => {
            // On macOS/Linux, PowerShell profile lives under ~/.config/powershell/.
            let profile = home
                .join(".config")
                .join("powershell")
                .join("Microsoft.PowerShell_profile.ps1");
            if profile.exists() || profile.parent().map(|p| p.exists()).unwrap_or(false) {
                profile
            } else {
                return None;
            }
        }
        _ => return None,
    };

    Some((shell, profile))
}

/// Detect a manually-added `tirith init` (uncommented executable line). Skips
/// comments/blanks to avoid false positives on `# TODO: tirith init`.
fn has_executable_tirith_init(content: &str) -> bool {
    content.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            return false;
        }
        if trimmed.is_empty() {
            return false;
        }
        trimmed.contains("tirith init")
    })
}

/// Validate that each BEGIN marker has a matching END marker. Err on unbalanced
/// or nested markers so `remove_hook_blocks` never silently drops user content.
fn validate_marker_pairing(content: &str) -> Result<(), String> {
    let mut in_block = false;
    for line in content.lines() {
        if line.starts_with(BEGIN_PREFIX) {
            if in_block {
                return Err(
                    "corrupted tirith-hook block — nested BEGIN markers, fix manually".to_string(),
                );
            }
            in_block = true;
        } else if line == END_MARKER {
            if !in_block {
                return Err(
                    "corrupted tirith-hook block — END marker without BEGIN, fix manually"
                        .to_string(),
                );
            }
            in_block = false;
        }
    }
    if in_block {
        return Err("corrupted tirith-hook block — missing END marker, fix manually".to_string());
    }
    Ok(())
}

/// Extract the full managed block (BEGIN through END, inclusive) from content.
fn extract_managed_block(content: &str) -> Option<String> {
    let mut in_block = false;
    let mut block_lines = Vec::new();

    for line in content.lines() {
        if line.starts_with(BEGIN_PREFIX) {
            in_block = true;
            block_lines.push(line);
            continue;
        }
        if in_block {
            block_lines.push(line);
            if line == END_MARKER {
                break;
            }
        }
    }

    if block_lines.is_empty() {
        None
    } else {
        let mut out = block_lines.join("\n");
        out.push('\n');
        Some(out)
    }
}

/// Install the tirith shell hook (a managed block with the detected shell's init
/// line) into the user's profile. Idempotent: skips a matching block unless
/// `force`, reports drift when content differs.
///
/// For bash (non-dry-run) also runs the enter-mode delivery self-test (issue
/// #111) and caches the verdict so the next shell picks enter-vs-preexec
/// correctly. The probe is best-effort and never fails the setup.
pub fn install_shell_hook(tirith_bin: &str, force: bool, dry_run: bool) -> Result<(), String> {
    let result = install_shell_hook_inner(tirith_bin, force, dry_run);

    // Refresh the bash enter-mode capability cache after a successful install,
    // scoped to bash users without threading the shell name through the inner fn.
    #[cfg(unix)]
    if result.is_ok() && !dry_run {
        if let Some(("bash", _)) = detect_shell_profile() {
            let _ = crate::cli::bash_capability::run_and_cache();
        }
    }

    result
}

fn install_shell_hook_inner(tirith_bin: &str, force: bool, dry_run: bool) -> Result<(), String> {
    let (shell, profile_path) = detect_shell_profile().ok_or_else(|| {
        "could not detect shell — add eval \"$(tirith init)\" to your shell profile manually"
            .to_string()
    })?;

    let quoted_bin = shell_quote(tirith_bin, shell);
    let hook_line = match shell {
        "fish" => format!("{quoted_bin} init --shell fish | source"),
        "nushell" => {
            // Nushell can't eval dynamically — resolve the source path at setup time.
            match std::process::Command::new(tirith_bin)
                .args(["init", "--shell", "nushell"])
                .output()
            {
                Ok(out) if out.status.success() => {
                    String::from_utf8_lossy(&out.stdout).trim().to_string()
                }
                _ => {
                    return Err(
                        "could not resolve nushell hook path — run `tirith init --shell nushell` \
                         and add the output to your config.nu manually"
                            .to_string(),
                    );
                }
            }
        }
        "powershell" => {
            format!("Invoke-Expression (& {quoted_bin} init --shell powershell)")
        }
        _ => format!("eval \"$({quoted_bin} init)\""),
    };

    let managed_block = format!("{BEGIN_MARKER}\n{hook_line}\n{END_MARKER}\n");

    let existing = if profile_path.exists() {
        fs::read_to_string(&profile_path)
            .map_err(|e| format!("read {}: {e}", profile_path.display()))?
    } else {
        String::new()
    };

    let begin_count = existing
        .lines()
        .filter(|line| line.starts_with(BEGIN_PREFIX))
        .count();

    // If the user manually added `tirith init` (no managed block), don't
    // touch their profile — they opted out of the managed setup.
    if begin_count == 0 && has_executable_tirith_init(&existing) {
        eprintln!(
            "tirith: shell hook already in {} (manually added), skipping",
            profile_path.display()
        );
        return Ok(());
    }

    validate_marker_pairing(&existing)?;

    match begin_count {
        0 => {
            if dry_run {
                eprintln!(
                    "[dry-run] would append tirith shell hook to {}",
                    profile_path.display()
                );
                return Ok(());
            }

            let mut content = existing;
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            if !content.is_empty() {
                content.push('\n');
            }
            content.push_str(&managed_block);

            super::fs_helpers::atomic_write(&profile_path, &content, 0o644)?;
            eprintln!("tirith: added shell hook to {}", profile_path.display());
        }
        1 => {
            let existing_block = extract_managed_block(&existing);
            let matches = existing_block
                .as_deref()
                .map(|b| b == managed_block)
                .unwrap_or(false);

            if matches && !force {
                eprintln!(
                    "tirith: shell hook already in {}, up to date",
                    profile_path.display()
                );
                return Ok(());
            }

            if !matches && !force {
                return Err(format!(
                    "shell hook in {} has different content than expected — use --force to update",
                    profile_path.display()
                ));
            }

            if dry_run {
                eprintln!(
                    "[dry-run] would replace tirith shell hook in {}",
                    profile_path.display()
                );
                return Ok(());
            }

            let cleaned = remove_hook_blocks(&existing);
            let mut content = cleaned;
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push('\n');
            content.push_str(&managed_block);

            super::fs_helpers::atomic_write(&profile_path, &content, 0o644)?;
            eprintln!("tirith: replaced shell hook in {}", profile_path.display());
        }
        _ => {
            if !force {
                return Err(format!(
                    "multiple tirith-hook blocks found in {} — use --force to deduplicate",
                    profile_path.display()
                ));
            }
            if dry_run {
                eprintln!(
                    "[dry-run] would deduplicate tirith-hook blocks in {}",
                    profile_path.display()
                );
                return Ok(());
            }

            let cleaned = remove_hook_blocks(&existing);
            let mut content = cleaned;
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push('\n');
            content.push_str(&managed_block);

            super::fs_helpers::atomic_write(&profile_path, &content, 0o644)?;
            eprintln!(
                "tirith: deduplicated tirith-hook blocks in {}",
                profile_path.display()
            );
        }
    }

    Ok(())
}

/// Remove all lines between BEGIN/END markers (inclusive). Caller MUST call
/// `validate_marker_pairing` first — this does not re-validate, and unbalanced
/// markers would drop trailing content.
fn remove_hook_blocks(content: &str) -> String {
    let mut result = Vec::new();
    let mut suppressing = false;

    for line in content.lines() {
        if line.starts_with(BEGIN_PREFIX) {
            suppressing = true;
            continue;
        }
        if line == END_MARKER {
            suppressing = false;
            continue;
        }
        if !suppressing {
            result.push(line);
        }
    }

    let mut out = result.join("\n");
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_simple_name_unchanged() {
        assert_eq!(shell_quote("tirith", "zsh"), "tirith");
        assert_eq!(shell_quote("tirith", "fish"), "tirith");
        assert_eq!(shell_quote("tirith", "powershell"), "tirith");
    }

    #[test]
    fn quote_path_with_spaces_posix() {
        assert_eq!(
            shell_quote("/usr/local/my apps/tirith", "zsh"),
            "'/usr/local/my apps/tirith'"
        );
        assert_eq!(
            shell_quote("/usr/local/my apps/tirith", "bash"),
            "'/usr/local/my apps/tirith'"
        );
    }

    #[test]
    fn quote_path_with_spaces_fish() {
        assert_eq!(
            shell_quote("/usr/local/my apps/tirith", "fish"),
            "'/usr/local/my apps/tirith'"
        );
    }

    #[test]
    fn quote_path_with_spaces_powershell() {
        assert_eq!(
            shell_quote("/usr/local/my apps/tirith", "powershell"),
            "'/usr/local/my apps/tirith'"
        );
    }

    #[test]
    fn quote_path_with_single_quote_posix() {
        assert_eq!(
            shell_quote("/opt/it's/tirith", "zsh"),
            "'/opt/it'\\''s/tirith'"
        );
    }

    #[test]
    fn quote_path_with_single_quote_powershell() {
        assert_eq!(
            shell_quote("/opt/it's/tirith", "powershell"),
            "'/opt/it''s/tirith'"
        );
    }

    #[test]
    fn quote_path_with_dollar_sign() {
        assert_eq!(
            shell_quote("/home/$user/tirith", "bash"),
            "'/home/$user/tirith'"
        );
    }

    #[test]
    fn quote_path_with_redirection_and_glob_chars() {
        assert_eq!(
            shell_quote("/tmp/hook>[abc]?*", "bash"),
            "'/tmp/hook>[abc]?*'"
        );
    }

    #[test]
    fn detects_eval_form() {
        let content = "export PATH=...\neval \"$(tirith init)\"\n";
        assert!(has_executable_tirith_init(content));
    }

    #[test]
    fn detects_fish_form() {
        let content = "set -x PATH ...\ntirith init --shell fish | source\n";
        assert!(has_executable_tirith_init(content));
    }

    #[test]
    fn skips_commented_line() {
        let content = "# eval \"$(tirith init)\"\n# TODO: add tirith init\n";
        assert!(!has_executable_tirith_init(content));
    }

    #[test]
    fn skips_empty_file() {
        assert!(!has_executable_tirith_init(""));
        assert!(!has_executable_tirith_init("\n\n"));
    }

    #[test]
    fn valid_single_block() {
        let content = "before\n# BEGIN tirith-hook v1\nhook\n# END tirith-hook\nafter\n";
        assert!(validate_marker_pairing(content).is_ok());
    }

    #[test]
    fn valid_no_blocks() {
        assert!(validate_marker_pairing("just content\n").is_ok());
    }

    #[test]
    fn missing_end_marker() {
        let content = "# BEGIN tirith-hook v1\nhook\nno end\n";
        let err = validate_marker_pairing(content).unwrap_err();
        assert!(err.contains("missing END"), "got: {err}");
    }

    #[test]
    fn orphan_end_marker() {
        let content = "stuff\n# END tirith-hook\n";
        let err = validate_marker_pairing(content).unwrap_err();
        assert!(err.contains("END marker without BEGIN"), "got: {err}");
    }

    #[test]
    fn nested_begin_markers() {
        let content = "# BEGIN tirith-hook v1\n# BEGIN tirith-hook v1\n# END tirith-hook\n";
        let err = validate_marker_pairing(content).unwrap_err();
        assert!(err.contains("nested BEGIN"), "got: {err}");
    }

    #[test]
    fn extract_existing_block() {
        let content =
            "before\n# BEGIN tirith-hook v1\neval \"$(tirith init)\"\n# END tirith-hook\nafter\n";
        let block = extract_managed_block(content).unwrap();
        assert_eq!(
            block,
            "# BEGIN tirith-hook v1\neval \"$(tirith init)\"\n# END tirith-hook\n"
        );
    }

    #[test]
    fn extract_no_block() {
        assert!(extract_managed_block("just content\n").is_none());
    }

    #[test]
    fn remove_single_block() {
        let content =
            "before\n# BEGIN tirith-hook v1\neval \"$(tirith init)\"\n# END tirith-hook\nafter\n";
        let result = remove_hook_blocks(content);
        assert_eq!(result, "before\nafter\n");
    }

    #[test]
    fn remove_multiple_blocks() {
        let content = "# BEGIN tirith-hook v1\nline1\n# END tirith-hook\nmiddle\n# BEGIN tirith-hook v1\nline2\n# END tirith-hook\nend\n";
        let result = remove_hook_blocks(content);
        assert_eq!(result, "middle\nend\n");
    }

    #[test]
    fn remove_no_blocks() {
        let content = "just content\nno hook\n";
        let result = remove_hook_blocks(content);
        assert_eq!(result, "just content\nno hook\n");
    }

    #[test]
    fn remove_preserves_surrounding_content() {
        let content = "export FOO=bar\n# BEGIN tirith-hook v1\neval stuff\n# END tirith-hook\nexport BAZ=qux\n";
        let result = remove_hook_blocks(content);
        assert_eq!(result, "export FOO=bar\nexport BAZ=qux\n");
    }

    #[test]
    fn end_marker_exact_match_only() {
        // "# END tirith-hooking" is a prefix match but NOT equal to the END
        // marker, so it stays inside the block and gets removed with it.
        let content =
            "# BEGIN tirith-hook v1\nhook\n# END tirith-hooking\nstuff\n# END tirith-hook\n";
        let result = remove_hook_blocks(content);
        assert_eq!(result, "");
    }

    #[test]
    fn drift_detected_when_content_differs() {
        let existing_block =
            "# BEGIN tirith-hook v1\neval \"$(old-tirith init)\"\n# END tirith-hook\n";
        let new_block = "# BEGIN tirith-hook v1\neval \"$(tirith init)\"\n# END tirith-hook\n";
        assert_ne!(existing_block, new_block);
    }
}
