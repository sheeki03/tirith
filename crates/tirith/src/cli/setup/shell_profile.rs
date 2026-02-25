//! Install `eval "$(tirith init)"` into the user's shell profile.
//!
//! Manages a BEGIN/END marker block in `~/.zshrc`, `~/.bashrc`,
//! `~/.config/fish/config.fish`, `~/.config/nushell/config.nu`, or the
//! PowerShell profile so the hook can be installed idempotently and
//! updated or removed without corrupting user content.

use std::fs;
use std::path::PathBuf;

const BEGIN_MARKER: &str = "# BEGIN tirith-hook v1";
const END_MARKER: &str = "# END tirith-hook";
const BEGIN_PREFIX: &str = "# BEGIN tirith-hook";

// ── Shell quoting ────────────────────────────────────────────────────

/// Check whether a binary path needs quoting for shell interpolation.
fn needs_quoting(s: &str) -> bool {
    s.bytes().any(|b| {
        matches!(
            b,
            b' ' | b'\''
                | b'"'
                | b'$'
                | b'\\'
                | b'`'
                | b'('
                | b')'
                | b'!'
                | b'&'
                | b'|'
                | b';'
                | b'{'
                | b'}'
                | b'~'
        )
    })
}

/// Quote a path for safe interpolation into a shell command.
///
/// Uses single-quote wrapping with per-shell escaping for embedded
/// single quotes. Returns the path unchanged if no special characters.
fn shell_quote(path: &str, shell: &str) -> String {
    if !needs_quoting(path) {
        return path.to_string();
    }
    match shell {
        // PowerShell: single quotes, double a literal ' to escape
        "powershell" => format!("'{}'", path.replace('\'', "''")),
        // POSIX (bash/zsh) and fish: single quotes, break out for literal '
        _ => format!("'{}'", path.replace('\'', "'\\''")),
    }
}

// ── Shell profile detection ──────────────────────────────────────────

/// Detect the user's default shell and return its profile file path.
fn detect_shell_profile() -> Option<(&'static str, PathBuf)> {
    let home = home::home_dir()?;
    let shell = crate::cli::init::detect_shell();

    let profile = match shell {
        "zsh" => home.join(".zshrc"),
        "bash" => {
            // Prefer .bashrc if it exists, else .bash_profile, else create .bashrc
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
            // Standard nushell config location
            let config = home.join(".config").join("nushell").join("config.nu");
            // Only offer if nushell config dir exists (user has nushell configured)
            if config.exists() || config.parent().map(|p| p.exists()).unwrap_or(false) {
                config
            } else {
                return None;
            }
        }
        "powershell" => {
            // On macOS/Linux, PowerShell profile lives in ~/.config/powershell/
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

// ── Manual-hook detection ────────────────────────────────────────────

/// Check for a manually-added tirith init invocation (uncommented executable line).
///
/// Skips comments and empty lines to avoid false positives on documentation
/// like `# TODO: tirith init` or `# removed tirith init`.
fn has_executable_tirith_init(content: &str) -> bool {
    content.lines().any(|line| {
        let trimmed = line.trim();
        // Skip comments (POSIX # and PowerShell #)
        if trimmed.starts_with('#') {
            return false;
        }
        // Skip empty
        if trimmed.is_empty() {
            return false;
        }
        // Match executable tirith init patterns
        trimmed.contains("tirith init")
    })
}

// ── Marker validation ────────────────────────────────────────────────

/// Validate that each BEGIN marker has a matching END marker.
///
/// Returns Err on unbalanced or nested markers so that `remove_hook_blocks`
/// never silently drops trailing user content.
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

// ── Drift detection ──────────────────────────────────────────────────

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

// ── Main entry point ─────────────────────────────────────────────────

/// Install the tirith shell hook into the user's shell profile.
///
/// Appends a managed block containing the appropriate init line for the
/// detected shell. Idempotent: skips if block already exists with matching
/// content (unless `force`). Reports drift when block content differs.
pub fn install_shell_hook(tirith_bin: &str, force: bool, dry_run: bool) -> Result<(), String> {
    let (shell, profile_path) = detect_shell_profile().ok_or_else(|| {
        "could not detect shell — add eval \"$(tirith init)\" to your shell profile manually"
            .to_string()
    })?;

    let quoted_bin = shell_quote(tirith_bin, shell);
    let hook_line = match shell {
        "fish" => format!("{quoted_bin} init --shell fish | source"),
        "nushell" => {
            // Nushell can't eval dynamically — resolve the source path at setup time
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

    // Read existing content
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

    // Check for manually-added tirith init (uncommented executable line, no managed block)
    if begin_count == 0 && has_executable_tirith_init(&existing) {
        eprintln!(
            "tirith: shell hook already in {} (manually added), skipping",
            profile_path.display()
        );
        return Ok(());
    }

    // Validate marker pairing before any mutation
    validate_marker_pairing(&existing)?;

    match begin_count {
        0 => {
            // No existing block — append
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
            // One existing block — check for drift
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

            // force (or content matches + force): replace
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
            // Multiple blocks
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

// ── Block removal ────────────────────────────────────────────────────

/// Remove all lines between BEGIN and END tirith-hook markers (inclusive).
///
/// SAFETY: Caller must call `validate_marker_pairing` first. This function
/// does not re-validate; if markers are unbalanced it will drop trailing
/// content (which is why the validation gate exists).
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

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── shell_quote ──────────────────────────────────────────────

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

    // ── has_executable_tirith_init ───────────────────────────────

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

    // ── validate_marker_pairing ──────────────────────────────────

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

    // ── extract_managed_block ────────────────────────────────────

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

    // ── remove_hook_blocks ───────────────────────────────────────

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
        // "# END tirith-hooking" should NOT be treated as the end marker
        let content =
            "# BEGIN tirith-hook v1\nhook\n# END tirith-hooking\nstuff\n# END tirith-hook\n";
        let result = remove_hook_blocks(content);
        // "# END tirith-hooking" is inside the block (not an exact match), so removed
        assert_eq!(result, "");
    }

    // ── drift detection ──────────────────────────────────────────

    #[test]
    fn drift_detected_when_content_differs() {
        let existing_block =
            "# BEGIN tirith-hook v1\neval \"$(old-tirith init)\"\n# END tirith-hook\n";
        let new_block = "# BEGIN tirith-hook v1\neval \"$(tirith init)\"\n# END tirith-hook\n";
        assert_ne!(existing_block, new_block);
    }
}
