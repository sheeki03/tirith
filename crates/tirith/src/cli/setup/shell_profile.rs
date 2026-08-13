//! Install `eval "$(tirith init)"` into the user's shell profile.
//!
//! Manages a BEGIN/END marker block in the shell's rc file (zsh/bash/fish/
//! nushell/PowerShell) so the hook installs idempotently and updates/removes
//! without corrupting user content.

use std::path::PathBuf;

const BEGIN_MARKER: &str = "# BEGIN tirith-hook v1";
const END_MARKER: &str = "# END tirith-hook";
const BEGIN_MARKER_STEM: &str = "# BEGIN tirith-hook v";

/// Match only the managed marker grammar, while still recognizing a future
/// numeric block version. Prefix-like user comments must remain user content.
fn is_managed_begin_marker(line: &str) -> bool {
    let Some(version) = line.strip_prefix(BEGIN_MARKER_STEM) else {
        return false;
    };
    !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
}

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
    if shell == "nushell" {
        return crate::cli::init::nushell_string_literal(path);
    }
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
fn detect_shell_profile() -> Result<Option<(&'static str, PathBuf)>, String> {
    let Some(home) = home::home_dir() else {
        return Ok(None);
    };
    let shell = crate::cli::init::detect_shell();

    Ok(profile_for_shell(shell, &home)?.map(|profile| (shell, profile)))
}

fn profile_for_shell(shell: &str, home: &std::path::Path) -> Result<Option<PathBuf>, String> {
    let profile = match shell {
        "zsh" => home.join(".zshrc"),
        "bash" => {
            // .bashrc preferred; fall back to .bash_profile, else create .bashrc.
            let bashrc = home.join(".bashrc");
            let bash_profile = home.join(".bash_profile");
            if super::fs_helpers::read_to_string_scoped(&bashrc, home)?.is_some() {
                bashrc
            } else if super::fs_helpers::read_to_string_scoped(&bash_profile, home)?.is_some() {
                bash_profile
            } else {
                bashrc
            }
        }
        "fish" => home.join(".config").join("fish").join("config.fish"),
        "nushell" => {
            let config = home.join(".config").join("nushell").join("config.nu");
            // Only offer if the user already has a nushell config directory.
            if super::fs_helpers::read_to_string_scoped(&config, home)?.is_some()
                || super::fs_helpers::parent_exists_scoped(&config, home)?
            {
                config
            } else {
                return Ok(None);
            }
        }
        "powershell" => {
            // On macOS/Linux, PowerShell profile lives under ~/.config/powershell/.
            let profile = home
                .join(".config")
                .join("powershell")
                .join("Microsoft.PowerShell_profile.ps1");
            if super::fs_helpers::read_to_string_scoped(&profile, home)?.is_some()
                || super::fs_helpers::parent_exists_scoped(&profile, home)?
            {
                profile
            } else {
                return Ok(None);
            }
        }
        _ => return Ok(None),
    };

    Ok(Some(profile))
}

fn revalidate_profile_selection(
    shell: &str,
    home: &std::path::Path,
    expected: &std::path::Path,
) -> Result<(), String> {
    let selected = profile_for_shell(shell, home)?;
    if selected.as_deref() != Some(expected) {
        return Err(format!(
            "shell profile selection changed while setup was running; refusing to update {}",
            expected.display()
        ));
    }
    Ok(())
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
        // repo-0495: a substring match counts `echo "tirith init"` or
        // `false && eval "$(tirith init)"` as installed. Require a real
        // activation shape: a leading eval/source/direct invocation of
        // `tirith init`.
        trimmed.starts_with("tirith init")
            || ((trimmed.starts_with("eval") || trimmed.starts_with("source"))
                && (trimmed.contains("$(tirith init")
                    || trimmed.contains("`tirith init")
                    || trimmed.contains("<(tirith init")))
    })
}

/// Validate that each BEGIN marker has a matching END marker. Err on unbalanced
/// or nested markers so `remove_hook_blocks` never silently drops user content.
fn validate_marker_pairing(content: &str) -> Result<(), String> {
    let mut in_block = false;
    for line in content.lines() {
        if is_managed_begin_marker(line) {
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
        if is_managed_begin_marker(line) {
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
        if let Ok(Some(("bash", _))) = detect_shell_profile() {
            let _ = crate::cli::bash_capability::run_and_cache();
        }
    }

    result
}

fn install_shell_hook_inner(tirith_bin: &str, force: bool, dry_run: bool) -> Result<(), String> {
    let home = home::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;
    let (shell, profile_path) = detect_shell_profile()?.ok_or_else(|| {
        "could not detect shell — add eval \"$(tirith init)\" to your shell profile manually"
            .to_string()
    })?;

    let quoted_bin = shell_quote(tirith_bin, shell);
    let hook_line = match shell {
        "fish" => format!("{quoted_bin} init --shell fish | source"),
        "nushell" => {
            // Nushell cannot eval dynamically. Resolve the same hook asset that
            // `tirith init --shell nushell` would print without spawning a
            // second Tirith process with inherited environment or unbounded I/O.
            resolve_nushell_hook_line()?
        }
        "powershell" => {
            format!("Invoke-Expression (& {quoted_bin} init --shell powershell)")
        }
        _ => format!("eval \"$({quoted_bin} init)\""),
    };

    let managed_block = format!("{BEGIN_MARKER}\n{hook_line}\n{END_MARKER}\n");
    let mut completed_verb = "updated";
    let outcome = super::fs_helpers::transactional_update_checked(
        &profile_path,
        &home,
        dry_run,
        |snapshot| {
            let existing = snapshot.text(&profile_path)?.unwrap_or_default();
            let begin_count = existing
                .lines()
                .filter(|line| is_managed_begin_marker(line))
                .count();

            // A manually-added hook is an intentional opt-out from managed
            // setup and must remain untouched.
            if begin_count == 0 && has_executable_tirith_init(existing) {
                eprintln!(
                    "tirith: shell hook already in {} (manually added), skipping",
                    profile_path.display()
                );
                return Ok(super::fs_helpers::FileUpdate::unchanged());
            }
            validate_marker_pairing(existing)?;

            let mut content = match begin_count {
                0 => {
                    completed_verb = "added";
                    if dry_run {
                        eprintln!(
                            "[dry-run] would append tirith shell hook to {}",
                            profile_path.display()
                        );
                    }
                    existing.to_string()
                }
                1 => {
                    let matches = extract_managed_block(existing)
                        .as_deref()
                        .is_some_and(|block| block == managed_block);
                    if matches && !force {
                        eprintln!(
                            "tirith: shell hook already in {}, up to date",
                            profile_path.display()
                        );
                        return Ok(super::fs_helpers::FileUpdate::unchanged());
                    }
                    if !matches && !force {
                        return Err(format!(
                            "shell hook in {} has different content than expected — use --force to update",
                            profile_path.display()
                        ));
                    }
                    completed_verb = "replaced";
                    if dry_run {
                        eprintln!(
                            "[dry-run] would replace tirith shell hook in {}",
                            profile_path.display()
                        );
                    }
                    remove_hook_blocks(existing)
                }
                _ if !force => {
                    return Err(format!(
                        "multiple tirith-hook blocks found in {} — use --force to deduplicate",
                        profile_path.display()
                    ));
                }
                _ => {
                    completed_verb = "deduplicated";
                    if dry_run {
                        eprintln!(
                            "[dry-run] would deduplicate tirith-hook blocks in {}",
                            profile_path.display()
                        );
                    }
                    remove_hook_blocks(existing)
                }
            };
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            if !content.is_empty() {
                content.push('\n');
            }
            content.push_str(&managed_block);
            Ok(super::fs_helpers::FileUpdate::write_text(content, 0o644))
        },
        || revalidate_profile_selection(shell, &home, &profile_path),
    )?;
    if let Some(annotation) = outcome.completion_annotation() {
        eprintln!(
            "tirith: {completed_verb} shell hook in {}{annotation}",
            profile_path.display(),
        );
    }

    Ok(())
}

fn resolve_nushell_hook_line() -> Result<String, String> {
    let hook_dir = crate::cli::init::find_hook_dir().ok_or_else(|| {
        "could not resolve nushell hook path — run `tirith init --shell nushell` and add the output to your config.nu manually"
            .to_string()
    })?;
    nushell_hook_line_for_dir(&hook_dir)
}

fn nushell_hook_line_for_dir(hook_dir: &std::path::Path) -> Result<String, String> {
    let hook_path = hook_dir.join("lib").join("nushell-hook.nu");
    let hook_path_text = super::run_impl::path_to_utf8(&hook_path, "Nushell hook")?;
    if !hook_path.is_file() {
        return Err(format!(
            "resolved nushell hook is missing or not a file: {}",
            hook_path.display()
        ));
    }
    Ok(format!(
        "source {}",
        shell_quote(&hook_path_text, "nushell")
    ))
}

/// Remove all lines between BEGIN/END markers (inclusive). Caller MUST call
/// `validate_marker_pairing` first — this does not re-validate, and unbalanced
/// markers would drop trailing content.
fn remove_hook_blocks(content: &str) -> String {
    let mut result = Vec::new();
    let mut suppressing = false;

    for line in content.lines() {
        if is_managed_begin_marker(line) {
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
    fn nushell_hook_line_uses_existing_hook_without_a_child_process() {
        let root = tempfile::tempdir().unwrap();
        let hook_dir = root.path().join("shell assets");
        let lib = hook_dir.join("lib");
        std::fs::create_dir_all(&lib).unwrap();
        let hook = lib.join("nushell-hook.nu");
        std::fs::write(&hook, "# inert test hook\n").unwrap();

        let line = nushell_hook_line_for_dir(&hook_dir).unwrap();
        assert_eq!(
            line,
            format!("source {}", shell_quote(hook.to_str().unwrap(), "nushell"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn nushell_hook_line_rejects_non_utf8_persisted_path() {
        use std::os::unix::ffi::OsStringExt;

        let root = tempfile::tempdir().unwrap();
        let name = std::ffi::OsString::from_vec(b"shell-\xff".to_vec());
        let hook_dir = root.path().join(name);

        let error = nushell_hook_line_for_dir(&hook_dir).unwrap_err();
        assert!(error.contains("not valid UTF-8"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn profile_discovery_refuses_symlinked_intermediate_directory() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("nushell")).unwrap();
        std::fs::write(outside.path().join("nushell/config.nu"), "# outside").unwrap();
        std::os::unix::fs::symlink(outside.path(), home.path().join(".config")).unwrap();

        assert!(profile_for_shell("nushell", home.path()).is_err());
    }

    #[test]
    fn bash_profile_discovery_preserves_existing_fallback() {
        let home = tempfile::tempdir().unwrap();
        let bash_profile = home.path().join(".bash_profile");
        std::fs::write(&bash_profile, "# existing").unwrap();

        assert_eq!(
            profile_for_shell("bash", home.path()).unwrap(),
            Some(bash_profile)
        );
    }

    #[test]
    fn bash_profile_selection_revalidation_detects_new_higher_priority_file() {
        let home = tempfile::tempdir().unwrap();
        let bash_profile = home.path().join(".bash_profile");
        std::fs::write(&bash_profile, "# existing").unwrap();
        assert_eq!(
            profile_for_shell("bash", home.path()).unwrap(),
            Some(bash_profile.clone())
        );

        std::fs::write(home.path().join(".bashrc"), "# appeared concurrently").unwrap();
        let error = revalidate_profile_selection("bash", home.path(), &bash_profile).unwrap_err();
        assert!(error.contains("selection changed"));
    }

    #[test]
    fn quote_simple_name_unchanged() {
        assert_eq!(shell_quote("tirith", "zsh"), "tirith");
        assert_eq!(shell_quote("tirith", "fish"), "tirith");
        assert_eq!(shell_quote("tirith", "powershell"), "tirith");
        assert_eq!(shell_quote("tirith", "nushell"), "\"tirith\"");
    }

    #[test]
    fn quote_nushell_path_uses_double_quoted_nushell_escapes() {
        assert_eq!(
            shell_quote("/tmp/it's \\quoted\" #hook\n\t", "nushell"),
            "\"/tmp/it's \\\\quoted\\\" #hook\\n\\t\""
        );
    }

    #[test]
    fn quote_nushell_path_encodes_other_control_characters() {
        assert_eq!(shell_quote("a\u{001f}b", "nushell"), "\"a\\u{1f}b\"");
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
    fn begin_marker_requires_an_exact_numeric_version_grammar() {
        for line in [
            "# BEGIN tirith-hook",
            "# BEGIN tirith-hook migration notes",
            "# BEGIN tirith-hook v",
            "# BEGIN tirith-hook v1 notes",
            "# BEGIN tirith-hook v1 ",
            " # BEGIN tirith-hook v1",
        ] {
            assert!(!is_managed_begin_marker(line), "line={line:?}");
        }
        assert!(is_managed_begin_marker("# BEGIN tirith-hook v1"));
        assert!(is_managed_begin_marker("# BEGIN tirith-hook v27"));
    }

    #[test]
    fn prefix_like_comments_are_not_extracted_or_removed() {
        let content = "# BEGIN tirith-hook v1 migration notes\nkeep this\n# END tirith-hook migration notes\n";
        assert!(validate_marker_pairing(content).is_ok());
        assert!(extract_managed_block(content).is_none());
        assert_eq!(remove_hook_blocks(content), content);
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
