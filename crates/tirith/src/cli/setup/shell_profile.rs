//! Install `eval "$(tirith init)"` into the user's shell profile.
//!
//! Manages a BEGIN/END marker block in the shell's rc file (zsh/bash/fish/
//! nushell/PowerShell) so the hook installs idempotently and updates/removes
//! without corrupting user content.

const END_MARKER: &str = "# END tirith-hook";
const BEGIN_MARKER_STEM: &str = "# BEGIN tirith-hook v";

/// Match only the managed marker grammar, while still recognizing a future
/// numeric block version. Prefix-like user comments must remain user content.
pub(super) fn is_managed_begin_marker(line: &str) -> bool {
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
        // PowerShell doubles a literal apostrophe. Fish also decodes escaped
        // backslashes inside single quotes, so preserve those explicitly.
        "powershell" | "pwsh" => format!("'{}'", path.replace('\'', "''")),
        "fish" => format!("'{}'", path.replace('\\', "\\\\").replace('\'', "\\'")),
        _ => format!("'{}'", path.replace('\'', "'\\''")),
    }
}

/// Use the same target list for setup, inspection, update and removal.
fn selected_targets() -> Result<crate::cli::shell_target::ShellTarget, String> {
    crate::cli::shell_target::inspect_current()
}

/// Detect a manually-added `tirith init` (uncommented executable line). Skips
/// comments/blanks to avoid false positives on `# TODO: tirith init`.
pub(super) fn has_executable_tirith_init(content: &str) -> bool {
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
pub(super) fn validate_marker_pairing(content: &str) -> Result<(), String> {
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
#[cfg(test)]
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

/// Install through the same immutable, journaled plan used by local controls.
pub fn install_shell_hook(tirith_bin: &str, force: bool, dry_run: bool) -> Result<(), String> {
    let target = selected_targets()?;
    crate::cli::shell_target::require_personal_writer(&target)?;
    if let Some(reason) = target.unsupported_reason {
        return Err(reason);
    }
    let shell = super::shell_service::ShellKind::parse(&target.shell)?;
    let prepared = super::shell_service::PreparedShell::capture_with_binary(
        super::shell_service::ShellChange::Install { shell, force },
        None,
        Some(tirith_bin),
    )?;
    apply_prepared_shell(prepared, dry_run)?;
    #[cfg(unix)]
    if !dry_run && target.shell == "bash" {
        let _ = crate::cli::bash_capability::run_and_cache();
    }
    Ok(())
}

/// Remove managed blocks from the shared target set, including shadowed Bash
/// login files. Manual startup commands retain their exact bytes.
pub(crate) fn remove_shell_hook(shell: &str, dry_run: bool) -> Result<(), String> {
    let shell = super::shell_service::ShellKind::parse(shell)?;
    let prepared = super::shell_service::PreparedShell::capture(
        super::shell_service::ShellChange::Remove { shell },
        None,
    )?;
    apply_prepared_shell(prepared, dry_run)
}

pub(super) fn apply_prepared_shell(
    prepared: super::shell_service::PreparedShell,
    dry_run: bool,
) -> Result<(), String> {
    use super::change_plan::{JobState, MutationService};
    if dry_run {
        let preview = prepared.projection();
        if let Some(profiles) = preview["profiles"].as_array() {
            for profile in profiles {
                eprintln!(
                    "[dry-run] {}: {}",
                    profile["action"].as_str().unwrap_or("inspect"),
                    profile["target"]
                        .as_str()
                        .unwrap_or("selected personal startup file")
                );
            }
        }
        return Ok(());
    }
    let id = uuid::Uuid::new_v4().to_string();
    let redact = |error: String| {
        tirith_core::redact::redact_sanitize_redact_with_compiled(&error, &prepared.compiled)
    };
    if prepared
        .plan(&id)
        .map_err(redact)?
        .is_some_and(|status| status.no_op)
    {
        eprintln!("tirith: managed shell configuration is already current; manual startup entries were preserved");
        return Ok(());
    }
    let outcome = MutationService::current()
        .map_err(redact)?
        .apply(&id, &prepared.snapshot)
        .map_err(redact)?;
    if !matches!(
        outcome.state,
        JobState::Completed | JobState::CompletedWithRecovery
    ) {
        return Err(redact(format!(
            "shell operation {id} stopped in {:?}: {}. Inspect with tirith policy operation {id}",
            outcome.state,
            outcome
                .detail
                .as_deref()
                .unwrap_or("review the retained operation")
        )));
    }
    eprintln!("tirith: shell configuration operation {id} completed; inspect or undo with tirith policy operation {id}");
    if outcome.state == JobState::CompletedWithRecovery {
        eprintln!(
            "tirith: platform recovery material was retained; inspect the operation before cleanup"
        );
    }
    Ok(())
}

#[cfg(test)]
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
        "{}\nsource {}\n{}",
        crate::cli::init::integration_stamp("nushell", hook_dir),
        shell_quote(&hook_path_text, "nushell"),
        crate::cli::init::integration_handoff_cleanup("nushell"),
    ))
}

/// Remove all lines between BEGIN/END markers (inclusive). Caller MUST call
/// `validate_marker_pairing` first — this does not re-validate, and unbalanced
/// markers would drop trailing content.
#[cfg(test)]
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
    fn managed_removal_preserves_manual_bytes_and_retires_shadowed_bash_blocks() {
        crate::cli::test_harness::with_fake_env(false, |home, _| {
            let manual = "# personal profile without final newline";
            std::fs::write(home.join(".bashrc"), manual).unwrap();
            std::fs::write(home.join(".bash_profile"), "# chosen login\n").unwrap();
            let inactive = home.join(".bash_login");
            std::fs::write(&inactive, "# before\n# BEGIN tirith-hook v1\neval \"$(tirith init)\"\n# END tirith-hook\n# after\n").unwrap();
            remove_shell_hook("bash", false).unwrap();
            assert_eq!(
                std::fs::read_to_string(home.join(".bashrc")).unwrap(),
                manual
            );
            assert_eq!(
                std::fs::read_to_string(&inactive).unwrap(),
                "# before\n# after\n"
            );
            remove_shell_hook("bash", false).unwrap();
            assert_eq!(
                std::fs::read_to_string(home.join(".bashrc")).unwrap(),
                manual
            );
        });
    }

    #[test]
    fn removal_preflights_corrupt_markers_before_mutating_any_profile() {
        crate::cli::test_harness::with_fake_env(false, |home, _| {
            let first = "# BEGIN tirith-hook v1\nhook\n# END tirith-hook\n";
            std::fs::write(home.join(".bashrc"), first).unwrap();
            std::fs::write(
                home.join(".bash_profile"),
                "# BEGIN tirith-hook v1\nmissing end\n",
            )
            .unwrap();
            assert!(remove_shell_hook("bash", false).is_err());
            assert_eq!(
                std::fs::read_to_string(home.join(".bashrc")).unwrap(),
                first
            );
        });
    }

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
            format!(
                "{}\nsource {}\n{}",
                crate::cli::init::integration_stamp("nushell", &hook_dir),
                shell_quote(hook.to_str().unwrap(), "nushell"),
                crate::cli::init::integration_handoff_cleanup("nushell")
            )
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
    fn selected_external_config_still_refuses_symlinked_profile_parent() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("fish")).unwrap();
        let result = super::super::fs_helpers::read_to_string_scoped(
            &root.path().join("fish/config.fish"),
            root.path(),
        );
        assert!(result.is_err());
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
    fn quote_fish_preserves_backslashes_and_apostrophes() {
        assert_eq!(
            shell_quote("/tmp/a\\b'c\\", "fish"),
            "'/tmp/a\\\\b\\'c\\\\'"
        );
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
