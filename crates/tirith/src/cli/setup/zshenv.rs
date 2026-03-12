use std::fs;
use std::process::Command;

const BEGIN_MARKER: &str = "# BEGIN tirith-guard v1";
const END_MARKER: &str = "# END tirith-guard";
const BEGIN_PREFIX: &str = "# BEGIN tirith-guard";

/// Install or print the zshenv guard for non-interactive `zsh -lc` interception.
///
/// - If `!install`: print the guard snippet to stdout with instructions, return Ok.
/// - If `install`: manage the `~/.zshenv` managed block (BEGIN/END markers).
/// - `force`: remove existing blocks and append fresh.
/// - `dry_run`: read existing file, report what would happen, write nothing.
pub fn offer_zshenv_guard(
    install: bool,
    force: bool,
    dry_run: bool,
    tirith_bin: &str,
) -> Result<(), String> {
    let guard_content = crate::assets::ZSHENV_GUARD.replace("__TIRITH_BIN__", tirith_bin);
    let managed_block = format!("{BEGIN_MARKER}\n{guard_content}\n{END_MARKER}\n");

    if !install {
        println!("Add the following to ~/.zshenv to protect non-interactive zsh sessions:\n");
        println!("{managed_block}");
        println!("Or re-run with --install-zshenv to install automatically.");
        return Ok(());
    }

    let home = home::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;
    let zshenv_path = home.join(".zshenv");

    let existing = if zshenv_path.exists() {
        fs::read_to_string(&zshenv_path)
            .map_err(|e| format!("read {}: {e}", zshenv_path.display()))?
    } else {
        String::new()
    };

    // Count BEGIN markers
    let begin_count = existing
        .lines()
        .filter(|line| line.starts_with(BEGIN_PREFIX))
        .count();

    // Validate marker pairing: each BEGIN must have a matching END
    validate_marker_pairing(&existing)?;

    match begin_count {
        0 => {
            // No existing block — append
            if dry_run {
                eprintln!(
                    "[dry-run] would append tirith-guard block to {}",
                    zshenv_path.display()
                );
                return Ok(());
            }
            // Syntax validation (not in dry-run)
            validate_zsh_syntax(&managed_block)?;

            let mut content = existing;
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(&managed_block);

            super::fs_helpers::atomic_write(&zshenv_path, &content, 0o644)?;
            eprintln!(
                "tirith: appended tirith-guard block to {}",
                zshenv_path.display()
            );
        }
        1 => {
            if !force {
                eprintln!(
                    "tirith: tirith-guard already in {}, up to date",
                    zshenv_path.display()
                );
                return Ok(());
            }
            // force: remove old block, append fresh
            if dry_run {
                eprintln!(
                    "[dry-run] would replace tirith-guard block in {}",
                    zshenv_path.display()
                );
                return Ok(());
            }
            validate_zsh_syntax(&managed_block)?;

            let cleaned = remove_guard_blocks(&existing);
            let mut content = cleaned;
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(&managed_block);

            super::fs_helpers::atomic_write(&zshenv_path, &content, 0o644)?;
            eprintln!(
                "tirith: replaced tirith-guard block in {}",
                zshenv_path.display()
            );
        }
        _ => {
            // Multiple blocks
            if !force {
                return Err(format!(
                    "tirith: multiple tirith-guard blocks found in {} — use --force to deduplicate",
                    zshenv_path.display()
                ));
            }
            // force: remove all, append one
            if dry_run {
                eprintln!(
                    "[dry-run] would deduplicate tirith-guard blocks in {}",
                    zshenv_path.display()
                );
                return Ok(());
            }
            validate_zsh_syntax(&managed_block)?;

            let cleaned = remove_guard_blocks(&existing);
            let mut content = cleaned;
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(&managed_block);

            super::fs_helpers::atomic_write(&zshenv_path, &content, 0o644)?;
            eprintln!(
                "tirith: deduplicated tirith-guard blocks in {}",
                zshenv_path.display()
            );
        }
    }

    Ok(())
}

/// Validate that each BEGIN marker has a matching END marker.
pub(crate) fn validate_marker_pairing(content: &str) -> Result<(), String> {
    let mut in_block = false;
    for line in content.lines() {
        if line.starts_with(BEGIN_PREFIX) {
            if in_block {
                return Err(
                    "tirith: corrupted tirith-guard block in ~/.zshenv — nested BEGIN markers, fix manually"
                        .to_string(),
                );
            }
            in_block = true;
        } else if line.starts_with(END_MARKER) {
            if !in_block {
                return Err(
                    "tirith: corrupted tirith-guard block in ~/.zshenv — END marker without BEGIN, fix manually"
                        .to_string(),
                );
            }
            in_block = false;
        }
    }
    if in_block {
        return Err(
            "tirith: corrupted tirith-guard block in ~/.zshenv — missing END marker, fix manually"
                .to_string(),
        );
    }
    Ok(())
}

/// Remove all lines between BEGIN and END tirith-guard markers (inclusive).
pub(crate) fn remove_guard_blocks(content: &str) -> String {
    let mut result = Vec::new();
    let mut suppressing = false;

    for line in content.lines() {
        if line.starts_with(BEGIN_PREFIX) {
            suppressing = true;
            continue;
        }
        if line.starts_with(END_MARKER) {
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

/// Run `zsh -n` on the snippet to validate syntax before writing.
/// Skipped in dry-run mode (caller is responsible for gating).
pub(crate) fn validate_zsh_syntax(snippet: &str) -> Result<(), String> {
    let output = Command::new("zsh")
        .arg("-n")
        .arg("-c")
        .arg(snippet)
        .output()
        .map_err(|e| format!("zsh -n failed to start: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "tirith: zshenv guard snippet has invalid zsh syntax (bug in embedded asset): {stderr}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- validate_marker_pairing ---

    #[test]
    fn pairing_valid_single_block() {
        let content =
            "some stuff\n# BEGIN tirith-guard v1\nguard code\n# END tirith-guard\nmore stuff\n";
        assert!(validate_marker_pairing(content).is_ok());
    }

    #[test]
    fn pairing_valid_multiple_blocks() {
        let content = "# BEGIN tirith-guard v1\nblock1\n# END tirith-guard\nstuff\n# BEGIN tirith-guard v1\nblock2\n# END tirith-guard\n";
        assert!(validate_marker_pairing(content).is_ok());
    }

    #[test]
    fn pairing_valid_no_blocks() {
        let content = "just some zshenv content\nexport PATH=...\n";
        assert!(validate_marker_pairing(content).is_ok());
    }

    #[test]
    fn pairing_missing_end_marker() {
        let content = "# BEGIN tirith-guard v1\nguard code\nno end marker\n";
        let err = validate_marker_pairing(content).unwrap_err();
        assert!(err.contains("missing END marker"), "got: {err}");
    }

    #[test]
    fn pairing_orphan_end_marker() {
        let content = "stuff\n# END tirith-guard\nmore stuff\n";
        let err = validate_marker_pairing(content).unwrap_err();
        assert!(err.contains("END marker without BEGIN"), "got: {err}");
    }

    #[test]
    fn pairing_nested_begin_markers() {
        let content = "# BEGIN tirith-guard v1\n# BEGIN tirith-guard v1\n# END tirith-guard\n";
        let err = validate_marker_pairing(content).unwrap_err();
        assert!(err.contains("nested BEGIN"), "got: {err}");
    }

    // --- remove_guard_blocks ---

    #[test]
    fn remove_single_block() {
        let content = "before\n# BEGIN tirith-guard v1\nguard\n# END tirith-guard\nafter\n";
        let result = remove_guard_blocks(content);
        assert_eq!(result, "before\nafter\n");
    }

    #[test]
    fn remove_multiple_blocks() {
        let content = "# BEGIN tirith-guard v1\nblock1\n# END tirith-guard\nmiddle\n# BEGIN tirith-guard v1\nblock2\n# END tirith-guard\nend\n";
        let result = remove_guard_blocks(content);
        assert_eq!(result, "middle\nend\n");
    }

    #[test]
    fn remove_no_blocks() {
        let content = "just content\nno guard\n";
        let result = remove_guard_blocks(content);
        assert_eq!(result, "just content\nno guard\n");
    }

    #[test]
    fn remove_preserves_surrounding_content() {
        let content = "export FOO=bar\n# BEGIN tirith-guard v1\nif [[ ... ]]; then\nfi\n# END tirith-guard\nexport BAZ=qux\n";
        let result = remove_guard_blocks(content);
        assert_eq!(result, "export FOO=bar\nexport BAZ=qux\n");
    }

    // --- validate_zsh_syntax ---

    #[test]
    fn valid_zsh_syntax() {
        let snippet = "if [[ -n \"${ZSH_EXECUTION_STRING:-}\" ]]; then\n  echo hello\nfi\n";
        if std::process::Command::new("zsh")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping validate_zsh_syntax test: zsh not found");
            return;
        }
        assert!(validate_zsh_syntax(snippet).is_ok());
    }

    #[test]
    fn invalid_zsh_syntax() {
        let snippet = "if [[ -n \"${FOO}\" ]]; then\n  # missing fi\n";
        if std::process::Command::new("zsh")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping validate_zsh_syntax test: zsh not found");
            return;
        }
        assert!(validate_zsh_syntax(snippet).is_err());
    }

    // --- offer_zshenv_guard integration tests ---

    #[cfg(unix)]
    mod integration {
        use super::*;

        fn zsh_available() -> bool {
            std::process::Command::new("zsh")
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
        }

        /// RAII guard that restores (or removes) an env var on Drop.
        struct EnvGuard {
            key: &'static str,
            old: Option<std::ffi::OsString>,
        }

        impl EnvGuard {
            fn set(key: &'static str, val: &std::path::Path) -> Self {
                let old = std::env::var_os(key);
                unsafe { std::env::set_var(key, val) };
                Self { key, old }
            }
        }

        impl Drop for EnvGuard {
            fn drop(&mut self) {
                match &self.old {
                    Some(h) => unsafe { std::env::set_var(self.key, h) },
                    None => unsafe { std::env::remove_var(self.key) },
                }
            }
        }

        fn with_fake_home<F: std::panic::UnwindSafe + FnOnce(&std::path::Path) -> R, R>(f: F) -> R {
            let _lock = super::super::super::HOME_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let tmp = tempfile::tempdir().unwrap();
            let _home_guard = EnvGuard::set("HOME", tmp.path());
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(tmp.path())));
            match result {
                Ok(v) => v,
                Err(e) => std::panic::resume_unwind(e),
            }
        }

        #[test]
        fn install_creates_zshenv_with_guard() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                let result = offer_zshenv_guard(true, false, false, "tirith");
                assert!(result.is_ok(), "got: {result:?}");

                let zshenv = home.join(".zshenv");
                assert!(zshenv.exists());
                let content = std::fs::read_to_string(&zshenv).unwrap();
                assert!(content.contains(BEGIN_MARKER));
                assert!(content.contains(END_MARKER));
                assert!(content.contains("tirith"));
                assert!(!content.contains("__TIRITH_BIN__"));
            });
        }

        #[test]
        fn install_idempotent_skips_second_run() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                offer_zshenv_guard(true, false, false, "tirith").unwrap();
                let content1 = std::fs::read_to_string(home.join(".zshenv")).unwrap();

                offer_zshenv_guard(true, false, false, "tirith").unwrap();
                let content2 = std::fs::read_to_string(home.join(".zshenv")).unwrap();

                assert_eq!(content1, content2);
            });
        }

        #[test]
        fn install_force_replaces_block() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                offer_zshenv_guard(true, false, false, "tirith").unwrap();

                offer_zshenv_guard(true, true, false, "/usr/local/bin/tirith").unwrap();
                let content = std::fs::read_to_string(home.join(".zshenv")).unwrap();

                assert!(content.contains("/usr/local/bin/tirith"));
                let begin_count = content
                    .lines()
                    .filter(|l| l.starts_with(BEGIN_PREFIX))
                    .count();
                assert_eq!(begin_count, 1);
            });
        }

        #[test]
        fn install_preserves_existing_content() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                let zshenv = home.join(".zshenv");
                std::fs::write(&zshenv, "export MY_VAR=hello\n").unwrap();

                offer_zshenv_guard(true, false, false, "tirith").unwrap();
                let content = std::fs::read_to_string(&zshenv).unwrap();

                assert!(content.starts_with("export MY_VAR=hello\n"));
                assert!(content.contains(BEGIN_MARKER));
            });
        }

        #[test]
        fn multiple_blocks_error_without_force() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                let zshenv = home.join(".zshenv");
                let double_block = format!(
                    "{BEGIN_MARKER}\nguard1\n{END_MARKER}\n{BEGIN_MARKER}\nguard2\n{END_MARKER}\n"
                );
                std::fs::write(&zshenv, &double_block).unwrap();

                let result = offer_zshenv_guard(true, false, false, "tirith");
                assert!(result.is_err());
                let err = result.unwrap_err();
                assert!(err.contains("multiple tirith-guard blocks"), "got: {err}");
            });
        }

        #[test]
        fn multiple_blocks_deduped_with_force() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                let zshenv = home.join(".zshenv");
                let double_block = format!(
                    "{BEGIN_MARKER}\nguard1\n{END_MARKER}\n{BEGIN_MARKER}\nguard2\n{END_MARKER}\n"
                );
                std::fs::write(&zshenv, &double_block).unwrap();

                offer_zshenv_guard(true, true, false, "tirith").unwrap();
                let content = std::fs::read_to_string(&zshenv).unwrap();

                let begin_count = content
                    .lines()
                    .filter(|l| l.starts_with(BEGIN_PREFIX))
                    .count();
                assert_eq!(begin_count, 1);
            });
        }

        #[test]
        fn dry_run_no_write() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                let result = offer_zshenv_guard(true, false, true, "tirith");
                assert!(result.is_ok());

                let zshenv = home.join(".zshenv");
                assert!(!zshenv.exists(), "dry-run should not create file");
            });
        }

        #[test]
        fn tirith_bin_placeholder_replaced() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                offer_zshenv_guard(true, false, false, "/opt/custom/tirith").unwrap();
                let content = std::fs::read_to_string(home.join(".zshenv")).unwrap();

                assert!(content.contains("/opt/custom/tirith"));
                assert!(!content.contains("__TIRITH_BIN__"));
            });
        }

        /// Helper: write a .zshenv with the guard plus a trailing export,
        /// then run `zsh -c 'echo $POST_GUARD'` with the given extra env
        /// vars. Returns (stdout, exit_code).
        ///
        /// `tirith_bin` is baked into the guard via placeholder replacement.
        /// Use a nonexistent path to trigger the "not found" block branch.
        fn run_guard_scenario(
            home: &std::path::Path,
            tirith_bin: &str,
            extra_env: &[(&str, &str)],
        ) -> (String, i32) {
            offer_zshenv_guard(true, true, false, tirith_bin).unwrap();

            // Append an export AFTER the guard block to verify that later
            // .zshenv lines still execute when the guard is skipped.
            let zshenv = home.join(".zshenv");
            let mut content = std::fs::read_to_string(&zshenv).unwrap();
            content.push_str("\nexport POST_GUARD=loaded\n");
            std::fs::write(&zshenv, &content).unwrap();

            // ZDOTDIR + HOME → fake home so zsh reads our .zshenv.
            // No --no-rcs: that flag suppresses .zshenv too.
            // Non-interactive `zsh -c` sources .zshenv but NOT .zshrc.
            let output = std::process::Command::new("zsh")
                .arg("-c")
                .arg("echo \"POST_GUARD=${POST_GUARD:-unset}\"")
                .env("ZDOTDIR", home)
                .env("HOME", home)
                .envs(extra_env.iter().copied())
                .output()
                .expect("failed to spawn zsh");

            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let code = output.status.code().unwrap_or(-1);
            (stdout, code)
        }

        #[test]
        fn vscode_bypass_skips_guard_and_continues_zshenv() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                // tirith_bin is nonexistent — guard would block if it ran.
                // With VSCODE_RESOLVING_ENVIRONMENT the compound condition
                // is false, so the guard block is skipped entirely and the
                // trailing export must still load.
                let (stdout, code) = run_guard_scenario(
                    home,
                    "/nonexistent/tirith",
                    &[("VSCODE_RESOLVING_ENVIRONMENT", "1")],
                );
                assert_eq!(code, 0, "IDE probe should exit 0");
                assert_eq!(
                    stdout, "POST_GUARD=loaded",
                    "exports after guard must still load during IDE probe"
                );
            });
        }

        #[test]
        fn tirith_skip_bypass_skips_guard_and_continues_zshenv() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                let (stdout, code) =
                    run_guard_scenario(home, "/nonexistent/tirith", &[("TIRITH_ZSHENV_SKIP", "1")]);
                assert_eq!(code, 0, "TIRITH_ZSHENV_SKIP should exit 0");
                assert_eq!(
                    stdout, "POST_GUARD=loaded",
                    "exports after guard must still load when skip is set"
                );
            });
        }

        #[test]
        fn guard_blocks_without_bypass_env() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                // tirith_bin is nonexistent → guard hits "not found" → exit 1.
                let (_stdout, code) = run_guard_scenario(home, "/nonexistent/tirith", &[]);
                assert_eq!(code, 1, "guard should exit 1 when tirith binary not found");
            });
        }
    }
}
