use std::path::PathBuf;

const BEGIN_MARKER: &str = "# BEGIN tirith-guard v1";
const END_MARKER: &str = "# END tirith-guard";
const TRUSTED_ZSH_SEARCH_DIRS: [&str; 4] = [
    "/bin",
    "/usr/bin",
    "/run/current-system/sw/bin",
    "/nix/var/nix/profiles/default/bin",
];

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
    // Quote for zsh so a path with spaces/apostrophes/metacharacters can't break
    // the assignment. The template's `__TIRITH_BIN__` is unquoted because the
    // substitution yields an already-quoted literal.
    let quoted_tirith_bin = super::shell_profile::shell_quote(tirith_bin, "zsh");
    let guard_content = crate::assets::ZSHENV_GUARD.replace("__TIRITH_BIN__", &quoted_tirith_bin);
    let managed_block = format!("{BEGIN_MARKER}\n{guard_content}\n{END_MARKER}\n");

    if !install {
        println!("Add the following to ~/.zshenv to protect non-interactive zsh sessions:\n");
        println!("{managed_block}");
        println!("Or re-run with --install-zshenv to install automatically.");
        return Ok(());
    }

    let home = home::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;
    let zshenv_path = home.join(".zshenv");
    let mut completed_verb = "updated";
    // `transactional_update` may run the transform twice (preflight, then a
    // locked recompute when the destination drifted in between). The managed
    // block is snapshot-independent, so one successful `zsh -n` proves it for
    // both runs — never spawn the validator a second time.
    let mut block_validated = false;
    let outcome = super::fs_helpers::transactional_update(
        &zshenv_path,
        &home,
        dry_run,
        |snapshot| {
            let existing = snapshot.text(&zshenv_path)?.unwrap_or_default();
            let begin_count = existing
                .lines()
                .filter(|line| *line == BEGIN_MARKER)
                .count();
            validate_marker_pairing(existing)?;

            let mut content = match begin_count {
                0 => {
                    completed_verb = "appended";
                    if dry_run {
                        eprintln!(
                            "[dry-run] would append tirith-guard block to {}",
                            zshenv_path.display()
                        );
                    } else if !block_validated {
                        validate_zsh_syntax(&managed_block)?;
                        block_validated = true;
                    }
                    existing.to_string()
                }
                1 if !force => {
                    let matches = extract_guard_block(existing)
                        .is_some_and(|block| block == managed_block.as_str());
                    if !matches {
                        return Err(format!(
                            "tirith: tirith-guard block in {} differs from the expected guard — use --force to repair",
                            zshenv_path.display()
                        ));
                    }
                    eprintln!(
                        "tirith: tirith-guard already in {}, up to date",
                        zshenv_path.display()
                    );
                    return Ok(super::fs_helpers::FileUpdate::unchanged());
                }
                1 => {
                    completed_verb = "replaced";
                    if dry_run {
                        eprintln!(
                            "[dry-run] would replace tirith-guard block in {}",
                            zshenv_path.display()
                        );
                    } else if !block_validated {
                        validate_zsh_syntax(&managed_block)?;
                        block_validated = true;
                    }
                    remove_guard_blocks(existing)
                }
                _ if !force => {
                    return Err(format!(
                        "tirith: multiple tirith-guard blocks found in {} — use --force to deduplicate",
                        zshenv_path.display()
                    ));
                }
                _ => {
                    completed_verb = "deduplicated";
                    if dry_run {
                        eprintln!(
                            "[dry-run] would deduplicate tirith-guard blocks in {}",
                            zshenv_path.display()
                        );
                    } else if !block_validated {
                        validate_zsh_syntax(&managed_block)?;
                        block_validated = true;
                    }
                    remove_guard_blocks(existing)
                }
            };
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(&managed_block);
            Ok(super::fs_helpers::FileUpdate::write_text(content, 0o644))
        },
    )?;
    if let Some(annotation) = outcome.completion_annotation() {
        eprintln!(
            "tirith: {completed_verb} tirith-guard block in {}{annotation}",
            zshenv_path.display(),
        );
    }

    Ok(())
}

/// Validate that each BEGIN marker has a matching END marker.
pub(crate) fn validate_marker_pairing(content: &str) -> Result<(), String> {
    let mut in_block = false;
    for line in content.lines() {
        if line == BEGIN_MARKER {
            if in_block {
                return Err(
                    "tirith: corrupted tirith-guard block in ~/.zshenv — nested BEGIN markers, fix manually"
                        .to_string(),
                );
            }
            in_block = true;
        } else if line == END_MARKER {
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

/// Extract one validated managed block as its exact source slice. Pairing and
/// multiplicity are checked by the caller before this helper is used. Keeping
/// the original line endings is intentional: a CRLF block or a block missing
/// its final LF is drift, not an exact match for the generated block.
fn extract_guard_block(content: &str) -> Option<&str> {
    let mut block_start = None;
    let mut offset = 0;

    for source_line in content.split_inclusive('\n') {
        let line = source_line.strip_suffix('\n').unwrap_or(source_line);
        match block_start {
            None if line == BEGIN_MARKER => block_start = Some(offset),
            Some(start) if line == END_MARKER => {
                return Some(&content[start..offset + source_line.len()]);
            }
            _ => {}
        }
        offset += source_line.len();
    }

    None
}

/// Remove all lines between BEGIN and END tirith-guard markers (inclusive).
pub(crate) fn remove_guard_blocks(content: &str) -> String {
    let mut result = Vec::new();
    let mut suppressing = false;

    for line in content.lines() {
        if line == BEGIN_MARKER {
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

/// Run `zsh -n` on the snippet to validate syntax before writing.
/// Skipped in dry-run mode (caller is responsible for gating).
pub(crate) fn validate_zsh_syntax(snippet: &str) -> Result<(), String> {
    let executable = resolve_trusted_zsh()?;
    let spec = tirith_core::trusted_child::ChildSpec::new(
        ["-f", "-n", "-c", snippet],
        tirith_core::trusted_child::ChildLimits::new(
            std::time::Duration::from_secs(3),
            64 * 1024,
            64 * 1024,
        ),
    );
    match tirith_core::trusted_child::run(&executable, &spec) {
        tirith_core::trusted_child::ChildOutcome::Completed { status, .. }
            if status.success() =>
        {
            Ok(())
        }
        tirith_core::trusted_child::ChildOutcome::Completed { stderr, .. } => {
            let stderr = String::from_utf8_lossy(&stderr);
            Err(format!(
                "tirith: zshenv guard snippet has invalid zsh syntax (bug in embedded asset): {stderr}"
            ))
        }
        tirith_core::trusted_child::ChildOutcome::SpawnError(reason) => {
            Err(format!("trusted zsh syntax check failed to start: {reason}"))
        }
        tirith_core::trusted_child::ChildOutcome::WaitError(reason) => {
            Err(format!("trusted zsh syntax check wait failed: {reason}"))
        }
        tirith_core::trusted_child::ChildOutcome::CleanupError(reason) => Err(format!(
            "trusted zsh syntax check process-tree cleanup failed: {reason}"
        )),
        tirith_core::trusted_child::ChildOutcome::Timeout { cleanup_succeeded } => Err(format!(
            "trusted zsh syntax check timed out (process-tree cleanup succeeded: {cleanup_succeeded})"
        )),
        tirith_core::trusted_child::ChildOutcome::OutputLimitExceeded {
            stream,
            cleanup_succeeded,
        } => Err(format!(
            "trusted zsh syntax check exceeded its {stream:?} limit (process-tree cleanup succeeded: {cleanup_succeeded})"
        )),
    }
}

/// Resolve zsh only from fixed global system locations, then apply the shared
/// full lexical-selection and canonical-target provenance policy. The two Nix
/// roots are global root-managed profiles; per-user Nix profiles are omitted.
fn resolve_trusted_zsh() -> Result<tirith_core::trusted_child::TrustedExecutable, String> {
    let search_path = std::env::join_paths(TRUSTED_ZSH_SEARCH_DIRS)
        .map_err(|error| format!("could not construct trusted zsh search path: {error}"))?;
    tirith_core::trusted_child::resolve_system_helper_on_path("zsh", &search_path)
        .map_err(|error| format!("trusted system zsh not found: {error}"))
}

pub(crate) fn trusted_zsh_executable() -> Result<PathBuf, String> {
    resolve_trusted_zsh().map(|executable| executable.path().to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_valid_single_block() {
        let content =
            "some stuff\n# BEGIN tirith-guard v1\nguard code\n# END tirith-guard\nmore stuff\n";
        assert!(validate_marker_pairing(content).is_ok());
    }

    #[test]
    fn trusted_zsh_search_is_fixed_to_global_root_managed_profiles() {
        assert_eq!(
            TRUSTED_ZSH_SEARCH_DIRS,
            [
                "/bin",
                "/usr/bin",
                "/run/current-system/sw/bin",
                "/nix/var/nix/profiles/default/bin",
            ]
        );
        assert!(TRUSTED_ZSH_SEARCH_DIRS
            .iter()
            .all(|path| !path.contains("per-user") && !path.contains(".nix-profile")));
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

    #[test]
    fn prefix_like_comments_are_not_markers_or_removed() {
        let content =
            "# BEGIN tirith-guard migration notes\nkeep this\n# END tirith-guard migration notes\n";
        assert!(validate_marker_pairing(content).is_ok());
        assert_eq!(remove_guard_blocks(content), content);
        assert!(extract_guard_block(content).is_none());
    }

    #[test]
    fn extract_guard_block_returns_complete_exact_block() {
        let content = "before\n# BEGIN tirith-guard v1\nexact body\n# END tirith-guard\nafter\n";
        assert_eq!(
            extract_guard_block(content),
            Some("# BEGIN tirith-guard v1\nexact body\n# END tirith-guard\n")
        );
    }

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

    #[test]
    fn valid_zsh_syntax() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let snippet = "if [[ -n \"${ZSH_EXECUTION_STRING:-}\" ]]; then\n  echo hello\nfi\n";
        if trusted_zsh_executable().is_err() {
            eprintln!("skipping validate_zsh_syntax test: trusted system zsh not found");
            return;
        }
        assert!(validate_zsh_syntax(snippet).is_ok());
    }

    #[test]
    fn invalid_zsh_syntax() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let snippet = "if [[ -n \"${FOO}\" ]]; then\n  # missing fi\n";
        if trusted_zsh_executable().is_err() {
            eprintln!("skipping validate_zsh_syntax test: trusted system zsh not found");
            return;
        }
        assert!(validate_zsh_syntax(snippet).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn syntax_validation_does_not_source_ambient_zdotdir() {
        use crate::cli::test_harness::{with_fake_env, EnvGuard};

        if trusted_zsh_executable().is_err() {
            eprintln!("skipping validate_zsh_syntax test: trusted system zsh not found");
            return;
        }
        with_fake_env(false, |home, _cwd| {
            let sentinel = home.join("startup-file-ran");
            let quoted =
                super::super::shell_profile::shell_quote(sentinel.to_str().unwrap(), "zsh");
            std::fs::write(
                home.join(".zshenv"),
                format!("print -r -- sourced > {quoted}\n"),
            )
            .unwrap();
            let _zdotdir = EnvGuard::set("ZDOTDIR", home);

            validate_zsh_syntax("if true; then\n  print ok\nfi\n").unwrap();
            assert!(
                !sentinel.exists(),
                "syntax validation executed the ambient .zshenv"
            );
        });
    }

    #[test]
    fn embedded_guard_has_no_path_resolved_precheck_helpers() {
        let guard = crate::assets::ZSHENV_GUARD;
        assert!(!guard.contains("${TIRITH_BIN"));
        assert!(!guard.contains("$TIRITH_BIN"));
        assert!(!guard.contains("command -v"));
        assert!(!guard.contains("mktemp"));
        assert!(!guard
            .lines()
            .any(|line| line.trim_start().starts_with("cat ")));
        assert!(!guard
            .lines()
            .any(|line| line.trim_start().starts_with("rm ")));
        assert!(guard.contains("builtin print"));
    }

    #[cfg(unix)]
    mod integration {
        use super::*;
        use crate::cli::test_harness::with_fake_env;

        fn zsh_available() -> bool {
            trusted_zsh_executable().is_ok()
        }

        fn with_fake_home<F: std::panic::UnwindSafe + FnOnce(&std::path::Path) -> R, R>(f: F) -> R {
            with_fake_env(false, |home, _cwd| f(home))
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
                let begin_count = content.lines().filter(|l| *l == BEGIN_MARKER).count();
                assert_eq!(begin_count, 1);
            });
        }

        #[test]
        fn install_rejects_drifted_single_block_without_force() {
            with_fake_home(|home| {
                let zshenv = home.join(".zshenv");
                for body in ["", "# guard was removed\n"] {
                    let drifted = format!("{BEGIN_MARKER}\n{body}{END_MARKER}\n");
                    std::fs::write(&zshenv, &drifted).unwrap();

                    let error = offer_zshenv_guard(true, false, false, "/opt/tirith")
                        .expect_err("empty or drifted guard must not be called up to date");
                    assert!(error.contains("differs from the expected guard"), "{error}");
                    assert_eq!(std::fs::read_to_string(&zshenv).unwrap(), drifted);
                }
            });
        }

        #[test]
        fn install_rejects_crlf_managed_block_without_force() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                let zshenv = home.join(".zshenv");
                offer_zshenv_guard(true, false, false, "/opt/tirith").unwrap();
                let canonical = std::fs::read_to_string(&zshenv).unwrap();
                let crlf = canonical.replace('\n', "\r\n");
                std::fs::write(&zshenv, crlf.as_bytes()).unwrap();

                let error = offer_zshenv_guard(true, false, false, "/opt/tirith")
                    .expect_err("CRLF managed block must be treated as drift");

                assert!(error.contains("differs from the expected guard"), "{error}");
                assert_eq!(std::fs::read(&zshenv).unwrap(), crlf.as_bytes());
            });
        }

        #[test]
        fn install_force_repairs_crlf_managed_block_to_canonical_lf() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                let zshenv = home.join(".zshenv");
                offer_zshenv_guard(true, false, false, "/opt/tirith").unwrap();
                let canonical = std::fs::read(&zshenv).unwrap();
                let crlf = String::from_utf8(canonical.clone())
                    .unwrap()
                    .replace('\n', "\r\n");
                std::fs::write(&zshenv, crlf.as_bytes()).unwrap();

                offer_zshenv_guard(true, true, false, "/opt/tirith").unwrap();

                assert_eq!(std::fs::read(&zshenv).unwrap(), canonical);
            });
        }

        #[test]
        fn install_force_repairs_drift_and_preserves_prefix_like_comments() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                let zshenv = home.join(".zshenv");
                let original = format!(
                    "# BEGIN tirith-guard migration notes\nkeep this\n# END tirith-guard migration notes\n{BEGIN_MARKER}\n# stale\n{END_MARKER}\n"
                );
                std::fs::write(&zshenv, original).unwrap();

                offer_zshenv_guard(true, true, false, "/opt/tirith").unwrap();
                let repaired = std::fs::read_to_string(&zshenv).unwrap();
                assert!(repaired.contains("# BEGIN tirith-guard migration notes\nkeep this\n# END tirith-guard migration notes"));
                assert!(repaired.contains("_tirith_bin=/opt/tirith"));
                assert!(!repaired.contains("# stale"));
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

                let begin_count = content.lines().filter(|l| *l == BEGIN_MARKER).count();
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
        fn up_to_date_and_dry_run_refuse_symlinked_zshenv() {
            with_fake_home(|home| {
                let outside = tempfile::NamedTempFile::new().unwrap();
                std::fs::write(outside.path(), "outside-profile").unwrap();
                std::os::unix::fs::symlink(outside.path(), home.join(".zshenv")).unwrap();

                let result = offer_zshenv_guard(true, false, true, "tirith");

                assert!(result.is_err());
                assert_eq!(
                    std::fs::read_to_string(outside.path()).unwrap(),
                    "outside-profile"
                );
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

        /// Write a .zshenv with the guard plus a trailing export, then run
        /// `zsh -c 'echo $POST_GUARD'` with extra env vars. Returns (stdout,
        /// exit_code). A nonexistent `tirith_bin` triggers the "not found" branch.
        fn run_guard_scenario(
            home: &std::path::Path,
            tirith_bin: &str,
            extra_env: &[(&str, &str)],
        ) -> (String, i32) {
            offer_zshenv_guard(true, true, false, tirith_bin).unwrap();

            // Export AFTER the guard to verify later .zshenv lines still run
            // when the guard is skipped.
            let zshenv = home.join(".zshenv");
            let mut content = std::fs::read_to_string(&zshenv).unwrap();
            content.push_str("\nexport POST_GUARD=loaded\n");
            std::fs::write(&zshenv, &content).unwrap();

            // ZDOTDIR + HOME → fake home so zsh reads our .zshenv (no --no-rcs,
            // which would suppress .zshenv). `zsh -c` sources .zshenv not .zshrc.
            let output = std::process::Command::new("zsh")
                .arg("-c")
                .arg("echo \"POST_GUARD=${POST_GUARD:-unset}\"")
                .env("ZDOTDIR", home)
                .env("HOME", home)
                // An exported TIRITH_BIN would leak in and shadow the placeholder.
                .env_remove("TIRITH_BIN")
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
                // VSCODE_RESOLVING_ENVIRONMENT makes the condition false, so the
                // guard is skipped even with a nonexistent tirith_bin.
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

        #[test]
        fn tirith_bin_placeholder_is_quoted_for_zsh() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                offer_zshenv_guard(true, false, false, "/opt/it's tirith/bin/tirith").unwrap();
                let content = std::fs::read_to_string(home.join(".zshenv")).unwrap();
                // shell_quote(..., "zsh") wraps in single quotes and escapes
                // embedded apostrophes via the '\'' idiom.
                assert!(
                    content.contains("_tirith_bin='/opt/it'\\''s tirith/bin/tirith'"),
                    "rendered content should be zsh-quoted; got:\n{content}"
                );
                // The placeholder token must not survive substitution.
                assert!(
                    !content.contains("__TIRITH_BIN__"),
                    "placeholder must be fully replaced; got:\n{content}"
                );
            });
        }

        #[test]
        fn guard_uses_baked_absolute_tirith_when_path_lacks_it() {
            if !zsh_available() {
                return;
            }
            with_fake_home(|home| {
                use std::os::unix::fs::PermissionsExt;
                // Real (no-op) tirith binary that PATH below won't reach.
                let dir = tempfile::tempdir().unwrap();
                let tirith = dir.path().join("tirith");
                std::fs::write(&tirith, "#!/bin/sh\nexit 0\n").unwrap();
                let mut perms = std::fs::metadata(&tirith).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&tirith, perms).unwrap();

                // Strip PATH to system dirs that don't contain tirith.
                let (stdout, code) = run_guard_scenario(
                    home,
                    &tirith.display().to_string(),
                    &[("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")],
                );
                assert_eq!(
                    code, 0,
                    "guard should pass with baked absolute path even when PATH lacks tirith"
                );
                assert_eq!(stdout, "POST_GUARD=loaded");
            });
        }
    }
}
