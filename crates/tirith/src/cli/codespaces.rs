//! `tirith codespaces setup|inject` (M8 ch5).
//!
//! Codespaces-specific wrappers around `devcontainer_writer`; a distinct command
//! surface from `tirith devcontainer` over the same file.
//!
//! - `setup` — write `.devcontainer/devcontainer.json` if absent (tirith hook +
//!   `TIRITH_DEVCONTAINER=1`) and add a `.tirith/` entry to `.gitignore`.
//! - `inject` — alias of `tirith devcontainer inject`.

use std::io::Write;
use std::path::Path;

use tirith_core::devcontainer_writer::{
    default_devcontainer_json, find_devcontainer_json, InjectOutcome,
};
use tirith_core::policy::Policy;

use super::devcontainer::report_outcome;

/// `tirith codespaces setup [--path <dir>]` — bootstrap a devcontainer.json with
/// the tirith hook + `.tirith/` ignore entry.
pub fn setup(path: Option<&Path>, json: bool) -> i32 {
    setup_with_policy(path, json, None)
}

fn setup_with_policy(path: Option<&Path>, json: bool, policy_override: Option<&Policy>) -> i32 {
    let cwd = match path {
        Some(p) => p.to_path_buf(),
        None => match std::env::current_dir() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("tirith codespaces setup: cannot resolve cwd: {e}");
                return 1;
            }
        },
    };
    // Resolve the selected root once so containment is proven against the
    // canonical repository location, not a lexical alias (repo-0369). The
    // writer revalidates every component descriptor-relatively regardless;
    // this keeps the displayed/recorded path honest.
    let cwd = std::fs::canonicalize(&cwd).unwrap_or(cwd);
    let discovered_policy = policy_override
        .is_none()
        .then(|| Policy::discover_local_only(cwd.to_str()));
    let policy = policy_override
        .or(discovered_policy.as_ref())
        .expect("a supplied or discovered policy exists");

    let target = find_devcontainer_json(&cwd).unwrap_or_else(|| default_devcontainer_json(&cwd));
    if let Err(error) =
        super::preflight_config_write_authorization(&cwd, &target, true, policy, false)
    {
        if json {
            let out = serde_json::json!({
                "schema_version": 1,
                "status": "error",
                "devcontainer_path": target.display().to_string(),
                "gitignore_path": cwd.join(".gitignore").display().to_string(),
                "error": error.to_string(),
            });
            let mut stdout = std::io::stdout().lock();
            let _ = serde_json::to_writer_pretty(&mut stdout, &out);
            let _ = writeln!(stdout);
        } else {
            eprintln!("tirith codespaces setup: task gate refused setup: {error}");
        }
        return 1;
    }

    // Commit the root-level ignore first. Its retained rollback capability can
    // restore exact prior bytes (or remove the exact just-created file) if the
    // devcontainer update subsequently fails.
    let gitignore_update = match ensure_gitignore_entry_permitted(&cwd, policy) {
        Ok(update) => update,
        Err(error) => {
            if json {
                let out = serde_json::json!({
                    "schema_version": 1,
                    "status": "error",
                    "devcontainer_path": target.display().to_string(),
                    "gitignore_path": cwd.join(".gitignore").display().to_string(),
                    "error": error.to_string(),
                });
                let mut stdout = std::io::stdout().lock();
                let _ = serde_json::to_writer_pretty(&mut stdout, &out);
                let _ = writeln!(stdout);
            } else {
                eprintln!("tirith codespaces setup: could not update .gitignore: {error}");
            }
            return 1;
        }
    };
    let gitignore_added = gitignore_update.changed();

    let outcome = super::devcontainer::inject_tirith_hook_permitted(&target, &cwd, true, policy);
    let injected_code = if matches!(
        outcome,
        InjectOutcome::Created(_) | InjectOutcome::Updated(_) | InjectOutcome::AlreadyInjected(_)
    ) {
        0
    } else {
        1
    };
    if injected_code != 0 {
        let rollback_result = gitignore_update.rollback(&cwd);
        if let Err(rollback_error) = &rollback_result {
            eprintln!(
                "tirith codespaces setup: devcontainer update failed and .gitignore rollback failed: {rollback_error}"
            );
        }
        if json {
            let (path, error) = match &outcome {
                InjectOutcome::NotFound(path) => {
                    (path, "devcontainer destination was not found".to_string())
                }
                InjectOutcome::ParseError(path, error) => (path, error.clone()),
                _ => (&target, "devcontainer update failed".to_string()),
            };
            let out = serde_json::json!({
                "schema_version": 1,
                "status": "error",
                "devcontainer_path": path.display().to_string(),
                "gitignore_path": cwd.join(".gitignore").display().to_string(),
                "gitignore_rolled_back": gitignore_added && rollback_result.is_ok(),
                "error": error,
            });
            let mut stdout = std::io::stdout().lock();
            let _ = serde_json::to_writer_pretty(&mut stdout, &out);
            let _ = writeln!(stdout);
        } else {
            let _ = report_outcome("codespaces setup", &outcome, false);
        }
        return injected_code;
    }

    if !json {
        let _ = report_outcome("codespaces setup", &outcome, false);
    }

    if json {
        let (status, path) = match &outcome {
            InjectOutcome::Created(path) => ("created", path),
            InjectOutcome::Updated(path) => ("updated", path),
            InjectOutcome::AlreadyInjected(path) => ("already_injected", path),
            _ => unreachable!("non-success outcome returned a zero exit code"),
        };
        let out = serde_json::json!({
            "schema_version": 1,
            "status": status,
            "devcontainer_path": path.display().to_string(),
            "gitignore_updated": gitignore_added,
            "gitignore_path": cwd.join(".gitignore").display().to_string(),
        });
        let mut stdout = std::io::stdout().lock();
        if serde_json::to_writer_pretty(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
            return 1;
        }
    } else if gitignore_added {
        eprintln!(
            "tirith codespaces setup: added `.tirith/` entry to {}",
            cwd.join(".gitignore").display()
        );
    } else {
        eprintln!(
            "tirith codespaces setup: `.tirith/` already present in {}",
            cwd.join(".gitignore").display()
        );
    }

    0
}

enum GitignoreUpdate {
    Unchanged,
    Changed {
        rollback: tirith_core::util::ContainedAtomicFile,
        original: Option<Vec<u8>>,
        written: Vec<u8>,
    },
}

impl GitignoreUpdate {
    fn changed(&self) -> bool {
        matches!(self, Self::Changed { .. })
    }

    fn rollback(self, cwd: &Path) -> std::io::Result<()> {
        let Self::Changed {
            rollback,
            original,
            written,
        } = self
        else {
            return Ok(());
        };
        let path = cwd.join(".gitignore");
        rollback.lock_parent_for_mutation()?;
        if !rollback.matches_visible(cwd, &path)? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                ".gitignore identity changed before rollback",
            ));
        }
        match original {
            Some(bytes) => {
                let current = rollback
                    .read_capped(written.len().saturating_add(1) as u64)
                    .map_err(|error| {
                        std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!("cannot verify .gitignore rollback target: {error:?}"),
                        )
                    })?;
                if current != written {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        ".gitignore changed after setup publication; refusing rollback",
                    ));
                }
                rollback.write_atomic_if_observed(&bytes, true)
            }
            None => rollback.remove_if_contents(&written),
        }
    }
}

fn ensure_gitignore_entry_permitted(
    cwd: &Path,
    policy: &Policy,
) -> std::io::Result<GitignoreUpdate> {
    const CONFIG_READ_CAP: u64 = 1024 * 1024;
    let path = cwd.join(".gitignore");
    super::preflight_config_write_authorization(cwd, &path, true, policy, false)?;
    let prepared = tirith_core::util::ContainedAtomicFile::prepare(cwd, &path, false)?;
    prepared.lock_parent_for_mutation()?;
    let original = match prepared.read_capped(CONFIG_READ_CAP) {
        Ok(bytes) => Some(bytes),
        Err(tirith_core::util::OpenRegularError::NotFound) => None,
        Err(error) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("refusing to read unsafe .gitignore: {error:?}"),
            ));
        }
    };
    let existing = match original.as_deref() {
        Some(bytes) => String::from_utf8(bytes.to_vec()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                ".gitignore is not UTF-8; refusing to rewrite it",
            )
        })?,
        None => String::new(),
    };
    if existing.lines().any(|line| {
        matches!(
            line.trim(),
            ".tirith" | ".tirith/" | "/.tirith" | "/.tirith/"
        )
    }) {
        return Ok(GitignoreUpdate::Unchanged);
    }
    let mut contents = existing;
    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str("# tirith state directory (devcontainer / codespaces)\n");
    contents.push_str(".tirith/\n");
    let written = contents.into_bytes();
    let rollback = tirith_core::util::ContainedAtomicFile::prepare(cwd, &path, false)?;
    super::write_prepared_config_file_permitted(
        cwd, &path, prepared, &written, true, policy, false,
    )?;
    Ok(GitignoreUpdate::Changed {
        rollback,
        original,
        written,
    })
}

/// `tirith codespaces inject [--path <dir>]` — alias of `tirith devcontainer inject`.
pub fn inject(path: Option<&Path>, create: bool, json: bool) -> i32 {
    super::devcontainer::inject(path, create, json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::tempdir;

    fn write_decoy_hook(root: &Path) -> std::path::PathBuf {
        let config_dir = root.join(".devcontainer");
        std::fs::create_dir_all(&config_dir).unwrap();
        let config_path = config_dir.join("devcontainer.json");
        std::fs::write(
            &config_path,
            serde_json::to_vec_pretty(&json!({
                "postCreateCommand": "echo 'tirith init --shell auto'",
                "containerEnv": {"TIRITH_DEVCONTAINER": "1"}
            }))
            .unwrap(),
        )
        .unwrap();
        config_path
    }

    fn assert_decoy_replaced_by_exact_independent_hook(config_path: &Path) {
        let updated: serde_json::Value =
            serde_json::from_slice(&std::fs::read(config_path).unwrap()).unwrap();
        assert_eq!(
            updated["postCreateCommand"][tirith_core::devcontainer_writer::TIRITH_HOOK_KEY],
            json!(["tirith", "init", "--shell", "auto"]),
        );
        assert_eq!(
            updated["postCreateCommand"]["existing"], "echo 'tirith init --shell auto'",
            "the repository command must remain separate from Tirith's managed hook",
        );
    }

    #[test]
    fn setup_creates_devcontainer_and_gitignore() {
        let dir = tempdir().unwrap();
        let code = setup(Some(dir.path()), false);
        assert_eq!(code, 0);
        let dc = dir.path().join(".devcontainer/devcontainer.json");
        assert!(dc.is_file());
        let gi = dir.path().join(".gitignore");
        let body = std::fs::read_to_string(&gi).unwrap();
        assert!(body.contains(".tirith/"));
    }

    #[test]
    fn setup_idempotent_second_run() {
        let dir = tempdir().unwrap();
        let _ = setup(Some(dir.path()), false);
        let code = setup(Some(dir.path()), false);
        assert_eq!(code, 0);
    }

    #[test]
    fn setup_off_mode_publishes_both_config_files() {
        let dir = tempdir().unwrap();
        let mut policy = Policy::default();
        policy.task_gate.mode = tirith_core::web3_policy::TaskGateMode::Off;

        assert_eq!(setup_with_policy(Some(dir.path()), false, Some(&policy)), 0);
        assert!(dir.path().join(".devcontainer/devcontainer.json").is_file());
        assert!(std::fs::read_to_string(dir.path().join(".gitignore"))
            .unwrap()
            .contains(".tirith/"));
    }

    #[test]
    fn setup_deny_leaves_devcontainer_and_gitignore_byte_identical() {
        let dir = tempdir().unwrap();
        let config_path = write_decoy_hook(dir.path());
        let gitignore_path = dir.path().join(".gitignore");
        std::fs::write(&gitignore_path, b"existing-entry\n").unwrap();
        let config_before = std::fs::read(&config_path).unwrap();
        let gitignore_before = std::fs::read(&gitignore_path).unwrap();
        let mut policy = Policy::default();
        policy.task_gate.mode = tirith_core::web3_policy::TaskGateMode::Enforce;
        policy
            .task_gate
            .effects_denied_for_untrusted_sources
            .insert(tirith_core::effects::CommandEffectKind::FilesystemWrite);

        assert_ne!(setup_with_policy(Some(dir.path()), false, Some(&policy)), 0);
        assert_eq!(std::fs::read(&config_path).unwrap(), config_before);
        assert_eq!(std::fs::read(&gitignore_path).unwrap(), gitignore_before);
    }

    #[test]
    fn setup_deny_creates_no_devcontainer_directory_or_files() {
        let dir = tempdir().unwrap();
        let mut policy = Policy::default();
        policy.task_gate.mode = tirith_core::web3_policy::TaskGateMode::Enforce;
        policy
            .task_gate
            .effects_denied_for_untrusted_sources
            .insert(tirith_core::effects::CommandEffectKind::FilesystemWrite);

        assert_ne!(setup_with_policy(Some(dir.path()), false, Some(&policy)), 0);
        assert!(!dir.path().join(".devcontainer").exists());
        assert!(!dir.path().join(".gitignore").exists());
    }

    #[cfg(unix)]
    #[test]
    fn setup_rolls_back_a_new_gitignore_when_devcontainer_is_unsafe() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join(".devcontainer")).unwrap();
        let policy = Policy::default();

        assert_ne!(setup_with_policy(Some(dir.path()), false, Some(&policy)), 0);
        assert!(!dir.path().join(".gitignore").exists());
        assert!(!outside.path().join("devcontainer.json").exists());
        assert!(std::fs::symlink_metadata(dir.path().join(".devcontainer"))
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn setup_restores_existing_gitignore_bytes_when_devcontainer_is_unsafe() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let original = b"target/\n# keep exact spacing  \n";
        std::fs::write(dir.path().join(".gitignore"), original).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join(".devcontainer")).unwrap();

        assert_ne!(
            setup_with_policy(Some(dir.path()), false, Some(&Policy::default())),
            0
        );
        assert_eq!(
            std::fs::read(dir.path().join(".gitignore")).unwrap(),
            original
        );
        assert!(!outside.path().join("devcontainer.json").exists());
    }

    #[test]
    fn rollback_preserves_a_competing_gitignore_replacement() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".gitignore");
        let written = b".tirith/\n".to_vec();
        std::fs::write(&path, &written).unwrap();
        let rollback =
            tirith_core::util::ContainedAtomicFile::prepare(dir.path(), &path, false).unwrap();
        let update = GitignoreUpdate::Changed {
            rollback,
            original: Some(b"target/\n".to_vec()),
            written,
        };
        std::fs::write(&path, b"concurrent editor\n").unwrap();

        assert!(update.rollback(dir.path()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"concurrent editor\n");
    }

    #[test]
    fn setup_does_not_trust_a_hook_substring() {
        let dir = tempdir().unwrap();
        let config_path = write_decoy_hook(dir.path());

        assert_eq!(setup(Some(dir.path()), false), 0);
        assert_decoy_replaced_by_exact_independent_hook(&config_path);
    }

    #[test]
    fn inject_does_not_trust_a_hook_substring() {
        let dir = tempdir().unwrap();
        let config_path = write_decoy_hook(dir.path());

        assert_eq!(inject(Some(dir.path()), false, false), 0);
        assert_decoy_replaced_by_exact_independent_hook(&config_path);
    }
}
