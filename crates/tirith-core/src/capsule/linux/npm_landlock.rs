//! Exact-file and held-directory Landlock policy for the closed npm launcher.

use std::os::fd::BorrowedFd;

use landlock::{
    Access, AccessFs, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, ABI,
};

use super::ContainError;

/// The caller validates the nine exact files and two distinct writable directory
/// descriptors and keeps all of them alive until this function returns.
pub(super) fn apply(
    read_files: &[(i32, bool)],
    write_directories: &[i32],
) -> Result<(), ContainError> {
    // npm moves cache/tmp files into cache/content-v2. ABI 1 always denies
    // cross-directory rename, even beneath one writable grant. ABI 2 adds
    // REFER; require it rather than falling back to a policy that cannot run npm.
    // https://docs.kernel.org/5.19/userspace-api/landlock.html#filesystem-flags
    // No containing runtime directory or additional writable root is granted.
    let all = AccessFs::from_all(ABI::V2);
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(all)
        .map_err(|e| ContainError::Landlock(e.to_string()))?
        .create()
        .map_err(|e| ContainError::Landlock(e.to_string()))?;
    for (fd, executable) in read_files {
        // SAFETY: caller retains and validates every descriptor through apply.
        let file = unsafe { BorrowedFd::borrow_raw(*fd) };
        ruleset = ruleset
            .add_rule(PathBeneath::new(
                file,
                if *executable {
                    AccessFs::ReadFile | AccessFs::Execute
                } else {
                    AccessFs::ReadFile.into()
                },
            ))
            .map_err(|e| ContainError::Landlock(format!("exact npm runtime file: {e}")))?;
    }
    let writable = all & !AccessFs::Execute;
    for fd in write_directories {
        // SAFETY: the validated directory descriptor remains held by the caller.
        let directory = unsafe { BorrowedFd::borrow_raw(*fd) };
        ruleset = ruleset
            .add_rule(PathBeneath::new(directory, writable))
            .map_err(|e| ContainError::Landlock(format!("held npm directory: {e}")))?;
    }
    let status = ruleset
        .restrict_self()
        .map_err(|e| ContainError::Landlock(e.to_string()))?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(ContainError::Unsupported(
            "closed npm requires full Landlock enforcement".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const ROOT: &str = "TIRITH_NPM_LANDLOCK_TEST_ROOT";
    const MODE: &str = "TIRITH_NPM_LANDLOCK_TEST_MODE";

    struct OwnedChild(Child);

    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn denied(result: std::io::Result<()>) {
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EACCES));
    }

    #[test]
    fn npm_landlock_rename_subprocess() {
        let Some(root) = std::env::var_os(ROOT) else {
            return;
        };
        let root = Path::new(&root);
        let mode = std::env::var(MODE).unwrap();
        // Open all capabilities before installing the production policy.
        let files: Vec<_> = (0..9)
            .map(|i| File::open(root.join(format!("runtime/file-{i}"))).unwrap())
            .collect();
        let read_files: Vec<_> = files
            .iter()
            .enumerate()
            .map(|(i, file)| (file.as_raw_fd(), i == 0))
            .collect();
        let directories = [
            File::open(root.join("target")).unwrap(),
            File::open(root.join("cache")).unwrap(),
        ];
        let write_directories = directories.each_ref().map(AsRawFd::as_raw_fd);
        super::super::set_no_new_privs().unwrap();
        if mode == "unsupported" {
            assert!(apply(&read_files, &write_directories).is_err());
            return;
        }
        if mode == "v1" {
            let all = AccessFs::from_all(ABI::V1);
            let mut ruleset = Ruleset::default()
                .set_compatibility(CompatLevel::HardRequirement)
                .handle_access(all)
                .unwrap()
                .create()
                .unwrap();
            for directory in &directories {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(directory, all & !AccessFs::Execute))
                    .unwrap();
            }
            assert_eq!(
                ruleset.restrict_self().unwrap().ruleset,
                RulesetStatus::FullyEnforced
            );
        } else {
            assert_eq!(mode, "npm");
            apply(&read_files, &write_directories).unwrap();
        }
        // Exercise the production native syscall policy too: no renameat2,
        // copyFile metadata, or general syscall exceptions are added for npm.
        #[cfg(target_arch = "aarch64")]
        super::super::aarch64_seccomp::apply_npm(files[0].as_raw_fd()).unwrap();
        #[cfg(target_arch = "x86_64")]
        assert!(super::super::apply_seccomp().unwrap());
        let source = root.join("cache/tmp/source");
        let destination = root.join("cache/content-v2/content");
        let result = std::fs::rename(&source, &destination);
        if mode == "v1" {
            assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EXDEV));
            return;
        }
        result.unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"cache-content");
        assert!(!source.exists());
        std::fs::rename(
            root.join("target/tmp/source"),
            root.join("target/content/source"),
        )
        .unwrap();
        // The executable's exact-file grant and the other read-only file grants
        // do not authorize either parent directory or reparenting those files.
        for name in ["runtime/file-0", "runtime/file-1", "outside/source"] {
            let path = root.join(name);
            denied(std::fs::rename(&path, root.join("cache/imported")));
            denied(std::fs::rename(&destination, &path));
            denied(std::fs::write(&path, b"changed"));
        }
        for name in ["runtime/new-file", "outside/new-file"] {
            denied(std::fs::rename(&destination, root.join(name)));
        }
        // Metadata mutation remains denied even for a file in an admitted tree.
        let content = File::open(&destination).unwrap();
        assert_eq!(unsafe { libc::fchmod(content.as_raw_fd(), 0o777) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
    }

    #[test]
    fn npm_landlock_requires_v2_for_confined_cache_reparenting() {
        let abi = super::super::best_effort_abi();
        let modes: &[&str] = if abi.is_some_and(|abi| abi >= 2) {
            &["v1", "npm"]
        } else {
            // ABI 1 or unavailable kernels must refuse the production helper,
            // not silently grant a weaker ruleset or an unconfined launch.
            &["unsupported"]
        };
        for mode in modes {
            let root = tempfile::tempdir().unwrap();
            for path in [
                "runtime",
                "outside",
                "target/tmp",
                "target/content",
                "cache/tmp",
                "cache/content-v2",
            ] {
                std::fs::create_dir_all(root.path().join(path)).unwrap();
            }
            for i in 0..9 {
                std::fs::write(root.path().join(format!("runtime/file-{i}")), b"runtime").unwrap();
            }
            std::fs::write(root.path().join("outside/source"), b"outside").unwrap();
            std::fs::write(root.path().join("cache/tmp/source"), b"cache-content").unwrap();
            std::fs::write(root.path().join("target/tmp/source"), b"target-content").unwrap();
            let output_path = root.path().join("child-output");
            let output = File::create(&output_path).unwrap();
            let mut child = OwnedChild(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "capsule::linux::npm_landlock::tests::npm_landlock_rename_subprocess",
                        "--exact",
                        "--test-threads=1",
                    ])
                    .env(ROOT, root.path())
                    .env(MODE, mode)
                    .stdin(Stdio::null())
                    .stdout(output.try_clone().unwrap())
                    .stderr(output)
                    .spawn()
                    .unwrap(),
            );
            let deadline = Instant::now() + Duration::from_secs(10);
            let status = loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                assert!(
                    Instant::now() < deadline,
                    "npm Landlock {mode} exceeded deadline"
                );
                std::thread::sleep(Duration::from_millis(10));
            };
            let mut output = Vec::new();
            File::open(&output_path)
                .unwrap()
                .take(16 * 1024 + 1)
                .read_to_end(&mut output)
                .unwrap();
            assert!(
                output.len() <= 16 * 1024,
                "oversized npm Landlock test output"
            );
            assert!(
                status.success(),
                "npm Landlock {mode} child failed: {status}: {}",
                String::from_utf8_lossy(&output)
            );
            for i in 0..9 {
                assert_eq!(
                    std::fs::read(root.path().join(format!("runtime/file-{i}"))).unwrap(),
                    b"runtime"
                );
            }
            assert_eq!(
                std::fs::read(root.path().join("outside/source")).unwrap(),
                b"outside"
            );
            assert!(!root.path().join("runtime/new-file").exists());
            assert!(!root.path().join("outside/new-file").exists());
            let result_path = if *mode == "npm" {
                "cache/content-v2/content"
            } else {
                "cache/tmp/source"
            };
            assert_eq!(
                std::fs::read(root.path().join(result_path)).unwrap(),
                b"cache-content"
            );
            let target_path = if *mode == "npm" {
                "target/content/source"
            } else {
                "target/tmp/source"
            };
            assert_eq!(
                std::fs::read(root.path().join(target_path)).unwrap(),
                b"target-content"
            );
        }
    }
}
