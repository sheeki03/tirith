//! Exact native code-import admission for the initial automatic Zsh row.
//! These hashes name the Apple-signed Zsh 5.9 files whose native dependencies
//! and module behavior were inspected together. An OS update with different
//! bytes needs a reviewed row. No environment path, version string, signature
//! status supplied by the shell, or successful bootstrap is execution proof.

use tirith_core::execution_state::AuthenticatedShellContext;

pub(super) fn qualify(shell: &AuthenticatedShellContext) -> Result<(), String> {
    shell.revalidate()?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        macos::qualify(shell)
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        Err("automatic native module row is unavailable".into())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos {
    use super::*;
    use crate::cli::control::identity::{BinaryIdentity, DirectoryIdentity};
    use std::os::macos::fs::MetadataExt as DarwinMetadataExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    // Full files, including all Mach-O slices and signature data. The audited
    // dependency closure imports only the four fixed system dylibs documented
    // in docs/next-cycle/automatic-zsh-native-row.md. Runtime does not parse or
    // load code, invoke codesign, or accept another Apple-signed file.
    const FILES: [(&str, &str); 5] = [
        (
            "/bin/zsh",
            "ca835f58545521f3e845c2ffcd3822a865df8ac2cde4ab5e686fb621369b9c99",
        ),
        (
            "/usr/lib/zsh/5.9/zsh/rlimits.so",
            "d1369dd01a981fd25bd454d3805ec095090fea3e899b91c850fb78fe852c70a0",
        ),
        (
            "/usr/lib/zsh/5.9/zsh/system.so",
            "16f1639bfc56d8a3f09578fc761d8ae00ec91492779c90860e28f656cf0ac4f9",
        ),
        (
            "/usr/lib/zsh/5.9/zsh/stat.so",
            "3766413e5a54b7c388e3e54e08c3605634fb2069aefe39a004085fb5a25ea899",
        ),
        (
            "/usr/lib/zsh/5.9/zsh/files.so",
            "ed8fde185decd05069060110d39dd328710a6a86ab9dd6a71e97c2e1de86c5e2",
        ),
    ];
    const DIRECTORIES: [&str; 7] = [
        "/",
        "/bin",
        "/usr",
        "/usr/lib",
        "/usr/lib/zsh",
        "/usr/lib/zsh/5.9",
        "/usr/lib/zsh/5.9/zsh",
    ];
    const FILE_CAP: u64 = 2 * 1024 * 1024;
    const SF_RESTRICTED: u32 = 0x0008_0000;

    #[link(name = "System")]
    unsafe extern "C" {
        fn csr_get_active_config(config: *mut u32) -> libc::c_int;
        fn proc_pidpath(pid: libc::c_int, buffer: *mut libc::c_void, size: u32) -> libc::c_int;
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            size: libc::c_int,
        ) -> libc::c_int;
    }

    fn refused() -> String {
        "automatic native module row is unavailable".into()
    }

    fn system_protection() -> Result<(), String> {
        let mut config = u32::MAX;
        // The initial row is qualified only with standard, fully enabled SIP.
        // Neither root nor an environment option can bypass this admission.
        if unsafe { csr_get_active_config(&mut config) } != 0 || config != 0 {
            return Err(refused());
        }
        Ok(())
    }

    fn native_shell_path(shell: &AuthenticatedShellContext) -> Result<(), String> {
        let pid = i32::try_from(shell.shell_pid()).map_err(|_| refused())?;
        #[repr(C)]
        struct ArchInfo {
            cpu_type: i32,
            cpu_subtype: i32,
        }
        let mut arch = ArchInfo {
            cpu_type: 0,
            cpu_subtype: 0,
        };
        let arch_size = std::mem::size_of::<ArchInfo>() as i32;
        // PROC_PIDARCHINFO observes the actual parent, rather than inferring
        // its architecture from the helper or a shell-provided version string.
        if unsafe { proc_pidinfo(pid, 19, 0, (&mut arch as *mut ArchInfo).cast(), arch_size) }
            != arch_size
            || arch.cpu_type != 0x0100_000c
        {
            return Err(refused());
        }
        let mut bytes = [0u8; 4096];
        let count = unsafe { proc_pidpath(pid, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
        if count <= 0 || count as usize >= bytes.len() {
            return Err(refused());
        }
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(refused)?;
        if &bytes[..end] != b"/bin/zsh" {
            return Err(refused());
        }
        Ok(())
    }

    fn metadata_admitted(mode: u32, uid: u32, flags: u32, directory: bool, root: bool) -> bool {
        let kind = mode & u32::from(libc::S_IFMT);
        uid == 0
            && mode & 0o022 == 0
            && kind
                == u32::from(if directory {
                    libc::S_IFDIR
                } else {
                    libc::S_IFREG
                })
            && (directory || mode & 0o111 != 0)
            && (root || flags & SF_RESTRICTED != 0)
    }

    fn protected_metadata(path: &str, directory: bool) -> Result<(), String> {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| refused())?;
        if !metadata_admitted(
            metadata.mode(),
            metadata.uid(),
            metadata.st_flags(),
            directory,
            path == "/",
        ) {
            return Err(refused());
        }
        Ok(())
    }

    pub(super) fn qualify(shell: &AuthenticatedShellContext) -> Result<(), String> {
        system_protection()?;
        native_shell_path(shell)?;
        for path in DIRECTORIES {
            protected_metadata(path, true)?;
        }
        // Retain real ancestor handles and ACL checks across all file reads.
        let shell_directory = DirectoryIdentity::capture_trusted(Path::new("/bin"))?;
        let module_directory =
            DirectoryIdentity::capture_trusted(Path::new("/usr/lib/zsh/5.9/zsh"))?;
        let mut held = Vec::with_capacity(FILES.len());
        for (path, expected) in FILES {
            protected_metadata(path, false)?;
            let file = BinaryIdentity::capture_input_capped(Path::new(path), FILE_CAP)?;
            if file.sha256() != expected {
                return Err(refused());
            }
            protected_metadata(path, false)?;
            held.push(file);
        }
        shell.revalidate()?;
        native_shell_path(shell)?;
        shell_directory.revalidate()?;
        module_directory.revalidate()?;
        for (file, (path, _)) in held.iter().zip(FILES) {
            file.revalidate()?;
            protected_metadata(path, false)?;
        }
        for path in DIRECTORIES {
            protected_metadata(path, true)?;
        }
        system_protection()?;
        shell.revalidate()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn native_row_metadata_refuses_writable_unprotected_or_substituted_inputs() {
            assert!(metadata_admitted(0o100755, 0, SF_RESTRICTED, false, false));
            assert!(metadata_admitted(0o040755, 0, SF_RESTRICTED, true, false));
            assert!(metadata_admitted(0o040755, 0, 0, true, true));
            for (mode, uid, flags) in [
                (0o100775, 0, SF_RESTRICTED),
                (0o100757, 0, SF_RESTRICTED),
                (0o100755, 501, SF_RESTRICTED),
                (0o100755, 0, 0),
                (0o100644, 0, SF_RESTRICTED),
                (0o120755, 0, SF_RESTRICTED),
                (0o040755, 0, SF_RESTRICTED),
            ] {
                assert!(!metadata_admitted(mode, uid, flags, false, false));
            }
            assert!(!metadata_admitted(0o040755, 0, 0, true, false));
        }
    }
}
