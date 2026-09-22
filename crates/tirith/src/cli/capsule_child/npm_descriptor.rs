//! Validation at the trusted, single-threaded ARM64 launcher boundary.
use super::*;
use crate::cli::capsule::npm_descriptor::{self as wire, Content, Manifest};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use tirith_core::capsule::CapsuleSpec;

pub(super) struct Prepared {
    manifest: Manifest,
}

fn stat(fd: i32) -> Result<libc::stat, String> {
    let mut value: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(value)
}
fn hash(fd: i32, size: u64) -> Result<String, String> {
    // The inherited owner is retained by the launcher. The duplicate exists only
    // during bounded pre-containment validation and never enters the whitelist.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let file = File::from(borrowed.try_clone_to_owned().map_err(|e| e.to_string())?);
    let mut digest = Sha256::new();
    let mut offset = 0;
    let mut bytes = [0u8; 64 * 1024];
    while offset < size {
        let wanted = bytes.len().min((size - offset) as usize);
        let count = file
            .read_at(&mut bytes[..wanted], offset)
            .map_err(|e| e.to_string())?;
        if count == 0 {
            return Err("truncated npm descriptor".into());
        }
        digest.update(&bytes[..count]);
        offset += count as u64;
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn sealed(content: &Content, mode: libc::mode_t, cap: u64) -> Result<(), String> {
    let before = stat(content.fd)?;
    let seals = unsafe { libc::fcntl(content.fd, libc::F_GET_SEALS) };
    if before.st_mode & libc::S_IFMT != libc::S_IFREG
        || before.st_mode & 0o7777 != mode
        || before.st_size < 0
        || before.st_size as u64 != content.size
        || content.size > cap
        || before.st_uid != unsafe { libc::geteuid() }
        || seals < 0
        || seals & wire::SEALED != wire::SEALED
    {
        return Err("npm descriptor type/mode/seals/size changed".into());
    }
    if hash(content.fd, content.size)? != content.sha256 {
        return Err("npm descriptor digest mismatch".into());
    }
    Ok(())
}
/// The final executable inode must never be owned by the ordinary dumpable
/// parent. F_SEAL_EXEC freezes executable bits, not readability. A peer holding
/// a parent's descriptor could otherwise chmod0100 to0500 after validation and
/// make exec reset dumpability. Create this inode only after PR_SET_DUMPABLE(0),
/// then move it to the already-reserved child slot. The parent still holds its
/// separate sealed source inode, whose bytes cannot change.
fn private_executor_copy(content: &Content) -> Result<(), String> {
    if unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err("npm launcher is dumpable before private executable creation".into());
    }
    let mut policy = Vec::new();
    File::open("/proc/sys/fs/suid_dumpable")
        .map_err(|e| e.to_string())?
        .take(16)
        .read_to_end(&mut policy)
        .map_err(|e| e.to_string())?;
    if policy != b"0\n" && policy != b"0" {
        return Err("npm execute-only launch requires fs.suid_dumpable=0".into());
    }
    let source = File::from(
        unsafe { BorrowedFd::borrow_raw(content.fd) }
            .try_clone_to_owned()
            .map_err(|e| e.to_string())?,
    );
    let raw = unsafe {
        libc::memfd_create(
            c"tirith-private-node".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | libc::MFD_EXEC,
        )
    };
    if raw < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut private = unsafe { File::from_raw_fd(raw) };
    let mut hash = Sha256::new();
    let mut offset = 0;
    let mut buffer = [0u8; 64 * 1024];
    while offset < content.size {
        let wanted = buffer.len().min((content.size - offset) as usize);
        let count = source
            .read_at(&mut buffer[..wanted], offset)
            .map_err(|e| e.to_string())?;
        if count == 0 {
            return Err("private npm executable copy truncated".into());
        }
        private
            .write_all(&buffer[..count])
            .map_err(|e| e.to_string())?;
        hash.update(&buffer[..count]);
        offset += count as u64;
    }
    if format!("{:x}", hash.finalize()) != content.sha256 {
        return Err("private npm executable digest changed".into());
    }
    let seals = wire::SEALED | libc::F_SEAL_EXEC;
    if unsafe { libc::fchmod(raw, 0o100) } != 0
        || unsafe { libc::fcntl(raw, libc::F_ADD_SEALS, seals) } < 0
    {
        return Err("execute-only npm mode/sealing unavailable".into());
    }
    if unsafe { libc::dup3(raw, content.fd, libc::O_CLOEXEC) } != content.fd {
        return Err("cannot bind private npm executable to reserved child slot".into());
    }
    let final_stat = stat(content.fd)?;
    let source_stat = stat(source.as_raw_fd())?;
    let final_seals = unsafe { libc::fcntl(content.fd, libc::F_GET_SEALS) };
    let final_flags = unsafe { libc::fcntl(content.fd, libc::F_GETFD) };
    if final_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || final_stat.st_mode & 0o7777 != 0o100
        || final_stat.st_size < 0
        || final_stat.st_size as u64 != content.size
        || final_stat.st_uid != unsafe { libc::geteuid() }
        || (final_stat.st_dev, final_stat.st_ino) == (source_stat.st_dev, source_stat.st_ino)
        || !final_executor_seals(final_seals)
        || final_flags < 0
        || final_flags & libc::FD_CLOEXEC == 0
    {
        return Err("private npm executable identity/mode/seals changed".into());
    }
    // private/source drops close only their distinct owned descriptors. The
    // replaced reserved slot remains process-owned through execveat+CLOEXEC.
    Ok(())
}

fn final_executor_seals(seals: i32) -> bool {
    let required = wire::SEALED | libc::F_SEAL_EXEC;
    seals >= 0 && seals & required == required
}

fn directory(row: &wire::Directory, path: &Path) -> Result<(), String> {
    let held = stat(row.fd)?;
    if held.st_mode & libc::S_IFMT != libc::S_IFDIR
        || held.st_uid != unsafe { libc::geteuid() }
        || held.st_mode & 0o777 != 0o700
        || held.st_dev.to_string() != row.device
        || held.st_ino.to_string() != row.inode
    {
        return Err("npm target/cache identity or owner changed".into());
    }
    let canonical = validate_held_ephemeral_directory(path.as_os_str(), row.fd, "npm directory")?;
    if canonical != path {
        return Err("npm directory alias".into());
    }
    Ok(())
}
fn cloexec(fd: i32) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

pub(super) fn prepare(parsed: &ParsedArgs, spec: &CapsuleSpec) -> Result<Option<Prepared>, String> {
    let Some(raw) = parsed.npm_launch_json.as_deref() else {
        return Ok(None);
    };
    if raw.len() > wire::MAX_MANIFEST {
        return Err("native npm manifest exceeds bound".into());
    }
    let manifest: Manifest =
        serde_json::from_str(raw).map_err(|e| format!("native npm manifest: {e}"))?;
    if serde_json::to_string(&manifest).map_err(|e| e.to_string())? != raw {
        return Err("native npm manifest is not canonical".into());
    }
    let b = &manifest.inputs;
    let status = parsed.launch_status_fd.ok_or("npm status proof required")?;
    let ack = parsed
        .launch_ack_fd
        .ok_or("npm resume authorization required")?;
    let coverage = parsed
        .coverage_status_fd
        .ok_or("npm coverage proof required")?;
    wire::check_shape(&manifest, &[status, ack, coverage])?;
    if parsed.program != tirith_core::artifact::npm_install::tools::NODE_PATH
        || parsed.target_argv0.is_some()
        || parsed.target_fd != Some(manifest.node.fd)
        || parsed.script_fd.is_some()
        || parsed.cwd_fd.is_some()
        || parsed.work_fd.is_some()
        || parsed.staging_fd.is_some()
        || !parsed.inputs.is_empty()
        || parsed.target_dir_fd.is_some()
        || parsed.temp_home_fd != Some(b.cache.fd)
        || parsed.temp_home.as_deref() != Some(manifest.cache_path.as_os_str())
        || parsed.program_args != wire::node_args(manifest.bootstrap.fd, manifest.binding.fd)
    {
        return Err("npm mode cannot accept generic launch options/argv".into());
    }
    let mut expected_fds = vec![
        manifest.node.fd,
        manifest.bootstrap.fd,
        manifest.binding.fd,
        b.runtime.fd,
        b.target.fd,
        b.cache.fd,
        b.user_config.fd,
        b.global_config.fd,
        status,
        ack,
        coverage,
    ];
    expected_fds.extend(b.artifacts.iter().map(|r| r.fd));
    expected_fds.extend(manifest.runtime_files.iter().map(|r| r.content.fd));
    expected_fds.sort_unstable();
    let mut actual_fds = spec.handles.extra_unix_fds.clone();
    actual_fds.sort_unstable();
    if expected_fds != actual_fds {
        return Err("npm inherited descriptor set differs from manifest".into());
    }
    let expected_env = wire::fixed_environment(b.user_config.fd);
    let actual_env: std::collections::BTreeMap<_, _> = std::env::vars_os().collect();
    let env: std::collections::BTreeMap<_, _> = expected_env
        .iter()
        .map(|(key, val)| (OsString::from(key), OsString::from(val)))
        .collect();
    if env != actual_env {
        return Err("npm launcher environment differs from closed contract".into());
    }
    let mut expected_spec = crate::cli::capsule::supervised_stdin_spec();
    expected_spec.resources.wall_clock_seconds = None;
    expected_spec.resources.max_output_bytes = None;
    expected_spec.filesystem.read_roots = manifest
        .runtime_files
        .iter()
        .map(|r| r.path.clone())
        .collect();
    expected_spec.filesystem.write_roots =
        vec![manifest.target_path.clone(), manifest.cache_path.clone()];
    expected_spec.environment.allow = expected_env.into_iter().map(|(key, _)| key).collect();
    expected_spec.handles.extra_unix_fds = spec.handles.extra_unix_fds.clone();
    // Canonical policy normalization is pure aside from resolving the already
    // retained paths. It must not insert ambient grants or weaken denials.
    expected_spec.filesystem = tirith_core::capsule::canonicalize_and_validate_filesystem_policy(
        &expected_spec.filesystem,
    )
    .map_err(|e| e.to_string())?;
    if serde_json::to_value(&expected_spec).map_err(|e| e.to_string())?
        != serde_json::to_value(spec).map_err(|e| e.to_string())?
    {
        return Err("npm capsule policy is not the closed native policy".into());
    }
    directory(&b.target, &manifest.target_path)?;
    directory(&b.cache, &manifest.cache_path)?;
    if manifest.target_path.starts_with(&manifest.cache_path)
        || manifest.cache_path.starts_with(&manifest.target_path)
    {
        return Err("overlapping npm writable capabilities".into());
    }
    sealed(&manifest.node, 0o100, 256 * 1024 * 1024)?;
    private_executor_copy(&manifest.node)?;
    sealed(&manifest.node, 0o100, 256 * 1024 * 1024)?;
    sealed(&manifest.bootstrap, 0o400, 128 * 1024)?;
    sealed(&manifest.binding, 0o400, wire::MAX_BINDING as u64)?;
    sealed(&b.runtime, 0o400, 64 * 1024 * 1024)?;
    for row in &b.artifacts {
        sealed(
            &Content {
                fd: row.fd,
                sha256: row.sha256.clone(),
                size: row.size,
            },
            0o400,
            32 * 1024 * 1024,
        )?;
    }
    for row in [&b.user_config, &b.global_config] {
        sealed(
            &Content {
                fd: row.fd,
                sha256: wire::digest(b""),
                size: 0,
            },
            0o400,
            0,
        )?;
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Pin {
        path: PathBuf,
        canonical: PathBuf,
        sha256: String,
        size: u64,
    }
    let pins: Vec<Pin> = serde_json::from_str(include_str!(
        "../../../../tirith-core/tests/fixtures/npm/install/node-26.7.0-arm64-libraries.json"
    ))
    .map_err(|e| e.to_string())?;
    let mut paths = BTreeSet::new();
    for row in &manifest.runtime_files {
        let pin = pins
            .iter()
            .find(|p| p.canonical == row.path)
            .ok_or("unexpected npm runtime path")?;
        if !paths.insert(&row.path)
            || pin.sha256 != row.content.sha256
            || pin.size != row.content.size
            || pin.path.canonicalize().map_err(|e| e.to_string())? != pin.canonical
        {
            return Err("npm runtime closure differs from compiled inventory".into());
        }
        let held = stat(row.content.fd)?;
        let visible = std::fs::symlink_metadata(&row.path).map_err(|e| e.to_string())?;
        if held.st_mode & libc::S_IFMT != libc::S_IFREG
            || held.st_uid != 0
            || held.st_mode & 0o022 != 0
            || held.st_size as u64 != row.content.size
            || held.st_dev != row.device
            || held.st_ino != row.inode
            || !visible.is_file()
            || visible.dev() != row.device
            || visible.ino() != row.inode
            || hash(row.content.fd, row.content.size)? != row.content.sha256
        {
            return Err("npm retained runtime file changed".into());
        }
        // The rule consumes each file's identity before exec. The guest needs
        // path-open access to exactly that inode, not these authority handles.
        cloexec(row.content.fd)?;
    }
    cloexec(manifest.node.fd)?;
    // Node's numeric readFileSync consumes the bootstrap's shared file offset.
    // All hashing above used pread; explicitly reset immediately before launch.
    if unsafe { libc::lseek(manifest.bootstrap.fd, 0, libc::SEEK_SET) } != 0 {
        return Err("cannot rewind npm bootstrap descriptor".into());
    }
    if unsafe { libc::fchdir(b.cache.fd) } != 0 {
        return Err("cannot enter held npm cache directory".into());
    }
    Ok(Some(Prepared { manifest }))
}

impl Prepared {
    pub(super) fn apply(
        &self,
        spec: &CapsuleSpec,
    ) -> Result<tirith_core::capsule::CapsuleCoverage, tirith_core::capsule::linux::ContainError>
    {
        let runtime: Vec<_> = self
            .manifest
            .runtime_files
            .iter()
            .map(|row| {
                (
                    row.content.fd,
                    row.path == Path::new("/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"),
                )
            })
            .collect();
        let runtime_home =
            PathBuf::from(format!("/proc/self/fd/{}", self.manifest.inputs.cache.fd));
        tirith_core::capsule::linux::apply_npm_descriptor_containment(
            spec,
            &runtime_home,
            self.manifest.node.fd,
            &runtime,
            &[
                self.manifest.inputs.target.fd,
                self.manifest.inputs.cache.fd,
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    #[test]
    fn final_executor_requires_exec_seal_and_rejects_query_errors() {
        assert!(final_executor_seals(wire::SEALED | libc::F_SEAL_EXEC));
        assert!(!final_executor_seals(wire::SEALED));
        assert!(!final_executor_seals(-1));
        assert!(!final_executor_seals(libc::F_SEAL_EXEC));
    }

    #[test]
    fn regular_unsealed_files_never_satisfy_the_content_contract() {
        let file = tempfile::tempfile().unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o400))
            .unwrap();
        let content = Content {
            fd: file.as_raw_fd(),
            sha256: wire::digest(b""),
            size: 0,
        };
        assert!(
            sealed(&content, 0o400, 0).is_err(),
            "F_GET_SEALS=-1 is refusal, never all seals"
        );
    }
}
