//! Bounded private input filesystems. Captured source descriptors are sealed;
//! copied files become immutable to ordinary writers only after the entire
//! private superblock becomes read-only and a full inventory/hash check passes.
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
const MAX_ENTRIES: usize = 4096;
const MAX_DIRECTORY_ENTRIES: usize = 16_384;
/// Shared wheel/npm input mechanism. The source descriptors already carry all
/// four memfd seals; the private filesystem copy is frozen and compared in full.
pub(super) fn materialize_inputs(
    root: &File,
    inputs: &[(i32, std::ffi::OsString)],
    payload_limit: u64,
) -> Result<(), String> {
    if payload_limit == 0 || payload_limit > 128 * 1024 * 1024 || inputs.len() > MAX_ENTRIES {
        return Err("private input collection exceeds its fixed bounds".into());
    }
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    let mut proofs = Vec::with_capacity(inputs.len());
    // Validate the entire set before the first private copy. Mode-specific
    // wheel/npm names and limits have already been checked by the caller.
    for (fd, name) in inputs {
        let name = name.to_str().ok_or("non-UTF-8 sealed input name")?;
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains(['/', '\\', '\0'])
            || !names.insert(name)
        {
            return Err("private inputs require distinct simple filenames".into());
        }
        let source = clone_fd(*fd)?;
        let metadata = source.metadata().map_err(|_| "inspect sealed input size")?;
        let seals = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GET_SEALS) };
        if !metadata.is_file() || seals < 0 || seals & SEALS != SEALS {
            return Err("input source is not a regular fully sealed file".into());
        }
        total = total
            .checked_add(metadata.len())
            .ok_or("private input size overflow")?;
        if total > payload_limit {
            return Err("private inputs exceed their aggregate byte bound".into());
        }
    }
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    for (fd, name) in inputs {
        let name = name.to_str().expect("validated input name");
        let mut source = clone_fd(*fd)?;
        let size = source
            .metadata()
            .map_err(|_| "inspect sealed input size")?
            .len();
        let seals = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_GET_SEALS) };
        if seals < 0 || seals & SEALS != SEALS {
            return Err("input source is not fully sealed".into());
        }
        source
            .seek(SeekFrom::Start(0))
            .map_err(|_| "rewind sealed input")?;
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let count = source.read(&mut buffer).map_err(|_| "hash sealed input")?;
            if count == 0 {
                break;
            }
            total += count as u64;
            if total > size {
                return Err("sealed input length changed".into());
            }
            hash.update(&buffer[..count]);
        }
        if total != size {
            return Err("sealed input length changed".into());
        }
        let digest = format!("{:x}", hash.finalize());
        source
            .seek(SeekFrom::Start(0))
            .map_err(|_| "rewind captured input copy")?;
        copy_file(
            root,
            name,
            &mut source,
            size,
            0o444,
            &mut files,
            &mut directories,
        )?;
        proofs.push((name.to_owned(), size, digest));
    }
    make_filesystem_read_only(root)?;
    verify_inventory(root, &files, &directories)?;
    for (name, size, digest) in proofs {
        let installed = open_file_beneath(root, &name)?;
        verify_read_only_bytes(&installed, &digest, Some(size), size)?;
        verify_mode(&installed, false)?;
    }
    Ok(())
}

fn os_error(context: &str) -> String {
    format!("{context}: {}", std::io::Error::last_os_error())
}

pub(super) fn clone_fd(fd: i32) -> Result<File, String> {
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(os_error("retain runtime input descriptor"));
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(duplicate) })
}

pub(super) fn open_directory_at(parent: i32, name: &CStr) -> Result<File, String> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(os_error("retain runtime directory without following links"));
    }
    // SAFETY: openat returned one fresh descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn verify_bytes(
    file: &File,
    expected: &str,
    size: Option<u64>,
    cap: u64,
) -> Result<(), String> {
    let metadata = file.metadata().map_err(|_| "inspect runtime file")?;
    if !metadata.is_file()
        || metadata.len() > cap
        || size.is_some_and(|size| size != metadata.len())
    {
        return Err("runtime file lacks its bounded exact identity".into());
    }
    let mut reader = file
        .try_clone()
        .map_err(|_| "retain runtime file for hash")?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| "rewind runtime file")?;
    let mut hash = Sha256::new();
    let mut read = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer).map_err(|_| "hash runtime file")?;
        if count == 0 {
            break;
        }
        read += count as u64;
        if read > cap {
            return Err("runtime file exceeded its byte bound".into());
        }
        hash.update(&buffer[..count]);
    }
    if read != metadata.len() || format!("{:x}", hash.finalize()) != expected {
        return Err("runtime file differs from captured bytes".into());
    }
    Ok(())
}

fn relative_parts(relative: &str) -> Result<Vec<&str>, String> {
    let parts = relative.split('/').collect::<Vec<_>>();
    if relative.len() > 4096
        || parts.len() > 72
        || parts.iter().any(|part| {
            part.is_empty() || *part == "." || *part == ".." || part.as_bytes().contains(&0)
        })
    {
        return Err("invalid closed runtime path".into());
    }
    Ok(parts)
}

fn parent_beneath(
    root: &File,
    relative: &str,
    mut directories: Option<&mut BTreeSet<String>>,
) -> Result<(File, CString), String> {
    let parts = relative_parts(relative)?;
    let mut parent = root.try_clone().map_err(|_| "retain runtime root")?;
    let mut prefix = String::new();
    for part in &parts[..parts.len() - 1] {
        let component = CString::new(*part).map_err(|_| "invalid runtime component")?;
        if let Some(created) = directories.as_deref_mut() {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            if created.insert(prefix.clone()) {
                if created.len() > MAX_DIRECTORY_ENTRIES {
                    return Err("runtime directory count exceeds its bound".into());
                }
                if unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o755) } != 0 {
                    return Err(os_error("create exact private runtime directory"));
                }
            }
        }
        parent = open_directory_at(parent.as_raw_fd(), &component)?;
    }
    Ok((
        parent,
        CString::new(*parts.last().expect("nonempty validated path"))
            .map_err(|_| "invalid runtime name")?,
    ))
}

pub(super) fn copy_file(
    root: &File,
    relative: &str,
    source: &mut impl Read,
    size: u64,
    mode: u32,
    files: &mut BTreeSet<String>,
    directories: &mut BTreeSet<String>,
) -> Result<(), String> {
    if !files.insert(relative.to_owned()) || files.len() > MAX_ENTRIES + 1 {
        return Err("duplicate or excessive runtime files".into());
    }
    let (parent, name) = parent_beneath(root, relative, Some(directories))?;
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if raw < 0 {
        return Err(os_error("create private runtime file"));
    }
    let mut file = unsafe { File::from_raw_fd(raw) };
    let copied = std::io::copy(&mut source.take(size.saturating_add(1)), &mut file)
        .map_err(|_| "copy bounded captured runtime bytes")?;
    if copied != size {
        return Err("runtime source changed its captured length".into());
    }
    if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
        return Err(os_error("set canonical private runtime mode"));
    }
    // Any other retained writer or shared writable mapping must cause the
    // following filesystem-wide readonly transition to refuse.
    drop(file);
    Ok(())
}

fn open_file_at(parent: &File, name: &CStr) -> Result<File, String> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(os_error("open exact runtime file"));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(super) fn open_file_beneath(root: &File, relative: &str) -> Result<File, String> {
    let (parent, name) = parent_beneath(root, relative, None)?;
    open_file_at(&parent, &name)
}

pub(super) fn make_filesystem_read_only(root: &File) -> Result<(), String> {
    // fspick supports a detached mount. Reconfigure the complete private
    // superblock, not merely a read-only bind whose backing inode stays mutable.
    const FSPICK_CLOEXEC_EMPTY: u32 = 1 | 8;
    const FSCONFIG_SET_FLAG: u32 = 0;
    const FSCONFIG_CMD_RECONFIGURE: u32 = 7;
    let context = unsafe {
        libc::syscall(
            libc::SYS_fspick,
            root.as_raw_fd(),
            c"".as_ptr(),
            FSPICK_CLOEXEC_EMPTY,
        )
    };
    if context < 0 {
        return Err(os_error(
            "retain private runtime superblock for readonly transition",
        ));
    }
    let context = unsafe { File::from_raw_fd(context as i32) };
    if unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            context.as_raw_fd(),
            FSCONFIG_SET_FLAG,
            c"ro".as_ptr(),
            std::ptr::null::<libc::c_void>(),
            0,
        )
    } != 0
        || unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                context.as_raw_fd(),
                FSCONFIG_CMD_RECONFIGURE,
                std::ptr::null::<libc::c_char>(),
                std::ptr::null::<libc::c_void>(),
                0,
            )
        } != 0
    {
        return Err(os_error(
            "refuse runtime with an unavailable readonly-superblock transition or retained writer",
        ));
    }
    verify_read_only_filesystem(root)
}

fn verify_read_only_filesystem(file: &File) -> Result<(), String> {
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(os_error("inspect private runtime read-only filesystem"));
    }
    let stat = unsafe { stat.assume_init() };
    if stat.f_flag & libc::ST_RDONLY == 0 {
        return Err("private runtime filesystem is still writable".into());
    }
    Ok(())
}

pub(super) fn verify_read_only_bytes(
    file: &File,
    expected: &str,
    size: Option<u64>,
    cap: u64,
) -> Result<(), String> {
    verify_read_only_filesystem(file)?;
    verify_bytes(file, expected, size, cap)
}

pub(super) fn verify_mode(file: &File, executable: bool) -> Result<(), String> {
    let metadata = file.metadata().map_err(|_| "inspect runtime mode")?;
    if metadata.mode() & 0o7777 != if executable { 0o555 } else { 0o444 } {
        return Err("runtime file mode differs from the canonical sealed mode".into());
    }
    Ok(())
}

pub(super) fn verify_inventory(
    root: &File,
    expected_files: &BTreeSet<String>,
    expected_dirs: &BTreeSet<String>,
) -> Result<(), String> {
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut queue = vec![String::new()];
    while let Some(relative) = queue.pop() {
        let directory = if relative.is_empty() {
            root.try_clone().map_err(|_| "retain inventory root")?
        } else {
            let (parent, name) = parent_beneath(root, &format!("{relative}/.inventory"), None)?;
            let _ = name;
            parent
        };
        for item in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
            .map_err(|_| "enumerate private runtime inventory")?
        {
            let item = item.map_err(|_| "read private runtime inventory")?;
            let name = item
                .file_name()
                .into_string()
                .map_err(|_| "non-UTF-8 private runtime entry")?;
            let path = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            let metadata = std::fs::symlink_metadata(item.path())
                .map_err(|_| "inspect private runtime entry")?;
            if metadata.is_dir() {
                directories.insert(path.clone());
                queue.push(path);
            } else if metadata.is_file() {
                files.insert(path);
            } else {
                return Err("private runtime contains an unapproved entry type".into());
            }
            if files.len() > MAX_ENTRIES + 1 || directories.len() > MAX_DIRECTORY_ENTRIES {
                return Err("private runtime inventory exceeds its bound".into());
            }
        }
    }
    if files != *expected_files || directories != *expected_dirs {
        return Err("private runtime inventory differs from the captured closure".into());
    }
    Ok(())
}

pub(super) fn attach_mount(mounted: &File, target: &File) -> Result<(), String> {
    const EMPTY_SOURCE_AND_TARGET: u32 = 0x4 | 0x40;
    if unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mounted.as_raw_fd(),
            c"".as_ptr(),
            target.as_raw_fd(),
            c"".as_ptr(),
            EMPTY_SOURCE_AND_TARGET,
        )
    } != 0
    {
        return Err(os_error(
            "attach private runtime to retained host directory",
        ));
    }
    Ok(())
}

pub(super) fn verify_visible_mount(path: &str, retained: &File) -> Result<(), String> {
    let name = CString::new(path).expect("fixed runtime path");
    let visible = open_directory_at(libc::AT_FDCWD, &name)?;
    let visible = visible
        .metadata()
        .map_err(|_| "inspect visible runtime identity")?;
    let retained = retained
        .metadata()
        .map_err(|_| "inspect retained runtime identity")?;
    if (visible.dev(), visible.ino()) != (retained.dev(), retained.ino()) {
        return Err("runtime overlay moved before containment".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn sealed(bytes: &[u8]) -> File {
        let raw = unsafe {
            libc::memfd_create(
                c"private-input-regression".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        assert!(raw >= 0);
        let mut file = unsafe { File::from_raw_fd(raw) };
        file.write_all(bytes).unwrap();
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) },
            0
        );
        file
    }

    #[test]
    fn bounds_names_and_seals_are_checked_before_any_copy() {
        let directory = tempfile::tempdir().unwrap();
        let root = File::open(directory.path()).unwrap();
        let input = sealed(b"four");
        let mut cases = vec![
            (vec![(input.as_raw_fd(), "approved.txt".into())], 3),
            (vec![(input.as_raw_fd(), "../outside".into())], 4),
            (
                vec![
                    (input.as_raw_fd(), "approved.txt".into()),
                    (input.as_raw_fd(), "approved.txt".into()),
                ],
                8,
            ),
        ];
        let unsealed = tempfile::tempfile().unwrap();
        cases.push((vec![(unsealed.as_raw_fd(), "approved.txt".into())], 4));
        for (inputs, cap) in cases {
            assert!(materialize_inputs(&root, &inputs, cap).is_err());
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn exact_byte_verifier_rejects_same_size_changes() {
        let source = sealed(b"approved");
        let digest = format!("{:x}", Sha256::digest(b"approved"));
        verify_bytes(&source, &digest, Some(8), 8).unwrap();
        let changed = sealed(b"modified");
        assert!(verify_bytes(&changed, &digest, Some(8), 8).is_err());
        assert!(verify_bytes(&source, &digest, Some(7), 8).is_err());
    }
}
