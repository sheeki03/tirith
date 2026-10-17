//! Protected namespace admission for descriptor-relative publication/removal.
//! Every ancestor is retained and checked. Another ordinary UID must not be
//! able to replace the destination/journal basename between revalidation and
//! rename. The current UID and privileged root are explicitly not excluded.
use super::*;
#[cfg(unix)]
const MAX_ANCESTORS: usize = 64;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

pub(super) struct ProtectedNamespace {
    #[cfg(unix)]
    chain: Vec<Anchor>,
}
#[cfg(unix)]
struct Anchor {
    file: File,
    path: PathBuf,
    name: Option<String>,
    identity: (u64, u64),
    uid: u32,
    gid: u32,
    mode: u32,
    acl_digest: String,
}
impl ProtectedNamespace {
    pub(super) fn capture(parent: &Path, expected: (u64, u64)) -> MaterializationResult<Self> {
        #[cfg(not(unix))]
        {
            let _ = (parent, expected);
            Ok(Self {})
        }
        #[cfg(unix)]
        {
            if !parent.is_absolute() || parent.as_os_str().as_encoded_bytes().len() > 4096 {
                return Err(Refusal::DestinationChanged);
            }
            let parts = parent.components().collect::<Vec<_>>();
            if parts.len() > MAX_ANCESTORS
                || parts
                    .iter()
                    .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
            {
                return Err(Refusal::ResourceLimit);
            }
            let mut chain = Vec::new();
            let mut path = PathBuf::from("/");
            let root = unsafe {
                libc::open(
                    c"/".as_ptr(),
                    libc::O_RDONLY
                        | libc::O_DIRECTORY
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK,
                )
            };
            if root < 0 {
                return Err(Refusal::DestinationChanged);
            }
            let mut next = Some(unsafe { File::from_raw_fd(root) });
            for (index, part) in parts.iter().enumerate() {
                let name = match part {
                    Component::RootDir => None,
                    Component::Normal(name) => {
                        Some(name.to_str().ok_or(Refusal::DestinationChanged)?.to_owned())
                    }
                    _ => return Err(Refusal::DestinationChanged),
                };
                let file = if let Some(file) = next.take() {
                    file
                } else {
                    let name = name.as_deref().ok_or(Refusal::DestinationChanged)?;
                    path.push(name);
                    let c =
                        std::ffi::CString::new(name).map_err(|_| Refusal::DestinationChanged)?;
                    let parent: &Anchor = chain.last().ok_or(Refusal::DestinationChanged)?;
                    let raw = unsafe {
                        libc::openat(
                            parent.file.as_raw_fd(),
                            c.as_ptr(),
                            libc::O_RDONLY
                                | libc::O_DIRECTORY
                                | libc::O_CLOEXEC
                                | libc::O_NOFOLLOW
                                | libc::O_NONBLOCK,
                        )
                    };
                    if raw < 0 {
                        return Err(Refusal::DestinationChanged);
                    }
                    unsafe { File::from_raw_fd(raw) }
                };
                let metadata = file.metadata().map_err(|_| Refusal::DestinationChanged)?;
                admit_directory(&metadata, index + 1 == parts.len())?;
                let acl_digest = acl_digest(&file, &path, true)?;
                chain.push(Anchor {
                    identity: file_identity(&file).map_err(|_| Refusal::DestinationChanged)?,
                    file,
                    path: path.clone(),
                    name,
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                    mode: metadata.mode(),
                    acl_digest,
                });
            }
            if chain.last().map(|a| a.identity) != Some(expected) {
                return Err(Refusal::DestinationChanged);
            }
            let value = Self { chain };
            value.revalidate()?;
            Ok(value)
        }
    }
    pub(super) fn revalidate(&self) -> MaterializationResult<()> {
        #[cfg(not(unix))]
        {
            Err(Refusal::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            if self.chain.is_empty() || self.chain.len() > MAX_ANCESTORS {
                return Err(Refusal::DestinationChanged);
            }
            for (index, anchor) in self.chain.iter().enumerate() {
                let before = anchor
                    .file
                    .metadata()
                    .map_err(|_| Refusal::DestinationChanged)?;
                admit_directory(&before, index + 1 == self.chain.len())?;
                if (before.dev(), before.ino()) != anchor.identity
                    || before.uid() != anchor.uid
                    || before.gid() != anchor.gid
                    || before.mode() != anchor.mode
                {
                    return Err(Refusal::DestinationChanged);
                }
                let mut stat: libc::stat = unsafe { std::mem::zeroed() };
                let rc = if let Some(parent) = index.checked_sub(1).map(|n| &self.chain[n]) {
                    let name = std::ffi::CString::new(
                        anchor.name.as_deref().ok_or(Refusal::DestinationChanged)?,
                    )
                    .map_err(|_| Refusal::DestinationChanged)?;
                    unsafe {
                        libc::fstatat(
                            parent.file.as_raw_fd(),
                            name.as_ptr(),
                            &mut stat,
                            libc::AT_SYMLINK_NOFOLLOW,
                        )
                    }
                } else {
                    unsafe { libc::lstat(c"/".as_ptr(), &mut stat) }
                };
                if rc != 0
                    || stat.st_dev as u64 != anchor.identity.0
                    || stat.st_ino as u64 != anchor.identity.1
                    || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
                {
                    return Err(Refusal::DestinationChanged);
                }
                if acl_digest(&anchor.file, &anchor.path, true)? != anchor.acl_digest {
                    return Err(Refusal::DestinationChanged);
                }
                let after = anchor
                    .file
                    .metadata()
                    .map_err(|_| Refusal::DestinationChanged)?;
                if after.uid() != anchor.uid
                    || after.gid() != anchor.gid
                    || after.mode() != anchor.mode
                {
                    return Err(Refusal::DestinationChanged);
                }
            }
            Ok(())
        }
    }
}
#[cfg(unix)]
fn admit_directory(m: &std::fs::Metadata, destination_parent: bool) -> MaterializationResult<()> {
    let uid = unsafe { libc::geteuid() };
    if !m.is_dir() || (m.uid() != uid && m.uid() != 0) || m.mode() & 0o6000 != 0 {
        return Err(Refusal::DestinationChanged);
    }
    // The basename we publish/remove is immediately below an ordinary-owned
    // non-shared parent. Sticky ancestors may protect that parent's name, but
    // are not themselves acceptable destination parents.
    if destination_parent && (m.uid() != uid || m.mode() & 0o022 != 0) {
        return Err(Refusal::DestinationChanged);
    }
    if m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0 && !destination_parent) {
        return Err(Refusal::DestinationChanged);
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn acl_digest(file: &File, _path: &Path, directory: bool) -> MaterializationResult<String> {
    let uid = file
        .metadata()
        .map_err(|_| Refusal::DestinationChanged)?
        .uid();
    let mut hash = Sha256::new();
    for (name, default) in [
        (c"system.posix_acl_access", false),
        (c"system.posix_acl_default", true),
    ] {
        if default && !directory {
            continue;
        }
        let mut bytes = vec![0u8; 64 * 1024];
        let size = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if size < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA) {
                hash.update([0]);
                continue;
            }
            return Err(Refusal::DestinationChanged);
        }
        bytes.truncate(size as usize);
        validate_acl(&bytes, uid, unsafe { libc::geteuid() }, default)?;
        hash.update([1]);
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    Ok(hex::encode(hash.finalize()))
}
#[cfg(all(unix, not(target_os = "linux")))]
fn acl_digest(_file: &File, path: &Path, directory: bool) -> MaterializationResult<String> {
    // This admission supports read-only plans on other qualified Unix readers;
    // the actual writer/recovery remains Linux-only. Revalidation repeats the
    // native ACL check inside the retained protected ancestry, not an untrusted
    // path supplied by an operation record.
    crate::trusted_child::validate_unix_trusted_path_acl(path, directory)
        .map_err(|_| Refusal::DestinationChanged)?;
    Ok("native-unix-acl-admission-v1".into())
}
#[cfg(target_os = "linux")]
pub(super) fn check_object_acl(file: &File, directory: bool) -> MaterializationResult<()> {
    acl_digest(file, Path::new("/"), directory).map(|_| ())
}
#[cfg(target_os = "linux")]
fn validate_acl(bytes: &[u8], owner: u32, euid: u32, default: bool) -> MaterializationResult<()> {
    if bytes.len() < 4
        || (bytes.len() - 4) % 8 != 0
        || u32::from_le_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| Refusal::DestinationChanged)?,
        ) != 2
    {
        return Err(Refusal::DestinationChanged);
    }
    let mut keys = BTreeSet::new();
    let mut base = BTreeSet::new();
    let mut named = false;
    let mut mask = false;
    for entry in bytes[4..].chunks_exact(8) {
        let tag = u16::from_le_bytes(
            entry[..2]
                .try_into()
                .map_err(|_| Refusal::DestinationChanged)?,
        );
        let perm = u16::from_le_bytes(
            entry[2..4]
                .try_into()
                .map_err(|_| Refusal::DestinationChanged)?,
        );
        let id = u32::from_le_bytes(
            entry[4..]
                .try_into()
                .map_err(|_| Refusal::DestinationChanged)?,
        );
        if perm > 7 || !keys.insert((tag, id)) {
            return Err(Refusal::DestinationChanged);
        }
        let valid = match tag {
            1 | 4 | 32 => {
                base.insert(tag);
                id == u32::MAX && (!default || tag == 1 || perm & 2 == 0)
            }
            16 => {
                mask = true;
                id == u32::MAX
            }
            2 => {
                named = true;
                id != u32::MAX && (perm & 2 == 0 || id == 0 || id == owner || id == euid)
            }
            8 => {
                named = true;
                id != u32::MAX && perm & 2 == 0
            }
            _ => false,
        };
        if !valid {
            return Err(Refusal::DestinationChanged);
        }
    }
    if base != BTreeSet::from([1, 4, 32]) || (named && !mask) {
        return Err(Refusal::DestinationChanged);
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn mode(path: &Path, bits: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
    }
    fn capture(path: &Path) -> MaterializationResult<ProtectedNamespace> {
        let canonical = path.canonicalize().unwrap();
        let metadata = std::fs::metadata(&canonical).unwrap();
        ProtectedNamespace::capture(&canonical, (metadata.dev(), metadata.ino()))
    }
    #[test]
    fn shared_destination_parent_and_nonsticky_shared_ancestor_are_refused_before_writes() {
        let temp = tempfile::tempdir().unwrap();
        for bits in [0o777, 0o770, 0o1777] {
            mode(temp.path(), bits);
            assert!(capture(temp.path()).is_err());
        }
        mode(temp.path(), 0o700);
        capture(temp.path()).unwrap().revalidate().unwrap();
        let shared = temp.path().join("shared");
        let private = shared.join("private");
        std::fs::create_dir(&shared).unwrap();
        std::fs::create_dir(&private).unwrap();
        mode(&private, 0o700);
        mode(&shared, 0o777);
        assert!(capture(&private).is_err());
    }
    #[test]
    fn retained_namespace_detects_permission_and_same_name_replacement_drift() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("parent");
        std::fs::create_dir(&path).unwrap();
        mode(&path, 0o700);
        let lease = capture(&path).unwrap();
        mode(&path, 0o777);
        assert!(lease.revalidate().is_err());
        mode(&path, 0o700);
        std::fs::rename(&path, temp.path().join("old")).unwrap();
        std::fs::create_dir(&path).unwrap();
        mode(&path, 0o700);
        assert!(lease.revalidate().is_err());
    }
    #[cfg(target_os = "linux")]
    fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut out = 2u32.to_le_bytes().to_vec();
        for (t, p, id) in entries {
            out.extend(t.to_le_bytes());
            out.extend(p.to_le_bytes());
            out.extend(id.to_le_bytes());
        }
        out
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn access_and_default_acl_classifier_refuses_foreign_write_even_if_masked() {
        let none = u32::MAX;
        let base = [(1, 7, none), (4, 5, none), (32, 5, none)];
        validate_acl(&acl(&base), 1000, 1000, false).unwrap();
        validate_acl(&acl(&base), 1000, 1000, true).unwrap();
        for default in [false, true] {
            let foreign = [
                (1, 7, none),
                (2, 7, 2000),
                (4, 5, none),
                (16, 0, none),
                (32, 0, none),
            ];
            assert!(validate_acl(&acl(&foreign), 1000, 1000, default).is_err());
            let group = [
                (1, 7, none),
                (4, 5, none),
                (8, 7, 1000),
                (16, 0, none),
                (32, 0, none),
            ];
            assert!(validate_acl(&acl(&group), 1000, 1000, default).is_err());
            let self_grant = [
                (1, 7, none),
                (2, 7, 1000),
                (4, 5, none),
                (16, 7, none),
                (32, 5, none),
            ];
            validate_acl(&acl(&self_grant), 1000, 1000, default).unwrap();
        }
        assert!(validate_acl(
            &acl(&[(1, 7, none), (4, 7, none), (32, 5, none)]),
            1000,
            1000,
            true
        )
        .is_err());
        assert!(validate_acl(
            &acl(&[(1, 7, none), (1, 7, none), (4, 5, none), (32, 5, none)]),
            1000,
            1000,
            false
        )
        .is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn actual_default_acl_foreign_grant_and_later_acl_drift_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let current = unsafe { libc::geteuid() };
        let foreign = if current == 2000 { 2001 } else { 2000 };
        let none = u32::MAX;
        let lease = capture(temp.path()).unwrap();
        let bytes = acl(&[
            (1, 7, none),
            (2, 7, foreign),
            (4, 5, none),
            (16, 7, none),
            (32, 0, none),
        ]);
        let file = std::fs::File::open(temp.path()).unwrap();
        let rc = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                c"system.posix_acl_default".as_ptr(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
            )
        };
        assert_eq!(
            rc,
            0,
            "owned test filesystem must support POSIX ACL fixture: {}",
            std::io::Error::last_os_error()
        );
        assert!(capture(temp.path()).is_err());
        assert!(lease.revalidate().is_err());
    }
}
