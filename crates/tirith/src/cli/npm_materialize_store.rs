//! Bounded per-state-root immutable intent records. Records are comparison and
//! history only: no method returns an execution, write, or deletion capability.

#[cfg(target_os = "linux")]
mod linux {
    use super::super::{create_file_at, file_identity, open_directory_nofollow};
    use fs2::FileExt as _;
    use std::collections::BTreeMap;
    use std::io::Write as _;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::fs::MetadataExt;
    use std::{
        ffi::{CString, OsStr, OsString},
        fs::File,
        path::PathBuf,
    };

    pub(crate) const RECORD_CAP: usize = 64 * 1024;
    const RECORD_COUNT_CAP: usize = 1024;

    #[derive(Clone, Copy)]
    pub(crate) enum RecordKind {
        Intent,
        Started,
        Finished,
        Withdrawn,
        Recovered,
        Undone,
        ConfirmStarted,
        UndoStarted,
        ContinueUndoStarted,
        ContinuedUndo,
        PrivateMilestone,
        CommittedMilestone,
    }
    impl RecordKind {
        fn suffix(self) -> &'static str {
            match self {
                Self::Intent => "intent",
                Self::Started => "started",
                Self::Finished => "finished",
                Self::Withdrawn => "withdrawn",
                Self::Recovered => "recovered",
                Self::Undone => "undone",
                Self::ConfirmStarted => "confirm-started",
                Self::UndoStarted => "undo-started",
                Self::ContinueUndoStarted => "continue-undo-started",
                Self::ContinuedUndo => "continued-undo",
                Self::PrivateMilestone => "private",
                Self::CommittedMilestone => "committed",
            }
        }
    }
    struct RetainedRecord {
        file: File,
        bytes: Vec<u8>,
    }
    /// Owns a lock from acquisition through validation and the final store or
    /// checkpoint lifetime. No lock descriptor is transferred to a writer.
    pub(crate) struct MaterializationLock(File);

    impl MaterializationLock {
        pub(crate) fn try_acquire(file: File) -> std::io::Result<Self> {
            file.try_lock_exclusive()?;
            Ok(Self(file))
        }
    }

    impl std::ops::Deref for MaterializationLock {
        type Target = File;
        fn deref(&self) -> &File {
            &self.0
        }
    }

    impl Drop for MaterializationLock {
        fn drop(&mut self) {
            // Closing only this descriptor can leave flock held by a duplicate
            // or fork-inherited copy. Only this guard owns the lock lifetime.
            let _ = fs2::FileExt::unlock(&self.0);
        }
    }

    pub(crate) struct OperationStore {
        directory: MaterializationLock,
        path: PathBuf,
        identity: (u64, u64),
        operation: String,
        retained: BTreeMap<String, RetainedRecord>,
        namespace: IntentNamespace,
    }
    #[derive(Clone, Copy)]
    enum IntentNamespace {
        Materialization,
        NpmInstall,
        NpmRecovery,
    }
    impl IntentNamespace {
        fn directory(&self) -> &'static str {
            match self {
                Self::Materialization => "materialization-intents",
                Self::NpmInstall => "npm-install-intents",
                Self::NpmRecovery => "npm-install-recovery",
            }
        }
    }
    impl OperationStore {
        pub(crate) fn open(operation: &str, create: bool) -> std::io::Result<Self> {
            Self::open_namespace(operation, create, IntentNamespace::Materialization)
        }
        /// Fixed, separate closed-install namespace. Callers cannot select a path.
        pub(crate) fn open_npm_install(operation: &str, create: bool) -> std::io::Result<Self> {
            Self::open_namespace(operation, create, IntentNamespace::NpmInstall)
        }
        pub(crate) fn open_npm_recovery(operation: &str, create: bool) -> std::io::Result<Self> {
            Self::open_namespace(operation, create, IntentNamespace::NpmRecovery)
        }
        fn open_namespace(
            operation: &str,
            create: bool,
            namespace: IntentNamespace,
        ) -> std::io::Result<Self> {
            canonical_operation(operation)?;
            let state = tirith_core::policy::state_dir()
                .ok_or_else(|| refusal("state directory unavailable"))?;
            if !state.is_absolute()
                || state
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(refusal(
                    "materialization state root must be absolute without parent components",
                ));
            }
            let path = state.join(namespace.directory());
            if create {
                crate::cli::setup::fs_helpers::ensure_private_directory(&path, &state).map_err(
                    |_| refusal("cannot create private materialization state directory"),
                )?;
            }
            let directory = open_directory_nofollow(&path)?;
            check_directory(&directory)?;
            let directory = MaterializationLock::try_acquire(directory)?;
            let identity = file_identity(&directory)?;
            let result = Self {
                directory,
                path,
                identity,
                operation: operation.into(),
                retained: BTreeMap::new(),
                namespace,
            };
            result.revalidate()?;
            Ok(result)
        }
        pub(crate) fn read(&mut self, kind: RecordKind) -> std::io::Result<Option<Vec<u8>>> {
            self.revalidate()?;
            let name = self.name(kind);
            if let Some(record) = self.retained.get(&name) {
                return Ok(Some(record.bytes.clone()));
            }
            let file = match open_record(&self.directory, &name) {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(e),
            };
            let bytes = read_record(&file)?;
            verify_record(&self.directory, &name, &file, &bytes)?;
            self.retained.insert(
                name,
                RetainedRecord {
                    file,
                    bytes: bytes.clone(),
                },
            );
            self.revalidate()?;
            Ok(Some(bytes))
        }
        pub(crate) fn append(&mut self, kind: RecordKind, bytes: Vec<u8>) -> std::io::Result<()> {
            if bytes.is_empty() || bytes.len() > RECORD_CAP {
                return Err(refusal("materialization record exceeds bound"));
            }
            self.revalidate()?;
            if directory_names(&self.directory)?.len() >= RECORD_COUNT_CAP {
                return Err(refusal("materialization history capacity reached"));
            }
            let name = self.name(kind);
            let allowed = match self.namespace {
                IntentNamespace::NpmRecovery => matches!(
                    kind,
                    RecordKind::PrivateMilestone | RecordKind::CommittedMilestone
                ),
                IntentNamespace::NpmInstall => matches!(
                    kind,
                    RecordKind::Intent
                        | RecordKind::Started
                        | RecordKind::Finished
                        | RecordKind::Withdrawn
                        | RecordKind::Recovered
                ),
                IntentNamespace::Materialization => !matches!(
                    kind,
                    RecordKind::PrivateMilestone | RecordKind::CommittedMilestone
                ),
            };
            if !allowed {
                return Err(refusal("record kind does not belong to fixed namespace"));
            }
            // Exclusive creation is the durable compare-and-set. An interrupted
            // partial record is preserved and never interpreted as permission.
            let mut file = create_file_at(self.directory.as_raw_fd(), OsStr::new(&name), 0o600)?;
            check_record(&file)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            self.directory.sync_all()?;
            verify_record(&self.directory, &name, &file, &bytes)?;
            self.retained.insert(name, RetainedRecord { file, bytes });
            self.revalidate()
        }
        pub(crate) fn revalidate(&self) -> std::io::Result<()> {
            check_directory(&self.directory)?;
            let visible = open_directory_nofollow(&self.path)?;
            check_directory(&visible)?;
            if file_identity(&visible)? != self.identity
                || file_identity(&self.directory)? != self.identity
            {
                return Err(refusal("materialization intent directory changed"));
            }
            for name in directory_names(&self.directory)? {
                let s = name
                    .to_str()
                    .ok_or_else(|| refusal("unexpected materialization record name"))?;
                let Some((id, suffix)) = s.split_once('.') else {
                    return Err(refusal("unexpected materialization record name"));
                };
                canonical_operation(id)?;
                let supported = match self.namespace {
                    IntentNamespace::NpmRecovery => {
                        matches!(suffix, "private.json" | "committed.json")
                    }
                    IntentNamespace::NpmInstall => matches!(
                        suffix,
                        "intent.json"
                            | "started.json"
                            | "finished.json"
                            | "withdrawn.json"
                            | "recovered.json"
                    ),
                    IntentNamespace::Materialization => matches!(
                        suffix,
                        "intent.json"
                            | "started.json"
                            | "finished.json"
                            | "withdrawn.json"
                            | "recovered.json"
                            | "undone.json"
                            | "confirm-started.json"
                            | "undo-started.json"
                            | "continue-undo-started.json"
                            | "continued-undo.json"
                    ),
                };
                if !supported {
                    return Err(refusal("unexpected record in fixed namespace"));
                }
            }
            for (name, record) in &self.retained {
                verify_record(&self.directory, name, &record.file, &record.bytes)?;
            }
            Ok(())
        }
        fn name(&self, kind: RecordKind) -> String {
            format!("{}.{}.json", self.operation, kind.suffix())
        }
    }
    pub(crate) fn canonical_operation(id: &str) -> std::io::Result<()> {
        let parsed = uuid::Uuid::parse_str(id)
            .map_err(|_| refusal("operation must be a canonical non-nil UUID"))?;
        if parsed.is_nil() || parsed.to_string() != id {
            return Err(refusal("operation must be a canonical non-nil UUID"));
        }
        Ok(())
    }
    fn refusal(message: &str) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, message)
    }
    fn check_directory(file: &File) -> std::io::Result<()> {
        let m = file.metadata()?;
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7777 != 0o700 {
            return Err(refusal(
                "materialization record directory is not private and operator-owned",
            ));
        }
        Ok(())
    }
    fn check_record(file: &File) -> std::io::Result<()> {
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
            || m.len() > RECORD_CAP as u64
        {
            return Err(refusal(
                "materialization record is not a bounded private single-link regular file",
            ));
        }
        Ok(())
    }
    fn open_record(parent: &File, name: &str) -> std::io::Result<File> {
        let c = CString::new(name).map_err(|_| refusal("invalid record component"))?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        check_record(&file)?;
        Ok(file)
    }
    fn read_record(file: &File) -> std::io::Result<Vec<u8>> {
        check_record(file)?;
        let mut reader = file.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        reader
            .take((RECORD_CAP + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > RECORD_CAP {
            return Err(refusal("materialization record truncated or oversized"));
        }
        check_record(file)?;
        Ok(bytes)
    }
    fn verify_record(
        parent: &File,
        name: &str,
        file: &File,
        expected: &[u8],
    ) -> std::io::Result<()> {
        let visible = open_record(parent, name)?;
        if file_identity(&visible)? != file_identity(file)?
            || read_record(file)? != expected
            || read_record(&visible)? != expected
        {
            return Err(refusal("materialization record generation changed"));
        }
        check_record(file)?;
        Ok(())
    }

    fn directory_names(parent: &File) -> std::io::Result<Vec<OsString>> {
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        let result = (|| {
            let mut names = Vec::new();
            loop {
                unsafe { *libc::__errno_location() = 0 };
                let entry = unsafe { libc::readdir(stream) };
                if entry.is_null() {
                    let n = unsafe { *libc::__errno_location() };
                    if n != 0 {
                        return Err(std::io::Error::from_raw_os_error(n));
                    }
                    return Ok(names);
                }
                let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                if name != b"." && name != b".." {
                    if names.len() >= RECORD_COUNT_CAP {
                        return Err(refusal("materialization history capacity exceeded"));
                    }
                    use std::os::unix::ffi::OsStringExt;
                    names.push(OsString::from_vec(name.to_vec()));
                }
            }
        })();
        let close = unsafe { libc::closedir(stream) };
        if close < 0 {
            return Err(std::io::Error::last_os_error());
        }
        result
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::{symlink, PermissionsExt};
        use tirith_test_support::GlobalStateGuard;

        #[test]
        fn immutable_record_refuses_replacement_content_and_preserves_it() {
            let _scope = GlobalStateGuard::new().unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            let mut store = OperationStore::open(&id, true).unwrap();
            store
                .append(RecordKind::Intent, b"{\"intent\":1}".to_vec())
                .unwrap();
            assert!(store
                .append(RecordKind::Intent, b"different".to_vec())
                .is_err());
            let path = store.path.join(store.name(RecordKind::Intent));
            std::fs::write(&path, b"changed").unwrap();
            assert!(store.revalidate().is_err());
            drop(store);
            assert_eq!(std::fs::read(path).unwrap(), b"changed");
        }
        #[test]
        fn nofollow_special_and_oversized_records_refuse_without_deletion() {
            let _scope = GlobalStateGuard::new().unwrap();
            for kind in 0..3 {
                let id = uuid::Uuid::new_v4().to_string();
                let mut store = OperationStore::open(&id, true).unwrap();
                let path = store.path.join(store.name(RecordKind::Intent));
                if kind == 0 {
                    symlink("absent-target", &path).unwrap();
                } else if kind == 1 {
                    let name = CString::new(path.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                } else {
                    std::fs::write(&path, vec![b'x'; RECORD_CAP + 1]).unwrap();
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                assert!(store.read(RecordKind::Intent).is_err());
                assert!(std::fs::symlink_metadata(&path).is_ok());
            }
        }
        #[test]
        fn npm_install_namespace_has_separate_records_and_lock_authority() {
            let scope = GlobalStateGuard::new().unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            let mut materialize = OperationStore::open(&id, true).unwrap();
            let mut install = OperationStore::open_npm_install(&id, true).unwrap();
            assert_ne!(materialize.path, install.path);
            materialize
                .append(RecordKind::Intent, b"materialize".to_vec())
                .unwrap();
            assert!(install.read(RecordKind::Intent).unwrap().is_none());
            install
                .append(RecordKind::Intent, b"npm-install".to_vec())
                .unwrap();
            assert_eq!(
                materialize.read(RecordKind::Intent).unwrap(),
                Some(b"materialize".to_vec())
            );
            assert_eq!(
                install.read(RecordKind::Intent).unwrap(),
                Some(b"npm-install".to_vec())
            );
            assert!(OperationStore::open_npm_install(&id, false).is_err());
            assert!(OperationStore::open(&id, false).is_err());
            drop(install);
            assert!(OperationStore::open_npm_install(&id, false).is_ok());
            assert!(OperationStore::open(&id, false).is_err());
            assert!(scope.roots().cwd.exists());
        }
        #[test]
        fn npm_install_store_refuses_replaced_namespace_and_preserves_original_record() {
            let _scope = GlobalStateGuard::new().unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            let mut install = OperationStore::open_npm_install(&id, true).unwrap();
            install
                .append(RecordKind::Intent, b"retained".to_vec())
                .unwrap();
            let displaced = install.path.with_file_name("retained-npm-install-intents");
            std::fs::rename(&install.path, &displaced).unwrap();
            std::fs::create_dir(&install.path).unwrap();
            std::fs::set_permissions(&install.path, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            assert!(install.revalidate().is_err());
            assert!(install
                .append(RecordKind::Started, b"forged".to_vec())
                .is_err());
            assert_eq!(
                std::fs::read(displaced.join(install.name(RecordKind::Intent))).unwrap(),
                b"retained"
            );
            assert!(!install
                .path
                .join(install.name(RecordKind::Started))
                .exists());
        }
        #[test]
        fn store_lock_release_is_not_extended_by_a_retained_descriptor() {
            let _scope = GlobalStateGuard::new().unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            let first = OperationStore::open(&id, true).unwrap();
            let retained = first.directory.try_clone().unwrap();
            assert!(OperationStore::open(&id, false).is_err());
            drop(first);
            let next = OperationStore::open(&id, false)
                .expect("the store owner releases before duplicate descriptors close");
            assert!(OperationStore::open(&id, false).is_err());
            drop(retained);
            assert!(OperationStore::open(&id, false).is_err());
            drop(next);
            assert!(OperationStore::open(&id, false).is_ok());
        }

        #[test]
        fn checkpoint_lock_release_covers_failure_before_owner_construction() {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("lock");
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            let competitor = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let mut retained = None;
            let refused: std::io::Result<()> = (|| {
                let lock = MaterializationLock::try_acquire(file)?;
                retained = Some(lock.try_clone()?);
                assert_eq!(
                    competitor.try_lock_exclusive().unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                // Both checkpoint constructors perform fallible work here,
                // after acquisition but before their final owner exists.
                Err(std::io::Error::other("refused checkpoint validation"))
            })();
            assert!(refused.is_err());
            let next = MaterializationLock::try_acquire(competitor)
                .expect("failed construction releases the held file lock");
            let third = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            drop(retained);
            assert_eq!(
                third.try_lock_exclusive().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            drop(next);
            let final_owner = MaterializationLock::try_acquire(third).unwrap();
            drop(final_owner);
            assert!(
                path.exists(),
                "releasing a lock never deletes its checkpoint"
            );
        }

        #[test]
        fn global_store_lock_rejects_competing_operation_without_start() {
            let _scope = GlobalStateGuard::new().unwrap();
            let first = OperationStore::open(&uuid::Uuid::new_v4().to_string(), true).unwrap();
            assert!(OperationStore::open(&uuid::Uuid::new_v4().to_string(), false).is_err());
            drop(first);
            assert!(OperationStore::open(&uuid::Uuid::new_v4().to_string(), false).is_ok());
        }
        #[test]
        fn canonical_ids_and_unknown_entries_never_select_paths() {
            for id in [
                "../target",
                "00000000-0000-0000-0000-000000000000",
                "A1111111-1111-4111-8111-111111111111",
            ] {
                assert!(canonical_operation(id).is_err());
            }
            let _scope = GlobalStateGuard::new().unwrap();
            let store = OperationStore::open(&uuid::Uuid::new_v4().to_string(), true).unwrap();
            let unknown = store.path.join("unknown");
            std::fs::write(&unknown, b"preserve").unwrap();
            assert!(store.revalidate().is_err());
            drop(store);
            assert_eq!(std::fs::read(unknown).unwrap(), b"preserve");
        }
    }
}
#[cfg(target_os = "linux")]
pub(crate) use linux::{
    canonical_operation, MaterializationLock, OperationStore, RecordKind, RECORD_CAP,
};
