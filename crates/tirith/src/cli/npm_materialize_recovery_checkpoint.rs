//! Read an exact fixed checkpoint under a retained lock. Deserialized bytes are
//! expected history only; core must independently recapture and authorize every
//! recovery effect against the actual current native objects.

#[cfg(target_os = "linux")]
mod linux {
    use super::super::materialization_store::MaterializationLock;
    use super::super::{
        c_component, entry_identity_at, file_identity, open_directory_nofollow, openat_directory,
    };
    use serde::Deserialize;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::{
        collections::{BTreeMap, BTreeSet},
        io::{Read, Seek, SeekFrom},
        os::unix::fs::MetadataExt,
    };
    use std::{
        ffi::{OsStr, OsString},
        fs::File,
        path::{Path, PathBuf},
    };
    const INVENTORY_CAP: usize = 2 * 1024 * 1024;
    const SMALL_EVENT_CAP: usize = 16 * 1024;
    const EVENTS: &[&str] = &[
        "00-staging.json",
        "01-verified-private.json",
        "02-publishing.json",
        "03-published-verified.json",
        "04-private-empty.json",
    ];

    #[derive(Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct CheckpointEvent {
        schema_version: u32,
        contract: String,
        operation_id: String,
        private_plan_digest: String,
        event: String,
        target_identity: [u64; 2],
        observation: Option<serde_json::Value>,
        recovery_inventory: Option<serde_json::Value>,
        package_code_executed: bool,
        execution_authority: bool,
    }
    struct Record {
        file: File,
        bytes: Vec<u8>,
    }
    pub(crate) struct RecoveryCheckpoint {
        parent: File,
        parent_path: PathBuf,
        parent_identity: (u64, u64),
        target_name: OsString,
        root_identity: (u64, u64),
        journal: File,
        journal_name: OsString,
        lock: MaterializationLock,
        records: BTreeMap<String, Record>,
        pending: bool,
        inventory: Vec<u8>,
    }
    impl RecoveryCheckpoint {
        pub(crate) fn open(
            target: &Path,
            id: &str,
            parent_identity: (u64, u64),
            private_digest: &str,
        ) -> std::io::Result<Self> {
            super::super::materialization_store::canonical_operation(id)?;
            let parent_path = target
                .parent()
                .ok_or_else(|| refusal("recovery target parent unavailable"))?
                .to_path_buf();
            let parent = open_directory_nofollow(&parent_path)?;
            if file_identity(&parent)? != parent_identity {
                return Err(refusal("reviewed recovery parent identity changed"));
            }
            let journal_name = OsString::from(format!(".tirith-materialize-{id}"));
            let journal = openat_directory(parent.as_raw_fd(), &journal_name)?;
            private_directory(&journal)?;
            same_directory(&parent, &journal_name, &journal)?;
            let lock = open_file(&journal, "lock", SMALL_EVENT_CAP)?;
            if lock.metadata()?.len() != 0 {
                return Err(refusal("recovery lock is not empty"));
            }
            let lock = MaterializationLock::try_acquire(lock)?;
            let actual = names(&journal)?;
            let pending = actual.contains("pending-target");
            if !actual.contains("lock")
                || !actual.contains("00-staging.json")
                || actual.iter().any(|name| {
                    name != "lock" && name != "pending-target" && !EVENTS.contains(&name.as_str())
                })
            {
                return Err(refusal(
                    "checkpoint has unexpected or missing entries; objects preserved",
                ));
            }
            let mut records = BTreeMap::new();
            let mut inventories = BTreeMap::new();
            let mut root_identity = None;
            for name in EVENTS {
                if !actual.contains(*name) {
                    continue;
                }
                let cap = if name.contains("verified") {
                    INVENTORY_CAP
                } else {
                    SMALL_EVENT_CAP
                };
                let file = open_file(&journal, name, cap)?;
                let bytes = read_file(&file, cap)?;
                let text =
                    std::str::from_utf8(&bytes).map_err(|_| refusal("checkpoint is not UTF-8"))?;
                let value = tirith_core::mcp_lock::parse_json_no_duplicates(text)
                    .map_err(|_| refusal("checkpoint has ambiguous JSON"))?;
                let event: CheckpointEvent = serde_json::from_value(value)
                    .map_err(|_| refusal("checkpoint schema refused"))?;
                if event.schema_version != crate::cli::npm_materialize::CHECKPOINT_SCHEMA_VERSION
                    || event.contract != "LocalLeafMaterializeV1"
                    || event.operation_id != id
                    || event.private_plan_digest != private_digest
                    || event.event != *name
                    || event.package_code_executed
                    || event.execution_authority
                {
                    return Err(refusal(
                        "checkpoint binding differs from reviewed operation",
                    ));
                }
                if let Some(prior) = root_identity {
                    if prior != event.target_identity {
                        return Err(refusal("checkpoint root identities conflict"));
                    }
                } else {
                    root_identity = Some(event.target_identity);
                }
                if name.contains("verified") {
                    if event.observation.is_none() {
                        return Err(refusal("verified checkpoint lacks its observation"));
                    }
                    let inventory = event.recovery_inventory.ok_or_else(|| {
                        refusal("complete recovery inventory unavailable; objects preserved")
                    })?;
                    if inventory.get("root").and_then(|r| r.get("identity"))
                        != Some(&serde_json::json!(event.target_identity))
                    {
                        return Err(refusal("checkpoint inventory and root identity disagree"));
                    }
                    inventories.insert(
                        (*name).to_string(),
                        serde_json::to_vec(&inventory).map_err(std::io::Error::other)?,
                    );
                } else if event.recovery_inventory.is_some() || event.observation.is_some() {
                    return Err(refusal("checkpoint phase has unexpected inventory"));
                }
                records.insert((*name).to_string(), Record { file, bytes });
            }
            if records.contains_key("03-published-verified.json")
                && (!records.contains_key("02-publishing.json")
                    || !records.contains_key("01-verified-private.json"))
            {
                return Err(refusal("published history lacks required predecessors"));
            }
            if records.contains_key("02-publishing.json")
                && !records.contains_key("01-verified-private.json")
            {
                return Err(refusal(
                    "publication history lacks verified private predecessor",
                ));
            }
            if records.contains_key("04-private-empty.json") {
                return Err(refusal(
                    "private cleanup already recorded; empty checkpoint preserved",
                ));
            }
            // The newest verified event is historical evidence. A later
            // explicit undo may already have relocated that exact public root
            // back under pending-target; core checks the actual namespace and
            // transition under fresh deletion authority, never this DTO alone.
            let selected = if records.contains_key("03-published-verified.json") {
                "03-published-verified.json"
            } else {
                "01-verified-private.json"
            };
            let inventory = inventories.remove(selected).ok_or_else(|| {
                refusal("complete recorded inventory unavailable; unfinished objects preserved")
            })?;
            if inventory.len() > INVENTORY_CAP {
                return Err(refusal("recovery inventory exceeds bound"));
            }
            let result = Self {
                parent,
                parent_path,
                parent_identity,
                target_name: target
                    .file_name()
                    .ok_or_else(|| refusal("recovery target component unavailable"))?
                    .to_os_string(),
                root_identity: root_identity
                    .map(|i| (i[0], i[1]))
                    .ok_or_else(|| refusal("recorded root identity unavailable"))?,
                journal,
                journal_name,
                lock,
                records,
                pending,
                inventory,
            };
            result.revalidate()?;
            Ok(result)
        }
        /// Read-only acknowledgement of the one fixed namespace transition.
        /// This creates no deletion authority; the caller already consumed the
        /// distinct core undo lease and holds its live outcome observation.
        pub(crate) fn observe_private_transition(&mut self) -> std::io::Result<()> {
            if entry_identity_at(self.parent.as_raw_fd(), &self.target_name)?.is_some()
                || entry_identity_at(self.journal.as_raw_fd(), OsStr::new("pending-target"))?
                    != Some(self.root_identity)
            {
                return Err(refusal(
                    "undo namespace outcome differs from recorded root; objects preserved",
                ));
            }
            self.pending = true;
            self.revalidate()
        }
        pub(crate) fn inventory(&self) -> &[u8] {
            &self.inventory
        }
        pub(crate) fn revalidate(&self) -> std::io::Result<()> {
            if file_identity(&open_directory_nofollow(&self.parent_path)?)? != self.parent_identity
            {
                return Err(refusal("recovery parent changed"));
            }
            private_directory(&self.journal)?;
            same_directory(&self.parent, &self.journal_name, &self.journal)?;
            let mut expected = self.records.keys().cloned().collect::<BTreeSet<_>>();
            expected.insert("lock".into());
            if self.pending {
                expected.insert("pending-target".into());
            }
            if names(&self.journal)? != expected {
                return Err(refusal("recovery checkpoint entry set changed"));
            }
            verify_file(&self.journal, "lock", &self.lock, &[], SMALL_EVENT_CAP)?;
            for (name, record) in &self.records {
                verify_file(
                    &self.journal,
                    name,
                    &record.file,
                    &record.bytes,
                    if name.contains("verified") {
                        INVENTORY_CAP
                    } else {
                        SMALL_EVENT_CAP
                    },
                )?;
            }
            Ok(())
        }
    }

    fn refusal(message: &str) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::InvalidData, message)
    }
    fn private_directory(file: &File) -> std::io::Result<()> {
        let m = file.metadata()?;
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7777 != 0o700 {
            return Err(refusal(
                "recovery checkpoint is not a private owned directory",
            ));
        }
        Ok(())
    }
    fn same_directory(parent: &File, name: &OsStr, file: &File) -> std::io::Result<()> {
        if entry_identity_at(parent.as_raw_fd(), name)? != Some(file_identity(file)?) {
            return Err(refusal("recovery checkpoint name changed"));
        }
        Ok(())
    }
    fn open_file(parent: &File, name: &str, cap: usize) -> std::io::Result<File> {
        let name = c_component(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        private_file(&file, cap)?;
        Ok(file)
    }
    fn private_file(file: &File, cap: usize) -> std::io::Result<()> {
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != unsafe { libc::geteuid() }
            || m.nlink() != 1
            || m.mode() & 0o7777 != 0o600
            || m.len() > cap as u64
        {
            return Err(refusal(
                "recovery record is not a bounded private ordinary file",
            ));
        }
        Ok(())
    }
    fn read_file(file: &File, cap: usize) -> std::io::Result<Vec<u8>> {
        private_file(file, cap)?;
        let mut reader = file.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        reader.take((cap + 1) as u64).read_to_end(&mut bytes)?;
        if bytes.len() > cap {
            return Err(refusal("recovery record exceeds bound"));
        }
        private_file(file, cap)?;
        Ok(bytes)
    }
    fn verify_file(
        parent: &File,
        name: &str,
        file: &File,
        bytes: &[u8],
        cap: usize,
    ) -> std::io::Result<()> {
        let current = open_file(parent, name, cap)?;
        if file_identity(&current)? != file_identity(file)?
            || read_file(&current, cap)? != bytes
            || read_file(file, cap)? != bytes
        {
            return Err(refusal("recovery record generation changed"));
        }
        Ok(())
    }
    fn names(parent: &File) -> std::io::Result<BTreeSet<String>> {
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
            let mut names = BTreeSet::new();
            loop {
                unsafe { *libc::__errno_location() = 0 };
                let entry = unsafe { libc::readdir(stream) };
                if entry.is_null() {
                    let e = unsafe { *libc::__errno_location() };
                    return if e == 0 {
                        Ok(names)
                    } else {
                        Err(std::io::Error::from_raw_os_error(e))
                    };
                }
                let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
                    .to_str()
                    .map_err(|_| refusal("non-UTF8 recovery journal name"))?;
                if name != "." && name != ".." {
                    if names.len() >= 12 {
                        return Err(refusal("recovery journal entry count exceeded"));
                    }
                    names.insert(name.to_string());
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
        use crate::cli::package_checkpoint::create_file_at;
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;
        fn fixture() -> (tempfile::TempDir, PathBuf, String, (u64, u64), PathBuf) {
            let root = tempfile::tempdir().unwrap();
            let target = root.path().join("target");
            let id = uuid::Uuid::new_v4().to_string();
            let identity = file_identity(&open_directory_nofollow(root.path()).unwrap()).unwrap();
            let journal = root.path().join(format!(".tirith-materialize-{id}"));
            std::fs::create_dir(&journal).unwrap();
            std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o700)).unwrap();
            let held = open_directory_nofollow(&journal).unwrap();
            create_file_at(held.as_raw_fd(), OsStr::new("lock"), 0o600).unwrap();
            std::fs::create_dir(journal.join("pending-target")).unwrap();
            std::fs::set_permissions(
                journal.join("pending-target"),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            let root_id =
                file_identity(&open_directory_nofollow(&journal.join("pending-target")).unwrap())
                    .unwrap();
            for (name, inventory) in [
                ("00-staging.json", false),
                ("01-verified-private.json", true),
            ] {
                // Input-reader fixture only, not a core recovery proof. The
                // core must reject this deliberately incomplete inventory.
                let event=CheckpointEvent{schema_version:1,contract:"LocalLeafMaterializeV1".into(),operation_id:id.clone(),private_plan_digest:"a".repeat(64),event:name.into(),target_identity:[root_id.0,root_id.1],observation:inventory.then(||serde_json::json!({"descriptive":true})),recovery_inventory:inventory.then(||serde_json::json!({"root":{"identity":[root_id.0,root_id.1]},"reader_fixture_only":true})),package_code_executed:false,execution_authority:false};
                let mut file = create_file_at(held.as_raw_fd(), OsStr::new(name), 0o600).unwrap();
                file.write_all(&serde_json::to_vec(&event).unwrap())
                    .unwrap();
            }
            (root, target, id, identity, journal)
        }
        #[test]
        fn retained_checkpoint_reader_refuses_extra_entries_and_keeps_them() {
            let (_root, target, id, parent, journal) = fixture();
            let reader = RecoveryCheckpoint::open(&target, &id, parent, &"a".repeat(64)).unwrap();
            std::fs::write(journal.join("unexpected"), b"preserve").unwrap();
            assert!(reader.revalidate().is_err());
            drop(reader);
            assert_eq!(
                std::fs::read(journal.join("unexpected")).unwrap(),
                b"preserve"
            );
        }
        #[test]
        fn missing_inventory_and_cross_operation_records_refuse_before_core_capture() {
            let (_root, target, id, parent, journal) = fixture();
            let path = journal.join("01-verified-private.json");
            let bytes = std::fs::read(&path).unwrap();
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            value["operation_id"] = serde_json::json!(uuid::Uuid::new_v4().to_string());
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(RecoveryCheckpoint::open(&target, &id, parent, &"a".repeat(64)).is_err());
            std::fs::remove_file(&path).unwrap();
            assert!(RecoveryCheckpoint::open(&target, &id, parent, &"a".repeat(64)).is_err());
            assert!(journal.join("pending-target").is_dir());
        }
        #[test]
        fn checkpoint_reader_releases_lock_before_duplicate_descriptor_closes() {
            let (_root, target, id, parent, journal) = fixture();
            let digest = "a".repeat(64);
            let first = RecoveryCheckpoint::open(&target, &id, parent, &digest).unwrap();
            let retained = first.lock.try_clone().unwrap();
            assert!(RecoveryCheckpoint::open(&target, &id, parent, &digest).is_err());
            drop(first);
            let next = RecoveryCheckpoint::open(&target, &id, parent, &digest)
                .expect("the checkpoint reader releases before duplicate descriptors close");
            assert!(RecoveryCheckpoint::open(&target, &id, parent, &digest).is_err());
            drop(retained);
            assert!(RecoveryCheckpoint::open(&target, &id, parent, &digest).is_err());
            drop(next);
            assert!(RecoveryCheckpoint::open(&target, &id, parent, &digest).is_ok());
            assert!(journal.join("01-verified-private.json").is_file());
            assert!(journal.join("pending-target").is_dir());
        }

        #[test]
        fn checkpoint_reader_holds_original_lock_and_rejects_record_replacement() {
            let (_root, target, id, parent, journal) = fixture();
            let reader = RecoveryCheckpoint::open(&target, &id, parent, &"a".repeat(64)).unwrap();
            assert!(RecoveryCheckpoint::open(&target, &id, parent, &"a".repeat(64)).is_err());
            let path = journal.join("01-verified-private.json");
            let bytes = std::fs::read(&path).unwrap();
            std::fs::rename(&path, journal.join("displaced")).unwrap();
            std::fs::write(&path, bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(reader.revalidate().is_err());
        }
    }
}
#[cfg(target_os = "linux")]
pub(crate) use linux::RecoveryCheckpoint;
