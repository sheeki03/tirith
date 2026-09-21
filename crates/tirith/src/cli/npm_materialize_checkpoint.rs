//! Separate data-only checkpoint. It cannot extract launch authority or accept
//! a serialized report as publication proof. Drop only closes owned handles.

#[cfg(target_os = "linux")]
mod linux {
    use super::super::{
        c_component, create_file_at, entry_identity_at, file_identity, mkdirat_component,
        open_directory_nofollow, openat_directory, renameat2_noreplace_component,
        InstallTargetBinding,
    };
    use fs2::FileExt as _;
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Write as _;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::fs::MetadataExt;
    use std::{
        ffi::{OsStr, OsString},
        fs::File,
        path::PathBuf,
    };
    use tirith_core::artifact::npm_install::materialize::{
        MaterializationCheckpointAuthorization, MaterializationRecoveryInventory,
        MaterializationSummary, MaterializationWriter, VerifiedMaterializedTree, STAGING_COMPONENT,
    };

    pub(crate) const EVENT_CAP: usize = 2 * 1024 * 1024;
    const JOURNAL_ENTRY_CAP: usize = 12;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
    #[serde(rename_all = "snake_case")]
    pub(crate) enum State {
        Private,
        PublicationPossible,
        PublishedUnconfirmed,
        Committed,
        PrivateEmpty,
    }

    /// Immutable event bytes are compared through their retained descriptors.
    /// No old event, temporary name, or unknown entry is overwritten or removed.
    struct Event {
        file: File,
        bytes: Vec<u8>,
    }

    pub(crate) struct MaterializationCheckpoint<'a> {
        authority: MaterializationCheckpointAuthorization<'a>,
        parent: File,
        parent_path: PathBuf,
        parent_identity: (u64, u64),
        journal: File,
        journal_name: OsString,
        target: File,
        target_name: OsString,
        target_identity: (u64, u64),
        events: BTreeMap<String, Event>,
        lock: File,
        state: State,
    }

    impl<'a> MaterializationCheckpoint<'a> {
        pub(crate) fn begin(
            binding: &InstallTargetBinding,
            authority: MaterializationCheckpointAuthorization<'a>,
        ) -> std::io::Result<Self> {
            if authority.target_identity() != binding.package_target_identity() {
                return Err(refusal(
                    "materialization target differs from its exact plan",
                ));
            }
            authority.revalidate().map_err(core_error)?;
            binding.verify_visible_parent()?;
            let parent = binding.parent.try_clone()?;
            let journal_name = OsString::from(authority.journal_component());
            // Existing journals are interrupted intent, never restart authority.
            // Even initialization errors retain the new journal for inspection.
            mkdirat_component(parent.as_raw_fd(), &journal_name, 0o700)?;
            let journal = openat_directory(parent.as_raw_fd(), &journal_name)?;
            private_directory(&journal)?;
            same_directory(&parent, &journal_name, &journal)?;
            parent.sync_all()?;
            if !names(&journal)?.is_empty() {
                return Err(refusal("new materialization journal is not empty"));
            }
            authority.revalidate().map_err(core_error)?;
            let lock = create_file_at(journal.as_raw_fd(), OsStr::new("lock"), 0o600)?;
            private_file(&lock)?;
            lock.try_lock_exclusive()?;
            lock.sync_all()?;
            journal.sync_all()?;
            authority.revalidate().map_err(core_error)?;
            mkdirat_component(journal.as_raw_fd(), OsStr::new(STAGING_COMPONENT), 0o700)?;
            let target = openat_directory(journal.as_raw_fd(), OsStr::new(STAGING_COMPONENT))?;
            private_directory(&target)?;
            same_directory(&journal, OsStr::new(STAGING_COMPONENT), &target)?;
            if !names(&target)?.is_empty() {
                return Err(refusal("new materialization target is not empty"));
            }
            let target_identity = file_identity(&target)?;
            let mut result = Self {
                authority,
                parent,
                parent_path: binding.parent_path.clone(),
                parent_identity: (binding.parent_dev, binding.parent_ino),
                journal,
                journal_name,
                target,
                target_name: binding.target_name.clone(),
                target_identity,
                events: BTreeMap::new(),
                lock,
                state: State::Private,
            };
            result.validate_layout()?;
            result.authority.revalidate().map_err(core_error)?;
            result.append_event("00-staging.json", None, None)?;
            result.authority.revalidate().map_err(core_error)?;
            Ok(result)
        }

        pub(crate) fn writer_handles(&self) -> std::io::Result<(File, File)> {
            if self.state != State::Private {
                return Err(refusal("materialization checkpoint is not private"));
            }
            self.authority.revalidate().map_err(core_error)?;
            self.validate_layout()?;
            Ok((self.journal.try_clone()?, self.target.try_clone()?))
        }

        pub(crate) fn state(&self) -> State {
            self.state
        }

        /// A public result can only be derived after the core writer confirms
        /// the actual public target and rehashes its complete retained inventory.
        pub(crate) fn publish(
            &mut self,
            writer: &mut MaterializationWriter<'_>,
        ) -> std::io::Result<MaterializationSummary> {
            if self.state != State::Private {
                return Err(refusal("materialization publication cannot be retried"));
            }
            {
                let tree = writer.verify().map_err(core_error)?;
                self.require_tree(&tree, false)?;
                self.append_event(
                    "01-verified-private.json",
                    Some(tree.summary()),
                    Some(&tree.recovery_inventory().map_err(core_error)?),
                )?;
                self.require_tree(&tree, false)?;
            }
            self.authority.revalidate().map_err(core_error)?;
            self.validate_layout()?;
            self.append_event("02-publishing.json", None, None)?;
            // Both owners forbid private cleanup before rename may publish.
            // Even a definite no-replace failure is retained conservatively.
            writer.begin_publication().map_err(core_error)?;
            self.state = State::PublicationPossible;
            self.authority.revalidate().map_err(core_error)?;
            self.validate_layout()?;
            renameat2_noreplace_component(
                self.journal.as_raw_fd(),
                OsStr::new(STAGING_COMPONENT),
                self.parent.as_raw_fd(),
                &self.target_name,
            )?;
            self.state = State::PublishedUnconfirmed;
            self.parent.sync_all()?;
            self.journal.sync_all()?;
            writer.confirm_published().map_err(core_error)?;
            let tree = writer.verify().map_err(core_error)?;
            self.require_tree(&tree, true)?;
            self.append_event(
                "03-published-verified.json",
                Some(tree.summary()),
                Some(&tree.recovery_inventory().map_err(core_error)?),
            )?;
            self.require_tree(&tree, true)?;
            self.target.sync_all()?;
            self.parent.sync_all()?;
            self.state = State::Committed;
            Ok(tree.summary().clone())
        }

        /// Called only after the core's inventory-aware cleanup succeeds.
        /// This removes no output, journal, event or lock; an interrupted or
        /// changed object remains available for explicit recovery inspection.
        pub(crate) fn record_private_empty(&mut self) -> std::io::Result<()> {
            if self.state != State::Private {
                return Err(refusal(
                    "publication may have occurred; private cleanup is forbidden",
                ));
            }
            self.authority.revalidate().map_err(core_error)?;
            self.validate_layout()?;
            if !names(&self.target)?.is_empty() {
                return Err(refusal(
                    "private tree still contains materialization or foreign data",
                ));
            }
            self.append_event("04-private-empty.json", None, None)?;
            self.state = State::PrivateEmpty;
            Ok(())
        }

        fn require_tree(
            &self,
            tree: &VerifiedMaterializedTree<'_, '_>,
            published: bool,
        ) -> std::io::Result<()> {
            self.authority.revalidate_tree(tree).map_err(core_error)?;
            if tree.published() != published {
                return Err(refusal(
                    "materialization evidence describes the wrong publication phase",
                ));
            }
            self.validate_layout()
        }

        fn validate_layout(&self) -> std::io::Result<()> {
            if file_identity(&open_directory_nofollow(&self.parent_path)?)? != self.parent_identity
            {
                return Err(refusal("materialization parent changed"));
            }
            same_directory(&self.parent, &self.journal_name, &self.journal)?;
            private_directory(&self.journal)?;
            private_directory(&self.target)?;
            if file_identity(&self.target)? != self.target_identity {
                return Err(refusal("materialization target identity changed"));
            }
            let published = matches!(self.state, State::PublishedUnconfirmed | State::Committed);
            if published {
                same_directory(&self.parent, &self.target_name, &self.target)?;
            } else {
                same_directory(&self.journal, OsStr::new(STAGING_COMPONENT), &self.target)?;
            }
            let mut expected: BTreeSet<String> = self.events.keys().cloned().collect();
            expected.insert("lock".into());
            if !published {
                expected.insert(STAGING_COMPONENT.into());
            }
            if names(&self.journal)? != expected {
                return Err(refusal(
                    "materialization journal has unexpected or missing entries",
                ));
            }
            same_file(&self.journal, "lock", &self.lock)?;
            if self.lock.metadata()?.len() != 0 {
                return Err(refusal("materialization lock changed"));
            }
            for (name, event) in &self.events {
                same_file(&self.journal, name, &event.file)?;
                let mut file = event.file.try_clone()?;
                file.seek(SeekFrom::Start(0))?;
                let mut bytes = Vec::new();
                file.take((EVENT_CAP + 1) as u64).read_to_end(&mut bytes)?;
                if bytes != event.bytes {
                    return Err(refusal("materialization event changed"));
                }
                same_file(&self.journal, name, &event.file)?;
            }
            Ok(())
        }

        fn append_event(
            &mut self,
            name: &str,
            summary: Option<&MaterializationSummary>,
            inventory: Option<&MaterializationRecoveryInventory>,
        ) -> std::io::Result<()> {
            self.validate_layout()?;
            let value = serde_json::json!({
                "schema_version":1, "contract":"LocalLeafMaterializeV1",
                "operation_id":self.authority.operation_id(),
                "private_plan_digest":self.authority.private_plan_digest(),
                "event":name, "target_identity":[self.target_identity.0,self.target_identity.1],
                "observation":summary, "recovery_inventory":inventory,
                "package_code_executed":false, "execution_authority":false,
            });
            let mut bytes = serde_json::to_vec(&value).map_err(std::io::Error::other)?;
            bytes.push(b'\n');
            if bytes.len() > EVENT_CAP || self.events.len() >= 5 {
                return Err(refusal("materialization journal exceeds its bound"));
            }
            let mut file = create_file_at(self.journal.as_raw_fd(), OsStr::new(name), 0o600)?;
            private_file(&file)?;
            same_file(&self.journal, name, &file)?;
            // A partial event is deliberately retained. It cannot be treated as
            // a valid state transition or overwritten during recovery.
            file.write_all(&bytes)?;
            file.sync_all()?;
            self.events.insert(name.into(), Event { file, bytes });
            self.journal.sync_all()?;
            self.parent.sync_all()?;
            self.validate_layout()
        }
    }

    fn core_error(error: impl std::fmt::Debug) -> std::io::Error {
        std::io::Error::other(format!("materialization refused: {error:?}"))
    }
    fn refusal(detail: &str) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, detail)
    }
    fn private_directory(file: &File) -> std::io::Result<()> {
        let metadata = file.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(refusal(
                "materialization directory must be private and operator-owned",
            ));
        }
        Ok(())
    }
    fn private_file(file: &File) -> std::io::Result<()> {
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(refusal(
                "materialization record must be private, regular and single-link",
            ));
        }
        Ok(())
    }
    fn same_directory(parent: &File, name: &OsStr, file: &File) -> std::io::Result<()> {
        if entry_identity_at(parent.as_raw_fd(), name)? != Some(file_identity(file)?) {
            return Err(refusal("materialization directory name changed"));
        }
        Ok(())
    }
    fn same_file(parent: &File, name: &str, held: &File) -> std::io::Result<()> {
        let name = c_component(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let current = unsafe { File::from_raw_fd(fd) };
        private_file(held)?;
        private_file(&current)?;
        if file_identity(&current)? != file_identity(held)? {
            return Err(refusal("materialization record name changed"));
        }
        Ok(())
    }
    fn names(directory: &File) -> std::io::Result<BTreeSet<String>> {
        // Open a fresh enumeration description, not dup's shared directory
        // offset. This fixed dot operand is not an archive member name.
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            unsafe { libc::close(fd) };
            return Err(std::io::Error::last_os_error());
        }
        struct Close(*mut libc::DIR);
        impl Drop for Close {
            fn drop(&mut self) {
                unsafe { libc::closedir(self.0) };
            }
        }
        let _close = Close(stream);
        let mut result = BTreeSet::new();
        loop {
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                let errno = unsafe { *libc::__errno_location() };
                if errno != 0 {
                    return Err(std::io::Error::from_raw_os_error(errno));
                }
                return Ok(result);
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
                .to_str()
                .map_err(|_| refusal("non-UTF8 materialization journal entry"))?;
            if name == "." || name == ".." {
                continue;
            }
            if result.len() >= JOURNAL_ENTRY_CAP {
                return Err(refusal(
                    "materialization directory exceeds enumeration bound",
                ));
            }
            result.insert(name.to_owned());
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::{MaterializationCheckpoint, State};
