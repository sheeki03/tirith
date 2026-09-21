//! Shared read-modify-write transaction orchestration for setup-managed files.
//!
//! Platform modules provide capability-style parent traversal, snapshots,
//! temporary files, backups, and publication. This module owns the ordering:
//! lock, live snapshot, transform, backup, durable temp, generation check,
//! publication, directory durability, and retention.

use std::path::Path;

use super::fs_helpers::{PlatformSnapshot, PlatformTransaction};

/// Setup files are configuration and hook text, not arbitrary payloads. The
/// cap bounds both the initial snapshot and the mandatory pre-publication
/// generation check. Reads use cap+1 so an exact-limit file remains valid.
pub(crate) const MAX_SETUP_FILE_BYTES: usize = 10 * 1024 * 1024;

/// The former global setup lock waited indefinitely. Existing contention tests
/// measured roughly 23 seconds in aggregate; one acquisition now has a generous
/// 30-second ceiling, while short injected budgets make timeout tests practical.
pub(crate) const SETUP_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) fn wait_for_lock(
    timeout: std::time::Duration,
    mut acquire: impl FnMut() -> Result<bool, String>,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    loop {
        if acquire()? {
            return Ok(());
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Err(format!("setup lock timed out after {} ms; another operation is still running; retry after it completes", elapsed.as_millis()));
        }
        std::thread::sleep(std::time::Duration::from_millis(25).min(timeout - elapsed));
    }
}

/// Immutable live state observed through a no-follow handle.
pub(crate) struct FileSnapshot {
    inner: PlatformSnapshot,
}

impl FileSnapshot {
    pub(crate) fn require_private(&self) -> Result<(), String> {
        self.inner.require_private()
    }

    pub(crate) fn exists(&self) -> bool {
        self.inner.bytes.is_some()
    }

    pub(crate) fn bytes(&self) -> Option<&[u8]> {
        self.inner.bytes.as_deref()
    }

    pub(crate) fn text(&self, path: &Path) -> Result<Option<&str>, String> {
        self.bytes()
            .map(|bytes| {
                std::str::from_utf8(bytes)
                    .map_err(|error| format!("{} is not valid UTF-8: {error}", path.display()))
            })
            .transpose()
    }

    #[cfg(unix)]
    pub(crate) fn mode(&self) -> Option<u32> {
        self.inner.mode
    }
}

/// A pure transform result. The shared transaction owns all filesystem side
/// effects represented here.
pub(crate) enum FileUpdate {
    Unchanged,
    Write {
        bytes: Vec<u8>,
        mode: u32,
        preserve_existing_mode: bool,
        backup: bool,
    },
}

impl FileUpdate {
    pub(crate) fn unchanged() -> Self {
        Self::Unchanged
    }

    pub(crate) fn write_text(content: String, mode: u32) -> Self {
        Self::Write {
            bytes: content.into_bytes(),
            mode,
            preserve_existing_mode: true,
            backup: false,
        }
    }

    /// Publish the requested Unix mode atomically, for executable hooks and
    /// private records. Windows keeps its native private ACL validation; it
    /// does not interpret a Unix mode as Windows permission authority.
    pub(crate) fn with_exact_mode(mut self) -> Self {
        if let Self::Write {
            preserve_existing_mode,
            ..
        } = &mut self
        {
            *preserve_existing_mode = false;
        }
        self
    }

    pub(crate) fn with_backup(mut self, backup: bool) -> Self {
        if let Self::Write {
            backup: requested, ..
        } = &mut self
        {
            *requested = backup;
        }
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransactionOutcome {
    Unchanged,
    DryRunWouldWrite,
    Written,
    WrittenWithRecovery,
}

impl TransactionOutcome {
    /// Caller-visible completion annotation. A retained recovery is a
    /// successful publication, but never presented as indistinguishable from
    /// a clean transaction.
    pub(crate) fn completion_annotation(self) -> Option<&'static str> {
        match self {
            Self::Written => Some(""),
            Self::WrittenWithRecovery => Some(" [recovery retained]"),
            Self::Unchanged | Self::DryRunWouldWrite => None,
        }
    }
}

/// Honest result after the platform publication capability has survived the
/// durability gate. Windows cannot prove ReplaceFileW's directory/name
/// transition durable, so it returns a successful-but-degraded outcome with
/// exact recovery material instead of claiming a clean commit.
pub(crate) enum PublicationOutcome {
    Clean,
    RecoveryRetained(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub(crate) enum TestStage {
    PreflightReady,
    TempSynced,
    SnapshotValidated,
    PublicationReady,
    Published,
}

fn validate_update_size(update: &FileUpdate) -> Result<(), String> {
    if let FileUpdate::Write { bytes, .. } = update {
        if bytes.len() > MAX_SETUP_FILE_BYTES {
            return Err(format!(
                "setup output exceeds setup file limit of {MAX_SETUP_FILE_BYTES} bytes"
            ));
        }
    }
    Ok(())
}

pub(crate) fn transactional_update<F>(
    path: &Path,
    scope_root: &Path,
    dry_run: bool,
    transform: F,
) -> Result<TransactionOutcome, String>
where
    F: FnMut(&FileSnapshot) -> Result<FileUpdate, String>,
{
    transactional_update_checked(path, scope_root, dry_run, transform, || Ok(()))
}

/// Variant used when selecting the destination itself requires filesystem
/// preflights (for example bash's `.bashrc`/`.bash_profile` fallback). The
/// selection is revalidated after the live snapshot and immediately before
/// the destination generation check.
pub(crate) fn transactional_update_checked<F, V>(
    path: &Path,
    scope_root: &Path,
    dry_run: bool,
    transform: F,
    revalidate_selection: V,
) -> Result<TransactionOutcome, String>
where
    F: FnMut(&FileSnapshot) -> Result<FileUpdate, String>,
    V: FnMut() -> Result<(), String>,
{
    transactional_update_authorized(
        path,
        scope_root,
        dry_run,
        transform,
        revalidate_selection,
        |_| Ok(()),
    )
}

/// Retain the same checked destination and exact transformed bytes through a
/// single authorization boundary immediately before publication. The caller
/// also performs pure authorization preflight before any filesystem effects.
pub(crate) fn transactional_update_authorized<F, V, A>(
    path: &Path,
    scope_root: &Path,
    dry_run: bool,
    transform: F,
    revalidate_selection: V,
    authorize_publication: A,
) -> Result<TransactionOutcome, String>
where
    F: FnMut(&FileSnapshot) -> Result<FileUpdate, String>,
    V: FnMut() -> Result<(), String>,
    A: FnMut(&[u8]) -> Result<(), String>,
{
    transactional_update_impl(
        path,
        scope_root,
        TransactionOptions::ordinary(dry_run),
        transform,
        revalidate_selection,
        authorize_publication,
        #[cfg(test)]
        |_| Ok(()),
    )
}

#[derive(Clone, Copy)]
struct TransactionOptions {
    dry_run: bool,
    lock_timeout: std::time::Duration,
    read_cap: usize,
    quiet: bool,
    retain_artifacts: bool,
    #[cfg(unix)]
    private_parent: bool,
}
impl TransactionOptions {
    fn ordinary(dry_run: bool) -> Self {
        Self {
            dry_run,
            lock_timeout: SETUP_LOCK_TIMEOUT,
            read_cap: MAX_SETUP_FILE_BYTES,
            quiet: false,
            retain_artifacts: true,
            #[cfg(unix)]
            private_parent: false,
        }
    }
}

/// Small internal health notices reuse the same protected native transaction.
/// This is not a configurable environment timeout and changes no ordinary writer.
pub(crate) fn write_private_notice_bounded(
    path: &Path,
    scope_root: &Path,
    content: String,
    cap: usize,
    lock_timeout: std::time::Duration,
    valid_existing: impl Fn(&[u8]) -> bool,
) -> Result<TransactionOutcome, String> {
    if cap == 0 || cap > MAX_SETUP_FILE_BYTES || content.len() > cap {
        return Err("private notice exceeds its fixed bound".into());
    }
    transactional_update_impl(
        path,
        scope_root,
        TransactionOptions {
            dry_run: false,
            lock_timeout,
            read_cap: cap,
            quiet: true,
            retain_artifacts: false,
            #[cfg(unix)]
            private_parent: false,
        },
        |snapshot| {
            snapshot.require_private()?;
            if let Some(existing) = snapshot.bytes() {
                // Keep the first valid observation. Replacing a Windows file
                // retains a displaced recovery generation; a failure reporter
                // must never accumulate one for each new failed append.
                if !valid_existing(existing) {
                    return Err("existing private notice is not valid for this destination".into());
                }
                return Ok(FileUpdate::Unchanged);
            }
            let update = FileUpdate::write_text(content.clone(), 0o600);
            #[cfg(unix)]
            let update = update.with_exact_mode();
            Ok(update)
        },
        || Ok(()),
        |_| Ok(()),
        #[cfg(test)]
        |_| Ok(()),
    )
}

/// Fixed native stores for optional enrollment and immutable review/state
/// records. The selector alone determines target and cap; no arbitrary path is
/// accepted. The caller still supplies actual state-machine/authority checks.
pub(crate) fn update_private_team_record<F, V>(
    selector: &tirith_core::policy_team_connection::TeamRecord,
    mut transform: F,
    mut revalidate: V,
) -> Result<TransactionOutcome, String>
where
    F: FnMut(&FileSnapshot) -> Result<FileUpdate, String>,
    V: FnMut() -> Result<(), String>,
{
    let witness = selector.capture_current().map_err(|e| e.to_string())?;
    let cap = selector.cap();
    transactional_update_impl(witness.private_path(),witness.private_scope(),TransactionOptions{
        dry_run:false,lock_timeout:std::time::Duration::from_secs(2),read_cap:cap,quiet:true,retain_artifacts:false,
        #[cfg(unix)] private_parent:true,
    },|snapshot|{
        witness.revalidate().map_err(|e|e.to_string())?;snapshot.require_private()?;
        if !witness.matches_private_bytes(snapshot.bytes()){return Err("private team record changed before publication".into())}
        let update=private_team_record_update(transform(snapshot)?,cap)?;
        witness.revalidate().map_err(|e|e.to_string())?;Ok(update)
    },||{witness.revalidate().map_err(|e|e.to_string())?;revalidate()},|bytes|{
        if bytes.len()>cap{return Err("private team record exceeds its fixed bound".into())}Ok(())
    },#[cfg(test)] |_|Ok(()))
    // Native errors may carry private paths. Public operation services receive
    // a closed outcome message and must recapture status before retrying.
    .map_err(|_|"private team record publication was not confirmed; inspect its current state before retrying".into())
}
fn private_team_record_update(update: FileUpdate, cap: usize) -> Result<FileUpdate, String> {
    match update {
        FileUpdate::Unchanged => Ok(FileUpdate::Unchanged),
        FileUpdate::Write { bytes, .. } => {
            if bytes.len() > cap {
                return Err("private team record exceeds its fixed bound".into());
            }
            Ok(FileUpdate::Write {
                bytes,
                mode: 0o600,
                preserve_existing_mode: false,
                backup: false,
            })
        }
    }
}

/// Selected team connections use the existing private transaction with a fixed
/// bounded payload. No backup or directory-wide retention scan copies credentials.
pub(crate) fn update_private_team_connection<F, V>(
    path: &Path,
    scope: &Path,
    mut transform: F,
    revalidate: V,
) -> Result<TransactionOutcome, String>
where
    F: FnMut(&FileSnapshot) -> Result<FileUpdate, String>,
    V: FnMut() -> Result<(), String>,
{
    transactional_update_impl(
        path,
        scope,
        TransactionOptions {
            dry_run: false,
            lock_timeout: std::time::Duration::from_secs(2),
            read_cap: 128 * 1024,
            quiet: true,
            retain_artifacts: false,
            #[cfg(unix)]
            private_parent: true,
        },
        |snapshot| {
            snapshot.require_private()?;
            let update = transform(snapshot)?;
            if matches!(&update,FileUpdate::Write{bytes,..} if bytes.len()>128*1024) {
                return Err("team connection exceeds its fixed bound".into());
            }
            Ok(update)
        },
        revalidate,
        |_| Ok(()),
        #[cfg(test)]
        |_| Ok(()),
    )
}
/// Explicit disconnect, under the same writer rendezvous. The caller retains
/// its stronger owner/ACL source witness until the exact native delete begins.
pub(crate) fn delete_private_team_connection<F, V>(
    path: &Path,
    scope: &Path,
    matches: F,
    mut revalidate: V,
) -> Result<(), String>
where
    F: Fn(Option<&[u8]>) -> bool,
    V: FnMut() -> Result<(), String>,
{
    revalidate()?;
    let pre = super::fs_helpers::read_snapshot_scoped_capped(path, scope, 128 * 1024)?;
    pre.require_private()?;
    if pre.bytes.is_none() || !matches(pre.bytes.as_deref()) {
        return Err("team connection changed before disconnect".into());
    }
    let lock = PlatformTransaction::lock_for(path, scope, std::time::Duration::from_secs(2))?;
    revalidate()?;
    let tx = PlatformTransaction::begin(path, scope, lock)?;
    tx.validate_snapshot(&pre)?;
    revalidate()?;
    tx.delete_private_expected(&pre, 128 * 1024)
}

/// Closed enrollment withdrawal. The connection path retains its independent
/// 128 KiB limit; no arbitrary destination or caller-selected cap is accepted.
pub(crate) fn delete_private_team_record<F, V>(
    selector: &tirith_core::policy_team_connection::TeamRecord,
    matches: F,
    mut revalidate: V,
) -> Result<(), String>
where
    F: Fn(Option<&[u8]>) -> bool,
    V: FnMut() -> Result<(), String>,
{
    use tirith_core::policy_team_connection::TeamRecord;
    if !matches!(selector, TeamRecord::Enrollment) {
        return Err("only an explicit enrollment can be withdrawn by this operation".into());
    }
    let mut operation = || -> Result<(), String> {
        let witness = selector.capture_current().map_err(|e| e.to_string())?;
        let path = witness.private_path();
        let scope = witness.private_scope();
        let cap = selector.cap();
        revalidate()?;
        witness.revalidate().map_err(|e| e.to_string())?;
        let pre = super::fs_helpers::read_snapshot_scoped_capped(path, scope, cap)?;
        pre.require_private()?;
        if pre.bytes.is_none()
            || !matches(pre.bytes.as_deref())
            || !witness.matches_private_bytes(pre.bytes.as_deref())
        {
            return Err("enrollment changed before withdrawal".into());
        }
        let lock = PlatformTransaction::lock_for(path, scope, std::time::Duration::from_secs(2))?;
        revalidate()?;
        witness.revalidate().map_err(|e| e.to_string())?;
        let tx = PlatformTransaction::begin(path, scope, lock)?;
        tx.validate_snapshot(&pre)?;
        revalidate()?;
        witness.revalidate().map_err(|e| e.to_string())?;
        tx.delete_private_expected(&pre, cap)
    };
    operation().map_err(|_| {
        "enrollment withdrawal was not confirmed; inspect local status before retrying".into()
    })
}

/// Fixed small private activation claims share contained publication and the
/// setup writer rendezvous. Inventory/authority validation runs again while
/// that global lock is held, including when the transform is unchanged.
#[cfg(unix)]
pub(super) fn update_private_activation_claim<F, V>(
    path: &Path,
    scope: &Path,
    mut transform: F,
    revalidate: V,
) -> Result<TransactionOutcome, String>
where
    F: FnMut(&FileSnapshot) -> Result<FileUpdate, String>,
    V: FnMut() -> Result<(), String>,
{
    transactional_update_impl(
        path,
        scope,
        TransactionOptions {
            dry_run: false,
            lock_timeout: std::time::Duration::from_millis(100),
            read_cap: 4096,
            quiet: true,
            retain_artifacts: false,
            private_parent: true,
        },
        |snapshot| {
            let update = transform(snapshot)?;
            if matches!(&update, FileUpdate::Write { bytes, .. } if bytes.len() > 4096) {
                return Err("automatic claim exceeds its fixed 4 KiB bound".into());
            }
            Ok(update)
        },
        revalidate,
        |bytes| {
            if bytes.len() > 4096 {
                return Err("automatic claim exceeds its fixed 4 KiB bound".into());
            }
            Ok(())
        },
        #[cfg(test)]
        |_| Ok(()),
    )
}

/// Keep the existing ancestor and resulting private parent simultaneously
/// retained. The earlier scoped snapshot walk already rejects symlinks below
/// the authority root, traversal, and paths outside that root.
#[cfg(unix)]
fn prepare_private_activation_parent(
    path: &Path,
    scope_root: &Path,
) -> Result<crate::cli::control::identity::DirectoryIdentity, String> {
    use crate::cli::control::identity::DirectoryIdentity;
    let parent = path
        .parent()
        .ok_or("private activation record has no parent")?;
    let mut existing = parent;
    loop {
        match std::fs::symlink_metadata(existing) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err("private activation parent is not a real directory".into());
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                existing = existing
                    .parent()
                    .ok_or("private parent has no existing ancestor")?;
            }
            Err(_) => return Err("cannot inspect private activation parent".into()),
        }
    }
    let ancestor = DirectoryIdentity::capture_trusted(existing)?;
    if existing == parent {
        ancestor.make_private_leaf()?;
    } else {
        super::fs_helpers::ensure_private_directory(parent, scope_root)?;
    }
    ancestor.revalidate()?;
    let private = DirectoryIdentity::capture(parent)?;
    ancestor.revalidate()?;
    Ok(private)
}

fn transactional_update_impl<F, V, A>(
    path: &Path,
    scope_root: &Path,
    options: TransactionOptions,
    mut transform: F,
    mut revalidate_selection: V,
    mut authorize_publication: A,
    #[cfg(test)] mut test_hook: impl FnMut(TestStage) -> Result<(), String>,
) -> Result<TransactionOutcome, String>
where
    F: FnMut(&FileSnapshot) -> Result<FileUpdate, String>,
    V: FnMut() -> Result<(), String>,
    A: FnMut(&[u8]) -> Result<(), String>,
{
    // Compute and cap the transformed payload before creating a parent,
    // persistent lock file, backup, or temporary file. Missing-parent dry runs and
    // rejected oversized writes therefore remain completely non-mutating.
    revalidate_selection()?;
    let preflight_snapshot = FileSnapshot {
        inner: super::fs_helpers::read_snapshot_scoped_capped(path, scope_root, options.read_cap)?,
    };
    let mut update = transform(&preflight_snapshot)?;
    validate_update_size(&update)?;
    #[cfg(test)]
    test_hook(TestStage::PreflightReady)?;

    if options.dry_run {
        return match update {
            FileUpdate::Unchanged => Ok(TransactionOutcome::Unchanged),
            FileUpdate::Write { .. } => Ok(TransactionOutcome::DryRunWouldWrite),
        };
    }

    // Acquire a transient cross-process synchronization capability that does
    // not create a lock file or destination parent. Re-read and recompute
    // while holding it, so a drifted oversized transform is rejected before
    // any persistent filesystem side effect.
    let transaction_lock = PlatformTransaction::lock_for(path, scope_root, options.lock_timeout)?;
    revalidate_selection()?;
    let snapshot = FileSnapshot {
        inner: super::fs_helpers::read_snapshot_scoped_capped(path, scope_root, options.read_cap)?,
    };
    if snapshot.inner != preflight_snapshot.inner {
        // A cooperative writer may have completed between the side-effect-free
        // preflight and our lock acquisition. Recompute under the lock so both
        // updates are retained, then enforce the same cap again.
        update = transform(&snapshot)?;
        validate_update_size(&update)?;
    }
    // Admission happens after the capped, locked transform and before any
    // private record/artifact is written. An unchanged existing record may
    // tighten its original owned parent, but an absent no-op creates nothing.
    #[cfg(unix)]
    let private_parent = if options.private_parent
        && (snapshot.exists() || matches!(&update, FileUpdate::Write { .. }))
    {
        Some(prepare_private_activation_parent(path, scope_root)?)
    } else {
        None
    };
    let FileUpdate::Write {
        bytes,
        mode,
        preserve_existing_mode,
        backup,
    } = update
    else {
        return Ok(TransactionOutcome::Unchanged);
    };

    // Parent creation begins only after the final locked transform has passed
    // the cap. The transient lock is transferred into the transaction and
    // remains held through publication, durability, backup, and retention.
    let transaction = PlatformTransaction::begin(path, scope_root, transaction_lock)?;
    let transaction_result = (|| -> Result<TransactionOutcome, String> {
        transaction.validate_snapshot(&snapshot.inner)?;
        #[cfg(unix)]
        if let Some(parent) = &private_parent {
            parent.revalidate()?;
        }

        let mut backup_guard = if backup && snapshot.exists() {
            Some(transaction.create_backup(&snapshot.inner)?)
        } else {
            None
        };

        // `TempGuard` is armed before any bytes are written. Every error from this
        // point until publication neutralizes the exact temporary identity through
        // a held capability; no cleanup re-selects a possibly swapped pathname.
        let temp = transaction.prepare_temp(
            &bytes,
            mode,
            preserve_existing_mode,
            &snapshot.inner,
            backup_guard.as_ref(),
        )?;
        #[cfg(test)]
        test_hook(TestStage::TempSynced)?;

        revalidate_selection()?;
        #[cfg(unix)]
        if let Some(parent) = &private_parent {
            parent.revalidate()?;
        }
        transaction.validate_snapshot(&snapshot.inner)?;
        #[cfg(test)]
        test_hook(TestStage::SnapshotValidated)?;

        authorize_publication(&bytes)?;

        let mut publication = transaction.publish(
            temp,
            &snapshot.inner,
            #[cfg(test)]
            &mut test_hook,
        )?;

        // Publication completed. If a later durability gate fails, retain the
        // exact backup and name it in the returned recovery message. A normal
        // "backup at" announcement is emitted only after the durable commit.
        #[cfg(test)]
        let post_publication =
            test_hook(TestStage::Published).and_then(|()| transaction.sync_parent());
        #[cfg(not(test))]
        let post_publication = transaction.sync_parent();
        if let Err(error) = post_publication {
            let recovery_context = publication.retain_for_recovery();
            if let Some(backup) = backup_guard.as_mut() {
                let recovery = backup.retain_for_recovery().map_err(|backup_error| {
                format!(
                    "{error}; publication completed but durability was not confirmed; {recovery_context}; recovery-backup validation failed: {backup_error}"
                )
            })?;
                return Err(format!(
                "{error}; publication completed but durability was not confirmed; {recovery_context}; retained recovery backup at {}",
                recovery.display()
            ));
            }
            return Err(format!(
            "{error}; publication completed but durability was not confirmed; {recovery_context}"
        ));
        }

        let publication_outcome = match publication.finish_after_durability() {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Some(backup) = backup_guard.as_mut() {
                    let recovery = backup.retain_for_recovery().map_err(|backup_error| {
                        format!("{error}; recovery-backup validation failed: {backup_error}")
                    })?;
                    return Err(format!(
                        "{error}; retained recovery backup at {}",
                        recovery.display()
                    ));
                }
                return Err(error);
            }
        };
        if let Some(backup) = backup_guard.as_mut() {
            backup
                .commit()
                .map_err(|error| format!("update committed, but {error}"))?;
        }

        // Tiny failure notices create no backup and must not scan a possibly
        // large directory of unrelated old artifacts on the command path.
        let retention_warning = options
            .retain_artifacts
            .then(|| transaction.cleanup_old_backups(backup_guard.as_ref()).err())
            .flatten()
            .map(|error| format!("could not enforce transaction-artifact retention: {error}"));

        #[cfg(unix)]
        if let Some(parent) = &private_parent {
            parent.revalidate()?;
        }
        match (publication_outcome, retention_warning) {
            (PublicationOutcome::Clean, None) => Ok(TransactionOutcome::Written),
            (PublicationOutcome::Clean, Some(message))
            | (PublicationOutcome::RecoveryRetained(message), None) => {
                if !options.quiet {
                    eprintln!("tirith: WARNING: {message}");
                }
                Ok(TransactionOutcome::WrittenWithRecovery)
            }
            (PublicationOutcome::RecoveryRetained(publication), Some(retention)) => {
                if !options.quiet {
                    eprintln!("tirith: WARNING: {publication}; {retention}");
                }
                Ok(TransactionOutcome::WrittenWithRecovery)
            }
        }
    })();

    let cleanup_failures = transaction.take_cleanup_failures();
    if cleanup_failures.is_empty() {
        return transaction_result;
    }
    let cleanup = cleanup_failures.join("; ");
    match transaction_result {
        Err(error) => Err(format!(
            "{error}; transaction-artifact cleanup also failed: {cleanup}"
        )),
        Ok(TransactionOutcome::Written) => {
            if !options.quiet { eprintln!(
                "tirith: WARNING: update completed but transaction-artifact cleanup failed: {cleanup}"
            ); }
            Ok(TransactionOutcome::WrittenWithRecovery)
        }
        Ok(TransactionOutcome::WrittenWithRecovery) => {
            if !options.quiet { eprintln!("tirith: WARNING: transaction-artifact cleanup also failed: {cleanup}"); }
            Ok(TransactionOutcome::WrittenWithRecovery)
        }
        Ok(other) => Err(format!(
            "transaction-artifact cleanup failed before completion: {cleanup}; outcome was {other:?}"
        )),
    }
}

#[cfg(test)]
pub(crate) fn transactional_update_with_hook<F, H>(
    path: &Path,
    scope_root: &Path,
    transform: F,
    hook: H,
) -> Result<TransactionOutcome, String>
where
    F: FnMut(&FileSnapshot) -> Result<FileUpdate, String>,
    H: FnMut(TestStage) -> Result<(), String>,
{
    transactional_update_impl(
        path,
        scope_root,
        TransactionOptions::ordinary(false),
        transform,
        || Ok(()),
        |_| Ok(()),
        hook,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn publication_authorization_binds_exact_bytes_and_refusal_preserves_destination() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy.yaml");
        std::fs::write(&path, "old\n").unwrap();
        let mut calls = 0;
        let error = super::transactional_update_authorized(
            &path,
            root.path(),
            false,
            |_| Ok(super::FileUpdate::write_text("new\n".into(), 0o600)),
            || Ok(()),
            |bytes| {
                calls += 1;
                assert_eq!(bytes, b"new\n");
                Err("authorization refused".into())
            },
        )
        .unwrap_err();
        assert!(error.contains("authorization refused"));
        assert_eq!(calls, 1);
        assert_eq!(std::fs::read(&path).unwrap(), b"old\n");
    }

    #[test]
    fn contended_lock_has_a_measured_deadline() {
        let started = std::time::Instant::now();
        let error =
            super::wait_for_lock(std::time::Duration::from_millis(40), || Ok(false)).unwrap_err();
        assert!(error.contains("timed out"));
        assert!(started.elapsed() >= std::time::Duration::from_millis(40));
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
    }

    #[test]
    fn lock_retry_can_acquire_before_deadline() {
        let mut attempts = 0;
        super::wait_for_lock(std::time::Duration::from_secs(1), || {
            attempts += 1;
            Ok(attempts == 2)
        })
        .unwrap();
        assert_eq!(attempts, 2);
    }

    use super::TransactionOutcome;

    #[test]
    fn recovery_retention_has_a_distinct_caller_visible_completion_annotation() {
        assert_eq!(
            TransactionOutcome::Written.completion_annotation(),
            Some("")
        );
        assert_eq!(
            TransactionOutcome::WrittenWithRecovery.completion_annotation(),
            Some(" [recovery retained]")
        );
        assert_eq!(TransactionOutcome::Unchanged.completion_annotation(), None);
        assert_eq!(
            TransactionOutcome::DryRunWouldWrite.completion_annotation(),
            None
        );
    }
}

#[cfg(test)]
mod private_notice_tests {
    use super::*;
    #[test]
    fn repeated_private_notices_keep_one_generation_without_replacement_artifacts() {
        let _guard = crate::cli::test_harness::ENV_LOCK.lock().unwrap();
        let scope = tempfile::tempdir().unwrap();
        let target = scope.path().join("notice.json");
        for index in 0..12 {
            let outcome = write_private_notice_bounded(
                &target,
                scope.path(),
                format!("{{\"failure\":{index}}}"),
                1024,
                SETUP_LOCK_TIMEOUT,
                |bytes| bytes == b"{\"failure\":0}",
            )
            .unwrap();
            assert!(matches!(
                outcome,
                TransactionOutcome::Written | TransactionOutcome::Unchanged
            ));
            assert_eq!(std::fs::read(&target).unwrap(), b"{\"failure\":0}");
        }
        assert_eq!(
            std::fs::read_dir(scope.path()).unwrap().count(),
            1,
            "repeated failures must not leave Windows displaced/backup/temp generations"
        );
        assert!(write_private_notice_bounded(
            &target,
            scope.path(),
            "new".into(),
            1024,
            SETUP_LOCK_TIMEOUT,
            |_| false
        )
        .is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"{\"failure\":0}");
    }

    #[test]
    fn private_notice_lock_deadline_creates_no_destination_when_contended() {
        let _guard = crate::cli::test_harness::ENV_LOCK.lock().unwrap();
        let scope = tempfile::tempdir().unwrap();
        let target = scope.path().join("notice.json");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let held_target = target.clone();
        let held_scope = scope.path().to_path_buf();
        let worker = std::thread::spawn(move || {
            let _held = PlatformTransaction::lock(&held_target, &held_scope).unwrap();
            ready_tx.send(()).unwrap();
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(5));
        });
        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let started = std::time::Instant::now();
        let outcome = write_private_notice_bounded(
            &target,
            scope.path(),
            "{}".into(),
            1024,
            std::time::Duration::from_millis(25),
            |_| true,
        );
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        assert!(outcome.unwrap_err().contains("timed out"));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert!(!target.exists());
    }
}

#[cfg(all(test, unix))]
mod activation_parent_tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn activation_parent_refuses_unsafe_aliases_permissions_and_outside_scope() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let unsafe_parent = root.path().join("unsafe-parent");
        std::fs::create_dir(&unsafe_parent).unwrap();
        std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let alias = root.path().join("alias");
        symlink(outside.path(), &alias).unwrap();
        for path in [
            unsafe_parent.join("claim.json"),
            alias.join("claim.json"),
            outside.path().join("claim.json"),
        ] {
            assert!(update_private_activation_claim(
                &path,
                root.path(),
                |_| Ok(FileUpdate::write_text("{}".into(), 0o600).with_exact_mode()),
                || Ok(()),
            )
            .is_err());
            assert!(!path.exists());
        }
        assert_eq!(
            unsafe_parent.metadata().unwrap().permissions().mode() & 0o777,
            0o777
        );
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[test]
    fn activation_parent_admission_follows_locked_authorization_and_size_checks() {
        for denied in [true, false] {
            let root = tempfile::tempdir().unwrap();
            let target = root.path().join("never-created").join("claim.json");
            let mut authority_calls = 0;
            assert!(update_private_activation_claim(
                &target,
                root.path(),
                |_| Ok(FileUpdate::write_text(
                    if denied {
                        "{}".into()
                    } else {
                        "x".repeat(4097)
                    },
                    0o600
                )),
                || {
                    authority_calls += 1;
                    if denied && authority_calls == 2 {
                        Err("locked authority lost".into())
                    } else {
                        Ok(())
                    }
                },
            )
            .is_err());
            assert!(!target.parent().unwrap().exists());
        }
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("absent-noop").join("claim.json");
        assert_eq!(
            update_private_activation_claim(
                &target,
                root.path(),
                |_| Ok(FileUpdate::unchanged()),
                || Ok(()),
            )
            .unwrap(),
            TransactionOutcome::Unchanged
        );
        assert!(!target.parent().unwrap().exists());
    }
}

#[cfg(test)]
mod team_connection_tests {
    use super::*;
    #[test]
    fn private_connection_delete_rejects_changed_bytes_and_preserves_siblings() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("team-policy/connection.json");
        update_private_team_connection(
            &path,
            root.path(),
            |_| {
                Ok(FileUpdate::write_text("private-test-record".into(), 0o600)
                    .with_exact_mode()
                    .with_backup(false))
            },
            || Ok(()),
        )
        .unwrap();
        let sibling = path.parent().unwrap().join("enrollment.json");
        std::fs::write(&sibling, b"unrelated enrollment").unwrap();
        assert!(delete_private_team_connection(
            &path,
            root.path(),
            |bytes| bytes == Some(b"different"),
            || Ok(())
        )
        .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"private-test-record");
        delete_private_team_connection(
            &path,
            root.path(),
            |bytes| bytes == Some(b"private-test-record"),
            || Ok(()),
        )
        .unwrap();
        assert!(!path.exists());
        assert_eq!(std::fs::read(&sibling).unwrap(), b"unrelated enrollment");
    }
    #[test]
    fn private_connection_revalidation_refusal_creates_no_parent() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("team-policy/connection.json");
        assert!(update_private_team_connection(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("private-test-record".into(), 0o600)),
            || Err("source changed".into())
        )
        .is_err());
        assert!(!path.parent().unwrap().exists());
    }
    #[test]
    fn private_connection_cap_is_applied_before_parent_creation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("team-policy/connection.json");
        assert!(update_private_team_connection(
            &path,
            root.path(),
            |_| Ok(FileUpdate::write_text("a".repeat(128 * 1024 + 1), 0o600)),
            || Ok(())
        )
        .is_err());
        assert!(!path.parent().unwrap().exists());
    }
}

#[cfg(test)]
mod closed_team_record_tests {
    use super::*;
    use tirith_core::policy_team::Id;
    use tirith_core::policy_team_connection::TeamRecord;
    #[test]
    fn fixed_store_forces_private_mode_and_no_backup_at_exact_cap() {
        for selector in [TeamRecord::Enrollment, TeamRecord::Rollout(Id::new())] {
            let cap = selector.cap();
            let update = FileUpdate::write_text("x".repeat(cap), 0o666).with_backup(true);
            let FileUpdate::Write {
                bytes,
                mode,
                preserve_existing_mode,
                backup,
            } = private_team_record_update(update, cap).unwrap()
            else {
                panic!("write required")
            };
            assert_eq!(bytes.len(), cap);
            assert_eq!(mode, 0o600);
            assert!(!preserve_existing_mode);
            assert!(!backup);
            assert!(private_team_record_update(
                FileUpdate::write_text("x".repeat(cap + 1), 0o600),
                cap
            )
            .is_err());
        }
    }
    #[test]
    fn immutable_rollout_append_then_exact_preimage_update_preserves_sibling() {
        let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        let selector = TeamRecord::Rollout(Id::new());
        let append = |snapshot: &FileSnapshot| {
            if snapshot.exists() {
                return Err("immutable intent already exists".into());
            }
            Ok(FileUpdate::write_text("intent-v1".into(), 0o600))
        };
        update_private_team_record(&selector, append, || Ok(())).unwrap();
        assert!(update_private_team_record(&selector, append, || Ok(())).is_err());
        let sibling = TeamRecord::Rollout(Id::new());
        update_private_team_record(
            &sibling,
            |_| Ok(FileUpdate::write_text("sibling".into(), 0o600)),
            || Ok(()),
        )
        .unwrap();
        let old = selector.capture_current().unwrap();
        assert!(old.matches_private_bytes(Some(b"intent-v1")));
        update_private_team_record(
            &selector,
            |snapshot| {
                if snapshot.bytes() != Some(b"intent-v1") {
                    return Err("old state changed".into());
                }
                Ok(FileUpdate::write_text("state-v2".into(), 0o600))
            },
            || Ok(()),
        )
        .unwrap();
        assert!(old.revalidate().is_err());
        assert!(update_private_team_record(
            &selector,
            |snapshot| {
                if snapshot.bytes() != Some(b"intent-v1") {
                    return Err("old state changed".into());
                }
                Ok(FileUpdate::write_text("state-v3".into(), 0o600))
            },
            || Ok(())
        )
        .is_err());
        assert_eq!(
            selector.capture_current().unwrap().private_bytes(),
            Some(b"state-v2".as_slice())
        );
        assert_eq!(
            sibling.capture_current().unwrap().private_bytes(),
            Some(b"sibling".as_slice())
        );
        assert!(!tirith_core::policy::config_dir()
            .unwrap()
            .join("team-policy/connection.json")
            .exists());
    }
    #[test]
    fn enrollment_refusal_and_oversize_rollout_have_no_persistent_effect() {
        let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        assert!(update_private_team_record(
            &TeamRecord::Enrollment,
            |_| Ok(FileUpdate::write_text("intent".into(), 0o600)),
            || Err("fresh authorization refused".into())
        )
        .is_err());
        let selector = TeamRecord::Rollout(Id::new());
        assert!(update_private_team_record(
            &selector,
            |_| Ok(FileUpdate::write_text(
                "x".repeat(selector.cap() + 1),
                0o600
            )),
            || Ok(())
        )
        .is_err());
        assert!(!tirith_core::policy::config_dir()
            .unwrap()
            .join("team-policy")
            .exists());
    }
}
