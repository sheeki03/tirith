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

    /// Hook scripts must become executable in the same atomic publication,
    /// rather than through a later chmod of the live path.
    #[cfg(unix)]
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
}
impl TransactionOptions {
    fn ordinary(dry_run: bool) -> Self {
        Self {
            dry_run,
            lock_timeout: SETUP_LOCK_TIMEOUT,
            read_cap: MAX_SETUP_FILE_BYTES,
            quiet: false,
            retain_artifacts: true,
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
