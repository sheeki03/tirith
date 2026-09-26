//! Explicit native prerequisites and public signed-source admission controls.
//! These fixtures never replace a signature key or reconstruct a task/launch
//! capability from a saved report. All application paths are fresh and retained.

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use crate::cli::test_harness::{CwdGuard, EnvGuard, ENV_LOCK};
use tirith_core::artifact::npm_install::{
    NewNpmDestination, NpmInstallPlan, NpmInstallRefusal, VerifiedNpmArtifact,
};
use tirith_core::policy::BoundedRuntimePolicyInputs;
use tirith_core::policy_snapshot::EffectivePolicySnapshot;
use tirith_core::threatdb::ThreatDb;

const ARCHIVE: &[u8] =
    include_bytes!("../../../../tirith-core/tests/fixtures/npm/npm-11.19.0-portable-pax.tgz");

fn fixture_inputs() -> (PathBuf, PathBuf) {
    let root = PathBuf::from(
        std::env::var_os("TIRITH_NPM_NATIVE_FIXTURE_ROOT")
            .expect("explicit owned fixture root is required"),
    );
    let source = PathBuf::from(
        std::env::var_os("TIRITH_NPM_NATIVE_THREATDB")
            .expect("explicit published signed threat database is required"),
    );
    assert_eq!(root.canonicalize().unwrap(), root);
    let stat = root.symlink_metadata().unwrap();
    assert!(stat.is_dir() && stat.uid() == unsafe { libc::geteuid() } && stat.mode() & 0o077 == 0);
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "native fixtures run without root"
    );
    (root, source)
}

fn source_generation(file: &std::fs::File) -> [i128; 11] {
    let metadata = file.metadata().unwrap();
    [
        metadata.dev().into(),
        metadata.ino().into(),
        metadata.size().into(),
        metadata.nlink().into(),
        metadata.mode().into(),
        metadata.uid().into(),
        metadata.gid().into(),
        metadata.mtime().into(),
        metadata.mtime_nsec().into(),
        metadata.ctime().into(),
        metadata.ctime_nsec().into(),
    ]
}

fn private_directory(path: &Path) {
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

// No TempDir owns this state: a failed native observation must not implicitly
// erase the target/journal when a test unwinds. The outer owned-container runner
// retains reports and is responsible for proving its complete process cleanup.
fn install_source(root: &Path, source: &Path, case: &str) -> (PathBuf, PathBuf, ThreatDb) {
    let case = root.join(case);
    private_directory(&case);
    for name in [
        "home",
        "data",
        "cache",
        "config",
        "state",
        "tmp",
        "workspace",
    ] {
        private_directory(&case.join(name));
    }
    let mut held = tirith_core::util::open_read_no_follow_capped(source, 64 * 1024 * 1024)
        .expect("bounded no-follow published source");
    let mut bytes = Vec::new();
    use std::io::Read as _;
    let before = source_generation(&held);
    (&mut held)
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 64 * 1024 * 1024);
    assert_eq!(source_generation(&held), before);
    let db = ThreatDb::from_bytes(bytes.clone(), 0).expect("production threat source parser");
    db.verify_signature()
        .expect("embedded production signing key");
    let source_path = case.join("data/threatdb.dat");
    std::fs::write(case.join("data/threatdb-v2.dat"), &bytes).unwrap();
    std::fs::write(case.join("leaf.tgz"), ARCHIVE).unwrap();
    (case, source_path, db)
}

fn isolated_environment(case: &Path, source_path: &Path) -> Vec<EnvGuard> {
    vec![
        EnvGuard::set("HOME", &case.join("home")),
        EnvGuard::set("XDG_DATA_HOME", &case.join("data")),
        EnvGuard::set("XDG_CONFIG_HOME", &case.join("config")),
        EnvGuard::set("XDG_CACHE_HOME", &case.join("cache")),
        EnvGuard::set("XDG_STATE_HOME", &case.join("state")),
        EnvGuard::set("TMPDIR", &case.join("tmp")),
        EnvGuard::set("TIRITH_THREATDB_PATH", source_path),
    ]
}

#[test]
#[ignore = "requires an explicitly retained public production-signed v1 database and owned nonroot fixture root"]
fn actual_published_v1_is_signed_but_refused_for_npm_install() {
    let (root, source) = fixture_inputs();
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (case, source_path, db) = install_source(&root, &source, "signed-v1-refusal");
    assert_eq!(
        db.stats().format_version,
        1,
        "this control requires real v1 bytes"
    );
    let _environment = isolated_environment(&case, &source_path);
    let cwd = case.join("workspace");
    let _cwd = CwdGuard::set(&cwd);
    let _bounded = BoundedRuntimePolicyInputs::enter();
    let policy = EffectivePolicySnapshot::resolve_for_local_mutation(Some(
        cwd.to_str().expect("UTF-8 fixture cwd"),
    ))
    .unwrap();
    let artifact = VerifiedNpmArtifact::open(&case.join("leaf.tgz")).unwrap();
    let target = case.join("installed");
    let destination = NewNpmDestination::capture(&target).unwrap();
    let outcome = NpmInstallPlan::prepare(
        &uuid::Uuid::new_v4().to_string(),
        &[artifact],
        destination,
        &policy,
    );
    assert!(matches!(
        outcome,
        Err(NpmInstallRefusal::ThreatDataUnavailable)
    ));
    assert!(!target.exists());
    println!(
        "{}",
        serde_json::json!({
            "control": "actual_production_signed_v1_refused_for_npm_install",
            "signature_verified_by_product": true,
            "format_version": db.stats().format_version,
            "build_sequence": db.build_sequence(),
            "native_execution_attempted": false,
            "target_created": false,
        })
    );
}

// This is test harness plumbing, not a product setting. Only this module can
// install a launcher, and it must supply an immutable image matching the exact
// production binary captured by the outer build/ownership harness.
std::thread_local! {
    static LAUNCHER: std::cell::RefCell<Option<std::fs::File>> = const { std::cell::RefCell::new(None) };
}

pub(super) fn retained_launcher() -> Result<Option<std::fs::File>, String> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    LAUNCHER.with(|slot| {
        let slot = slot.borrow();
        let Some(source) = slot.as_ref() else {
            return Ok(None);
        };
        // Choose an unused slot above stdio atomically. Every npm/control slot
        // is already occupied before this duplicate is made. Common pre_exec
        // only clears CLOEXEC on those distinct slots; it never relocates this
        // launcher. This descriptor keeps CLOEXEC and closes at launcher exec.
        let descriptor = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if descriptor < 0 {
            return Err("cannot retain captured native fixture launcher".into());
        }
        Ok(Some(unsafe { std::fs::File::from_raw_fd(descriptor) }))
    })
}

#[cfg(target_arch = "aarch64")]
struct LauncherGuard;
#[cfg(target_arch = "aarch64")]
impl Drop for LauncherGuard {
    fn drop(&mut self) {
        LAUNCHER.with(|slot| {
            slot.borrow_mut().take();
        });
    }
}

#[cfg(target_arch = "aarch64")]
fn install_launcher(path: &Path, expected_sha256: &str) -> LauncherGuard {
    use sha2::{Digest as _, Sha256};
    use std::os::fd::{AsRawFd as _, BorrowedFd};
    use std::os::unix::fs::FileExt as _;
    assert_eq!(expected_sha256.len(), 64);
    assert!(expected_sha256
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    let program = tirith_core::trusted_child::TrustedExecutable::from_absolute(path, &[])
        .unwrap()
        .bind_content()
        .unwrap();
    program.verify_identity().unwrap();
    let descriptor = program
        .bound_launch_fd()
        .expect("sealed production launcher");
    let borrowed = unsafe { BorrowedFd::borrow_raw(descriptor) };
    let retained = std::fs::File::from(borrowed.try_clone_to_owned().unwrap());
    let size = retained.metadata().unwrap().len();
    assert!((64..=512 * 1024 * 1024).contains(&size));
    let mut header = [0u8; 64];
    retained.read_exact_at(&mut header, 0).unwrap();
    assert_eq!(&header[..6], b"\x7fELF\x02\x01");
    assert_eq!(
        u16::from_le_bytes([header[18], header[19]]),
        183,
        "native ARM64 image"
    );
    let mut hash = Sha256::new();
    let mut offset = 0;
    let mut buffer = [0u8; 65536];
    while offset < size {
        let count = buffer.len().min((size - offset) as usize);
        let actual = retained.read_at(&mut buffer[..count], offset).unwrap();
        assert!(actual > 0);
        hash.update(&buffer[..actual]);
        offset += actual as u64;
    }
    assert_eq!(format!("{:x}", hash.finalize()), expected_sha256);
    let seals = unsafe { libc::fcntl(retained.as_raw_fd(), libc::F_GET_SEALS) };
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    assert!(seals >= 0 && seals & required == required);
    LAUNCHER.with(|slot| {
        assert!(slot.borrow_mut().replace(retained).is_none());
    });
    LauncherGuard
}

#[cfg(target_arch = "aarch64")]
#[test]
#[ignore = "requires pinned ARM64 Node/npm, fresh production-signed v2 data, and a captured production launcher"]
fn genuine_signed_v2_native_leaf_completes_with_exact_output() {
    use super::BoundOutputPresentation;
    use crate::cli::package_checkpoint::{EnvironmentCheckpoint, InstallTargetBinding};
    use tirith_core::artifact::npm_install::{
        tools::QualifiedNpmToolClosure, PreparedNpmExecution,
    };
    use tirith_core::artifact::quarantine::QuarantineStore;
    use tirith_core::task_boundary::{self, PackageInstallPreparationBoundary};
    let (root, source) = fixture_inputs();
    let launcher = PathBuf::from(
        std::env::var_os("TIRITH_NPM_NATIVE_LAUNCHER")
            .expect("captured production launcher required"),
    );
    let launcher_sha256 = std::env::var("TIRITH_NPM_NATIVE_LAUNCHER_SHA256")
        .expect("captured production launcher hash required");
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let (case, source_path, db) = install_source(&root, &source, "signed-v2-native-leaf");
    assert_eq!(db.stats().format_version, 2);
    let _environment = isolated_environment(&case, &source_path);
    let cwd = case.join("workspace");
    let _cwd = CwdGuard::set(&cwd);
    let _bounded = BoundedRuntimePolicyInputs::enter();
    let policy = EffectivePolicySnapshot::resolve_for_local_mutation(Some(
        cwd.to_str().expect("UTF-8 fixture cwd"),
    ))
    .unwrap();
    let artifacts = [VerifiedNpmArtifact::open(&case.join("leaf.tgz")).unwrap()];
    let target = case.join("installed");
    let binding = InstallTargetBinding::bind(&target).unwrap();
    let destination = NewNpmDestination::capture(&target).unwrap();
    let plan = NpmInstallPlan::prepare(
        &uuid::Uuid::new_v4().to_string(),
        &artifacts,
        destination,
        &policy,
    )
    .unwrap();
    // This lower-layer qualification never enables the user-facing route.
    assert!(matches!(
        plan.execution_qualification(),
        Err(NpmInstallRefusal::NativeExecutionUnqualified)
    ));
    let operation = plan.operation();
    let permit = task_boundary::prepare_locally_derived_boundary_authorization::<
        PackageInstallPreparationBoundary,
    >(
        &operation,
        &policy.policy.task_gate,
        &tirith_core::task_analysis::TaskAnalysisContext::default(),
    )
    .unwrap()
    .consume_default_for_operation(&operation, chrono::Utc::now())
    .unwrap();
    let tools = QualifiedNpmToolClosure::capture().unwrap();
    let store = QuarantineStore::open().unwrap();
    let staged = plan.stage(&artifacts, &policy, &store, permit).unwrap();
    let mut prepared =
        PreparedNpmExecution::capture(&plan, &artifacts, &policy, staged, tools).unwrap();
    let authorization = prepared.checkpoint_authorization().unwrap();
    let mut checkpoint =
        EnvironmentCheckpoint::begin_npm_authorized(&binding, authorization).unwrap();
    let launch = checkpoint.take_authorized_launch().unwrap();
    let _launcher = install_launcher(&launcher, &launcher_sha256);
    let mut authority_checks = 0;
    let mut validate = || {
        authority_checks += 1;
        // Reinspect through the same public constructors as a fresh caller.
        // The native adapter separately revalidates its retained preparation.
        let destination = NewNpmDestination::capture(&target).map_err(|e| format!("{e:?}"))?;
        let current = NpmInstallPlan::prepare(
            &plan.summary().operation_id,
            &artifacts,
            destination,
            &policy,
        )
        .map_err(|e| format!("{e:?}"))?;
        if current.private_plan_digest() != plan.private_plan_digest() {
            return Err("fresh native fixture authority differs from reviewed preparation".into());
        }
        Ok(())
    };
    // Preserve before entering the adapter: a panic is as ambiguous as a
    // returned cleanup failure and must not trigger private-target deletion.
    checkpoint.preserve_for_recovery();
    let result = super::run_to_completion_npm_local_leaf(
        &mut prepared,
        launch,
        BoundOutputPresentation::Suppress,
        &mut validate,
    );
    let completed = result.expect("actual authenticated native success and owned-tree cleanup");
    assert!(
        authority_checks >= 2,
        "authority checked both before spawn and resume ACK"
    );
    let verified = prepared.verify_output().unwrap();
    let target_handle = std::fs::File::open(checkpoint.install_path()).unwrap();
    completed
        .matches_binding(prepared.operation_id(), &target_handle)
        .unwrap();
    assert!(completed
        .matches_binding(&uuid::Uuid::new_v4().to_string(), &target_handle)
        .is_err());
    let wrong_target = std::fs::File::open(&cwd).unwrap();
    assert!(completed
        .matches_binding(prepared.operation_id(), &wrong_target)
        .is_err());
    verified.revalidate().unwrap();
    let _receipt_evidence = verified.receipt_evidence().unwrap();
    assert!(
        !target.exists(),
        "native seam test must not publish the target"
    );
    println!(
        "{}",
        serde_json::json!({
            "control": "genuine_signed_v2_native_leaf_exact_output",
            "parent": "test_harness", "child": "captured_production_launcher",
            "production_launcher_sha256": launcher_sha256,
            "threat_db_format": db.stats().format_version,
            "threat_db_sequence": db.build_sequence(),
            "execution_exit": completed.outcome().exit_code,
            "native_completion_proof": true,
            "exact_installed_tree_verified": true,
            "publication_attempted": false,
            "user_facing_execution_qualification_enabled": false,
            "ongoing_immutability": false,
        })
    );
}
