//! Explicit lower-layer transaction qualification, never public CLI admission.
//! Ordinary tests exercise refusal only. The ignored ARM test requires an outer
//! owner to provision all inputs and retain every case after success or failure.

use std::ffi::OsString;
use std::path::{Component, PathBuf};

#[derive(Debug)]
#[cfg_attr(
    not(all(
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu",
        target_endian = "little",
        target_pointer_width = "64"
    )),
    allow(dead_code)
)]
struct NativeInputs {
    root: PathBuf,
    source: PathBuf,
    source_sha256: String,
    launcher: PathBuf,
    launcher_sha256: String,
    audit_public_sha256: String,
}

impl NativeInputs {
    fn from_lookup(mut lookup: impl FnMut(&str) -> Option<OsString>) -> Result<Self, String> {
        fn path(value: Option<OsString>, name: &str) -> Result<PathBuf, String> {
            let path = PathBuf::from(value.ok_or_else(|| format!("explicit {name} required"))?);
            if !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, Component::ParentDir))
            {
                return Err(format!("{name} must be absolute without parent traversal"));
            }
            Ok(path)
        }
        fn digest(value: Option<OsString>, name: &str) -> Result<String, String> {
            let value = value
                .and_then(|value| value.into_string().ok())
                .ok_or_else(|| format!("explicit {name} required"))?;
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(format!("{name} must be a lowercase SHA-256"));
            }
            Ok(value)
        }
        Ok(Self {
            root: path(lookup("TIRITH_NPM_NATIVE_FIXTURE_ROOT"), "fixture root")?,
            source: path(lookup("TIRITH_NPM_NATIVE_THREATDB"), "threat source")?,
            source_sha256: digest(
                lookup("TIRITH_NPM_NATIVE_THREATDB_SHA256"),
                "threat source pin",
            )?,
            launcher: path(lookup("TIRITH_NPM_NATIVE_LAUNCHER"), "captured launcher")?,
            launcher_sha256: digest(
                lookup("TIRITH_NPM_NATIVE_LAUNCHER_SHA256"),
                "captured launcher pin",
            )?,
            audit_public_sha256: digest(
                lookup("TIRITH_NPM_NATIVE_AUDIT_PUBLIC_SHA256"),
                "audit public key pin",
            )?,
        })
    }
}

fn verified_v2(bytes: &[u8], expected: &str) -> Result<tirith_core::threatdb::ThreatDb, String> {
    use sha2::{Digest as _, Sha256};
    if bytes.len() > 64 * 1024 * 1024 || format!("{:x}", Sha256::digest(bytes)) != expected {
        return Err("published threat source exceeds its bound or changed".into());
    }
    let db = tirith_core::threatdb::ThreatDb::from_bytes(bytes.to_vec(), 0)
        .map_err(|error| format!("threat source parser refused: {error}"))?;
    db.verify_signature()
        .map_err(|error| format!("embedded signature refused: {error}"))?;
    if db.stats().format_version != 2 {
        return Err("a trusted signed v2 is required; v1 cannot qualify installation".into());
    }
    Ok(db)
}

#[test]
fn native_transaction_prerequisites_have_no_ambient_defaults() {
    let names = [
        "TIRITH_NPM_NATIVE_FIXTURE_ROOT",
        "TIRITH_NPM_NATIVE_THREATDB",
        "TIRITH_NPM_NATIVE_THREATDB_SHA256",
        "TIRITH_NPM_NATIVE_LAUNCHER",
        "TIRITH_NPM_NATIVE_LAUNCHER_SHA256",
        "TIRITH_NPM_NATIVE_AUDIT_PUBLIC_SHA256",
    ];
    let valid = |name: &str| {
        if name.ends_with("SHA256") {
            Some("a".repeat(64).into())
        } else {
            Some(
                std::env::current_dir()
                    .unwrap()
                    .join("explicit-fixture")
                    .into_os_string(),
            )
        }
    };
    assert!(NativeInputs::from_lookup(valid).is_ok());
    assert!(NativeInputs::from_lookup(|_| None).is_err());
    for missing in names {
        assert!(
            NativeInputs::from_lookup(|name| {
                if name == missing {
                    None
                } else {
                    valid(name)
                }
            })
            .is_err(),
            "missing {missing} must refuse before fixture or transaction effects"
        );
    }
}

#[test]
fn native_transaction_prerequisites_reject_relative_paths_and_unpinned_bytes() {
    for bad in ["", "not-a-digest", &"A".repeat(64)] {
        let error = NativeInputs::from_lookup(|name| {
            if name.ends_with("SHA256") {
                Some(bad.into())
            } else {
                Some(
                    std::env::current_dir()
                        .unwrap()
                        .join("explicit-fixture")
                        .into_os_string(),
                )
            }
        })
        .unwrap_err();
        assert!(error.contains("SHA-256"), "unexpected refusal: {error}");
    }
    assert!(NativeInputs::from_lookup(|name| {
        if name.ends_with("SHA256") {
            Some("a".repeat(64).into())
        } else {
            Some("relative-fixture".into())
        }
    })
    .is_err());
}

#[test]
fn native_transaction_feed_admission_never_promotes_an_unsigned_fixture() {
    use sha2::{Digest as _, Sha256};
    // This is a negative parser/signature control, never positive feed evidence.
    let fixture = include_bytes!("../../../../tests/fixtures/test-threatdb.dat");
    assert!(verified_v2(fixture, &"0".repeat(64)).is_err());
    assert!(verified_v2(fixture, &format!("{:x}", Sha256::digest(fixture))).is_err());
    assert!(verified_v2(&[], &format!("{:x}", Sha256::digest([]))).is_err());
}

const SCRIPT_CASES: [&str; 2] = ["lifecycle-sentinels", "implicit-gyp-sentinel"];
const LIFECYCLE_EVENTS: [&str; 7] = [
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
];

fn script_archive(case: &str) -> Vec<u8> {
    use std::io::Write as _;
    let mut files: Vec<(&str, Vec<u8>)> = Vec::new();
    let manifest = match case {
        "lifecycle-sentinels" => {
            let scripts: serde_json::Map<String, serde_json::Value> = LIFECYCLE_EVENTS
                .iter()
                .map(|event| {
                    (
                        event.to_string(),
                        format!("node sentinel.cjs {event}").into(),
                    )
                })
                .collect();
            files.push(("package/sentinel.cjs", br#"'use strict';
require('fs').writeFileSync(require('path').join(__dirname, '.tirith-lifecycle-' + process.argv[2]), 'executed');
"#.to_vec()));
            serde_json::json!({"name":"tirith-native-lifecycle-sentinels","version":"1.0.0","scripts":scripts})
        }
        "implicit-gyp-sentinel" => {
            // No explicit install script: npm must discover binding.gyp itself.
            // If its implicit build runs, the action writes inside this package,
            // not to a path whose denial could hide an executed script.
            files.push((
                "package/binding.gyp",
                serde_json::to_vec(&serde_json::json!({
                    "targets":[{"target_name":"sentinel","type":"none","actions":[{
                        "action_name":"tirith_implicit_gyp_sentinel","inputs":[],
                        "outputs":["<(module_root_dir)/.tirith-implicit-gyp-sentinel"],
                        "action":["/usr/local/bin/node","<(module_root_dir)/implicit-gyp.cjs"]
                    }]}]
                }))
                .unwrap(),
            ));
            files.push(("package/implicit-gyp.cjs", br#"'use strict';
require('fs').writeFileSync(require('path').join(__dirname, '.tirith-implicit-gyp-sentinel'), 'executed');
"#.to_vec()));
            serde_json::json!({"name":"tirith-native-implicit-gyp-sentinel","version":"1.0.0"})
        }
        _ => panic!("unknown bounded script fixture"),
    };
    files.push((
        "package/package.json",
        serde_json::to_vec(&manifest).unwrap(),
    ));
    files.sort_by_key(|(name, _)| *name);
    let mut tar = Vec::new();
    for (name, bytes) in files {
        assert!(name.len() < 100 && bytes.len() <= 8192);
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        for (start, width, value) in [
            (100, 8, 0o644),
            (108, 8, 0),
            (116, 8, 0),
            (124, 12, bytes.len()),
            (136, 12, 0),
        ] {
            let encoded = format!("{value:0width$o}\0", width = width - 1);
            assert_eq!(encoded.len(), width);
            header[start..start + width].copy_from_slice(encoded.as_bytes());
        }
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: usize = header.iter().map(|byte| usize::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        tar.extend_from_slice(&header);
        tar.extend_from_slice(&bytes);
        tar.resize(tar.len().next_multiple_of(512), 0);
    }
    tar.resize(tar.len() + 1024, 0);
    assert!(tar.len() <= 32768);
    let mut encoder = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar).unwrap();
    let archive = encoder.finish().unwrap();
    assert!(archive.len() <= 65536);
    archive
}

#[test]
fn native_transaction_script_archives_are_deterministic_admitted_leaf_contracts() {
    for name in SCRIPT_CASES {
        let bytes = script_archive(name);
        assert_eq!(bytes, script_archive(name));
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("leaf.tgz");
        std::fs::write(&path, bytes).unwrap();
        let captured =
            tirith_core::artifact::npm_install::VerifiedNpmArtifact::open(&path).unwrap();
        captured.revalidate().unwrap();
        let inspection = captured.inspection();
        assert!(inspection.coverage.archive_complete && inspection.coverage.metadata_complete);
        let members: Vec<_> = inspection
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect();
        assert_eq!(
            members,
            if name == "lifecycle-sentinels" {
                vec!["package/package.json", "package/sentinel.cjs"]
            } else {
                vec![
                    "package/binding.gyp",
                    "package/implicit-gyp.cjs",
                    "package/package.json",
                ]
            }
        );
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    PrivateMilestone,
    TargetPublished,
}

#[cfg(target_os = "linux")]
std::thread_local! {
    static INTERRUPT_AT: std::cell::Cell<Option<Phase>> = const { std::cell::Cell::new(None) };
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct ObservedInterruption(Phase);

#[cfg(target_os = "linux")]
pub(super) fn observe_phase(phase: Phase) {
    INTERRUPT_AT.with(|selected| {
        if selected.get() == Some(phase) {
            selected.set(None);
            std::panic::panic_any(ObservedInterruption(phase));
        }
    });
}

#[cfg(target_os = "linux")]
#[test]
fn native_transaction_interruption_is_explicit_and_consumed_once() {
    observe_phase(Phase::PrivateMilestone);
    INTERRUPT_AT.with(|slot| slot.set(Some(Phase::TargetPublished)));
    observe_phase(Phase::PrivateMilestone);
    let failure = std::panic::catch_unwind(|| observe_phase(Phase::TargetPublished)).unwrap_err();
    assert_eq!(
        failure
            .downcast_ref::<ObservedInterruption>()
            .map(|value| value.0),
        Some(Phase::TargetPublished)
    );
    observe_phase(Phase::TargetPublished);
}

#[cfg(all(
    target_os = "linux",
    target_arch = "aarch64",
    target_env = "gnu",
    target_endian = "little",
    target_pointer_width = "64"
))]
mod native {
    use super::*;
    use crate::cli::{
        capsule::npm_native_tests::install_launcher,
        npm_install_recovery::{preflight_milestone_signing, NpmRecoveryStore},
        package_checkpoint::{
            materialization_store::{OperationStore, RecordKind},
            InstallTargetBinding,
        },
        test_harness::{CwdGuard, EnvGuard, ENV_LOCK},
    };
    use sha2::{Digest as _, Sha256};
    use std::{io::Read as _, os::unix::fs::MetadataExt as _, path::Path};
    use tirith_core::{
        artifact::npm_install::{
            tools::QualifiedNpmToolClosure, NewNpmDestination, NpmInstallPlan, NpmInstallRefusal,
            VerifiedNpmArtifact,
        },
        policy::BoundedRuntimePolicyInputs,
        policy_snapshot::EffectivePolicySnapshot,
        task_boundary::{self, PackageInstallPreparationBoundary},
    };

    const PRODUCTION_KEY_SHA256: &str =
        "ee65a4cf011b55b19a8bbc6cc64d6b46dbcc5a2e35a690f8cf6f511f6d993db9";
    const COMPILED_THREAT_KEY: &[u8; 32] =
        include_bytes!("../../../tirith-core/assets/keys/threatdb-verify.pub");
    const ARCHIVE: &[u8] =
        include_bytes!("../../../tirith-core/tests/fixtures/npm/npm-11.19.0-portable-pax.tgz");
    const CASES: [&str; 4] = [
        "transaction-success",
        "transaction-cancel-before-effects",
        "transaction-private-unwind",
        "transaction-published-unwind",
    ];

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
    fn private_directory(path: &Path) {
        assert_eq!(path.canonicalize().unwrap(), path);
        let metadata = path.symlink_metadata().unwrap();
        assert!(
            metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0
        );
    }
    fn bounded_bytes(path: &Path, cap: usize) -> Vec<u8> {
        let mut held = tirith_core::util::open_read_no_follow_capped(path, cap as u64).unwrap();
        let before = held.metadata().unwrap();
        let mut bytes = Vec::new();
        (&mut held)
            .take(cap as u64 + 1)
            .read_to_end(&mut bytes)
            .unwrap();
        let after = held.metadata().unwrap();
        assert!(bytes.len() <= cap);
        assert_eq!(
            (
                before.dev(),
                before.ino(),
                before.size(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec()
            ),
            (
                after.dev(),
                after.ino(),
                after.size(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec()
            )
        );
        bytes
    }
    fn admit_case(root: &Path, name: &str, inputs: &NativeInputs) -> PathBuf {
        let case = root.join(name);
        private_directory(&case);
        for directory in [
            "home",
            "data",
            "cache",
            "config",
            "state",
            "tmp",
            "workspace",
        ] {
            private_directory(&case.join(directory));
        }
        for empty in ["home", "cache", "state", "tmp", "workspace"] {
            assert!(
                case.join(empty).read_dir().unwrap().next().is_none(),
                "outer owner must provision a fresh case"
            );
        }
        private_directory(&case.join("config/tirith"));
        let names: Vec<_> = case
            .join("data")
            .read_dir()
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            vec![OsString::from("threatdb-v2.dat")],
            "no valid primary fallback or supplemental source may be provisioned"
        );
        assert_eq!(
            bounded_bytes(&case.join("leaf.tgz"), 1024 * 1024),
            archive_for_case(name)
        );
        assert_eq!(
            digest(&bounded_bytes(
                &case.join("data/threatdb-v2.dat"),
                64 * 1024 * 1024
            )),
            inputs.source_sha256
        );
        assert_eq!(
            digest(&bounded_bytes(
                &case.join("config/tirith/audit-signing.pub"),
                32
            )),
            inputs.audit_public_sha256
        );
        assert!(!case.join("installed").exists());
        case
    }
    fn environment(case: &Path) -> Vec<EnvGuard> {
        vec![
            EnvGuard::set("HOME", &case.join("home")),
            EnvGuard::set("XDG_DATA_HOME", &case.join("data")),
            EnvGuard::set("XDG_CONFIG_HOME", &case.join("config")),
            EnvGuard::set("XDG_CACHE_HOME", &case.join("cache")),
            EnvGuard::set("XDG_STATE_HOME", &case.join("state")),
            EnvGuard::set("TMPDIR", &case.join("tmp")),
            EnvGuard::set("TIRITH_THREATDB_PATH", &case.join("data/threatdb.dat")),
            EnvGuard::set(
                "TIRITH_THREATDB_SUPPLEMENTAL_PATH",
                &case.join("data/supplemental.dat"),
            ),
        ]
    }
    struct InterruptGuard;
    impl Drop for InterruptGuard {
        fn drop(&mut self) {
            INTERRUPT_AT.with(|slot| slot.set(None));
        }
    }

    #[test]
    #[ignore = "requires a fresh production-signed v2 feed, exact pinned ARM Node/npm and captured production launcher, preprovisioned private audit keys and four owned fresh cases"]
    fn genuine_v2_native_coordinator_publication_and_interruption() {
        assert_eq!(
            digest(COMPILED_THREAT_KEY),
            PRODUCTION_KEY_SHA256,
            "genuine-production evidence requires the original compiled key"
        );
        run_native_mechanics(
            "genuine_production_key",
            PRODUCTION_KEY_SHA256,
            false,
            false,
        );
    }

    #[test]
    #[ignore = "requires an explicitly reviewed sole-key fixture build, signed fixture v2, exact ARM tools/launcher and owned preprovisioned cases; not production-feed evidence"]
    fn fixture_authority_native_coordinator_publication_and_interruption() {
        let expected = fixture_key_pin();
        assert_ne!(expected, PRODUCTION_KEY_SHA256);
        assert_eq!(
            digest(COMPILED_THREAT_KEY),
            expected,
            "fixture build must contain the reviewed fixture key"
        );
        run_native_mechanics("isolated_fixture_key", &expected, false, false);
    }

    #[test]
    #[ignore = "one diagnostic success case only; requires the reviewed fixture-key build and all real native transaction prerequisites"]
    fn fixture_authority_native_first_coordinator_case() {
        let expected = fixture_key_pin();
        assert_ne!(expected, PRODUCTION_KEY_SHA256);
        assert_eq!(digest(COMPILED_THREAT_KEY), expected);
        run_native_mechanics("isolated_fixture_key", &expected, false, true);
    }

    #[test]
    #[ignore = "requires the reviewed fixture-key build and exact native tools; successful real installs must suppress lifecycle and implicit binding.gyp sentinels"]
    fn fixture_authority_native_script_suppression() {
        let expected = fixture_key_pin();
        assert_ne!(expected, PRODUCTION_KEY_SHA256);
        assert_eq!(digest(COMPILED_THREAT_KEY), expected);
        run_native_mechanics("isolated_fixture_key", &expected, true, false);
    }

    fn archive_for_case(name: &str) -> Vec<u8> {
        if SCRIPT_CASES.contains(&name) {
            script_archive(name)
        } else {
            ARCHIVE.to_vec()
        }
    }

    fn fixture_key_pin() -> String {
        let expected = std::env::var("TIRITH_NPM_NATIVE_FIXTURE_PUBLIC_SHA256")
            .expect("explicit fixture public key pin");
        assert!(
            expected.len() == 64
                && expected
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        expected
    }

    fn run_native_mechanics(
        authority: &str,
        trusted_key_sha256: &str,
        script_controls: bool,
        first_case_only: bool,
    ) {
        // Resolve explicit inputs before acquiring a guard that resets ambient
        // application paths. Missing prerequisites create no transaction state.
        let inputs = NativeInputs::from_lookup(|name| std::env::var_os(name))
            .expect("explicit native prerequisites");
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "native qualification must be nonroot"
        );
        private_directory(&inputs.root);
        let published = bounded_bytes(&inputs.source, 64 * 1024 * 1024);
        let db = verified_v2(&published, &inputs.source_sha256)
            .expect("actual compiled key and format-2 source");
        let tools = QualifiedNpmToolClosure::capture()
            .expect("exact root-managed Node/npm/runtime closure");
        tools.revalidate().unwrap();
        assert!(!(script_controls && first_case_only));
        let names = if script_controls {
            &SCRIPT_CASES[..]
        } else if first_case_only {
            &CASES[..1]
        } else {
            &CASES[..]
        };
        let cases: Vec<_> = names
            .iter()
            .map(|name| admit_case(&inputs.root, name, &inputs))
            .collect();
        let _lock = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _launcher = install_launcher(&inputs.launcher, &inputs.launcher_sha256);
        // Check every provisioned signing pair before any transaction is entered.
        for case in &cases {
            let _environment = environment(case);
            preflight_milestone_signing().expect("real configured audit signing/verifying pair");
        }
        for (index, case) in cases.iter().enumerate() {
            let _environment = environment(case);
            let _cwd = CwdGuard::set(&case.join("workspace"));
            let _bounded = BoundedRuntimePolicyInputs::enter();
            let policy = EffectivePolicySnapshot::resolve_for_local_mutation(Some(
                case.join("workspace").to_str().unwrap(),
            ))
            .unwrap();
            let artifacts = [VerifiedNpmArtifact::open(&case.join("leaf.tgz")).unwrap()];
            let target = case.join("installed");
            let binding = InstallTargetBinding::bind(&target).unwrap();
            let operation_id = uuid::Uuid::new_v4().to_string();
            let plan = NpmInstallPlan::prepare(
                &operation_id,
                &artifacts,
                NewNpmDestination::capture(&target).unwrap(),
                &policy,
            )
            .expect("fresh signed-source artifact Allow and retained current authority");
            assert_eq!(plan.execution_qualification(), Ok(()));
            let permit = || {
                task_boundary::prepare_locally_derived_boundary_authorization::<
                    PackageInstallPreparationBoundary,
                >(
                    &plan.operation(),
                    &policy.policy.task_gate,
                    &tirith_core::task_analysis::TaskAnalysisContext::default(),
                )
                .unwrap()
                .consume_default_for_operation(&plan.operation(), chrono::Utc::now())
                .unwrap()
            };
            let reviewed = digest(
                tirith_core::audit::canonical_json_for_hash(&serde_json::json!({
                    "scope":"internal_native_transaction_fixture", "operation":operation_id,
                    "plan":plan.private_plan_digest(), "nonce":uuid::Uuid::new_v4().to_string()
                }))
                .as_bytes(),
            );
            // This is a bounded qualification journal, explicitly not a saved
            // public CLI intent. It excludes replay while all effect authority
            // below is freshly constructed from the real retained inputs.
            let mut journal = OperationStore::open_npm_install(&operation_id, true).unwrap();
            let intent = serde_json::to_vec(&serde_json::json!({"qualification_only":true,"operation":operation_id,"reviewed":reviewed})).unwrap();
            let started = serde_json::to_vec(&serde_json::json!({"qualification_only":true,"operation":operation_id,"started":true})).unwrap();
            journal.append(RecordKind::Intent, intent.clone()).unwrap();
            journal
                .append(RecordKind::Started, started.clone())
                .unwrap();
            let selected = match (script_controls, index) {
                (false, 2) => Some(Phase::PrivateMilestone),
                (false, 3) => Some(Phase::TargetPublished),
                _ => None,
            };
            INTERRUPT_AT.with(|slot| {
                assert!(slot.replace(selected).is_none());
            });
            let _interrupt = InterruptGuard;
            let mut checks = 0;
            let mut validate = || {
                checks += 1;
                journal.revalidate().map_err(|error| error.to_string())?;
                if journal
                    .read(RecordKind::Intent)
                    .map_err(|error| error.to_string())?
                    != Some(intent.clone())
                    || journal
                        .read(RecordKind::Started)
                        .map_err(|error| error.to_string())?
                        != Some(started.clone())
                {
                    return Err("qualification intent/start binding changed".into());
                }
                if !script_controls && index == 1 {
                    return Err("explicit qualification cancellation before effects".into());
                }
                Ok(())
            };
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                super::super::execute(
                    &plan,
                    &artifacts,
                    &policy,
                    &binding,
                    permit(),
                    true,
                    &reviewed,
                    &mut validate,
                )
            }));
            journal.revalidate().unwrap();
            assert_eq!(journal.read(RecordKind::Started).unwrap(), Some(started));
            if let Some(phase) = selected {
                let payload = outcome.expect_err("explicit post-completion interruption must fire");
                assert_eq!(
                    payload
                        .downcast_ref::<ObservedInterruption>()
                        .map(|value| value.0),
                    Some(phase)
                );
                assert_eq!(target.exists(), phase == Phase::TargetPublished);
                let mut recovery = NpmRecoveryStore::open(&operation_id, false).unwrap();
                let parent = case.metadata().unwrap();
                assert!(
                    recovery
                        .load_committed(
                            &reviewed,
                            plan.private_plan_digest(),
                            &plan.summary().public_plan_digest,
                            &target,
                            (parent.dev(), parent.ino())
                        )
                        .is_err(),
                    "partial completion never grants reconfirmation"
                );
                assert!(
                    case.read_dir().unwrap().any(|entry| entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".tirith-install-journal-")),
                    "interrupted private/public checkpoint must remain preserved"
                );
            } else if !script_controls && index == 1 {
                let failure = outcome.unwrap().unwrap_err();
                assert_eq!(failure.phase, "intent_revalidation");
                assert!(
                    failure.cleanup_confirmed
                        && !failure.target_publication_crossed
                        && !target.exists()
                );
                assert!(!case.join("state/tirith/npm-install-recovery").exists());
            } else {
                let value = outcome.unwrap().unwrap();
                assert_eq!(value["phase"], "published_verified");
                assert_eq!(value["cleanup_confirmed"], true);
                assert_eq!(value["target_publication_crossed"], true);
                if script_controls {
                    let package = target.join("node_modules").join(if index == 0 {
                        "tirith-native-lifecycle-sentinels"
                    } else {
                        "tirith-native-implicit-gyp-sentinel"
                    });
                    assert!(package.is_dir());
                    for event in LIFECYCLE_EVENTS {
                        assert!(package
                            .join(format!(".tirith-lifecycle-{event}"))
                            .symlink_metadata()
                            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound));
                    }
                    assert!(package
                        .join(".tirith-implicit-gyp-sentinel")
                        .symlink_metadata()
                        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound));
                    // Publication already required complete member/hidden-lock
                    // verification. Sentinel absence alone is never a pass.
                }
                let mut recovery = NpmRecoveryStore::open(&operation_id, false).unwrap();
                let parent = case.metadata().unwrap();
                let observation = recovery
                    .load_committed(
                        &reviewed,
                        plan.private_plan_digest(),
                        &plan.summary().public_plan_digest,
                        &target,
                        (parent.dev(), parent.ino()),
                    )
                    .unwrap();
                assert_eq!(value["private_receipt_id"], observation.private_receipt_id);
                assert_eq!(
                    value["committed_receipt_id"],
                    observation.committed_receipt_id
                );
                let captured =
                    tirith_core::artifact::npm_install::recovery::NpmPublishedRecovery::capture(
                        &operation_id,
                        &artifacts,
                        &policy,
                        &target,
                        &observation.tree,
                        (parent.dev(), parent.ino()),
                    )
                    .unwrap();
                let operation = captured.operation();
                let lease = task_boundary::prepare_locally_derived_boundary_authorization::<
                    task_boundary::LocalPackageRecoveryBoundary,
                >(
                    &operation,
                    &policy.policy.task_gate,
                    &tirith_core::task_analysis::TaskAnalysisContext::default(),
                )
                .unwrap()
                .consume_default_for_operation(&operation, chrono::Utc::now())
                .unwrap()
                .into_effect_lease_for_gate_at(
                    &operation,
                    &policy.policy.task_gate,
                    chrono::Utc::now(),
                )
                .unwrap();
                captured.revalidate().unwrap();
                lease
                    .authorize_effect_for_gate_at(
                        &operation,
                        &policy.policy.task_gate,
                        chrono::Utc::now(),
                    )
                    .unwrap();
                drop(captured);
                // A caller's later edit must refuse reconfirmation and survive.
                let sentinel = target.join("operator-change");
                std::fs::write(&sentinel, b"preserve external change").unwrap();
                assert!(
                    tirith_core::artifact::npm_install::recovery::NpmPublishedRecovery::capture(
                        &operation_id,
                        &artifacts,
                        &policy,
                        &target,
                        &observation.tree,
                        (parent.dev(), parent.ino())
                    )
                    .is_err()
                );
                assert_eq!(
                    std::fs::read(&sentinel).unwrap(),
                    b"preserve external change"
                );
            }
            assert!(checks > 0);
            println!(
                "{}",
                serde_json::json!({"control":if script_controls {"native_script_suppression"} else {"native_transaction_mechanics"}, "case":names[index],
                "authority":authority,"trusted_public_key_sha256":trusted_key_sha256,
                "production_feed_evidence":authority == "genuine_production_key",
                "threat_source_sha256":inputs.source_sha256,"threat_db_sequence":db.build_sequence(),
                "captured_launcher_sha256":inputs.launcher_sha256,"audit_public_sha256":inputs.audit_public_sha256,
                "coordinator_seam_only":true,"public_cli_execution_enabled":true,
                "public_cli_exercised":false,"native_contract_gate_qualified":true,
                "successful_install_and_exact_tree_verified":script_controls || index == 0,
                "script_sentinels_absent":script_controls,
                "archive_sha256":digest(&archive_for_case(names[index])),
                "interruption_kind":selected.map(|_| "controlled_unwind_after_authenticated_native_completion"),
                "fixture_journal_is_public_cli_intent":false,"installation_replayed":false,
                "diagnostic_first_case_only":first_case_only,
                "target_exists":target.exists(),"fixture_preserved_for_outer_owner":true})
            );
        }
        tools.revalidate().unwrap();
        assert_eq!(
            digest(&bounded_bytes(&inputs.source, 64 * 1024 * 1024)),
            inputs.source_sha256
        );
    }
    fn independently_verify_fixture(bytes: &[u8], key: &[u8; 32]) {
        assert!(bytes.len() >= 172 && bytes.len() <= 64 * 1024 * 1024);
        assert_eq!(&bytes[..8], b"TIRITHDB");
        let fingerprint: [u8; 32] = Sha256::digest(key).into();
        assert_eq!(&bytes[76..108], fingerprint.as_slice());
        let public = ed25519_dalek::VerifyingKey::from_bytes(key).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&bytes[108..172]).unwrap();
        let mut signed = bytes[..108].to_vec();
        signed.extend_from_slice(&bytes[172..]);
        public.verify_strict(&signed, &signature).unwrap();
    }

    #[test]
    #[ignore = "normal production-key native negative control using the exact reviewed fixture-signed v2 and ordinary source slots; no npm launch"]
    fn fixture_signed_v2_is_refused_by_normal_product_preparation() {
        assert_eq!(digest(COMPILED_THREAT_KEY), PRODUCTION_KEY_SHA256);
        let inputs = NativeInputs::from_lookup(|name| std::env::var_os(name))
            .expect("explicit source/fixture pins");
        let expected_fixture = fixture_key_pin();
        assert_ne!(expected_fixture, PRODUCTION_KEY_SHA256);
        assert_ne!(unsafe { libc::geteuid() }, 0);
        private_directory(&inputs.root);
        let key: [u8; 32] = bounded_bytes(&inputs.root.join("fixture-signing.pub"), 32)
            .try_into()
            .unwrap();
        assert_eq!(digest(&key), expected_fixture);
        let bytes = bounded_bytes(&inputs.source, 64 * 1024 * 1024);
        assert_eq!(digest(&bytes), inputs.source_sha256);
        independently_verify_fixture(&bytes, &key);
        let db = tirith_core::threatdb::ThreatDb::from_bytes(bytes, 0).unwrap();
        assert_eq!(db.stats().format_version, 2);
        assert!(db.stats().artifact_sha256_count > 0 && db.stats().file_sha256_count > 0);
        assert!(
            db.verify_signature().is_err(),
            "normal compiled production key must reject the independently valid fixture signature"
        );
        let case = admit_case(&inputs.root, "normal-key-negative", &inputs);
        let _lock = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _environment = environment(&case);
        let _cwd = CwdGuard::set(&case.join("workspace"));
        let _bounded = BoundedRuntimePolicyInputs::enter();
        assert_eq!(
            tirith_core::threatdb::ThreatDb::default_path_v2().unwrap(),
            case.join("data/threatdb-v2.dat")
        );
        assert!(!tirith_core::threatdb::ThreatDb::default_path()
            .unwrap()
            .exists());
        assert!(!tirith_core::threatdb::ThreatDb::supplemental_path_v2()
            .unwrap()
            .exists());
        assert!(!tirith_core::threatdb::ThreatDb::supplemental_path()
            .unwrap()
            .exists());
        let policy = EffectivePolicySnapshot::resolve_for_local_mutation(Some(
            case.join("workspace").to_str().unwrap(),
        ))
        .unwrap();
        let artifact = VerifiedNpmArtifact::open(&case.join("leaf.tgz")).unwrap();
        let target = case.join("installed");
        let destination = NewNpmDestination::capture(&target).unwrap();
        let result = NpmInstallPlan::prepare(
            &uuid::Uuid::new_v4().to_string(),
            &[artifact],
            destination,
            &policy,
        );
        assert!(
            matches!(result, Err(NpmInstallRefusal::ThreatDataUnavailable)),
            "actual source admission must refuse fixture authority"
        );
        assert!(
            !target.exists()
                && !case.join("state/tirith/npm-install-intents").exists()
                && !case.join("state/tirith/npm-install-recovery").exists()
        );
        println!(
            "{}",
            serde_json::json!({"control":"normal_product_rejects_fixture_authority","production_public_key_sha256":PRODUCTION_KEY_SHA256,
            "fixture_public_key_sha256":expected_fixture,"source_sha256":inputs.source_sha256,"independent_fixture_signature_valid":true,
            "product_signature_rejected":true,"preparation_refusal":"ThreatDataUnavailable","fallback_slots_absent":true,
            "intent_or_transaction_effects":false,"npm_launch_attempted":false,"production_feed_evidence":false})
        );
    }

    #[test]
    #[ignore = "explicit fixture generator for an owned empty native-container tmpfs root; emits no production evidence or package execution"]
    fn generate_native_transaction_fixture_inputs() {
        use tirith_core::threatdb::{Confidence, ThreatDbFormat, ThreatDbWriter, ThreatSource};
        let root = PathBuf::from(
            std::env::var_os("TIRITH_NPM_NATIVE_FIXTURE_ROOT")
                .expect("explicit empty owned fixture root"),
        );
        assert_eq!(
            unsafe { libc::geteuid() },
            65534,
            "fixture generator runs only in the reviewed nonroot native container"
        );
        private_directory(&root);
        assert!(root.read_dir().unwrap().next().is_none());
        let mut random = std::fs::File::open("/dev/urandom").unwrap();
        let mut secret = [0u8; 32];
        random.read_exact(&mut secret).unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&secret);
        let fixture_key = signer.verifying_key().to_bytes();
        assert_ne!(digest(&fixture_key), PRODUCTION_KEY_SHA256);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let sequence = u64::try_from(now.as_millis()).unwrap();
        let mut writer = ThreatDbWriter::new(now.as_secs(), sequence);
        let blocked_artifact: [u8; 32] =
            Sha256::digest(b"native-qualification-malicious-artifact-control").into();
        let blocked_member: [u8; 32] =
            Sha256::digest(b"native-qualification-malicious-member-control").into();
        writer.add_artifact_sha256(
            blocked_artifact,
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        writer.add_file_sha256(
            blocked_member,
            ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            &[],
            None,
        );
        let bytes = writer.build_format(ThreatDbFormat::V2, &signer).unwrap();
        independently_verify_fixture(&bytes, &fixture_key);
        let parsed = tirith_core::threatdb::ThreatDb::from_bytes(bytes.clone(), 0).unwrap();
        assert_eq!(parsed.stats().format_version, 2);
        assert!(parsed.check_artifact_sha256(&blocked_artifact).is_some());
        assert!(parsed
            .check_artifact_sha256(&Sha256::digest(ARCHIVE).into())
            .is_none());
        let audit_public_sha256 = provision_cases(&root, &fixture_key, &bytes);
        println!(
            "{}",
            serde_json::json!({"control":"fixture_authority_generation","production_feed_evidence":false,
            "fixture_public_key_sha256":digest(&fixture_key),"source_sha256":digest(&bytes),"source_size":bytes.len(),
            "audit_public_sha256":audit_public_sha256,"archive_sha256":digest(ARCHIVE),
            "build_timestamp":now.as_secs(),"build_sequence":sequence,"format_version":2,
            "artifact_hash_records":parsed.stats().artifact_sha256_count,"member_hash_records":parsed.stats().file_sha256_count,
            "independent_fixture_signature_valid":true,"secrets_written_only_under_fixture_root":true})
        );
    }

    #[test]
    #[ignore = "provisions fresh owned cases from exact phase-one public fixture bytes; never re-signs or refreshes the feed"]
    fn provision_native_transaction_fixture_cases() {
        let expected = fixture_key_pin();
        assert_ne!(expected, PRODUCTION_KEY_SHA256);
        assert_eq!(digest(COMPILED_THREAT_KEY), expected);
        let root = PathBuf::from(std::env::var_os("TIRITH_NPM_NATIVE_FIXTURE_ROOT").unwrap());
        let public =
            PathBuf::from(std::env::var_os("TIRITH_NPM_NATIVE_FIXTURE_PUBLIC_PATH").unwrap());
        let source = PathBuf::from(std::env::var_os("TIRITH_NPM_NATIVE_THREATDB").unwrap());
        let expected_source = std::env::var("TIRITH_NPM_NATIVE_THREATDB_SHA256").unwrap();
        assert!(public.is_absolute() && source.is_absolute());
        let key: [u8; 32] = bounded_bytes(&public, 32).try_into().unwrap();
        assert_eq!(digest(&key), expected);
        let bytes = bounded_bytes(&source, 64 * 1024 * 1024);
        independently_verify_fixture(&bytes, &key);
        let db = verified_v2(&bytes, &expected_source).unwrap();
        assert!(db.stats().artifact_sha256_count > 0 && db.stats().file_sha256_count > 0);
        let audit_public_sha256 = provision_cases(&root, &key, &bytes);
        println!(
            "{}",
            serde_json::json!({"control":"fixture_authority_case_provisioning",
            "production_feed_evidence":false,"fixture_public_key_sha256":expected,
            "source_sha256":expected_source,"source_size":bytes.len(),
            "audit_public_sha256":audit_public_sha256,"build_sequence":db.build_sequence(),
            "feed_resigned_or_refreshed":false,"secrets_written_only_under_fixture_root":true})
        );
    }

    fn provision_cases(root: &Path, fixture_key: &[u8; 32], bytes: &[u8]) -> String {
        use std::io::Write as _;
        use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
        assert_eq!(unsafe { libc::geteuid() }, 65534);
        private_directory(root);
        assert!(root.read_dir().unwrap().next().is_none());
        let mut secret = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut secret)
            .unwrap();
        let audit = ed25519_dalek::SigningKey::from_bytes(&secret);
        let write = |path: &Path, contents: &[u8]| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .unwrap();
            file.write_all(contents).unwrap();
            file.sync_all().unwrap();
        };
        write(&root.join("fixture-signing.pub"), fixture_key);
        write(&root.join("fixture-threatdb-v2.dat"), bytes);
        for name in CASES
            .into_iter()
            .chain(["normal-key-negative", "public-cli"])
            .chain(SCRIPT_CASES)
        {
            let case = root.join(name);
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&case)
                .unwrap();
            for name in [
                "home",
                "data",
                "cache",
                "config",
                "state",
                "tmp",
                "workspace",
                "config/tirith",
            ] {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(case.join(name))
                    .unwrap();
            }
            write(&case.join("leaf.tgz"), &archive_for_case(name));
            write(&case.join("data/threatdb-v2.dat"), bytes);
            write(
                &case.join("config/tirith/audit-signing.key"),
                &audit.to_bytes(),
            );
            write(
                &case.join("config/tirith/audit-signing.pub"),
                &audit.verifying_key().to_bytes(),
            );
        }
        digest(&audit.verifying_key().to_bytes())
    }
}
