use super::*;
use flate2::{write::GzEncoder, Compression};
use std::io::Write as _;

pub(super) const MANIFEST: &[u8] = br#"{"name":"leaf-data","version":"1.2.3"}"#;
const JS: &[u8] = b"module.exports = () => 'inert data only';\n";
fn append(tar: &mut Vec<u8>, name: &str, body: &[u8], mode: u32) {
    let mut header = [0u8; 512];
    assert!(name.len() <= 100);
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", body.len()).as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].fill(b' ');
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let sum: usize = header.iter().map(|b| usize::from(*b)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    tar.extend_from_slice(&header);
    tar.extend_from_slice(body);
    tar.resize(tar.len() + (512 - body.len() % 512) % 512, 0);
}
fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}
fn tar(manifest: &[u8], files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = Vec::new();
    append(&mut tar, "package/package.json", manifest, 0o644);
    for (name, body) in files {
        append(&mut tar, name, body, 0o755);
    }
    tar.resize(tar.len() + 1024, 0);
    tar
}
pub(super) fn artifact(
    root: &Path,
    manifest: &[u8],
    files: &[(&str, &[u8])],
) -> VerifiedNpmArtifact {
    let path = root.join(format!("{}.tgz", uuid::Uuid::new_v4()));
    std::fs::write(&path, gzip(&tar(manifest, files))).unwrap();
    VerifiedNpmArtifact::open(&path).unwrap()
}
#[cfg(unix)]
pub(super) fn policy() -> EffectivePolicySnapshot {
    EffectivePolicySnapshot::resolve(None, crate::policy_snapshot::ResolutionMode::Runtime)
}
#[cfg(unix)]
pub(super) fn plan(root: &Path, policy: &EffectivePolicySnapshot) -> MaterializationPlan {
    MaterializationPlan::prepare_with_source(
        &uuid::Uuid::new_v4().to_string(),
        vec![artifact(root, MANIFEST, &[("package/index.js", JS)])],
        NewNpmDestination::capture(&root.join("installed")).unwrap(),
        policy,
        MaterializationThreatSource::fixture_empty(),
    )
    .unwrap()
}
#[cfg(unix)]
fn permit(plan: &MaterializationPlan) -> TaskBoundaryPermit<LocalPackageMaterializationBoundary> {
    TaskBoundaryPermit::for_test_with_deadline(
        &plan.operation(),
        Utc::now() + chrono::Duration::minutes(5),
    )
}

#[test]
fn retained_payload_matches_complete_parser_inventory_and_exact_raw_bytes() {
    let compressed = gzip(&tar(MANIFEST, &[("package/index.js", JS)]));
    let (inspection, payload) =
        npm_archive::capture_npm_payload(&compressed, &NpmLimits::default());
    let payload = payload.unwrap();
    assert!(inspection.coverage.archive_complete && inspection.coverage.metadata_complete);
    let entries: Vec<_> = payload.members().collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].bytes, MANIFEST);
    assert_eq!(entries[1].bytes, JS);
    for (member, file) in entries.iter().zip(inspection.files) {
        assert_eq!(member.path, file.path);
        assert_eq!(digest(member.bytes), file.sha256);
    }
}
#[test]
fn no_payload_escapes_late_tar_duplicate_gzip_or_checksum_refusal() {
    let good = tar(MANIFEST, &[("package/index.js", JS)]);
    let mut duplicate = good[..good.len() - 1024].to_vec();
    append(
        &mut duplicate,
        "package/index.js",
        b"late replacement",
        0o644,
    );
    duplicate.resize(duplicate.len() + 1024, 0);
    let mut late = good.clone();
    let n = late.len();
    late[n - 1] = 1;
    let mut trailer = gzip(&good);
    let n = trailer.len();
    trailer[n - 8] ^= 1;
    let mut concatenated = gzip(&good);
    concatenated.extend_from_slice(&gzip(&good));
    for compressed in [gzip(&duplicate), gzip(&late), trailer, concatenated] {
        let (inspection, payload) =
            npm_archive::capture_npm_payload(&compressed, &NpmLimits::default());
        assert_eq!(inspection.archive_state, NpmArchiveState::Refused);
        assert!(payload.is_none());
        assert!(inspection.files.is_empty());
    }
}
#[test]
fn strict_script_build_and_entrypoint_declarations_refuse_but_ordinary_js_remains_data() {
    let root = tempfile::tempdir().unwrap();
    for (key, value) in [
        ("scripts", serde_json::json!({"postinstall":"echo never"})),
        ("scripts", serde_json::json!({"test":""})),
        ("scripts", Value::Null),
        ("scripts", serde_json::json!([])),
        ("bin", serde_json::json!("index.js")),
        ("man", serde_json::json!(["manual.1"])),
        ("gypfile", Value::Bool(true)),
        ("gypfile", serde_json::json!("false")),
    ] {
        let mut manifest: Value = serde_json::from_slice(MANIFEST).unwrap();
        manifest[key] = value;
        // Existing execution leaf normalization is intentionally not weakened.
        // If it refuses before the stricter new contract, that is also refusal.
        let path = root.path().join("refusal.tgz");
        std::fs::write(
            &path,
            gzip(&tar(&serde_json::to_vec(&manifest).unwrap(), &[])),
        )
        .unwrap();
        if let Ok(artifact) = VerifiedNpmArtifact::open(&path) {
            let payload = validated_payload(&artifact).unwrap();
            assert_eq!(
                admit_contract(&artifact, &payload),
                Err(Refusal::ExecutionDeclaration),
                "{key}"
            );
        }
    }
    let artifact = artifact(root.path(), MANIFEST, &[("package/index.js", JS)]);
    let payload = validated_payload(&artifact).unwrap();
    admit_contract(&artifact, &payload).unwrap();
    assert!(artifact.inspection.files.iter().any(|m| m.executable));
}
#[test]
fn recognized_native_wasm_and_implicit_build_members_refuse() {
    let root = tempfile::tempdir().unwrap();
    for (path, bytes, want) in [
        (
            "package/addon.node",
            b"data".as_slice(),
            Refusal::NativePayload,
        ),
        (
            "package/hidden",
            b"\x7fELFfake".as_slice(),
            Refusal::NativePayload,
        ),
        (
            "package/data.wasm",
            b"\0asmdata".as_slice(),
            Refusal::NativePayload,
        ),
        (
            "package/binding.gyp",
            b"{}".as_slice(),
            Refusal::ExecutionDeclaration,
        ),
    ] {
        let artifact = artifact(root.path(), MANIFEST, &[(path, bytes)]);
        let payload = validated_payload(&artifact).unwrap();
        assert_eq!(admit_contract(&artifact, &payload), Err(want));
    }
}
#[test]
fn forged_inspection_inventory_cannot_supply_payload() {
    let root = tempfile::tempdir().unwrap();
    let mut artifact = artifact(root.path(), MANIFEST, &[("package/index.js", JS)]);
    artifact.inspection.files[1].sha256 = digest(b"forged");
    assert!(matches!(
        validated_payload(&artifact),
        Err(Refusal::ArchiveUnsupported)
    ));
}
#[test]
fn implicit_directories_count_towards_cap_and_portable_aliases_refuse() {
    let mut expected = BTreeMap::new();
    let entry = ExpectedEntry {
        directory: false,
        size: 0,
        sha256: digest(b""),
        mode: 0o644,
    };
    add_expected(&mut expected, "node_modules/leaf/A/index.js", entry.clone()).unwrap();
    assert_eq!(expected.len(), 4);
    assert_eq!(
        add_expected(&mut expected, "node_modules/leaf/a/other.js", entry.clone()),
        Err(Refusal::ArchiveUnsupported)
    );
    let mut expected = BTreeMap::new();
    for n in 0..(MAX_ENTRIES - 2) {
        add_expected(
            &mut expected,
            &format!("node_modules/leaf/f{n}"),
            entry.clone(),
        )
        .unwrap();
    }
    assert_eq!(expected.len(), MAX_ENTRIES);
    assert_eq!(
        add_expected(&mut expected, "node_modules/leaf/overflow", entry),
        Err(Refusal::ResourceLimit)
    );
}
#[cfg(unix)]
#[test]
fn canonical_nonnil_uuid_only_and_source_drift_precede_authorization() {
    let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
    let root = tempfile::tempdir().unwrap();
    let snapshot = policy();
    for id in [
        "00000000-0000-0000-0000-000000000000",
        "AAAAAAAA-AAAA-4AAA-AAAA-AAAAAAAAAAAA",
        "aaaaaaaaaaaa4aaaaaaaaaaaaaaaaaaa",
    ] {
        let result = MaterializationPlan::prepare_with_source(
            id,
            vec![artifact(root.path(), MANIFEST, &[])],
            NewNpmDestination::capture(&root.path().join("installed")).unwrap(),
            &snapshot,
            MaterializationThreatSource::fixture_empty(),
        );
        assert!(matches!(result, Err(Refusal::InvalidOperationId)));
    }
    let plan = plan(root.path(), &snapshot);
    let mut changed = plan.artifacts[0].source.try_clone().unwrap();
    // Source is retained read-only. Mutate only this explicit test-owned path.
    let source = std::fs::read_dir(root.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            File::open(p).ok().and_then(|f| file_identity(&f).ok()) == file_identity(&changed).ok()
        })
        .unwrap();
    let mut bytes = std::fs::read(&source).unwrap();
    bytes[0] ^= 1;
    std::fs::write(source, bytes).unwrap();
    changed.seek(SeekFrom::Start(0)).unwrap();
    assert!(matches!(
        plan.authorize(&snapshot, permit(&plan)),
        Err(Refusal::InputChanged)
    ));
    assert!(!root.path().join(plan.journal_component()).exists());
}
#[cfg(unix)]
#[test]
fn different_plan_permit_never_authorizes_other_target() {
    let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let snapshot = policy();
    let a = plan(first.path(), &snapshot);
    let b = plan(second.path(), &snapshot);
    assert!(matches!(
        a.authorize(&snapshot, permit(&b)),
        Err(Refusal::AuthorizationRefused)
    ));
}

#[cfg(unix)]
#[test]
fn same_reviewed_commitment_cannot_reuse_another_live_plan_permit_or_publish_private_digest() {
    let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
    let root = tempfile::tempdir().unwrap();
    let snapshot = policy();
    let id = uuid::Uuid::new_v4().to_string();
    let make = || {
        MaterializationPlan::prepare_with_source(
            &id,
            vec![artifact(root.path(), MANIFEST, &[])],
            NewNpmDestination::capture(&root.path().join("installed")).unwrap(),
            &snapshot,
            MaterializationThreatSource::fixture_empty(),
        )
        .unwrap()
    };
    let a = make();
    let b = make();
    assert_eq!(a.summary.public_plan_digest, b.summary.public_plan_digest);
    assert!(matches!(
        a.authorize(&snapshot, permit(&b)),
        Err(Refusal::AuthorizationRefused)
    ));
    let public = serde_json::to_string(a.summary()).unwrap();
    assert!(!public.contains(&a.private_digest));
    assert!(!public.contains("private_plan_digest"));
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    fn directory(path: &Path) -> File {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .unwrap()
    }
    fn writer<'a>(
        plan: &'a MaterializationPlan,
        snapshot: &'a EffectivePolicySnapshot,
    ) -> MaterializationWriter<'a> {
        let mut authorized = plan.authorize(snapshot, permit(plan)).unwrap();
        let proof = authorized.checkpoint_authorization().unwrap();
        proof.revalidate().unwrap();
        assert!(authorized.checkpoint_authorization().is_err());
        let journal = plan
            .destination
            .parent
            .path()
            .join(plan.journal_component());
        let target = journal.join(STAGING_COMPONENT);
        std::fs::create_dir(&journal).unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        let result = authorized
            .writer(directory(&journal), directory(&target))
            .unwrap();
        assert!(authorized
            .writer(directory(&journal), directory(&target))
            .is_err());
        result
    }
    fn private(plan: &MaterializationPlan) -> PathBuf {
        plan.destination
            .parent
            .path()
            .join(plan.journal_component())
            .join(STAGING_COMPONENT)
    }
    #[test]
    fn actual_exclusive_writer_preserves_raw_bytes_strips_execute_and_observes_publication() {
        let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let snapshot = policy();
        let plan = plan(root.path(), &snapshot);
        let mut writer = writer(&plan, &snapshot);
        writer.populate(&AtomicBool::new(false)).unwrap();
        let leaf = private(&plan).join("node_modules/leaf-data/index.js");
        assert_eq!(std::fs::read(&leaf).unwrap(), JS);
        assert_eq!(std::fs::metadata(&leaf).unwrap().mode() & 0o7777, 0o644);
        let evidence = writer.verify().unwrap();
        assert!(!evidence.published());
        assert!(!evidence.summary().package_code_executed);
        evidence.revalidate().unwrap();
        writer.begin_publication().unwrap();
        // Checkpoint's no-replace implementation is separately qualified; this
        // unit exercises only the core's before/after observed-root contract.
        std::fs::rename(private(&plan), plan.target_path()).unwrap();
        writer.confirm_published().unwrap();
        assert!(writer.verify().unwrap().published());
        assert_eq!(writer.cleanup(), Err(Refusal::RecoveryRequired));
        assert_eq!(
            std::fs::read(plan.target_path().join("node_modules/leaf-data/index.js")).unwrap(),
            JS
        );
    }
    #[test]
    fn cancellation_and_complete_private_cleanup_are_explicit_idempotent_and_no_replay() {
        let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let snapshot = policy();
        let plan = plan(root.path(), &snapshot);
        let mut writer = writer(&plan, &snapshot);
        assert_eq!(
            writer.populate(&AtomicBool::new(true)),
            Err(Refusal::Cancelled)
        );
        assert_eq!(
            writer.populate(&AtomicBool::new(false)),
            Err(Refusal::StateConflict)
        );
        writer.cleanup().unwrap();
        writer.cleanup().unwrap();
        assert_eq!(std::fs::read_dir(private(&plan)).unwrap().count(), 0);
        let root2 = tempfile::tempdir().unwrap();
        let plan2 = super::plan(root2.path(), &snapshot);
        let mut writer2 = self::writer(&plan2, &snapshot);
        writer2.populate(&AtomicBool::new(false)).unwrap();
        writer2.cleanup().unwrap();
        assert_eq!(std::fs::read_dir(private(&plan2)).unwrap().count(), 0);
    }
    #[test]
    fn unknown_or_edited_objects_preserve_entire_tree_including_owned_siblings() {
        let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        for edit in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let snapshot = policy();
            let plan = plan(root.path(), &snapshot);
            let mut writer = writer(&plan, &snapshot);
            writer.populate(&AtomicBool::new(false)).unwrap();
            let target = private(&plan);
            let path = if edit {
                target.join("node_modules/leaf-data/index.js")
            } else {
                target.join("foreign")
            };
            std::fs::write(&path, b"user change").unwrap();
            assert!(writer.cleanup().is_err());
            assert_eq!(std::fs::read(&path).unwrap(), b"user change");
            assert_eq!(
                std::fs::read(target.join("node_modules/leaf-data/package.json")).unwrap(),
                MANIFEST
            );
            drop(writer);
            assert!(path.exists(), "Drop must never delete recovery data");
        }
    }
    #[test]
    fn replacements_links_and_hardlinks_never_become_cleanup_authority() {
        let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        for kind in ["symlink", "hardlink", "replacement"] {
            let root = tempfile::tempdir().unwrap();
            let snapshot = policy();
            let plan = plan(root.path(), &snapshot);
            let mut writer = writer(&plan, &snapshot);
            writer.populate(&AtomicBool::new(false)).unwrap();
            let leaf = private(&plan).join("node_modules/leaf-data/index.js");
            let outside = root.path().join("outside");
            std::fs::write(&outside, b"preserve").unwrap();
            if kind == "hardlink" {
                std::fs::hard_link(&leaf, root.path().join("extra-link")).unwrap();
            } else {
                std::fs::remove_file(&leaf).unwrap();
                if kind == "symlink" {
                    std::os::unix::fs::symlink(&outside, &leaf).unwrap();
                } else {
                    std::fs::write(&leaf, JS).unwrap();
                }
            }
            assert!(writer.verify().is_err());
            assert!(writer.cleanup().is_err());
            assert!(leaf.symlink_metadata().is_ok());
            assert_eq!(std::fs::read(&outside).unwrap(), b"preserve");
        }
    }
    #[test]
    fn wrong_staging_handle_refuses_without_payload_writes() {
        let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let snapshot = policy();
        let plan = plan(root.path(), &snapshot);
        let mut authorization = plan.authorize(&snapshot, permit(&plan)).unwrap();
        authorization.checkpoint_authorization().unwrap();
        let other = tempfile::tempdir().unwrap();
        assert!(authorization
            .writer(directory(other.path()), directory(other.path()))
            .is_err());
        assert_eq!(std::fs::read_dir(other.path()).unwrap().count(), 0);
    }
}

#[cfg(unix)]
#[test]
fn real_receiptless_default_gate_permit_cannot_bypass_resolved_required_provenance() {
    let state = tirith_test_support::GlobalStateGuard::new().unwrap();
    let policy_root = state.roots().policy.join(".tirith");
    std::fs::create_dir_all(&policy_root).unwrap();
    std::fs::write(
        policy_root.join("policy.yaml"),
        "task_gate:\n  mode: enforce\n  effects_requiring_verified_provenance: [package_install]\n",
    )
    .unwrap();
    let snapshot = policy();
    assert_eq!(
        snapshot.policy.task_gate.mode,
        crate::web3_policy::TaskGateMode::Enforce
    );
    let root = tempfile::tempdir().unwrap();
    let plan = plan(root.path(), &snapshot);
    let pending = crate::task_boundary::prepare_locally_derived_boundary_authorization::<
        LocalPackageMaterializationBoundary,
    >(
        &plan.operation(),
        &crate::web3_policy::TaskGatePolicy::default(),
        &crate::task_analysis::TaskAnalysisContext::default(),
    )
    .unwrap();
    let wrong_gate = pending.consume_default(Utc::now()).unwrap();
    assert!(wrong_gate.binds_operation(&plan.operation()));
    assert!(matches!(
        plan.authorize(&snapshot, wrong_gate),
        Err(Refusal::AuthorizationRefused)
    ));
    assert!(
        crate::task_boundary::prepare_locally_derived_boundary_authorization::<
            LocalPackageMaterializationBoundary,
        >(
            &plan.operation(),
            &snapshot.policy.task_gate,
            &crate::task_analysis::TaskAnalysisContext::default()
        )
        .is_err()
    );
}
#[cfg(unix)]
#[test]
fn mutated_resolved_policy_and_matching_posture_cannot_mint_materialization_plan() {
    let _state = tirith_test_support::GlobalStateGuard::new().unwrap();
    let root = tempfile::tempdir().unwrap();
    let mut snapshot = policy();
    snapshot
        .policy
        .action_overrides
        .insert("artifact_known_malicious".into(), "allow".into());
    snapshot.policy_posture_sha256 = snapshot.policy.enforcement_projection_hash();
    assert!(matches!(
        MaterializationPlan::prepare_with_source(
            &uuid::Uuid::new_v4().to_string(),
            vec![artifact(root.path(), MANIFEST, &[])],
            NewNpmDestination::capture(&root.path().join("installed")).unwrap(),
            &snapshot,
            MaterializationThreatSource::fixture_empty()
        ),
        Err(Refusal::PolicyChanged)
    ));
}
