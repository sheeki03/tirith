use super::*;

fn inspection() -> NpmInspection {
    let mut result = npm_archive::read_npm_tarball(
        include_bytes!("../../tests/fixtures/npm/npm-11.19.0-portable-pax.tgz").as_slice(),
        "fixture.tgz",
        &NpmLimits::default(),
    );
    // Tests of the private manifest parser are separate from the only public
    // VerifiedNpmArtifact constructor, which supplies its own exact inspection.
    result.artifact.name = Some("leaf-fixture".into());
    result.artifact.version = Some("1.2.3".into());
    result
}

#[test]
fn empty_graph_fields_are_captured_and_development_dependencies_are_not_selected() {
    let manifest = br#"{"name":"leaf-fixture","version":"1.2.3","dependencies":{},"optionalDependencies":{},"peerDependencies":{},"bundledDependencies":false,"workspaces":[],"devDependencies":{"test-only":"*"},"scripts":{"postinstall":"touch never-run"}}"#;
    let leaf = LeafManifest::capture(manifest, &inspection()).unwrap();
    assert_eq!(leaf.dependency_fields.len(), 5);
    assert_eq!(leaf.manifest_sha256, digest(manifest));
}

#[test]
fn every_install_affecting_nonempty_graph_or_wrong_shape_refuses() {
    for (field, value) in [
        ("dependencies", serde_json::json!({"dep":"1.0.0"})),
        ("optionalDependencies", serde_json::json!({"dep":"1.0.0"})),
        ("peerDependencies", serde_json::json!({"dep":"*"})),
        ("acceptDependencies", serde_json::json!({"dep":"*"})),
        (
            "peerDependenciesMeta",
            serde_json::json!({"dep":{"optional":true}}),
        ),
        ("overrides", serde_json::json!({"dep":"file:outside"})),
        ("resolutions", serde_json::json!({"dep":"*"})),
        ("bundleDependencies", serde_json::json!(true)),
        ("bundledDependencies", serde_json::json!(["dep"])),
        ("workspaces", serde_json::json!(["../outside"])),
        ("dependencies", Value::Null),
        ("workspaces", serde_json::json!({"packages":[]})),
    ] {
        let mut manifest = serde_json::json!({"name":"leaf-fixture","version":"1.2.3"});
        manifest[field] = value;
        assert!(
            matches!(
                LeafManifest::capture(&serde_json::to_vec(&manifest).unwrap(), &inspection()),
                Err(NpmInstallRefusal::DependencyGraphUnsupported)
            ),
            "{field}"
        );
    }
}

#[test]
fn ambiguous_metadata_embedded_packages_and_noncanonical_identity_refuse() {
    assert!(LeafManifest::capture(br#"{"name":"leaf-fixture","version":"1.2.3","dependencies":{},"dependencies":{"hidden":"*"}}"#, &inspection()).is_err());
    let mut inspected = inspection();
    inspected.files.push(NpmFile {
        path: "package/node_modules/hidden/index.js".into(),
        size: 0,
        sha256: digest(b""),
        executable: false,
        kind: NpmFileKind::JavaScript,
    });
    assert!(matches!(
        LeafManifest::capture(br#"{"name":"leaf-fixture","version":"1.2.3"}"#, &inspected),
        Err(NpmInstallRefusal::EmbeddedDependencies)
    ));
    for path in [
        "package/npm-shrinkwrap.json",
        "package/package-lock.json",
        "package/.npmrc",
    ] {
        let mut inspected = inspection();
        inspected.files.push(NpmFile {
            path: path.into(),
            size: 2,
            sha256: digest(b"{}"),
            executable: false,
            kind: NpmFileKind::Resource,
        });
        assert!(matches!(
            LeafManifest::capture(br#"{"name":"leaf-fixture","version":"1.2.3"}"#, &inspected),
            Err(NpmInstallRefusal::EmbeddedResolutionMetadata)
        ));
    }
    for name in [
        "../outside",
        "@scope/../../outside",
        "UPPER",
        ".bin",
        "node_modules",
        "file:local",
        "@scope/name/more",
    ] {
        assert!(!valid_package_name(name), "{name}");
    }
    for name in ["leaf", "@scope/leaf", "leaf-2.0"] {
        assert!(valid_package_name(name), "{name}");
    }
    for version in [
        "1",
        "1.2",
        "01.2.3",
        "1.2.3-",
        "1.2.3+",
        "1.2.3-01",
        "file:local",
        "^1.2.3",
    ] {
        assert!(!valid_version(version), "{version}");
    }
    assert!(valid_version("1.2.3-beta.1+build.004"));
}

#[test]
fn retained_artifact_detects_same_length_in_place_change_without_reopening_path() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("artifact.tgz");
    let bytes = include_bytes!("../../tests/fixtures/npm/npm-11.19.0-portable-pax.tgz");
    std::fs::write(&path, bytes).unwrap();
    let artifact = VerifiedNpmArtifact::open(&path).unwrap();
    artifact.revalidate().unwrap();
    let mut altered = bytes.to_vec();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    std::fs::write(&path, altered).unwrap();
    assert_eq!(artifact.revalidate(), Err(NpmInstallRefusal::InputChanged));
}

fn staged_fixture() -> (tempfile::TempDir, PathBuf, BTreeMap<String, NpmFile>) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir_all(root.join("node_modules/leaf-fixture")).unwrap();
    std::fs::write(root.join("node_modules/leaf-fixture/package.json"), b"{}\n").unwrap();
    let expected = BTreeMap::from([(
        "node_modules/leaf-fixture/package.json".into(),
        NpmFile {
            path: "package/package.json".into(),
            size: 3,
            sha256: digest(b"{}\n"),
            executable: false,
            kind: NpmFileKind::Metadata,
        },
    )]);
    (temp, root, expected)
}

#[test]
fn exact_staged_members_pass_but_generated_hidden_lock_and_changed_bytes_refuse() {
    let (_temp, root, expected) = staged_fixture();
    let retained = File::open(&root).unwrap();
    verify_tree(&root, &retained, &expected).unwrap();
    std::fs::write(root.join("node_modules/.package-lock.json"), b"{}").unwrap();
    assert_eq!(
        verify_tree(&root, &retained, &expected),
        Err(NpmInstallRefusal::UnexpectedInstalledEntry)
    );
    std::fs::remove_file(root.join("node_modules/.package-lock.json")).unwrap();
    std::fs::write(root.join("node_modules/leaf-fixture/package.json"), b"[]\n").unwrap();
    assert_eq!(
        verify_tree(&root, &retained, &expected),
        Err(NpmInstallRefusal::InstalledContentChanged)
    );
}

#[cfg(unix)]
#[test]
fn symlinks_hardlinks_and_replaced_staging_roots_refuse() {
    let (_temp, root, expected) = staged_fixture();
    let retained = File::open(&root).unwrap();
    let file = root.join("node_modules/leaf-fixture/package.json");
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), b"{}\n").unwrap();
    std::fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink(outside.path(), &file).unwrap();
    assert_eq!(
        verify_tree(&root, &retained, &expected),
        Err(NpmInstallRefusal::UnexpectedInstalledEntry)
    );
    std::fs::remove_file(&file).unwrap();
    std::fs::hard_link(outside.path(), &file).unwrap();
    assert_eq!(
        verify_tree(&root, &retained, &expected),
        Err(NpmInstallRefusal::InstalledContentChanged)
    );
    let other = tempfile::tempdir().unwrap();
    assert_eq!(
        verify_tree(other.path(), &retained, &expected),
        Err(NpmInstallRefusal::InstalledContentChanged)
    );
}

#[test]
fn destination_binding_refuses_existing_target_and_parent_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("parent")).unwrap();
    let binding = NewNpmDestination::capture(&root.join("parent/new-environment")).unwrap();
    std::fs::create_dir(root.join("parent/new-environment")).unwrap();
    assert_eq!(
        binding.revalidate(),
        Err(NpmInstallRefusal::DestinationChanged)
    );
    std::fs::remove_dir(root.join("parent/new-environment")).unwrap();
    binding.revalidate().unwrap();
    std::fs::rename(root.join("parent"), root.join("old-parent")).unwrap();
    std::fs::create_dir(root.join("parent")).unwrap();
    assert_eq!(
        binding.revalidate(),
        Err(NpmInstallRefusal::DestinationChanged)
    );
}

fn retained_fixture(root: &Path) -> Vec<VerifiedNpmArtifact> {
    let path = root.join("source.tgz");
    std::fs::write(
        &path,
        include_bytes!("../../tests/fixtures/npm/npm-11.19.0-portable-pax.tgz"),
    )
    .unwrap();
    vec![VerifiedNpmArtifact::open(&path).unwrap()]
}

fn preparation_permit(
    plan: &NpmInstallPlan,
    policy: &EffectivePolicySnapshot,
) -> TaskBoundaryPermit<PackageInstallPreparationBoundary> {
    let operation = plan.operation();
    task_boundary::prepare_locally_derived_boundary_authorization::<
        PackageInstallPreparationBoundary,
    >(
        &operation,
        &policy.policy.task_gate,
        &crate::task_analysis::TaskAnalysisContext::default(),
    )
    .unwrap()
    .consume_default_for_operation(&operation, Utc::now())
    .unwrap()
}

#[test]
fn staged_leaf_retry_keeps_exact_inputs_but_never_replays_a_started_execution() {
    let _environment = tirith_test_support::GlobalStateGuard::new().unwrap();
    let root = tempfile::tempdir().unwrap();
    let artifacts = retained_fixture(root.path());
    let target = root.path().join("installed");
    let snapshot =
        EffectivePolicySnapshot::resolve(None, crate::policy_snapshot::ResolutionMode::Runtime);
    let id = uuid::Uuid::new_v4().to_string();
    let plan = NpmInstallPlan::prepare(
        &id,
        &artifacts,
        NewNpmDestination::capture(&target).unwrap(),
        &snapshot,
        "fixture-sequence-1",
    )
    .unwrap();
    assert_eq!(
        plan.execution_qualification(),
        Err(NpmInstallRefusal::NativeExecutionUnqualified)
    );
    let store = QuarantineStore::with_root(root.path().join("quarantine")).unwrap();
    let staged = plan
        .stage(
            &artifacts,
            &snapshot,
            &store,
            preparation_permit(&plan, &snapshot),
        )
        .unwrap();
    let transaction = staged.transaction.dir().to_owned();
    let journal = transaction.join(JOURNAL_NAME);
    let first_record = std::fs::read(&journal).unwrap();
    let artifact_path = transaction.join(format!("npm-{}.tgz", artifacts[0].sha256()));
    assert_eq!(
        std::fs::read(&artifact_path).unwrap(),
        artifacts[0].compressed
    );
    assert_eq!(
        std::fs::read(transaction.join(execution::USER_CONFIG)).unwrap(),
        b""
    );
    assert_eq!(
        std::fs::read(transaction.join(execution::GLOBAL_CONFIG)).unwrap(),
        b""
    );
    assert!(!target.exists());
    drop(staged);
    let retried = plan
        .stage(
            &artifacts,
            &snapshot,
            &store,
            preparation_permit(&plan, &snapshot),
        )
        .unwrap();
    assert_eq!(std::fs::read(&journal).unwrap(), first_record);
    assert_eq!(
        std::fs::read(&artifact_path).unwrap(),
        artifacts[0].compressed
    );
    let mut record: PreparationRecord = serde_json::from_slice(&first_record).unwrap();
    record.phase = PreparationPhase::LaunchAccepted;
    retried
        .transaction
        .write_control_file_atomic_0600(JOURNAL_NAME, &serde_json::to_vec(&record).unwrap())
        .unwrap();
    let started_record = std::fs::read(&journal).unwrap();
    drop(retried);
    assert!(matches!(
        plan.stage(
            &artifacts,
            &snapshot,
            &store,
            preparation_permit(&plan, &snapshot)
        ),
        Err(NpmInstallRefusal::RecoveryRequired)
    ));
    assert_eq!(std::fs::read(journal).unwrap(), started_record);
    assert!(!target.exists());
}

#[test]
fn different_operation_permit_refuses_before_journal_or_input_creation() {
    let _environment = tirith_test_support::GlobalStateGuard::new().unwrap();
    let root = tempfile::tempdir().unwrap();
    let artifacts = retained_fixture(root.path());
    let snapshot =
        EffectivePolicySnapshot::resolve(None, crate::policy_snapshot::ResolutionMode::Runtime);
    let make_plan = |target: &str| {
        NpmInstallPlan::prepare(
            &uuid::Uuid::new_v4().to_string(),
            &artifacts,
            NewNpmDestination::capture(&root.path().join(target)).unwrap(),
            &snapshot,
            "fixture-sequence-1",
        )
        .unwrap()
    };
    let plan = make_plan("first");
    let other = make_plan("second");
    let store = QuarantineStore::with_root(root.path().join("quarantine")).unwrap();
    let before: Vec<_> = std::fs::read_dir(store.root().join("transactions"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(matches!(
        plan.stage(
            &artifacts,
            &snapshot,
            &store,
            preparation_permit(&other, &snapshot)
        ),
        Err(NpmInstallRefusal::AuthorizationRefused)
    ));
    let after: Vec<_> = std::fs::read_dir(store.root().join("transactions"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(after, before);
    assert!(!root.path().join("first").exists());
    assert!(!root.path().join("second").exists());
}

#[test]
fn same_id_with_changed_review_identity_cannot_rewrite_prepared_journal() {
    let _environment = tirith_test_support::GlobalStateGuard::new().unwrap();
    let root = tempfile::tempdir().unwrap();
    let artifacts = retained_fixture(root.path());
    let snapshot =
        EffectivePolicySnapshot::resolve(None, crate::policy_snapshot::ResolutionMode::Runtime);
    let id = uuid::Uuid::new_v4().to_string();
    let make_plan = |sequence| {
        NpmInstallPlan::prepare(
            &id,
            &artifacts,
            NewNpmDestination::capture(&root.path().join("installed")).unwrap(),
            &snapshot,
            sequence,
        )
        .unwrap()
    };
    let plan = make_plan("fixture-sequence-1");
    let other = make_plan("fixture-sequence-2");
    let store = QuarantineStore::with_root(root.path().join("quarantine")).unwrap();
    let staged = plan
        .stage(
            &artifacts,
            &snapshot,
            &store,
            preparation_permit(&plan, &snapshot),
        )
        .unwrap();
    let journal = staged.transaction.dir().join(JOURNAL_NAME);
    let before = std::fs::read(&journal).unwrap();
    drop(staged);
    assert!(matches!(
        other.stage(
            &artifacts,
            &snapshot,
            &store,
            preparation_permit(&other, &snapshot)
        ),
        Err(NpmInstallRefusal::JournalConflict)
    ));
    assert_eq!(std::fs::read(journal).unwrap(), before);
}

#[test]
fn public_boundary_binding_does_not_publish_a_secret_policy_fingerprint() {
    let _environment = tirith_test_support::GlobalStateGuard::new().unwrap();
    let root = tempfile::tempdir().unwrap();
    let artifacts = retained_fixture(root.path());
    let policy_path = crate::policy::config_dir().unwrap().join("policy.yaml");
    std::fs::create_dir_all(policy_path.parent().unwrap()).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let make_plan = |secret: &str| {
        std::fs::write(&policy_path, format!("policy_server_api_key: {secret}\n")).unwrap();
        let snapshot =
            EffectivePolicySnapshot::resolve(None, crate::policy_snapshot::ResolutionMode::Runtime);
        NpmInstallPlan::prepare(
            &id,
            &artifacts,
            NewNpmDestination::capture(&root.path().join("installed")).unwrap(),
            &snapshot,
            "fixture-sequence-1",
        )
        .unwrap()
    };
    let first = make_plan("private-key-one");
    let second = make_plan("private-key-two");
    assert_ne!(first.digest, second.digest);
    let public = serde_json::to_value(first.operation().envelope).unwrap();
    assert_eq!(
        public,
        serde_json::to_value(second.operation().envelope).unwrap()
    );
    let public = public.to_string();
    for private in [
        &first.digest,
        &second.digest,
        "private-key-one",
        "private-key-two",
    ] {
        assert!(!public.contains(private));
    }
}
