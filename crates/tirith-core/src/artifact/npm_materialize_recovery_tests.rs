use super::*;

fn record_json() -> serde_json::Value {
    serde_json::json!({
        "schema":1,"contract":CONTRACT,"operation_id":"11111111-1111-4111-8111-111111111111",
        "public_plan_digest":"a".repeat(64),"private_plan_digest":"b".repeat(64),"operator":"uid:1",
        "target_component":"output","target_path_sha256":"c".repeat(64),"inventory_digest":"d".repeat(64),
        "packages":[{"name":"leaf","version":"1.0.0","compressed_sha256":"e".repeat(64)}],
        "phase":"private","parent":[1,2],"journal":[1,3],
        "root":{"identity":[1,4],"size":0,"links":2,"modified_seconds":1,"modified_nanos":2,"changed_seconds":3,"changed_nanos":4},
        "entries":{"node_modules":{"generation":{"identity":[1,5],"size":0,"links":2,"modified_seconds":1,"modified_nanos":2,"changed_seconds":3,"changed_nanos":4},"expected":{"directory":true,"size":0,"sha256":digest(b""),"mode":448}}}
    })
}
#[test]
fn recovery_decoder_rejects_duplicate_unknown_oversize_uuid_and_missing_milestone() {
    let good = record_json();
    assert!(decode(&serde_json::to_vec(&good).unwrap()).is_ok());
    let text = serde_json::to_string(&good).unwrap();
    let duplicate = format!("{{\"schema\":1,{}", &text[1..]);
    assert!(decode(duplicate.as_bytes()).is_err());
    assert!(decode(&vec![b' '; INVENTORY_BYTES + 1]).is_err());
    for (name, value) in [
        ("schema", serde_json::json!(2)),
        (
            "operation_id",
            serde_json::json!(uuid::Uuid::nil().to_string()),
        ),
        ("phase", serde_json::json!("writing")),
        ("entries", serde_json::json!({})),
        ("private_plan_digest", serde_json::json!("x")),
        ("caller_skip_identity", serde_json::json!(true)),
    ] {
        let mut bad = good.clone();
        bad[name] = value;
        assert!(
            decode(&serde_json::to_vec(&bad).unwrap()).is_err(),
            "{name}"
        );
    }
}
#[test]
fn observed_rename_accepts_only_ctime_change_not_identity_content_or_links() {
    let before: FileGeneration = decode(&serde_json::to_vec(&record_json()).unwrap())
        .unwrap()
        .root
        .into();
    let mut moved = before;
    moved.changed_seconds += 10;
    assert!(rename_generation(before, moved));
    for n in 0..5 {
        let mut bad = moved;
        match n {
            0 => bad.identity.1 += 1,
            1 => bad.size += 1,
            2 => bad.links += 1,
            3 => bad.modified_seconds += 1,
            _ => bad.modified_nanos += 1,
        }
        assert!(!rename_generation(before, bad));
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::super::super::tests::{artifact, plan, policy, MANIFEST};
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn permit(
        plan: &MaterializationPlan,
    ) -> TaskBoundaryPermit<LocalPackageMaterializationBoundary> {
        TaskBoundaryPermit::for_test_with_deadline(
            &plan.operation(),
            Utc::now() + chrono::Duration::minutes(5),
        )
    }
    fn recovery_permit(
        value: &MaterializationRecovery,
    ) -> TaskBoundaryPermit<LocalPackageRecoveryBoundary> {
        TaskBoundaryPermit::for_test_with_deadline(
            &value.operation(),
            Utc::now() + chrono::Duration::minutes(5),
        )
    }
    fn stage<'a>(
        plan: &'a MaterializationPlan,
        policy: &'a EffectivePolicySnapshot,
    ) -> MaterializationWriter<'a> {
        let mut authorized = plan.authorize(policy, permit(plan)).unwrap();
        let _checkpoint = authorized.checkpoint_authorization().unwrap();
        let journal = plan
            .destination
            .parent
            .path()
            .join(plan.journal_component());
        let pending = journal.join(STAGING_COMPONENT);
        for path in [&journal, &pending] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut writer = authorized
            .writer(
                native::open_root(&journal).unwrap(),
                native::open_root(&pending).unwrap(),
            )
            .unwrap();
        writer.populate(&AtomicBool::new(false)).unwrap();
        writer
    }
    fn source_copies(plan: &MaterializationPlan, root: &Path) -> Vec<VerifiedNpmArtifact> {
        plan.artifacts
            .iter()
            .map(|a| {
                let path = root.join(format!("fresh-{}.tgz", uuid::Uuid::new_v4()));
                std::fs::write(&path, &a.compressed).unwrap();
                VerifiedNpmArtifact::open(&path).unwrap()
            })
            .collect()
    }
    fn inventory(writer: &MaterializationWriter<'_>) -> Vec<u8> {
        serde_json::to_vec(&writer.verify().unwrap().recovery_inventory().unwrap()).unwrap()
    }
    fn capture(
        plan: &MaterializationPlan,
        root: &Path,
        json: &[u8],
        action: MaterializationRecoveryAction,
        policy: &EffectivePolicySnapshot,
    ) -> MaterializationResult<MaterializationRecovery> {
        MaterializationRecovery::capture_inner(
            &plan.id,
            &plan.target_path(),
            source_copies(plan, root),
            json,
            action,
            policy,
            Some(MaterializationThreatSource::fixture_empty()),
        )
    }
    #[test]
    fn dropped_original_handles_require_fresh_permit_before_private_undo_and_public_summary_has_no_private_digest(
    ) {
        let _global = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let policy = policy();
        let plan = plan(root.path(), &policy);
        let writer = stage(&plan, &policy);
        let json = inventory(&writer);
        drop(writer);
        let value = capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::UndoPrivate,
            &policy,
        )
        .unwrap();
        let permit = recovery_permit(&value);
        let mut owner = value.authorize(&policy, permit).unwrap();
        owner.relocate_for_undo().unwrap();
        owner.relocate_for_undo().unwrap();
        let observation = owner.undo_private(&AtomicBool::new(false)).unwrap();
        observation.revalidate().unwrap();
        let public = serde_json::to_string(observation.summary()).unwrap();
        assert!(!public.contains(&plan.private_digest));
        assert!(!public.contains("private_plan_digest"));
        assert!(public.contains("removed_exact_private_contents"));
        let pending = plan
            .destination
            .parent
            .path()
            .join(plan.journal_component())
            .join(STAGING_COMPONENT);
        assert!(pending.is_dir());
        assert_eq!(std::fs::read_dir(pending).unwrap().count(), 0);
        assert!(owner.undo_private(&AtomicBool::new(false)).is_err());
    }
    #[test]
    fn actual_publication_crash_gap_confirms_only_current_public_tree_without_repeating_rename() {
        let _global = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let policy = policy();
        let plan = plan(root.path(), &policy);
        let mut writer = stage(&plan, &policy);
        let before = inventory(&writer);
        writer.begin_publication().unwrap();
        let pending = plan
            .destination
            .parent
            .path()
            .join(plan.journal_component())
            .join(STAGING_COMPONENT);
        std::fs::rename(&pending, plan.target_path()).unwrap();
        drop(writer);
        let value = capture(
            &plan,
            root.path(),
            &before,
            MaterializationRecoveryAction::ConfirmPublished,
            &policy,
        )
        .unwrap();
        let permit = recovery_permit(&value);
        let mut owner = value.authorize(&policy, permit).unwrap();
        let observed = owner.confirm_published().unwrap();
        observed.revalidate().unwrap();
        assert!(observed.summary().root_relocated_since_observation);
        assert!(!pending.exists());
        assert!(plan.target_path().is_dir());
        assert!(owner.relocate_for_undo().is_err());
        assert!(owner.undo_private(&AtomicBool::new(false)).is_err());
    }
    #[test]
    fn public_undo_relocates_once_and_recovery_after_relocation_uses_fresh_delete_only_binding() {
        let _global = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let policy = policy();
        let plan = plan(root.path(), &policy);
        let mut writer = stage(&plan, &policy);
        writer.begin_publication().unwrap();
        let pending = plan
            .destination
            .parent
            .path()
            .join(plan.journal_component())
            .join(STAGING_COMPONENT);
        std::fs::rename(&pending, plan.target_path()).unwrap();
        writer.confirm_published().unwrap();
        let json = inventory(&writer);
        drop(writer);
        let value = capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::UndoPrivate,
            &policy,
        )
        .unwrap();
        assert!(value.decision.is_none());
        let effects = crate::task::infer_effects(&value.envelope.actions[0]);
        assert!(!effects.contains(&crate::effects::CommandEffectKind::PackageInstall));
        assert!(!effects.contains(&crate::effects::CommandEffectKind::NetworkEgress));
        let permit = recovery_permit(&value);
        let mut owner = value.authorize(&policy, permit).unwrap();
        assert!(owner.undo_private(&AtomicBool::new(false)).is_err());
        owner.relocate_for_undo().unwrap();
        drop(owner);
        assert!(!plan.target_path().exists());
        assert!(pending.is_dir());
        let fresh = capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::UndoPrivate,
            &policy,
        )
        .unwrap();
        assert!(fresh.summary.root_relocated_since_observation);
        let permit = recovery_permit(&fresh);
        let mut fresh = fresh.authorize(&policy, permit).unwrap();
        fresh
            .undo_private(&AtomicBool::new(false))
            .unwrap()
            .revalidate()
            .unwrap();
    }
    #[test]
    fn current_observation_instance_prevents_old_or_other_action_permit_reuse() {
        let _global = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let policy = policy();
        let plan = plan(root.path(), &policy);
        let writer = stage(&plan, &policy);
        let json = inventory(&writer);
        drop(writer);
        let a = capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::UndoPrivate,
            &policy,
        )
        .unwrap();
        let b = capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::UndoPrivate,
            &policy,
        )
        .unwrap();
        assert!(matches!(
            b.authorize(&policy, recovery_permit(&a)),
            Err(Refusal::AuthorizationRefused)
        ));
        assert!(capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::ConfirmPublished,
            &policy
        )
        .is_err());
    }
    #[test]
    fn edited_extra_missing_mode_hardlink_and_symlink_entries_preserve_entire_tree() {
        let _global = tirith_test_support::GlobalStateGuard::new().unwrap();
        let policy = policy();
        for kind in 0..6 {
            let root = tempfile::tempdir().unwrap();
            let plan = plan(root.path(), &policy);
            let writer = stage(&plan, &policy);
            let json = inventory(&writer);
            drop(writer);
            let pending = plan
                .destination
                .parent
                .path()
                .join(plan.journal_component())
                .join(STAGING_COMPONENT);
            let file = pending.join("node_modules/leaf-data/index.js");
            match kind {
                0 => std::fs::write(&file, b"changed").unwrap(),
                1 => std::fs::write(pending.join("unknown"), b"preserve").unwrap(),
                2 => std::fs::remove_file(&file).unwrap(),
                3 => {
                    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap()
                }
                4 => std::fs::hard_link(&file, root.path().join("extra-link")).unwrap(),
                _ => {
                    std::fs::remove_file(&file).unwrap();
                    std::os::unix::fs::symlink("package.json", &file).unwrap();
                }
            }
            assert!(
                capture(
                    &plan,
                    root.path(),
                    &json,
                    MaterializationRecoveryAction::UndoPrivate,
                    &policy
                )
                .is_err(),
                "kind={kind}"
            );
            assert!(pending
                .join("node_modules/leaf-data/package.json")
                .is_file());
        }
    }
    #[test]
    fn relocation_conflict_and_cancel_are_preserved_and_never_accepted_as_completed() {
        let _global = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let policy = policy();
        let plan = plan(root.path(), &policy);
        let writer = stage(&plan, &policy);
        let json = inventory(&writer);
        drop(writer);
        let value = capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::UndoPrivate,
            &policy,
        )
        .unwrap();
        let permit = recovery_permit(&value);
        let mut owner = value.authorize(&policy, permit).unwrap();
        assert!(matches!(
            owner.undo_private(&AtomicBool::new(true)),
            Err(Refusal::Cancelled)
        ));
        assert!(owner.undo_private(&AtomicBool::new(false)).is_err());
        let fresh = capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::UndoPrivate,
            &policy,
        )
        .unwrap();
        let permit = recovery_permit(&fresh);
        let mut fresh = fresh.authorize(&policy, permit).unwrap();
        std::fs::create_dir(plan.target_path()).unwrap();
        assert!(fresh.relocate_for_undo().is_err());
        assert!(fresh.undo_private(&AtomicBool::new(false)).is_err());
        assert!(plan.target_path().is_dir());
    }
    #[test]
    fn changed_archive_or_forged_record_cannot_authorize_an_existing_tree() {
        let _global = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let policy = policy();
        let plan = plan(root.path(), &policy);
        let writer = stage(&plan, &policy);
        let json = inventory(&writer);
        drop(writer);
        let wrong = vec![artifact(
            root.path(),
            MANIFEST,
            &[("package/other.js", b"different")],
        )];
        assert!(MaterializationRecovery::capture(
            &plan.id,
            &plan.target_path(),
            wrong,
            &json,
            MaterializationRecoveryAction::UndoPrivate,
            &policy
        )
        .is_err());
        let mut record: serde_json::Value = serde_json::from_slice(&json).unwrap();
        record["entries"]["node_modules/leaf-data/index.js"]["expected"]["mode"] =
            serde_json::json!(0o755);
        assert!(capture(
            &plan,
            root.path(),
            &serde_json::to_vec(&record).unwrap(),
            MaterializationRecoveryAction::UndoPrivate,
            &policy
        )
        .is_err());
    }
    #[test]
    fn newly_malicious_classification_refuses_confirmation_but_never_grants_or_vetoes_exact_undo() {
        let _global = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let policy = policy();
        let plan = plan(root.path(), &policy);
        let mut writer = stage(&plan, &policy);
        writer.begin_publication().unwrap();
        let pending = plan
            .destination
            .parent
            .path()
            .join(plan.journal_component())
            .join(STAGING_COMPONENT);
        std::fs::rename(&pending, plan.target_path()).unwrap();
        writer.confirm_published().unwrap();
        let json = inventory(&writer);
        drop(writer);
        let hash: [u8; 32] = hex::decode(plan.artifacts[0].sha256())
            .unwrap()
            .try_into()
            .unwrap();
        let capture_with_block = |action| {
            MaterializationRecovery::capture_inner(
                &plan.id,
                &plan.target_path(),
                source_copies(&plan, root.path()),
                &json,
                action,
                &policy,
                Some(MaterializationThreatSource::fixture_blocking_artifact(hash)),
            )
        };
        assert!(matches!(
            capture_with_block(MaterializationRecoveryAction::ConfirmPublished),
            Err(Refusal::ArtifactPolicyRefused)
        ));
        let recovery = capture_with_block(MaterializationRecoveryAction::UndoPrivate).unwrap();
        assert!(recovery.decision.is_none());
        let permit = recovery_permit(&recovery);
        let mut owner = recovery.authorize(&policy, permit).unwrap();
        owner.relocate_for_undo().unwrap();
        owner
            .undo_private(&AtomicBool::new(false))
            .unwrap()
            .revalidate()
            .unwrap();
        assert!(!plan.target_path().exists());
    }
    #[test]
    fn expired_delete_permit_and_post_capture_byte_drift_cannot_remove_anything() {
        let _global = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let policy = policy();
        let plan = plan(root.path(), &policy);
        let writer = stage(&plan, &policy);
        let json = inventory(&writer);
        drop(writer);
        let recovery = capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::UndoPrivate,
            &policy,
        )
        .unwrap();
        let expired = TaskBoundaryPermit::<LocalPackageRecoveryBoundary>::for_test_with_deadline(
            &recovery.operation(),
            Utc::now() - chrono::Duration::seconds(1),
        );
        assert!(matches!(
            recovery.authorize(&policy, expired),
            Err(Refusal::AuthorizationRefused)
        ));
        let recovery = capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::UndoPrivate,
            &policy,
        )
        .unwrap();
        let permit = recovery_permit(&recovery);
        let mut owner = recovery.authorize(&policy, permit).unwrap();
        let pending = plan
            .destination
            .parent
            .path()
            .join(plan.journal_component())
            .join(STAGING_COMPONENT);
        std::fs::write(
            pending.join("node_modules/leaf-data/index.js"),
            b"changed after current capture",
        )
        .unwrap();
        assert!(owner.undo_private(&AtomicBool::new(false)).is_err());
        assert!(pending
            .join("node_modules/leaf-data/package.json")
            .is_file());
    }
    #[test]
    fn real_default_gate_permit_cannot_bypass_current_delete_provenance_gate() {
        let state = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let old = policy();
        let plan = plan(root.path(), &old);
        let writer = stage(&plan, &old);
        let json = inventory(&writer);
        drop(writer);
        let policy_root = state.roots().policy.join(".tirith");
        std::fs::create_dir_all(&policy_root).unwrap();
        std::fs::write(policy_root.join("policy.yaml"),"task_gate:\n  mode: enforce\n  effects_requiring_verified_provenance: [filesystem_write]\n").unwrap();
        let current = policy();
        let recovery = capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::UndoPrivate,
            &current,
        )
        .unwrap();
        let pending = crate::task_boundary::prepare_locally_derived_boundary_authorization::<
            LocalPackageRecoveryBoundary,
        >(
            &recovery.operation(),
            &crate::web3_policy::TaskGatePolicy::default(),
            &crate::task_analysis::TaskAnalysisContext::default(),
        )
        .unwrap();
        let weak = pending.consume_default(Utc::now()).unwrap();
        assert!(matches!(
            recovery.authorize(&current, weak),
            Err(Refusal::AuthorizationRefused)
        ));
        assert!(plan
            .destination
            .parent
            .path()
            .join(plan.journal_component())
            .join(STAGING_COMPONENT)
            .join("node_modules/leaf-data/package.json")
            .is_file());
    }
    #[test]
    fn explicit_continuation_removes_only_current_remaining_private_entries() {
        let _global = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let policy = policy();
        let plan = plan(root.path(), &policy);
        let writer = stage(&plan, &policy);
        let json = inventory(&writer);
        drop(writer);
        let pending = plan
            .destination
            .parent
            .path()
            .join(plan.journal_component())
            .join(STAGING_COMPONENT);
        // Simulate the durable prefix left by an interrupted authorized unlink.
        // This unit does not claim a native process-death qualification.
        std::fs::remove_file(pending.join("node_modules/leaf-data/index.js")).unwrap();
        assert!(capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::UndoPrivate,
            &policy
        )
        .is_err());
        let current = capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::ContinueUndoPrivate,
            &policy,
        )
        .unwrap();
        assert_eq!(current.summary.missing_recorded_entries, 1);
        assert_eq!(
            current.summary.recorded_entries,
            current.summary.remaining_entries_at_capture + 1
        );
        let permit = recovery_permit(&current);
        let mut owner = current.authorize(&policy, permit).unwrap();
        owner.relocate_for_undo().unwrap();
        let outcome = owner.undo_private(&AtomicBool::new(false)).unwrap();
        outcome.revalidate().unwrap();
        assert_eq!(
            outcome.summary().outcome,
            "removed_exact_remaining_private_contents"
        );
        assert_eq!(std::fs::read_dir(&pending).unwrap().count(), 0);
    }
    #[test]
    fn wholly_absent_recorded_subtree_is_reported_as_absence_not_prior_success() {
        let _global = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let policy = policy();
        let plan = plan(root.path(), &policy);
        let writer = stage(&plan, &policy);
        let json = inventory(&writer);
        drop(writer);
        let pending = plan
            .destination
            .parent
            .path()
            .join(plan.journal_component())
            .join(STAGING_COMPONENT);
        for name in ["index.js", "package.json"] {
            std::fs::remove_file(pending.join("node_modules/leaf-data").join(name)).unwrap();
        }
        std::fs::remove_dir(pending.join("node_modules/leaf-data")).unwrap();
        std::fs::remove_dir(pending.join("node_modules")).unwrap();
        let current = capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::ContinueUndoPrivate,
            &policy,
        )
        .unwrap();
        assert_eq!(current.summary.remaining_entries_at_capture, 0);
        assert_eq!(
            current.summary.recorded_entries,
            current.summary.missing_recorded_entries
        );
        let permit = recovery_permit(&current);
        let mut owner = current.authorize(&policy, permit).unwrap();
        let outcome = owner.undo_private(&AtomicBool::new(false)).unwrap();
        outcome.revalidate().unwrap();
        assert_eq!(
            outcome.summary().outcome,
            "observed_private_tree_already_empty"
        );
    }
    #[test]
    fn continuation_refuses_unknown_modified_and_replaced_remaining_objects() {
        let _global = tirith_test_support::GlobalStateGuard::new().unwrap();
        let policy = policy();
        for kind in 0..3 {
            let root = tempfile::tempdir().unwrap();
            let plan = plan(root.path(), &policy);
            let writer = stage(&plan, &policy);
            let json = inventory(&writer);
            drop(writer);
            let pending = plan
                .destination
                .parent
                .path()
                .join(plan.journal_component())
                .join(STAGING_COMPONENT);
            std::fs::remove_file(pending.join("node_modules/leaf-data/index.js")).unwrap();
            match kind {
                0 => std::fs::write(pending.join("unknown"), b"preserve").unwrap(),
                1 => std::fs::write(
                    pending.join("node_modules/leaf-data/package.json"),
                    b"changed",
                )
                .unwrap(),
                _ => {
                    std::fs::rename(
                        pending.join("node_modules/leaf-data"),
                        root.path().join("old-leaf"),
                    )
                    .unwrap();
                    std::fs::create_dir(pending.join("node_modules/leaf-data")).unwrap();
                    std::fs::set_permissions(
                        pending.join("node_modules/leaf-data"),
                        std::fs::Permissions::from_mode(0o700),
                    )
                    .unwrap();
                }
            }
            assert!(capture(
                &plan,
                root.path(),
                &json,
                MaterializationRecoveryAction::ContinueUndoPrivate,
                &policy
            )
            .is_err());
            assert!(pending.join("node_modules").is_dir());
        }
    }
    #[test]
    fn continuation_is_private_only_and_original_undo_permit_cannot_authorize_it() {
        let _global = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let policy = policy();
        let plan = plan(root.path(), &policy);
        let writer = stage(&plan, &policy);
        let json = inventory(&writer);
        drop(writer);
        let undo = capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::UndoPrivate,
            &policy,
        )
        .unwrap();
        let old_permit = recovery_permit(&undo);
        let pending = plan
            .destination
            .parent
            .path()
            .join(plan.journal_component())
            .join(STAGING_COMPONENT);
        std::fs::remove_file(pending.join("node_modules/leaf-data/index.js")).unwrap();
        let continuation = capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::ContinueUndoPrivate,
            &policy,
        )
        .unwrap();
        assert!(matches!(
            continuation.authorize(&policy, old_permit),
            Err(Refusal::AuthorizationRefused)
        ));
        std::fs::rename(&pending, plan.target_path()).unwrap();
        assert!(capture(
            &plan,
            root.path(),
            &json,
            MaterializationRecoveryAction::ContinueUndoPrivate,
            &policy
        )
        .is_err());
    }
}
