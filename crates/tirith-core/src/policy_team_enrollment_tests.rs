use super::*;
use crate::policy_team::POLICY_SEMANTICS_VERSION;

fn policy(authority: Id, policy: Id, now: u64) -> PolicyDocument {
    PolicyDocument {
        schema_version: SCHEMA_VERSION,
        authority_id: authority,
        policy_id: policy,
        revision: Id::new(),
        created_unix_ms: now,
        policy_semantics_version: POLICY_SEMANTICS_VERSION,
        yaml: "paranoia: 2\n".into(),
    }
}
fn record(now: u64) -> Record {
    let authority_id = Id::new();
    let policy_id = Id::new();
    Record {
        schema_version: SCHEMA_VERSION,
        connection_id: Id::new(),
        authority_id: authority_id.clone(),
        policy_id: policy_id.clone(),
        activation_id: Id::new(),
        client_id: Id::new(),
        selection_commitment: PrivateCommitment::of("test-only-selection", b"private"),
        fetched_unix_ms: now,
        cached_policy: Some(policy(authority_id, policy_id, now)),
    }
}

#[test]
fn cache_age_refuses_zero_future_and_exact_twenty_four_hours() {
    let now = CACHE_MAX_AGE_MS * 3;
    assert!(cache_time(now, now).is_ok());
    assert!(cache_time(now - CACHE_MAX_AGE_MS + 1, now).is_ok());
    assert_eq!(cache_time(0, now), Err(EnrollmentError::InvalidCache));
    assert_eq!(cache_time(now + 1, now), Err(EnrollmentError::FutureCache));
    assert_eq!(
        cache_time(now - CACHE_MAX_AGE_MS, now),
        Err(EnrollmentError::StaleCache)
    );
    assert_eq!(cache_time(u64::MAX, now), Err(EnrollmentError::FutureCache));
}
#[test]
fn cached_document_is_bound_to_authority_policy_schema_and_fetch_time() {
    let now = CACHE_MAX_AGE_MS * 3;
    let encoded = serde_json::to_vec(&record(now)).unwrap();
    assert!(document(&decode(&encoded).unwrap(), now).is_ok());
    for field in [
        "authority_id",
        "policy_id",
        "revision",
        "schema_version",
        "created_unix_ms",
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        value["cached_policy"][field] = match field {
            "revision" => serde_json::json!("00000000-0000-0000-0000-000000000000"),
            "schema_version" => serde_json::json!(99),
            "created_unix_ms" => {
                serde_json::json!(now + crate::policy_team::MAX_FUTURE_SKEW_MS + 1)
            }
            _ => serde_json::json!(Id::new()),
        };
        assert!(
            decode(&serde_json::to_vec(&value).unwrap())
                .and_then(|r| document(&r, now).map(|_| ()))
                .is_err(),
            "{field}"
        );
    }
}
#[test]
fn cached_yaml_cannot_add_connection_credentials_unknown_keys_or_duplicate_keys() {
    let now = CACHE_MAX_AGE_MS * 3;
    for yaml in [
        "policy_server_api_key: secret\n",
        "policy_server_url: https://example.com\n",
        "unknown: true\n",
        "paranoia: 1\nparanoia: 3\n",
        "paranoia: [",
        "paranoia: 5\n",
    ] {
        let mut r = record(now);
        r.cached_policy.as_mut().unwrap().yaml = yaml.into();
        assert!(document(&r, now).is_err(), "{yaml}");
    }
}
#[test]
fn enrollment_wire_is_closed_and_bounded_before_decode() {
    let r = record(CACHE_MAX_AGE_MS * 3);
    let raw = serde_json::to_string(&r).unwrap();
    assert!(decode(raw.as_bytes()).is_ok());
    for key in [
        "enabled",
        "credential",
        "base_url",
        "applied",
        "role",
        "reported",
    ] {
        let mut value = serde_json::to_value(&r).unwrap();
        value[key] = serde_json::json!(true);
        assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    assert!(decode(format!("{{\"schema_version\":1,{}", &raw[1..]).as_bytes()).is_err());
    assert!(decode(&vec![b' '; MAX_ENROLLMENT_BYTES + 1]).is_err());
    let mut value = serde_json::to_value(&r).unwrap();
    value["schema_version"] = serde_json::json!(2);
    assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
}
#[test]
fn missing_and_invalid_cache_do_not_erase_activation_identity() {
    let now = CACHE_MAX_AGE_MS * 3;
    let mut r = record(now);
    let activation = r.activation_id.clone();
    r.cached_policy = None;
    let decoded = decode(&serde_json::to_vec(&r).unwrap()).unwrap();
    assert_eq!(decoded.activation_id, activation);
    assert_eq!(
        document(&decoded, now).err(),
        Some(EnrollmentError::MissingCache)
    );
    r.cached_policy = Some(policy(r.authority_id.clone(), r.policy_id.clone(), now));
    r.cached_policy.as_mut().unwrap().yaml = "broken: [".into();
    let decoded = decode(&serde_json::to_vec(&r).unwrap()).unwrap();
    assert_eq!(decoded.activation_id, activation);
    assert_eq!(
        document(&decoded, now).err(),
        Some(EnrollmentError::InvalidCache)
    );
}

// Pure contract predicates above run on every target. Native generation tests
// use ordinary-owner Unix fixtures; Windows uses the shared TeamRecord native
// ACL/reparse reader and still requires its actual-platform qualification.
#[cfg(unix)]
mod native {
    use super::*;
    use crate::policy_team::Limits;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    fn private_file(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn fixture() -> (tirith_test_support::GlobalStateGuard, PathBuf) {
        let guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        let scope = crate::policy::config_dir().unwrap();
        let parent = scope.join("team-policy");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        (guard, parent)
    }
    fn connection(parent: &Path) -> Arc<ConnectionWitness> {
        let binding = crate::policy_team_client::AuthorityBinding {
            schema_version: SCHEMA_VERSION,
            base_url: "https://policy.example.invalid".into(),
            authority_id: Id::new(),
            policy_id: Id::new(),
            transport: Default::default(),
        };
        private_file(&parent.join("connection.json"), &serde_json::to_vec(&serde_json::json!({
            "schema_version":SCHEMA_VERSION, "connection_id":Id::new(), "binding":binding, "credential":"c".repeat(64)
        })).unwrap());
        Arc::new(SelectedConnection::capture_current().unwrap())
    }
    fn enrollment(connection: &ConnectionWitness, now: u64) -> Record {
        let binding = connection.binding().unwrap();
        Record {
            schema_version: SCHEMA_VERSION,
            connection_id: connection.connection_id().unwrap().clone(),
            authority_id: binding.authority_id.clone(),
            policy_id: binding.policy_id.clone(),
            activation_id: Id::new(),
            client_id: connection.connection_id().unwrap().clone(),
            selection_commitment: connection.private_selection_commitment().unwrap(),
            fetched_unix_ms: now,
            cached_policy: Some(policy(
                binding.authority_id.clone(),
                binding.policy_id.clone(),
                now,
            )),
        }
    }
    fn install(parent: &Path, record: &Record) -> Arc<EnrollmentWitness> {
        private_file(
            &parent.join("enrollment.json"),
            &serde_json::to_vec(record).unwrap(),
        );
        Arc::new(TeamEnrollment::capture_current().unwrap())
    }
    // Unit-only sealed observation construction. This exercises intent predicates,
    // not real authenticated fetch qualification. Product construction uses fetch().
    fn fetched(connection: Arc<ConnectionWitness>, now: u64) -> FetchedTeamPolicy {
        let binding = connection.binding().unwrap();
        let document = policy(binding.authority_id.clone(), binding.policy_id.clone(), now);
        let capabilities = Capabilities {
            schema_version: SCHEMA_VERSION,
            contract: crate::policy_team::CONTRACT.into(),
            authority_id: binding.authority_id.clone(),
            policy_id: binding.policy_id.clone(),
            role: Role::Client,
            client_id: connection.connection_id().cloned(),
            client_report_sequence: Some(0),
            credential_expires_unix_ms: now + 120_000,
            policy_semantics_version: POLICY_SEMANTICS_VERSION,
            limits: Limits::default(),
        };
        let selection_commitment = connection.private_selection_commitment().unwrap();
        FetchedTeamPolicy {
            connection,
            capabilities,
            document,
            fetched_unix_ms: now,
            selection_commitment,
        }
    }
    fn personal_alias_fixture() -> (tirith_test_support::GlobalStateGuard, PathBuf, PathBuf) {
        let guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        let scope = crate::policy::config_dir().unwrap();
        let target = scope.with_file_name("personal-config-target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&target, &scope).unwrap();
        private_file(&target.join("policy.yaml"), b"paranoia: 1\n");
        (guard, scope, target)
    }
    #[test]
    fn absent_enrollment_preserves_personal_config_alias_and_detects_later_entry() {
        use crate::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
        let (_guard, _scope, target) = personal_alias_fixture();
        // The management reader remains strict; its refusal is not swallowed.
        assert!(TeamEnrollment::capture_current().is_err());
        let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert_eq!(snapshot.policy.paranoia, 1);
        assert_ne!(snapshot.policy.path.as_deref(), Some("fail-closed"));
        assert_eq!(snapshot.team_runtime_evidence().unwrap(), None);
        assert!(snapshot.revalidate_captured().is_ok());
        assert!(!target.join("team-policy").exists());
        let parent = target.join("team-policy");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        private_file(&parent.join("enrollment.json"), b"{}");
        assert!(snapshot.revalidate_captured().is_err());
        let next = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert_eq!(next.policy.path.as_deref(), Some("fail-closed"));
        assert!(next.team_runtime_evidence().is_err());
    }
    #[test]
    fn present_enrollment_through_personal_alias_never_becomes_off() {
        let (_guard, _scope, target) = personal_alias_fixture();
        let parent = target.join("team-policy");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Well-formed cached bytes still require the strict native enrollment
        // reader. This is not a malformed-JSON-only negative control.
        private_file(
            &parent.join("enrollment.json"),
            &serde_json::to_vec(&record(now_ms().unwrap())).unwrap(),
        );
        assert_eq!(
            TeamEnrollment::capture_runtime().err(),
            Some(EnrollmentError::UnsafeStorage)
        );
    }
    #[test]
    fn off_witness_detects_alias_retargeting_to_a_present_enrollment() {
        let (_guard, scope, target) = personal_alias_fixture();
        let off = TeamEnrollment::capture_runtime().unwrap();
        let other = target.with_file_name("other-config-target");
        std::fs::create_dir_all(other.join("team-policy")).unwrap();
        private_file(&other.join("team-policy/enrollment.json"), b"{}");
        std::fs::remove_file(&scope).unwrap();
        symlink(&other, &scope).unwrap();
        assert_eq!(off.revalidate(), Err(EnrollmentError::ChangedEnrollment));
        assert!(TeamEnrollment::capture_runtime().is_err());
    }
    #[test]
    fn missing_enrollment_does_not_require_or_change_a_private_parent() {
        let (_guard, parent) = fixture();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(TeamEnrollment::capture_current().is_err());
        let off = TeamEnrollment::capture_runtime().unwrap();
        assert!(off.document().is_none());
        assert!(off.revalidate().is_ok());
        assert_eq!(
            std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o755
        );
        private_file(&parent.join("enrollment.json"), b"{}");
        assert_eq!(off.revalidate(), Err(EnrollmentError::ChangedEnrollment));
        assert!(TeamEnrollment::capture_runtime().is_err());
    }
    #[test]
    fn every_present_entry_type_and_non_notfound_parent_error_refuses_off() {
        let (_guard, parent) = fixture();
        let path = parent.join("enrollment.json");
        let off = TeamEnrollment::capture_runtime().unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(TeamEnrollment::capture_runtime().is_err());
        assert!(off.revalidate().is_err());
        std::fs::remove_dir(&path).unwrap();
        symlink(parent.join("missing-target"), &path).unwrap();
        assert!(!path.exists()); // follows the dangling link: not a safe probe
        assert!(TeamEnrollment::capture_runtime().is_err());
        assert!(off.revalidate().is_err());
        std::fs::remove_file(&path).unwrap();
        for bytes in [b"{malformed".to_vec(), vec![b' '; MAX_ENROLLMENT_BYTES + 1]] {
            private_file(&path, &bytes);
            assert!(TeamEnrollment::capture_runtime().is_err());
            assert!(off.revalidate().is_err());
            std::fs::remove_file(&path).unwrap();
        }
        std::fs::remove_dir(&parent).unwrap();
        private_file(&parent, b"a regular file is not an absent parent");
        assert_eq!(
            TeamEnrollment::capture_runtime().err(),
            Some(EnrollmentError::UnsafeStorage)
        );
        assert!(off.revalidate().is_err());
    }
    #[test]
    fn off_witness_cannot_follow_a_changed_config_root_even_if_both_are_absent() {
        let (mut guard, _parent) = fixture();
        let old_root = crate::policy::config_dir().unwrap();
        let off = TeamEnrollment::capture_runtime().unwrap();
        let other = guard.roots().home.join("other-config");
        std::fs::create_dir(&other).unwrap();
        guard.set_env("XDG_CONFIG_HOME", &other);
        assert_ne!(crate::policy::config_dir().as_ref(), Some(&old_root));
        assert_eq!(off.revalidate(), Err(EnrollmentError::ChangedEnrollment));
        let new_off = TeamEnrollment::capture_runtime().unwrap();
        assert!(new_off.revalidate().is_ok());
    }
    #[test]
    fn no_root_witness_is_invalid_when_a_root_is_selected_and_probe_is_bounded() {
        let (_guard, _parent) = fixture();
        assert!(runtime_entry_absent(None).unwrap());
        let no_root = RuntimeEnrollment::Off { config_root: None };
        assert!(no_root.document().is_none());
        assert!(no_root.evidence().is_none());
        assert_eq!(
            no_root.revalidate(),
            Err(EnrollmentError::ChangedEnrollment)
        );
        for path in [
            PathBuf::from("relative"),
            PathBuf::from("/parent/../other"),
            PathBuf::from(format!("/{}", "x".repeat(8192))),
            PathBuf::from(format!("/{}", "part/".repeat(128))),
        ] {
            assert_eq!(
                runtime_entry_absent(Some(&path)),
                Err(EnrollmentError::UnsafeStorage)
            );
        }
    }
    #[test]
    fn off_does_not_read_broken_selected_connection_or_create_enrollment() {
        let (_guard, parent) = fixture();
        private_file(
            &parent.join("connection.json"),
            b"broken selected connection",
        );
        let off = TeamEnrollment::capture_runtime().unwrap();
        assert!(off.document().is_none());
        assert!(off.evidence().is_none());
        assert!(off.revalidate().is_ok());
        assert!(!parent.join("enrollment.json").exists());
    }
    #[test]
    fn absent_runtime_witness_detects_later_enrollment_without_recapture() {
        let (_guard, parent) = fixture();
        let off = TeamEnrollment::capture_runtime().unwrap();
        private_file(&parent.join("enrollment.json"), b"{}");
        assert_eq!(off.revalidate(), Err(EnrollmentError::ChangedEnrollment));
    }
    #[test]
    fn admitted_ids_come_from_exact_private_cache_and_projection_contains_no_private_material() {
        let (_guard, parent) = fixture();
        let connection = connection(&parent);
        let r = enrollment(&connection, now_ms().unwrap());
        let witness = install(&parent, &r);
        let runtime = witness.admit_runtime().unwrap();
        let evidence = runtime.evidence().unwrap();
        assert_eq!(evidence.connection_id(), &r.connection_id);
        assert_eq!(evidence.authority_id(), &r.authority_id);
        assert_eq!(evidence.policy_id(), &r.policy_id);
        assert_eq!(evidence.activation_id(), &r.activation_id);
        assert_eq!(evidence.client_id(), &r.client_id);
        assert_eq!(
            evidence.revision(),
            &r.cached_policy.as_ref().unwrap().revision
        );
        assert_eq!(evidence.fetched_unix_ms(), r.fetched_unix_ms);
        let output = serde_json::to_string(&evidence).unwrap();
        for secret in [
            "yaml",
            "paranoia",
            "selection_commitment",
            r.selection_commitment.as_str(),
            &"c".repeat(64),
        ] {
            assert!(!output.contains(secret));
        }
    }
    #[test]
    fn stale_missing_invalid_and_future_cache_refuse_runtime_but_allow_exact_disable() {
        let (_guard, parent) = fixture();
        let connection = connection(&parent);
        let now = now_ms().unwrap();
        for kind in ["stale", "missing", "invalid", "future"] {
            let mut r = enrollment(&connection, now);
            match kind {
                "stale" => r.fetched_unix_ms = now - CACHE_MAX_AGE_MS,
                "missing" => r.cached_policy = None,
                "invalid" => r.cached_policy.as_mut().unwrap().yaml = "paranoia: [".into(),
                _ => r.fetched_unix_ms = now + 60_000,
            }
            let witness = install(&parent, &r);
            assert!(witness.admit_runtime().is_err(), "{kind}");
            let intent = witness.prepare_disable(&r.activation_id).unwrap();
            assert_eq!(intent.kind(), EnrollmentWriteKind::Disable);
            assert!(intent.replacement().is_none());
            assert!(intent.revalidate().is_ok());
            assert_eq!(
                intent.expected_private_bytes(),
                Some(serde_json::to_vec(&r).unwrap().as_slice())
            );
        }
    }
    #[test]
    fn changed_connection_refuses_runtime_and_sync_but_explicit_disable_remains_available() {
        let (_guard, parent) = fixture();
        let old_connection = connection(&parent);
        let r = enrollment(&old_connection, now_ms().unwrap());
        let witness = install(&parent, &r);
        let runtime = witness.admit_runtime().unwrap();
        let new_connection = connection(&parent);
        assert_eq!(
            runtime.revalidate(),
            Err(EnrollmentError::ChangedConnection)
        );
        assert_eq!(
            witness.admit_runtime().err(),
            Some(EnrollmentError::ChangedConnection)
        );
        assert!(witness.prepare_disable(&r.activation_id).is_ok());
        assert_eq!(
            witness
                .prepare_sync(
                    &r.activation_id,
                    fetched(new_connection.clone(), now_ms().unwrap())
                )
                .err(),
            Some(EnrollmentError::ChangedConnection)
        );
        let activate = witness
            .prepare_activation(
                Some(&r.activation_id),
                fetched(new_connection, now_ms().unwrap()),
            )
            .unwrap();
        let saved = decode(activate.replacement().unwrap().as_bytes()).unwrap();
        assert_ne!(saved.activation_id, r.activation_id);
    }
    #[test]
    fn sync_cannot_reinterpret_an_unchanged_selected_credentials_client_identity() {
        let (_guard, parent) = fixture();
        let connection = connection(&parent);
        let r = enrollment(&connection, now_ms().unwrap());
        let witness = install(&parent, &r);
        let mut observation = fetched(connection.clone(), now_ms().unwrap());
        observation.capabilities.client_id = Some(Id::new());
        assert_eq!(
            witness.prepare_sync(&r.activation_id, observation).err(),
            Some(EnrollmentError::ChangedConnection)
        );
        let mut observation = fetched(connection, now_ms().unwrap());
        let new_client = Id::new();
        observation.capabilities.client_id = Some(new_client.clone());
        let intent = witness
            .prepare_activation(Some(&r.activation_id), observation)
            .unwrap();
        let saved = decode(intent.replacement().unwrap().as_bytes()).unwrap();
        assert_eq!(saved.client_id, new_client);
        assert_ne!(saved.activation_id, r.activation_id);
    }
    #[test]
    fn same_bytes_connection_replacement_is_a_new_generation() {
        let (_guard, parent) = fixture();
        let connection = connection(&parent);
        let r = enrollment(&connection, now_ms().unwrap());
        let runtime = install(&parent, &r).admit_runtime().unwrap();
        let raw = std::fs::read(parent.join("connection.json")).unwrap();
        private_file(&parent.join("next.json"), &raw);
        std::fs::rename(parent.join("next.json"), parent.join("connection.json")).unwrap();
        assert_eq!(
            runtime.revalidate(),
            Err(EnrollmentError::ChangedConnection)
        );
        assert_eq!(
            TeamEnrollment::capture_runtime().err(),
            Some(EnrollmentError::ChangedConnection)
        );
    }
    #[test]
    fn malformed_record_removal_needs_exact_capture_and_preserves_replaced_bytes() {
        let (_guard, parent) = fixture();
        private_file(&parent.join("enrollment.json"), b"{invalid");
        let witness = Arc::new(TeamEnrollment::capture_current().unwrap());
        assert_eq!(
            witness.admit_runtime().err(),
            Some(EnrollmentError::InvalidRecord)
        );
        assert!(witness.prepare_disable(&Id::new()).is_err());
        assert!(witness.prepare_malformed_removal(&Id::new()).is_err());
        let intent = witness
            .prepare_malformed_removal(witness.capture_id())
            .unwrap();
        assert_eq!(intent.kind(), EnrollmentWriteKind::RemoveMalformed);
        private_file(&parent.join("enrollment.json"), b"{changed");
        assert!(intent.revalidate().is_err());
        assert_eq!(
            std::fs::read(parent.join("enrollment.json")).unwrap(),
            b"{changed"
        );
    }
    #[test]
    fn valid_record_cannot_use_malformed_repair_or_disable_another_activation() {
        let (_guard, parent) = fixture();
        let connection = connection(&parent);
        let r = enrollment(&connection, now_ms().unwrap());
        let witness = install(&parent, &r);
        assert!(witness
            .prepare_malformed_removal(witness.capture_id())
            .is_err());
        assert!(witness.prepare_disable(&Id::new()).is_err());
        assert!(witness
            .prepare_activation(None, fetched(connection, now_ms().unwrap()))
            .is_err());
    }
    #[test]
    fn sync_preserves_activation_while_activation_mints_a_new_id_and_neither_reports_applied() {
        let (_guard, parent) = fixture();
        let connection = connection(&parent);
        let r = enrollment(&connection, now_ms().unwrap());
        let witness = install(&parent, &r);
        let observation = fetched(connection.clone(), now_ms().unwrap());
        let revision = observation.document.revision.clone();
        let sync = witness.prepare_sync(&r.activation_id, observation).unwrap();
        let bytes = sync.replacement().unwrap().as_bytes();
        let saved = decode(bytes).unwrap();
        assert_eq!(saved.activation_id, r.activation_id);
        assert_eq!(saved.cached_policy.unwrap().revision, revision);
        let encoded = std::str::from_utf8(bytes).unwrap();
        assert!(!encoded.contains("applied"));
        assert!(!encoded.contains(&"c".repeat(64)));
        assert_eq!(
            std::fs::read(parent.join("enrollment.json")).unwrap(),
            serde_json::to_vec(&r).unwrap()
        );
        let activate = witness
            .prepare_activation(
                Some(&r.activation_id),
                fetched(connection, now_ms().unwrap()),
            )
            .unwrap();
        assert_ne!(
            decode(activate.replacement().unwrap().as_bytes())
                .unwrap()
                .activation_id,
            r.activation_id
        );
    }
    #[test]
    fn publication_intent_expires_with_fetch_or_authentication_and_has_no_write_effect() {
        let (_guard, parent) = fixture();
        let connection = connection(&parent);
        let witness = Arc::new(TeamEnrollment::capture_current().unwrap());
        let mut observation = fetched(connection.clone(), now_ms().unwrap());
        observation.fetched_unix_ms -= FETCH_PREPARATION_MAX_AGE_MS;
        assert_eq!(
            witness.prepare_activation(None, observation).err(),
            Some(EnrollmentError::FetchExpired)
        );
        let mut observation = fetched(connection, now_ms().unwrap());
        observation.capabilities.credential_expires_unix_ms = 1;
        assert_eq!(
            witness.prepare_activation(None, observation).err(),
            Some(EnrollmentError::AuthenticationFailed)
        );
        assert!(!parent.join("enrollment.json").exists());
    }
    #[test]
    fn publisher_and_observer_observations_cannot_prepare_runtime_enrollment() {
        let (_guard, parent) = fixture();
        let connection = connection(&parent);
        let witness = Arc::new(TeamEnrollment::capture_current().unwrap());
        for role in [Role::Publisher, Role::Observer] {
            let mut observation = fetched(connection.clone(), now_ms().unwrap());
            observation.capabilities.role = role;
            observation.capabilities.client_id = None;
            observation.capabilities.client_report_sequence = None;
            assert_eq!(
                witness.prepare_activation(None, observation).err(),
                Some(EnrollmentError::ClientRoleRequired)
            );
        }
    }
    #[test]
    fn retained_enrollment_refuses_same_bytes_replacement_and_parent_replacement() {
        let (_guard, parent) = fixture();
        let connection = connection(&parent);
        let r = enrollment(&connection, now_ms().unwrap());
        let witness = install(&parent, &r);
        private_file(&parent.join("next.json"), &serde_json::to_vec(&r).unwrap());
        std::fs::rename(parent.join("next.json"), parent.join("enrollment.json")).unwrap();
        assert!(witness.revalidate().is_err());
        let witness = Arc::new(TeamEnrollment::capture_current().unwrap());
        std::fs::rename(&parent, parent.with_extension("old")).unwrap();
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        private_file(
            &parent.join("enrollment.json"),
            &serde_json::to_vec(&r).unwrap(),
        );
        assert!(witness.revalidate().is_err());
    }
    #[test]
    fn native_enrollment_reader_refuses_shared_linked_special_and_oversized_records() {
        let (_guard, parent) = fixture();
        let path = parent.join("enrollment.json");
        private_file(&parent.join("target"), b"{}");
        symlink(parent.join("target"), &path).unwrap();
        assert!(TeamEnrollment::capture_current().is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(parent.join("target"), &path).unwrap();
        assert!(TeamEnrollment::capture_current().is_err());
        std::fs::remove_file(&path).unwrap();
        private_file(&path, b"{}");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(TeamEnrollment::capture_current().is_err());
        private_file(&path, &vec![b' '; MAX_ENROLLMENT_BYTES + 1]);
        assert!(TeamEnrollment::capture_current().is_err());
        std::fs::remove_file(&path).unwrap();
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(TeamEnrollment::capture_current().is_err());
    }
    #[test]
    fn runtime_composes_cached_team_repo_and_list_restrictions_and_reports_exact_capture() {
        use crate::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
        let (state, parent) = fixture();
        let connection = connection(&parent);
        let mut r = enrollment(&connection, now_ms().unwrap());
        r.cached_policy.as_mut().unwrap().yaml =
            "paranoia: 2\nblocklist: [team-deny.example]\n".into();
        let _witness = install(&parent, &r);
        let cwd = &state.roots().cwd;
        std::fs::create_dir_all(cwd.join(".git")).unwrap();
        std::fs::create_dir_all(cwd.join(".tirith")).unwrap();
        std::fs::write(
            cwd.join(".tirith/policy.yaml"),
            "paranoia: 4\nblocklist: [repo-deny.example]\nallowlist: [repo-grant.example]\n",
        )
        .unwrap();
        std::fs::write(
            parent.parent().unwrap().join("blocklist"),
            "local-deny.example\n",
        )
        .unwrap();
        let snapshot = EffectivePolicySnapshot::resolve(cwd.to_str(), ResolutionMode::Runtime);
        assert_eq!(snapshot.policy.paranoia, 4);
        assert_eq!(snapshot.policy.scope, crate::policy::PolicyScope::Remote);
        for domain in [
            "team-deny.example",
            "repo-deny.example",
            "local-deny.example",
        ] {
            assert!(snapshot.policy.is_blocklisted(domain));
        }
        assert!(!snapshot
            .policy
            .allowlist
            .iter()
            .any(|domain| domain == "repo-grant.example"));
        assert_eq!(snapshot.remote.availability, "team_enrolled_cache");
        assert!(snapshot.revalidate_for_mutation().is_err());
        let evidence = snapshot.team_runtime_evidence().unwrap().unwrap();
        assert_eq!(evidence.activation_id(), &r.activation_id);
        assert_eq!(evidence.client_id(), &r.client_id);
        assert_eq!(
            evidence.revision(),
            &r.cached_policy.as_ref().unwrap().revision
        );
        assert_eq!(evidence.fetched_unix_ms(), r.fetched_unix_ms);
        std::fs::write(
            parent.parent().unwrap().join("blocklist"),
            "changed.example\n",
        )
        .unwrap();
        assert!(snapshot.team_runtime_evidence().is_err());
    }
    #[test]
    fn runtime_never_falls_back_from_stale_or_malformed_enrollment_to_personal_policy() {
        use crate::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
        let (_state, parent) = fixture();
        std::fs::write(
            parent.parent().unwrap().join("policy.yaml"),
            "paranoia: 1\n",
        )
        .unwrap();
        let connection = connection(&parent);
        let mut r = enrollment(&connection, now_ms().unwrap());
        r.fetched_unix_ms -= CACHE_MAX_AGE_MS;
        let _witness = install(&parent, &r);
        for bytes in [serde_json::to_vec(&r).unwrap(), b"{malformed".to_vec()] {
            private_file(&parent.join("enrollment.json"), &bytes);
            let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
            assert_eq!(snapshot.policy.path.as_deref(), Some("fail-closed"));
            assert_eq!(snapshot.remote.availability, "team_enrollment_refused");
            assert!(snapshot.team_runtime_evidence().is_err());
            assert!(snapshot.revalidate_captured().is_err());
        }
    }
    #[test]
    fn runtime_evidence_is_refused_after_same_bytes_enrollment_replacement() {
        use crate::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
        let (_state, parent) = fixture();
        let connection = connection(&parent);
        let r = enrollment(&connection, now_ms().unwrap());
        let _witness = install(&parent, &r);
        let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert!(snapshot.team_runtime_evidence().unwrap().is_some());
        private_file(&parent.join("next.json"), &serde_json::to_vec(&r).unwrap());
        std::fs::rename(parent.join("next.json"), parent.join("enrollment.json")).unwrap();
        assert!(snapshot.team_runtime_evidence().is_err());
    }
    #[test]
    fn explicit_team_runtime_refuses_an_existing_trusted_legacy_authority() {
        use crate::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
        let (_state, parent) = fixture();
        let connection = connection(&parent);
        let r = enrollment(&connection, now_ms().unwrap());
        let _witness = install(&parent, &r);
        std::fs::write(
            parent.parent().unwrap().join("policy.yaml"),
            "policy_server_url: must-not-connect://legacy\npolicy_server_api_key: stored-secret\n",
        )
        .unwrap();
        let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert_eq!(snapshot.policy.path.as_deref(), Some("fail-closed"));
        assert!(snapshot.team_runtime_evidence().is_err());
        assert!(EffectivePolicySnapshot::resolve_team_preview(
            None,
            r.cached_policy.as_ref().unwrap()
        )
        .is_err());
    }
    #[test]
    fn absent_runtime_snapshot_is_invalidated_by_explicit_enrollment() {
        use crate::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
        let (_state, parent) = fixture();
        let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert_eq!(snapshot.team_runtime_evidence().unwrap(), None);
        let connection = connection(&parent);
        let r = enrollment(&connection, now_ms().unwrap());
        let _witness = install(&parent, &r);
        assert!(snapshot.revalidate_captured().is_err());
    }
}
