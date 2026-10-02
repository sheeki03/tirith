//! Fixed, bounded observations of newer private stores. These are format
//! declarations, never authority to retry a request or recover a target tree.
use super::FormatFact;
use crate::cli::setup::fs_helpers;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) const RECOVERY_RULE: &str =
    "linux_only_schema2_bound_review_fresh_policy_and_exact_current_ownership_required";
pub(crate) const INVENTORY_SCOPE: &str =
    "fixed_team_records_and_bounded_rollout_materialization_and_npm_install_intents_and_completion_milestones_and_shell_receipts; external_target_checkpoints_not_discovered";

/// Missing contracts deserialize to empty readers and fail compatibility.
/// Unknown fields are refused: adding a stored surface requires review.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedFormats {
    #[serde(default)]
    pub shell_execution_receipt: Vec<u32>,
    pub team_connection: Vec<u32>,
    pub team_enrollment: Vec<u32>,
    pub team_report: Vec<u32>,
    pub team_rollout: Vec<u32>,
    pub team_policy_document: Vec<u32>,
    pub team_policy_semantics: Vec<u32>,
    pub npm_materialization_intent: Vec<u32>,
    /// Historical closed-install records, not a native execution/recovery claim.
    #[serde(default)]
    pub npm_install_intent: Vec<u32>,
    /// Signed complete-only npm reconfirmation; never install replay or deletion.
    #[serde(default)]
    pub npm_install_completion_milestone: Vec<u32>,
    pub npm_materialization_checkpoint: Vec<u32>,
    pub npm_materialization_inventory: Vec<u32>,
    pub npm_materialization_recovery_rule: String,
}
impl PersistedFormats {
    pub(crate) fn current() -> Self {
        let team = tirith_core::policy_team::SCHEMA_VERSION;
        Self {
            shell_execution_receipt: tirith_core::execution_state::SHELL_RECEIPT_READ_VERSIONS
                .to_vec(),
            team_connection: vec![team],
            team_enrollment: vec![team],
            team_report: vec![team],
            team_rollout: vec![team],
            team_policy_document: vec![team],
            team_policy_semantics: vec![tirith_core::policy_team::POLICY_SEMANTICS_VERSION],
            // Schema 1 remains readable history, but cannot authorize mutation.
            npm_materialization_intent: vec![1, crate::cli::npm_materialize::INTENT_SCHEMA_VERSION],
            npm_install_intent: vec![crate::cli::npm_install::INTENT_SCHEMA_VERSION],
            npm_install_completion_milestone: vec![
                crate::cli::npm_install_recovery::RECOVERY_MILESTONE_SCHEMA_VERSION,
            ],
            npm_materialization_checkpoint: vec![
                crate::cli::npm_materialize::CHECKPOINT_SCHEMA_VERSION,
            ],
            npm_materialization_inventory: vec![
                tirith_core::artifact::npm_install::materialize::RECOVERY_INVENTORY_VERSION,
            ],
            npm_materialization_recovery_rule: RECOVERY_RULE.into(),
        }
    }
    pub(crate) fn readers(&self) -> [(&'static str, &Vec<u32>); 12] {
        [
            ("shell_execution_receipt", &self.shell_execution_receipt),
            ("team_connection", &self.team_connection),
            ("team_enrollment", &self.team_enrollment),
            ("team_report", &self.team_report),
            ("team_rollout", &self.team_rollout),
            ("team_policy_document", &self.team_policy_document),
            ("team_policy_semantics", &self.team_policy_semantics),
            (
                "npm_materialization_intent",
                &self.npm_materialization_intent,
            ),
            ("npm_install_intent", &self.npm_install_intent),
            (
                "npm_install_completion_milestone",
                &self.npm_install_completion_milestone,
            ),
            (
                "npm_materialization_checkpoint",
                &self.npm_materialization_checkpoint,
            ),
            (
                "npm_materialization_inventory",
                &self.npm_materialization_inventory,
            ),
        ]
    }
    pub(crate) fn versions(&self, surface: &str) -> Option<&Vec<u32>> {
        self.readers()
            .into_iter()
            .find_map(|(name, versions)| (name == surface).then_some(versions))
    }
    pub(crate) fn validate(&self) -> Result<(), String> {
        for (_, versions) in self.readers() {
            if versions.len() > 32
                || versions.contains(&0)
                || versions
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != versions.len()
            {
                return Err("candidate persisted-format readers are invalid".into());
            }
        }
        if self.npm_materialization_recovery_rule.len() > 128 {
            return Err("candidate materialization recovery contract is oversized".into());
        }
        Ok(())
    }
    pub(crate) fn supports_current_contract(&self) -> bool {
        Self::current()
            .readers()
            .into_iter()
            .all(|(surface, required)| {
                self.versions(surface).is_some_and(|versions| {
                    required.iter().all(|version| versions.contains(version))
                })
            })
            && self.npm_materialization_recovery_rule == RECOVERY_RULE
    }
}

const DIRECTORY_CAP: usize = 1024;
const TOTAL_BYTES: usize = 16 * 1024 * 1024;
struct Budget {
    remaining: usize,
    started: Instant,
}
impl Budget {
    fn new() -> Self {
        Self {
            remaining: TOTAL_BYTES,
            started: Instant::now(),
        }
    }
    fn available(&self) -> bool {
        self.remaining > 0 && self.started.elapsed() < Duration::from_secs(1)
    }
}
fn unknown(surface: &'static str, state: &'static str) -> FormatFact {
    FormatFact {
        surface,
        declared_version: None,
        state,
    }
}
fn private_observation(
    path: &Path,
    scope: &Path,
    surface: &'static str,
    field: &str,
    cap: usize,
    budget: &mut Budget,
) -> (FormatFact, Option<serde_json::Value>) {
    if !budget.available() {
        return (unknown(surface, "inventory_limited"), None);
    }
    let snapshot =
        match fs_helpers::read_snapshot_scoped_capped(path, scope, cap.min(budget.remaining)) {
            Ok(snapshot) if snapshot.require_private().is_ok() => snapshot,
            _ => return (unknown(surface, "unreadable"), None),
        };
    let Some(bytes) = snapshot.bytes else {
        return (unknown(surface, "absent"), None);
    };
    budget.remaining = budget.remaining.saturating_sub(bytes.len());
    let value = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| tirith_core::mcp_lock::parse_json_no_duplicates(text).ok());
    let version = value
        .as_ref()
        .filter(|value| value.is_object())
        .and_then(|value| value.get(field))
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0);
    (
        FormatFact {
            surface,
            declared_version: version,
            state: if version.is_some() {
                "declared_local_unverified"
            } else {
                "invalid"
            },
        },
        value,
    )
}
#[cfg(test)]
fn private_fact(
    path: &Path,
    scope: &Path,
    surface: &'static str,
    field: &str,
    cap: usize,
    budget: &mut Budget,
) -> FormatFact {
    private_observation(path, scope, surface, field, cap, budget).0
}

fn policy_document_facts(
    document: Option<&serde_json::Value>,
    optional: bool,
    facts: &mut Vec<FormatFact>,
) {
    if optional && document.is_none_or(serde_json::Value::is_null) {
        return;
    }
    for (surface, field) in [
        ("team_policy_document", "schema_version"),
        ("team_policy_semantics", "policy_semantics_version"),
    ] {
        let version = document
            .filter(|value| value.is_object())
            .and_then(|value| value.get(field))
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .filter(|version| *version > 0);
        facts.push(FormatFact {
            surface,
            declared_version: version,
            state: if version.is_some() {
                "declared_local_unverified"
            } else {
                "invalid"
            },
        });
    }
}

fn canonical_id(value: &str) -> bool {
    tirith_core::policy_team::Id::parse(value).is_ok()
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordDirectory {
    TeamRollout,
    Materialization,
    NpmInstall,
    NpmCompletion,
}
fn supported_name(name: &std::ffi::OsStr, kind: RecordDirectory) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    if kind == RecordDirectory::TeamRollout {
        return name.strip_suffix(".json").is_some_and(canonical_id);
    }
    let Some((id, suffix)) = name.split_once('.') else {
        return false;
    };
    canonical_id(id)
        && match kind {
            RecordDirectory::TeamRollout => false,
            RecordDirectory::Materialization => matches!(
                suffix,
                "intent.json"
                    | "started.json"
                    | "finished.json"
                    | "withdrawn.json"
                    | "recovered.json"
                    | "undone.json"
                    | "confirm-started.json"
                    | "undo-started.json"
                    | "continue-undo-started.json"
                    | "continued-undo.json"
            ),
            // The only recovery history is complete-only public reconfirmation.
            RecordDirectory::NpmInstall => matches!(
                suffix,
                "intent.json"
                    | "started.json"
                    | "finished.json"
                    | "withdrawn.json"
                    | "recovered.json"
            ),
            RecordDirectory::NpmCompletion => matches!(suffix, "private.json" | "committed.json"),
        }
}
fn directory_facts(
    directory: &Path,
    scope: &Path,
    surface: &'static str,
    kind: RecordDirectory,
    budget: &mut Budget,
    facts: &mut Vec<FormatFact>,
) {
    if !budget.available() {
        facts.push(unknown(surface, "inventory_limited"));
        return;
    }
    let (mut names, limited) =
        match fs_helpers::private_directory_names(directory, scope, DIRECTORY_CAP) {
            Ok(result) => result,
            Err(_) => {
                facts.push(unknown(surface, "unreadable"));
                return;
            }
        };
    names.sort();
    if limited {
        facts.push(unknown(surface, "inventory_limited"));
    }
    if names.is_empty() && !limited {
        facts.push(unknown(surface, "absent"));
    }
    for name in &names {
        if !budget.available() {
            facts.push(unknown(surface, "inventory_limited"));
            break;
        }
        if !supported_name(name, kind) {
            facts.push(unknown(surface, "unknown_entry"));
            continue;
        }
        let (fact, value) = private_observation(
            &directory.join(name),
            scope,
            surface,
            if kind != RecordDirectory::TeamRollout {
                "schema"
            } else {
                "schema_version"
            },
            if kind != RecordDirectory::TeamRollout {
                64 * 1024
            } else {
                4 * 1024 * 1024
            },
            budget,
        );
        // An enumerated entry disappearing is a partial observation, not absence.
        facts.push(if fact.state == "absent" {
            unknown(surface, "inventory_changed")
        } else {
            fact
        });
        if kind == RecordDirectory::TeamRollout {
            for field in ["before", "candidate"] {
                policy_document_facts(
                    value.as_ref().and_then(|value| value.get(field)),
                    false,
                    facts,
                );
            }
        }
    }
    match fs_helpers::private_directory_names(directory, scope, DIRECTORY_CAP) {
        Ok((mut after, after_limited)) => {
            after.sort();
            if after != names || after_limited != limited {
                facts.push(unknown(surface, "inventory_changed"));
            }
        }
        Err(_) => facts.push(unknown(surface, "inventory_changed")),
    }
    if kind != RecordDirectory::TeamRollout && !cfg!(target_os = "linux") && !names.is_empty() {
        facts.push(unknown(
            surface,
            if kind == RecordDirectory::Materialization {
                "recovery_unsupported_on_this_platform"
            } else {
                "operation_state_unsupported_on_this_platform"
            },
        ));
    }
}
fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn receipt_auxiliary_name(name: &str) -> bool {
    name == ".receipt-registry.lock"
        || name
            .strip_suffix(".lock")
            .is_some_and(|stem| lower_hex(stem, 64))
        || name.strip_prefix(".hook-").is_some_and(|rest| {
            rest.strip_suffix(".capability")
                .or_else(|| rest.strip_suffix(".capability.lock"))
                .is_some_and(|stem| lower_hex(stem, 64))
        })
}

/// Observe receipt format declarations only. The known lock/capability names
/// are not receipt payloads; this does not claim to authenticate those stores.
fn shell_receipt_facts(scope: &Path, budget: &mut Budget, facts: &mut Vec<FormatFact>) {
    const SURFACE: &str = "shell_execution_receipt";
    let directory = scope.join("sessions/execution-receipts");
    if !budget.available() {
        facts.push(unknown(SURFACE, "inventory_limited"));
        return;
    }
    let (mut names, limited) =
        match fs_helpers::private_directory_names(&directory, scope, DIRECTORY_CAP) {
            Ok(result) => result,
            Err(_) => {
                facts.push(unknown(SURFACE, "unreadable"));
                return;
            }
        };
    names.sort();
    if limited {
        facts.push(unknown(SURFACE, "inventory_limited"));
    }
    let mut observed = false;
    for name in &names {
        if !budget.available() {
            facts.push(unknown(SURFACE, "inventory_limited"));
            break;
        }
        if name.to_str().is_some_and(receipt_auxiliary_name) {
            continue;
        }
        observed = true;
        if !name
            .to_str()
            .and_then(|name| name.strip_suffix(".json"))
            .is_some_and(|stem| lower_hex(stem, 64))
        {
            facts.push(unknown(SURFACE, "unknown_entry"));
            continue;
        }
        let (fact, _) = private_observation(
            &directory.join(name),
            scope,
            SURFACE,
            "schema_version",
            64 * 1024,
            budget,
        );
        facts.push(if fact.state == "absent" {
            unknown(SURFACE, "inventory_changed")
        } else {
            fact
        });
    }
    if !observed && !limited {
        facts.push(unknown(SURFACE, "absent"));
    }
    match fs_helpers::private_directory_names(&directory, scope, DIRECTORY_CAP) {
        Ok((mut after, after_limited)) => {
            after.sort();
            if after != names || after_limited != limited {
                facts.push(unknown(SURFACE, "inventory_changed"));
            }
        }
        Err(_) => facts.push(unknown(SURFACE, "inventory_changed")),
    }
}

pub(super) fn observe(config: Option<&Path>, state: Option<&Path>) -> Vec<FormatFact> {
    let mut budget = Budget::new();
    let mut facts = Vec::new();
    if let Some(scope) = config {
        for (name, surface, cap) in [
            (
                "connection.json",
                "team_connection",
                tirith_core::policy_team_connection::MAX_CONNECTION_BYTES,
            ),
            (
                "enrollment.json",
                "team_enrollment",
                tirith_core::policy_team_enrollment::MAX_ENROLLMENT_BYTES,
            ),
            ("report.json", "team_report", 16 * 1024),
        ] {
            let (fact, value) = private_observation(
                &scope.join("team-policy").join(name),
                scope,
                surface,
                "schema_version",
                cap,
                &mut budget,
            );
            facts.push(fact);
            if surface == "team_enrollment" {
                policy_document_facts(
                    value.as_ref().and_then(|value| value.get("cached_policy")),
                    true,
                    &mut facts,
                );
            }
        }
        directory_facts(
            &scope.join("team-policy/rollouts"),
            scope,
            "team_rollout",
            RecordDirectory::TeamRollout,
            &mut budget,
            &mut facts,
        );
    } else {
        for surface in [
            "team_connection",
            "team_enrollment",
            "team_report",
            "team_rollout",
        ] {
            facts.push(unknown(surface, "configuration_root_unavailable"));
        }
    }
    if let Some(scope) = state {
        shell_receipt_facts(scope, &mut budget, &mut facts);
        directory_facts(
            &scope.join("materialization-intents"),
            scope,
            "npm_materialization_intent",
            RecordDirectory::Materialization,
            &mut budget,
            &mut facts,
        );
        directory_facts(
            &scope.join("npm-install-intents"),
            scope,
            "npm_install_intent",
            RecordDirectory::NpmInstall,
            &mut budget,
            &mut facts,
        );
        directory_facts(
            &scope.join("npm-install-recovery"),
            scope,
            "npm_install_completion_milestone",
            RecordDirectory::NpmCompletion,
            &mut budget,
            &mut facts,
        );
    } else {
        facts.push(unknown("shell_execution_receipt", "state_root_unavailable"));
        facts.push(unknown(
            "npm_materialization_intent",
            "state_root_unavailable",
        ));
        facts.push(unknown("npm_install_intent", "state_root_unavailable"));
        facts.push(unknown(
            "npm_install_completion_milestone",
            "state_root_unavailable",
        ));
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_reader_contract_is_closed_bounded_and_requires_recovery_semantics() {
        let current = PersistedFormats::current();
        assert!(current.validate().is_ok());
        assert!(current.supports_current_contract());
        assert!(!PersistedFormats::default().supports_current_contract());
        for (surface, _) in current.readers() {
            let mut raw = serde_json::to_value(&current).unwrap();
            raw[surface] = serde_json::json!([]);
            let missing: PersistedFormats = serde_json::from_value(raw).unwrap();
            assert!(!missing.supports_current_contract(), "{surface}");
            for invalid in [
                serde_json::json!([0]),
                serde_json::json!([1, 1]),
                serde_json::json!(vec![1; 33]),
            ] {
                let mut raw = serde_json::to_value(&current).unwrap();
                raw[surface] = invalid;
                assert!(
                    serde_json::from_value::<PersistedFormats>(raw)
                        .unwrap()
                        .validate()
                        .is_err(),
                    "{surface}"
                );
            }
        }
        let mut old = serde_json::to_value(&current).unwrap();
        old.as_object_mut()
            .unwrap()
            .remove("shell_execution_receipt");
        let old: PersistedFormats = serde_json::from_value(old).unwrap();
        assert!(old.shell_execution_receipt.is_empty());
        assert!(!old.supports_current_contract());
        assert_eq!(current.npm_materialization_intent, [1, 2]);
        let mut legacy_materialization = current.clone();
        legacy_materialization.npm_materialization_intent = vec![1];
        assert!(!legacy_materialization.supports_current_contract());
        assert_eq!(current.npm_install_intent, [1]);
        assert_eq!(current.npm_install_completion_milestone, [1]);
        let mut old = serde_json::to_value(&current).unwrap();
        old.as_object_mut().unwrap().remove("npm_install_intent");
        let old: PersistedFormats = serde_json::from_value(old).unwrap();
        assert!(old.npm_install_intent.is_empty());
        assert!(!old.supports_current_contract());
        let mut schema_three_only = current.clone();
        schema_three_only.shell_execution_receipt = vec![3];
        assert!(!schema_three_only.supports_current_contract());
        let mut raw = serde_json::to_value(&current).unwrap();
        raw["future_store"] = serde_json::json!([1]);
        assert!(serde_json::from_value::<PersistedFormats>(raw).is_err());
        let mut changed = current;
        changed.npm_materialization_recovery_rule = "blind_replay".into();
        assert!(!changed.supports_current_contract());
    }

    #[cfg(unix)]
    mod private_inventory {
        use super::*;
        use std::os::unix::fs::{symlink, PermissionsExt};

        fn directory(path: &Path) {
            std::fs::create_dir_all(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        fn file(path: &Path, bytes: &[u8]) {
            directory(path.parent().unwrap());
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        fn scope() -> tempfile::TempDir {
            let temp = tempfile::tempdir().unwrap();
            directory(temp.path());
            temp
        }
        #[test]
        fn absent_optional_stores_are_observed_without_creating_them() {
            let temp = scope();
            let facts = observe(Some(temp.path()), Some(temp.path()));
            assert_eq!(facts.len(), 8);
            assert!(facts.iter().all(|fact| fact.state == "absent"));
            assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
            assert!(observe(None, None)
                .iter()
                .all(|fact| fact.declared_version.is_none() && fact.state != "absent"));
        }
        #[test]
        fn receipt_inventory_distinguishes_ack_schema_without_exposing_private_payloads() {
            let temp = scope();
            let receipts = temp.path().join("sessions/execution-receipts");
            file(&receipts.join(".receipt-registry.lock"), b"");
            file(
                &receipts.join(format!(".hook-{}.capability", "a".repeat(64))),
                b"not inventoried",
            );
            for (index, version) in [3, 4, 99].into_iter().enumerate() {
                file(
                    &receipts.join(format!("{index:064x}.json")),
                    format!(r#"{{"schema_version":{version},"private":"receipt-secret"}}"#)
                        .as_bytes(),
                );
                file(&receipts.join(format!("{index:064x}.lock")), b"");
            }
            let facts = observe(None, Some(temp.path()));
            let receipts_facts: Vec<_> = facts
                .iter()
                .filter(|fact| fact.surface == "shell_execution_receipt")
                .collect();
            assert_eq!(receipts_facts.len(), 3);
            assert_eq!(
                receipts_facts
                    .iter()
                    .map(|fact| fact.declared_version)
                    .collect::<Vec<_>>(),
                vec![Some(3), Some(4), Some(99)]
            );
            assert!(!serde_json::to_string(&facts)
                .unwrap()
                .contains("receipt-secret"));
            file(&receipts.join("unexpected.json"), b"{}");
            assert!(observe(None, Some(temp.path()))
                .iter()
                .any(|fact| fact.surface == "shell_execution_receipt"
                    && fact.state == "unknown_entry"));
        }

        #[test]
        fn fixed_team_stores_and_journals_preserve_future_versions_without_private_contents() {
            let temp = scope();
            let id = "11111111-1111-4111-8111-111111111111";
            for name in ["connection.json", "enrollment.json", "report.json"] {
                file(
                    &temp.path().join("team-policy").join(name),
                    br#"{"schema_version":99,"credential":"secret-test-marker"}"#,
                );
            }
            file(
                &temp.path().join(format!("team-policy/rollouts/{id}.json")),
                br#"{"schema_version":99}"#,
            );
            file(
                &temp
                    .path()
                    .join(format!("materialization-intents/{id}.intent.json")),
                br#"{"schema":99,"target":"/not-followed/secret-test-marker"}"#,
            );
            let facts = observe(Some(temp.path()), Some(temp.path()));
            for surface in [
                "team_connection",
                "team_enrollment",
                "team_report",
                "team_rollout",
                "npm_materialization_intent",
            ] {
                assert!(
                    facts
                        .iter()
                        .any(|fact| fact.surface == surface && fact.declared_version == Some(99)),
                    "{surface}: {facts:?}"
                );
            }
            let output = serde_json::to_string(&facts).unwrap();
            assert!(!output.contains("secret-test-marker"));
            assert!(!output.contains(temp.path().to_str().unwrap()));
        }
        #[test]
        fn embedded_enrollment_and_both_rollout_documents_keep_unknown_versions_visible() {
            let temp = scope();
            let enrollment = temp.path().join("team-policy/enrollment.json");
            let rollout = temp
                .path()
                .join("team-policy/rollouts/11111111-1111-4111-8111-111111111111.json");
            let valid = serde_json::json!({"schema_version":1,"policy_semantics_version":1,"yaml":"private-policy-bytes"});
            for (field, surface) in [
                ("schema_version", "team_policy_document"),
                ("policy_semantics_version", "team_policy_semantics"),
            ] {
                for changed in [
                    serde_json::json!(99),
                    serde_json::json!("invalid"),
                    serde_json::Value::Null,
                ] {
                    if rollout.exists() {
                        std::fs::remove_file(&rollout).unwrap();
                    }
                    let expected_version = changed.as_u64().map(|value| value as u32);
                    let expected_state = if expected_version.is_some() {
                        "declared_local_unverified"
                    } else {
                        "invalid"
                    };
                    let mut document = valid.clone();
                    document[field] = changed.clone();
                    file(
                        &enrollment,
                        &serde_json::to_vec(
                            &serde_json::json!({"schema_version":1,"cached_policy":document}),
                        )
                        .unwrap(),
                    );
                    let facts = observe(Some(temp.path()), Some(temp.path()));
                    assert!(
                        facts.iter().any(|fact| fact.surface == surface
                            && fact.declared_version == expected_version
                            && fact.state == expected_state),
                        "enrollment {field}: {facts:?}"
                    );
                    for selected in ["before", "candidate"] {
                        let mut record = serde_json::json!({"schema_version":1,"before":valid,"candidate":valid});
                        record[selected][field] = changed.clone();
                        file(&rollout, &serde_json::to_vec(&record).unwrap());
                        // Remove enrollment so each assertion isolates the selected rollout document.
                        if enrollment.exists() {
                            std::fs::remove_file(&enrollment).unwrap();
                        }
                        let facts = observe(Some(temp.path()), Some(temp.path()));
                        assert!(
                            facts.iter().any(|fact| fact.surface == surface
                                && fact.declared_version == expected_version
                                && fact.state == expected_state),
                            "rollout {selected}/{field}: {facts:?}"
                        );
                        assert!(!serde_json::to_string(&facts)
                            .unwrap()
                            .contains("private-policy-bytes"));
                    }
                }
            }
        }
        #[test]
        fn malformed_duplicate_symlink_oversized_and_unknown_entries_remain_visible() {
            let temp = scope();
            let team = temp.path().join("team-policy");
            let connection = team.join("connection.json");
            for bytes in [
                br#"{"schema_version":1,"schema_version":2}"#.as_slice(),
                b"{truncated",
                br#"{"schema_version":0}"#,
            ] {
                file(&connection, bytes);
                assert_eq!(
                    observe(Some(temp.path()), Some(temp.path()))[0].state,
                    "invalid"
                );
            }
            file(
                &connection,
                &vec![b' '; tirith_core::policy_team_connection::MAX_CONNECTION_BYTES + 1],
            );
            assert_eq!(
                observe(Some(temp.path()), Some(temp.path()))[0].state,
                "unreadable"
            );
            std::fs::remove_file(&connection).unwrap();
            symlink("missing-secret-target", &connection).unwrap();
            assert_eq!(
                observe(Some(temp.path()), Some(temp.path()))[0].state,
                "unreadable"
            );
            assert!(std::fs::symlink_metadata(&connection)
                .unwrap()
                .file_type()
                .is_symlink());
            file(
                &team.join("rollouts/unrecognized.json"),
                br#"{"schema_version":1}"#,
            );
            assert!(observe(Some(temp.path()), Some(temp.path()))
                .iter()
                .any(|fact| fact.surface == "team_rollout" && fact.state == "unknown_entry"));
        }
        #[test]
        fn directory_and_byte_limits_never_look_like_absence() {
            let temp = scope();
            let rolls = temp.path().join("team-policy/rollouts");
            directory(&rolls);
            for index in 0..=DIRECTORY_CAP {
                file(&rolls.join(format!("entry-{index}")), b"{}");
            }
            let facts = observe(Some(temp.path()), Some(temp.path()));
            assert!(facts
                .iter()
                .any(|fact| fact.surface == "team_rollout" && fact.state == "inventory_limited"));
            let mut budget = Budget {
                remaining: 0,
                started: Instant::now(),
            };
            assert_eq!(
                private_fact(
                    &temp.path().join("missing"),
                    temp.path(),
                    "team_connection",
                    "schema_version",
                    16,
                    &mut budget
                )
                .state,
                "inventory_limited"
            );
        }
        #[test]
        fn private_storage_and_descendant_links_are_not_treated_as_ordinary_state() {
            let temp = scope();
            let connection = temp.path().join("team-policy/connection.json");
            file(&connection, br#"{"schema_version":1}"#);
            std::fs::set_permissions(&connection, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(
                observe(Some(temp.path()), Some(temp.path()))[0].state,
                "unreadable"
            );
            std::fs::remove_file(&connection).unwrap();
            std::fs::remove_dir(connection.parent().unwrap()).unwrap();
            let outside = scope();
            file(
                &outside.path().join("connection.json"),
                br#"{"schema_version":1,"credential":"outside-secret"}"#,
            );
            symlink(outside.path(), connection.parent().unwrap()).unwrap();
            let facts = observe(Some(temp.path()), Some(temp.path()));
            assert_eq!(facts[0].state, "unreadable");
            assert!(!serde_json::to_string(&facts)
                .unwrap()
                .contains("outside-secret"));
        }
        #[test]
        fn npm_install_names_are_distinct_and_observations_do_not_claim_recovery() {
            let temp = scope();
            let id = "11111111-1111-4111-8111-111111111111";
            let intents = temp.path().join("npm-install-intents");
            for suffix in ["intent", "started", "finished", "withdrawn", "recovered"] {
                file(&intents.join(format!("{id}.{suffix}.json")),
                    br#"{"schema":1,"target":"/never/followed/private-npm-target","private":"npm-private-marker"}"#);
            }
            let facts = observe(Some(temp.path()), Some(temp.path()));
            assert_eq!(
                facts
                    .iter()
                    .filter(|f| f.surface == "npm_install_intent" && f.declared_version == Some(1))
                    .count(),
                5
            );
            let output = serde_json::to_string(&facts).unwrap();
            assert!(!output.contains("npm-private-marker"));
            assert!(!output.contains("private-npm-target"));
            assert!(!output.contains(temp.path().to_str().unwrap()));
            if !cfg!(target_os = "linux") {
                assert!(facts.iter().any(|f| f.surface == "npm_install_intent"
                    && f.state == "operation_state_unsupported_on_this_platform"));
            }
            for suffix in ["private", "undone", "future-event"] {
                file(
                    &intents.join(format!("{id}.{suffix}.json")),
                    br#"{"schema":1}"#,
                );
            }
            assert_eq!(
                observe(Some(temp.path()), Some(temp.path()))
                    .iter()
                    .filter(|f| f.surface == "npm_install_intent" && f.state == "unknown_entry")
                    .count(),
                3
            );
            assert!(INVENTORY_SCOPE.contains("npm_install_intents"));
            assert!(INVENTORY_SCOPE.contains("external_target_checkpoints_not_discovered"));
        }
        #[test]
        fn npm_completion_store_inventory_is_closed_private_and_not_authentication() {
            let temp = scope();
            let id = "11111111-1111-4111-8111-111111111111";
            let root = temp.path().join("npm-install-recovery");
            for suffix in ["private", "committed"] {
                file(&root.join(format!("{id}.{suffix}.json")), br#"{"schema":1,"private_plan_digest":"never-export-me","target":"/never/follow"}"#);
            }
            let facts = observe(None, Some(temp.path()));
            assert_eq!(
                facts
                    .iter()
                    .filter(|f| f.surface == "npm_install_completion_milestone"
                        && f.declared_version == Some(1))
                    .count(),
                2
            );
            let public = serde_json::to_string(&facts).unwrap();
            assert!(!public.contains("never-export-me") && !public.contains("/never/follow"));
            file(&root.join(format!("{id}.replay.json")), br#"{"schema":1}"#);
            assert!(observe(None, Some(temp.path()))
                .iter()
                .any(|f| f.surface == "npm_install_completion_milestone"
                    && f.state == "unknown_entry"));
            let committed = root.join(format!("{id}.committed.json"));
            std::fs::remove_file(&committed).unwrap();
            symlink("never-followed", &committed).unwrap();
            assert!(observe(None, Some(temp.path())).iter().any(|f| f.surface
                == "npm_install_completion_milestone"
                && f.state == "unreadable"));
        }
        #[test]
        fn npm_install_unknown_versions_and_unsafe_records_do_not_disappear() {
            let temp = scope();
            let path = temp
                .path()
                .join("npm-install-intents/11111111-1111-4111-8111-111111111111.intent.json");
            file(&path, br#"{"schema":99}"#);
            assert!(observe(None, Some(temp.path()))
                .iter()
                .any(|f| f.surface == "npm_install_intent" && f.declared_version == Some(99)));
            for (bytes, expected) in [
                (br#"{"schema":1,"schema":2}"#.as_slice(), "invalid"),
                (b"{truncated".as_slice(), "invalid"),
                (&vec![b' '; 64 * 1024 + 1], "unreadable"),
            ] {
                file(&path, bytes);
                assert!(observe(None, Some(temp.path()))
                    .iter()
                    .any(|f| f.surface == "npm_install_intent" && f.state == expected));
            }
            std::fs::remove_file(&path).unwrap();
            symlink("not-followed-private-target", &path).unwrap();
            assert!(observe(None, Some(temp.path()))
                .iter()
                .any(|f| f.surface == "npm_install_intent" && f.state == "unreadable"));
            assert!(std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink());
            let mut facts = Vec::new();
            let mut budget = Budget {
                remaining: 0,
                started: Instant::now(),
            };
            directory_facts(
                path.parent().unwrap(),
                temp.path(),
                "npm_install_intent",
                RecordDirectory::NpmInstall,
                &mut budget,
                &mut facts,
            );
            assert_eq!(facts.len(), 1);
            assert_eq!(facts[0].state, "inventory_limited");
        }
        #[test]
        fn materialization_inventory_preserves_legacy_and_complete_review_declarations() {
            let temp = scope();
            let intents = temp.path().join("materialization-intents");
            for schema in [1, 2] {
                let id = uuid::Uuid::new_v4().to_string();
                for suffix in ["intent", "started"] {
                    file(&intents.join(format!("{id}.{suffix}.json")),
                        &serde_json::to_vec(&serde_json::json!({"schema":schema,
                            "target":"/not-followed/private-target", "review_nonce":"private-nonce"})).unwrap());
                }
            }
            let facts = observe(Some(temp.path()), Some(temp.path()));
            for schema in [1, 2] {
                assert_eq!(
                    facts
                        .iter()
                        .filter(|fact| fact.surface == "npm_materialization_intent"
                            && fact.declared_version == Some(schema)
                            && fact.state == "declared_local_unverified")
                        .count(),
                    2
                );
            }
            let output = serde_json::to_string(&facts).unwrap();
            assert!(!output.contains("private-target"));
            assert!(!output.contains("private-nonce"));
        }

        #[test]
        fn materialization_names_are_closed_and_external_targets_are_not_followed() {
            let temp = scope();
            let id = "11111111-1111-4111-8111-111111111111";
            let intents = temp.path().join("materialization-intents");
            file(
                &intents.join(format!("{id}.intent.json")),
                br#"{"schema":1,"target":"/a/nonexistent/external/checkpoint"}"#,
            );
            for suffix in [
                "started",
                "finished",
                "withdrawn",
                "recovered",
                "undone",
                "confirm-started",
                "undo-started",
                "continue-undo-started",
                "continued-undo",
            ] {
                file(
                    &intents.join(format!("{id}.{suffix}.json")),
                    br#"{"schema":1}"#,
                );
            }
            let facts = observe(Some(temp.path()), Some(temp.path()));
            assert_eq!(
                facts
                    .iter()
                    .filter(|fact| fact.surface == "npm_materialization_intent"
                        && fact.declared_version == Some(1))
                    .count(),
                10
            );
            assert!(INVENTORY_SCOPE.contains("external_target_checkpoints_not_discovered"));
            file(&intents.join(format!("{id}.future-event.json")), b"{}");
            assert!(observe(Some(temp.path()), Some(temp.path()))
                .iter()
                .any(|fact| fact.surface == "npm_materialization_intent"
                    && fact.state == "unknown_entry"));
        }
    }
}
