//! Fixed, bounded observations of newer private stores. These are format
//! declarations, never authority to retry a request or recover a target tree.
use super::FormatFact;
use crate::cli::setup::fs_helpers;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) const RECOVERY_RULE: &str =
    "linux_only_fresh_policy_and_exact_current_ownership_required";
pub(crate) const INVENTORY_SCOPE: &str =
    "fixed_team_records_and_bounded_rollout_and_materialization_intents; external_target_checkpoints_not_discovered";

/// Missing contracts deserialize to empty readers and fail compatibility.
/// Unknown fields are refused: adding a stored surface requires review.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersistedFormats {
    pub team_connection: Vec<u32>,
    pub team_enrollment: Vec<u32>,
    pub team_report: Vec<u32>,
    pub team_rollout: Vec<u32>,
    pub team_policy_document: Vec<u32>,
    pub team_policy_semantics: Vec<u32>,
    pub npm_materialization_intent: Vec<u32>,
    pub npm_materialization_checkpoint: Vec<u32>,
    pub npm_materialization_inventory: Vec<u32>,
    pub npm_materialization_recovery_rule: String,
}
impl PersistedFormats {
    pub(crate) fn current() -> Self {
        let team = tirith_core::policy_team::SCHEMA_VERSION;
        Self {
            team_connection: vec![team],
            team_enrollment: vec![team],
            team_report: vec![team],
            team_rollout: vec![team],
            team_policy_document: vec![team],
            team_policy_semantics: vec![tirith_core::policy_team::POLICY_SEMANTICS_VERSION],
            npm_materialization_intent: vec![crate::cli::npm_materialize::INTENT_SCHEMA_VERSION],
            npm_materialization_checkpoint: vec![
                crate::cli::npm_materialize::CHECKPOINT_SCHEMA_VERSION,
            ],
            npm_materialization_inventory: vec![
                tirith_core::artifact::npm_install::materialize::RECOVERY_INVENTORY_VERSION,
            ],
            npm_materialization_recovery_rule: RECOVERY_RULE.into(),
        }
    }
    pub(crate) fn readers(&self) -> [(&'static str, &Vec<u32>); 9] {
        [
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
    pub(crate) fn supports_current_recovery(&self) -> bool {
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
fn supported_name(name: &std::ffi::OsStr, materialization: bool) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    if !materialization {
        return name.strip_suffix(".json").is_some_and(canonical_id);
    }
    let Some((id, suffix)) = name.split_once('.') else {
        return false;
    };
    canonical_id(id)
        && matches!(
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
        )
}
fn directory_facts(
    directory: &Path,
    scope: &Path,
    surface: &'static str,
    materialization: bool,
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
        if !supported_name(name, materialization) {
            facts.push(unknown(surface, "unknown_entry"));
            continue;
        }
        let (fact, value) = private_observation(
            &directory.join(name),
            scope,
            surface,
            if materialization {
                "schema"
            } else {
                "schema_version"
            },
            if materialization {
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
        if !materialization {
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
    if materialization && !cfg!(target_os = "linux") && !names.is_empty() {
        facts.push(unknown(surface, "recovery_unsupported_on_this_platform"));
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
            false,
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
        directory_facts(
            &scope.join("materialization-intents"),
            scope,
            "npm_materialization_intent",
            true,
            &mut budget,
            &mut facts,
        );
    } else {
        facts.push(unknown(
            "npm_materialization_intent",
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
        assert!(current.supports_current_recovery());
        assert!(!PersistedFormats::default().supports_current_recovery());
        for (surface, _) in current.readers() {
            let mut raw = serde_json::to_value(&current).unwrap();
            raw[surface] = serde_json::json!([]);
            let missing: PersistedFormats = serde_json::from_value(raw).unwrap();
            assert!(!missing.supports_current_recovery(), "{surface}");
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
        let mut raw = serde_json::to_value(&current).unwrap();
        raw["future_store"] = serde_json::json!([1]);
        assert!(serde_json::from_value::<PersistedFormats>(raw).is_err());
        let mut changed = current;
        changed.npm_materialization_recovery_rule = "blind_replay".into();
        assert!(!changed.supports_current_recovery());
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
            assert_eq!(facts.len(), 5);
            assert!(facts.iter().all(|fact| fact.state == "absent"));
            assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
            assert!(observe(None, None)
                .iter()
                .all(|fact| fact.declared_version.is_none() && fact.state != "absent"));
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
