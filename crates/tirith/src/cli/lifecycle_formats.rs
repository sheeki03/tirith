//! Fixed, bounded observations of newer private stores. These are format
//! declarations, never authority to retry a request or recover a target tree.
use super::FormatFact;
use crate::cli::setup::fs_helpers;
use serde::Serialize;
use std::path::Path;
use std::time::{Duration, Instant};

pub(crate) const INVENTORY_SCOPE: &str =
    "fixed_team_records_and_bounded_rollouts_and_shell_receipts; external_target_checkpoints_not_discovered";

/// One version for every persisted-state contract this binary owns beyond the
/// policy, MCP-lock and trust readers (which release metadata lists
/// separately): the readers in [`PersistedFormats::current`], owned-change
/// journals (schema 1, exact originating client version), the control-service
/// protocol (1, exact binary identity), byte-preserving configuration updates,
/// and team Runtime enforcement with report/rollout recovery. A candidate or
/// rollback binary is compatible only if it reads this version. Changing any of
/// these requires a new version and a reviewed release generator contract.
pub(crate) const STATE_CONTRACT_VERSION: u32 = 1;

/// The stored-surface readers of [`STATE_CONTRACT_VERSION`]. Local stores
/// whose declared version is outside this table cannot be vouched for.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct PersistedFormats {
    pub shell_execution_receipt: Vec<u32>,
    pub team_connection: Vec<u32>,
    pub team_enrollment: Vec<u32>,
    pub team_report: Vec<u32>,
    pub team_rollout: Vec<u32>,
    pub team_policy_document: Vec<u32>,
    pub team_policy_semantics: Vec<u32>,
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
        }
    }
    pub(crate) fn readers(&self) -> [(&'static str, &Vec<u32>); 7] {
        [
            ("shell_execution_receipt", &self.shell_execution_receipt),
            ("team_connection", &self.team_connection),
            ("team_enrollment", &self.team_enrollment),
            ("team_report", &self.team_report),
            ("team_rollout", &self.team_rollout),
            ("team_policy_document", &self.team_policy_document),
            ("team_policy_semantics", &self.team_policy_semantics),
        ]
    }
    pub(crate) fn versions(&self, surface: &str) -> Option<&Vec<u32>> {
        self.readers()
            .into_iter()
            .find_map(|(name, versions)| (name == surface).then_some(versions))
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
/// Team rollout records are named `<canonical id>.json`; anything else is an
/// unknown entry.
fn supported_rollout_name(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .and_then(|name| name.strip_suffix(".json"))
        .is_some_and(canonical_id)
}
fn rollout_directory_facts(
    directory: &Path,
    scope: &Path,
    surface: &'static str,
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
        if !supported_rollout_name(name) {
            facts.push(unknown(surface, "unknown_entry"));
            continue;
        }
        let (fact, value) = private_observation(
            &directory.join(name),
            scope,
            surface,
            "schema_version",
            4 * 1024 * 1024,
            budget,
        );
        // An enumerated entry disappearing is a partial observation, not absence.
        facts.push(if fact.state == "absent" {
            unknown(surface, "inventory_changed")
        } else {
            fact
        });
        for field in ["before", "candidate"] {
            policy_document_facts(
                value.as_ref().and_then(|value| value.get(field)),
                false,
                facts,
            );
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
}
fn receipt_auxiliary_name(name: &str) -> bool {
    name == ".receipt-registry.lock"
        || name
            .strip_suffix(".lock")
            .is_some_and(|stem| tirith_core::util::is_lower_hex(stem, 64))
        || name.strip_prefix(".hook-").is_some_and(|rest| {
            rest.strip_suffix(".capability")
                .or_else(|| rest.strip_suffix(".capability.lock"))
                .is_some_and(|stem| tirith_core::util::is_lower_hex(stem, 64))
        })
        // PowerShell/Nushell hook load records (hook freshness evidence only).
        || name
            .strip_prefix(".hook-presence-")
            .and_then(|rest| rest.strip_suffix(".record"))
            .is_some_and(|stem| tirith_core::util::is_lower_hex(stem, 64))
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
            .is_some_and(|stem| tirith_core::util::is_lower_hex(stem, 64))
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
        rollout_directory_facts(
            &scope.join("team-policy/rollouts"),
            scope,
            "team_rollout",
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
    } else {
        facts.push(unknown("shell_execution_receipt", "state_root_unavailable"));
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_contract_v1_pins_every_persisted_reader() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // Independent literals: deriving expectations from the implementation
        // constants would let a format change slip past the contract version.
        // Changing a reader means bumping STATE_CONTRACT_VERSION (and the
        // release generator's contract table) instead of editing this table.
        assert_eq!(STATE_CONTRACT_VERSION, 1);
        let current = PersistedFormats::current();
        let readers: Vec<_> = current
            .readers()
            .into_iter()
            .map(|(surface, versions)| (surface, versions.clone()))
            .collect();
        assert_eq!(
            readers,
            [
                ("shell_execution_receipt", vec![3, 4]),
                ("team_connection", vec![1]),
                ("team_enrollment", vec![1]),
                ("team_report", vec![1]),
                ("team_rollout", vec![1]),
                ("team_policy_document", vec![1]),
                ("team_policy_semantics", vec![1]),
            ]
        );
        assert_eq!(current.versions("team_rollout"), Some(&vec![1]));
        // Retired local-leaf npm stores are not part of the contract.
        assert!(current.versions("npm_install_intent").is_none());
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
            let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
        fn receipt_inventory_distinguishes_ack_schema_without_exposing_private_payloads() {
            let _shared_state = tirith_test_support::SharedStateGuard::acquire();
            let temp = scope();
            let receipts = temp.path().join("sessions/execution-receipts");
            file(&receipts.join(".receipt-registry.lock"), b"");
            file(
                &receipts.join(format!(".hook-{}.capability", "a".repeat(64))),
                b"not inventoried",
            );
            file(
                &receipts.join(format!(".hook-presence-{}.record", "b".repeat(64))),
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
            let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
            let facts = observe(Some(temp.path()), Some(temp.path()));
            for surface in [
                "team_connection",
                "team_enrollment",
                "team_report",
                "team_rollout",
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
            let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
            let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
            let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
            let _shared_state = tirith_test_support::SharedStateGuard::acquire();
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
        fn rollout_unknown_versions_and_unsafe_records_do_not_disappear() {
            let _shared_state = tirith_test_support::SharedStateGuard::acquire();
            let temp = scope();
            let path = temp
                .path()
                .join("team-policy/rollouts/11111111-1111-4111-8111-111111111111.json");
            file(&path, br#"{"schema_version":99}"#);
            assert!(observe(Some(temp.path()), None)
                .iter()
                .any(|f| f.surface == "team_rollout" && f.declared_version == Some(99)));
            for (bytes, expected) in [
                (
                    br#"{"schema_version":1,"schema_version":2}"#.as_slice(),
                    "invalid",
                ),
                (b"{truncated".as_slice(), "invalid"),
                (&vec![b' '; 4 * 1024 * 1024 + 1], "unreadable"),
            ] {
                file(&path, bytes);
                assert!(observe(Some(temp.path()), None)
                    .iter()
                    .any(|f| f.surface == "team_rollout" && f.state == expected));
            }
            std::fs::remove_file(&path).unwrap();
            symlink("not-followed-private-target", &path).unwrap();
            assert!(observe(Some(temp.path()), None)
                .iter()
                .any(|f| f.surface == "team_rollout" && f.state == "unreadable"));
            assert!(std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink());
            let mut facts = Vec::new();
            let mut budget = Budget {
                remaining: 0,
                started: Instant::now(),
            };
            rollout_directory_facts(
                path.parent().unwrap(),
                temp.path(),
                "team_rollout",
                &mut budget,
                &mut facts,
            );
            assert_eq!(facts.len(), 1);
            assert_eq!(facts[0].state, "inventory_limited");
            assert!(INVENTORY_SCOPE.contains("external_target_checkpoints_not_discovered"));
        }
    }
}
