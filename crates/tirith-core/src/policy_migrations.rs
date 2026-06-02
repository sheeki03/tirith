//! Policy schema migration registry (M5.5 F3).
//!
//! Policies carry a `schema_version: u32`; absent = `v1` (pre-M5.5 files).
//! Migrations operate on the raw `serde_yaml::Value` BEFORE typed
//! deserialization — typed deser discards unknown fields, so a post-deser
//! migration couldn't see (let alone rename) them.
//!
//! One entry today: `v1 → v2` moves top-level `internal_package_names: [String]`
//! under `package_policy.internal_package_names: [{name}]`. Loaders accept any
//! version ≤ [`CURRENT_SCHEMA_VERSION`]; a higher version fails with an
//! upgrade-tirith message rather than silently dropping unknown fields.

use serde_yaml::Value;

/// The schema version this tirith build understands. Bump when a wave changes
/// the policy shape AND registers a migration in [`MIGRATIONS`].
pub const CURRENT_SCHEMA_VERSION: u32 = 2;

/// A single forward migration `from → to`. Mutates the raw `Value` in place so
/// typed deser sees the new shape; MUST be idempotent.
#[derive(Clone, Copy)]
pub struct Migration {
    pub from: u32,
    pub to: u32,
    pub run: fn(&mut Value),
}

/// Registered forward migrations. Each entry's `to` MUST equal the next's
/// `from`, walking from 1 to [`CURRENT_SCHEMA_VERSION`] (checked by a unit test).
pub const MIGRATIONS: &[Migration] = &[Migration {
    from: 1,
    to: 2,
    run: migrate_v1_to_v2,
}];

/// M6 ch7 — move top-level `internal_package_names: [String]` under
/// `package_policy.internal_package_names: [{name}]`. Idempotent.
fn migrate_v1_to_v2(value: &mut Value) {
    let Some(map) = value.as_mapping_mut() else {
        return;
    };
    let key = Value::String("internal_package_names".to_string());
    let legacy = map.remove(&key);
    let Some(legacy) = legacy else {
        return;
    };
    // Legacy shape is a sequence of strings; anything else is dropped to avoid
    // shadowing whatever lives under `package_policy`.
    let Some(seq) = legacy.as_sequence() else {
        return;
    };
    let mut new_entries: Vec<Value> = Vec::new();
    for (idx, entry) in seq.iter().enumerate() {
        let Some(s) = entry.as_str() else {
            // A non-string entry is a migration error the operator should see —
            // warn per entry (silent drop would hide config drift) and continue.
            eprintln!(
                "tirith: migration warning: v1→v2 internal_package_names[{idx}] is not a \
                 string ({entry:?}); dropped — the v1 shape is `[\"name1\", \"name2\", ...]`",
            );
            continue;
        };
        let mut entry_map = serde_yaml::Mapping::new();
        entry_map.insert(
            Value::String("name".to_string()),
            Value::String(s.to_string()),
        );
        new_entries.push(Value::Mapping(entry_map));
    }
    if new_entries.is_empty() {
        return;
    }

    let pp_key = Value::String("package_policy".to_string());
    let existing = map.get(&pp_key).cloned();
    let mut pp_map = match existing {
        Some(Value::Mapping(m)) => m,
        _ => serde_yaml::Mapping::new(),
    };

    let ipn_key = Value::String("internal_package_names".to_string());
    // Append to any existing list, de-duping by `name` (idempotency contract).
    let mut combined: Vec<Value> = match pp_map.get(&ipn_key).cloned() {
        Some(Value::Sequence(s)) => s,
        _ => Vec::new(),
    };
    for entry in new_entries {
        if !combined.iter().any(|existing| {
            existing
                .as_mapping()
                .and_then(|m| m.get(Value::String("name".to_string())))
                .and_then(|v| v.as_str())
                .zip(
                    entry
                        .as_mapping()
                        .and_then(|m| m.get(Value::String("name".to_string())))
                        .and_then(|v| v.as_str()),
                )
                .is_some_and(|(a, b)| a == b)
        }) {
            combined.push(entry);
        }
    }
    pp_map.insert(ipn_key, Value::Sequence(combined));
    map.insert(pp_key, Value::Mapping(pp_map));
}

/// Migrate a raw policy `Value` forward to [`CURRENT_SCHEMA_VERSION`]. No-op
/// when already current; `Err(FutureVersion)` when the policy declares a higher
/// version (so we never quietly drop fields a newer tirith added).
pub fn migrate_forward(value: &mut Value) -> Result<(), MigrationError> {
    let mut current = detect_schema_version(value);

    if current > CURRENT_SCHEMA_VERSION {
        return Err(MigrationError::FutureVersion {
            policy_version: current,
            supported_version: CURRENT_SCHEMA_VERSION,
        });
    }

    while current < CURRENT_SCHEMA_VERSION {
        let migration = MIGRATIONS
            .iter()
            .find(|m| m.from == current)
            .ok_or(MigrationError::MissingMigration { from: current })?;
        (migration.run)(value);
        current = migration.to;
        set_schema_version(value, current);
    }
    Ok(())
}

/// Read the policy's declared `schema_version`, defaulting to `1` when absent
/// (the pre-M5.5 convention).
pub fn detect_schema_version(value: &Value) -> u32 {
    value
        .as_mapping()
        .and_then(|m| m.get(Value::String("schema_version".to_string())))
        .and_then(|v| v.as_u64())
        .map(|n| n as u32)
        .unwrap_or(1)
}

fn set_schema_version(value: &mut Value, version: u32) {
    if let Some(map) = value.as_mapping_mut() {
        map.insert(
            Value::String("schema_version".to_string()),
            Value::Number(version.into()),
        );
    }
}

/// Errors returned by [`migrate_forward`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationError {
    /// The policy declares a version newer than this binary — upgrade tirith
    /// rather than silently drop unrecognised fields.
    FutureVersion {
        policy_version: u32,
        supported_version: u32,
    },
    /// No registered migration advances `from` — a build-time bug (the chain is
    /// enforced by a unit test).
    MissingMigration { from: u32 },
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationError::FutureVersion {
                policy_version,
                supported_version,
            } => write!(
                f,
                "policy schema v{policy_version} requires a newer tirith binary; \
                 this build supports schema v{supported_version}. Upgrade tirith \
                 (or remove the `schema_version` field to load as v1)."
            ),
            MigrationError::MissingMigration { from } => write!(
                f,
                "internal error: no registered migration from policy schema v{from}; \
                 this is a tirith bug — please report it."
            ),
        }
    }
}

impl std::error::Error for MigrationError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_value(version: Option<u32>) -> Value {
        let mut map = serde_yaml::Mapping::new();
        if let Some(v) = version {
            map.insert(
                Value::String("schema_version".to_string()),
                Value::Number(v.into()),
            );
        }
        map.insert(
            Value::String("paranoia".to_string()),
            Value::Number(2.into()),
        );
        Value::Mapping(map)
    }

    #[test]
    fn migration_chain_is_continuous() {
        // Entry N's `to` must equal entry N+1's `from`, 1 → CURRENT_SCHEMA_VERSION.
        let mut expected = 1u32;
        for m in MIGRATIONS {
            assert_eq!(
                m.from, expected,
                "migration chain broken: expected from={expected}, got {}",
                m.from
            );
            assert!(
                m.to > m.from,
                "migration must move forward: from={} to={}",
                m.from,
                m.to
            );
            expected = m.to;
        }
        if !MIGRATIONS.is_empty() {
            assert_eq!(
                expected, CURRENT_SCHEMA_VERSION,
                "migration chain stops at v{expected} but CURRENT_SCHEMA_VERSION is v{CURRENT_SCHEMA_VERSION}"
            );
        }
    }

    #[test]
    fn missing_field_defaults_to_v1() {
        let v = make_value(None);
        assert_eq!(detect_schema_version(&v), 1);
    }

    #[test]
    fn explicit_v1_field_works() {
        let v = make_value(Some(1));
        assert_eq!(detect_schema_version(&v), 1);
    }

    #[test]
    fn future_version_rejected_with_clear_error() {
        let mut v = make_value(Some(CURRENT_SCHEMA_VERSION + 10));
        let err = migrate_forward(&mut v).expect_err("should fail forward");
        match err {
            MigrationError::FutureVersion {
                policy_version,
                supported_version,
            } => {
                assert_eq!(policy_version, CURRENT_SCHEMA_VERSION + 10);
                assert_eq!(supported_version, CURRENT_SCHEMA_VERSION);
            }
            other => panic!("expected FutureVersion, got {other:?}"),
        }
        let msg = format!("{err}");
        assert!(msg.contains("Upgrade tirith") || msg.contains("upgrade tirith"));
    }

    #[test]
    fn v1_policy_migrates_to_current() {
        // v1 must reach the current version cleanly even with no legacy field.
        let mut v = make_value(None);
        migrate_forward(&mut v).expect("v1 should migrate cleanly");
        if CURRENT_SCHEMA_VERSION > 1 {
            assert_eq!(detect_schema_version(&v), CURRENT_SCHEMA_VERSION);
        }
    }

    #[test]
    fn v1_to_v2_moves_top_level_internal_package_names() {
        // Top-level `internal_package_names` lifted under `package_policy` as
        // structured `{name}` entries.
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            Value::String("paranoia".to_string()),
            Value::Number(1.into()),
        );
        map.insert(
            Value::String("internal_package_names".to_string()),
            Value::Sequence(vec![
                Value::String("@my-co/*".to_string()),
                Value::String("internal-tool".to_string()),
            ]),
        );
        let mut v = Value::Mapping(map);
        migrate_forward(&mut v).expect("migration must succeed");

        // Top-level field gone.
        let top = v.as_mapping().unwrap();
        assert!(!top.contains_key(Value::String("internal_package_names".to_string())));

        // Lifted under package_policy.internal_package_names with `name` keys.
        let pp = top
            .get(Value::String("package_policy".to_string()))
            .and_then(|v| v.as_mapping())
            .expect("package_policy must exist after migration");
        let ipn = pp
            .get(Value::String("internal_package_names".to_string()))
            .and_then(|v| v.as_sequence())
            .expect("internal_package_names lifted as sequence");
        let names: Vec<&str> = ipn
            .iter()
            .filter_map(|e| {
                e.as_mapping()
                    .and_then(|m| m.get(Value::String("name".to_string())))
                    .and_then(|v| v.as_str())
            })
            .collect();
        assert_eq!(names, vec!["@my-co/*", "internal-tool"]);
        assert_eq!(detect_schema_version(&v), CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn v1_to_v2_with_no_legacy_field_is_clean() {
        let mut v = make_value(None);
        migrate_forward(&mut v).expect("migration must succeed");
        // package_policy is not created when there's nothing to move.
        let top = v.as_mapping().unwrap();
        assert!(!top.contains_key(Value::String("internal_package_names".to_string())));
    }

    #[test]
    fn v1_to_v2_idempotent_merge_preserves_existing() {
        // Legacy top-level list AND a v2-shape entry must merge without
        // duplicating by name.
        let mut existing_ipn = serde_yaml::Mapping::new();
        existing_ipn.insert(
            Value::String("name".to_string()),
            Value::String("@my-co/*".to_string()),
        );
        let mut pp = serde_yaml::Mapping::new();
        pp.insert(
            Value::String("internal_package_names".to_string()),
            Value::Sequence(vec![Value::Mapping(existing_ipn)]),
        );
        let mut map = serde_yaml::Mapping::new();
        map.insert(
            Value::String("paranoia".to_string()),
            Value::Number(1.into()),
        );
        map.insert(
            Value::String("package_policy".to_string()),
            Value::Mapping(pp),
        );
        map.insert(
            Value::String("internal_package_names".to_string()),
            Value::Sequence(vec![
                Value::String("@my-co/*".to_string()),
                Value::String("other".to_string()),
            ]),
        );
        let mut v = Value::Mapping(map);
        migrate_forward(&mut v).expect("migration must succeed");

        let names: Vec<&str> = v
            .as_mapping()
            .unwrap()
            .get(Value::String("package_policy".to_string()))
            .and_then(|v| v.as_mapping())
            .and_then(|m| m.get(Value::String("internal_package_names".to_string())))
            .and_then(|v| v.as_sequence())
            .unwrap()
            .iter()
            .filter_map(|e| {
                e.as_mapping()
                    .and_then(|m| m.get(Value::String("name".to_string())))
                    .and_then(|v| v.as_str())
            })
            .collect();
        // Both present; "@my-co/*" appears once.
        assert_eq!(names.iter().filter(|n| **n == "@my-co/*").count(), 1);
        assert!(names.contains(&"other"));
    }
}
