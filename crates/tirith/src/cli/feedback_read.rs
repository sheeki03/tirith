//! Bounded read-only annotation selection from an already captured history page.
use super::Expectation;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use tirith_core::history::HistoryQueryResult;

const LIMIT: usize = 50;
const RECORD_BYTES: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Annotation {
    schema_version: u32,
    event_id: String,
    expectation: Expectation,
    recorded_check_timestamp: String,
    source: String,
    safety_validated: bool,
    execution_established: bool,
    policy_changed: bool,
}

fn valid(record: &Annotation, id: &str, timestamp: &str) -> bool {
    record.schema_version == 1
        && record.event_id == id
        && record.recorded_check_timestamp == timestamp
        && record.source == "operator_annotation"
        && !record.safety_validated
        && !record.execution_established
        && !record.policy_changed
}

/// No enumeration, directory creation, repair, or mutation. Only canonical IDs
/// observed exactly once in this captured page can select a derived file.
pub(crate) fn read_for_history(history: &HistoryQueryResult) -> Value {
    let started = Instant::now();
    let root = tirith_core::policy::state_dir();
    let mut occurrences = BTreeMap::<&str, usize>::new();
    for event in &history.events {
        if let Some(id) = event.record.event_id.as_deref() {
            *occurrences.entry(id).or_default() += 1;
        }
    }
    let mut selected = BTreeSet::new();
    let mut entries = Vec::new();
    let mut omitted = 0;
    let mut ambiguous_or_invalid = 0;
    for event in history
        .events
        .iter()
        .rev()
        .filter(|event| event.semantics == "recorded_check")
    {
        let Some(id) = event.record.event_id.as_deref() else {
            continue;
        };
        if !uuid::Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id)
            || occurrences.get(id) != Some(&1)
        {
            ambiguous_or_invalid += 1;
            continue;
        }
        if !selected.insert(id) {
            continue;
        }
        if entries.len() >= LIMIT || started.elapsed() >= Duration::from_secs(1) {
            omitted += 1;
            continue;
        }
        let timestamp = chrono::DateTime::parse_from_rfc3339(&event.record.timestamp)
            .ok()
            .map(|value| value.to_rfc3339());
        let read = (|| -> Result<Option<Expectation>, ()> {
            let root = root.as_ref().ok_or(())?;
            let snapshot = crate::cli::setup::fs_helpers::read_snapshot_scoped_capped(
                &root.join("feedback").join(format!("{id}.json")),
                root,
                RECORD_BYTES,
            )
            .map_err(|_| ())?;
            let Some(bytes) = snapshot.bytes.as_ref() else {
                return Ok(None);
            };
            snapshot.require_private().map_err(|_| ())?;
            if bytes.iter().all(u8::is_ascii_whitespace) {
                return Ok(None);
            }
            let record: Annotation = serde_json::from_slice(bytes).map_err(|_| ())?;
            if !valid(&record, id, timestamp.as_deref().ok_or(())?) {
                return Err(());
            }
            Ok(Some(record.expectation))
        })();
        entries.push(match read {
            Ok(Some(expectation)) => {
                json!({"event_id":id,"availability":"available","expectation":expectation})
            }
            Ok(None) => json!({"event_id":id,"availability":"not_recorded"}),
            Err(()) => json!({"event_id":id,"availability":"unavailable"}),
        });
    }
    json!({"schema_version":1,"kind":"operator_annotations","entries":entries,
        "coverage":{"selected":entries.len(),"omitted":omitted,"ambiguous_or_invalid_ids":ambiguous_or_invalid,
            "selection_limit":LIMIT,"record_byte_limit":RECORD_BYTES,"earlier_history_searched":false,
            "deadline":"one_second_checked_between_native_reads"},
        "source":"operator_annotation","safety_validated":false,"execution_established":false,
        "policy_changed":false})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn annotation_contract_rejects_duplicate_fields_and_invented_authority() {
        let raw = r#"{"schema_version":1,"event_id":"id","expectation":"expected","recorded_check_timestamp":"time","source":"operator_annotation","safety_validated":false,"execution_established":false,"policy_changed":false}"#;
        let annotation: Annotation = serde_json::from_str(raw).unwrap();
        assert!(valid(&annotation, "id", "time"));
        assert!(!valid(&annotation, "other-id", "time"));
        assert!(!valid(&annotation, "id", "other-time"));
        assert!(serde_json::from_str::<Annotation>(&raw.replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1"
        ))
        .is_err());
        let changed: Annotation = serde_json::from_str(
            &raw.replace("\"safety_validated\":false", "\"safety_validated\":true"),
        )
        .unwrap();
        assert!(!valid(&changed, "id", "time"));
    }
}
