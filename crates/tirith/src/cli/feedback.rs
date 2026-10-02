//! Explicit operator annotations. These records never participate in policy,
//! trust, reputation scoring, or execution authorization.
use super::setup::change_plan::{Edit, MutationService, OperationKind, RequestedChange};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};

#[path = "feedback_read.rs"]
mod reader;
pub(crate) use reader::read_for_history;

#[derive(Clone, Copy, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Expectation {
    Expected,
    Unexpected,
    Unsure,
}

impl Expectation {
    fn token(self) -> &'static str {
        match self {
            Self::Expected => "expected",
            Self::Unexpected => "unexpected",
            Self::Unsure => "unsure",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FeedbackRequest {
    pub event_id: String,
    pub expectation: Expectation,
}

#[derive(Serialize)]
struct Intent<'a> {
    change: &'a FeedbackRequest,
    cwd: Option<String>,
}

fn intent<'a>(change: &'a FeedbackRequest, cwd: Option<&str>) -> Result<Intent<'a>, String> {
    if !uuid::Uuid::parse_str(&change.event_id).is_ok_and(|id| id.to_string() == change.event_id) {
        return Err("feedback requires a canonical incident event UUID".into());
    }
    Ok(Intent {
        change,
        cwd: cwd.map(str::to_owned).or_else(|| {
            std::env::current_dir()
                .ok()
                .map(|p| p.display().to_string())
        }),
    })
}

fn observed_incident(id: &str) -> Result<String, String> {
    let path = tirith_core::audit::audit_log_path().ok_or("history is unavailable")?;
    let report = tirith_core::history::HistoryReader::new(path).recent(
        Default::default(),
        500,
        std::env::var("TIRITH_LOG").ok().as_deref() != Some("0"),
    )?;
    let matches: Vec<_> = report
        .events
        .iter()
        .filter(|event| {
            event.semantics == "recorded_check" && event.record.event_id.as_deref() == Some(id)
        })
        .collect();
    if matches.len() != 1 {
        return Err("incident is absent or ambiguous in bounded recent history; refresh Activity and select an available check".into());
    }
    // RFC3339 parsers may accept far more fractional digits than they retain.
    // Store a normalized timestamp, never an unbounded copy of an audit field.
    chrono::DateTime::parse_from_rfc3339(&matches[0].record.timestamp)
        .map(|timestamp| timestamp.to_rfc3339())
        .map_err(|_| "incident timestamp is unavailable".into())
}

pub(crate) fn prepare(
    id: &str,
    change: FeedbackRequest,
    cwd: Option<&str>,
    dry_run: bool,
) -> Result<Value, String> {
    let intent = intent(&change, cwd)?;
    let service = MutationService::current()?;
    let snapshot = EffectivePolicySnapshot::resolve(intent.cwd.as_deref(), ResolutionMode::Runtime);
    let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(
        &tirith_core::policy::captured_policy_dlp_patterns_or(&snapshot.policy.dlp_custom_patterns),
    );
    if !dry_run {
        if let Some(status) =
            service.status_for_intent(id, OperationKind::RecordFeedback, &intent)?
        {
            return Ok(
                json!({"schema_version":1,"kind":"feedback_plan","applied":false,"operation":super::profile::status_projection(&status,&compiled)?,"policy_changed":false}),
            );
        }
    }
    let timestamp = observed_incident(&change.event_id)?;
    let scope = tirith_core::policy::state_dir().ok_or("personal state location unavailable")?;
    let path = scope
        .join("feedback")
        .join(format!("{}.json", change.event_id));
    let before = super::setup::fs_helpers::read_snapshot_scoped_capped(&path, &scope, 4096)?;
    if before.bytes.is_some() {
        before.require_private()?;
    }
    let previous = before
        .bytes
        .as_deref()
        .map(|bytes| {
            String::from_utf8(bytes.to_vec())
                .map_err(|_| "existing feedback is unreadable".to_string())
        })
        .transpose()?;
    if let Some(previous) = previous.as_ref().filter(|text| !text.trim().is_empty()) {
        if previous.len() > 4096 {
            return Err("existing feedback exceeds its supported record limit".into());
        }
        let record: Value = serde_json::from_str(previous).map_err(|_| {
            "existing feedback is malformed; inspect it before changing the annotation"
        })?;
        let known = [
            "schema_version",
            "event_id",
            "expectation",
            "recorded_check_timestamp",
            "source",
            "safety_validated",
            "execution_established",
            "policy_changed",
        ];
        if !record.as_object().is_some_and(|object| {
            object.len() == known.len() && object.keys().all(|key| known.contains(&key.as_str()))
        }) || record["schema_version"] != 1
            || record["event_id"] != change.event_id
            || serde_json::from_value::<Expectation>(record["expectation"].clone()).is_err()
            || record["recorded_check_timestamp"] != timestamp
            || record["source"] != "operator_annotation"
            || record["safety_validated"] != false
            || record["execution_established"] != false
            || record["policy_changed"] != false
        {
            return Err("existing feedback has unsupported fields or belongs to a different incident observation".into());
        }
    }
    let record = json!({"schema_version":1,"event_id":change.event_id,"expectation":change.expectation,"recorded_check_timestamp":timestamp,
        "source":"operator_annotation","safety_validated":false,"execution_established":false,"policy_changed":false});
    let text = serde_json::to_string_pretty(&record).map_err(|_| "cannot encode feedback")?;
    let preview = json!({"schema_version":1,"kind":"feedback_preview","applied":false,"record":record,
        "notice":"This records what you intended. It does not establish that the command was safe or executed, and does not approve future commands."});
    if dry_run {
        return Ok(preview);
    }
    let status = if previous.as_deref() == Some(text.as_str()) {
        service.complete_noop_with_intent(id, OperationKind::RecordFeedback, &snapshot, &intent)?
    } else {
        service.plan_with_preimages_and_intent(
            id,
            OperationKind::RecordFeedback,
            vec![RequestedChange {
                target: path.clone(),
                scope_root: scope,
                edit: Edit::PrivateFile(text),
                activation: false,
                description: format!(
                    "Mark incident {} as {}; enforcement and trust stay unchanged",
                    change.event_id,
                    change.expectation.token()
                ),
            }],
            &snapshot,
            &BTreeMap::from([(path, previous)]),
            &intent,
        )?
    };
    Ok(
        json!({"schema_version":1,"kind":"feedback_plan","applied":false,"preview":preview,"operation":super::profile::status_projection(&status,&compiled)?,"policy_changed":false}),
    )
}

pub(crate) fn run(
    event_id: String,
    expectation: Expectation,
    operation_id: Option<String>,
    dry_run: bool,
    json_output: bool,
) -> i32 {
    let result = (|| -> Result<Value, String> {
        let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
        let id = operation_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let cwd = std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string());
        let preview = prepare(
            &id,
            FeedbackRequest {
                event_id,
                expectation,
            },
            cwd.as_deref(),
            dry_run,
        )?;
        if dry_run {
            return Ok(preview);
        }
        let snapshot = EffectivePolicySnapshot::resolve(cwd.as_deref(), ResolutionMode::Runtime);
        let status = MutationService::current()?.apply(&id, &snapshot)?;
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(
            &tirith_core::policy::captured_policy_dlp_patterns_or(
                &snapshot.policy.dlp_custom_patterns,
            ),
        );
        super::profile::status_projection(&status, &compiled)
    })();
    match result {
        Ok(value) => {
            if json_output {
                if !super::write_json_stdout(&value, "tirith audit feedback: cannot write result") {
                    return 1;
                }
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).unwrap_or_default()
                );
            }
            if value
                .get("state")
                .is_some_and(|state| state != "completed" && state != "completed-with-recovery")
            {
                1
            } else {
                0
            }
        }
        Err(error) => {
            eprintln!(
                "tirith audit feedback: {}",
                tirith_core::redact::redact_sanitize_redact(
                    &error,
                    &tirith_core::policy::captured_policy_dlp_patterns_or(&[])
                )
            );
            1
        }
    }
}
