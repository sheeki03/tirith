//! Bounded historical friction review, never automatic policy relaxation.
use serde_json::{json, Value};
use tirith_core::history::{Availability, HistoryFilter, HistoryReader};
use tirith_core::policy::{captured_policy_dlp_patterns_or, PolicyDiagnosticCapture};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
use tirith_core::redact::CompiledCustomPatterns;

pub(crate) fn review(cwd: Option<&str>) -> Result<Value, String> {
    let _capture = PolicyDiagnosticCapture::start();
    let snapshot = EffectivePolicySnapshot::resolve(cwd, ResolutionMode::Runtime);
    let path = tirith_core::audit::audit_log_path().ok_or("audit history location unavailable")?;
    let history = HistoryReader::new(path).recent(
        HistoryFilter::default(),
        500,
        std::env::var("TIRITH_LOG").ok().as_deref() != Some("0"),
    )?;
    let records = history
        .events
        .iter()
        .filter(|event| event.semantics == "recorded_check")
        .map(|event| event.record.clone())
        .collect::<Vec<_>>();
    let known = tirith_core::rule_explanations::list_all();
    let known = known.iter().map(|rule| rule.id).collect::<Vec<_>>();
    let report = tirith_core::audit_tune::analyze(&records, &known);
    let annotations = super::feedback::read_for_history(&history);
    let patterns = captured_policy_dlp_patterns_or(&snapshot.policy.dlp_custom_patterns);
    let compiled = CompiledCustomPatterns::new_silent(&patterns);
    let mut value = serde_json::to_value(&report).map_err(|_| "cannot encode tuning review")?;
    let omitted_rules = report.rule_stats.len().saturating_sub(100);
    let omitted_suggestions = report.suggestions.len().saturating_sub(20);
    value["rule_stats"].as_array_mut().unwrap().truncate(100);
    value["suggestions"].as_array_mut().unwrap().truncate(20);
    for group in ["rule_stats", "suggestions"] {
        for item in value[group].as_array_mut().unwrap() {
            let canonical =
                serde_json::from_value::<tirith_core::verdict::RuleId>(item["rule_id"].clone())
                    .ok()
                    .and_then(|rule| serde_json::to_value(rule).ok())
                    .is_some_and(|rule| rule == item["rule_id"]);
            if !canonical {
                tirith_core::redact::redact_json_strings(&mut item["rule_id"], &compiled);
            }
            for field in ["observation", "recommendation", "policy_snippet"] {
                if let Some(text) = item.get_mut(field) {
                    tirith_core::redact::redact_json_strings(text, &compiled);
                }
            }
        }
    }
    // Examples are references to redacted recorded checks. They are never
    // automatically replayed as if their original command bytes were available.
    let mut examples = Vec::new();
    let mut withheld_examples = 0;
    let mut seen = std::collections::BTreeSet::new();
    for rule in report.rule_stats.iter().take(10) {
        for event in history
            .events
            .iter()
            .rev()
            .filter(|event| {
                event.semantics == "recorded_check" && event.record.rule_ids.contains(&rule.rule_id)
            })
            .take(3)
        {
            if examples.len() + withheld_examples >= 20 || !seen.insert(&event.record_id) {
                continue;
            }
            let mut projected =
                serde_json::to_value(&event.record).map_err(|_| "cannot encode tuning example")?;
            tirith_core::output_contract::redact_projection(
                &mut projected,
                tirith_core::output_contract::Projection::HistoryRecord,
                &compiled,
            );
            if serde_json::to_vec_pretty(&projected).map_or(true, |bytes| bytes.len() > 8192) {
                withheld_examples += 1;
            } else {
                examples.push(
                    json!({"record_id":event.record_id,"input_quality":"redacted_record",
                    "execution_established":false,"record":projected}),
                );
            }
        }
    }
    value["schema_version"] = 1.into();
    value["kind"] = "policy_tuning_review".into();
    value["availability"] = serde_json::to_value(history.availability).unwrap();
    value["policy_changed"] = false.into();
    value["executed"] = false.into();
    value["automatic_approval"] = false.into();
    value["annotations"] = annotations;
    value["examples"] = examples.into();
    value["notice"] = "Counts and expectation labels describe recorded checks and user intent, not confirmed execution or validated false positives. They do not establish command safety. No safe relaxation is established by recorded outcomes alone.".into();
    value["next_action"] = "Review the recorded examples and 'tirith policy effective --runtime', then compare a representative command with 'tirith policy simulate'. Apply any reviewed relaxation only to an operator-writable user or organization policy. Repository policy cannot lower severity or suppress findings. A profile or scoped exception change still needs an explicit review.".into();
    value["coverage"] = json!({"record_limit":500,"byte_limit":2097152,
        "inspected_bytes":history.inspected_bytes,"earlier_history_uninspected":history.earlier_history_uninspected,
        "more_available":history.more_available,"malformed_lines":history.malformed_lines,
        "oversized_lines":history.oversized_lines,"incomplete_tail":history.incomplete_tail,
        "omitted_rules":omitted_rules,"omitted_suggestions":omitted_suggestions,
        "example_limit":20,"withheld_examples":withheld_examples,"integrity":"not_verified"});
    value["policy_diagnostics"] =
        tirith_core::policy::drain_captured_policy_diagnostics_for_output(&compiled).into();
    value["presentation_incomplete"] = false.into();
    if serde_json::to_vec_pretty(&value)
        .map_err(|_| "cannot measure tuning review")?
        .len()
        > 256 * 1024
    {
        value["presentation_incomplete"] = true.into();
        value["examples"] = json!([]);
        value["suggestions"] = json!([]);
        value["rule_stats"] = json!([]);
        value["policy_diagnostics"] = json!(["Detailed review withheld: display limit"]);
    }
    Ok(value)
}

pub(crate) fn run(from_audit: bool, json_output: bool) -> i32 {
    if !from_audit {
        eprintln!("tirith policy tune: specify --from-audit to review bounded recent history");
        return 1;
    }
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.display().to_string());
    match review(cwd.as_deref()) {
        Ok(value) => {
            if value["availability"] == "absent" {
                eprintln!("tirith policy tune: no audit log is available; use Tirith normally before reviewing recorded history");
            }
            if json_output {
                if !super::write_json_stdout(&value, "tirith policy tune: cannot write review") {
                    return 1;
                }
            } else {
                eprintln!(
                    "tirith policy tune: analyzed {} audit check record(s)",
                    value["records_analyzed"]
                );
                eprintln!(
                    "{}",
                    tirith_core::output::sanitize_human_field(
                        value["notice"].as_str().unwrap_or_default(),
                        &[]
                    )
                );
                if value["data_is_thin"] == true {
                    eprintln!("  not enough audit history to suggest policy changes yet (need at least {}).", tirith_core::audit_tune::MIN_OBSERVATIONS);
                }
                if let Some(rules) = value["rule_stats"].as_array() {
                    for rule in rules
                        .iter()
                        .filter(|rule| {
                            rule["blocked"].as_u64().unwrap_or(0)
                                >= tirith_core::audit_tune::MIN_RULE_FIRINGS as u64
                        })
                        .take(10)
                    {
                        eprintln!("  Recurring blocked checks: {}: {} blocked / {} checks containing this rule", tirith_core::output::sanitize_human_field(rule["rule_id"].as_str().unwrap_or_default(), &[]), rule["blocked"], rule["total"]);
                    }
                }
                if let Some(suggestions) = value["suggestions"].as_array() {
                    if suggestions.is_empty() {
                        eprintln!("  No policy changes suggested: this history does not establish a safe relaxation.");
                    }
                    for item in suggestions {
                        eprintln!(
                            "  {}\n    {}",
                            tirith_core::output::sanitize_human_field(
                                item["observation"].as_str().unwrap_or_default(),
                                &[]
                            ),
                            tirith_core::output::sanitize_human_field(
                                item["recommendation"].as_str().unwrap_or_default(),
                                &[]
                            )
                        );
                    }
                }
                eprintln!("  History coverage: {}", value["coverage"]);
                eprintln!(
                    "  {}",
                    tirith_core::output::sanitize_human_field(
                        value["next_action"].as_str().unwrap_or_default(),
                        &[]
                    )
                );
                eprintln!("  tirith did not change your policy.");
            }
            let unavailable = serde_json::to_value([
                Availability::Absent,
                Availability::Unreadable,
                Availability::Corrupt,
                Availability::RefreshRequired,
            ])
            .unwrap();
            if unavailable
                .as_array()
                .unwrap()
                .contains(&value["availability"])
            {
                1
            } else {
                0
            }
        }
        Err(error) => {
            eprintln!(
                "tirith policy tune: {}",
                tirith_core::output::sanitize_human_field(
                    &error,
                    &captured_policy_dlp_patterns_or(&[])
                )
            );
            1
        }
    }
}
