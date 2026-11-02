//! Aggregates over the bounded newest audit suffix, rebuilt on every request.
//! Only canonical rule IDs, counters, and a bounded set of examples are
//! reported; the signed log remains authoritative. Nothing is cached between
//! requests, so a restart, rotation, clock change or newly eligible
//! future-dated record can never leave a stale count behind.
use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;

use crate::history::{Availability, HistoryEvent, HistoryReader};

const EXAMPLES_PER_RULE: usize = 3;
const RULE_LIMIT: usize = 1024;
const EXAMPLE_BYTES: usize = 256;

#[derive(Clone, Default, Serialize)]
pub struct CheckCounts {
    pub recorded_checks: u64,
    pub allowed_checks: u64,
    pub warning_checks: u64,
    pub acknowledgement_required_checks: u64,
    pub blocked_checks: u64,
    pub unknown_action_checks: u64,
    pub bypass_requested_checks: u64,
    pub bypass_honored_checks: u64,
}

#[derive(Clone, Serialize)]
pub struct CheckExample {
    pub record_id: String,
    pub timestamp: String,
    pub action: &'static str,
    pub command_preview: String,
    pub command_truncated: bool,
}

#[derive(Clone, Serialize)]
pub struct RuleAggregate {
    pub rule_id: String,
    pub recorded_checks: u64,
    pub interruptions: u64,
    pub examples: Vec<CheckExample>,
}

#[derive(Clone, Serialize)]
pub struct AggregateReport {
    pub schema_version: u32,
    pub kind: &'static str,
    pub generation: String,
    pub source_generation: Option<String>,
    /// Always true: every report is a complete view that replaces the last.
    pub replace_previous: bool,
    pub availability: Availability,
    pub window_start: NaiveDate,
    pub window_end: NaiveDate,
    pub window_basis: &'static str,
    pub counts: CheckCounts,
    pub other_records: u64,
    pub future_dated_records: u64,
    pub invalid_rule_ids: u64,
    pub omitted_rule_records: u64,
    pub malformed_lines: u64,
    pub oversized_lines: u64,
    pub incomplete_tail: bool,
    pub earlier_history_uninspected: bool,
    pub more_available: bool,
    pub inspected_bytes_this_refresh: u64,
    pub rules: Vec<RuleAggregate>,
    pub integrity: &'static str,
    pub semantics: &'static str,
}

#[derive(Default)]
struct Tally {
    counts: CheckCounts,
    other_records: u64,
    future_records: u64,
    invalid_rules: u64,
    omitted_rules: u64,
    rules: BTreeMap<String, RuleAggregate>,
}

/// Summarize one bounded read (at most 2 MiB) of the newest audit suffix over
/// an explicit UTC calendar window. Future-dated records are counted apart and
/// never inside the window.
pub fn summarize(
    reader: &HistoryReader,
    now: DateTime<Utc>,
    days: u32,
    logging_enabled: bool,
) -> Result<AggregateReport, &'static str> {
    if !(1..=31).contains(&days) {
        return Err("aggregate window must be between 1 and 31 UTC days");
    }
    let end = now.date_naive();
    let start = end
        .checked_sub_days(chrono::Days::new(u64::from(days - 1)))
        .ok_or("aggregate date window is unsupported")?;
    let page = reader.suffix(logging_enabled)?;
    let mut tally = Tally::default();
    if page.availability != Availability::RefreshRequired {
        for event in &page.events {
            tally.observe(event, start, now);
        }
    }
    let mut rules: Vec<_> = tally.rules.into_values().collect();
    rules.sort_by(|a, b| {
        b.interruptions
            .cmp(&a.interruptions)
            .then_with(|| b.recorded_checks.cmp(&a.recorded_checks))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    let availability = if matches!(
        page.availability,
        Availability::Available | Availability::Empty
    ) && tally.counts.recorded_checks > 0
    {
        Availability::Available
    } else {
        page.availability
    };
    Ok(AggregateReport {
        schema_version: 1,
        kind: "history_aggregate",
        generation: uuid::Uuid::new_v4().to_string(),
        source_generation: Some(page.generation),
        replace_previous: true,
        availability,
        window_start: start,
        window_end: end,
        window_basis: "utc_calendar_days_excluding_future_timestamps",
        counts: tally.counts,
        other_records: tally.other_records,
        future_dated_records: tally.future_records,
        invalid_rule_ids: tally.invalid_rules,
        omitted_rule_records: tally.omitted_rules,
        malformed_lines: page.malformed_lines as u64,
        oversized_lines: page.oversized_lines as u64,
        incomplete_tail: page.incomplete_tail,
        earlier_history_uninspected: page.earlier_history_uninspected,
        more_available: page.more_available,
        inspected_bytes_this_refresh: page.inspected_bytes,
        rules,
        integrity: "not_verified_by_collector",
        semantics: "recorded_checks_not_confirmed_execution_or_prevented_attacks",
    })
}

impl Tally {
    fn observe(&mut self, event: &HistoryEvent, start: NaiveDate, now: DateTime<Utc>) {
        let Ok(timestamp) = DateTime::parse_from_rfc3339(&event.record.timestamp)
            .map(|time| time.with_timezone(&Utc))
        else {
            return;
        };
        if timestamp > now {
            self.future_records = self.future_records.saturating_add(1);
            return;
        }
        if timestamp.date_naive() < start {
            return;
        }
        if event.semantics != "recorded_check" {
            self.other_records = self.other_records.saturating_add(1);
            return;
        }
        self.counts.recorded_checks = self.counts.recorded_checks.saturating_add(1);
        let (action, interrupted) = match event.record.action.to_ascii_lowercase().as_str() {
            "allow" => {
                self.counts.allowed_checks = self.counts.allowed_checks.saturating_add(1);
                ("allow", false)
            }
            "warn" => {
                self.counts.warning_checks = self.counts.warning_checks.saturating_add(1);
                ("warn", true)
            }
            "warnack" | "warn_ack" => {
                self.counts.acknowledgement_required_checks = self
                    .counts
                    .acknowledgement_required_checks
                    .saturating_add(1);
                ("warn_ack", true)
            }
            "block" => {
                self.counts.blocked_checks = self.counts.blocked_checks.saturating_add(1);
                ("block", true)
            }
            _ => {
                self.counts.unknown_action_checks =
                    self.counts.unknown_action_checks.saturating_add(1);
                ("unknown", false)
            }
        };
        self.counts.bypass_requested_checks = self
            .counts
            .bypass_requested_checks
            .saturating_add(u64::from(event.record.bypass_requested));
        self.counts.bypass_honored_checks = self
            .counts
            .bypass_honored_checks
            .saturating_add(u64::from(event.record.bypass_honored));
        let mut ids = event.record.rule_ids.clone();
        ids.sort();
        ids.dedup();
        for id in ids {
            let canonical = serde_json::from_value::<crate::verdict::RuleId>(id.clone().into())
                .ok()
                .and_then(|rule| serde_json::to_value(rule).ok())
                .is_some_and(|rule| rule == id);
            if !canonical {
                self.invalid_rules = self.invalid_rules.saturating_add(1);
                continue;
            }
            if self.rules.len() >= RULE_LIMIT && !self.rules.contains_key(&id) {
                self.omitted_rules = self.omitted_rules.saturating_add(1);
                continue;
            }
            let row = self
                .rules
                .entry(id.clone())
                .or_insert_with(|| RuleAggregate {
                    rule_id: id,
                    recorded_checks: 0,
                    interruptions: 0,
                    examples: Vec::new(),
                });
            row.recorded_checks = row.recorded_checks.saturating_add(1);
            row.interruptions = row.interruptions.saturating_add(u64::from(interrupted));
            let truncated = event.record.command_redacted.len() > EXAMPLE_BYTES;
            // Truncating before current-policy redaction can expose a prefix
            // of a newly protected secret. Withhold oversized examples instead.
            row.examples.push(CheckExample {
                record_id: event.record_id.clone(),
                timestamp: timestamp.to_rfc3339(),
                action,
                command_preview: if truncated {
                    "Command withheld: exceeds aggregate example limit".into()
                } else {
                    event.record.command_redacted.clone()
                },
                command_truncated: truncated,
            });
            if row.examples.len() > EXAMPLES_PER_RULE {
                row.examples.remove(0);
            }
        }
    }
}

pub fn display_projection(report: &AggregateReport, patterns: &[String]) -> serde_json::Value {
    let compiled = crate::redact::CompiledCustomPatterns::new_silent(patterns);
    let mut report = report.clone();
    for rule in &mut report.rules {
        for example in &mut rule.examples {
            example.command_preview = crate::redact::redact_sanitize_redact_command_with_compiled(
                &example.command_preview,
                &compiled,
            );
        }
    }
    // Every remaining string was constructed here or canonically validated.
    serde_json::to_value(report).expect("aggregate contains serializable primitives")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn now() -> DateTime<Utc> {
        "2026-09-12T12:00:00Z".parse().unwrap()
    }
    fn line(timestamp: &str, action: &str, kind: &str) -> String {
        format!(
            "{}\n",
            serde_json::json!({"timestamp":timestamp,"action":action,"entry_type":kind,"command_redacted":"private fixture","rule_ids":["curl_pipe_shell","curl_pipe_shell"],"bypass_requested":true,"bypass_honored":false})
        )
    }
    fn refresh(reader: &HistoryReader, now: DateTime<Utc>) -> AggregateReport {
        summarize(reader, now, 7, true).unwrap()
    }

    #[test]
    fn first_refresh_counts_the_newest_records_not_only_the_oldest_page() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("log");
        // More than one 500-record page: 550 allowed checks, then the newest
        // 100 checks are blocks. A refresh must observe the newest records
        // instead of stopping after the oldest page of the suffix.
        let mut log = String::new();
        for _ in 0..550 {
            log.push_str(&line("2026-09-12T00:00:00Z", "Allow", "verdict"));
        }
        for _ in 0..100 {
            log.push_str(&line("2026-09-12T00:05:00Z", "Block", "verdict"));
        }
        std::fs::write(&path, log).unwrap();
        let reader = HistoryReader::new(path.clone());
        let first = refresh(&reader, now());
        assert_eq!(first.counts.recorded_checks, 650);
        assert_eq!(first.counts.blocked_checks, 100);
        assert!(!first.more_available);
        assert!(first.inspected_bytes_this_refresh <= 2 * 1024 * 1024);
        let retry = refresh(&reader, now());
        assert_eq!(retry.counts.recorded_checks, 650);
        assert!(retry.replace_previous);
        assert_eq!(retry.source_generation, first.source_generation);
    }

    #[test]
    fn a_suffix_larger_than_the_window_is_bounded_and_marked() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("log");
        let record = line("2026-09-12T00:00:00Z", "Block", "verdict");
        let count = (3 * 1024 * 1024) / record.len() + 1;
        std::fs::write(&path, record.repeat(count)).unwrap();
        let report = refresh(&HistoryReader::new(path), now());
        assert!(report.inspected_bytes_this_refresh <= 2 * 1024 * 1024);
        assert!(report.earlier_history_uninspected);
        assert_eq!(report.availability, Availability::Partial);
        assert!(report.counts.blocked_checks > 0);
        assert!((report.counts.blocked_checks as usize) < count);
    }

    #[test]
    fn append_refresh_and_non_verdict_records_do_not_double_count_checks() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("log");
        std::fs::write(
            &path,
            line("2026-09-12T00:00:00Z", "WarnAck", "verdict")
                + &line("2026-09-12T00:01:00Z", "Allow", "trust_change"),
        )
        .unwrap();
        let reader = HistoryReader::new(path.clone());
        let first = refresh(&reader, now());
        assert_eq!(first.counts.recorded_checks, 1);
        assert_eq!(first.other_records, 1);
        assert_eq!(first.rules[0].recorded_checks, 1);
        let retry = refresh(&reader, now());
        assert_eq!(retry.counts.recorded_checks, 1);
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(line("2026-09-12T00:02:00Z", "Block", "verdict").as_bytes())
            .unwrap();
        let after = refresh(&reader, now());
        assert_eq!(after.counts.recorded_checks, 2);
        assert_eq!(after.counts.blocked_checks, 1);
        assert_eq!(after.counts.acknowledgement_required_checks, 1);
        assert_eq!(after.rules[0].examples.len(), 2);
        assert_eq!(after.counts.bypass_honored_checks, 0);
        let displayed = display_projection(&after, &[".+".into()]);
        assert!(!displayed.to_string().contains("private fixture"));
        assert_eq!(displayed["rules"][0]["rule_id"], "curl_pipe_shell");
    }

    #[test]
    fn rotation_clock_change_and_future_records_are_reflected_on_the_next_read() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("log");
        std::fs::write(&path, line("2026-09-12T12:01:00Z", "Block", "verdict")).unwrap();
        let reader = HistoryReader::new(path.clone());
        let before = refresh(&reader, now());
        assert_eq!(before.counts.recorded_checks, 0);
        assert_eq!(before.future_dated_records, 1);
        let after = refresh(&reader, now() + chrono::Duration::minutes(2));
        assert!(after.replace_previous);
        assert_eq!(after.counts.recorded_checks, 1);
        let rewind = refresh(&reader, now());
        assert_eq!(rewind.counts.recorded_checks, 0);
        let restart = refresh(&HistoryReader::new(path.clone()), now());
        assert_ne!(restart.generation, rewind.generation);
        assert_ne!(restart.source_generation, rewind.source_generation);
        std::fs::write(&path, line("2026-09-12T11:01:00Z", "Allow", "verdict")).unwrap();
        let rebuilt = refresh(&reader, now());
        assert_ne!(rebuilt.source_generation, rewind.source_generation);
        assert_eq!(rebuilt.counts.recorded_checks, 1);
        assert_eq!(rebuilt.counts.allowed_checks, 1);
        assert_eq!(rebuilt.counts.blocked_checks, 0);
        let disabled = summarize(&reader, now(), 7, false).unwrap();
        assert_eq!(disabled.availability, Availability::Disabled);
        assert_eq!(disabled.counts.recorded_checks, 0);
        let reenabled = refresh(&reader, now());
        assert_eq!(reenabled.counts.recorded_checks, 1);
        assert!(summarize(&reader, now(), 0, true).is_err());
        assert!(summarize(&reader, now(), 32, true).is_err());
    }

    #[test]
    fn oversized_examples_do_not_leak_newly_protected_secret_prefixes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("log");
        let secret = "sensitive".repeat(100);
        let record = serde_json::json!({"timestamp":"2026-09-12T11:00:00Z", "action":"Block", "entry_type":"verdict", "command_redacted":secret, "rule_ids":["curl_pipe_shell"]});
        std::fs::write(&path, format!("{record}\n")).unwrap();
        let report = refresh(&HistoryReader::new(path), now());
        let projection = display_projection(&report, &[secret]);
        assert!(projection["rules"][0]["examples"][0]["command_truncated"]
            .as_bool()
            .unwrap());
        assert!(!projection.to_string().contains("sensitive"));
    }
}
