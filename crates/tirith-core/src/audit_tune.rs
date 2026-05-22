//! Deterministic policy-tuning suggestions derived from the local audit log.
//!
//! `policy tune --from-audit` reads the JSONL audit log and proposes concrete,
//! conservative policy adjustments — and *only* suggests; it never rewrites the
//! policy. The user reviews each suggestion and applies it by hand.
//!
//! ## What this is not
//!
//! There is no model here. Every suggestion is a fixed rule over plain counts:
//! "rule X fired N times and the user bypassed it every time" is an arithmetic
//! fact about the log, not an inference. The thresholds below are constants,
//! documented inline, so a suggestion is fully reproducible from the log.
//!
//! ## Honesty about thin data
//!
//! A suggestion is only emitted when the log carries enough observations to
//! support it (`MIN_OBSERVATIONS`). When the log is too small, [`analyze`]
//! returns an empty suggestion list and sets `data_is_thin`, so the caller can
//! say plainly "not enough data" instead of guessing.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::audit_aggregator::AuditRecord;

/// Minimum number of `verdict` records in the log before any suggestion is
/// emitted. Below this the sample is too small to be meaningful.
pub const MIN_OBSERVATIONS: usize = 20;

/// Minimum times a single rule must fire before a per-rule suggestion is made.
/// A rule seen only once or twice is noise, not a pattern.
pub const MIN_RULE_FIRINGS: usize = 5;

/// Largest "never fired" rule list that is still useful to print. Above this,
/// the unused set is so large the sample is simply too narrow to say anything,
/// so the never-fired note is suppressed entirely rather than dumped.
pub const NEVER_FIRED_MAX_LIST: usize = 12;

/// Per-rule firing statistics rolled up from the audit log.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct RuleStats {
    /// Rule ID (snake_case, as stored in the log).
    pub rule_id: String,
    /// Total number of verdict records this rule appeared in.
    pub total: usize,
    /// Records where the final action was `Allow`.
    pub allowed: usize,
    /// Records where the final action was `Warn` or `WarnAck`.
    pub warned: usize,
    /// Records where the final action was `Block`.
    pub blocked: usize,
    /// Records where the user requested a `TIRITH=0` bypass that was honored.
    pub bypassed: usize,
}

impl RuleStats {
    /// Records where the user effectively waved the finding through: either the
    /// final action was `Allow`, or a bypass was honored. This is the signal
    /// that the rule is firing on something the user does not consider a threat.
    fn waved_through(&self) -> usize {
        // `allowed` and `bypassed` can overlap (a bypassed command is logged as
        // Allow). Take the max so an honored-bypass Allow is not double-counted.
        self.allowed.max(self.bypassed)
    }
}

/// How strongly the audit data supports a suggestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// The pattern is unambiguous (e.g. a rule waved through 100% of the time).
    Strong,
    /// The pattern is suggestive but not absolute.
    Moderate,
}

/// A single concrete, conservative policy-tuning suggestion.
///
/// Every field is plain text or a count — there is nothing here the user cannot
/// trace back to the log. The suggestion is advisory; applying it is a manual
/// edit the user makes after reviewing.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TuneSuggestion {
    /// Stable machine kind, e.g. `"frequently_bypassed"` or `"never_fired"`.
    pub kind: &'static str,
    /// The rule this suggestion is about.
    pub rule_id: String,
    /// How strongly the data supports the suggestion.
    pub confidence: Confidence,
    /// One-line headline of what was observed.
    pub observation: String,
    /// The concrete adjustment the user could make, in plain language.
    pub recommendation: String,
    /// A copy-pasteable policy YAML snippet, when one applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_snippet: Option<String>,
}

/// The full result of analysing an audit log for tuning opportunities.
#[derive(Debug, Clone, Serialize)]
pub struct TuneReport {
    /// Number of `verdict` records considered.
    pub records_analyzed: usize,
    /// True when there were fewer than [`MIN_OBSERVATIONS`] records — no
    /// suggestion is trustworthy and the list below is empty.
    pub data_is_thin: bool,
    /// Per-rule firing statistics, sorted by total firings descending.
    pub rule_stats: Vec<RuleStats>,
    /// The concrete suggestions, most actionable first. Empty when the data is
    /// thin or when nothing in the log warrants a change.
    pub suggestions: Vec<TuneSuggestion>,
}

/// Roll up per-rule statistics from a slice of audit records.
///
/// Only `verdict` records are counted; `hook_telemetry` and `trust_change`
/// entries are ignored. Returned vec is sorted by `total` descending, then by
/// `rule_id` for a stable order.
pub fn compute_rule_stats(records: &[AuditRecord]) -> Vec<RuleStats> {
    let mut by_rule: BTreeMap<String, RuleStats> = BTreeMap::new();

    for record in records.iter().filter(|r| is_verdict(r)) {
        let action = record.action.to_ascii_lowercase();
        for rule_id in &record.rule_ids {
            let stats = by_rule.entry(rule_id.clone()).or_default();
            stats.rule_id = rule_id.clone();
            stats.total += 1;
            match action.as_str() {
                "allow" => stats.allowed += 1,
                "warn" | "warnack" => stats.warned += 1,
                "block" => stats.blocked += 1,
                _ => {}
            }
            if record.bypass_honored {
                stats.bypassed += 1;
            }
        }
    }

    let mut stats: Vec<RuleStats> = by_rule.into_values().collect();
    stats.sort_by(|a, b| {
        b.total
            .cmp(&a.total)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    stats
}

/// A `verdict` record (empty `entry_type` is a pre-tagged-union verdict record).
fn is_verdict(r: &AuditRecord) -> bool {
    r.entry_type.is_empty() || r.entry_type == "verdict"
}

/// Analyse audit records and produce conservative tuning suggestions.
///
/// `known_rule_ids` is the set of every rule ID tirith can emit, used to point
/// out rules that have *never* fired. Pass an empty slice to skip that check.
pub fn analyze(records: &[AuditRecord], known_rule_ids: &[&str]) -> TuneReport {
    let verdict_count = records.iter().filter(|r| is_verdict(r)).count();
    let rule_stats = compute_rule_stats(records);

    // Thin data: report stats but make no suggestions. Honesty over guessing.
    if verdict_count < MIN_OBSERVATIONS {
        return TuneReport {
            records_analyzed: verdict_count,
            data_is_thin: true,
            rule_stats,
            suggestions: Vec::new(),
        };
    }

    let mut suggestions = Vec::new();

    // Suggestion 1 — a rule that fires often and is waved through every time,
    // or nearly every time. This is the strongest, most useful signal: the rule
    // is producing findings the user consistently does not act on.
    for stats in &rule_stats {
        if stats.total < MIN_RULE_FIRINGS {
            continue;
        }
        let waved = stats.waved_through();
        // Only suggest when the rule was NEVER blocked — a rule the user
        // sometimes blocks on is doing its job and must not be downgraded.
        if stats.blocked > 0 {
            continue;
        }
        if waved == stats.total {
            // 100% waved through, never blocked: strong.
            suggestions.push(TuneSuggestion {
                kind: "frequently_bypassed",
                rule_id: stats.rule_id.clone(),
                confidence: Confidence::Strong,
                observation: format!(
                    "Rule '{}' fired {} time(s) and was allowed or bypassed every time — never blocked.",
                    stats.rule_id, stats.total
                ),
                recommendation: format!(
                    "If these were all legitimate, consider scoping an allowlist entry for the \
                     specific source(s), or a severity override to lower '{}'. Review the \
                     matching commands first — do not downgrade a rule that is catching real issues.",
                    stats.rule_id
                ),
                policy_snippet: Some(severity_override_snippet(&stats.rule_id)),
            });
        } else if waved >= (stats.total * 4).div_ceil(5) {
            // >= 80% waved through (ceil division), never blocked: moderate.
            suggestions.push(TuneSuggestion {
                kind: "frequently_bypassed",
                rule_id: stats.rule_id.clone(),
                confidence: Confidence::Moderate,
                observation: format!(
                    "Rule '{}' fired {} time(s); {} were allowed or bypassed and none were blocked.",
                    stats.rule_id, stats.total, waved
                ),
                recommendation: format!(
                    "'{}' is mostly being waved through. Review those commands: if they share a \
                     trusted source, an allowlist entry is cleaner than repeatedly bypassing.",
                    stats.rule_id
                ),
                policy_snippet: None,
            });
        }
    }

    // Suggestion 2 — rules that have never fired. Purely informational: it
    // never recommends disabling a rule (a rule that has not fired may simply
    // not have been provoked yet). It is only emitted when it is genuinely
    // informative — i.e. the command history exercises *most* rules and only a
    // short, nameable list is unused. When the log is small relative to the
    // rule set (the common case), "never fired" is just "you have not used
    // tirith much" and is silently skipped rather than dumping a huge list.
    if !known_rule_ids.is_empty() {
        let fired: std::collections::HashSet<&str> =
            rule_stats.iter().map(|s| s.rule_id.as_str()).collect();
        let mut never: Vec<&str> = known_rule_ids
            .iter()
            .copied()
            .filter(|id| !fired.contains(id))
            .collect();
        never.sort_unstable();
        // Only informative when at most NEVER_FIRED_MAX_LIST rules are unused —
        // a short list the user can actually scan. A larger unused set means
        // the sample is just too narrow to say anything about those rules.
        if !never.is_empty() && never.len() <= NEVER_FIRED_MAX_LIST {
            suggestions.push(TuneSuggestion {
                kind: "never_fired",
                rule_id: String::new(),
                confidence: Confidence::Moderate,
                observation: format!(
                    "{} detection rule(s) never fired across the {} analysed record(s).",
                    never.len(),
                    verdict_count
                ),
                recommendation: format!(
                    "Informational only — these rules were simply not provoked by your command \
                     history; this is not a reason to disable them. Rules: {}.",
                    never.join(", ")
                ),
                policy_snippet: None,
            });
        }
    }

    // Most actionable first: strong before moderate, then by kind.
    suggestions.sort_by(|a, b| {
        confidence_rank(b.confidence)
            .cmp(&confidence_rank(a.confidence))
            .then_with(|| a.kind.cmp(b.kind))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    TuneReport {
        records_analyzed: verdict_count,
        data_is_thin: false,
        rule_stats,
        suggestions,
    }
}

fn confidence_rank(c: Confidence) -> u8 {
    match c {
        Confidence::Strong => 1,
        Confidence::Moderate => 0,
    }
}

/// A commented `severity_overrides` snippet for a rule. The user fills in the
/// target severity — tirith deliberately does not pick one, because lowering a
/// severity is a judgement call only the user can make.
fn severity_override_snippet(rule_id: &str) -> String {
    format!(
        "# Reviewed and trusted? Lower the severity (pick LOW/MEDIUM yourself):\nseverity_overrides:\n  {rule_id}: LOW   # or MEDIUM — your call after reviewing the commands"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict_record(action: &str, rules: &[&str], bypass_honored: bool) -> AuditRecord {
        AuditRecord {
            timestamp: "2026-05-20T10:00:00Z".into(),
            session_id: "s1".into(),
            action: action.into(),
            rule_ids: rules.iter().map(|s| s.to_string()).collect(),
            command_redacted: "cmd".into(),
            bypass_requested: bypass_honored,
            bypass_honored,
            interactive: true,
            policy_path: None,
            event_id: None,
            tier_reached: 3,
            entry_type: "verdict".into(),
            event: None,
            integration: None,
            hook_type: None,
            detail: None,
            elapsed_ms: None,
            raw_action: None,
            raw_rule_ids: None,
            trust_pattern: None,
            trust_rule_id: None,
            trust_action: None,
            trust_ttl_expires: None,
            trust_scope: None,
        }
    }

    /// Build N records, all with the same action / rule / bypass state.
    fn n_records(n: usize, action: &str, rule: &str, bypass: bool) -> Vec<AuditRecord> {
        (0..n)
            .map(|_| verdict_record(action, &[rule], bypass))
            .collect()
    }

    #[test]
    fn thin_data_makes_no_suggestions() {
        // Below MIN_OBSERVATIONS: data_is_thin, empty suggestions.
        let records = n_records(10, "Block", "curl_pipe_shell", false);
        let report = analyze(&records, &[]);
        assert!(report.data_is_thin);
        assert!(report.suggestions.is_empty());
        assert_eq!(report.records_analyzed, 10);
    }

    #[test]
    fn exactly_min_observations_is_not_thin() {
        let records = n_records(MIN_OBSERVATIONS, "Allow", "shortened_url", false);
        let report = analyze(&records, &[]);
        assert!(!report.data_is_thin);
    }

    #[test]
    fn rule_always_allowed_yields_strong_suggestion() {
        // 25 records, rule always Allow, never blocked → strong suggestion.
        let records = n_records(25, "Allow", "shortened_url", false);
        let report = analyze(&records, &[]);
        let s = report
            .suggestions
            .iter()
            .find(|s| s.rule_id == "shortened_url")
            .expect("frequently-bypassed suggestion expected");
        assert_eq!(s.kind, "frequently_bypassed");
        assert_eq!(s.confidence, Confidence::Strong);
        assert!(s.policy_snippet.is_some());
    }

    #[test]
    fn rule_bypassed_via_honored_bypass_counts_as_waved_through() {
        // Bypassed commands are logged as Allow with bypass_honored=true.
        let records = n_records(25, "Allow", "curl_pipe_shell", true);
        let report = analyze(&records, &[]);
        let s = report
            .suggestions
            .iter()
            .find(|s| s.rule_id == "curl_pipe_shell")
            .expect("bypassed rule should yield a suggestion");
        assert_eq!(s.confidence, Confidence::Strong);
        // waved_through must not double-count Allow + honored-bypass.
        let stats = report
            .rule_stats
            .iter()
            .find(|st| st.rule_id == "curl_pipe_shell")
            .unwrap();
        assert_eq!(stats.waved_through(), 25);
    }

    #[test]
    fn rule_sometimes_blocked_is_never_suggested_for_downgrade() {
        // 20 Allow + 5 Block of the same rule: the rule IS catching real
        // things, so it must NOT be suggested for a downgrade.
        let mut records = n_records(20, "Allow", "curl_pipe_shell", false);
        records.extend(n_records(5, "Block", "curl_pipe_shell", false));
        let report = analyze(&records, &[]);
        assert!(
            report
                .suggestions
                .iter()
                .all(|s| s.rule_id != "curl_pipe_shell"),
            "a rule that is sometimes blocked must never be suggested for downgrade"
        );
    }

    #[test]
    fn mostly_waved_through_yields_moderate_suggestion() {
        // 22 Allow + 3 Warn (no Block) of the same rule = 88% waved through.
        let mut records = n_records(22, "Allow", "non_standard_port", false);
        records.extend(n_records(3, "Warn", "non_standard_port", false));
        let report = analyze(&records, &[]);
        let s = report
            .suggestions
            .iter()
            .find(|s| s.rule_id == "non_standard_port")
            .expect("mostly-waved-through rule should yield a suggestion");
        assert_eq!(s.confidence, Confidence::Moderate);
    }

    #[test]
    fn warned_but_not_allowed_rule_is_not_suggested() {
        // 25 Warn records, never Allow, never Block: not waved through,
        // not blocked — no downgrade suggestion (only ~0% waved).
        let records = n_records(25, "Warn", "shortened_url", false);
        let report = analyze(&records, &[]);
        assert!(
            report
                .suggestions
                .iter()
                .all(|s| s.rule_id != "shortened_url"),
            "a purely-warned rule is not waved through and should not be suggested"
        );
    }

    #[test]
    fn rule_below_min_firings_is_not_suggested() {
        // 22 records: 3 fire shortened_url (always Allow), 19 fire something
        // else. shortened_url is below MIN_RULE_FIRINGS so no suggestion.
        let mut records = n_records(3, "Allow", "shortened_url", false);
        records.extend(n_records(19, "Allow", "plain_http_to_sink", false));
        let report = analyze(&records, &[]);
        assert!(
            report
                .suggestions
                .iter()
                .all(|s| s.rule_id != "shortened_url"),
            "a rule that fired fewer than MIN_RULE_FIRINGS times must not be suggested"
        );
    }

    #[test]
    fn never_fired_rules_are_reported_informationally() {
        let records = n_records(25, "Allow", "shortened_url", false);
        let known = ["shortened_url", "curl_pipe_shell", "raw_ip_url"];
        let report = analyze(&records, &known);
        let nf = report
            .suggestions
            .iter()
            .find(|s| s.kind == "never_fired")
            .expect("never-fired suggestion expected");
        // curl_pipe_shell and raw_ip_url never fired.
        assert!(nf.recommendation.contains("curl_pipe_shell"));
        assert!(nf.recommendation.contains("raw_ip_url"));
        assert!(!nf.recommendation.contains("shortened_url"));
        // It must be explicitly informational, never a disable recommendation.
        assert!(nf.recommendation.to_lowercase().contains("informational"));
    }

    #[test]
    fn no_never_fired_suggestion_when_all_rules_fired() {
        let records = n_records(25, "Allow", "shortened_url", false);
        let report = analyze(&records, &["shortened_url"]);
        assert!(report.suggestions.iter().all(|s| s.kind != "never_fired"));
    }

    #[test]
    fn never_fired_suppressed_when_unused_list_is_too_large() {
        // Only `shortened_url` fired; a known set far larger than
        // NEVER_FIRED_MAX_LIST has not. The never-fired note must be SKIPPED
        // rather than dumping a huge, useless list.
        let records = n_records(25, "Allow", "shortened_url", false);
        let mut known: Vec<String> = (0..NEVER_FIRED_MAX_LIST + 5)
            .map(|i| format!("rule_{i}"))
            .collect();
        known.push("shortened_url".to_string());
        let known_refs: Vec<&str> = known.iter().map(String::as_str).collect();
        let report = analyze(&records, &known_refs);
        assert!(
            report.suggestions.iter().all(|s| s.kind != "never_fired"),
            "a never-fired list larger than NEVER_FIRED_MAX_LIST must be suppressed"
        );
        // The frequently-bypassed suggestion is unaffected.
        assert!(report
            .suggestions
            .iter()
            .any(|s| s.kind == "frequently_bypassed"));
    }

    #[test]
    fn never_fired_emitted_when_unused_list_is_small() {
        // Exactly NEVER_FIRED_MAX_LIST unused rules — at the boundary, still
        // emitted (the list is short enough to scan).
        let records = n_records(25, "Allow", "shortened_url", false);
        let mut known: Vec<String> = (0..NEVER_FIRED_MAX_LIST)
            .map(|i| format!("rule_{i}"))
            .collect();
        known.push("shortened_url".to_string());
        let known_refs: Vec<&str> = known.iter().map(String::as_str).collect();
        let report = analyze(&records, &known_refs);
        assert!(
            report.suggestions.iter().any(|s| s.kind == "never_fired"),
            "exactly NEVER_FIRED_MAX_LIST unused rules should still be reported"
        );
    }

    #[test]
    fn strong_suggestions_sort_before_moderate() {
        // shortened_url: 25/25 Allow → strong. non_standard_port: 22 Allow +
        // 3 Warn → moderate. Strong must come first.
        let mut records = n_records(25, "Allow", "shortened_url", false);
        records.extend(n_records(22, "Allow", "non_standard_port", false));
        records.extend(n_records(3, "Warn", "non_standard_port", false));
        let report = analyze(&records, &[]);
        let frequently: Vec<&TuneSuggestion> = report
            .suggestions
            .iter()
            .filter(|s| s.kind == "frequently_bypassed")
            .collect();
        assert_eq!(frequently.len(), 2);
        assert_eq!(frequently[0].confidence, Confidence::Strong);
        assert_eq!(frequently[1].confidence, Confidence::Moderate);
    }

    #[test]
    fn compute_rule_stats_ignores_non_verdict_entries() {
        let mut records = n_records(5, "Block", "curl_pipe_shell", false);
        // A hook_telemetry entry must not be counted.
        let mut hook = verdict_record("hook", &[], false);
        hook.entry_type = "hook_telemetry".into();
        hook.rule_ids = vec!["curl_pipe_shell".into()];
        records.push(hook);
        let stats = compute_rule_stats(&records);
        let cps = stats
            .iter()
            .find(|s| s.rule_id == "curl_pipe_shell")
            .unwrap();
        assert_eq!(cps.total, 5, "hook_telemetry entries must be ignored");
    }

    #[test]
    fn compute_rule_stats_counts_actions_correctly() {
        let mut records = n_records(3, "Block", "r", false);
        records.extend(n_records(2, "Warn", "r", false));
        records.extend(n_records(4, "Allow", "r", false));
        let stats = compute_rule_stats(&records);
        let r = stats.iter().find(|s| s.rule_id == "r").unwrap();
        assert_eq!(r.total, 9);
        assert_eq!(r.blocked, 3);
        assert_eq!(r.warned, 2);
        assert_eq!(r.allowed, 4);
    }

    #[test]
    fn empty_log_is_thin_not_a_crash() {
        let report = analyze(&[], &["shortened_url"]);
        assert!(report.data_is_thin);
        assert_eq!(report.records_analyzed, 0);
        assert!(report.suggestions.is_empty());
    }
}
