//! Deterministic policy-tuning suggestions derived from the local audit log.
//!
//! `policy tune --from-audit` reads the JSONL audit log and proposes
//! conservative adjustments — it only suggests, never rewrites the policy.
//!
//! No model: every suggestion is a fixed rule over plain counts (reproducible
//! from the log). A suggestion is emitted only with enough observations
//! (`MIN_OBSERVATIONS`); below that, [`analyze`] returns an empty list and sets
//! `data_is_thin` so the caller says "not enough data" rather than guessing.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::audit_aggregator::AuditRecord;

/// Minimum `verdict` records before any suggestion is emitted (below this the
/// sample is too small to be meaningful).
pub const MIN_OBSERVATIONS: usize = 20;

/// Minimum firings of a single rule before a per-rule suggestion (fewer is noise).
pub const MIN_RULE_FIRINGS: usize = 5;

/// Largest "never fired" list still worth printing — above it the unused set is
/// too large to say anything, so the note is suppressed.
pub const NEVER_FIRED_MAX_LIST: usize = 12;

/// Per-rule firing statistics rolled up from the audit log.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct RuleStats {
    /// Rule ID (snake_case, as stored in the log).
    pub rule_id: String,
    /// Total verdict records this rule appeared in.
    pub total: usize,
    pub allowed: usize,
    /// Records where the final action was `Warn` or `WarnAck`.
    pub warned: usize,
    pub blocked: usize,
    /// Records with an honored `TIRITH=0` bypass.
    pub bypassed: usize,
}

impl RuleStats {
    /// Records the user effectively waved through (`Allow` or honored bypass) —
    /// the signal the rule is firing on something the user doesn't see as a threat.
    fn waved_through(&self) -> usize {
        // `allowed` and `bypassed` overlap (a bypass is logged as Allow); max
        // avoids double-counting.
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

/// A single conservative, advisory policy-tuning suggestion. Every field is
/// plain text or a count the user can trace back to the log.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TuneSuggestion {
    /// Stable machine kind, e.g. `"frequently_bypassed"` / `"never_fired"`.
    pub kind: &'static str,
    pub rule_id: String,
    pub confidence: Confidence,
    /// One-line headline of what was observed.
    pub observation: String,
    /// The concrete adjustment, in plain language.
    pub recommendation: String,
    /// A copy-pasteable policy YAML snippet, when one applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_snippet: Option<String>,
}

/// The full result of analysing an audit log for tuning opportunities.
#[derive(Debug, Clone, Serialize)]
pub struct TuneReport {
    pub records_analyzed: usize,
    /// True when fewer than [`MIN_OBSERVATIONS`] records — no suggestion is
    /// trustworthy, `suggestions` is empty.
    pub data_is_thin: bool,
    /// Per-rule stats, sorted by total firings descending.
    pub rule_stats: Vec<RuleStats>,
    /// Suggestions, most actionable first; empty when data is thin or nothing warrants a change.
    pub suggestions: Vec<TuneSuggestion>,
}

/// Roll up per-rule statistics from audit records. Only `verdict` records are
/// counted; returned sorted by `total` descending, then `rule_id`.
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
/// `known_rule_ids` (every rule tirith can emit) drives the never-fired check;
/// pass empty to skip it.
pub fn analyze(records: &[AuditRecord], known_rule_ids: &[&str]) -> TuneReport {
    let verdict_count = records.iter().filter(|r| is_verdict(r)).count();
    let rule_stats = compute_rule_stats(records);

    // Thin data: report stats but make no suggestions.
    if verdict_count < MIN_OBSERVATIONS {
        return TuneReport {
            records_analyzed: verdict_count,
            data_is_thin: true,
            rule_stats,
            suggestions: Vec::new(),
        };
    }

    let mut suggestions = Vec::new();

    // Suggestion 1 — a rule that fires often and is (nearly) always waved
    // through: the strongest signal the user isn't acting on it.
    for stats in &rule_stats {
        if stats.total < MIN_RULE_FIRINGS {
            continue;
        }
        let waved = stats.waved_through();
        // Never suggest downgrading a rule the user sometimes blocks on.
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
            // >= 80% waved through, never blocked: moderate.
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

    // Suggestion 2 — never-fired rules. Purely informational (never recommends
    // disabling); emitted only when most rules fired and a short list is unused,
    // else it's just "you haven't used tirith much" and is skipped.
    if !known_rule_ids.is_empty() {
        let fired: std::collections::HashSet<&str> =
            rule_stats.iter().map(|s| s.rule_id.as_str()).collect();
        let mut never: Vec<&str> = known_rule_ids
            .iter()
            .copied()
            .filter(|id| !fired.contains(id))
            .collect();
        never.sort_unstable();
        // Only informative with a short, scannable unused list (≤ the max).
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

    // Most actionable first: strong before moderate, then by kind, then rule_id.
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

/// A commented `severity_overrides` snippet — the user fills in the target
/// severity (lowering one is a judgement call only they can make).
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
            agent_origin: None,
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
        // Always Allow, never blocked → strong.
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
        // A bypass is logged as Allow with bypass_honored=true.
        let records = n_records(25, "Allow", "curl_pipe_shell", true);
        let report = analyze(&records, &[]);
        let s = report
            .suggestions
            .iter()
            .find(|s| s.rule_id == "curl_pipe_shell")
            .expect("bypassed rule should yield a suggestion");
        assert_eq!(s.confidence, Confidence::Strong);
        // waved_through must not double-count Allow + honored bypass.
        let stats = report
            .rule_stats
            .iter()
            .find(|st| st.rule_id == "curl_pipe_shell")
            .unwrap();
        assert_eq!(stats.waved_through(), 25);
    }

    #[test]
    fn rule_sometimes_blocked_is_never_suggested_for_downgrade() {
        // 20 Allow + 5 Block: the rule IS catching real things → no downgrade.
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
        // 22 Allow + 3 Warn (no Block) = 88% waved through → moderate.
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
        // 25 Warn, never Allow/Block → not waved through, no downgrade.
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
        // shortened_url fires only 3× (< MIN_RULE_FIRINGS) → no suggestion.
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
        assert!(nf.recommendation.contains("curl_pipe_shell"));
        assert!(nf.recommendation.contains("raw_ip_url"));
        assert!(!nf.recommendation.contains("shortened_url"));
        // Must be informational, never a disable recommendation.
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
        // Unused set > NEVER_FIRED_MAX_LIST → the note is SKIPPED.
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
        // Exactly NEVER_FIRED_MAX_LIST unused rules — boundary, still emitted.
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
        // shortened_url (strong) must sort before non_standard_port (moderate).
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
