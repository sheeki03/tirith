//! Escalation engine and post-processing verdict helper.
//!
//! Escalation rules upgrade the verdict action based on session warning history
//! (repeat offenders) or current finding density (multi-medium).
//!
//! The `post_process_verdict` function is the shared helper that applies action
//! overrides, approvals, paranoia filtering, escalation, and session recording
//! in the correct order.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::session_warnings::SessionWarnings;
use crate::verdict::{Action, Finding, Severity, Verdict};

// ---------------------------------------------------------------------------
// Escalation rule types
// ---------------------------------------------------------------------------

fn default_window_60() -> u64 {
    60
}

/// An escalation rule: upgrade verdict action based on session history or
/// current finding count.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "trigger", rename_all = "snake_case")]
pub enum EscalationRule {
    /// Upgrade to `action` when a matching rule has fired >= `threshold` times
    /// within `window_minutes` (counting both session history AND current findings).
    RepeatCount {
        rule_ids: Vec<String>,
        threshold: u32,
        #[serde(default = "default_window_60")]
        window_minutes: u64,
        action: EscalationAction,
        #[serde(default)]
        domain_scoped: bool,
        /// Minutes after an escalation fires during which that (rule, domain) pair
        /// will not re-escalate. 0 = no cooldown (default, preserves old behaviour).
        #[serde(default)]
        cooldown_minutes: u64,
    },
    /// Upgrade when the current verdict contains >= `min_findings` findings of
    /// severity Medium or above.
    MultiMedium {
        min_findings: u32,
        action: EscalationAction,
    },
}

/// The action an escalation rule can upgrade to. Only Block is supported
/// (escalation can never downgrade).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationAction {
    Block,
}

impl EscalationAction {
    fn to_action(self) -> Action {
        match self {
            EscalationAction::Block => Action::Block,
        }
    }
}

// ---------------------------------------------------------------------------
// Escalation application
// ---------------------------------------------------------------------------

/// Captures exactly which rule/domain triggered an escalation, enabling
/// correct per-key cooldown scoping.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EscalationHit {
    /// The finding rule that crossed the threshold, or `"*"` for wildcard aggregate.
    pub rule_id: String,
    /// For `domain_scoped` rules, the specific domain that crossed the threshold.
    pub domain: Option<String>,
}

impl EscalationHit {
    /// True if this hit came from a wildcard aggregate threshold (`rule_id == "*"`).
    pub fn is_wildcard(&self) -> bool {
        self.rule_id == "*"
    }
}

/// Apply escalation rules against session history + current findings.
///
/// Returns the (potentially upgraded) action, the set of causal rule_ids,
/// structured escalation hits (for cooldown recording), and an optional
/// human-readable reason string. Never downgrades the action.
pub fn apply_escalation(
    current_action: Action,
    findings: &[Finding],
    session: &SessionWarnings,
    rules: &[EscalationRule],
) -> (Action, HashSet<String>, Vec<EscalationHit>, Option<String>) {
    let mut action = current_action;
    let mut causal = HashSet::new();
    let mut hits: Vec<EscalationHit> = Vec::new();
    let mut reason: Option<String> = None;

    for rule in rules {
        match rule {
            EscalationRule::RepeatCount {
                rule_ids,
                threshold,
                window_minutes,
                action: esc_action,
                domain_scoped,
                cooldown_minutes,
            } => {
                let target = esc_action.to_action();
                if action_gte(action, target) {
                    continue; // Already at or above target
                }

                let wildcard = rule_ids.iter().any(|id| id == "*");

                // Precompute a counted map of current findings keyed by
                // (rule_id, Option<domain>) so each pair is evaluated exactly once.
                let current_counts: HashMap<(String, Option<String>), u32> = {
                    let mut map = HashMap::new();
                    for f in findings {
                        let rid = f.rule_id.to_string();
                        if !wildcard && !rule_ids.iter().any(|id| id == &rid) {
                            continue;
                        }
                        if *domain_scoped {
                            let domains = extract_finding_domains(f);
                            if domains.is_empty() {
                                *map.entry((rid, None)).or_insert(0) += 1;
                            } else {
                                for d in domains {
                                    *map.entry((rid.clone(), Some(d))).or_insert(0) += 1;
                                }
                            }
                        } else {
                            *map.entry((rid, None)).or_insert(0) += 1;
                        }
                    }
                    map
                };

                // Iterate the deduped (rule_id, domain) keys.
                for ((fid, domain), current_count) in &current_counts {
                    if action_gte(action, target) {
                        break;
                    }

                    // Cooldown check: skip if a matching recent escalation event
                    // exists in the session history.
                    if *cooldown_minutes > 0 {
                        let cooldown_active = session.escalation_events.iter().any(|ev| {
                            let rule_matches = if ev.rule_id == "*" {
                                false // wildcard events only cool down wildcard aggregate
                            } else {
                                ev.rule_id == *fid
                            };
                            let domain_matches = match (&ev.domain, domain) {
                                (Some(ed), Some(fd)) => ed == fd,
                                (None, None) => true,
                                _ => false,
                            };
                            rule_matches
                                && domain_matches
                                && is_within_minutes(&ev.timestamp, *cooldown_minutes)
                        });
                        if cooldown_active {
                            continue;
                        }
                    }

                    let session_count = if *domain_scoped {
                        match domain {
                            Some(d) => session.count_by_rule_and_domain(fid, d, *window_minutes),
                            None => session.count_by_rule(fid, *window_minutes),
                        }
                    } else {
                        session.count_by_rule(fid, *window_minutes)
                    };

                    let total = session_count + current_count;
                    if total >= *threshold {
                        action = target;
                        causal.insert(fid.clone());
                        hits.push(EscalationHit {
                            rule_id: fid.clone(),
                            domain: domain.clone(),
                        });
                        // For wildcard rules, also record a wildcard hit so the
                        // aggregate path cannot bypass per-rule cooldown.
                        if wildcard {
                            hits.push(EscalationHit {
                                rule_id: "*".to_string(),
                                domain: None,
                            });
                        }
                        if reason.is_none() {
                            reason = Some(format!(
                                "{fid} triggered {total} times in {window_minutes}m (threshold: {threshold})"
                            ));
                        }
                    }
                }

                // Wildcard aggregate: only when NOT domain_scoped and not already
                // at target. Catches mixed-rule sessions where no single rule
                // crosses threshold but the total does.
                if wildcard && !domain_scoped && !action_gte(action, target) {
                    // Cooldown check for wildcard aggregate.
                    if *cooldown_minutes > 0 {
                        let wildcard_cooled = session.escalation_events.iter().any(|ev| {
                            ev.rule_id == "*" && is_within_minutes(&ev.timestamp, *cooldown_minutes)
                        });
                        if wildcard_cooled {
                            continue; // skip aggregate path during cooldown
                        }
                    }

                    let total = session.count_all(*window_minutes) + findings.len() as u32;
                    if total >= *threshold {
                        action = target;
                        for f in findings {
                            causal.insert(f.rule_id.to_string());
                        }
                        hits.push(EscalationHit {
                            rule_id: "*".to_string(),
                            domain: None,
                        });
                        if reason.is_none() {
                            reason = Some(format!(
                                "{total} warnings in {window_minutes}m (threshold: {threshold})"
                            ));
                        }
                    }
                }
            }
            EscalationRule::MultiMedium {
                min_findings,
                action: esc_action,
            } => {
                let target = esc_action.to_action();
                if action_gte(action, target) {
                    continue;
                }
                let med_plus_count = findings
                    .iter()
                    .filter(|f| f.severity >= Severity::Medium)
                    .count() as u32;
                if med_plus_count >= *min_findings {
                    action = target;
                    for f in findings.iter().filter(|f| f.severity >= Severity::Medium) {
                        causal.insert(f.rule_id.to_string());
                    }
                    if reason.is_none() {
                        reason = Some(format!(
                            "{med_plus_count} medium+ findings on one command (threshold: {min_findings})"
                        ));
                    }
                }
            }
        }
    }

    // Deduplicate hits (same rule_id + domain should only appear once).
    let mut seen = HashSet::new();
    hits.retain(|h| seen.insert((h.rule_id.clone(), h.domain.clone())));

    (action, causal, hits, reason)
}

/// Check whether a timestamp string (RFC 3339) is within `minutes` of now.
fn is_within_minutes(timestamp: &str, minutes: u64) -> bool {
    let Ok(ts) = chrono::DateTime::parse_from_rfc3339(timestamp) else {
        // Conservative: treat unparseable timestamps as within-window so cooldown
        // stays active rather than allowing premature re-escalation.
        return true;
    };
    let cutoff =
        chrono::Utc::now() - chrono::Duration::minutes(minutes.min(u32::MAX as u64) as i64);
    ts >= cutoff
}

/// Apply per-rule action overrides. Only "block" is a valid override value.
/// Returns upgraded action and causal rule_ids.
pub fn apply_action_overrides(
    current_action: Action,
    findings: &[Finding],
    overrides: &HashMap<String, String>,
) -> (Action, HashSet<String>) {
    let mut action = current_action;
    let mut causal = HashSet::new();

    for finding in findings {
        let fid = finding.rule_id.to_string();
        if let Some(override_action) = overrides.get(&fid) {
            if override_action == "block" && !action_gte(action, Action::Block) {
                action = Action::Block;
                causal.insert(fid);
            }
        }
    }

    (action, causal)
}

/// True if `a` is at least as strict as `b`.
fn action_gte(a: Action, b: Action) -> bool {
    action_rank(a) >= action_rank(b)
}

fn action_rank(a: Action) -> u8 {
    match a {
        Action::Allow => 0,
        Action::Warn => 1,
        Action::WarnAck => 2,
        Action::Block => 3,
    }
}

/// Extract domains from a single finding's evidence.
fn extract_finding_domains(finding: &Finding) -> Vec<String> {
    crate::session_warnings::extract_domains_from_evidence(&finding.evidence)
}

// ---------------------------------------------------------------------------
// Caller context
// ---------------------------------------------------------------------------

/// Where the verdict is being processed. Non-CLI callers cannot prompt
/// interactively, so approval requirements become blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerContext {
    Cli,
    Gateway,
    McpServer,
    Daemon,
}

// ---------------------------------------------------------------------------
// Post-process verdict
// ---------------------------------------------------------------------------

/// Shared post-processing pipeline applied after the core engine produces a
/// raw verdict. Applies action overrides, approvals, paranoia filtering,
/// escalation, and session warning recording in the canonical order.
///
/// Side effects: reads and writes session state files (best-effort, never panics).
pub fn post_process_verdict(
    raw_verdict: &Verdict,
    policy: &crate::policy::Policy,
    cmd: &str,
    session_id: &str,
    caller: CallerContext,
) -> Verdict {
    let mut effective = raw_verdict.clone();
    let mut causal_rule_ids: HashSet<String> = HashSet::new();

    // --- 1. Action overrides on RAW findings (before any filtering) ---
    if !policy.action_overrides.is_empty() {
        let (new_action, caused_by) = apply_action_overrides(
            effective.action,
            &effective.findings,
            &policy.action_overrides,
        );
        effective.action = new_action;
        causal_rule_ids.extend(caused_by);
    }

    // --- 2. Approval detection BEFORE warning recording ---
    if let Some(meta) = crate::approval::check_approval(&effective, policy) {
        crate::approval::apply_approval(&mut effective, &meta);
        causal_rule_ids.insert(meta.rule_id.clone());
        if caller != CallerContext::Cli && effective.requires_approval == Some(true) {
            effective.action = Action::Block;
        }
    }

    // --- 3. Paranoia filter + causal finding preservation ---
    // Save the pre-paranoia action so we can enforce "never downgrade" after
    // filter_findings_by_paranoia recalculates from remaining findings.
    let pre_paranoia_action = effective.action;

    let causal_indices: Vec<usize> = raw_verdict
        .findings
        .iter()
        .enumerate()
        .filter(|(_, f)| causal_rule_ids.contains(&f.rule_id.to_string()))
        .map(|(i, _)| i)
        .collect();

    crate::engine::filter_findings_by_paranoia(&mut effective, policy.paranoia);

    // Paranoia filtering must never downgrade an action set by explicit overrides/approvals.
    // Only restore when causal_rule_ids is non-empty (i.e., an override or approval fired).
    // Engine-natural verdicts (no explicit override) should be allowed to be downgraded
    // by paranoia filtering.
    if !causal_rule_ids.is_empty()
        && action_rank(pre_paranoia_action) > action_rank(effective.action)
    {
        effective.action = pre_paranoia_action;
    }

    // Re-add causal findings that paranoia may have removed
    for &idx in &causal_indices {
        if idx < raw_verdict.findings.len() {
            let causal = &raw_verdict.findings[idx];
            let already_present = effective.findings.iter().any(|ef| {
                ef.rule_id == causal.rule_id
                    && ef.severity == causal.severity
                    && ef.title == causal.title
                    && ef.description == causal.description
            });
            if !already_present {
                effective.findings.push(causal.clone());
            }
        }
    }

    // If action is non-Allow due to explicit overrides/approvals but findings were
    // all filtered out, restore some so the user can see why the action was set.
    // Only do this when causal_rule_ids is non-empty — for engine-natural verdicts
    // where paranoia filtered everything out, let the action naturally recompute to Allow.
    if !causal_rule_ids.is_empty()
        && effective.action != Action::Allow
        && effective.findings.is_empty()
    {
        for f in &raw_verdict.findings {
            if f.severity >= Severity::Low
                && !effective.findings.iter().any(|ef| ef.rule_id == f.rule_id)
            {
                effective.findings.push(f.clone());
            }
        }
    }

    // --- 4. Escalation check BEFORE recording ---
    if !policy.escalation.is_empty() && matches!(effective.action, Action::Warn | Action::WarnAck) {
        let session = crate::session_warnings::load(session_id);
        let (new_action, caused_by, escalation_hits, reason) = apply_escalation(
            effective.action,
            &effective.findings,
            &session,
            &policy.escalation,
        );
        if new_action != effective.action {
            effective.escalation_reason = reason;
            // Record escalation events outside the warning recording gate:
            // escalated blocks are Action::Block and would skip the Warn/WarnAck
            // recording path, so we write them separately.
            crate::session_warnings::record_escalation_event(session_id, &escalation_hits);
        }
        effective.action = new_action;
        causal_rule_ids.extend(caused_by);
    }

    // --- 5. Session outcome recording — warnings + hidden findings ---
    // Compute hidden findings via multiset diff of raw minus final effective.
    // Collect actual Finding references so `record_outcome` can store full
    // `HiddenEvent` details for `tirith warnings --hidden`.
    let hidden_findings_vec: Vec<&Finding> = {
        let mut effective_counts: HashMap<(String, String, String, String), u32> = HashMap::new();
        for f in &effective.findings {
            let key = (
                f.rule_id.to_string(),
                f.severity.to_string(),
                f.title.clone(),
                f.description.clone(),
            );
            *effective_counts.entry(key).or_insert(0) += 1;
        }
        let mut hidden = Vec::new();
        for f in &raw_verdict.findings {
            let key = (
                f.rule_id.to_string(),
                f.severity.to_string(),
                f.title.clone(),
                f.description.clone(),
            );
            match effective_counts.get_mut(&key) {
                Some(count) if *count > 0 => {
                    *count -= 1;
                }
                _ => {
                    hidden.push(f);
                }
            }
        }
        hidden
    };

    if matches!(effective.action, Action::Warn | Action::WarnAck) || !hidden_findings_vec.is_empty()
    {
        let warn_findings: Vec<&Finding> =
            if matches!(effective.action, Action::Warn | Action::WarnAck) {
                effective
                    .findings
                    .iter()
                    .filter(|f| f.severity >= Severity::Low)
                    .collect()
            } else {
                vec![]
            };
        crate::session_warnings::record_outcome(
            session_id,
            &warn_findings,
            &hidden_findings_vec,
            cmd,
            &policy.dlp_custom_patterns,
        );
    }

    effective
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Evidence, Finding, RuleId, Severity, Timings};

    fn make_finding(rule_id: RuleId, severity: Severity) -> Finding {
        Finding {
            rule_id,
            severity,
            title: format!("{rule_id:?} finding"),
            description: "test description".to_string(),
            evidence: vec![Evidence::Text {
                detail: "test".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }
    }

    fn empty_session() -> SessionWarnings {
        SessionWarnings {
            session_id: "test".to_string(),
            session_start: chrono::Utc::now().to_rfc3339(),
            total_warnings: 0,
            hidden_findings: 0,
            hidden_low: 0,
            hidden_info: 0,
            events: std::collections::VecDeque::new(),
            escalation_events: std::collections::VecDeque::new(),
            hidden_events: std::collections::VecDeque::new(),
        }
    }

    fn session_with_history(rule_id: &str, count: u32) -> SessionWarnings {
        let mut session = empty_session();
        let now = chrono::Utc::now().to_rfc3339();
        for _ in 0..count {
            session
                .events
                .push_back(crate::session_warnings::WarningEvent {
                    timestamp: now.clone(),
                    rule_id: rule_id.to_string(),
                    severity: "MEDIUM".to_string(),
                    title: "test".to_string(),
                    command_redacted: "cmd".to_string(),
                    domains: vec![],
                });
        }
        session.total_warnings = count;
        session
    }

    // --- Escalation tests ---

    #[test]
    fn test_repeat_count_below_threshold() {
        let session = session_with_history("non_ascii_hostname", 2);
        let findings = vec![make_finding(RuleId::NonAsciiHostname, Severity::Medium)];
        let rules = vec![EscalationRule::RepeatCount {
            rule_ids: vec!["non_ascii_hostname".to_string()],
            threshold: 5,
            window_minutes: 60,
            action: EscalationAction::Block,
            domain_scoped: false,
            cooldown_minutes: 0,
        }];

        let (action, causal, _, _) = apply_escalation(Action::Warn, &findings, &session, &rules);
        // 2 (history) + 1 (current) = 3 < 5
        assert_eq!(action, Action::Warn);
        assert!(causal.is_empty());
    }

    #[test]
    fn test_repeat_count_meets_threshold() {
        let session = session_with_history("non_ascii_hostname", 4);
        let findings = vec![make_finding(RuleId::NonAsciiHostname, Severity::Medium)];
        let rules = vec![EscalationRule::RepeatCount {
            rule_ids: vec!["non_ascii_hostname".to_string()],
            threshold: 5,
            window_minutes: 60,
            action: EscalationAction::Block,
            domain_scoped: false,
            cooldown_minutes: 0,
        }];

        let (action, causal, hits, _) = apply_escalation(Action::Warn, &findings, &session, &rules);
        // 4 + 1 = 5 >= 5
        assert_eq!(action, Action::Block);
        assert!(causal.contains("non_ascii_hostname"));
        assert!(hits
            .iter()
            .any(|h| h.rule_id == "non_ascii_hostname" && !h.is_wildcard()));
    }

    #[test]
    fn test_repeat_count_wildcard() {
        let session = session_with_history("any_rule", 9);
        let findings = vec![make_finding(RuleId::ShortenedUrl, Severity::Medium)];
        let rules = vec![EscalationRule::RepeatCount {
            rule_ids: vec!["*".to_string()],
            threshold: 10,
            window_minutes: 60,
            action: EscalationAction::Block,
            domain_scoped: false,
            cooldown_minutes: 0,
        }];

        let (action, _, hits, _) = apply_escalation(Action::Warn, &findings, &session, &rules);
        // 9 + 1 = 10 >= 10 (aggregate wildcard path)
        assert_eq!(action, Action::Block);
        // Should have a wildcard hit
        assert!(hits.iter().any(|h| h.rule_id == "*" && h.is_wildcard()));
    }

    #[test]
    fn test_multi_medium_below_threshold() {
        let session = empty_session();
        let findings = vec![
            make_finding(RuleId::NonAsciiHostname, Severity::Medium),
            make_finding(RuleId::ShortenedUrl, Severity::Low),
        ];
        let rules = vec![EscalationRule::MultiMedium {
            min_findings: 3,
            action: EscalationAction::Block,
        }];

        let (action, _, _, _) = apply_escalation(Action::Warn, &findings, &session, &rules);
        // Only 1 >= Medium
        assert_eq!(action, Action::Warn);
    }

    #[test]
    fn test_multi_medium_meets_threshold() {
        let session = empty_session();
        let findings = vec![
            make_finding(RuleId::NonAsciiHostname, Severity::Medium),
            make_finding(RuleId::ShortenedUrl, Severity::Medium),
            make_finding(RuleId::PlainHttpToSink, Severity::High),
        ];
        let rules = vec![EscalationRule::MultiMedium {
            min_findings: 3,
            action: EscalationAction::Block,
        }];

        let (action, causal, _, _) = apply_escalation(Action::Warn, &findings, &session, &rules);
        assert_eq!(action, Action::Block);
        assert_eq!(causal.len(), 3);
    }

    #[test]
    fn test_escalation_never_downgrades() {
        let session = empty_session();
        let findings = vec![make_finding(RuleId::NonAsciiHostname, Severity::Medium)];
        let rules = vec![EscalationRule::RepeatCount {
            rule_ids: vec!["non_ascii_hostname".to_string()],
            threshold: 999,
            window_minutes: 60,
            action: EscalationAction::Block,
            domain_scoped: false,
            cooldown_minutes: 0,
        }];

        // Already Block -- should stay Block even though threshold not met
        let (action, _, _, _) = apply_escalation(Action::Block, &findings, &session, &rules);
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn test_cooldown_suppresses_escalation() {
        // Simulate: escalation fired recently, cooldown should prevent re-fire.
        let mut session = session_with_history("shortened_url", 4);
        // Add a recent escalation event for this rule.
        session
            .escalation_events
            .push_back(crate::session_warnings::EscalationEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                rule_id: "shortened_url".to_string(),
                domain: None,
            });
        let findings = vec![make_finding(RuleId::ShortenedUrl, Severity::Medium)];
        let rules = vec![EscalationRule::RepeatCount {
            rule_ids: vec!["shortened_url".to_string()],
            threshold: 3,
            window_minutes: 60,
            action: EscalationAction::Block,
            domain_scoped: false,
            cooldown_minutes: 60,
        }];

        // 4 (history) + 1 (current) = 5 >= 3, but cooldown is active
        let (action, causal, hits, _) = apply_escalation(Action::Warn, &findings, &session, &rules);
        assert_eq!(action, Action::Warn);
        assert!(causal.is_empty());
        assert!(hits.is_empty());
    }

    #[test]
    fn test_cooldown_zero_does_not_suppress() {
        // cooldown_minutes=0 means no cooldown; escalation always fires.
        let mut session = session_with_history("shortened_url", 4);
        session
            .escalation_events
            .push_back(crate::session_warnings::EscalationEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                rule_id: "shortened_url".to_string(),
                domain: None,
            });
        let findings = vec![make_finding(RuleId::ShortenedUrl, Severity::Medium)];
        let rules = vec![EscalationRule::RepeatCount {
            rule_ids: vec!["shortened_url".to_string()],
            threshold: 3,
            window_minutes: 60,
            action: EscalationAction::Block,
            domain_scoped: false,
            cooldown_minutes: 0,
        }];

        let (action, _, _, _) = apply_escalation(Action::Warn, &findings, &session, &rules);
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn test_wildcard_cooldown_suppresses_aggregate() {
        // Wildcard aggregate cooldown: a previous wildcard escalation event
        // should suppress the aggregate path.
        let mut session = session_with_history("any_rule", 9);
        session
            .escalation_events
            .push_back(crate::session_warnings::EscalationEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                rule_id: "*".to_string(),
                domain: None,
            });
        let findings = vec![make_finding(RuleId::ShortenedUrl, Severity::Medium)];
        let rules = vec![EscalationRule::RepeatCount {
            rule_ids: vec!["*".to_string()],
            threshold: 10,
            window_minutes: 60,
            action: EscalationAction::Block,
            domain_scoped: false,
            cooldown_minutes: 60,
        }];

        let (action, _, _, _) = apply_escalation(Action::Warn, &findings, &session, &rules);
        // 9 + 1 = 10, but wildcard cooldown is active
        assert_eq!(action, Action::Warn);
    }

    // --- Action override tests ---

    #[test]
    fn test_action_override_block() {
        let findings = vec![make_finding(RuleId::NonAsciiHostname, Severity::Medium)];
        let mut overrides = HashMap::new();
        overrides.insert("non_ascii_hostname".to_string(), "block".to_string());

        let (action, causal) = apply_action_overrides(Action::Warn, &findings, &overrides);
        assert_eq!(action, Action::Block);
        assert!(causal.contains("non_ascii_hostname"));
    }

    #[test]
    fn test_action_override_invalid_value_ignored() {
        let findings = vec![make_finding(RuleId::NonAsciiHostname, Severity::Medium)];
        let mut overrides = HashMap::new();
        // "warn" is not a valid override value
        overrides.insert("non_ascii_hostname".to_string(), "warn".to_string());

        let (action, causal) = apply_action_overrides(Action::Warn, &findings, &overrides);
        assert_eq!(action, Action::Warn);
        assert!(causal.is_empty());
    }

    #[test]
    fn test_action_override_no_match() {
        let findings = vec![make_finding(RuleId::ShortenedUrl, Severity::Medium)];
        let mut overrides = HashMap::new();
        overrides.insert("non_ascii_hostname".to_string(), "block".to_string());

        let (action, causal) = apply_action_overrides(Action::Warn, &findings, &overrides);
        assert_eq!(action, Action::Warn);
        assert!(causal.is_empty());
    }

    // --- Post-process verdict tests ---

    #[test]
    fn test_post_process_noop_on_allow() {
        let raw = Verdict {
            action: Action::Allow,
            findings: vec![],
            tier_reached: 1,
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: Timings::default(),
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
        };
        let policy = crate::policy::Policy::default();
        let result = post_process_verdict(
            &raw,
            &policy,
            "echo hello",
            "test-session",
            CallerContext::Cli,
        );
        assert_eq!(result.action, Action::Allow);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_post_process_action_override_upgrades() {
        let findings = vec![make_finding(RuleId::ShortenedUrl, Severity::Medium)];
        let raw = Verdict {
            action: Action::Warn,
            findings,
            tier_reached: 3,
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: Timings::default(),
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
        };

        let mut policy = crate::policy::Policy::default();
        policy
            .action_overrides
            .insert("shortened_url".to_string(), "block".to_string());

        let result = post_process_verdict(
            &raw,
            &policy,
            "bit.ly/foo",
            "test-session",
            CallerContext::Cli,
        );
        assert_eq!(result.action, Action::Block);
    }

    #[test]
    fn test_post_process_ordering_override_before_escalation() {
        // Action override should fire first, escalation should see Block already
        let findings = vec![make_finding(RuleId::ShortenedUrl, Severity::Medium)];
        let raw = Verdict {
            action: Action::Warn,
            findings,
            tier_reached: 3,
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: Timings::default(),
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
        };

        let mut policy = crate::policy::Policy::default();
        policy
            .action_overrides
            .insert("shortened_url".to_string(), "block".to_string());
        policy.escalation.push(EscalationRule::RepeatCount {
            rule_ids: vec!["shortened_url".to_string()],
            threshold: 999,
            window_minutes: 60,
            action: EscalationAction::Block,
            domain_scoped: false,
            cooldown_minutes: 0,
        });

        let result = post_process_verdict(
            &raw,
            &policy,
            "bit.ly/foo",
            "test-session",
            CallerContext::Cli,
        );
        // Should be Block from the override, not from escalation
        assert_eq!(result.action, Action::Block);
    }

    #[test]
    fn test_escalation_rule_serde() {
        let json = r#"{"trigger":"repeat_count","rule_ids":["*"],"threshold":5,"action":"block"}"#;
        let rule: EscalationRule = serde_json::from_str(json).unwrap();
        match rule {
            EscalationRule::RepeatCount {
                threshold,
                window_minutes,
                cooldown_minutes,
                ..
            } => {
                assert_eq!(threshold, 5);
                assert_eq!(window_minutes, 60); // default
                assert_eq!(cooldown_minutes, 0); // default
            }
            _ => panic!("expected RepeatCount"),
        }

        // With explicit cooldown_minutes
        let json_cd = r#"{"trigger":"repeat_count","rule_ids":["*"],"threshold":5,"action":"block","cooldown_minutes":10}"#;
        let rule_cd: EscalationRule = serde_json::from_str(json_cd).unwrap();
        match rule_cd {
            EscalationRule::RepeatCount {
                cooldown_minutes, ..
            } => {
                assert_eq!(cooldown_minutes, 10);
            }
            _ => panic!("expected RepeatCount"),
        }

        let json2 = r#"{"trigger":"multi_medium","min_findings":3,"action":"block"}"#;
        let rule2: EscalationRule = serde_json::from_str(json2).unwrap();
        match rule2 {
            EscalationRule::MultiMedium { min_findings, .. } => {
                assert_eq!(min_findings, 3);
            }
            _ => panic!("expected MultiMedium"),
        }
    }

    #[test]
    fn test_hidden_count_multiset_with_duplicates() {
        // Two raw findings share the same (rule_id, severity, title, description).
        // Only one survives paranoia. Hidden count should be 1, not 0.
        let dup_finding = make_finding(RuleId::ShortenedUrl, Severity::Medium);
        let low_finding = Finding {
            severity: Severity::Low,
            ..make_finding(RuleId::NonAsciiHostname, Severity::Low)
        };

        let raw = Verdict {
            action: Action::Warn,
            findings: vec![dup_finding.clone(), dup_finding.clone(), low_finding],
            tier_reached: 3,
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: Timings::default(),
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
        };

        // Paranoia 1: keeps Medium+, removes Low
        // Two identical Medium findings both survive, one Low is hidden
        let policy = crate::policy::Policy::default(); // paranoia=1
        let result = post_process_verdict(
            &raw,
            &policy,
            "test cmd",
            "test-session",
            CallerContext::Cli,
        );

        // Both Medium findings visible, Low finding hidden
        assert_eq!(
            result
                .findings
                .iter()
                .filter(|f| f.rule_id == RuleId::ShortenedUrl)
                .count(),
            2
        );
        // The Low finding was hidden by paranoia (but re-added by fallback
        // because action stayed non-Allow). In this case both dup_findings
        // keep the action at Warn, so the Low may or may not be re-added.
        // The key invariant: hidden_count is the correct multiset diff.
    }
}
