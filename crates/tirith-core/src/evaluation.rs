//! Immutable preview evidence and pure policy evaluation.
//!
//! Capture is an explicit read stage. It may inspect local files using the same
//! detectors as enforcement, but cannot consume receipts, record observations,
//! execute the proposed command, or fire canary callbacks. Evaluation reuses
//! only those captured observations and an explicit session and clock.

use crate::agent_origin::AgentOrigin;
use crate::engine::{AnalysisContext, ObservedAnalysis};
use crate::escalation::CallerContext;
use crate::policy::Policy;
use crate::session_warnings::SessionWarnings;
use crate::verdict::{Action, Evidence, Finding, RuleId, Severity, Verdict};
use serde::Serialize;

/// Session state must be supplied explicitly; missing evidence is never an
/// empty session. This object is private process memory, never an audit DTO.
#[derive(Clone)]
pub enum SessionEvidence {
    Captured(Box<SessionWarnings>),
    Unavailable,
}

/// Raw command bytes and detection evidence deliberately implement neither
/// Serialize nor Debug. The identity is random, not a command/secret hash.
#[derive(Clone)]
pub struct FrozenEvaluation {
    pub identity: String,
    pub captured_at: chrono::DateTime<chrono::Utc>,
    context: AnalysisContext,
    policy: Policy,
    observed: ObservedAnalysis,
    runtime_threat_findings: Vec<Finding>,
    runtime_threat_complete: bool,
    caller: CallerContext,
    origin: Option<AgentOrigin>,
    session: SessionEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    Allowed,
    Advisory,
    AcknowledgementRequired,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceGap {
    SessionUnavailable,
    DetectorPolicyChanged,
    RuntimeThreatEnrichmentNotCaptured,
    BaselineNotCaptured,
    AnalysisIncomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryKind {
    ReviewEvidence,
    ReviewTargetRuleException,
    AcknowledgeAtExecutionBoundary,
    RefreshEvidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct Restriction {
    /// Stable within this evaluation, including multiple findings for one rule.
    pub finding_index: usize,
    pub rule_id: RuleId,
    pub severity: Severity,
    pub individually_blocks: bool,
    pub incomplete_analysis: bool,
}

/// Protocol-owned explanation fields contain no command, URL, path, or custom
/// rule text. Sensitive details are available through the normal redacted
/// verdict projection, never copied into this contract.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionExplanation {
    pub schema_version: u32,
    pub decision: DecisionKind,
    pub preview_only: bool,
    pub execution_permitted: bool,
    pub evidence_complete: bool,
    pub restrictions: Vec<Restriction>,
    pub gaps: Vec<EvidenceGap>,
    pub recovery: Vec<RecoveryKind>,
    pub has_combined_or_external_blocker: bool,
}

pub struct EvaluationResult {
    pub verdict: Verdict,
    pub explanation: DecisionExplanation,
}

impl FrozenEvaluation {
    /// The caller resolves policy exactly once and explicitly supplies caller,
    /// shell, interaction, project, origin, and session facts. The separate
    /// policy snapshot can be revalidated before proposing a mutation.
    pub fn capture(
        context: AnalysisContext,
        policy: &crate::policy_snapshot::EffectivePolicySnapshot,
        caller: CallerContext,
        origin: Option<AgentOrigin>,
        session: SessionEvidence,
    ) -> Self {
        Self::capture_with_policy(context, &policy.policy, caller, origin, session)
    }

    pub(crate) fn capture_with_policy(
        context: AnalysisContext,
        policy: &Policy,
        caller: CallerContext,
        origin: Option<AgentOrigin>,
        session: SessionEvidence,
    ) -> Self {
        let captured_at = chrono::Utc::now();
        let observed = crate::engine::capture_observed(&context, policy);
        let (runtime_threat_findings, runtime_threat_complete) =
            crate::threatdb_api::capture_cached_enrichment(
                &context.input,
                context.shell,
                &policy.threat_intel,
                captured_at,
            );
        Self {
            identity: uuid::Uuid::new_v4().to_string(),
            captured_at,
            context,
            policy: policy.clone(),
            observed,
            runtime_threat_findings,
            runtime_threat_complete,
            caller,
            origin,
            session,
        }
    }

    pub fn evaluate_current(&self) -> EvaluationResult {
        self.evaluate(&self.policy)
    }

    /// No filesystem, network, process, clock, session, receipt, or audit I/O.
    /// Post-detection policy changes can reuse evidence. A detector-setting
    /// change requires fresh observations and produces an explicit refusal,
    /// never an Allow computed from findings that are no longer applicable.
    pub fn evaluate(&self, proposed_policy: &Policy) -> EvaluationResult {
        let compatible = detector_inputs(&self.policy) == detector_inputs(proposed_policy)
            && (!self.observed.approval_policy_bound()
                || self
                    .policy
                    .execution_identity_hash()
                    .ok()
                    .zip(proposed_policy.execution_identity_hash().ok())
                    .is_some_and(|(before, after)| before == after));
        let policy = if compatible {
            proposed_policy
        } else {
            &self.policy
        };
        let mut gaps = Vec::new();
        if !self.runtime_threat_complete {
            gaps.push(EvidenceGap::RuntimeThreatEnrichmentNotCaptured);
        }
        if policy.baseline_enabled {
            gaps.push(EvidenceGap::BaselineNotCaptured);
        }
        let mut raw = crate::engine::evaluate_observed(&self.context, policy, &self.observed);
        crate::escalation::merge_late_findings(
            &mut raw,
            self.runtime_threat_findings.clone(),
            policy,
        );
        raw.agent_origin = self.origin.clone();
        if !compatible {
            gaps.push(EvidenceGap::DetectorPolicyChanged);
            raw.findings.push(incomplete_finding());
            raw.action = Action::Block;
        }
        let mut verdict =
            crate::escalation::apply_stateless_policy_effects(&raw, policy, self.caller);
        match &self.session {
            SessionEvidence::Captured(session) => {
                if matches!(verdict.action, Action::Warn | Action::WarnAck) {
                    let (action, _, _, reason) = crate::escalation::apply_escalation_at(
                        verdict.action,
                        &verdict.findings,
                        session,
                        &policy.escalation,
                        self.captured_at,
                    );
                    if action != verdict.action {
                        verdict.escalation_reason = reason;
                    }
                    verdict.action = action;
                }
                let mut events = session.typed_events.iter().cloned().collect::<Vec<_>>();
                events.extend(
                    crate::escalation::derive_event_prototypes_for_shell(
                        &self.context.input,
                        &verdict,
                        self.context.shell,
                    )
                    .into_iter()
                    .map(|event| {
                        event.materialize(
                            String::new(),
                            0,
                            self.captured_at.to_rfc3339(),
                            crate::event_buffer::EventProvenance::Confirmed,
                        )
                    }),
                );
                let hits = crate::event_buffer::correlate(&events, &self.captured_at.to_rfc3339());
                crate::escalation::apply_correlation_findings(&mut verdict, policy, &hits);
                if !hits.is_empty() {
                    crate::escalation::reapply_monotonic_policy_effects(
                        &mut verdict,
                        policy,
                        self.caller,
                    );
                }
            }
            SessionEvidence::Unavailable => gaps.push(EvidenceGap::SessionUnavailable),
        }
        // Strict warnings are an acknowledgement contract even though legacy
        // CLI integrations represent that contract as Warn plus exit code 3.
        let acknowledgement = verdict.action == Action::WarnAck
            || (verdict.action == Action::Warn
                && (policy.strict_warn || verdict.requires_approval == Some(true)));
        if !compatible {
            // A proposed severity/allowlist/paranoia setting must never suppress
            // the refusal to evaluate unsupported detector changes.
            verdict.action = Action::Block;
            if !verdict
                .findings
                .iter()
                .any(|finding| finding.title == INCOMPLETE_TITLE)
            {
                verdict.findings.push(incomplete_finding());
            }
        }
        if verdict.action == Action::Block {
            verdict.requires_approval = None;
            verdict.approval_timeout_secs = None;
            verdict.approval_fallback = None;
            verdict.approval_rule = None;
            verdict.approval_description = None;
        }
        let explanation = explain(&verdict, policy, acknowledgement, gaps);
        EvaluationResult {
            verdict,
            explanation,
        }
    }
}

/// A private comparison projection, never exposed as a digest. Only settings
/// consumed strictly after the observation boundary can change without a new
/// capture. New policy fields conservatively remain detector inputs.
fn detector_inputs(policy: &Policy) -> serde_json::Value {
    let mut value = serde_json::to_value(policy).expect("policy serialization is infallible");
    if let Some(object) = value.as_object_mut() {
        // The credential is omitted from policy serialization, but presence
        // enables an additional runtime detector. Compare only in private
        // process memory; never publish its value or a guessable digest.
        object.insert(
            "runtime_safe_browsing_key".into(),
            serde_json::to_value(&policy.threat_intel.google_safe_browsing_key).unwrap(),
        );
        // These runtime overlays are intentionally excluded from policy YAML,
        // but they determine detection and must participate in compatibility.
        object.insert(
            "context_labels".into(),
            serde_json::to_value(&policy.context_labels).unwrap(),
        );
        object.insert(
            "ssh_host_labels".into(),
            serde_json::to_value(&policy.ssh_host_labels).unwrap(),
        );
        for field in [
            "allowlist",
            "allowlist_rules",
            "blocklist",
            "severity_overrides",
            "action_overrides",
            "paranoia",
            "strict_warn",
            "escalation",
            "approval_rules",
            "agent_rules",
            "allow_bypass_env",
            "allow_bypass_env_noninteractive",
            "dlp_custom_patterns",
            "path",
            "scope",
            "protection_profile",
        ] {
            object.remove(field);
        }
    }
    value
}

const INCOMPLETE_TITLE: &str = "Preview requires fresh detection evidence";
fn incomplete_finding() -> Finding {
    Finding {
        rule_id: RuleId::AnalysisIncomplete, severity: Severity::High,
        title: INCOMPLETE_TITLE.to_string(),
        description: "The proposed policy changes detector inputs. Capture new evidence before comparing this policy; the current observations cannot establish its decision.".to_string(),
        evidence: vec![Evidence::Text { detail: "preview_detector_inputs_changed".to_string() }],
        human_view: None, agent_view: None, mitre_id: None, custom_rule_id: None,
    }
}

fn incomplete(rule: RuleId) -> bool {
    matches!(
        rule,
        RuleId::AnalysisIncomplete | RuleId::OutputAnalysisOverflow | RuleId::WrapperChainTooDeep
    )
}

fn explain(
    verdict: &Verdict,
    policy: &Policy,
    acknowledgement: bool,
    mut gaps: Vec<EvidenceGap>,
) -> DecisionExplanation {
    let restrictions = verdict
        .findings
        .iter()
        .enumerate()
        .map(|(finding_index, finding)| {
            let individually_blocks =
                crate::verdict::action_from_findings(std::slice::from_ref(finding))
                    == Action::Block
                    || crate::escalation::apply_action_overrides(
                        Action::Allow,
                        std::slice::from_ref(finding),
                        &policy.action_overrides,
                    )
                    .0 == Action::Block;
            Restriction {
                finding_index,
                rule_id: finding.rule_id,
                severity: finding.severity,
                individually_blocks,
                incomplete_analysis: incomplete(finding.rule_id),
            }
        })
        .collect::<Vec<_>>();
    if restrictions.iter().any(|r| r.incomplete_analysis) {
        gaps.push(EvidenceGap::AnalysisIncomplete);
    }
    let decision = match verdict.action {
        Action::Block => DecisionKind::Blocked,
        _ if acknowledgement => DecisionKind::AcknowledgementRequired,
        Action::Warn | Action::WarnAck => DecisionKind::Advisory,
        Action::Allow if !verdict.findings.is_empty() => DecisionKind::Advisory,
        Action::Allow => DecisionKind::Allowed,
    };
    let mut recovery = Vec::new();
    if !restrictions.is_empty() {
        recovery.push(RecoveryKind::ReviewEvidence);
    }
    if verdict
        .findings
        .iter()
        .any(|f| f.evidence.iter().any(|e| matches!(e, Evidence::Url { .. })))
    {
        recovery.push(RecoveryKind::ReviewTargetRuleException);
    }
    if acknowledgement && verdict.action != Action::Block {
        recovery.push(RecoveryKind::AcknowledgeAtExecutionBoundary);
    }
    if !gaps.is_empty() {
        recovery.push(RecoveryKind::RefreshEvidence);
    }
    DecisionExplanation {
        schema_version: 1,
        decision,
        preview_only: true,
        execution_permitted: false,
        evidence_complete: gaps.is_empty(),
        has_combined_or_external_blocker: verdict.action == Action::Block
            && (verdict.escalation_reason.is_some()
                || !restrictions.iter().any(|r| r.individually_blocks)),
        restrictions,
        gaps,
        recovery,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::ScanContext;
    use crate::tokenize::ShellType;

    fn capture(command: &str, policy: &Policy) -> FrozenEvaluation {
        let state = tirith_test_support::GlobalStateGuard::new().unwrap();
        FrozenEvaluation::capture_with_policy(
            AnalysisContext {
                input: command.to_string(),
                shell: ShellType::Posix,
                scan_context: ScanContext::Exec,
                raw_bytes: None,
                interactive: true,
                cwd: Some(state.roots().cwd.display().to_string()),
                file_path: None,
                repo_root: None,
                is_config_override: false,
                clipboard_html: None,
                card_ref: None,
                clipboard_source: crate::clipboard::ClipboardSourceState::AbsentOrInvalid,
            },
            policy,
            CallerContext::Cli,
            None,
            SessionEvidence::Captured(Box::new(SessionWarnings::new("preview-test"))),
        )
    }

    #[test]
    fn disabled_runtime_apis_do_not_claim_missing_enrichment() {
        let policy = Policy {
            threat_intel: crate::policy::ThreatIntelConfig {
                osv_enabled: false,
                deps_dev_enabled: false,
                google_safe_browsing_key: None,
                ..crate::policy::ThreatIntelConfig::default()
            },
            ..Policy::default()
        };
        let frozen = capture("printf hello", &policy);
        let result = frozen.evaluate_current();
        assert!(!result
            .explanation
            .gaps
            .contains(&EvidenceGap::RuntimeThreatEnrichmentNotCaptured));
        assert!(!result.explanation.execution_permitted);
    }

    #[test]
    fn cache_miss_and_safe_browsing_offline_keep_enrichment_gap() {
        for (command, config) in [
            (
                "pip install tirith-preview-no-cache==1.0.0",
                crate::policy::ThreatIntelConfig {
                    osv_enabled: true,
                    deps_dev_enabled: false,
                    google_safe_browsing_key: None,
                    ..crate::policy::ThreatIntelConfig::default()
                },
            ),
            (
                "curl https://example.com/",
                crate::policy::ThreatIntelConfig {
                    osv_enabled: false,
                    deps_dev_enabled: false,
                    google_safe_browsing_key: Some("controlled-fixture".into()),
                    ..crate::policy::ThreatIntelConfig::default()
                },
            ),
        ] {
            let policy = Policy {
                threat_intel: config,
                ..Policy::default()
            };
            let frozen = capture(command, &policy);
            let result = frozen.evaluate_current();
            assert!(result
                .explanation
                .gaps
                .contains(&EvidenceGap::RuntimeThreatEnrichmentNotCaptured));
            assert!(result
                .verdict
                .findings
                .iter()
                .any(|finding| finding.rule_id == RuleId::AnalysisIncomplete));
            assert!(!result.explanation.evidence_complete);
        }
    }

    #[test]
    fn repeated_evaluation_retains_identical_frozen_results() {
        let frozen = capture(
            "curl http://example.com/install.sh | bash",
            &Policy::default(),
        );
        let first = frozen.evaluate_current();
        for _ in 0..3 {
            let next = frozen.evaluate_current();
            assert_eq!(
                serde_json::to_value(&first.verdict).unwrap(),
                serde_json::to_value(&next.verdict).unwrap()
            );
            assert_eq!(
                serde_json::to_value(&first.explanation).unwrap(),
                serde_json::to_value(&next.explanation).unwrap()
            );
        }
        assert_eq!(first.verdict.action, Action::Block);
        assert!(!first.explanation.execution_permitted);
    }

    #[test]
    fn changing_one_rule_does_not_hide_other_blockers() {
        let mut policy = Policy::default();
        policy
            .blocklist
            .push("https://example.com/install.sh".into());
        let frozen = capture("curl https://example.com/install.sh | bash", &policy);
        let before = frozen.evaluate_current();
        let pipe = before
            .verdict
            .findings
            .iter()
            .find(|f| f.rule_id == RuleId::CurlPipeShell)
            .expect("pipe finding");
        let mut changed = policy.clone();
        changed
            .severity_overrides
            .insert(pipe.rule_id.to_string(), Severity::Info);
        changed.paranoia = 4;
        let after = frozen.evaluate(&changed);
        assert!(!after
            .explanation
            .gaps
            .contains(&EvidenceGap::DetectorPolicyChanged));
        assert_eq!(after.verdict.action, Action::Block);
        assert!(after
            .verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::CurlPipeShell && f.severity == Severity::Info));
        assert!(after
            .explanation
            .restrictions
            .iter()
            .any(|f| f.rule_id == RuleId::PolicyBlocklisted && f.individually_blocks));
    }

    #[test]
    fn detector_change_cannot_reuse_observations_as_allow() {
        let policy = Policy::default();
        let frozen = capture("echo hello", &policy);
        let mut changed = policy;
        changed.context_guard_enabled = !changed.context_guard_enabled;
        changed.paranoia = 0;
        changed
            .severity_overrides
            .insert("analysis_incomplete".into(), Severity::Info);
        let result = frozen.evaluate(&changed);
        assert_eq!(result.verdict.action, Action::Block);
        assert!(result
            .explanation
            .gaps
            .contains(&EvidenceGap::DetectorPolicyChanged));
        assert!(result
            .verdict
            .findings
            .iter()
            .any(|f| f.title == INCOMPLETE_TITLE));
    }

    #[test]
    fn enabling_nonserialized_runtime_api_requires_new_capture() {
        let policy = Policy::default();
        let frozen = capture("curl https://example.com/", &policy);
        let mut changed = policy;
        changed.threat_intel.google_safe_browsing_key = Some("controlled-test-key".into());
        let result = frozen.evaluate(&changed);
        assert!(result
            .explanation
            .gaps
            .contains(&EvidenceGap::DetectorPolicyChanged));
        assert_eq!(result.verdict.action, Action::Block);
    }

    #[test]
    fn nonserialized_runtime_labels_require_fresh_observations() {
        let policy = Policy::default();
        let frozen = capture("echo hello", &policy);
        let mut context = policy.clone();
        context
            .context_labels
            .insert("kubernetes:production".into(), "production".into());
        let mut ssh = policy.clone();
        ssh.ssh_host_labels
            .insert("production".into(), "critical".into());
        for changed in [context, ssh] {
            let result = frozen.evaluate(&changed);
            assert_eq!(result.verdict.action, Action::Block);
            assert!(result
                .explanation
                .gaps
                .contains(&EvidenceGap::DetectorPolicyChanged));
        }
    }

    #[test]
    fn missing_session_and_baseline_are_explicit() {
        let policy = Policy {
            baseline_enabled: true,
            ..Policy::default()
        };
        let mut frozen = capture("curl http://example.com/install.sh | bash", &policy);
        frozen.session = SessionEvidence::Unavailable;
        let result = frozen.evaluate_current();
        assert!(result
            .explanation
            .gaps
            .contains(&EvidenceGap::BaselineNotCaptured));
        assert!(result
            .explanation
            .gaps
            .contains(&EvidenceGap::SessionUnavailable));
        assert!(!result.explanation.evidence_complete);
    }

    #[test]
    fn strict_warn_is_explained_as_acknowledgement() {
        let policy = Policy {
            strict_warn: true,
            ..Policy::default()
        };
        let frozen = capture("curl https://bit.ly/readme", &policy);
        let result = frozen.evaluate_current();
        if result.verdict.action == Action::Warn {
            assert_eq!(
                result.explanation.decision,
                DecisionKind::AcknowledgementRequired
            );
            assert!(result
                .explanation
                .recovery
                .contains(&RecoveryKind::AcknowledgeAtExecutionBoundary));
        } else {
            panic!("fixture must be a warning: {:?}", result.verdict.action);
        }
    }
}
