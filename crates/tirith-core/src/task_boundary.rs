//! Enforcement of the task decision at Tirith-OWNED irreversible transitions
//! (C12).
//!
//! C08 built the decision ([`crate::task::decide`]) and C07 built the policy
//! vocabulary ([`TaskGatePolicy`]). This module invents no new analysis. It is
//! the one adapter every owned boundary calls immediately before the step it
//! cannot take back:
//!
//! 1. the MCP gateway's upstream forward, before pending registration;
//! 2. `tirith pkg approve` / `tirith pkg install`, before resolver network;
//! 3. `tirith pkg install` again, before install preparation;
//! 4. `tirith install <manager>`, before registry network and before spawn;
//! 5. `tirith run <url>` and `tirith install url <URL>`, before download and
//!    launch;
//! 6. a Tirith-owned config write, before the final atomic rename.
//!
//! Four properties govern everything here.
//!
//! **Enforcement keys on the mode, never on the denial set.**
//! [`crate::task::decide`] populates `denied_effects` in EVERY mode, including
//! [`TaskGateMode::Off`], because reporting what WOULD be refused is the whole
//! point of the observing modes. Keying a refusal on "something was denied"
//! would turn the default-off gate into live enforcement for any operator who
//! filled in the effect sets without ever choosing a mode. Only
//! [`TaskGateMode::Enforce`] refuses.
//!
//! **Observe mode records and nothing else.** It must not raise a verdict's
//! action to `Warn` to "note" a task denial: the gateway converts `Warn` into a
//! hard deny whenever `warn_action` is `deny`, which is its default, so a
//! recording implemented that way would silently become enforcement.
//! [`BoundaryAssessment::refusal`] therefore returns `None` in every non-enforce
//! mode, whatever the decision says.
//!
//! **The boundary evaluates before the side effect, or it is not a boundary.**
//! Each call site is placed upstream of its own irreversible step and the deny
//! path returns without taking it.
//!
//! **The default ships inert.** [`TaskGatePolicy::mode`] defaults to
//! [`TaskGateMode::Off`], so an installation that never writes a `task_gate`
//! section behaves exactly as it did before this slice.
//!
//! # The incomplete-analysis trap an operator must know about
//!
//! [`crate::task::infer_effects_detailed`] models the Web3 shell grammar and
//! nothing else, and it reports completeness per top-level segment. Any shell
//! line the Web3 grammar does not model, which is nearly every ordinary
//! command, is therefore reported INCOMPLETE. That is deliberate honesty about
//! coverage, but it has a sharp consequence at an enforcing boundary:
//!
//! ```yaml
//! task_gate:
//!   mode: enforce
//!   action_incomplete_analysis: block
//! ```
//!
//! refuses essentially every guarded gateway call, because essentially every
//! guarded command is incompletely modelled. `block` here means "refuse what I
//! do not understand", and today Tirith does not understand general shell. An
//! operator who wants enforcement over the effects Tirith DOES derive should
//! leave `action_incomplete_analysis` at its `warn` default and populate
//! `effects_denied_for_untrusted_sources` instead. The behaviour is pinned by
//! `incomplete_shell_analysis_blocks_when_the_operator_asks_it_to` in
//! `crates/tirith-core/tests/task_boundary.rs`.
//!
//! # What this does not cover
//!
//! Only Tirith-owned transitions. A shell the operator types into directly, an
//! MCP client that does not route through the gateway, and a program that calls
//! [`crate::runner`] as a library are all outside these chokepoints. The
//! diagnostic surfaces (`tirith task check`, the `tirith_check_task` MCP tool)
//! declare [`BoundaryCapability::ObserveOnly`] precisely so that the difference
//! is structural rather than a claim in prose.

use std::collections::BTreeSet;

use crate::effects::{BoundaryCapability, CommandEffectKind};
use crate::task::{
    assign_provenance, decide_with_boundary_effects, decision_projection, validate_envelope,
    EnvelopeRejection, IngressAdapter, ProposedAction, TaskDecision, TaskEnvelopeInput,
    TaskSourceInput,
};
use crate::web3_policy::{TaskGateMode, TaskGatePolicy, Web3GuardAction};

/// The Tirith-owned irreversible transition being guarded. The token is a
/// stable wire string, so an audit consumer can tell the boundaries apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnedBoundary {
    /// The MCP gateway is about to register a pending request and write the
    /// call upstream.
    GatewayForward,
    /// `tirith pkg approve` is about to run the resolver: PATH lookup,
    /// quarantine creation, DNS, and artifact download.
    PackageApproval,
    /// `tirith pkg install` is about to run the same resolver network.
    PackageResolve,
    /// `tirith pkg install` is about to checkpoint the target environment and
    /// prepare the contained install.
    PackageInstallPreparation,
    /// `tirith install <manager>` is about to contact a registry.
    PackageManagerNetwork,
    /// `tirith install <manager>` is about to spawn the package manager.
    PackageManagerExecution,
    /// `tirith run <url>` or `tirith install url <URL>` is about to download
    /// and launch a remote script. One token for both, because they are one
    /// transition: both end in `runner::run_with_verified_executor`.
    RemoteScriptRun,
    /// A Tirith-owned configuration file is about to be published by rename.
    ConfigWrite,
    /// `tirith capsule run --preset untrusted-project` is about to copy an
    /// untrusted project into a held ephemeral directory and launch the
    /// operator's argv inside it. Evaluated before the copy, so a refusal costs
    /// the operator nothing and leaves no copy of an attacker's repository on
    /// disk.
    CapsulePresetRun,
}

impl OwnedBoundary {
    pub fn token(self) -> &'static str {
        match self {
            Self::GatewayForward => "gateway_forward",
            Self::PackageApproval => "package_approval",
            Self::PackageResolve => "package_resolve",
            Self::PackageInstallPreparation => "package_install_preparation",
            Self::PackageManagerNetwork => "package_manager_network",
            Self::PackageManagerExecution => "package_manager_execution",
            Self::RemoteScriptRun => "remote_script_run",
            Self::ConfigWrite => "config_write",
            Self::CapsulePresetRun => "capsule_preset_run",
        }
    }
}

/// What the boundary must do before its irreversible step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundaryOutcome {
    /// Proceed. Reached in every non-enforce mode, and in enforce mode when
    /// nothing was denied and the analysis was good enough for the policy.
    Allow,
    /// Enforce mode, and the operator asked for a human decision on this
    /// class. A boundary with no approval channel treats this as a refusal.
    RequireApproval { reason: String },
    /// Enforce mode, and the operation is refused.
    Deny { reason: String },
}

/// One boundary evaluation: the decision, why it landed where it did, and the
/// projection an audit line renders from.
#[derive(Debug, Clone)]
pub struct BoundaryAssessment {
    pub boundary: OwnedBoundary,
    pub outcome: BoundaryOutcome,
    pub decision: TaskDecision,
    pub rejections: Vec<EnvelopeRejection>,
}

impl BoundaryAssessment {
    /// The reason this operation must not proceed, or `None` to continue.
    ///
    /// `approval_already_crossed` is the call site's own honest statement that a
    /// human authorised THIS operation through an existing gate (a matching
    /// `tirith pkg approve` record, or an explicit unattended flag). Only a
    /// boundary that really has such a gate may pass `true`; every other site
    /// passes `false` and a required approval becomes a refusal, because a gate
    /// that cannot ask is a gate that must say no.
    pub fn refusal(&self, approval_already_crossed: bool) -> Option<&str> {
        match &self.outcome {
            BoundaryOutcome::Allow => None,
            BoundaryOutcome::Deny { reason } => Some(reason),
            BoundaryOutcome::RequireApproval { reason } => {
                if approval_already_crossed {
                    None
                } else {
                    Some(reason)
                }
            }
        }
    }

    /// Whether this assessment refuses regardless of any approval evidence.
    pub fn is_denied(&self) -> bool {
        matches!(self.outcome, BoundaryOutcome::Deny { .. })
    }

    /// The denied effects a caller may ACT on, which is the empty set in every
    /// mode but [`TaskGateMode::Enforce`].
    ///
    /// `decision.denied_effects` is the full report and is populated even when
    /// the gate is off, so acting on it directly would tighten a capsule, or
    /// trip a downstream assertion, on an installation that never switched the
    /// gate on. Anything that CHANGES behaviour reads this instead.
    pub fn enforced_denied_effects(&self) -> BTreeSet<CommandEffectKind> {
        if self.decision.mode == TaskGateMode::Enforce {
            self.decision.denied_effects.clone()
        } else {
            BTreeSet::new()
        }
    }

    /// Whether this decision should be recorded at all.
    ///
    /// An observing gate exists to be recorded; an off gate is inert, and a
    /// per-call audit line it never asked for is not inertness.
    pub fn is_recordable(&self) -> bool {
        self.decision.mode != TaskGateMode::Off
    }

    /// The audit projection. Built on top of the shared
    /// [`decision_projection`] so a boundary line and a `tirith task check` line
    /// describe the same assessment in the same words, with the boundary's own
    /// three extra fields on top.
    ///
    /// `diagnostic` is overwritten to `false`: unlike the CLI and MCP surfaces,
    /// this evaluation can actually stop something.
    pub fn projection(&self) -> serde_json::Value {
        let mut value = decision_projection(&self.decision, &self.rejections);
        if let Some(object) = value.as_object_mut() {
            object.insert("diagnostic".to_string(), serde_json::Value::Bool(false));
            object.insert(
                "boundary".to_string(),
                serde_json::Value::String(self.boundary.token().to_string()),
            );
            object.insert(
                "outcome".to_string(),
                serde_json::Value::String(outcome_token(&self.outcome).to_string()),
            );
            object.insert(
                "outcome_reason".to_string(),
                match &self.outcome {
                    BoundaryOutcome::Allow => serde_json::Value::Null,
                    BoundaryOutcome::Deny { reason }
                    | BoundaryOutcome::RequireApproval { reason } => {
                        serde_json::Value::String(reason.clone())
                    }
                },
            );
        }
        value
    }
}

fn outcome_token(outcome: &BoundaryOutcome) -> &'static str {
    match outcome {
        BoundaryOutcome::Allow => "allow",
        BoundaryOutcome::RequireApproval { .. } => "require_approval",
        BoundaryOutcome::Deny { .. } => "deny",
    }
}

/// The operation an owned boundary is about to perform.
///
/// `boundary_effects` is what the TRANSITION knows about itself, independent of
/// what the envelope's grammar could derive: a package manager run is a package
/// install and network egress whether or not the argv parses. It can only widen
/// the inferred set; the policy filter still runs over the union.
pub struct BoundaryOperation<'a> {
    pub boundary: OwnedBoundary,
    pub envelope: &'a TaskEnvelopeInput,
    pub adapter: IngressAdapter,
    pub boundary_effects: BTreeSet<CommandEffectKind>,
}

/// Evaluate one owned transition.
///
/// Deterministic and side-effect-free: no file is opened, no host is contacted,
/// nothing is recorded. The caller owns the audit write and the refusal.
pub fn evaluate(operation: &BoundaryOperation<'_>, gate: &TaskGatePolicy) -> BoundaryAssessment {
    let rejections = validate_envelope(operation.envelope);
    let provenance = operation
        .envelope
        .sources
        .iter()
        .map(|source| assign_provenance(source, operation.adapter, None, None))
        .collect::<Vec<_>>();

    // `Enforceable` is the honest value here and only here: these sites hold
    // the transition open and can still refuse it.
    let decision = decide_with_boundary_effects(
        operation.envelope,
        provenance,
        gate,
        BoundaryCapability::Enforceable,
        &operation.boundary_effects,
    );

    let outcome = outcome_for(&decision, gate);
    BoundaryAssessment {
        boundary: operation.boundary,
        outcome,
        decision,
        rejections,
    }
}

/// Map a decision onto what the boundary does.
///
/// Off and Observe both allow. That is the "observe mode has no hidden
/// enforcement" property: a recorded denial in Observe changes nothing a caller
/// can act on, so no downstream `warn_action` can promote it.
fn outcome_for(decision: &TaskDecision, gate: &TaskGatePolicy) -> BoundaryOutcome {
    if gate.mode != TaskGateMode::Enforce {
        return BoundaryOutcome::Allow;
    }

    // A known denial is more specific than "we could not tell", so it is
    // reported first and is also the stricter of the two.
    if !decision.denied_effects.is_empty() {
        let effects = decision
            .denied_effects
            .iter()
            .map(|effect| effect_token(*effect))
            .collect::<Vec<_>>()
            .join(", ");
        return BoundaryOutcome::Deny {
            reason: format!("task gate denied these effects at this boundary: {effects}"),
        };
    }

    if !decision.complete {
        // `decide` deliberately does NOT apply this action, because the same
        // decision is rendered by observe-only surfaces that must not turn an
        // admission of incomplete coverage into a refusal.
        let reason = "task analysis is incomplete at this boundary; the shell grammar Tirith \
                      models does not account for every segment of this operation"
            .to_string();
        return match gate.action_incomplete_analysis {
            Web3GuardAction::Allow | Web3GuardAction::Warn => BoundaryOutcome::Allow,
            Web3GuardAction::RequireApproval => BoundaryOutcome::RequireApproval { reason },
            Web3GuardAction::Block => BoundaryOutcome::Deny { reason },
        };
    }

    BoundaryOutcome::Allow
}

/// The stable wire token for an effect, matching the serde spelling the
/// projection emits.
fn effect_token(effect: CommandEffectKind) -> &'static str {
    match effect {
        CommandEffectKind::PackageInstall => "package_install",
        CommandEffectKind::PersistenceChange => "persistence_change",
        CommandEffectKind::PolicyChange => "policy_change",
        CommandEffectKind::SecretRead => "secret_read",
        CommandEffectKind::NetworkEgress => "network_egress",
        CommandEffectKind::FilesystemWrite => "filesystem_write",
        CommandEffectKind::ResourceEscalation => "resource_escalation",
        CommandEffectKind::Web3Write => "web3_write",
        CommandEffectKind::Web3SignerUse => "web3_signer_use",
    }
}

// ---------------------------------------------------------------------------
// Envelope construction from a boundary's real operation
// ---------------------------------------------------------------------------

/// The source an owned boundary attributes its operation to.
///
/// Nothing at these chokepoints identified itself: an MCP client is just a pipe,
/// and an argv is just an argv. [`IngressAdapter::Unattributed`] is the truthful
/// answer, and it collapses any claimed kind to [`crate::task::SourceKind::Unknown`].
/// The source is recorded explicitly rather than left absent so an operator
/// reading the audit sees an unattributed origin instead of a blank.
fn unattributed_source() -> TaskSourceInput {
    TaskSourceInput {
        claimed_source: crate::task::SourceKind::Unknown,
        content: String::new(),
        locator: None,
        receipt: None,
    }
}

/// An envelope for a shell command an owned boundary is about to let through.
pub fn shell_envelope(command: &str) -> TaskEnvelopeInput {
    TaskEnvelopeInput {
        task_id: None,
        sources: vec![unattributed_source()],
        actions: vec![ProposedAction::Shell {
            command: command.to_string(),
        }],
        requested_effects: BTreeSet::new(),
    }
}

/// An envelope for a package install an owned boundary is about to prepare or
/// perform. Every requested package becomes its own action, bounded by
/// [`crate::task::MAX_ACTIONS`] so a long argv cannot itself become the attack.
pub fn package_envelope(ecosystem: &str, packages: &[String]) -> TaskEnvelopeInput {
    TaskEnvelopeInput {
        task_id: None,
        sources: vec![unattributed_source()],
        actions: packages
            .iter()
            .take(crate::task::MAX_ACTIONS)
            .map(|package| ProposedAction::PackageInstall {
                ecosystem: ecosystem.to_string(),
                package: package.clone(),
            })
            .collect(),
        requested_effects: BTreeSet::new(),
    }
}

/// An envelope for a Tirith-owned configuration write.
///
/// The plan's prose names an `AgentConfigWrite` effect. No such
/// [`CommandEffectKind`] exists, and minting one would change the serde wire
/// tokens of the policy's effect sets for no gain, so the write is described by
/// the effects [`crate::task::infer_effects_detailed`] already derives for
/// [`ProposedAction::ConfigWrite`]: filesystem write, persistence change, and
/// secret read when the path is sensitive. A write that changes Tirith's own
/// policy additionally carries [`CommandEffectKind::PolicyChange`], which the
/// caller passes as a boundary effect because only the caller knows which file
/// it owns.
pub fn config_write_envelope(path: &str) -> TaskEnvelopeInput {
    TaskEnvelopeInput {
        task_id: None,
        sources: vec![unattributed_source()],
        actions: vec![ProposedAction::ConfigWrite {
            path: path.to_string(),
        }],
        requested_effects: BTreeSet::new(),
    }
}

// ---------------------------------------------------------------------------
// Capsule tightening
// ---------------------------------------------------------------------------

/// Tighten a capsule spec with what the task decision refused.
///
/// The plan asks for "capsule specs tightened with task policy budgets", but
/// [`TaskGatePolicy`] carries no budget fields and adding them would drag in the
/// repo-scope monotonicity, sanitisation, and validation machinery for a value
/// that can be derived. The denied-effect set already says everything needed:
/// a denied effect becomes a removed capability. Because
/// [`crate::capsule::CapsuleSpec::required_coverage`] is computed FROM the spec,
/// tightening the spec automatically raises what the backend must deliver, and
/// the existing shortfall check refuses a backend that cannot.
///
/// Only tightens. Every branch removes a capability; none adds one.
pub fn tighten_capsule_spec(
    spec: &mut crate::capsule::CapsuleSpec,
    denied: &BTreeSet<CommandEffectKind>,
) {
    if denied.contains(&CommandEffectKind::NetworkEgress) {
        spec.network = crate::capsule::NetworkPolicy::DenyAll;
    }
    if denied.contains(&CommandEffectKind::FilesystemWrite) {
        spec.filesystem.write_roots.clear();
    }
    if denied.contains(&CommandEffectKind::ResourceEscalation) {
        let conservative = crate::capsule::ResourceLimits::conservative();
        fn tighten<T: Ord>(current: Option<T>, ceiling: Option<T>) -> Option<T> {
            match (current, ceiling) {
                (Some(current), Some(ceiling)) => Some(current.min(ceiling)),
                (None, ceiling) => ceiling,
                (current, None) => current,
            }
        }
        spec.resources.cpu_seconds = tighten(spec.resources.cpu_seconds, conservative.cpu_seconds);
        spec.resources.memory_bytes =
            tighten(spec.resources.memory_bytes, conservative.memory_bytes);
        spec.resources.max_processes =
            tighten(spec.resources.max_processes, conservative.max_processes);
        spec.resources.max_open_files =
            tighten(spec.resources.max_open_files, conservative.max_open_files);
        spec.resources.max_output_bytes = tighten(
            spec.resources.max_output_bytes,
            conservative.max_output_bytes,
        );
        spec.resources.wall_clock_seconds = tighten(
            spec.resources.wall_clock_seconds,
            conservative.wall_clock_seconds,
        );
    }
}

/// The stable binding string an approval records for the task-gate ceiling in
/// force when it was granted.
///
/// Bound into the install plan digest so an approval taken under one ceiling
/// cannot authorise an install under a looser one: changing the mode or the
/// denied set changes this string, which changes the digest, which invalidates
/// the stored approval.
pub fn ceiling_binding(decision: &TaskDecision) -> String {
    let mode = match decision.mode {
        TaskGateMode::Off => "off",
        TaskGateMode::Observe => "observe",
        TaskGateMode::Enforce => "enforce",
    };
    let denied = decision
        .denied_effects
        .iter()
        .map(|effect| effect_token(*effect))
        .collect::<Vec<_>>()
        .join("+");
    format!("task_gate:v1:mode={mode};denied={denied}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enforcing() -> TaskGatePolicy {
        TaskGatePolicy {
            mode: TaskGateMode::Enforce,
            effects_denied_for_untrusted_sources: [CommandEffectKind::NetworkEgress]
                .into_iter()
                .collect(),
            ..TaskGatePolicy::default()
        }
    }

    fn operation<'a>(envelope: &'a TaskEnvelopeInput) -> BoundaryOperation<'a> {
        BoundaryOperation {
            boundary: OwnedBoundary::GatewayForward,
            envelope,
            adapter: IngressAdapter::Unattributed,
            boundary_effects: BTreeSet::new(),
        }
    }

    #[test]
    fn the_default_policy_allows_and_records_nothing_to_refuse() {
        let envelope = shell_envelope("cast send 0xabc --private-key 0xdead");
        let assessment = evaluate(&operation(&envelope), &TaskGatePolicy::default());
        assert_eq!(assessment.outcome, BoundaryOutcome::Allow);
        assert!(assessment.refusal(false).is_none());
    }

    #[test]
    fn boundary_effects_widen_the_inferred_set_but_never_grant() {
        let envelope = shell_envelope("echo hello");
        let mut operation = operation(&envelope);
        operation.boundary_effects = [CommandEffectKind::NetworkEgress].into_iter().collect();
        let assessment = evaluate(&operation, &enforcing());
        assert!(assessment
            .decision
            .inferred_effects
            .contains(&CommandEffectKind::NetworkEgress));
        // The policy filter still ran over the union, so the widened effect is
        // refused rather than admitted.
        assert!(assessment
            .decision
            .denied_effects
            .contains(&CommandEffectKind::NetworkEgress));
        assert!(assessment.refusal(false).is_some());
    }

    #[test]
    fn required_approval_is_a_refusal_where_no_human_gate_exists() {
        let gate = TaskGatePolicy {
            mode: TaskGateMode::Enforce,
            action_incomplete_analysis: Web3GuardAction::RequireApproval,
            ..TaskGatePolicy::default()
        };
        let envelope = shell_envelope("ls -la");
        let assessment = evaluate(&operation(&envelope), &gate);
        assert!(matches!(
            assessment.outcome,
            BoundaryOutcome::RequireApproval { .. }
        ));
        assert!(assessment.refusal(false).is_some());
        assert!(assessment.refusal(true).is_none());
        // It is not an unconditional denial, so a site with a real approval
        // gate can honour it.
        assert!(!assessment.is_denied());
    }

    #[test]
    fn the_projection_says_it_is_not_diagnostic() {
        let envelope = shell_envelope("ls");
        let assessment = evaluate(&operation(&envelope), &TaskGatePolicy::default());
        let projection = assessment.projection();
        assert_eq!(projection["diagnostic"], serde_json::Value::Bool(false));
        assert_eq!(projection["boundary"], "gateway_forward");
        assert_eq!(projection["outcome"], "allow");
    }

    #[test]
    fn tightening_only_removes_capabilities() {
        let mut spec = crate::capsule::CapsuleSpec::locked_down();
        spec.network = crate::capsule::NetworkPolicy::AllowListedDomains {
            domains: ["example.test".to_string()].into_iter().collect(),
            ports: [443].into_iter().collect(),
        };
        spec.filesystem.write_roots.push("/tmp".into());
        let denied = [
            CommandEffectKind::NetworkEgress,
            CommandEffectKind::FilesystemWrite,
        ]
        .into_iter()
        .collect();
        tighten_capsule_spec(&mut spec, &denied);
        assert!(spec.network.is_deny_all());
        assert!(spec.filesystem.write_roots.is_empty());
    }

    #[test]
    fn tightening_never_raises_an_already_lower_resource_ceiling() {
        let mut spec = crate::capsule::CapsuleSpec::locked_down();
        spec.resources.cpu_seconds = Some(5);
        spec.resources.memory_bytes = None;
        tighten_capsule_spec(
            &mut spec,
            &[CommandEffectKind::ResourceEscalation]
                .into_iter()
                .collect(),
        );
        assert_eq!(spec.resources.cpu_seconds, Some(5));
        assert_eq!(
            spec.resources.memory_bytes,
            crate::capsule::ResourceLimits::conservative().memory_bytes
        );
    }

    /// C14 launches through `tighten_capsule_spec` and must be able to state
    /// that the merge is monotone, not just believe it: applying any denial set
    /// twice equals applying it once, and no dimension is ever raised.
    #[test]
    fn tightening_is_monotone_and_idempotent_over_every_effect() {
        let every_effect: BTreeSet<CommandEffectKind> = [
            CommandEffectKind::PackageInstall,
            CommandEffectKind::PersistenceChange,
            CommandEffectKind::PolicyChange,
            CommandEffectKind::SecretRead,
            CommandEffectKind::NetworkEgress,
            CommandEffectKind::FilesystemWrite,
            CommandEffectKind::ResourceEscalation,
            CommandEffectKind::Web3Write,
            CommandEffectKind::Web3SignerUse,
        ]
        .into_iter()
        .collect();

        let mut spec = crate::capsule::CapsuleSpec::locked_down();
        spec.resources.cpu_seconds = Some(5);
        spec.resources.memory_bytes = None;
        spec.resources.max_output_bytes = Some(1);
        spec.filesystem.write_roots.push("/tmp/held".into());
        let before = spec.clone();

        tighten_capsule_spec(&mut spec, &every_effect);
        let once = spec.clone();
        tighten_capsule_spec(&mut spec, &every_effect);
        assert_eq!(once, spec, "tightening must be idempotent");

        // Never raises a populated ceiling, and only ever ADDS a ceiling where
        // there was none.
        fn never_raised<T: Ord + Copy>(before: Option<T>, after: Option<T>) -> bool {
            match (before, after) {
                (Some(before), Some(after)) => after <= before,
                (Some(_), None) => false,
                (None, _) => true,
            }
        }
        assert!(never_raised(
            before.resources.cpu_seconds,
            once.resources.cpu_seconds
        ));
        assert!(never_raised(
            before.resources.max_output_bytes,
            once.resources.max_output_bytes
        ));
        assert!(never_raised(
            before.resources.wall_clock_seconds,
            once.resources.wall_clock_seconds
        ));
        assert!(once.resources.memory_bytes.is_some());
        // Capabilities only ever shrink.
        assert!(once.network.is_deny_all());
        assert!(once.filesystem.write_roots.len() <= before.filesystem.write_roots.len());
    }

    /// The C14 preset is already the tightest spec the product builds, so the
    /// gate can never widen it. Pinned, because "it happens to be a no-op today"
    /// is exactly the property a future preset change could silently break.
    #[test]
    fn tightening_the_untrusted_project_preset_never_widens_it() {
        let base = tempfile::tempdir().expect("tempdir");
        let project = base.path().join("held-copy");
        std::fs::create_dir(&project).expect("create held copy");
        let preset = crate::capsule::CapsuleSpec::untrusted_project(&project, &[]);

        let mut tightened = preset.clone();
        tighten_capsule_spec(
            &mut tightened,
            &[
                CommandEffectKind::ResourceEscalation,
                CommandEffectKind::NetworkEgress,
            ]
            .into_iter()
            .collect(),
        );
        assert_eq!(tightened.resources, preset.resources);
        assert_eq!(tightened.network, preset.network);
        assert_eq!(tightened.filesystem, preset.filesystem);
    }

    #[test]
    fn the_ceiling_binding_changes_with_the_mode() {
        let envelope = shell_envelope("ls");
        let off = evaluate(&operation(&envelope), &TaskGatePolicy::default());
        let on = evaluate(&operation(&envelope), &enforcing());
        assert_ne!(
            ceiling_binding(&off.decision),
            ceiling_binding(&on.decision)
        );
    }
}
