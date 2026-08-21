//! C12: the owned-boundary decision mapping and the config-write permit.
//!
//! These tests pin the four properties the slice is judged on that can be
//! stated without a process: the gate keys on the MODE and not on the denial
//! set, observe mode carries no enforcement, an unattributed origin fails
//! closed, and the permit is single-use and content-bound. The
//! "denial happens before the side effect" property is behavioural and lives in
//! `crates/tirith/tests/owned_boundary_enforcement.rs`.

use std::collections::BTreeSet;

use tirith_core::effects::{BoundaryCapability, CommandEffectKind};
use tirith_core::task::{IngressAdapter, TaskEnvelopeInput};
use tirith_core::task_boundary::{self, BoundaryOperation, BoundaryOutcome, OwnedBoundary};
use tirith_core::web3_policy::{TaskGateMode, TaskGatePolicy, Web3GuardAction};

/// A policy that denies a real effect but has NOT been switched on.
fn effects_populated_but_mode_off() -> TaskGatePolicy {
    TaskGatePolicy {
        mode: TaskGateMode::Off,
        effects_denied_for_untrusted_sources: [CommandEffectKind::Web3Write].into_iter().collect(),
        ..TaskGatePolicy::default()
    }
}

fn with_mode(mode: TaskGateMode) -> TaskGatePolicy {
    TaskGatePolicy {
        mode,
        effects_denied_for_untrusted_sources: [CommandEffectKind::Web3Write].into_iter().collect(),
        ..TaskGatePolicy::default()
    }
}

fn assess(
    envelope: &TaskEnvelopeInput,
    gate: &TaskGatePolicy,
) -> task_boundary::BoundaryAssessment {
    let operation = BoundaryOperation {
        boundary: OwnedBoundary::GatewayForward,
        envelope,
        adapter: IngressAdapter::Unattributed,
        boundary_effects: BTreeSet::new(),
    };
    task_boundary::evaluate(&operation, gate)
}

/// A Web3 write the grammar models completely, so the only variable under test
/// is the mode.
fn denied_effect_envelope() -> TaskEnvelopeInput {
    task_boundary::shell_envelope("forge script Deploy.s.sol --broadcast")
}

/// The single most likely implementation bug: `task::decide` populates
/// `denied_effects` in EVERY mode, so a gate that keys on "something was
/// denied" turns the default-off policy into live enforcement for any operator
/// who filled in the effect sets and never chose a mode.
#[test]
fn a_populated_denial_set_does_not_enforce_while_the_mode_is_off() {
    let assessment = assess(&denied_effect_envelope(), &effects_populated_but_mode_off());
    assert!(
        !assessment.decision.denied_effects.is_empty(),
        "the fixture no longer exercises the bug it exists for"
    );
    assert_eq!(assessment.outcome, BoundaryOutcome::Allow);
    assert!(assessment.refusal(false).is_none());
    // Nothing else may act on the report either: an off gate must not tighten a
    // capsule or trip a downstream assertion, and it must not write a per-call
    // audit line an operator never asked for.
    assert!(assessment.enforced_denied_effects().is_empty());
    assert!(!assessment.is_recordable());
}

/// Observe mode is the one place the two split: it records everything and acts
/// on nothing.
#[test]
fn observe_mode_records_without_letting_anything_act_on_the_denial() {
    let assessment = assess(&denied_effect_envelope(), &with_mode(TaskGateMode::Observe));
    assert!(assessment.is_recordable());
    assert!(
        assessment.enforced_denied_effects().is_empty(),
        "observe mode handed a denial to a caller that would act on it"
    );

    let enforcing = assess(&denied_effect_envelope(), &with_mode(TaskGateMode::Enforce));
    assert!(enforcing.is_recordable());
    assert_eq!(
        enforcing.enforced_denied_effects(),
        enforcing.decision.denied_effects
    );
}

/// Observe mode records and does nothing else. Returning any refusal here would
/// be enough for the gateway's `warn_action: deny` to turn an observation into a
/// hard block.
#[test]
fn observe_mode_records_a_denial_and_still_allows() {
    let assessment = assess(&denied_effect_envelope(), &with_mode(TaskGateMode::Observe));
    assert!(
        assessment
            .decision
            .denied_effects
            .contains(&CommandEffectKind::Web3Write),
        "observe mode must still REPORT what it would refuse"
    );
    assert_eq!(assessment.outcome, BoundaryOutcome::Allow);
    assert!(assessment.refusal(false).is_none());
    // Not even conditionally: no call site can promote this to an approval
    // requirement.
    assert!(assessment.refusal(true).is_none());
    assert!(!assessment.is_denied());
    let projection = assessment.projection();
    assert_eq!(projection["mode"], "observe");
    assert_eq!(projection["outcome"], "allow");
}

#[test]
fn enforce_mode_refuses_the_same_decision_observe_only_recorded() {
    let observing = assess(&denied_effect_envelope(), &with_mode(TaskGateMode::Observe));
    let enforcing = assess(&denied_effect_envelope(), &with_mode(TaskGateMode::Enforce));
    assert_eq!(
        observing.decision.denied_effects, enforcing.decision.denied_effects,
        "the two modes must agree about the analysis and differ only in what they do"
    );
    let reason = enforcing.refusal(false).expect("enforce mode must refuse");
    assert!(reason.contains("web3_write"), "reason: {reason}");
    assert!(enforcing.is_denied());
}

/// An owned boundary has no identified origin, so provenance is never verified
/// and the source is never trusted. Both restriction families therefore bite.
#[test]
fn an_unattributed_origin_fails_closed_on_both_restriction_families() {
    let gate = TaskGatePolicy {
        mode: TaskGateMode::Enforce,
        effects_requiring_verified_provenance: [CommandEffectKind::Web3Write].into_iter().collect(),
        ..TaskGatePolicy::default()
    };
    let assessment = assess(&denied_effect_envelope(), &gate);
    assert!(
        assessment
            .decision
            .denied_effects
            .contains(&CommandEffectKind::Web3Write),
        "a receipt-less unattributed source was treated as verified"
    );
    assert!(assessment.refusal(false).is_some());

    // The same holds when the envelope carries no source at all: an empty
    // provenance list is not "nothing to object to".
    let empty = TaskEnvelopeInput {
        actions: denied_effect_envelope().actions,
        ..TaskEnvelopeInput::default()
    };
    let assessment = assess(&empty, &gate);
    assert!(assessment.decision.provenance.is_empty());
    assert!(assessment.refusal(false).is_some());
}

/// The hazard the module documents. `infer_effects_detailed` models the Web3
/// grammar and nothing else, so almost every ordinary shell line is INCOMPLETE.
/// An operator who sets `action_incomplete_analysis: block` is therefore
/// refusing almost every guarded command. This fixture exists so that
/// behaviour is met in a test and in the docs rather than in production.
#[test]
fn incomplete_shell_analysis_blocks_when_the_operator_asks_it_to() {
    let gate = TaskGatePolicy {
        mode: TaskGateMode::Enforce,
        action_incomplete_analysis: Web3GuardAction::Block,
        ..TaskGatePolicy::default()
    };
    // As plain as a command gets, and still not modelled.
    let assessment = assess(&task_boundary::shell_envelope("ls"), &gate);
    assert!(!assessment.decision.complete);
    assert!(
        assessment.decision.denied_effects.is_empty(),
        "nothing was denied; the refusal must be about coverage, not an effect"
    );
    let reason = assessment.refusal(false).expect("must refuse");
    assert!(
        reason.contains("incomplete"),
        "the reason must name incompleteness, not invent a denied effect: {reason}"
    );
}

/// The same policy at its default `warn` leaves those commands alone, which is
/// the configuration an operator should actually run.
#[test]
fn incomplete_shell_analysis_is_allowed_under_the_default_action() {
    let gate = TaskGatePolicy {
        mode: TaskGateMode::Enforce,
        ..TaskGatePolicy::default()
    };
    assert_eq!(gate.action_incomplete_analysis, Web3GuardAction::Warn);
    let assessment = assess(&task_boundary::shell_envelope("ls"), &gate);
    assert!(!assessment.decision.complete);
    assert!(assessment.refusal(false).is_none());
}

#[test]
fn an_owned_boundary_declares_itself_enforceable_and_not_diagnostic() {
    let assessment = assess(&denied_effect_envelope(), &TaskGatePolicy::default());
    assert_eq!(
        assessment.decision.enforceability,
        BoundaryCapability::Enforceable
    );
    let projection = assessment.projection();
    assert_eq!(projection["enforceability"], "enforceable");
    assert_eq!(projection["diagnostic"], false);
    assert_eq!(projection["boundary"], "gateway_forward");
}

/// Boundary effects widen what is assessed; they never authorise anything. The
/// policy filter runs over the union, so a boundary that admits it reaches the
/// network gets that admission held against it.
#[test]
fn a_boundary_effect_is_assessed_and_never_granted() {
    let envelope = task_boundary::shell_envelope("ls");
    let gate = TaskGatePolicy {
        mode: TaskGateMode::Enforce,
        effects_denied_for_untrusted_sources: [CommandEffectKind::NetworkEgress]
            .into_iter()
            .collect(),
        ..TaskGatePolicy::default()
    };
    let operation = BoundaryOperation {
        boundary: OwnedBoundary::RemoteScriptRun,
        envelope: &envelope,
        adapter: IngressAdapter::Unattributed,
        boundary_effects: [CommandEffectKind::NetworkEgress].into_iter().collect(),
    };
    let assessment = task_boundary::evaluate(&operation, &gate);
    assert!(assessment
        .decision
        .denied_effects
        .contains(&CommandEffectKind::NetworkEgress));
    assert!(assessment.refusal(false).is_some());
}

/// The ceiling bound into an install-plan digest has to move when the ceiling
/// moves, or an approval taken under a strict gate would survive its removal.
#[test]
fn the_ceiling_binding_distinguishes_every_gate_posture() {
    let envelope = denied_effect_envelope();
    let mut seen = BTreeSet::new();
    for gate in [
        TaskGatePolicy::default(),
        with_mode(TaskGateMode::Observe),
        with_mode(TaskGateMode::Enforce),
    ] {
        let assessment = assess(&envelope, &gate);
        seen.insert(task_boundary::ceiling_binding(&assessment.decision));
    }
    assert_eq!(
        seen.len(),
        3,
        "two postures bound to the same string: {seen:?}"
    );
}

// ---------------------------------------------------------------------------
// ConfigWritePermit
// ---------------------------------------------------------------------------

use tirith_core::config_write::{ConfigWriteError, ConfigWritePermit};

/// Compile-time proof that the permit is not `Clone`.
///
/// The inherent const wins whenever the `Clone` bound is satisfied; when it is
/// not, resolution falls back to the blanket trait const. A `derive(Clone)`
/// slipping onto `ConfigWritePermit` therefore fails this assertion instead of
/// silently allowing one authorisation to publish twice.
struct IsClone<T>(std::marker::PhantomData<T>);

trait NotClone {
    const CLONEABLE: bool = false;
}

impl<T> NotClone for IsClone<T> {}

impl<T: Clone> IsClone<T> {
    #[allow(dead_code)]
    const CLONEABLE: bool = true;
}

#[test]
fn the_permit_cannot_be_duplicated() {
    // Both consts resolve at compile time, so this fails the build rather than
    // the test run if `Clone` is ever derived on the permit. The `String`
    // control proves the probe reports `true` for a type that really is `Clone`,
    // so the assertion above is not vacuous.
    const {
        assert!(
            !<IsClone<ConfigWritePermit>>::CLONEABLE,
            "ConfigWritePermit became Clone; one authorisation can now publish twice"
        );
        assert!(<IsClone<String>>::CLONEABLE);
    }
}

#[test]
fn a_permit_refuses_bytes_it_was_not_issued_for_and_publishes_nothing() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("policy.yaml");
    let permit =
        ConfigWritePermit::prepare(root.path(), &path, b"approved\n", true, "policy-identity")
            .expect("prepare");
    let error = permit
        .commit(b"swapped after approval\n")
        .expect_err("a substituted payload must be refused");
    assert!(matches!(error, ConfigWriteError::ContentMismatch));
    assert!(
        !path.exists(),
        "the refusal happened after the rename, which is not a gate"
    );
}

#[test]
fn a_permit_publishes_exactly_once_and_binds_the_policy_identity() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("policy.yaml");
    let permit =
        ConfigWritePermit::prepare(root.path(), &path, b"safe: true\n", true, "policy-identity")
            .expect("prepare");
    assert_eq!(permit.policy_identity(), "policy-identity");
    // `commit` takes `self`, so a second call does not compile. Single use is a
    // property of the type, not a runtime flag someone can forget to check.
    permit.commit(b"safe: true\n").expect("commit");
    assert_eq!(
        std::fs::read(&path).expect("read back"),
        b"safe: true\n".to_vec()
    );
}

#[test]
fn permit_debug_carries_digests_and_never_the_destination_or_the_payload() {
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("distinctive-config-name.yaml");
    let permit = ConfigWritePermit::prepare(
        root.path(),
        &path,
        b"api_key: sk-live-should-never-print\n",
        true,
        "policy-identity",
    )
    .expect("prepare");
    let rendered = format!("{permit:?}");
    assert!(
        !rendered.contains("distinctive-config-name"),
        "the permit printed its destination: {rendered}"
    );
    assert!(
        !rendered.contains("sk-live-should-never-print"),
        "the permit printed its payload: {rendered}"
    );
    assert!(rendered.contains(permit.content_sha256()));
}
