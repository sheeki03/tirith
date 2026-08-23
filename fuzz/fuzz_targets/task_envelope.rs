#![no_main]
//! Fuzz the current versioned task-envelope parser and diagnostic decision.
//!
//! Arbitrary input exercises the wire parser directly and is also embedded in
//! a valid schema-v2 document so every fuzz case reaches provenance assignment,
//! effect inference, requested-effect narrowing, and the shared projection.

use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

use tirith_core::effects::{BoundaryCapability, CommandEffectKind};
use tirith_core::task::{
    assign_provenance, decide_document, document_decision_projection, parse_envelope_document,
    rejection_token, validate_envelope, IngressAdapter, ProposedAction, TaskDecision, MAX_ACTIONS,
};
use tirith_core::task_envelope::{ShellDialectClaim, TaskEnvelopeDocument};
use tirith_core::web3_policy::{TaskGateMode, TaskGatePolicy, Web3GuardAction};

fn all_effects() -> BTreeSet<CommandEffectKind> {
    [
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
    .collect()
}

fn enforcing_gate() -> TaskGatePolicy {
    TaskGatePolicy {
        mode: TaskGateMode::Enforce,
        effects_requiring_verified_provenance: [CommandEffectKind::PackageInstall]
            .into_iter()
            .collect(),
        effects_denied_for_untrusted_sources: all_effects(),
        action_incomplete_analysis: Web3GuardAction::Block,
    }
}

fn wrap_as_v2_content(data: &str) -> String {
    serde_json::json!({
        "version": 2,
        "task_id": "fuzz-task",
        "sources": [
            {
                "source_id": "issue-source",
                "claimed_source": "issue_body",
                "content": data,
                "locator": data,
            },
            {
                "source_id": "config-source",
                "claimed_source": "repository_config",
                "content": data,
            },
            {
                "source_id": "unknown-source",
                "claimed_source": "unknown",
                "content": data,
            },
        ],
        "actions": [
            { "shell": { "command": data, "claimed_shell": "posix" } },
            { "config_write": { "path": data } },
            { "package_install": { "ecosystem": data, "package": data } },
            { "narrative": { "text": data } },
        ],
        // Keep the non-empty intersection path live. Inferred package effects
        // omitted here must be reported as unrequested and denied, never
        // silently authorized as part of the atomic action.
        "requested_effects": [
            "package_install",
            "policy_change",
            "secret_read",
            "web3_write",
        ],
        "authorizations": [],
    })
    .to_string()
}

fn assigned_sources(
    document: &TaskEnvelopeDocument,
    adapter: IngressAdapter,
) -> Vec<tirith_core::task::AssignedProvenance> {
    document
        .envelope
        .sources
        .iter()
        .map(|source| assign_provenance(source, adapter, None, None))
        .collect()
}

fn assert_full_projection(
    document: &TaskEnvelopeDocument,
    decision: &TaskDecision,
    repeat: &TaskDecision,
    rejections: &[tirith_core::task::EnvelopeRejection],
) {
    assert_eq!(decision, repeat, "task decision is not deterministic");

    let projection = document_decision_projection(document, decision, rejections);
    let repeat_projection = document_decision_projection(document, repeat, rejections);
    assert_eq!(
        projection, repeat_projection,
        "task projection is not deterministic"
    );
    assert_eq!(
        serde_json::to_vec(&projection).expect("projection serialization"),
        serde_json::to_vec(&repeat_projection).expect("repeat projection serialization"),
        "task projection bytes are not deterministic",
    );

    let decision_value = serde_json::to_value(decision).expect("decision serialization");
    for field in [
        "mode",
        "complete",
        "enforceability",
        "inferred_effects",
        "allowed_effects",
        "denied_effects",
        "unrequested_effects",
        "provenance",
    ] {
        assert_eq!(
            projection.get(field),
            decision_value.get(field),
            "projection drifted from TaskDecision field {field}",
        );
    }
    assert_eq!(projection["envelope_version"], document.version);
    assert_eq!(
        projection["shell_dialect_claims"],
        serde_json::to_value(&document.shell_claims).expect("shell-claim serialization"),
    );
    assert_eq!(projection["shell_dialect_claims_authoritative"], false);
    assert_eq!(projection["diagnostic"], true);
    assert_eq!(
        projection["envelope_rejections"],
        serde_json::json!(rejections.iter().map(rejection_token).collect::<Vec<_>>()),
    );
}

fn assert_contracts_hold(document: &TaskEnvelopeDocument) {
    let rejections = validate_envelope(&document.envelope);
    let gate = enforcing_gate();

    for adapter in [
        IngressAdapter::OperatorIngest,
        IngressAdapter::GithubIssue,
        IngressAdapter::GithubPullRequest,
        IngressAdapter::FileRead,
        IngressAdapter::HttpFetch,
        IngressAdapter::Unattributed,
    ] {
        let provenance = assigned_sources(document, adapter);
        assert!(
            provenance.iter().all(|source| !source.is_source_trusted()),
            "an untrusted document produced a trusted source assignment",
        );

        for boundary in [
            BoundaryCapability::ObserveOnly,
            BoundaryCapability::BoundaryDependent,
            BoundaryCapability::Enforceable,
        ] {
            let decision = decide_document(document, provenance.clone(), &gate, boundary, None);

            assert!(
                decision
                    .allowed_effects
                    .is_subset(&decision.inferred_effects),
                "the decision allowed an effect the action does not have",
            );
            if !document.envelope.requested_effects.is_empty() {
                assert!(
                    decision
                        .allowed_effects
                        .is_subset(&document.envelope.requested_effects),
                    "allowed effects escaped the requested_effects ceiling",
                );
                let expected_unrequested = decision
                    .inferred_effects
                    .difference(&document.envelope.requested_effects)
                    .copied()
                    .collect::<BTreeSet<_>>();
                assert_eq!(decision.unrequested_effects, expected_unrequested);
                assert!(decision
                    .denied_effects
                    .is_superset(&decision.unrequested_effects));
            }

            // Every effective source is untrusted and the enforcing fuzz policy
            // denies every effect for such sources. No claimed source token,
            // receipt-shaped input, or boundary label may make one survive.
            assert_eq!(decision.mode, TaskGateMode::Enforce);
            assert!(
                decision.allowed_effects.is_empty(),
                "an enforcing gate allowed an effect denied for untrusted sources",
            );

            if !rejections.is_empty() {
                assert!(
                    !decision.complete,
                    "an invalid envelope produced a complete decision",
                );
            }

            let repeat = decide_document(document, provenance.clone(), &gate, boundary, None);
            assert_full_projection(document, &decision, &repeat, &rejections);
        }
    }
}

fn assert_invalid_is_incomplete(document: &TaskEnvelopeDocument) {
    let mut invalid = document.clone();
    while invalid.envelope.actions.len() <= MAX_ACTIONS {
        invalid.envelope.actions.push(ProposedAction::Narrative {
            text: "bounded invalid probe".to_string(),
        });
        invalid.shell_claims.push(ShellDialectClaim::Unknown);
    }
    let rejections = validate_envelope(&invalid.envelope);
    assert!(
        !rejections.is_empty(),
        "invalid fuzz probe was not rejected"
    );

    let provenance = assigned_sources(&invalid, IngressAdapter::Unattributed);
    let decision = decide_document(
        &invalid,
        provenance,
        &enforcing_gate(),
        BoundaryCapability::Enforceable,
        None,
    );
    assert!(!decision.complete, "invalid envelope was reported complete");
    assert_eq!(
        document_decision_projection(&invalid, &decision, &rejections)["complete"],
        false,
    );
}

fuzz_target!(|data: &str| {
    // Direct arbitrary wire input: parse failure is the terminal refusal and
    // never reaches the decision path.
    if let Ok(document) = parse_envelope_document(data) {
        assert_contracts_hold(&document);
    }

    // Keep all decision contracts non-vacuous even when random input is not a
    // task document by embedding the same bytes in every schema-v2 action arm.
    let wrapped = wrap_as_v2_content(data);
    if let Ok(document) = parse_envelope_document(&wrapped) {
        assert_contracts_hold(&document);
        assert_invalid_is_incomplete(&document);
    }
});
