//! `tirith task check` — diagnostic assessment of an untrusted task envelope
//! (C11).
//!
//! This is a DIAGNOSTIC surface. It reports what an envelope would be allowed
//! to do under the current policy; it does not execute anything, fetch
//! anything, resolve any package, or write anything. That property is the
//! slice's exit gate, not an implementation detail, so the only filesystem
//! access here is reading the envelope the operator explicitly pointed at.
//!
//! The output deliberately reports the INFERRED effects alongside the allowed
//! ones. An operator enabling the task gate for the first time needs to see
//! what the analysis understood before trusting what it permits, and a task
//! whose assessment is incomplete has to be visibly incomplete rather than
//! quietly narrower.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use tirith_core::effects::{BoundaryCapability, CommandEffectKind};
use tirith_core::policy::Policy;
use tirith_core::task::{
    assign_provenance, decide, parse_envelope, validate_envelope, EnvelopeRejection,
    IngressAdapter, TaskDecision, TaskEnvelopeInput, MAX_INLINE_BYTES,
};

/// Exit codes, matching the repository's existing convention: 0 clean, 1 a
/// security decision the operator should look at, 2 usage or input error.
const EXIT_OK: i32 = 0;
const EXIT_RESTRICTED: i32 = 1;
const EXIT_INPUT: i32 = 2;

/// Read the envelope from a file or from stdin, bounded before parsing.
///
/// The cap is applied to the READ, not after it, so an oversized file cannot
/// be materialized in full just to be rejected.
fn read_envelope(path: Option<&Path>) -> Result<String, String> {
    let cap = MAX_INLINE_BYTES.saturating_mul(2);
    let mut buffer = String::new();
    match path {
        Some(path) => {
            let file = std::fs::File::open(path)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
            file.take(cap as u64 + 1)
                .read_to_string(&mut buffer)
                .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        }
        None => {
            std::io::stdin()
                .take(cap as u64 + 1)
                .read_to_string(&mut buffer)
                .map_err(|error| format!("cannot read stdin: {error}"))?;
        }
    }
    if buffer.len() > cap {
        return Err(format!("envelope exceeds the {cap}-byte input cap"));
    }
    Ok(buffer)
}

/// Which ingress adapter to attribute the content to.
///
/// This is an OPERATOR assertion made on the command line, never something the
/// envelope can claim for itself. Defaulting to an explicit operator ingest is
/// right for a diagnostic run a human invoked, and it still confers no trust:
/// no source kind is trusted, so the adapter only decides which claimed kind
/// is believable.
fn adapter_from_flag(name: Option<&str>) -> Result<IngressAdapter, String> {
    Ok(match name.unwrap_or("operator-ingest") {
        "operator-ingest" => IngressAdapter::OperatorIngest,
        "github-issue" => IngressAdapter::GithubIssue,
        "github-pull-request" => IngressAdapter::GithubPullRequest,
        "file-read" => IngressAdapter::FileRead,
        "http-fetch" => IngressAdapter::HttpFetch,
        "unattributed" => IngressAdapter::Unattributed,
        other => {
            return Err(format!(
                "unknown --adapter '{other}'; expected one of operator-ingest, github-issue, \
                 github-pull-request, file-read, http-fetch, unattributed"
            ))
        }
    })
}

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

fn effects_json(effects: &BTreeSet<CommandEffectKind>) -> Vec<String> {
    effects
        .iter()
        .map(|effect| effect_token(*effect).to_string())
        .collect()
}

fn rejection_token(rejection: &EnvelopeRejection) -> String {
    match rejection {
        EnvelopeRejection::TooManySources { max } => format!("too_many_sources(max={max})"),
        EnvelopeRejection::TooManyActions { max } => format!("too_many_actions(max={max})"),
        EnvelopeRejection::SourceTooLarge { max } => format!("source_too_large(max={max})"),
        EnvelopeRejection::InlineContentTooLarge { max } => {
            format!("inline_content_too_large(max={max})")
        }
        EnvelopeRejection::StringTooLong { max } => format!("string_too_long(max={max})"),
        EnvelopeRejection::PathTooLong { max } => format!("path_too_long(max={max})"),
        // The detail is a serde message about SHAPE, not content, so it is safe
        // to surface; it never echoes a field value.
        EnvelopeRejection::Malformed { detail } => format!("malformed({detail})"),
    }
}

fn decision_json(decision: &TaskDecision, rejections: &[EnvelopeRejection]) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "mode": decision.mode,
        "complete": decision.complete,
        "enforceability": match decision.enforceability {
            BoundaryCapability::ObserveOnly => "observe_only",
            BoundaryCapability::BoundaryDependent => "boundary_dependent",
            BoundaryCapability::Enforceable => "enforceable",
        },
        "inferred_effects": effects_json(&decision.inferred_effects),
        "allowed_effects": effects_json(&decision.allowed_effects),
        "denied_effects": effects_json(&decision.denied_effects),
        // Serialized through serde, NOT `{:?}`. These enums already declare
        // `rename_all = "snake_case"`, so serde yields the stable wire tokens
        // (`github_issue`, `agent_config`); Debug formatting would emit
        // `githubissue` and would silently change if a variant were renamed.
        "provenance": decision.provenance.iter().map(|p| serde_json::json!({
            // The CLAIM is reported next to the assignment on purpose: an
            // operator debugging a refusal needs to see that the two differ.
            "claimed_source": p.claimed_source,
            "effective_source": p.effective_source,
            "adapter": p.adapter,
            "receipt_status": p.receipt_status,
        })).collect::<Vec<_>>(),
        "envelope_rejections": rejections.iter().map(rejection_token).collect::<Vec<_>>(),
        "diagnostic": true,
    })
}

fn print_human(decision: &TaskDecision, rejections: &[EnvelopeRejection]) {
    println!("tirith task check (diagnostic — nothing was executed)");
    println!("  gate mode:      {:?}", decision.mode);
    println!(
        "  assessment:     {}",
        if decision.complete {
            "complete"
        } else {
            "INCOMPLETE — treat unlisted effects as unknown, not absent"
        }
    );
    println!("  enforceable at: {:?}", decision.enforceability);

    for provenance in &decision.provenance {
        let laundered = provenance.claimed_source != provenance.effective_source;
        println!(
            "  source:         claimed {:?} -> assigned {:?}{} (receipt: {:?})",
            provenance.claimed_source,
            provenance.effective_source,
            if laundered {
                "  [claim not honored]"
            } else {
                ""
            },
            provenance.receipt_status
        );
    }

    let render = |label: &str, effects: &BTreeSet<CommandEffectKind>| {
        if effects.is_empty() {
            println!("  {label}: (none)");
        } else {
            println!(
                "  {label}: {}",
                effects
                    .iter()
                    .map(|effect| effect_token(*effect))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    };
    render("inferred", &decision.inferred_effects);
    render("allowed ", &decision.allowed_effects);
    render("denied  ", &decision.denied_effects);

    for rejection in rejections {
        println!("  rejected:       {}", rejection_token(rejection));
    }
}

/// Run `tirith task check`.
pub fn run(path: Option<&Path>, adapter: Option<&str>, json: bool) -> i32 {
    let adapter = match adapter_from_flag(adapter) {
        Ok(adapter) => adapter,
        Err(message) => {
            eprintln!("tirith task check: {message}");
            return EXIT_INPUT;
        }
    };

    let raw = match read_envelope(path) {
        Ok(raw) => raw,
        Err(message) => {
            eprintln!("tirith task check: {message}");
            return EXIT_INPUT;
        }
    };

    let envelope: TaskEnvelopeInput = match parse_envelope(&raw) {
        Ok(envelope) => envelope,
        Err(rejection) => {
            let token = rejection_token(&rejection);
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema_version": 1,
                        "envelope_rejections": [token],
                        "diagnostic": true,
                    })
                );
            } else {
                eprintln!("tirith task check: envelope rejected: {token}");
            }
            return EXIT_INPUT;
        }
    };

    let rejections = validate_envelope(&envelope);

    // Local discovery only. A diagnostic must not reach the network, so this
    // deliberately uses the offline policy path.
    let policy = Policy::discover_local_only(None);

    let provenance = envelope
        .sources
        .iter()
        .map(|source| assign_provenance(source, adapter, None, None))
        .collect::<Vec<_>>();

    // A CLI run is advisory: it reports what WOULD happen, and cannot itself
    // stop anything, so it declares observe-only rather than claiming an
    // enforcement capability it does not have.
    let decision = decide(
        &envelope,
        provenance,
        &policy.task_gate,
        BoundaryCapability::ObserveOnly,
    );

    if json {
        println!("{}", decision_json(&decision, &rejections));
    } else {
        print_human(&decision, &rejections);
    }

    // Exit 1 when something was refused or the picture is incomplete, so a
    // script can tell "nothing to see" from "look at this".
    if !decision.denied_effects.is_empty() || !decision.complete || !rejections.is_empty() {
        EXIT_RESTRICTED
    } else {
        EXIT_OK
    }
}
