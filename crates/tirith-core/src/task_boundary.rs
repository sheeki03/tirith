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

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::artifact::resolver::ResolverRequest;
use crate::effects::{BoundaryCapability, CommandEffectKind};
use crate::package_approval::VerifiedPackageApproval;
use crate::task::{
    assign_provenance, decide_with_boundary_effects_and_context, decide_with_verified_evidence,
    decision_projection, infer_effects_detailed_with_context,
    validate_canonical_acquisition_identity, validate_envelope,
    validate_receipt_context_identifier, verify_authorization_set, AssignedProvenance,
    DurableReplayStore, EnforcementProjectionV1, EnvelopeRejection, IngressAdapter, ProposedAction,
    ProvenanceReceiptV2, ReceiptStatus, ReceiptV2Error, ReplayOutcome, ReplayReservation,
    ReplayReservationOutcome, ReplayStore, ReplayStoreError, TaskAuthorizationProjectionV1,
    TaskDecision, TaskEnvelopeInput, TaskSourceInput,
};
use crate::task_analysis::TaskAnalysisContext;
use crate::task_envelope::{TaskEnvelopeDocument, MAX_AUTHORIZATION_RECEIPTS};
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
    /// `tirith fetch <URL>` or its MCP equivalent is about to run the fixed
    /// multi-user-agent cloaking probe set.
    FetchCloaking,
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
            Self::FetchCloaking => "fetch_cloaking",
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

/// Trusted ingress identity for one schema-v2 source.
///
/// The canonical acquisition identity may be a sensitive URL or path. It is
/// intentionally private, has no `Debug`/serde implementation, and is hashed
/// immediately when the expected receipt projection is constructed.
pub struct TrustedReceiptSourceContext {
    source_id: String,
    adapter: IngressAdapter,
    canonical_acquisition_identity: String,
}

impl TrustedReceiptSourceContext {
    /// Construct the only trusted source identity accepted by receipt-v2.
    ///
    /// The caller supplies the adapter-owned canonical acquisition identity,
    /// never a document-provided `source_id`. The resulting identifier is a
    /// stable domain-separated digest and is safe to place in the task wire
    /// document and authorization projection.
    pub fn from_canonical_acquisition(
        adapter: IngressAdapter,
        canonical_acquisition_identity: &str,
    ) -> Result<Self, ReceiptV2Error> {
        validate_canonical_acquisition_identity(canonical_acquisition_identity)?;
        Ok(Self {
            source_id: deterministic_source_id(adapter, canonical_acquisition_identity),
            adapter,
            canonical_acquisition_identity: canonical_acquisition_identity.to_string(),
        })
    }

    /// Compatibility constructor for callers that already materialized a
    /// source identifier. The supplied identifier is checked against the
    /// adapter-derived value; it is never accepted as authority.
    pub fn new(
        source_id: &str,
        adapter: IngressAdapter,
        canonical_acquisition_identity: &str,
    ) -> Result<Self, ReceiptV2Error> {
        validate_receipt_context_identifier("source_id", source_id)?;
        let derived = Self::from_canonical_acquisition(adapter, canonical_acquisition_identity)?;
        if source_id != derived.source_id {
            return Err(ReceiptV2Error::ContextMismatch("source_id"));
        }
        Ok(derived)
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn adapter(&self) -> IngressAdapter {
        self.adapter
    }
}

fn deterministic_source_id(
    adapter: IngressAdapter,
    canonical_acquisition_identity: &str,
) -> String {
    let mut binding = b"tirith-task-source-id:v1\0".to_vec();
    binding.extend_from_slice(ingress_adapter_token(adapter).as_bytes());
    binding.push(0);
    binding.extend_from_slice(canonical_acquisition_identity.as_bytes());
    crate::command_card::sha256_hex(&binding)
}

fn ingress_adapter_token(adapter: IngressAdapter) -> &'static str {
    match adapter {
        IngressAdapter::OperatorIngest => "operator_ingest",
        IngressAdapter::GithubIssue => "github_issue",
        IngressAdapter::GithubPullRequest => "github_pull_request",
        IngressAdapter::FileRead => "file_read",
        IngressAdapter::HttpFetch => "http_fetch",
        IngressAdapter::Unattributed => "unattributed",
    }
}

/// Inputs that only a trusted boundary may supply while deriving the expected
/// receipt projection. No keys, clocks, environment, or command-card trust are
/// involved in this first stage, so the exact safe projections may be handed
/// to an external issuer before any receipt exists.
pub struct BoundaryAuthorizationProjectionContext<'a> {
    sources: &'a [TrustedReceiptSourceContext],
    action_identities: &'a [String],
    enforcement: &'a EnforcementProjectionV1,
}

impl<'a> BoundaryAuthorizationProjectionContext<'a> {
    pub fn new(
        sources: &'a [TrustedReceiptSourceContext],
        action_identities: &'a [String],
        enforcement: &'a EnforcementProjectionV1,
    ) -> Self {
        Self {
            sources,
            action_identities,
            enforcement,
        }
    }
}

/// Second-stage verification inputs. No environment or command-card trust is
/// consulted.
pub struct TrustedBoundaryReceiptContext<'a> {
    trusted_keys: &'a BTreeMap<String, [u8; 32]>,
    now: DateTime<Utc>,
    sources: &'a [TrustedReceiptSourceContext],
    action_identities: &'a [String],
    enforcement: &'a EnforcementProjectionV1,
}

impl<'a> TrustedBoundaryReceiptContext<'a> {
    pub fn new(
        trusted_keys: &'a BTreeMap<String, [u8; 32]>,
        now: DateTime<Utc>,
        sources: &'a [TrustedReceiptSourceContext],
        action_identities: &'a [String],
        enforcement: &'a EnforcementProjectionV1,
    ) -> Self {
        Self {
            trusted_keys,
            now,
            sources,
            action_identities,
            enforcement,
        }
    }

    pub fn projection_context(&self) -> BoundaryAuthorizationProjectionContext<'_> {
        BoundaryAuthorizationProjectionContext::new(
            self.sources,
            self.action_identities,
            self.enforcement,
        )
    }
}

mod boundary_marker_sealed {
    pub trait Sealed {}
}

/// Sealed type-level identity for an owned irreversible transition.
pub trait BoundaryMarker: boundary_marker_sealed::Sealed + 'static {
    const BOUNDARY: OwnedBoundary;
}

macro_rules! boundary_markers {
    ($(($marker:ident, $boundary:ident)),+ $(,)?) => {
        $(
            pub enum $marker {}
            impl boundary_marker_sealed::Sealed for $marker {}
            impl BoundaryMarker for $marker {
                const BOUNDARY: OwnedBoundary = OwnedBoundary::$boundary;
            }
        )+
    };
}

boundary_markers!(
    (GatewayForwardBoundary, GatewayForward),
    (PackageApprovalBoundary, PackageApproval),
    (PackageResolveBoundary, PackageResolve),
    (PackageInstallPreparationBoundary, PackageInstallPreparation),
    (PackageManagerNetworkBoundary, PackageManagerNetwork),
    (PackageManagerExecutionBoundary, PackageManagerExecution),
    (RemoteScriptRunBoundary, RemoteScriptRun),
    (FetchCloakingBoundary, FetchCloaking),
    (ConfigWriteBoundary, ConfigWrite),
);

mod approval_boundary_sealed {
    pub trait Sealed {}
}

/// Boundary markers with an existing, honest approval channel. The trait is
/// sealed so a caller cannot relabel a boundary that has no approval mechanism
/// and turn `RequireApproval` into `Allow`.
pub trait ApprovalCapableBoundary: BoundaryMarker + approval_boundary_sealed::Sealed {}

impl approval_boundary_sealed::Sealed for PackageInstallPreparationBoundary {}
impl ApprovalCapableBoundary for PackageInstallPreparationBoundary {}
impl approval_boundary_sealed::Sealed for PackageManagerExecutionBoundary {}
impl ApprovalCapableBoundary for PackageManagerExecutionBoundary {}

/// Internal evidence minted only by a channel-specific verifier. Keeping this
/// type private prevents downstream callers from converting an operation alone
/// into approval.
struct BoundaryApprovalEvidence<B: ApprovalCapableBoundary> {
    operation_binding_sha256: String,
    channel_binding_sha256: String,
    nonce: String,
    not_after: Option<DateTime<Utc>>,
    marker: PhantomData<fn() -> B>,
}

/// Opaque, non-cloneable capability returned only from a cryptographically
/// verified native-authority package approval. It is bound to both the final
/// plan digest and the exact install-preparation operation.
pub struct PackageInstallApprovalChannel {
    evidence: BoundaryApprovalEvidence<PackageInstallPreparationBoundary>,
}

/// Canonical preparation operation for one already-resolved, expiry-independent
/// install plan. It is derived entirely from signed-plan fields; callers cannot
/// add an unrelated action while retaining the same operation identity.
pub fn package_install_plan_envelope(
    requested_plan: &crate::artifact::install::InstallPlanDigest,
) -> Result<TaskEnvelopeInput, BoundaryAuthorizationError> {
    let requested = crate::package_approval::expiry_independent_plan(requested_plan)
        .map_err(|_| BoundaryAuthorizationError::ApprovalMismatch)?;
    let mut source = unattributed_source();
    source.content = format!(
        "tirith-package-install-plan:v2:sha256:{}",
        requested.plan_digest
    );
    Ok(TaskEnvelopeInput {
        task_id: None,
        sources: vec![source],
        actions: vec![ProposedAction::PackageInstall {
            ecosystem: "pip".to_string(),
            package: format!("plan-sha256:{}", requested.plan_digest),
        }],
        requested_effects: BTreeSet::new(),
    })
}

impl PackageInstallApprovalChannel {
    /// Consume opaque proof minted only after schema-v2 signature, authority,
    /// freshness, and exact-plan verification, and bind it to the final typed
    /// preparation operation. No boolean or self-consistent digest can mint this
    /// channel.
    pub fn from_native_authority(
        approval: VerifiedPackageApproval,
        operation: &BoundaryOperation<'_>,
    ) -> Result<Self, BoundaryAuthorizationError> {
        let expected_envelope = package_install_plan_envelope(approval.requested_plan())?;
        let expected_operation = BoundaryOperation {
            boundary: OwnedBoundary::PackageInstallPreparation,
            envelope: &expected_envelope,
            adapter: IngressAdapter::Unattributed,
            boundary_effects: BTreeSet::new(),
        };
        if operation_binding_digest(operation) != operation_binding_digest(&expected_operation) {
            return Err(BoundaryAuthorizationError::ApprovalMismatch);
        }
        let not_after = DateTime::parse_from_rfc3339(approval.expires_at())
            .map_err(|_| BoundaryAuthorizationError::ApprovalMismatch)?
            .with_timezone(&Utc);
        let channel_binding_sha256 = approval_channel_binding(&serde_json::json!({
            "channel": "native_package_approval_v2",
            "authority_key_id": approval.authority_key_id(),
            "approved_plan_digest": approval.approved_plan_digest(),
            "requested_plan_digest": approval.requested_plan_digest(),
            "approved_expiry": approval.expires_at(),
        }));
        Ok(Self {
            evidence: approval_evidence_for::<PackageInstallPreparationBoundary>(
                operation,
                channel_binding_sha256,
                Some(not_after),
            )?,
        })
    }
}

/// Which real package-manager confirmation channel produced an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManagerApprovalKind {
    Interactive,
    Unattended,
}

/// Opaque, non-cloneable capability returned only after a package-manager
/// confirmation channel reports success. Its fields and nonce are private.
///
/// An operation by itself cannot mint approval:
///
/// ```compile_fail
/// use tirith_core::task_boundary::{BoundaryApprovalEvidence, PackageManagerExecutionBoundary};
/// let _ = std::mem::size_of::<BoundaryApprovalEvidence<PackageManagerExecutionBoundary>>();
/// ```
pub struct PackageManagerApprovalChannel {
    evidence: BoundaryApprovalEvidence<PackageManagerExecutionBoundary>,
}

/// One exact pending manager approval. It can be completed only by the core's
/// real process-level CLI verifier, not from an operation plus a caller boolean.
pub struct PackageManagerApprovalChallenge {
    operation_binding_sha256: String,
}

impl PackageManagerApprovalChallenge {
    pub fn confirm_cli(
        self,
        kind: PackageManagerApprovalKind,
        prompt: &str,
    ) -> Result<PackageManagerApprovalChannel, BoundaryAuthorizationError> {
        match kind {
            PackageManagerApprovalKind::Interactive => confirm_package_manager_tty(prompt)?,
            PackageManagerApprovalKind::Unattended => {
                let explicit_yes = std::env::args_os().any(|argument| argument == "--yes");
                if !explicit_yes {
                    return Err(BoundaryAuthorizationError::ApprovalRequired);
                }
            }
        }
        let channel_binding_sha256 = approval_channel_binding(&serde_json::json!({
            "channel": match kind {
                PackageManagerApprovalKind::Interactive => "interactive_package_manager",
                PackageManagerApprovalKind::Unattended => "unattended_package_manager",
            },
        }));
        Ok(PackageManagerApprovalChannel {
            evidence: BoundaryApprovalEvidence {
                operation_binding_sha256: self.operation_binding_sha256,
                channel_binding_sha256,
                nonce: uuid::Uuid::new_v4().simple().to_string(),
                not_after: None,
                marker: PhantomData,
            },
        })
    }
}

fn confirm_package_manager_tty(prompt: &str) -> Result<(), BoundaryAuthorizationError> {
    use std::io::{BufRead as _, Write as _};

    #[cfg(unix)]
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| BoundaryAuthorizationError::ApprovalRequired)?;
    #[cfg(not(unix))]
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONIN$")
        .map_err(|_| BoundaryAuthorizationError::ApprovalRequired)?;
    tty.write_all(prompt.as_bytes())
        .and_then(|()| tty.flush())
        .map_err(|_| BoundaryAuthorizationError::ApprovalRequired)?;
    let mut answer = String::new();
    std::io::BufReader::new(
        tty.try_clone()
            .map_err(|_| BoundaryAuthorizationError::ApprovalRequired)?,
    )
    .read_line(&mut answer)
    .map_err(|_| BoundaryAuthorizationError::ApprovalRequired)?;
    if matches!(answer.trim(), "y" | "Y" | "yes" | "Yes") {
        Ok(())
    } else {
        Err(BoundaryAuthorizationError::ApprovalRequired)
    }
}

fn approval_evidence_for<B: ApprovalCapableBoundary>(
    operation: &BoundaryOperation<'_>,
    channel_binding_sha256: String,
    not_after: Option<DateTime<Utc>>,
) -> Result<BoundaryApprovalEvidence<B>, BoundaryAuthorizationError> {
    if operation.boundary != B::BOUNDARY {
        return Err(BoundaryAuthorizationError::BoundaryMismatch);
    }
    Ok(BoundaryApprovalEvidence {
        operation_binding_sha256: operation_binding_digest(operation),
        channel_binding_sha256,
        nonce: uuid::Uuid::new_v4().simple().to_string(),
        not_after,
        marker: PhantomData,
    })
}

fn approval_channel_binding(projection: &serde_json::Value) -> String {
    crate::command_card::sha256_hex(crate::audit::canonical_json_for_hash(projection).as_bytes())
}

fn earliest_deadline(
    first: Option<DateTime<Utc>>,
    second: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    match (first, second) {
        (Some(first), Some(second)) => Some(first.min(second)),
        (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
        (None, None) => None,
    }
}

#[derive(Debug, Error)]
pub enum BoundaryAuthorizationError {
    #[error("task authorization boundary type does not match the operation")]
    BoundaryMismatch,
    #[error("task authorization document does not match the boundary operation")]
    EnvelopeMismatch,
    #[error("verified provenance requires a strict schema-v2 task envelope")]
    SchemaV2Required,
    #[error("trusted task authorization context is missing")]
    MissingTrustedContext,
    #[error("invalid trusted task authorization context: {0}")]
    InvalidTrustedContext(&'static str),
    #[error("task boundary decision refused the transition")]
    DecisionDenied { assessment: Box<BoundaryAssessment> },
    #[error("task boundary requires approval from its typed approval channel")]
    ApprovalRequired,
    #[error("task boundary approval does not bind this exact operation")]
    ApprovalMismatch,
    #[error(transparent)]
    Receipt(#[from] ReceiptV2Error),
    #[error("provenance authorization receipt was already consumed")]
    Replayed,
    #[error("provenance authorization receipt is reserved; retry after {retry_after_ms} ms")]
    ReplayBusy { retry_after_ms: u64 },
    #[error(transparent)]
    ReplayStore(#[from] ReplayStoreError),
}

impl BoundaryAuthorizationError {
    pub fn assessment(&self) -> Option<&BoundaryAssessment> {
        match self {
            Self::DecisionDenied { assessment } => Some(assessment),
            _ => None,
        }
    }
}

enum PendingReplayAuthorization {
    NotRequired,
    Required(crate::task::VerifiedProvenanceEvidence),
}

/// A successful pure decision held before the irreversible transition.
///
/// This value is non-cloneable and non-serializable. It is not yet permission
/// to perform the effect: a required receipt set must first be atomically
/// consumed from the replay store.
#[must_use = "a pending task authorization must be consumed immediately before the side effect"]
pub struct PendingBoundaryAuthorization<B: BoundaryMarker> {
    assessment: BoundaryAssessment,
    replay: PendingReplayAuthorization,
    approval_required: bool,
    approval_satisfied: bool,
    approval_not_after: Option<DateTime<Utc>>,
    operation_binding_sha256: String,
    marker: PhantomData<fn() -> B>,
}

impl<B: BoundaryMarker> PendingBoundaryAuthorization<B> {
    pub fn assessment(&self) -> &BoundaryAssessment {
        &self.assessment
    }

    /// Check the exact operation binding before consuming replay state.
    /// Side-effect adapters use this to reject internal operation swaps without
    /// burning an otherwise valid one-time receipt.
    pub fn binds_operation(&self, operation: &BoundaryOperation<'_>) -> bool {
        operation.boundary == B::BOUNDARY
            && self.operation_binding_sha256 == operation_binding_digest(operation)
    }

    pub fn requires_replay(&self) -> bool {
        matches!(&self.replay, PendingReplayAuthorization::Required(_))
    }

    pub fn requires_approval(&self) -> bool {
        self.approval_required && !self.approval_satisfied
    }

    /// Atomically consume replay state and mint the only token an effect API
    /// may accept. A not-required decision deliberately does not touch the
    /// store, so store failure can only block policy-required provenance.
    pub fn consume(
        self,
        replay_store: &dyn ReplayStore,
        now: DateTime<Utc>,
    ) -> Result<TaskBoundaryPermit<B>, BoundaryAuthorizationError> {
        self.consume_inner(Some(replay_store), now)
    }

    /// Check the exact operation before touching replay state, then consume it.
    /// This is the defensive last seam for callers whose operation is rebuilt
    /// from live side-effect inputs after the pending authorization was made.
    pub fn consume_for_operation(
        self,
        operation: &BoundaryOperation<'_>,
        replay_store: &dyn ReplayStore,
        now: DateTime<Utc>,
    ) -> Result<TaskBoundaryPermit<B>, BoundaryAuthorizationError> {
        if !self.binds_operation(operation) {
            return Err(BoundaryAuthorizationError::EnvelopeMismatch);
        }
        self.consume(replay_store, now)
    }

    /// Consume using Tirith's durable default ledger. The ledger is resolved
    /// lazily only when this particular authorization carries verified
    /// receipts, so receipt-less policy paths cannot fail due to state-dir or
    /// replay-store availability.
    pub fn consume_default(
        self,
        now: DateTime<Utc>,
    ) -> Result<TaskBoundaryPermit<B>, BoundaryAuthorizationError> {
        if self.requires_approval() {
            return Err(BoundaryAuthorizationError::ApprovalRequired);
        }
        if !self.requires_replay() {
            return self.consume_inner(None, now);
        }
        let replay_store = DurableReplayStore::from_default_state_dir()?;
        self.consume_inner(Some(&replay_store), now)
    }

    /// Default-ledger counterpart of [`Self::consume_for_operation`]. The
    /// binding check happens before the durable ledger is resolved or written.
    pub fn consume_default_for_operation(
        self,
        operation: &BoundaryOperation<'_>,
        now: DateTime<Utc>,
    ) -> Result<TaskBoundaryPermit<B>, BoundaryAuthorizationError> {
        if !self.binds_operation(operation) {
            return Err(BoundaryAuthorizationError::EnvelopeMismatch);
        }
        self.consume_default(now)
    }

    /// Reserve required replay identities without consuming them. The returned
    /// value remains abortable while the caller completes every other fallible
    /// pre-write preparation. Its `commit_at_effect` method is the sole final
    /// transition from a reservation to an effect-capable permit.
    pub fn reserve_default_for_operation(
        self,
        operation: &BoundaryOperation<'_>,
        now: DateTime<Utc>,
    ) -> Result<ReservedBoundaryAuthorization<B>, BoundaryAuthorizationError> {
        if !self.binds_operation(operation) {
            return Err(BoundaryAuthorizationError::EnvelopeMismatch);
        }
        if self.approval_required && !self.approval_satisfied {
            return Err(BoundaryAuthorizationError::ApprovalRequired);
        }
        let operation_binding_sha256 = self.operation_binding_sha256;
        let approval_not_after = self.approval_not_after;
        if approval_not_after.is_some_and(|deadline| now >= deadline) {
            return Err(ReplayStoreError::Expired.into());
        }
        let (verified_receipts, boundary_operation_sha256, receipt_not_after, replay) = match self
            .replay
        {
            PendingReplayAuthorization::NotRequired => (
                0,
                BTreeSet::new(),
                None,
                ReservedReplayAuthorization::NotRequired,
            ),
            PendingReplayAuthorization::Required(evidence) => {
                let not_after = evidence
                    .validated_receipts()
                    .iter()
                    .map(crate::task::ValidatedReceiptV2::expires_at)
                    .min()
                    .ok_or(ReceiptV2Error::InvalidAuthorizationSet)?;
                if now >= not_after {
                    return Err(ReplayStoreError::Expired.into());
                }
                let store = DurableReplayStore::from_default_state_dir()?;
                let reservation = match store.reserve_batch(evidence.validated_receipts(), now)? {
                    ReplayReservationOutcome::Reserved(reservation) => reservation,
                    ReplayReservationOutcome::Busy { retry_after_ms } => {
                        return Err(BoundaryAuthorizationError::ReplayBusy { retry_after_ms })
                    }
                    ReplayReservationOutcome::Replayed => {
                        return Err(BoundaryAuthorizationError::Replayed)
                    }
                };
                (
                    evidence.validated_receipts().len(),
                    evidence.boundary_operation_digests().clone(),
                    Some(not_after),
                    ReservedReplayAuthorization::Required { store, reservation },
                )
            }
        };
        let not_after = earliest_deadline(receipt_not_after, approval_not_after);
        if not_after.is_some_and(|deadline| now >= deadline) {
            if let ReservedReplayAuthorization::Required { store, reservation } = &replay {
                let _ = store.abort_reservation(reservation);
            }
            return Err(ReplayStoreError::Expired.into());
        }
        Ok(ReservedBoundaryAuthorization {
            operation_binding_sha256,
            boundary_operation_sha256,
            verified_receipts,
            not_after,
            replay,
            marker: PhantomData,
        })
    }

    fn consume_inner(
        self,
        replay_store: Option<&dyn ReplayStore>,
        now: DateTime<Utc>,
    ) -> Result<TaskBoundaryPermit<B>, BoundaryAuthorizationError> {
        if self.approval_required && !self.approval_satisfied {
            return Err(BoundaryAuthorizationError::ApprovalRequired);
        }
        let approval_not_after = self.approval_not_after;
        if approval_not_after.is_some_and(|deadline| now >= deadline) {
            return Err(ReplayStoreError::Expired.into());
        }
        let (verified_receipts, boundary_operation_sha256, receipt_not_after) = match self.replay {
            PendingReplayAuthorization::NotRequired => (0, BTreeSet::new(), None),
            PendingReplayAuthorization::Required(evidence) => {
                let replay_store = replay_store.ok_or_else(|| {
                    ReplayStoreError::Unavailable(
                        "required replay store was not provided".to_string(),
                    )
                })?;
                match replay_store.consume_batch(evidence.validated_receipts(), now)? {
                    ReplayOutcome::Recorded => {}
                    ReplayOutcome::Replayed => return Err(BoundaryAuthorizationError::Replayed),
                }
                (
                    evidence.validated_receipts().len(),
                    evidence.boundary_operation_digests().clone(),
                    evidence
                        .validated_receipts()
                        .iter()
                        .map(crate::task::ValidatedReceiptV2::expires_at)
                        .min(),
                )
            }
        };
        let not_after = earliest_deadline(receipt_not_after, approval_not_after);
        if not_after.is_some_and(|deadline| now >= deadline) {
            return Err(ReplayStoreError::Expired.into());
        }
        Ok(TaskBoundaryPermit {
            operation_binding_sha256: self.operation_binding_sha256,
            boundary_operation_sha256,
            verified_receipts,
            not_after,
            marker: PhantomData,
        })
    }
}

enum ReservedReplayAuthorization {
    NotRequired,
    Required {
        store: DurableReplayStore,
        reservation: ReplayReservation,
    },
}

/// A replay lease held while the caller prepares a side effect.
///
/// This type is non-cloneable and non-serializable. `abort` releases an unused
/// lease; `commit_at_effect` consumes it and mints the typed one-shot permit.
#[must_use = "a reserved task authorization must be committed or aborted"]
pub struct ReservedBoundaryAuthorization<B: BoundaryMarker> {
    operation_binding_sha256: String,
    boundary_operation_sha256: BTreeSet<String>,
    verified_receipts: usize,
    not_after: Option<DateTime<Utc>>,
    replay: ReservedReplayAuthorization,
    marker: PhantomData<fn() -> B>,
}

impl<B: BoundaryMarker> ReservedBoundaryAuthorization<B> {
    pub fn binds_operation(&self, operation: &BoundaryOperation<'_>) -> bool {
        operation.boundary == B::BOUNDARY
            && self.operation_binding_sha256 == operation_binding_digest(operation)
    }

    /// Release a reservation after a locally proven zero-byte outcome.
    pub fn abort(self) -> Result<(), BoundaryAuthorizationError> {
        match self.replay {
            ReservedReplayAuthorization::NotRequired => Ok(()),
            ReservedReplayAuthorization::Required { store, reservation } => {
                store.abort_reservation(&reservation)?;
                Ok(())
            }
        }
    }

    /// Commit replay immediately at the effect seam. Exact operation and
    /// minimum-expiry validation happen before the durable commit; the store
    /// then samples a fresh clock under its lock before marking receipts used.
    pub fn commit_at_effect(
        self,
        operation: &BoundaryOperation<'_>,
        now: DateTime<Utc>,
    ) -> Result<TaskBoundaryPermit<B>, BoundaryAuthorizationError> {
        if !self.binds_operation(operation) {
            self.abort()?;
            return Err(BoundaryAuthorizationError::EnvelopeMismatch);
        }
        if self.not_after.is_some_and(|not_after| now >= not_after) {
            self.abort()?;
            return Err(ReplayStoreError::Expired.into());
        }
        if let ReservedReplayAuthorization::Required { store, reservation } = &self.replay {
            match store.commit_reservation(reservation, now) {
                Ok(ReplayOutcome::Recorded) => {}
                Ok(ReplayOutcome::Replayed) => return Err(BoundaryAuthorizationError::Replayed),
                Err(error) => {
                    // A failed commit did not authorize an effect. Release the
                    // still-live lease when possible; a crash or cleanup error
                    // remains recoverable through its bounded expiry.
                    if let Err(abort_error) = store.abort_reservation(reservation) {
                        return Err(abort_error.into());
                    }
                    return Err(error.into());
                }
            }
        }
        Ok(TaskBoundaryPermit {
            operation_binding_sha256: self.operation_binding_sha256,
            boundary_operation_sha256: self.boundary_operation_sha256,
            verified_receipts: self.verified_receipts,
            not_after: self.not_after,
            marker: PhantomData,
        })
    }
}

impl<B: ApprovalCapableBoundary> PendingBoundaryAuthorization<B> {
    fn attach_approval(
        mut self,
        evidence: BoundaryApprovalEvidence<B>,
    ) -> Result<Self, BoundaryAuthorizationError> {
        if evidence.operation_binding_sha256 != self.operation_binding_sha256
            || evidence.channel_binding_sha256.is_empty()
            || evidence.nonce.is_empty()
        {
            return Err(BoundaryAuthorizationError::ApprovalMismatch);
        }
        self.approval_satisfied = true;
        self.approval_not_after = earliest_deadline(self.approval_not_after, evidence.not_after);
        Ok(self)
    }
}

impl PendingBoundaryAuthorization<PackageInstallPreparationBoundary> {
    /// Attach a native-authority-verified package-install channel capability.
    /// No boolean or operation-only evidence API exists.
    pub fn with_package_install_approval(
        self,
        approval: PackageInstallApprovalChannel,
    ) -> Result<Self, BoundaryAuthorizationError> {
        self.attach_approval(approval.evidence)
    }
}

impl PendingBoundaryAuthorization<PackageManagerExecutionBoundary> {
    pub fn package_manager_approval_challenge(&self) -> PackageManagerApprovalChallenge {
        PackageManagerApprovalChallenge {
            operation_binding_sha256: self.operation_binding_sha256.clone(),
        }
    }

    /// Attach a real interactive or unattended package-manager confirmation.
    pub fn with_package_manager_approval(
        self,
        approval: PackageManagerApprovalChannel,
    ) -> Result<Self, BoundaryAuthorizationError> {
        self.attach_approval(approval.evidence)
    }
}

/// Unforgeable, boundary-typed authorization for exactly one side-effect API.
///
/// Fields and constructor are private; the type implements neither `Clone` nor
/// serde. The eventual side-effect function must take it by value.
#[must_use = "the task boundary permit must be consumed by its side-effect API"]
pub struct TaskBoundaryPermit<B: BoundaryMarker> {
    operation_binding_sha256: String,
    boundary_operation_sha256: BTreeSet<String>,
    verified_receipts: usize,
    not_after: Option<DateTime<Utc>>,
    marker: PhantomData<fn() -> B>,
}

/// Crate-internal retained authorization used by a compound side-effect
/// transaction. It preserves the permit's earliest deadline and exact
/// operation binding so every individual effect can revalidate immediately
/// before it happens.
pub(crate) struct TaskBoundaryEffectLease<B: BoundaryMarker> {
    operation_binding_sha256: String,
    _boundary_operation_sha256: BTreeSet<String>,
    _verified_receipts: usize,
    not_after: Option<DateTime<Utc>>,
    marker: PhantomData<fn() -> B>,
}

impl<B: BoundaryMarker> TaskBoundaryEffectLease<B> {
    pub(crate) fn authorize_effect_at(
        &self,
        operation: &BoundaryOperation<'_>,
        now: DateTime<Utc>,
    ) -> Result<(), BoundaryAuthorizationError> {
        if operation.boundary != B::BOUNDARY
            || self.operation_binding_sha256 != operation_binding_digest(operation)
        {
            return Err(BoundaryAuthorizationError::EnvelopeMismatch);
        }
        if self.not_after.is_some_and(|not_after| now >= not_after) {
            return Err(ReplayStoreError::Expired.into());
        }
        Ok(())
    }
}

impl<B: BoundaryMarker> TaskBoundaryPermit<B> {
    pub fn binds_operation(&self, operation: &BoundaryOperation<'_>) -> bool {
        operation.boundary == B::BOUNDARY
            && self.operation_binding_sha256 == operation_binding_digest(operation)
    }

    pub fn verified_receipt_count(&self) -> usize {
        self.verified_receipts
    }

    pub fn boundary_operation_digests(&self) -> &BTreeSet<String> {
        &self.boundary_operation_sha256
    }

    /// Consume the typed permit at the final effect and reject an operation
    /// swap or a receipt set whose earliest expiry has been reached.
    pub fn authorize_effect_at(
        self,
        operation: &BoundaryOperation<'_>,
        now: DateTime<Utc>,
    ) -> Result<(), BoundaryAuthorizationError> {
        self.into_effect_lease_at(operation, now).map(|_| ())
    }

    pub(crate) fn into_effect_lease_at(
        self,
        operation: &BoundaryOperation<'_>,
        now: DateTime<Utc>,
    ) -> Result<TaskBoundaryEffectLease<B>, BoundaryAuthorizationError> {
        let lease = TaskBoundaryEffectLease {
            operation_binding_sha256: self.operation_binding_sha256,
            _boundary_operation_sha256: self.boundary_operation_sha256,
            _verified_receipts: self.verified_receipts,
            not_after: self.not_after,
            marker: PhantomData,
        };
        lease.authorize_effect_at(operation, now)?;
        Ok(lease)
    }
}

/// First-stage authorization challenge for an exact owned-boundary operation.
///
/// This value is non-cloneable and non-serializable. Its public projection
/// slice contains only canonical identifiers and hashes, so an issuer can sign
/// it without receiving raw task content, commands, acquisition locators, or
/// private decision evidence. The exact same internally held projections are
/// used by [`Self::verify_receipts`]; callers never reconstruct them.
#[must_use = "an authorization challenge must be completed before the boundary can proceed"]
pub struct BoundaryAuthorizationChallenge<B: BoundaryMarker> {
    authorization_projections: Vec<TaskAuthorizationProjectionV1>,
    receiptless_assessment: Option<BoundaryAssessment>,
    envelope: TaskEnvelopeInput,
    provenance: Vec<AssignedProvenance>,
    gate: TaskGatePolicy,
    analysis: TaskAnalysisContext,
    boundary_effects: BTreeSet<CommandEffectKind>,
    operation_binding_sha256: String,
    marker: PhantomData<fn() -> B>,
}

impl<B: BoundaryMarker> BoundaryAuthorizationChallenge<B> {
    /// Exact safe projections the receipt issuer must sign, one per
    /// source/action pair. An empty slice means policy does not require
    /// verified provenance for this operation.
    pub fn authorization_projections(&self) -> &[TaskAuthorizationProjectionV1] {
        &self.authorization_projections
    }

    pub fn requires_verified_provenance(&self) -> bool {
        self.receiptless_assessment.is_none()
    }

    /// Verify externally delivered receipts against the exact projections
    /// held by this challenge. This is pure: replay is consumed only by the
    /// returned pending authorization immediately before the side effect.
    pub fn verify_receipts(
        self,
        receipts: &[ProvenanceReceiptV2],
        trusted_keys: &BTreeMap<String, [u8; 32]>,
        now: DateTime<Utc>,
    ) -> Result<PendingBoundaryAuthorization<B>, BoundaryAuthorizationError> {
        if let Some(assessment) = self.receiptless_assessment {
            return pending_from_assessment::<B>(
                assessment,
                PendingReplayAuthorization::NotRequired,
                self.operation_binding_sha256,
            );
        }

        let evidence =
            verify_authorization_set(receipts, &self.authorization_projections, trusted_keys, now)?;
        let mut provenance = self.provenance;
        for assigned in &mut provenance {
            // Diagnostic rendering only. The decision's authorization boolean
            // comes exclusively from the private evidence argument below.
            assigned.receipt_status = ReceiptStatus::VerifiedV2;
        }
        let decision = decide_with_verified_evidence(
            &self.envelope,
            provenance,
            &self.gate,
            BoundaryCapability::Enforceable,
            B::BOUNDARY,
            &self.boundary_effects,
            &self.analysis,
            &evidence,
        );
        let assessment = BoundaryAssessment {
            boundary: B::BOUNDARY,
            outcome: outcome_for(&decision, &self.gate),
            decision,
            rejections: Vec::new(),
        };
        pending_from_assessment::<B>(
            assessment,
            PendingReplayAuthorization::Required(evidence),
            self.operation_binding_sha256,
        )
    }

    /// Complete a challenge that does not require verified provenance. This
    /// exists for receipt-less compatibility paths and fails closed if called
    /// for a receipt-bearing challenge.
    pub fn complete_without_receipts(
        self,
    ) -> Result<PendingBoundaryAuthorization<B>, BoundaryAuthorizationError> {
        if self.receiptless_assessment.is_none() {
            return Err(BoundaryAuthorizationError::MissingTrustedContext);
        }
        self.verify_receipts(&[], &BTreeMap::new(), Utc::now())
    }
}

fn pending_from_assessment<B: BoundaryMarker>(
    assessment: BoundaryAssessment,
    replay: PendingReplayAuthorization,
    operation_binding_sha256: String,
) -> Result<PendingBoundaryAuthorization<B>, BoundaryAuthorizationError> {
    let approval_required = match &assessment.outcome {
        BoundaryOutcome::Allow => false,
        BoundaryOutcome::Deny { .. } => {
            return Err(BoundaryAuthorizationError::DecisionDenied {
                assessment: Box::new(assessment),
            });
        }
        BoundaryOutcome::RequireApproval { .. } => {
            if !boundary_has_approval_channel(B::BOUNDARY) {
                return Err(BoundaryAuthorizationError::DecisionDenied {
                    assessment: Box::new(assessment),
                });
            }
            true
        }
    };
    Ok(PendingBoundaryAuthorization {
        assessment,
        replay,
        approval_required,
        approval_satisfied: false,
        approval_not_after: None,
        operation_binding_sha256,
        marker: PhantomData,
    })
}

fn boundary_has_approval_channel(boundary: OwnedBoundary) -> bool {
    matches!(
        boundary,
        OwnedBoundary::PackageInstallPreparation | OwnedBoundary::PackageManagerExecution
    )
}

/// Derive an exact first-stage challenge without accepting or verifying any
/// receipt. Invalid or absent receipts remain irrelevant when policy does not
/// require provenance. When it does, schema v2 and trusted adapter-owned source
/// identities are mandatory.
pub fn derive_boundary_authorization_challenge<B: BoundaryMarker>(
    operation: &BoundaryOperation<'_>,
    document: &TaskEnvelopeDocument,
    gate: &TaskGatePolicy,
    analysis: &TaskAnalysisContext,
    projection_context: Option<&BoundaryAuthorizationProjectionContext<'_>>,
) -> Result<BoundaryAuthorizationChallenge<B>, BoundaryAuthorizationError> {
    if operation.boundary != B::BOUNDARY {
        return Err(BoundaryAuthorizationError::BoundaryMismatch);
    }
    if operation.envelope != &document.envelope {
        return Err(BoundaryAuthorizationError::EnvelopeMismatch);
    }

    let provenance_required = gate.mode == TaskGateMode::Enforce
        && effective_operation_effects(operation, analysis)
            .iter()
            .any(|effect| gate.effects_requiring_verified_provenance.contains(effect));
    let operation_binding_sha256 = operation_binding_digest(operation);

    if !provenance_required {
        let assessment = evaluate_with_analysis_context(operation, gate, analysis);
        let provenance = operation
            .envelope
            .sources
            .iter()
            .map(|source| assign_provenance(source, operation.adapter, None, None))
            .collect();
        return Ok(BoundaryAuthorizationChallenge {
            authorization_projections: Vec::new(),
            receiptless_assessment: Some(assessment),
            envelope: operation.envelope.clone(),
            provenance,
            gate: gate.clone(),
            analysis: analysis.clone(),
            boundary_effects: operation.boundary_effects.clone(),
            operation_binding_sha256,
            marker: PhantomData,
        });
    }

    if document.version != 2 {
        return Err(BoundaryAuthorizationError::SchemaV2Required);
    }
    if !validate_envelope(operation.envelope).is_empty() {
        return Err(BoundaryAuthorizationError::InvalidTrustedContext(
            "invalid_envelope",
        ));
    }
    let task_id = operation
        .envelope
        .task_id
        .as_deref()
        .ok_or(BoundaryAuthorizationError::SchemaV2Required)?;
    validate_receipt_context_identifier("task_id", task_id)?;
    if operation.envelope.sources.is_empty() || operation.envelope.actions.is_empty() {
        return Err(BoundaryAuthorizationError::InvalidTrustedContext(
            "empty_source_or_action_set",
        ));
    }
    if document.source_ids.len() != operation.envelope.sources.len()
        || document.authorizations.len() > MAX_AUTHORIZATION_RECEIPTS
    {
        return Err(BoundaryAuthorizationError::InvalidTrustedContext(
            "document_cardinality",
        ));
    }

    let projection_context =
        projection_context.ok_or(BoundaryAuthorizationError::MissingTrustedContext)?;
    if !projection_context.enforcement.matches_task_gate(gate) {
        return Err(BoundaryAuthorizationError::InvalidTrustedContext(
            "task_gate_projection",
        ));
    }
    if projection_context.action_identities.len() != operation.envelope.actions.len() {
        return Err(BoundaryAuthorizationError::InvalidTrustedContext(
            "action_identity_cardinality",
        ));
    }

    let mut source_contexts = BTreeMap::new();
    for source in projection_context.sources {
        if source_contexts
            .insert(source.source_id.as_str(), source)
            .is_some()
        {
            return Err(BoundaryAuthorizationError::InvalidTrustedContext(
                "duplicate_source_context",
            ));
        }
    }
    if source_contexts.len() != operation.envelope.sources.len() {
        return Err(BoundaryAuthorizationError::InvalidTrustedContext(
            "source_context_cardinality",
        ));
    }

    let per_action = operation
        .envelope
        .actions
        .iter()
        .map(|action| infer_effects_detailed_with_context(action, analysis))
        .collect::<Vec<_>>();
    let mut expected = Vec::with_capacity(
        operation
            .envelope
            .sources
            .len()
            .saturating_mul(operation.envelope.actions.len()),
    );
    let mut provenance = Vec::with_capacity(operation.envelope.sources.len());
    for (source_index, source) in operation.envelope.sources.iter().enumerate() {
        let source_id = document.source_ids[source_index]
            .as_deref()
            .ok_or(BoundaryAuthorizationError::SchemaV2Required)?;
        validate_receipt_context_identifier("source_id", source_id)?;
        let source_context = source_contexts.get(source_id).ok_or(
            BoundaryAuthorizationError::InvalidTrustedContext("source_identity"),
        )?;
        let effective_source = source_context
            .adapter
            .permitted_source(source.claimed_source);
        provenance.push(assign_provenance(
            source,
            source_context.adapter,
            None,
            None,
        ));
        for (action_index, action) in operation.envelope.actions.iter().enumerate() {
            let derived = &per_action[action_index];
            expected.push(TaskAuthorizationProjectionV1::new(
                task_id,
                source_id,
                effective_source,
                source.content.as_bytes(),
                source_context.adapter,
                &source_context.canonical_acquisition_identity,
                operation.boundary,
                action_index,
                &projection_context.action_identities[action_index],
                action,
                &operation.envelope.requested_effects,
                &derived.effects,
                &operation.boundary_effects,
                derived.complete,
                projection_context.enforcement,
            )?);
        }
    }

    Ok(BoundaryAuthorizationChallenge {
        authorization_projections: expected,
        receiptless_assessment: None,
        envelope: operation.envelope.clone(),
        provenance,
        gate: gate.clone(),
        analysis: analysis.clone(),
        boundary_effects: operation.boundary_effects.clone(),
        operation_binding_sha256,
        marker: PhantomData,
    })
}

/// Compatibility one-shot wrapper over the public two-stage challenge API.
/// Projection derivation remains centralized in
/// [`derive_boundary_authorization_challenge`]. This function never consumes
/// replay state.
pub fn prepare_boundary_authorization<B: BoundaryMarker>(
    operation: &BoundaryOperation<'_>,
    document: &TaskEnvelopeDocument,
    gate: &TaskGatePolicy,
    analysis: &TaskAnalysisContext,
    trusted_context: Option<&TrustedBoundaryReceiptContext<'_>>,
) -> Result<PendingBoundaryAuthorization<B>, BoundaryAuthorizationError> {
    let projection_context = trusted_context.map(TrustedBoundaryReceiptContext::projection_context);
    let challenge = derive_boundary_authorization_challenge::<B>(
        operation,
        document,
        gate,
        analysis,
        projection_context.as_ref(),
    )?;
    match trusted_context {
        Some(context) => {
            challenge.verify_receipts(&document.authorizations, context.trusted_keys, context.now)
        }
        None => challenge.complete_without_receipts(),
    }
}

/// Prepare a Tirith-derived operation when no external schema-v2 task
/// document was supplied.
///
/// This compatibility path is intentionally fail-closed: as soon as the
/// effective policy requires verified provenance for any operation effect,
/// challenge derivation returns [`BoundaryAuthorizationError::SchemaV2Required`]
/// and no permit can be minted. Production callers use this helper while the
/// optional authorization provider is absent, rather than bypassing the typed
/// permit boundary with the older assessment-only API.
pub fn prepare_locally_derived_boundary_authorization<B: BoundaryMarker>(
    operation: &BoundaryOperation<'_>,
    gate: &TaskGatePolicy,
    analysis: &TaskAnalysisContext,
) -> Result<PendingBoundaryAuthorization<B>, BoundaryAuthorizationError> {
    let document = TaskEnvelopeDocument::from_legacy(operation.envelope.clone());
    derive_boundary_authorization_challenge::<B>(operation, &document, gate, analysis, None)?
        .complete_without_receipts()
}

fn effective_operation_effects(
    operation: &BoundaryOperation<'_>,
    analysis: &TaskAnalysisContext,
) -> BTreeSet<CommandEffectKind> {
    let mut effects = operation.boundary_effects.clone();
    for action in &operation.envelope.actions {
        effects.extend(infer_effects_detailed_with_context(action, analysis).effects);
    }
    effects
}

fn operation_binding_digest(operation: &BoundaryOperation<'_>) -> String {
    let projection = serde_json::json!({
        "projection_version": 1,
        "boundary": operation.boundary.token(),
        "adapter": operation.adapter,
        "envelope": operation.envelope,
        "boundary_effects": operation.boundary_effects,
    });
    crate::command_card::sha256_hex(crate::audit::canonical_json_for_hash(&projection).as_bytes())
}

/// Evaluate one owned transition.
///
/// Deterministic and side-effect-free: no file is opened, no host is contacted,
/// nothing is recorded. The caller owns the audit write and the refusal.
pub fn evaluate(operation: &BoundaryOperation<'_>, gate: &TaskGatePolicy) -> BoundaryAssessment {
    evaluate_with_analysis_context(operation, gate, &TaskAnalysisContext::default())
}

/// Evaluate one owned transition with runtime facts supplied by the trusted
/// boundary. The envelope cannot select these values: callers use this entry
/// point only after they have resolved the effective shell, working directory,
/// and policy that will govern the transition.
pub fn evaluate_with_analysis_context(
    operation: &BoundaryOperation<'_>,
    gate: &TaskGatePolicy,
    analysis: &TaskAnalysisContext,
) -> BoundaryAssessment {
    let rejections = validate_envelope(operation.envelope);
    let provenance = operation
        .envelope
        .sources
        .iter()
        .map(|source| assign_provenance(source, operation.adapter, None, None))
        .collect::<Vec<_>>();

    // `Enforceable` is the honest value here and only here: these sites hold
    // the transition open and can still refuse it.
    let decision = decide_with_boundary_effects_and_context(
        operation.envelope,
        provenance,
        gate,
        BoundaryCapability::Enforceable,
        &operation.boundary_effects,
        analysis,
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
        if !decision.unrequested_effects.is_empty() {
            let effects = decision
                .unrequested_effects
                .iter()
                .map(|effect| effect_token(*effect))
                .collect::<Vec<_>>()
                .join(", ");
            return BoundaryOutcome::Deny {
                reason: format!(
                    "task action implies effects omitted from requested_effects: {effects}"
                ),
            };
        }
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

/// Exact, side-effect-free identity of the fixed cloaking probe transaction.
///
/// Construction performs URL syntax and literal-IP validation only. DNS is
/// deliberately deferred until a [`TaskBoundaryPermit`] for
/// [`FetchCloakingBoundary`] reaches the cloaking network sink. The ordered
/// probe set is part of the binding so a permit for fewer or different
/// user-agent requests cannot authorize the real operation.
pub struct FetchCloakingOperationBinding {
    envelope: TaskEnvelopeInput,
}

impl FetchCloakingOperationBinding {
    pub fn operation(&self) -> BoundaryOperation<'_> {
        BoundaryOperation {
            boundary: OwnedBoundary::FetchCloaking,
            envelope: &self.envelope,
            adapter: IngressAdapter::Unattributed,
            boundary_effects: [CommandEffectKind::NetworkEgress].into_iter().collect(),
        }
    }
}

/// Bind a cloaking fetch to its canonical URL and exact ordered probe set.
pub fn fetch_cloaking_operation_binding(
    url: &str,
    probes: &[(&str, &str)],
) -> Result<FetchCloakingOperationBinding, String> {
    let parsed = crate::url_validate::validate_fetch_url_syntax(url)?;
    if probes.is_empty() || probes.len() > crate::task::MAX_ACTIONS {
        return Err(format!(
            "cloaking probe set must contain 1..={} entries",
            crate::task::MAX_ACTIONS
        ));
    }
    if probes.iter().any(|(name, user_agent)| {
        name.is_empty()
            || user_agent.is_empty()
            || name.len() > crate::task::MAX_STRING_BYTES
            || user_agent.len() > crate::task::MAX_STRING_BYTES
    }) {
        return Err("cloaking probe identity is empty or exceeds task bounds".to_string());
    }

    let projection = serde_json::json!({
        "projection_version": 1,
        "canonical_url": parsed.as_str(),
        "ordered_probes": probes.iter().map(|(name, user_agent)| serde_json::json!({
            "name": name,
            "user_agent": user_agent,
        })).collect::<Vec<_>>(),
    });
    let projection_sha256 = crate::command_card::sha256_hex(
        crate::audit::canonical_json_for_hash(&projection).as_bytes(),
    );
    let mut source = unattributed_source();
    source.content = format!("tirith-fetch-cloaking:v1:sha256:{projection_sha256}");
    Ok(FetchCloakingOperationBinding {
        envelope: TaskEnvelopeInput {
            task_id: None,
            sources: vec![source],
            actions: Vec::new(),
            requested_effects: BTreeSet::new(),
        },
    })
}

/// Stable identity of the held package-install target selected before resolver
/// or checkpoint side effects. The path itself is represented by a digest so a
/// task receipt never exposes a local filesystem name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageTargetIdentity {
    target_path_sha256: String,
    parent_identity: String,
    target_component: String,
}

impl PackageTargetIdentity {
    pub fn new(
        target_path_sha256: impl Into<String>,
        parent_identity: impl Into<String>,
        target_component: impl Into<String>,
    ) -> Self {
        Self {
            target_path_sha256: target_path_sha256.into(),
            parent_identity: parent_identity.into(),
            target_component: target_component.into(),
        }
    }
}

/// The complete package request that an owned resolver or checkpoint boundary
/// must bind. Keeping the resolver request by reference prevents a caller from
/// accidentally authorizing only its displayed requirements while omitting
/// indexes or resolver allowances.
pub struct PackageOperationBinding<'a> {
    ecosystem: &'a str,
    request: &'a ResolverRequest,
    artifact_origins: &'a [String],
    target: &'a PackageTargetIdentity,
}

impl<'a> PackageOperationBinding<'a> {
    pub fn new(
        ecosystem: &'a str,
        request: &'a ResolverRequest,
        artifact_origins: &'a [String],
        target: &'a PackageTargetIdentity,
    ) -> Self {
        Self {
            ecosystem,
            request,
            artifact_origins,
            target,
        }
    }
}

/// A package argv larger than the task-envelope action ceiling cannot be
/// represented exactly and is therefore rejected rather than truncated.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PackageEnvelopeError {
    #[error(
        "package request has {provided} requirements, exceeding the exact authorization limit of {max}"
    )]
    TooManyRequirements { provided: usize, max: usize },
}

/// Build the exact envelope for a package operation. Every requirement remains
/// a visible action, while the unattributed source carries only a
/// domain-separated digest of the canonical full request projection: raw
/// requirements, registry/index endpoints, broker-only artifact origins,
/// resolver allowances, and held target identity.
pub fn package_envelope(
    binding: &PackageOperationBinding<'_>,
) -> Result<TaskEnvelopeInput, PackageEnvelopeError> {
    if binding.request.requirements.len() > crate::task::MAX_ACTIONS {
        return Err(PackageEnvelopeError::TooManyRequirements {
            provided: binding.request.requirements.len(),
            max: crate::task::MAX_ACTIONS,
        });
    }

    let allowances = &binding.request.allowances;
    let projection = serde_json::json!({
        "binding_version": 1,
        "ecosystem": binding.ecosystem,
        "requirements": binding.request.requirements,
        "index_urls": binding.request.index_urls,
        "artifact_origins": binding.artifact_origins,
        "resolver_allowances": {
            "allow_sdist": allowances.allow_sdist,
            "allow_vcs": allowances.allow_vcs,
            "allow_editable": allowances.allow_editable,
            "allow_local_path": allowances.allow_local_path,
            "allow_direct_url": allowances.allow_direct_url,
            "allow_untrusted_tool": allowances.allow_untrusted_tool,
        },
        "target": {
            "path_sha256": binding.target.target_path_sha256,
            "parent_identity": binding.target.parent_identity,
            "component": binding.target.target_component,
        },
    });
    let binding_sha256 = crate::command_card::sha256_hex(
        crate::audit::canonical_json_for_hash(&projection).as_bytes(),
    );
    let mut source = unattributed_source();
    source.content = format!("tirith-package-operation:v1:sha256:{binding_sha256}");

    Ok(TaskEnvelopeInput {
        task_id: None,
        sources: vec![source],
        actions: binding
            .request
            .requirements
            .iter()
            .map(|package| ProposedAction::PackageInstall {
                ecosystem: binding.ecosystem.to_string(),
                package: package.clone(),
            })
            .collect(),
        requested_effects: BTreeSet::new(),
    })
}

/// Complete, privacy-preserving identity of a Tirith-owned configuration write.
/// The path remains visible as the action so effect inference can classify
/// sensitive destinations; every other binding is represented only by its
/// already-domain-separated identity or digest.
pub struct ConfigWriteOperationBinding<'a> {
    destination: &'a str,
    root_identity_sha256: &'a str,
    destination_identity_sha256: &'a str,
    content_sha256: &'a str,
    preimage_sha256: Option<&'a str>,
    overwrite: bool,
    policy_identity: &'a str,
    policy_change: bool,
}

impl<'a> ConfigWriteOperationBinding<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        destination: &'a str,
        root_identity_sha256: &'a str,
        destination_identity_sha256: &'a str,
        content_sha256: &'a str,
        preimage_sha256: Option<&'a str>,
        overwrite: bool,
        policy_identity: &'a str,
        policy_change: bool,
    ) -> Self {
        Self {
            destination,
            root_identity_sha256,
            destination_identity_sha256,
            content_sha256,
            preimage_sha256,
            overwrite,
            policy_identity,
            policy_change,
        }
    }
}

/// An envelope for a Tirith-owned configuration write.
///
/// The plan's prose names an `AgentConfigWrite` effect. No such
/// [`CommandEffectKind`] exists, and minting one would change the serde wire
/// tokens of the policy's effect sets for no gain, so the write is described by
/// the effects [`crate::task::infer_effects_detailed`] already derives for
/// [`ProposedAction::ConfigWrite`]: filesystem write, persistence change, and
/// secret read when the path is sensitive. The source content is a
/// domain-separated digest of the complete publication projection, so changing
/// the held root/destination, prior leaf identity/digest, output bytes,
/// overwrite mode, policy snapshot, or PolicyChange classification changes the
/// task-operation binding without exposing those values to receipt projections.
pub fn config_write_envelope(binding: &ConfigWriteOperationBinding<'_>) -> TaskEnvelopeInput {
    let projection = serde_json::json!({
        "binding_version": 2,
        "root_identity_sha256": binding.root_identity_sha256,
        "destination_identity_sha256": binding.destination_identity_sha256,
        "content_sha256": binding.content_sha256,
        "preimage_sha256": binding.preimage_sha256,
        "overwrite": binding.overwrite,
        "policy_identity": binding.policy_identity,
        "policy_change": binding.policy_change,
    });
    let binding_sha256 = crate::command_card::sha256_hex(
        crate::audit::canonical_json_for_hash(&projection).as_bytes(),
    );
    let mut source = unattributed_source();
    source.content = format!("tirith-config-write-operation:v2:sha256:{binding_sha256}");
    let requested_effects = if binding.policy_change {
        [CommandEffectKind::PolicyChange].into_iter().collect()
    } else {
        BTreeSet::new()
    };
    TaskEnvelopeInput {
        task_id: None,
        sources: vec![source],
        actions: vec![ProposedAction::ConfigWrite {
            path: binding.destination.to_string(),
        }],
        requested_effects,
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
    use chrono::TimeDelta;
    use ed25519_dalek::Signer as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    fn authorization_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-08-17T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn provenance_gate() -> TaskGatePolicy {
        TaskGatePolicy {
            mode: TaskGateMode::Enforce,
            effects_requiring_verified_provenance: [CommandEffectKind::PackageInstall]
                .into_iter()
                .collect(),
            effects_denied_for_untrusted_sources: BTreeSet::new(),
            action_incomplete_analysis: Web3GuardAction::Warn,
        }
    }

    fn enforcement(gate: &TaskGatePolicy) -> EnforcementProjectionV1 {
        let policy = crate::policy::Policy {
            task_gate: gate.clone(),
            ..Default::default()
        };
        EnforcementProjectionV1::new(
            &policy,
            crate::task::SecureProfileFloorProjectionV1::NotApplicable,
            crate::task::GatewayEnforcementProjectionV1::NotApplicable,
            crate::task::ToolIdentityProjectionV1::NotApplicable,
            crate::task::CanonicalCommandProjectionV1::NotApplicable,
            crate::task::ReceiptEffectiveShell::NotApplicable,
            crate::task::ResourceCeilingsProjectionV1 {
                cpu_seconds: Some(30),
                memory_bytes: Some(512 * 1024 * 1024),
                max_processes: Some(64),
                max_open_files: Some(256),
                max_output_bytes: Some(1024 * 1024),
                wall_clock_seconds: Some(60),
                network_egress_allowed: true,
                writable_roots_sha256: "ab".repeat(32),
                allowed_destinations_sha256: "cd".repeat(32),
            },
        )
        .unwrap()
    }

    fn github_source_context() -> TrustedReceiptSourceContext {
        TrustedReceiptSourceContext::from_canonical_acquisition(
            IngressAdapter::GithubIssue,
            "github:owner/repo:issue:1:body",
        )
        .unwrap()
    }

    fn authorization_document() -> TaskEnvelopeDocument {
        let source = github_source_context();
        TaskEnvelopeDocument {
            version: 2,
            envelope: TaskEnvelopeInput {
                task_id: Some("task-1".to_string()),
                sources: vec![TaskSourceInput {
                    claimed_source: crate::task::SourceKind::IssueBody,
                    content: "install packages".to_string(),
                    locator: Some("issue display".to_string()),
                    receipt: None,
                }],
                actions: vec![
                    ProposedAction::PackageInstall {
                        ecosystem: "npm".to_string(),
                        package: "left-pad".to_string(),
                    },
                    ProposedAction::PackageInstall {
                        ecosystem: "npm".to_string(),
                        package: "is-even".to_string(),
                    },
                ],
                requested_effects: BTreeSet::new(),
            },
            shell_claims: vec![
                crate::task_envelope::ShellDialectClaim::Unknown,
                crate::task_envelope::ShellDialectClaim::Unknown,
            ],
            source_ids: vec![Some(source.source_id().to_string())],
            authorizations: Vec::new(),
        }
    }

    fn sign_authorizations(
        document: &TaskEnvelopeDocument,
        boundary: OwnedBoundary,
        boundary_effects: &BTreeSet<CommandEffectKind>,
        action_identities: &[String],
        enforcement: &EnforcementProjectionV1,
    ) -> (
        Vec<crate::task::ProvenanceReceiptV2>,
        BTreeMap<String, [u8; 32]>,
    ) {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[41u8; 32]);
        let public = signing.verifying_key().to_bytes();
        let key_id = crate::command_card::key_id_for_pubkey(&public);
        let analysis = TaskAnalysisContext::default();
        let source = &document.envelope.sources[0];
        let receipts = document
            .envelope
            .actions
            .iter()
            .enumerate()
            .map(|(action_index, action)| {
                let derived = infer_effects_detailed_with_context(action, &analysis);
                let projection = TaskAuthorizationProjectionV1::new(
                    document.envelope.task_id.as_deref().unwrap(),
                    document.source_ids[0].as_deref().unwrap(),
                    crate::task::SourceKind::IssueBody,
                    source.content.as_bytes(),
                    IngressAdapter::GithubIssue,
                    "github:owner/repo:issue:1:body",
                    boundary,
                    action_index,
                    &action_identities[action_index],
                    action,
                    &document.envelope.requested_effects,
                    &derived.effects,
                    boundary_effects,
                    derived.complete,
                    enforcement,
                )
                .unwrap();
                let mut receipt = crate::task::ProvenanceReceiptV2::new_unsigned(
                    &format!("receipt-{action_index}"),
                    &key_id,
                    &projection,
                    authorization_now() - TimeDelta::minutes(1),
                    authorization_now() + TimeDelta::minutes(59),
                    &format!("nonce-{action_index}"),
                )
                .unwrap();
                receipt.signature = crate::command_card::hex_encode(
                    &signing
                        .sign(
                            crate::task::receipt_v2_signing_payload(&receipt)
                                .unwrap()
                                .as_bytes(),
                        )
                        .to_bytes(),
                );
                receipt
            })
            .collect();
        (receipts, BTreeMap::from([(key_id, public)]))
    }

    #[derive(Default)]
    struct AtomicRecordingStore {
        batches: AtomicUsize,
        single_receipts: AtomicUsize,
    }

    impl ReplayStore for AtomicRecordingStore {
        fn consume(
            &self,
            _receipt: &crate::task::ValidatedReceiptV2,
            _now: DateTime<Utc>,
        ) -> Result<ReplayOutcome, ReplayStoreError> {
            self.single_receipts.fetch_add(1, Ordering::SeqCst);
            Ok(ReplayOutcome::Recorded)
        }

        fn consume_batch(
            &self,
            receipts: &[crate::task::ValidatedReceiptV2],
            _now: DateTime<Utc>,
        ) -> Result<ReplayOutcome, ReplayStoreError> {
            assert_eq!(receipts.len(), 2);
            let previous = self.batches.fetch_add(1, Ordering::SeqCst);
            Ok(if previous == 0 {
                ReplayOutcome::Recorded
            } else {
                ReplayOutcome::Replayed
            })
        }
    }

    struct UnavailableStore;

    impl ReplayStore for UnavailableStore {
        fn consume(
            &self,
            _receipt: &crate::task::ValidatedReceiptV2,
            _now: DateTime<Utc>,
        ) -> Result<ReplayOutcome, ReplayStoreError> {
            Err(ReplayStoreError::Unavailable("test".to_string()))
        }

        fn consume_batch(
            &self,
            _receipts: &[crate::task::ValidatedReceiptV2],
            _now: DateTime<Utc>,
        ) -> Result<ReplayOutcome, ReplayStoreError> {
            Err(ReplayStoreError::Unavailable("test".to_string()))
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
    fn cloaking_boundary_binds_the_exact_url_and_ordered_probe_set() {
        let probes = [("browser", "Browser/1"), ("bot", "Bot/1")];
        let binding = fetch_cloaking_operation_binding("https://example.com/a", &probes).unwrap();
        let operation = binding.operation();
        assert_eq!(operation.boundary, OwnedBoundary::FetchCloaking);
        assert_eq!(
            operation.boundary_effects,
            [CommandEffectKind::NetworkEgress].into_iter().collect()
        );
        let pending = prepare_locally_derived_boundary_authorization::<FetchCloakingBoundary>(
            &operation,
            &TaskGatePolicy::default(),
            &TaskAnalysisContext::default(),
        )
        .unwrap();
        let permit = pending.consume_default(authorization_now()).unwrap();

        let other_url = fetch_cloaking_operation_binding("https://example.com/b", &probes).unwrap();
        assert!(!permit.binds_operation(&other_url.operation()));

        let reversed = [("bot", "Bot/1"), ("browser", "Browser/1")];
        let other_probes =
            fetch_cloaking_operation_binding("https://example.com/a", &reversed).unwrap();
        assert!(!permit.binds_operation(&other_probes.operation()));
    }

    #[test]
    fn cloaking_boundary_has_no_require_approval_bypass() {
        let mut binding =
            fetch_cloaking_operation_binding("https://example.com", &[("bot", "Bot/1")]).unwrap();
        binding.envelope.actions.push(ProposedAction::Narrative {
            text: "intentionally incomplete test action".to_string(),
        });
        let operation = binding.operation();
        let gate = TaskGatePolicy {
            mode: TaskGateMode::Enforce,
            action_incomplete_analysis: Web3GuardAction::RequireApproval,
            ..TaskGatePolicy::default()
        };
        assert!(matches!(
            prepare_locally_derived_boundary_authorization::<FetchCloakingBoundary>(
                &operation,
                &gate,
                &TaskAnalysisContext::default(),
            ),
            Err(BoundaryAuthorizationError::DecisionDenied { assessment })
                if matches!(&assessment.outcome, BoundaryOutcome::RequireApproval { .. })
        ));
    }

    #[test]
    fn package_envelope_rejects_a_thirty_third_requirement_instead_of_truncating() {
        let request = ResolverRequest {
            requirements: (0..=crate::task::MAX_ACTIONS)
                .map(|index| format!("package-{index}==1.0"))
                .collect(),
            index_urls: vec!["https://index.example/simple".to_string()],
            allowances: Default::default(),
        };
        let target = PackageTargetIdentity::new("ab".repeat(32), "linux-devino-v1:1:2", "target");
        let binding = PackageOperationBinding::new("pip", &request, &[], &target);

        assert_eq!(
            package_envelope(&binding).unwrap_err(),
            PackageEnvelopeError::TooManyRequirements {
                provided: crate::task::MAX_ACTIONS + 1,
                max: crate::task::MAX_ACTIONS,
            }
        );
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

    #[test]
    fn source_identity_is_adapter_derived_and_cannot_be_document_selected() {
        let first = github_source_context();
        let second = github_source_context();
        assert_eq!(first.source_id(), second.source_id());
        assert_eq!(first.source_id().len(), 64);
        assert!(matches!(
            TrustedReceiptSourceContext::new(
                "attacker-selected",
                IngressAdapter::GithubIssue,
                "github:owner/repo:issue:1:body",
            ),
            Err(ReceiptV2Error::ContextMismatch("source_id"))
        ));
        let other_adapter = TrustedReceiptSourceContext::from_canonical_acquisition(
            IngressAdapter::FileRead,
            "github:owner/repo:issue:1:body",
        )
        .unwrap();
        assert_ne!(first.source_id(), other_adapter.source_id());
    }

    #[test]
    fn public_challenge_exposes_and_verifies_the_same_safe_projections() {
        let gate = provenance_gate();
        let enforcement = enforcement(&gate);
        let boundary_effects: BTreeSet<CommandEffectKind> =
            [CommandEffectKind::NetworkEgress].into_iter().collect();
        let action_identities = vec!["pkg:left-pad".to_string(), "pkg:is-even".to_string()];
        let document = authorization_document();
        let sources = vec![github_source_context()];
        let projection_context =
            BoundaryAuthorizationProjectionContext::new(&sources, &action_identities, &enforcement);
        let operation = BoundaryOperation {
            boundary: OwnedBoundary::PackageResolve,
            envelope: &document.envelope,
            adapter: IngressAdapter::GithubIssue,
            boundary_effects: boundary_effects.clone(),
        };
        let challenge = derive_boundary_authorization_challenge::<PackageResolveBoundary>(
            &operation,
            &document,
            &gate,
            &TaskAnalysisContext::default(),
            Some(&projection_context),
        )
        .unwrap();
        assert!(challenge.requires_verified_provenance());
        assert_eq!(challenge.authorization_projections().len(), 2);

        let (receipts, keys) = sign_authorizations(
            &document,
            OwnedBoundary::PackageResolve,
            &boundary_effects,
            &action_identities,
            &enforcement,
        );
        let pending = challenge
            .verify_receipts(&receipts, &keys, authorization_now())
            .unwrap();
        assert!(pending.requires_replay());
    }

    #[test]
    fn mixed_source_adapters_are_bound_per_source_in_one_challenge() {
        let gate = provenance_gate();
        let enforcement = enforcement(&gate);
        let action_identities = vec!["pkg:left-pad".to_string(), "pkg:is-even".to_string()];
        let mut document = authorization_document();
        let file_source = TrustedReceiptSourceContext::from_canonical_acquisition(
            IngressAdapter::FileRead,
            "repo-relative:docs/task.md",
        )
        .unwrap();
        document.envelope.sources.push(TaskSourceInput {
            claimed_source: crate::task::SourceKind::SourceComment,
            content: "install from reviewed file".to_string(),
            locator: None,
            receipt: None,
        });
        document
            .source_ids
            .push(Some(file_source.source_id().to_string()));
        let sources = vec![github_source_context(), file_source];
        let projection_context =
            BoundaryAuthorizationProjectionContext::new(&sources, &action_identities, &enforcement);
        let operation = BoundaryOperation {
            boundary: OwnedBoundary::PackageResolve,
            envelope: &document.envelope,
            adapter: IngressAdapter::Unattributed,
            boundary_effects: BTreeSet::new(),
        };
        let challenge = derive_boundary_authorization_challenge::<PackageResolveBoundary>(
            &operation,
            &document,
            &gate,
            &TaskAnalysisContext::default(),
            Some(&projection_context),
        )
        .unwrap();
        let projections = serde_json::to_value(challenge.authorization_projections()).unwrap();
        assert_eq!(challenge.authorization_projections().len(), 4);
        assert!(projections.to_string().contains("github_issue"));
        assert!(projections.to_string().contains("file_read"));
    }

    #[test]
    fn typed_approval_is_required_before_lazy_receiptless_consumption() {
        let envelope = shell_envelope("ls -la");
        let document = TaskEnvelopeDocument {
            version: 1,
            shell_claims: vec![crate::task_envelope::ShellDialectClaim::Unknown],
            source_ids: vec![None],
            authorizations: Vec::new(),
            envelope,
        };
        let operation = BoundaryOperation {
            boundary: OwnedBoundary::PackageManagerExecution,
            envelope: &document.envelope,
            adapter: IngressAdapter::Unattributed,
            boundary_effects: BTreeSet::new(),
        };
        let gate = TaskGatePolicy {
            mode: TaskGateMode::Enforce,
            action_incomplete_analysis: Web3GuardAction::RequireApproval,
            ..TaskGatePolicy::default()
        };
        let analysis = TaskAnalysisContext::default();
        let pending = prepare_boundary_authorization::<PackageManagerExecutionBoundary>(
            &operation, &document, &gate, &analysis, None,
        )
        .unwrap();
        assert!(pending.requires_approval());
        assert!(!pending.requires_replay());
        assert!(matches!(
            pending.consume(&UnavailableStore, authorization_now()),
            Err(BoundaryAuthorizationError::ApprovalRequired)
        ));

        let pending = prepare_boundary_authorization::<PackageManagerExecutionBoundary>(
            &operation, &document, &gate, &analysis, None,
        )
        .unwrap();
        let approval = PackageManagerApprovalChannel {
            evidence: approval_evidence_for::<PackageManagerExecutionBoundary>(
                &operation,
                approval_channel_binding(&serde_json::json!({
                    "channel": "verified_test_channel",
                })),
                None,
            )
            .unwrap(),
        };
        let permit = pending
            .with_package_manager_approval(approval)
            .unwrap()
            .consume_default(authorization_now())
            .unwrap();
        assert_eq!(permit.verified_receipt_count(), 0);
        assert!(permit.binds_operation(&operation));
    }

    #[test]
    fn approval_expiry_is_intersected_into_the_final_effect_permit() {
        let envelope = shell_envelope("ls -la");
        let document = TaskEnvelopeDocument {
            version: 1,
            shell_claims: vec![crate::task_envelope::ShellDialectClaim::Unknown],
            source_ids: vec![None],
            authorizations: Vec::new(),
            envelope,
        };
        let operation = BoundaryOperation {
            boundary: OwnedBoundary::PackageManagerExecution,
            envelope: &document.envelope,
            adapter: IngressAdapter::Unattributed,
            boundary_effects: BTreeSet::new(),
        };
        let gate = TaskGatePolicy {
            mode: TaskGateMode::Enforce,
            action_incomplete_analysis: Web3GuardAction::RequireApproval,
            ..TaskGatePolicy::default()
        };
        let pending = prepare_boundary_authorization::<PackageManagerExecutionBoundary>(
            &operation,
            &document,
            &gate,
            &TaskAnalysisContext::default(),
            None,
        )
        .unwrap();
        let now = authorization_now();
        let deadline = now + TimeDelta::minutes(1);
        let approval = PackageManagerApprovalChannel {
            evidence: approval_evidence_for::<PackageManagerExecutionBoundary>(
                &operation,
                approval_channel_binding(&serde_json::json!({
                    "channel": "deadline_test",
                })),
                Some(deadline),
            )
            .unwrap(),
        };
        let permit = pending
            .with_package_manager_approval(approval)
            .unwrap()
            .consume_default(now)
            .unwrap();
        assert!(matches!(
            permit.authorize_effect_at(&operation, deadline),
            Err(BoundaryAuthorizationError::ReplayStore(
                ReplayStoreError::Expired
            ))
        ));
    }

    #[test]
    fn strict_v2_decision_consumes_one_atomic_batch_before_minting_a_permit() {
        let gate = provenance_gate();
        let enforcement = enforcement(&gate);
        let boundary_effects = [CommandEffectKind::NetworkEgress].into_iter().collect();
        let action_identities = vec!["pkg:left-pad".to_string(), "pkg:is-even".to_string()];
        let mut document = authorization_document();
        let (receipts, keys) = sign_authorizations(
            &document,
            OwnedBoundary::PackageResolve,
            &boundary_effects,
            &action_identities,
            &enforcement,
        );
        document.authorizations = receipts;
        let sources = vec![github_source_context()];
        let trusted = TrustedBoundaryReceiptContext::new(
            &keys,
            authorization_now(),
            &sources,
            &action_identities,
            &enforcement,
        );
        let operation = BoundaryOperation {
            boundary: OwnedBoundary::PackageResolve,
            envelope: &document.envelope,
            adapter: IngressAdapter::GithubIssue,
            boundary_effects,
        };
        let analysis = TaskAnalysisContext::default();

        let pending = prepare_boundary_authorization::<PackageResolveBoundary>(
            &operation,
            &document,
            &gate,
            &analysis,
            Some(&trusted),
        )
        .unwrap();
        assert_eq!(pending.assessment().outcome, BoundaryOutcome::Allow);
        assert!(pending
            .assessment()
            .decision
            .provenance
            .iter()
            .all(
                |assigned| assigned.receipt_status == ReceiptStatus::VerifiedV2
                    && !assigned.is_verified()
            ));

        let store = AtomicRecordingStore::default();
        let permit = pending.consume(&store, authorization_now()).unwrap();
        assert_eq!(permit.verified_receipt_count(), 2);
        assert!(permit.binds_operation(&operation));
        assert_eq!(store.batches.load(Ordering::SeqCst), 1);
        assert_eq!(store.single_receipts.load(Ordering::SeqCst), 0);

        let replay = prepare_boundary_authorization::<PackageResolveBoundary>(
            &operation,
            &document,
            &gate,
            &analysis,
            Some(&trusted),
        )
        .unwrap()
        .consume(&store, authorization_now());
        assert!(matches!(replay, Err(BoundaryAuthorizationError::Replayed)));
        assert_eq!(store.batches.load(Ordering::SeqCst), 2);
        assert_eq!(store.single_receipts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn operation_mismatch_is_rejected_before_any_replay_state_is_consumed() {
        let gate = provenance_gate();
        let enforcement = enforcement(&gate);
        let boundary_effects = [CommandEffectKind::NetworkEgress].into_iter().collect();
        let action_identities = vec!["pkg:left-pad".to_string(), "pkg:is-even".to_string()];
        let mut document = authorization_document();
        let (receipts, keys) = sign_authorizations(
            &document,
            OwnedBoundary::PackageResolve,
            &boundary_effects,
            &action_identities,
            &enforcement,
        );
        document.authorizations = receipts;
        let sources = vec![github_source_context()];
        let trusted = TrustedBoundaryReceiptContext::new(
            &keys,
            authorization_now(),
            &sources,
            &action_identities,
            &enforcement,
        );
        let operation = BoundaryOperation {
            boundary: OwnedBoundary::PackageResolve,
            envelope: &document.envelope,
            adapter: IngressAdapter::GithubIssue,
            boundary_effects: boundary_effects.clone(),
        };
        let pending = prepare_boundary_authorization::<PackageResolveBoundary>(
            &operation,
            &document,
            &gate,
            &TaskAnalysisContext::default(),
            Some(&trusted),
        )
        .unwrap();
        let mut changed_envelope = document.envelope.clone();
        changed_envelope.actions[0] = ProposedAction::PackageInstall {
            ecosystem: "npm".to_string(),
            package: "other".to_string(),
        };
        let changed_operation = BoundaryOperation {
            boundary: OwnedBoundary::PackageResolve,
            envelope: &changed_envelope,
            adapter: IngressAdapter::GithubIssue,
            boundary_effects,
        };
        let store = AtomicRecordingStore::default();

        assert!(matches!(
            pending.consume_for_operation(&changed_operation, &store, authorization_now()),
            Err(BoundaryAuthorizationError::EnvelopeMismatch)
        ));
        assert_eq!(store.batches.load(Ordering::SeqCst), 0);
        assert_eq!(store.single_receipts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn strict_v2_rejects_cross_action_boundary_and_task_context() {
        let gate = provenance_gate();
        let enforcement = enforcement(&gate);
        let boundary_effects = [CommandEffectKind::NetworkEgress].into_iter().collect();
        let action_identities = vec!["pkg:left-pad".to_string(), "pkg:is-even".to_string()];
        let mut document = authorization_document();
        let (receipts, keys) = sign_authorizations(
            &document,
            OwnedBoundary::PackageResolve,
            &boundary_effects,
            &action_identities,
            &enforcement,
        );
        document.authorizations = receipts;
        let sources = vec![github_source_context()];
        let analysis = TaskAnalysisContext::default();

        let wrong_actions = vec!["pkg:left-pad".to_string(), "pkg:other".to_string()];
        let wrong_action_context = TrustedBoundaryReceiptContext::new(
            &keys,
            authorization_now(),
            &sources,
            &wrong_actions,
            &enforcement,
        );
        let resolve = BoundaryOperation {
            boundary: OwnedBoundary::PackageResolve,
            envelope: &document.envelope,
            adapter: IngressAdapter::GithubIssue,
            boundary_effects: boundary_effects.clone(),
        };
        assert!(matches!(
            prepare_boundary_authorization::<PackageResolveBoundary>(
                &resolve,
                &document,
                &gate,
                &analysis,
                Some(&wrong_action_context),
            ),
            Err(BoundaryAuthorizationError::Receipt(
                ReceiptV2Error::UnexpectedAuthorization
            ))
        ));

        let correct_context = TrustedBoundaryReceiptContext::new(
            &keys,
            authorization_now(),
            &sources,
            &action_identities,
            &enforcement,
        );
        let mut missing_receipt = document.clone();
        missing_receipt.authorizations.pop();
        let missing_operation = BoundaryOperation {
            boundary: OwnedBoundary::PackageResolve,
            envelope: &missing_receipt.envelope,
            adapter: IngressAdapter::GithubIssue,
            boundary_effects: boundary_effects.clone(),
        };
        assert!(matches!(
            prepare_boundary_authorization::<PackageResolveBoundary>(
                &missing_operation,
                &missing_receipt,
                &gate,
                &analysis,
                Some(&correct_context),
            ),
            Err(BoundaryAuthorizationError::Receipt(
                ReceiptV2Error::MissingAuthorization
            ))
        ));

        let other_boundary = BoundaryOperation {
            boundary: OwnedBoundary::PackageInstallPreparation,
            envelope: &document.envelope,
            adapter: IngressAdapter::GithubIssue,
            boundary_effects: boundary_effects.clone(),
        };
        assert!(matches!(
            prepare_boundary_authorization::<PackageInstallPreparationBoundary>(
                &other_boundary,
                &document,
                &gate,
                &analysis,
                Some(&correct_context),
            ),
            Err(BoundaryAuthorizationError::Receipt(
                ReceiptV2Error::UnexpectedAuthorization
            ))
        ));

        let mut other_task = document.clone();
        other_task.envelope.task_id = Some("task-2".to_string());
        let other_task_operation = BoundaryOperation {
            boundary: OwnedBoundary::PackageResolve,
            envelope: &other_task.envelope,
            adapter: IngressAdapter::GithubIssue,
            boundary_effects,
        };
        assert!(matches!(
            prepare_boundary_authorization::<PackageResolveBoundary>(
                &other_task_operation,
                &other_task,
                &gate,
                &analysis,
                Some(&correct_context),
            ),
            Err(BoundaryAuthorizationError::Receipt(
                ReceiptV2Error::UnexpectedAuthorization
            ))
        ));
    }

    #[test]
    fn v1_and_missing_v2_receipts_fail_only_when_provenance_is_required() {
        let envelope = TaskEnvelopeInput {
            task_id: Some("legacy-task".to_string()),
            sources: vec![TaskSourceInput {
                claimed_source: crate::task::SourceKind::IssueBody,
                content: "install left-pad".to_string(),
                locator: None,
                receipt: None,
            }],
            actions: vec![ProposedAction::PackageInstall {
                ecosystem: "npm".to_string(),
                package: "left-pad".to_string(),
            }],
            requested_effects: BTreeSet::new(),
        };
        let document = TaskEnvelopeDocument {
            version: 1,
            shell_claims: vec![crate::task_envelope::ShellDialectClaim::Unknown],
            source_ids: vec![None],
            authorizations: Vec::new(),
            envelope,
        };
        let operation = BoundaryOperation {
            boundary: OwnedBoundary::PackageResolve,
            envelope: &document.envelope,
            adapter: IngressAdapter::GithubIssue,
            boundary_effects: BTreeSet::new(),
        };
        let analysis = TaskAnalysisContext::default();

        assert!(matches!(
            prepare_boundary_authorization::<PackageResolveBoundary>(
                &operation,
                &document,
                &provenance_gate(),
                &analysis,
                None,
            ),
            Err(BoundaryAuthorizationError::SchemaV2Required)
        ));

        let pending = prepare_boundary_authorization::<PackageResolveBoundary>(
            &operation,
            &document,
            &TaskGatePolicy::default(),
            &analysis,
            None,
        )
        .unwrap();
        let permit = pending
            .consume(&UnavailableStore, authorization_now())
            .unwrap();
        assert_eq!(permit.verified_receipt_count(), 0);
        assert!(permit.binds_operation(&operation));
    }

    #[test]
    fn required_replay_store_failure_never_mints_a_permit() {
        let gate = provenance_gate();
        let enforcement = enforcement(&gate);
        let boundary_effects = [CommandEffectKind::NetworkEgress].into_iter().collect();
        let action_identities = vec!["pkg:left-pad".to_string(), "pkg:is-even".to_string()];
        let mut document = authorization_document();
        let (receipts, keys) = sign_authorizations(
            &document,
            OwnedBoundary::PackageResolve,
            &boundary_effects,
            &action_identities,
            &enforcement,
        );
        document.authorizations = receipts;
        let sources = vec![github_source_context()];
        let trusted = TrustedBoundaryReceiptContext::new(
            &keys,
            authorization_now(),
            &sources,
            &action_identities,
            &enforcement,
        );
        let operation = BoundaryOperation {
            boundary: OwnedBoundary::PackageResolve,
            envelope: &document.envelope,
            adapter: IngressAdapter::GithubIssue,
            boundary_effects,
        };
        let pending = prepare_boundary_authorization::<PackageResolveBoundary>(
            &operation,
            &document,
            &gate,
            &TaskAnalysisContext::default(),
            Some(&trusted),
        )
        .unwrap();
        assert!(matches!(
            pending.consume(&UnavailableStore, authorization_now()),
            Err(BoundaryAuthorizationError::ReplayStore(
                ReplayStoreError::Unavailable(_)
            ))
        ));
    }

    #[test]
    fn typed_permit_rechecks_earliest_receipt_expiry_at_effect() {
        let gate = provenance_gate();
        let enforcement = enforcement(&gate);
        let boundary_effects = [CommandEffectKind::NetworkEgress].into_iter().collect();
        let action_identities = vec!["pkg:left-pad".to_string(), "pkg:is-even".to_string()];
        let mut document = authorization_document();
        let (receipts, keys) = sign_authorizations(
            &document,
            OwnedBoundary::PackageResolve,
            &boundary_effects,
            &action_identities,
            &enforcement,
        );
        document.authorizations = receipts;
        let sources = vec![github_source_context()];
        let trusted = TrustedBoundaryReceiptContext::new(
            &keys,
            authorization_now(),
            &sources,
            &action_identities,
            &enforcement,
        );
        let operation = BoundaryOperation {
            boundary: OwnedBoundary::PackageResolve,
            envelope: &document.envelope,
            adapter: IngressAdapter::GithubIssue,
            boundary_effects,
        };
        let permit = prepare_boundary_authorization::<PackageResolveBoundary>(
            &operation,
            &document,
            &gate,
            &TaskAnalysisContext::default(),
            Some(&trusted),
        )
        .unwrap()
        .consume(&AtomicRecordingStore::default(), authorization_now())
        .unwrap();
        assert!(matches!(
            permit.authorize_effect_at(&operation, authorization_now() + TimeDelta::hours(1)),
            Err(BoundaryAuthorizationError::ReplayStore(
                ReplayStoreError::Expired
            ))
        ));
    }
}
