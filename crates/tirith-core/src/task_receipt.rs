//! Versioned, authorization-grade provenance receipts.
//!
//! The legacy receipt in [`super::ProvenanceReceipt`] is intentionally retained
//! for diagnostics and wire compatibility.  It is not an authorization token:
//! its verifier has no authoritative task/action context and its historical
//! replay cache is process-local.  This module is the v2 boundary.  A v2
//! receipt binds an exact, canonical task authorization projection, produces a
//! typed validated token, and can be consumed only through a mandatory replay
//! store.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, TimeDelta, Utc};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{IngressAdapter, ProposedAction, SourceKind, MAX_REPLAY_ENTRIES};
use crate::effects::CommandEffectKind;
use crate::task_boundary::OwnedBoundary;
use crate::web3_policy::{TaskGateMode, TaskGatePolicy, Web3GuardAction};

pub const PROVENANCE_RECEIPT_V2: u16 = 2;
pub const TASK_AUTHORIZATION_PROJECTION_V1: u16 = 1;
pub const RECEIPT_V2_MAX_TTL_SECONDS: i64 = 60 * 60;
pub const RECEIPT_V2_CLOCK_SKEW_SECONDS: i64 = 5 * 60;

const MAX_RECEIPT_ID_BYTES: usize = 256;
const MAX_CONTEXT_ID_BYTES: usize = 1024;
const MAX_ACQUISITION_IDENTITY_BYTES: usize = 4096;
const MAX_ACTION_ID_BYTES: usize = 256;
const MAX_NONCE_BYTES: usize = 256;
const MAX_TOOL_NAME_BYTES: usize = 4096;
const MAX_TOOL_DISPLAY_CHARS: usize = 80;
const SHA256_HEX_BYTES: usize = 64;
const ED25519_SIGNATURE_HEX_BYTES: usize = 128;
const ISSUER_KEY_ID_HEX_BYTES: usize = 16;
const REPLAY_LEDGER_SCHEMA_VERSION: u16 = 1;
const REPLAY_LEDGER_READ_CAP: u64 = 4 * 1024 * 1024;
const REPLAY_LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const REPLAY_LOCK_RETRY: Duration = Duration::from_millis(5);
const REPLAY_RESERVATION_TTL: Duration = Duration::from_secs(30);

/// The exact task-gate posture used when deriving an authorization decision.
///
/// This is deliberately separate from `Policy::security_projection_hash()`:
/// that older projection does not include `task_gate`, while every field here
/// can alter whether verified provenance is required or an operation proceeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaskGateAuthorizationProjectionV1 {
    projection_version: u16,
    mode: TaskGateMode,
    effects_requiring_verified_provenance: BTreeSet<CommandEffectKind>,
    effects_denied_for_untrusted_sources: BTreeSet<CommandEffectKind>,
    action_incomplete_analysis: Web3GuardAction,
}

impl From<&TaskGatePolicy> for TaskGateAuthorizationProjectionV1 {
    fn from(gate: &TaskGatePolicy) -> Self {
        Self {
            projection_version: TASK_AUTHORIZATION_PROJECTION_V1,
            mode: gate.mode,
            effects_requiring_verified_provenance: gate
                .effects_requiring_verified_provenance
                .clone(),
            effects_denied_for_untrusted_sources: gate.effects_denied_for_untrusted_sources.clone(),
            action_incomplete_analysis: gate.action_incomplete_analysis,
        }
    }
}

/// Canonical wire projection of [`OwnedBoundary`].
///
/// The authoritative enum remains `task_boundary::OwnedBoundary`; this private
/// projection exists only because the current boundary enum deliberately has
/// no serde surface. The exhaustive conversions below make a newly added
/// boundary a compile-time error until receipt v2 gives it a stable wire name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OwnedBoundaryProjectionV1 {
    GatewayForward,
    PackageApproval,
    PackageResolve,
    PackageInstallPreparation,
    PackageManagerNetwork,
    PackageManagerExecution,
    RemoteScriptRun,
    FetchCloaking,
    ConfigWrite,
}

impl From<OwnedBoundary> for OwnedBoundaryProjectionV1 {
    fn from(boundary: OwnedBoundary) -> Self {
        match boundary {
            OwnedBoundary::GatewayForward => Self::GatewayForward,
            OwnedBoundary::PackageApproval => Self::PackageApproval,
            OwnedBoundary::PackageResolve => Self::PackageResolve,
            OwnedBoundary::PackageInstallPreparation => Self::PackageInstallPreparation,
            OwnedBoundary::PackageManagerNetwork => Self::PackageManagerNetwork,
            OwnedBoundary::PackageManagerExecution => Self::PackageManagerExecution,
            OwnedBoundary::RemoteScriptRun => Self::RemoteScriptRun,
            OwnedBoundary::FetchCloaking => Self::FetchCloaking,
            OwnedBoundary::ConfigWrite => Self::ConfigWrite,
        }
    }
}

impl From<OwnedBoundaryProjectionV1> for OwnedBoundary {
    fn from(boundary: OwnedBoundaryProjectionV1) -> Self {
        match boundary {
            OwnedBoundaryProjectionV1::GatewayForward => Self::GatewayForward,
            OwnedBoundaryProjectionV1::PackageApproval => Self::PackageApproval,
            OwnedBoundaryProjectionV1::PackageResolve => Self::PackageResolve,
            OwnedBoundaryProjectionV1::PackageInstallPreparation => Self::PackageInstallPreparation,
            OwnedBoundaryProjectionV1::PackageManagerNetwork => Self::PackageManagerNetwork,
            OwnedBoundaryProjectionV1::PackageManagerExecution => Self::PackageManagerExecution,
            OwnedBoundaryProjectionV1::RemoteScriptRun => Self::RemoteScriptRun,
            OwnedBoundaryProjectionV1::FetchCloaking => Self::FetchCloaking,
            OwnedBoundaryProjectionV1::ConfigWrite => Self::ConfigWrite,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptGatewayFailMode {
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptGatewayWarnAction {
    Forward,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptServerRequestPolicy {
    DenyAll,
    AllowNegotiated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptEffectiveShell {
    Posix,
    Fish,
    PowerShell,
    Cmd,
    NotApplicable,
}

/// The secure-profile floor after resolving explicit configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SecureProfileFloorProjectionV1 {
    NotApplicable,
    Gateway {
        fail_closed: bool,
        deny_warnings: bool,
        output_filter_required: bool,
        server_requests_require_negotiation: bool,
        max_request_bytes: u64,
        max_analysis_timeout_ms: u64,
        max_pending_requests: u64,
        max_output_queue: u64,
        max_analysis_workers: u64,
    },
}

/// Effective gateway runtime settings that can alter admission or response
/// trust. Non-gateway boundaries bind an explicit `NotApplicable` variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GatewayEnforcementProjectionV1 {
    NotApplicable,
    Mcp {
        fail_mode: ReceiptGatewayFailMode,
        warn_action: ReceiptGatewayWarnAction,
        filter_output: bool,
        sanitize_tool_output: bool,
        inspect_resource_uris: bool,
        server_request_policy: ReceiptServerRequestPolicy,
        max_request_bytes: u64,
        analysis_timeout_ms: u64,
        pending_timeout_ms: u64,
        tombstone_retention_ms: u64,
        max_pending_requests: u64,
        max_output_queue: u64,
        max_analysis_workers: u64,
    },
}

/// Exact MCP tool/descriptor identity. Potentially identifying launch, tool
/// name, and schema material are retained only as digests. The display token is
/// non-authoritative and sanitized for bounded diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ToolIdentityProjectionV1 {
    NotApplicable,
    Mcp {
        identity: McpToolIdentityProjectionV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McpToolIdentityProjectionV1 {
    server_identity_sha256: String,
    tool_name_sha256: String,
    tool_display_token: String,
    input_schema_sha256: String,
    output_schema_sha256: String,
    descriptor_sha256: String,
}

impl ToolIdentityProjectionV1 {
    pub fn mcp(
        server_identity_sha256: &str,
        tool_name: &str,
        input_schema_sha256: &str,
        output_schema_sha256: &str,
        descriptor_sha256: &str,
    ) -> Result<Self, ReceiptV2Error> {
        validate_nonempty_text("tool_name", tool_name, MAX_TOOL_NAME_BYTES)?;
        let identity = McpToolIdentityProjectionV1 {
            server_identity_sha256: server_identity_sha256.to_string(),
            tool_name_sha256: crate::command_card::sha256_hex(tool_name.as_bytes()),
            // Tool names are untrusted and may themselves contain credentials.
            // The exact name is already bound above by SHA-256; diagnostics
            // retain only a constant class label so an alphanumeric secret is
            // not mistaken for safe text merely because it needs no escaping.
            tool_display_token: "mcp-tool".to_string(),
            input_schema_sha256: input_schema_sha256.to_string(),
            output_schema_sha256: output_schema_sha256.to_string(),
            descriptor_sha256: descriptor_sha256.to_string(),
        };
        identity.validate()?;
        Ok(Self::Mcp { identity })
    }
}

impl McpToolIdentityProjectionV1 {
    fn validate(&self) -> Result<(), ReceiptV2Error> {
        validate_sha256("server_identity_sha256", &self.server_identity_sha256)?;
        validate_sha256("tool_name_sha256", &self.tool_name_sha256)?;
        validate_safe_identifier(
            "tool_display_token",
            &self.tool_display_token,
            MAX_TOOL_DISPLAY_CHARS,
        )?;
        validate_sha256("input_schema_sha256", &self.input_schema_sha256)?;
        validate_sha256("output_schema_sha256", &self.output_schema_sha256)?;
        validate_sha256("descriptor_sha256", &self.descriptor_sha256)?;
        Ok(())
    }
}

/// The one command field selected by the trusted gateway configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CanonicalCommandProjectionV1 {
    NotApplicable,
    JsonPointer {
        field_pointer: String,
        command_sha256: String,
    },
}

/// Resource ceilings in force at the transition. `None` means no ceiling was
/// available and is therefore distinct from a large numeric limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResourceCeilingsProjectionV1 {
    pub cpu_seconds: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub max_processes: Option<u64>,
    pub max_open_files: Option<u64>,
    pub max_output_bytes: Option<u64>,
    pub wall_clock_seconds: Option<u64>,
    pub network_egress_allowed: bool,
    pub writable_roots_sha256: String,
    pub allowed_destinations_sha256: String,
}

/// Full typed enforcement posture. The core policy identity and task-gate
/// projection are computed internally from the actual [`crate::policy::Policy`]
/// rather than accepted as opaque hashes by the authorization constructor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementProjectionV1 {
    projection_version: u16,
    core_policy_projection_sha256: String,
    task_gate: TaskGateAuthorizationProjectionV1,
    secure_profile_floor: SecureProfileFloorProjectionV1,
    gateway: GatewayEnforcementProjectionV1,
    tool_identity: ToolIdentityProjectionV1,
    canonical_command: CanonicalCommandProjectionV1,
    effective_shell: ReceiptEffectiveShell,
    resource_ceilings: ResourceCeilingsProjectionV1,
}

impl EnforcementProjectionV1 {
    pub fn new(
        policy: &crate::policy::Policy,
        secure_profile_floor: SecureProfileFloorProjectionV1,
        gateway: GatewayEnforcementProjectionV1,
        tool_identity: ToolIdentityProjectionV1,
        canonical_command: CanonicalCommandProjectionV1,
        effective_shell: ReceiptEffectiveShell,
        resource_ceilings: ResourceCeilingsProjectionV1,
    ) -> Result<Self, ReceiptV2Error> {
        let projection = Self {
            projection_version: TASK_AUTHORIZATION_PROJECTION_V1,
            core_policy_projection_sha256: policy.enforcement_projection_hash(),
            task_gate: TaskGateAuthorizationProjectionV1::from(&policy.task_gate),
            secure_profile_floor,
            gateway,
            tool_identity,
            canonical_command,
            effective_shell,
            resource_ceilings,
        };
        projection.validate()?;
        Ok(projection)
    }

    fn validate(&self) -> Result<(), ReceiptV2Error> {
        if self.projection_version != TASK_AUTHORIZATION_PROJECTION_V1 {
            return Err(ReceiptV2Error::InvalidShape(
                "enforcement_projection_version",
            ));
        }
        validate_sha256(
            "core_policy_projection_sha256",
            &self.core_policy_projection_sha256,
        )?;
        if let ToolIdentityProjectionV1::Mcp { identity } = &self.tool_identity {
            identity.validate()?;
        }
        if let CanonicalCommandProjectionV1::JsonPointer {
            field_pointer,
            command_sha256,
        } = &self.canonical_command
        {
            validate_json_pointer(field_pointer)?;
            validate_sha256("command_sha256", command_sha256)?;
        }
        validate_sha256(
            "writable_roots_sha256",
            &self.resource_ceilings.writable_roots_sha256,
        )?;
        validate_sha256(
            "allowed_destinations_sha256",
            &self.resource_ceilings.allowed_destinations_sha256,
        )?;
        Ok(())
    }

    fn validate_for_boundary(&self, boundary: OwnedBoundary) -> Result<(), ReceiptV2Error> {
        if boundary == OwnedBoundary::GatewayForward {
            if !matches!(
                self.secure_profile_floor,
                SecureProfileFloorProjectionV1::Gateway { .. }
            ) {
                return Err(ReceiptV2Error::InvalidShape("secure_profile_floor"));
            }
            if !matches!(self.gateway, GatewayEnforcementProjectionV1::Mcp { .. }) {
                return Err(ReceiptV2Error::InvalidShape("gateway_enforcement"));
            }
            if !matches!(self.tool_identity, ToolIdentityProjectionV1::Mcp { .. }) {
                return Err(ReceiptV2Error::InvalidShape("tool_identity"));
            }
            if !matches!(
                self.canonical_command,
                CanonicalCommandProjectionV1::JsonPointer { .. }
            ) {
                return Err(ReceiptV2Error::InvalidShape("canonical_command"));
            }
            if self.effective_shell == ReceiptEffectiveShell::NotApplicable {
                return Err(ReceiptV2Error::InvalidShape("effective_shell"));
            }
        } else if !matches!(
            self.secure_profile_floor,
            SecureProfileFloorProjectionV1::NotApplicable
        ) || !matches!(self.gateway, GatewayEnforcementProjectionV1::NotApplicable)
            || !matches!(self.tool_identity, ToolIdentityProjectionV1::NotApplicable)
            || !matches!(
                self.canonical_command,
                CanonicalCommandProjectionV1::NotApplicable
            )
        {
            return Err(ReceiptV2Error::InvalidShape("non_gateway_mcp_projection"));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ReceiptV2Error> {
        self.validate()?;
        digest_serializable(self)
    }

    pub(crate) fn matches_task_gate(&self, gate: &TaskGatePolicy) -> bool {
        self.task_gate == TaskGateAuthorizationProjectionV1::from(gate)
    }
}

/// Canonical, non-secret authorization context a v2 receipt must match.
///
/// Raw actions are hashed into `action_projection_sha256` immediately instead
/// of being retained here: shell actions may contain credentials.  The effect
/// projection separately distinguishes inferred, boundary-known, and effective
/// effects and includes analysis completeness, so a partially understood action
/// cannot be replayed as a complete one with the same union of effect kinds.
/// The trusted adapter's canonical acquisition identity is likewise
/// domain-separated and hashed immediately; raw URLs and filesystem paths
/// never enter a receipt or its signing payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TaskAuthorizationProjectionV1 {
    projection_version: u16,
    task_id: String,
    source_id: String,
    source_kind: SourceKind,
    content_sha256: String,
    adapter: IngressAdapter,
    acquisition_identity_sha256: String,
    boundary: OwnedBoundaryProjectionV1,
    action_index: u16,
    action_identity: String,
    action_projection_sha256: String,
    effects_projection_sha256: String,
    enforcement_projection_sha256: String,
    boundary_operation_sha256: String,
}

impl TaskAuthorizationProjectionV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        task_id: &str,
        source_id: &str,
        source_kind: SourceKind,
        content: &[u8],
        adapter: IngressAdapter,
        // Stable identity canonicalized by the trusted ingress adapter. This
        // value is hashed immediately and is never retained or returned.
        canonical_acquisition_identity: &str,
        boundary: OwnedBoundary,
        action_index: usize,
        action_identity: &str,
        action: &ProposedAction,
        requested_effects: &BTreeSet<CommandEffectKind>,
        inferred_effects: &BTreeSet<CommandEffectKind>,
        boundary_effects: &BTreeSet<CommandEffectKind>,
        analysis_complete: bool,
        enforcement: &EnforcementProjectionV1,
    ) -> Result<Self, ReceiptV2Error> {
        validate_safe_identifier("task_id", task_id, MAX_CONTEXT_ID_BYTES)?;
        validate_safe_identifier("source_id", source_id, MAX_CONTEXT_ID_BYTES)?;
        validate_nonempty_text(
            "canonical_acquisition_identity",
            canonical_acquisition_identity,
            MAX_ACQUISITION_IDENTITY_BYTES,
        )?;
        validate_safe_identifier("action_identity", action_identity, MAX_ACTION_ID_BYTES)?;
        let action_index = u16::try_from(action_index)
            .map_err(|_| ReceiptV2Error::InvalidShape("action_index"))?;
        enforcement.validate()?;
        enforcement.validate_for_boundary(boundary)?;
        let boundary = OwnedBoundaryProjectionV1::from(boundary);

        let action_projection = serde_json::json!({
            "projection_version": TASK_AUTHORIZATION_PROJECTION_V1,
            "action_index": action_index,
            "action_identity": action_identity,
            "action": action,
            "requested_effects": requested_effects,
        });
        let mut effective_effects = inferred_effects.clone();
        effective_effects.extend(boundary_effects.iter().copied());
        let effects_projection = serde_json::json!({
            "projection_version": TASK_AUTHORIZATION_PROJECTION_V1,
            "inferred_effects": inferred_effects,
            "boundary_effects": boundary_effects,
            "effective_effects": effective_effects,
            "analysis_complete": analysis_complete,
        });
        let action_projection_sha256 = digest_canonical_json(&action_projection);
        let effects_projection_sha256 = digest_serializable(&effects_projection)?;
        let enforcement_projection_sha256 = enforcement.digest()?;
        let boundary_operation = serde_json::json!({
            "projection_version": TASK_AUTHORIZATION_PROJECTION_V1,
            "boundary": boundary,
            "action_index": action_index,
            "action_identity": action_identity,
            "action_projection_sha256": action_projection_sha256,
            "effects_projection_sha256": effects_projection_sha256,
            "enforcement_projection_sha256": enforcement_projection_sha256,
        });

        Ok(Self {
            projection_version: TASK_AUTHORIZATION_PROJECTION_V1,
            task_id: task_id.to_string(),
            source_id: source_id.to_string(),
            source_kind,
            content_sha256: crate::command_card::sha256_hex(content),
            adapter,
            acquisition_identity_sha256: acquisition_identity_digest(
                adapter,
                canonical_acquisition_identity,
            ),
            boundary,
            action_index,
            action_identity: action_identity.to_string(),
            action_projection_sha256,
            effects_projection_sha256,
            enforcement_projection_sha256,
            boundary_operation_sha256: digest_canonical_json(&boundary_operation),
        })
    }

    /// Digest of the complete canonical authorization projection.
    pub fn context_digest(&self) -> Result<String, ReceiptV2Error> {
        digest_serializable(self)
    }
}

/// Strict v2 receipt. Every authorization-bearing field is mandatory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceReceiptV2 {
    pub schema_version: u16,
    pub receipt_id: String,
    pub issuer_key_id: String,
    pub task_id: String,
    pub source_id: String,
    pub source_kind: SourceKind,
    pub content_sha256: String,
    pub adapter: IngressAdapter,
    pub acquisition_identity_sha256: String,
    boundary: OwnedBoundaryProjectionV1,
    pub action_index: u16,
    pub action_identity: String,
    pub action_projection_sha256: String,
    pub effects_projection_sha256: String,
    pub enforcement_projection_sha256: String,
    pub boundary_operation_sha256: String,
    pub authorization_projection_sha256: String,
    pub issued_at: String,
    pub expires_at: String,
    pub nonce: String,
    pub signature: String,
}

impl ProvenanceReceiptV2 {
    pub fn boundary(&self) -> OwnedBoundary {
        self.boundary.into()
    }

    /// Build an unsigned v2 receipt from the exact expected projection.
    /// Issuers sign [`receipt_v2_signing_payload`] and then fill `signature`.
    pub fn new_unsigned(
        receipt_id: &str,
        issuer_key_id: &str,
        projection: &TaskAuthorizationProjectionV1,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        nonce: &str,
    ) -> Result<Self, ReceiptV2Error> {
        let receipt = Self {
            schema_version: PROVENANCE_RECEIPT_V2,
            receipt_id: receipt_id.to_string(),
            issuer_key_id: issuer_key_id.to_string(),
            task_id: projection.task_id.clone(),
            source_id: projection.source_id.clone(),
            source_kind: projection.source_kind,
            content_sha256: projection.content_sha256.clone(),
            adapter: projection.adapter,
            acquisition_identity_sha256: projection.acquisition_identity_sha256.clone(),
            boundary: projection.boundary,
            action_index: projection.action_index,
            action_identity: projection.action_identity.clone(),
            action_projection_sha256: projection.action_projection_sha256.clone(),
            effects_projection_sha256: projection.effects_projection_sha256.clone(),
            enforcement_projection_sha256: projection.enforcement_projection_sha256.clone(),
            boundary_operation_sha256: projection.boundary_operation_sha256.clone(),
            authorization_projection_sha256: projection.context_digest()?,
            issued_at: issued_at.to_rfc3339(),
            expires_at: expires_at.to_rfc3339(),
            nonce: nonce.to_string(),
            signature: String::new(),
        };
        receipt.validate_shape()?;
        Ok(receipt)
    }

    fn validate_shape(&self) -> Result<(), ReceiptV2Error> {
        if self.schema_version != PROVENANCE_RECEIPT_V2 {
            return Err(ReceiptV2Error::UnsupportedVersion(self.schema_version));
        }
        validate_safe_identifier("receipt_id", &self.receipt_id, MAX_RECEIPT_ID_BYTES)?;
        if self.issuer_key_id.len() != ISSUER_KEY_ID_HEX_BYTES
            || !self
                .issuer_key_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ReceiptV2Error::InvalidShape("issuer_key_id"));
        }
        validate_safe_identifier("task_id", &self.task_id, MAX_CONTEXT_ID_BYTES)?;
        validate_safe_identifier("source_id", &self.source_id, MAX_CONTEXT_ID_BYTES)?;
        validate_sha256(
            "acquisition_identity_sha256",
            &self.acquisition_identity_sha256,
        )?;
        validate_safe_identifier(
            "action_identity",
            &self.action_identity,
            MAX_ACTION_ID_BYTES,
        )?;
        validate_safe_identifier("nonce", &self.nonce, MAX_NONCE_BYTES)?;
        validate_sha256("content_sha256", &self.content_sha256)?;
        validate_sha256("action_projection_sha256", &self.action_projection_sha256)?;
        validate_sha256("effects_projection_sha256", &self.effects_projection_sha256)?;
        validate_sha256(
            "enforcement_projection_sha256",
            &self.enforcement_projection_sha256,
        )?;
        validate_sha256("boundary_operation_sha256", &self.boundary_operation_sha256)?;
        validate_sha256(
            "authorization_projection_sha256",
            &self.authorization_projection_sha256,
        )?;
        if !self.signature.is_empty()
            && (self.signature.len() != ED25519_SIGNATURE_HEX_BYTES
                || !self.signature.bytes().all(|byte| byte.is_ascii_hexdigit()))
        {
            return Err(ReceiptV2Error::InvalidShape("signature"));
        }
        validate_nonempty_text("issued_at", &self.issued_at, 64)?;
        validate_nonempty_text("expires_at", &self.expires_at, 64)?;
        Ok(())
    }
}

/// Domain-separated canonical payload signed by a v2 issuer.
pub fn receipt_v2_signing_payload(receipt: &ProvenanceReceiptV2) -> Result<String, ReceiptV2Error> {
    receipt.validate_shape()?;
    let value = serde_json::json!({
        "schema_version": receipt.schema_version,
        "receipt_id": receipt.receipt_id,
        "issuer_key_id": receipt.issuer_key_id,
        "task_id": receipt.task_id,
        "source_id": receipt.source_id,
        "source_kind": receipt.source_kind,
        "content_sha256": receipt.content_sha256,
        "adapter": receipt.adapter,
        "acquisition_identity_sha256": receipt.acquisition_identity_sha256,
        "boundary": receipt.boundary,
        "action_index": receipt.action_index,
        "action_identity": receipt.action_identity,
        "action_projection_sha256": receipt.action_projection_sha256,
        "effects_projection_sha256": receipt.effects_projection_sha256,
        "enforcement_projection_sha256": receipt.enforcement_projection_sha256,
        "boundary_operation_sha256": receipt.boundary_operation_sha256,
        "authorization_projection_sha256": receipt.authorization_projection_sha256,
        "issued_at": receipt.issued_at,
        "expires_at": receipt.expires_at,
        "nonce": receipt.nonce,
    });
    Ok(format!(
        "tirith-provenance-receipt:v2\n{}",
        crate::audit::canonical_json_for_hash(&value)
    ))
}

/// Errors are deliberately field-token based: untrusted receipt values never
/// enter diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReceiptV2Error {
    #[error("unsupported provenance receipt schema version {0}")]
    UnsupportedVersion(u16),
    #[error("invalid provenance receipt field: {0}")]
    InvalidShape(&'static str),
    #[error("trusted issuer key was not found")]
    UntrustedIssuer,
    #[error("provenance receipt signature is invalid")]
    InvalidSignature,
    #[error("provenance receipt does not match expected field: {0}")]
    ContextMismatch(&'static str),
    #[error("provenance receipt timestamp is invalid: {0}")]
    InvalidTimestamp(&'static str),
    #[error("provenance receipt was issued too far in the future")]
    NotYetValid,
    #[error("provenance receipt is expired")]
    Expired,
    #[error("provenance receipt validity interval is invalid")]
    InvalidLifetime,
    #[error("provenance receipt validity exceeds one hour")]
    LifetimeTooLong,
    #[error("cannot serialize the canonical authorization projection")]
    ProjectionSerialization,
    #[error("a required provenance authorization receipt is missing")]
    MissingAuthorization,
    #[error("a provenance authorization receipt is duplicated")]
    DuplicateAuthorization,
    #[error("an unexpected provenance authorization receipt was supplied")]
    UnexpectedAuthorization,
    #[error("the provenance authorization set is internally inconsistent")]
    InvalidAuthorizationSet,
}

/// Proof that signature, exact context, and time checks succeeded.
///
/// Fields are private and there is no public constructor. Replay stores accept
/// this token instead of attacker-controlled receipt bytes, so invalid receipts
/// cannot burn a replay slot.
#[derive(Debug)]
pub struct ValidatedReceiptV2 {
    issuer_key_id: String,
    receipt_id: String,
    authorization_projection_sha256: String,
    task_id: String,
    source_id: String,
    boundary: OwnedBoundary,
    action_index: u16,
    boundary_operation_sha256: String,
    expires_at: DateTime<Utc>,
}

impl ValidatedReceiptV2 {
    pub fn issuer_key_id(&self) -> &str {
        &self.issuer_key_id
    }

    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    pub fn authorization_projection_sha256(&self) -> &str {
        &self.authorization_projection_sha256
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

/// Complete pure-verification evidence for one exact task/boundary operation.
///
/// This type is crate-private, has private fields, and is neither cloneable nor
/// serializable. Public diagnostic statuses and caller-provided booleans cannot
/// create it. The task decision can therefore treat its presence as proof that
/// every required source/action projection passed strict v2 verification, but
/// only the replay-consuming boundary can turn it into an execution permit.
pub(crate) struct VerifiedProvenanceEvidence {
    task_id: String,
    boundary: OwnedBoundary,
    source_ids: BTreeSet<String>,
    action_indices: BTreeSet<u16>,
    validated: Vec<ValidatedReceiptV2>,
    boundary_operation_sha256: BTreeSet<String>,
}

impl VerifiedProvenanceEvidence {
    pub(crate) fn authorizes(
        &self,
        envelope: &super::TaskEnvelopeInput,
        boundary: OwnedBoundary,
    ) -> bool {
        envelope.task_id.as_deref() == Some(self.task_id.as_str())
            && boundary == self.boundary
            && envelope.sources.len() == self.source_ids.len()
            && envelope.actions.len() == self.action_indices.len()
            && !self.source_ids.is_empty()
            && !self.action_indices.is_empty()
    }

    pub(crate) fn validated_receipts(&self) -> &[ValidatedReceiptV2] {
        &self.validated
    }

    pub(crate) fn boundary_operation_digests(&self) -> &BTreeSet<String> {
        &self.boundary_operation_sha256
    }
}

/// Pure v2 validation. This function performs no replay-store I/O.
///
/// Replay consumption is a separate, mandatory boundary step so diagnostics
/// can inspect a receipt without spending it.
pub fn verify_receipt_v2(
    receipt: &ProvenanceReceiptV2,
    expected: &TaskAuthorizationProjectionV1,
    trusted_keys: &BTreeMap<String, [u8; 32]>,
    now: DateTime<Utc>,
) -> Result<ValidatedReceiptV2, ReceiptV2Error> {
    receipt.validate_shape()?;
    if receipt.signature.len() != ED25519_SIGNATURE_HEX_BYTES {
        return Err(ReceiptV2Error::InvalidShape("signature"));
    }

    let public_key = trusted_keys
        .get(&receipt.issuer_key_id)
        .ok_or(ReceiptV2Error::UntrustedIssuer)?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|_| ReceiptV2Error::UntrustedIssuer)?;
    let signature = crate::command_card::hex_decode(&receipt.signature)
        .and_then(|bytes| <[u8; 64]>::try_from(bytes.as_slice()).ok())
        .ok_or(ReceiptV2Error::InvalidShape("signature"))?;
    verifying_key
        .verify_strict(
            receipt_v2_signing_payload(receipt)?.as_bytes(),
            &ed25519_dalek::Signature::from_bytes(&signature),
        )
        .map_err(|_| ReceiptV2Error::InvalidSignature)?;

    compare_context(receipt, expected)?;

    let issued_at = parse_timestamp(&receipt.issued_at, "issued_at")?;
    let expires_at = parse_timestamp(&receipt.expires_at, "expires_at")?;
    if expires_at <= issued_at {
        return Err(ReceiptV2Error::InvalidLifetime);
    }
    if expires_at.signed_duration_since(issued_at) > TimeDelta::seconds(RECEIPT_V2_MAX_TTL_SECONDS)
    {
        return Err(ReceiptV2Error::LifetimeTooLong);
    }
    if issued_at > now + TimeDelta::seconds(RECEIPT_V2_CLOCK_SKEW_SECONDS) {
        return Err(ReceiptV2Error::NotYetValid);
    }
    // Clock skew is intentionally one-sided: it tolerates an issuer clock up to
    // five minutes ahead, but never extends a receipt past its signed expiry.
    if now >= expires_at {
        return Err(ReceiptV2Error::Expired);
    }

    Ok(ValidatedReceiptV2 {
        issuer_key_id: receipt.issuer_key_id.clone(),
        receipt_id: receipt.receipt_id.clone(),
        authorization_projection_sha256: receipt.authorization_projection_sha256.clone(),
        task_id: receipt.task_id.clone(),
        source_id: receipt.source_id.clone(),
        boundary: receipt.boundary(),
        action_index: receipt.action_index,
        boundary_operation_sha256: receipt.boundary_operation_sha256.clone(),
        expires_at,
    })
}

/// Purely verify an exact complete authorization set.
///
/// Expected projections are constructed from trusted boundary context. Receipt
/// ordering is irrelevant, but the set must be exact: no omissions, extras, or
/// duplicate projections. Replay state is intentionally untouched here.
pub(crate) fn verify_authorization_set(
    receipts: &[ProvenanceReceiptV2],
    expected: &[TaskAuthorizationProjectionV1],
    trusted_keys: &BTreeMap<String, [u8; 32]>,
    now: DateTime<Utc>,
) -> Result<VerifiedProvenanceEvidence, ReceiptV2Error> {
    if expected.is_empty() {
        return Err(ReceiptV2Error::InvalidAuthorizationSet);
    }
    if receipts.len() < expected.len() {
        return Err(ReceiptV2Error::MissingAuthorization);
    }
    if receipts.len() > expected.len() {
        return Err(ReceiptV2Error::UnexpectedAuthorization);
    }

    let task_id = expected[0].task_id.clone();
    let boundary = OwnedBoundary::from(expected[0].boundary);
    let mut expected_by_digest = BTreeMap::new();
    let mut source_ids = BTreeSet::new();
    let mut action_indices = BTreeSet::new();
    for projection in expected {
        if projection.task_id != task_id || OwnedBoundary::from(projection.boundary) != boundary {
            return Err(ReceiptV2Error::InvalidAuthorizationSet);
        }
        let digest = projection.context_digest()?;
        if expected_by_digest.insert(digest, projection).is_some() {
            return Err(ReceiptV2Error::InvalidAuthorizationSet);
        }
        source_ids.insert(projection.source_id.clone());
        action_indices.insert(projection.action_index);
    }

    let mut seen_digests = BTreeSet::new();
    let mut validated = Vec::with_capacity(receipts.len());
    let mut operation_digests = BTreeSet::new();
    for receipt in receipts {
        if !seen_digests.insert(receipt.authorization_projection_sha256.clone()) {
            return Err(ReceiptV2Error::DuplicateAuthorization);
        }
        let projection = expected_by_digest
            .get(&receipt.authorization_projection_sha256)
            .ok_or(ReceiptV2Error::UnexpectedAuthorization)?;
        let token = verify_receipt_v2(receipt, projection, trusted_keys, now)?;
        operation_digests.insert(token.boundary_operation_sha256.clone());
        validated.push(token);
    }
    if seen_digests.len() != expected_by_digest.len() {
        return Err(ReceiptV2Error::MissingAuthorization);
    }

    // The exact-set match above already establishes these facts; assert them
    // again from the private tokens so later refactors cannot accidentally
    // weaken the evidence constructor without failing closed.
    if validated.iter().any(|token| {
        token.task_id != task_id
            || token.boundary != boundary
            || !source_ids.contains(&token.source_id)
            || !action_indices.contains(&token.action_index)
    }) {
        return Err(ReceiptV2Error::InvalidAuthorizationSet);
    }

    Ok(VerifiedProvenanceEvidence {
        task_id,
        boundary,
        source_ids,
        action_indices,
        validated,
        boundary_operation_sha256: operation_digests,
    })
}

fn compare_context(
    receipt: &ProvenanceReceiptV2,
    expected: &TaskAuthorizationProjectionV1,
) -> Result<(), ReceiptV2Error> {
    macro_rules! exact {
        ($field:ident) => {
            if receipt.$field != expected.$field {
                return Err(ReceiptV2Error::ContextMismatch(stringify!($field)));
            }
        };
    }
    exact!(task_id);
    exact!(source_id);
    exact!(source_kind);
    exact!(content_sha256);
    exact!(adapter);
    exact!(acquisition_identity_sha256);
    exact!(boundary);
    exact!(action_index);
    exact!(action_identity);
    exact!(action_projection_sha256);
    exact!(effects_projection_sha256);
    exact!(enforcement_projection_sha256);
    exact!(boundary_operation_sha256);
    if receipt.authorization_projection_sha256 != expected.context_digest()? {
        return Err(ReceiptV2Error::ContextMismatch(
            "authorization_projection_sha256",
        ));
    }
    Ok(())
}

fn parse_timestamp(value: &str, field: &'static str) -> Result<DateTime<Utc>, ReceiptV2Error> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| ReceiptV2Error::InvalidTimestamp(field))
}

fn validate_nonempty_text(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), ReceiptV2Error> {
    if value.is_empty()
        || value.len() > max
        || value.chars().any(|character| character.is_control())
    {
        return Err(ReceiptV2Error::InvalidShape(field));
    }
    Ok(())
}

fn validate_safe_identifier(
    field: &'static str,
    value: &str,
    max: usize,
) -> Result<(), ReceiptV2Error> {
    validate_nonempty_text(field, value, max)?;
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'#')
    }) {
        return Err(ReceiptV2Error::InvalidShape(field));
    }
    Ok(())
}

pub(crate) fn validate_receipt_context_identifier(
    field: &'static str,
    value: &str,
) -> Result<(), ReceiptV2Error> {
    validate_safe_identifier(field, value, MAX_CONTEXT_ID_BYTES)
}

pub(crate) fn validate_canonical_acquisition_identity(value: &str) -> Result<(), ReceiptV2Error> {
    validate_nonempty_text(
        "canonical_acquisition_identity",
        value,
        MAX_ACQUISITION_IDENTITY_BYTES,
    )
}

fn validate_json_pointer(value: &str) -> Result<(), ReceiptV2Error> {
    validate_nonempty_text("command_field_pointer", value, MAX_CONTEXT_ID_BYTES)?;
    if !value.starts_with('/') {
        return Err(ReceiptV2Error::InvalidShape("command_field_pointer"));
    }
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'~'
            && (index + 1 >= bytes.len() || !matches!(bytes[index + 1], b'0' | b'1'))
        {
            return Err(ReceiptV2Error::InvalidShape("command_field_pointer"));
        }
        index += 1;
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), ReceiptV2Error> {
    if value.len() != SHA256_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ReceiptV2Error::InvalidShape(field));
    }
    Ok(())
}

fn digest_serializable<T: Serialize + ?Sized>(value: &T) -> Result<String, ReceiptV2Error> {
    let value = serde_json::to_value(value).map_err(|_| ReceiptV2Error::ProjectionSerialization)?;
    Ok(digest_canonical_json(&value))
}

/// Hash a trusted adapter's canonical acquisition identity without retaining a
/// URL, filesystem path, username, credential, or other locator material.
/// Including the adapter prevents the same opaque identity from crossing
/// ingress namespaces.
fn acquisition_identity_digest(adapter: IngressAdapter, canonical_identity: &str) -> String {
    let projection = serde_json::json!({
        "domain": "tirith-acquisition-identity",
        "projection_version": TASK_AUTHORIZATION_PROJECTION_V1,
        "adapter": adapter,
        "canonical_identity": canonical_identity,
    });
    digest_canonical_json(&projection)
}

fn digest_canonical_json(value: &serde_json::Value) -> String {
    crate::command_card::sha256_hex(crate::audit::canonical_json_for_hash(value).as_bytes())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayOutcome {
    Recorded,
    Replayed,
}

/// Opaque ownership of a durable, non-consuming replay reservation.
///
/// The store persists the exact receipt batch under a random identity. Holding
/// this value is not authorization to perform an effect: the same store must
/// atomically commit it at the final side-effect seam. The type is deliberately
/// non-cloneable and does not expose receipt or path material through `Debug`.
pub struct ReplayReservation {
    reservation_id: String,
    batch_sha256: String,
}

impl std::fmt::Debug for ReplayReservation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReplayReservation")
            .field(
                "reservation_id_sha256",
                &crate::command_card::sha256_hex(self.reservation_id.as_bytes()),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub enum ReplayReservationOutcome {
    Reserved(ReplayReservation),
    /// Another process owns a still-live, non-consuming lease. This is not a
    /// permanent replay: the caller may retry after the bounded delay.
    Busy {
        retry_after_ms: u64,
    },
    Replayed,
}

#[derive(Debug, Error)]
pub enum ReplayStoreError {
    #[error("provenance replay store is unavailable: {0}")]
    Unavailable(String),
    #[error("provenance replay store is corrupt")]
    Corrupt,
    #[error("provenance replay store has insecure filesystem state: {0}")]
    Insecure(&'static str),
    #[error("timed out acquiring provenance replay store lock")]
    LockTimeout,
    #[error("provenance replay store is full of live entries")]
    Capacity,
    #[error("validated provenance receipt expired before consumption")]
    Expired,
    #[error("provenance replay batch is empty")]
    EmptyBatch,
    #[error("provenance replay ledger publication outcome is unknown")]
    CommitUnknown,
    #[error("native owner-only replay storage is not implemented on this platform")]
    BlockedNative,
}

/// Mandatory one-shot consumption seam for authorization-grade receipts.
pub trait ReplayStore: Send + Sync {
    fn consume(
        &self,
        receipt: &ValidatedReceiptV2,
        now: DateTime<Utc>,
    ) -> Result<ReplayOutcome, ReplayStoreError>;

    /// Atomically consume every receipt in one authorization decision. Either
    /// all identities are recorded under the same store lock, or none are.
    fn consume_batch(
        &self,
        receipts: &[ValidatedReceiptV2],
        now: DateTime<Utc>,
    ) -> Result<ReplayOutcome, ReplayStoreError> {
        let _ = (receipts, now);
        // Preserve source compatibility for existing embedding stores without
        // silently degrading an atomic authorization into sequential writes.
        Err(ReplayStoreError::Unavailable(
            "atomic replay batch consumption is not implemented by this store".to_string(),
        ))
    }

    /// Durably reserve an exact batch without marking any receipt consumed.
    /// Active reservations serialize concurrent attempts for the same receipt;
    /// abandoned reservations expire and become reusable after a bounded lease.
    fn reserve_batch(
        &self,
        receipts: &[ValidatedReceiptV2],
        now: DateTime<Utc>,
    ) -> Result<ReplayReservationOutcome, ReplayStoreError> {
        let _ = (receipts, now);
        Err(ReplayStoreError::Unavailable(
            "atomic replay reservation is not implemented by this store".to_string(),
        ))
    }

    /// Atomically convert one exact reservation into consumed replay entries.
    /// Implementations must sample a fresh clock after acquiring their durable
    /// lock and reject equality with the receipt expiry.
    fn commit_reservation(
        &self,
        reservation: &ReplayReservation,
        now: DateTime<Utc>,
    ) -> Result<ReplayOutcome, ReplayStoreError> {
        let _ = (reservation, now);
        Err(ReplayStoreError::Unavailable(
            "atomic replay reservation commit is not implemented by this store".to_string(),
        ))
    }

    /// Release a reservation after a locally proven zero-effect outcome. A
    /// post-publication commit whose confirmation failed is rolled back by the
    /// same reservation identity; missing or expired state remains idempotent.
    fn abort_reservation(&self, reservation: &ReplayReservation) -> Result<(), ReplayStoreError> {
        let _ = reservation;
        Err(ReplayStoreError::Unavailable(
            "atomic replay reservation abort is not implemented by this store".to_string(),
        ))
    }
}

/// Cross-process, crash-durable replay store.
///
/// A stable lock inode serializes the complete load/prune/check/record/publish
/// transaction. The data file is atomically replaced at mode 0600; the lock and
/// containing directory are never replaced.
#[derive(Debug, Clone)]
pub struct DurableReplayStore {
    root: PathBuf,
    lock_timeout: Duration,
}

#[derive(Debug, Clone, Copy, Default)]
struct ReplayCommitFailureInjection {
    fail_after_commit_publish: bool,
    fail_restore_before_publish: bool,
}

impl DurableReplayStore {
    pub fn from_default_state_dir() -> Result<Self, ReplayStoreError> {
        let state = crate::policy::state_dir().ok_or_else(|| {
            ReplayStoreError::Unavailable("cannot resolve Tirith state directory".to_string())
        })?;
        Ok(Self {
            root: state.join("task-receipt-replay"),
            lock_timeout: REPLAY_LOCK_TIMEOUT,
        })
    }

    /// Explicit root for hermetic tests and embedding applications.
    pub fn with_root(root: PathBuf) -> Self {
        Self {
            root,
            lock_timeout: REPLAY_LOCK_TIMEOUT,
        }
    }

    #[cfg(test)]
    fn with_root_and_lock_timeout(root: PathBuf, lock_timeout: Duration) -> Self {
        Self { root, lock_timeout }
    }

    fn ledger_path(&self) -> PathBuf {
        self.root.join("seen.json")
    }

    fn lock_path(&self) -> PathBuf {
        self.root.join(".seen.lock")
    }
}

impl ReplayStore for DurableReplayStore {
    fn consume(
        &self,
        receipt: &ValidatedReceiptV2,
        now: DateTime<Utc>,
    ) -> Result<ReplayOutcome, ReplayStoreError> {
        self.consume_batch(std::slice::from_ref(receipt), now)
    }

    fn consume_batch(
        &self,
        receipts: &[ValidatedReceiptV2],
        now: DateTime<Utc>,
    ) -> Result<ReplayOutcome, ReplayStoreError> {
        if receipts.is_empty() {
            return Err(ReplayStoreError::EmptyBatch);
        }
        self.consume_batch_with_clock(receipts, now, &Utc::now)
    }

    fn reserve_batch(
        &self,
        receipts: &[ValidatedReceiptV2],
        now: DateTime<Utc>,
    ) -> Result<ReplayReservationOutcome, ReplayStoreError> {
        if receipts.is_empty() {
            return Err(ReplayStoreError::EmptyBatch);
        }
        self.reserve_batch_with_clock(receipts, now, &Utc::now)
    }

    fn commit_reservation(
        &self,
        reservation: &ReplayReservation,
        now: DateTime<Utc>,
    ) -> Result<ReplayOutcome, ReplayStoreError> {
        self.commit_reservation_with_clock(reservation, now, &Utc::now)
    }

    fn abort_reservation(&self, reservation: &ReplayReservation) -> Result<(), ReplayStoreError> {
        self.abort_reservation_inner(reservation, Utc::now())
    }
}

impl DurableReplayStore {
    #[cfg(unix)]
    fn reserve_batch_with_clock(
        &self,
        receipts: &[ValidatedReceiptV2],
        now: DateTime<Utc>,
        clock: &dyn Fn() -> DateTime<Utc>,
    ) -> Result<ReplayReservationOutcome, ReplayStoreError> {
        if receipts.is_empty() {
            return Err(ReplayStoreError::EmptyBatch);
        }
        if receipts.iter().any(|receipt| now >= receipt.expires_at()) {
            return Err(ReplayStoreError::Expired);
        }
        let batch_entries = replay_entries(receipts)?;
        ensure_secure_directory(&self.root)?;
        let _lock = open_and_lock(&self.lock_path(), self.lock_timeout)?;
        let mut ledger = load_ledger(&self.ledger_path())?;
        let reserve_now = clock();
        ledger.prune_expired(reserve_now)?;
        let receipt_expiries = batch_entries
            .iter()
            .map(parse_replay_expiry)
            .collect::<Result<Vec<_>, _>>()?;
        if receipt_expiries.iter().any(|expiry| reserve_now >= *expiry) {
            return Err(ReplayStoreError::Expired);
        }
        if ledger.contains_consumed(&batch_entries) {
            return Ok(ReplayReservationOutcome::Replayed);
        }
        if let Some(retry_after_ms) =
            ledger.reservation_retry_after_ms(&batch_entries, reserve_now)?
        {
            return Ok(ReplayReservationOutcome::Busy { retry_after_ms });
        }
        let live_receipts = ledger.live_receipt_count()?;
        if live_receipts.saturating_add(batch_entries.len()) > MAX_REPLAY_ENTRIES {
            return Err(ReplayStoreError::Capacity);
        }
        let ttl =
            TimeDelta::from_std(REPLAY_RESERVATION_TTL).map_err(|_| ReplayStoreError::Corrupt)?;
        let lease_cap = reserve_now
            .checked_add_signed(ttl)
            .ok_or(ReplayStoreError::Corrupt)?;
        let receipt_expiry = receipt_expiries
            .into_iter()
            .min()
            .ok_or(ReplayStoreError::EmptyBatch)?;
        let lease_expires_at = lease_cap.min(receipt_expiry);
        if reserve_now >= lease_expires_at {
            return Err(ReplayStoreError::Expired);
        }
        let reservation_id = format!("replay-reservation-{}", uuid::Uuid::new_v4().simple());
        let batch_sha256 = replay_batch_digest(&batch_entries);
        ledger.reservations.push(ReplayReservationEntry {
            reservation_id: reservation_id.clone(),
            batch_sha256: batch_sha256.clone(),
            lease_expires_at: lease_expires_at.to_rfc3339(),
            entries: batch_entries,
        });
        ledger
            .reservations
            .sort_by(|left, right| left.reservation_id.cmp(&right.reservation_id));
        save_ledger(&self.ledger_path(), &ledger)?;
        Ok(ReplayReservationOutcome::Reserved(ReplayReservation {
            reservation_id,
            batch_sha256,
        }))
    }

    #[cfg(not(unix))]
    fn reserve_batch_with_clock(
        &self,
        receipts: &[ValidatedReceiptV2],
        now: DateTime<Utc>,
        _clock: &dyn Fn() -> DateTime<Utc>,
    ) -> Result<ReplayReservationOutcome, ReplayStoreError> {
        let _ = (receipts, now);
        Err(ReplayStoreError::BlockedNative)
    }

    #[cfg(unix)]
    fn commit_reservation_with_clock(
        &self,
        reservation: &ReplayReservation,
        now: DateTime<Utc>,
        clock: &dyn Fn() -> DateTime<Utc>,
    ) -> Result<ReplayOutcome, ReplayStoreError> {
        self.commit_reservation_with_clock_and_failures(
            reservation,
            now,
            clock,
            ReplayCommitFailureInjection::default(),
        )
    }

    #[cfg(unix)]
    fn commit_reservation_with_clock_and_failures(
        &self,
        reservation: &ReplayReservation,
        now: DateTime<Utc>,
        clock: &dyn Fn() -> DateTime<Utc>,
        failures: ReplayCommitFailureInjection,
    ) -> Result<ReplayOutcome, ReplayStoreError> {
        ensure_secure_directory(&self.root)?;
        let _lock = open_and_lock(&self.lock_path(), self.lock_timeout)?;
        let mut ledger = load_ledger(&self.ledger_path())?;
        let commit_now = clock();
        let Some(index) = ledger
            .reservations
            .iter()
            .position(|candidate| candidate.reservation_id == reservation.reservation_id)
        else {
            let committed = ledger
                .entries
                .iter()
                .filter(|entry| {
                    entry.committed_reservation_id.as_deref()
                        == Some(reservation.reservation_id.as_str())
                })
                .collect::<Vec<_>>();
            if !committed.is_empty() {
                if committed
                    .iter()
                    .any(|entry| match parse_replay_expiry(entry) {
                        Ok(expires_at) => now >= expires_at || commit_now >= expires_at,
                        Err(_) => true,
                    })
                {
                    return Err(ReplayStoreError::Expired);
                }
                let mut projected = committed
                    .into_iter()
                    .map(|entry| ReplayEntry {
                        issuer_key_id: entry.issuer_key_id.clone(),
                        receipt_id: entry.receipt_id.clone(),
                        authorization_projection_sha256: entry
                            .authorization_projection_sha256
                            .clone(),
                        expires_at: entry.expires_at.clone(),
                        committed_reservation_id: None,
                    })
                    .collect::<Vec<_>>();
                projected.sort_by(|left, right| replay_identity(left).cmp(&replay_identity(right)));
                if replay_batch_digest(&projected) != reservation.batch_sha256 {
                    return Err(ReplayStoreError::Corrupt);
                }
                return Ok(ReplayOutcome::Recorded);
            }
            ledger.prune_expired(commit_now)?;
            return Ok(ReplayOutcome::Replayed);
        };
        if ledger.reservations[index].batch_sha256 != reservation.batch_sha256 {
            return Err(ReplayStoreError::Corrupt);
        }
        let lease_expiry = parse_timestamp(
            &ledger.reservations[index].lease_expires_at,
            "lease_expires_at",
        )
        .map_err(|_| ReplayStoreError::Corrupt)?;
        let receipt_expired = ledger.reservations[index]
            .entries
            .iter()
            .map(parse_replay_expiry)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .any(|expiry| now >= expiry || commit_now >= expiry);
        if now >= lease_expiry || commit_now >= lease_expiry || receipt_expired {
            ledger.reservations.remove(index);
            ledger.prune_expired(commit_now)?;
            save_ledger(&self.ledger_path(), &ledger)?;
            return Err(ReplayStoreError::Expired);
        }
        // Keep the exact pre-commit ledger so a known post-publication failure
        // can restore the still-live reservation before the caller reports a
        // zero-byte outcome. Without this rollback, a successful rename followed
        // by a directory-fsync error burns the receipt even though no effect was
        // attempted.
        let before_commit = ledger.clone();
        let mut reserved = ledger.reservations.remove(index);
        ledger.prune_expired(commit_now)?;
        if ledger.contains_consumed(&reserved.entries) {
            save_ledger(&self.ledger_path(), &ledger)?;
            return Ok(ReplayOutcome::Replayed);
        }
        for entry in &mut reserved.entries {
            entry.committed_reservation_id = Some(reservation.reservation_id.clone());
        }
        ledger.entries.extend(reserved.entries);
        ledger.entries.sort_by(|left, right| {
            (&left.issuer_key_id, &left.receipt_id).cmp(&(&right.issuer_key_id, &right.receipt_id))
        });
        match save_ledger_classified(
            &self.ledger_path(),
            &ledger,
            failures.fail_after_commit_publish,
        ) {
            Ok(()) => Ok(ReplayOutcome::Recorded),
            Err(LedgerPublishError::PrePublish(error)) => Err(error),
            Err(LedgerPublishError::PublishedUnknown(original_error)) => {
                if failures.fail_restore_before_publish {
                    return Err(ReplayStoreError::CommitUnknown);
                }
                match save_ledger_classified(&self.ledger_path(), &before_commit, false) {
                    Ok(()) => Err(original_error),
                    Err(_) => Err(ReplayStoreError::CommitUnknown),
                }
            }
        }
    }

    #[cfg(not(unix))]
    fn commit_reservation_with_clock(
        &self,
        reservation: &ReplayReservation,
        now: DateTime<Utc>,
        _clock: &dyn Fn() -> DateTime<Utc>,
    ) -> Result<ReplayOutcome, ReplayStoreError> {
        let _ = (reservation, now);
        Err(ReplayStoreError::BlockedNative)
    }

    #[cfg(unix)]
    fn abort_reservation_inner(
        &self,
        reservation: &ReplayReservation,
        now: DateTime<Utc>,
    ) -> Result<(), ReplayStoreError> {
        ensure_secure_directory(&self.root)?;
        let _lock = open_and_lock(&self.lock_path(), self.lock_timeout)?;
        let mut ledger = load_ledger(&self.ledger_path())?;
        let reserved_index = ledger
            .reservations
            .iter()
            .position(|candidate| candidate.reservation_id == reservation.reservation_id);
        let mut committed = ledger
            .entries
            .iter()
            .filter(|entry| {
                entry.committed_reservation_id.as_deref()
                    == Some(reservation.reservation_id.as_str())
            })
            .cloned()
            .collect::<Vec<_>>();
        if reserved_index.is_some() && !committed.is_empty() {
            return Err(ReplayStoreError::Corrupt);
        }
        if let Some(index) = reserved_index {
            if ledger.reservations[index].batch_sha256 != reservation.batch_sha256 {
                return Err(ReplayStoreError::Corrupt);
            }
            ledger.reservations.remove(index);
        } else if !committed.is_empty() {
            for entry in &mut committed {
                entry.committed_reservation_id = None;
            }
            committed.sort_by(|left, right| replay_identity(left).cmp(&replay_identity(right)));
            if replay_batch_digest(&committed) != reservation.batch_sha256 {
                return Err(ReplayStoreError::Corrupt);
            }
            ledger.entries.retain(|entry| {
                entry.committed_reservation_id.as_deref()
                    != Some(reservation.reservation_id.as_str())
            });
        }
        ledger.prune_expired(now)?;
        save_ledger(&self.ledger_path(), &ledger)
    }

    #[cfg(not(unix))]
    fn abort_reservation_inner(
        &self,
        reservation: &ReplayReservation,
        now: DateTime<Utc>,
    ) -> Result<(), ReplayStoreError> {
        let _ = (reservation, now);
        Err(ReplayStoreError::BlockedNative)
    }

    /// Complete the replay transaction against a fresh clock sample taken only
    /// after the cross-process lock is held. The caller-supplied `now` remains a
    /// useful early rejection and test anchor, but it cannot authorize a receipt
    /// that expires while this process is waiting for the ledger lock.
    #[cfg(unix)]
    fn consume_batch_with_clock(
        &self,
        receipts: &[ValidatedReceiptV2],
        now: DateTime<Utc>,
        clock: &dyn Fn() -> DateTime<Utc>,
    ) -> Result<ReplayOutcome, ReplayStoreError> {
        if receipts.iter().any(|receipt| now >= receipt.expires_at()) {
            return Err(ReplayStoreError::Expired);
        }
        let batch_entries = match replay_entries(receipts) {
            Ok(entries) => entries,
            Err(ReplayStoreError::Corrupt) => return Ok(ReplayOutcome::Replayed),
            Err(error) => return Err(error),
        };
        ensure_secure_directory(&self.root)?;
        let _lock = open_and_lock(&self.lock_path(), self.lock_timeout)?;

        let mut ledger = load_ledger(&self.ledger_path())?;

        // No post-expiry grace: sample time only after the lock is held and the
        // existing ledger is loaded, immediately before the replay decision and
        // durable ledger mutation. Lock wait and ledger I/O therefore cannot
        // turn a stale authorization into a committed one.
        let commit_now = clock();
        if receipts
            .iter()
            .any(|receipt| commit_now >= receipt.expires_at())
        {
            return Err(ReplayStoreError::Expired);
        }
        ledger.prune_expired(commit_now)?;
        if ledger.contains_any(&batch_entries) {
            return Ok(ReplayOutcome::Replayed);
        }
        if ledger
            .live_receipt_count()?
            .saturating_add(batch_entries.len())
            > MAX_REPLAY_ENTRIES
        {
            return Err(ReplayStoreError::Capacity);
        }
        ledger.entries.extend(batch_entries);
        ledger.entries.sort_by(|left, right| {
            (&left.issuer_key_id, &left.receipt_id).cmp(&(&right.issuer_key_id, &right.receipt_id))
        });
        save_ledger(&self.ledger_path(), &ledger)?;
        Ok(ReplayOutcome::Recorded)
    }

    #[cfg(not(unix))]
    fn consume_batch_with_clock(
        &self,
        receipts: &[ValidatedReceiptV2],
        now: DateTime<Utc>,
        _clock: &dyn Fn() -> DateTime<Utc>,
    ) -> Result<ReplayOutcome, ReplayStoreError> {
        let _ = (receipts, now);
        Err(ReplayStoreError::BlockedNative)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayLedger {
    schema_version: u16,
    entries: Vec<ReplayEntry>,
    #[serde(default)]
    reservations: Vec<ReplayReservationEntry>,
}

impl Default for ReplayLedger {
    fn default() -> Self {
        Self {
            schema_version: REPLAY_LEDGER_SCHEMA_VERSION,
            entries: Vec::new(),
            reservations: Vec::new(),
        }
    }
}

impl ReplayLedger {
    fn prune_expired(&mut self, now: DateTime<Utc>) -> Result<(), ReplayStoreError> {
        if self.schema_version != REPLAY_LEDGER_SCHEMA_VERSION
            || self.live_receipt_count()? > MAX_REPLAY_ENTRIES
        {
            return Err(ReplayStoreError::Corrupt);
        }
        let mut seen = BTreeSet::new();
        for entry in &self.entries {
            if !seen.insert((entry.issuer_key_id.clone(), entry.receipt_id.clone()))
                || validate_replay_entry(entry).is_err()
            {
                return Err(ReplayStoreError::Corrupt);
            }
        }
        let mut reservation_ids = BTreeSet::new();
        for reservation in &self.reservations {
            validate_replay_reservation_entry(reservation)?;
            if !reservation_ids.insert(reservation.reservation_id.clone()) {
                return Err(ReplayStoreError::Corrupt);
            }
            for entry in &reservation.entries {
                if !seen.insert((entry.issuer_key_id.clone(), entry.receipt_id.clone())) {
                    return Err(ReplayStoreError::Corrupt);
                }
            }
        }
        let mut malformed = false;
        self.entries.retain(|entry| {
            let Ok(expires_at) = parse_timestamp(&entry.expires_at, "expires_at") else {
                malformed = true;
                return true;
            };
            now < expires_at
        });
        if malformed {
            return Err(ReplayStoreError::Corrupt);
        }
        self.reservations.retain(|reservation| {
            let Ok(lease_expires_at) =
                parse_timestamp(&reservation.lease_expires_at, "lease_expires_at")
            else {
                malformed = true;
                return true;
            };
            let receipt_live = reservation
                .entries
                .iter()
                .all(|entry| parse_replay_expiry(entry).is_ok_and(|expires_at| now < expires_at));
            now < lease_expires_at && receipt_live
        });
        if malformed {
            return Err(ReplayStoreError::Corrupt);
        }
        Ok(())
    }

    fn live_receipt_count(&self) -> Result<usize, ReplayStoreError> {
        self.reservations
            .iter()
            .try_fold(self.entries.len(), |count, reservation| {
                count
                    .checked_add(reservation.entries.len())
                    .ok_or(ReplayStoreError::Corrupt)
            })
    }

    fn contains_consumed(&self, candidates: &[ReplayEntry]) -> bool {
        candidates.iter().any(|candidate| {
            self.entries
                .iter()
                .any(|entry| replay_identity(entry) == replay_identity(candidate))
        })
    }

    fn contains_any(&self, candidates: &[ReplayEntry]) -> bool {
        self.contains_consumed(candidates)
            || candidates.iter().any(|candidate| {
                self.reservations.iter().any(|reservation| {
                    reservation
                        .entries
                        .iter()
                        .any(|entry| replay_identity(entry) == replay_identity(candidate))
                })
            })
    }

    fn reservation_retry_after_ms(
        &self,
        candidates: &[ReplayEntry],
        now: DateTime<Utc>,
    ) -> Result<Option<u64>, ReplayStoreError> {
        let mut retry_after_ms = None;
        for reservation in &self.reservations {
            let overlaps = candidates.iter().any(|candidate| {
                reservation
                    .entries
                    .iter()
                    .any(|entry| replay_identity(entry) == replay_identity(candidate))
            });
            if !overlaps {
                continue;
            }
            let lease_expires_at =
                parse_timestamp(&reservation.lease_expires_at, "lease_expires_at")
                    .map_err(|_| ReplayStoreError::Corrupt)?;
            let remaining = lease_expires_at.signed_duration_since(now);
            if remaining <= TimeDelta::zero() {
                continue;
            }
            let millis = remaining.num_milliseconds().max(1) as u64;
            let bounded = millis.min(REPLAY_RESERVATION_TTL.as_millis() as u64);
            retry_after_ms = Some(retry_after_ms.map_or(bounded, |seen: u64| seen.min(bounded)));
        }
        Ok(retry_after_ms)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayEntry {
    issuer_key_id: String,
    receipt_id: String,
    authorization_projection_sha256: String,
    expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    committed_reservation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayReservationEntry {
    reservation_id: String,
    batch_sha256: String,
    lease_expires_at: String,
    entries: Vec<ReplayEntry>,
}

fn validate_replay_reservation_entry(
    reservation: &ReplayReservationEntry,
) -> Result<(), ReplayStoreError> {
    validate_safe_identifier(
        "reservation_id",
        &reservation.reservation_id,
        MAX_RECEIPT_ID_BYTES,
    )
    .map_err(|_| ReplayStoreError::Corrupt)?;
    validate_sha256("batch_sha256", &reservation.batch_sha256)
        .map_err(|_| ReplayStoreError::Corrupt)?;
    let lease_expires_at = parse_timestamp(&reservation.lease_expires_at, "lease_expires_at")
        .map_err(|_| ReplayStoreError::Corrupt)?;
    if reservation.entries.is_empty() || reservation.entries.len() > MAX_REPLAY_ENTRIES {
        return Err(ReplayStoreError::Corrupt);
    }
    let mut seen = BTreeSet::new();
    for entry in &reservation.entries {
        validate_replay_entry(entry).map_err(|_| ReplayStoreError::Corrupt)?;
        if !seen.insert(replay_identity(entry)) || lease_expires_at > parse_replay_expiry(entry)? {
            return Err(ReplayStoreError::Corrupt);
        }
    }
    if replay_batch_digest(&reservation.entries) != reservation.batch_sha256 {
        return Err(ReplayStoreError::Corrupt);
    }
    Ok(())
}

fn replay_entries(receipts: &[ValidatedReceiptV2]) -> Result<Vec<ReplayEntry>, ReplayStoreError> {
    let mut identities = BTreeSet::new();
    let mut entries = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        if !identities.insert((receipt.issuer_key_id(), receipt.receipt_id())) {
            return Err(ReplayStoreError::Corrupt);
        }
        entries.push(ReplayEntry {
            issuer_key_id: receipt.issuer_key_id().to_string(),
            receipt_id: receipt.receipt_id().to_string(),
            authorization_projection_sha256: receipt.authorization_projection_sha256().to_string(),
            expires_at: receipt.expires_at().to_rfc3339(),
            committed_reservation_id: None,
        });
    }
    entries.sort_by(|left, right| replay_identity(left).cmp(&replay_identity(right)));
    Ok(entries)
}

fn replay_identity(entry: &ReplayEntry) -> (&str, &str) {
    (&entry.issuer_key_id, &entry.receipt_id)
}

fn parse_replay_expiry(entry: &ReplayEntry) -> Result<DateTime<Utc>, ReplayStoreError> {
    parse_timestamp(&entry.expires_at, "expires_at").map_err(|_| ReplayStoreError::Corrupt)
}

fn replay_batch_digest(entries: &[ReplayEntry]) -> String {
    let projection = entries
        .iter()
        .map(|entry| {
            serde_json::json!({
                "issuer_key_id": entry.issuer_key_id,
                "receipt_id": entry.receipt_id,
                "authorization_projection_sha256": entry.authorization_projection_sha256,
                "expires_at": entry.expires_at,
            })
        })
        .collect::<Vec<_>>();
    digest_canonical_json(&serde_json::json!({
        "domain": "tirith-replay-reservation-batch:v1",
        "entries": projection,
    }))
}

fn validate_replay_entry(entry: &ReplayEntry) -> Result<(), ReceiptV2Error> {
    if entry.issuer_key_id.len() != ISSUER_KEY_ID_HEX_BYTES
        || !entry
            .issuer_key_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ReceiptV2Error::InvalidShape("issuer_key_id"));
    }
    validate_safe_identifier("receipt_id", &entry.receipt_id, MAX_RECEIPT_ID_BYTES)?;
    validate_sha256(
        "authorization_projection_sha256",
        &entry.authorization_projection_sha256,
    )?;
    if let Some(reservation_id) = entry.committed_reservation_id.as_deref() {
        validate_safe_identifier(
            "committed_reservation_id",
            reservation_id,
            MAX_RECEIPT_ID_BYTES,
        )?;
    }
    parse_timestamp(&entry.expires_at, "expires_at")?;
    Ok(())
}

fn load_ledger(path: &Path) -> Result<ReplayLedger, ReplayStoreError> {
    let mut file = match open_secure_regular(path, false) {
        Ok(file) => file,
        Err(ReplayStoreError::Unavailable(message)) if message == "not found" => {
            return Ok(ReplayLedger::default());
        }
        Err(error) => return Err(error),
    };
    let metadata = file
        .metadata()
        .map_err(|error| ReplayStoreError::Unavailable(error.to_string()))?;
    if metadata.len() > REPLAY_LEDGER_READ_CAP {
        return Err(ReplayStoreError::Corrupt);
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(REPLAY_LEDGER_READ_CAP.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| ReplayStoreError::Unavailable(error.to_string()))?;
    if bytes.len() as u64 > REPLAY_LEDGER_READ_CAP {
        return Err(ReplayStoreError::Corrupt);
    }
    let ledger: ReplayLedger =
        serde_json::from_slice(&bytes).map_err(|_| ReplayStoreError::Corrupt)?;
    if ledger.schema_version != REPLAY_LEDGER_SCHEMA_VERSION
        || ledger.live_receipt_count()? > MAX_REPLAY_ENTRIES
    {
        return Err(ReplayStoreError::Corrupt);
    }
    Ok(ledger)
}

enum LedgerPublishError {
    /// The replacement was not published; the old reservation is still visible.
    PrePublish(ReplayStoreError),
    /// The replacement was renamed into place, but its durability or visible
    /// identity could not be confirmed. The caller must reconcile or restore.
    PublishedUnknown(ReplayStoreError),
}

fn save_ledger_classified(
    path: &Path,
    ledger: &ReplayLedger,
    inject_after_publish: bool,
) -> Result<(), LedgerPublishError> {
    let bytes = serde_json::to_vec(ledger)
        .map_err(|_| LedgerPublishError::PrePublish(ReplayStoreError::Corrupt))?;
    if bytes.len() as u64 > REPLAY_LEDGER_READ_CAP {
        return Err(LedgerPublishError::PrePublish(ReplayStoreError::Capacity));
    }
    crate::util::write_file_atomic_0600(path, &bytes).map_err(|error| {
        LedgerPublishError::PrePublish(ReplayStoreError::Unavailable(error.to_string()))
    })?;
    if inject_after_publish {
        return Err(LedgerPublishError::PublishedUnknown(
            ReplayStoreError::Unavailable("injected post-publish replay failure".to_string()),
        ));
    }
    crate::util::fsync_parent_dir(path).map_err(|error| {
        LedgerPublishError::PublishedUnknown(ReplayStoreError::Unavailable(error.to_string()))
    })?;
    let _file = open_secure_regular(path, false).map_err(LedgerPublishError::PublishedUnknown)?;
    Ok(())
}

fn save_ledger(path: &Path, ledger: &ReplayLedger) -> Result<(), ReplayStoreError> {
    save_ledger_classified(path, ledger, false).map_err(|error| match error {
        LedgerPublishError::PrePublish(error) | LedgerPublishError::PublishedUnknown(error) => {
            error
        }
    })
}

fn ensure_secure_directory(path: &Path) -> Result<(), ReplayStoreError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| ReplayStoreError::Unavailable(error.to_string()))?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(path) {
                    Ok(()) => crate::util::fsync_parent_dir(path)
                        .map_err(|error| ReplayStoreError::Unavailable(error.to_string()))?,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(ReplayStoreError::Unavailable(error.to_string()));
                    }
                }
            }
            #[cfg(not(unix))]
            match std::fs::create_dir(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(ReplayStoreError::Unavailable(error.to_string())),
            }
        }
        Err(error) => return Err(ReplayStoreError::Unavailable(error.to_string())),
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| ReplayStoreError::Unavailable(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ReplayStoreError::Insecure("directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(ReplayStoreError::Insecure("directory owner"));
        }
        if metadata.mode() & 0o777 != 0o700 {
            return Err(ReplayStoreError::Insecure("directory mode"));
        }
    }
    Ok(())
}

fn open_and_lock(path: &Path, timeout: Duration) -> Result<File, ReplayStoreError> {
    let file = open_secure_regular(path, true)?;
    file.sync_all()
        .map_err(|error| ReplayStoreError::Unavailable(error.to_string()))?;
    crate::util::fsync_parent_dir(path)
        .map_err(|error| ReplayStoreError::Unavailable(error.to_string()))?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| ReplayStoreError::Unavailable("lock deadline overflow".to_string()))?;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => break,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(ReplayStoreError::LockTimeout);
                }
                std::thread::sleep(REPLAY_LOCK_RETRY);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(ReplayStoreError::Unavailable(error.to_string())),
        }
    }
    verify_visible_identity(path, &file)?;
    Ok(file)
}

fn open_secure_regular(path: &Path, create: bool) -> Result<File, ReplayStoreError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(ReplayStoreError::Insecure("symlink"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(ReplayStoreError::Unavailable(error.to_string())),
    }
    let mut options = OpenOptions::new();
    options.read(true).write(create).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ReplayStoreError::Unavailable("not found".to_string())
        } else {
            ReplayStoreError::Unavailable(error.to_string())
        }
    })?;
    validate_secure_file(&file)?;
    Ok(file)
}

fn validate_secure_file(file: &File) -> Result<(), ReplayStoreError> {
    let metadata = file
        .metadata()
        .map_err(|error| ReplayStoreError::Unavailable(error.to_string()))?;
    if !metadata.is_file() {
        return Err(ReplayStoreError::Insecure("regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(ReplayStoreError::Insecure("file owner"));
        }
        if metadata.mode() & 0o777 != 0o600 {
            return Err(ReplayStoreError::Insecure("file mode"));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn verify_visible_identity(path: &Path, file: &File) -> Result<(), ReplayStoreError> {
    use std::os::unix::fs::MetadataExt as _;
    let held = file
        .metadata()
        .map_err(|error| ReplayStoreError::Unavailable(error.to_string()))?;
    let visible = std::fs::symlink_metadata(path)
        .map_err(|error| ReplayStoreError::Unavailable(error.to_string()))?;
    if visible.file_type().is_symlink()
        || !visible.is_file()
        || held.dev() != visible.dev()
        || held.ino() != visible.ino()
    {
        return Err(ReplayStoreError::Insecure("lock identity"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_visible_identity(path: &Path, _file: &File) -> Result<(), ReplayStoreError> {
    let visible = std::fs::symlink_metadata(path)
        .map_err(|error| ReplayStoreError::Unavailable(error.to_string()))?;
    if visible.file_type().is_symlink() || !visible.is_file() {
        return Err(ReplayStoreError::Insecure("lock identity"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;
    use std::sync::LazyLock;

    static TEST_NOW: LazyLock<DateTime<Utc>> = LazyLock::new(Utc::now);

    fn now() -> DateTime<Utc> {
        *TEST_NOW
    }

    fn enforcement() -> EnforcementProjectionV1 {
        let policy = crate::policy::Policy {
            task_gate: TaskGatePolicy {
                mode: TaskGateMode::Enforce,
                effects_requiring_verified_provenance: BTreeSet::from([
                    CommandEffectKind::PackageInstall,
                ]),
                effects_denied_for_untrusted_sources: BTreeSet::new(),
                action_incomplete_analysis: Web3GuardAction::Block,
            },
            ..Default::default()
        };
        EnforcementProjectionV1::new(
            &policy,
            SecureProfileFloorProjectionV1::NotApplicable,
            GatewayEnforcementProjectionV1::NotApplicable,
            ToolIdentityProjectionV1::NotApplicable,
            CanonicalCommandProjectionV1::NotApplicable,
            ReceiptEffectiveShell::NotApplicable,
            ResourceCeilingsProjectionV1 {
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

    fn projection() -> TaskAuthorizationProjectionV1 {
        projection_with_acquisition(
            IngressAdapter::GithubIssue,
            "github:owner/repo:issue:1:body",
        )
    }

    fn projection_with_acquisition(
        adapter: IngressAdapter,
        canonical_acquisition_identity: &str,
    ) -> TaskAuthorizationProjectionV1 {
        let action = ProposedAction::PackageInstall {
            ecosystem: "npm".to_string(),
            package: "left-pad".to_string(),
        };
        let inferred = BTreeSet::from([
            CommandEffectKind::PackageInstall,
            CommandEffectKind::NetworkEgress,
            CommandEffectKind::FilesystemWrite,
        ]);
        let boundary = BTreeSet::from([CommandEffectKind::NetworkEgress]);
        TaskAuthorizationProjectionV1::new(
            "task-1",
            "source-1",
            SourceKind::IssueBody,
            b"trusted issue body",
            adapter,
            canonical_acquisition_identity,
            OwnedBoundary::PackageResolve,
            0,
            "pkg:left-pad",
            &action,
            &BTreeSet::new(),
            &inferred,
            &boundary,
            true,
            &enforcement(),
        )
        .unwrap()
    }

    fn signed_receipt(
        projection: &TaskAuthorizationProjectionV1,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> (ProvenanceReceiptV2, BTreeMap<String, [u8; 32]>) {
        signed_receipt_with_id(projection, "receipt-1", issued_at, expires_at)
    }

    fn signed_receipt_with_id(
        projection: &TaskAuthorizationProjectionV1,
        receipt_id: &str,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> (ProvenanceReceiptV2, BTreeMap<String, [u8; 32]>) {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[31u8; 32]);
        let public = signing.verifying_key().to_bytes();
        let key_id = crate::command_card::key_id_for_pubkey(&public);
        let mut receipt = ProvenanceReceiptV2::new_unsigned(
            receipt_id, &key_id, projection, issued_at, expires_at, "nonce-1",
        )
        .unwrap();
        receipt.signature = crate::command_card::hex_encode(
            &signing
                .sign(receipt_v2_signing_payload(&receipt).unwrap().as_bytes())
                .to_bytes(),
        );
        (receipt, BTreeMap::from([(key_id, public)]))
    }

    #[test]
    fn every_authorization_dimension_changes_the_context_digest() {
        let baseline = projection();
        let baseline_digest = baseline.context_digest().unwrap();
        let mut variants = Vec::new();

        macro_rules! changed {
            ($field:ident, $value:expr) => {{
                let mut variant = baseline.clone();
                variant.$field = $value;
                variants.push(variant);
            }};
        }
        changed!(task_id, "task-2".to_string());
        changed!(source_id, "source-2".to_string());
        changed!(source_kind, SourceKind::IssueComment);
        changed!(content_sha256, "cd".repeat(32));
        changed!(adapter, IngressAdapter::GithubPullRequest);
        changed!(acquisition_identity_sha256, "ef".repeat(32));
        changed!(
            boundary,
            OwnedBoundaryProjectionV1::from(OwnedBoundary::PackageInstallPreparation)
        );
        changed!(action_index, 1);
        changed!(action_identity, "pkg:other".to_string());
        changed!(action_projection_sha256, "01".repeat(32));
        changed!(effects_projection_sha256, "02".repeat(32));
        changed!(enforcement_projection_sha256, "03".repeat(32));
        changed!(boundary_operation_sha256, "04".repeat(32));

        for variant in variants {
            assert_ne!(variant.context_digest().unwrap(), baseline_digest);
        }
    }

    #[test]
    fn every_owned_boundary_has_one_stable_receipt_projection() {
        let cases = [
            (OwnedBoundary::GatewayForward, "gateway_forward"),
            (OwnedBoundary::PackageApproval, "package_approval"),
            (OwnedBoundary::PackageResolve, "package_resolve"),
            (
                OwnedBoundary::PackageInstallPreparation,
                "package_install_preparation",
            ),
            (
                OwnedBoundary::PackageManagerNetwork,
                "package_manager_network",
            ),
            (
                OwnedBoundary::PackageManagerExecution,
                "package_manager_execution",
            ),
            (OwnedBoundary::RemoteScriptRun, "remote_script_run"),
            (OwnedBoundary::FetchCloaking, "fetch_cloaking"),
            (OwnedBoundary::ConfigWrite, "config_write"),
        ];
        for (boundary, wire_name) in cases {
            let projection = OwnedBoundaryProjectionV1::from(boundary);
            assert_eq!(OwnedBoundary::from(projection), boundary);
            assert_eq!(boundary.token(), wire_name);
            assert_eq!(
                serde_json::to_value(projection).unwrap(),
                serde_json::Value::String(wire_name.to_string())
            );
        }
    }

    #[test]
    fn every_typed_enforcement_component_changes_its_digest() {
        let baseline = enforcement();
        let baseline_digest = baseline.digest().unwrap();
        let mut variants = Vec::new();

        let mut core = baseline.clone();
        core.core_policy_projection_sha256 = "01".repeat(32);
        variants.push(core);

        let mut gate = baseline.clone();
        gate.task_gate.mode = TaskGateMode::Observe;
        variants.push(gate);

        let mut floor = baseline.clone();
        floor.secure_profile_floor = SecureProfileFloorProjectionV1::Gateway {
            fail_closed: true,
            deny_warnings: true,
            output_filter_required: true,
            server_requests_require_negotiation: true,
            max_request_bytes: 1024,
            max_analysis_timeout_ms: 1000,
            max_pending_requests: 64,
            max_output_queue: 64,
            max_analysis_workers: 4,
        };
        variants.push(floor);

        let mut gateway = baseline.clone();
        gateway.gateway = GatewayEnforcementProjectionV1::Mcp {
            fail_mode: ReceiptGatewayFailMode::Closed,
            warn_action: ReceiptGatewayWarnAction::Deny,
            filter_output: true,
            sanitize_tool_output: true,
            inspect_resource_uris: true,
            server_request_policy: ReceiptServerRequestPolicy::AllowNegotiated,
            max_request_bytes: 1024,
            analysis_timeout_ms: 1000,
            pending_timeout_ms: 2000,
            tombstone_retention_ms: 3000,
            max_pending_requests: 64,
            max_output_queue: 64,
            max_analysis_workers: 4,
        };
        variants.push(gateway);

        let mut tool = baseline.clone();
        tool.tool_identity = ToolIdentityProjectionV1::mcp(
            &"02".repeat(32),
            "safe tool / 工具",
            &"03".repeat(32),
            &"04".repeat(32),
            &"05".repeat(32),
        )
        .unwrap();
        variants.push(tool);

        let mut command = baseline.clone();
        command.canonical_command = CanonicalCommandProjectionV1::JsonPointer {
            field_pointer: "/arguments/command".to_string(),
            command_sha256: "06".repeat(32),
        };
        variants.push(command);

        let mut shell = baseline.clone();
        shell.effective_shell = ReceiptEffectiveShell::Posix;
        variants.push(shell);

        let mut resources = baseline.clone();
        resources.resource_ceilings.memory_bytes = Some(1);
        variants.push(resources);

        for variant in variants {
            assert_ne!(variant.digest().unwrap(), baseline_digest);
        }
    }

    #[test]
    fn arbitrary_mcp_tool_names_are_bound_by_digest_not_rejected_or_retained() {
        let secret_canary = "sk_live_SECRET123";
        let raw_name = format!("tool with spaces / 工具 🛠 {secret_canary}");
        let tool = ToolIdentityProjectionV1::mcp(
            &"02".repeat(32),
            &raw_name,
            &"03".repeat(32),
            &"04".repeat(32),
            &"05".repeat(32),
        )
        .unwrap();
        let value = serde_json::to_value(&tool).unwrap();
        let rendered = crate::audit::canonical_json_for_hash(&value);
        assert!(!rendered.contains(&raw_name));
        assert!(!rendered.contains(secret_canary));
        assert!(!format!("{tool:?}").contains(secret_canary));
        assert_eq!(
            value.pointer("/identity/tool_name_sha256"),
            Some(&serde_json::Value::String(crate::command_card::sha256_hex(
                raw_name.as_bytes()
            )))
        );
        let display = value
            .pointer("/identity/tool_display_token")
            .and_then(serde_json::Value::as_str)
            .unwrap();
        assert_eq!(display, "mcp-tool");
        validate_safe_identifier("tool_display_token", display, MAX_TOOL_DISPLAY_CHARS).unwrap();
    }

    #[test]
    fn gateway_and_non_gateway_projection_semantics_are_strict() {
        let action = ProposedAction::Shell {
            command: "echo safe".to_string(),
        };
        let build = |boundary: OwnedBoundary, enforcement: &EnforcementProjectionV1| {
            TaskAuthorizationProjectionV1::new(
                "task-1",
                "source-1",
                SourceKind::IssueBody,
                b"body",
                IngressAdapter::GithubIssue,
                "github://owner/repo/issues/1#body",
                boundary,
                0,
                "action:0",
                &action,
                &BTreeSet::new(),
                &BTreeSet::new(),
                &BTreeSet::new(),
                true,
                enforcement,
            )
        };

        assert_eq!(
            build(OwnedBoundary::GatewayForward, &enforcement()).unwrap_err(),
            ReceiptV2Error::InvalidShape("secure_profile_floor")
        );

        let mut gateway = enforcement();
        gateway.secure_profile_floor = SecureProfileFloorProjectionV1::Gateway {
            fail_closed: true,
            deny_warnings: true,
            output_filter_required: true,
            server_requests_require_negotiation: true,
            max_request_bytes: 1024,
            max_analysis_timeout_ms: 1000,
            max_pending_requests: 64,
            max_output_queue: 64,
            max_analysis_workers: 4,
        };
        gateway.gateway = GatewayEnforcementProjectionV1::Mcp {
            fail_mode: ReceiptGatewayFailMode::Closed,
            warn_action: ReceiptGatewayWarnAction::Deny,
            filter_output: true,
            sanitize_tool_output: true,
            inspect_resource_uris: true,
            server_request_policy: ReceiptServerRequestPolicy::AllowNegotiated,
            max_request_bytes: 1024,
            analysis_timeout_ms: 1000,
            pending_timeout_ms: 2000,
            tombstone_retention_ms: 3000,
            max_pending_requests: 64,
            max_output_queue: 64,
            max_analysis_workers: 4,
        };
        gateway.tool_identity = ToolIdentityProjectionV1::mcp(
            &"02".repeat(32),
            "safe tool",
            &"03".repeat(32),
            &"04".repeat(32),
            &"05".repeat(32),
        )
        .unwrap();
        gateway.canonical_command = CanonicalCommandProjectionV1::JsonPointer {
            field_pointer: "/arguments/command".to_string(),
            command_sha256: "06".repeat(32),
        };
        gateway.effective_shell = ReceiptEffectiveShell::Posix;
        assert!(build(OwnedBoundary::GatewayForward, &gateway).is_ok());
        assert_eq!(
            build(OwnedBoundary::PackageResolve, &gateway).unwrap_err(),
            ReceiptV2Error::InvalidShape("non_gateway_mcp_projection")
        );

        macro_rules! missing_gateway_component {
            ($field:ident, $value:expr, $error:literal) => {{
                let mut incomplete = gateway.clone();
                incomplete.$field = $value;
                assert_eq!(
                    build(OwnedBoundary::GatewayForward, &incomplete).unwrap_err(),
                    ReceiptV2Error::InvalidShape($error)
                );
            }};
        }
        missing_gateway_component!(
            secure_profile_floor,
            SecureProfileFloorProjectionV1::NotApplicable,
            "secure_profile_floor"
        );
        missing_gateway_component!(
            gateway,
            GatewayEnforcementProjectionV1::NotApplicable,
            "gateway_enforcement"
        );
        missing_gateway_component!(
            tool_identity,
            ToolIdentityProjectionV1::NotApplicable,
            "tool_identity"
        );
        missing_gateway_component!(
            canonical_command,
            CanonicalCommandProjectionV1::NotApplicable,
            "canonical_command"
        );
        missing_gateway_component!(
            effective_shell,
            ReceiptEffectiveShell::NotApplicable,
            "effective_shell"
        );
    }

    #[test]
    fn v2_rejects_empty_acquisition_and_unsafe_identifiers() {
        let action = ProposedAction::Narrative {
            text: "diagnostic".to_string(),
        };
        let base = |task_id: &str, source_id: &str, acquisition: &str| {
            TaskAuthorizationProjectionV1::new(
                task_id,
                source_id,
                SourceKind::IssueBody,
                b"body",
                IngressAdapter::GithubIssue,
                acquisition,
                OwnedBoundary::GatewayForward,
                0,
                "action:0",
                &action,
                &BTreeSet::new(),
                &BTreeSet::new(),
                &BTreeSet::new(),
                false,
                &enforcement(),
            )
        };
        assert_eq!(
            base("task-1", "source-1", "").unwrap_err(),
            ReceiptV2Error::InvalidShape("canonical_acquisition_identity")
        );
        assert_eq!(
            base("task 1", "source-1", "github://x").unwrap_err(),
            ReceiptV2Error::InvalidShape("task_id")
        );
        assert_eq!(
            base("task-1", "source\n1", "github://x").unwrap_err(),
            ReceiptV2Error::InvalidShape("source_id")
        );
    }

    #[test]
    fn acquisition_identity_never_exposes_locator_secrets_or_usernames() {
        let cases = [
            (
                IngressAdapter::HttpFetch,
                "https://alice:bearer-secret@example.invalid/private/recovery-key?access_token=query-secret",
            ),
            (
                IngressAdapter::FileRead,
                "/Users/alice/private/wallet-seed.txt",
            ),
        ];
        let canaries = [
            "alice",
            "bearer-secret",
            "recovery-key",
            "query-secret",
            "wallet-seed",
        ];

        for (adapter, canonical_identity) in cases {
            let projection = projection_with_acquisition(adapter, canonical_identity);
            let (receipt, keys) = signed_receipt(
                &projection,
                now() - TimeDelta::minutes(1),
                now() + TimeDelta::minutes(59),
            );
            let artifacts = [
                format!("{projection:?}"),
                format!("{receipt:?}"),
                serde_json::to_string(&receipt).unwrap(),
                receipt_v2_signing_payload(&receipt).unwrap(),
            ];
            for artifact in artifacts {
                for canary in canaries {
                    assert!(!artifact.contains(canary), "leaked canary {canary}");
                }
            }

            let different = projection_with_acquisition(adapter, "different-canonical-source");
            let error = verify_receipt_v2(&receipt, &different, &keys, now()).unwrap_err();
            assert_eq!(
                error,
                ReceiptV2Error::ContextMismatch("acquisition_identity_sha256")
            );
            let rendered_error = format!("{error:?}: {error}");
            for canary in canaries {
                assert!(!rendered_error.contains(canary));
            }
        }
    }

    #[test]
    fn v2_verification_binds_exact_context_and_signature() {
        let expected = projection();
        let (receipt, keys) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        assert!(verify_receipt_v2(&receipt, &expected, &keys, now()).is_ok());

        let mut mismatches = Vec::new();
        macro_rules! mismatched {
            ($field:ident, $value:expr) => {{
                let mut projection = expected.clone();
                projection.$field = $value;
                mismatches.push((projection, stringify!($field)));
            }};
        }
        mismatched!(task_id, "task-2".to_string());
        mismatched!(source_id, "source-2".to_string());
        mismatched!(source_kind, SourceKind::IssueComment);
        mismatched!(content_sha256, "11".repeat(32));
        mismatched!(adapter, IngressAdapter::GithubPullRequest);
        mismatched!(acquisition_identity_sha256, "66".repeat(32));
        mismatched!(
            boundary,
            OwnedBoundaryProjectionV1::from(OwnedBoundary::PackageInstallPreparation)
        );
        mismatched!(action_index, 1);
        mismatched!(action_identity, "pkg:other".to_string());
        mismatched!(action_projection_sha256, "22".repeat(32));
        mismatched!(effects_projection_sha256, "33".repeat(32));
        mismatched!(enforcement_projection_sha256, "44".repeat(32));
        mismatched!(boundary_operation_sha256, "55".repeat(32));
        for (mismatch, field) in mismatches {
            assert_eq!(
                verify_receipt_v2(&receipt, &mismatch, &keys, now()).unwrap_err(),
                ReceiptV2Error::ContextMismatch(field)
            );
        }

        let mut forged = receipt.clone();
        forged.signature = "00".repeat(64);
        assert_eq!(
            verify_receipt_v2(&forged, &expected, &keys, now()).unwrap_err(),
            ReceiptV2Error::InvalidSignature
        );
    }

    #[test]
    fn v2_wire_shape_rejects_unknown_and_missing_fields() {
        let expected = projection();
        let (receipt, _) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        let mut unknown = serde_json::to_value(&receipt).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("unexpected".to_string(), serde_json::json!(true));
        assert!(serde_json::from_value::<ProvenanceReceiptV2>(unknown).is_err());

        let mut missing = serde_json::to_value(&receipt).unwrap();
        missing
            .as_object_mut()
            .unwrap()
            .remove("boundary_operation_sha256");
        assert!(serde_json::from_value::<ProvenanceReceiptV2>(missing).is_err());

        let mut future = receipt;
        future.schema_version = PROVENANCE_RECEIPT_V2 + 1;
        assert_eq!(
            future.validate_shape().unwrap_err(),
            ReceiptV2Error::UnsupportedVersion(PROVENANCE_RECEIPT_V2 + 1)
        );
    }

    #[test]
    fn v2_time_window_enforces_skew_order_and_one_hour_ttl() {
        let expected = projection();
        let reference = now();

        let (edge, keys) = signed_receipt(
            &expected,
            reference + TimeDelta::minutes(5),
            reference + TimeDelta::minutes(65),
        );
        assert!(verify_receipt_v2(&edge, &expected, &keys, reference).is_ok());

        let (future, keys) = signed_receipt(
            &expected,
            reference + TimeDelta::minutes(5) + TimeDelta::milliseconds(1),
            reference + TimeDelta::minutes(65),
        );
        assert_eq!(
            verify_receipt_v2(&future, &expected, &keys, reference).unwrap_err(),
            ReceiptV2Error::NotYetValid
        );

        let (too_long, keys) = signed_receipt(
            &expected,
            reference,
            reference + TimeDelta::hours(1) + TimeDelta::milliseconds(1),
        );
        assert_eq!(
            verify_receipt_v2(&too_long, &expected, &keys, reference).unwrap_err(),
            ReceiptV2Error::LifetimeTooLong
        );

        let (reversed, keys) =
            signed_receipt(&expected, reference, reference - TimeDelta::milliseconds(1));
        assert_eq!(
            verify_receipt_v2(&reversed, &expected, &keys, reference).unwrap_err(),
            ReceiptV2Error::InvalidLifetime
        );

        let (zero_lifetime, keys) = signed_receipt(&expected, reference, reference);
        assert_eq!(
            verify_receipt_v2(&zero_lifetime, &expected, &keys, reference).unwrap_err(),
            ReceiptV2Error::InvalidLifetime
        );

        let (before_expiry, keys) = signed_receipt(
            &expected,
            reference - TimeDelta::minutes(59),
            reference + TimeDelta::milliseconds(1),
        );
        assert!(verify_receipt_v2(&before_expiry, &expected, &keys, reference).is_ok());

        let (at_expiry, keys) =
            signed_receipt(&expected, reference - TimeDelta::hours(1), reference);
        assert_eq!(
            verify_receipt_v2(&at_expiry, &expected, &keys, reference).unwrap_err(),
            ReceiptV2Error::Expired
        );

        let (past_expiry, keys) = signed_receipt(
            &expected,
            reference - TimeDelta::hours(1),
            reference - TimeDelta::milliseconds(1),
        );
        assert_eq!(
            verify_receipt_v2(&past_expiry, &expected, &keys, reference).unwrap_err(),
            ReceiptV2Error::Expired
        );

        let (expired, keys) = signed_receipt(
            &expected,
            reference - TimeDelta::minutes(66),
            reference - TimeDelta::minutes(6),
        );
        assert_eq!(
            verify_receipt_v2(&expired, &expected, &keys, reference).unwrap_err(),
            ReceiptV2Error::Expired
        );
    }

    #[cfg(unix)]
    #[test]
    fn durable_replay_store_survives_reopen_and_rejects_corruption() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("replay");
        let expected = projection();
        let (receipt, keys) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        let validated = verify_receipt_v2(&receipt, &expected, &keys, now()).unwrap();

        let first = DurableReplayStore::with_root(root.clone());
        assert_eq!(
            first.consume(&validated, now()).unwrap(),
            ReplayOutcome::Recorded
        );
        let reopened = DurableReplayStore::with_root(root.clone());
        assert_eq!(
            reopened.consume(&validated, now()).unwrap(),
            ReplayOutcome::Replayed
        );

        std::fs::write(root.join("seen.json"), b"not-json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(
                root.join("seen.json"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        assert!(matches!(
            reopened.consume(&validated, now()),
            Err(ReplayStoreError::Corrupt)
        ));
        assert_eq!(std::fs::read(root.join("seen.json")).unwrap(), b"not-json");
    }

    #[cfg(unix)]
    #[test]
    fn replay_batch_is_all_or_none_and_rejects_duplicates() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("replay");
        let expected = projection();
        let issued = now() - TimeDelta::minutes(1);
        let expires = now() + TimeDelta::minutes(59);
        let (first_receipt, keys) = signed_receipt_with_id(&expected, "receipt-a", issued, expires);
        let (second_receipt, _) = signed_receipt_with_id(&expected, "receipt-b", issued, expires);
        let store = DurableReplayStore::with_root(root);

        assert!(matches!(
            store.consume_batch(&[], now()),
            Err(ReplayStoreError::EmptyBatch)
        ));
        let duplicate_batch = vec![
            verify_receipt_v2(&first_receipt, &expected, &keys, now()).unwrap(),
            verify_receipt_v2(&first_receipt, &expected, &keys, now()).unwrap(),
        ];
        assert_eq!(
            store.consume_batch(&duplicate_batch, now()).unwrap(),
            ReplayOutcome::Replayed
        );
        let batch = vec![
            verify_receipt_v2(&first_receipt, &expected, &keys, now()).unwrap(),
            verify_receipt_v2(&second_receipt, &expected, &keys, now()).unwrap(),
        ];
        assert_eq!(
            store.consume_batch(&batch, now()).unwrap(),
            ReplayOutcome::Recorded
        );
        assert_eq!(
            store.consume(&batch[0], now()).unwrap(),
            ReplayOutcome::Replayed
        );
        assert_eq!(
            store.consume(&batch[1], now()).unwrap(),
            ReplayOutcome::Replayed
        );
    }

    #[cfg(unix)]
    #[test]
    fn replay_reservation_is_exclusive_abortable_and_commits_once() {
        let temp = tempfile::tempdir().unwrap();
        let store = DurableReplayStore::with_root(temp.path().join("replay"));
        let expected = projection();
        let (receipt, keys) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        let validated = verify_receipt_v2(&receipt, &expected, &keys, now()).unwrap();

        let first = match store
            .reserve_batch(std::slice::from_ref(&validated), now())
            .unwrap()
        {
            ReplayReservationOutcome::Reserved(reservation) => reservation,
            ReplayReservationOutcome::Busy { .. } | ReplayReservationOutcome::Replayed => {
                panic!("fresh receipt was already reserved")
            }
        };
        let busy = store
            .reserve_batch(std::slice::from_ref(&validated), now())
            .unwrap();
        assert!(matches!(
            busy,
            ReplayReservationOutcome::Busy { retry_after_ms }
                if retry_after_ms > 0
                    && retry_after_ms <= REPLAY_RESERVATION_TTL.as_millis() as u64
        ));
        store.abort_reservation(&first).unwrap();

        let second = match store
            .reserve_batch(std::slice::from_ref(&validated), now())
            .unwrap()
        {
            ReplayReservationOutcome::Reserved(reservation) => reservation,
            ReplayReservationOutcome::Busy { .. } | ReplayReservationOutcome::Replayed => {
                panic!("aborted receipt was not reusable")
            }
        };
        assert_eq!(
            store.commit_reservation(&second, now()).unwrap(),
            ReplayOutcome::Recorded
        );
        assert_eq!(
            store.consume(&validated, now()).unwrap(),
            ReplayOutcome::Replayed
        );
    }

    #[cfg(unix)]
    #[test]
    fn crashed_reservation_expires_and_becomes_reusable() {
        let temp = tempfile::tempdir().unwrap();
        let store = DurableReplayStore::with_root(temp.path().join("replay"));
        let expected = projection();
        let (receipt, keys) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        let validated = verify_receipt_v2(&receipt, &expected, &keys, now()).unwrap();
        let _abandoned = store
            .reserve_batch_with_clock(std::slice::from_ref(&validated), now(), &now)
            .unwrap();
        let recovered_at =
            now() + TimeDelta::from_std(REPLAY_RESERVATION_TTL).unwrap() + TimeDelta::seconds(1);
        let recovered = store
            .reserve_batch_with_clock(std::slice::from_ref(&validated), recovered_at, &|| {
                recovered_at
            })
            .unwrap();
        let ReplayReservationOutcome::Reserved(recovered) = recovered else {
            panic!("stale crash reservation still blocked reuse");
        };
        store.abort_reservation(&recovered).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_reservation_has_exactly_one_owner() {
        use std::sync::{Arc, Barrier};

        let temp = tempfile::tempdir().unwrap();
        let store = DurableReplayStore::with_root(temp.path().join("replay"));
        let expected = projection();
        let (receipt, keys) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        let validated = Arc::new(verify_receipt_v2(&receipt, &expected, &keys, now()).unwrap());
        let barrier = Arc::new(Barrier::new(2));
        let handles = (0..2)
            .map(|_| {
                let store = store.clone();
                let validated = Arc::clone(&validated);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    store.reserve_batch(std::slice::from_ref(validated.as_ref()), now())
                })
            })
            .collect::<Vec<_>>();
        let outcomes = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ReplayReservationOutcome::Reserved(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ReplayReservationOutcome::Busy { .. }))
                .count(),
            1
        );
        for outcome in outcomes {
            if let ReplayReservationOutcome::Reserved(reservation) = outcome {
                store.abort_reservation(&reservation).unwrap();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn reservation_commit_at_expiry_consumes_nothing() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("replay");
        let store = DurableReplayStore::with_root(root.clone());
        let expected = projection();
        let expiry = now() + TimeDelta::seconds(10);
        let (receipt, keys) = signed_receipt(&expected, now() - TimeDelta::minutes(1), expiry);
        let validated = verify_receipt_v2(&receipt, &expected, &keys, now()).unwrap();
        let reservation = match store
            .reserve_batch_with_clock(std::slice::from_ref(&validated), now(), &now)
            .unwrap()
        {
            ReplayReservationOutcome::Reserved(reservation) => reservation,
            ReplayReservationOutcome::Busy { .. } | ReplayReservationOutcome::Replayed => {
                panic!("fresh receipt was already reserved")
            }
        };
        assert!(matches!(
            store.commit_reservation_with_clock(&reservation, expiry, &|| expiry),
            Err(ReplayStoreError::Expired)
        ));
        let ledger = load_ledger(&root.join("seen.json")).unwrap();
        assert!(ledger.entries.is_empty());
        assert!(ledger.reservations.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn post_publish_commit_failure_restores_the_unconsumed_reservation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("replay");
        let store = DurableReplayStore::with_root(root.clone());
        let expected = projection();
        let (receipt, keys) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        let validated = verify_receipt_v2(&receipt, &expected, &keys, now()).unwrap();
        let reservation = match store
            .reserve_batch(std::slice::from_ref(&validated), now())
            .unwrap()
        {
            ReplayReservationOutcome::Reserved(reservation) => reservation,
            _ => panic!("fresh receipt was not reservable"),
        };

        assert!(matches!(
            store.commit_reservation_with_clock_and_failures(
                &reservation,
                now(),
                &now,
                ReplayCommitFailureInjection {
                    fail_after_commit_publish: true,
                    fail_restore_before_publish: false,
                },
            ),
            Err(ReplayStoreError::Unavailable(_))
        ));
        let ledger = load_ledger(&root.join("seen.json")).unwrap();
        assert!(ledger.entries.is_empty());
        assert_eq!(ledger.reservations.len(), 1);

        store.abort_reservation(&reservation).unwrap();
        assert!(matches!(
            store.reserve_batch(std::slice::from_ref(&validated), now()),
            Ok(ReplayReservationOutcome::Reserved(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn commit_unknown_after_double_publication_failure_can_be_durably_aborted() {
        let temp = tempfile::tempdir().unwrap();
        let store = DurableReplayStore::with_root(temp.path().join("replay"));
        let expected = projection();
        let (receipt, keys) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        let validated = verify_receipt_v2(&receipt, &expected, &keys, now()).unwrap();
        let ReplayReservationOutcome::Reserved(reservation) = store
            .reserve_batch(std::slice::from_ref(&validated), now())
            .unwrap()
        else {
            panic!("fresh receipt was not reservable");
        };
        assert!(matches!(
            store.commit_reservation_with_clock_and_failures(
                &reservation,
                now(),
                &now,
                ReplayCommitFailureInjection {
                    fail_after_commit_publish: true,
                    fail_restore_before_publish: true,
                },
            ),
            Err(ReplayStoreError::CommitUnknown)
        ));
        store.abort_reservation(&reservation).unwrap();
        assert!(matches!(
            store.reserve_batch(std::slice::from_ref(&validated), now()),
            Ok(ReplayReservationOutcome::Reserved(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn replay_store_subprocess_helper() {
        let Some(root) = std::env::var_os("TIRITH_TEST_RECEIPT_REPLAY_ROOT") else {
            return;
        };
        let output = std::env::var_os("TIRITH_TEST_RECEIPT_REPLAY_OUTPUT").unwrap();
        let expected = projection();
        let (receipt, keys) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        let validated = verify_receipt_v2(&receipt, &expected, &keys, now()).unwrap();
        let outcome = DurableReplayStore::with_root(PathBuf::from(root))
            .consume(&validated, now())
            .unwrap();
        let rendered = match outcome {
            ReplayOutcome::Recorded => "recorded",
            ReplayOutcome::Replayed => "replayed",
        };
        std::fs::write(output, rendered).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cross_process_consumers_allow_exactly_one_recording() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("replay");
        let executable = std::env::current_exe().unwrap();
        let outputs = [temp.path().join("one"), temp.path().join("two")];
        let mut children = outputs
            .iter()
            .map(|output| {
                std::process::Command::new(&executable)
                    .arg("replay_store_subprocess_helper")
                    .arg("--nocapture")
                    .env("TIRITH_TEST_RECEIPT_REPLAY_ROOT", &root)
                    .env("TIRITH_TEST_RECEIPT_REPLAY_OUTPUT", output)
                    .spawn()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        for child in &mut children {
            assert!(child.wait().unwrap().success());
        }
        let outcomes = outputs
            .iter()
            .map(|output| std::fs::read_to_string(output).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| *outcome == "recorded")
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| *outcome == "replayed")
                .count(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_consumers_allow_exactly_one_recording() {
        use std::sync::{Arc, Barrier};

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("replay");
        let expected = projection();
        let (receipt, keys) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        let validated = Arc::new(verify_receipt_v2(&receipt, &expected, &keys, now()).unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let root = root.clone();
            let validated = Arc::clone(&validated);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                let store = DurableReplayStore::with_root(root);
                barrier.wait();
                store.consume(&validated, now()).unwrap()
            }));
        }
        barrier.wait();
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == ReplayOutcome::Recorded)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == ReplayOutcome::Replayed)
                .count(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn replay_consumption_and_pruning_expire_at_equality() {
        let expected = projection();
        let (receipt, keys) = signed_receipt(&expected, now() - TimeDelta::hours(1), now());
        let validated = verify_receipt_v2(
            &receipt,
            &expected,
            &keys,
            now() - TimeDelta::milliseconds(1),
        )
        .unwrap();
        let expired_temp = tempfile::tempdir().unwrap();
        let expired_root = expired_temp.path().join("replay");
        assert!(matches!(
            DurableReplayStore::with_root(expired_root).consume(&validated, now()),
            Err(ReplayStoreError::Expired)
        ));

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("replay");
        ensure_secure_directory(&root).unwrap();
        save_ledger(
            &root.join("seen.json"),
            &ReplayLedger {
                schema_version: REPLAY_LEDGER_SCHEMA_VERSION,
                entries: vec![ReplayEntry {
                    issuer_key_id: "0123456789abcdef".to_string(),
                    receipt_id: "expired-at-equality".to_string(),
                    authorization_projection_sha256: "ab".repeat(32),
                    expires_at: now().to_rfc3339(),
                    committed_reservation_id: None,
                }],
                reservations: Vec::new(),
            },
        )
        .unwrap();
        let (fresh_receipt, fresh_keys) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        let fresh = verify_receipt_v2(&fresh_receipt, &expected, &fresh_keys, now()).unwrap();
        assert_eq!(
            DurableReplayStore::with_root(root.clone())
                .consume(&fresh, now())
                .unwrap(),
            ReplayOutcome::Recorded
        );
        let ledger = load_ledger(&root.join("seen.json")).unwrap();
        assert!(!ledger
            .entries
            .iter()
            .any(|entry| entry.receipt_id == "expired-at-equality"));
    }

    #[cfg(unix)]
    #[test]
    fn replay_store_rejects_symlink_and_loose_mode_state() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let expected = projection();
        let (receipt, keys) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        let validated = verify_receipt_v2(&receipt, &expected, &keys, now()).unwrap();

        let symlink_temp = tempfile::tempdir().unwrap();
        let symlink_root = symlink_temp.path().join("replay");
        ensure_secure_directory(&symlink_root).unwrap();
        let target = symlink_temp.path().join("attacker-lock");
        std::fs::write(&target, b"").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, symlink_root.join(".seen.lock")).unwrap();
        assert!(matches!(
            DurableReplayStore::with_root(symlink_root).consume(&validated, now()),
            Err(ReplayStoreError::Insecure("symlink"))
        ));

        let data_symlink_temp = tempfile::tempdir().unwrap();
        let data_symlink_root = data_symlink_temp.path().join("replay");
        ensure_secure_directory(&data_symlink_root).unwrap();
        let data_target = data_symlink_temp.path().join("attacker-data");
        std::fs::write(&data_target, b"{}").unwrap();
        std::fs::set_permissions(&data_target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&data_target, data_symlink_root.join("seen.json")).unwrap();
        assert!(matches!(
            DurableReplayStore::with_root(data_symlink_root).consume(&validated, now()),
            Err(ReplayStoreError::Insecure("symlink"))
        ));

        let loose_root_temp = tempfile::tempdir().unwrap();
        let loose_root = loose_root_temp.path().join("replay");
        ensure_secure_directory(&loose_root).unwrap();
        std::fs::set_permissions(&loose_root, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            DurableReplayStore::with_root(loose_root).consume(&validated, now()),
            Err(ReplayStoreError::Insecure("directory mode"))
        ));

        let loose_temp = tempfile::tempdir().unwrap();
        let loose_root = loose_temp.path().join("replay");
        let loose_store = DurableReplayStore::with_root(loose_root.clone());
        assert_eq!(
            loose_store.consume(&validated, now()).unwrap(),
            ReplayOutcome::Recorded
        );
        std::fs::set_permissions(
            loose_root.join(".seen.lock"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            loose_store.consume(&validated, now()),
            Err(ReplayStoreError::Insecure("file mode"))
        ));

        let loose_data_temp = tempfile::tempdir().unwrap();
        let loose_data_root = loose_data_temp.path().join("replay");
        let loose_data_store = DurableReplayStore::with_root(loose_data_root.clone());
        assert_eq!(
            loose_data_store.consume(&validated, now()).unwrap(),
            ReplayOutcome::Recorded
        );
        std::fs::set_permissions(
            loose_data_root.join("seen.json"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(
            loose_data_store.consume(&validated, now()),
            Err(ReplayStoreError::Insecure("file mode"))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn replay_store_lock_timeout_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("replay");
        ensure_secure_directory(&root).unwrap();
        let held = open_and_lock(&root.join(".seen.lock"), Duration::from_millis(20)).unwrap();

        let expected = projection();
        let (receipt, keys) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        let validated = verify_receipt_v2(&receipt, &expected, &keys, now()).unwrap();
        let store = DurableReplayStore::with_root_and_lock_timeout(root, Duration::from_millis(20));
        assert!(matches!(
            store.consume(&validated, now()),
            Err(ReplayStoreError::LockTimeout)
        ));
        drop(held);
    }

    #[cfg(unix)]
    #[test]
    fn replay_store_rechecks_expiry_at_the_locked_commit_point() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("replay");
        let store = DurableReplayStore::with_root(root);
        let started = now();
        let expires_at = started + TimeDelta::seconds(1);
        let expected = projection();
        let (receipt, keys) =
            signed_receipt(&expected, started - TimeDelta::minutes(1), expires_at);
        let validated = verify_receipt_v2(&receipt, &expected, &keys, started).unwrap();

        assert!(matches!(
            store.consume_batch_with_clock(std::slice::from_ref(&validated), started, &|| {
                expires_at
            },),
            Err(ReplayStoreError::Expired)
        ));
        assert!(
            !store.ledger_path().exists(),
            "an authorization expired at commit must not publish replay state"
        );
    }

    #[cfg(unix)]
    #[test]
    fn full_store_never_evicts_a_live_receipt() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("replay");
        ensure_secure_directory(&root).unwrap();
        let ledger = ReplayLedger {
            schema_version: REPLAY_LEDGER_SCHEMA_VERSION,
            entries: (0..MAX_REPLAY_ENTRIES)
                .map(|index| ReplayEntry {
                    issuer_key_id: "0123456789abcdef".to_string(),
                    receipt_id: format!("live-{index}"),
                    authorization_projection_sha256: "ab".repeat(32),
                    expires_at: (now() + TimeDelta::minutes(30)).to_rfc3339(),
                    committed_reservation_id: None,
                })
                .collect(),
            reservations: Vec::new(),
        };
        save_ledger(&root.join("seen.json"), &ledger).unwrap();

        let expected = projection();
        let (receipt, keys) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        let validated = verify_receipt_v2(&receipt, &expected, &keys, now()).unwrap();
        let store = DurableReplayStore::with_root(root.clone());
        assert!(matches!(
            store.consume(&validated, now()),
            Err(ReplayStoreError::Capacity)
        ));
        let persisted = load_ledger(&root.join("seen.json")).unwrap();
        assert_eq!(persisted.entries.len(), MAX_REPLAY_ENTRIES);
        assert!(persisted
            .entries
            .iter()
            .any(|entry| entry.receipt_id == "live-0"));
    }

    #[test]
    fn invalid_receipt_cannot_burn_replay_slot() {
        let temp = tempfile::tempdir().unwrap();
        let expected = projection();
        let (mut receipt, keys) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        receipt.signature = "00".repeat(64);
        assert!(verify_receipt_v2(&receipt, &expected, &keys, now()).is_err());
        assert!(!temp.path().join("replay").exists());
    }

    #[cfg(not(unix))]
    #[test]
    fn replay_store_explicitly_blocks_without_native_owner_only_storage() {
        let temp = tempfile::tempdir().unwrap();
        let expected = projection();
        let (receipt, keys) = signed_receipt(
            &expected,
            now() - TimeDelta::minutes(1),
            now() + TimeDelta::minutes(59),
        );
        let validated = verify_receipt_v2(&receipt, &expected, &keys, now()).unwrap();
        assert!(matches!(
            DurableReplayStore::with_root(temp.path().join("replay")).consume(&validated, now()),
            Err(ReplayStoreError::BlockedNative)
        ));
    }

    #[test]
    fn legacy_verified_status_is_diagnostic_only() {
        assert!(!super::super::ReceiptStatus::Verified.is_verified());
        assert!(!super::super::ReceiptStatus::VerifiedV2.is_verified());
    }
}
