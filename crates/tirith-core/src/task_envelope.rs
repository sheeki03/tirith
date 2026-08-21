//! Versioned wire representation for task envelopes.
//!
//! `TaskEnvelopeInput` remains the public schema-v1/source API. Schema v2 adds
//! stable task/source identities, shell-dialect claims, and a bounded receipt
//! collection separate from source content. Existing Rust callers and stored
//! v1 documents remain compatible, but v1 receipts remain diagnostic-only.

use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;

use crate::effects::CommandEffectKind;
use crate::task::{
    ProposedAction, ProvenanceReceiptV2, SourceKind, TaskEnvelopeInput, TaskSourceInput,
};
use crate::tokenize::ShellType;

/// Maximum source/action Cartesian product in an authorization-capable v2
/// document. A compact receipt is already roughly 1 KiB on the wire, so the
/// independent 32-source and 32-action envelope limits cannot honestly imply a
/// 1,024-receipt set inside the 128 KiB task-document budget. Sixty-four leaves
/// bounded room for the envelope itself while supporting ordinary multi-source,
/// multi-action requests.
pub const MAX_AUTHORIZATION_PAIRS: usize = 64;

/// A complete v2 authorization has exactly one receipt per source/action pair.
/// Keep this compatibility name for existing schema and gateway callers.
pub const MAX_AUTHORIZATION_RECEIPTS: usize = MAX_AUTHORIZATION_PAIRS;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellDialectClaim {
    Posix,
    Fish,
    PowerShell,
    Cmd,
    /// Unknown and future dialect strings remain bounded diagnostic claims;
    /// they never silently select POSIX or make analysis complete.
    #[default]
    Unknown,
}

impl ShellDialectClaim {
    pub fn known(self) -> Option<ShellType> {
        match self {
            Self::Posix => Some(ShellType::Posix),
            Self::Fish => Some(ShellType::Fish),
            Self::PowerShell => Some(ShellType::PowerShell),
            Self::Cmd => Some(ShellType::Cmd),
            Self::Unknown => None,
        }
    }
}

impl<'de> Deserialize<'de> for ShellDialectClaim {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() > 64 {
            return Ok(Self::Unknown);
        }
        Ok(match value.to_ascii_lowercase().as_str() {
            "posix" | "bash" | "zsh" | "sh" => Self::Posix,
            "fish" => Self::Fish,
            "powershell" | "pwsh" => Self::PowerShell,
            "cmd" | "cmd.exe" => Self::Cmd,
            _ => Self::Unknown,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ProposedActionV2 {
    Shell {
        command: String,
        #[serde(default)]
        claimed_shell: ShellDialectClaim,
    },
    PackageInstall {
        ecosystem: String,
        package: String,
    },
    ConfigWrite {
        path: String,
    },
    Narrative {
        text: String,
    },
}

impl ProposedActionV2 {
    fn into_legacy(self) -> (ProposedAction, ShellDialectClaim) {
        match self {
            Self::Shell {
                command,
                claimed_shell,
            } => (ProposedAction::Shell { command }, claimed_shell),
            Self::PackageInstall { ecosystem, package } => (
                ProposedAction::PackageInstall { ecosystem, package },
                ShellDialectClaim::Unknown,
            ),
            Self::ConfigWrite { path } => (
                ProposedAction::ConfigWrite { path },
                ShellDialectClaim::Unknown,
            ),
            Self::Narrative { text } => (
                ProposedAction::Narrative { text },
                ShellDialectClaim::Unknown,
            ),
        }
    }
}

/// One v2 source with a stable identity assigned by the trusted ingress
/// adapter. Authorization receipts are deliberately not nested here: one
/// source may participate in multiple independently authorized actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskSourceInputV2 {
    #[serde(deserialize_with = "deserialize_source_id")]
    pub source_id: String,
    pub claimed_source: SourceKind,
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub locator: Option<String>,
}

impl TaskSourceInputV2 {
    fn into_legacy(self) -> (String, TaskSourceInput) {
        (
            self.source_id,
            TaskSourceInput {
                claimed_source: self.claimed_source,
                content: self.content,
                locator: self.locator,
                // V1 receipts cannot authorize a v2 transition. Keeping them
                // out of the v2 source shape prevents an ambiguous migration.
                receipt: None,
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskEnvelopeInputV2 {
    pub version: u8,
    #[serde(deserialize_with = "deserialize_task_id")]
    pub task_id: String,
    #[serde(default)]
    pub sources: Vec<TaskSourceInputV2>,
    #[serde(default)]
    pub actions: Vec<ProposedActionV2>,
    #[serde(default)]
    pub requested_effects: BTreeSet<CommandEffectKind>,
    /// Strict v2 receipts, one per required source/action authorization.
    #[serde(default, deserialize_with = "deserialize_authorizations")]
    pub authorizations: Vec<ProvenanceReceiptV2>,
}

fn deserialize_task_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    crate::task::validate_receipt_context_identifier("task_id", &value)
        .map_err(serde::de::Error::custom)?;
    Ok(value)
}

fn deserialize_source_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    crate::task::validate_receipt_context_identifier("source_id", &value)
        .map_err(serde::de::Error::custom)?;
    Ok(value)
}

fn deserialize_authorizations<'de, D>(deserializer: D) -> Result<Vec<ProvenanceReceiptV2>, D::Error>
where
    D: Deserializer<'de>,
{
    let receipts = Vec::<ProvenanceReceiptV2>::deserialize(deserializer)?;
    if receipts.len() > MAX_AUTHORIZATION_RECEIPTS {
        return Err(serde::de::Error::custom(
            "too many task authorization receipts",
        ));
    }
    Ok(receipts)
}

/// Parsed schema plus per-action untrusted dialect claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskEnvelopeDocument {
    pub version: u8,
    pub envelope: TaskEnvelopeInput,
    pub shell_claims: Vec<ShellDialectClaim>,
    /// Stable IDs parallel to `envelope.sources`. V1 has no stable source
    /// identity and therefore preserves explicit `None` entries.
    pub source_ids: Vec<Option<String>>,
    /// Authorization-grade receipts are present only for schema v2. They are
    /// preserved exactly for a later trusted-boundary verification pass.
    pub authorizations: Vec<ProvenanceReceiptV2>,
}

impl TaskEnvelopeDocument {
    /// Wrap a Tirith-derived operation in the legacy diagnostic shape.
    ///
    /// Owned production boundaries use this only when no external v2 task
    /// document was supplied. If policy requires verified provenance, the
    /// authorization challenge rejects this document with `SchemaV2Required`;
    /// it can never silently stand in for receipt-bearing v2 input.
    pub fn from_legacy(envelope: TaskEnvelopeInput) -> Self {
        Self {
            version: 1,
            shell_claims: vec![ShellDialectClaim::Unknown; envelope.actions.len()],
            source_ids: vec![None; envelope.sources.len()],
            authorizations: Vec::new(),
            envelope,
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum WireEnvelope {
    V1(TaskEnvelopeInput),
    V2(TaskEnvelopeInputV2),
}

pub(crate) fn parse_document(json: &str) -> Result<TaskEnvelopeDocument, serde_json::Error> {
    match serde_json::from_str::<WireEnvelope>(json)? {
        WireEnvelope::V1(envelope) => Ok(TaskEnvelopeDocument::from_legacy(envelope)),
        WireEnvelope::V2(document) => {
            if document.version != 2 {
                return Err(<serde_json::Error as serde::de::Error>::custom(
                    "unsupported task envelope version",
                ));
            }
            crate::task::validate_receipt_context_identifier("task_id", &document.task_id)
                .map_err(<serde_json::Error as serde::de::Error>::custom)?;
            if document.authorizations.len() > MAX_AUTHORIZATION_RECEIPTS {
                return Err(<serde_json::Error as serde::de::Error>::custom(
                    "too many task authorization receipts",
                ));
            }
            let authorization_pairs = document
                .sources
                .len()
                .checked_mul(document.actions.len())
                .ok_or_else(|| {
                    <serde_json::Error as serde::de::Error>::custom(
                        "task source/action authorization product overflowed",
                    )
                })?;
            if authorization_pairs > MAX_AUTHORIZATION_PAIRS {
                return Err(<serde_json::Error as serde::de::Error>::custom(
                    "too many task source/action authorization pairs",
                ));
            }

            let mut seen_source_ids = BTreeSet::new();
            let (source_ids, sources): (Vec<_>, Vec<_>) = document
                .sources
                .into_iter()
                .map(|source| {
                    crate::task::validate_receipt_context_identifier(
                        "source_id",
                        &source.source_id,
                    )
                    .map_err(<serde_json::Error as serde::de::Error>::custom)?;
                    if !seen_source_ids.insert(source.source_id.clone()) {
                        return Err(<serde_json::Error as serde::de::Error>::custom(
                            "duplicate task source_id",
                        ));
                    }
                    let (source_id, source) = source.into_legacy();
                    Ok((Some(source_id), source))
                })
                .collect::<Result<Vec<_>, serde_json::Error>>()?
                .into_iter()
                .unzip();
            let (actions, shell_claims): (Vec<_>, Vec<_>) = document
                .actions
                .into_iter()
                .map(ProposedActionV2::into_legacy)
                .unzip();
            Ok(TaskEnvelopeDocument {
                version: 2,
                envelope: TaskEnvelopeInput {
                    task_id: Some(document.task_id),
                    sources,
                    actions,
                    requested_effects: document.requested_effects,
                },
                shell_claims,
                source_ids,
                authorizations: document.authorizations,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt_json() -> serde_json::Value {
        let digest = "ab".repeat(32);
        serde_json::json!({
            "schema_version": 2,
            "receipt_id": "receipt-1",
            "issuer_key_id": "0123456789abcdef",
            "task_id": "task-1",
            "source_id": "source-1",
            "source_kind": "issue_body",
            "content_sha256": digest,
            "adapter": "github_issue",
            "acquisition_identity_sha256": digest,
            "boundary": "package_resolve",
            "action_index": 0,
            "action_identity": "pkg:left-pad",
            "action_projection_sha256": digest,
            "effects_projection_sha256": digest,
            "enforcement_projection_sha256": digest,
            "boundary_operation_sha256": digest,
            "authorization_projection_sha256": digest,
            "issued_at": "2026-08-17T11:00:00Z",
            "expires_at": "2026-08-17T12:00:00Z",
            "nonce": "nonce-1",
            "signature": ""
        })
    }

    fn v2_json(task_id: Option<&str>, source_ids: &[&str]) -> String {
        let mut value = serde_json::json!({
            "version": 2,
            "sources": source_ids.iter().map(|source_id| serde_json::json!({
                "source_id": source_id,
                "claimed_source": "issue_body",
                "content": "install left-pad"
            })).collect::<Vec<_>>(),
            "actions": [{
                "package_install": {"ecosystem": "npm", "package": "left-pad"}
            }],
            "authorizations": [receipt_json()]
        });
        if let Some(task_id) = task_id {
            value["task_id"] = serde_json::Value::String(task_id.to_string());
        }
        serde_json::to_string(&value).unwrap()
    }

    fn cardinality_json(source_count: usize, action_count: usize, receipt_count: usize) -> String {
        serde_json::to_string(&serde_json::json!({
            "version": 2,
            "task_id": "task-1",
            "sources": (0..source_count).map(|index| serde_json::json!({
                "source_id": format!("source-{index}"),
                "claimed_source": "issue_body",
                "content": "x"
            })).collect::<Vec<_>>(),
            "actions": (0..action_count).map(|index| serde_json::json!({
                "package_install": {
                    "ecosystem": "npm",
                    "package": format!("package-{index}")
                }
            })).collect::<Vec<_>>(),
            "authorizations": (0..receipt_count).map(|index| {
                let mut receipt = receipt_json();
                receipt["receipt_id"] = serde_json::Value::String(format!("receipt-{index}"));
                receipt
            }).collect::<Vec<_>>()
        }))
        .unwrap()
    }

    #[test]
    fn v2_preserves_stable_ids_and_separate_authorizations() {
        let document = parse_document(&v2_json(Some("task-1"), &["source-1"])).unwrap();
        assert_eq!(document.version, 2);
        assert_eq!(document.envelope.task_id.as_deref(), Some("task-1"));
        assert_eq!(document.source_ids, vec![Some("source-1".to_string())]);
        assert_eq!(document.authorizations.len(), 1);
        assert_eq!(document.authorizations[0].receipt_id, "receipt-1");
        assert!(document.envelope.sources[0].receipt.is_none());
    }

    #[test]
    fn v2_requires_a_nonempty_task_id_and_unique_stable_source_ids() {
        assert!(parse_document(&v2_json(None, &["source-1"])).is_err());
        assert!(parse_document(&v2_json(Some(""), &["source-1"])).is_err());
        assert!(parse_document(&v2_json(Some("task-1"), &["source-1", "source-1"])).is_err());
    }

    #[test]
    fn v1_remains_diagnostic_and_has_no_authorization_identity() {
        let document = parse_document(
            r#"{"task_id":"legacy","sources":[],"actions":[],"requested_effects":[]}"#,
        )
        .unwrap();
        assert_eq!(document.version, 1);
        assert!(document.source_ids.is_empty());
        assert!(document.authorizations.is_empty());
    }

    #[test]
    fn exact_authorization_pair_and_receipt_boundary_fits_the_document_budget() {
        let json = cardinality_json(8, 8, MAX_AUTHORIZATION_RECEIPTS);
        assert!(
            json.len() <= crate::task::MAX_TASK_DOCUMENT_BYTES,
            "64 compact receipts must fit the declared document budget: {} bytes",
            json.len()
        );
        let document = crate::task::parse_envelope_document(&json).unwrap();
        assert_eq!(document.envelope.sources.len(), 8);
        assert_eq!(document.envelope.actions.len(), 8);
        assert_eq!(document.authorizations.len(), MAX_AUTHORIZATION_RECEIPTS);
    }

    #[test]
    fn authorization_pair_or_receipt_count_above_the_boundary_is_rejected() {
        // 5 * 13 is the smallest factorization available under the independent
        // 32-source/32-action limits that is exactly one above the pair cap.
        let too_many_pairs = cardinality_json(5, 13, 0);
        let error = crate::task::parse_envelope_document(&too_many_pairs).unwrap_err();
        assert!(matches!(
            error,
            crate::task::EnvelopeRejection::Malformed { ref detail }
                if detail.contains("too many task source/action authorization pairs")
        ));

        let too_many_receipts = cardinality_json(1, 1, MAX_AUTHORIZATION_RECEIPTS + 1);
        // Exercise the schema cardinality guard directly. The public parser's
        // independent 128 KiB byte cap may reject this deliberately verbose
        // fixture before deserialization.
        let error = serde_json::from_str::<TaskEnvelopeInputV2>(&too_many_receipts).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("too many task authorization receipts"),
            "{error}"
        );
    }
}
