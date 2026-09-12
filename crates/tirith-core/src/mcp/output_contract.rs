//! Privacy contracts for Tirith-owned MCP projections. Upstream MCP payloads
//! must use `output_filter`; they cannot opt into these protocol-field exemptions.

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

use crate::redact::{redact_json_strings, CompiledCustomPatterns};

/// Select the schema at the producing call site, never from an untrusted field.
#[derive(Clone, Copy)]
pub(super) enum Projection {
    Verdict,
    FileScan,
    DirectoryScan,
    Task,
    Cloaking,
    Finding,
    Evidence,
    AgentOrigin,
    CoverageGap,
    Provenance,
    Agent,
    Diff,
    Content,
}

impl Projection {
    pub(super) fn for_tool(name: Option<&str>) -> Self {
        match name {
            Some("tirith_check_command" | "tirith_check_url" | "tirith_check_paste") => {
                Self::Verdict
            }
            Some("tirith_scan_file" | "tirith_verify_mcp_config") => Self::FileScan,
            Some("tirith_scan_directory") => Self::DirectoryScan,
            Some("tirith_check_task") => Self::Task,
            Some("tirith_fetch_cloaking") => Self::Cloaking,
            _ => Self::Content,
        }
    }
}

/// Preserve only schema-positioned, canonical protocol values. Unknown fields,
/// invalid enum spellings, free-form labels and content receive full DLP. This
/// also reapplies the session's frozen DLP policy after a tool's own projection.
pub(super) fn redact_projection(
    value: &mut Value,
    schema: Projection,
    compiled: &CompiledCustomPatterns,
) {
    match value {
        Value::Array(items) => {
            for item in items {
                redact_projection(item, schema, compiled);
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                if protocol_field(schema, key, value) {
                    continue;
                }
                let child = match (schema, key.as_str()) {
                    (
                        Projection::Verdict | Projection::FileScan | Projection::Cloaking,
                        "findings",
                    ) => Projection::Finding,
                    (Projection::DirectoryScan, "files") => Projection::FileScan,
                    (Projection::DirectoryScan | Projection::FileScan, "coverage_gaps") => {
                        Projection::CoverageGap
                    }
                    (Projection::Verdict, "agent_origin") => Projection::AgentOrigin,
                    (Projection::Finding, "evidence") => Projection::Evidence,
                    (Projection::Task, "provenance") => Projection::Provenance,
                    (Projection::Cloaking, "task_boundary") => Projection::Task,
                    (Projection::Cloaking, "agents") => Projection::Agent,
                    (Projection::Cloaking, "diffs") => Projection::Diff,
                    _ => Projection::Content,
                };
                redact_projection(value, child, compiled);
            }
        }
        _ => redact_json_strings(value, compiled),
    }
}

fn canonical<T: DeserializeOwned + Serialize>(value: &Value) -> bool {
    serde_json::from_value::<T>(value.clone())
        .ok()
        .and_then(|parsed| serde_json::to_value(parsed).ok())
        .as_ref()
        == Some(value)
}

fn token(value: &Value, tokens: &[&str]) -> bool {
    value.as_str().is_some_and(|text| tokens.contains(&text))
}

fn protocol_field(schema: Projection, key: &str, value: &Value) -> bool {
    use Projection::*;
    match (schema, key) {
        (Verdict, "action" | "approval_fallback") => canonical::<crate::verdict::Action>(value),
        (Verdict, "approval_rule") | (Finding, "rule_id") => {
            canonical::<crate::verdict::RuleId>(value)
        }
        (Finding, "severity") => canonical::<crate::verdict::Severity>(value),
        (Evidence, "type") => token(
            value,
            &[
                "url",
                "host_comparison",
                "command_pattern",
                "byte_sequence",
                "env_var",
                "text",
                "threat_intel",
                "homoglyph_analysis",
            ],
        ),
        (Evidence, "confidence") => canonical::<crate::threatdb::Confidence>(value),
        (Evidence, "detail") => value
            .as_str()
            .is_some_and(crate::verdict::is_internal_categorical_evidence_record),
        (AgentOrigin, "kind") => token(value, &["human", "agent", "mcp", "gateway", "ci", "ide"]),
        (CoverageGap, "kind") => canonical::<crate::scan::CoverageGapKind>(value),
        (CoverageGap, "sha256") => value.as_str().is_some_and(|text| {
            text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
        }),
        (Task, "mode") => canonical::<crate::web3_policy::TaskGateMode>(value),
        (Task, "enforceability") => canonical::<crate::effects::BoundaryCapability>(value),
        (
            Task,
            "inferred_effects" | "allowed_effects" | "denied_effects" | "unrequested_effects",
        ) => canonical::<Vec<crate::effects::CommandEffectKind>>(value),
        (Task, "shell_dialect_claims") => {
            canonical::<Vec<crate::task_envelope::ShellDialectClaim>>(value)
        }
        (Task, "outcome") => token(value, &["allow", "deny", "require_approval"]),
        (Task, "boundary") => token(
            value,
            &[
                "gateway_forward",
                "package_approval",
                "package_resolve",
                "package_install_preparation",
                "package_manager_network",
                "package_manager_execution",
                "remote_script_run",
                "fetch_cloaking",
                "config_write",
                "verify_self",
                "self_update",
                "capsule_preset_run",
            ],
        ),
        (Provenance, "claimed_source" | "effective_source") => {
            canonical::<crate::task::SourceKind>(value)
        }
        (Provenance, "adapter") => canonical::<crate::task::IngressAdapter>(value),
        (Provenance, "receipt_status") => canonical::<crate::task::ReceiptStatus>(value),
        (Agent, "agent") | (Diff, "agent_a" | "agent_b") => token(
            value,
            &[
                "chrome",
                "claudebot",
                "chatgpt",
                "perplexity",
                "googlebot",
                "curl",
            ],
        ),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn broad_patterns() -> CompiledCustomPatterns {
        CompiledCustomPatterns::new_silent(&["(?s).+".to_string()])
    }

    #[test]
    fn broad_dlp_preserves_verdict_protocol_but_redacts_content_and_unknown_fields() {
        let mut value = json!({
            "action": "block", "approval_fallback": "warn", "approval_rule": "bidi_controls",
            "policy_path_used": "/private/operator/policy.yaml",
            "agent_origin": {"kind": "mcp", "client_name": "block"},
            "findings": [{"rule_id": "bidi_controls", "severity": "CRITICAL",
                "title": "block", "evidence": [{"type": "text", "detail": "block"}]}],
            "future_metadata": {"action": "block", "receipt_status": "unverified"}
        });
        redact_projection(&mut value, Projection::Verdict, &broad_patterns());
        assert_eq!(value["action"], "block");
        assert_eq!(value["approval_fallback"], "warn");
        assert_eq!(value["approval_rule"], "bidi_controls");
        assert_eq!(value["agent_origin"]["kind"], "mcp");
        assert_eq!(value["findings"][0]["rule_id"], "bidi_controls");
        assert_eq!(value["findings"][0]["severity"], "CRITICAL");
        assert_eq!(value["findings"][0]["evidence"][0]["type"], "text");
        for field in [
            &value["policy_path_used"],
            &value["agent_origin"]["client_name"],
            &value["findings"][0]["title"],
            &value["findings"][0]["evidence"][0]["detail"],
            &value["future_metadata"]["action"],
            &value["future_metadata"]["receipt_status"],
        ] {
            assert_eq!(field, "[REDACTED:custom]");
        }
    }

    #[test]
    fn broad_dlp_preserves_task_receipt_metadata_without_exposing_receipts() {
        let mut value = json!({
            "schema_version": 1, "mode": "observe", "outcome": "deny",
            "boundary": "fetch_cloaking", "complete": false,
            "inferred_effects": ["network_egress"],
            "provenance": [{"claimed_source": "web_page", "effective_source": "unknown",
                "adapter": "unattributed", "receipt_status": "unverified"}],
            "outcome_reason": "unverified", "receipt": {"signature": "operator-secret"}
        });
        redact_projection(&mut value, Projection::Task, &broad_patterns());
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["mode"], "observe");
        assert_eq!(value["outcome"], "deny");
        assert_eq!(value["boundary"], "fetch_cloaking");
        assert_eq!(value["complete"], false);
        assert_eq!(value["inferred_effects"], json!(["network_egress"]));
        assert_eq!(value["provenance"][0]["receipt_status"], "unverified");
        assert_eq!(value["outcome_reason"], "[REDACTED:custom]");
        // A new receipt-shaped field is not permission to expose canonical
        // signed input through a display projection.
        assert_eq!(value["receipt"]["signature"], "[REDACTED:custom]");
    }

    #[test]
    fn invalid_protocol_values_and_lookalike_fields_are_redacted() {
        let mut value = json!({
            "action": "operator-secret", "approval_fallback": "operator-secret",
            "findings": [{"rule_id": "operator-secret", "severity": "operator-secret"}],
            "task_boundary": {"outcome": "allow"}
        });
        redact_projection(&mut value, Projection::Verdict, &broad_patterns());
        assert!(!value.to_string().contains("operator-secret"));
        assert_eq!(value["task_boundary"]["outcome"], "[REDACTED:custom]");
    }

    #[test]
    fn mandatory_secret_redaction_survives_protocol_exemptions() {
        let secret = format!("ghp_{}", "A".repeat(36));
        let mut value = json!({"action": "allow", "policy_path_used": secret,
            "findings": [{"rule_id": "bidi_controls", "title": secret}]});
        redact_projection(
            &mut value,
            Projection::Verdict,
            &CompiledCustomPatterns::new_silent(&[]),
        );
        assert_eq!(value["action"], "allow");
        assert!(!value.to_string().contains(&secret));
    }
}
