//! Privacy contracts for Tirith-owned machine projections. Upstream MCP payloads
//! must use `output_filter`; they cannot opt into these protocol-field exemptions.

use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

use crate::redact::CompiledCustomPatterns;

/// Select the schema at the producing call site, never from an untrusted field.
#[derive(Clone, Copy)]
pub enum Projection {
    Verdict,
    SafeSuggestion,
    Run,
    RunReceipt,
    Score,
    ScoreFactor,
    Install,
    InstallAnalysis,
    InstallOutcome,
    InstallUrl,
    InstallPackage,
    CommandsError,
    HistoryRecord,
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
    pub(crate) fn for_tool(name: Option<&str>) -> Self {
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
pub fn redact_projection(value: &mut Value, schema: Projection, compiled: &CompiledCustomPatterns) {
    project_sensitive_strings(value, schema, &|text| {
        crate::redact::redact_sanitize_redact_with_compiled(text, compiled)
    });
}

/// Apply an audience-specific content projection through the same schema.
/// Callers cannot use this to rewrite protocol tokens or signed representations.
pub(crate) fn project_sensitive_strings(
    value: &mut Value,
    schema: Projection,
    project: &impl Fn(&str) -> String,
) {
    match value {
        Value::Array(items) => {
            for item in items {
                project_sensitive_strings(item, schema, project);
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                if protocol_field(schema, key, value) {
                    continue;
                }
                let child = match (schema, key.as_str()) {
                    (
                        Projection::Verdict
                        | Projection::FileScan
                        | Projection::Cloaking
                        | Projection::Score,
                        "findings",
                    ) => Projection::Finding,
                    (Projection::DirectoryScan, "files") => Projection::FileScan,
                    (Projection::Run | Projection::InstallAnalysis, "verdict") => {
                        Projection::Verdict
                    }
                    (Projection::Run, "receipt") => Projection::RunReceipt,
                    (Projection::Score, "score_breakdown") => Projection::Score,
                    (Projection::Score, "factors") => Projection::ScoreFactor,
                    (Projection::InstallUrl, "preflight") => Projection::Verdict,
                    (Projection::InstallUrl, "outcome") => Projection::Run,
                    (Projection::Install, "analysis") => Projection::InstallAnalysis,
                    (Projection::Install, "outcome") => Projection::InstallOutcome,
                    (Projection::InstallAnalysis, "packages") => Projection::InstallPackage,
                    (Projection::DirectoryScan | Projection::FileScan, "coverage_gaps") => {
                        Projection::CoverageGap
                    }
                    (Projection::Verdict | Projection::HistoryRecord, "agent_origin") => {
                        Projection::AgentOrigin
                    }
                    (Projection::Verdict, "safe_suggestions") => Projection::SafeSuggestion,
                    (Projection::Finding, "evidence") => Projection::Evidence,
                    (Projection::Task, "provenance") => Projection::Provenance,
                    (Projection::Cloaking, "task_boundary") => Projection::Task,
                    (Projection::Cloaking, "agents") => Projection::Agent,
                    (Projection::Cloaking, "diffs") => Projection::Diff,
                    _ => Projection::Content,
                };
                project_sensitive_strings(value, child, project);
            }
        }
        Value::String(text) => *text = project(text),
        _ => {}
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
        (Verdict, "action" | "approval_fallback")
        | (Run | InstallUrl | CommandsError, "action") => {
            canonical::<crate::verdict::Action>(value)
        }
        (Score | InstallPackage, "risk_level") => {
            token(value, &["low", "medium", "high", "critical"])
        }
        (RunReceipt, "sha256") => value
            .as_str()
            .is_some_and(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())),
        (RunReceipt, "privilege") => token(value, &["user", "normal", "elevated"]),
        (RunReceipt, "timestamp") => value
            .as_str()
            .is_some_and(|v| chrono::DateTime::parse_from_rfc3339(v).is_ok()),
        (ScoreFactor, "id") => token(
            value,
            &[
                "base_severity",
                "additional_findings",
                "threat_intel_corroboration",
                "clamp",
            ],
        ),
        (Install, "kind") => token(value, &["install"]),
        (InstallAnalysis, "kind") => token(value, &["install_analysis"]),
        (InstallOutcome, "kind") => token(value, &["install_outcome"]),
        (InstallUrl, "kind") => token(value, &["install_url"]),
        (InstallUrl, "execution_policy") => token(value, &["contained_by_default"]),
        (Install, "status") => token(
            value,
            &["not_run", "spawn_failed", "signal_terminated", "exited"],
        ),
        (InstallOutcome, "verdict_action") => token(value, &["Allow", "Warn", "WarnAck", "Block"]),
        (InstallAnalysis | InstallOutcome, "manager") => token(
            value,
            &[
                "npm", "pnpm", "yarn", "bun", "pip", "pip3", "uv", "cargo", "gem", "go", "brew",
                "apt", "apt-get", "dnf", "yum", "pacman", "winget", "choco", "scoop",
            ],
        ),
        (CommandsError, "kind") => token(value, &["commands_error"]),
        (CommandsError, "status") => token(value, &["error"]),
        (HistoryRecord, "action" | "raw_action") => token(
            value,
            &[
                "Allow", "Warn", "WarnAck", "Block", "allow", "warn", "warn_ack", "block",
            ],
        ),
        (HistoryRecord, "rule_ids" | "raw_rule_ids") => {
            canonical::<Vec<crate::verdict::RuleId>>(value)
        }
        (HistoryRecord, "entry_type") => token(
            value,
            &["verdict", "hook_telemetry", "trust_change", "task_boundary"],
        ),
        (HistoryRecord, "timestamp") => value
            .as_str()
            .is_some_and(|text| chrono::DateTime::parse_from_rfc3339(text).is_ok()),
        (HistoryRecord, "event_id") => value
            .as_str()
            .is_some_and(|text| uuid::Uuid::parse_str(text).is_ok()),
        (SafeSuggestion, "rule_id") => {
            canonical::<crate::verdict::RuleId>(value)
                || token(
                    value,
                    &["sudo_narrow", "env_scrub", "composed_safe_command"],
                )
        }
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
    fn nested_cli_contracts_preserve_metadata_and_redact_sensitive_values() {
        let digest = "a".repeat(64);
        let mut run = json!({"action": "block", "error": "block",
            "verdict": {"action": "warn_ack", "findings": [{"rule_id": "curl_pipe_shell", "severity": "HIGH", "description": "operator-secret"}]},
            "receipt": {"sha256": digest, "timestamp": "2026-09-12T00:00:00Z", "privilege": "user", "url": "https://operator-secret.example", "analysis_method": "operator-secret"}});
        redact_projection(&mut run, Projection::Run, &broad_patterns());
        assert_eq!(run["action"], "block");
        assert_eq!(run["verdict"]["action"], "warn_ack");
        assert_eq!(run["verdict"]["findings"][0]["rule_id"], "curl_pipe_shell");
        assert_eq!(run["receipt"]["sha256"], digest);
        assert_eq!(run["receipt"]["privilege"], "user");
        assert_eq!(run["receipt"]["timestamp"], "2026-09-12T00:00:00Z");
        assert_eq!(run["error"], "[REDACTED:custom]");
        assert!(!run.to_string().contains("operator-secret"));

        let mut install = json!({"kind": "install", "status": "not_run",
            "analysis": {"kind": "install_analysis", "manager": "npm", "command": "operator-secret", "verdict": {"action": "block"}},
            "outcome": {"kind": "install_outcome", "manager": "npm", "verdict_action": "Block", "error": "operator-secret"}});
        redact_projection(&mut install, Projection::Install, &broad_patterns());
        assert_eq!(install["kind"], "install");
        assert_eq!(install["status"], "not_run");
        assert_eq!(install["analysis"]["manager"], "npm");
        assert_eq!(install["analysis"]["verdict"]["action"], "block");
        assert_eq!(install["outcome"]["verdict_action"], "Block");
        assert!(!install.to_string().contains("operator-secret"));

        let mut score = json!({"risk_level": "high", "url": "operator-secret",
            "score_breakdown": {"risk_level": "high", "factors": [{"id": "base_severity", "label": "operator-secret", "detail": "operator-secret"}]}});
        redact_projection(&mut score, Projection::Score, &broad_patterns());
        assert_eq!(score["risk_level"], "high");
        assert_eq!(
            score["score_breakdown"]["factors"][0]["id"],
            "base_severity"
        );
        assert!(!score.to_string().contains("operator-secret"));
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
