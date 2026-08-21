/// SARIF 2.1.0 output for scan findings.
use crate::rule_explanations;
use crate::verdict::{Finding, Severity};
use std::collections::HashMap;

fn project_sarif_text(value: &str) -> String {
    let share_safe =
        crate::redact::redact_for_audience(value, crate::redact::ShareAudience::PublicPaste)
            .redacted_content;
    crate::redact::redact_blocked_output(&share_safe)
}

/// Convert scan findings to SARIF 2.1.0 JSON. Severity maps as
/// CRITICAL/HIGH -> "error", MEDIUM -> "warning", LOW/INFO -> "note".
pub fn to_sarif(findings: &[SarifFinding], tool_version: &str) -> serde_json::Value {
    let mut rule_map: HashMap<String, usize> = HashMap::new();
    let mut rules = Vec::new();

    for f in findings {
        // repo-0467: custom rules share RuleId::CustomRuleMatch; their real
        // identity lives in `custom_rule_id`. Key the SARIF rule descriptor
        // by the EFFECTIVE id so distinct custom rules get distinct
        // descriptors and fingerprints.
        let raw_rule_str = f
            .finding
            .custom_rule_id
            .clone()
            .unwrap_or_else(|| f.finding.rule_id.to_string());
        let rule_str = project_sarif_text(&raw_rule_str);
        if !rule_map.contains_key(&rule_str) {
            let idx = rules.len();
            rule_map.insert(rule_str.clone(), idx);

            let mut rule = serde_json::json!({
                "id": rule_str,
                "shortDescription": {
                    "text": project_sarif_text(&f.finding.title)
                }
            });

            if let Some(explanation) = rule_explanations::explain(&raw_rule_str) {
                rule["fullDescription"] = serde_json::json!({
                    "text": project_sarif_text(explanation.description)
                });

                let mut tags: Vec<&str> = Vec::new();
                if let Some(mitre) = explanation.mitre_id {
                    tags.push(mitre);
                }
                if !tags.is_empty() {
                    rule["properties"] = serde_json::json!({
                        "tags": tags
                    });
                }

                if let Some(uri) = explanation.references.first() {
                    rule["helpUri"] = serde_json::json!(uri);
                }
            }

            rules.push(rule);
        }
    }

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let rule_str = project_sarif_text(
                &f.finding
                    .custom_rule_id
                    .clone()
                    .unwrap_or_else(|| f.finding.rule_id.to_string()),
            );
            let rule_index = rule_map[&rule_str];
            let level = severity_to_level(f.finding.severity);
            let projected_path = f.file_path.as_deref().map(project_sarif_text);

            let mut result = serde_json::json!({
                "ruleId": rule_str,
                "ruleIndex": rule_index,
                "level": level,
                "message": {
                    "text": project_sarif_text(&f.finding.description)
                }
            });

            // Fingerprint for deduplication across runs
            let rule_id_str = &rule_str;
            result["fingerprints"] = serde_json::json!({
                "tirith/v1": format!("{}:{}:{}",
                    rule_id_str,
                    projected_path.as_deref().unwrap_or(""),
                    f.line_number.unwrap_or(0))
            });

            if let Some(path) = projected_path {
                let mut location = serde_json::json!({
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": path
                        }
                    }
                });

                if let Some(line) = f.line_number {
                    location["physicalLocation"]["region"] = serde_json::json!({
                        "startLine": line
                    });
                }

                result["locations"] = serde_json::json!([location]);
            }

            // Suppressions for policy-allowlisted findings
            if f.suppressed {
                result["suppressions"] = serde_json::json!([{
                    "kind": "inSource",
                    "justification": "Suppressed by policy allowlist"
                }]);
            }

            result
        })
        .collect();

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "tirith",
                    "version": project_sarif_text(tool_version),
                    "informationUri": "https://tirith.dev",
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

/// A finding with optional file location context for SARIF output.
pub struct SarifFinding<'a> {
    pub finding: &'a Finding,
    pub file_path: Option<String>,
    pub line_number: Option<u64>,
    /// Whether this finding was suppressed by the policy allowlist.
    pub suppressed: bool,
}

fn severity_to_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Finding, RuleId, Severity};

    fn make_finding(rule_id: RuleId, severity: Severity, title: &str) -> Finding {
        Finding {
            rule_id,
            severity,
            title: title.to_string(),
            description: format!("{title} description"),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }
    }

    #[test]
    fn test_empty_findings() {
        let sarif = to_sarif(&[], "0.1.0");
        assert_eq!(sarif["version"], "2.1.0");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_single_finding() {
        let f = make_finding(RuleId::AnsiEscapes, Severity::High, "ANSI escape");
        let findings = vec![SarifFinding {
            finding: &f,
            file_path: Some("test.sh".to_string()),
            line_number: Some(5),
            suppressed: false,
        }];
        let sarif = to_sarif(&findings, "0.1.0");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
            5
        );
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(severity_to_level(Severity::Critical), "error");
        assert_eq!(severity_to_level(Severity::High), "error");
        assert_eq!(severity_to_level(Severity::Medium), "warning");
        assert_eq!(severity_to_level(Severity::Low), "note");
        assert_eq!(severity_to_level(Severity::Info), "note");
    }

    #[test]
    fn test_dedup_rules() {
        let f1 = make_finding(RuleId::AnsiEscapes, Severity::High, "ANSI");
        let f2 = make_finding(RuleId::AnsiEscapes, Severity::Medium, "ANSI");
        let findings = vec![
            SarifFinding {
                finding: &f1,
                file_path: None,
                line_number: None,
                suppressed: false,
            },
            SarifFinding {
                finding: &f2,
                file_path: None,
                line_number: None,
                suppressed: false,
            },
        ];
        let sarif = to_sarif(&findings, "0.1.0");
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1, "Duplicate rule IDs should be deduped");
    }

    #[test]
    fn test_rule_enrichment_full_description() {
        // AnsiEscapes has an explanation entry, so fullDescription should be populated
        let f = make_finding(RuleId::AnsiEscapes, Severity::High, "ANSI escape");
        let findings = vec![SarifFinding {
            finding: &f,
            file_path: None,
            line_number: None,
            suppressed: false,
        }];
        let sarif = to_sarif(&findings, "0.1.0");
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert!(
            rule.get("fullDescription").is_some(),
            "fullDescription should be present for rules with explanations"
        );
        assert!(
            !rule["fullDescription"]["text"].as_str().unwrap().is_empty(),
            "fullDescription text should not be empty"
        );
    }

    #[test]
    fn test_rule_enrichment_mitre_tags() {
        // MixedScriptInLabel has mitre_id = "T1036.005" in rule_explanations.toml
        let f = make_finding(RuleId::MixedScriptInLabel, Severity::High, "Mixed script");
        let findings = vec![SarifFinding {
            finding: &f,
            file_path: None,
            line_number: None,
            suppressed: false,
        }];
        let sarif = to_sarif(&findings, "0.1.0");
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let rule = &rules[0];
        let tags = rule["properties"]["tags"].as_array().unwrap();
        assert!(
            tags.iter().any(|t| t.as_str() == Some("T1036.005")),
            "MITRE ATT&CK tag should be present"
        );
    }

    #[test]
    fn test_rule_enrichment_help_uri() {
        // MixedScriptInLabel has references in rule_explanations.toml
        let f = make_finding(RuleId::MixedScriptInLabel, Severity::High, "Mixed script");
        let findings = vec![SarifFinding {
            finding: &f,
            file_path: None,
            line_number: None,
            suppressed: false,
        }];
        let sarif = to_sarif(&findings, "0.1.0");
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let rule = &rules[0];
        assert!(
            rule.get("helpUri").is_some(),
            "helpUri should be present for rules with references"
        );
        let uri = rule["helpUri"].as_str().unwrap();
        assert!(uri.starts_with("https://"), "helpUri should be a valid URL");
    }

    #[test]
    fn test_fingerprint_present() {
        let f = make_finding(RuleId::AnsiEscapes, Severity::High, "ANSI escape");
        let findings = vec![SarifFinding {
            finding: &f,
            file_path: Some("test.sh".to_string()),
            line_number: Some(5),
            suppressed: false,
        }];
        let sarif = to_sarif(&findings, "0.1.0");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let result = &results[0];
        let fp = result["fingerprints"]["tirith/v1"].as_str().unwrap();
        assert_eq!(fp, "ansi_escapes:test.sh:5");
    }

    #[test]
    fn test_fingerprint_no_file() {
        let f = make_finding(RuleId::AnsiEscapes, Severity::High, "ANSI escape");
        let findings = vec![SarifFinding {
            finding: &f,
            file_path: None,
            line_number: None,
            suppressed: false,
        }];
        let sarif = to_sarif(&findings, "0.1.0");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let fp = results[0]["fingerprints"]["tirith/v1"].as_str().unwrap();
        assert_eq!(fp, "ansi_escapes::0");
    }

    #[test]
    fn test_suppression_present_when_suppressed() {
        let f = make_finding(RuleId::AnsiEscapes, Severity::High, "ANSI escape");
        let findings = vec![SarifFinding {
            finding: &f,
            file_path: Some("test.sh".to_string()),
            line_number: None,
            suppressed: true,
        }];
        let sarif = to_sarif(&findings, "0.1.0");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let suppressions = results[0]["suppressions"].as_array().unwrap();
        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0]["kind"], "inSource");
    }

    #[test]
    fn test_no_suppression_when_not_suppressed() {
        let f = make_finding(RuleId::AnsiEscapes, Severity::High, "ANSI escape");
        let findings = vec![SarifFinding {
            finding: &f,
            file_path: None,
            line_number: None,
            suppressed: false,
        }];
        let sarif = to_sarif(&findings, "0.1.0");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert!(
            results[0].get("suppressions").is_none(),
            "suppressions should not be present when not suppressed"
        );
    }

    #[test]
    fn sarif_projects_custom_rule_text_path_and_fingerprint() {
        let secret = format!("ghp_{}", "S".repeat(36));
        let mut finding = make_finding(
            RuleId::CustomRuleMatch,
            Severity::High,
            &format!("title {secret}"),
        );
        finding.description = format!("description {secret}");
        finding.custom_rule_id = Some(format!("custom-{secret}"));
        let findings = vec![SarifFinding {
            finding: &finding,
            file_path: Some(format!("/Users/alice/private/{secret}.txt")),
            line_number: Some(9),
            suppressed: false,
        }];

        let sarif = to_sarif(&findings, "0.1.0");
        let serialized = sarif.to_string();
        assert!(!serialized.contains(&secret), "{serialized}");
        assert!(!serialized.contains("/Users/alice"), "{serialized}");
        assert!(serialized.contains("REDACTED"), "{serialized}");
    }

    #[test]
    fn sarif_preserves_benign_relative_locations_and_rule_ids() {
        let finding = make_finding(RuleId::AnsiEscapes, Severity::High, "ANSI escape");
        let findings = vec![SarifFinding {
            finding: &finding,
            file_path: Some("src/bin/check.rs".to_string()),
            line_number: Some(7),
            suppressed: false,
        }];
        let sarif = to_sarif(&findings, "0.1.0");
        let result = &sarif["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "ansi_escapes");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "src/bin/check.rs"
        );
        assert_eq!(
            result["fingerprints"]["tirith/v1"],
            "ansi_escapes:src/bin/check.rs:7"
        );
    }
}
