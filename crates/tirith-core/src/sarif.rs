/// SARIF 2.1.0 output for scan findings.
use crate::verdict::{Finding, Severity};
use std::collections::HashMap;

/// Convert scan findings to SARIF 2.1.0 JSON.
///
/// Each finding becomes a SARIF result, with unique rules collected into the
/// `tool.driver.rules` array. Severity mapping:
///   CRITICAL/HIGH -> "error", MEDIUM -> "warning", LOW/INFO -> "note"
pub fn to_sarif(findings: &[SarifFinding], tool_version: &str) -> serde_json::Value {
    // Collect unique rules by rule_id display string
    let mut rule_map: HashMap<String, usize> = HashMap::new();
    let mut rules = Vec::new();

    for f in findings {
        let rule_str = f.finding.rule_id.to_string();
        if !rule_map.contains_key(&rule_str) {
            let idx = rules.len();
            rule_map.insert(rule_str.clone(), idx);
            rules.push(serde_json::json!({
                "id": rule_str,
                "shortDescription": {
                    "text": f.finding.title
                }
            }));
        }
    }

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let rule_str = f.finding.rule_id.to_string();
            let rule_index = rule_map[&rule_str];
            let level = severity_to_level(f.finding.severity);

            let mut result = serde_json::json!({
                "ruleId": rule_str,
                "ruleIndex": rule_index,
                "level": level,
                "message": {
                    "text": f.finding.description
                }
            });

            if let Some(ref path) = f.file_path {
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
                    "version": tool_version,
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
            },
            SarifFinding {
                finding: &f2,
                file_path: None,
                line_number: None,
            },
        ];
        let sarif = to_sarif(&findings, "0.1.0");
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert_eq!(rules.len(), 1, "Duplicate rule IDs should be deduped");
    }
}
