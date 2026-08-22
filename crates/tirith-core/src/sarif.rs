/// SARIF 2.1.0 output for scan findings.
use crate::rule_explanations;
use crate::verdict::{Finding, Severity};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

fn project_sarif_text(value: &str) -> String {
    let share_safe =
        crate::redact::redact_for_audience(value, crate::redact::ShareAudience::PublicPaste)
            .redacted_content;
    crate::redact::redact_blocked_output(&share_safe)
}

fn raw_and_projected_rule_identity(finding: &Finding) -> (String, String) {
    let raw = finding
        .custom_rule_id
        .clone()
        .unwrap_or_else(|| finding.rule_id.to_string());
    let projected = project_sarif_text(&raw);
    (raw, projected)
}

fn sarif_fingerprint_v2(projected_rule: &str, projected_path: &str, line_number: u64) -> String {
    let mut hasher = Sha256::new();
    // Hash only fields already emitted publicly in SARIF. Free-form finding
    // text/evidence may contain an unrecognized low-entropy secret; hashing it
    // would create an offline dictionary oracle and would churn dedup identity
    // whenever explanatory wording changes.
    for component in [projected_rule, projected_path, &line_number.to_string()] {
        let bytes = component.as_bytes();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    hex::encode(hasher.finalize())
}

/// Convert scan findings to SARIF 2.1.0 JSON. Severity maps as
/// CRITICAL/HIGH -> "error", MEDIUM -> "warning", LOW/INFO -> "note".
pub fn to_sarif(findings: &[SarifFinding], tool_version: &str) -> serde_json::Value {
    let mut rule_map: HashMap<String, usize> = HashMap::new();
    let mut rules = Vec::new();

    // Projection is intentionally non-injective: two private custom IDs may
    // become the same public text. Distinguishing them with a raw-derived hash
    // would create a dictionary oracle, while encounter/set ordinals would
    // make rule IDs unstable across runs. Instead, custom rules live in a
    // closed `custom/` namespace and projected collisions deliberately share
    // one public descriptor and fingerprint.
    let mut custom_projected_raw_ids: HashMap<String, HashSet<String>> = HashMap::new();
    for finding in findings {
        if finding.finding.custom_rule_id.is_some() {
            let (raw, projected) = raw_and_projected_rule_identity(finding.finding);
            custom_projected_raw_ids
                .entry(projected)
                .or_default()
                .insert(raw);
        }
    }

    let rule_identity = |finding: &Finding| {
        let custom = finding.custom_rule_id.is_some();
        let (raw, projected) = raw_and_projected_rule_identity(finding);
        if custom {
            let projected_collision = custom_projected_raw_ids
                .get(&projected)
                .is_some_and(|raw_ids| raw_ids.len() > 1);
            let presentation = format!("custom/{projected}");
            (raw, presentation, projected_collision, true)
        } else {
            (raw, projected, false, false)
        }
    };

    for f in findings {
        // Custom rules share RuleId::CustomRuleMatch, so key descriptors by
        // their stable public custom namespace. Private IDs that collapse to
        // the same public projection intentionally aggregate.
        let (raw_rule_str, rule_str, projected_collision, custom) = rule_identity(f.finding);
        if !rule_map.contains_key(&rule_str) {
            let idx = rules.len();
            rule_map.insert(rule_str.clone(), idx);

            let mut rule = serde_json::json!({
                "id": rule_str,
                "shortDescription": {
                    "text": if custom {
                        format!("Custom rule: {}", rule_str.trim_start_matches("custom/"))
                    } else {
                        project_sarif_text(&f.finding.title)
                    }
                }
            });

            if projected_collision {
                rule["properties"] = serde_json::json!({
                    "tirithProjectedRuleCollision": true
                });
            }

            if !custom {
                if let Some(explanation) = rule_explanations::explain(&raw_rule_str) {
                    rule["fullDescription"] = serde_json::json!({
                        "text": project_sarif_text(explanation.description)
                    });

                    let mut tags: Vec<&str> = Vec::new();
                    if let Some(mitre) = explanation.mitre_id {
                        tags.push(mitre);
                    }
                    if !tags.is_empty() {
                        rule["properties"]["tags"] = serde_json::json!(tags);
                    }

                    if let Some(uri) = explanation.references.first() {
                        rule["helpUri"] = serde_json::json!(uri);
                    }
                }
            }

            rules.push(rule);
        }
    }

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let (_, rule_str, projected_collision, _) = rule_identity(f.finding);
            let rule_index = rule_map[&rule_str];
            let level = severity_to_level(f.finding.severity);
            let projected_path = f.file_path.as_deref().map(project_sarif_text);
            let mut result = serde_json::json!({
                "ruleId": rule_str.clone(),
                "ruleIndex": rule_index,
                "level": level,
                "message": {
                    "text": project_sarif_text(&f.finding.description)
                }
            });
            if projected_collision {
                result["properties"] = serde_json::json!({
                    "tirithProjectedRuleCollision": true,
                    "tirithStableProjectedRuleId": rule_str.clone(),
                });
            }

            // Versioned, privacy-safe fingerprint for deduplication across
            // runs. It uses the same stable public rule ID emitted in SARIF,
            // never a hidden raw custom ID.
            result["fingerprints"] = serde_json::json!({
                "tirith/v2": sarif_fingerprint_v2(
                    &rule_str,
                    projected_path.as_deref().unwrap_or(""),
                    f.line_number.unwrap_or(0),
                )
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
    use crate::verdict::{Evidence, Finding, RuleId, Severity};

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
        let fp = result["fingerprints"]["tirith/v2"].as_str().unwrap();
        assert_eq!(fp.len(), 64);
        assert!(fp.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(result["fingerprints"].get("tirith/v1").is_none());
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
        let fp = results[0]["fingerprints"]["tirith/v2"].as_str().unwrap();
        assert_eq!(fp.len(), 64);
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
    fn projected_custom_rule_collisions_collapse_to_stable_public_identity() {
        let first_secret = format!("ghp_{}", "A".repeat(36));
        let second_secret = format!("ghp_{}", "B".repeat(36));
        let mut first = make_finding(RuleId::CustomRuleMatch, Severity::High, "same title");
        first.description = "same description".to_string();
        first.custom_rule_id = Some(format!("custom-{first_secret}"));
        let mut second = first.clone();
        second.custom_rule_id = Some(format!("custom-{second_secret}"));
        let findings = vec![
            SarifFinding {
                finding: &first,
                file_path: Some("src/main.rs".to_string()),
                line_number: Some(1),
                suppressed: false,
            },
            SarifFinding {
                finding: &second,
                file_path: Some("src/main.rs".to_string()),
                line_number: Some(1),
                suppressed: false,
            },
        ];

        let sarif = to_sarif(&findings, "0.1.0");
        let serialized = sarif.to_string();
        assert!(!serialized.contains(&first_secret), "{serialized}");
        assert!(!serialized.contains(&second_secret), "{serialized}");
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(
            rules.len(),
            1,
            "private projected collisions must aggregate"
        );
        assert_eq!(results[0]["ruleId"], results[1]["ruleId"]);
        assert!(results[0]["ruleId"]
            .as_str()
            .unwrap()
            .starts_with("custom/"));
        assert_eq!(
            results[0]["fingerprints"]["tirith/v2"], results[1]["fingerprints"]["tirith/v2"],
            "a hidden raw-ID collision must not enter public dedup identity"
        );
        assert_eq!(
            results[0]["properties"]["tirithProjectedRuleCollision"],
            true
        );

        let singleton = to_sarif(&findings[..1], "0.1.0");
        assert_eq!(
            singleton["runs"][0]["results"][0]["ruleId"], results[0]["ruleId"],
            "adding a private projected collision must not churn the public rule ID"
        );
        assert_eq!(
            singleton["runs"][0]["results"][0]["fingerprints"]["tirith/v2"],
            results[0]["fingerprints"]["tirith/v2"],
            "adding a projected-colliding rule must not churn existing history"
        );

        let reversed = vec![
            SarifFinding {
                finding: &second,
                file_path: Some("src/main.rs".to_string()),
                line_number: Some(1),
                suppressed: false,
            },
            SarifFinding {
                finding: &first,
                file_path: Some("src/main.rs".to_string()),
                line_number: Some(1),
                suppressed: false,
            },
        ];
        let reversed_sarif = to_sarif(&reversed, "0.1.0");
        assert!(
            reversed_sarif["runs"][0]["results"]
                .as_array()
                .unwrap()
                .iter()
                .all(|result| {
                    result["ruleId"] == results[0]["ruleId"]
                        && result["fingerprints"]["tirith/v2"]
                            == results[0]["fingerprints"]["tirith/v2"]
                }),
            "input order must not affect public rule or fingerprint identity"
        );
    }

    #[test]
    fn custom_rule_equal_to_builtin_gets_a_distinct_descriptor() {
        let builtin = make_finding(RuleId::AnsiEscapes, Severity::High, "builtin");
        let mut custom = make_finding(RuleId::CustomRuleMatch, Severity::High, "custom");
        custom.custom_rule_id = Some(builtin.rule_id.to_string());
        let findings = vec![
            SarifFinding {
                finding: &custom,
                file_path: None,
                line_number: None,
                suppressed: false,
            },
            SarifFinding {
                finding: &builtin,
                file_path: None,
                line_number: None,
                suppressed: false,
            },
        ];

        let sarif = to_sarif(&findings, "0.1.0");
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        assert_ne!(results[0]["ruleId"], results[1]["ruleId"]);
        assert_eq!(results[0]["ruleId"], "custom/ansi_escapes");
        assert_eq!(results[1]["ruleId"], builtin.rule_id.to_string());
        assert_ne!(
            results[0]["fingerprints"]["tirith/v2"],
            results[1]["fingerprints"]["tirith/v2"]
        );
    }

    #[test]
    fn custom_namespace_is_injective_for_public_projected_ids() {
        let mut first = make_finding(RuleId::CustomRuleMatch, Severity::High, "first");
        first.custom_rule_id = Some("foo".to_string());
        let mut second = make_finding(RuleId::CustomRuleMatch, Severity::High, "second");
        second.custom_rule_id = Some("custom/foo".to_string());

        let findings = [&first, &second]
            .into_iter()
            .map(|finding| SarifFinding {
                finding,
                file_path: None,
                line_number: None,
                suppressed: false,
            })
            .collect::<Vec<_>>();
        let sarif = to_sarif(&findings, "0.1.0");
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        let ids = results
            .iter()
            .map(|result| result["ruleId"].as_str().unwrap())
            .collect::<HashSet<_>>();
        assert_eq!(
            ids.len(),
            2,
            "public custom projections must remain injective"
        );
        assert!(ids.contains("custom/foo"));
        assert!(ids.contains("custom/custom/foo"));
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
            result["fingerprints"]["tirith/v2"]
                .as_str()
                .expect("v2 fingerprint")
                .len(),
            64
        );
    }

    #[test]
    fn fingerprint_v2_is_stable_across_wording_and_private_evidence_changes() {
        let mut first = make_finding(RuleId::AnsiEscapes, Severity::High, "first wording");
        first.evidence = vec![Evidence::Text {
            detail: "PIN=0000".to_string(),
        }];
        let mut second = make_finding(RuleId::AnsiEscapes, Severity::High, "new wording");
        second.evidence = vec![Evidence::Text {
            detail: "PIN=9999".to_string(),
        }];
        let make = |finding| SarifFinding {
            finding,
            file_path: Some("src/main.rs".to_string()),
            line_number: Some(7),
            suppressed: false,
        };

        let first_once = to_sarif(&[make(&first)], "0.1.0");
        let first_twice = to_sarif(&[make(&first)], "0.1.0");
        let second_sarif = to_sarif(&[make(&second)], "0.1.0");
        let fingerprint = |sarif: &serde_json::Value| {
            sarif["runs"][0]["results"][0]["fingerprints"]["tirith/v2"]
                .as_str()
                .expect("v2 fingerprint")
                .to_string()
        };

        assert_eq!(fingerprint(&first_once), fingerprint(&first_twice));
        assert_eq!(
            fingerprint(&first_once),
            fingerprint(&second_sarif),
            "private/free-form text must not become a fingerprint oracle or churn dedup identity"
        );
    }
}
