use regex::Regex;

use crate::extract::ScanContext;
use crate::policy::CustomRule;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// A compiled custom rule ready for matching.
pub struct CompiledCustomRule {
    pub id: String,
    pub regex: Regex,
    pub contexts: Vec<ScanContext>,
    pub severity: Severity,
    pub title: String,
    pub description: String,
}

/// Compile custom rules from policy. Invalid regexes are logged and skipped.
pub fn compile_rules(rules: &[CustomRule]) -> Vec<CompiledCustomRule> {
    let mut compiled = Vec::new();
    for rule in rules {
        if rule.pattern.len() > 1024 {
            eprintln!(
                "tirith: custom rule '{}' pattern too long ({} chars), skipping",
                rule.id,
                rule.pattern.len()
            );
            continue;
        }
        let regex = match Regex::new(&rule.pattern) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "tirith: warning: custom rule '{}' has invalid regex: {e}",
                    rule.id
                );
                continue;
            }
        };

        let contexts: Vec<ScanContext> = rule
            .context
            .iter()
            .filter_map(|c| match c.as_str() {
                "exec" => Some(ScanContext::Exec),
                "paste" => Some(ScanContext::Paste),
                "file" => Some(ScanContext::FileScan),
                other => {
                    eprintln!(
                        "tirith: warning: custom rule '{}' has unknown context: {other}",
                        rule.id
                    );
                    None
                }
            })
            .collect();

        if contexts.is_empty() {
            eprintln!(
                "tirith: warning: custom rule '{}' has no valid contexts, skipping",
                rule.id
            );
            continue;
        }

        compiled.push(CompiledCustomRule {
            id: rule.id.clone(),
            regex,
            contexts,
            severity: rule.severity,
            title: rule.title.clone(),
            description: rule.description.clone(),
        });
    }
    compiled
}

/// Check input against compiled custom rules for a given context.
pub fn check(input: &str, context: ScanContext, compiled: &[CompiledCustomRule]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for rule in compiled {
        if !rule.contexts.contains(&context) {
            continue;
        }

        if let Some(m) = rule.regex.find(input) {
            let matched_text = m.as_str();
            let preview: String = matched_text.chars().take(100).collect();

            findings.push(Finding {
                rule_id: RuleId::CustomRuleMatch,
                severity: rule.severity,
                title: rule.title.clone(),
                description: if rule.description.is_empty() {
                    format!("Custom rule '{}' matched", rule.id)
                } else {
                    rule.description.clone()
                },
                evidence: vec![Evidence::Text {
                    detail: format!("Matched: \"{preview}\""),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: Some(rule.id.clone()),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(id: &str, pattern: &str, contexts: &[&str]) -> CustomRule {
        CustomRule {
            id: id.to_string(),
            pattern: pattern.to_string(),
            context: contexts.iter().map(|s| s.to_string()).collect(),
            severity: Severity::High,
            title: format!("Test rule: {id}"),
            description: String::new(),
        }
    }

    #[test]
    fn test_compile_valid_rule() {
        let rules = vec![make_rule("test1", r"internal\.corp", &["exec"])];
        let compiled = compile_rules(&rules);
        assert_eq!(compiled.len(), 1);
        assert_eq!(compiled[0].id, "test1");
    }

    #[test]
    fn test_compile_invalid_regex_skipped() {
        let rules = vec![make_rule("bad", r"(unclosed", &["exec"])];
        let compiled = compile_rules(&rules);
        assert_eq!(compiled.len(), 0);
    }

    #[test]
    fn test_check_matches_in_context() {
        let rules = vec![make_rule(
            "corp",
            r"internal\.corp\.example\.com",
            &["exec"],
        )];
        let compiled = compile_rules(&rules);

        let findings = check(
            "curl https://internal.corp.example.com/api",
            ScanContext::Exec,
            &compiled,
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::CustomRuleMatch);
        assert_eq!(findings[0].custom_rule_id.as_deref(), Some("corp"));
    }

    #[test]
    fn test_check_no_match_wrong_context() {
        let rules = vec![make_rule("corp", r"internal\.corp", &["exec"])];
        let compiled = compile_rules(&rules);

        let findings = check("internal.corp.example.com", ScanContext::Paste, &compiled);
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn test_check_no_match_when_pattern_absent() {
        let rules = vec![make_rule("corp", r"internal\.corp", &["exec"])];
        let compiled = compile_rules(&rules);

        let findings = check("curl https://example.com", ScanContext::Exec, &compiled);
        assert_eq!(findings.len(), 0);
    }
}
