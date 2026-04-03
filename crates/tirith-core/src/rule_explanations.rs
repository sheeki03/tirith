//! Rule explanation lookup — compiled from `assets/data/rule_explanations.toml` by `build.rs`.
//!
//! Separate from `rule_metadata.rs` (which handles early-access licensing gates).
//! This module provides human-readable documentation for every `RuleId` variant.

#[derive(serde::Serialize)]
pub struct RuleExplanation {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub severity_rationale: &'static str,
    pub description: &'static str,
    pub examples_bad: &'static [&'static str],
    pub examples_good: &'static [&'static str],
    pub false_positive_guidance: &'static str,
    pub remediation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_id: Option<&'static str>,
    pub references: &'static [&'static str],
}

include!(concat!(env!("OUT_DIR"), "/rule_explanations_gen.rs"));

/// Look up an explanation by snake_case rule ID (e.g., `"pipe_to_interpreter"`).
pub fn explain(id: &str) -> Option<&'static RuleExplanation> {
    RULE_EXPLANATIONS.iter().find(|r| r.id == id)
}

/// All explanations in TOML definition order.
pub fn list_all() -> &'static [RuleExplanation] {
    RULE_EXPLANATIONS
}

/// All explanations for a given category (case-insensitive match).
pub fn list_by_category(category: &str) -> Vec<&'static RuleExplanation> {
    let cat_lower = category.to_ascii_lowercase();
    RULE_EXPLANATIONS
        .iter()
        .filter(|r| r.category.to_ascii_lowercase() == cat_lower)
        .collect()
}

/// All distinct category names in stable (definition) order.
pub fn categories() -> Vec<&'static str> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for r in RULE_EXPLANATIONS {
        if seen.insert(r.category) {
            out.push(r.category);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explain_known_rule() {
        let e = explain("pipe_to_interpreter");
        assert!(e.is_some(), "pipe_to_interpreter must have an explanation");
        let e = e.unwrap();
        assert_eq!(e.category, "command");
        assert!(!e.title.is_empty());
    }

    #[test]
    fn test_explain_unknown_rule() {
        assert!(explain("not_a_real_rule").is_none());
    }

    #[test]
    fn test_list_by_category() {
        let hostname_rules = list_by_category("hostname");
        assert_eq!(hostname_rules.len(), 10);
        for r in &hostname_rules {
            assert_eq!(r.category, "hostname");
        }
    }

    #[test]
    fn test_categories_no_duplicates() {
        let cats = categories();
        let unique: std::collections::HashSet<_> = cats.iter().collect();
        assert_eq!(cats.len(), unique.len(), "categories must be unique");
    }

    #[test]
    fn test_list_by_unknown_category() {
        let rules = list_by_category("nonexistent_category");
        assert!(rules.is_empty());
    }

    #[test]
    fn test_all_explanation_ids_are_valid_rules() {
        // Every explanation ID must map to a valid RuleId variant.
        // The reverse (every RuleId has an explanation) is enforced at build time
        // by EXPECTED_RULES in build.rs and by test_rule_id_list_is_complete in golden_fixtures.rs.
        use crate::verdict::RuleId;
        for entry in list_all() {
            let parsed: Result<RuleId, _> =
                serde_json::from_value(serde_json::Value::String(entry.id.to_string()));
            assert!(
                parsed.is_ok(),
                "explanation id '{}' does not match any RuleId variant",
                entry.id
            );
        }
    }

    #[test]
    fn test_mitre_id_for_rule_matches_toml() {
        // Verify the generated mitre_id_for_rule agrees with the explanation data
        use crate::verdict::RuleId;
        for entry in list_all() {
            if let Some(expected_mitre) = entry.mitre_id {
                // Parse the rule ID back to enum via serde
                let rule_id: RuleId =
                    serde_json::from_value(serde_json::Value::String(entry.id.to_string()))
                        .unwrap_or_else(|_| panic!("cannot parse rule id '{}'", entry.id));
                let actual = mitre_id_for_rule(rule_id);
                assert_eq!(
                    actual,
                    Some(expected_mitre),
                    "MITRE mismatch for {}",
                    entry.id
                );
            }
        }
    }
}
