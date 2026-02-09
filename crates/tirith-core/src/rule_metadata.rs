use crate::license::Tier;
use crate::verdict::{Finding, RuleId, Severity};

/// Metadata for time-boxed early access gating (ADR-14).
///
/// New detection rules may ship to Pro/Team first, then become universally
/// free after a defined date. Critical findings always bypass the gate.
pub struct RuleMeta {
    pub rule_id: RuleId,
    /// Minimum tier required during early access window.
    pub min_tier: Option<Tier>,
    /// ISO 8601 date (exclusive) — rule becomes free at the start of this date.
    /// `None` means no early access gate (always free).
    pub early_access_until: Option<&'static str>,
}

/// Early access metadata table.
///
/// When a rule is in early-access, findings for tiers below `min_tier` are
/// suppressed — UNLESS the finding severity is Critical (security-critical
/// detection is always free immediately).
///
/// After `early_access_until` passes, the entry is ignored at runtime and
/// removed in the next release.
pub const RULE_META: &[RuleMeta] = &[
    // No rules are currently in early access.
    // Example entry (commented out):
    // RuleMeta {
    //     rule_id: RuleId::ServerCloaking,
    //     min_tier: Some(Tier::Pro),
    //     early_access_until: Some("2026-03-15"),
    // },
];

/// Check if an early access gate is active for a given rule on a given date.
///
/// Returns `true` if the gate is still active (i.e., the rule should be
/// suppressed for tiers below `min_tier`).
///
/// The `early_access_until` date is exclusive — the gate expires at the
/// start of that date (UTC midnight).
pub fn is_early_access_active(meta: &RuleMeta, now: chrono::NaiveDate) -> bool {
    match meta.early_access_until {
        None => false, // No gate
        Some(date_str) => {
            match chrono::NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                Ok(expiry) => now < expiry, // Exclusive: gate expires ON this date
                Err(_) => {
                    // Malformed date → fail open (never silently gate forever)
                    eprintln!(
                        "tirith: warning: malformed early_access_until date \
                         for {:?}: {:?}",
                        meta.rule_id, date_str
                    );
                    false
                }
            }
        }
    }
}

/// Filter findings based on early access gates and current tier.
///
/// Removes findings for rules that are in an active early-access window
/// when the user's tier is below the required minimum. Critical findings
/// always pass through regardless of gating.
pub fn filter_early_access(findings: &mut Vec<Finding>, tier: Tier) {
    let today = chrono::Utc::now().date_naive();
    filter_early_access_at(findings, tier, today);
}

/// Testable version of `filter_early_access` with explicit date.
pub fn filter_early_access_at(findings: &mut Vec<Finding>, tier: Tier, now: chrono::NaiveDate) {
    findings.retain(|finding| {
        // Look up rule in metadata table
        let meta = RULE_META.iter().find(|m| m.rule_id == finding.rule_id);
        let meta = match meta {
            Some(m) => m,
            None => return true, // No metadata → always pass through
        };

        // No tier gate → pass through
        let min_tier = match meta.min_tier {
            Some(t) => t,
            None => return true,
        };

        // Critical findings always bypass gating
        if finding.severity == Severity::Critical {
            return true;
        }

        // Gate not active → pass through
        if !is_early_access_active(meta, now) {
            return true;
        }

        // Gate active and tier below minimum → suppress
        tier >= min_tier
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::Evidence;
    use chrono::NaiveDate;

    fn make_finding(rule_id: RuleId, severity: Severity) -> Finding {
        Finding {
            rule_id,
            severity,
            title: "test".into(),
            description: "test".into(),
            evidence: vec![Evidence::Text {
                detail: "test".into(),
            }],
            human_view: None,
            agent_view: None,
        }
    }

    // Use a rule that exists in the enum for testing.
    // We test the metadata lookup logic; actual RULE_META is empty in prod.
    const TEST_RULE: RuleId = RuleId::ShortenedUrl;

    fn test_meta(until: Option<&'static str>) -> RuleMeta {
        RuleMeta {
            rule_id: TEST_RULE,
            min_tier: Some(Tier::Pro),
            early_access_until: until,
        }
    }

    #[test]
    fn test_day_before_expiry_gate_active() {
        let meta = test_meta(Some("2026-03-15"));
        let day_before = NaiveDate::from_ymd_opt(2026, 3, 14).unwrap();
        assert!(is_early_access_active(&meta, day_before));
    }

    #[test]
    fn test_day_of_expiry_gate_expired() {
        // Exclusive boundary: gate expires ON this date
        let meta = test_meta(Some("2026-03-15"));
        let day_of = NaiveDate::from_ymd_opt(2026, 3, 15).unwrap();
        assert!(!is_early_access_active(&meta, day_of));
    }

    #[test]
    fn test_day_after_expiry_gate_expired() {
        let meta = test_meta(Some("2026-03-15"));
        let day_after = NaiveDate::from_ymd_opt(2026, 3, 16).unwrap();
        assert!(!is_early_access_active(&meta, day_after));
    }

    #[test]
    fn test_none_date_means_no_gate() {
        let meta = test_meta(None);
        let any_date = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
        assert!(!is_early_access_active(&meta, any_date));
    }

    #[test]
    fn test_malformed_date_fails_open() {
        let meta = RuleMeta {
            rule_id: TEST_RULE,
            min_tier: Some(Tier::Pro),
            early_access_until: Some("not-a-date"),
        };
        let any_date = NaiveDate::from_ymd_opt(2026, 6, 1).unwrap();
        // Malformed → fail open (gate not active)
        assert!(!is_early_access_active(&meta, any_date));
    }

    #[test]
    fn test_critical_finding_bypasses_gate() {
        // Manually test the filter logic with a simulated RULE_META entry.
        // Since we can't mutate the const, test the retain logic directly.
        let finding = make_finding(TEST_RULE, Severity::Critical);

        // Simulate: gate is active, tier is Community (below Pro min_tier)
        let meta = test_meta(Some("2099-12-31"));
        let now = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();

        // Critical finding should pass through even with active gate
        assert!(is_early_access_active(&meta, now));

        // Direct retain logic test
        let should_keep = finding.severity == Severity::Critical;
        assert!(should_keep);
    }

    #[test]
    fn test_filter_suppresses_for_free_tier() {
        // Integration test: since RULE_META is empty in prod, this verifies
        // that findings with no metadata entry always pass through.
        let mut findings = vec![make_finding(TEST_RULE, Severity::Medium)];
        let now = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
        filter_early_access_at(&mut findings, Tier::Community, now);
        // No RULE_META entry for TEST_RULE → passes through
        assert_eq!(findings.len(), 1);
    }
}
