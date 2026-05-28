//! Deterministic, fully explainable risk scoring.
//!
//! tirith's risk score is **not** a learned model, a statistical classifier, or
//! any black box. It is a fixed sum of named, inspectable factors. Every score
//! is reproducible by hand from the finding set: read the breakdown, add the
//! per-factor contributions, clamp to 100, done.
//!
//! ## The factor model
//!
//! The score for a URL/command is the sum of:
//!
//! 1. **Base severity** — the single highest-severity finding sets a base value
//!    (`Critical` 90, `High` 70, `Medium` 40, `Low` 15, `Info`/none 0). This is
//!    the dominant term: one critical finding alone scores 90.
//! 2. **Additional findings** — each finding *beyond the first* adds a flat +5.
//!    More independent problems mean more risk, but secondarily to severity.
//! 3. **Threat-intel corroboration** (context-aware, additive) — if at least
//!    one finding comes from the local threat-intelligence database (a known-bad
//!    package / IP / URL / typosquat) *and* there is at least one other finding,
//!    add +5. A threat-DB hit is an unambiguous, deterministic external
//!    corroboration that the other findings are not a false positive. It is
//!    additive only and never fires on its own, so it cannot push a clean URL
//!    up — it only sharpens an already-flagged one.
//!
//! The final score is `min(100, sum)`. The clamp itself is reported as a factor
//! when it bites, so the breakdown still sums exactly to the displayed number.
//!
//! Factors 1 and 2 reproduce the historical `severity_to_score` formula exactly,
//! so adding the breakdown changed no existing score. Factor 3 is the only new
//! term and is purely additive.
//!
//! ## Relationship to the verdict
//!
//! The score is advisory. It is derived *from* a [`Verdict`] but never changes
//! one: `Action`, exit codes, and audit logs are untouched. `tirith score` is an
//! inspection command, not an enforcement path.

use serde::Serialize;

use crate::verdict::{Finding, RuleId, Severity, Verdict};

/// Base contribution for the highest-severity finding.
fn severity_base(sev: Severity) -> u32 {
    match sev {
        Severity::Critical => 90,
        Severity::High => 70,
        Severity::Medium => 40,
        Severity::Low => 15,
        Severity::Info => 0,
    }
}

/// Flat contribution for each finding beyond the first.
const ADDITIONAL_FINDING_WEIGHT: u32 = 5;

/// Contribution when a threat-intel finding corroborates other findings.
const THREAT_INTEL_CORROBORATION_WEIGHT: u32 = 5;

/// The maximum possible score. Scores are clamped here.
pub const MAX_SCORE: u32 = 100;

/// Whether a rule id belongs to the threat-intelligence family — i.e. it fired
/// because the local threat-DB matched a known-bad indicator, not because of a
/// structural heuristic.
///
/// Exhaustive `match` (no wildcard arm) on purpose: a new `RuleId` variant
/// forces a compile error here so this classification is never silently stale.
pub fn is_threat_intel_rule(rule_id: RuleId) -> bool {
    match rule_id {
        RuleId::ThreatMaliciousPackage
        | RuleId::ThreatMaliciousIp
        | RuleId::ThreatPackageTyposquat
        | RuleId::ThreatPackageSimilarName
        | RuleId::ThreatMaliciousUrl
        | RuleId::ThreatPhishingUrl
        | RuleId::ThreatTorExitNode
        | RuleId::ThreatThreatFoxIoc
        | RuleId::ThreatOsvVulnerable
        | RuleId::ThreatCisaKev
        | RuleId::ThreatSuspiciousPackage
        | RuleId::ThreatSafeBrowsing => true,

        RuleId::NonAsciiHostname
        | RuleId::PunycodeDomain
        | RuleId::MixedScriptInLabel
        | RuleId::UserinfoTrick
        | RuleId::ConfusableDomain
        | RuleId::RawIpUrl
        | RuleId::NonStandardPort
        | RuleId::InvalidHostChars
        | RuleId::TrailingDotWhitespace
        | RuleId::LookalikeTld
        | RuleId::NonAsciiPath
        | RuleId::HomoglyphInPath
        | RuleId::DoubleEncoding
        | RuleId::PlainHttpToSink
        | RuleId::SchemelessToSink
        | RuleId::InsecureTlsFlags
        | RuleId::ShortenedUrl
        | RuleId::AnsiEscapes
        | RuleId::ControlChars
        | RuleId::BidiControls
        | RuleId::ZeroWidthChars
        | RuleId::HiddenMultiline
        | RuleId::UnicodeTags
        | RuleId::InvisibleMathOperator
        | RuleId::VariationSelector
        | RuleId::InvisibleWhitespace
        | RuleId::HangulFiller
        | RuleId::ConfusableText
        | RuleId::PipeToInterpreter
        | RuleId::CurlPipeShell
        | RuleId::WgetPipeShell
        | RuleId::HttpiePipeShell
        | RuleId::XhPipeShell
        | RuleId::DotfileOverwrite
        | RuleId::ArchiveExtract
        | RuleId::ProcMemAccess
        | RuleId::DockerRemotePrivEsc
        | RuleId::CredentialFileSweep
        | RuleId::Base64DecodeExecute
        | RuleId::DataExfiltration
        | RuleId::PsSetExecutionPolicyBypass
        | RuleId::PsDefenderExclusion
        | RuleId::PsInlineDownloadExecute
        | RuleId::DynamicCodeExecution
        | RuleId::ObfuscatedPayload
        | RuleId::SuspiciousCodeExfiltration
        | RuleId::ProxyEnvSet
        | RuleId::SensitiveEnvExport
        | RuleId::CodeInjectionEnv
        | RuleId::InterpreterHijackEnv
        | RuleId::ShellInjectionEnv
        | RuleId::MetadataEndpoint
        | RuleId::PrivateNetworkAccess
        | RuleId::CommandNetworkDeny
        | RuleId::ConfigInjection
        | RuleId::ConfigSuspiciousIndicator
        | RuleId::ConfigMalformed
        | RuleId::ConfigNonAscii
        | RuleId::ConfigInvisibleUnicode
        | RuleId::McpInsecureServer
        | RuleId::McpUntrustedServer
        | RuleId::McpDuplicateServerName
        | RuleId::McpOverlyPermissive
        | RuleId::McpSuspiciousArgs
        | RuleId::McpServerDrift
        | RuleId::GitTyposquat
        | RuleId::DockerUntrustedRegistry
        | RuleId::PipUrlInstall
        | RuleId::NpmUrlInstall
        | RuleId::Web3RpcEndpoint
        | RuleId::Web3AddressInUrl
        | RuleId::VetNotConfigured
        | RuleId::RepoAddFromPipe
        | RuleId::UnsignedRepoTrust
        | RuleId::GpgCheckDisabled
        | RuleId::KubectlApplyRemote
        | RuleId::HelmUntrustedRepo
        | RuleId::TerraformRemoteModule
        | RuleId::BrewUntrustedTap
        | RuleId::WorkflowUnpinnedAction
        | RuleId::WorkflowDangerousTrigger
        | RuleId::WorkflowCurlPipeShell
        | RuleId::WorkflowUntrustedInput
        | RuleId::DockerfileUnpinnedImage
        | RuleId::PackageScriptDangerous
        | RuleId::NotebookHiddenContent
        | RuleId::NotebookSuspiciousOutput
        | RuleId::AgentInstructionHidden
        | RuleId::SvgScriptEmbedded
        | RuleId::SvgExternalReference
        | RuleId::HiddenCssContent
        | RuleId::HiddenColorContent
        | RuleId::HiddenHtmlAttribute
        | RuleId::MarkdownComment
        | RuleId::HtmlComment
        | RuleId::ServerCloaking
        | RuleId::ClipboardHidden
        | RuleId::PdfHiddenText
        | RuleId::CredentialInText
        | RuleId::HighEntropySecret
        | RuleId::PrivateKeyExposed
        | RuleId::PolicyBlocklisted
        | RuleId::AgentDeniedByPolicy
        | RuleId::CustomRuleMatch
        | RuleId::LicenseRequired
        // M6 ch6 — package reputation rules. These are NOT threat-DB driven
        // (no local malicious-name match); they're signal-driven, surfaced
        // from the registry-API path (and the snapshot store). They are
        // structural reputation signals, not threat-intel hits.
        | RuleId::PackageNotFoundInRegistry
        | RuleId::PackageMaintainerChangeRecent
        | RuleId::PackageOwnershipTransferred
        | RuleId::PackageOsvAdvisoryActive
        | RuleId::PackageDependencyConfusion
        | RuleId::PackageInstallScriptNetworkCall
        | RuleId::PackageRepoMismatch
        // M6 ch7 — package-policy gated rules. Same family as the ch6
        // reputation signals: signal-driven, surfaced by install_txn /
        // ecosystem_scan from policy thresholds, not from the local
        // threat-DB.
        | RuleId::PackagePolicyNewerThanDays
        | RuleId::PackagePolicyLowDownloads
        | RuleId::PackagePolicyTyposquatDistance
        | RuleId::PackagePolicyUnknownPackageWithInstallScripts
        | RuleId::PackagePolicyNotFound
        // M7 ch1 — output-direction rules. Structural escape-sequence
        // detection on stdout/stderr; never threat-DB driven.
        | RuleId::OutputOsc52ClipboardWrite
        | RuleId::OutputHiddenText
        | RuleId::OutputFakePrompt
        | RuleId::OutputTerminalHyperlinkMismatch
        | RuleId::OutputTitleManipulation
        | RuleId::OutputClearScreen
        | RuleId::OutputTruncatedEscapeSequence
        // M7 ch5 — prompt-injection seed phrases. Pattern-matching on
        // human-readable text; not threat-DB driven.
        | RuleId::PromptInjectionInOutput
        | RuleId::IgnorePreviousInstructions
        // M8 ch1 — operational-context rules. Heuristics on parsed
        // command verbs vs. operator-supplied labels; not threat-DB
        // driven.
        | RuleId::ContextProdDestructiveCommand
        | RuleId::ContextProdWriteOperation
        | RuleId::ContextProdCredentialChange
        // M8 ch2 — SSH operational-context rules. Same character as the
        // M8 ch1 context rules — heuristic on parsed args + operator
        // labels, no threat-DB involvement.
        | RuleId::SshRemoteDestructiveOnLabeledHost
        | RuleId::SshRemoteShellOnLabeledHost
        // M8 ch3 — IaC operational-context rules. Heuristics on parsed
        // IaC CLI args + (for prod rules) operator-supplied context
        // labels. No threat-DB involvement.
        | RuleId::IacApplyWithoutPlan
        | RuleId::IacApplyAutoApprove
        | RuleId::IacApplyAutoApproveProd
        | RuleId::IacDestroyProd
        | RuleId::IacPlanHighRiskChanges
        | RuleId::IacPlanHashMismatch
        // M8 ch4 — sudo-escalation rules. Heuristics on the parsed
        // sudo invocation + (for env-preserve) presence-only check
        // against the sensitive-env asset list. No threat-DB
        // involvement.
        | RuleId::SudoShellSpawn
        | RuleId::SudoEnvPreserveSensitive
        | RuleId::SudoTeeSystemFile
        | RuleId::SudoDownloadInstall
        | RuleId::SudoRecursivePermsBroadPath
        // M8 ch5 — container-runtime rules. Heuristics on parsed
        // docker / podman args + (for exec) operator-supplied context
        // labels keyed by `container:<name>`. No threat-DB involvement.
        | RuleId::DockerRunPrivileged
        | RuleId::DockerRunSensitiveBindMount
        | RuleId::DockerExecProdContainer
        // M9 ch1 — workstation hygiene rules. Filesystem perm/contents/
        // location checks from `tirith hygiene`; no threat-DB involvement.
        | RuleId::HygienePrivateKeyLoosePerms
        | RuleId::HygieneEnvWorldReadable
        | RuleId::HygieneKubeconfigGroupReadable
        | RuleId::HygieneNpmrcPlaintextToken
        | RuleId::HygienePypircPlaintextToken
        | RuleId::HygieneSshConfigUnsafeInclude
        | RuleId::HygieneGitCredentialHelperStore
        | RuleId::HygieneShellHistorySecretLike
        | RuleId::HygieneCloudCredsBadPerms
        | RuleId::HygieneDbDumpInRepo
        // M9 ch2 — persistence-mechanism state-change rules. Filesystem /
        // crontab snapshot-diff detection from `tirith persistence`; no
        // threat-DB involvement.
        | RuleId::PersistenceShellRcModified
        | RuleId::PersistenceAuthorizedKeysNewEntry
        | RuleId::PersistenceCrontabModified
        | RuleId::PersistenceLaunchAgentAdded
        | RuleId::PersistenceSshConfigInclude
        | RuleId::PersistenceDirenvNewEnvrc => false,
    }
}

/// One named, inspectable contributor to a risk score.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ScoreFactor {
    /// Stable machine identifier (e.g. `"base_severity"`).
    pub id: &'static str,
    /// Human-readable label (e.g. `"Highest-severity finding"`).
    pub label: String,
    /// Points this factor contributes to the score. Always >= 0 except the
    /// `clamp` factor, which is <= 0 and brings an over-100 sum back to 100.
    pub points: i32,
    /// Plain-language explanation of why this factor has this value, written so
    /// the reader can verify it by hand.
    pub detail: String,
}

/// A complete, reproducible explanation of how a risk score was derived.
///
/// Invariant: `factors.iter().map(|f| f.points).sum() == score as i32`. The
/// `verify` method asserts this; `score_verdict` always produces a breakdown
/// that satisfies it.
#[derive(Debug, Clone, Serialize)]
pub struct ScoreBreakdown {
    /// Final risk score, 0..=100.
    pub score: u32,
    /// Risk level bucket derived from `score`.
    pub risk_level: &'static str,
    /// The factors that sum to `score`, in display order.
    pub factors: Vec<ScoreFactor>,
}

impl ScoreBreakdown {
    /// Sum of all factor contributions. Equal to `score` for any breakdown
    /// produced by [`score_verdict`].
    pub fn factor_sum(&self) -> i32 {
        self.factors.iter().map(|f| f.points).sum()
    }

    /// Returns `true` iff the factors sum exactly to the final score — the
    /// reproducible-by-hand contract. Used by tests and as a debug assert.
    pub fn verify(&self) -> bool {
        self.factor_sum() == self.score as i32
    }
}

/// Map a numeric score to its risk-level bucket.
///
/// Thresholds are fixed and match the historical `tirith score` buckets so the
/// breakdown does not reclassify any URL.
pub fn risk_level(score: u32) -> &'static str {
    match score {
        0..=20 => "low",
        21..=50 => "medium",
        51..=75 => "high",
        _ => "critical",
    }
}

/// Compute the deterministic risk score and its full factor breakdown for a
/// verdict's findings.
///
/// This is the single source of truth for the `tirith score` number. The
/// breakdown it returns always satisfies `breakdown.verify()`.
pub fn score_verdict(verdict: &Verdict) -> ScoreBreakdown {
    score_findings(&verdict.findings)
}

/// Compute the score breakdown from a raw finding slice.
///
/// Separated from [`score_verdict`] so tests can drive it with synthetic
/// findings without constructing a whole [`Verdict`].
pub fn score_findings(findings: &[Finding]) -> ScoreBreakdown {
    let mut factors: Vec<ScoreFactor> = Vec::new();

    // Factor 1 — base severity. The highest-severity finding sets the floor.
    let max_severity = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);
    let base = severity_base(max_severity);
    let base_detail = if findings.is_empty() {
        "No findings — base score is 0.".to_string()
    } else {
        format!(
            "Highest-severity finding is {max_severity}; a {max_severity} finding contributes {base} base points."
        )
    };
    factors.push(ScoreFactor {
        id: "base_severity",
        label: "Highest-severity finding".to_string(),
        points: base as i32,
        detail: base_detail,
    });

    // Factor 2 — additional findings. Each finding past the first adds +5.
    let extra = findings.len().saturating_sub(1) as u32;
    let extra_points = extra * ADDITIONAL_FINDING_WEIGHT;
    let extra_detail = match findings.len() {
        0 | 1 => format!(
            "{} finding(s) — no additional-finding points (the first finding is already counted by base severity).",
            findings.len()
        ),
        n => format!(
            "{n} findings total; {extra} beyond the first × {ADDITIONAL_FINDING_WEIGHT} points each = {extra_points}."
        ),
    };
    factors.push(ScoreFactor {
        id: "additional_findings",
        label: "Additional findings".to_string(),
        points: extra_points as i32,
        detail: extra_detail,
    });

    // Factor 3 — threat-intel corroboration (context-aware, additive). Only
    // fires when a threat-DB finding sits alongside at least one other finding.
    let threat_hits: Vec<&Finding> = findings
        .iter()
        .filter(|f| is_threat_intel_rule(f.rule_id))
        .collect();
    let corroborates = !threat_hits.is_empty() && findings.len() > 1;
    if corroborates {
        let rule_list = threat_hits
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        factors.push(ScoreFactor {
            id: "threat_intel_corroboration",
            label: "Threat-intel corroboration".to_string(),
            points: THREAT_INTEL_CORROBORATION_WEIGHT as i32,
            detail: format!(
                "A threat-intelligence rule fired ({rule_list}) alongside other findings — \
                 the local threat database independently confirms a known-bad indicator, \
                 adding {THREAT_INTEL_CORROBORATION_WEIGHT} points."
            ),
        });
    }

    // Sum and clamp. When the raw sum exceeds MAX_SCORE, the overflow is
    // reported as an explicit negative `clamp` factor so the breakdown still
    // sums exactly to the displayed score.
    let raw_sum: i32 = factors.iter().map(|f| f.points).sum();
    let score = raw_sum.clamp(0, MAX_SCORE as i32) as u32;
    if raw_sum > MAX_SCORE as i32 {
        let clamp = MAX_SCORE as i32 - raw_sum;
        factors.push(ScoreFactor {
            id: "clamp",
            label: "Score cap".to_string(),
            points: clamp,
            detail: format!(
                "Factors summed to {raw_sum}; the score is capped at {MAX_SCORE}, so {clamp} points are removed."
            ),
        });
    }

    ScoreBreakdown {
        score,
        risk_level: risk_level(score),
        factors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Evidence, Finding, RuleId, Severity};

    fn finding(rule_id: RuleId, severity: Severity) -> Finding {
        Finding {
            rule_id,
            severity,
            title: "test".to_string(),
            description: "test".to_string(),
            evidence: vec![Evidence::Text {
                detail: "t".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }
    }

    #[test]
    fn empty_findings_score_zero() {
        let b = score_findings(&[]);
        assert_eq!(b.score, 0);
        assert_eq!(b.risk_level, "low");
        assert!(b.verify(), "factors must sum to score");
    }

    #[test]
    fn single_critical_scores_ninety() {
        let b = score_findings(&[finding(RuleId::CurlPipeShell, Severity::Critical)]);
        assert_eq!(b.score, 90);
        assert_eq!(b.risk_level, "critical");
        assert!(b.verify());
    }

    #[test]
    fn single_high_scores_seventy() {
        let b = score_findings(&[finding(RuleId::PlainHttpToSink, Severity::High)]);
        assert_eq!(b.score, 70);
        assert_eq!(b.risk_level, "high");
        assert!(b.verify());
    }

    #[test]
    fn single_medium_scores_forty() {
        let b = score_findings(&[finding(RuleId::ShortenedUrl, Severity::Medium)]);
        assert_eq!(b.score, 40);
        assert_eq!(b.risk_level, "medium");
        assert!(b.verify());
    }

    #[test]
    fn single_low_scores_fifteen() {
        let b = score_findings(&[finding(RuleId::NonStandardPort, Severity::Low)]);
        assert_eq!(b.score, 15);
        assert_eq!(b.risk_level, "low");
        assert!(b.verify());
    }

    #[test]
    fn additional_findings_add_five_each() {
        // One High + two more Medium findings: 70 base + 2*5 = 80.
        let b = score_findings(&[
            finding(RuleId::PlainHttpToSink, Severity::High),
            finding(RuleId::ShortenedUrl, Severity::Medium),
            finding(RuleId::NonStandardPort, Severity::Medium),
        ]);
        assert_eq!(b.score, 80);
        assert!(b.verify());
        // Base 70 + additional 10 = two factors, no threat factor.
        assert_eq!(b.factors.len(), 2);
        assert_eq!(b.factors[0].id, "base_severity");
        assert_eq!(b.factors[0].points, 70);
        assert_eq!(b.factors[1].id, "additional_findings");
        assert_eq!(b.factors[1].points, 10);
    }

    #[test]
    fn matches_historical_formula_for_non_threat_findings() {
        // Reproduces the old severity_to_score(max, count) for a spread of
        // inputs — proves the breakdown changed no pre-existing score.
        fn historical(max: Severity, count: usize) -> u32 {
            let base = match max {
                Severity::Critical => 90,
                Severity::High => 70,
                Severity::Medium => 40,
                Severity::Low => 15,
                Severity::Info => 0,
            };
            let bonus = (count.saturating_sub(1) as u32) * 5;
            (base + bonus).min(100)
        }
        for (sev, count) in [
            (Severity::Critical, 1),
            (Severity::Critical, 5),
            (Severity::High, 1),
            (Severity::High, 3),
            (Severity::Medium, 2),
            (Severity::Low, 4),
            (Severity::Low, 1),
        ] {
            // Use a non-threat rule so factor 3 stays silent.
            let findings: Vec<Finding> = (0..count)
                .map(|_| finding(RuleId::ShortenedUrl, sev))
                .collect();
            let b = score_findings(&findings);
            assert_eq!(
                b.score,
                historical(sev, count),
                "score mismatch for {sev} x{count}"
            );
            assert!(b.verify());
        }
    }

    #[test]
    fn threat_intel_corroboration_only_with_other_findings() {
        // A lone threat-intel finding: factor 3 must NOT fire.
        let lone = score_findings(&[finding(RuleId::ThreatMaliciousIp, Severity::High)]);
        assert!(
            lone.factors
                .iter()
                .all(|f| f.id != "threat_intel_corroboration"),
            "lone threat-intel finding must not get the corroboration factor"
        );
        assert_eq!(lone.score, 70);
        assert!(lone.verify());

        // Threat-intel finding + another finding: factor 3 fires (+5).
        let pair = score_findings(&[
            finding(RuleId::ThreatMaliciousIp, Severity::High),
            finding(RuleId::PlainHttpToSink, Severity::High),
        ]);
        let factor = pair
            .factors
            .iter()
            .find(|f| f.id == "threat_intel_corroboration")
            .expect("corroboration factor must be present");
        assert_eq!(factor.points, 5);
        // 70 base + 5 additional + 5 corroboration = 80.
        assert_eq!(pair.score, 80);
        assert!(pair.verify());
    }

    #[test]
    fn threat_corroboration_cannot_fire_without_a_threat_rule() {
        // Two non-threat findings: no corroboration factor.
        let b = score_findings(&[
            finding(RuleId::PlainHttpToSink, Severity::High),
            finding(RuleId::ShortenedUrl, Severity::Medium),
        ]);
        assert!(b
            .factors
            .iter()
            .all(|f| f.id != "threat_intel_corroboration"));
        assert!(b.verify());
    }

    #[test]
    fn score_is_clamped_to_100_with_explicit_clamp_factor() {
        // 5 critical findings: 90 + 4*5 = 110 raw → clamps to 100.
        let findings: Vec<Finding> = (0..5)
            .map(|_| finding(RuleId::CurlPipeShell, Severity::Critical))
            .collect();
        let b = score_findings(&findings);
        assert_eq!(b.score, 100);
        assert_eq!(b.risk_level, "critical");
        // The clamp must be an explicit factor so the breakdown still sums.
        let clamp = b
            .factors
            .iter()
            .find(|f| f.id == "clamp")
            .expect("clamp factor must be present when sum exceeds 100");
        assert_eq!(clamp.points, -10);
        assert!(b.verify(), "even clamped, factors must sum to score");
    }

    #[test]
    fn every_breakdown_verifies_for_wide_input_range() {
        // Exhaustive-ish: every severity, finding counts 0..=8, threat or not.
        for count in 0..=8usize {
            for sev in [
                Severity::Info,
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical,
            ] {
                for threat in [false, true] {
                    let rule = if threat {
                        RuleId::ThreatMaliciousPackage
                    } else {
                        RuleId::ShortenedUrl
                    };
                    let findings: Vec<Finding> = (0..count).map(|_| finding(rule, sev)).collect();
                    let b = score_findings(&findings);
                    assert!(
                        b.verify(),
                        "breakdown must sum to score: count={count} sev={sev} threat={threat} \
                         (score={}, factor_sum={})",
                        b.score,
                        b.factor_sum()
                    );
                    assert!(b.score <= MAX_SCORE);
                }
            }
        }
    }

    #[test]
    fn is_threat_intel_rule_classifies_threat_family() {
        assert!(is_threat_intel_rule(RuleId::ThreatMaliciousPackage));
        assert!(is_threat_intel_rule(RuleId::ThreatCisaKev));
        assert!(is_threat_intel_rule(RuleId::ThreatSafeBrowsing));
        assert!(!is_threat_intel_rule(RuleId::CurlPipeShell));
        assert!(!is_threat_intel_rule(RuleId::PolicyBlocklisted));
        assert!(!is_threat_intel_rule(RuleId::NonAsciiHostname));
    }
}
