//! Deterministic, fully explainable risk scoring.
//!
//! Not a learned model — a fixed sum of named, inspectable factors, reproducible
//! by hand. The score for a URL/command is:
//!
//! 1. **Base severity** — the highest-severity finding sets a base (`Critical`
//!    90, `High` 70, `Medium` 40, `Low` 15, `Info`/none 0).
//! 2. **Additional findings** — each *substantive* finding beyond the first adds
//!    +5. Note-only Info annotations are excluded (CodeRabbit R11 #3).
//! 3. **Threat-intel corroboration** (additive, +5) — fires only when a
//!    local-threat-DB hit sits alongside another finding; never on its own.
//!
//! Final score is `min(100, sum)`; the clamp is reported as a factor so the
//! breakdown sums exactly. Factors 1+2 reproduce the historical
//! `severity_to_score` formula. The score is advisory — it never changes the
//! verdict's `Action`, exit codes, or audit logs.

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

/// `true` for note-only Info findings that annotate a command without being an
/// independent risk signal, so they must not inflate `additional_findings`
/// (CodeRabbit R11 #3). Only the card/manifest/paste-source metadata rules:
/// `CommandCardVerified`, `CommandCardUnverified`, `RepoCommandUnknown`, and
/// `PasteSourceMismatch` (only at Info — its High case is a real signal, kept
/// counted by the severity gate in [`is_excluded_note`]).
///
/// Deliberately NOT note-only (real signals): `CommandCardMismatch`,
/// `RepoCommandDangerousPattern`, `CanaryTokenTouched`, and the `Anomaly*`
/// baseline-novelty rules.
fn is_note_only_rule(rule: RuleId) -> bool {
    matches!(
        rule,
        RuleId::CommandCardVerified
            | RuleId::CommandCardUnverified
            | RuleId::RepoCommandUnknown
            | RuleId::PasteSourceMismatch
    )
}

/// Whether a finding is an excluded note — a note-only rule still at `Info`
/// severity, dropped from the substantive-findings count (factors 2 and 3).
///
/// The severity check matters (CodeRabbit R15 #6): `severity_overrides` can
/// PROMOTE a note-only rule, and once promoted the operator has declared it
/// risk-relevant, so it must be counted. Exempt ONLY while severity is `Info`.
fn is_excluded_note(finding: &Finding) -> bool {
    is_note_only_rule(finding.rule_id) && finding.severity == Severity::Info
}

/// Contribution when a threat-intel finding corroborates other findings.
const THREAT_INTEL_CORROBORATION_WEIGHT: u32 = 5;

/// The maximum possible score. Scores are clamped here.
pub const MAX_SCORE: u32 = 100;

/// Whether a rule fired because the local threat-DB matched a known-bad
/// indicator (vs a structural heuristic).
///
/// Exhaustive `match` (no wildcard) on purpose: a new `RuleId` forces a compile
/// error here so this classification never goes silently stale.
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
        // M13 — structural obfuscation heuristic, not a threat-DB hit.
        | RuleId::WrapperChainTooDeep
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
        // M6 ch6 — package reputation signals (registry-API/snapshot driven),
        // not threat-DB hits.
        | RuleId::PackageNotFoundInRegistry
        | RuleId::PackageMaintainerChangeRecent
        | RuleId::PackageOwnershipTransferred
        | RuleId::PackageOsvAdvisoryActive
        | RuleId::PackageDependencyConfusion
        | RuleId::PackageInstallScriptNetworkCall
        | RuleId::PackageRepoMismatch
        // M6 ch7 — package-policy gated rules (policy thresholds), not threat-DB.
        | RuleId::PackagePolicyNewerThanDays
        | RuleId::PackagePolicyLowDownloads
        | RuleId::PackagePolicyTyposquatDistance
        | RuleId::PackagePolicyUnknownPackageWithInstallScripts
        | RuleId::PackagePolicyNotFound
        // M7 ch1 — output-direction (escape-sequence) rules, not threat-DB.
        | RuleId::OutputOsc52ClipboardWrite
        | RuleId::OutputHiddenText
        | RuleId::OutputFakePrompt
        | RuleId::OutputTerminalHyperlinkMismatch
        | RuleId::OutputTitleManipulation
        | RuleId::OutputClearScreen
        | RuleId::OutputTruncatedEscapeSequence
        // M7 ch5 — prompt-injection seed phrases (text matching), not threat-DB.
        | RuleId::PromptInjectionInOutput
        | RuleId::IgnorePreviousInstructions
        | RuleId::PromptInjectionObfuscated
        // C7 — output-side data-exfiltration vector (content match), not threat-DB.
        | RuleId::OutputDataExfiltration
        // M8 ch1 — operational-context rules (verbs vs operator labels).
        | RuleId::ContextProdDestructiveCommand
        | RuleId::ContextProdWriteOperation
        | RuleId::ContextProdCredentialChange
        // M8 ch2 — SSH operational-context rules (args + operator labels).
        | RuleId::SshRemoteDestructiveOnLabeledHost
        | RuleId::SshRemoteShellOnLabeledHost
        // M8 ch3 — IaC operational-context rules (CLI args + labels).
        | RuleId::IacApplyWithoutPlan
        | RuleId::IacApplyAutoApprove
        | RuleId::IacApplyAutoApproveProd
        | RuleId::IacDestroyProd
        | RuleId::IacPlanHighRiskChanges
        | RuleId::IacPlanHashMismatch
        // M8 ch4 — sudo-escalation rules (parsed sudo invocation).
        | RuleId::SudoShellSpawn
        | RuleId::SudoEnvPreserveSensitive
        | RuleId::SudoTeeSystemFile
        | RuleId::SudoDownloadInstall
        | RuleId::SudoRecursivePermsBroadPath
        // M8 ch5 — container-runtime rules (docker/podman args + labels).
        | RuleId::DockerRunPrivileged
        | RuleId::DockerRunSensitiveBindMount
        | RuleId::DockerExecProdContainer
        // M9 ch1 — workstation hygiene rules (filesystem checks).
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
        // M9 ch2 — persistence state-change rules (snapshot-diff).
        | RuleId::PersistenceShellRcModified
        | RuleId::PersistenceAuthorizedKeysNewEntry
        | RuleId::PersistenceCrontabModified
        | RuleId::PersistenceLaunchAgentAdded
        | RuleId::PersistenceSshConfigInclude
        | RuleId::PersistenceDirenvNewEnvrc
        // M9 ch3 — shell-alias/function risk rules (parsed bodies).
        | RuleId::AliasOverridesCriticalCommand
        | RuleId::AliasContainsNetworkCall
        | RuleId::AliasContainsCredentialRead
        | RuleId::AliasRecentlyAdded
        // M9 ch4 — env-variable lifecycle rules (command shape + rc scan).
        | RuleId::EnvSensitiveExposedToUnknownScript
        | RuleId::EnvSensitivePersistedInShellRc
        | RuleId::EnvPrintenvToNetworkSink
        // M9 ch5 — exec-provenance + PATH-shadowing rules (stat/path/sig).
        | RuleId::ExecInTmp
        | RuleId::ExecRecentlyModified
        | RuleId::ExecWorldWritable
        | RuleId::ExecShadowsSystemCommand
        | RuleId::ExecUnsigned
        | RuleId::ExecInRepoBin
        | RuleId::PathWritableDirBeforeSystem
        | RuleId::PathDuplicateCommandName
        | RuleId::PathDirInRepo
        | RuleId::PathDirInTmp
        // M9 ch6 — repo-hook/automation guard rules (body-content).
        | RuleId::RepoHookNetworkCall
        | RuleId::RepoHookCredentialRead
        | RuleId::RepoHookSudo
        | RuleId::RepoHookSuspiciousShellPattern
        | RuleId::RepoHookExternalFetch
        // M10 ch1 — blast-radius rules (structural/simulation).
        | RuleId::BlastDeletesOutsideRepo
        | RuleId::BlastWritesSystemPath
        | RuleId::BlastSymlinkTraversal
        | RuleId::BlastEmptyVarGlob
        | RuleId::BlastFindDelete
        | RuleId::BlastRsyncDelete
        | RuleId::BlastLargeFileCount
        // M10 ch2 — post-run shell-rc modification (snapshot-diff).
        | RuleId::PostRunShellRcModified
        // M10 ch3 — tainted-content tracking (local taint store).
        | RuleId::ExecOfTaintedFile
        | RuleId::CommandSourcedFromTaintedFile
        // M10 ch5 — anomaly-detection rules (baseline novelty).
        | RuleId::AnomalyFirstTimeInThisRepo
        | RuleId::AnomalyRareInBaseline
        // M11 ch1 — command-card attestation (local ed25519 check).
        | RuleId::CommandCardVerified
        | RuleId::CommandCardUnverified
        | RuleId::CommandCardMismatch
        // M11 ch2 — repo command-manifest rules (commands.yaml match).
        | RuleId::RepoCommandUnknown
        | RuleId::RepoCommandDangerousPattern
        // M11 ch3 — honeytoken/canary (local store lookup).
        | RuleId::CanaryTokenTouched
        // M12 ch1 — paste provenance (companion-file hash + host compare).
        | RuleId::PasteSourceMismatch
        // M13 ch5 — AI-config drift rules (snapshot-vs-current diff).
        | RuleId::AiConfigHiddenInstructionAdded
        | RuleId::AiConfigToolUseEscalation
        // W7: cross-event correlation rules (session/post-process sequence match).
        | RuleId::SecretWriteThenNetwork
        | RuleId::DependencyChangeThenNetwork
        | RuleId::DeleteThenForcePush
        | RuleId::MassFileDeletion => false,
    }
}

/// One named, inspectable contributor to a risk score.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ScoreFactor {
    /// Stable machine identifier (e.g. `"base_severity"`).
    pub id: &'static str,
    /// Human-readable label (e.g. `"Highest-severity finding"`).
    pub label: String,
    /// Points this factor contributes. >= 0 except the `clamp` factor (<= 0).
    pub points: i32,
    /// Plain-language explanation, verifiable by hand.
    pub detail: String,
}

/// A reproducible explanation of how a risk score was derived.
///
/// Invariant (checked by [`verify`](Self::verify)): the factors sum to `score`.
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
    /// Sum of all factor contributions (equals `score`).
    pub fn factor_sum(&self) -> i32 {
        self.factors.iter().map(|f| f.points).sum()
    }

    /// `true` iff the factors sum exactly to the final score.
    pub fn verify(&self) -> bool {
        self.factor_sum() == self.score as i32
    }
}

/// Map a numeric score to its risk-level bucket (fixed historical thresholds).
pub fn risk_level(score: u32) -> &'static str {
    match score {
        0..=20 => "low",
        21..=50 => "medium",
        51..=75 => "high",
        _ => "critical",
    }
}

/// Compute the deterministic risk score and full factor breakdown for a
/// verdict's findings — the single source of truth for `tirith score`.
pub fn score_verdict(verdict: &Verdict) -> ScoreBreakdown {
    score_findings(&verdict.findings)
}

/// Compute the score breakdown from a raw finding slice. Separated from
/// [`score_verdict`] so tests can drive it with synthetic findings.
pub fn score_findings(findings: &[Finding]) -> ScoreBreakdown {
    let mut factors: Vec<ScoreFactor> = Vec::new();

    // Factor 1 — base severity (highest-severity finding sets the floor).
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

    // Factor 2 — additional findings (+5 each past the first). Note-only Info
    // annotations are excluded (CodeRabbit R11 #3); a promotion above Info makes
    // them count (CodeRabbit R15 #6), picked up via `is_excluded_note`.
    let substantive = findings.iter().filter(|f| !is_excluded_note(f)).count();
    let extra = substantive.saturating_sub(1) as u32;
    let extra_points = extra * ADDITIONAL_FINDING_WEIGHT;
    let extra_detail = match substantive {
        0 | 1 => format!(
            "{substantive} substantive finding(s) — no additional-finding points (the first is already counted by base severity; note-only card/manifest annotations are excluded)."
        ),
        n => format!(
            "{n} substantive findings; {extra} beyond the first × {ADDITIONAL_FINDING_WEIGHT} points each = {extra_points} (note-only card/manifest annotations excluded)."
        ),
    };
    factors.push(ScoreFactor {
        id: "additional_findings",
        label: "Additional findings".to_string(),
        points: extra_points as i32,
        detail: extra_detail,
    });

    // Factor 3 — threat-intel corroboration (+5). Fires only when a threat-DB
    // finding sits alongside another SUBSTANTIVE finding; note-only annotations
    // must not corroborate (CodeRabbit R12 #D). Threat rules are themselves
    // substantive, so `substantive > 1` means "threat hit + another finding".
    let threat_hits: Vec<&Finding> = findings
        .iter()
        .filter(|f| is_threat_intel_rule(f.rule_id))
        .collect();
    let corroborates = !threat_hits.is_empty() && substantive > 1;
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

    // Sum and clamp. Overflow past MAX_SCORE is reported as an explicit negative
    // `clamp` factor so the breakdown still sums exactly.
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
    fn note_only_card_findings_do_not_change_score() {
        // CodeRabbit R11 #3: a note-only Info finding must not inflate the score
        // (lone note scores 0; alongside real findings it adds nothing).
        for note in [
            RuleId::CommandCardVerified,
            RuleId::CommandCardUnverified,
            RuleId::RepoCommandUnknown,
        ] {
            // (a) Lone note → identical to no findings at all (score 0).
            let lone = score_findings(&[finding(note, Severity::Info)]);
            assert_eq!(lone.score, 0, "a lone {note:?} note must score 0");
            assert!(lone.verify());

            // (b) A real High finding + the note scores the SAME as the High
            // finding alone — the note adds no additional-finding points.
            let without = score_findings(&[finding(RuleId::PlainHttpToSink, Severity::High)]);
            let with = score_findings(&[
                finding(RuleId::PlainHttpToSink, Severity::High),
                finding(note, Severity::Info),
            ]);
            assert_eq!(
                with.score, without.score,
                "{note:?} must not change the score (with={}, without={})",
                with.score, without.score
            );
            assert_eq!(with.score, 70, "High alone is 70; the note adds nothing");
            assert!(with.verify());
        }
    }

    #[test]
    fn paste_source_mismatch_info_is_note_only_but_high_is_counted() {
        // M12 ch1: the Info host-mismatch case is advisory metadata (lone scores
        // 0; adds nothing alongside a real High).
        let lone = score_findings(&[finding(RuleId::PasteSourceMismatch, Severity::Info)]);
        assert_eq!(lone.score, 0, "a lone Info paste-source mismatch scores 0");
        assert!(lone.verify());

        let with_info = score_findings(&[
            finding(RuleId::PlainHttpToSink, Severity::High),
            finding(RuleId::PasteSourceMismatch, Severity::Info),
        ]);
        assert_eq!(
            with_info.score, 70,
            "an Info paste-source mismatch must not add an additional-finding point"
        );

        // The High case is a real signal: alongside another High it adds +5
        // (70 → 75), kept counted by the severity gate in `is_excluded_note`.
        let with_high = score_findings(&[
            finding(RuleId::PlainHttpToSink, Severity::High),
            finding(RuleId::PasteSourceMismatch, Severity::High),
        ]);
        assert_eq!(
            with_high.score, 75,
            "a High paste-source mismatch must count as an additional finding"
        );
        assert!(with_high.verify());
    }

    #[test]
    fn canary_touched_is_counted_not_note_only() {
        // Contrast: CanaryTokenTouched (High) is a real signal — 70 + 5 = 75.
        let b = score_findings(&[
            finding(RuleId::CanaryTokenTouched, Severity::High),
            finding(RuleId::PlainHttpToSink, Severity::High),
        ]);
        assert_eq!(b.score, 75, "canary-touched must still count as a finding");
        assert!(b.verify());
    }

    #[test]
    fn promoted_note_only_rule_is_counted_but_info_one_is_not() {
        // CodeRabbit R15 #6: a note-only rule is exempt only at Info; an operator
        // promotion via `severity_overrides` makes it count.
        //
        // (1) An Info CommandCardVerified note adds nothing (stays 70).
        let at_info = score_findings(&[
            finding(RuleId::PlainHttpToSink, Severity::High),
            finding(RuleId::CommandCardVerified, Severity::Info),
        ]);
        assert_eq!(
            at_info.score, 70,
            "an Info note-only finding must not add an additional-finding point"
        );
        assert!(at_info.verify());

        // (2) The same rule promoted to Medium is counted: alongside the High it
        // adds +5 (70 → 75; base stays High).
        let promoted = score_findings(&[
            finding(RuleId::PlainHttpToSink, Severity::High),
            finding(RuleId::CommandCardVerified, Severity::Medium),
        ]);
        assert_eq!(
            promoted.score, 75,
            "a promoted (Medium) CommandCardVerified must count as an additional finding"
        );
        assert!(promoted.verify());
        assert!(
            promoted.score > at_info.score,
            "promotion must raise the score relative to the Info note (75 > 70)"
        );

        // A lone promoted note scores on its own severity (Medium = 40), not 0.
        let lone_promoted =
            score_findings(&[finding(RuleId::CommandCardVerified, Severity::Medium)]);
        assert_eq!(
            lone_promoted.score, 40,
            "a lone promoted note scores on its (Medium) severity, not 0"
        );
        assert!(lone_promoted.verify());
        // Contrast: a lone Info note still scores 0.
        let lone_info = score_findings(&[finding(RuleId::CommandCardVerified, Severity::Info)]);
        assert_eq!(lone_info.score, 0, "a lone Info note still scores 0");
    }

    #[test]
    fn matches_historical_formula_for_non_threat_findings() {
        // Reproduces the old severity_to_score(max, count) for a spread of inputs.
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
    fn note_only_finding_does_not_corroborate_threat_intel() {
        // CodeRabbit R12 #D: a note-only Info annotation must not corroborate a
        // threat-intel hit — corroboration requires another substantive finding.
        for note in [
            RuleId::CommandCardVerified,
            RuleId::CommandCardUnverified,
            RuleId::RepoCommandUnknown,
        ] {
            let with_note = score_findings(&[
                finding(RuleId::ThreatMaliciousIp, Severity::High),
                finding(note, Severity::Info),
            ]);
            assert!(
                with_note
                    .factors
                    .iter()
                    .all(|f| f.id != "threat_intel_corroboration"),
                "{note:?} must NOT corroborate a threat-intel hit"
            );
            // Identical to the lone threat hit (the note is excluded everywhere).
            let lone = score_findings(&[finding(RuleId::ThreatMaliciousIp, Severity::High)]);
            assert_eq!(
                with_note.score, lone.score,
                "a note alongside a lone threat hit must not change the score (note={note:?})"
            );
            assert_eq!(with_note.score, 70);
            assert!(with_note.verify());
        }

        // Sanity: a substantive second finding does still corroborate (+5).
        let real_pair = score_findings(&[
            finding(RuleId::ThreatMaliciousIp, Severity::High),
            finding(RuleId::PlainHttpToSink, Severity::High),
        ]);
        assert!(
            real_pair
                .factors
                .iter()
                .any(|f| f.id == "threat_intel_corroboration"),
            "a substantive second finding must still corroborate"
        );
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
        // Every severity, finding counts 0..=8, threat or not.
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

    #[test]
    fn ai_config_drift_rules_are_not_threat_intel() {
        // CodeRabbit M13 round-24: the M13 ch5 AI-config drift rules are
        // structural snapshot-diff signals, not threat-DB hits — pin them in the
        // `=> false` arm so the corroboration factor never fires off them.
        assert!(
            !is_threat_intel_rule(RuleId::AiConfigHiddenInstructionAdded),
            "AiConfigHiddenInstructionAdded is structural drift, not threat-intel"
        );
        assert!(
            !is_threat_intel_rule(RuleId::AiConfigToolUseEscalation),
            "AiConfigToolUseEscalation is structural drift, not threat-intel"
        );

        // They are also not note-only — an AI-config drift is an independent
        // risk signal, so it stays counted.
        assert!(
            !is_note_only_rule(RuleId::AiConfigHiddenInstructionAdded),
            "AiConfigHiddenInstructionAdded is a substantive signal, not a note-only annotation"
        );
        assert!(
            !is_note_only_rule(RuleId::AiConfigToolUseEscalation),
            "AiConfigToolUseEscalation is a substantive signal, not a note-only annotation"
        );
    }
}
