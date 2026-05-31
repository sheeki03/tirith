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
//! 2. **Additional findings** — each *substantive* finding *beyond the first*
//!    adds a flat +5. More independent problems mean more risk, but secondarily
//!    to severity. **Note-only** Info annotations are EXCLUDED from this count:
//!    a verified/unverified command-card note and the "command not in the repo
//!    manifest" note describe the command rather than adding a second problem
//!    with it, so they never inflate the additive term (CodeRabbit R11 #3).
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

/// `true` for **note-only** Info findings that annotate a command without being
/// an independent risk signal. These must NOT inflate the additive
/// `additional_findings` factor: a verified/unverified command-card note, or a
/// "this command is not catalogued" manifest note, is metadata about the
/// command, not a second problem with it (CodeRabbit R11 #3).
///
/// Scope: only the rules whose DOCUMENTED semantics are "Info, never changes the
/// action, pure annotation". Concretely:
///   * [`RuleId::CommandCardVerified`] — "this command matched a trusted card".
///   * [`RuleId::CommandCardUnverified`] — "a card was referenced but could not
///     be verified" (remote URL / bad sig / unreadable). Info note, not a claim.
///   * [`RuleId::RepoCommandUnknown`] — "not listed in `.tirith/commands.yaml`".
///     Info annotation; the suppressible "you ran something uncatalogued" note.
///   * [`RuleId::PasteSourceMismatch`] — at its Info severity (a BARE host
///     mismatch with no corroborating risk signal) this is an advisory "the
///     paste came from a different host than where it runs" note: docs pages
///     legitimately link install URLs on other hosts, so the lone-mismatch case
///     must not inflate the score. The severity gate in [`is_excluded_note`]
///     means the **High** case (mismatch + a risk signal) is STILL counted — it
///     is a real signal, not an annotation, so the exemption never suppresses it.
///
/// Deliberately NOT note-only (these ARE real signals and stay counted):
///   * `CommandCardMismatch` (High) — the command differs from a trusted card.
///   * `RepoCommandDangerousPattern` (High/Medium) — a dangerous-glob match.
///   * `CanaryTokenTouched` (High) — a planted honeytoken was touched; a strong
///     detection, not an annotation.
///   * `AnomalyFirstTimeInThisRepo` / `AnomalyRareInBaseline` (Info) — these are
///     baseline NOVELTY signals (a new/rare pattern is mildly risk-relevant), a
///     different class from card/manifest metadata, so they keep their +5.
fn is_note_only_rule(rule: RuleId) -> bool {
    matches!(
        rule,
        RuleId::CommandCardVerified
            | RuleId::CommandCardUnverified
            | RuleId::RepoCommandUnknown
            | RuleId::PasteSourceMismatch
    )
}

/// Whether a finding is an EXCLUDED note — a note-only rule that is STILL at its
/// documented `Info` severity. Such a finding is metadata, not a risk signal, so
/// it is dropped from the substantive-findings count (factors 2 and 3).
///
/// The severity check matters (CodeRabbit R15 #6): `policy.severity_overrides`
/// can PROMOTE a note-only rule (e.g. an operator raises `CommandCardVerified` to
/// Medium to make an unverified-card run count). Once promoted, the finding is no
/// longer "just a note" — the operator has declared it risk-relevant — so it must
/// be COUNTED. Exempting it purely by `rule_id` (ignoring severity) would silently
/// discard that operator intent. Exempt ONLY while severity is exactly `Info`.
fn is_excluded_note(finding: &Finding) -> bool {
    is_note_only_rule(finding.rule_id) && finding.severity == Severity::Info
}

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
        | RuleId::PersistenceDirenvNewEnvrc
        // M9 ch3 — shell-alias / function risk rules. Heuristics on parsed
        // alias/function bodies from `tirith aliases`; no threat-DB
        // involvement.
        | RuleId::AliasOverridesCriticalCommand
        | RuleId::AliasContainsNetworkCall
        | RuleId::AliasContainsCredentialRead
        | RuleId::AliasRecentlyAdded
        // M9 ch4 — environment-variable lifecycle rules. Heuristics on the
        // exec command shape + sensitive-env presence + rc-file scan from
        // `tirith env`; no threat-DB involvement.
        | RuleId::EnvSensitiveExposedToUnknownScript
        | RuleId::EnvSensitivePersistedInShellRc
        | RuleId::EnvPrintenvToNetworkSink
        // M9 ch5 — executable-provenance + PATH-shadowing rules. Stat / path /
        // signature heuristics from `tirith exec`/`path` + the cheap hot-path
        // leader-location subset; no threat-DB involvement.
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
        // M9 ch6 — repo-hook / automation guard rules. Body-content heuristics
        // from the `tirith hooks` scanner; no threat-DB involvement.
        | RuleId::RepoHookNetworkCall
        | RuleId::RepoHookCredentialRead
        | RuleId::RepoHookSudo
        | RuleId::RepoHookSuspiciousShellPattern
        | RuleId::RepoHookExternalFetch
        // M10 ch1 — blast-radius rules. Structural/simulation heuristics on a
        // destructive command's targets; no threat-DB involvement.
        | RuleId::BlastDeletesOutsideRepo
        | RuleId::BlastWritesSystemPath
        | RuleId::BlastSymlinkTraversal
        | RuleId::BlastEmptyVarGlob
        | RuleId::BlastFindDelete
        | RuleId::BlastRsyncDelete
        | RuleId::BlastLargeFileCount
        // M10 ch2 — post-run shell-rc modification. Snapshot-diff state change
        // from `tirith watch`; no threat-DB involvement.
        | RuleId::PostRunShellRcModified
        // M10 ch3 — tainted-content tracking. Path-key match against the local
        // taint store; no threat-DB involvement.
        | RuleId::ExecOfTaintedFile
        | RuleId::CommandSourcedFromTaintedFile
        // M10 ch5 — anomaly-detection rules. Sliding-window novelty signal from
        // the local baseline store; no threat-DB involvement.
        | RuleId::AnomalyFirstTimeInThisRepo
        | RuleId::AnomalyRareInBaseline
        // M11 ch1 — command-card attestation. Local ed25519 signature check
        // against operator-trusted keys; no threat-DB involvement.
        | RuleId::CommandCardVerified
        | RuleId::CommandCardUnverified
        | RuleId::CommandCardMismatch
        // M11 ch2 — repo command-manifest rules. Local `.tirith/commands.yaml`
        // allowlist/dangerous-glob match; no threat-DB involvement.
        | RuleId::RepoCommandUnknown
        | RuleId::RepoCommandDangerousPattern
        // M11 ch3 — honeytoken / canary. A local store lookup against the
        // user's own planted tokens; not a threat-DB indicator match.
        | RuleId::CanaryTokenTouched
        // M12 ch1 — paste provenance. A companion-file content-hash match plus a
        // URL-host comparison; not a threat-DB indicator match.
        | RuleId::PasteSourceMismatch
        // M13 ch5 — AI-config drift rules. A snapshot-vs-current diff of an
        // AI-config file's hidden-content / tool-use directives; structural, not
        // a threat-DB indicator match.
        | RuleId::AiConfigHiddenInstructionAdded
        | RuleId::AiConfigToolUseEscalation => false,
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

    // Factor 2 — additional findings. Each finding past the first adds +5, but a
    // note-only annotation (verified/unverified card, uncatalogued-command note)
    // STILL AT ITS Info severity is EXCLUDED from the count: it is metadata about
    // the command, not a second independent problem, so it must not inflate the
    // score (CodeRabbit R11 #3). When `severity_overrides` PROMOTES such a note
    // above Info, the operator has declared it risk-relevant, so it is COUNTED
    // (CodeRabbit R15 #6) — and factor 1 (max-severity) naturally picks up the
    // promotion too. A verdict carrying only an UN-promoted note scores exactly
    // the same as one carrying none.
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

    // Factor 3 — threat-intel corroboration (context-aware, additive). Only
    // fires when a threat-DB finding sits alongside at least one other
    // SUBSTANTIVE finding. Note-only annotations (verified/unverified card,
    // uncatalogued-command note) must NOT corroborate a threat-intel hit
    // (CodeRabbit R12 #D): they are metadata about the command, not an
    // independent known-bad signal, so a `findings.len() > 1` test would let a
    // single card note falsely "confirm" a threat hit and inflate the score.
    // Threat-intel rules are themselves substantive (never note-only), so the
    // shared `substantive` count already includes the threat hit; `> 1`
    // therefore means "the threat hit AND at least one other substantive
    // finding" — mirroring the additional-findings factor above.
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
    fn note_only_card_findings_do_not_change_score() {
        // CodeRabbit R11 #3: a note-only Info finding (verified/unverified card,
        // uncatalogued-command note) must NOT inflate the additive score. A
        // verdict carrying ONLY such a note scores the same as an empty one (0),
        // and adding one alongside real findings does not bump the count.
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
        // M12 ch1: the BARE-host-mismatch Info case is advisory metadata — a lone
        // such note scores 0, and alongside a real High finding it adds nothing.
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

        // The HIGH case (mismatch + a risk signal) IS a real signal and must be
        // counted: alongside another High finding it adds the +5 (70 → 75). The
        // severity gate in `is_excluded_note` keeps it counted even though the
        // rule_id is in the note-only set.
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
        // Contrast: CanaryTokenTouched (High) is a REAL signal, not a note. A
        // High finding alongside it scores 70 base + 5 additional = 75, proving
        // the canary is still counted toward the additive factor.
        let b = score_findings(&[
            finding(RuleId::CanaryTokenTouched, Severity::High),
            finding(RuleId::PlainHttpToSink, Severity::High),
        ]);
        assert_eq!(b.score, 75, "canary-touched must still count as a finding");
        assert!(b.verify());
    }

    #[test]
    fn promoted_note_only_rule_is_counted_but_info_one_is_not() {
        // CodeRabbit R15 #6 — regression pinning BOTH properties: a note-only rule
        // is exempt ONLY while at Info; an operator promotion via
        // `severity_overrides` makes it count.
        //
        // (1) PRIOR-ROUND PROPERTY PRESERVED: a CommandCardVerified note STILL AT
        // Info adds nothing alongside a real High finding (score stays 70).
        let at_info = score_findings(&[
            finding(RuleId::PlainHttpToSink, Severity::High),
            finding(RuleId::CommandCardVerified, Severity::Info),
        ]);
        assert_eq!(
            at_info.score, 70,
            "an Info note-only finding must not add an additional-finding point"
        );
        assert!(at_info.verify());

        // (2) NEW FIX: the SAME rule PROMOTED to Medium is now a risk signal the
        // operator opted into — it must be COUNTED. Alongside the High finding it
        // adds the +5 additional-finding point (70 → 75); base severity stays High
        // (Medium < High), so the delta is exactly the additive +5 the promotion
        // unlocked.
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

        // And a LONE promoted note now scores on its own severity (Medium = 40),
        // not 0 — proving the exemption is fully severity-gated, not rule-id-only.
        let lone_promoted =
            score_findings(&[finding(RuleId::CommandCardVerified, Severity::Medium)]);
        assert_eq!(
            lone_promoted.score, 40,
            "a lone promoted note scores on its (Medium) severity, not 0"
        );
        assert!(lone_promoted.verify());
        // Contrast: a lone Info note still scores 0 (unchanged prior behavior).
        let lone_info = score_findings(&[finding(RuleId::CommandCardVerified, Severity::Info)]);
        assert_eq!(lone_info.score, 0, "a lone Info note still scores 0");
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
    fn note_only_finding_does_not_corroborate_threat_intel() {
        // CodeRabbit R12 #D: a note-only Info annotation must NOT corroborate a
        // threat-intel hit. Before the fix, `findings.len() > 1` let a single
        // card/manifest note falsely "confirm" the threat and add +5. Now
        // corroboration requires another SUBSTANTIVE finding.
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
            // Identical to the lone threat hit: 70 base, no corroboration, no
            // additional-finding points (the note is excluded everywhere).
            let lone = score_findings(&[finding(RuleId::ThreatMaliciousIp, Severity::High)]);
            assert_eq!(
                with_note.score, lone.score,
                "a note alongside a lone threat hit must not change the score (note={note:?})"
            );
            assert_eq!(with_note.score, 70);
            assert!(with_note.verify());
        }

        // Sanity: a SUBSTANTIVE second finding DOES still corroborate (+5), so
        // the fix did not over-suppress the factor.
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
