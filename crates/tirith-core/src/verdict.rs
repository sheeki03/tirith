use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for each detection rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleId {
    // Hostname rules
    NonAsciiHostname,
    PunycodeDomain,
    MixedScriptInLabel,
    UserinfoTrick,
    ConfusableDomain,
    RawIpUrl,
    NonStandardPort,
    InvalidHostChars,
    TrailingDotWhitespace,
    LookalikeTld,

    // Path rules
    NonAsciiPath,
    HomoglyphInPath,
    DoubleEncoding,

    // Transport rules
    PlainHttpToSink,
    SchemelessToSink,
    InsecureTlsFlags,
    ShortenedUrl,

    // Terminal deception rules
    AnsiEscapes,
    ControlChars,
    BidiControls,
    ZeroWidthChars,
    HiddenMultiline,
    UnicodeTags,
    InvisibleMathOperator,
    VariationSelector,
    InvisibleWhitespace,
    HangulFiller,
    ConfusableText,

    // Command shape rules
    PipeToInterpreter,
    CurlPipeShell,
    WgetPipeShell,
    HttpiePipeShell,
    XhPipeShell,
    DotfileOverwrite,
    ArchiveExtract,
    ProcMemAccess,
    DockerRemotePrivEsc,
    CredentialFileSweep,
    Base64DecodeExecute,
    DataExfiltration,
    /// M5 item 16 — PowerShell `Set-ExecutionPolicy Bypass` (cmdlet or
    /// `powershell -ExecutionPolicy Bypass` flag form). Disables script
    /// signing enforcement so subsequent downloaded scripts run unsigned.
    PsSetExecutionPolicyBypass,
    /// M5 item 16 — PowerShell `Add-MpPreference -ExclusionPath`,
    /// `-ExclusionProcess`, or `-ExclusionExtension`. Adds a Windows Defender
    /// exclusion to hide malicious payloads from scanning.
    PsDefenderExclusion,
    /// M5 item 16 — PowerShell `iex (iwr https://...)` inline form where
    /// `iex` / `invoke-expression` is the leading command. The pipe form
    /// (`iwr url | iex`) is handled by `pipe_to_interpreter`.
    PsInlineDownloadExecute,

    // Code file scan rules
    DynamicCodeExecution,
    ObfuscatedPayload,
    SuspiciousCodeExfiltration,

    // Environment rules
    ProxyEnvSet,
    SensitiveEnvExport,
    CodeInjectionEnv,
    InterpreterHijackEnv,
    ShellInjectionEnv,

    // Network destination rules
    MetadataEndpoint,
    PrivateNetworkAccess,
    CommandNetworkDeny,

    // Config file rules
    ConfigInjection,
    ConfigSuspiciousIndicator,
    ConfigMalformed,
    ConfigNonAscii,
    ConfigInvisibleUnicode,
    McpInsecureServer,
    McpUntrustedServer,
    McpDuplicateServerName,
    McpOverlyPermissive,
    McpSuspiciousArgs,
    McpServerDrift,

    // Ecosystem rules
    GitTyposquat,
    DockerUntrustedRegistry,
    PipUrlInstall,
    NpmUrlInstall,
    Web3RpcEndpoint,
    Web3AddressInUrl,
    VetNotConfigured,

    // Install-command rules (package-manager / infrastructure)
    RepoAddFromPipe,
    UnsignedRepoTrust,
    GpgCheckDisabled,
    KubectlApplyRemote,
    HelmUntrustedRepo,
    TerraformRemoteModule,
    BrewUntrustedTap,

    // CI / repo supply-chain scan rules (file-content scan)
    WorkflowUnpinnedAction,
    WorkflowDangerousTrigger,
    WorkflowCurlPipeShell,
    WorkflowUntrustedInput,
    DockerfileUnpinnedImage,
    PackageScriptDangerous,

    // AI-relevant file hidden-content scan rules (file-content scan)
    NotebookHiddenContent,
    NotebookSuspiciousOutput,
    AgentInstructionHidden,
    SvgScriptEmbedded,
    SvgExternalReference,

    // Threat intelligence rules — local DB
    ThreatMaliciousPackage,
    ThreatMaliciousIp,
    ThreatPackageTyposquat,
    ThreatPackageSimilarName,
    // Supplemental-feed rules are defined now so RuleId stays stable.
    ThreatMaliciousUrl,
    ThreatPhishingUrl,
    ThreatTorExitNode,
    ThreatThreatFoxIoc,
    // Real-time lookup rules
    ThreatOsvVulnerable,
    ThreatCisaKev,
    ThreatSuspiciousPackage,
    ThreatSafeBrowsing,

    // Package reputation rules (M6 ch6) — emitted by package_risk /
    // install_txn / ecosystem_scan when the registry-API path returns one of
    // the seven new signals. Tier-1 attach via the existing
    // `install_command` / package extractor; no new PATTERN_TABLE entry.
    /// M6 ch6 — the registry positively reports the package does not exist
    /// (HTTP 404). Distinct from `ApiSignals::Unavailable` (timeout /
    /// unsupported registry / offline), which carries no "exists" claim.
    /// Medium baseline; elevated to Block via ch7 `block_not_found: true`.
    PackageNotFoundInRegistry,
    /// M6 ch6 — `MaintainerChangeHistory` diff between the two most recent
    /// local snapshots shows added or removed maintainers within the
    /// recency window. Medium severity.
    PackageMaintainerChangeRecent,
    /// M6 ch6 — registry snapshot diff confirms a *real* ownership transfer
    /// (every previous maintainer is gone; non-empty new set). Distinct
    /// from the inferred `ApiProvenance::ownership_transferred` flag (which
    /// is `zero owners` only), now superseded by snapshot-vs-snapshot diff.
    /// Medium severity.
    PackageOwnershipTransferred,
    /// M6 ch6 — OSV correlation through the shipping `threatdb_api.rs`
    /// cache surfaced an active advisory for `(eco, name, version)`. High
    /// severity when CVSS ≥ 7.
    PackageOsvAdvisoryActive,
    /// M6 ch6 — dependency-confusion heuristic: the package name matches
    /// an operator-supplied internal name AND tirith fetched it from the
    /// public registry, OR an `@org` scope is reserved but the package
    /// lives in the public registry. High severity.
    PackageDependencyConfusion,
    /// M6 ch6 — install-script heuristic found a network call or shell
    /// spawn inside an npm `preinstall`/`install`/`postinstall`/`prepare`
    /// script, a `setup.py` body, or a `build.rs` body. Medium severity;
    /// heuristic, document the false-positive risk.
    PackageInstallScriptNetworkCall,
    /// M6 ch6 — registry-claimed repository URL fails verification under
    /// `--online`: dead host, parses as a non-git URL, or hosted manifest
    /// does not mention the package name. High severity.
    PackageRepoMismatch,

    // Package-policy gated rules (M6 ch7) — these fire from
    // `install_txn` / `ecosystem_scan` when the `package_policy` section
    // (chunk 7) crosses a configured threshold. Each has a clean default
    // behavior at the M6 ch6 baseline and only fires when policy carries
    // a stronger threshold.
    /// M6 ch7 — the package is newer than the policy's
    /// `block_newer_than_days` / `warn_newer_than_days`. Warn baseline;
    /// elevated to Block when the Block threshold is configured AND the
    /// package's age is at or below it.
    PackagePolicyNewerThanDays,
    /// M6 ch7 — the package's `recent_downloads` is at or below the
    /// policy's `warn_low_downloads_below`. Warn severity. Requires
    /// `--online` to gather the downloads count.
    PackagePolicyLowDownloads,
    /// M6 ch7 — the package name is within the policy's
    /// `block_typosquat_distance` edit distance of a known-popular name.
    /// Block severity. Distinct from `ThreatPackageTyposquat` (DB-confirmed)
    /// and `ThreatPackageSimilarName` (advisory) — this fires from a
    /// policy-supplied distance threshold rather than the threat-DB.
    PackagePolicyTyposquatDistance,
    /// M6 ch7 — the package is `NameVsPopular::Unknown` AND the
    /// install-script analysis flagged a network call or shell spawn.
    /// Block severity. Requires the install-script signal — `--online`
    /// install (npm inline), `ecosystem scan --installed`, or
    /// `package scan --lockfile --online`.
    PackagePolicyUnknownPackageWithInstallScripts,
    /// M6 ch7 — the registry positively reports the package does not
    /// exist (`PackageExistence::NotFound`) AND the policy carries
    /// `block_not_found: true`. Block severity. Requires `--online`;
    /// offline runs report `Unknown` and this rule never fires.
    PackagePolicyNotFound,

    // Rendered content rules
    HiddenCssContent,
    HiddenColorContent,
    HiddenHtmlAttribute,
    MarkdownComment,
    HtmlComment,

    // Cloaking rules
    ServerCloaking,

    // Clipboard rules
    ClipboardHidden,

    // PDF rules
    PdfHiddenText,

    // Credential rules
    CredentialInText,
    HighEntropySecret,
    PrivateKeyExposed,

    // Policy rules
    PolicyBlocklisted,
    /// M4 item 8 chunk 3 — the verdict's caller `AgentOrigin` matched a
    /// `deny` matcher in `agent_rules`. Forces the verdict's [`Action`] to
    /// [`Action::Block`] regardless of any detection finding. See
    /// `policy::agent_decision` and `docs/agent-governance-design.md` §5.
    AgentDeniedByPolicy,

    // Custom rules
    CustomRuleMatch,

    // License/infrastructure rules
    LicenseRequired,

    // Output-direction rules (M7 ch1) — fire from `engine::analyze_output`
    // when scanning the stdout/stderr of a command (e.g. `tirith view <file>`,
    // future M7 ch4 MCP gateway, M7 ch5 log viewer). They never fire from the
    // exec / paste hot path. Detection is byte-scan based (OSC52, OSC8, title
    // set, screen-clear sequences) and bypasses `PATTERN_TABLE` — the
    // `analyze_output` pipeline does not go through the tier-1 exec/paste
    // regex gate.
    /// M7 ch1 — `\e]52;c;<base64>\a` writes to the system clipboard from a
    /// stream the user is only watching. High severity — silent exfil of
    /// secrets the user just typed becomes a one-key paste away.
    OutputOsc52ClipboardWrite,
    /// M7 ch1 — text rendered invisibly. v1 scope is narrow: (i) explicit
    /// ANSI foreground == explicit ANSI background within a single SGR
    /// sequence, OR (ii) a zero-width-character run > 8 chars. Terminal-
    /// theme-dependent detection (text inherits a default color) is out of
    /// v1 — documented as a follow-up in `rules/output.rs`.
    OutputHiddenText,
    /// M7 ch1 — a `[PS1-shaped text]` injected mid-stream looks like a
    /// fresh prompt and tricks the user into typing the next command at
    /// what is actually the wrapped command's output. Medium severity.
    OutputFakePrompt,
    /// M7 ch1 — OSC 8 hyperlink where the visible text itself parses as a
    /// URL with a host that differs from the link's `href` host. High
    /// severity. "Click here" vs `https://example.com` does NOT fire —
    /// only when the visible text is a URL whose host doesn't match.
    OutputTerminalHyperlinkMismatch,
    /// M7 ch1 — terminal window title rewrite (`\e]0;…\a` / `\e]2;…\a`)
    /// from an untrusted output stream. Info severity. Used by attackers
    /// to mask a backgrounded shell as "$EDITOR foo.txt".
    OutputTitleManipulation,
    /// M7 ch1 — explicit screen-clear sequences (`\e[2J` / `\e[H`) mid-
    /// stream. Info severity — used to scroll the prior output (your
    /// command, the program's output) off-screen so a fake banner can
    /// take its place.
    OutputClearScreen,
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{self:?}"));
        write!(f, "{s}")
    }
}

/// Severity level for findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Evidence supporting a finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Evidence {
    Url {
        raw: String,
    },
    HostComparison {
        raw_host: String,
        similar_to: String,
    },
    CommandPattern {
        pattern: String,
        matched: String,
    },
    ByteSequence {
        offset: usize,
        hex: String,
        description: String,
    },
    EnvVar {
        name: String,
        value_preview: String,
    },
    Text {
        detail: String,
    },
    ThreatIntel {
        source: String,
        threat_type: String,
        confidence: crate::threatdb::Confidence,
        #[serde(skip_serializing_if = "Option::is_none")]
        reference: Option<String>,
    },
    /// Detailed character analysis for homograph detection
    HomoglyphAnalysis {
        /// The raw input string
        raw: String,
        /// The ASCII/punycode escaped version
        escaped: String,
        /// Positions of suspicious characters (byte offset, char, description)
        suspicious_chars: Vec<SuspiciousChar>,
    },
}

/// A suspicious character with its position and details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousChar {
    /// Byte offset in the string
    pub offset: usize,
    /// The suspicious character
    #[serde(rename = "character")]
    pub character: char,
    /// Unicode codepoint (e.g., "U+0456")
    pub codepoint: String,
    /// Human description (e.g., "Cyrillic Small Letter Byelorussian-Ukrainian I")
    pub description: String,
    /// Hex bytes of this character
    pub hex_bytes: String,
}

/// A single detection finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: RuleId,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: Vec<Evidence>,
    /// What a human sees (populated by Pro enrichment).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human_view: Option<String>,
    /// What an AI agent processes (populated by Pro enrichment).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_view: Option<String>,
    /// MITRE ATT&CK technique ID (populated by Team enrichment).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_id: Option<String>,
    /// User-defined custom rule ID (populated only for CustomRuleMatch findings).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_rule_id: Option<String>,
}

/// The action to take based on analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Warn,
    Block,
    /// Warn findings require explicit interactive acknowledgement.
    /// Used by `strict_warn` in hook-driven mode (exit code 3).
    WarnAck,
}

impl Action {
    pub fn exit_code(self) -> i32 {
        match self {
            Action::Allow => 0,
            Action::Block => 1,
            Action::Warn => 2,
            Action::WarnAck => 3,
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            Action::Allow => 0,
            Action::Warn | Action::WarnAck => 1,
            Action::Block => 2,
        }
    }
}

impl std::str::FromStr for Action {
    type Err = String;
    /// Parse the strict lowercase tokens used by lab-corpus / fixture TOML.
    /// Closed enum set: `allow`, `warn`, `block`, `warn_ack` — case-sensitive
    /// on purpose, so a corpus typo like `"BLOCK"` or `"blocK"` (which used
    /// to slip past the inline match-on-string and silently always-FAIL the
    /// scenario) surfaces as a hard parse error instead. Centralised here so
    /// callers (`lab.rs::run`, future consumers) share one parse table — the
    /// existing `#[serde(rename_all = "snake_case")]` derive only handles
    /// deserialization through serde; this is the explicit `&str` path used
    /// by the corpus' `expected_action` field.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow" => Ok(Action::Allow),
            "warn" => Ok(Action::Warn),
            "block" => Ok(Action::Block),
            "warn_ack" => Ok(Action::WarnAck),
            other => Err(format!("unknown action: {other}")),
        }
    }
}

pub fn action_from_findings(findings: &[Finding]) -> Action {
    if findings.is_empty() {
        return Action::Allow;
    }

    let max_severity = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);

    match max_severity {
        Severity::Critical | Severity::High => Action::Block,
        Severity::Medium | Severity::Low => Action::Warn,
        Severity::Info => Action::Allow,
    }
}

pub fn upgraded_action_from_findings(findings: &[Finding], current: Action) -> Action {
    let derived = action_from_findings(findings);
    if derived.rank() > current.rank() {
        derived
    } else {
        current
    }
}

/// Complete analysis verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub action: Action,
    pub findings: Vec<Finding>,
    pub tier_reached: u8,
    pub bypass_requested: bool,
    pub bypass_honored: bool,
    pub bypass_available: bool,
    pub interactive_detected: bool,
    pub policy_path_used: Option<String>,
    pub timings_ms: Timings,
    /// Number of URLs extracted during Tier 3 analysis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls_extracted_count: Option<usize>,

    /// Whether this verdict requires human approval before execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<bool>,
    /// Timeout in seconds for approval (0 = indefinite).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_timeout_secs: Option<u64>,
    /// Fallback action when approval times out: "block", "warn", or "allow".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_fallback: Option<String>,
    /// The rule_id that triggered the approval requirement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_rule: Option<String>,
    /// Sanitized single-line description of why approval is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_description: Option<String>,

    /// Human-readable reason when escalation upgraded the action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation_reason: Option<String>,

    /// Best-effort origin of the caller — *who* invoked tirith. M4 item 8
    /// records this on the verdict and the audit entry; the policy schema
    /// `agent_rules` is consulted against it by
    /// [`crate::escalation::apply_agent_rules`] inside
    /// [`crate::escalation::post_process_verdict`], where a `deny` match
    /// forces [`Action::Block`] and appends a
    /// [`RuleId::AgentDeniedByPolicy`] finding. See
    /// [`crate::agent_origin`] for the trust model (caller-claimed,
    /// operator-trust, never adversary-resistant).
    ///
    /// `None` means the caller path that produced this verdict has not been
    /// wired (engine-internal fast-exits, the gateway's short-circuit path
    /// before classification, etc.) or did not have enough signal to
    /// classify. `apply_agent_rules` treats `None` as
    /// [`crate::policy::AgentDecision::Unspecified`] — no enforcement
    /// effect, an engine path that never set an origin has nothing to match
    /// against. Old JSON without this field still parses (serde-default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_origin: Option<crate::agent_origin::AgentOrigin>,
}

/// Per-tier timing information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Timings {
    pub tier0_ms: f64,
    pub tier1_ms: f64,
    pub tier2_ms: Option<f64>,
    pub tier3_ms: Option<f64>,
    pub total_ms: f64,
}

impl Verdict {
    /// Create an allow verdict with no findings (fast path).
    pub fn allow_fast(tier_reached: u8, timings: Timings) -> Self {
        Self {
            action: Action::Allow,
            findings: Vec::new(),
            tier_reached,
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: timings,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
        }
    }

    /// Determine action from findings: max severity → action mapping.
    pub fn from_findings(findings: Vec<Finding>, tier_reached: u8, timings: Timings) -> Self {
        let action = action_from_findings(&findings);
        Self {
            action,
            findings,
            tier_reached,
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: timings,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_info_severity_maps_to_allow() {
        let findings = vec![Finding {
            rule_id: RuleId::NonAsciiHostname, // arbitrary rule
            severity: Severity::Info,
            title: "test".to_string(),
            description: "test".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];
        let verdict = Verdict::from_findings(findings, 3, Timings::default());
        assert_eq!(verdict.action, Action::Allow);
    }

    #[test]
    fn test_info_severity_display() {
        assert_eq!(format!("{}", Severity::Info), "INFO");
    }

    #[test]
    fn test_info_severity_ordering() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
    }

    #[test]
    fn test_upgraded_action_from_findings_upgrades_when_findings_are_stronger() {
        let findings = vec![Finding {
            rule_id: RuleId::ThreatSuspiciousPackage,
            severity: Severity::Medium,
            title: "test".to_string(),
            description: "test".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];

        assert_eq!(
            upgraded_action_from_findings(&findings, Action::Allow),
            Action::Warn
        );
    }

    #[test]
    fn test_upgraded_action_from_findings_preserves_stronger_current_action() {
        let findings = vec![Finding {
            rule_id: RuleId::ThreatSuspiciousPackage,
            severity: Severity::Medium,
            title: "test".to_string(),
            description: "test".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];

        assert_eq!(
            upgraded_action_from_findings(&findings, Action::Block),
            Action::Block
        );
    }

    #[test]
    fn test_action_from_findings_empty_returns_allow() {
        assert_eq!(action_from_findings(&[]), Action::Allow);
    }

    #[test]
    fn test_action_from_findings_high_returns_block() {
        let findings = vec![Finding {
            rule_id: RuleId::ThreatOsvVulnerable,
            severity: Severity::High,
            title: "test".to_string(),
            description: "test".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];
        assert_eq!(action_from_findings(&findings), Action::Block);
    }

    #[test]
    fn test_action_from_findings_critical_returns_block() {
        let findings = vec![Finding {
            rule_id: RuleId::ThreatMaliciousPackage,
            severity: Severity::Critical,
            title: "test".to_string(),
            description: "test".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];
        assert_eq!(action_from_findings(&findings), Action::Block);
    }

    #[test]
    fn test_action_from_findings_low_returns_warn() {
        let findings = vec![Finding {
            rule_id: RuleId::ThreatSuspiciousPackage,
            severity: Severity::Low,
            title: "test".to_string(),
            description: "test".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }];
        assert_eq!(action_from_findings(&findings), Action::Warn);
    }

    #[test]
    fn test_upgraded_action_preserves_current_on_empty_findings() {
        assert_eq!(
            upgraded_action_from_findings(&[], Action::Block),
            Action::Block
        );
    }
}
