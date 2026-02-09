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

    // Command shape rules
    PipeToInterpreter,
    CurlPipeShell,
    WgetPipeShell,
    HttpiePipeShell,
    XhPipeShell,
    DotfileOverwrite,
    ArchiveExtract,

    // Environment rules
    ProxyEnvSet,

    // Ecosystem rules
    GitTyposquat,
    DockerUntrustedRegistry,
    PipUrlInstall,
    NpmUrlInstall,
    Web3RpcEndpoint,
    Web3AddressInUrl,

    // Policy rules
    PolicyBlocklisted,
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
}

/// The action to take based on analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Warn,
    Block,
}

impl Action {
    pub fn exit_code(self) -> i32 {
        match self {
            Action::Allow => 0,
            Action::Block => 1,
            Action::Warn => 2,
        }
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
    pub interactive_detected: bool,
    pub policy_path_used: Option<String>,
    pub timings_ms: Timings,
    /// Number of URLs extracted during Tier 3 analysis.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls_extracted_count: Option<usize>,
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
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: timings,
            urls_extracted_count: None,
        }
    }

    /// Determine action from findings: max severity → action mapping.
    pub fn from_findings(findings: Vec<Finding>, tier_reached: u8, timings: Timings) -> Self {
        let action = if findings.is_empty() {
            Action::Allow
        } else {
            let max_severity = findings
                .iter()
                .map(|f| f.severity)
                .max()
                .unwrap_or(Severity::Low);
            match max_severity {
                Severity::Critical | Severity::High => Action::Block,
                Severity::Medium | Severity::Low => Action::Warn,
                Severity::Info => Action::Allow,
            }
        };
        Self {
            action,
            findings,
            tier_reached,
            bypass_requested: false,
            bypass_honored: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: timings,
            urls_extracted_count: None,
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
}
