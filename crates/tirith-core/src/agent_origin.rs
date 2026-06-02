//! Agent origin — *who* invoked tirith.
//!
//! The identity layer for M4 item 8 (agent governance): [`AgentOrigin`] records
//! the best-effort "what kind of caller produced this verdict?" and threads it
//! through [`crate::verdict::Verdict`] and [`crate::audit::AuditEntry`].
//!
//! It does NOT enforce anything itself — enforcement lives in
//! [`crate::escalation::apply_agent_rules`]. Populating [`Verdict::agent_origin`]
//! makes that reachable; unstamped paths are treated as
//! [`crate::policy::AgentDecision::Unspecified`] (no behavior change).
//!
//! [`Verdict::agent_origin`]: crate::verdict::Verdict#structfield.agent_origin
//!
//! # Trust model
//!
//! Every signal is caller-controlled (env var, MCP `initialize` param,
//! fakeable `is_terminal()`), so the origin is **operator-trust**, not
//! adversary-resistant. Code that gates behavior on origin must layer its own
//! threat model on top of that honesty.
//!
//! The enum is intentionally **closed** so a third party cannot smuggle a
//! fabricated category through `TIRITH_INTEGRATION`; the free-form strings
//! inside variants are caller-controlled, capped, and debug-escaped on render.

use serde::{Deserialize, Serialize};

/// Cap on a free-form caller-supplied label (`tool`, `client_name`, `name`,
/// `provider`), bounded so a hostile million-byte `TIRITH_INTEGRATION` cannot
/// bloat every audit entry.
pub const MAX_LABEL_LEN: usize = 256;

/// Maximum length of a free-form caller-supplied version string before
/// truncation. SemVer is short; we cap to a forgiving 64 bytes.
pub const MAX_VERSION_LEN: usize = 64;

/// Who invoked tirith — the best-effort origin recorded with the verdict and
/// audit entry.
///
/// **Closed enum, operator-trust only.** A third party cannot add a variant;
/// every signal is caller-controlled (informative, not adversary-resistant).
/// Free-form payloads are length-capped + sanitized at construction via
/// [`sanitize_caller_label`] / [`sanitize_caller_version`].
///
/// Serialized as a tagged union (`tag = "kind"`, snake_case), e.g.
/// `{"kind":"agent","tool":"claude-code"}`. An older log with no `agent_origin`
/// still parses (the field serde-defaults to `None`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentOrigin {
    /// A human at a terminal — the default. `interactive` duplicates
    /// [`Verdict::interactive_detected`] so an audit consumer reading only
    /// `agent_origin` need not know the verdict-level field.
    ///
    /// [`Verdict::interactive_detected`]: crate::verdict::Verdict#structfield.interactive_detected
    Human {
        /// Whether stderr looked like a TTY or `TIRITH_INTERACTIVE=1` was set.
        /// Caller-controllable; not load-bearing.
        interactive: bool,
    },
    /// An AI coding agent self-reporting via `TIRITH_INTEGRATION`.
    Agent {
        /// Sanitized integration name (caller-claimed, not verified). See
        /// [`sanitize_caller_label`].
        tool: String,
        /// Sanitized integration version, when supplied.
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<String>,
    },
    /// An MCP client identifying itself via the JSON-RPC `initialize.clientInfo`
    /// payload (caller-claimed; not normalized across vendors).
    Mcp {
        /// Sanitized `clientInfo.name`.
        client_name: String,
        /// Sanitized `clientInfo.version`.
        #[serde(skip_serializing_if = "Option::is_none")]
        client_version: Option<String>,
    },
    /// `tirith gateway` acting as a policy enforcement point in front of another
    /// consumer. No payload yet.
    Gateway,
    /// A CI runner identified by env heuristics; `provider` is the env-key shape
    /// (e.g. `"github-actions"`), `None` for a generic `CI` signal.
    Ci {
        /// Sanitized provider name; `None` when only generic `CI` was observed.
        #[serde(skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
    },
    /// IDE-driven invocation. Unused today (IDEs set `TIRITH_INTEGRATION` and
    /// land in [`AgentOrigin::Agent`]); reserved for a more-trusted IDE signal.
    Ide {
        /// Sanitized IDE name.
        name: String,
    },
}

impl AgentOrigin {
    /// Build a [`AgentOrigin::Human`] with the supplied interactive flag.
    pub fn human(interactive: bool) -> Self {
        Self::Human { interactive }
    }

    /// Build an [`AgentOrigin::Agent`]; both fields are sanitized, and an empty
    /// sanitized tool yields `None` so the caller can fall back.
    pub fn agent(tool: &str, version: Option<&str>) -> Option<Self> {
        let tool = sanitize_caller_label(tool);
        if tool.is_empty() {
            return None;
        }
        Some(Self::Agent {
            tool,
            version: version.and_then(non_empty_version),
        })
    }

    /// Build an [`AgentOrigin::Mcp`] from `clientInfo.name`/`.version`; both are
    /// sanitized, and an empty sanitized name yields `None`.
    pub fn mcp(client_name: &str, client_version: Option<&str>) -> Option<Self> {
        let client_name = sanitize_caller_label(client_name);
        if client_name.is_empty() {
            return None;
        }
        Some(Self::Mcp {
            client_name,
            client_version: client_version.and_then(non_empty_version),
        })
    }

    /// Build a [`AgentOrigin::Ci`] from an optional provider name. The
    /// sanitized provider may be `None` (generic CI) or a non-empty string.
    pub fn ci(provider: Option<&str>) -> Self {
        Self::Ci {
            provider: provider.and_then(non_empty_label),
        }
    }

    /// Build a [`AgentOrigin::Ide`] from a caller-supplied IDE name. Returns
    /// `None` if the sanitized name is empty.
    pub fn ide(name: &str) -> Option<Self> {
        let name = sanitize_caller_label(name);
        if name.is_empty() {
            None
        } else {
            Some(Self::Ide { name })
        }
    }

    /// A short, lower-case category tag — `"human"`, `"agent"`, `"mcp"`,
    /// `"gateway"`, `"ci"`, `"ide"`. Useful for aggregation and dashboards;
    /// does NOT carry the payload (the tool / client name).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Human { .. } => "human",
            Self::Agent { .. } => "agent",
            Self::Mcp { .. } => "mcp",
            Self::Gateway => "gateway",
            Self::Ci { .. } => "ci",
            Self::Ide { .. } => "ide",
        }
    }
}

/// Resolve an [`AgentOrigin`] for the CLI path from the process environment.
/// First match wins: `TIRITH_INTEGRATION` → [`AgentOrigin::Agent`]; CI heuristics
/// → [`AgentOrigin::Ci`]; else [`AgentOrigin::Human`] with the caller's
/// `interactive` flag (pass the same value tirith computed for the verdict).
///
/// Caller-trust only — every signal is settable by any process running as the
/// user; never a sole defense against a hostile environment.
pub fn resolve_cli_origin(interactive: bool) -> AgentOrigin {
    // 1. Explicit self-identification wins. `TIRITH_INTEGRATION_VERSION` is an
    //    optional companion version slot (documented; unused today).
    if let Ok(raw) = std::env::var("TIRITH_INTEGRATION") {
        let version = std::env::var("TIRITH_INTEGRATION_VERSION").ok();
        if let Some(origin) = AgentOrigin::agent(&raw, version.as_deref()) {
            return origin;
        }
    }

    // 2. CI heuristic. A named provider beats a generic `CI=true`.
    if let Some(provider) = detect_ci_provider() {
        return AgentOrigin::ci(Some(&provider));
    }
    if env_is_truthy("CI") {
        return AgentOrigin::ci(None);
    }

    // 3. Default: a human at (or pretending to be at) a terminal.
    AgentOrigin::human(interactive)
}

/// Detect a CI provider from a small audited set of env vars, returning the
/// first match's sanitized provider tag (or `None`). The tag is fixed in source,
/// not derived from env values.
pub fn detect_ci_provider() -> Option<String> {
    // (env_var_name, canonical lowercase-kebab provider tag).
    const PROVIDERS: &[(&str, &str)] = &[
        ("GITHUB_ACTIONS", "github-actions"),
        ("GITLAB_CI", "gitlab-ci"),
        ("BUILDKITE", "buildkite"),
        ("CIRCLECI", "circleci"),
        ("JENKINS_URL", "jenkins"),
        ("TRAVIS", "travis-ci"),
        ("TF_BUILD", "azure-pipelines"),
        ("BITBUCKET_BUILD_NUMBER", "bitbucket-pipelines"),
        ("TEAMCITY_VERSION", "teamcity"),
        ("DRONE", "drone-ci"),
        ("CODEBUILD_BUILD_ID", "aws-codebuild"),
    ];

    for (var, tag) in PROVIDERS {
        if env_is_truthy(var) {
            return Some((*tag).to_string());
        }
    }
    None
}

/// True when the env var exists and is not `"0"`/`""`/`"false"`
/// (case-insensitive) — CI vars take varied values, so "present and not
/// explicitly disabled" is the honest test.
fn env_is_truthy(var: &str) -> bool {
    match std::env::var(var) {
        Ok(v) => {
            let v = v.trim();
            !v.is_empty() && !v.eq_ignore_ascii_case("0") && !v.eq_ignore_ascii_case("false")
        }
        Err(_) => false,
    }
}

/// Sanitize a caller-supplied free-form label: trim, replace control/format/
/// invisible chars with `?` (so a hostile value can't inject newlines/ANSI/NUL
/// into an audit line or JSON), and cap at [`MAX_LABEL_LEN`] bytes truncating on
/// a char boundary. Empty result is preserved (caller decides the fallback).
pub fn sanitize_caller_label(raw: &str) -> String {
    let trimmed = raw.trim();
    let mut out = String::with_capacity(trimmed.len().min(MAX_LABEL_LEN));
    for ch in trimmed.chars() {
        // Keep printable ASCII + printable Unicode; drop C0 control, DEL, and
        // invisible/format/surrogate codepoints (the byte classes the byte-scan
        // rules flag in command input).
        let keep = if (ch as u32) < 0x20 || ch == '\u{7f}' {
            false
        } else {
            !is_invisible_or_format(ch)
        };
        if keep {
            // A 4-byte char must still fit the byte budget.
            if out.len() + ch.len_utf8() > MAX_LABEL_LEN {
                break;
            }
            out.push(ch);
        } else {
            if out.len() + 1 > MAX_LABEL_LEN {
                break;
            }
            out.push('?');
        }
    }
    out
}

/// Sanitize a caller-supplied version string. Same rules as
/// [`sanitize_caller_label`] but with a tighter cap ([`MAX_VERSION_LEN`]).
pub fn sanitize_caller_version(raw: &str) -> String {
    let trimmed = raw.trim();
    let mut out = String::with_capacity(trimmed.len().min(MAX_VERSION_LEN));
    for ch in trimmed.chars() {
        let keep = (ch as u32) >= 0x20 && ch != '\u{7f}' && !is_invisible_or_format(ch);
        if keep {
            if out.len() + ch.len_utf8() > MAX_VERSION_LEN {
                break;
            }
            out.push(ch);
        } else {
            if out.len() + 1 > MAX_VERSION_LEN {
                break;
            }
            out.push('?');
        }
    }
    out
}

/// True for codepoints we never round-trip through the origin payload: bidi
/// controls, zero-width, Unicode tags, variation selectors, surrogates, C1
/// controls, and other format-class chars — the byte classes tirith already
/// flags in command input. C1 controls (U+0080..U+009F) are included because the
/// C0 drop in [`sanitize_caller_label`] catches `< 0x20` only, so an 8-bit CSI
/// (U+009B) / OSC (U+009D) could otherwise reach the terminal.
fn is_invisible_or_format(ch: char) -> bool {
    matches!(
        ch as u32,
        // C1 controls (CSI/OSC/DCS/APC) — not covered by the C0 `< 0x20` check.
        0x80..=0x9F
        // Bidirectional controls (U+202A..U+202E, U+2066..U+2069)
        | 0x202A..=0x202E
        | 0x2066..=0x2069
        // Zero-width characters (ZWSP, ZWNJ, ZWJ, WJ)
        | 0x200B..=0x200D
        | 0x2060
        // Soft hyphen
        | 0x00AD
        // BOM / no-break-zero-width
        | 0xFEFF
        // Mongolian / Hangul fillers
        | 0x180E
        | 0x115F
        | 0x1160
        | 0x3164
        | 0xFFA0
        // Unicode tags
        | 0xE0000..=0xE007F
        // Variation selectors
        | 0xFE00..=0xFE0F
        | 0xE0100..=0xE01EF
        // Invisible math operators
        | 0x2061..=0x2064
        // Line / paragraph separators
        | 0x2028
        | 0x2029
        // Surrogates (should never appear in &str, but be defensive)
        | 0xD800..=0xDFFF
    )
}

/// Helper used by [`AgentOrigin::ci`] for the provider slot, where we never
/// want a zero-length tag to survive sanitization.
fn non_empty_label(raw: &str) -> Option<String> {
    let s = sanitize_caller_label(raw);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn non_empty_version(raw: &str) -> Option<String> {
    let s = sanitize_caller_version(raw);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_tags_are_stable() {
        assert_eq!(AgentOrigin::human(true).kind(), "human");
        assert_eq!(
            AgentOrigin::agent("claude-code", None).unwrap().kind(),
            "agent"
        );
        assert_eq!(AgentOrigin::mcp("cursor", None).unwrap().kind(), "mcp");
        assert_eq!(AgentOrigin::Gateway.kind(), "gateway");
        assert_eq!(AgentOrigin::ci(Some("github-actions")).kind(), "ci");
        assert_eq!(AgentOrigin::ide("vscode").unwrap().kind(), "ide");
    }

    #[test]
    fn sanitize_label_strips_control_and_caps_length() {
        // ANSI escape + newline + NUL must be replaced with `?` — no literal
        // CR/LF/ESC/NUL that could splice into a JSONL audit line.
        let hostile = "claude\x1b[31mcode\n\x00";
        let clean = sanitize_caller_label(hostile);
        assert!(!clean.contains('\n'));
        assert!(!clean.contains('\x1b'));
        assert!(!clean.contains('\x00'));
        assert!(clean.starts_with("claude"));
        assert!(clean.contains('?'));

        // Length cap: a million bytes truncates cleanly without panicking.
        let huge = "a".repeat(1_000_000);
        let clean = sanitize_caller_label(&huge);
        assert!(clean.len() <= MAX_LABEL_LEN);
        assert!(clean.chars().all(|c| c == 'a'));
    }

    #[test]
    fn sanitize_label_drops_invisible_unicode() {
        // Bidi RLO + zero-width joiner + Unicode tag must NOT survive.
        let hostile = "claude\u{202E}code\u{200B}\u{E0041}";
        let clean = sanitize_caller_label(hostile);
        assert!(!clean.contains('\u{202E}'));
        assert!(!clean.contains('\u{200B}'));
        assert!(!clean.contains('\u{E0041}'));
        assert!(clean.contains("claude"));
        assert!(clean.contains("code"));
    }

    #[test]
    fn sanitize_label_drops_c1_controls() {
        // C1 controls (CSI/OSC/DCS/APC) are not `< 0x20`, so they must be filtered
        // via is_invisible_or_format — else an 8-bit CSI could reach the terminal.
        let hostile = "cur\u{009B}sor\u{009D}name\u{0090}\u{009F}";
        let clean = sanitize_caller_label(hostile);
        for c1 in ['\u{0080}', '\u{0090}', '\u{009B}', '\u{009D}', '\u{009F}'] {
            assert!(
                !clean.contains(c1),
                "C1 control U+{:04X} survived sanitizer: {clean:?}",
                c1 as u32,
            );
        }
        assert!(
            clean.starts_with("cur"),
            "ASCII prefix must survive: {clean:?}"
        );
    }

    #[test]
    fn sanitize_label_truncates_on_char_boundary_without_panic() {
        // A 4-byte char ('🦀') repeated past the cap — never slice mid-codepoint.
        let crab = "🦀".repeat(MAX_LABEL_LEN);
        let clean = sanitize_caller_label(&crab);
        assert!(clean.len() <= MAX_LABEL_LEN);
        // Every kept char is a full crab, never a partial sequence.
        assert!(clean.chars().all(|c| c == '🦀'));
    }

    #[test]
    fn agent_returns_none_for_blank_label() {
        assert!(AgentOrigin::agent("", None).is_none());
        assert!(AgentOrigin::agent("   \t  ", None).is_none());
        // Pure-control input sanitizes to "???" — non-empty, so kept (a hostile
        // env must not slip through as "human" silently).
        assert!(AgentOrigin::agent("\x00\x01\x02", None).is_some());
    }

    #[test]
    fn mcp_returns_none_for_blank_client_name() {
        assert!(AgentOrigin::mcp("", None).is_none());
        assert!(AgentOrigin::mcp("   ", None).is_none());
        assert!(AgentOrigin::mcp("cursor", Some("0.42.0")).is_some());
    }

    #[test]
    fn agent_version_is_sanitized_and_capped() {
        let huge_version = "1.2.3-".to_string() + &"a".repeat(1_000);
        let origin = AgentOrigin::agent("claude-code", Some(&huge_version)).unwrap();
        if let AgentOrigin::Agent {
            version: Some(v), ..
        } = origin
        {
            assert!(v.len() <= MAX_VERSION_LEN);
            assert!(v.starts_with("1.2.3-"));
        } else {
            panic!("expected Agent with version");
        }
    }

    #[test]
    fn ci_with_empty_provider_yields_none_payload() {
        let origin = AgentOrigin::ci(Some(""));
        if let AgentOrigin::Ci { provider } = origin {
            assert_eq!(provider, None);
        } else {
            panic!("expected Ci");
        }
    }

    // env-driven resolver tests; hold the global env lock (they mutate env).

    #[test]
    fn resolve_cli_origin_prefers_tirith_integration() {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // TIRITH_INTEGRATION wins over CI signals.
        unsafe {
            std::env::set_var("TIRITH_INTEGRATION", "claude-code");
            std::env::set_var("TIRITH_INTEGRATION_VERSION", "1.2.3");
            std::env::set_var("CI", "true");
            std::env::set_var("GITHUB_ACTIONS", "true");
        }

        let origin = resolve_cli_origin(false);
        assert_eq!(origin.kind(), "agent");
        if let AgentOrigin::Agent { tool, version } = origin {
            assert_eq!(tool, "claude-code");
            assert_eq!(version.as_deref(), Some("1.2.3"));
        } else {
            panic!("expected Agent");
        }

        unsafe {
            std::env::remove_var("TIRITH_INTEGRATION");
            std::env::remove_var("TIRITH_INTEGRATION_VERSION");
            std::env::remove_var("CI");
            std::env::remove_var("GITHUB_ACTIONS");
        }
    }

    #[test]
    fn resolve_cli_origin_detects_named_ci_when_no_integration() {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        unsafe {
            std::env::remove_var("TIRITH_INTEGRATION");
            std::env::remove_var("TIRITH_INTEGRATION_VERSION");
            std::env::set_var("GITHUB_ACTIONS", "true");
            std::env::remove_var("CI");
            std::env::remove_var("GITLAB_CI");
            std::env::remove_var("BUILDKITE");
        }

        let origin = resolve_cli_origin(false);
        assert_eq!(origin.kind(), "ci");
        if let AgentOrigin::Ci { provider } = origin {
            assert_eq!(provider.as_deref(), Some("github-actions"));
        } else {
            panic!("expected Ci");
        }

        unsafe {
            std::env::remove_var("GITHUB_ACTIONS");
        }
    }

    #[test]
    fn resolve_cli_origin_detects_generic_ci_without_named_provider() {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Clear every named-provider variable we know about, then set only CI=true.
        let named = [
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "BUILDKITE",
            "CIRCLECI",
            "JENKINS_URL",
            "TRAVIS",
            "TF_BUILD",
            "BITBUCKET_BUILD_NUMBER",
            "TEAMCITY_VERSION",
            "DRONE",
            "CODEBUILD_BUILD_ID",
        ];
        unsafe {
            std::env::remove_var("TIRITH_INTEGRATION");
            for v in named {
                std::env::remove_var(v);
            }
            std::env::set_var("CI", "true");
        }

        let origin = resolve_cli_origin(false);
        assert_eq!(origin.kind(), "ci");
        if let AgentOrigin::Ci { provider } = origin {
            assert_eq!(provider, None);
        } else {
            panic!("expected Ci");
        }

        unsafe {
            std::env::remove_var("CI");
        }
    }

    #[test]
    fn resolve_cli_origin_falls_back_to_human() {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let to_clear = [
            "TIRITH_INTEGRATION",
            "TIRITH_INTEGRATION_VERSION",
            "CI",
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "BUILDKITE",
            "CIRCLECI",
            "JENKINS_URL",
            "TRAVIS",
            "TF_BUILD",
            "BITBUCKET_BUILD_NUMBER",
            "TEAMCITY_VERSION",
            "DRONE",
            "CODEBUILD_BUILD_ID",
        ];
        unsafe {
            for v in to_clear {
                std::env::remove_var(v);
            }
        }

        let origin = resolve_cli_origin(true);
        assert_eq!(origin.kind(), "human");
        if let AgentOrigin::Human { interactive } = origin {
            assert!(interactive);
        } else {
            panic!("expected Human");
        }
    }

    #[test]
    fn resolve_cli_origin_treats_ci_false_as_not_ci() {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Some shells default `CI=false` — that should NOT trip the CI branch.
        let to_clear = [
            "TIRITH_INTEGRATION",
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "BUILDKITE",
            "CIRCLECI",
            "JENKINS_URL",
            "TRAVIS",
            "TF_BUILD",
            "BITBUCKET_BUILD_NUMBER",
            "TEAMCITY_VERSION",
            "DRONE",
            "CODEBUILD_BUILD_ID",
        ];
        unsafe {
            for v in to_clear {
                std::env::remove_var(v);
            }
            std::env::set_var("CI", "false");
        }

        let origin = resolve_cli_origin(false);
        assert_eq!(origin.kind(), "human");

        unsafe {
            std::env::remove_var("CI");
        }
    }

    #[test]
    fn resolve_cli_origin_ignores_hostile_tirith_integration() {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // A million-byte hostile value with control bytes must not crash, not
        // produce a multi-line audit-poisoning label, and cap at MAX_LABEL_LEN.
        let hostile = format!(
            "{}\n\x1b[31m{}",
            "x".repeat(1_000_000),
            "y".repeat(1_000_000)
        );
        unsafe {
            std::env::set_var("TIRITH_INTEGRATION", &hostile);
            std::env::remove_var("CI");
        }

        let origin = resolve_cli_origin(false);
        assert_eq!(origin.kind(), "agent");
        if let AgentOrigin::Agent { tool, .. } = origin {
            assert!(tool.len() <= MAX_LABEL_LEN);
            assert!(!tool.contains('\n'));
            assert!(!tool.contains('\x1b'));
        } else {
            panic!("expected Agent");
        }

        unsafe {
            std::env::remove_var("TIRITH_INTEGRATION");
        }
    }

    // --- serde round-trip ---

    #[test]
    fn serde_round_trip_agent() {
        let origin = AgentOrigin::agent("claude-code", Some("1.2.3")).unwrap();
        let json = serde_json::to_string(&origin).unwrap();
        // Closed-enum tag is `kind`.
        assert!(json.contains(r#""kind":"agent""#));
        assert!(json.contains(r#""tool":"claude-code""#));
        assert!(json.contains(r#""version":"1.2.3""#));
        let parsed: AgentOrigin = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, origin);
    }

    #[test]
    fn serde_round_trip_human() {
        let origin = AgentOrigin::human(true);
        let json = serde_json::to_string(&origin).unwrap();
        assert_eq!(json, r#"{"kind":"human","interactive":true}"#);
        let parsed: AgentOrigin = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, origin);
    }

    #[test]
    fn serde_round_trip_mcp() {
        let origin = AgentOrigin::mcp("Cursor", Some("0.42")).unwrap();
        let json = serde_json::to_string(&origin).unwrap();
        let parsed: AgentOrigin = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, origin);
    }

    #[test]
    fn serde_round_trip_ci_named() {
        let origin = AgentOrigin::ci(Some("github-actions"));
        let json = serde_json::to_string(&origin).unwrap();
        let parsed: AgentOrigin = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, origin);
    }

    #[test]
    fn serde_round_trip_ci_generic() {
        let origin = AgentOrigin::ci(None);
        let json = serde_json::to_string(&origin).unwrap();
        // `provider` is `skip_serializing_if = Option::is_none` — omitted, not null.
        assert_eq!(json, r#"{"kind":"ci"}"#);
        let parsed: AgentOrigin = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, origin);
    }

    #[test]
    fn serde_round_trip_gateway() {
        let origin = AgentOrigin::Gateway;
        let json = serde_json::to_string(&origin).unwrap();
        assert_eq!(json, r#"{"kind":"gateway"}"#);
        let parsed: AgentOrigin = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, origin);
    }

    #[test]
    fn serde_unknown_kind_fails_cleanly() {
        // Unrecognized variant — serde returns an error, never a panic.
        let bad = r#"{"kind":"telepathy","aura":"violet"}"#;
        let res: Result<AgentOrigin, _> = serde_json::from_str(bad);
        assert!(res.is_err());
    }

    #[test]
    fn version_sanitization_drops_control_bytes() {
        let v = sanitize_caller_version("1.2.3\n\x1b[31m");
        assert!(!v.contains('\n'));
        assert!(!v.contains('\x1b'));
        assert!(v.starts_with("1.2.3"));
    }
}
