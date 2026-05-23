//! Agent origin — *who* invoked tirith.
//!
//! This module is the **identity layer** for Milestone 4 item 8 ("Agent
//! governance — per-agent identity + policy"). It defines a single data
//! type, [`AgentOrigin`], that records the best-effort answer to *"what
//! kind of caller produced this verdict?"* and threads it through
//! [`crate::verdict::Verdict`] and [`crate::audit::AuditEntry`].
//!
//! It does **NOT** enforce anything on its own — enforcement lives in
//! [`crate::escalation::apply_agent_rules`], which consults
//! [`crate::policy::agent_decision`] against the stored origin and, on a
//! `deny` match, forces [`Verdict::action`] to
//! [`crate::verdict::Action::Block`] and appends a
//! [`crate::verdict::RuleId::AgentDeniedByPolicy`] finding. Populating
//! [`Verdict::agent_origin`] is what makes that enforcement reachable;
//! engine paths that do not stamp an origin are treated as
//! [`crate::policy::AgentDecision::Unspecified`] (no behavior change).
//!
//! [`RuleId`]: crate::verdict::RuleId
//! [`Verdict::action`]: crate::verdict::Verdict#structfield.action
//! [`Verdict::agent_origin`]: crate::verdict::Verdict#structfield.agent_origin
//!
//! # Trust model
//!
//! Every signal that feeds [`AgentOrigin`] is **caller-controlled**: an
//! environment variable an attacker on the same machine can set, an MCP
//! `initialize` parameter the attacker's client can lie about, an
//! `is_terminal()` result an attacker can fake by allocating a PTY. The
//! origin is therefore **operator-trust**, not adversary-resistant: useful
//! for explaining what an honest caller looked like, never sufficient on its
//! own to attribute an action to a determined adversary controlling the
//! environment. Subsequent chunks that gate behavior on origin must layer
//! their threat model on top of that honesty, not assume it.
//!
//! # Surface
//!
//! The enum is intentionally **closed** — adding a new variant requires a
//! source change, so a third party cannot smuggle a fabricated category
//! through `TIRITH_INTEGRATION`. The free-form `tool` / `client_name` /
//! `name` strings *inside* the variants are caller-controlled, capped, and
//! safe to debug-escape on render (see [`sanitize_caller_label`] and
//! [`sanitize_caller_version`]).

use serde::{Deserialize, Serialize};

/// Maximum length of a free-form caller-supplied label (`tool`, `client_name`,
/// `name`, `provider`) before truncation. The cap is generous (256 bytes) —
/// real values are short (`claude-code`, `cursor`) — but bounded so a hostile
/// `TIRITH_INTEGRATION` of a million bytes cannot bloat every audit entry.
pub const MAX_LABEL_LEN: usize = 256;

/// Maximum length of a free-form caller-supplied version string before
/// truncation. SemVer is short; we cap to a forgiving 64 bytes.
pub const MAX_VERSION_LEN: usize = 64;

/// Who invoked tirith — the best-effort origin signal recorded alongside the
/// verdict and the audit entry.
///
/// **Closed enum.** A third party cannot extend this set without a source
/// change. Free-form strings appear only as variant *payloads* (`tool`,
/// `client_name`, `name`, `provider`), are caller-controlled, and are
/// length-capped + content-sanitized at construction time via
/// [`sanitize_caller_label`] / [`sanitize_caller_version`].
///
/// **Operator-trust only.** Every signal that produces a variant is
/// caller-controlled — `TIRITH_INTEGRATION`, `CI`, `GITHUB_ACTIONS`, MCP
/// `initialize.client_info`, `is_terminal()`. The origin is informative, not
/// adversary-resistant.
///
/// # Serialization
///
/// Tagged union (`#[serde(tag = "kind", rename_all = "snake_case")]`) — the
/// JSON representation is, e.g., `{"kind":"agent","tool":"claude-code"}`. An
/// older log file with no `agent_origin` field still parses (the parent
/// struct serde-defaults the field to `None`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentOrigin {
    /// A human at a terminal — the default when nothing else identifies the
    /// caller. `interactive` carries the same flag tirith already records on
    /// [`Verdict::interactive_detected`], duplicated here so a downstream
    /// audit consumer that only reads `agent_origin` does not need to know
    /// the verdict-level field.
    ///
    /// [`Verdict::interactive_detected`]: crate::verdict::Verdict#structfield.interactive_detected
    Human {
        /// Best-effort: whether stderr looked like a TTY or `TIRITH_INTERACTIVE=1`
        /// was set. Caller-controllable; not load-bearing for any decision.
        interactive: bool,
    },
    /// An AI coding agent (Claude Code, Cursor, Windsurf, …) self-reporting
    /// via `TIRITH_INTEGRATION`.
    ///
    /// `tool` is the raw, sanitized value of `TIRITH_INTEGRATION` (or an
    /// equivalent integration name passed by a daemon caller). Treat this as
    /// **caller-claimed**, not verified — any process running as the user can
    /// set `TIRITH_INTEGRATION` to anything.
    Agent {
        /// Sanitized integration name. Length-capped at [`MAX_LABEL_LEN`];
        /// control bytes replaced. See [`sanitize_caller_label`].
        tool: String,
        /// Sanitized integration version, when the caller supplied one.
        /// Length-capped at [`MAX_VERSION_LEN`].
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<String>,
    },
    /// An MCP client connected to `tirith mcp-server`, identifying itself via
    /// the JSON-RPC `initialize.clientInfo` payload.
    ///
    /// `client_name` is the raw, sanitized value of `clientInfo.name` and is
    /// caller-claimed — an MCP client may report anything. We do not normalize
    /// across vendors (no "Claude Code" → "claude-code"); the operator sees
    /// the string the client sent, debug-escaped for terminal safety.
    Mcp {
        /// Sanitized `clientInfo.name`. Length-capped at [`MAX_LABEL_LEN`].
        client_name: String,
        /// Sanitized `clientInfo.version`. Length-capped at [`MAX_VERSION_LEN`].
        #[serde(skip_serializing_if = "Option::is_none")]
        client_version: Option<String>,
    },
    /// The gateway path — `tirith gateway` is acting as a policy enforcement
    /// point in front of another consumer (a chat UI, an LLM proxy). No
    /// payload yet; chunk 2+ may extend this with the upstream consumer name.
    Gateway,
    /// A CI runner identified by environment heuristics (`GITHUB_ACTIONS`,
    /// `BUILDKITE`, etc.). The provider name is the env-key shape (e.g.
    /// `"github-actions"`); `None` means CI was inferred from a generic `CI`
    /// signal without a specific provider.
    Ci {
        /// Sanitized provider name. `None` when only the generic `CI` env was
        /// observed.
        #[serde(skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
    },
    /// IDE-driven invocation when not otherwise classifiable. Today this is
    /// unused — IDE integrations set `TIRITH_INTEGRATION` and land in
    /// [`AgentOrigin::Agent`]. Reserved for a future signal an IDE can provide
    /// that tirith trusts more strongly than `TIRITH_INTEGRATION`.
    Ide {
        /// Sanitized IDE name. Length-capped at [`MAX_LABEL_LEN`].
        name: String,
    },
}

impl AgentOrigin {
    /// Build a [`AgentOrigin::Human`] with the supplied interactive flag.
    pub fn human(interactive: bool) -> Self {
        Self::Human { interactive }
    }

    /// Build a [`AgentOrigin::Agent`] from a caller-supplied tool name and
    /// optional version. Both are sanitized; if the sanitized tool is empty,
    /// returns `None` so the caller can fall back to a safer default.
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

    /// Build a [`AgentOrigin::Mcp`] from a caller-supplied `clientInfo.name`
    /// and optional `clientInfo.version`. Both are sanitized; if the
    /// sanitized name is empty, returns `None`.
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

/// Resolve an [`AgentOrigin`] for the **CLI path** from the current process
/// environment.
///
/// Priority order — first match wins:
/// 1. `TIRITH_INTEGRATION` is set and sanitizes to non-empty →
///    [`AgentOrigin::Agent`].
/// 2. CI heuristics fire ([`detect_ci_provider`] returns `Some(_)` or the
///    generic `CI` env signal is set) → [`AgentOrigin::Ci`].
/// 3. Otherwise → [`AgentOrigin::Human`] with the caller-supplied
///    `interactive` flag.
///
/// Caller is responsible for passing the same `interactive` value tirith
/// computed for the verdict — see [`crate::verdict::Verdict::interactive_detected`].
///
/// **Caller-trust only.** Every signal here is settable by any process running
/// as the user. The output identifies an honest caller's category; it is
/// never a sole defense against a hostile environment.
pub fn resolve_cli_origin(interactive: bool) -> AgentOrigin {
    // 1. Explicit self-identification wins. We accept "TIRITH_INTEGRATION_VERSION"
    //    as an optional companion variable so an integration can report its
    //    version without us having to invent a separate channel; today no
    //    integration sets it, but the slot is documented.
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

/// Detect a specific CI provider by walking a small, audited set of well-known
/// environment variables. Returns the sanitized provider tag the first match
/// produces, or `None` when no named provider is observed.
///
/// The list is deliberately small — every entry has to come back through here
/// in a future chunk if the operator wants to gate on a specific provider,
/// and an attacker controlling the env can already set any of these. We
/// surface what the provider sets natively; we do not invent new identifiers.
pub fn detect_ci_provider() -> Option<String> {
    // (env_var_name, canonical_provider_tag) — env shape, lowercase-kebab tag.
    // The tag is fixed in source; it never includes attacker bytes.
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

/// True when the given env var exists and is not literally `"0"`, `""`, or
/// `"false"` (case-insensitive). CI env vars are set to varied values by
/// providers — sometimes `"true"`, sometimes a URL, sometimes the build ID —
/// so "present and not explicitly disabled" is the honest test.
fn env_is_truthy(var: &str) -> bool {
    match std::env::var(var) {
        Ok(v) => {
            let v = v.trim();
            !v.is_empty() && !v.eq_ignore_ascii_case("0") && !v.eq_ignore_ascii_case("false")
        }
        Err(_) => false,
    }
}

/// Sanitize a caller-supplied free-form label (`TIRITH_INTEGRATION`,
/// `clientInfo.name`, IDE name, CI provider tag).
///
/// Rules — applied in order:
/// 1. Trim leading/trailing ASCII whitespace.
/// 2. Replace any non-printable / control byte (ASCII < 0x20 or == 0x7F, and
///    any byte that's part of a non-ASCII control codepoint) with `?`. This
///    prevents a hostile `TIRITH_INTEGRATION` from injecting newlines into an
///    audit log line, ANSI escapes into a terminal, or NUL bytes into a JSON
///    string the parser later rejects.
/// 3. Cap at [`MAX_LABEL_LEN`] bytes by **truncating to a char boundary** —
///    naive `&s[..N]` could panic on multibyte UTF-8.
///
/// Empty result is preserved (the caller decides whether empty → fall back).
pub fn sanitize_caller_label(raw: &str) -> String {
    let trimmed = raw.trim();
    let mut out = String::with_capacity(trimmed.len().min(MAX_LABEL_LEN));
    for ch in trimmed.chars() {
        // Hold to printable ASCII + printable Unicode. Drop ASCII control
        // (incl. CR/LF/NUL/ESC), DEL, and any non-character / format
        // codepoint. Non-ASCII printable codepoints are kept — an integration
        // name could legitimately contain a non-ASCII letter — but the byte
        // cap below stops the output from blowing past MAX_LABEL_LEN.
        let keep = if (ch as u32) < 0x20 || ch == '\u{7f}' {
            false
        } else {
            // Reject Unicode general categories that are invisible / format /
            // surrogate — these are the same byte-classes the byte-scan rules
            // already treat as suspicious in command/paste input.
            !is_invisible_or_format(ch)
        };
        if keep {
            // Byte-budget check: a 4-byte char must still fit.
            if out.len() + ch.len_utf8() > MAX_LABEL_LEN {
                break;
            }
            out.push(ch);
        } else {
            // Substitute a visible placeholder, but only when we have room.
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

/// True for codepoints we never want to round-trip through the agent-origin
/// payload: bidi controls, zero-width characters, Unicode tags, variation
/// selectors, surrogates, C1 controls (CSI/OSC/APC/DCS), and other
/// format-class characters. Mirrors the byte classes tirith already flags
/// in command input — re-emitting them via the origin label would be
/// self-defeating.
///
/// **C1 controls (U+0080..U+009F)** are included because the C0 control
/// drop in [`sanitize_caller_label`] catches `< 0x20` only — a hostile
/// caller could otherwise route an ANSI control sequence introducer
/// (U+009B = CSI) or operating-system-command introducer (U+009D = OSC)
/// past sanitization and into the operator's terminal at
/// `tirith agent explain` time.
fn is_invisible_or_format(ch: char) -> bool {
    matches!(
        ch as u32,
        // C1 controls (U+0080..U+009F) — includes CSI (0x9B), OSC (0x9D),
        // DCS (0x90), APC (0x9F), and the rest of the C1 family. Not
        // covered by the C0 (`< 0x20`) check in `sanitize_caller_label`.
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
        // ANSI escape + newline + NUL — all must be replaced with `?` and
        // the result must NOT contain a literal CR/LF/ESC/NUL byte that could
        // splice into a JSONL audit line.
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
        // Bidi RLO + zero-width joiner + Unicode tag — all must NOT survive
        // (they're exactly the classes the byte-scan rules flag in commands).
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
        // C1 controls (U+0080..U+009F) include CSI (U+009B), OSC (U+009D),
        // DCS (U+0090), APC (U+009F) — these are *not* `< 0x20` so the C0
        // drop in sanitize_caller_label doesn't catch them. They have to
        // be filtered via is_invisible_or_format, otherwise a hostile
        // caller could ship an 8-bit CSI past sanitization and into the
        // operator's terminal at `tirith agent explain` time. This is the
        // ingest-side belt-and-braces; the human-output path also uses
        // `{:?}` (Finding G part 1).
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
        // 4-byte UTF-8 char ('🦀' = U+1F980, 4 bytes in UTF-8) repeated past
        // the cap. We must never slice mid-codepoint.
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
        // Pure-control input sanitizes to "???" — non-empty, so we keep it.
        // (We don't want a hostile env to slip through as "human" silently.)
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

    // --- env-driven resolver ---
    // These hold the global env lock because they mutate process env.

    #[test]
    fn resolve_cli_origin_prefers_tirith_integration() {
        let _g = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Pin the env to a known shape: TIRITH_INTEGRATION wins over CI signals.
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

        // A million-byte hostile value with embedded control bytes must
        // (a) not crash, (b) not produce a multi-line audit-poisoning label,
        // (c) cap at MAX_LABEL_LEN.
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
