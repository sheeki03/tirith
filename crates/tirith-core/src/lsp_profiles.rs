//! M14 (IDE Extensions) — per-file-type LSP analysis profiles.
//!
//! The LSP server analyzes a buffer through [`crate::engine::analyze`] in a
//! chosen [`ScanContext`], then POST-FILTERS the findings to the diagnostics
//! that fit the file type. There is no engine-side rule toggle; this module
//! describes, per file type:
//!   1. [`contexts_for`] — the ordered [`ScanContext`]s to analyze in (selects
//!      WHICH rule families run). Most profiles use one ([`scan_context_for`] is
//!      the one-context accessor); [`LspProfile::AiConfig`] uses TWO because its
//!      signal families live in different branches of `engine::analyze`. The
//!      server runs `analyze` per context and UNIONs the findings.
//!   2. [`retains`] — the per-profile [`RuleId`] allow-set kept in diagnostics.
//!
//! No new [`RuleId`] for M14 — every id below is a shipping variant.
//!
//! Routing precedence ([`profile_for_path`]), filename then extension:
//!   1. AI-config — wins over all, so `CLAUDE.md` and `.claude/`/`.cursor/rules/`
//!      files route here (via [`crate::rules::aifile::is_ai_config_file`]),
//!      regardless of extension.
//!   2. Markdown install doc — a curated filename set, NOT every `.md`.
//!   3. Source code — a curated extension set.
//!   4. Log file — the `.log` extension.
//!   5. else `None` — no diagnostics for an unrecognised type.

use std::path::Path;

// `ScanContext` lives in `crate::extract`; this is its canonical public path and
// the type the engine's `analyze` / `build_dsl_backing` signatures take.
use crate::extract::ScanContext;
use crate::verdict::RuleId;

/// The per-file-type LSP analysis profile. Each maps to a [`ScanContext`]
/// ([`scan_context_for`]) and a [`RuleId`] allow-set ([`retains`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LspProfile {
    /// Agent-instruction surface (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`,
    /// `.claude/*`, MCP configs, …). Surfaces static hidden-instruction /
    /// invisible-unicode config rules.
    AiConfig,
    /// Install docs (`README.md`, `INSTALL.md`, …) whose fenced blocks carry
    /// `curl | sh` lines. Surfaces URL/transport/hostname + command-shape rules.
    MarkdownInstallDoc,
    /// A source file. Surfaces confusable/bidi/zero-width terminal rules plus
    /// credential leaks.
    SourceCode,
    /// A `.log` (captured command output). Analyzed via the M7 OUTPUT FIREWALL
    /// ([`crate::engine::analyze_output`]) so the `output_*` rules fire; the
    /// server signals this via [`uses_output_analysis`], and [`contexts_for`] /
    /// [`scan_context_for`] are not consulted. See [`retains`].
    LogFile,
}

/// Curated install-doc markdown basenames (lowercased). NOT every `.md`: only
/// files that conventionally hold copy-paste install instructions route here.
const INSTALL_DOC_BASENAMES: &[&str] = &[
    "readme.md",
    "install.md",
    "installation.md",
    "installing.md",
    "getting-started.md",
    "getting_started.md",
];

/// Curated source-code extensions (lowercased, no dot). Analyzed for
/// invisible-unicode / confusable trojan-source and hard-coded credentials.
/// Finite (no "looks like code" heuristic) for predictable routing; shell
/// extensions included since a homoglyph/credential in a `*.sh` is the same threat.
const SOURCE_EXTENSIONS: &[&str] = &[
    "rs", "py", "ts", "tsx", "js", "jsx", "mjs", "cjs", "go", "rb", "java", "kt", "c", "cc", "cpp",
    "cxx", "h", "hpp", "hh", "cs", "php", "swift", "scala", "sh", "bash", "zsh", "fish", "ps1",
];

/// Route a path to its LSP analysis profile, or `None` when not analyzed.
/// Precedence (module doc): AI-config > markdown-install-doc > extension-based
/// source/log. `CLAUDE.md` is therefore `AiConfig`, not `MarkdownInstallDoc`.
pub fn profile_for_path(path: &Path) -> Option<LspProfile> {
    // 1. AI-config wins. The canonical detector is directory- and basename-aware,
    //    so `CLAUDE.md` (also Markdown) routes here, not to install-doc.
    if crate::rules::aifile::is_ai_config_file(path) {
        return Some(LspProfile::AiConfig);
    }

    let basename_lower = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_ascii_lowercase());

    // 2. Markdown install docs — curated basename set (NOT every `.md`).
    if let Some(ref name) = basename_lower {
        if INSTALL_DOC_BASENAMES.contains(&name.as_str()) {
            return Some(LspProfile::MarkdownInstallDoc);
        }
    }

    // 3/4. Extension-based routing — source code, then log files.
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_ascii_lowercase();
        if SOURCE_EXTENSIONS.contains(&ext_lower.as_str()) {
            return Some(LspProfile::SourceCode);
        }
        // `.log` only — a rotated `*.log.1` keeps `.log.1`, so it doesn't match (narrow).
        if ext_lower == "log" {
            return Some(LspProfile::LogFile);
        }
    }

    // 5. Safe default: no diagnostics for an unrecognised type.
    None
}

/// The [`ScanContext`] to analyze a buffer in, chosen so the profile's rule
/// families actually fire on the [`crate::engine::analyze`] hot path:
///
/// * [`LspProfile::AiConfig`] → [`ScanContext::FileScan`] (PRIMARY; see
///   [`contexts_for`] for the second context). The static AI-config rules
///   (`AgentInstructionHidden`, `ConfigInvisibleUnicode`/`ConfigNonAscii`, the
///   terminal byte-scan family) run ONLY in `FileScan`; Exec/Paste never invoke
///   those file scanners. (Drift rules are diff-triggered, so can't fire on one
///   buffer — see [`retains`].) But a suspicious URL in a `CLAUDE.md` body fires
///   nothing in `FileScan`, so this profile also analyzes in Paste ([`contexts_for`]).
///
/// * [`LspProfile::MarkdownInstallDoc`] → [`ScanContext::Paste`]. URL/transport/
///   hostname and command-shape rules run only in Exec/Paste, not `FileScan`.
///   Paste over Exec because a README is pasted-like prose: Exec strips a
///   `# tirith-card:` prelude and runs hot-path guards meaningless for docs,
///   while Paste's tier-1 regex is a superset of Exec's (nothing gated out).
///
/// * [`LspProfile::SourceCode`] → [`ScanContext::Paste`]. Paste runs
///   `terminal::check_bytes` over the full byte buffer (every terminal rule),
///   while Exec filters to the invisible-char subset; `credential::check` fires
///   in both.
///
/// * [`LspProfile::LogFile`] → [`ScanContext::Paste`], but a `.log` does NOT take
///   the per-context path — it routes through the M7 OUTPUT FIREWALL
///   ([`crate::engine::analyze_output`]) where the `output_*` rules live (via
///   [`uses_output_analysis`]). This value is only a harmless default for the
///   one-context accessor; see [`retains`].
pub fn scan_context_for(profile: LspProfile) -> ScanContext {
    // First element of `contexts_for` — single source of truth so the
    // one-context accessor can't drift from the multi-context list.
    contexts_for(profile)[0]
}

/// The ordered [`ScanContext`]s to analyze a buffer in. The server runs
/// [`crate::engine::analyze`] once per context, UNIONs the findings, applies
/// [`retains`].
///
/// Every profile except [`LspProfile::AiConfig`] returns one context (= what
/// [`scan_context_for`] yields). `AiConfig` returns TWO: [`ScanContext::FileScan`]
/// (the static config / hidden-instruction scanners run only here) and
/// [`ScanContext::Paste`] (URL/transport/hostname + command-shape rules run only
/// in Exec/Paste). Both are needed and verified empirically: a suspicious URL in
/// a `CLAUDE.md` produces zero findings under FileScan alone, and a hidden-comment
/// directive zero under Paste alone. Paste over Exec for the same reasons as the
/// other Paste profiles ([`scan_context_for`]). The [`retains`] post-filter drops
/// the incidental Paste-only noise.
pub fn contexts_for(profile: LspProfile) -> &'static [ScanContext] {
    match profile {
        // BOTH branches — the only multi-context profile (see fn doc).
        LspProfile::AiConfig => &[ScanContext::FileScan, ScanContext::Paste],
        LspProfile::MarkdownInstallDoc => &[ScanContext::Paste],
        LspProfile::SourceCode => &[ScanContext::Paste],
        // LogFile does NOT take this path (see `uses_output_analysis`); an unused
        // harmless default so the one-context accessor stays total.
        LspProfile::LogFile => &[ScanContext::Paste],
    }
}

/// Whether to analyze this profile via the M7 OUTPUT FIREWALL
/// ([`crate::engine::analyze_output`]) instead of the [`contexts_for`] +
/// [`crate::engine::analyze`] path.
///
/// `true` ONLY for [`LspProfile::LogFile`]: a `.log` is captured output, and the
/// `output_*` rules fire only from `analyze_output`. The paths are mutually
/// exclusive (`true` → run `analyze_output` once, ignore [`contexts_for`]); both
/// apply the same [`retains`] allow-set.
pub fn uses_output_analysis(profile: LspProfile) -> bool {
    matches!(profile, LspProfile::LogFile)
}

/// Whether `rule_id` is RETAINED in diagnostics for a profile — the post-filter
/// over `verdict.findings`. Each list is curated (not "everything the context can
/// fire"); every id is a real shipping [`RuleId`], so this compile-checks the sets.
pub fn retains(profile: LspProfile, rule_id: RuleId) -> bool {
    match profile {
        // AI-config: the static hidden-instruction / invisible-content rules from
        // `FileScan`, PLUS the suspicious-URL families from the Paste half (see
        // `contexts_for`). The allow-set drops the incidental Paste-only noise.
        LspProfile::AiConfig => matches!(
            rule_id,
            // Hidden directive in an agent-instruction file. Primary AI-config signal.
            RuleId::AgentInstructionHidden
            // Config-file invisible / non-ASCII smuggling.
            | RuleId::ConfigInvisibleUnicode
            | RuleId::ConfigNonAscii
            // Visible prompt-injection / suspicious indicators.
            | RuleId::ConfigInjection
            | RuleId::ConfigSuspiciousIndicator
            // Terminal byte-scan invisible/deception family (FileScan branch).
            | RuleId::BidiControls
            | RuleId::ZeroWidthChars
            | RuleId::UnicodeTags
            | RuleId::InvisibleMathOperator
            | RuleId::VariationSelector
            | RuleId::InvisibleWhitespace
            | RuleId::HangulFiller
            | RuleId::ConfusableText
            // Suspicious URL in the config body — an agent reading a poisoned
            // `CLAUDE.md` may FETCH it. Fire only in Paste (`contexts_for`);
            // identical family to `MarkdownInstallDoc`'s allow-set.
            | RuleId::PipeToInterpreter
            | RuleId::CurlPipeShell
            | RuleId::WgetPipeShell
            | RuleId::HttpiePipeShell
            | RuleId::XhPipeShell
            | RuleId::PlainHttpToSink
            | RuleId::SchemelessToSink
            | RuleId::InsecureTlsFlags
            | RuleId::ShortenedUrl
            | RuleId::NonAsciiHostname
            | RuleId::PunycodeDomain
            | RuleId::MixedScriptInLabel
            | RuleId::UserinfoTrick
            | RuleId::ConfusableDomain
            | RuleId::RawIpUrl
            | RuleId::LookalikeTld
            // AI-config DRIFT rules — only via `tirith ai diff`, not a single
            // buffer (see fn doc). Listed so a diff-aware LSP keeps them.
            | RuleId::AiConfigHiddenInstructionAdded
            | RuleId::AiConfigToolUseEscalation
        ),

        // Markdown install docs: URL/transport + command-shape rules on the
        // fenced install commands.
        LspProfile::MarkdownInstallDoc => matches!(
            rule_id,
            // Command-shape: pipe-to-shell (`curl … | sh`).
            RuleId::PipeToInterpreter
            | RuleId::CurlPipeShell
            | RuleId::WgetPipeShell
            | RuleId::HttpiePipeShell
            | RuleId::XhPipeShell
            // Transport: plain HTTP / insecure TLS / shortened URLs.
            | RuleId::PlainHttpToSink
            | RuleId::SchemelessToSink
            | RuleId::InsecureTlsFlags
            | RuleId::ShortenedUrl
            // Hostname: homograph/punycode/mixed-script/confusable/userinfo/raw-IP.
            | RuleId::NonAsciiHostname
            | RuleId::PunycodeDomain
            | RuleId::MixedScriptInLabel
            | RuleId::UserinfoTrick
            | RuleId::ConfusableDomain
            | RuleId::RawIpUrl
            | RuleId::LookalikeTld
        ),

        // Source code: confusable/bidi/zero-width (trojan-source) + credentials.
        LspProfile::SourceCode => matches!(
            rule_id,
            // Trojan-source / homoglyph terminal family.
            RuleId::ConfusableText
            | RuleId::BidiControls
            | RuleId::ZeroWidthChars
            | RuleId::UnicodeTags
            | RuleId::InvisibleMathOperator
            | RuleId::VariationSelector
            | RuleId::InvisibleWhitespace
            | RuleId::HangulFiller
            // Hard-coded secrets.
            | RuleId::CredentialInText
            | RuleId::HighEntropySecret
            | RuleId::PrivateKeyExposed
        ),

        // Log files: M7 output-direction rules, which fire only via
        // `engine::analyze_output` (the output firewall, `uses_output_analysis`
        // is `true`) — the correct analyzer for captured command output.
        LspProfile::LogFile => matches!(
            rule_id,
            RuleId::OutputOsc52ClipboardWrite
                | RuleId::OutputHiddenText
                | RuleId::OutputFakePrompt
                | RuleId::OutputTerminalHyperlinkMismatch
                | RuleId::OutputTitleManipulation
                | RuleId::OutputClearScreen
                | RuleId::OutputTruncatedEscapeSequence
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn profile_for_path_routes_ai_config() {
        assert_eq!(
            profile_for_path(Path::new("CLAUDE.md")),
            Some(LspProfile::AiConfig)
        );
        assert_eq!(
            profile_for_path(Path::new("AGENTS.md")),
            Some(LspProfile::AiConfig)
        );
        assert_eq!(
            profile_for_path(Path::new(".cursorrules")),
            Some(LspProfile::AiConfig)
        );
        // Directory-aware: `.cursor/rules/*` is AI-config regardless of extension.
        assert_eq!(
            profile_for_path(Path::new(".cursor/rules/style.md")),
            Some(LspProfile::AiConfig)
        );
        assert_eq!(
            profile_for_path(Path::new("repo/.claude/commands/foo.md")),
            Some(LspProfile::AiConfig)
        );
    }

    #[test]
    fn ai_config_wins_over_markdown_install_doc() {
        // `CLAUDE.md` is both AI-config and Markdown; AI-config wins.
        assert_eq!(
            profile_for_path(Path::new("CLAUDE.md")),
            Some(LspProfile::AiConfig)
        );
    }

    #[test]
    fn profile_for_path_routes_markdown_install_doc() {
        assert_eq!(
            profile_for_path(Path::new("README.md")),
            Some(LspProfile::MarkdownInstallDoc)
        );
        assert_eq!(
            profile_for_path(Path::new("INSTALL.md")),
            Some(LspProfile::MarkdownInstallDoc)
        );
        assert_eq!(
            profile_for_path(Path::new("docs/install.md")),
            Some(LspProfile::MarkdownInstallDoc)
        );
        assert_eq!(
            profile_for_path(Path::new("docs/installation.md")),
            Some(LspProfile::MarkdownInstallDoc)
        );
        // A non-install `.md` is NOT routed.
        assert_eq!(profile_for_path(Path::new("CHANGELOG.md")), None);
        assert_eq!(profile_for_path(Path::new("docs/architecture.md")), None);
    }

    #[test]
    fn profile_for_path_routes_source_code() {
        for name in ["foo.rs", "main.py", "app.ts", "lib.go", "x.sh", "h.hpp"] {
            assert_eq!(
                profile_for_path(Path::new(name)),
                Some(LspProfile::SourceCode),
                "{name} should route to SourceCode"
            );
        }
    }

    #[test]
    fn profile_for_path_routes_log_file() {
        assert_eq!(
            profile_for_path(Path::new("server.log")),
            Some(LspProfile::LogFile)
        );
        assert_eq!(
            profile_for_path(Path::new("var/log/app.log")),
            Some(LspProfile::LogFile)
        );
        // Rotated `*.log.1` keeps `.1` → not matched (narrow).
        assert_eq!(profile_for_path(Path::new("app.log.1")), None);
    }

    #[test]
    fn profile_for_path_unknown_is_none() {
        assert_eq!(profile_for_path(Path::new("random.txt")), None);
        assert_eq!(profile_for_path(Path::new("data.json")), None);
        assert_eq!(profile_for_path(Path::new("image.png")), None);
        assert_eq!(profile_for_path(Path::new("noext")), None);
    }

    #[test]
    fn scan_context_for_returns_documented_context() {
        // The accessor returns each profile's PRIMARY context.
        assert_eq!(
            scan_context_for(LspProfile::AiConfig),
            ScanContext::FileScan
        );
        assert_eq!(
            scan_context_for(LspProfile::MarkdownInstallDoc),
            ScanContext::Paste
        );
        assert_eq!(scan_context_for(LspProfile::SourceCode), ScanContext::Paste);
        assert_eq!(scan_context_for(LspProfile::LogFile), ScanContext::Paste);
    }

    #[test]
    fn contexts_for_ai_config_is_filescan_then_paste() {
        // AiConfig is the only multi-context profile: FileScan THEN Paste. Order
        // is load-bearing (`scan_context_for` returns element 0).
        assert_eq!(
            contexts_for(LspProfile::AiConfig),
            &[ScanContext::FileScan, ScanContext::Paste]
        );
        // The primary accessor must agree with element 0.
        assert_eq!(
            scan_context_for(LspProfile::AiConfig),
            contexts_for(LspProfile::AiConfig)[0]
        );
    }

    #[test]
    fn contexts_for_single_context_profiles() {
        // Every non-AiConfig profile analyzes in exactly one context.
        for p in [
            LspProfile::MarkdownInstallDoc,
            LspProfile::SourceCode,
            LspProfile::LogFile,
        ] {
            assert_eq!(
                contexts_for(p),
                &[ScanContext::Paste],
                "{p:?} should be single-context Paste"
            );
            assert_eq!(scan_context_for(p), contexts_for(p)[0]);
        }
    }

    #[test]
    fn retains_ai_config_in_profile() {
        assert!(retains(
            LspProfile::AiConfig,
            RuleId::AgentInstructionHidden
        ));
        assert!(retains(
            LspProfile::AiConfig,
            RuleId::ConfigInvisibleUnicode
        ));
        assert!(retains(LspProfile::AiConfig, RuleId::BidiControls));
        // Suspicious-URL / command-shape rules ARE retained (the Paste half).
        assert!(retains(LspProfile::AiConfig, RuleId::CurlPipeShell));
        assert!(retains(LspProfile::AiConfig, RuleId::PunycodeDomain));
        assert!(retains(LspProfile::AiConfig, RuleId::PlainHttpToSink));
        // Credential rules are NOT AI-config diagnostics (source-code only).
        assert!(!retains(LspProfile::AiConfig, RuleId::HighEntropySecret));
        assert!(!retains(LspProfile::AiConfig, RuleId::CredentialInText));
    }

    #[test]
    fn retains_markdown_install_doc_in_profile() {
        assert!(retains(
            LspProfile::MarkdownInstallDoc,
            RuleId::PipeToInterpreter
        ));
        assert!(retains(
            LspProfile::MarkdownInstallDoc,
            RuleId::CurlPipeShell
        ));
        assert!(retains(
            LspProfile::MarkdownInstallDoc,
            RuleId::PlainHttpToSink
        ));
        assert!(retains(
            LspProfile::MarkdownInstallDoc,
            RuleId::ConfusableDomain
        ));
        // A credential rule is not an install-doc diagnostic.
        assert!(!retains(
            LspProfile::MarkdownInstallDoc,
            RuleId::HighEntropySecret
        ));
    }

    #[test]
    fn retains_source_code_in_profile() {
        assert!(retains(LspProfile::SourceCode, RuleId::ConfusableText));
        assert!(retains(LspProfile::SourceCode, RuleId::BidiControls));
        assert!(retains(LspProfile::SourceCode, RuleId::CredentialInText));
        assert!(retains(LspProfile::SourceCode, RuleId::PrivateKeyExposed));
        // A command-shape rule must NOT be retained for source code.
        assert!(!retains(LspProfile::SourceCode, RuleId::CurlPipeShell));
        assert!(!retains(LspProfile::SourceCode, RuleId::PipeToInterpreter));
    }

    #[test]
    fn retains_log_file_in_profile() {
        assert!(retains(
            LspProfile::LogFile,
            RuleId::OutputOsc52ClipboardWrite
        ));
        assert!(retains(LspProfile::LogFile, RuleId::OutputHiddenText));
        assert!(retains(LspProfile::LogFile, RuleId::OutputFakePrompt));
        // An unrelated rule is not a log diagnostic.
        assert!(!retains(LspProfile::LogFile, RuleId::CredentialInText));
    }

    #[test]
    fn uses_output_analysis_is_logfile_only() {
        // LogFile is the only profile via the output firewall; others take the
        // per-context `analyze` path.
        assert!(uses_output_analysis(LspProfile::LogFile));
        for p in [
            LspProfile::AiConfig,
            LspProfile::MarkdownInstallDoc,
            LspProfile::SourceCode,
        ] {
            assert!(
                !uses_output_analysis(p),
                "{p:?} must NOT use output analysis (takes the analyze path)"
            );
        }
    }
}
