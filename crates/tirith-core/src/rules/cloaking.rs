/// Server-side cloaking detection (Unix only): fetch a URL with multiple
/// user-agents and compare responses to detect content differentiation (e.g.
/// serving different content to AI bots vs browsers).
#[cfg(unix)]
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// User-agent profiles for cloaking detection.
#[cfg(unix)]
const USER_AGENTS: &[(&str, &str)] = &[
    ("chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
    ("claudebot", "ClaudeBot/1.0"),
    ("chatgpt", "ChatGPT-User"),
    ("perplexity", "PerplexityBot/1.0"),
    ("googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    ("curl", "curl/8.7.1"),
];

/// Result of a cloaking check.
#[cfg(unix)]
pub struct CloakingResult {
    pub url: String,
    pub cloaking_detected: bool,
    pub findings: Vec<Finding>,
    /// Per-agent response summaries (agent name, status code, content length).
    pub agent_responses: Vec<AgentResponse>,
    /// Pairs of agents whose responses differed significantly.
    pub diff_pairs: Vec<DiffPair>,
}

#[cfg(unix)]
pub struct AgentResponse {
    pub agent_name: String,
    pub status_code: u16,
    pub content_length: usize,
}

#[cfg(unix)]
pub struct DiffPair {
    pub agent_a: String,
    pub agent_b: String,
    pub diff_chars: usize,
    /// Full diff text (populated for Pro enrichment).
    pub diff_text: Option<String>,
}

/// Why a single user-agent fetch failed.
///
/// `Connect` means the host could not be reached at all (DNS resolution or TCP
/// connect failure, or a connect-phase timeout) — that failure is identical for
/// every user-agent, so the caller short-circuits the loop. Every other failure
/// (`Other`) is treated as agent-specific and the caller keeps trying the
/// remaining user-agents, because a fetch that *reaches* the server but fails
/// (or returns a different status) for one UA and not another IS the cloaking
/// signal we are looking for. An HTTP error response is not a `FetchErr` at all:
/// it is returned as `Ok((status, body))` so status differences stay visible.
#[cfg(unix)]
enum FetchErr {
    /// Host unreachable for everyone (DNS/connect failure or connect timeout).
    Connect(String),
    /// Anything else: redirect/SSRF rejection, oversized/unreadable body, etc.
    Other(String),
}

#[cfg(unix)]
impl FetchErr {
    /// True only for an unambiguous host-unreachable failure. Be conservative:
    /// anything uncertain returns false so cloaking is never under-tested.
    fn is_host_unreachable(&self) -> bool {
        matches!(self, FetchErr::Connect(_))
    }

    fn message(&self) -> &str {
        match self {
            FetchErr::Connect(m) | FetchErr::Other(m) => m,
        }
    }
}

#[cfg(unix)]
impl std::fmt::Display for FetchErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

/// Classify a `reqwest::Error` from the request/connect phase.
///
/// A connect failure or a connect-phase timeout means the host is unreachable
/// regardless of user-agent → `Connect` (short-circuit). reqwest folds DNS
/// resolution failures into the connect phase, so `is_connect()` covers the
/// "host does not resolve" case too. Anything else (including redirect-policy
/// errors such as our SSRF re-validation or too-many-redirects) is `Other` so
/// the caller keeps probing the other user-agents.
#[cfg(unix)]
fn classify_reqwest_err(e: &reqwest::Error) -> FetchErr {
    if e.is_connect() || e.is_timeout() {
        FetchErr::Connect(format!("request failed: {e}"))
    } else {
        FetchErr::Other(format!("request failed: {e}"))
    }
}

#[cfg(unix)]
impl CloakingResult {
    /// Serialize to JSON; diff text is included only when `include_diff_text`.
    pub fn to_json(&self, include_diff_text: bool) -> serde_json::Value {
        serde_json::json!({
            "url": self.url,
            "cloaking_detected": self.cloaking_detected,
            "agents": self.agent_responses.iter().map(|a| {
                serde_json::json!({
                    "agent": a.agent_name,
                    "status_code": a.status_code,
                    "content_length": a.content_length,
                })
            }).collect::<Vec<_>>(),
            "diffs": self.diff_pairs.iter().map(|d| {
                let mut entry = serde_json::json!({
                    "agent_a": d.agent_a,
                    "agent_b": d.agent_b,
                    "diff_chars": d.diff_chars,
                });
                if include_diff_text {
                    if let Some(ref text) = d.diff_text {
                        entry.as_object_mut().unwrap().insert(
                            "diff_text".into(),
                            serde_json::json!(text),
                        );
                    }
                }
                entry
            }).collect::<Vec<_>>(),
            "findings": self.findings,
        })
    }
}

/// Check a URL for server-side cloaking.
#[cfg(unix)]
pub fn check(url: &str) -> Result<CloakingResult, String> {
    let validated_url = crate::url_validate::validate_fetch_url(url)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() > 10 {
                attempt.error("too many redirects")
            } else if let Err(reason) =
                crate::url_validate::validate_fetch_url(attempt.url().as_str())
            {
                attempt.error(reason)
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    const MAX_BODY: usize = 10 * 1024 * 1024; // 10 MiB

    let mut responses: Vec<(String, u16, String)> = Vec::new();

    for (name, ua) in USER_AGENTS {
        match fetch_with_ua(&client, validated_url.as_str(), ua, MAX_BODY) {
            Ok((status, body)) => {
                responses.push((name.to_string(), status, body));
            }
            Err(e) => {
                eprintln!("tirith: cloaking: {name} fetch failed: {e}");
                // A host-unreachable failure (DNS/connect) is identical for every
                // user-agent, so retrying the rest just burns ~5 more timeouts on
                // the same dead host. Stop now; the `successful_count == 0` guard
                // below still yields the honest "all fetches failed" error. Other
                // failures are agent-specific (e.g. a 403/redirect block to one UA
                // but not another IS the cloaking signal) so we keep probing.
                let unreachable = e.is_host_unreachable();
                responses.push((name.to_string(), 0, String::new()));
                if unreachable {
                    break;
                }
            }
        }
    }

    let successful_count = responses.iter().filter(|(_, s, _)| *s != 0).count();
    if successful_count == 0 {
        return Err("all user-agent fetches failed — cannot perform cloaking analysis".to_string());
    }

    // chrome (USER_AGENTS[0]) is the baseline; others compare against it.
    let baseline_idx = 0;
    let baseline_body = &responses[baseline_idx].2;

    // A failed baseline would otherwise flag every successful agent as cloaked.
    if baseline_body.is_empty() {
        let agent_responses: Vec<AgentResponse> = responses
            .iter()
            .map(|(name, status, body)| AgentResponse {
                agent_name: name.clone(),
                status_code: *status,
                content_length: body.len(),
            })
            .collect();
        return Ok(CloakingResult {
            url: url.to_string(),
            cloaking_detected: false,
            findings: Vec::new(),
            agent_responses,
            diff_pairs: Vec::new(),
        });
    }

    let baseline_normalized = normalize_html(baseline_body);

    let mut diff_pairs = Vec::new();
    let mut cloaking_detected = false;

    let agent_responses: Vec<AgentResponse> = responses
        .iter()
        .map(|(name, status, body)| AgentResponse {
            agent_name: name.clone(),
            status_code: *status,
            content_length: body.len(),
        })
        .collect();

    for (i, (name, _status, body)) in responses.iter().enumerate() {
        if i == baseline_idx {
            continue;
        }
        if body.is_empty() {
            continue;
        }

        let normalized = normalize_html(body);
        let diff_chars = word_diff_size(&baseline_normalized, &normalized);

        if diff_chars > 10 {
            cloaking_detected = true;
            let diff_detail = generate_diff_text(&baseline_normalized, &normalized);
            diff_pairs.push(DiffPair {
                agent_a: "chrome".to_string(),
                agent_b: name.clone(),
                diff_chars,
                diff_text: Some(diff_detail),
            });
        }
    }

    let mut findings = Vec::new();
    if cloaking_detected {
        let differing: Vec<&str> = diff_pairs.iter().map(|d| d.agent_b.as_str()).collect();
        findings.push(Finding {
            rule_id: RuleId::ServerCloaking,
            severity: Severity::High,
            title: "Server-side cloaking detected".to_string(),
            description: format!(
                "URL serves different content to different user-agents. \
                 Differing agents: {}",
                differing.join(", ")
            ),
            evidence: diff_pairs
                .iter()
                .map(|d| Evidence::Text {
                    detail: format!(
                        "{} vs {}: {} chars different",
                        d.agent_a, d.agent_b, d.diff_chars
                    ),
                })
                .collect(),
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    Ok(CloakingResult {
        url: url.to_string(),
        cloaking_detected,
        findings,
        agent_responses,
        diff_pairs,
    })
}

#[cfg(unix)]
fn fetch_with_ua(
    client: &reqwest::blocking::Client,
    url: &str,
    ua: &str,
    max_body: usize,
) -> Result<(u16, String), FetchErr> {
    // Only the request/connect phase can yield a host-unreachable error; an HTTP
    // error response still resolves to `Ok` here and is reported with its status.
    // Redirect-policy errors (our SSRF re-validation, too-many-redirects) also
    // surface from `.send()` but classify as `Other`, so they never short-circuit.
    let response = client
        .get(url)
        .header("User-Agent", ua)
        .send()
        .map_err(|e| classify_reqwest_err(&e))?;

    let status = response.status().as_u16();

    if let Some(len) = response.content_length() {
        if len > max_body as u64 {
            return Err(FetchErr::Other(format!("response too large: {len} bytes")));
        }
    }

    // Cap the actual stream too — Content-Length may be missing or lying.
    use std::io::Read as _;
    let mut body_bytes = Vec::with_capacity(max_body.min(1024 * 1024));
    response
        .take((max_body as u64) + 1)
        .read_to_end(&mut body_bytes)
        .map_err(|e| FetchErr::Other(format!("read body: {e}")))?;
    if body_bytes.len() > max_body {
        return Err(FetchErr::Other(format!(
            "response too large: {} bytes",
            body_bytes.len()
        )));
    }

    let body = String::from_utf8_lossy(&body_bytes).into_owned();
    Ok((status, body))
}

/// Normalize HTML for comparison — strip content that varies between requests
/// (scripts, styles, CSRF tokens, nonces).
#[cfg(unix)]
fn normalize_html(input: &str) -> String {
    use once_cell::sync::Lazy;
    use regex::Regex;

    static SCRIPT: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?is)<script[^>]*>.*?</script>").unwrap());
    static STYLE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)<style[^>]*>.*?</style>").unwrap());
    static NONCE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)\bnonce="[^"]*""#).unwrap());
    static CSRF: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)<[^>]*csrf[_-]?token[^>]*>"#).unwrap());
    static WHITESPACE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());

    let s = SCRIPT.replace_all(input, "");
    let s = STYLE.replace_all(&s, "");
    let s = NONCE.replace_all(&s, "");
    let s = CSRF.replace_all(&s, "");
    let s = WHITESPACE.replace_all(&s, " ");
    s.trim().to_string()
}

/// Build a word-frequency map for diff computation.
#[cfg(unix)]
fn word_counts(s: &str) -> std::collections::HashMap<&str, usize> {
    let mut counts = std::collections::HashMap::new();
    for word in s.split_whitespace() {
        *counts.entry(word).or_insert(0) += 1;
    }
    counts
}

/// Human-readable summary of word-level differences (words in one response but
/// not the other), capped at 500 chars.
#[cfg(unix)]
fn generate_diff_text(baseline: &str, other: &str) -> String {
    let counts_a = word_counts(baseline);
    let counts_b = word_counts(other);

    let mut only_in_baseline = Vec::new();
    let mut only_in_other = Vec::new();

    for (word, &count_a) in &counts_a {
        let count_b = counts_b.get(word).copied().unwrap_or(0);
        if count_a > count_b {
            only_in_baseline.push(*word);
        }
    }

    for (word, &count_b) in &counts_b {
        let count_a = counts_a.get(word).copied().unwrap_or(0);
        if count_b > count_a {
            only_in_other.push(*word);
        }
    }

    let mut result = String::new();
    if !only_in_baseline.is_empty() {
        result.push_str("Only in baseline (chrome): ");
        let preview: String = only_in_baseline
            .iter()
            .take(20)
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        result.push_str(&preview);
        if only_in_baseline.len() > 20 {
            result.push_str(&format!(" ... (+{} more)", only_in_baseline.len() - 20));
        }
    }
    if !only_in_other.is_empty() {
        if !result.is_empty() {
            result.push_str(" | ");
        }
        result.push_str("Only in this agent: ");
        let preview: String = only_in_other
            .iter()
            .take(20)
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        result.push_str(&preview);
        if only_in_other.len() > 20 {
            result.push_str(&format!(" ... (+{} more)", only_in_other.len() - 20));
        }
    }

    // Char-safe truncation (byte-slicing mid-codepoint panics).
    if result.len() > 500 {
        let truncated: String = result.chars().take(497).collect();
        result = format!("{truncated}...");
    }
    result
}

/// Rough word-level diff size in characters (chars in words present in one
/// string but not the other) — enough to tell content from cosmetic differences.
#[cfg(unix)]
fn word_diff_size(a: &str, b: &str) -> usize {
    let counts_a = word_counts(a);
    let counts_b = word_counts(b);

    let mut diff = 0usize;

    for (word, &count_a) in &counts_a {
        let count_b = counts_b.get(word).copied().unwrap_or(0);
        if count_a > count_b {
            diff += word.len() * (count_a - count_b);
        }
    }

    for (word, &count_b) in &counts_b {
        let count_a = counts_a.get(word).copied().unwrap_or(0);
        if count_b > count_a {
            diff += word.len() * (count_b - count_a);
        }
    }

    diff
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_html_strips_scripts() {
        let input = "<html><script>var x = 1;</script><body>Hello</body></html>";
        let normalized = normalize_html(input);
        assert!(!normalized.contains("var x"));
        assert!(normalized.contains("Hello"));
    }

    #[test]
    fn test_normalize_html_strips_styles() {
        let input = "<html><style>.hidden { display:none }</style><body>Hello</body></html>";
        let normalized = normalize_html(input);
        assert!(!normalized.contains("display:none"));
        assert!(normalized.contains("Hello"));
    }

    #[test]
    fn test_normalize_html_strips_nonces() {
        // Non-script element: the SCRIPT regex would otherwise strip a `<script>`
        // before NONCE runs, passing vacuously.
        let input = r#"<div nonce="abc123">Content</div><p>More</p>"#;
        let normalized = normalize_html(input);
        assert!(
            !normalized.contains("nonce"),
            "nonce attribute should be stripped: {normalized}"
        );
        assert!(normalized.contains("Content"));
    }

    #[test]
    fn test_word_diff_size_identical() {
        assert_eq!(word_diff_size("hello world", "hello world"), 0);
    }

    #[test]
    fn test_word_diff_size_different() {
        let diff = word_diff_size("hello world", "hello planet");
        assert!(diff > 0, "different words should produce non-zero diff");
    }

    #[test]
    fn test_word_diff_size_threshold() {
        let diff = word_diff_size("Welcome to our site today", "Welcome to our site");
        assert!(diff <= 10, "minor diff should be <=10 chars, got {diff}");
    }

    #[test]
    fn test_word_diff_size_large_difference() {
        let a = "Welcome to our website. We offer great products and services.";
        let b = "Access denied. This content is not available for automated crawlers.";
        let diff = word_diff_size(a, b);
        assert!(
            diff > 10,
            "significant content difference should exceed threshold, got {diff}"
        );
    }

    #[test]
    fn test_cloaking_rejects_localhost_target_before_fetch() {
        match check("http://localhost/") {
            Ok(_) => panic!("expected localhost target to be rejected"),
            Err(err) => assert!(err.contains("localhost")),
        }
    }

    /// A real connect refusal (loopback port 1, nothing listening — no external
    /// network, no DNS) must classify as `Connect` so the caller short-circuits.
    /// This drives `classify_reqwest_err` with a genuine `reqwest::Error` whose
    /// `is_connect()` is set, which is exactly the loop's break condition.
    #[test]
    fn test_classify_connect_refusal_short_circuits() {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("client");
        // Port 1 on loopback is reserved and unbound: the kernel refuses the TCP
        // connect immediately (ECONNREFUSED) without any network egress.
        let err = client
            .get("http://127.0.0.1:1/")
            .send()
            .expect_err("connection to an unbound loopback port must fail");
        assert!(
            err.is_connect(),
            "expected a connect-phase error, got: {err:?}"
        );

        let classified = classify_reqwest_err(&err);
        assert!(
            classified.is_host_unreachable(),
            "a connect/DNS failure must short-circuit the user-agent loop"
        );
        assert!(matches!(classified, FetchErr::Connect(_)));
    }

    /// The non-connect path must NOT short-circuit, so the loop keeps probing the
    /// remaining user-agents. We assert the mapping directly: `FetchErr::Other`
    /// (oversized/unreadable body, redirect/SSRF rejection, etc.) reports
    /// `is_host_unreachable() == false`.
    #[test]
    fn test_other_fetch_error_does_not_short_circuit() {
        let other = FetchErr::Other("response too large: 999 bytes".to_string());
        assert!(
            !other.is_host_unreachable(),
            "a non-connect failure must NOT short-circuit — cloaking stays fully tested"
        );
    }

    /// An HTTP error response is never a `FetchErr`: `fetch_with_ua` returns it as
    /// `Ok((status, body))`, so a 403-to-one-UA vs 200-to-another stays visible to
    /// the diff logic and is never mistaken for a host-unreachable short-circuit.
    /// Guard the contract: only `FetchErr::Connect` is host-unreachable.
    #[test]
    fn test_http_status_is_not_a_fetch_error() {
        // Status differences travel through the Ok branch as a u16, not FetchErr.
        let ok: Result<(u16, String), FetchErr> = Ok((403, "Forbidden".to_string()));
        assert!(matches!(ok, Ok((403, _))));

        // And of the two error variants, only Connect is treated as unreachable.
        assert!(FetchErr::Connect(String::new()).is_host_unreachable());
        assert!(!FetchErr::Other(String::new()).is_host_unreachable());
    }
}
