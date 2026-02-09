/// Server-side cloaking detection — Unix only.
///
/// Fetches a URL with multiple user-agents and compares responses to detect
/// content differentiation (serving different content to AI bots vs browsers).
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

/// Check a URL for server-side cloaking.
#[cfg(unix)]
pub fn check(url: &str) -> Result<CloakingResult, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    const MAX_BODY: usize = 10 * 1024 * 1024; // 10 MiB

    // Fetch with each user-agent
    let mut responses: Vec<(String, u16, String)> = Vec::new();

    for (name, ua) in USER_AGENTS {
        match fetch_with_ua(&client, url, ua, MAX_BODY) {
            Ok((status, body)) => {
                responses.push((name.to_string(), status, body));
            }
            Err(e) => {
                eprintln!("tirith: cloaking: {name} fetch failed: {e}");
                responses.push((name.to_string(), 0, String::new()));
            }
        }
    }

    // Use chrome as baseline
    let baseline_idx = 0; // chrome is first
    let baseline_body = &responses[baseline_idx].2;
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

    // Compare each non-baseline response against chrome baseline
    for (i, (name, _status, body)) in responses.iter().enumerate() {
        if i == baseline_idx {
            continue;
        }
        if body.is_empty() {
            continue; // Skip failed fetches
        }

        let normalized = normalize_html(body);
        let diff_chars = word_diff_size(&baseline_normalized, &normalized);

        if diff_chars > 10 {
            cloaking_detected = true;
            // Generate diff text showing what words differ
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
) -> Result<(u16, String), String> {
    let response = client
        .get(url)
        .header("User-Agent", ua)
        .send()
        .map_err(|e| format!("request failed: {e}"))?;

    let status = response.status().as_u16();

    // Check content length hint
    if let Some(len) = response.content_length() {
        if len > max_body as u64 {
            return Err(format!("response too large: {len} bytes"));
        }
    }

    let bytes = response.bytes().map_err(|e| format!("read body: {e}"))?;
    if bytes.len() > max_body {
        return Err(format!("response too large: {} bytes", bytes.len()));
    }

    let body = String::from_utf8_lossy(&bytes).into_owned();
    Ok((status, body))
}

/// Normalize HTML for comparison — strip volatile content that changes
/// between requests (scripts, styles, CSRF tokens, nonces, timestamps).
#[cfg(unix)]
fn normalize_html(input: &str) -> String {
    use once_cell::sync::Lazy;
    use regex::Regex;

    static SCRIPT: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?is)<script[^>]*>.*?</script>").unwrap());
    static STYLE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)<style[^>]*>.*?</style>").unwrap());
    static NONCE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)\bnonce="[^"]*""#).unwrap());
    static CSRF: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"(?i)csrf[_-]?token[^"]*"[^"]*""#).unwrap());
    static WHITESPACE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());

    let s = SCRIPT.replace_all(input, "");
    let s = STYLE.replace_all(&s, "");
    let s = NONCE.replace_all(&s, "");
    let s = CSRF.replace_all(&s, "");
    let s = WHITESPACE.replace_all(&s, " ");
    s.trim().to_string()
}

/// Generate a human-readable summary of word-level differences between two texts.
/// Shows words present in one response but not the other (capped at 500 chars).
#[cfg(unix)]
fn generate_diff_text(baseline: &str, other: &str) -> String {
    use std::collections::HashMap;

    fn word_counts(s: &str) -> HashMap<&str, usize> {
        let mut counts = HashMap::new();
        for word in s.split_whitespace() {
            *counts.entry(word).or_insert(0) += 1;
        }
        counts
    }

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

    // Char-safe truncation (avoid panic on multibyte boundary)
    if result.len() > 500 {
        let truncated: String = result.chars().take(497).collect();
        result = format!("{truncated}...");
    }
    result
}

/// Simple word-level diff size in characters.
///
/// Counts total characters in words that are in one string but not the other.
/// This is a rough measure — not a proper edit distance, but sufficient for
/// detecting meaningful content differences vs. cosmetic variations.
#[cfg(unix)]
fn word_diff_size(a: &str, b: &str) -> usize {
    use std::collections::HashMap;

    fn word_counts(s: &str) -> HashMap<&str, usize> {
        let mut counts = HashMap::new();
        for word in s.split_whitespace() {
            *counts.entry(word).or_insert(0) += 1;
        }
        counts
    }

    let counts_a = word_counts(a);
    let counts_b = word_counts(b);

    let mut diff = 0usize;

    // Words in A not in B (or fewer in B)
    for (word, &count_a) in &counts_a {
        let count_b = counts_b.get(word).copied().unwrap_or(0);
        if count_a > count_b {
            diff += word.len() * (count_a - count_b);
        }
    }

    // Words in B not in A (or fewer in A)
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
        let input = r#"<script nonce="abc123">alert(1)</script><p>Content</p>"#;
        let normalized = normalize_html(input);
        assert!(!normalized.contains("nonce"));
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
        // Small cosmetic difference (single word)
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
}
