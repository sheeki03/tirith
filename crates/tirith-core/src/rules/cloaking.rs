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

#[cfg(unix)]
type CloakingEffectAuthorizer = dyn Fn() -> Result<(), String> + Send + Sync;

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

/// A completed cloaking check together with the exact owned-boundary decision
/// that authorized its network transaction.
#[cfg(unix)]
pub struct AuthorizedCloakingResult {
    pub result: CloakingResult,
    pub assessment: crate::task_boundary::BoundaryAssessment,
}

/// A cloaking failure that retains any boundary assessment already reached.
/// Syntax failures occur before an assessment exists; policy denials and
/// post-authorization network failures retain it for structured output.
#[cfg(unix)]
#[derive(Debug)]
pub struct CloakingCheckError {
    message: String,
    assessment: Option<Box<crate::task_boundary::BoundaryAssessment>>,
}

#[cfg(unix)]
impl CloakingCheckError {
    pub fn assessment(&self) -> Option<&crate::task_boundary::BoundaryAssessment> {
        self.assessment.as_deref()
    }
}

#[cfg(unix)]
impl std::fmt::Display for CloakingCheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

#[cfg(unix)]
impl std::error::Error for CloakingCheckError {}

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
/// A connect failure means the host is unreachable regardless of user-agent →
/// `Connect` (short-circuit). reqwest folds DNS resolution failures into the
/// connect phase, so `is_connect()` covers the "host does not resolve" case too.
///
/// A TIMEOUT is deliberately NOT host-unreachable. A reachable but malicious
/// server can accept the connection and then stall the RESPONSE for one
/// user-agent past the client timeout (`is_timeout()` true, `is_connect()`
/// false); short-circuiting there would skip the remaining user-agents and miss
/// exactly the cloaking the detector exists to catch (Codex Security, PR #139).
/// So a timeout — like a redirect-policy error or an HTTP-level failure — is
/// `Other`, and the caller keeps probing the other user-agents.
#[cfg(unix)]
fn classify_reqwest_err(e: &reqwest::Error) -> FetchErr {
    if e.is_connect() {
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

/// Check a URL for server-side cloaking under the frozen operator task gate.
///
/// The boundary binding performs syntax-only URL validation. The typed permit
/// becomes a retained effect lease before `network` is invoked, so an enforcing
/// refusal cannot reach DNS resolution, client construction, or a socket. The
/// exact binding and its earliest expiry are then revalidated before each DNS
/// preflight, request dispatch, and redirect follow. The ordered [`USER_AGENTS`]
/// set is included in the operation binding and is therefore authorized as one
/// fixed multi-request probe transaction.
#[cfg(unix)]
pub fn check(
    url: &str,
    gate: &crate::web3_policy::TaskGatePolicy,
) -> Result<CloakingResult, String> {
    authorize_then_check(url, gate, check_network)
}

/// Check with an explicit audit sink. The callback runs exactly once for every
/// recordable assessment, after the policy decision and before target DNS on
/// allows, or after the refusal on denies. It never runs in Off mode.
#[cfg(unix)]
pub fn check_with_audit(
    url: &str,
    gate: &crate::web3_policy::TaskGatePolicy,
    audit: impl FnMut(&crate::task_boundary::BoundaryAssessment),
) -> Result<AuthorizedCloakingResult, CloakingCheckError> {
    authorize_then_check_with_audit(url, gate, check_network, audit)
        .map(|(result, assessment)| AuthorizedCloakingResult { result, assessment })
}

#[cfg(unix)]
fn authorize_then_check<T>(
    url: &str,
    gate: &crate::web3_policy::TaskGatePolicy,
    network: impl FnOnce(&str, std::sync::Arc<CloakingEffectAuthorizer>) -> Result<T, String>,
) -> Result<T, String> {
    authorize_then_check_with_audit(url, gate, network, |_| {})
        .map(|(result, _assessment)| result)
        .map_err(|error| error.to_string())
}

#[cfg(unix)]
fn authorize_then_check_with_audit<T>(
    url: &str,
    gate: &crate::web3_policy::TaskGatePolicy,
    network: impl FnOnce(&str, std::sync::Arc<CloakingEffectAuthorizer>) -> Result<T, String>,
    mut audit: impl FnMut(&crate::task_boundary::BoundaryAssessment),
) -> Result<(T, crate::task_boundary::BoundaryAssessment), CloakingCheckError> {
    let binding = crate::task_boundary::fetch_cloaking_operation_binding(url, USER_AGENTS)
        .map_err(|message| CloakingCheckError {
            message,
            assessment: None,
        })?;
    let operation = binding.operation();
    let pending = match crate::task_boundary::prepare_locally_derived_boundary_authorization::<
        crate::task_boundary::FetchCloakingBoundary,
    >(
        &operation,
        gate,
        &crate::task_analysis::TaskAnalysisContext::default(),
    ) {
        Ok(pending) => pending,
        Err(error) => {
            let assessment = error.assessment().cloned();
            if let Some(assessment) = assessment.as_ref().filter(|value| value.is_recordable()) {
                audit(assessment);
            }
            return Err(CloakingCheckError {
                message: format!("cloaking task authorization refused: {error}"),
                assessment: assessment.map(Box::new),
            });
        }
    };
    let assessment = pending.assessment().clone();
    let permit = match pending.consume_default_for_operation(&operation, chrono::Utc::now()) {
        Ok(permit) => permit,
        Err(error) => {
            if assessment.is_recordable() {
                audit(&assessment);
            }
            return Err(CloakingCheckError {
                message: format!("cloaking task authorization refused: {error}"),
                assessment: Some(Box::new(assessment)),
            });
        }
    };
    let lease = match permit.into_effect_lease_at(&operation, chrono::Utc::now()) {
        Ok(lease) => lease,
        Err(error) => {
            if assessment.is_recordable() {
                audit(&assessment);
            }
            return Err(CloakingCheckError {
                message: format!("cloaking task authorization refused: {error}"),
                assessment: Some(Box::new(assessment)),
            });
        }
    };
    drop(operation);
    let authorization: std::sync::Arc<CloakingEffectAuthorizer> = std::sync::Arc::new(move || {
        lease
            .authorize_effect_at(&binding.operation(), chrono::Utc::now())
            .map_err(|error| format!("cloaking task authorization refused: {error}"))
    });
    if assessment.is_recordable() {
        audit(&assessment);
    }
    let result = network(url, authorization).map_err(|message| CloakingCheckError {
        message,
        assessment: Some(Box::new(assessment.clone())),
    })?;
    Ok((result, assessment))
}

#[cfg(unix)]
fn check_network(
    url: &str,
    authorization: std::sync::Arc<CloakingEffectAuthorizer>,
) -> Result<CloakingResult, String> {
    let client = cloaking_client(
        crate::ssrf_guard::fetch_resolver(),
        std::sync::Arc::clone(&authorization),
    )?;

    const MAX_BODY: usize = 10 * 1024 * 1024; // 10 MiB

    let mut responses: Vec<(String, u16, String)> = Vec::new();

    for (name, ua) in USER_AGENTS {
        let validated_url = authorize_immediately_before(authorization.as_ref(), || {
            crate::url_validate::validate_fetch_url(url)
        })??;
        let fetch_result = authorize_immediately_before(authorization.as_ref(), || {
            fetch_with_ua(&client, validated_url.as_str(), ua, MAX_BODY)
        })?;
        match fetch_result {
            Ok((status, body)) => {
                responses.push((name.to_string(), status, body));
            }
            Err(e) => {
                // A redirect callback can be the point where the retained lease
                // expires. reqwest surfaces that refusal as a request error; do
                // not downgrade it to an agent-specific probe failure or allow
                // the loop to continue under an expired authorization.
                authorization()?;
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

    // The baseline (chrome) is the reference every other user-agent is diffed
    // against. If it never loaded (its fetch failed, or returned an empty body)
    // there is nothing to compare to, so the check could not actually run. This
    // is only reachable when the baseline UA specifically failed while some other
    // UA succeeded; an all-failed run already returned the `successful_count == 0`
    // error above. Report it as inconclusive (Err) rather than `cloaking_detected:
    // false`. Claiming "no cloaking" off an absent baseline is a false negative,
    // and a cloaking site that serves chrome an empty/blocked page is exactly the
    // case we must not silently pass.
    if baseline_body.is_empty() {
        return Err("baseline (chrome) fetch failed or returned an empty body, \
             cloaking analysis inconclusive (no reference to compare against)"
            .to_string());
    }

    let baseline_normalized = normalize_html(baseline_body);
    let baseline_scripts = normalize_active_content(baseline_body);
    let baseline_status = responses[baseline_idx].1;

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

    for (i, (name, status, body)) in responses.iter().enumerate() {
        if i == baseline_idx {
            continue;
        }
        // `0` is the sentinel this function pushes for a probe that never
        // produced a response, not an HTTP status. A transient timeout or
        // connect reset is not a server serving one agent something different,
        // so it must not read as a cloaking signal. The agent-specific blocks
        // this check targets — a 403 or a redirect served to one UA but not
        // another — arrive as real status codes and still compare below. The
        // failed probe stays visible in the per-agent evidence.
        if *status == 0 {
            continue;
        }
        // repo-0321: an agent-specific STATUS difference is itself a cloaking
        // signal (identical text at a different status code).
        if *status != baseline_status {
            cloaking_detected = true;
            diff_pairs.push(DiffPair {
                agent_a: "chrome".to_string(),
                agent_b: name.clone(),
                diff_chars: 0,
                diff_text: Some(format!(
                    "status differs: baseline {baseline_status} vs agent {status}"
                )),
            });
            continue;
        }
        // repo-0321: an EMPTY response to a selected agent (while the baseline
        // loaded) is cloaking, not a skip.
        if body.is_empty() {
            cloaking_detected = true;
            diff_pairs.push(DiffPair {
                agent_a: "chrome".to_string(),
                agent_b: name.clone(),
                diff_chars: baseline_body.len(),
                diff_text: Some("agent received an empty body; baseline did not".to_string()),
            });
            continue;
        }

        let normalized = normalize_html(body);
        let diff_chars = word_diff_size(&baseline_normalized, &normalized);
        // repo-0321: visible-text normalization strips <script>/<style>; an
        // agent-specific payload hiding only in active content must still
        // count, so compare the active-content channel too.
        let scripts = normalize_active_content(body);
        let script_diff = word_diff_size(&baseline_scripts, &scripts);

        if diff_chars > 10 || script_diff > 10 {
            cloaking_detected = true;
            let diff_detail = if diff_chars > 10 {
                generate_diff_text(&baseline_normalized, &normalized)
            } else {
                "agent-specific <script>/<style> content".to_string()
            };
            diff_pairs.push(DiffPair {
                agent_a: "chrome".to_string(),
                agent_b: name.clone(),
                diff_chars: diff_chars.max(script_diff),
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

/// Build the exact client used by cloaking probes. The guarded resolver closes
/// the gap between URL preflight DNS and the address selected for `connect()`.
#[cfg(unix)]
fn cloaking_client(
    resolver: std::sync::Arc<crate::ssrf_guard::SsrfGuardResolver>,
    authorization: std::sync::Arc<CloakingEffectAuthorizer>,
) -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .dns_resolver(resolver)
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() > 10 {
                attempt.error("too many redirects")
            } else if let Err(reason) = authorization() {
                attempt.error(reason)
            } else if let Err(reason) =
                crate::url_validate::validate_fetch_url(attempt.url().as_str())
            {
                attempt.error(reason)
            } else if let Err(reason) = authorization() {
                attempt.error(reason)
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))
}

#[cfg(unix)]
fn authorize_immediately_before<T>(
    authorization: &CloakingEffectAuthorizer,
    effect: impl FnOnce() -> T,
) -> Result<T, String> {
    authorization()?;
    Ok(effect())
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
/// repo-0321: normalize ONLY the active-content channel (`<script>`/`<style>`
/// bodies) so agent-specific JavaScript/CSS differences are comparable; the
/// visible-text normalization deliberately strips these.
fn normalize_active_content(input: &str) -> String {
    use once_cell::sync::Lazy;
    use regex::Regex;

    static SCRIPT_BODY: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?is)<script[^>]*>(.*?)</script>").unwrap());
    static STYLE_BODY: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?is)<style[^>]*>(.*?)</style>").unwrap());
    static NONCE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)\bnonce="[^"]*""#).unwrap());
    static WHITESPACE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());

    let mut parts: Vec<String> = Vec::new();
    for cap in SCRIPT_BODY.captures_iter(input) {
        parts.push(cap[1].to_string());
    }
    for cap in STYLE_BODY.captures_iter(input) {
        parts.push(cap[1].to_string());
    }
    let joined = parts.join(" ");
    let s = NONCE.replace_all(&joined, "");
    WHITESPACE.replace_all(&s, " ").trim().to_string()
}

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
    fn enforcing_network_denial_never_reaches_the_network_sink() {
        let calls = std::cell::Cell::new(0usize);
        let gate = crate::web3_policy::TaskGatePolicy {
            mode: crate::web3_policy::TaskGateMode::Enforce,
            effects_denied_for_untrusted_sources: [
                crate::effects::CommandEffectKind::NetworkEgress,
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let result = authorize_then_check("https://example.com", &gate, |_, _| {
            calls.set(calls.get() + 1);
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(calls.get(), 0, "a denied probe reached DNS/client setup");
    }

    #[test]
    fn off_and_observe_preserve_cloaking_probe_execution() {
        for mode in [
            crate::web3_policy::TaskGateMode::Off,
            crate::web3_policy::TaskGateMode::Observe,
        ] {
            let calls = std::cell::Cell::new(0usize);
            let gate = crate::web3_policy::TaskGatePolicy {
                mode,
                effects_denied_for_untrusted_sources: [
                    crate::effects::CommandEffectKind::NetworkEgress,
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            };
            authorize_then_check("https://example.com", &gate, |_, _| {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .unwrap();
            assert_eq!(calls.get(), 1, "{mode:?} changed fetch behavior");
        }
    }

    #[test]
    fn recordable_assessments_reach_the_explicit_audit_sink_once() {
        let calls = std::cell::Cell::new(0usize);
        let audits = std::cell::RefCell::new(Vec::new());
        let gate = crate::web3_policy::TaskGatePolicy {
            mode: crate::web3_policy::TaskGateMode::Observe,
            effects_denied_for_untrusted_sources: [
                crate::effects::CommandEffectKind::NetworkEgress,
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let (_result, assessment) = authorize_then_check_with_audit(
            "https://example.com",
            &gate,
            |_, _| {
                calls.set(calls.get() + 1);
                Ok(())
            },
            |assessment| audits.borrow_mut().push(assessment.projection()),
        )
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(audits.borrow().len(), 1);
        assert_eq!(audits.borrow()[0]["boundary"], "fetch_cloaking");
        assert_eq!(audits.borrow()[0]["mode"], "observe");
        assert!(assessment.is_recordable());
    }

    #[test]
    fn denied_assessment_is_audited_and_retained_without_network() {
        let calls = std::cell::Cell::new(0usize);
        let audits = std::cell::RefCell::new(Vec::new());
        let gate = crate::web3_policy::TaskGatePolicy {
            mode: crate::web3_policy::TaskGateMode::Enforce,
            effects_denied_for_untrusted_sources: [
                crate::effects::CommandEffectKind::NetworkEgress,
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };
        let error = authorize_then_check_with_audit(
            "https://example.com",
            &gate,
            |_, _| {
                calls.set(calls.get() + 1);
                Ok(())
            },
            |assessment| audits.borrow_mut().push(assessment.projection()),
        )
        .unwrap_err();
        assert_eq!(calls.get(), 0);
        assert_eq!(audits.borrow().len(), 1);
        assert_eq!(audits.borrow()[0]["outcome"], "deny");
        assert_eq!(
            error.assessment().unwrap().boundary,
            crate::task_boundary::OwnedBoundary::FetchCloaking
        );
    }

    #[test]
    fn effect_lease_expiry_after_dns_refuses_before_socket_dispatch() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let binding = crate::task_boundary::fetch_cloaking_operation_binding(
            "https://example.com",
            USER_AGENTS,
        )
        .unwrap();
        let operation = binding.operation();
        let deadline = chrono::DateTime::parse_from_rfc3339("2026-08-18T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let before_deadline = deadline - chrono::TimeDelta::milliseconds(1);
        let permit = crate::task_boundary::TaskBoundaryPermit::<
            crate::task_boundary::FetchCloakingBoundary,
        >::for_test_with_deadline(&operation, deadline);
        let lease = permit
            .into_effect_lease_at(&operation, before_deadline)
            .unwrap();
        drop(operation);

        let checks = std::sync::Arc::new(AtomicUsize::new(0));
        let authorization_checks = std::sync::Arc::clone(&checks);
        let expires_after_dns: std::sync::Arc<CloakingEffectAuthorizer> =
            std::sync::Arc::new(move || {
                let now = if authorization_checks.fetch_add(1, Ordering::SeqCst) == 0 {
                    before_deadline
                } else {
                    deadline
                };
                lease
                    .authorize_effect_at(&binding.operation(), now)
                    .map_err(|error| format!("cloaking task authorization refused: {error}"))
            });
        let dns_calls = std::cell::Cell::new(0usize);
        let socket_calls = std::cell::Cell::new(0usize);

        let dns = authorize_immediately_before(&*expires_after_dns, || {
            dns_calls.set(dns_calls.get() + 1);
        });
        let socket = authorize_immediately_before(&*expires_after_dns, || {
            socket_calls.set(socket_calls.get() + 1);
        });

        assert!(dns.is_ok());
        assert!(socket.is_err());
        assert_eq!(dns_calls.get(), 1, "authorized DNS preflight did not run");
        assert_eq!(
            socket_calls.get(),
            0,
            "expired lease reached socket dispatch"
        );
        assert_eq!(checks.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_cloaking_rejects_localhost_target_before_fetch() {
        // Serialize with the empty-baseline test below: that test sets
        // `TIRITH_PRIVATE_FETCH_ALLOW` process-wide, which (if it overlapped)
        // would relax the very localhost rejection this test asserts.
        let mut global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global cloaking state");
        global.remove_env("TIRITH_PRIVATE_FETCH_ALLOW");
        match check(
            "http://localhost/",
            &crate::web3_policy::TaskGatePolicy::default(),
        ) {
            Ok(_) => panic!("expected localhost target to be rejected"),
            Err(err) => assert!(
                matches!(
                    err.as_str(),
                    "refusing to connect to localhost destination"
                        | "refusing to connect to non-public address"
                ),
                "unexpected categorical localhost rejection: {err}"
            ),
        }
    }

    #[test]
    fn test_production_client_rejects_connect_time_private_rebind() {
        use std::error::Error as _;

        let url = "http://rebind.example.test/cloaking";
        let preflight =
            crate::url_validate::validate_fetch_url_with_resolver_for_test(url, &|host, _| {
                assert_eq!(host, "rebind.example.test");
                Ok(vec!["93.184.216.34".parse().unwrap()])
            });
        assert!(preflight.is_ok(), "the public preflight answer must pass");

        let resolver = crate::ssrf_guard::fetch_resolver_with_lookup_for_test(|host| {
            assert_eq!(host, "rebind.example.test");
            Ok(vec!["127.0.0.1:9".parse().unwrap()])
        });
        let client = cloaking_client(resolver, std::sync::Arc::new(|| Ok(())))
            .expect("build guarded cloaking client");
        let error = client
            .get(url)
            .send()
            .expect_err("connect-time private DNS answer must be refused");

        let mut messages = vec![error.to_string()];
        let mut source = error.source();
        while let Some(cause) = source {
            messages.push(cause.to_string());
            source = cause.source();
        }
        assert!(
            messages.iter().any(|message| {
                message.contains("ssrf_guard") && message.contains("non-public address")
            }),
            "failure must come from the guarded resolver, got: {messages:?}"
        );
    }

    /// A real connect refusal (loopback port 1, nothing listening — no external
    /// network, no DNS) must classify as `Connect` so the caller short-circuits.
    /// This drives `classify_reqwest_err` with a genuine `reqwest::Error` whose
    /// `is_connect()` is set, which is exactly the loop's break condition.
    #[test]
    fn test_classify_connect_refusal_short_circuits() {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
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

    /// A reachable server that ACCEPTS the connection but stalls the RESPONSE past
    /// the client timeout produces `is_timeout() == true` / `is_connect() == false`.
    /// That is NOT host-unreachable: short-circuiting there would skip the remaining
    /// user-agents and miss exactly the cloaking the detector exists to catch (Codex
    /// Security, PR #139). Assert it classifies as `Other` so the loop keeps probing.
    #[test]
    fn test_response_timeout_does_not_short_circuit() {
        use std::io::Read as _;
        use std::net::TcpListener;

        // Loopback listener that ACCEPTS the TCP connect (so this is NOT a connect
        // failure) but never writes a response, forcing a RESPONSE-phase timeout.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 64];
                let _ = sock.read(&mut buf);
                std::thread::sleep(std::time::Duration::from_millis(800));
            }
        });

        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_millis(200))
            .build()
            .expect("client");
        let err = client
            .get(format!("http://{addr}/"))
            .send()
            .expect_err("a stalled response must time out");
        assert!(
            err.is_timeout() && !err.is_connect(),
            "expected a response-phase timeout, not a connect failure, got: {err:?}"
        );

        let classified = classify_reqwest_err(&err);
        assert!(
            !classified.is_host_unreachable(),
            "a response timeout from a REACHABLE server must NOT short-circuit the \
             user-agent sweep (cloaking evasion guard)"
        );
        assert!(matches!(classified, FetchErr::Other(_)));

        let _ = handle.join();
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

    /// Snapshot an env var and restore it on `Drop`.
    /// When the BASELINE (chrome, USER_AGENTS[0]) returns an empty body but other
    /// user-agents succeed, there is no reference to diff against and the check
    /// could not actually run. It MUST come back inconclusive (`Err`), never
    /// `Ok { cloaking_detected: false }`. Claiming "no cloaking" off an absent
    /// baseline is the false negative this guards. A cloaking site that serves
    /// chrome an empty/blocked page while serving bots real content is exactly
    /// this case, so a silent "no cloaking" would be the worst possible answer.
    ///
    /// Driven end-to-end against a loopback server that returns an empty 200 to
    /// the chrome UA and real content to everyone else. `successful_count` is
    /// therefore > 0 (chrome's empty 200 still counts as a successful fetch), so
    /// the `successful_count == 0` guard does NOT fire and execution reaches the
    /// empty-baseline branch under test.
    #[test]
    fn test_empty_baseline_is_inconclusive_not_no_cloaking() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        // Loopback fetches are SSRF-blocked by default; the carve-out opt-in is
        // process-wide, so serialize with other env-sensitive cloaking tests.
        let mut global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global cloaking state");
        global.set_env("TIRITH_PRIVATE_FETCH_ALLOW", "127.0.0.1/32");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("addr");

        // Serve one connection per user-agent. Chrome (the baseline) gets an empty
        // 200; every other UA gets a non-empty body. `Connection: close` keeps each
        // request on its own connection so the accept loop stays deterministic.
        let n_agents = USER_AGENTS.len();
        let server = std::thread::spawn(move || {
            for _ in 0..n_agents {
                let (mut sock, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                // Read the request head; the User-Agent line tells us who is asking.
                let mut buf = [0u8; 2048];
                let n = sock.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let is_chrome = req
                    .lines()
                    .filter_map(|l| l.split_once(':'))
                    .any(|(k, v)| k.eq_ignore_ascii_case("user-agent") && v.contains("Chrome/"));

                let body = if is_chrome {
                    String::new()
                } else {
                    "<html><body>Real content served to this agent.</body></html>".to_string()
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes());
                let _ = sock.flush();
            }
        });

        let result = check(
            &format!("http://{addr}/"),
            &crate::web3_policy::TaskGatePolicy::default(),
        );
        let _ = server.join();

        // The contract: an empty baseline is inconclusive (Err), NOT a successful
        // `cloaking_detected: false`. Before the fix this returned exactly that
        // false-negative Ok value.
        match result {
            Ok(r) => panic!(
                "empty baseline must be inconclusive (Err), got Ok with \
                 cloaking_detected={}",
                r.cloaking_detected
            ),
            Err(msg) => assert!(
                msg.contains("baseline") && msg.contains("inconclusive"),
                "error should name the empty baseline as inconclusive, got: {msg}"
            ),
        }
    }
}
