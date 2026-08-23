use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use axum::extract::{Path, Query, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use tracing::error;

use crate::error::AppError;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct LookupQuery {
    pub checkout: String,
    /// `1` when the not-ready page polls via fetch (repo-0235): returns JSON
    /// instead of following a redirect into the human confirmation page.
    #[serde(default)]
    pub poll: Option<String>,
}

pub async fn receipt_lookup(
    State(state): State<AppState>,
    Query(query): Query<LookupQuery>,
) -> Result<Response, AppError> {
    if query.checkout.is_empty() {
        return Err(AppError::BadWebhook("missing checkout parameter".into()));
    }

    let secret = state.db.receipt_lookup(&query.checkout).await?;

    // repo-0235: the not-ready poller must not follow the redirect into HTML it
    // cannot interpret. Polling with `poll=1` returns the confirmation URL as
    // JSON; the script then navigates there at top level.
    if query.poll.as_deref() == Some("1") {
        let body = match &secret {
            Some(s) => format!(
                "{{\"status\":\"ready\",\"url\":\"/receipt/{}\"}}",
                html_escape(s)
            ),
            None => "{\"status\":\"pending\"}".to_string(),
        };
        return Ok((
            StatusCode::OK,
            [
                ("content-type", "application/json"),
                ("cache-control", "no-store"),
            ],
            body,
        )
            .into_response());
    }

    match secret {
        Some(s) => {
            let redirect_url = format!("/receipt/{s}");
            let mut response = Redirect::to(&redirect_url).into_response();
            set_no_store_headers(&mut response);
            Ok(response)
        }
        None => {
            // Redirect arrived before the webhook finished processing.
            // Serve a page that retries the redirect automatically.
            let html = receipt_not_ready_page(&query.checkout);
            Ok((
                StatusCode::OK,
                [
                    ("content-type", "text/html; charset=utf-8"),
                    ("cache-control", "no-store"),
                ],
                html,
            )
                .into_response())
        }
    }
}

/// Confirm that a one-time receipt is available without consuming it. Browsers,
/// mail clients, security scanners, and link-preview bots routinely issue GET or
/// HEAD requests automatically, so neither safe method may reveal credentials or
/// delete the row. Axum's `get` router also directs HEAD here.
pub async fn receipt_confirmation(
    method: Method,
    State(state): State<AppState>,
    Path(receipt_secret): Path<String>,
) -> Result<Response, AppError> {
    if !state.db.receipt_available(&receipt_secret).await? {
        return Ok(receipt_not_found_response());
    }

    // Return no representation for HEAD even when this handler is called
    // directly; axum also strips GET-handler bodies for implicit HEAD requests.
    let body = if method == Method::HEAD {
        String::new()
    } else {
        receipt_confirmation_page()
    };
    let mut response = (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        body,
    )
        .into_response();
    set_no_store_headers(&mut response);
    Ok(response)
}

/// Reveal and atomically consume a one-time receipt. This handler is mounted
/// only on POST; a second concurrent or repeated POST loses the atomic DELETE
/// race and receives the not-found response.
pub async fn receipt_consume(
    State(state): State<AppState>,
    Path(receipt_secret): Path<String>,
) -> Result<Response, AppError> {
    // repo-0237: peek first and decrypt/validate BEFORE the destructive
    // consume — a key-rotation mismatch or corrupt row must not delete the
    // only recoverable copy of the customer's API key.
    let Some(row) = state.db.receipt_peek(&receipt_secret).await? else {
        return Ok(receipt_not_found_response());
    };

    let cipher = Aes256Gcm::new_from_slice(&state.config.receipt_encryption_key).map_err(|e| {
        error!("AES-GCM key init failed: {e}");
        AppError::Internal("License delivery error. Contact support@tirith.dev".into())
    })?;

    if row.api_key_nonce.len() != 12 {
        error!(
            sub_id = %row.subscription_id,
            "invalid nonce length: {}",
            row.api_key_nonce.len()
        );
        return Err(AppError::Internal(
            "License delivery error. Contact support@tirith.dev".into(),
        ));
    }
    let nonce = Nonce::from_slice(&row.api_key_nonce);

    let api_key_bytes = cipher
        .decrypt(nonce, row.api_key_enc.as_ref())
        .map_err(|e| {
            error!(sub_id = %row.subscription_id, "AES-GCM decrypt failed: {e}");
            AppError::Internal(
                "License delivery error. Contact support@tirith.dev with your checkout reference."
                    .into(),
            )
        })?;

    let api_key = String::from_utf8(api_key_bytes).map_err(|_| {
        error!(sub_id = %row.subscription_id, "decrypted API key is not UTF-8");
        AppError::Internal("License delivery error. Contact support@tirith.dev".into())
    })?;

    // Everything validated — NOW consume atomically. If another request won
    // the race, the row is gone and we report it as already viewed.
    let Some(consumed) = state.db.receipt_consume(&receipt_secret).await? else {
        return Ok(receipt_not_found_response());
    };
    if consumed.subscription_id != row.subscription_id {
        return Ok(receipt_not_found_response());
    }

    let server_url = state
        .config
        .receipt_base_url
        .as_deref()
        .unwrap_or("http://localhost:8080");

    let html = match row.token {
        Some(token) => receipt_full_page(&token, &api_key, server_url),
        None => receipt_partial_page(&api_key, server_url),
    };

    let mut response = (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        html,
    )
        .into_response();
    set_no_store_headers(&mut response);
    Ok(response)
}

fn set_no_store_headers(response: &mut Response) {
    use axum::http::header::{CACHE_CONTROL, PRAGMA, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS};
    use axum::http::HeaderValue;

    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
}

fn receipt_not_found_response() -> Response {
    let mut response = (
        StatusCode::NOT_FOUND,
        "Receipt expired or already viewed".to_string(),
    )
        .into_response();
    set_no_store_headers(&mut response);
    response
}

fn receipt_confirmation_page() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Tirith — Reveal Your License</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 600px; margin: 60px auto; padding: 0 20px; color: #333; }
  .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 12px; border-radius: 6px; margin: 20px 0; }
  button { background: #333; color: #fff; border: none; padding: 10px 18px; border-radius: 4px; cursor: pointer; font-size: 15px; }
  button:hover { background: #555; }
</style>
</head>
<body>
<h1>Your Tirith License Is Ready</h1>
<div class="warning">
  Continue only when you are ready to save your credentials. Submitting this form reveals and consumes the one-time receipt.
</div>
<form method="post">
  <button type="submit">Reveal my license</button>
</form>
</body>
</html>"#
        .to_string()
}

fn receipt_not_ready_page(checkout_id: &str) -> String {
    let escaped_id = html_escape(checkout_id);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Tirith — Processing</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 600px; margin: 60px auto; padding: 0 20px; color: #333; }}
  .spinner {{ display: inline-block; width: 20px; height: 20px; border: 3px solid #ddd; border-top-color: #333; border-radius: 50%; animation: spin 1s linear infinite; }}
  @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
  .status {{ margin-top: 20px; color: #666; }}
</style>
<script>
  let retries = 0;
  const maxRetries = 30;
  const poll = setInterval(async () => {{
    retries++;
    const el = document.getElementById('count');
    if (el) el.textContent = retries;
    if (retries >= maxRetries) {{
      clearInterval(poll);
      document.getElementById('loading').style.display = 'none';
      document.getElementById('timeout').style.display = 'block';
      return;
    }}
    try {{
      // Poll the JSON endpoint: following the redirect with fetch() would return
      // the human confirmation HTML rather than a machine-readable status.
      const u = new URL(location.href);
      u.searchParams.set('poll', '1');
      const r = await fetch(u, {{ redirect: 'manual' }});
      if (r.ok) {{
        const body = await r.json();
        if (body.status === 'ready' && body.url) {{
          clearInterval(poll);
          location.href = body.url;
        }}
      }}
    }} catch(_) {{}}
  }}, 2000);
</script>
</head>
<body>
<h1>Processing Your License</h1>
<div id="loading">
  <p><span class="spinner"></span> Your license is being prepared...</p>
  <p class="status">This page will refresh automatically. Attempt <span id="count">1</span>/30</p>
</div>
<div id="timeout" style="display:none">
  <p>Your license is still being processed. Please try again in a few minutes.</p>
  <p>If the issue persists, contact <a href="mailto:support@tirith.dev">support@tirith.dev</a>
     with reference: <code>{escaped_id}</code></p>
</div>
</body>
</html>"#
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn receipt_full_page(token: &str, api_key: &str, server_url: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Tirith — Your License</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 700px; margin: 60px auto; padding: 0 20px; color: #333; }}
  pre {{ background: #f5f5f5; padding: 16px; border-radius: 6px; overflow-x: auto; position: relative; font-size: 13px; word-break: break-all; white-space: pre-wrap; }}
  .copy-btn {{ position: absolute; top: 8px; right: 8px; background: #333; color: #fff; border: none; padding: 4px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; }}
  .copy-btn:hover {{ background: #555; }}
  .warning {{ background: #fff3cd; border: 1px solid #ffc107; padding: 12px; border-radius: 6px; margin: 20px 0; }}
  code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 13px; }}
  h2 {{ margin-top: 32px; }}
</style>
<script>
function copyText(id) {{
  const el = document.getElementById(id);
  navigator.clipboard.writeText(el.textContent.trim()).then(() => {{
    const btn = el.parentElement.querySelector('.copy-btn');
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = 'Copy', 2000);
  }});
}}
</script>
</head>
<body>
<h1>Your Tirith License</h1>

<div class="warning">
  <strong>Save these now</strong> — this page can only be viewed once.
</div>

<h2>License Token</h2>
<pre><button class="copy-btn" onclick="copyText('token')">Copy</button><span id="token">{token}</span></pre>
<p>Activate with:</p>
<pre>tirith activate {token}</pre>

<h2>API Key</h2>
<pre><button class="copy-btn" onclick="copyText('apikey')">Copy</button><span id="apikey">{api_key}</span></pre>

<h2>Automatic Refresh Setup</h2>
<p>Add to your shell profile for automatic token renewal:</p>
<pre>export TIRITH_SERVER_URL="{server_url}"
export TIRITH_API_KEY="{api_key}"</pre>
<p>Then run <code>tirith license refresh</code> to get a fresh token at any time.</p>
</body>
</html>"#
    )
}

fn receipt_partial_page(api_key: &str, server_url: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Tirith — Your License (Pending)</title>
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 700px; margin: 60px auto; padding: 0 20px; color: #333; }}
  pre {{ background: #f5f5f5; padding: 16px; border-radius: 6px; overflow-x: auto; position: relative; font-size: 13px; word-break: break-all; white-space: pre-wrap; }}
  .copy-btn {{ position: absolute; top: 8px; right: 8px; background: #333; color: #fff; border: none; padding: 4px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; }}
  .copy-btn:hover {{ background: #555; }}
  .warning {{ background: #fff3cd; border: 1px solid #ffc107; padding: 12px; border-radius: 6px; margin: 20px 0; }}
  .info {{ background: #d1ecf1; border: 1px solid #0dcaf0; padding: 12px; border-radius: 6px; margin: 20px 0; }}
  code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-size: 13px; }}
</style>
<script>
function copyText(id) {{
  const el = document.getElementById(id);
  navigator.clipboard.writeText(el.textContent.trim()).then(() => {{
    const btn = el.parentElement.querySelector('.copy-btn');
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = 'Copy', 2000);
  }});
}}
</script>
</head>
<body>
<h1>Your Tirith License (Pending)</h1>

<div class="info">
  Your subscription is currently pending. Once your account is active,
  run <code>tirith license refresh</code> with the API key below to receive your license token.
</div>

<div class="warning">
  <strong>Save your API key now</strong> — this page can only be viewed once.
</div>

<h2>API Key</h2>
<pre><button class="copy-btn" onclick="copyText('apikey')">Copy</button><span id="apikey">{api_key}</span></pre>

<h2>Setup</h2>
<p>Add to your shell profile:</p>
<pre>export TIRITH_SERVER_URL="{server_url}"
export TIRITH_API_KEY="{api_key}"</pre>
<p>Then run <code>tirith license refresh</code> once your subscription is active.</p>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::config::Config;
    use crate::db::{CreatedData, CreatedOutcome, Db};
    use crate::sign::TokenSigner;

    const RECEIPT_SECRET: &str = "receipt-route-test-secret";
    const API_KEY: &str = "tirith_api_key_route_test";
    const TOKEN: &str = "route.test.token";

    async fn test_state() -> AppState {
        let encryption_key = [0x42; 32];
        let nonce = [0x24; 12];
        let cipher = Aes256Gcm::new_from_slice(&encryption_key).unwrap();
        let api_key_enc = cipher
            .encrypt(Nonce::from_slice(&nonce), API_KEY.as_bytes())
            .unwrap();

        let db = Db::open(":memory:").unwrap();
        let outcome = db
            .process_subscription_created(CreatedData {
                event_id: "evt_receipt_route".to_string(),
                event_type: "subscription.active".to_string(),
                subscription_id: "sub_receipt_route".to_string(),
                customer_id: "customer_receipt_route".to_string(),
                email: "receipt-route@example.invalid".to_string(),
                tier: "pro".to_string(),
                product_id: "product_receipt_route".to_string(),
                occurred_at: Some("2026-08-19T00:00:00Z".to_string()),
                checkout_id: Some("checkout_receipt_route".to_string()),
                key_hash: "route-test-key-hash".to_string(),
                token: Some(TOKEN.to_string()),
                token_expires_at: 4_102_444_800,
                receipt_secret: RECEIPT_SECRET.to_string(),
                api_key_enc,
                api_key_nonce: nonce.to_vec(),
            })
            .await
            .unwrap();
        assert!(matches!(outcome, CreatedOutcome::Provisioned));

        let config = Config {
            ed25519_seed_hex: "00".repeat(32),
            polar_webhook_secret: "whsec_test".to_string(),
            polar_api_key: "polar_test".to_string(),
            receipt_encryption_key: encryption_key,
            product_tier_map: HashMap::new(),
            kid: "test".to_string(),
            token_ttl_days: 30,
            port: 0,
            database_url: ":memory:".to_string(),
            receipt_base_url: Some("https://license.example.invalid".to_string()),
            trusted_proxy: false,
            backup_r2_endpoint: None,
            backup_r2_bucket: None,
            backup_r2_access_key_id: None,
            backup_r2_secret_access_key: None,
        };

        AppState {
            db,
            signer: Arc::new(
                TokenSigner::from_hex_seed(&config.ed25519_seed_hex, config.kid.clone()).unwrap(),
            ),
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
        }
    }

    fn assert_no_store(response: &Response) {
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::REFERRER_POLICY)
                .and_then(|value| value.to_str().ok()),
            Some("no-referrer")
        );
    }

    async fn body_text(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn get_and_head_confirm_without_consuming_or_revealing_credentials() {
        let state = test_state().await;

        let get = receipt_confirmation(
            Method::GET,
            State(state.clone()),
            Path(RECEIPT_SECRET.to_string()),
        )
        .await
        .unwrap();
        assert_eq!(get.status(), StatusCode::OK);
        assert_no_store(&get);
        let get_body = body_text(get).await;
        assert!(get_body.contains("<form method=\"post\">"));
        assert!(!get_body.contains(API_KEY));
        assert!(!get_body.contains(TOKEN));
        assert!(state
            .db
            .receipt_peek(RECEIPT_SECRET)
            .await
            .unwrap()
            .is_some());

        let head = receipt_confirmation(
            Method::HEAD,
            State(state.clone()),
            Path(RECEIPT_SECRET.to_string()),
        )
        .await
        .unwrap();
        assert_eq!(head.status(), StatusCode::OK);
        assert_no_store(&head);
        assert!(body_text(head).await.is_empty());
        assert!(state
            .db
            .receipt_peek(RECEIPT_SECRET)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn lookup_redirect_is_no_store_and_does_not_consume() {
        let state = test_state().await;
        let response = receipt_lookup(
            State(state.clone()),
            Query(LookupQuery {
                checkout: "checkout_receipt_route".to_string(),
                poll: None,
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_no_store(&response);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/receipt/receipt-route-test-secret")
        );
        assert!(state
            .db
            .receipt_peek(RECEIPT_SECRET)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn concurrent_posts_reveal_and_consume_exactly_once() {
        let state = test_state().await;
        let left = receipt_consume(State(state.clone()), Path(RECEIPT_SECRET.to_string()));
        let right = receipt_consume(State(state.clone()), Path(RECEIPT_SECRET.to_string()));
        let (left, right) = tokio::join!(left, right);
        let responses = [left.unwrap(), right.unwrap()];

        assert_eq!(
            responses
                .iter()
                .filter(|response| response.status() == StatusCode::OK)
                .count(),
            1
        );
        assert_eq!(
            responses
                .iter()
                .filter(|response| response.status() == StatusCode::NOT_FOUND)
                .count(),
            1
        );
        for response in &responses {
            assert_no_store(response);
        }

        let mut bodies = Vec::new();
        for response in responses {
            bodies.push(body_text(response).await);
        }
        assert_eq!(
            bodies.iter().filter(|body| body.contains(API_KEY)).count(),
            1
        );
        assert_eq!(bodies.iter().filter(|body| body.contains(TOKEN)).count(), 1);
        assert!(state
            .db
            .receipt_peek(RECEIPT_SECRET)
            .await
            .unwrap()
            .is_none());
    }
}
