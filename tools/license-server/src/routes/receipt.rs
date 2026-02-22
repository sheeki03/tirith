use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use tracing::error;

use crate::error::AppError;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct LookupQuery {
    pub checkout: String,
}

pub async fn receipt_lookup(
    State(state): State<AppState>,
    Query(query): Query<LookupQuery>,
) -> Result<Response, AppError> {
    if query.checkout.is_empty() {
        return Err(AppError::BadWebhook("missing checkout parameter".into()));
    }

    let secret = state.db.receipt_lookup(&query.checkout).await?;

    match secret {
        Some(s) => {
            let redirect_url = format!("/receipt/{s}");
            Ok(Redirect::to(&redirect_url).into_response())
        }
        None => {
            // Race condition: redirect arrived before webhook processed
            // Return a page with meta-refresh retry
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

pub async fn receipt_view(
    State(state): State<AppState>,
    Path(receipt_secret): Path<String>,
) -> Result<Response, AppError> {
    // Atomic consume — exactly one request gets the row
    let row = state
        .db
        .receipt_consume(&receipt_secret)
        .await?
        .ok_or_else(|| AppError::NotFound("Receipt expired or already viewed".into()))?;

    // Decrypt API key
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

    let server_url = state
        .config
        .receipt_base_url
        .as_deref()
        .unwrap_or("http://localhost:8080");

    let html = match row.token {
        Some(token) => receipt_full_page(&token, &api_key, server_url),
        None => receipt_partial_page(&api_key, server_url),
    };

    Ok((
        StatusCode::OK,
        [
            ("content-type", "text/html; charset=utf-8"),
            ("cache-control", "no-store"),
            ("pragma", "no-cache"),
            ("x-content-type-options", "nosniff"),
        ],
        html,
    )
        .into_response())
}

fn receipt_not_ready_page(checkout_id: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Tirith — Processing</title>
<meta http-equiv="refresh" content="2">
<style>
  body {{ font-family: -apple-system, system-ui, sans-serif; max-width: 600px; margin: 60px auto; padding: 0 20px; color: #333; }}
  .spinner {{ display: inline-block; width: 20px; height: 20px; border: 3px solid #ddd; border-top-color: #333; border-radius: 50%; animation: spin 1s linear infinite; }}
  @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
  .status {{ margin-top: 20px; color: #666; }}
</style>
<script>
  let retries = 0;
  const maxRetries = 30;
  const interval = setInterval(() => {{
    retries++;
    const el = document.getElementById('count');
    if (el) el.textContent = retries;
    if (retries >= maxRetries) {{
      clearInterval(interval);
      document.getElementById('loading').style.display = 'none';
      document.getElementById('timeout').style.display = 'block';
    }}
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
     with reference: <code>{checkout_id}</code></p>
</div>
</body>
</html>"#
    )
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
