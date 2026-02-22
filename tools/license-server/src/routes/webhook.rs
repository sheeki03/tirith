use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use base64::Engine;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

use crate::db::{
    CanceledData, CreatedData, CreatedOutcome, DeadLetterData, UpdatedData, UpdatedOutcome,
};
use crate::error::AppError;
use crate::paddle::{self, PaddleSignature};
use crate::state::AppState;

const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub async fn webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    // 1. HMAC verification
    let sig_header = headers
        .get("paddle-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("missing Paddle-Signature header".into()))?;

    let sig = PaddleSignature::parse(sig_header)
        .ok_or_else(|| AppError::Unauthorized("malformed Paddle-Signature header".into()))?;

    paddle::verify_webhook(&state.config.paddle_webhook_secret, &body, &sig, 300)
        .map_err(|e| AppError::Unauthorized(format!("webhook verification: {e}")))?;

    // 2. Parse JSON
    let event: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadWebhook(format!("invalid JSON: {e}")))?;

    let event_type = event
        .get("event_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let event_id = event
        .get("event_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if event_id.is_empty() {
        return Err(AppError::BadWebhook("missing event_id".into()));
    }

    // 3. Early idempotency precheck (optimization — avoids external calls on duplicates)
    if state.db.event_exists(&event_id).await? {
        return Ok(StatusCode::OK);
    }

    // 4. Route by event type
    match event_type {
        "subscription.created" => handle_created(&state, &event, &event_id).await,
        "subscription.canceled" => handle_canceled(&state, &event, &event_id).await,
        "subscription.updated" => handle_updated(&state, &event, &event_id).await,
        "transaction.completed" => {
            info!(event_id = %event_id, "transaction.completed logged");
            Ok(StatusCode::OK)
        }
        _ => {
            info!(event_type = %event_type, event_id = %event_id, "unknown event type, ignored");
            Ok(StatusCode::OK)
        }
    }
}

// ─── subscription.created ────────────────────────────────────────────

async fn handle_created(
    state: &AppState,
    event: &serde_json::Value,
    event_id: &str,
) -> Result<StatusCode, AppError> {
    let data = event
        .get("data")
        .ok_or_else(|| AppError::BadWebhook("missing data".into()))?;

    // Required fields
    let sub_id = json_str(data, "id")
        .ok_or_else(|| AppError::BadWebhook("missing subscription id".into()))?;
    let checkout_id = data
        .pointer("/checkout/id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadWebhook("missing checkout.id".into()))?;

    let occurred_at = event
        .get("occurred_at")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Email — try webhook payload, then Paddle API fallback
    let email = json_str(data, "email").or_else(|| {
        data.pointer("/customer/email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let email = match email {
        Some(e) => e,
        None => {
            // Paddle API fallback for email
            let customer_id = json_str(data, "customer_id");
            match customer_id {
                Some(ref cid) => fetch_customer_email(state, cid).await.unwrap_or_else(|| {
                    warn!(sub_id = %sub_id, "email not in webhook and Paddle API fallback failed");
                    "unknown".to_string()
                }),
                None => "unknown".to_string(),
            }
        }
    };

    let customer_id = json_str(data, "customer_id").unwrap_or_else(|| "unknown".to_string());

    // Price → tier
    let price_id = data
        .pointer("/items/0/price/id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let tier = match &price_id {
        Some(pid) => match state.config.tier_for_price(pid) {
            Some(t) => t.to_string(),
            None => {
                // Dead-letter: unknown price on created → 500 (Paddle retries after config fix)
                let _ = state
                    .db
                    .insert_dead_letter(DeadLetterData {
                        event_id: event_id.to_string(),
                        subscription_id: Some(sub_id.clone()),
                        event_type: "subscription.created".to_string(),
                        reason: "unresolvable_price".to_string(),
                        occurred_at: occurred_at.clone(),
                        payload: redact_event(event),
                    })
                    .await;
                return Err(AppError::Internal(format!("unknown price_id: {pid}")));
            }
        },
        None => {
            let _ = state
                .db
                .insert_dead_letter(DeadLetterData {
                    event_id: event_id.to_string(),
                    subscription_id: Some(sub_id.clone()),
                    event_type: "subscription.created".to_string(),
                    reason: "missing_price_id".to_string(),
                    occurred_at: occurred_at.clone(),
                    payload: redact_event(event),
                })
                .await;
            return Err(AppError::Internal("missing price_id".into()));
        }
    };

    // Generate API key
    let mut api_key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut api_key_bytes);
    let api_key_raw = B64URL.encode(api_key_bytes);

    // Hash for storage
    let mut hasher = Sha256::new();
    hasher.update(api_key_raw.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    // Sign token
    let exp_ts = chrono::Utc::now().timestamp() + (state.config.token_ttl_days * 86400);
    let token = state.signer.sign_token(&tier, exp_ts);

    // Generate receipt secret (32 bytes)
    let mut receipt_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut receipt_bytes);
    let receipt_secret = B64URL.encode(receipt_bytes);

    // Encrypt API key for pending_receipts
    let cipher = Aes256Gcm::new_from_slice(&state.config.receipt_encryption_key)
        .map_err(|e| AppError::Internal(format!("AES init: {e}")))?;
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let api_key_enc = cipher
        .encrypt(nonce, api_key_raw.as_bytes())
        .map_err(|e| AppError::Internal(format!("AES encrypt: {e}")))?;

    let created_data = CreatedData {
        event_id: event_id.to_string(),
        subscription_id: sub_id.clone(),
        customer_id,
        email,
        tier,
        price_id: price_id.unwrap_or_default(),
        occurred_at,
        checkout_id: checkout_id.to_string(),
        key_hash,
        token: Some(token),
        token_expires_at: exp_ts,
        receipt_secret,
        api_key_enc,
        api_key_nonce: nonce_bytes.to_vec(),
    };

    let outcome = state.db.process_subscription_created(created_data).await?;

    match outcome {
        CreatedOutcome::Provisioned => {
            info!(sub_id = %sub_id, "subscription created — fully provisioned");
        }
        CreatedOutcome::PartialProvisioned => {
            warn!(sub_id = %sub_id, "subscription created — partial provisioning (degraded state)");
        }
        CreatedOutcome::SkippedCanceled => {
            warn!(sub_id = %sub_id, "created event for canceled subscription, skipping provisioning");
        }
        CreatedOutcome::AlreadyProvisioned => {
            info!(sub_id = %sub_id, "created event for already-provisioned subscription");
        }
        CreatedOutcome::Duplicate => {
            info!(event_id = %event_id, "duplicate event, skipped");
        }
    }

    Ok(StatusCode::OK)
}

// ─── subscription.canceled ───────────────────────────────────────────

async fn handle_canceled(
    state: &AppState,
    event: &serde_json::Value,
    event_id: &str,
) -> Result<StatusCode, AppError> {
    let data = event
        .get("data")
        .ok_or_else(|| AppError::BadWebhook("missing data".into()))?;

    // subscription_id is REQUIRED for cancelation
    let sub_id = match json_str(data, "id") {
        Some(id) => id,
        None => {
            // Permanent parse failure — return 200 (Paddle won't fix payload on retry)
            let _ = state
                .db
                .insert_dead_letter(DeadLetterData {
                    event_id: event_id.to_string(),
                    subscription_id: None,
                    event_type: "subscription.canceled".to_string(),
                    reason: "missing_subscription_id".to_string(),
                    occurred_at: event
                        .get("occurred_at")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    payload: redact_event(event),
                })
                .await;
            error!(event_id = %event_id, "canceled event missing subscription_id");
            return Ok(StatusCode::OK);
        }
    };

    let occurred_at = event
        .get("occurred_at")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Optional metadata (best-effort)
    let customer_id = json_str(data, "customer_id");
    let email = json_str(data, "email").or_else(|| {
        data.pointer("/customer/email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let price_id = data
        .pointer("/items/0/price/id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let tier = price_id
        .as_deref()
        .and_then(|pid| state.config.tier_for_price(pid).map(|t| t.to_string()));

    let canceled_data = CanceledData {
        event_id: event_id.to_string(),
        subscription_id: sub_id.clone(),
        customer_id,
        email,
        tier,
        price_id,
        occurred_at,
    };

    let processed = state
        .db
        .process_subscription_canceled(canceled_data)
        .await?;
    if processed {
        info!(sub_id = %sub_id, "subscription canceled — key revoked");
    } else {
        info!(event_id = %event_id, "duplicate canceled event, skipped");
    }

    Ok(StatusCode::OK)
}

// ─── subscription.updated ────────────────────────────────────────────

async fn handle_updated(
    state: &AppState,
    event: &serde_json::Value,
    event_id: &str,
) -> Result<StatusCode, AppError> {
    let data = event
        .get("data")
        .ok_or_else(|| AppError::BadWebhook("missing data".into()))?;

    // subscription_id and status are REQUIRED
    let sub_id = match json_str(data, "id") {
        Some(id) => id,
        None => {
            let _ = state
                .db
                .insert_dead_letter(DeadLetterData {
                    event_id: event_id.to_string(),
                    subscription_id: None,
                    event_type: "subscription.updated".to_string(),
                    reason: "missing_subscription_id".to_string(),
                    occurred_at: event
                        .get("occurred_at")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    payload: redact_event(event),
                })
                .await;
            error!(event_id = %event_id, "updated event missing subscription_id");
            return Ok(StatusCode::OK);
        }
    };

    let new_status = match json_str(data, "status") {
        Some(s) => s,
        None => {
            let _ = state
                .db
                .insert_dead_letter(DeadLetterData {
                    event_id: event_id.to_string(),
                    subscription_id: Some(sub_id.clone()),
                    event_type: "subscription.updated".to_string(),
                    reason: "missing_status".to_string(),
                    occurred_at: event
                        .get("occurred_at")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    payload: redact_event(event),
                })
                .await;
            error!(event_id = %event_id, sub_id = %sub_id, "updated event missing status");
            return Ok(StatusCode::OK);
        }
    };

    let occurred_at = event
        .get("occurred_at")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Optional metadata
    let customer_id = json_str(data, "customer_id");
    let email = json_str(data, "email").or_else(|| {
        data.pointer("/customer/email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });
    let price_id = data
        .pointer("/items/0/price/id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Tier resolution — fail-closed on unknown
    let (resolved_tier, tier_unknown) = match &price_id {
        Some(pid) => match state.config.tier_for_price(pid) {
            Some(t) => (Some(t.to_string()), false),
            None => {
                error!(
                    sub_id = %sub_id,
                    price_id = %pid,
                    "unresolvable price_id on updated event — setting tier to unknown"
                );
                let _ = state
                    .db
                    .insert_dead_letter(DeadLetterData {
                        event_id: event_id.to_string(),
                        subscription_id: Some(sub_id.clone()),
                        event_type: "subscription.updated".to_string(),
                        reason: "unresolvable_price".to_string(),
                        occurred_at: occurred_at.clone(),
                        payload: redact_event(event),
                    })
                    .await;
                (None, true)
            }
        },
        None => {
            // No price_id at all — fail-closed
            warn!(
                sub_id = %sub_id,
                "no price_id in updated event — setting tier to unknown"
            );
            let _ = state
                .db
                .insert_dead_letter(DeadLetterData {
                    event_id: event_id.to_string(),
                    subscription_id: Some(sub_id.clone()),
                    event_type: "subscription.updated".to_string(),
                    reason: "unresolvable_price".to_string(),
                    occurred_at: occurred_at.clone(),
                    payload: redact_event(event),
                })
                .await;
            (None, true)
        }
    };

    let updated_data = UpdatedData {
        event_id: event_id.to_string(),
        subscription_id: sub_id.clone(),
        new_status: new_status.clone(),
        customer_id,
        email,
        tier: resolved_tier.clone(),
        price_id,
        occurred_at,
        resolved_tier,
        tier_unknown,
    };

    let outcome = state.db.process_subscription_updated(updated_data).await?;

    match outcome {
        UpdatedOutcome::Unrevoked => {
            info!(sub_id = %sub_id, status = %new_status, "subscription updated — key un-revoked");
        }
        UpdatedOutcome::Revoked => {
            info!(sub_id = %sub_id, status = %new_status, "subscription updated — key revoked");
        }
        UpdatedOutcome::ActiveNoKey => {
            warn!(sub_id = %sub_id, "active sub has no API key — awaiting subscription.created");
        }
        UpdatedOutcome::StaleActiveIgnored => {
            warn!(
                sub_id = %sub_id,
                event_id = %event_id,
                "stale updated(active) for canceled subscription, ignoring"
            );
        }
        UpdatedOutcome::UnknownStatusRevoked => {
            warn!(sub_id = %sub_id, status = %new_status, "unknown status treated as inactive");
        }
        UpdatedOutcome::Duplicate => {
            info!(event_id = %event_id, "duplicate updated event, skipped");
        }
    }

    Ok(StatusCode::OK)
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn json_str(val: &serde_json::Value, key: &str) -> Option<String> {
    val.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Redact event payload — keep only safe fields for dead-letter storage.
fn redact_event(event: &serde_json::Value) -> String {
    let mut redacted = serde_json::json!({});

    if let Some(eid) = event.get("event_id") {
        redacted["event_id"] = eid.clone();
    }
    if let Some(et) = event.get("event_type") {
        redacted["event_type"] = et.clone();
    }
    if let Some(oa) = event.get("occurred_at") {
        redacted["occurred_at"] = oa.clone();
    }
    if let Some(data) = event.get("data") {
        let mut rd = serde_json::json!({});
        if let Some(id) = data.get("id") {
            rd["id"] = id.clone();
        }
        if let Some(status) = data.get("status") {
            rd["status"] = status.clone();
        }
        if let Some(items) = data.get("items").and_then(|v| v.as_array()) {
            let redacted_items: Vec<serde_json::Value> = items
                .iter()
                .map(|item| {
                    let mut ri = serde_json::json!({});
                    if let Some(price) = item.get("price") {
                        if let Some(pid) = price.get("id") {
                            ri["price"] = serde_json::json!({"id": pid});
                        }
                    }
                    ri
                })
                .collect();
            rd["items"] = serde_json::json!(redacted_items);
        }
        if let Some(checkout) = data.get("checkout") {
            if let Some(cid) = checkout.get("id") {
                rd["checkout"] = serde_json::json!({"id": cid});
            }
        }
        redacted["data"] = rd;
    }

    serde_json::to_string(&redacted).unwrap_or_else(|_| "{}".to_string())
}

/// Fetch customer email from Paddle API.
async fn fetch_customer_email(state: &AppState, customer_id: &str) -> Option<String> {
    let url = format!("https://api.paddle.com/customers/{customer_id}");
    let resp = state
        .http_client
        .get(&url)
        .header(
            "Authorization",
            format!("Bearer {}", state.config.paddle_api_key),
        )
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let body: serde_json::Value = resp.json().await.ok()?;
    body.pointer("/data/email")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}
