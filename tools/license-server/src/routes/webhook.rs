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
    CanceledData, CreatedData, CreatedOutcome, DeadLetterData, RevokedData, UpdatedData,
    UpdatedOutcome,
};
use crate::error::AppError;
use crate::state::AppState;
use crate::webhook_verify;

const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub async fn webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
    // 1. Standard Webhooks HMAC verification
    let msg_id = header_str(&headers, "webhook-id")
        .ok_or_else(|| AppError::Unauthorized("missing webhook-id header".into()))?;
    let timestamp = header_str(&headers, "webhook-timestamp")
        .ok_or_else(|| AppError::Unauthorized("missing webhook-timestamp header".into()))?;
    let sig_header = header_str(&headers, "webhook-signature")
        .ok_or_else(|| AppError::Unauthorized("missing webhook-signature header".into()))?;

    webhook_verify::verify_webhook(
        &state.config.polar_webhook_secret,
        msg_id,
        timestamp,
        &body,
        sig_header,
        300,
    )
    .map_err(|e| AppError::Unauthorized(format!("webhook verification: {e}")))?;

    // 2. Parse JSON
    let event: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadWebhook(format!("invalid JSON: {e}")))?;

    let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");

    // Use webhook-id header as event_id (Polar doesn't put event_id in body)
    let event_id = msg_id.to_string();

    // 3. Early idempotency precheck
    if state.db.event_exists(&event_id).await? {
        return Ok(StatusCode::OK);
    }

    // 4. Route by event type
    match event_type {
        "order.paid" => handle_order_paid(&state, &event, &event_id).await,
        "subscription.active" => handle_sub_active(&state, &event, &event_id).await,
        "subscription.canceled" => handle_sub_canceled(&state, &event, &event_id).await,
        "subscription.revoked" => handle_sub_revoked(&state, &event, &event_id).await,
        "subscription.past_due" => handle_sub_past_due(&state, &event, &event_id).await,
        "subscription.uncanceled" => handle_sub_uncanceled(&state, &event, &event_id).await,
        _ => {
            info!(event_type = %event_type, event_id = %event_id, "unknown event type, ignored");
            Ok(StatusCode::OK)
        }
    }
}

// ─── order.paid (Pro lifetime one-time purchase) ────────────────────────

async fn handle_order_paid(
    state: &AppState,
    event: &serde_json::Value,
    event_id: &str,
) -> Result<StatusCode, AppError> {
    let data = event
        .get("data")
        .ok_or_else(|| AppError::BadWebhook("missing data".into()))?;

    // Gate: one-time orders only
    // Reject if subscription_id is present (subscription renewal, not lifetime Pro)
    if data
        .get("subscription_id")
        .map(|v| !v.is_null())
        .unwrap_or(false)
    {
        info!(
            event_id = %event_id,
            "order.paid with subscription_id present — subscription renewal, ignoring"
        );
        return Ok(StatusCode::OK);
    }
    // Reject if product is recurring
    if data
        .pointer("/product/is_recurring")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        info!(
            event_id = %event_id,
            "order.paid for recurring product — handled via subscription events, ignoring"
        );
        return Ok(StatusCode::OK);
    }

    let order_id =
        json_str(data, "id").ok_or_else(|| AppError::BadWebhook("missing order id".into()))?;
    let customer_id = json_str(data, "customer_id").unwrap_or_else(|| "unknown".to_string());
    let email = data
        .pointer("/customer/email")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown")
        .to_string();
    let checkout_id = json_str(data, "checkout_id")
        .ok_or_else(|| AppError::BadWebhook("missing checkout_id".into()))?;

    let created_at = event
        .get("created_at")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Product → tier resolution
    let product_id = json_str(data, "product_id")
        .ok_or_else(|| AppError::BadWebhook("missing product_id".into()))?;

    let tier = match state.config.tier_for_product(&product_id) {
        Some(t) => t.to_string(),
        None => {
            // Unknown product → return 500 so Polar retries the full event.
            // No dead-letter: provisioning requires the full event, not just tier fix.
            error!(
                event_id = %event_id,
                product_id = %product_id,
                "unknown product_id on order.paid — returning 500 for Polar retry"
            );
            return Err(AppError::Internal(format!(
                "unknown product_id: {product_id}"
            )));
        }
    };

    // Provision: generate API key, token, receipt
    let creds = provision_credentials(state, &tier)?;

    let created_data = CreatedData {
        event_id: event_id.to_string(),
        event_type: "order.paid".to_string(),
        subscription_id: order_id.clone(),
        customer_id,
        email,
        tier,
        product_id,
        occurred_at: created_at,
        checkout_id,
        key_hash: creds.key_hash,
        token: Some(creds.token),
        token_expires_at: creds.token_expires_at,
        receipt_secret: creds.receipt_secret,
        api_key_enc: creds.api_key_enc,
        api_key_nonce: creds.api_key_nonce,
    };

    let outcome = state.db.process_subscription_created(created_data).await?;
    log_created_outcome(&outcome, &order_id, event_id);

    Ok(StatusCode::OK)
}

// ─── subscription.active (Team/Enterprise provision or reconciliation) ──

async fn handle_sub_active(
    state: &AppState,
    event: &serde_json::Value,
    event_id: &str,
) -> Result<StatusCode, AppError> {
    let data = event
        .get("data")
        .ok_or_else(|| AppError::BadWebhook("missing data".into()))?;

    let sub_id = json_str(data, "id")
        .ok_or_else(|| AppError::BadWebhook("missing subscription id".into()))?;
    let customer_id = json_str(data, "customer_id").unwrap_or_else(|| "unknown".to_string());
    let email = data
        .pointer("/customer/email")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown")
        .to_string();
    let product_id = json_str(data, "product_id");
    let checkout_id = json_str(data, "checkout_id");

    let created_at = event
        .get("created_at")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Tier resolution
    let (tier, tier_unknown) = resolve_tier(
        state,
        &sub_id,
        product_id.as_deref(),
        event_id,
        "subscription.active",
        &created_at,
        event,
    )
    .await;

    // Check if API key already exists for this subscription
    let key_exists = state.db.has_api_key(&sub_id).await?;

    if key_exists {
        // Status reconciliation + potential un-revoke
        let updated_data = UpdatedData {
            event_id: event_id.to_string(),
            event_type: "subscription.active".to_string(),
            subscription_id: sub_id.clone(),
            new_status: "active".to_string(),
            customer_id: Some(customer_id),
            email: Some(email),
            tier: tier.clone(),
            product_id: product_id.clone(),
            occurred_at: created_at,
            resolved_tier: tier.clone(),
            tier_unknown,
        };

        let outcome = state.db.process_subscription_updated(updated_data).await?;
        match outcome {
            UpdatedOutcome::Unrevoked => {
                info!(sub_id = %sub_id, "subscription.active — key un-revoked");
            }
            UpdatedOutcome::StatusUpdated => {
                info!(sub_id = %sub_id, "subscription.active — status reconciled");
            }
            UpdatedOutcome::TerminalIgnored => {
                warn!(sub_id = %sub_id, "subscription.active absorbed by terminal revoked state");
            }
            UpdatedOutcome::ActiveNoKey => {
                warn!(sub_id = %sub_id, "subscription.active — key check race, no key found in update");
            }
            UpdatedOutcome::Duplicate => {
                info!(event_id = %event_id, "duplicate event, skipped");
            }
            other => {
                info!(sub_id = %sub_id, outcome = ?other, "subscription.active — updated");
            }
        }
    } else {
        // New subscription — full provision
        let tier_str = match &tier {
            Some(t) => t.clone(),
            None => {
                // Unknown product → dead-letter and return 500 for retry
                error!(
                    event_id = %event_id,
                    sub_id = %sub_id,
                    "subscription.active with unknown product, cannot provision"
                );
                let _ = state
                    .db
                    .insert_dead_letter(DeadLetterData {
                        event_id: event_id.to_string(),
                        subscription_id: Some(sub_id.clone()),
                        event_type: "subscription.active".to_string(),
                        reason: "unresolvable_product".to_string(),
                        occurred_at: created_at.clone(),
                        payload: redact_event(event),
                    })
                    .await;
                return Err(AppError::Internal("unknown product_id".into()));
            }
        };

        let cid = checkout_id.unwrap_or_else(|| "unknown".to_string());

        let creds = provision_credentials(state, &tier_str)?;

        let created_data = CreatedData {
            event_id: event_id.to_string(),
            event_type: "subscription.active".to_string(),
            subscription_id: sub_id.clone(),
            customer_id,
            email,
            tier: tier_str,
            product_id: product_id.unwrap_or_default(),
            occurred_at: created_at,
            checkout_id: cid,
            key_hash: creds.key_hash,
            token: Some(creds.token),
            token_expires_at: creds.token_expires_at,
            receipt_secret: creds.receipt_secret,
            api_key_enc: creds.api_key_enc,
            api_key_nonce: creds.api_key_nonce,
        };

        let outcome = state.db.process_subscription_created(created_data).await?;
        log_created_outcome(&outcome, &sub_id, event_id);
    }

    Ok(StatusCode::OK)
}

// ─── subscription.canceled (benefits continue until period end) ─────────

async fn handle_sub_canceled(
    state: &AppState,
    event: &serde_json::Value,
    event_id: &str,
) -> Result<StatusCode, AppError> {
    let data = event
        .get("data")
        .ok_or_else(|| AppError::BadWebhook("missing data".into()))?;

    let sub_id = match json_str(data, "id") {
        Some(id) => id,
        None => {
            let _ = state
                .db
                .insert_dead_letter(DeadLetterData {
                    event_id: event_id.to_string(),
                    subscription_id: None,
                    event_type: "subscription.canceled".to_string(),
                    reason: "missing_subscription_id".to_string(),
                    occurred_at: event
                        .get("created_at")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    payload: redact_event(event),
                })
                .await;
            error!(event_id = %event_id, "canceled event missing subscription_id");
            return Ok(StatusCode::OK);
        }
    };

    let created_at = event
        .get("created_at")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let customer_id = json_str(data, "customer_id");
    let email = data
        .pointer("/customer/email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let product_id = json_str(data, "product_id");
    let tier = product_id
        .as_deref()
        .and_then(|pid| state.config.tier_for_product(pid).map(|t| t.to_string()));

    let canceled_data = CanceledData {
        event_id: event_id.to_string(),
        subscription_id: sub_id.clone(),
        customer_id,
        email,
        tier,
        product_id,
        occurred_at: created_at,
    };

    let processed = state
        .db
        .process_subscription_canceled(canceled_data)
        .await?;
    if processed {
        info!(sub_id = %sub_id, "subscription canceled — key stays active (benefits continue)");
    } else {
        info!(event_id = %event_id, "duplicate/absorbed canceled event, skipped");
    }

    Ok(StatusCode::OK)
}

// ─── subscription.revoked (terminal — revoke key) ──────────────────────

async fn handle_sub_revoked(
    state: &AppState,
    event: &serde_json::Value,
    event_id: &str,
) -> Result<StatusCode, AppError> {
    let data = event
        .get("data")
        .ok_or_else(|| AppError::BadWebhook("missing data".into()))?;

    let sub_id = match json_str(data, "id") {
        Some(id) => id,
        None => {
            let _ = state
                .db
                .insert_dead_letter(DeadLetterData {
                    event_id: event_id.to_string(),
                    subscription_id: None,
                    event_type: "subscription.revoked".to_string(),
                    reason: "missing_subscription_id".to_string(),
                    occurred_at: event
                        .get("created_at")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    payload: redact_event(event),
                })
                .await;
            error!(event_id = %event_id, "revoked event missing subscription_id");
            return Ok(StatusCode::OK);
        }
    };

    let created_at = event
        .get("created_at")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let customer_id = json_str(data, "customer_id");
    let email = data
        .pointer("/customer/email")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let product_id = json_str(data, "product_id");
    let tier = product_id
        .as_deref()
        .and_then(|pid| state.config.tier_for_product(pid).map(|t| t.to_string()));

    let revoked_data = RevokedData {
        event_id: event_id.to_string(),
        subscription_id: sub_id.clone(),
        customer_id,
        email,
        tier,
        product_id,
        occurred_at: created_at,
    };

    let processed = state.db.process_subscription_revoked(revoked_data).await?;
    if processed {
        info!(sub_id = %sub_id, "subscription revoked — key revoked (terminal)");
    } else {
        info!(event_id = %event_id, "duplicate revoked event, skipped");
    }

    Ok(StatusCode::OK)
}

// ─── subscription.past_due (payment failed — revoke key) ───────────────

async fn handle_sub_past_due(
    state: &AppState,
    event: &serde_json::Value,
    event_id: &str,
) -> Result<StatusCode, AppError> {
    let data = event
        .get("data")
        .ok_or_else(|| AppError::BadWebhook("missing data".into()))?;

    let sub_id = match json_str(data, "id") {
        Some(id) => id,
        None => {
            error!(event_id = %event_id, "past_due event missing subscription_id");
            return Ok(StatusCode::OK);
        }
    };

    let created_at = event
        .get("created_at")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let product_id = json_str(data, "product_id");
    let (tier, tier_unknown) = resolve_tier(
        state,
        &sub_id,
        product_id.as_deref(),
        event_id,
        "subscription.past_due",
        &created_at,
        event,
    )
    .await;

    let updated_data = UpdatedData {
        event_id: event_id.to_string(),
        event_type: "subscription.past_due".to_string(),
        subscription_id: sub_id.clone(),
        new_status: "past_due".to_string(),
        customer_id: json_str(data, "customer_id"),
        email: data
            .pointer("/customer/email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        tier: tier.clone(),
        product_id,
        occurred_at: created_at,
        resolved_tier: tier,
        tier_unknown,
    };

    let outcome = state.db.process_subscription_updated(updated_data).await?;
    match outcome {
        UpdatedOutcome::Revoked => {
            info!(sub_id = %sub_id, "subscription past_due — key revoked");
        }
        UpdatedOutcome::TerminalIgnored => {
            warn!(sub_id = %sub_id, "past_due absorbed by terminal revoked state");
        }
        UpdatedOutcome::Duplicate => {
            info!(event_id = %event_id, "duplicate event, skipped");
        }
        other => {
            info!(sub_id = %sub_id, outcome = ?other, "subscription past_due");
        }
    }

    Ok(StatusCode::OK)
}

// ─── subscription.uncanceled (cancel reversal → back to active) ────────

async fn handle_sub_uncanceled(
    state: &AppState,
    event: &serde_json::Value,
    event_id: &str,
) -> Result<StatusCode, AppError> {
    let data = event
        .get("data")
        .ok_or_else(|| AppError::BadWebhook("missing data".into()))?;

    let sub_id = match json_str(data, "id") {
        Some(id) => id,
        None => {
            error!(event_id = %event_id, "uncanceled event missing subscription_id");
            return Ok(StatusCode::OK);
        }
    };

    let created_at = event
        .get("created_at")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let product_id = json_str(data, "product_id");
    let (tier, tier_unknown) = resolve_tier(
        state,
        &sub_id,
        product_id.as_deref(),
        event_id,
        "subscription.uncanceled",
        &created_at,
        event,
    )
    .await;

    let updated_data = UpdatedData {
        event_id: event_id.to_string(),
        event_type: "subscription.uncanceled".to_string(),
        subscription_id: sub_id.clone(),
        new_status: "active".to_string(),
        customer_id: json_str(data, "customer_id"),
        email: data
            .pointer("/customer/email")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        tier: tier.clone(),
        product_id,
        occurred_at: created_at,
        resolved_tier: tier,
        tier_unknown,
    };

    let outcome = state.db.process_subscription_updated(updated_data).await?;
    match outcome {
        UpdatedOutcome::Unrevoked => {
            info!(sub_id = %sub_id, "subscription uncanceled — back to active");
        }
        UpdatedOutcome::StatusUpdated => {
            info!(sub_id = %sub_id, "subscription uncanceled — status reconciled to active");
        }
        UpdatedOutcome::TerminalIgnored => {
            warn!(sub_id = %sub_id, "uncanceled absorbed by terminal revoked state");
        }
        UpdatedOutcome::Duplicate => {
            info!(event_id = %event_id, "duplicate event, skipped");
        }
        other => {
            info!(sub_id = %sub_id, outcome = ?other, "subscription uncanceled");
        }
    }

    Ok(StatusCode::OK)
}

// ─── Helpers ──────────────────────────────────────────────────────────────

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn json_str(val: &serde_json::Value, key: &str) -> Option<String> {
    val.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Resolve product_id → tier. On unknown product, insert dead-letter and return None.
async fn resolve_tier(
    state: &AppState,
    sub_id: &str,
    product_id: Option<&str>,
    event_id: &str,
    event_type: &str,
    created_at: &Option<String>,
    event: &serde_json::Value,
) -> (Option<String>, bool) {
    match product_id {
        Some(pid) => match state.config.tier_for_product(pid) {
            Some(t) => (Some(t.to_string()), false),
            None => {
                error!(
                    sub_id = %sub_id,
                    product_id = %pid,
                    "unresolvable product_id — setting tier to unknown"
                );
                let _ = state
                    .db
                    .insert_dead_letter(DeadLetterData {
                        event_id: event_id.to_string(),
                        subscription_id: Some(sub_id.to_string()),
                        event_type: event_type.to_string(),
                        reason: "unresolvable_product".to_string(),
                        occurred_at: created_at.clone(),
                        payload: redact_event(event),
                    })
                    .await;
                (None, true)
            }
        },
        None => {
            warn!(
                sub_id = %sub_id,
                "no product_id in event — setting tier to unknown"
            );
            let _ = state
                .db
                .insert_dead_letter(DeadLetterData {
                    event_id: event_id.to_string(),
                    subscription_id: Some(sub_id.to_string()),
                    event_type: event_type.to_string(),
                    reason: "unresolvable_product".to_string(),
                    occurred_at: created_at.clone(),
                    payload: redact_event(event),
                })
                .await;
            (None, true)
        }
    }
}

struct ProvisionResult {
    key_hash: String,
    api_key_enc: Vec<u8>,
    api_key_nonce: Vec<u8>,
    token: String,
    token_expires_at: i64,
    receipt_secret: String,
}

/// Generate API key, encrypt it, sign token, generate receipt secret.
fn provision_credentials(state: &AppState, tier: &str) -> Result<ProvisionResult, AppError> {
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
    let token = state.signer.sign_token(tier, exp_ts);

    // Generate receipt secret
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

    Ok(ProvisionResult {
        key_hash,
        api_key_enc,
        api_key_nonce: nonce_bytes.to_vec(),
        token,
        token_expires_at: exp_ts,
        receipt_secret,
    })
}

fn log_created_outcome(outcome: &CreatedOutcome, id: &str, event_id: &str) {
    match outcome {
        CreatedOutcome::Provisioned => {
            info!(id = %id, "provisioned — API key, token, and receipt created");
        }
        CreatedOutcome::PartialProvisioned => {
            warn!(id = %id, "partial provisioning (degraded state)");
        }
        CreatedOutcome::SkippedRevoked => {
            warn!(id = %id, "provisioning skipped — subscription is revoked (terminal)");
        }
        CreatedOutcome::AlreadyProvisioned => {
            info!(id = %id, "already provisioned, skipped");
        }
        CreatedOutcome::Duplicate => {
            info!(event_id = %event_id, "duplicate event, skipped");
        }
    }
}

/// Redact event payload — keep only safe fields for dead-letter storage.
fn redact_event(event: &serde_json::Value) -> String {
    let mut redacted = serde_json::json!({});

    if let Some(t) = event.get("type") {
        redacted["type"] = t.clone();
    }
    if let Some(ca) = event.get("created_at") {
        redacted["created_at"] = ca.clone();
    }
    if let Some(data) = event.get("data") {
        let mut rd = serde_json::json!({});
        if let Some(id) = data.get("id") {
            rd["id"] = id.clone();
        }
        if let Some(status) = data.get("status") {
            rd["status"] = status.clone();
        }
        if let Some(pid) = data.get("product_id") {
            rd["product_id"] = pid.clone();
        }
        if let Some(cid) = data.get("checkout_id") {
            rd["checkout_id"] = cid.clone();
        }
        if let Some(cust_id) = data.get("customer_id") {
            rd["customer_id"] = cust_id.clone();
        }
        redacted["data"] = rd;
    }

    serde_json::to_string(&redacted).unwrap_or_else(|_| "{}".to_string())
}
