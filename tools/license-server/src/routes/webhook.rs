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

/// Record a dead-letter row, logging at error level if the insert itself fails.
///
/// The caller has already decided to answer the webhook: these paths handle a
/// malformed or unresolvable event that a Polar retry would not help, so they
/// return 200 rather than 500. That makes the dead-letter the sole durable
/// trace of the event, and a silently swallowed insert failure would leave a
/// terminal event with no record at all. Logging keeps the 200/no-retry
/// contract while making the loss visible to operators.
async fn record_dead_letter(state: &AppState, data: DeadLetterData) {
    let summary = format!("{} ({})", data.event_type, data.reason);
    if let Err(error) = state.db.insert_dead_letter(data).await {
        error!(
            error = %error,
            dead_letter = %summary,
            "failed to record dead-letter; this terminal event now has no durable trace"
        );
    }
}

pub async fn webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, AppError> {
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

    let event: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadWebhook(format!("invalid JSON: {e}")))?;

    let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");

    // Enforce the ordering prerequisite at the dispatcher as well as inside
    // each state-changing handler. That keeps a newly added subscription event
    // from accidentally bypassing the fail-closed timestamp contract.
    if event_type.starts_with("subscription.") {
        let _ = required_event_created_at(&event)?;
    }

    // Polar does not include event_id in the body; the webhook-id header
    // is the authoritative identifier.
    let event_id = msg_id.to_string();

    if state.db.event_exists(&event_id).await? {
        return Ok(StatusCode::OK);
    }

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

/// Handles `order.paid` — the one-time lifetime Pro purchase path.
async fn handle_order_paid(
    state: &AppState,
    event: &serde_json::Value,
    event_id: &str,
) -> Result<StatusCode, AppError> {
    let data = event
        .get("data")
        .ok_or_else(|| AppError::BadWebhook("missing data".into()))?;

    // Skip subscription renewals; those are handled by subscription.* events.
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
    // Skip recurring products; those arrive as subscription.* events.
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

    let created_at = required_event_created_at(event)?;

    let product_id = json_str(data, "product_id")
        .ok_or_else(|| AppError::BadWebhook("missing product_id".into()))?;

    let tier = match state.config.tier_for_product(&product_id) {
        Some(t) => t.to_string(),
        None => {
            // Return 500 so Polar retries the full event. Provisioning
            // needs the whole event, not just a tier-fix dead-letter.
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

    let creds = provision_credentials(state, &tier)?;

    let created_data = CreatedData {
        event_id: event_id.to_string(),
        event_type: "order.paid".to_string(),
        subscription_id: order_id.clone(),
        customer_id,
        email,
        tier,
        product_id,
        occurred_at: Some(created_at),
        // order.paid always carries a checkout_id (enforced above).
        checkout_id: Some(checkout_id),
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

/// Handles `subscription.active` — first-time Team/Enterprise provision
/// or reconciliation for an existing subscription.
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

    let created_at = required_event_created_at(event)?;

    let (tier, tier_unknown) = resolve_tier(
        state,
        &sub_id,
        product_id.as_deref(),
        event_id,
        "subscription.active",
        &Some(created_at.clone()),
        event,
    )
    .await;

    let key_exists = state.db.has_api_key(&sub_id).await?;

    if key_exists {
        // Existing subscription: reconcile status and potentially un-revoke.
        let updated_data = UpdatedData {
            event_id: event_id.to_string(),
            event_type: "subscription.active".to_string(),
            subscription_id: sub_id.clone(),
            new_status: "active".to_string(),
            customer_id: Some(customer_id),
            email: Some(email),
            tier: tier.clone(),
            product_id: product_id.clone(),
            occurred_at: Some(created_at),
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
            UpdatedOutcome::StaleIgnored => {
                warn!(sub_id = %sub_id, "stale subscription.active ignored — older than last processed event, key state preserved");
            }
            UpdatedOutcome::Duplicate => {
                info!(event_id = %event_id, "duplicate event, skipped");
            }
            other => {
                info!(sub_id = %sub_id, outcome = ?other, "subscription.active — updated");
            }
        }
    } else {
        // New subscription — full provision path.
        let tier_str = match &tier {
            Some(t) => t.clone(),
            None => {
                // Unknown product → dead-letter, 500 so Polar retries.
                error!(
                    event_id = %event_id,
                    sub_id = %sub_id,
                    "subscription.active with unknown product, cannot provision"
                );
                record_dead_letter(
                    state,
                    DeadLetterData {
                        event_id: event_id.to_string(),
                        subscription_id: Some(sub_id.clone()),
                        event_type: "subscription.active".to_string(),
                        reason: "unresolvable_product".to_string(),
                        occurred_at: Some(created_at.clone()),
                        payload: redact_event(event),
                    },
                )
                .await;
                return Err(AppError::Internal("unknown product_id".into()));
            }
        };

        let creds = provision_credentials(state, &tier_str)?;

        let created_data = CreatedData {
            event_id: event_id.to_string(),
            event_type: "subscription.active".to_string(),
            subscription_id: sub_id.clone(),
            customer_id,
            email,
            tier: tier_str,
            product_id: product_id.unwrap_or_default(),
            occurred_at: Some(created_at),
            // None for checkout-less subscriptions — process_subscription_created
            // then skips the pending_receipts row instead of keying it by a
            // guessable id that /receipt/lookup could race.
            checkout_id,
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

/// Handles `subscription.canceled`. Benefits continue until period end,
/// so the API key is NOT revoked here.
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
            record_dead_letter(
                state,
                DeadLetterData {
                    event_id: event_id.to_string(),
                    subscription_id: None,
                    event_type: "subscription.canceled".to_string(),
                    reason: "missing_subscription_id".to_string(),
                    occurred_at: event
                        .get("created_at")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    payload: redact_event(event),
                },
            )
            .await;
            error!(event_id = %event_id, "canceled event missing subscription_id");
            return Ok(StatusCode::OK);
        }
    };

    let created_at = required_event_created_at(event)?;

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
        occurred_at: Some(created_at),
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

/// Handles `subscription.revoked` — terminal state, revokes the API key.
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
            record_dead_letter(
                state,
                DeadLetterData {
                    event_id: event_id.to_string(),
                    subscription_id: None,
                    event_type: "subscription.revoked".to_string(),
                    reason: "missing_subscription_id".to_string(),
                    occurred_at: event
                        .get("created_at")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    payload: redact_event(event),
                },
            )
            .await;
            error!(event_id = %event_id, "revoked event missing subscription_id");
            return Ok(StatusCode::OK);
        }
    };

    let created_at = required_event_created_at(event)?;

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
        occurred_at: Some(created_at),
    };

    let processed = state.db.process_subscription_revoked(revoked_data).await?;
    if processed {
        info!(sub_id = %sub_id, "subscription revoked — key revoked (terminal)");
    } else {
        info!(event_id = %event_id, "duplicate revoked event, skipped");
    }

    Ok(StatusCode::OK)
}

/// Handles `subscription.past_due` — payment failed, revokes the API key.
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

    let created_at = required_event_created_at(event)?;

    let product_id = json_str(data, "product_id");
    let (tier, tier_unknown) = resolve_tier(
        state,
        &sub_id,
        product_id.as_deref(),
        event_id,
        "subscription.past_due",
        &Some(created_at.clone()),
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
        occurred_at: Some(created_at),
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
        UpdatedOutcome::StaleIgnored => {
            warn!(sub_id = %sub_id, "stale subscription.past_due ignored — older than last processed event");
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

/// Handles `subscription.uncanceled` — a prior cancel was reversed, the
/// subscription is back to active.
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

    let created_at = required_event_created_at(event)?;

    let product_id = json_str(data, "product_id");
    let (tier, tier_unknown) = resolve_tier(
        state,
        &sub_id,
        product_id.as_deref(),
        event_id,
        "subscription.uncanceled",
        &Some(created_at.clone()),
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
        occurred_at: Some(created_at),
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
        UpdatedOutcome::StaleIgnored => {
            warn!(sub_id = %sub_id, "stale subscription.uncanceled ignored — older than last processed event, key state preserved");
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

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn json_str(val: &serde_json::Value, key: &str) -> Option<String> {
    val.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Lifecycle ordering is only safe when Polar supplies a parseable event
/// creation instant. The signed delivery timestamp proves freshness of the
/// HTTP message, not ordering of the underlying subscription event, so it
/// cannot substitute for this payload field.
fn required_event_created_at(event: &serde_json::Value) -> Result<String, AppError> {
    let raw = event
        .get("created_at")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::BadWebhook("missing created_at".into()))?;
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|timestamp| {
            timestamp
                .to_utc()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        })
        .map_err(|_| AppError::BadWebhook("invalid created_at".into()))
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
                record_dead_letter(
                    state,
                    DeadLetterData {
                        event_id: event_id.to_string(),
                        subscription_id: Some(sub_id.to_string()),
                        event_type: event_type.to_string(),
                        reason: "unresolvable_product".to_string(),
                        occurred_at: created_at.clone(),
                        payload: redact_event(event),
                    },
                )
                .await;
                (None, true)
            }
        },
        None => {
            warn!(
                sub_id = %sub_id,
                "no product_id in event — setting tier to unknown"
            );
            record_dead_letter(
                state,
                DeadLetterData {
                    event_id: event_id.to_string(),
                    subscription_id: Some(sub_id.to_string()),
                    event_type: event_type.to_string(),
                    reason: "unresolvable_product".to_string(),
                    occurred_at: created_at.clone(),
                    payload: redact_event(event),
                },
            )
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

/// Generate a fresh API key + signed token + receipt secret and return
/// the values the caller needs for DB insertion.
fn provision_credentials(state: &AppState, tier: &str) -> Result<ProvisionResult, AppError> {
    let mut api_key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut api_key_bytes);
    let api_key_raw = B64URL.encode(api_key_bytes);

    let mut hasher = Sha256::new();
    hasher.update(api_key_raw.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    let exp_ts = chrono::Utc::now().timestamp() + (state.config.token_ttl_days * 86400);
    let token = state.signer.sign_token(tier, exp_ts);

    let mut receipt_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut receipt_bytes);
    let receipt_secret = B64URL.encode(receipt_bytes);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_event_keeps_only_the_allowlisted_fields() {
        // The dead-letter payload is stored, so it must carry the operational
        // ids needed to retry and nothing else: no customer email, no API key,
        // no arbitrary nested data. This is the only thing standing between a
        // dropped event and a plaintext PII leak into the dead-letter table.
        let event = serde_json::json!({
            "type": "subscription.past_due",
            "created_at": "2024-01-01T00:00:00Z",
            "secret_top_level": "must-not-appear",
            "data": {
                "id": "sub_1",
                "status": "past_due",
                "product_id": "prod_1",
                "checkout_id": "chk_1",
                "customer_id": "cust_1",
                "customer": { "email": "victim@example.com" },
                "metadata": { "api_key": "sk_live_should_not_leak" },
                "raw_note": "free text that could hold anything"
            }
        });
        let redacted = redact_event(&event);
        let parsed: serde_json::Value = serde_json::from_str(&redacted).unwrap();

        assert_eq!(parsed["type"], "subscription.past_due");
        assert_eq!(parsed["created_at"], "2024-01-01T00:00:00Z");
        assert_eq!(parsed["data"]["id"], "sub_1");
        assert_eq!(parsed["data"]["status"], "past_due");
        assert_eq!(parsed["data"]["product_id"], "prod_1");
        assert_eq!(parsed["data"]["checkout_id"], "chk_1");
        assert_eq!(parsed["data"]["customer_id"], "cust_1");

        // Everything not on the allowlist is absent, checked structurally and
        // by substring so a future field addition cannot quietly leak.
        assert!(parsed["secret_top_level"].is_null());
        assert!(parsed["data"]["customer"].is_null());
        assert!(parsed["data"]["metadata"].is_null());
        assert!(parsed["data"]["raw_note"].is_null());
        assert!(
            !redacted.contains("victim@example.com"),
            "email leaked: {redacted}"
        );
        assert!(
            !redacted.contains("sk_live_should_not_leak"),
            "api key leaked: {redacted}"
        );
        assert!(
            !redacted.contains("free text"),
            "arbitrary data leaked: {redacted}"
        );
    }

    #[test]
    fn lifecycle_timestamp_is_required_and_must_be_rfc3339() {
        for event in [
            serde_json::json!({"type": "subscription.active"}),
            serde_json::json!({"type": "subscription.active", "created_at": null}),
            serde_json::json!({"type": "subscription.active", "created_at": ""}),
            serde_json::json!({"type": "subscription.active", "created_at": "not-a-time"}),
        ] {
            assert!(matches!(
                required_event_created_at(&event),
                Err(AppError::BadWebhook(_))
            ));
        }
    }

    #[test]
    fn lifecycle_timestamp_is_normalized_to_one_utc_encoding() {
        let event = serde_json::json!({
            "type": "subscription.active",
            "created_at": "2024-03-01T13:30:00+02:00"
        });
        assert_eq!(
            required_event_created_at(&event).unwrap(),
            "2024-03-01T11:30:00.000Z"
        );
    }
}
