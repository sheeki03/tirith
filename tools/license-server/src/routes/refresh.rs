use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use sha2::{Digest, Sha256};
use tracing::error;

use crate::db::RefreshPublishOutcome;
use crate::error::AppError;
use crate::state::AppState;

pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let api_key = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| AppError::Unauthorized("missing or invalid Authorization header".into()))?;

    if api_key.is_empty() {
        return Err(AppError::Unauthorized("empty API key".into()));
    }

    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    let sub_id = state.db.lookup_api_key(&key_hash).await?.ok_or_else(|| {
        AppError::Unauthorized("Authentication failed. Check your API key.".into())
    })?;

    let sub = state.db.get_subscription(&sub_id).await?.ok_or_else(|| {
        error!(sub_id = %sub_id, "api_key references missing subscription");
        AppError::Internal("subscription not found".into())
    })?;

    // Match the atomic publication gate: trials have benefits, and canceled
    // subscriptions keep them until the provider sends period-end revocation.
    if !matches!(sub.status.as_str(), "active" | "trialing" | "canceled") {
        return Err(AppError::PaymentRequired(
            "Subscription inactive. Renew at https://tirith.dev/account".into(),
        ));
    }

    // Fail closed on any unknown/invalid tier.
    match sub.tier.as_str() {
        "pro" | "team" | "enterprise" => {}
        other => {
            error!(
                sub_id = %sub.id,
                tier = %other,
                "invalid tier, cannot sign token"
            );
            return Err(AppError::Internal(
                "License configuration error. Contact support@tirith.dev".into(),
            ));
        }
    }

    // repo-0449: per-subscription issuance interval. Every refresh signs a new
    // Ed25519 token and INSERTs a row retained ~90 days past expiry, so an
    // unthrottled loop could exhaust disk and contend on the DB mutex. 60s is
    // far below any legitimate CLI refresh cadence.
    const MIN_REFRESH_INTERVAL_SECS: i64 = 60;
    let exp_ts = chrono::Utc::now().timestamp() + (state.config.token_ttl_days * 86400);
    let token = state.signer.sign_token(&sub.tier, exp_ts);

    // The throttle check and token publication are one atomic database
    // operation. Signing can happen speculatively, but only the single winner
    // is persisted and returned; every parallel loser is rate-limited.
    match state
        .db
        .publish_refresh_token_if_authorized(
            &key_hash,
            &sub.id,
            &sub.tier,
            &token,
            exp_ts,
            MIN_REFRESH_INTERVAL_SECS,
        )
        .await?
    {
        RefreshPublishOutcome::Inserted => {}
        RefreshPublishOutcome::RateLimited => return Err(AppError::RateLimited),
        RefreshPublishOutcome::NotAuthorized => {
            return Err(AppError::Unauthorized(
                "Authentication or subscription state changed. Retry with an active API key."
                    .into(),
            ));
        }
    }

    Ok((
        StatusCode::OK,
        [
            ("content-type", "text/plain"),
            ("cache-control", "no-store"),
            ("pragma", "no-cache"),
            ("x-content-type-options", "nosniff"),
        ],
        token,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    use base64::Engine as _;

    use crate::config::Config;
    use crate::db::{CreatedData, CreatedOutcome, Db, UpdatedData};
    use crate::sign::TokenSigner;

    const API_KEY: &str = "tirith_refresh_route_test_key";

    async fn test_state(status: &str, tier: &str) -> AppState {
        let config = Config {
            ed25519_seed_hex: "11".repeat(32),
            polar_webhook_secret: "whsec_test".into(),
            polar_api_key: "polar_test".into(),
            receipt_encryption_key: [7; 32],
            product_tier_map: HashMap::new(),
            kid: "test".into(),
            token_ttl_days: 30,
            port: 0,
            database_url: ":memory:".into(),
            receipt_base_url: None,
            trusted_proxy: false,
            backup_r2_endpoint: None,
            backup_r2_bucket: None,
            backup_r2_access_key_id: None,
            backup_r2_secret_access_key: None,
        };
        let db = Db::open(":memory:").unwrap();
        assert!(matches!(
            db.process_subscription_created(CreatedData {
                event_id: "evt_refresh_created".into(),
                event_type: "subscription.active".into(),
                subscription_id: "sub_refresh".into(),
                customer_id: "customer_refresh".into(),
                email: "refresh@example.invalid".into(),
                tier: tier.into(),
                product_id: "product_refresh".into(),
                occurred_at: Some("2026-01-01T00:00:00Z".into()),
                checkout_id: None,
                key_hash: hex::encode(Sha256::digest(API_KEY.as_bytes())),
                token: None,
                token_expires_at: 0,
                receipt_secret: "unused".into(),
                api_key_enc: vec![],
                api_key_nonce: vec![],
            })
            .await
            .unwrap(),
            CreatedOutcome::Provisioned
        ));
        if status != "active" {
            db.process_subscription_updated(UpdatedData {
                event_id: "evt_refresh_updated".into(),
                event_type: "subscription.updated".into(),
                subscription_id: "sub_refresh".into(),
                new_status: status.into(),
                customer_id: None,
                email: None,
                tier: None,
                product_id: None,
                occurred_at: Some("2026-01-02T00:00:00Z".into()),
                resolved_tier: Some(tier.into()),
                tier_unknown: false,
            })
            .await
            .unwrap();
        }
        AppState {
            db,
            signer: Arc::new(
                TokenSigner::from_hex_seed(&config.ed25519_seed_hex, config.kid.clone()).unwrap(),
            ),
            config: Arc::new(config),
            http_client: reqwest::Client::new(),
        }
    }

    async fn request(state: AppState, authorization: Option<&str>) -> axum::response::Response {
        let mut headers = HeaderMap::new();
        if let Some(value) = authorization {
            headers.insert("authorization", value.parse().unwrap());
        }
        refresh(State(state), headers).await.into_response()
    }

    #[tokio::test]
    async fn refresh_route_issues_valid_tokens_for_entitled_subscriptions() {
        for status in ["active", "trialing", "canceled"] {
            let state = test_state(status, "team").await;
            let response = request(state.clone(), Some(&format!("Bearer {API_KEY}"))).await;
            assert_eq!(response.status(), StatusCode::OK, "status={status}");
            assert_eq!(response.headers()["cache-control"], "no-store");
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let token = std::str::from_utf8(&body).unwrap();
            let (payload, signature) = token.split_once('.').unwrap();
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let payload = b64.decode(payload).unwrap();
            let signature =
                ed25519_dalek::Signature::from_slice(&b64.decode(signature).unwrap()).unwrap();
            ed25519_dalek::SigningKey::from_bytes(&[0x11; 32])
                .verifying_key()
                .verify_strict(&payload, &signature)
                .unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(payload["tier"], "team");
            assert!(payload["exp"].as_i64().unwrap() > chrono::Utc::now().timestamp());

            // The route must have persisted the issuance through the atomic
            // authorization/throttle check, not merely returned a signed token.
            let repeated = request(state, Some(&format!("Bearer {API_KEY}"))).await;
            assert_eq!(repeated.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }

    #[tokio::test]
    async fn refresh_route_rejects_revoked_or_inactive_subscriptions() {
        for status in ["revoked", "past_due", "unrecognized_status"] {
            let state = test_state(status, "team").await;
            let response = request(state, Some(&format!("Bearer {API_KEY}"))).await;
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "status={status}"
            );
        }
    }

    #[tokio::test]
    async fn refresh_route_rejects_invalid_credentials_and_tiers() {
        let state = test_state("active", "team").await;
        for authorization in [
            None,
            Some("Bearer "),
            Some("Basic key"),
            Some("Bearer invalid"),
        ] {
            let response = request(state.clone(), authorization).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        let state = test_state("active", "unrecognized_tier").await;
        let response = request(state, Some(&format!("Bearer {API_KEY}"))).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
