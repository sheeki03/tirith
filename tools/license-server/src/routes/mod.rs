pub mod health;
pub mod receipt;
pub mod refresh;
pub mod webhook;

use axum::routing::{get, post};
use axum::Router;

use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health::health))
        .route("/api/polar/webhook", post(webhook::webhook))
        .route("/receipt/lookup", get(receipt::receipt_lookup))
        // `get` also handles HEAD in axum. Both methods only confirm that the
        // receipt is available; the explicit POST is the sole consuming route.
        .route(
            "/receipt/{receipt_secret}",
            get(receipt::receipt_confirmation).post(receipt::receipt_consume),
        )
        .route("/api/license/refresh", post(refresh::refresh))
}
