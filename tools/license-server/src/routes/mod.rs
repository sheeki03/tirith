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
        .route("/receipt/{receipt_secret}", get(receipt::receipt_view))
        .route("/api/license/refresh", post(refresh::refresh))
}
