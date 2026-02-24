use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug)]
pub enum AppError {
    /// HMAC verification failure or replay protection
    Unauthorized(String),
    /// Bad webhook payload (permanent parse failure)
    BadWebhook(String),
    /// Subscription inactive (402)
    PaymentRequired(String),
    /// Rate limit exceeded (used by rate-limiting middleware)
    #[allow(dead_code)]
    RateLimited,
    /// Not found (receipt expired, etc.)
    NotFound(String),
    /// Internal server error (DB, signing, transient)
    Internal(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized(msg) => write!(f, "unauthorized: {msg}"),
            Self::BadWebhook(msg) => write!(f, "bad webhook: {msg}"),
            Self::PaymentRequired(msg) => write!(f, "payment required: {msg}"),
            Self::RateLimited => write!(f, "rate limited"),
            Self::NotFound(msg) => write!(f, "not found: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, body) = match &self {
            Self::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            Self::BadWebhook(_) => (StatusCode::BAD_REQUEST, "Bad request"),
            Self::PaymentRequired(msg) => (StatusCode::PAYMENT_REQUIRED, msg.as_str()),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "Too many requests"),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg.as_str()),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        };
        (status, body.to_string()).into_response()
    }
}
