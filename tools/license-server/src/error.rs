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
    /// Rate limit exceeded (constructed by the refresh route).
    RateLimited,
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
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"),
        };
        // The client body is deliberately generic (no internal detail leaks to
        // the caller), but the detail is the only record of WHY a request
        // failed. A 500 with the body "Internal server error" and no log line
        // is an unresolvable incident. Log the full error here, once, at a
        // level matched to severity: a 5xx is an error, a 4xx is a warning.
        // The `Display` impl carries the internal message.
        if status.is_server_error() {
            tracing::error!(status = %status.as_u16(), detail = %self, "request failed");
        } else {
            tracing::warn!(status = %status.as_u16(), detail = %self, "request rejected");
        }
        (status, body.to_string()).into_response()
    }
}
