use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub struct PaddleSignature {
    pub timestamp: String,
    pub hash: String,
}

impl PaddleSignature {
    pub fn parse(header: &str) -> Option<Self> {
        let mut ts = None;
        let mut h1 = None;
        for part in header.split(';') {
            if let Some(val) = part.strip_prefix("ts=") {
                ts = Some(val.to_string());
            } else if let Some(val) = part.strip_prefix("h1=") {
                h1 = Some(val.to_string());
            }
        }
        Some(PaddleSignature {
            timestamp: ts?,
            hash: h1?,
        })
    }
}

pub fn verify_webhook(
    secret: &str,
    raw_body: &[u8],
    signature: &PaddleSignature,
    max_age_secs: i64,
) -> Result<(), WebhookError> {
    // Replay protection
    let ts: i64 = signature
        .timestamp
        .parse()
        .map_err(|_| WebhookError::InvalidTimestamp)?;
    let now = chrono::Utc::now().timestamp();
    if (now - ts).abs() > max_age_secs {
        return Err(WebhookError::TimestampExpired);
    }

    // HMAC-SHA256: key=secret, msg=ts_bytes + ":" + raw_body_bytes
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| WebhookError::InvalidSecret)?;
    mac.update(signature.timestamp.as_bytes());
    mac.update(b":");
    mac.update(raw_body);

    let expected = mac.finalize().into_bytes();
    let provided = hex::decode(&signature.hash).map_err(|_| WebhookError::InvalidHash)?;

    // Constant-time comparison
    if expected.as_slice() != provided.as_slice() {
        return Err(WebhookError::SignatureMismatch);
    }

    Ok(())
}

#[derive(Debug)]
pub enum WebhookError {
    InvalidTimestamp,
    TimestampExpired,
    InvalidSecret,
    InvalidHash,
    SignatureMismatch,
}

impl std::fmt::Display for WebhookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTimestamp => write!(f, "invalid timestamp"),
            Self::TimestampExpired => write!(f, "timestamp expired"),
            Self::InvalidSecret => write!(f, "invalid webhook secret"),
            Self::InvalidHash => write!(f, "invalid hash format"),
            Self::SignatureMismatch => write!(f, "signature mismatch"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign_body(secret: &str, body: &[u8], ts: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(ts.as_bytes());
        mac.update(b":");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn test_valid_signature() {
        let secret = "test-secret-key";
        let body = b"test body content";
        let ts = chrono::Utc::now().timestamp().to_string();
        let hash = sign_body(secret, body, &ts);
        let sig = PaddleSignature {
            timestamp: ts,
            hash,
        };
        assert!(verify_webhook(secret, body, &sig, 300).is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let body = b"test body";
        let ts = chrono::Utc::now().timestamp().to_string();
        let hash = sign_body("correct-secret", body, &ts);
        let sig = PaddleSignature {
            timestamp: ts,
            hash,
        };
        let result = verify_webhook("wrong-secret", body, &sig, 300);
        assert!(matches!(result, Err(WebhookError::SignatureMismatch)));
    }

    #[test]
    fn test_expired_timestamp() {
        let secret = "test-secret";
        let body = b"body";
        let old_ts = (chrono::Utc::now().timestamp() - 600).to_string();
        let hash = sign_body(secret, body, &old_ts);
        let sig = PaddleSignature {
            timestamp: old_ts,
            hash,
        };
        let result = verify_webhook(secret, body, &sig, 300);
        assert!(matches!(result, Err(WebhookError::TimestampExpired)));
    }

    #[test]
    fn test_parse_paddle_signature() {
        let sig = PaddleSignature::parse("ts=1234567890;h1=abcdef0123456789").unwrap();
        assert_eq!(sig.timestamp, "1234567890");
        assert_eq!(sig.hash, "abcdef0123456789");
    }

    #[test]
    fn test_parse_missing_parts() {
        assert!(PaddleSignature::parse("ts=123").is_none());
        assert!(PaddleSignature::parse("h1=abc").is_none());
    }
}
