use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};

const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

pub struct TokenSigner {
    sk: SigningKey,
    kid: String,
}

impl TokenSigner {
    pub fn from_hex_seed(hex: &str, kid: String) -> Result<Self, String> {
        let seed_bytes = hex::decode(hex).map_err(|e| format!("invalid hex seed: {e}"))?;
        if seed_bytes.len() != 32 {
            return Err(format!(
                "invalid seed: expected 32 bytes, got {}",
                seed_bytes.len()
            ));
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed_bytes);
        let sk = SigningKey::from_bytes(&seed_arr);
        Ok(Self { sk, kid })
    }

    pub fn sign_token(&self, tier: &str, exp_ts: i64) -> String {
        self.sign_token_full(tier, exp_ts, None, None, None)
    }

    pub fn sign_token_full(
        &self,
        tier: &str,
        exp_ts: i64,
        org_id: Option<&str>,
        sso: Option<&str>,
        seats: Option<u32>,
    ) -> String {
        let mut payload = serde_json::json!({
            "iss": "tirith.dev",
            "aud": "tirith-cli",
            "kid": self.kid,
            "tier": tier,
            "exp": exp_ts,
        });

        if let Some(org) = org_id {
            payload["org_id"] = serde_json::json!(org);
        }
        if let Some(sso) = sso {
            payload["sso_provider"] = serde_json::json!(sso);
        }
        if let Some(seats) = seats {
            payload["seat_count"] = serde_json::json!(seats);
        }

        let payload_json = serde_json::to_string(&payload).expect("serialize payload");
        let payload_bytes = payload_json.as_bytes();

        let sig = self.sk.sign(payload_bytes);

        let payload_b64 = B64URL.encode(payload_bytes);
        let sig_b64 = B64URL.encode(sig.to_bytes());
        format!("{payload_b64}.{sig_b64}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let seed_hex: String = sk.to_bytes().iter().map(|b| format!("{b:02x}")).collect();

        let signer = TokenSigner::from_hex_seed(&seed_hex, "k2".into()).unwrap();
        let token = signer.sign_token("pro", 4070908800);

        let (p_b64, s_b64) = token.split_once('.').unwrap();
        let p_bytes = B64URL.decode(p_b64).unwrap();
        let s_bytes = B64URL.decode(s_b64).unwrap();

        let sig = ed25519_dalek::Signature::from_slice(&s_bytes).unwrap();
        let vk = sk.verifying_key();
        assert!(vk.verify_strict(&p_bytes, &sig).is_ok());

        let payload: serde_json::Value = serde_json::from_slice(&p_bytes).unwrap();
        assert_eq!(payload["iss"], "tirith.dev");
        assert_eq!(payload["aud"], "tirith-cli");
        assert_eq!(payload["kid"], "k2");
        assert_eq!(payload["tier"], "pro");
        assert_eq!(payload["exp"], 4070908800_i64);
    }

    #[test]
    fn test_sign_token_full() {
        let sk = SigningKey::generate(&mut OsRng);
        let seed_hex: String = sk.to_bytes().iter().map(|b| format!("{b:02x}")).collect();

        let signer = TokenSigner::from_hex_seed(&seed_hex, "k2".into()).unwrap();
        let token =
            signer.sign_token_full("team", 4070908800, Some("org-1"), Some("okta"), Some(5));

        let (p_b64, _) = token.split_once('.').unwrap();
        let p_bytes = B64URL.decode(p_b64).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&p_bytes).unwrap();
        assert_eq!(payload["tier"], "team");
        assert_eq!(payload["org_id"], "org-1");
        assert_eq!(payload["sso_provider"], "okta");
        assert_eq!(payload["seat_count"], 5);
    }

    #[test]
    fn test_invalid_seed() {
        assert!(TokenSigner::from_hex_seed("not-hex", "k1".into()).is_err());
        assert!(TokenSigner::from_hex_seed("aabb", "k1".into()).is_err()); // too short
    }
}
