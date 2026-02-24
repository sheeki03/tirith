use std::collections::HashMap;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Config {
    pub ed25519_seed_hex: String,
    pub polar_webhook_secret: String,
    pub polar_api_key: String,
    pub receipt_encryption_key: [u8; 32],
    pub product_tier_map: HashMap<String, String>,
    pub kid: String,
    pub token_ttl_days: i64,
    pub port: u16,
    pub database_url: String,
    pub receipt_base_url: Option<String>,
    pub trusted_proxy: bool,
    pub backup_r2_endpoint: Option<String>,
    pub backup_r2_bucket: Option<String>,
    pub backup_r2_access_key_id: Option<String>,
    pub backup_r2_secret_access_key: Option<String>,
}

impl Config {
    pub fn from_env() -> Self {
        let ed25519_seed_hex = required_env("ED25519_PRIVATE_KEY_HEX");
        assert!(
            ed25519_seed_hex.len() == 64,
            "ED25519_PRIVATE_KEY_HEX must be 64 hex chars (32 bytes)"
        );

        let polar_webhook_secret = required_env("POLAR_WEBHOOK_SECRET");
        let polar_api_key = required_env("POLAR_API_KEY");

        let enc_key_hex = required_env("RECEIPT_ENCRYPTION_KEY");
        let enc_key_bytes = hex::decode(&enc_key_hex).expect("RECEIPT_ENCRYPTION_KEY: invalid hex");
        assert!(
            enc_key_bytes.len() == 32,
            "RECEIPT_ENCRYPTION_KEY must be 32 bytes (64 hex chars)"
        );
        let mut receipt_encryption_key = [0u8; 32];
        receipt_encryption_key.copy_from_slice(&enc_key_bytes);

        // Map Polar product UUIDs to tier names
        let mut product_tier_map = HashMap::new();
        for (env_key, tier) in [
            ("POLAR_PRODUCT_PRO", "pro"),
            ("POLAR_PRODUCT_TEAM", "team"),
            ("POLAR_PRODUCT_ENTERPRISE", "enterprise"),
        ] {
            if let Ok(product_id) = std::env::var(env_key) {
                let product_id = product_id.trim().to_string();
                if !product_id.is_empty() {
                    product_tier_map.insert(product_id, tier.to_string());
                }
            }
        }

        let kid = std::env::var("KID")
            .unwrap_or_else(|_| "k2".to_string())
            .trim()
            .to_string();
        let token_ttl_days = std::env::var("TOKEN_TTL_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);
        let port = std::env::var("PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8080);
        let database_url =
            std::env::var("DATABASE_URL").unwrap_or_else(|_| "/data/tirith-license.db".to_string());
        let receipt_base_url = std::env::var("RECEIPT_BASE_URL").ok().map(|v| {
            let v = v.trim().to_string();
            if v.is_empty() {
                panic!("RECEIPT_BASE_URL is set but empty")
            }
            v
        });
        let trusted_proxy = std::env::var("TRUSTED_PROXY")
            .map(|v| v.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let backup_r2_endpoint = optional_env("BACKUP_R2_ENDPOINT");
        let backup_r2_bucket = optional_env("BACKUP_R2_BUCKET");
        let backup_r2_access_key_id = optional_env("BACKUP_R2_ACCESS_KEY_ID");
        let backup_r2_secret_access_key = optional_env("BACKUP_R2_SECRET_ACCESS_KEY");

        Config {
            ed25519_seed_hex,
            polar_webhook_secret,
            polar_api_key,
            receipt_encryption_key,
            product_tier_map,
            kid,
            token_ttl_days,
            port,
            database_url,
            receipt_base_url,
            trusted_proxy,
            backup_r2_endpoint,
            backup_r2_bucket,
            backup_r2_access_key_id,
            backup_r2_secret_access_key,
        }
    }

    pub fn tier_for_product(&self, product_id: &str) -> Option<&str> {
        self.product_tier_map.get(product_id).map(|s| s.as_str())
    }
}

fn required_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("missing required env var: {key}"))
}

fn optional_env(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|v| {
        let v = v.trim().to_string();
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    })
}
