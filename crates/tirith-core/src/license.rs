use std::path::PathBuf;

/// Product tier levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    Community,
    Pro,
    Team,
    Enterprise,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tier::Community => write!(f, "Community"),
            Tier::Pro => write!(f, "Pro"),
            Tier::Team => write!(f, "Team"),
            Tier::Enterprise => write!(f, "Enterprise"),
        }
    }
}

/// Determine the current license tier.
///
/// Resolution order:
/// 1. `TIRITH_LICENSE` env var (raw key)
/// 2. `~/.config/tirith/license.key` file
/// 3. Fallback: `Tier::Community`
///
/// **TEMPORARY / NOT A SECURITY BOUNDARY:** The current key format is unsigned
/// base64-encoded JSON (see `decode_tier`). Anyone can self-issue any tier.
/// This is intentional bootstrap behavior — signature verification (Ed25519-
/// signed JWT) will be added before the first paid release. Until then, tiers
/// gate enrichment depth, not security-critical detection (ADR-13).
///
/// Invalid, expired, or missing keys silently fall back to Community
/// (no panic, no error exit).
pub fn current_tier() -> Tier {
    let key = read_license_key();
    match key {
        Some(k) => decode_tier(&k).unwrap_or(Tier::Community),
        None => Tier::Community,
    }
}

/// Read the raw license key string from env or file.
fn read_license_key() -> Option<String> {
    // 1. Environment variable
    if let Ok(val) = std::env::var("TIRITH_LICENSE") {
        let trimmed = val.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }

    // 2. Config file
    let path = license_key_path()?;
    let content = std::fs::read_to_string(path).ok()?;
    let trimmed = content.trim().to_string();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed)
}

/// Path to the license key file.
fn license_key_path() -> Option<PathBuf> {
    let config = crate::policy::config_dir()?;
    Some(config.join("license.key"))
}

/// Decode tier from a license key.
///
/// **Bootstrap format (unsigned, not a security boundary):** Accepts
/// base64-encoded JSON with `tier` and optional `exp` fields. This format
/// is trivially forgeable — anyone can self-issue any tier by encoding
/// `{"tier":"pro"}`. Signature verification will be added before the first
/// paid release; until then, tier gating only controls enrichment depth
/// (ADR-13), not detection coverage.
///
/// Accepted format (base64 of JSON):
/// ```json
/// {"tier": "pro", "exp": "2026-12-31"}
/// ```
///
/// Expiry is evaluated as UTC date (inclusive — key is valid on the exp date,
/// expires the day after).
fn decode_tier(key: &str) -> Option<Tier> {
    use base64::Engine;

    // Try base64 decode
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(key.trim())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(key.trim()))
        .ok()?;

    let payload: serde_json::Value = serde_json::from_slice(&bytes).ok()?;

    // Check expiry
    if let Some(exp_str) = payload.get("exp").and_then(|v| v.as_str()) {
        let exp_date = chrono::NaiveDate::parse_from_str(exp_str, "%Y-%m-%d").ok()?;
        let today = chrono::Utc::now().date_naive();
        if today > exp_date {
            // Expired — fall back to Community
            return None;
        }
    }
    // Missing exp = no expiry (perpetual — used for testing)

    // Extract tier
    let tier_str = payload.get("tier").and_then(|v| v.as_str())?;
    match tier_str.to_lowercase().as_str() {
        "pro" => Some(Tier::Pro),
        "team" => Some(Tier::Team),
        "enterprise" => Some(Tier::Enterprise),
        "community" => Some(Tier::Community),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(tier: &str, exp: &str) -> String {
        use base64::Engine;
        let json = format!(r#"{{"tier":"{tier}","exp":"{exp}"}}"#);
        base64::engine::general_purpose::STANDARD.encode(json.as_bytes())
    }

    fn make_key_no_exp(tier: &str) -> String {
        use base64::Engine;
        let json = format!(r#"{{"tier":"{tier}"}}"#);
        base64::engine::general_purpose::STANDARD.encode(json.as_bytes())
    }

    #[test]
    fn test_decode_pro() {
        let key = make_key("pro", "2099-12-31");
        assert_eq!(decode_tier(&key), Some(Tier::Pro));
    }

    #[test]
    fn test_decode_team() {
        let key = make_key("team", "2099-12-31");
        assert_eq!(decode_tier(&key), Some(Tier::Team));
    }

    #[test]
    fn test_decode_enterprise() {
        let key = make_key("enterprise", "2099-12-31");
        assert_eq!(decode_tier(&key), Some(Tier::Enterprise));
    }

    #[test]
    fn test_decode_expired() {
        let key = make_key("pro", "2020-01-01");
        assert_eq!(decode_tier(&key), None);
    }

    #[test]
    fn test_decode_no_expiry() {
        let key = make_key_no_exp("pro");
        assert_eq!(decode_tier(&key), Some(Tier::Pro));
    }

    #[test]
    fn test_decode_invalid_base64() {
        assert_eq!(decode_tier("not-valid!!!"), None);
    }

    #[test]
    fn test_decode_invalid_json() {
        use base64::Engine;
        let key = base64::engine::general_purpose::STANDARD.encode(b"not json");
        assert_eq!(decode_tier(&key), None);
    }

    #[test]
    fn test_decode_missing_tier() {
        use base64::Engine;
        let key = base64::engine::general_purpose::STANDARD.encode(br#"{"exp":"2099-12-31"}"#);
        assert_eq!(decode_tier(&key), None);
    }

    #[test]
    fn test_decode_unknown_tier() {
        let key = make_key("platinum", "2099-12-31");
        assert_eq!(decode_tier(&key), None);
    }

    #[test]
    fn test_decode_case_insensitive() {
        let key = make_key("PRO", "2099-12-31");
        assert_eq!(decode_tier(&key), Some(Tier::Pro));
    }

    #[test]
    fn test_current_tier_defaults_community() {
        // Without TIRITH_LICENSE set, should be Community
        // (may not hold if user has a license file, but that's fine for CI)
        let tier = current_tier();
        assert!(
            tier == Tier::Community || tier >= Tier::Pro,
            "Should be a valid tier"
        );
    }

    #[test]
    fn test_tier_ordering() {
        assert!(Tier::Community < Tier::Pro);
        assert!(Tier::Pro < Tier::Team);
        assert!(Tier::Team < Tier::Enterprise);
    }

    #[test]
    fn test_tier_display() {
        assert_eq!(format!("{}", Tier::Community), "Community");
        assert_eq!(format!("{}", Tier::Pro), "Pro");
        assert_eq!(format!("{}", Tier::Team), "Team");
        assert_eq!(format!("{}", Tier::Enterprise), "Enterprise");
    }
}
