use std::path::PathBuf;

use chrono::{DateTime, Utc};

/// Product tier levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Tier {
    Community,
    #[default]
    Pro,
    Team,
    Enterprise,
}

/// Extended license information parsed from a license token.
#[derive(Debug, Clone, Default)]
pub struct LicenseInfo {
    pub tier: Tier,
    /// Organization ID (typically present on Team+ SSO-provisioned keys).
    pub org_id: Option<String>,
    /// SSO provider used for provisioning (e.g., "okta", "azure-ad").
    pub sso_provider: Option<String>,
    /// Expiry date (ISO 8601 for legacy, Unix timestamp for signed).
    pub expires: Option<String>,
    /// Seat count for the organization (Team+).
    pub seat_count: Option<u32>,
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

/// Controls whether unsigned (legacy) tokens are accepted.
/// `Legacy`: both accepted (dev/testing). `SignedPreferred`: both accepted, but
/// `tirith doctor` warns on unsigned (v0.2.x). `SignedOnly`: unsigned rejected (v0.3.0+).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum EnforcementMode {
    Legacy,
    SignedPreferred,
    SignedOnly,
}

const ENFORCEMENT_MODE: EnforcementMode = EnforcementMode::SignedOnly;

struct KeyEntry {
    kid: &'static str,
    key: [u8; 32],
}

// Key rotation: generate a new Ed25519 keypair offline, append it here with
// the next kid, and stash the private key in your secret manager. See
// docs/threat-model.md for details.
const KEYRING: &[KeyEntry] = &[
    KeyEntry {
        kid: "k1",
        key: [
            111, 227, 28, 151, 67, 117, 194, 85, 167, 179, 224, 109, 45, 172, 183, 106, 78, 3, 55,
            72, 57, 216, 160, 134, 78, 190, 54, 236, 190, 16, 22, 9,
        ],
    },
    KeyEntry {
        kid: "k2",
        key: [
            141, 30, 243, 157, 5, 88, 251, 150, 7, 123, 244, 84, 164, 1, 186, 200, 23, 1, 149, 246,
            53, 6, 251, 131, 104, 197, 106, 24, 188, 149, 137, 237,
        ],
    },
];

// A build-time guard: the compiled keyring must never be empty. Clippy sees the
// current literal is non-empty (`const_is_empty`), but the assert exists to fail
// the build if someone later edits KEYRING down to nothing.
#[allow(clippy::const_is_empty)]
const _: () = assert!(!KEYRING.is_empty());

/// Maximum token length accepted before any parsing — DoS guard.
const MAX_TOKEN_LEN: usize = 8192;

/// Extract tier from a parsed JSON payload.
fn tier_from_payload(payload: &serde_json::Value) -> Option<Tier> {
    let tier_str = payload.get("tier").and_then(|v| v.as_str())?;
    match tier_str.to_lowercase().as_str() {
        "pro" => Some(Tier::Pro),
        "team" => Some(Tier::Team),
        "enterprise" => Some(Tier::Enterprise),
        "community" => Some(Tier::Community),
        _ => None,
    }
}

/// Extract full LicenseInfo from a parsed JSON payload.
fn license_info_from_payload(payload: &serde_json::Value, tier: Tier) -> LicenseInfo {
    let org_id = payload
        .get("org_id")
        .and_then(|v| v.as_str())
        .map(String::from);
    let sso_provider = payload
        .get("sso_provider")
        .and_then(|v| v.as_str())
        .map(String::from);
    let seat_count = payload
        .get("seat_count")
        .and_then(|v| v.as_u64())
        .and_then(|v| match u32::try_from(v) {
            Ok(n) => Some(n),
            Err(_) => {
                eprintln!("tirith: warning: seat_count {v} exceeds u32 range, ignoring");
                None
            }
        });

    // Legacy tokens store `exp` as ISO 8601, signed tokens as Unix timestamp.
    // Normalize to string for display.
    let expires = payload.get("exp").and_then(|v| {
        v.as_str()
            .map(|s| s.to_string())
            .or_else(|| v.as_i64().map(|n| n.to_string()))
    });

    LicenseInfo {
        tier,
        org_id,
        sso_provider,
        expires,
        seat_count,
    }
}

/// Decode a legacy unsigned base64 JSON payload, checking expiry against `now`.
fn decode_legacy_payload(key: &str, now: DateTime<Utc>) -> Option<serde_json::Value> {
    use base64::Engine;

    let trimmed = key.trim();

    // Same DoS size gate as the signed path.
    if trimmed.len() > MAX_TOKEN_LEN {
        return None;
    }

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .ok()?;

    let payload: serde_json::Value = serde_json::from_slice(&bytes).ok()?;

    // Legacy `exp` is an ISO 8601 date; comparison is inclusive (valid on the exp date).
    match payload.get("exp").and_then(|v| v.as_str()) {
        Some(exp_str) => match chrono::NaiveDate::parse_from_str(exp_str, "%Y-%m-%d") {
            Ok(exp_date) => {
                let today = now.date_naive();
                if today > exp_date {
                    return None;
                }
            }
            Err(_) => {
                eprintln!(
                        "tirith: warning: legacy license has unparseable exp date '{exp_str}', rejecting"
                    );
                return None;
            }
        },
        None => {
            // All tokens must carry an expiration date.
            return None;
        }
    }

    Some(payload)
}

/// Decode tier from a legacy unsigned key.
fn decode_tier_legacy(key: &str, now: DateTime<Utc>) -> Option<Tier> {
    let payload = decode_legacy_payload(key, now)?;
    let tier = tier_from_payload(&payload)?;
    // Unsigned tokens are capped at Pro; Team/Enterprise require signed tokens.
    Some(match tier {
        Tier::Team | Tier::Enterprise => Tier::Pro,
        other => other,
    })
}

/// Decode full license info from a legacy unsigned key.
fn decode_license_info_legacy(key: &str, now: DateTime<Utc>) -> Option<LicenseInfo> {
    let payload = decode_legacy_payload(key, now)?;
    let tier = tier_from_payload(&payload)?;
    // Unsigned tokens are capped at Pro.
    let tier = match tier {
        Tier::Team | Tier::Enterprise => Tier::Pro,
        other => other,
    };
    Some(license_info_from_payload(&payload, tier))
}

/// Decode and verify a signed token: `base64url(payload_json).base64url(ed25519_sig)`.
///
/// Returns the parsed payload JSON on success, None on any failure.
fn decode_signed_token(
    token: &str,
    keyring: &[KeyEntry],
    now: DateTime<Utc>,
) -> Option<serde_json::Value> {
    use base64::Engine;
    use ed25519_dalek::{Signature, VerifyingKey};

    let token = token.trim();

    if token.len() > MAX_TOKEN_LEN {
        return None;
    }

    let (payload_b64, sig_b64) = token.split_once('.')?;
    if payload_b64.is_empty() || sig_b64.is_empty() || sig_b64.contains('.') {
        return None;
    }

    // base64url, with or without padding.
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload_b64))
        .ok()?;

    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(sig_b64))
        .ok()?;
    let signature = Signature::from_slice(&sig_bytes).ok()?;

    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;

    // With kid: look up a specific key. Without kid: try every key; first hit wins.
    let kid = payload.get("kid").and_then(|v| v.as_str());
    let verified = if let Some(kid_val) = kid {
        let entry = keyring.iter().find(|e| e.kid == kid_val)?;
        let vk = VerifyingKey::from_bytes(&entry.key).ok()?;
        vk.verify_strict(&payload_bytes, &signature)
            .ok()
            .map(|_| ())
    } else {
        keyring.iter().find_map(|entry| {
            let vk = VerifyingKey::from_bytes(&entry.key).ok()?;
            vk.verify_strict(&payload_bytes, &signature).ok()
        })
    };
    verified?;

    if payload.get("iss").and_then(|v| v.as_str()) != Some("tirith.dev") {
        return None;
    }

    if payload.get("aud").and_then(|v| v.as_str()) != Some("tirith-cli") {
        return None;
    }

    // exp is required on signed tokens and must be an i64 Unix timestamp.
    // Wrong type → None (fail-closed), and comparison is exclusive.
    let exp = {
        let v = payload.get("exp")?;
        v.as_i64()?
    };
    if now.timestamp() >= exp {
        return None;
    }

    // nbf is optional; if present, it must be i64 (fail-closed on wrong type)
    // and the comparison is inclusive.
    if let Some(nbf_val) = payload.get("nbf") {
        let nbf = nbf_val.as_i64()?;
        if now.timestamp() < nbf {
            return None;
        }
    }

    Some(payload)
}

/// Core dispatch: a `.` routes one-way to the signed path (never falling back to
/// legacy on failure — a dot is never valid legacy base64); otherwise legacy,
/// subject to `mode`.
fn decode_tier_at_with_mode(
    key: &str,
    now: DateTime<Utc>,
    mode: EnforcementMode,
    keyring: &[KeyEntry],
) -> Option<Tier> {
    if key.contains('.') {
        let payload = decode_signed_token(key, keyring, now)?;
        return tier_from_payload(&payload);
    }

    if mode == EnforcementMode::SignedOnly {
        return None;
    }
    decode_tier_legacy(key, now)
}

/// Core dispatch for license info.
fn decode_license_info_at_with_mode(
    key: &str,
    now: DateTime<Utc>,
    mode: EnforcementMode,
    keyring: &[KeyEntry],
) -> Option<LicenseInfo> {
    if key.contains('.') {
        let payload = decode_signed_token(key, keyring, now)?;
        let tier = tier_from_payload(&payload)?;
        return Some(license_info_from_payload(&payload, tier));
    }

    if mode == EnforcementMode::SignedOnly {
        return None;
    }
    decode_license_info_legacy(key, now)
}

/// Decode tier at a specific time (uses compile-time ENFORCEMENT_MODE and KEYRING).
fn decode_tier_at(key: &str, now: DateTime<Utc>) -> Option<Tier> {
    decode_tier_at_with_mode(key, now, ENFORCEMENT_MODE, KEYRING)
}

/// Decode license info at a specific time.
fn decode_license_info_at(key: &str, now: DateTime<Utc>) -> Option<LicenseInfo> {
    decode_license_info_at_with_mode(key, now, ENFORCEMENT_MODE, KEYRING)
}

/// Determine the current license tier.
///
/// Resolution order: `TIRITH_LICENSE` env var, then `~/.config/tirith/license.key`,
/// then `Tier::Pro`. Verification uses Ed25519-signed tokens. Invalid, expired,
/// or missing keys silently fall back to Pro (no panic, no error exit). Runtime
/// feature gating is collapsed to an always-on Pro baseline; tier parsing
/// remains for token compatibility.
pub fn current_tier() -> Tier {
    match read_license_key() {
        Some(k) => decode_tier_at(&k, Utc::now()).unwrap_or_else(|| {
            crate::audit::audit_diagnostic(
                "tirith: warning: license key present but decode failed, falling back to Pro",
            );
            Tier::Pro
        }),
        None => Tier::Pro,
    }
}

/// Get extended license information including org_id and SSO provider.
pub fn license_info() -> LicenseInfo {
    match read_license_key() {
        Some(k) => decode_license_info_at(&k, Utc::now()).unwrap_or_else(|| {
            crate::audit::audit_diagnostic(
                "tirith: warning: license key present but decode failed for license info",
            );
            LicenseInfo::default()
        }),
        None => LicenseInfo::default(),
    }
}

/// Structural format of the installed license key. Lightweight check only — does
/// NOT verify signatures or claims. For `tirith doctor` diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormatStatus {
    NoKey,
    /// No `.`, valid base64, decodes to JSON with a "tier" field.
    LegacyUnsigned,
    /// No `.`, not valid base64 or missing "tier".
    LegacyInvalid,
    /// One `.`, two non-empty base64url segments. Signature/claims NOT verified.
    SignedStructural,
    /// Has `.` but malformed (empty segments, multiple dots).
    Malformed,
}

/// Check the structural format only — `SignedStructural` means the shape is
/// right, NOT that signature/claims/key are valid. Use `current_tier()` for that.
pub fn key_format_status() -> KeyFormatStatus {
    use base64::Engine;
    match read_license_key() {
        None => KeyFormatStatus::NoKey,
        Some(k) => {
            let trimmed = k.trim();
            if let Some((left, right)) = trimmed.split_once('.') {
                if left.is_empty() || right.is_empty() || right.contains('.') {
                    return KeyFormatStatus::Malformed;
                }
                let is_b64url = |s: &str| {
                    base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(s)
                        .is_ok()
                        || base64::engine::general_purpose::URL_SAFE.decode(s).is_ok()
                };
                if is_b64url(left) && is_b64url(right) {
                    KeyFormatStatus::SignedStructural
                } else {
                    KeyFormatStatus::Malformed
                }
            } else {
                // Legacy: valid base64 AND JSON carrying a "tier" field.
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(trimmed)
                    .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed));
                match bytes {
                    Ok(b) => {
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&b) {
                            if v.get("tier").and_then(|t| t.as_str()).is_some() {
                                KeyFormatStatus::LegacyUnsigned
                            } else {
                                KeyFormatStatus::LegacyInvalid
                            }
                        } else {
                            KeyFormatStatus::LegacyInvalid
                        }
                    }
                    Err(_) => KeyFormatStatus::LegacyInvalid,
                }
            }
        }
    }
}

/// Read the raw license key string from env or config file.
fn read_license_key() -> Option<String> {
    if let Ok(val) = std::env::var("TIRITH_LICENSE") {
        let trimmed = val.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }

    let path = license_key_path()?;
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let trimmed = content.trim().to_string();
            if trimmed.is_empty() {
                return None;
            }
            Some(trimmed)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            eprintln!(
                "tirith: warning: cannot read license key {}: {e}",
                path.display()
            );
            None
        }
    }
}

/// Path to the license key file.
pub fn license_key_path() -> Option<PathBuf> {
    let config = crate::policy::config_dir()?;
    Some(config.join("license.key"))
}

/// Validate that a token has the signed token structure: exactly one `.` separator
/// with both parts being valid base64url.
pub fn validate_key_structure(token: &str) -> bool {
    use base64::Engine;
    let trimmed = token.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_TOKEN_LEN {
        return false;
    }
    let Some((left, right)) = trimmed.split_once('.') else {
        return false;
    };
    if left.is_empty() || right.is_empty() || right.contains('.') {
        return false;
    }
    let is_b64url = |s: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .is_ok()
            || base64::engine::general_purpose::URL_SAFE.decode(s).is_ok()
    };
    is_b64url(left) && is_b64url(right)
}

/// Decode a signed token using the compile-time KEYRING and ENFORCEMENT_MODE.
/// Returns the LicenseInfo on success (valid signature, claims, and not expired).
pub fn decode_and_validate_token(token: &str) -> Option<LicenseInfo> {
    decode_license_info_at_with_mode(token, Utc::now(), ENFORCEMENT_MODE, KEYRING)
}

/// Refresh the license token from a remote policy server.
///
/// POSTs to `{server_url}/api/license/refresh` with Bearer auth and returns
/// the raw token string on success.
#[cfg(unix)]
pub fn refresh_from_server(server_url: &str, api_key: &str) -> Result<String, String> {
    crate::url_validate::validate_server_url(server_url)
        .map_err(|reason| format!("invalid server URL: {reason}"))?;

    let url = format!("{}/api/license/refresh", server_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .dns_resolver(crate::ssrf_guard::ssrf_guard_resolver())
        .timeout(std::time::Duration::from_secs(30))
        // F7: re-validate every redirect target and cap the hop count; the
        // implicit default would silently follow up to 10 hops into anywhere.
        .redirect(crate::ssrf_guard::server_redirect_policy())
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .map_err(|e| format!("Request failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().unwrap_or_default();
        return match status.as_u16() {
            401 | 403 => Err("Authentication failed. Check your API key.".to_string()),
            402 => Err("Subscription inactive. Renew at https://tirith.dev/account".to_string()),
            _ => Err(format!("Server returned {status}: {body}")),
        };
    }
    let token = resp
        .text()
        .map_err(|e| format!("Failed to read response: {e}"))?;
    let trimmed = token.trim().to_string();
    if trimmed.is_empty() {
        return Err("Server returned empty token".to_string());
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn test_keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk_bytes = sk.verifying_key().to_bytes();
        (sk, pk_bytes)
    }

    fn test_keyring(pk: [u8; 32]) -> Vec<KeyEntry> {
        vec![KeyEntry { kid: "k1", key: pk }]
    }

    fn make_signed_token(payload_json: &str, sk: &SigningKey) -> String {
        use base64::Engine;
        use ed25519_dalek::Signer;
        let payload_bytes = payload_json.as_bytes();
        let sig = sk.sign(payload_bytes);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_bytes);
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{payload_b64}.{sig_b64}")
    }

    fn make_payload(tier: &str, exp_ts: i64) -> String {
        format!(
            r#"{{"iss":"tirith.dev","aud":"tirith-cli","kid":"k1","tier":"{tier}","exp":{exp_ts}}}"#
        )
    }

    fn make_full_payload(tier: &str, exp_ts: i64, org_id: &str, sso: &str, seats: u32) -> String {
        format!(
            r#"{{"iss":"tirith.dev","aud":"tirith-cli","kid":"k1","tier":"{tier}","exp":{exp_ts},"org_id":"{org_id}","sso_provider":"{sso}","seat_count":{seats}}}"#
        )
    }

    fn future_ts() -> i64 {
        4070908800 // 2099-01-01 00:00:00 UTC
    }

    fn past_ts() -> i64 {
        1577836800 // 2020-01-01 00:00:00 UTC
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

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

    fn make_team_sso_key(org_id: &str, sso_provider: &str) -> String {
        use base64::Engine;
        let json = format!(
            r#"{{"tier":"team","exp":"2099-12-31","org_id":"{org_id}","sso_provider":"{sso_provider}","seat_count":50}}"#
        );
        base64::engine::general_purpose::STANDARD.encode(json.as_bytes())
    }

    #[test]
    fn test_decode_pro() {
        let key = make_key("pro", "2099-12-31");
        assert_eq!(
            decode_tier_at_with_mode(&key, now(), EnforcementMode::Legacy, KEYRING),
            Some(Tier::Pro)
        );
    }

    #[test]
    fn test_decode_team() {
        // Legacy unsigned tokens are capped at Pro.
        let key = make_key("team", "2099-12-31");
        assert_eq!(
            decode_tier_at_with_mode(&key, now(), EnforcementMode::Legacy, KEYRING),
            Some(Tier::Pro)
        );
    }

    #[test]
    fn test_decode_enterprise() {
        // Legacy unsigned tokens are capped at Pro.
        let key = make_key("enterprise", "2099-12-31");
        assert_eq!(
            decode_tier_at_with_mode(&key, now(), EnforcementMode::Legacy, KEYRING),
            Some(Tier::Pro)
        );
    }

    #[test]
    fn test_decode_expired() {
        let key = make_key("pro", "2020-01-01");
        assert_eq!(
            decode_tier_at_with_mode(&key, now(), EnforcementMode::Legacy, KEYRING),
            None
        );
    }

    #[test]
    fn test_decode_no_expiry() {
        // Tokens without `exp` are rejected.
        let key = make_key_no_exp("pro");
        assert_eq!(
            decode_tier_at_with_mode(&key, now(), EnforcementMode::Legacy, KEYRING),
            None
        );
    }

    #[test]
    fn test_decode_invalid_base64() {
        assert_eq!(
            decode_tier_at_with_mode("not-valid!!!", now(), EnforcementMode::Legacy, KEYRING),
            None
        );
    }

    #[test]
    fn test_decode_invalid_json() {
        use base64::Engine;
        let key = base64::engine::general_purpose::STANDARD.encode(b"not json");
        assert_eq!(
            decode_tier_at_with_mode(&key, now(), EnforcementMode::Legacy, KEYRING),
            None
        );
    }

    #[test]
    fn test_decode_missing_tier() {
        use base64::Engine;
        let key = base64::engine::general_purpose::STANDARD.encode(br#"{"exp":"2099-12-31"}"#);
        assert_eq!(
            decode_tier_at_with_mode(&key, now(), EnforcementMode::Legacy, KEYRING),
            None
        );
    }

    #[test]
    fn test_decode_unknown_tier() {
        let key = make_key("platinum", "2099-12-31");
        assert_eq!(
            decode_tier_at_with_mode(&key, now(), EnforcementMode::Legacy, KEYRING),
            None
        );
    }

    #[test]
    fn test_decode_case_insensitive() {
        let key = make_key("PRO", "2099-12-31");
        assert_eq!(
            decode_tier_at_with_mode(&key, now(), EnforcementMode::Legacy, KEYRING),
            Some(Tier::Pro)
        );
    }

    #[test]
    fn test_current_tier_defaults_pro() {
        let tier = current_tier();
        assert_eq!(tier, Tier::Pro);
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

    #[test]
    fn test_decode_license_info_team_sso() {
        // Legacy unsigned tokens are capped at Pro.
        let key = make_team_sso_key("org-acme-123", "okta");
        let info = decode_license_info_at_with_mode(&key, now(), EnforcementMode::Legacy, KEYRING)
            .unwrap();
        assert_eq!(info.tier, Tier::Pro);
        assert_eq!(info.org_id.as_deref(), Some("org-acme-123"));
        assert_eq!(info.sso_provider.as_deref(), Some("okta"));
        assert_eq!(info.seat_count, Some(50));
        assert_eq!(info.expires.as_deref(), Some("2099-12-31"));
    }

    #[test]
    fn test_decode_license_info_pro_no_sso() {
        let key = make_key("pro", "2099-12-31");
        let info = decode_license_info_at_with_mode(&key, now(), EnforcementMode::Legacy, KEYRING)
            .unwrap();
        assert_eq!(info.tier, Tier::Pro);
        assert!(info.org_id.is_none());
        assert!(info.sso_provider.is_none());
        assert!(info.seat_count.is_none());
    }

    #[test]
    fn test_decode_license_info_expired() {
        use base64::Engine;
        let json =
            r#"{"tier":"team","exp":"2020-01-01","org_id":"org-123","sso_provider":"azure-ad"}"#;
        let expired_key = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        assert!(decode_license_info_at_with_mode(
            &expired_key,
            now(),
            EnforcementMode::Legacy,
            KEYRING
        )
        .is_none());
    }

    #[test]
    fn test_license_info_default() {
        let info = LicenseInfo::default();
        assert_eq!(info.tier, Tier::Pro);
        assert!(info.org_id.is_none());
    }

    #[test]
    fn test_signed_pro() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let token = make_signed_token(&make_payload("pro", future_ts()), &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            Some(Tier::Pro)
        );
    }

    #[test]
    fn test_signed_team() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let token = make_signed_token(&make_payload("team", future_ts()), &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            Some(Tier::Team)
        );
    }

    #[test]
    fn test_signed_enterprise() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let token = make_signed_token(&make_payload("enterprise", future_ts()), &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            Some(Tier::Enterprise)
        );
    }

    #[test]
    fn test_signed_community() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let token = make_signed_token(&make_payload("community", future_ts()), &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            Some(Tier::Community)
        );
    }

    #[test]
    fn test_signed_wrong_key() {
        let (sk, _pk) = test_keypair();
        let (_sk2, pk2) = test_keypair();
        let kr = test_keyring(pk2); // Wrong key in keyring.
        let token = make_signed_token(&make_payload("pro", future_ts()), &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_signed_tampered_payload() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let token = make_signed_token(&make_payload("pro", future_ts()), &sk);
        // Flip the first char of the payload segment.
        let mut chars: Vec<char> = token.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        let tampered: String = chars.into_iter().collect();
        assert_eq!(
            decode_tier_at_with_mode(&tampered, now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_signed_tampered_signature() {
        use base64::Engine;
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let token = make_signed_token(&make_payload("pro", future_ts()), &sk);
        let (payload_part, _sig_part) = token.split_once('.').unwrap();
        // Replace the signature with zero bytes.
        let bad_sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 64]);
        let tampered = format!("{payload_part}.{bad_sig}");
        assert_eq!(
            decode_tier_at_with_mode(&tampered, now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_signed_wrong_iss() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let payload = format!(
            r#"{{"iss":"evil.com","aud":"tirith-cli","kid":"k1","tier":"pro","exp":{}}}"#,
            future_ts()
        );
        let token = make_signed_token(&payload, &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_signed_wrong_aud() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let payload = format!(
            r#"{{"iss":"tirith.dev","aud":"wrong-aud","kid":"k1","tier":"pro","exp":{}}}"#,
            future_ts()
        );
        let token = make_signed_token(&payload, &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_signed_expired() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let token = make_signed_token(&make_payload("pro", past_ts()), &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_signed_missing_exp() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let payload = r#"{"iss":"tirith.dev","aud":"tirith-cli","kid":"k1","tier":"pro"}"#;
        let token = make_signed_token(payload, &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_signed_nbf_future() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        // Still in the far future relative to now.
        let far_future_nbf = future_ts() - 1000;
        let payload = format!(
            r#"{{"iss":"tirith.dev","aud":"tirith-cli","kid":"k1","tier":"pro","exp":{},"nbf":{}}}"#,
            future_ts(),
            far_future_nbf
        );
        let token = make_signed_token(&payload, &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_legacy_works_in_signed_preferred() {
        let key = make_key("pro", "2099-12-31");
        assert_eq!(
            decode_tier_at_with_mode(&key, now(), EnforcementMode::SignedPreferred, KEYRING),
            Some(Tier::Pro)
        );
    }

    #[test]
    fn test_legacy_rejected_in_signed_only() {
        let key = make_key("pro", "2099-12-31");
        assert_eq!(
            decode_tier_at_with_mode(&key, now(), EnforcementMode::SignedOnly, KEYRING),
            None
        );
    }

    #[test]
    fn test_signed_license_info_full() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let payload = make_full_payload("team", future_ts(), "org-acme-123", "okta", 50);
        let token = make_signed_token(&payload, &sk);
        let info =
            decode_license_info_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr)
                .unwrap();
        assert_eq!(info.tier, Tier::Team);
        assert_eq!(info.org_id.as_deref(), Some("org-acme-123"));
        assert_eq!(info.sso_provider.as_deref(), Some("okta"));
        assert_eq!(info.seat_count, Some(50));
    }

    #[test]
    fn test_signed_license_info_expired() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let payload = make_full_payload("team", past_ts(), "org-123", "okta", 50);
        let token = make_signed_token(&payload, &sk);
        assert!(decode_license_info_at_with_mode(
            &token,
            now(),
            EnforcementMode::SignedPreferred,
            &kr,
        )
        .is_none());
    }

    #[test]
    fn test_kid_correct() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let token = make_signed_token(&make_payload("pro", future_ts()), &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            Some(Tier::Pro)
        );
    }

    #[test]
    fn test_kid_mismatch() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        // "k99" is not in the test keyring.
        let payload = format!(
            r#"{{"iss":"tirith.dev","aud":"tirith-cli","kid":"k99","tier":"pro","exp":{}}}"#,
            future_ts()
        );
        let token = make_signed_token(&payload, &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_no_kid_tries_all() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        // No kid field — decoder should try every key in the ring.
        let payload = format!(
            r#"{{"iss":"tirith.dev","aud":"tirith-cli","tier":"pro","exp":{}}}"#,
            future_ts()
        );
        let token = make_signed_token(&payload, &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            Some(Tier::Pro)
        );
    }

    #[test]
    fn test_parser_empty_segment_left() {
        let (_, pk) = test_keypair();
        let kr = test_keyring(pk);
        assert_eq!(
            decode_tier_at_with_mode(".sig", now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_parser_empty_segment_right() {
        let (_, pk) = test_keypair();
        let kr = test_keyring(pk);
        assert_eq!(
            decode_tier_at_with_mode("payload.", now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_parser_extra_segments() {
        let (_, pk) = test_keypair();
        let kr = test_keyring(pk);
        assert_eq!(
            decode_tier_at_with_mode("a.b.c", now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_parser_oversized_token() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        // Pad a valid token past MAX_TOKEN_LEN to exercise the DoS gate.
        let token = make_signed_token(&make_payload("pro", future_ts()), &sk);
        let oversized = format!("{token}{}", "A".repeat(MAX_TOKEN_LEN));
        assert_eq!(
            decode_tier_at_with_mode(&oversized, now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_parser_bad_nbf_type() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        // nbf as a string (not i64) must fail closed.
        let payload = format!(
            r#"{{"iss":"tirith.dev","aud":"tirith-cli","kid":"k1","tier":"pro","exp":{},"nbf":"not-a-number"}}"#,
            future_ts()
        );
        let token = make_signed_token(&payload, &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_parser_whitespace_only() {
        let (_, pk) = test_keypair();
        let kr = test_keyring(pk);
        assert_eq!(
            decode_tier_at_with_mode("   ", now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_parser_exp_exact_boundary() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        // exp comparison is exclusive, so exp == now means expired.
        let ts = now().timestamp();
        let token = make_signed_token(&make_payload("pro", ts), &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_parser_nbf_exact_boundary() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        // nbf comparison is inclusive, so nbf == now is valid.
        let ts = now().timestamp();
        let payload = format!(
            r#"{{"iss":"tirith.dev","aud":"tirith-cli","kid":"k1","tier":"pro","exp":{},"nbf":{}}}"#,
            future_ts(),
            ts
        );
        let token = make_signed_token(&payload, &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            Some(Tier::Pro)
        );
    }

    #[test]
    fn test_parser_malformed_base64url() {
        let (_, pk) = test_keypair();
        let kr = test_keyring(pk);
        assert_eq!(
            decode_tier_at_with_mode(
                "not!valid!b64.also!not!valid",
                now(),
                EnforcementMode::SignedPreferred,
                &kr
            ),
            None
        );
    }

    #[test]
    fn test_parser_padded_base64url_structural() {
        // Padded base64url must still parse as SignedStructural.
        use base64::Engine;
        let payload = r#"{"iss":"tirith.dev","aud":"tirith-cli","tier":"pro","exp":9999999999}"#;
        let payload_b64 = base64::engine::general_purpose::URL_SAFE.encode(payload.as_bytes());
        let fake_sig_b64 = base64::engine::general_purpose::URL_SAFE.encode([0u8; 64]);
        let token = format!("{payload_b64}.{fake_sig_b64}");
        assert!(token.contains('='));

        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_LICENSE", &token) };
        let status = key_format_status();
        unsafe { std::env::remove_var("TIRITH_LICENSE") };
        assert_eq!(
            status,
            KeyFormatStatus::SignedStructural,
            "Padded base64url token should be recognized as SignedStructural"
        );
    }

    #[test]
    fn test_enforcement_legacy_accepts_unsigned() {
        let key = make_key("pro", "2099-12-31");
        assert_eq!(
            decode_tier_at_with_mode(&key, now(), EnforcementMode::Legacy, KEYRING),
            Some(Tier::Pro)
        );
    }

    #[test]
    fn test_enforcement_signed_only_rejects_unsigned() {
        let key = make_key("pro", "2099-12-31");
        assert_eq!(
            decode_tier_at_with_mode(&key, now(), EnforcementMode::SignedOnly, KEYRING),
            None
        );
    }

    #[test]
    #[allow(clippy::const_is_empty)]
    fn test_keyring_non_empty() {
        // Compile-time assert above covers this too, but test it anyway.
        #[allow(clippy::const_is_empty)]
        let not_empty = !KEYRING.is_empty();
        assert!(not_empty);
    }

    #[test]
    fn test_keyring_no_duplicate_kids() {
        let mut kids: Vec<&str> = KEYRING.iter().map(|e| e.kid).collect();
        kids.sort();
        kids.dedup();
        assert_eq!(kids.len(), KEYRING.len(), "Duplicate kid values in KEYRING");
    }

    #[test]
    fn test_keyring_all_keys_valid() {
        for entry in KEYRING {
            assert!(
                ed25519_dalek::VerifyingKey::from_bytes(&entry.key).is_ok(),
                "Invalid public key for kid {}",
                entry.kid
            );
        }
    }

    /// Release CI runs this explicitly to make sure the compiled enforcement
    /// mode matches the release tag's semver expectations.
    #[test]
    #[ignore]
    fn enforcement_mode_matches_release_tag() {
        let tag = std::env::var("RELEASE_TAG").expect("RELEASE_TAG env var not set");
        let mode = match ENFORCEMENT_MODE {
            EnforcementMode::Legacy => "Legacy",
            EnforcementMode::SignedPreferred => "SignedPreferred",
            EnforcementMode::SignedOnly => "SignedOnly",
        };

        let version = tag
            .strip_prefix('v')
            .unwrap_or_else(|| panic!("RELEASE_TAG must start with 'v', got: {tag}"));
        let parts: Vec<&str> = version.split('.').collect();
        assert!(
            parts.len() >= 2,
            "RELEASE_TAG must be semver (vX.Y.Z), got: {tag}"
        );
        let major: u32 = parts[0]
            .parse()
            .unwrap_or_else(|_| panic!("Invalid major version in {tag}"));
        let minor: u32 = parts[1]
            .parse()
            .unwrap_or_else(|_| panic!("Invalid minor version in {tag}"));

        if major > 0 || minor >= 3 {
            assert_eq!(
                mode, "SignedOnly",
                "Release {tag} (>= v0.3) requires SignedOnly, found {mode}"
            );
        } else if minor == 2 {
            assert!(
                mode == "SignedPreferred" || mode == "SignedOnly",
                "Release {tag} (v0.2.x) requires SignedPreferred+, found {mode}"
            );
        } else if minor <= 1 {
            // v0.1.x is the transition period: Legacy or SignedPreferred are OK.
            assert!(
                mode == "Legacy" || mode == "SignedPreferred",
                "Release {tag} (v0.1.x) should use Legacy or SignedPreferred, found {mode}"
            );
        }
    }

    #[test]
    fn test_key_revocation_after_removal() {
        // Removing a key from the keyring must invalidate any token it signed.
        let (sk, pk) = test_keypair();
        let kr_with_key = test_keyring(pk);
        let token = make_signed_token(&make_payload("pro", future_ts()), &sk);

        assert_eq!(
            decode_tier_at_with_mode(
                &token,
                now(),
                EnforcementMode::SignedPreferred,
                &kr_with_key
            ),
            Some(Tier::Pro)
        );

        let kr_empty: Vec<KeyEntry> = vec![];
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr_empty),
            None,
            "Token must be rejected after signing key is removed from keyring"
        );
    }

    #[test]
    fn test_multi_key_kid_directed_lookup() {
        let (sk1, pk1) = test_keypair();
        let (sk2, pk2) = test_keypair();
        let kr = vec![
            KeyEntry {
                kid: "k1",
                key: pk1,
            },
            KeyEntry {
                kid: "k2",
                key: pk2,
            },
        ];

        // kid="k2" signed with sk2 → resolved directly via kid lookup.
        let payload = format!(
            r#"{{"iss":"tirith.dev","aud":"tirith-cli","kid":"k2","tier":"team","exp":{}}}"#,
            future_ts()
        );
        let token = make_signed_token(&payload, &sk2);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            Some(Tier::Team)
        );

        let token1 = make_signed_token(&make_payload("pro", future_ts()), &sk1);
        assert_eq!(
            decode_tier_at_with_mode(&token1, now(), EnforcementMode::SignedPreferred, &kr),
            Some(Tier::Pro)
        );

        // kid="k2" but actually signed with sk1 → verification fails, rejected.
        let wrong_kid_payload = format!(
            r#"{{"iss":"tirith.dev","aud":"tirith-cli","kid":"k2","tier":"pro","exp":{}}}"#,
            future_ts()
        );
        let wrong_kid_token = make_signed_token(&wrong_kid_payload, &sk1);
        assert_eq!(
            decode_tier_at_with_mode(
                &wrong_kid_token,
                now(),
                EnforcementMode::SignedPreferred,
                &kr
            ),
            None,
            "Token signed with k1 but kid=k2 must be rejected"
        );
    }

    #[test]
    fn test_signed_missing_iss() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let payload = format!(
            r#"{{"aud":"tirith-cli","kid":"k1","tier":"pro","exp":{}}}"#,
            future_ts()
        );
        let token = make_signed_token(&payload, &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            None,
            "Missing iss claim must be rejected"
        );
    }

    #[test]
    fn test_signed_missing_aud() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let payload = format!(
            r#"{{"iss":"tirith.dev","kid":"k1","tier":"pro","exp":{}}}"#,
            future_ts()
        );
        let token = make_signed_token(&payload, &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            None,
            "Missing aud claim must be rejected"
        );
    }

    #[test]
    fn test_signed_exp_as_string_rejected() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        // Signed tokens require `exp` as an i64 Unix timestamp, not an ISO string.
        let payload =
            r#"{"iss":"tirith.dev","aud":"tirith-cli","kid":"k1","tier":"pro","exp":"2099-12-31"}"#;
        let token = make_signed_token(payload, &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedPreferred, &kr),
            None,
            "Signed token with exp as string must be rejected"
        );
    }

    #[test]
    fn test_empty_string_token() {
        let (_, pk) = test_keypair();
        let kr = test_keyring(pk);
        assert_eq!(
            decode_tier_at_with_mode("", now(), EnforcementMode::SignedPreferred, &kr),
            None
        );
    }

    #[test]
    fn test_legacy_mode_accepts_signed() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let token = make_signed_token(&make_payload("pro", future_ts()), &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::Legacy, &kr),
            Some(Tier::Pro),
            "Legacy mode should accept valid signed tokens"
        );
    }

    #[test]
    fn test_signed_only_accepts_signed() {
        let (sk, pk) = test_keypair();
        let kr = test_keyring(pk);
        let token = make_signed_token(&make_payload("pro", future_ts()), &sk);
        assert_eq!(
            decode_tier_at_with_mode(&token, now(), EnforcementMode::SignedOnly, &kr),
            Some(Tier::Pro),
            "SignedOnly mode should accept valid signed tokens"
        );
    }
}
