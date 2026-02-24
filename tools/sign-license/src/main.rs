//! tirith-sign — Internal license token signing tool.
//!
//! NOT distributed to end users. Used by the operator to:
//! 1. Generate Ed25519 keypairs for the compile-time KEYRING
//! 2. Sign license tokens for customers after purchase
//! 3. Inspect tokens (decode payload without signature verification)

use std::io::Read;
use std::path::PathBuf;

use base64::Engine;
use chrono::NaiveDate;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};

const B64URL: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Parser)]
#[command(name = "tirith-sign", about = "Sign tirith license tokens")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new Ed25519 keypair.
    ///
    /// Writes the 32-byte private seed to a file (mode 0600).
    /// Prints the public key as a Rust byte-array literal for KEYRING.
    Keygen {
        /// Output file for the private key seed (32 bytes, hex-encoded).
        #[arg(short, long, default_value = "tirith-sign.key")]
        output: PathBuf,

        /// Key ID to assign (e.g. "k1", "k2").
        #[arg(long, default_value = "k1")]
        kid: String,
    },

    /// Sign a license token.
    ///
    /// Reads the private key seed from a file and produces a signed token
    /// in the format: base64url(payload_json).base64url(ed25519_sig)
    Sign {
        /// Path to the private key seed file (hex-encoded, from keygen).
        #[arg(short, long)]
        key: PathBuf,

        /// Key ID matching the public key in the KEYRING (e.g. "k1").
        #[arg(long, default_value = "k1")]
        kid: String,

        /// License tier: community, pro, team, enterprise.
        #[arg(short, long)]
        tier: String,

        /// Expiry date (YYYY-MM-DD) or Unix timestamp.
        #[arg(short, long)]
        expires: String,

        /// Organization ID (Team/Enterprise).
        #[arg(long)]
        org_id: Option<String>,

        /// SSO provider (e.g. "okta", "azure-ad").
        #[arg(long)]
        sso_provider: Option<String>,

        /// Seat count (Team/Enterprise).
        #[arg(long)]
        seat_count: Option<u32>,

        /// Not-before date (YYYY-MM-DD) or Unix timestamp.
        #[arg(long)]
        nbf: Option<String>,
    },

    /// Inspect a token (decode payload without verifying signature).
    ///
    /// Reads token from argument or stdin.
    Inspect {
        /// The token to inspect (or pass via stdin).
        token: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Keygen { output, kid } => cmd_keygen(&output, &kid),
        Commands::Sign {
            key,
            kid,
            tier,
            expires,
            org_id,
            sso_provider,
            seat_count,
            nbf,
        } => cmd_sign(
            &key,
            &kid,
            &tier,
            &expires,
            org_id,
            sso_provider,
            seat_count,
            nbf,
        ),
        Commands::Inspect { token } => cmd_inspect(token),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn cmd_keygen(output: &PathBuf, kid: &str) -> Result<(), String> {
    use rand_core::OsRng;

    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();
    let seed = sk.to_bytes();

    // Write seed as hex to file
    let hex_seed: String = seed.iter().map(|b| format!("{b:02x}")).collect();

    // Write with restricted permissions
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(output)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    format!(
                        "{} already exists — refusing to overwrite private key",
                        output.display()
                    )
                } else {
                    format!("cannot create {}: {e}", output.display())
                }
            })?;
        f.write_all(hex_seed.as_bytes())
            .map_err(|e| format!("write failed: {e}"))?;
    }

    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    format!(
                        "{} already exists — refusing to overwrite private key",
                        output.display()
                    )
                } else {
                    format!("cannot create {}: {e}", output.display())
                }
            })?;
        f.write_all(hex_seed.as_bytes())
            .map_err(|e| format!("write failed: {e}"))?;
    }

    eprintln!("Private key seed written to: {}", output.display());
    eprintln!("KEEP THIS FILE SECRET. Do not commit it to version control.\n");

    // Print public key as Rust array literal for KEYRING
    let pk_bytes = pk.to_bytes();
    println!("// Add this to KEYRING in crates/tirith-core/src/license.rs:");
    println!("KeyEntry {{");
    println!("    kid: \"{kid}\",");
    print!("    key: [");
    for (i, b) in pk_bytes.iter().enumerate() {
        if i % 20 == 0 {
            print!("\n        ");
        }
        print!("{b}");
        if i < 31 {
            print!(", ");
        }
    }
    println!("\n    ],");
    println!("}}\n");

    // Also print as hex for reference
    let pk_hex: String = pk_bytes.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!("Public key (hex): {pk_hex}");

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_sign(
    key_path: &PathBuf,
    kid: &str,
    tier: &str,
    expires: &str,
    org_id: Option<String>,
    sso_provider: Option<String>,
    seat_count: Option<u32>,
    nbf: Option<String>,
) -> Result<(), String> {
    // Validate tier
    let tier_lower = tier.to_lowercase();
    match tier_lower.as_str() {
        "community" | "pro" | "team" | "enterprise" => {}
        _ => {
            return Err(format!(
                "invalid tier '{tier}' — use: community, pro, team, enterprise"
            ))
        }
    }

    // Parse expiry → Unix timestamp
    let exp_ts = parse_timestamp(expires)?;

    // Parse nbf if provided
    let nbf_ts = match &nbf {
        Some(s) => Some(parse_timestamp(s)?),
        None => None,
    };

    // Read private key seed
    let hex_seed = std::fs::read_to_string(key_path)
        .map_err(|e| format!("cannot read key file {}: {e}", key_path.display()))?;
    let seed_bytes = hex_to_bytes(hex_seed.trim())?;
    if seed_bytes.len() != 32 {
        return Err(format!(
            "invalid key: expected 32 bytes, got {}",
            seed_bytes.len()
        ));
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed_bytes);
    let sk = SigningKey::from_bytes(&seed_arr);

    // Build payload JSON
    let mut payload = serde_json::json!({
        "iss": "tirith.dev",
        "aud": "tirith-cli",
        "kid": kid,
        "tier": tier_lower,
        "exp": exp_ts,
    });

    if let Some(ref org) = org_id {
        payload["org_id"] = serde_json::json!(org);
    }
    if let Some(ref sso) = sso_provider {
        payload["sso_provider"] = serde_json::json!(sso);
    }
    if let Some(seats) = seat_count {
        payload["seat_count"] = serde_json::json!(seats);
    }
    if let Some(nbf) = nbf_ts {
        payload["nbf"] = serde_json::json!(nbf);
    }

    let payload_json = serde_json::to_string(&payload).map_err(|e| format!("serialize: {e}"))?;
    let payload_bytes = payload_json.as_bytes();

    // Sign
    let sig = sk.sign(payload_bytes);

    // Encode
    let payload_b64 = B64URL.encode(payload_bytes);
    let sig_b64 = B64URL.encode(sig.to_bytes());
    let token = format!("{payload_b64}.{sig_b64}");

    println!("{token}");

    // Print summary to stderr
    let exp_dt = chrono::DateTime::from_timestamp(exp_ts, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| exp_ts.to_string());
    eprintln!("\nToken issued:");
    eprintln!("  tier:    {tier_lower}");
    eprintln!("  kid:     {kid}");
    eprintln!("  expires: {exp_dt} (ts: {exp_ts})");
    if let Some(ref org) = org_id {
        eprintln!("  org_id:  {org}");
    }
    if let Some(ref sso) = sso_provider {
        eprintln!("  sso:     {sso}");
    }
    if let Some(seats) = seat_count {
        eprintln!("  seats:   {seats}");
    }
    eprintln!("\nActivate with: tirith activate <token>");

    // Verify round-trip
    let vk = sk.verifying_key();
    let (p_b64, s_b64) = token.split_once('.').unwrap();
    let p_bytes = B64URL.decode(p_b64).unwrap();
    let s_bytes = B64URL.decode(s_b64).unwrap();
    let sig_check = ed25519_dalek::Signature::from_slice(&s_bytes).unwrap();
    if vk.verify_strict(&p_bytes, &sig_check).is_ok() {
        eprintln!("Signature verified (round-trip OK)");
    } else {
        return Err("FATAL: round-trip signature verification failed".to_string());
    }

    Ok(())
}

fn cmd_inspect(token_arg: Option<String>) -> Result<(), String> {
    let token = match token_arg {
        Some(t) => t,
        None => {
            // Read from stdin
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("failed to read stdin: {e}"))?;
            buf
        }
    };
    let token = token.trim();

    if token.is_empty() {
        return Err("no token provided".to_string());
    }

    let (payload_b64, sig_b64) = token
        .split_once('.')
        .ok_or("not a signed token (no '.' separator)")?;

    if payload_b64.is_empty() || sig_b64.is_empty() {
        return Err("malformed token (empty segment)".to_string());
    }

    let payload_bytes = B64URL
        .decode(payload_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload_b64))
        .map_err(|_| "invalid base64url in payload segment")?;

    let sig_bytes = B64URL
        .decode(sig_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(sig_b64))
        .map_err(|_| "invalid base64url in signature segment")?;

    let payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("invalid JSON payload: {e}"))?;

    // Pretty-print payload
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).unwrap_or_else(|_| format!("{payload:?}"))
    );

    // Summary
    println!("\n--- Summary ---");
    if let Some(tier) = payload.get("tier").and_then(|v| v.as_str()) {
        println!("Tier:    {tier}");
    }
    if let Some(kid) = payload.get("kid").and_then(|v| v.as_str()) {
        println!("Key ID:  {kid}");
    }
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) {
        let exp_dt = chrono::DateTime::from_timestamp(exp, 0)
            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| exp.to_string());
        let now = chrono::Utc::now().timestamp();
        let status = if now >= exp { "EXPIRED" } else { "valid" };
        println!("Expires: {exp_dt} ({status})");
    }
    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64()) {
        let nbf_dt = chrono::DateTime::from_timestamp(nbf, 0)
            .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| nbf.to_string());
        println!("Not before: {nbf_dt}");
    }
    if let Some(org) = payload.get("org_id").and_then(|v| v.as_str()) {
        println!("Org ID:  {org}");
    }
    if let Some(sso) = payload.get("sso_provider").and_then(|v| v.as_str()) {
        println!("SSO:     {sso}");
    }
    if let Some(seats) = payload.get("seat_count").and_then(|v| v.as_u64()) {
        println!("Seats:   {seats}");
    }

    println!("Sig len: {} bytes", sig_bytes.len());
    if sig_bytes.len() == 64 {
        println!("Sig fmt: Ed25519 (64 bytes, correct)");
    } else {
        println!(
            "Sig fmt: UNEXPECTED ({} bytes, expected 64)",
            sig_bytes.len()
        );
    }

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────

/// Parse a date string (YYYY-MM-DD) or Unix timestamp into i64.
fn parse_timestamp(s: &str) -> Result<i64, String> {
    // Try Unix timestamp first
    if let Ok(ts) = s.parse::<i64>() {
        return Ok(ts);
    }

    // Try YYYY-MM-DD → end of day UTC
    let date = NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .map_err(|_| format!("invalid date/timestamp '{s}' — use YYYY-MM-DD or Unix timestamp"))?;
    let dt = date
        .and_hms_opt(23, 59, 59)
        .ok_or_else(|| format!("invalid date: {s}"))?;
    Ok(dt.and_utc().timestamp())
}

/// Decode hex string to bytes.
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("hex string has odd length".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| format!("invalid hex at position {i}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_parse_timestamp_unix() {
        assert_eq!(parse_timestamp("1735689599").unwrap(), 1735689599);
    }

    #[test]
    fn test_parse_timestamp_date() {
        let ts = parse_timestamp("2025-12-31").unwrap();
        // Should be 2025-12-31 23:59:59 UTC
        let dt = chrono::DateTime::from_timestamp(ts, 0).unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2025-12-31");
    }

    #[test]
    fn test_parse_timestamp_invalid() {
        assert!(parse_timestamp("not-a-date").is_err());
    }

    #[test]
    fn test_hex_roundtrip() {
        let bytes = vec![0u8, 255, 128, 1];
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex_to_bytes(&hex).unwrap(), bytes);
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();

        let payload = serde_json::json!({
            "iss": "tirith.dev",
            "aud": "tirith-cli",
            "kid": "k1",
            "tier": "pro",
            "exp": 4070908800_i64,
        });
        let payload_json = serde_json::to_string(&payload).unwrap();
        let payload_bytes = payload_json.as_bytes();

        let sig = sk.sign(payload_bytes);
        let payload_b64 = B64URL.encode(payload_bytes);
        let sig_b64 = B64URL.encode(sig.to_bytes());
        let token = format!("{payload_b64}.{sig_b64}");

        // Verify
        let (p, s) = token.split_once('.').unwrap();
        let p_bytes = B64URL.decode(p).unwrap();
        let s_bytes = B64URL.decode(s).unwrap();
        let sig_check = ed25519_dalek::Signature::from_slice(&s_bytes).unwrap();
        assert!(vk.verify_strict(&p_bytes, &sig_check).is_ok());
    }

    #[test]
    fn test_token_matches_license_rs_format() {
        // Verify the token format matches what license.rs expects:
        // base64url(payload_json).base64url(ed25519_sig)
        let sk = SigningKey::generate(&mut OsRng);

        let payload =
            r#"{"iss":"tirith.dev","aud":"tirith-cli","kid":"k1","tier":"pro","exp":4070908800}"#;
        let payload_bytes = payload.as_bytes();
        let sig = sk.sign(payload_bytes);

        let payload_b64 = B64URL.encode(payload_bytes);
        let sig_b64 = B64URL.encode(sig.to_bytes());
        let token = format!("{payload_b64}.{sig_b64}");

        // Token must have exactly one dot
        assert_eq!(token.matches('.').count(), 1);

        // Both segments must be non-empty
        let (left, right) = token.split_once('.').unwrap();
        assert!(!left.is_empty());
        assert!(!right.is_empty());

        // Signature must be 64 bytes when decoded
        let sig_decoded = B64URL.decode(right).unwrap();
        assert_eq!(sig_decoded.len(), 64);
    }
}
