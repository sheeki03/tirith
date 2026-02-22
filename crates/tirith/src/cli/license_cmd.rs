use tirith_core::license;

/// Activate a license by validating and writing the signed token.
pub fn activate(key: &str) -> i32 {
    if !license::validate_key_structure(key) {
        eprintln!("tirith: invalid license key format");
        eprintln!("  Expected a signed token (base64url.base64url)");
        return 1;
    }

    let info = match license::decode_and_validate_token(key) {
        Some(info) => info,
        None => {
            eprintln!("tirith: license key validation failed");
            eprintln!(
                "  The token signature is invalid, the key is expired, or the issuer is wrong."
            );
            return 1;
        }
    };

    // Write the token to the license key file
    let path = match license::license_key_path() {
        Some(p) => p,
        None => {
            eprintln!("tirith: cannot determine config directory");
            return 1;
        }
    };

    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("tirith: cannot create config directory: {e}");
            return 1;
        }
    }

    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        match opts.open(&path) {
            Ok(mut f) => {
                if let Err(e) = f.write_all(key.trim().as_bytes()) {
                    eprintln!("tirith: cannot write license key: {e}");
                    return 1;
                }
            }
            Err(e) => {
                eprintln!("tirith: cannot write license key: {e}");
                return 1;
            }
        }
    }

    eprintln!("License activated successfully.");
    eprintln!();
    print_license_info(&info);
    0
}

/// Show current license status.
pub fn show(json: bool) -> i32 {
    let info = license::license_info();

    if json {
        print_license_json(&info);
    } else if info.tier == license::Tier::Community {
        // Check if there's actually a key file
        if license::license_key_path()
            .map(|p| p.exists())
            .unwrap_or(false)
        {
            eprintln!("License: Community (free) — installed key is invalid or expired");
        } else {
            eprintln!("License: Community (free)");
            eprintln!("  Run 'tirith activate <key>' to activate a license.");
        }
    } else {
        print_license_info(&info);
    }
    0
}

/// Deactivate the current license (remove the key file).
pub fn deactivate() -> i32 {
    let path = match license::license_key_path() {
        Some(p) => p,
        None => {
            eprintln!("tirith: cannot determine config directory");
            return 1;
        }
    };

    if !path.exists() {
        eprintln!("No license key installed.");
        return 0;
    }

    if let Err(e) = std::fs::remove_file(&path) {
        eprintln!("tirith: cannot remove license key: {e}");
        return 1;
    }

    eprintln!("License deactivated. Tier reverted to Community (free).");
    0
}

/// Refresh the license token from the policy server.
pub fn refresh() -> i32 {
    #[cfg(not(unix))]
    {
        eprintln!("tirith: license refresh is only supported on Unix");
        return 1;
    }

    #[cfg(unix)]
    {
        // Read server URL and API key from env or policy config
        let server_url = std::env::var("TIRITH_SERVER_URL").ok().or_else(|| {
            let policy = tirith_core::policy::Policy::discover(None);
            policy.policy_server_url
        });
        let api_key = std::env::var("TIRITH_API_KEY").ok().or_else(|| {
            let policy = tirith_core::policy::Policy::discover(None);
            policy.policy_server_api_key
        });

        let server_url = match server_url {
            Some(u) if !u.trim().is_empty() => u,
            _ => {
                eprintln!("tirith: no policy server configured");
                eprintln!("  Set TIRITH_SERVER_URL or configure policy_server_url in policy.yaml");
                return 1;
            }
        };
        let api_key = match api_key {
            Some(k) if !k.trim().is_empty() => k,
            _ => {
                eprintln!("tirith: no API key configured");
                eprintln!("  Set TIRITH_API_KEY or configure policy_server_api_key in policy.yaml");
                return 1;
            }
        };

        match license::refresh_from_server(&server_url, &api_key) {
            Ok(token) => {
                // Validate the new token
                let info = match license::decode_and_validate_token(&token) {
                    Some(info) => info,
                    None => {
                        eprintln!("tirith: server returned invalid token");
                        return 1;
                    }
                };

                // Write token
                let path = match license::license_key_path() {
                    Some(p) => p,
                    None => {
                        eprintln!("tirith: cannot determine config directory");
                        return 1;
                    }
                };

                if let Some(parent) = path.parent() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        eprintln!("tirith: cannot create config directory: {e}");
                        return 1;
                    }
                }

                {
                    use std::io::Write;
                    let mut opts = std::fs::OpenOptions::new();
                    opts.write(true).create(true).truncate(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::OpenOptionsExt;
                        opts.mode(0o600);
                    }
                    match opts.open(&path) {
                        Ok(mut f) => {
                            if let Err(e) = f.write_all(token.trim().as_bytes()) {
                                eprintln!("tirith: cannot write license key: {e}");
                                return 1;
                            }
                        }
                        Err(e) => {
                            eprintln!("tirith: cannot write license key: {e}");
                            return 1;
                        }
                    }
                }

                eprintln!("License refreshed successfully.");
                eprintln!();
                print_license_info(&info);
                0
            }
            Err(e) => {
                eprintln!("tirith: refresh failed: {e}");
                1
            }
        }
    }
}

fn print_license_info(info: &license::LicenseInfo) {
    eprintln!("  Tier:       {}", info.tier);
    if let Some(ref org) = info.org_id {
        eprintln!("  Org:        {org}");
    }
    if let Some(seats) = info.seat_count {
        eprintln!("  Seats:      {seats}");
    }
    if let Some(ref exp) = info.expires {
        eprintln!("  Expires:    {}", format_expiry(exp));
        if let Some(days) = days_remaining(exp) {
            if days <= 30 {
                eprintln!("  Remaining:  {days} day(s)");
            }
        }
    }
}

fn print_license_json(info: &license::LicenseInfo) {
    let mut map = serde_json::Map::new();
    map.insert(
        "tier".to_string(),
        serde_json::Value::String(info.tier.to_string()),
    );
    if let Some(ref org) = info.org_id {
        map.insert("org_id".to_string(), serde_json::Value::String(org.clone()));
    }
    if let Some(seats) = info.seat_count {
        map.insert(
            "seat_count".to_string(),
            serde_json::Value::Number(seats.into()),
        );
    }
    if let Some(ref exp) = info.expires {
        map.insert(
            "expires".to_string(),
            serde_json::Value::String(exp.clone()),
        );
        if let Some(days) = days_remaining(exp) {
            map.insert(
                "days_remaining".to_string(),
                serde_json::Value::Number(days.into()),
            );
        }
    }
    let val = serde_json::Value::Object(map);
    if serde_json::to_writer_pretty(std::io::stdout().lock(), &val).is_err() {
        eprintln!("tirith: failed to write JSON output");
    }
    println!();
}

/// Format an expiry string for display.
/// Handles both Unix timestamps and ISO 8601 date strings.
fn format_expiry(exp: &str) -> String {
    if let Ok(ts) = exp.parse::<i64>() {
        if let Some(dt) = chrono::DateTime::from_timestamp(ts, 0) {
            return dt.format("%Y-%m-%d %H:%M UTC").to_string();
        }
    }
    // Already a date string
    exp.to_string()
}

/// Calculate days remaining from an expiry string.
fn days_remaining(exp: &str) -> Option<i64> {
    let now = chrono::Utc::now();
    if let Ok(ts) = exp.parse::<i64>() {
        let exp_dt = chrono::DateTime::from_timestamp(ts, 0)?;
        let delta = exp_dt.signed_duration_since(now);
        return Some(delta.num_days());
    }
    // ISO 8601 date
    if let Ok(date) = chrono::NaiveDate::parse_from_str(exp, "%Y-%m-%d") {
        let today = now.date_naive();
        return Some((date - today).num_days());
    }
    None
}

/// Check license expiry and print a warning if it's within 7 days.
/// Called from check.rs after printing the verdict.
pub fn warn_if_expiring_soon() {
    let info = license::license_info();
    if info.tier < license::Tier::Pro {
        return;
    }
    if let Some(ref exp) = info.expires {
        if let Some(days) = days_remaining(exp) {
            if days <= 7 {
                eprintln!(
                    "tirith: License expires in {days} day(s). Run 'tirith license refresh' to renew."
                );
            }
        }
    }
}
