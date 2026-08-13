use tirith_core::license;

#[cfg(unix)]
struct RefreshCredentials {
    server_url: String,
    api_key: String,
}

/// Resolve refresh credentials as one origin-bound pair.
///
/// If either environment variable is present, both values must come from the
/// environment; an empty or non-Unicode value is still an explicit (invalid)
/// override and never falls back to policy. With no overrides, `load_local` is
/// invoked exactly once so the URL and key come from one offline policy
/// snapshot.
#[cfg(unix)]
fn resolve_refresh_credentials_with<F>(
    env_server_url: Option<std::ffi::OsString>,
    env_api_key: Option<std::ffi::OsString>,
    load_local: F,
) -> Result<RefreshCredentials, String>
where
    F: FnOnce() -> tirith_core::policy::Policy,
{
    match (env_server_url, env_api_key) {
        (None, None) => {
            let policy = load_local();
            normalize_refresh_pair(
                policy.policy_server_url,
                policy.policy_server_api_key,
                "local policy",
            )
        }
        (Some(server_url), Some(api_key)) => {
            let server_url = server_url
                .into_string()
                .map_err(|_| "TIRITH_SERVER_URL must be valid UTF-8".to_string())?;
            let api_key = api_key
                .into_string()
                .map_err(|_| "TIRITH_API_KEY must be valid UTF-8".to_string())?;
            normalize_refresh_pair(Some(server_url), Some(api_key), "environment")
        }
        _ => Err(
            "TIRITH_SERVER_URL and TIRITH_API_KEY must be set together; refusing to mix environment and policy credentials"
                .to_string(),
        ),
    }
}

#[cfg(unix)]
fn normalize_refresh_pair(
    server_url: Option<String>,
    api_key: Option<String>,
    origin: &str,
) -> Result<RefreshCredentials, String> {
    let (server_url, api_key) = match (server_url, api_key) {
        (Some(server_url), Some(api_key)) => (server_url, api_key),
        (None, None) => {
            return Err(format!(
                "no policy-server credentials configured in the {origin}"
            ));
        }
        _ => {
            return Err(format!(
                "the {origin} must provide both policy_server_url and policy_server_api_key"
            ));
        }
    };

    let server_url = server_url.trim();
    if server_url.is_empty() {
        return Err(format!("the {origin} server URL must not be empty"));
    }
    let api_key = api_key.trim();
    if api_key.is_empty() {
        return Err(format!("the {origin} API key must not be empty"));
    }

    Ok(RefreshCredentials {
        server_url: server_url.to_string(),
        api_key: api_key.to_string(),
    })
}

#[cfg(unix)]
fn resolve_refresh_credentials() -> Result<RefreshCredentials, String> {
    resolve_refresh_credentials_with(
        std::env::var_os("TIRITH_SERVER_URL"),
        std::env::var_os("TIRITH_API_KEY"),
        || tirith_core::policy::Policy::discover_local_only(None),
    )
}

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
        // repo-0222: atomic publish — a crash or full disk mid-write must not
        // destroy the previously valid license key.
        if let Err(e) = tirith_core::util::write_file_atomic_0600(&path, key.trim().as_bytes()) {
            eprintln!("tirith: cannot write license key: {e}");
            return 1;
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

    eprintln!("License key removed. Baseline features remain available.");
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
        let credentials = match resolve_refresh_credentials() {
            Ok(credentials) => credentials,
            Err(reason) => {
                eprintln!("tirith: cannot refresh license: {reason}");
                eprintln!(
                    "  Set both TIRITH_SERVER_URL and TIRITH_API_KEY, or configure both fields in one trusted local policy."
                );
                return 1;
            }
        };

        match license::refresh_from_server(&credentials.server_url, &credentials.api_key) {
            Ok(token) => {
                let info = match license::decode_and_validate_token(&token) {
                    Some(info) => info,
                    None => {
                        eprintln!("tirith: server returned invalid token");
                        return 1;
                    }
                };

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
                    // repo-0222: atomic publish — a crash mid-write must not
                    // destroy the previously valid license key.
                    if let Err(e) =
                        tirith_core::util::write_file_atomic_0600(&path, token.trim().as_bytes())
                    {
                        eprintln!("tirith: cannot write license key: {e}");
                        return 1;
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

/// Format an expiry string (Unix timestamp or ISO 8601) for display.
fn format_expiry(exp: &str) -> String {
    if let Ok(ts) = exp.parse::<i64>() {
        if let Some(dt) = chrono::DateTime::from_timestamp(ts, 0) {
            return dt.format("%Y-%m-%d %H:%M UTC").to_string();
        }
    }
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
    if let Ok(date) = chrono::NaiveDate::parse_from_str(exp, "%Y-%m-%d") {
        let today = now.date_naive();
        return Some((date - today).num_days());
    }
    None
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn environment_credentials_are_an_indivisible_pair() {
        for (server_url, api_key) in [
            (Some(OsString::from("https://policy.example")), None),
            (None, Some(OsString::from("secret"))),
        ] {
            let result = resolve_refresh_credentials_with(server_url, api_key, || {
                panic!("a partial environment override must not load policy")
            });
            assert!(result
                .err()
                .expect("partial environment pair must fail")
                .contains("must be set together"));
        }
    }

    #[test]
    fn complete_environment_pair_never_loads_policy() {
        let credentials = resolve_refresh_credentials_with(
            Some(OsString::from(" https://policy.example ")),
            Some(OsString::from(" env-secret ")),
            || panic!("a complete environment override must not load policy"),
        )
        .unwrap();

        assert_eq!(credentials.server_url, "https://policy.example");
        assert_eq!(credentials.api_key, "env-secret");
    }

    #[test]
    fn empty_environment_value_never_falls_back_to_policy() {
        let result = resolve_refresh_credentials_with(
            Some(OsString::new()),
            Some(OsString::from("env-secret")),
            || panic!("an explicit empty override must not load policy"),
        );

        assert_eq!(
            result.err().expect("empty override must fail"),
            "the environment server URL must not be empty"
        );
    }

    #[test]
    fn local_credentials_come_from_one_snapshot() {
        let loads = AtomicUsize::new(0);
        let credentials = resolve_refresh_credentials_with(None, None, || {
            loads.fetch_add(1, Ordering::SeqCst);
            tirith_core::policy::Policy {
                policy_server_url: Some("https://local.example".to_string()),
                policy_server_api_key: Some("local-secret".to_string()),
                ..tirith_core::policy::Policy::default()
            }
        })
        .unwrap();

        assert_eq!(loads.load(Ordering::SeqCst), 1);
        assert_eq!(credentials.server_url, "https://local.example");
        assert_eq!(credentials.api_key, "local-secret");
    }

    #[test]
    fn incomplete_local_pair_is_rejected() {
        let result = resolve_refresh_credentials_with(None, None, || tirith_core::policy::Policy {
            policy_server_url: Some("https://local.example".to_string()),
            policy_server_api_key: None,
            ..tirith_core::policy::Policy::default()
        });

        assert!(result
            .err()
            .expect("incomplete local pair must fail")
            .contains("must provide both"));
    }

    #[test]
    fn non_unicode_environment_value_is_rejected_without_policy_fallback() {
        use std::os::unix::ffi::OsStringExt;

        let result = resolve_refresh_credentials_with(
            Some(OsString::from_vec(vec![0xff])),
            Some(OsString::from("env-secret")),
            || panic!("an invalid explicit override must not load policy"),
        );

        assert_eq!(
            result.err().expect("non-Unicode override must fail"),
            "TIRITH_SERVER_URL must be valid UTF-8"
        );
    }
}
