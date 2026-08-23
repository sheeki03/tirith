use tirith_core::license;

const LICENSE_FILE_READ_CAP: u64 = 1024 * 1024;

fn retained_license_root(path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    let absolute = std::path::absolute(path)?;
    for ancestor in absolute.ancestors().skip(1) {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_dir() => return Ok(ancestor.to_path_buf()),
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "license path has no existing directory ancestor",
    ))
}

fn write_license_key_with_policy(
    path: &std::path::Path,
    contents: &[u8],
    policy: &tirith_core::policy::Policy,
) -> std::io::Result<()> {
    let root = retained_license_root(path)?;
    // The shared helper performs its pure task-gate preflight before creating
    // the config directory or taking the retained parent mutation lock.
    let destination =
        super::prepare_config_destination_permitted(&root, path, true, policy, false, true)?;
    match destination.read_capped(LICENSE_FILE_READ_CAP) {
        Ok(_) | Err(tirith_core::util::OpenRegularError::NotFound) => {}
        Err(error) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("cannot inspect existing license key: {error:?}"),
            ));
        }
    }
    super::write_prepared_config_file_permitted(
        &root,
        path,
        destination,
        contents,
        true,
        policy,
        false,
    )
}

fn delete_license_key_with_policy(
    path: &std::path::Path,
    policy: &tirith_core::policy::Policy,
) -> std::io::Result<bool> {
    let root = retained_license_root(path)?;
    let destination = match super::prepare_config_destination_permitted(
        &root, path, true, policy, false, false,
    ) {
        Ok(destination) => destination,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let contents = match destination.read_capped(LICENSE_FILE_READ_CAP) {
        Ok(contents) => contents,
        Err(tirith_core::util::OpenRegularError::NotFound) => return Ok(false),
        Err(error) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("cannot inspect existing license key: {error:?}"),
            ));
        }
    };
    super::delete_prepared_config_file_permitted(
        &root,
        path,
        destination,
        &contents,
        policy,
        false,
    )?;
    Ok(true)
}

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

    let policy = tirith_core::policy::Policy::discover_local_only(None);
    if let Err(e) = write_license_key_with_policy(&path, key.trim().as_bytes(), &policy) {
        eprintln!("tirith: cannot write license key: {e}");
        return 1;
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

    let policy = tirith_core::policy::Policy::discover_local_only(None);
    match delete_license_key_with_policy(&path, &policy) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("No license key installed.");
            return 0;
        }
        Err(e) => {
            eprintln!("tirith: cannot remove license key: {e}");
            return 1;
        }
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
        // One trusted policy snapshot supplies both refresh credentials (when
        // not overridden as an indivisible environment pair) and the exact
        // ConfigWrite authorization used to publish the returned token.
        let policy = tirith_core::policy::Policy::discover_local_only(None);
        let credentials = match resolve_refresh_credentials_with(
            std::env::var_os("TIRITH_SERVER_URL"),
            std::env::var_os("TIRITH_API_KEY"),
            || policy.clone(),
        ) {
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

                if let Err(e) =
                    write_license_key_with_policy(&path, token.trim().as_bytes(), &policy)
                {
                    eprintln!("tirith: cannot write license key: {e}");
                    return 1;
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
    use std::sync::{Arc, Barrier};

    fn denied_license_write_policy() -> tirith_core::policy::Policy {
        let mut policy = tirith_core::policy::Policy::default();
        policy.task_gate.mode = tirith_core::web3_policy::TaskGateMode::Enforce;
        policy
            .task_gate
            .effects_denied_for_untrusted_sources
            .insert(tirith_core::effects::CommandEffectKind::FilesystemWrite);
        policy
    }

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

    #[test]
    fn denied_license_mutations_preserve_present_bytes_and_absent_namespace() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("config");
        let path = config.join("license.key");
        let policy = denied_license_write_policy();

        let error = write_license_key_with_policy(&path, b"new-token", &policy)
            .expect_err("a denied absent write must fail");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!config.exists(), "deny must happen before parent creation");

        std::fs::create_dir(&config).unwrap();
        std::fs::write(&path, b"original-token").unwrap();
        write_license_key_with_policy(&path, b"new-token", &policy)
            .expect_err("a denied overwrite must fail");
        assert_eq!(std::fs::read(&path).unwrap(), b"original-token");

        delete_license_key_with_policy(&path, &policy).expect_err("a denied deletion must fail");
        assert_eq!(std::fs::read(&path).unwrap(), b"original-token");
    }

    #[test]
    fn concurrent_license_writers_publish_only_one_complete_token() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("config");
        std::fs::create_dir(&config).unwrap();
        let path = config.join("license.key");
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for token in [b"first-complete-token".as_slice(), b"second-complete-token"] {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            let token = token.to_vec();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                write_license_key_with_policy(
                    &path,
                    &token,
                    &tirith_core::policy::Policy::default(),
                )
            }));
        }
        barrier.wait();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }

        let final_bytes = std::fs::read(&path).unwrap();
        assert!(final_bytes == b"first-complete-token" || final_bytes == b"second-complete-token");
    }

    #[test]
    fn concurrent_license_delete_and_write_are_parent_serialized() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("config");
        std::fs::create_dir(&config).unwrap();
        let path = config.join("license.key");
        std::fs::write(&path, b"original-token").unwrap();
        let barrier = Arc::new(Barrier::new(3));

        let delete_path = path.clone();
        let delete_barrier = Arc::clone(&barrier);
        let delete_thread = std::thread::spawn(move || {
            delete_barrier.wait();
            delete_license_key_with_policy(&delete_path, &tirith_core::policy::Policy::default())
        });
        let write_path = path.clone();
        let write_barrier = Arc::clone(&barrier);
        let write_thread = std::thread::spawn(move || {
            write_barrier.wait();
            write_license_key_with_policy(
                &write_path,
                b"replacement-token",
                &tirith_core::policy::Policy::default(),
            )
        });
        barrier.wait();
        assert!(delete_thread.join().unwrap().unwrap());
        write_thread.join().unwrap().unwrap();

        match std::fs::read(&path) {
            Ok(bytes) => assert_eq!(bytes, b"replacement-token"),
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::NotFound),
        }
    }
}
