mod config;
mod db;
mod error;
mod routes;
mod sign;
mod state;
mod webhook_verify;

use std::sync::Arc;
use std::time::Duration;

use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

use config::Config;
use db::Db;
use sign::TokenSigner;
use state::AppState;

#[tokio::main]
async fn main() {
    // Logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("LOG_LEVEL")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Config (panics on missing required vars — fail-fast)
    let config = Config::from_env();
    let port = config.port;

    // Database
    let db = Db::open(&config.database_url).expect("failed to open database");

    // Token signer
    let signer = TokenSigner::from_hex_seed(&config.ed25519_seed_hex, config.kid.clone())
        .expect("failed to init token signer");

    // HTTP client for Polar API
    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(3))
        .build()
        .expect("failed to build HTTP client");

    let state = AppState {
        db: db.clone(),
        signer: Arc::new(signer),
        config: Arc::new(config.clone()),
        http_client: http_client.clone(),
    };

    // Background tasks
    spawn_cleanup_task(db.clone());
    spawn_dead_letter_retry_task(db.clone(), Arc::new(config.clone()), http_client);
    spawn_backup_task(config.clone());

    // Router
    let app = routes::router()
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive());

    let addr = format!("0.0.0.0:{port}");
    info!("listening on {addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}

/// Cleanup expired receipts, old dead letters, old tokens — every 10 minutes.
fn spawn_cleanup_task(db: Db) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(600));
        loop {
            interval.tick().await;
            if let Err(e) = db.cleanup().await {
                error!("cleanup task failed: {e}");
            }
        }
    });
}

/// Dead-letter auto-retry: re-fetch unresolvable products from Polar API every 5 min.
/// Only retries subscription-type dead letters (order.paid unknown-product returns 500
/// so Polar retries the full event — those never enter the dead-letter table).
fn spawn_dead_letter_retry_task(db: Db, config: Arc<Config>, http_client: reqwest::Client) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300));
        loop {
            interval.tick().await;
            if let Err(e) = retry_dead_letters(&db, &config, &http_client).await {
                error!("dead-letter retry task failed: {e}");
            }
        }
    });
}

async fn retry_dead_letters(
    db: &Db,
    config: &Config,
    http_client: &reqwest::Client,
) -> Result<(), String> {
    // Only returns subscription-type dead letters (filtered in SQL)
    let entries = db
        .get_retryable_dead_letters()
        .await
        .map_err(|e| format!("query: {e}"))?;

    for entry in entries {
        let sub_id = match &entry.subscription_id {
            Some(id) => id.clone(),
            None => continue,
        };

        // Staleness guard 1: tier already fixed by a newer event
        if entry.current_tier.as_deref() != Some("unknown") {
            info!(
                dead_letter_id = entry.id,
                sub_id = %sub_id,
                "tier already resolved, removing stale dead letter"
            );
            let _ = db.delete_dead_letter(entry.id).await;
            continue;
        }

        // Staleness guard 2: check if a newer event has been processed
        if let (Some(ref dl_occurred), Some(ref sub_last)) =
            (&entry.occurred_at, &entry.last_event_at)
        {
            if dl_occurred < sub_last {
                info!(
                    dead_letter_id = entry.id,
                    sub_id = %sub_id,
                    "dead letter older than latest event, removing stale entry"
                );
                let _ = db.delete_dead_letter(entry.id).await;
                continue;
            }
        }

        // Fetch subscription from Polar API to resolve product_id → tier
        let url = format!("https://api.polar.sh/v1/subscriptions/{sub_id}");
        let resp = http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", config.polar_api_key))
            .send()
            .await;

        let resp = match resp {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                warn!(
                    dead_letter_id = entry.id,
                    sub_id = %sub_id,
                    status = %r.status(),
                    "Polar API returned non-success for retry"
                );
                continue;
            }
            Err(e) => {
                warn!(
                    dead_letter_id = entry.id,
                    sub_id = %sub_id,
                    "Polar API request failed for retry: {e}"
                );
                continue;
            }
        };

        let body: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    dead_letter_id = entry.id,
                    "failed to parse Polar API response: {e}"
                );
                continue;
            }
        };

        // Extract product_id from Polar API response
        let product_id = body.get("product_id").and_then(|v| v.as_str());

        if let Some(pid) = product_id {
            if let Some(tier) = config.tier_for_product(pid) {
                info!(
                    dead_letter_id = entry.id,
                    sub_id = %sub_id,
                    tier = %tier,
                    "resolved product via Polar API retry"
                );
                let _ = db.apply_retry_tier_fix(entry.id, &sub_id, tier, pid).await;
            } else {
                warn!(
                    dead_letter_id = entry.id,
                    sub_id = %sub_id,
                    product_id = %pid,
                    "Polar API returned product_id but it still doesn't map to a tier"
                );
            }
        }
    }

    Ok(())
}

/// Daily SQLite backup at 03:00 UTC — runs local .backup, optionally uploads to R2.
fn spawn_backup_task(config: Config) {
    tokio::spawn(async move {
        loop {
            // Sleep until next 03:00 UTC
            let now = chrono::Utc::now();
            let next_3am = {
                let today_3am = now.date_naive().and_hms_opt(3, 0, 0).unwrap();
                let today_3am_utc = today_3am.and_utc();
                if today_3am_utc > now {
                    today_3am_utc
                } else {
                    (today_3am + chrono::Duration::days(1)).and_utc()
                }
            };
            let sleep_dur = (next_3am - now)
                .to_std()
                .unwrap_or(Duration::from_secs(3600));
            tokio::time::sleep(sleep_dur).await;

            let db_path = config.database_url.clone();
            let date_str = chrono::Utc::now().format("%Y-%m-%d").to_string();

            // Derive backup dir from db path
            let db_dir = std::path::Path::new(&db_path)
                .parent()
                .unwrap_or(std::path::Path::new("/data"));
            let backup_dir = db_dir.join("backup");
            if let Err(e) = std::fs::create_dir_all(&backup_dir) {
                error!("failed to create backup dir: {e}");
                continue;
            }

            let backup_path = backup_dir.join(format!("tirith-license-{date_str}.db"));
            let backup_path_str = backup_path.display().to_string();

            // Run backup using a separate read-only connection
            let result = tokio::task::spawn_blocking({
                let db_path = db_path.clone();
                let backup_path_str = backup_path_str.clone();
                move || -> Result<(), String> {
                    let src =
                        Db::open_readonly(&db_path).map_err(|e| format!("open readonly: {e}"))?;
                    let safe_path = backup_path_str.replace('\'', "''");
                    src.execute_batch(&format!("VACUUM INTO '{safe_path}'"))
                        .map_err(|e| format!("VACUUM INTO: {e}"))?;
                    Ok(())
                }
            })
            .await;

            match result {
                Ok(Ok(())) => {
                    info!(path = %backup_path_str, "daily backup completed");

                    // Write SHA-256 checksum
                    if let Ok(data) = tokio::fs::read(&backup_path).await {
                        use sha2::{Digest, Sha256};
                        let hash = hex::encode(Sha256::digest(&data));
                        let checksum_path = format!("{backup_path_str}.sha256");
                        let content = format!("{hash}  tirith-license-{date_str}.db\n");
                        if let Err(e) = tokio::fs::write(&checksum_path, &content).await {
                            error!("failed to write checksum: {e}");
                        }
                    }

                    // Retain last 7 local copies
                    cleanup_old_backups(&backup_dir, 7).await;

                    // Optional R2 upload
                    if let (
                        Some(ref endpoint),
                        Some(ref bucket),
                        Some(ref key_id),
                        Some(ref secret),
                    ) = (
                        config.backup_r2_endpoint.clone(),
                        config.backup_r2_bucket.clone(),
                        config.backup_r2_access_key_id.clone(),
                        config.backup_r2_secret_access_key.clone(),
                    ) {
                        upload_to_r2(
                            endpoint,
                            bucket,
                            key_id,
                            secret,
                            &backup_path_str,
                            &date_str,
                        )
                        .await;
                    }
                }
                Ok(Err(e)) => error!("backup failed: {e}"),
                Err(e) => error!("backup task panicked: {e}"),
            }
        }
    });
}

async fn cleanup_old_backups(backup_dir: &std::path::Path, keep: usize) {
    let mut entries: Vec<_> = match std::fs::read_dir(backup_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with("tirith-license-") && n.ends_with(".db"))
                    .unwrap_or(false)
            })
            .collect(),
        Err(e) => {
            error!("failed to read backup dir: {e}");
            return;
        }
    };

    entries.sort_by_key(|e| e.file_name());
    entries.reverse();

    for old in entries.into_iter().skip(keep) {
        let path = old.path();
        let _ = std::fs::remove_file(&path);
        let sha_path = format!("{}.sha256", path.display());
        let _ = std::fs::remove_file(sha_path);
    }
}

async fn upload_to_r2(
    endpoint: &str,
    bucket_name: &str,
    access_key: &str,
    secret_key: &str,
    backup_path: &str,
    date_str: &str,
) {
    use s3::creds::Credentials;
    use s3::Bucket;
    use s3::Region;

    let region = Region::Custom {
        region: "auto".to_string(),
        endpoint: endpoint.to_string(),
    };
    let credentials = match Credentials::new(Some(access_key), Some(secret_key), None, None, None) {
        Ok(c) => c,
        Err(e) => {
            error!("R2 credentials error: {e}");
            return;
        }
    };

    let bucket = match Bucket::new(bucket_name, region, credentials) {
        Ok(b) => b,
        Err(e) => {
            error!("R2 bucket init error: {e}");
            return;
        }
    };

    let data = match tokio::fs::read(backup_path).await {
        Ok(d) => d,
        Err(e) => {
            error!("failed to read backup for R2 upload: {e}");
            return;
        }
    };

    let key = format!("backups/tirith-license-{date_str}.db");
    match bucket.put_object(&key, &data).await {
        Ok(resp) if resp.status_code() < 300 => {
            info!(key = %key, "backup uploaded to R2");
        }
        Ok(resp) => {
            error!(status = resp.status_code(), "R2 upload returned error");
        }
        Err(e) => {
            error!("R2 upload failed: {e}");
        }
    }

    // Upload checksum too
    let checksum_path = format!("{backup_path}.sha256");
    if let Ok(checksum_data) = tokio::fs::read(&checksum_path).await {
        let checksum_key = format!("backups/tirith-license-{date_str}.db.sha256");
        if let Err(e) = bucket.put_object(&checksum_key, &checksum_data).await {
            error!("R2 checksum upload failed: {e}");
        }
    }
}
