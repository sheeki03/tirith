mod config;
mod db;
mod error;
mod routes;
mod sign;
mod state;
mod webhook_verify;

use std::sync::Arc;
use std::time::Duration;

use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};

use config::Config;
use db::Db;
use sign::TokenSigner;
use state::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("LOG_LEVEL")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Fail-fast: Config::from_env panics if any required var is missing.
    let config = Config::from_env();
    let port = config.port;

    let db = Db::open(&config.database_url).expect("failed to open database");

    let signer = TokenSigner::from_hex_seed(&config.ed25519_seed_hex, config.kid.clone())
        .expect("failed to init token signer");

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

    spawn_cleanup_task(db.clone());
    spawn_dead_letter_retry_task(db.clone(), Arc::new(config.clone()), http_client);
    spawn_backup_task(config.clone());

    // No permissive CORS. Receipts (`/receipt/lookup`, `/receipt/{secret}`)
    // deliver one-time license tokens / API keys and are viewed same-origin in
    // a browser. The previous global `CorsLayer::permissive()` reflected any
    // Origin and set `Access-Control-Allow-Origin: *`, which would have let a
    // malicious cross-origin page read a victim's receipt via fetch(). With no
    // CORS layer the browser default — same-origin only — applies to every
    // route, blocking cross-origin reads. None of the other endpoints need
    // cross-origin access: the Polar webhook is server-to-server and license
    // refresh is called by the CLI (neither is subject to browser CORS), and
    // health is trivial.
    let app = routes::router()
        .with_state(state)
        // repo-0447: the default request span records the full URI, which
        // leaks the one-time receipt secret (`/receipt/{secret}`) and the
        // checkout capability (`/receipt/lookup?checkout=...`) into logs.
        // Trace only method + path template, never the raw URI.
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<_>| {
                // The path alone can carry the one-time receipt secret; the
                // query can carry the checkout capability. Both are replaced
                // with a static label.
                let path = request.uri().path();
                let safe_path = if path.starts_with("/receipt/") && path.len() > "/receipt/".len() {
                    "/receipt/[redacted]"
                } else if path == "/receipt/lookup" {
                    "/receipt/lookup"
                } else {
                    path
                };
                tracing::info_span!(
                    "http",
                    method = %request.method(),
                    route = %safe_path,
                )
            }),
        );

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

/// Dead-letter auto-retry: re-fetch unresolvable products from the Polar
/// API every five minutes.
///
/// Only subscription-type dead letters are retried here. `order.paid` with
/// an unknown product returns 500 so Polar retries the full event, and
/// those never land in the dead-letter table.
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
    let entries = db
        .get_retryable_dead_letters()
        .await
        .map_err(|e| format!("query: {e}"))?;

    for entry in entries {
        let sub_id = match &entry.subscription_id {
            Some(id) => id.clone(),
            None => continue,
        };

        // Stale if the tier was already fixed by a newer event.
        if entry.current_tier.as_deref() != Some("unknown") {
            info!(
                dead_letter_id = entry.id,
                sub_id = %sub_id,
                "tier already resolved, removing stale dead letter"
            );
            let _ = db.delete_dead_letter(entry.id).await;
            continue;
        }

        // Stale if a newer event has landed on the subscription.
        if let (Some(ref dl_occurred), Some(ref sub_last)) =
            (&entry.occurred_at, &entry.last_event_at)
        {
            // Compare as instants, not raw strings — a different UTC offset or
            // fractional-second encoding sorts incorrectly lexicographically. If
            // either timestamp fails to parse, keep the dead letter: its retry
            // reconciles against the CURRENT subscription state, which is safe.
            if let (Ok(dl_ts), Ok(sub_ts)) = (
                chrono::DateTime::parse_from_rfc3339(dl_occurred),
                chrono::DateTime::parse_from_rfc3339(sub_last),
            ) {
                if dl_ts < sub_ts {
                    info!(
                        dead_letter_id = entry.id,
                        sub_id = %sub_id,
                        "dead letter older than latest event, removing stale entry"
                    );
                    let _ = db.delete_dead_letter(entry.id).await;
                    continue;
                }
            }
        }

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

        let product_id = body.get("product_id").and_then(|v| v.as_str());

        if let Some(pid) = product_id {
            if let Some(tier) = config.tier_for_product(pid) {
                info!(
                    dead_letter_id = entry.id,
                    sub_id = %sub_id,
                    tier = %tier,
                    "resolved product via Polar API retry"
                );
                let _ = db
                    .apply_retry_tier_fix(entry.id, &sub_id, tier, pid, entry.last_event_at.clone())
                    .await;
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

            // VACUUM INTO is run on a separate read-only handle so writers
            // are never blocked by the backup.
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

                    if let Ok(data) = tokio::fs::read(&backup_path).await {
                        use sha2::{Digest, Sha256};
                        let hash = hex::encode(Sha256::digest(&data));
                        let checksum_path = format!("{backup_path_str}.sha256");
                        let content = format!("{hash}  tirith-license-{date_str}.db\n");
                        if let Err(e) = tokio::fs::write(&checksum_path, &content).await {
                            error!("failed to write checksum: {e}");
                        }
                    }

                    cleanup_old_backups(&backup_dir, 7).await;

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
    use std::time::Duration;

    use rusty_s3::{Bucket, Credentials, S3Action as _, UrlStyle};

    let endpoint = match endpoint.parse() {
        Ok(endpoint) => endpoint,
        Err(e) => {
            error!("R2 endpoint error: {e}");
            return;
        }
    };
    let bucket = match Bucket::new(endpoint, UrlStyle::Path, bucket_name.to_owned(), "auto") {
        Ok(bucket) => bucket,
        Err(e) => {
            error!("R2 bucket init error: {e}");
            return;
        }
    };
    let credentials = Credentials::new(access_key, secret_key);
    let client = match r2_http_client() {
        Ok(client) => client,
        Err(_) => {
            error!("R2 HTTP client initialization failed");
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
    let upload = bucket
        .put_object(Some(&credentials), &key)
        .sign(Duration::from_secs(300));
    match client.put(upload).body(data).send().await {
        Ok(response) if response.status().is_success() => {
            info!(key = %key, "backup uploaded to R2");
        }
        Ok(response) => {
            error!(status = %response.status(), "R2 upload returned error");
        }
        Err(_) => {
            // reqwest errors can retain the presigned bearer URL. Never render
            // them into durable logs.
            error!("R2 upload request failed");
        }
    }

    let checksum_path = format!("{backup_path}.sha256");
    if let Ok(checksum_data) = tokio::fs::read(&checksum_path).await {
        let checksum_key = format!("backups/tirith-license-{date_str}.db.sha256");
        let checksum_upload = bucket
            .put_object(Some(&credentials), &checksum_key)
            .sign(Duration::from_secs(300));
        match client.put(checksum_upload).body(checksum_data).send().await {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => {
                error!(status = %response.status(), "R2 checksum upload returned error");
            }
            Err(_) => {
                error!("R2 checksum upload request failed");
            }
        }
    }
}

fn r2_http_client() -> Result<reqwest::Client, reqwest::Error> {
    // A presigned URL is a bearer credential and PUT bodies are the private
    // database backup. Never replay either to a redirect-selected origin.
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

#[cfg(test)]
mod r2_tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::time::Duration;

    #[tokio::test]
    async fn backup_client_never_replays_a_presigned_put_across_redirects() {
        let redirect_target = TcpListener::bind("127.0.0.1:0").expect("bind redirect target");
        redirect_target
            .set_nonblocking(true)
            .expect("make redirect target observable");
        let target_address = redirect_target.local_addr().expect("target address");
        let (observed_sender, observed_receiver) = mpsc::channel();
        let target_thread = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_millis(500);
            while std::time::Instant::now() < deadline {
                match redirect_target.accept() {
                    Ok(_) => {
                        let _ = observed_sender.send(true);
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => return,
                }
            }
            let _ = observed_sender.send(false);
        });

        let origin = TcpListener::bind("127.0.0.1:0").expect("bind origin");
        let origin_address = origin.local_addr().expect("origin address");
        let origin_thread = std::thread::spawn(move || {
            let (mut stream, _) = origin.accept().expect("accept initial PUT");
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).expect("read initial PUT");
            write!(
                stream,
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target_address}/leak\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .expect("write redirect");
        });

        let response = super::r2_http_client()
            .expect("build R2 client")
            .put(format!(
                "http://{origin_address}/backup?X-Amz-Signature=secret"
            ))
            .body("private database bytes")
            .send()
            .await
            .expect("receive the redirect response");
        assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
        assert!(!observed_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("redirect observer result"));
        origin_thread.join().expect("origin thread");
        target_thread.join().expect("target thread");
    }
}
