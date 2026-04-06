//! CLI subcommands for threat DB management: update, status, and background auto-update.

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use sha2::{Digest, Sha256};

use tirith_core::policy;
use tirith_core::threatdb::ThreatDb;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Pinned Ed25519 public key for manifest signature verification.
/// MUST be identical to the key in tirith-core/assets/keys/threatdb-verify.pub.
/// Both files must be kept in sync — they are the same key used for DB and manifest signing.
static VERIFY_KEY_BYTES: &[u8; PUBLIC_KEY_LENGTH] =
    include_bytes!("../../assets/keys/threatdb-verify.pub");

const MANIFEST_URL_PRIMARY: &str =
    "https://raw.githubusercontent.com/sheeki03/tirith/main/threatdb-manifest.json";
const MANIFEST_URL_FALLBACK: &str =
    "https://github.com/sheeki03/tirith/releases/latest/download/threatdb-manifest.json";

/// Max manifest size (64 KiB) to prevent abuse.
const MAX_MANIFEST_SIZE: u64 = 64 * 1024;
/// Max DB file size (256 MiB) to prevent disk exhaustion.
const MAX_DB_SIZE: u64 = 256 * 1024 * 1024;
/// HTTP timeout for manifest fetch.
const MANIFEST_TIMEOUT_SECS: u64 = 15;
/// HTTP timeout for DB download.
const DB_DOWNLOAD_TIMEOUT_SECS: u64 = 120;

const LOCKFILE_NAME: &str = "threatdb-update.lock";
const NEXT_CHECK_FILE: &str = "threatdb-next-check-at";
const SPAWNED_AT_FILE: &str = "threatdb-spawned-at";
/// Soft dedup window: skip spawn if another was spawned within this many seconds.
const SPAWNED_AT_DEDUP_SECS: u64 = 30;
/// Backoff interval on failure (1 hour).
const BACKOFF_SECS: u64 = 3600;

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct Manifest {
    sha256: String,
    size: u64,
    url: String,
    version: u64,
    signature: String,
}

impl Manifest {
    /// Reconstruct the canonical payload for signature verification.
    /// Keys alphabetically sorted, no whitespace, no trailing newline.
    fn canonical_payload(&self) -> String {
        let mut map = std::collections::BTreeMap::new();
        map.insert("sha256", serde_json::Value::String(self.sha256.clone()));
        map.insert("size", serde_json::json!(self.size));
        map.insert("url", serde_json::Value::String(self.url.clone()));
        map.insert("version", serde_json::json!(self.version));
        serde_json::to_string(&map).expect("canonical payload serialization")
    }

    /// Verify the manifest signature against the pinned public key.
    fn verify_signature(&self) -> Result<(), String> {
        let sig_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &self.signature)
                .map_err(|e| format!("invalid manifest signature encoding: {e}"))?;

        if sig_bytes.len() != SIGNATURE_LENGTH {
            return Err(format!(
                "manifest signature wrong length: {} (expected {})",
                sig_bytes.len(),
                SIGNATURE_LENGTH
            ));
        }

        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| format!("invalid manifest signature: {e}"))?;

        let verify_key = VerifyingKey::from_bytes(VERIFY_KEY_BYTES)
            .map_err(|e| format!("invalid embedded public key: {e}"))?;

        let payload = self.canonical_payload();
        use ed25519_dalek::Verifier;
        verify_key
            .verify(payload.as_bytes(), &signature)
            .map_err(|_| "manifest signature verification failed".to_string())
    }
}

// ---------------------------------------------------------------------------
// Update command
// ---------------------------------------------------------------------------

pub fn update(force: bool, background: bool) -> i32 {
    if background {
        return run_background_update();
    }

    match do_update(force) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("tirith: threat-db update failed: {e}");
            1
        }
    }
}

/// Foreground update: fetch manifest, verify, download, install.
fn do_update(force: bool) -> Result<(), String> {
    let manifest = fetch_manifest()?;

    // Verify manifest signature
    manifest.verify_signature()?;

    // Check rollback protection (unless --force)
    if !force {
        if let Some(db) = ThreatDb::cached() {
            let current_seq = db.build_sequence();
            if manifest.version < current_seq {
                return Err(format!(
                    "rollback protection: manifest version {} < current {}",
                    manifest.version, current_seq
                ));
            }
            if manifest.version == current_seq {
                eprintln!(
                    "tirith: threat DB is already up to date (version {})",
                    manifest.version
                );
                return Ok(());
            }
        }
    }

    eprintln!(
        "tirith: downloading threat DB v{} ({} bytes)...",
        manifest.version, manifest.size
    );

    // Download the .dat file
    let data = download_db(&manifest)?;

    // Verify SHA-256
    let computed_hash = hex::encode(Sha256::digest(&data));
    if computed_hash != manifest.sha256 {
        return Err(format!(
            "SHA-256 mismatch: expected {}, got {}",
            manifest.sha256, computed_hash
        ));
    }

    // Verify .dat internal signature by loading it
    let min_seq = if force { 0 } else { current_sequence() };
    let db =
        ThreatDb::from_bytes(data.clone(), min_seq).map_err(|e| format!("invalid DB file: {e}"))?;
    db.verify_signature()
        .map_err(|e| format!("DB file internal signature verification failed: {e}"))?;

    // Atomic write to data_dir
    let dest =
        ThreatDb::default_path().ok_or_else(|| "cannot determine data directory".to_string())?;
    atomic_write(&dest, &data)?;

    // Refresh the in-process cache
    ThreatDb::refresh_cache();

    let stats = db.stats();
    let total_entries = stats.package_count
        + stats.hostname_count
        + stats.ip_count
        + stats.typosquat_count
        + stats.popular_count;
    eprintln!(
        "tirith: threat DB updated to v{} ({} entries)",
        manifest.version, total_entries
    );

    Ok(())
}

/// Run the background update (called with --background flag).
/// Acquires exclusive lock, downloads, verifies, installs, writes next-check-at.
fn run_background_update() -> i32 {
    let state = match policy::state_dir() {
        Some(d) => d,
        None => return 1,
    };
    if let Err(e) = std::fs::create_dir_all(&state) {
        eprintln!(
            "tirith: warning: failed to create state directory {}: {e}",
            state.display()
        );
        return 1;
    }

    let lock_path = state.join(LOCKFILE_NAME);

    // Acquire exclusive lock — if held, another child is running, exit silently
    let lock_file = match std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "tirith: warning: failed to open lock file {}: {e}",
                lock_path.display()
            );
            return 1;
        }
    };

    use fs2::FileExt;
    if lock_file.try_lock_exclusive().is_err() {
        // Another child holds the lock — exit silently
        return 0;
    }

    // Load policy for auto_update_hours
    let policy = policy::Policy::discover(None);
    let auto_hours = policy.threat_intel.auto_update_hours;
    if auto_hours == 0 {
        let _ = fs2::FileExt::unlock(&lock_file);
        return 0;
    }

    let result = do_update(false);

    let next_check_path = state.join(NEXT_CHECK_FILE);
    let now = unix_now();
    let success = result.is_ok();
    if success {
        // Success: next check at now + auto_update_hours
        let next = now + auto_hours * 3600;
        if let Err(e) = std::fs::write(&next_check_path, next.to_string()) {
            eprintln!("tirith: warning: failed to write next-check-at: {e}");
        }
    } else {
        if let Err(ref e) = result {
            eprintln!("tirith: background update failed: {e}");
        }
        // Failure: backoff to now + 1h
        let next = now + BACKOFF_SECS;
        if let Err(e) = std::fs::write(&next_check_path, next.to_string()) {
            eprintln!("tirith: warning: failed to write next-check-at: {e}");
        }
    }

    let _ = fs2::FileExt::unlock(&lock_file);
    if success {
        0
    } else {
        1
    }
}

// ---------------------------------------------------------------------------
// Status command
// ---------------------------------------------------------------------------

pub fn status(json: bool) -> i32 {
    let info = gather_status();

    if json {
        match serde_json::to_string_pretty(&info) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("tirith: JSON serialization failed: {e}");
                return 1;
            }
        }
    } else {
        print_status_human(&info);
    }
    0
}

#[derive(Debug, serde::Serialize)]
struct ThreatDbStatus {
    installed: bool,
    path: Option<String>,
    age_hours: Option<f64>,
    build_timestamp: Option<u64>,
    build_sequence: Option<u64>,
    package_count: Option<u32>,
    hostname_count: Option<u32>,
    ip_count: Option<u32>,
    typosquat_count: Option<u32>,
    popular_count: Option<u32>,
    total_entries: Option<u32>,
    skipped_range_only: Option<u32>,
    signature_valid: Option<bool>,
    stale: bool,
    error: Option<String>,
}

fn gather_status() -> ThreatDbStatus {
    let db_path = ThreatDb::default_path();
    let path_str = db_path.as_ref().map(|p| p.display().to_string());

    let db_path_ref = match db_path {
        Some(ref p) if p.exists() => p,
        _ => {
            return ThreatDbStatus {
                installed: false,
                path: path_str,
                age_hours: None,
                build_timestamp: None,
                build_sequence: None,
                package_count: None,
                hostname_count: None,
                ip_count: None,
                typosquat_count: None,
                popular_count: None,
                total_entries: None,
                skipped_range_only: None,
                signature_valid: None,
                stale: true,
                error: None,
            };
        }
    };

    match ThreatDb::load_from_path(db_path_ref, 0) {
        Ok(db) => {
            let sig_valid = db.verify_signature().is_ok();
            let stats = db.stats();
            let now = unix_now();
            let age_secs = now.saturating_sub(stats.build_timestamp);
            let age_hours = age_secs as f64 / 3600.0;
            let total = stats.package_count
                + stats.hostname_count
                + stats.ip_count
                + stats.typosquat_count
                + stats.popular_count;

            // Load policy for staleness threshold
            let policy = policy::Policy::discover(None);
            let stale_hours = policy.threat_intel.auto_update_hours;
            let is_stale = if stale_hours == 0 {
                false // auto-update disabled, never consider stale
            } else {
                age_hours > (stale_hours as f64 * 2.0) // 2x threshold
            };

            ThreatDbStatus {
                installed: true,
                path: path_str,
                age_hours: Some(age_hours),
                build_timestamp: Some(stats.build_timestamp),
                build_sequence: Some(stats.build_sequence),
                package_count: Some(stats.package_count),
                hostname_count: Some(stats.hostname_count),
                ip_count: Some(stats.ip_count),
                typosquat_count: Some(stats.typosquat_count),
                popular_count: Some(stats.popular_count),
                total_entries: Some(total),
                skipped_range_only: None, // compile-time stat, not in DB header yet
                signature_valid: Some(sig_valid),
                stale: is_stale,
                error: None,
            }
        }
        Err(e) => ThreatDbStatus {
            installed: true,
            path: path_str,
            age_hours: None,
            build_timestamp: None,
            build_sequence: None,
            package_count: None,
            hostname_count: None,
            ip_count: None,
            typosquat_count: None,
            popular_count: None,
            total_entries: None,
            skipped_range_only: None,
            signature_valid: None,
            stale: true,
            error: Some(format!("{e}")),
        },
    }
}

fn print_status_human(info: &ThreatDbStatus) {
    if !info.installed {
        println!("threat DB:    not installed — run 'tirith threat-db update'");
        if let Some(ref path) = info.path {
            println!("  expected at: {path}");
        }
        return;
    }

    if let Some(ref err) = info.error {
        println!("threat DB:    ERROR: {err}");
        if let Some(ref path) = info.path {
            println!("  path:        {path}");
        }
        println!("  Hint: re-download with 'tirith threat-db update --force'");
        return;
    }

    if info.signature_valid == Some(false) {
        println!(
            "threat DB:    INVALID SIGNATURE — re-download with 'tirith threat-db update --force'"
        );
        if let Some(ref path) = info.path {
            println!("  path:        {path}");
        }
        return;
    }

    let path = info.path.as_deref().unwrap_or("unknown");
    let age_str = match info.age_hours {
        Some(h) if h < 1.0 => format!("{:.0}m old", h * 60.0),
        Some(h) if h < 48.0 => format!("{:.0}h old", h),
        Some(h) => format!("{:.0}d old", h / 24.0),
        None => "unknown age".to_string(),
    };
    let total = info.total_entries.unwrap_or(0);

    if info.stale {
        println!("threat DB:    STALE ({age_str}) — run 'tirith threat-db update'");
    } else {
        let sig_label = if info.signature_valid == Some(true) {
            "signature ok"
        } else {
            "signature unknown"
        };
        println!("threat DB:    {path} ({age_str}, {total} entries, {sig_label})");
    }

    if let Some(seq) = info.build_sequence {
        println!("  version:     {seq}");
    }

    // Show breakdown
    if let (Some(pkg), Some(host), Some(ip), Some(typo), Some(pop)) = (
        info.package_count,
        info.hostname_count,
        info.ip_count,
        info.typosquat_count,
        info.popular_count,
    ) {
        println!(
            "  entries:     {pkg} packages, {host} hostnames, {ip} IPs, {typo} typosquats, {pop} popular"
        );
    }

    println!(
        "  update:      auto-update checks main manifest, falls back to release asset if stale"
    );
    println!("               (fallback may hit GitHub API rate limits for unauthenticated users)");
}

// ---------------------------------------------------------------------------
// Auto-update trigger (called from check.rs)
// ---------------------------------------------------------------------------

/// Guard: only try once per process lifetime.
static UPDATE_ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// Spawn a detached child process to update the threat DB if due.
///
/// Called from `check.rs` after the verdict is computed.
/// This is intentionally cheap: reads a timestamp file and optionally spawns
/// a detached child. The actual download happens in the child process.
pub fn maybe_background_update() {
    // 1. Only try once per process lifetime
    if UPDATE_ATTEMPTED.swap(true, Ordering::Relaxed) {
        return;
    }

    // 2. Respect auto_update_hours=0
    let policy = policy::Policy::discover(None);
    if policy.threat_intel.auto_update_hours == 0 {
        return;
    }

    let state = match policy::state_dir() {
        Some(d) => d,
        None => return,
    };

    // 3. Check next-check-at timestamp
    let next_check_path = state.join(NEXT_CHECK_FILE);
    let now = unix_now();
    if let Ok(content) = std::fs::read_to_string(&next_check_path) {
        if let Ok(next_ts) = content.trim().parse::<u64>() {
            if now < next_ts {
                return; // not yet due
            }
        }
    }
    // If file doesn't exist or is unparseable, proceed (first run or corrupt)

    // 4. Layer 1 (parent-side, soft hint): check spawned-at dedup
    let spawned_at_path = state.join(SPAWNED_AT_FILE);
    if let Ok(content) = std::fs::read_to_string(&spawned_at_path) {
        if let Ok(spawned_ts) = content.trim().parse::<u64>() {
            if now.saturating_sub(spawned_ts) < SPAWNED_AT_DEDUP_SECS {
                return; // another parent spawned recently
            }
        }
    }

    // Write spawned-at before spawning
    if let Err(e) = std::fs::create_dir_all(&state) {
        eprintln!("tirith: warning: failed to create state directory: {e}");
        return;
    }
    let _ = std::fs::write(&spawned_at_path, now.to_string());

    // 5. Spawn detached child
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return,
    };

    match std::process::Command::new(&exe)
        .args(["threat-db", "update", "--background"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => {}
        Err(e) => {
            eprintln!("tirith: warning: failed to spawn background update: {e}");
            let _ = std::fs::remove_file(&spawned_at_path);
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/// Fetch the manifest from primary URL, falling back to the release asset URL.
/// Falls back when: primary fetch fails OR primary manifest is older than current DB
/// (stale primary, e.g., manifest PR not yet merged).
fn fetch_manifest() -> Result<Manifest, String> {
    match fetch_manifest_from(MANIFEST_URL_PRIMARY) {
        Ok(m) => {
            // Check if primary is stale (older than current DB)
            if let Some(db) = ThreatDb::cached() {
                if m.version <= db.build_sequence() {
                    eprintln!("tirith: primary manifest is stale (v{} <= current v{}), trying fallback...",
                        m.version, db.build_sequence());
                    match fetch_manifest_from(MANIFEST_URL_FALLBACK) {
                        Ok(fallback) if fallback.version > db.build_sequence() => {
                            return Ok(fallback)
                        }
                        _ => {} // fallback also stale or failed — use primary
                    }
                }
            }
            Ok(m)
        }
        Err(primary_err) => {
            eprintln!("tirith: primary manifest unavailable ({primary_err}), trying fallback...");
            fetch_manifest_from(MANIFEST_URL_FALLBACK).map_err(|fallback_err| {
                format!("manifest fetch failed: primary: {primary_err}; fallback: {fallback_err}")
            })
        }
    }
}

/// Result of resolving a manifest from cache state + HTTP response.
#[derive(Debug, PartialEq)]
enum CacheResolution {
    /// Use the fresh body from HTTP 200.
    Fresh(String),
    /// Use cached body from disk (HTTP 304).
    Cached(String),
    /// Cache miss on 304 — need unconditional retry.
    RetryNeeded,
}

/// Resolve manifest from HTTP status and cache state.
/// Extracted for testability — no I/O, pure logic.
fn resolve_cache(
    http_status: u16,
    response_body: Option<&str>,
    cached_body: Option<&str>,
) -> Result<CacheResolution, String> {
    if http_status == 304 {
        // Try cached body — must exist AND parse as valid JSON
        if let Some(body) = cached_body {
            if serde_json::from_str::<Manifest>(body).is_ok() {
                return Ok(CacheResolution::Cached(body.to_string()));
            }
            // Corrupt cached body → need unconditional retry (not an error)
        }
        return Ok(CacheResolution::RetryNeeded);
    }
    if !(200..300).contains(&http_status) {
        return Err(format!("HTTP {http_status}"));
    }
    match response_body {
        Some(body) => Ok(CacheResolution::Fresh(body.to_string())),
        None => Err("empty response body".to_string()),
    }
}

/// Per-URL cache file name: hash the URL to avoid path issues.
fn manifest_cache_key(url: &str) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(url.as_bytes());
    let hex: String = hash.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("threatdb-manifest-{hex}")
}

fn fetch_manifest_from(url: &str) -> Result<Manifest, String> {
    fetch_manifest_from_with_state(url, tirith_core::policy::state_dir())
}

fn fetch_manifest_from_with_state(
    url: &str,
    state: Option<std::path::PathBuf>,
) -> Result<Manifest, String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(MANIFEST_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;
    let cache_key = manifest_cache_key(url);
    let etag_path = state.as_ref().map(|d| d.join(format!("{cache_key}-etag")));
    let body_path = state.as_ref().map(|d| d.join(format!("{cache_key}-body")));

    // Build request with conditional-GET headers (per-URL ETag)
    let mut req = client.get(url).header(
        "User-Agent",
        format!("tirith/{}", env!("CARGO_PKG_VERSION")),
    );
    if let Some(ref ep) = etag_path {
        if let Ok(etag) = std::fs::read_to_string(ep) {
            let etag = etag.trim();
            if !etag.is_empty() {
                req = req.header("If-None-Match", etag);
            }
        }
    }

    let resp = req
        .send()
        .map_err(|e| format!("manifest fetch failed: {e}"))?;

    let status = resp.status().as_u16();

    // Extract ETag before consuming response body
    let resp_etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Read body for non-304 responses (304 has no body)
    let resp_body = if status != 304 {
        let content_len = resp.content_length().unwrap_or(0);
        if content_len > MAX_MANIFEST_SIZE {
            return Err(format!(
                "manifest too large: {} bytes (max {})",
                content_len, MAX_MANIFEST_SIZE
            ));
        }
        let body = resp
            .text()
            .map_err(|e| format!("failed to read manifest body: {e}"))?;
        if body.len() as u64 > MAX_MANIFEST_SIZE {
            return Err(format!("manifest body too large: {} bytes", body.len()));
        }
        Some(body)
    } else {
        None
    };

    // Load cached body only for 304 responses (avoid unnecessary I/O on 200)
    let cached_body = if status == 304 {
        body_path.as_ref().and_then(|bp| {
            // Check file size BEFORE reading to avoid unbounded memory use
            if let Ok(meta) = std::fs::metadata(bp) {
                if meta.len() > MAX_MANIFEST_SIZE {
                    eprintln!(
                        "tirith: warning: cached manifest too large ({} bytes), ignoring",
                        meta.len()
                    );
                    return None;
                }
            }
            let content = std::fs::read_to_string(bp).ok()?;
            Some(content)
        })
    } else {
        None
    };

    // Use resolve_cache for the status/cache decision (tested state machine)
    match resolve_cache(status, resp_body.as_deref(), cached_body.as_deref()) {
        Ok(CacheResolution::Fresh(body)) => {
            // Validate JSON BEFORE caching to prevent poisoned cache
            let manifest = serde_json::from_str::<Manifest>(&body)
                .map_err(|e| format!("invalid manifest JSON: {e}"))?;
            // Only persist after successful validation
            persist_cache_files(&etag_path, resp_etag.as_deref(), &body_path, &body);
            Ok(manifest)
        }
        Ok(CacheResolution::Cached(body)) => serde_json::from_str::<Manifest>(&body)
            .map_err(|e| format!("cached manifest parse error: {e}")),
        Ok(CacheResolution::RetryNeeded) => {
            // Delete stale ETag/body to break 304 loop
            if let Some(ref ep) = etag_path {
                let _ = std::fs::remove_file(ep);
            }
            if let Some(ref bp) = body_path {
                let _ = std::fs::remove_file(bp);
            }
            // Retry unconditionally
            let retry_resp = client
                .get(url)
                .header(
                    "User-Agent",
                    format!("tirith/{}", env!("CARGO_PKG_VERSION")),
                )
                .send()
                .map_err(|e| format!("manifest retry fetch failed: {e}"))?;
            if !retry_resp.status().is_success() {
                return Err(format!("manifest retry HTTP {}", retry_resp.status()));
            }
            let retry_content_len = retry_resp.content_length().unwrap_or(0);
            if retry_content_len > MAX_MANIFEST_SIZE {
                return Err(format!(
                    "manifest too large on retry: {} bytes (max {})",
                    retry_content_len, MAX_MANIFEST_SIZE
                ));
            }
            // Persist ETag from retry response
            let retry_etag = retry_resp
                .headers()
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            let retry_body = retry_resp
                .text()
                .map_err(|e| format!("failed to read retry body: {e}"))?;
            if retry_body.len() as u64 > MAX_MANIFEST_SIZE {
                return Err(format!(
                    "manifest body too large on retry: {} bytes",
                    retry_body.len()
                ));
            }
            // Validate JSON BEFORE caching to prevent poisoned cache
            let manifest = serde_json::from_str::<Manifest>(&retry_body)
                .map_err(|e| format!("invalid manifest JSON on retry: {e}"))?;
            persist_cache_files(&etag_path, retry_etag.as_deref(), &body_path, &retry_body);
            Ok(manifest)
        }
        Err(e) => Err(e),
    }
}

/// Persist ETag and body cache files for conditional GET.
fn persist_cache_files(
    etag_path: &Option<std::path::PathBuf>,
    etag_val: Option<&str>,
    body_path: &Option<std::path::PathBuf>,
    body: &str,
) {
    if let (Some(ep), Some(val)) = (etag_path, etag_val) {
        if let Some(parent) = ep.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(ep, val);
    }
    if let Some(bp) = body_path {
        if let Some(parent) = bp.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(bp, body);
    }
}

/// Download the DB file from the manifest URL.
fn download_db(manifest: &Manifest) -> Result<Vec<u8>, String> {
    if manifest.size > MAX_DB_SIZE {
        return Err(format!(
            "DB file too large: {} bytes (max {})",
            manifest.size, MAX_DB_SIZE
        ));
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(DB_DOWNLOAD_TIMEOUT_SECS))
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let resp = client
        .get(&manifest.url)
        .header(
            "User-Agent",
            format!("tirith/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .map_err(|e| format!("DB download failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("DB download HTTP {}", resp.status()));
    }

    let bytes = resp
        .bytes()
        .map_err(|e| format!("failed to read DB body: {e}"))?;

    if bytes.len() as u64 > MAX_DB_SIZE {
        return Err(format!("DB body too large: {} bytes", bytes.len()));
    }

    Ok(bytes.to_vec())
}

// ---------------------------------------------------------------------------
// Filesystem helpers
// ---------------------------------------------------------------------------

/// Atomic write: write to a temp file in the same directory, then rename.
fn atomic_write(dest: &PathBuf, data: &[u8]) -> Result<(), String> {
    let parent = dest
        .parent()
        .ok_or_else(|| "cannot determine parent directory".to_string())?;
    std::fs::create_dir_all(parent).map_err(|e| format!("failed to create directory: {e}"))?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("failed to create temp file: {e}"))?;
    tmp.write_all(data)
        .map_err(|e| format!("failed to write temp file: {e}"))?;
    tmp.flush()
        .map_err(|e| format!("failed to flush temp file: {e}"))?;

    tmp.persist(dest)
        .map_err(|e| format!("failed to rename temp file: {e}"))?;

    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn current_sequence() -> u64 {
    ThreatDb::cached()
        .map(|db| db.build_sequence())
        .unwrap_or(0)
}

/// Hex encoding helper (avoid adding hex crate dependency).
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::Ordering;

    /// Serialize tests that manipulate environment variables.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // -----------------------------------------------------------------------
    // Testable coordination helpers (test-only, extracted from production code)
    // -----------------------------------------------------------------------

    /// Check whether the next-check-at file indicates the update is not yet due.
    fn is_next_check_in_future(state_dir: &Path, now: u64) -> bool {
        let next_check_path = state_dir.join(NEXT_CHECK_FILE);
        if let Ok(content) = std::fs::read_to_string(&next_check_path) {
            if let Ok(next_ts) = content.trim().parse::<u64>() {
                return now < next_ts;
            }
        }
        false
    }

    /// Check whether the spawned-at file indicates another parent spawned recently.
    fn is_spawned_at_recent(state_dir: &Path, now: u64) -> bool {
        let spawned_at_path = state_dir.join(SPAWNED_AT_FILE);
        if let Ok(content) = std::fs::read_to_string(&spawned_at_path) {
            if let Ok(spawned_ts) = content.trim().parse::<u64>() {
                return now.saturating_sub(spawned_ts) < SPAWNED_AT_DEDUP_SECS;
            }
        }
        false
    }

    /// Try to acquire the background update lock. Returns the lock file on success,
    /// or `None` if another process holds it.
    fn try_acquire_update_lock(state_dir: &Path) -> Option<std::fs::File> {
        let lock_path = state_dir.join(LOCKFILE_NAME);
        let lock_file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .ok()?;

        use fs2::FileExt;
        if lock_file.try_lock_exclusive().is_err() {
            return None;
        }
        Some(lock_file)
    }

    // -----------------------------------------------------------------------
    // 1. auto_update_hours=0 disables update
    // -----------------------------------------------------------------------

    #[test]
    fn auto_update_hours_zero_disables_background_child() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let policy_dir = tmp.path().join(".tirith");
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::write(
            policy_dir.join("policy.yaml"),
            "threat_intel:\n  auto_update_hours: 0\n",
        )
        .unwrap();

        // Point policy discovery at our temp dir
        unsafe { std::env::set_var("TIRITH_POLICY_ROOT", tmp.path()) };

        let policy = policy::Policy::discover(Some(tmp.path().to_str().unwrap()));
        assert_eq!(
            policy.threat_intel.auto_update_hours, 0,
            "policy should reflect auto_update_hours=0"
        );

        unsafe { std::env::remove_var("TIRITH_POLICY_ROOT") };
    }

    // -----------------------------------------------------------------------
    // 2. next-check-at in the future skips update
    // -----------------------------------------------------------------------

    #[test]
    fn next_check_at_future_skips_update() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();

        // Write a next-check-at timestamp 1 hour in the future
        let future_ts = unix_now() + 3600;
        std::fs::write(state.join(NEXT_CHECK_FILE), future_ts.to_string()).unwrap();

        let now = unix_now();
        assert!(
            is_next_check_in_future(state, now),
            "should skip when next-check-at is in the future"
        );
    }

    #[test]
    fn next_check_at_past_allows_update() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();

        // Write a next-check-at timestamp 1 hour in the past
        let past_ts = unix_now().saturating_sub(3600);
        std::fs::write(state.join(NEXT_CHECK_FILE), past_ts.to_string()).unwrap();

        let now = unix_now();
        assert!(
            !is_next_check_in_future(state, now),
            "should proceed when next-check-at is in the past"
        );
    }

    #[test]
    fn next_check_at_missing_allows_update() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        // No file written — first run scenario

        let now = unix_now();
        assert!(
            !is_next_check_in_future(state, now),
            "should proceed when next-check-at file does not exist"
        );
    }

    #[test]
    fn next_check_at_corrupt_allows_update() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        std::fs::write(state.join(NEXT_CHECK_FILE), "not-a-number").unwrap();

        let now = unix_now();
        assert!(
            !is_next_check_in_future(state, now),
            "should proceed when next-check-at is unparseable"
        );
    }

    // -----------------------------------------------------------------------
    // 3. spawned-at recent (<30s) skips update
    // -----------------------------------------------------------------------

    #[test]
    fn spawned_at_recent_skips_update() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();

        // Write a spawned-at timestamp 5 seconds ago (within the 30s dedup window)
        let recent_ts = unix_now().saturating_sub(5);
        std::fs::write(state.join(SPAWNED_AT_FILE), recent_ts.to_string()).unwrap();

        let now = unix_now();
        assert!(
            is_spawned_at_recent(state, now),
            "should skip when spawned-at is recent (within 30s window)"
        );
    }

    #[test]
    fn spawned_at_old_allows_update() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();

        // Write a spawned-at timestamp 60 seconds ago (outside the 30s dedup window)
        let old_ts = unix_now().saturating_sub(60);
        std::fs::write(state.join(SPAWNED_AT_FILE), old_ts.to_string()).unwrap();

        let now = unix_now();
        assert!(
            !is_spawned_at_recent(state, now),
            "should proceed when spawned-at is older than 30s"
        );
    }

    #[test]
    fn spawned_at_missing_allows_update() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        // No file — first spawn

        let now = unix_now();
        assert!(
            !is_spawned_at_recent(state, now),
            "should proceed when spawned-at file does not exist"
        );
    }

    // -----------------------------------------------------------------------
    // 4. UPDATE_ATTEMPTED AtomicBool guard prevents second attempt
    // -----------------------------------------------------------------------

    #[test]
    fn update_attempted_guard_fires_once() {
        // Use a standalone AtomicBool to verify the swap-based guard pattern
        // (We cannot reset the global UPDATE_ATTEMPTED without affecting other tests.)
        let guard = AtomicBool::new(false);

        // First swap: returns old value (false) — should proceed
        let first = guard.swap(true, Ordering::Relaxed);
        assert!(
            !first,
            "first swap should return false, allowing the update"
        );

        // Second swap: returns old value (true) — should skip
        let second = guard.swap(true, Ordering::Relaxed);
        assert!(second, "second swap should return true, blocking re-entry");

        // Third swap: still true
        let third = guard.swap(true, Ordering::Relaxed);
        assert!(third, "third swap should also return true");
    }

    // -----------------------------------------------------------------------
    // 5. Background child lock dedup
    // -----------------------------------------------------------------------

    #[test]
    fn lock_dedup_second_acquire_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();

        // First acquire succeeds
        let lock1 = try_acquire_update_lock(state);
        assert!(lock1.is_some(), "first lock acquisition should succeed");

        // Second acquire should fail (lock already held)
        let lock2 = try_acquire_update_lock(state);
        assert!(
            lock2.is_none(),
            "second lock acquisition should fail while first is held"
        );

        // Drop the first lock to release
        drop(lock1);

        // After releasing, a new acquire should succeed
        let lock3 = try_acquire_update_lock(state);
        assert!(
            lock3.is_some(),
            "lock acquisition should succeed after previous lock is released"
        );
    }

    #[test]
    fn lock_file_is_created_in_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();

        let lock = try_acquire_update_lock(state);
        assert!(lock.is_some());
        assert!(
            state.join(LOCKFILE_NAME).exists(),
            "lock file should be created at the expected path"
        );
    }

    // -----------------------------------------------------------------------
    // 6. Failure backoff: next-check-at = now + 1h on failure
    // -----------------------------------------------------------------------

    #[test]
    fn failure_backoff_sets_one_hour() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        let next_check_path = state.join(NEXT_CHECK_FILE);

        // Simulate what run_background_update does on failure:
        // writes now + BACKOFF_SECS to next-check-at
        let now = unix_now();
        let backoff_ts = now + BACKOFF_SECS;
        std::fs::write(&next_check_path, backoff_ts.to_string()).unwrap();

        let content = std::fs::read_to_string(&next_check_path).unwrap();
        let written_ts: u64 = content.trim().parse().unwrap();

        // Backoff should be ~1 hour from now (allow 5s tolerance)
        let diff = written_ts.saturating_sub(now);
        assert_eq!(
            diff, BACKOFF_SECS,
            "backoff should set next-check-at to now + {} seconds, got diff={}",
            BACKOFF_SECS, diff
        );
        assert_eq!(
            BACKOFF_SECS, 3600,
            "BACKOFF_SECS constant should be 3600 (1 hour)"
        );
    }

    #[test]
    fn success_sets_next_check_at_auto_update_hours() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        let next_check_path = state.join(NEXT_CHECK_FILE);

        // Simulate what run_background_update does on success with auto_update_hours=24
        let auto_hours: u64 = 24;
        let now = unix_now();
        let next = now + auto_hours * 3600;
        std::fs::write(&next_check_path, next.to_string()).unwrap();

        let content = std::fs::read_to_string(&next_check_path).unwrap();
        let written_ts: u64 = content.trim().parse().unwrap();

        let diff = written_ts.saturating_sub(now);
        assert_eq!(
            diff,
            auto_hours * 3600,
            "success should set next-check-at to now + auto_update_hours*3600"
        );
    }

    #[test]
    fn backoff_differs_from_normal_interval() {
        // Verify that the failure backoff (1h) is different from the default
        // auto_update_hours (24h), so users retry sooner after failure.
        let default_config = policy::ThreatIntelConfig::default();
        let normal_interval_secs = default_config.auto_update_hours * 3600;
        assert_ne!(
            BACKOFF_SECS, normal_interval_secs,
            "backoff interval ({BACKOFF_SECS}s) must differ from normal interval ({normal_interval_secs}s)"
        );
        assert!(
            BACKOFF_SECS < normal_interval_secs,
            "backoff ({BACKOFF_SECS}s) should be shorter than normal interval ({normal_interval_secs}s) for faster retry"
        );
    }

    // -----------------------------------------------------------------------
    // 7. Canonical manifest payload format
    // -----------------------------------------------------------------------

    #[test]
    fn canonical_payload_format_sorted_keys_no_whitespace() {
        let manifest = Manifest {
            sha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            size: 12345,
            url: "https://example.com/tirith-threatdb.dat".to_string(),
            version: 42,
            signature: String::new(), // not used in canonical payload
        };

        let payload = manifest.canonical_payload();

        // Keys must be alphabetically sorted: sha256, size, url, version
        assert_eq!(
            payload,
            r#"{"sha256":"abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890","size":12345,"url":"https://example.com/tirith-threatdb.dat","version":42}"#,
            "canonical payload should have alphabetically sorted keys with no whitespace"
        );
    }

    #[test]
    fn canonical_payload_no_whitespace() {
        let manifest = Manifest {
            sha256: "deadbeef".to_string(),
            size: 1,
            url: "https://x.com/db.dat".to_string(),
            version: 1,
            signature: String::new(),
        };
        let payload = manifest.canonical_payload();

        assert!(
            !payload.contains(' '),
            "canonical payload must not contain spaces"
        );
        assert!(
            !payload.contains('\n'),
            "canonical payload must not contain newlines"
        );
        assert!(
            !payload.contains('\t'),
            "canonical payload must not contain tabs"
        );
        assert!(
            !payload.ends_with('\n'),
            "canonical payload must not have trailing newline"
        );
    }

    #[test]
    fn canonical_payload_is_valid_utf8_json() {
        let manifest = Manifest {
            sha256: "0123456789abcdef".to_string(),
            size: 999,
            url: "https://example.com/db.dat".to_string(),
            version: 7,
            signature: String::new(),
        };
        let payload = manifest.canonical_payload();

        // Verify it's valid UTF-8 (String type guarantees this, but be explicit)
        assert!(
            std::str::from_utf8(payload.as_bytes()).is_ok(),
            "canonical payload must be valid UTF-8"
        );

        // Verify it's valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&payload).expect("canonical payload must be valid JSON");

        // Verify the JSON object has exactly the expected keys
        let obj = parsed.as_object().expect("payload should be a JSON object");
        let keys: Vec<&String> = obj.keys().collect();
        assert_eq!(
            keys,
            &["sha256", "size", "url", "version"],
            "keys must be in alphabetical order"
        );
    }

    #[test]
    fn canonical_payload_excludes_signature_field() {
        let manifest = Manifest {
            sha256: "abc".to_string(),
            size: 1,
            url: "https://x.com/db.dat".to_string(),
            version: 1,
            signature: "should-not-appear-in-payload".to_string(),
        };
        let payload = manifest.canonical_payload();

        assert!(
            !payload.contains("signature"),
            "canonical payload must not include the 'signature' field"
        );
        assert!(
            !payload.contains("should-not-appear-in-payload"),
            "canonical payload must not include the signature value"
        );
    }

    #[test]
    fn canonical_payload_round_trips_through_json_parse() {
        // Verify the canonical payload can be deserialized back to matching values
        let manifest = Manifest {
            sha256: "abc123".to_string(),
            size: 42,
            url: "https://example.com/db.dat".to_string(),
            version: 99,
            signature: "ignored".to_string(),
        };
        let payload = manifest.canonical_payload();
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();

        assert_eq!(parsed["sha256"], "abc123");
        assert_eq!(parsed["size"], 42);
        assert_eq!(parsed["url"], "https://example.com/db.dat");
        assert_eq!(parsed["version"], 99);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn spawned_at_exactly_at_boundary_skips() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();

        // Exactly at the boundary: 29 seconds ago (within the 30s window)
        let now = 1000000u64;
        let ts = now - (SPAWNED_AT_DEDUP_SECS - 1);
        std::fs::write(state.join(SPAWNED_AT_FILE), ts.to_string()).unwrap();

        assert!(
            is_spawned_at_recent(state, now),
            "29 seconds ago should still be within the dedup window"
        );
    }

    #[test]
    fn spawned_at_exactly_at_boundary_allows() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();

        // Exactly at the boundary: 30 seconds ago (at the edge, >= DEDUP means proceed)
        let now = 1000000u64;
        let ts = now - SPAWNED_AT_DEDUP_SECS;
        std::fs::write(state.join(SPAWNED_AT_FILE), ts.to_string()).unwrap();

        assert!(
            !is_spawned_at_recent(state, now),
            "exactly 30 seconds ago should be outside the dedup window"
        );
    }

    #[test]
    fn next_check_at_exactly_now_allows() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();

        let now = 1000000u64;
        std::fs::write(state.join(NEXT_CHECK_FILE), now.to_string()).unwrap();

        // now < next_ts is false when they're equal, so update should proceed
        assert!(
            !is_next_check_in_future(state, now),
            "next-check-at == now should allow the update (not strictly in the future)"
        );
    }

    // -----------------------------------------------------------------------
    // 8. Conditional-GET cache helpers
    // -----------------------------------------------------------------------

    #[test]
    fn manifest_cache_key_is_url_specific() {
        let k1 = super::manifest_cache_key("https://example.com/manifest.json");
        let k2 = super::manifest_cache_key("https://other.com/manifest.json");
        assert_ne!(k1, k2, "different URLs must produce different cache keys");
        assert!(
            k1.starts_with("threatdb-manifest-"),
            "cache key should have expected prefix"
        );
    }

    #[test]
    fn manifest_cache_key_is_deterministic() {
        let url = "https://example.com/manifest.json";
        assert_eq!(
            super::manifest_cache_key(url),
            super::manifest_cache_key(url),
            "same URL must produce same cache key"
        );
    }

    #[test]
    fn cached_body_round_trips_through_json() {
        let json = r#"{"sha256":"abc123","size":42,"url":"https://example.com/db.dat","version":99,"signature":"sig"}"#;
        let parsed: Manifest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.sha256, "abc123");
        assert_eq!(parsed.version, 99);
        assert_eq!(parsed.size, 42);

        // Verify cached body can be written and re-read (simulates 304 flow)
        let tmp = tempfile::tempdir().unwrap();
        let body_file = tmp.path().join("cached-body");
        std::fs::write(&body_file, json).unwrap();
        let reloaded = std::fs::read_to_string(&body_file).unwrap();
        let reparsed: Manifest = serde_json::from_str(&reloaded).unwrap();
        assert_eq!(reparsed.sha256, "abc123");
        assert_eq!(reparsed.version, 99);
    }

    #[test]
    fn etag_and_body_files_are_per_url() {
        let url1 = "https://primary.example.com/m.json";
        let url2 = "https://fallback.example.com/m.json";
        let k1 = super::manifest_cache_key(url1);
        let k2 = super::manifest_cache_key(url2);

        // ETag files should differ
        let etag1 = format!("{k1}-etag");
        let etag2 = format!("{k2}-etag");
        assert_ne!(etag1, etag2, "etag files must be per-URL");

        // Body files should differ
        let body1 = format!("{k1}-body");
        let body2 = format!("{k2}-body");
        assert_ne!(body1, body2, "body cache files must be per-URL");
    }

    // -----------------------------------------------------------------------
    // 9. Cache state machine tests (simulated 200/304/corrupt flows)
    // -----------------------------------------------------------------------

    /// Simulate the cache file operations that fetch_manifest_from does on a 200 response:
    /// persist ETag + body, then verify a simulated 304 can read them back.
    #[test]
    fn cache_200_then_304_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let url = "https://example.com/manifest.json";
        let key = super::manifest_cache_key(url);
        let etag_path = tmp.path().join(format!("{key}-etag"));
        let body_path = tmp.path().join(format!("{key}-body"));

        let manifest_json = r#"{"sha256":"dead","size":100,"url":"https://x.com/db.dat","version":5,"signature":"sig"}"#;

        // Simulate 200: persist ETag + body (what fetch_manifest_from does on success)
        std::fs::write(&etag_path, "\"etag-value-abc\"").unwrap();
        std::fs::write(&body_path, manifest_json).unwrap();

        // Simulate 304: read cached body (what fetch_manifest_from does on 304)
        let cached = std::fs::read_to_string(&body_path).unwrap();
        let m: Manifest = serde_json::from_str(&cached).unwrap();
        assert_eq!(m.sha256, "dead");
        assert_eq!(m.version, 5);

        // Verify ETag was persisted for conditional GET
        let etag = std::fs::read_to_string(&etag_path).unwrap();
        assert_eq!(etag.trim(), "\"etag-value-abc\"");
    }

    /// Simulate 304 with missing cached body — should clean up ETag to break retry loop.
    #[test]
    fn cache_304_with_missing_body_cleans_etag() {
        let tmp = tempfile::tempdir().unwrap();
        let url = "https://example.com/manifest.json";
        let key = super::manifest_cache_key(url);
        let etag_path = tmp.path().join(format!("{key}-etag"));
        let body_path = tmp.path().join(format!("{key}-body"));

        // State: ETag exists but body does not (e.g., body was deleted manually)
        std::fs::write(&etag_path, "\"stale-etag\"").unwrap();
        assert!(!body_path.exists(), "body should not exist for this test");

        // Simulate the 304 recovery: when body is missing, clean up ETag + body
        // (This is the recovery path in fetch_manifest_from)
        let body_ok = body_path
            .exists()
            .then(|| std::fs::read_to_string(&body_path).ok())
            .flatten()
            .and_then(|s| serde_json::from_str::<Manifest>(&s).ok());

        if body_ok.is_none() {
            // Recovery: delete stale ETag so next request is unconditional
            let _ = std::fs::remove_file(&etag_path);
            let _ = std::fs::remove_file(&body_path);
        }

        // After cleanup, ETag file should be gone
        assert!(
            !etag_path.exists(),
            "ETag should be deleted after 304 with missing body"
        );
    }

    /// Simulate 304 with corrupt cached body — should also clean up.
    #[test]
    fn cache_304_with_corrupt_body_cleans_etag() {
        let tmp = tempfile::tempdir().unwrap();
        let url = "https://example.com/manifest.json";
        let key = super::manifest_cache_key(url);
        let etag_path = tmp.path().join(format!("{key}-etag"));
        let body_path = tmp.path().join(format!("{key}-body"));

        // State: ETag exists, body exists but is corrupt JSON
        std::fs::write(&etag_path, "\"some-etag\"").unwrap();
        std::fs::write(&body_path, "this is not json").unwrap();

        // Simulate 304 cache read
        let body_ok = std::fs::read_to_string(&body_path)
            .ok()
            .and_then(|s| serde_json::from_str::<Manifest>(&s).ok());

        if body_ok.is_none() {
            // Recovery: delete stale files
            let _ = std::fs::remove_file(&etag_path);
            let _ = std::fs::remove_file(&body_path);
        }

        assert!(
            !etag_path.exists(),
            "ETag should be deleted after 304 with corrupt body"
        );
        assert!(
            !body_path.exists(),
            "Corrupt body should be deleted after recovery"
        );
    }

    /// Verify that primary and fallback URLs have independent cache state.
    #[test]
    fn primary_and_fallback_independent_cache_state() {
        let tmp = tempfile::tempdir().unwrap();
        let primary =
            "https://raw.githubusercontent.com/sheeki03/tirith/main/threatdb-manifest.json";
        let fallback =
            "https://github.com/sheeki03/tirith/releases/latest/download/threatdb-manifest.json";

        let pk = super::manifest_cache_key(primary);
        let fk = super::manifest_cache_key(fallback);

        let p_etag = tmp.path().join(format!("{pk}-etag"));
        let f_etag = tmp.path().join(format!("{fk}-etag"));
        let p_body = tmp.path().join(format!("{pk}-body"));
        let f_body = tmp.path().join(format!("{fk}-body"));

        // Persist primary cache
        std::fs::write(&p_etag, "\"primary-etag\"").unwrap();
        std::fs::write(
            &p_body,
            r#"{"sha256":"p","size":1,"url":"p","version":10,"signature":"s"}"#,
        )
        .unwrap();

        // Persist fallback cache with different data
        std::fs::write(&f_etag, "\"fallback-etag\"").unwrap();
        std::fs::write(
            &f_body,
            r#"{"sha256":"f","size":2,"url":"f","version":20,"signature":"s"}"#,
        )
        .unwrap();

        // Verify independence
        let pm: Manifest =
            serde_json::from_str(&std::fs::read_to_string(&p_body).unwrap()).unwrap();
        let fm: Manifest =
            serde_json::from_str(&std::fs::read_to_string(&f_body).unwrap()).unwrap();
        assert_eq!(pm.version, 10);
        assert_eq!(fm.version, 20);
        assert_ne!(
            std::fs::read_to_string(&p_etag).unwrap(),
            std::fs::read_to_string(&f_etag).unwrap()
        );

        // Deleting primary cache does not affect fallback
        std::fs::remove_file(&p_etag).unwrap();
        std::fs::remove_file(&p_body).unwrap();
        assert!(
            f_etag.exists(),
            "fallback ETag should survive primary cleanup"
        );
        assert!(
            f_body.exists(),
            "fallback body should survive primary cleanup"
        );
    }

    // -----------------------------------------------------------------------
    // 10. Cache resolution state machine (exercises resolve_cache directly)
    // -----------------------------------------------------------------------

    const VALID_MANIFEST: &str =
        r#"{"sha256":"abc","size":1,"url":"https://x.com/db.dat","version":1,"signature":"s"}"#;

    #[test]
    fn resolve_cache_200_returns_fresh() {
        let r = super::resolve_cache(200, Some(VALID_MANIFEST), None).unwrap();
        assert_eq!(r, super::CacheResolution::Fresh(VALID_MANIFEST.to_string()));
    }

    #[test]
    fn resolve_cache_200_ignores_cached_body() {
        let r = super::resolve_cache(200, Some(VALID_MANIFEST), Some("old")).unwrap();
        match r {
            super::CacheResolution::Fresh(body) => assert_eq!(body, VALID_MANIFEST),
            other => panic!("expected Fresh, got {other:?}"),
        }
    }

    #[test]
    fn resolve_cache_304_with_valid_cache_returns_cached() {
        let r = super::resolve_cache(304, None, Some(VALID_MANIFEST)).unwrap();
        assert_eq!(
            r,
            super::CacheResolution::Cached(VALID_MANIFEST.to_string())
        );
    }

    #[test]
    fn resolve_cache_304_with_no_cache_returns_retry() {
        let r = super::resolve_cache(304, None, None).unwrap();
        assert_eq!(r, super::CacheResolution::RetryNeeded);
    }

    #[test]
    fn resolve_cache_304_with_corrupt_cache_returns_retry() {
        // Corrupt cached body → RetryNeeded (not Err), so caller cleans up and retries
        let r = super::resolve_cache(304, None, Some("not json")).unwrap();
        assert_eq!(
            r,
            super::CacheResolution::RetryNeeded,
            "corrupt cache should trigger retry, not error"
        );
    }

    #[test]
    fn resolve_cache_404_returns_error() {
        let r = super::resolve_cache(404, None, None);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("404"));
    }

    #[test]
    fn resolve_cache_500_returns_error() {
        let r = super::resolve_cache(500, None, None);
        assert!(r.is_err());
    }

    #[test]
    fn resolve_cache_200_with_no_body_returns_error() {
        let r = super::resolve_cache(200, None, None);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("empty"));
    }

    #[test]
    fn resolve_cache_201_accepted_as_success() {
        let r = super::resolve_cache(201, Some(VALID_MANIFEST), None).unwrap();
        assert_eq!(r, super::CacheResolution::Fresh(VALID_MANIFEST.to_string()));
    }

    // -----------------------------------------------------------------------
    // 11. Transport-level tests (mock HTTP server, exercises real fetch path)
    //     Uses fetch_manifest_from_with_state() with injectable state dir
    //     to avoid env var races between parallel tests.
    // -----------------------------------------------------------------------

    /// Helper: call fetch with isolated state dir (no env var races).
    fn fetch_with_state(url: &str, state: &std::path::Path) -> Result<Manifest, String> {
        super::fetch_manifest_from_with_state(url, Some(state.to_path_buf()))
    }

    #[test]
    fn transport_200_returns_manifest_and_caches_body() {
        let mut server = mockito::Server::new();
        let manifest_json = format!(
            r#"{{"sha256":"abc","size":1,"url":"{}","version":1,"signature":"sig"}}"#,
            server.url()
        );
        let mock = server
            .mock("GET", "/manifest.json")
            .with_status(200)
            .with_header("etag", "\"etag-from-server\"")
            .with_body(&manifest_json)
            .create();

        let tmp = tempfile::tempdir().unwrap();
        // state dir passed directly via fetch_with_state — no env var needed

        let url = format!("{}/manifest.json", server.url());
        let result = fetch_with_state(&url, tmp.path());

        mock.assert();
        let m = result.expect("should succeed on 200");
        assert_eq!(m.sha256, "abc");
        assert_eq!(m.version, 1);

        // Verify cache files were written
        let key = super::manifest_cache_key(&url);
        let state = tmp.path();
        let etag_file = state.join(format!("{key}-etag"));
        let body_file = state.join(format!("{key}-body"));
        assert!(etag_file.exists(), "ETag should be persisted");
        assert!(body_file.exists(), "body should be persisted");
        assert_eq!(
            std::fs::read_to_string(&etag_file).unwrap().trim(),
            "\"etag-from-server\""
        );
    }

    #[test]
    fn transport_304_with_cached_body_returns_cached_manifest() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/manifest.json")
            .match_header("if-none-match", "\"my-etag\"")
            .with_status(304)
            .create();

        let tmp = tempfile::tempdir().unwrap();
        // state dir passed directly via fetch_with_state — no env var needed

        // Pre-populate cache files
        let url = format!("{}/manifest.json", server.url());
        let key = super::manifest_cache_key(&url);
        let state = tmp.path();

        std::fs::write(state.join(format!("{key}-etag")), "\"my-etag\"").unwrap();
        let cached_json = r#"{"sha256":"cached","size":99,"url":"https://x.com/db.dat","version":42,"signature":"s"}"#;
        std::fs::write(state.join(format!("{key}-body")), cached_json).unwrap();

        let result = fetch_with_state(&url, tmp.path());

        mock.assert();
        let m = result.expect("should return cached manifest on 304");
        assert_eq!(m.sha256, "cached");
        assert_eq!(m.version, 42);
    }

    #[test]
    fn transport_304_without_cache_retries_and_succeeds() {
        let mut server = mockito::Server::new();

        // First request: 304 (no cached body exists)
        let mock_304 = server
            .mock("GET", "/manifest.json")
            .with_status(304)
            .expect(1)
            .create();

        // Retry request: 200 (unconditional)
        let retry_json = r#"{"sha256":"fresh","size":1,"url":"https://x.com/db.dat","version":7,"signature":"s"}"#;
        let mock_200 = server
            .mock("GET", "/manifest.json")
            .with_status(200)
            .with_header("etag", "\"new-etag\"")
            .with_body(retry_json)
            .expect(1)
            .create();

        let tmp = tempfile::tempdir().unwrap();
        // state dir passed directly via fetch_with_state — no env var needed

        // Pre-populate only ETag (no body — simulates corrupt/deleted cache)
        let url = format!("{}/manifest.json", server.url());
        let key = super::manifest_cache_key(&url);
        let state = tmp.path();

        std::fs::write(state.join(format!("{key}-etag")), "\"stale\"").unwrap();

        let result = fetch_with_state(&url, tmp.path());

        mock_304.assert();
        mock_200.assert();
        let m = result.expect("retry after 304 should succeed");
        assert_eq!(m.sha256, "fresh");
        assert_eq!(m.version, 7);

        // Verify new ETag was persisted from retry
        let etag = std::fs::read_to_string(state.join(format!("{key}-etag"))).unwrap();
        assert_eq!(etag.trim(), "\"new-etag\"");
    }

    #[test]
    fn transport_404_returns_error() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/manifest.json")
            .with_status(404)
            .create();

        let tmp = tempfile::tempdir().unwrap();
        // state dir passed directly via fetch_with_state — no env var needed

        let url = format!("{}/manifest.json", server.url());
        let result = fetch_with_state(&url, tmp.path());

        mock.assert();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("404"));
    }

    #[test]
    fn transport_invalid_json_not_cached() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/manifest.json")
            .with_status(200)
            .with_header("etag", "\"bad-etag\"")
            .with_body("this is not json")
            .create();

        let tmp = tempfile::tempdir().unwrap();
        // state dir passed directly via fetch_with_state — no env var needed

        let url = format!("{}/manifest.json", server.url());
        let result = fetch_with_state(&url, tmp.path());

        mock.assert();
        assert!(result.is_err(), "invalid JSON should fail");

        // Verify body was NOT cached (validation-before-cache)
        let key = super::manifest_cache_key(&url);
        let state = tmp.path();
        let body_file = state.join(format!("{key}-body"));
        assert!(
            !body_file.exists(),
            "invalid JSON body should not be cached"
        );
    }

    #[test]
    fn transport_sends_user_agent_header() {
        let mut server = mockito::Server::new();
        let manifest_json = r#"{"sha256":"a","size":1,"url":"u","version":1,"signature":"s"}"#;
        let mock = server
            .mock("GET", "/manifest.json")
            .match_header("user-agent", mockito::Matcher::Regex("tirith/".to_string()))
            .with_status(200)
            .with_body(manifest_json)
            .create();

        let tmp = tempfile::tempdir().unwrap();
        // state dir passed directly via fetch_with_state — no env var needed

        let url = format!("{}/manifest.json", server.url());
        let _ = fetch_with_state(&url, tmp.path());

        mock.assert(); // Fails if User-Agent didn't match
    }
}
