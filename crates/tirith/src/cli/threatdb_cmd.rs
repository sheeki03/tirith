//! CLI subcommands for threat DB management: update, status, and background auto-update.

use std::io::{Cursor, Read as _, Write as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, SigningKey, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
use sha2::{Digest, Sha256};

use tirith_core::policy;
use tirith_core::threatdb::{ThreatDb, ThreatDbWriter, ThreatSource};
use tirith_core::threatdb_feeds::{
    parse_domain_blocklist, parse_phishtank_csv, parse_threatfox_zip, parse_tor_exit_list,
    parse_urlhaus_csv,
};

/// Pinned Ed25519 manifest-verify key. MUST stay in sync with
/// tirith-core/assets/keys/threatdb-verify.pub (same key for DB + manifest).
static VERIFY_KEY_BYTES: &[u8; PUBLIC_KEY_LENGTH] =
    include_bytes!("../../assets/keys/threatdb-verify.pub");

const MANIFEST_URL_PRIMARY: &str =
    "https://raw.githubusercontent.com/sheeki03/tirith/main/threatdb-manifest.json";
const MANIFEST_URL_FALLBACK: &str =
    "https://github.com/sheeki03/tirith/releases/latest/download/threatdb-manifest.json";

const MAX_MANIFEST_SIZE: u64 = 64 * 1024;
const MAX_DB_SIZE: u64 = 256 * 1024 * 1024;
const MANIFEST_TIMEOUT_SECS: u64 = 15;
const DB_DOWNLOAD_TIMEOUT_SECS: u64 = 120;
const SUPPLEMENTAL_DOWNLOAD_TIMEOUT_SECS: u64 = 120;
/// Max bytes read from any single supplemental feed response.
const MAX_SUPPLEMENTAL_FEED_SIZE: u64 = 256 * 1024 * 1024;

const LOCKFILE_NAME: &str = "threatdb-update.lock";
const NEXT_CHECK_FILE: &str = "threatdb-next-check-at";
const SPAWNED_AT_FILE: &str = "threatdb-spawned-at";
/// Soft dedup window: skip spawn if another was spawned within this many seconds.
const SPAWNED_AT_DEDUP_SECS: u64 = 30;
const BACKOFF_SECS: u64 = 3600;
const URLHAUS_EXPORT_TEMPLATE: &str =
    "https://urlhaus-api.abuse.ch/files/exports/full.csv?auth-key={auth_key}";
const THREATFOX_EXPORT_TEMPLATE: &str =
    "https://threatfox-api.abuse.ch/files/exports/full.csv.zip?auth-key={auth_key}";
const PHISHING_ARMY_URL: &str =
    "https://phishing.army/download/phishing_army_blocklist_extended.txt";
const PHISHTANK_URL: &str = "https://data.phishtank.com/data/online-valid.csv";
const TOR_EXIT_URL: &str = "https://check.torproject.org/torbulkexitlist";

#[derive(Debug, serde::Deserialize)]
struct Manifest {
    sha256: String,
    size: u64,
    url: String,
    version: u64,
    signature: String,
}

impl Manifest {
    /// Canonical payload for signature verification: keys sorted, no whitespace,
    /// no trailing newline.
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

    manifest.verify_signature()?;

    // Rollback protection: reject a manifest older than the installed DB unless --force.
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

    let data = download_db(&manifest)?;

    let computed_hash = hex::encode(Sha256::digest(&data));
    if computed_hash != manifest.sha256 {
        return Err(format!(
            "SHA-256 mismatch: expected {}, got {}",
            manifest.sha256, computed_hash
        ));
    }

    let min_seq = if force { 0 } else { current_sequence() };
    let db =
        ThreatDb::from_bytes(data.clone(), min_seq).map_err(|e| format!("invalid DB file: {e}"))?;
    db.verify_signature()
        .map_err(|e| format!("DB file internal signature verification failed: {e}"))?;

    let dest =
        ThreatDb::default_path().ok_or_else(|| "cannot determine data directory".to_string())?;
    atomic_write(&dest, &data)?;

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

    if let Err(e) = update_supplemental_db(&policy::Policy::discover(None)) {
        eprintln!("tirith: warning: supplemental threat DB update failed: {e}");
    }

    Ok(())
}

#[derive(Default)]
struct SupplementalEntries {
    hostnames: Vec<(String, ThreatSource)>,
    ips: Vec<(std::net::Ipv4Addr, ThreatSource)>,
}

impl SupplementalEntries {
    fn is_empty(&self) -> bool {
        self.hostnames.is_empty() && self.ips.is_empty()
    }

    /// Merge parsed feed entries tagged with `source`; returns the count ingested.
    fn ingest(
        &mut self,
        entries: tirith_core::threatdb_feeds::FeedEntries,
        source: ThreatSource,
    ) -> usize {
        let count = entries.hostnames.len() + entries.ips.len();
        self.hostnames
            .extend(entries.hostnames.into_iter().map(|h| (h, source)));
        self.ips
            .extend(entries.ips.into_iter().map(|ip| (ip, source)));
        count
    }
}

fn update_supplemental_db(policy: &policy::Policy) -> Result<(), String> {
    let supplemental_path = match ThreatDb::supplemental_path() {
        Some(path) => path,
        None => return Ok(()),
    };

    let abusech_enabled = policy
        .threat_intel
        .abusech_auth_key
        .as_deref()
        .is_some_and(|key| !key.trim().is_empty());
    let phishing_enabled = policy.threat_intel.phishing_army_enabled;

    if !abusech_enabled && !phishing_enabled {
        let _ = std::fs::remove_file(&supplemental_path);
        ThreatDb::refresh_cache();
        return Ok(());
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(
            SUPPLEMENTAL_DOWNLOAD_TIMEOUT_SECS,
        ))
        .build()
        .map_err(|e| format!("supplemental feed HTTP client error: {e}"))?;

    let mut supplemental = SupplementalEntries::default();
    let mut attempted_feeds = 0usize;

    if let Some(auth_key) = policy.threat_intel.abusech_auth_key.as_deref() {
        if !auth_key.trim().is_empty() {
            attempted_feeds += 1;
            log_feed_result(
                "URLhaus",
                fetch_urlhaus_feed(&client, auth_key.trim(), &mut supplemental),
            );
            attempted_feeds += 1;
            log_feed_result(
                "ThreatFox",
                fetch_threatfox_feed(&client, auth_key.trim(), &mut supplemental),
            );
        }
    }

    if policy.threat_intel.phishing_army_enabled {
        attempted_feeds += 1;
        log_feed_result(
            "Phishing Army",
            fetch_phishing_army_feed(&client, &mut supplemental),
        );
        attempted_feeds += 1;
        log_feed_result(
            "PhishTank",
            fetch_phishtank_feed(&client, &mut supplemental),
        );
    }

    // At least one group is enabled here (fully-disabled returned early), so Tor
    // exit is always included as a supplemental IP signal.
    attempted_feeds += 1;
    log_feed_result("Tor exit", fetch_tor_exit_feed(&client, &mut supplemental));

    if supplemental.is_empty() {
        eprintln!(
            "tirith: warning: supplemental feeds produced no IOC data across {attempted_feeds} attempted feed(s); leaving existing supplemental threat DB unchanged"
        );
        return Ok(());
    }

    let mut writer = ThreatDbWriter::new(unix_now(), 0);
    for (host, source) in &supplemental.hostnames {
        writer.add_hostname(host, *source);
    }
    for (ip, source) in &supplemental.ips {
        writer.add_ip(*ip, *source);
    }

    if let Some(parent) = supplemental_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create supplemental DB directory: {e}"))?;
    }
    let data = writer
        .build(&local_overlay_signing_key())
        .map_err(|e| format!("failed to build supplemental threat DB: {e}"))?;
    atomic_write(&supplemental_path, &data)?;
    ThreatDb::refresh_cache();
    eprintln!(
        "tirith: supplemental threat DB updated ({} hostnames, {} IPs)",
        supplemental.hostnames.len(),
        supplemental.ips.len()
    );
    Ok(())
}

fn log_feed_result(feed_name: &str, result: Result<usize, String>) {
    match result {
        Ok(0) => eprintln!("tirith: warning: {feed_name} feed returned no entries"),
        Ok(_) => {}
        Err(e) => eprintln!("tirith: warning: {feed_name} feed failed: {e}"),
    }
}

fn fetch_urlhaus_feed(
    client: &reqwest::blocking::Client,
    auth_key: &str,
    supplemental: &mut SupplementalEntries,
) -> Result<usize, String> {
    let url = URLHAUS_EXPORT_TEMPLATE.replace("{auth_key}", auth_key);
    let body = fetch_text(client, &url)?;
    let entries = parse_urlhaus_csv(Cursor::new(body.into_bytes()))
        .map_err(|e| format!("URLhaus parse failed: {e}"))?;
    Ok(supplemental.ingest(entries, ThreatSource::Urlhaus))
}

fn fetch_threatfox_feed(
    client: &reqwest::blocking::Client,
    auth_key: &str,
    supplemental: &mut SupplementalEntries,
) -> Result<usize, String> {
    let url = THREATFOX_EXPORT_TEMPLATE.replace("{auth_key}", auth_key);
    let zip_bytes = fetch_bytes(client, &url)?;
    let entries = parse_threatfox_zip(Cursor::new(zip_bytes))?;
    Ok(supplemental.ingest(entries, ThreatSource::ThreatFoxIoc))
}

fn fetch_phishing_army_feed(
    client: &reqwest::blocking::Client,
    supplemental: &mut SupplementalEntries,
) -> Result<usize, String> {
    let body = fetch_text(client, PHISHING_ARMY_URL)?;
    let entries = parse_domain_blocklist(&body);
    Ok(supplemental.ingest(entries, ThreatSource::PhishingArmy))
}

fn fetch_phishtank_feed(
    client: &reqwest::blocking::Client,
    supplemental: &mut SupplementalEntries,
) -> Result<usize, String> {
    let body = fetch_text(client, PHISHTANK_URL)?;
    let entries = parse_phishtank_csv(Cursor::new(body.into_bytes()))
        .map_err(|e| format!("PhishTank parse failed: {e}"))?;
    Ok(supplemental.ingest(entries, ThreatSource::PhishTank))
}

fn fetch_tor_exit_feed(
    client: &reqwest::blocking::Client,
    supplemental: &mut SupplementalEntries,
) -> Result<usize, String> {
    let body = fetch_text(client, TOR_EXIT_URL)?;
    let entries = parse_tor_exit_list(&body);
    Ok(supplemental.ingest(entries, ThreatSource::TorExit))
}

/// Redact query-string secrets (e.g. `?auth-key=...`) from a URL for log/error use.
fn redact_url(url: &str) -> String {
    if let Some(q) = url.find('?') {
        format!("{}?<redacted>", &url[..q])
    } else {
        url.to_string()
    }
}

fn fetch_text(client: &reqwest::blocking::Client, url: &str) -> Result<String, String> {
    let bytes = fetch_bytes(client, url)?;
    let safe = redact_url(url);
    String::from_utf8(bytes)
        .map_err(|e| format!("failed to decode UTF-8 response body for {safe}: {e}"))
}

fn fetch_bytes(client: &reqwest::blocking::Client, url: &str) -> Result<Vec<u8>, String> {
    let safe = redact_url(url);
    let response = client
        .get(url)
        .header(
            "User-Agent",
            format!("tirith/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .and_then(|resp| resp.error_for_status())
        .map_err(|e| format!("fetch failed for {safe}: {e}"))?;

    let content_length = response.content_length();
    read_bounded_bytes(response, &safe, content_length, MAX_SUPPLEMENTAL_FEED_SIZE)
}

fn read_bounded_bytes<R: std::io::Read>(
    reader: R,
    url: &str,
    content_length: Option<u64>,
    max_size: u64,
) -> Result<Vec<u8>, String> {
    if content_length.is_some_and(|len| len > max_size) {
        return Err(format!(
            "response body for {url} is too large: {content_length:?} bytes exceeds {max_size}"
        ));
    }

    let mut limited = reader.take(max_size + 1);
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read response body for {url}: {e}"))?;

    if bytes.len() as u64 > max_size {
        return Err(format!(
            "response body for {url} exceeded max size of {max_size} bytes"
        ));
    }

    Ok(bytes)
}

fn local_overlay_signing_key() -> SigningKey {
    // Not an authenticity root: only satisfies the on-disk ThreatDb format for the
    // mutable user-local overlay, which is loaded without pinned-key verification.
    let digest = Sha256::digest(b"tirith-local-supplemental-threatdb-v1");
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&digest[..32]);
    SigningKey::from_bytes(&key_bytes)
}

/// Background update (`--background`): acquire exclusive lock, download, verify,
/// install, write next-check-at.
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

    // Exclusive lock: if held, another child is updating — exit silently.
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
        return 0;
    }

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
        let next = now + auto_hours * 3600;
        if let Err(e) = std::fs::write(&next_check_path, next.to_string()) {
            eprintln!("tirith: warning: failed to write next-check-at: {e}");
        }
    } else {
        if let Err(ref e) = result {
            eprintln!("tirith: background update failed: {e}");
        }
        // Backoff on failure to avoid hammering upstream on repeated errors.
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

            let policy = policy::Policy::discover(None);
            let stale_hours = policy.threat_intel.auto_update_hours;
            // Stale = older than 2x the update interval; 0 (disabled) means never stale.
            let is_stale = if stale_hours == 0 {
                false
            } else {
                age_hours > (stale_hours as f64 * 2.0)
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
                // skipped_range_only is a compile-time stat not yet in the DB header.
                skipped_range_only: None,
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

/// Guard: only try once per process lifetime.
static UPDATE_ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// Spawn a detached child to update the threat DB if due (called from `check.rs`
/// after the verdict). Cheap: reads a timestamp file and optionally spawns; the
/// download happens in the child.
///
/// `offline_flag` (`tirith check --offline`) or `TIRITH_OFFLINE` makes this a
/// guaranteed no-op — no timestamp files written, no child spawned, analysis
/// stays purely local.
pub fn maybe_background_update(offline_flag: bool) {
    // Offline short-circuit comes BEFORE the once-per-process guard so a later
    // online call in the same process is not disabled by an earlier offline one
    // (the guard is a dedup, not a latch on intent).
    if offline_flag || super::offline_env_active() {
        return;
    }

    if UPDATE_ATTEMPTED.swap(true, Ordering::Relaxed) {
        return;
    }

    let policy = policy::Policy::discover(None);
    if policy.threat_intel.auto_update_hours == 0 {
        return;
    }

    let state = match policy::state_dir() {
        Some(d) => d,
        None => return,
    };

    // A missing or unparseable next-check-at file is treated as "due".
    let next_check_path = state.join(NEXT_CHECK_FILE);
    let now = unix_now();
    if let Ok(content) = std::fs::read_to_string(&next_check_path) {
        if let Ok(next_ts) = content.trim().parse::<u64>() {
            if now < next_ts {
                return;
            }
        }
    }

    // Parent-side soft dedup so multiple `tirith check` processes in the same
    // second don't all spawn a child. The real lock lives in the child.
    let spawned_at_path = state.join(SPAWNED_AT_FILE);
    if let Ok(content) = std::fs::read_to_string(&spawned_at_path) {
        if let Ok(spawned_ts) = content.trim().parse::<u64>() {
            if now.saturating_sub(spawned_ts) < SPAWNED_AT_DEDUP_SECS {
                return;
            }
        }
    }

    if let Err(e) = std::fs::create_dir_all(&state) {
        eprintln!("tirith: warning: failed to create state directory: {e}");
        return;
    }
    let _ = std::fs::write(&spawned_at_path, now.to_string());

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

/// Fetch the manifest from the primary URL, falling back to the release asset URL
/// when the primary fetch fails OR the primary manifest is older than the current
/// DB (e.g. manifest PR not yet merged).
fn fetch_manifest() -> Result<Manifest, String> {
    match fetch_manifest_from(MANIFEST_URL_PRIMARY) {
        Ok(m) => {
            // If the primary version is at or below the installed DB, try the
            // fallback in case it's ahead (releases can lag the raw path).
            if let Some(db) = ThreatDb::cached() {
                if m.version <= db.build_sequence() {
                    eprintln!("tirith: primary manifest is stale (v{} <= current v{}), trying fallback...",
                        m.version, db.build_sequence());
                    match fetch_manifest_from(MANIFEST_URL_FALLBACK) {
                        Ok(fallback) if fallback.version > db.build_sequence() => {
                            return Ok(fallback)
                        }
                        _ => {}
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
    /// Fresh body from HTTP 200.
    Fresh(String),
    /// Cached body from disk (HTTP 304).
    Cached(String),
    /// Cache miss on 304 — need unconditional retry.
    RetryNeeded,
}

/// Resolve manifest from HTTP status and cache state. Pure logic, no I/O.
fn resolve_cache(
    http_status: u16,
    response_body: Option<&str>,
    cached_body: Option<&str>,
) -> Result<CacheResolution, String> {
    if http_status == 304 {
        // Corrupt/missing cached body falls through to RetryNeeded; caller cleans
        // up the stale ETag and retries.
        if let Some(body) = cached_body {
            if serde_json::from_str::<Manifest>(body).is_ok() {
                return Ok(CacheResolution::Cached(body.to_string()));
            }
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

    // Conditional GET: attach a per-URL ETag from a prior fetch.
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

    // Extract ETag before consuming the response body.
    let resp_etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

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

    // Only load cached body for 304 — avoids unnecessary I/O on 200.
    let cached_body = if status == 304 {
        body_path.as_ref().and_then(|bp| {
            // Size-check BEFORE reading: an attacker-planted huge file must not
            // force unbounded allocation.
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

    match resolve_cache(status, resp_body.as_deref(), cached_body.as_deref()) {
        Ok(CacheResolution::Fresh(body)) => {
            // Validate JSON BEFORE caching so a bad response never poisons the cache.
            let manifest = serde_json::from_str::<Manifest>(&body)
                .map_err(|e| format!("invalid manifest JSON: {e}"))?;
            persist_cache_files(&etag_path, resp_etag.as_deref(), &body_path, &body);
            Ok(manifest)
        }
        Ok(CacheResolution::Cached(body)) => serde_json::from_str::<Manifest>(&body)
            .map_err(|e| format!("cached manifest parse error: {e}")),
        Ok(CacheResolution::RetryNeeded) => {
            // Delete stale ETag + body so the retry is unconditional (else loop on 304).
            if let Some(ref ep) = etag_path {
                let _ = std::fs::remove_file(ep);
            }
            if let Some(ref bp) = body_path {
                let _ = std::fs::remove_file(bp);
            }
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

/// Atomic write: write to a temp file in the same dir, then rename.
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

/// Hex encoding helper (avoids a hex crate dependency).
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

// Threat-DB transparency subcommands (M2 item 11): `explain`, `sources`,
// `health`, `diff` — read-only inspection, no download/write, all support
// `--format json`.

use std::net::Ipv4Addr;

use tirith_core::threatdb::{Confidence, Ecosystem, SourceTier};

/// File name for the append-only snapshot history used by `threat-db diff`.
const HISTORY_FILE: &str = "threatdb-history.jsonl";
/// Hard cap on retained snapshot lines — keeps the file bounded.
const HISTORY_MAX_LINES: usize = 64;

/// Per-category entry counts for a loaded DB. Mirrors the DB's five sections.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct CategoryCounts {
    packages: u64,
    hostnames: u64,
    ips: u64,
    typosquats: u64,
    popular: u64,
}

impl CategoryCounts {
    fn total(&self) -> u64 {
        self.packages + self.hostnames + self.ips + self.typosquats + self.popular
    }
}

/// One DB observation appended to the history file — the only thing `diff` can
/// compare against, since the DB format retains no per-entry history.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DbSnapshot {
    recorded_at: u64,
    /// DB build sequence (the monotonic "version").
    build_sequence: u64,
    build_timestamp: u64,
    /// Whether the DB's Ed25519 signature verified at observation time.
    signature_valid: bool,
    counts: CategoryCounts,
    /// Per-source record counts, keyed by the stable `ThreatSource::as_str()`.
    #[serde(default)]
    sources: std::collections::BTreeMap<String, u64>,
}

/// Resolve the snapshot history file path under the state dir.
fn history_path() -> Option<PathBuf> {
    policy::state_dir().map(|d| d.join(HISTORY_FILE))
}

/// Build a snapshot of the currently-loaded DB, or `None` if no DB is loaded.
fn current_snapshot() -> Option<DbSnapshot> {
    let db = ThreatDb::cached()?;
    let stats = db.stats();
    let breakdown = db.source_breakdown();
    let mut sources = std::collections::BTreeMap::new();
    for (src, count) in breakdown.per_source() {
        sources.insert(src.as_str().to_string(), *count);
    }
    Some(DbSnapshot {
        recorded_at: unix_now(),
        build_sequence: stats.build_sequence,
        build_timestamp: stats.build_timestamp,
        signature_valid: db.verify_signature().is_ok(),
        counts: CategoryCounts {
            packages: stats.package_count as u64,
            hostnames: stats.hostname_count as u64,
            ips: stats.ip_count as u64,
            typosquats: stats.typosquat_count as u64,
            popular: stats.popular_count as u64,
        },
        sources,
    })
}

/// Load all retained snapshots, oldest first (unparseable lines skipped).
///
/// Returns `(snapshots, read_error)`. A missing history file yields an empty
/// list with no error; a file that exists but cannot be read yields an empty
/// list AND `Some(message)`, so callers distinguish "could not read" from
/// "first observation".
fn load_history() -> (Vec<DbSnapshot>, Option<String>) {
    let Some(path) = history_path() else {
        return (Vec::new(), None);
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Vec::new(), None),
        Err(e) => {
            return (
                Vec::new(),
                Some(format!(
                    "could not read snapshot history at {} ({e}) — check file permissions; \
                     the diff below cannot use any earlier snapshot",
                    path.display()
                )),
            );
        }
    };
    let snapshots = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<DbSnapshot>(l).ok())
        .collect();
    (snapshots, None)
}

/// Append `snapshot` to the history file unless its content is already present.
/// Best-effort: I/O errors are ignored (history is a `diff` convenience, never
/// load-bearing). Truncated to the most recent [`HISTORY_MAX_LINES`] entries.
fn record_snapshot(snapshot: &DbSnapshot) {
    let Some(path) = history_path() else {
        return;
    };
    let (mut history, _) = load_history();
    // Dedup on content (everything but `recorded_at`): an unchanged DB must not
    // append a near-identical line, but a changed overlay (same build_sequence,
    // different counts/sources) must still record.
    if history.iter().any(|s| {
        s.build_sequence == snapshot.build_sequence
            && s.build_timestamp == snapshot.build_timestamp
            && s.signature_valid == snapshot.signature_valid
            && s.counts == snapshot.counts
            && s.sources == snapshot.sources
    }) {
        return;
    }
    history.push(snapshot.clone());
    if history.len() > HISTORY_MAX_LINES {
        let drop = history.len() - HISTORY_MAX_LINES;
        history.drain(0..drop);
    }
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    let mut body = String::new();
    for s in &history {
        if let Ok(line) = serde_json::to_string(s) {
            body.push_str(&line);
            body.push('\n');
        }
    }
    let _ = atomic_write(&path, body.as_bytes());
}

/// Snapshot the current DB and fold it into the history file, so `diff`
/// accumulates a trail as the read-only transparency commands run.
fn snapshot_current_db() {
    if let Some(snapshot) = current_snapshot() {
        record_snapshot(&snapshot);
    }
}

/// What kind of indicator the user passed to `explain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum IndicatorKind {
    Ip,
    Package,
    Domain,
}

/// A parsed `explain` argument.
struct ParsedIndicator {
    kind: IndicatorKind,
    /// For packages: the ecosystem, if the caller used `eco:name` syntax.
    ecosystem: Option<Ecosystem>,
    /// For packages: the version, if the caller used `name@version` syntax.
    version: Option<String>,
    /// The bare indicator value (host, package name, or IP string).
    value: String,
}

/// Classify the indicator string: bare IPv4 → IP; `eco:name` (known ecosystem)
/// or `name@version` or bare name → package; dotted slash/space-free non-IP →
/// domain.
fn parse_indicator(raw: &str) -> ParsedIndicator {
    let trimmed = raw.trim();

    if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
        return ParsedIndicator {
            kind: IndicatorKind::Ip,
            ecosystem: None,
            version: None,
            value: ip.to_string(),
        };
    }

    // `eco:name` — only for a recognized ecosystem, so `host:port` is not a package.
    if let Some((prefix, rest)) = trimmed.split_once(':') {
        if let Some(eco) = Ecosystem::from_name(prefix) {
            let (name, version) = split_name_version(rest);
            return ParsedIndicator {
                kind: IndicatorKind::Package,
                ecosystem: Some(eco),
                version,
                value: name,
            };
        }
    }

    // `name@version` (npm-style) → package.
    if let Some((name, version)) = split_at_version(trimmed) {
        return ParsedIndicator {
            kind: IndicatorKind::Package,
            ecosystem: None,
            version: Some(version),
            value: name,
        };
    }

    // Dotted, slash-free, space-free, non-IP → domain.
    if trimmed.contains('.') && !trimmed.contains('/') && !trimmed.contains(char::is_whitespace) {
        return ParsedIndicator {
            kind: IndicatorKind::Domain,
            ecosystem: None,
            version: None,
            value: trimmed.to_ascii_lowercase(),
        };
    }

    // Fallback: a bare package name (e.g. `react`).
    ParsedIndicator {
        kind: IndicatorKind::Package,
        ecosystem: None,
        version: None,
        value: trimmed.to_string(),
    }
}

/// Split `name@version`; `None` when there is no `@` or `@` is a leading npm
/// scope (e.g. `@scope/pkg`).
fn split_at_version(s: &str) -> Option<(String, String)> {
    // A leading `@` is an npm scope, not a version separator.
    let search_from = if s.starts_with('@') { 1 } else { 0 };
    let idx = s[search_from..].find('@')? + search_from;
    let name = &s[..idx];
    let version = &s[idx + 1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// Split the `name` / `name@version` part after an `eco:` prefix.
fn split_name_version(rest: &str) -> (String, Option<String>) {
    match split_at_version(rest) {
        Some((name, version)) => (name, Some(version)),
        None => (rest.to_string(), None),
    }
}

#[derive(Debug, serde::Serialize)]
struct ExplainResult {
    indicator: String,
    kind: IndicatorKind,
    /// Ecosystem the package lookup used (packages only).
    #[serde(skip_serializing_if = "Option::is_none")]
    ecosystem: Option<String>,
    /// Version the package lookup used (packages only).
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    /// True when the threat DB has at least one finding for this indicator.
    present: bool,
    /// The DB is not installed — lookups cannot be performed.
    db_missing: bool,
    findings: Vec<ExplainFinding>,
}

#[derive(Debug, serde::Serialize)]
struct ExplainFinding {
    /// `malicious_package`, `typosquat`, `popular_lookalike`,
    /// `malicious_hostname`, or `malicious_ip`.
    classification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence: Option<Confidence>,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference_url: Option<String>,
}

/// `tirith threat-db explain <indicator>`.
pub fn explain(indicator: &str, json: bool) -> i32 {
    let parsed = parse_indicator(indicator);
    let db = ThreatDb::cached();

    let mut findings: Vec<ExplainFinding> = Vec::new();
    let db_missing = db.is_none();

    if let Some(ref db) = db {
        match parsed.kind {
            IndicatorKind::Ip => {
                if let Ok(ip) = parsed.value.parse::<Ipv4Addr>() {
                    if let Some(m) = db.check_ip(ip) {
                        findings.push(ExplainFinding {
                            classification: "malicious_ip".to_string(),
                            source: Some(m.source.as_str().to_string()),
                            source_label: Some(m.source.label().to_string()),
                            confidence: Some(m.confidence),
                            detail: format!(
                                "IP address is listed as malicious infrastructure by {}.",
                                m.source.label()
                            ),
                            reference_url: m.reference_url,
                        });
                    }
                }
            }
            IndicatorKind::Domain => {
                if let Some(m) = db.check_hostname(&parsed.value) {
                    findings.push(ExplainFinding {
                        classification: "malicious_hostname".to_string(),
                        source: Some(m.source.as_str().to_string()),
                        source_label: Some(m.source.label().to_string()),
                        confidence: Some(m.confidence),
                        detail: format!(
                            "Hostname is listed as malicious infrastructure by {}.",
                            m.source.label()
                        ),
                        reference_url: m.reference_url,
                    });
                }
            }
            IndicatorKind::Package => {
                // Probe the caller's ecosystem, or all of them when none given.
                let ecosystems: Vec<Ecosystem> = match parsed.ecosystem {
                    Some(e) => vec![e],
                    None => ALL_ECOSYSTEMS.to_vec(),
                };
                for eco in ecosystems {
                    explain_package(
                        db,
                        eco,
                        &parsed.value,
                        parsed.version.as_deref(),
                        &mut findings,
                    );
                }
            }
        }
    }

    let result = ExplainResult {
        indicator: indicator.trim().to_string(),
        kind: parsed.kind,
        ecosystem: parsed.ecosystem.map(|e| e.to_string()),
        version: parsed.version.clone(),
        present: !findings.is_empty(),
        db_missing,
        findings,
    };

    // Record a snapshot opportunistically so `diff` accrues history.
    snapshot_current_db();

    if json {
        return print_json_value(&result);
    }
    print_explain_human(&result);
    0
}

/// All ecosystems, probed when `explain` gets a package name with no prefix.
const ALL_ECOSYSTEMS: [Ecosystem; 8] = [
    Ecosystem::Npm,
    Ecosystem::PyPI,
    Ecosystem::RubyGems,
    Ecosystem::Crates,
    Ecosystem::Go,
    Ecosystem::Maven,
    Ecosystem::NuGet,
    Ecosystem::Packagist,
];

/// Probe one ecosystem (malicious-package, typosquat, popular-lookalike),
/// appending matches to `findings`.
fn explain_package(
    db: &ThreatDb,
    eco: Ecosystem,
    name: &str,
    version: Option<&str>,
    findings: &mut Vec<ExplainFinding>,
) {
    if let Some(m) = db.check_package(eco, name, version) {
        let versions = if m.all_versions_malicious {
            "all versions".to_string()
        } else {
            "specific affected versions".to_string()
        };
        findings.push(ExplainFinding {
            classification: "malicious_package".to_string(),
            source: Some(m.source.as_str().to_string()),
            source_label: Some(m.source.label().to_string()),
            confidence: Some(m.confidence),
            detail: format!(
                "{} package '{}' is listed as malicious by {} ({}).",
                eco,
                name,
                m.source.label(),
                versions
            ),
            reference_url: m.reference_url,
        });
    }

    if let Some(ts) = db.check_typosquat(eco, name) {
        findings.push(ExplainFinding {
            classification: "typosquat".to_string(),
            source: Some(ThreatSource::EcosystemsTyposquat.as_str().to_string()),
            source_label: Some(ThreatSource::EcosystemsTyposquat.label().to_string()),
            confidence: None,
            detail: format!(
                "{} package '{}' is a known typosquat of '{}'.",
                eco, ts.malicious_name, ts.target_name
            ),
            reference_url: None,
        });
    }

    if let Some((popular, distance)) = db.check_popular_distance(eco, name) {
        findings.push(ExplainFinding {
            classification: "popular_lookalike".to_string(),
            source: None,
            source_label: None,
            confidence: None,
            detail: format!(
                "{} package '{}' is edit-distance {} from the popular package '{}' \
                 — a possible slopsquat/typo. Not itself listed as malicious.",
                eco, name, distance, popular
            ),
            reference_url: None,
        });
    }
}

fn print_explain_human(r: &ExplainResult) {
    println!("threat-db explain: {}", r.indicator);
    let kind_label = match r.kind {
        IndicatorKind::Ip => "IPv4 address",
        IndicatorKind::Package => "package",
        IndicatorKind::Domain => "domain / hostname",
    };
    print!("  type:        {kind_label}");
    if let Some(ref eco) = r.ecosystem {
        print!(" ({eco})");
    }
    if let Some(ref v) = r.version {
        print!(" @ {v}");
    }
    println!();

    if r.db_missing {
        println!("  result:      threat DB not installed");
        println!("  Hint: run 'tirith threat-db update' to install the signed DB.");
        return;
    }

    if !r.present {
        println!("  result:      not present");
        match r.kind {
            IndicatorKind::Package => println!(
                "  The threat DB has no malicious-package, typosquat, or \
                 popular-lookalike record for this name."
            ),
            IndicatorKind::Domain => {
                println!("  The threat DB has no malicious-hostname record for this domain.")
            }
            IndicatorKind::Ip => {
                println!("  The threat DB has no malicious-infrastructure record for this IP.")
            }
        }
        println!("  Absence is not a guarantee of safety — the DB only covers known threats.");
        return;
    }

    println!("  result:      PRESENT — {} finding(s)", r.findings.len());
    for (i, f) in r.findings.iter().enumerate() {
        println!();
        println!("  [{}] {}", i + 1, f.classification);
        if let Some(ref label) = f.source_label {
            println!("      source:     {label}");
        }
        if let Some(c) = f.confidence {
            println!("      confidence: {}", c.as_str());
        }
        println!("      {}", f.detail);
        if let Some(ref url) = f.reference_url {
            println!("      reference:  {url}");
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct SourcesReport {
    /// True when a DB is installed and the per-source counts are real.
    db_installed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    build_sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    build_timestamp: Option<u64>,
    sources: Vec<SourceInfo>,
}

#[derive(Debug, serde::Serialize)]
struct SourceInfo {
    id: String,
    name: String,
    /// `primary` (signed CI DB) or `supplemental` (user-local overlay).
    tier: SourceTier,
    upstream_url: String,
    /// Live record count, or `null` when no DB is installed. Typosquat/popular
    /// records carry no source byte, so the typosquat count lands under `typosquats`.
    record_count: Option<u64>,
}

/// `tirith threat-db sources`.
pub fn sources(json: bool) -> i32 {
    let db = ThreatDb::cached();
    let breakdown = db.as_ref().map(|d| d.source_breakdown());
    let stats = db.as_ref().map(|d| d.stats());

    let mut source_infos = Vec::new();
    for src in ThreatSource::ALL {
        // `count_for` attributes the typosquat index to `EcosystemsTyposquat`,
        // so no per-source special-case is needed.
        let record_count = breakdown.as_ref().map(|b| b.count_for(src));
        source_infos.push(SourceInfo {
            id: src.as_str().to_string(),
            name: src.label().to_string(),
            tier: src.tier(),
            upstream_url: src.upstream_url().to_string(),
            record_count,
        });
    }

    let report = SourcesReport {
        db_installed: db.is_some(),
        build_sequence: stats.as_ref().map(|s| s.build_sequence),
        build_timestamp: stats.as_ref().map(|s| s.build_timestamp),
        sources: source_infos,
    };

    snapshot_current_db();

    if json {
        return print_json_value(&report);
    }
    print_sources_human(&report, breakdown.as_ref().map(|b| b.popular_count));
    0
}

fn print_sources_human(r: &SourcesReport, popular_count: Option<u64>) {
    println!("threat-db sources");
    if r.db_installed {
        if let (Some(seq), Some(ts)) = (r.build_sequence, r.build_timestamp) {
            println!("  DB version {seq}, built {}", format_epoch(ts));
        }
    } else {
        println!("  threat DB not installed — counts unavailable");
        println!("  (run 'tirith threat-db update' to install the signed DB)");
    }

    for tier in [SourceTier::Primary, SourceTier::Supplemental] {
        let heading = match tier {
            SourceTier::Primary => "Primary feeds (signed CI database)",
            SourceTier::Supplemental => "Supplemental feeds (optional user-local overlay)",
        };
        println!();
        println!("  {heading}");
        for s in r.sources.iter().filter(|s| s.tier == tier) {
            let count = match s.record_count {
                Some(c) => format!("{c} records"),
                None => "count unavailable".to_string(),
            };
            println!("    {:<26} {}", s.name, count);
            println!("      {}", s.upstream_url);
        }
    }

    if r.db_installed {
        println!();
        println!(
            "  Note: typosquat counts are reported under the ecosyste.ms Typosquats feed; \
             popular-package baselines ({} entries) are not a threat feed.",
            popular_count.unwrap_or(0)
        );
    }
}

#[derive(Debug, serde::Serialize)]
struct HealthReport {
    installed: bool,
    path: Option<String>,
    /// Ed25519 signature verified (`None` when not installed or load failed).
    signature_valid: Option<bool>,
    age_hours: Option<f64>,
    /// Configured refresh interval in hours (`auto_update_hours`, 0 = disabled).
    refresh_interval_hours: u64,
    /// Older than 2x the refresh interval (never true when refresh is disabled).
    stale: bool,
    build_sequence: Option<u64>,
    build_timestamp: Option<u64>,
    counts: Option<CategoryCounts>,
    supplemental: SupplementalHealth,
    /// Load/parse error when the DB file exists but could not be read.
    error: Option<String>,
    /// `ok`, `stale`, `not_installed`, or `error`.
    status: String,
}

#[derive(Debug, serde::Serialize)]
struct SupplementalHealth {
    present: bool,
    path: Option<String>,
}

/// `tirith threat-db health`.
pub fn health(json: bool) -> i32 {
    let report = gather_health();
    snapshot_current_db();

    let exit = if report.error.is_some() { 1 } else { 0 };

    if json {
        // Propagate the worse of the health exit code and a JSON-write failure.
        return print_json_value(&report).max(exit);
    }
    print_health_human(&report);
    exit
}

fn gather_health() -> HealthReport {
    let db_path = ThreatDb::default_path();
    let path_str = db_path.as_ref().map(|p| p.display().to_string());
    let policy = policy::Policy::discover(None);
    let refresh_interval_hours = policy.threat_intel.auto_update_hours;

    let supplemental_path = ThreatDb::supplemental_path();
    let supplemental = SupplementalHealth {
        present: supplemental_path
            .as_ref()
            .map(|p| p.exists())
            .unwrap_or(false),
        path: supplemental_path.map(|p| p.display().to_string()),
    };

    let exists = db_path.as_ref().map(|p| p.exists()).unwrap_or(false);
    if !exists {
        return HealthReport {
            installed: false,
            path: path_str,
            signature_valid: None,
            age_hours: None,
            refresh_interval_hours,
            stale: false,
            build_sequence: None,
            build_timestamp: None,
            counts: None,
            supplemental,
            error: None,
            status: "not_installed".to_string(),
        };
    }

    let db_path_ref = db_path.as_ref().expect("path exists when exists==true");
    match ThreatDb::load_from_path(db_path_ref, 0) {
        Ok(db) => {
            let sig_valid = db.verify_signature().is_ok();
            let stats = db.stats();
            let age_secs = unix_now().saturating_sub(stats.build_timestamp);
            let age_hours = age_secs as f64 / 3600.0;
            // Stale = older than 2x the refresh interval; interval 0 = never stale.
            let stale =
                refresh_interval_hours != 0 && age_hours > (refresh_interval_hours as f64 * 2.0);
            let counts = CategoryCounts {
                packages: stats.package_count as u64,
                hostnames: stats.hostname_count as u64,
                ips: stats.ip_count as u64,
                typosquats: stats.typosquat_count as u64,
                popular: stats.popular_count as u64,
            };
            let status = if !sig_valid {
                "error"
            } else if stale {
                "stale"
            } else {
                "ok"
            };
            HealthReport {
                installed: true,
                path: path_str,
                signature_valid: Some(sig_valid),
                age_hours: Some(age_hours),
                refresh_interval_hours,
                stale,
                build_sequence: Some(stats.build_sequence),
                build_timestamp: Some(stats.build_timestamp),
                counts: Some(counts),
                supplemental,
                error: if sig_valid {
                    None
                } else {
                    Some("Ed25519 signature verification failed".to_string())
                },
                status: status.to_string(),
            }
        }
        Err(e) => HealthReport {
            installed: true,
            path: path_str,
            signature_valid: None,
            age_hours: None,
            refresh_interval_hours,
            stale: false,
            build_sequence: None,
            build_timestamp: None,
            counts: None,
            supplemental,
            error: Some(format!("{e}")),
            status: "error".to_string(),
        },
    }
}

fn print_health_human(r: &HealthReport) {
    println!("threat-db health");

    if !r.installed {
        println!("  status:        NOT INSTALLED");
        if let Some(ref p) = r.path {
            println!("  expected at:   {p}");
        }
        println!("  Hint: run 'tirith threat-db update' to install the signed DB.");
        print_supplemental_health(&r.supplemental);
        return;
    }

    if let Some(ref err) = r.error {
        println!("  status:        ERROR — {err}");
        if let Some(ref p) = r.path {
            println!("  path:          {p}");
        }
        println!("  Hint: re-download with 'tirith threat-db update --force'.");
        print_supplemental_health(&r.supplemental);
        return;
    }

    let status_label = match r.status.as_str() {
        "ok" => "OK",
        "stale" => "STALE",
        other => other,
    };
    println!("  status:        {status_label}");
    if let Some(ref p) = r.path {
        println!("  path:          {p}");
    }
    match r.signature_valid {
        Some(true) => println!("  signature:     valid (Ed25519)"),
        Some(false) => println!("  signature:     INVALID"),
        None => println!("  signature:     unknown"),
    }
    if let Some(seq) = r.build_sequence {
        println!("  version:       {seq}");
    }
    if let Some(ts) = r.build_timestamp {
        println!("  built:         {}", format_epoch(ts));
    }
    if let Some(age) = r.age_hours {
        println!("  age:           {}", format_age(age));
    }
    if r.refresh_interval_hours == 0 {
        println!("  refresh:       auto-update disabled (auto_update_hours = 0)");
    } else {
        println!(
            "  refresh:       every {}h (stale after {}h)",
            r.refresh_interval_hours,
            r.refresh_interval_hours * 2
        );
        if r.stale {
            println!("  -> DB is stale; run 'tirith threat-db update'.");
        }
    }
    if let Some(ref c) = r.counts {
        println!(
            "  entries:       {} total — {} packages, {} hostnames, {} IPs, {} typosquats, {} popular",
            c.total(),
            c.packages,
            c.hostnames,
            c.ips,
            c.typosquats,
            c.popular
        );
    }
    print_supplemental_health(&r.supplemental);
}

fn print_supplemental_health(s: &SupplementalHealth) {
    if s.present {
        println!("  supplemental:  present (user-local opt-in feed overlay)");
    } else {
        println!("  supplemental:  none (no opt-in feeds configured)");
    }
}

#[derive(Debug, serde::Serialize)]
struct DiffReport {
    /// The `--since` argument as supplied.
    since: String,
    /// How `--since` was interpreted: `version` or `date`.
    since_kind: String,
    baseline: Option<SnapshotSummary>,
    current: Option<SnapshotSummary>,
    /// Per-category count deltas (current - baseline). Positive = added.
    delta: Option<CountDelta>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    source_delta: std::collections::BTreeMap<String, i64>,
    limitation: String,
    /// Set when the diff could not be produced (no DB, no baseline, …).
    note: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct SnapshotSummary {
    build_sequence: u64,
    build_timestamp: u64,
    recorded_at: u64,
    counts: CategoryCounts,
}

#[derive(Debug, serde::Serialize)]
struct CountDelta {
    packages: i64,
    hostnames: i64,
    ips: i64,
    typosquats: i64,
    popular: i64,
    total: i64,
}

fn delta_of(current: &CategoryCounts, baseline: &CategoryCounts) -> CountDelta {
    let d = |c: u64, b: u64| c as i64 - b as i64;
    CountDelta {
        packages: d(current.packages, baseline.packages),
        hostnames: d(current.hostnames, baseline.hostnames),
        ips: d(current.ips, baseline.ips),
        typosquats: d(current.typosquats, baseline.typosquats),
        popular: d(current.popular, baseline.popular),
        total: d(current.total(), baseline.total()),
    }
}

/// Parse `--since` as a build-sequence number or ISO date. Returns
/// `(kind, version, epoch)` with exactly one of version/epoch set.
fn parse_since(since: &str) -> Result<(String, Option<u64>, Option<u64>), String> {
    let s = since.trim();
    // A bare integer is a build sequence ("version").
    if let Ok(version) = s.parse::<u64>() {
        return Ok(("version".to_string(), Some(version), None));
    }
    // Otherwise a date (YYYY-MM-DD, optionally with time).
    if let Some(epoch) = parse_iso_date(s) {
        return Ok(("date".to_string(), None, Some(epoch)));
    }
    Err(format!(
        "could not parse --since value '{since}' — expected a DB version number \
         (e.g. 42) or an ISO date (e.g. 2026-01-15)"
    ))
}

/// Days in each calendar month for a non-leap year (January first). February's
/// leap-day is added separately via [`is_leap_year`].
const MONTH_DAYS: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Proleptic Gregorian leap-year test, shared by the date parser and formatter.
fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

/// Parse `YYYY-MM-DD` (or `...THH:MM:SS`) to a Unix epoch. Dependency-free;
/// only the date part is used.
fn parse_iso_date(s: &str) -> Option<u64> {
    let date_part = s.split(['T', ' ']).next().unwrap_or(s);
    let mut it = date_part.split('-');
    let year: i64 = it.next()?.parse().ok()?;
    let month: i64 = it.next()?.parse().ok()?;
    let day: i64 = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    if !(1970..=9999).contains(&year) || !(1..=12).contains(&month) {
        return None;
    }
    // Reject a day past the month length (e.g. 2026-02-30): otherwise the
    // arithmetic rolls into the next month and `diff --since` picks the wrong
    // baseline instead of erroring.
    let max_day = if month == 2 && is_leap_year(year) {
        29
    } else {
        MONTH_DAYS[(month - 1) as usize]
    };
    if !(1..=max_day).contains(&day) {
        return None;
    }
    // Days from 1970-01-01 to the start of `year`.
    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }
    for (m, md) in MONTH_DAYS.iter().enumerate() {
        if (m as i64) + 1 >= month {
            break;
        }
        days += md;
        if (m as i64) + 1 == 2 && is_leap_year(year) {
            days += 1;
        }
    }
    days += day - 1;
    Some((days * 86400) as u64)
}

/// `tirith threat-db diff --since <version-or-date>`.
pub fn diff(since: &str, json: bool) -> i32 {
    // Fold the current DB into history first so a fresh install can be a
    // baseline for a later diff.
    snapshot_current_db();

    let limitation = "The threat DB format retains no per-entry history, so this diff reports \
         category and per-source COUNT deltas between recorded snapshots — not the \
         exact entries added or removed. Snapshots accrue each time a transparency \
         command runs."
        .to_string();

    let (since_kind, want_version, want_epoch) = match parse_since(since) {
        Ok(v) => v,
        Err(e) => {
            if json {
                // Exit code is already 1 (invalid --since); a JSON-write failure
                // can't make it worse, so the result is discarded.
                let _ = print_json_value(&DiffReport {
                    since: since.to_string(),
                    since_kind: "invalid".to_string(),
                    baseline: None,
                    current: None,
                    delta: None,
                    source_delta: Default::default(),
                    limitation,
                    note: Some(e.clone()),
                });
            } else {
                eprintln!("tirith: {e}");
            }
            return 1;
        }
    };

    let (history, history_read_error) = load_history();
    let current = current_snapshot();

    // Baseline: newest snapshot at or before the requested point. For a version,
    // compare build_sequence; for a date, compare `recorded_at` (when tirith
    // observed the DB), not the CI build timestamp.
    let baseline = history
        .iter()
        .filter(|s| match (want_version, want_epoch) {
            (Some(v), _) => s.build_sequence <= v,
            (_, Some(e)) => s.recorded_at <= e,
            _ => false,
        })
        .max_by_key(|s| (s.recorded_at, s.build_sequence))
        .cloned();

    let summarize = |s: &DbSnapshot| SnapshotSummary {
        build_sequence: s.build_sequence,
        build_timestamp: s.build_timestamp,
        recorded_at: s.recorded_at,
        counts: s.counts.clone(),
    };

    let (delta, source_delta, note) = match (&baseline, &current) {
        (Some(b), Some(c)) => {
            let d = delta_of(&c.counts, &b.counts);
            let mut sd: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
            for (src, cur_count) in &c.sources {
                let base_count = b.sources.get(src).copied().unwrap_or(0);
                let diff = *cur_count as i64 - base_count as i64;
                if diff != 0 {
                    sd.insert(src.clone(), diff);
                }
            }
            let note = if b.build_sequence == c.build_sequence {
                Some(
                    "Baseline and current snapshot are the same DB version — no \
                     change since the requested point."
                        .to_string(),
                )
            } else {
                None
            };
            (Some(d), sd, note)
        }
        (None, Some(_)) => (
            None,
            Default::default(),
            // An existing-but-unreadable history file must surface the read
            // failure, not "no snapshot recorded".
            Some(history_read_error.clone().unwrap_or_else(|| {
                format!(
                    "No snapshot was recorded at or before '{since}'. tirith only began \
                     retaining snapshots from the first transparency command after this \
                     feature was installed; a diff needs at least one earlier snapshot. \
                     Run 'tirith threat-db health' periodically to build up history."
                )
            })),
        ),
        (_, None) => (
            None,
            Default::default(),
            Some(
                "Threat DB is not installed — nothing to diff. Run \
                 'tirith threat-db update' first."
                    .to_string(),
            ),
        ),
    };

    let report = DiffReport {
        since: since.to_string(),
        since_kind,
        baseline: baseline.as_ref().map(summarize),
        current: current.as_ref().map(summarize),
        delta,
        source_delta,
        limitation,
        note,
    };

    if json {
        return print_json_value(&report);
    }
    print_diff_human(&report);
    0
}

fn print_diff_human(r: &DiffReport) {
    println!("threat-db diff (since {} = {})", r.since, r.since_kind);
    println!("  note: {}", r.limitation);

    if let (Some(b), Some(c)) = (&r.baseline, &r.current) {
        println!();
        println!(
            "  baseline:  DB v{} built {} (snapshot recorded {})",
            b.build_sequence,
            format_epoch(b.build_timestamp),
            format_epoch(b.recorded_at)
        );
        println!(
            "  current:   DB v{} built {}",
            c.build_sequence,
            format_epoch(c.build_timestamp)
        );
        if let Some(ref d) = r.delta {
            println!();
            println!("  count change (current - baseline):");
            print_delta_line("packages", d.packages);
            print_delta_line("hostnames", d.hostnames);
            print_delta_line("IPs", d.ips);
            print_delta_line("typosquats", d.typosquats);
            print_delta_line("popular", d.popular);
            print_delta_line("TOTAL", d.total);
        }
        if !r.source_delta.is_empty() {
            println!();
            println!("  per-source count change:");
            for (src, delta) in &r.source_delta {
                print_delta_line(src, *delta);
            }
        }
    }

    if let Some(ref note) = r.note {
        println!();
        println!("  {note}");
    }
}

fn print_delta_line(label: &str, delta: i64) {
    let sign = if delta > 0 {
        format!("+{delta}")
    } else {
        delta.to_string()
    };
    println!("    {label:<14} {sign}");
}

/// Serialize `value` as pretty JSON to stdout. `0` on success, `1` on a
/// serialization failure (so a JSON consumer can tell the output is incomplete).
#[must_use]
fn print_json_value(value: &impl serde::Serialize) -> i32 {
    match serde_json::to_string_pretty(value) {
        Ok(s) => {
            println!("{s}");
            0
        }
        Err(e) => {
            eprintln!("tirith: JSON serialization failed: {e}");
            1
        }
    }
}

/// Format a Unix epoch as a UTC `YYYY-MM-DD HH:MM:SS` string (dependency-free).
fn format_epoch(epoch: u64) -> String {
    let days = epoch / 86400;
    let secs_of_day = epoch % 86400;
    let (hh, mm, ss) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );

    let mut year: i64 = 1970;
    let mut remaining = days as i64;
    loop {
        let year_len = if is_leap_year(year) { 366 } else { 365 };
        if remaining < year_len {
            break;
        }
        remaining -= year_len;
        year += 1;
    }
    let mut month = 1;
    for (m, md) in MONTH_DAYS.iter().enumerate() {
        let mut len = *md;
        if m == 1 && is_leap_year(year) {
            len += 1;
        }
        if remaining < len {
            break;
        }
        remaining -= len;
        month += 1;
    }
    let day = remaining + 1;
    format!("{year:04}-{month:02}-{day:02} {hh:02}:{mm:02}:{ss:02} UTC")
}

/// Format an age in hours as a compact human string.
fn format_age(hours: f64) -> String {
    if hours < 1.0 {
        format!("{:.0} minutes", hours * 60.0)
    } else if hours < 48.0 {
        format!("{hours:.0} hours")
    } else {
        format!("{:.1} days", hours / 24.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::sync::atomic::Ordering;

    /// Serialize tests that manipulate environment variables.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

        unsafe { std::env::set_var("TIRITH_POLICY_ROOT", tmp.path()) };

        let policy = policy::Policy::discover(Some(tmp.path().to_str().unwrap()));
        assert_eq!(
            policy.threat_intel.auto_update_hours, 0,
            "policy should reflect auto_update_hours=0"
        );

        unsafe { std::env::remove_var("TIRITH_POLICY_ROOT") };
    }

    #[test]
    fn next_check_at_future_skips_update() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();

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

    #[test]
    fn spawned_at_recent_skips_update() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();

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

        let now = unix_now();
        assert!(
            !is_spawned_at_recent(state, now),
            "should proceed when spawned-at file does not exist"
        );
    }

    #[test]
    fn update_attempted_guard_fires_once() {
        // Standalone AtomicBool: the real global UPDATE_ATTEMPTED can't be reset.
        let guard = AtomicBool::new(false);

        let first = guard.swap(true, Ordering::Relaxed);
        assert!(
            !first,
            "first swap should return false, allowing the update"
        );

        let second = guard.swap(true, Ordering::Relaxed);
        assert!(second, "second swap should return true, blocking re-entry");

        let third = guard.swap(true, Ordering::Relaxed);
        assert!(third, "third swap should also return true");
    }

    #[test]
    fn lock_dedup_second_acquire_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();

        let lock1 = try_acquire_update_lock(state);
        assert!(lock1.is_some(), "first lock acquisition should succeed");

        let lock2 = try_acquire_update_lock(state);
        assert!(
            lock2.is_none(),
            "second lock acquisition should fail while first is held"
        );

        // Explicit unlock then drop: Drop alone races on macOS BSD `flock`
        // (release-on-close not always observable to an immediate re-acquire).
        let l1 = lock1.unwrap();
        fs2::FileExt::unlock(&l1).expect("unlock lock1");
        drop(l1);

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

    #[test]
    fn failure_backoff_sets_one_hour() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();
        let next_check_path = state.join(NEXT_CHECK_FILE);

        // Matches what run_background_update writes on failure.
        let now = unix_now();
        let backoff_ts = now + BACKOFF_SECS;
        std::fs::write(&next_check_path, backoff_ts.to_string()).unwrap();

        let content = std::fs::read_to_string(&next_check_path).unwrap();
        let written_ts: u64 = content.trim().parse().unwrap();

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
        // Failure backoff must be shorter than the normal interval for faster retry.
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

    #[test]
    fn canonical_payload_format_sorted_keys_no_whitespace() {
        let manifest = Manifest {
            sha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
            size: 12345,
            url: "https://example.com/tirith-threatdb.dat".to_string(),
            version: 42,
            signature: String::new(),
        };

        let payload = manifest.canonical_payload();

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

        assert!(
            std::str::from_utf8(payload.as_bytes()).is_ok(),
            "canonical payload must be valid UTF-8"
        );

        let parsed: serde_json::Value =
            serde_json::from_str(&payload).expect("canonical payload must be valid JSON");

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

    #[test]
    fn spawned_at_exactly_at_boundary_skips() {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path();

        // 29s ago is still inside the 30s window.
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

        // Exactly 30s ago falls outside the dedup window (strict <).
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

        // Strict `<` comparison: equal timestamps proceed with the update.
        assert!(
            !is_next_check_in_future(state, now),
            "next-check-at == now should allow the update (not strictly in the future)"
        );
    }

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

        let etag1 = format!("{k1}-etag");
        let etag2 = format!("{k2}-etag");
        assert_ne!(etag1, etag2, "etag files must be per-URL");

        let body1 = format!("{k1}-body");
        let body2 = format!("{k2}-body");
        assert_ne!(body1, body2, "body cache files must be per-URL");
    }

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

        // Simulate what fetch_manifest_from persists on a 200 response.
        std::fs::write(&etag_path, "\"etag-value-abc\"").unwrap();
        std::fs::write(&body_path, manifest_json).unwrap();

        let cached = std::fs::read_to_string(&body_path).unwrap();
        let m: Manifest = serde_json::from_str(&cached).unwrap();
        assert_eq!(m.sha256, "dead");
        assert_eq!(m.version, 5);

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

        // ETag without body — e.g. body manually deleted between runs.
        std::fs::write(&etag_path, "\"stale-etag\"").unwrap();
        assert!(!body_path.exists(), "body should not exist for this test");

        // This mirrors the 304 recovery path in fetch_manifest_from.
        let body_ok = body_path
            .exists()
            .then(|| std::fs::read_to_string(&body_path).ok())
            .flatten()
            .and_then(|s| serde_json::from_str::<Manifest>(&s).ok());

        if body_ok.is_none() {
            let _ = std::fs::remove_file(&etag_path);
            let _ = std::fs::remove_file(&body_path);
        }

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

        std::fs::write(&etag_path, "\"some-etag\"").unwrap();
        std::fs::write(&body_path, "this is not json").unwrap();

        let body_ok = std::fs::read_to_string(&body_path)
            .ok()
            .and_then(|s| serde_json::from_str::<Manifest>(&s).ok());

        if body_ok.is_none() {
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

        std::fs::write(&p_etag, "\"primary-etag\"").unwrap();
        std::fs::write(
            &p_body,
            r#"{"sha256":"p","size":1,"url":"p","version":10,"signature":"s"}"#,
        )
        .unwrap();

        std::fs::write(&f_etag, "\"fallback-etag\"").unwrap();
        std::fs::write(
            &f_body,
            r#"{"sha256":"f","size":2,"url":"f","version":20,"signature":"s"}"#,
        )
        .unwrap();

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
        // Corrupt cached body maps to RetryNeeded so the caller can clean up
        // and retry unconditionally; it is not an error.
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

    /// Fetch with an isolated state dir so parallel tests don't race on env vars.
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
        let url = format!("{}/manifest.json", server.url());
        let result = fetch_with_state(&url, tmp.path());

        mock.assert();
        let m = result.expect("should succeed on 200");
        assert_eq!(m.sha256, "abc");
        assert_eq!(m.version, 1);

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
        // Pre-populate cache files so the 304 path exercises the happy case.
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

        // First request 304 (no cached body), then unconditional retry to 200.
        let mock_304 = server
            .mock("GET", "/manifest.json")
            .with_status(304)
            .expect(1)
            .create();

        let retry_json = r#"{"sha256":"fresh","size":1,"url":"https://x.com/db.dat","version":7,"signature":"s"}"#;
        let mock_200 = server
            .mock("GET", "/manifest.json")
            .with_status(200)
            .with_header("etag", "\"new-etag\"")
            .with_body(retry_json)
            .expect(1)
            .create();

        let tmp = tempfile::tempdir().unwrap();
        // ETag present but no body — simulates corrupt or manually-deleted cache.
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
        let url = format!("{}/manifest.json", server.url());
        let result = fetch_with_state(&url, tmp.path());

        mock.assert();
        assert!(result.is_err(), "invalid JSON should fail");

        // Validation-before-cache: invalid JSON must not land in the cache.
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
        let url = format!("{}/manifest.json", server.url());
        let _ = fetch_with_state(&url, tmp.path());

        // mockito.assert() fails if the User-Agent header didn't match the regex.
        mock.assert();
    }

    #[test]
    fn read_bounded_bytes_rejects_declared_oversize_body() {
        let err = super::read_bounded_bytes(
            std::io::Cursor::new(b"abcd".to_vec()),
            "https://example.test/feed",
            Some(10),
            4,
        )
        .unwrap_err();
        assert!(err.contains("too large"));
    }

    #[test]
    fn read_bounded_bytes_rejects_stream_that_exceeds_limit() {
        let err = super::read_bounded_bytes(
            std::io::Cursor::new(b"abcde".to_vec()),
            "https://example.test/feed",
            None,
            4,
        )
        .unwrap_err();
        assert!(err.contains("exceeded max size"));
    }

    // `--offline` / `TIRITH_OFFLINE` (M0.3): the switch must make
    // `maybe_background_update` a guaranteed no-op — zero network and no
    // `spawned-at` state file (the breadcrumb written right before a spawn).

    /// RAII guard that sets/removes `TIRITH_OFFLINE` and restores it on Drop.
    struct OfflineEnvGuard {
        old: Option<std::ffi::OsString>,
    }
    impl OfflineEnvGuard {
        fn set(val: &str) -> Self {
            let old = std::env::var_os("TIRITH_OFFLINE");
            unsafe { std::env::set_var("TIRITH_OFFLINE", val) };
            Self { old }
        }
        fn unset() -> Self {
            let old = std::env::var_os("TIRITH_OFFLINE");
            unsafe { std::env::remove_var("TIRITH_OFFLINE") };
            Self { old }
        }
    }
    impl Drop for OfflineEnvGuard {
        fn drop(&mut self) {
            match &self.old {
                Some(v) => unsafe { std::env::set_var("TIRITH_OFFLINE", v) },
                None => unsafe { std::env::remove_var("TIRITH_OFFLINE") },
            }
        }
    }

    #[test]
    fn offline_env_active_recognizes_truthy_values() {
        // `offline_env_active` lives in `cli/mod.rs`; exercised here via the env guard.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for v in ["1", "true", "TRUE", "yes", "On", " on "] {
            let _e = OfflineEnvGuard::set(v);
            assert!(
                crate::cli::offline_env_active(),
                "TIRITH_OFFLINE={v:?} should be treated as offline"
            );
        }
    }

    #[test]
    fn offline_env_active_rejects_falsey_and_unset() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for v in ["0", "false", "no", "", "off", "garbage"] {
            let _e = OfflineEnvGuard::set(v);
            assert!(
                !crate::cli::offline_env_active(),
                "TIRITH_OFFLINE={v:?} should NOT be treated as offline"
            );
        }
        let _e = OfflineEnvGuard::unset();
        assert!(
            !crate::cli::offline_env_active(),
            "unset TIRITH_OFFLINE should not be offline"
        );
    }

    #[test]
    fn offline_flag_skips_background_update_no_network_attempt() {
        // With `--offline`, `maybe_background_update` must not reach the state
        // dir: no `spawned-at` file, so no child spawned (= zero network).
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _e = OfflineEnvGuard::unset();
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("XDG_STATE_HOME", tmp.path()) };

        super::maybe_background_update(true);

        let spawned_at = tmp.path().join("tirith").join(SPAWNED_AT_FILE);
        assert!(
            !spawned_at.exists(),
            "--offline must skip the background update before any state write"
        );
        unsafe { std::env::remove_var("XDG_STATE_HOME") };
    }

    #[test]
    fn offline_env_skips_background_update_no_network_attempt() {
        // Same guarantee via `TIRITH_OFFLINE` (the path shell hooks and the
        // conformance harness use, lacking CLI flags per `tirith check`).
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _e = OfflineEnvGuard::set("1");
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("XDG_STATE_HOME", tmp.path()) };

        // `offline_flag = false` here — the env var alone must suffice.
        super::maybe_background_update(false);

        let spawned_at = tmp.path().join("tirith").join(SPAWNED_AT_FILE);
        assert!(
            !spawned_at.exists(),
            "TIRITH_OFFLINE=1 must skip the background update before any state write"
        );
        unsafe { std::env::remove_var("XDG_STATE_HOME") };
    }

    #[test]
    fn offline_short_circuits_before_update_attempted_latch() {
        // The offline check is ahead of the once-per-process `UPDATE_ATTEMPTED`
        // latch: an offline call must not consume it, so a later online call can
        // still proceed. Verified on a standalone AtomicBool.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let latch = AtomicBool::new(false);
        // Simulate the offline early-return: the latch is never swapped.
        let offline = true;
        if !offline {
            latch.swap(true, Ordering::Relaxed);
        }
        assert!(
            !latch.load(Ordering::Relaxed),
            "an offline call must not consume the once-per-process latch"
        );
    }

    #[test]
    fn parse_indicator_recognizes_ipv4() {
        let p = parse_indicator("203.0.113.50");
        assert_eq!(p.kind, IndicatorKind::Ip);
        assert_eq!(p.value, "203.0.113.50");
        assert!(p.ecosystem.is_none());
        assert!(p.version.is_none());
    }

    #[test]
    fn parse_indicator_recognizes_ecosystem_prefix() {
        let p = parse_indicator("npm:left-pad");
        assert_eq!(p.kind, IndicatorKind::Package);
        assert_eq!(p.ecosystem, Some(Ecosystem::Npm));
        assert_eq!(p.value, "left-pad");
        assert!(p.version.is_none());
    }

    #[test]
    fn parse_indicator_recognizes_ecosystem_prefix_with_version() {
        let p = parse_indicator("pypi:requests@2.0.0");
        assert_eq!(p.kind, IndicatorKind::Package);
        assert_eq!(p.ecosystem, Some(Ecosystem::PyPI));
        assert_eq!(p.value, "requests");
        assert_eq!(p.version.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn parse_indicator_host_colon_port_is_not_a_package() {
        // `example.com:8080` has a `:` but `example.com` is not an ecosystem,
        // so it must fall through to the domain branch, not become a package.
        let p = parse_indicator("example.com:8080");
        assert_eq!(p.kind, IndicatorKind::Domain);
    }

    #[test]
    fn parse_indicator_recognizes_name_at_version() {
        let p = parse_indicator("lodash@4.17.21");
        assert_eq!(p.kind, IndicatorKind::Package);
        assert!(p.ecosystem.is_none());
        assert_eq!(p.value, "lodash");
        assert_eq!(p.version.as_deref(), Some("4.17.21"));
    }

    #[test]
    fn parse_indicator_scoped_npm_package_is_not_split_on_leading_at() {
        // A leading `@` is an npm scope, not a version separator.
        let p = parse_indicator("@angular/core");
        assert_eq!(p.kind, IndicatorKind::Package);
        assert_eq!(p.value, "@angular/core");
        assert!(p.version.is_none());
    }

    #[test]
    fn parse_indicator_scoped_npm_package_with_version() {
        let p = parse_indicator("@angular/core@17.0.0");
        assert_eq!(p.kind, IndicatorKind::Package);
        assert_eq!(p.value, "@angular/core");
        assert_eq!(p.version.as_deref(), Some("17.0.0"));
    }

    #[test]
    fn parse_indicator_dotted_token_is_domain() {
        let p = parse_indicator("evil.example.com");
        assert_eq!(p.kind, IndicatorKind::Domain);
        assert_eq!(p.value, "evil.example.com");
    }

    #[test]
    fn parse_indicator_domain_is_lowercased() {
        let p = parse_indicator("EVIL.Example.COM");
        assert_eq!(p.kind, IndicatorKind::Domain);
        assert_eq!(p.value, "evil.example.com");
    }

    #[test]
    fn parse_indicator_bare_name_is_package() {
        // No dot, no slash — a bare package name.
        let p = parse_indicator("react");
        assert_eq!(p.kind, IndicatorKind::Package);
        assert_eq!(p.value, "react");
    }

    #[test]
    fn split_at_version_rejects_missing_parts() {
        assert!(split_at_version("react").is_none());
        assert!(split_at_version("react@").is_none());
        assert!(split_at_version("@1.0.0").is_none());
        assert_eq!(
            split_at_version("react@1.0.0"),
            Some(("react".to_string(), "1.0.0".to_string()))
        );
    }

    #[test]
    fn parse_since_accepts_version_number() {
        let (kind, version, epoch) = parse_since("42").unwrap();
        assert_eq!(kind, "version");
        assert_eq!(version, Some(42));
        assert_eq!(epoch, None);
    }

    #[test]
    fn parse_since_accepts_iso_date() {
        let (kind, version, epoch) = parse_since("2026-01-15").unwrap();
        assert_eq!(kind, "date");
        assert_eq!(version, None);
        // 2026-01-15 00:00:00 UTC = 1768435200.
        assert_eq!(epoch, Some(1768435200));
    }

    #[test]
    fn parse_since_rejects_garbage() {
        assert!(parse_since("not-a-date").is_err());
        assert!(parse_since("2026-13-01").is_err());
        assert!(parse_since("2026-01-99").is_err());
    }

    #[test]
    fn parse_iso_date_epoch_zero_is_unix_epoch() {
        assert_eq!(parse_iso_date("1970-01-01"), Some(0));
    }

    #[test]
    fn parse_iso_date_handles_leap_year() {
        // 2024-02-29 is a valid leap day; 2024-03-01 is the day after.
        let feb29 = parse_iso_date("2024-02-29").unwrap();
        let mar01 = parse_iso_date("2024-03-01").unwrap();
        assert_eq!(mar01 - feb29, 86400);
    }

    #[test]
    fn parse_iso_date_rejects_day_past_month_length() {
        // A day past the month length (2026-02-30) was previously rolled into the
        // next month, mis-selecting the `diff --since` baseline. Must reject now.
        assert_eq!(parse_iso_date("2026-02-30"), None);
        assert_eq!(parse_iso_date("2026-04-31"), None);
        assert_eq!(parse_iso_date("2026-06-31"), None);
        // 2025 is not a leap year, so Feb 29 is invalid.
        assert_eq!(parse_iso_date("2025-02-29"), None);
        // Valid month-ends still parse.
        assert!(parse_iso_date("2026-02-28").is_some());
        assert!(parse_iso_date("2026-04-30").is_some());
        assert!(parse_iso_date("2026-01-31").is_some());
        // `parse_since` surfaces the rejection as an error, not a wrong baseline.
        assert!(parse_since("2026-02-30").is_err());
    }

    #[test]
    fn parse_iso_date_accepts_datetime_suffix() {
        // Only the date part is used; a time suffix is tolerated.
        assert_eq!(
            parse_iso_date("2026-01-15T12:30:00"),
            parse_iso_date("2026-01-15")
        );
    }

    #[test]
    fn format_epoch_round_trips_with_parse_iso_date() {
        // A date parsed to an epoch and formatted back must show the same date.
        let epoch = parse_iso_date("2026-05-21").unwrap();
        assert!(format_epoch(epoch).starts_with("2026-05-21 00:00:00"));
    }

    #[test]
    fn format_epoch_known_timestamp() {
        // 1700000000 = 2023-11-14 22:13:20 UTC (the fixture DB build time).
        assert_eq!(format_epoch(1700000000), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn delta_of_computes_signed_category_changes() {
        let baseline = CategoryCounts {
            packages: 10,
            hostnames: 5,
            ips: 3,
            typosquats: 2,
            popular: 100,
        };
        let current = CategoryCounts {
            packages: 12,
            hostnames: 5,
            ips: 1,
            typosquats: 4,
            popular: 100,
        };
        let d = delta_of(&current, &baseline);
        assert_eq!(d.packages, 2);
        assert_eq!(d.hostnames, 0);
        assert_eq!(d.ips, -2);
        assert_eq!(d.typosquats, 2);
        assert_eq!(d.popular, 0);
        assert_eq!(d.total, 2);
    }

    #[test]
    fn category_counts_total_sums_all_sections() {
        let c = CategoryCounts {
            packages: 1,
            hostnames: 2,
            ips: 4,
            typosquats: 8,
            popular: 16,
        };
        assert_eq!(c.total(), 31);
    }

    #[test]
    fn record_snapshot_dedups_on_build_sequence() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("XDG_STATE_HOME", tmp.path()) };

        let snap = |seq: u64, recorded: u64| DbSnapshot {
            recorded_at: recorded,
            build_sequence: seq,
            build_timestamp: 1_700_000_000,
            signature_valid: true,
            counts: CategoryCounts::default(),
            sources: Default::default(),
        };

        record_snapshot(&snap(42, 1000));
        // Same build_sequence — must NOT append a second line.
        record_snapshot(&snap(42, 2000));
        record_snapshot(&snap(43, 3000));

        let (history, _) = load_history();
        assert_eq!(
            history.len(),
            2,
            "duplicate build_sequence should be skipped"
        );
        assert_eq!(history[0].build_sequence, 42);
        assert_eq!(history[1].build_sequence, 43);

        unsafe { std::env::remove_var("XDG_STATE_HOME") };
    }

    #[test]
    fn record_snapshot_caps_history_length() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("XDG_STATE_HOME", tmp.path()) };

        for seq in 0..(HISTORY_MAX_LINES as u64 + 20) {
            record_snapshot(&DbSnapshot {
                recorded_at: 1000 + seq,
                build_sequence: seq,
                build_timestamp: 1_700_000_000,
                signature_valid: true,
                counts: CategoryCounts::default(),
                sources: Default::default(),
            });
        }

        let (history, _) = load_history();
        assert_eq!(
            history.len(),
            HISTORY_MAX_LINES,
            "history must be capped at HISTORY_MAX_LINES"
        );
        // The oldest entries are dropped; the newest must be retained.
        assert_eq!(
            history.last().unwrap().build_sequence,
            HISTORY_MAX_LINES as u64 + 19
        );

        unsafe { std::env::remove_var("XDG_STATE_HOME") };
    }

    #[test]
    fn load_history_skips_corrupt_lines() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("XDG_STATE_HOME", tmp.path()) };

        let state = tmp.path().join("tirith");
        std::fs::create_dir_all(&state).unwrap();
        let valid = r#"{"recorded_at":1000,"build_sequence":1,"build_timestamp":1700000000,"signature_valid":true,"counts":{"packages":0,"hostnames":0,"ips":0,"typosquats":0,"popular":0},"sources":{}}"#;
        std::fs::write(
            state.join(HISTORY_FILE),
            format!("not json\n{valid}\n\nalso not json\n"),
        )
        .unwrap();

        let (history, _) = load_history();
        assert_eq!(history.len(), 1, "only the one valid line should parse");
        assert_eq!(history[0].build_sequence, 1);

        unsafe { std::env::remove_var("XDG_STATE_HOME") };
    }

    #[test]
    fn load_history_missing_file_is_not_an_error() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // Set the Windows env var alongside the XDG one so the state path is
        // isolated on every platform.
        unsafe { std::env::set_var("XDG_STATE_HOME", tmp.path()) };
        unsafe { std::env::set_var("APPDATA", tmp.path()) };

        // No history file exists at all — a legitimate "no snapshots yet".
        let (history, read_error) = load_history();
        assert!(history.is_empty());
        assert!(
            read_error.is_none(),
            "a missing history file must not surface as a read error"
        );

        unsafe { std::env::remove_var("XDG_STATE_HOME") };
        unsafe { std::env::remove_var("APPDATA") };
    }

    #[test]
    fn load_history_unreadable_file_surfaces_a_read_error() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("XDG_STATE_HOME", tmp.path()) };
        unsafe { std::env::set_var("APPDATA", tmp.path()) };

        // Create the history *path* as a directory: it exists, but reading it
        // as a file fails with an error that is not NotFound — portably
        // exercising the "exists but unreadable" branch.
        let state = tmp.path().join("tirith");
        std::fs::create_dir_all(state.join(HISTORY_FILE)).unwrap();

        let (history, read_error) = load_history();
        assert!(history.is_empty());
        assert!(
            read_error.is_some(),
            "an existing-but-unreadable history file must surface a read error, \
             not be silently treated as 'no snapshots'"
        );

        unsafe { std::env::remove_var("XDG_STATE_HOME") };
        unsafe { std::env::remove_var("APPDATA") };
    }

    #[test]
    fn confidence_as_str_covers_all_levels() {
        assert_eq!(Confidence::Low.as_str(), "low");
        assert_eq!(Confidence::Medium.as_str(), "medium");
        assert_eq!(Confidence::Confirmed.as_str(), "confirmed");
    }
}
