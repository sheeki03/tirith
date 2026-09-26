//! Authenticated source evidence cache and one bounded update/recovery record.

use super::*;
use tirith_core::threatdb::operations::{self, FreshnessReport, PROVENANCE_LIMIT};

#[derive(serde::Serialize, serde::Deserialize)]
struct CachedEvidence {
    integrity: serde_json::Value,
    provenance: serde_json::Value,
}

fn cache_path(format: u32) -> Option<PathBuf> {
    policy::state_dir().map(|state| state.join(format!("threatdb-source-evidence-v{format}.json")))
}

fn source_urls(asset_url: &str) -> Option<(String, String)> {
    let url = url::Url::parse(asset_url).ok()?;
    if url.query().is_some() || url.fragment().is_some() {
        return None;
    }
    let name = url.path_segments()?.next_back()?;
    let generation = name
        .strip_prefix("tirith-threatdb-v2-")
        .or_else(|| name.strip_prefix("tirith-threatdb-"))?
        .strip_suffix(".dat")?;
    let (run, attempt) = generation.split_once('-')?;
    if run.is_empty()
        || attempt.is_empty()
        || !run.bytes().all(|c| c.is_ascii_digit())
        || !attempt.bytes().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some((
        url.join(&format!("threatdb-source-integrity-{generation}.json"))
            .ok()?
            .to_string(),
        url.join(&format!("threatdb-source-provenance-{generation}.json"))
            .ok()?
            .to_string(),
    ))
}

fn fetch(url: &str) -> Result<Vec<u8>, String> {
    validate_remote_url(url, "source evidence")?;
    let response = guarded_http_client(MANIFEST_TIMEOUT_SECS)?
        .get(url)
        .send()
        .map_err(|_| "source evidence transport failed".to_string())?;
    if !response.status().is_success() {
        return Err(format!("source evidence HTTP {}", response.status()));
    }
    read_bounded_bytes(response, "source evidence", None, PROVENANCE_LIMIT)
}

pub(super) fn refresh(asset_url: &str, sequence: u64, format: u32, sha256: &str) {
    if let Err(error) = refresh_inner(asset_url, sequence, format, sha256) {
        eprintln!("tirith: source freshness evidence unavailable ({error}); signed database remains usable");
    }
}

fn refresh_inner(asset_url: &str, sequence: u64, format: u32, sha256: &str) -> Result<(), String> {
    let (integrity_url, provenance_url) = source_urls(asset_url)
        .ok_or("this signed asset has no supported source-evidence location")?;
    let key = VerifyingKey::from_bytes(VERIFY_KEY_BYTES)
        .map_err(|_| "invalid embedded verification key")?;
    let integrity = fetch(&integrity_url)?;
    let provenance = fetch(&provenance_url)?;
    let document = operations::verify_source_evidence(
        &integrity,
        &provenance,
        &key,
        sequence,
        format,
        sha256,
    )?;
    operations::source_freshness(&document, 0, unix_now())?;
    let cached = CachedEvidence {
        integrity: serde_json::from_slice(&integrity)
            .map_err(|_| "invalid source integrity JSON")?,
        provenance: serde_json::from_slice(&provenance)
            .map_err(|_| "invalid source provenance JSON")?,
    };
    let path = cache_path(format).ok_or("cannot determine source evidence state directory")?;
    atomic_write(
        &path,
        &serde_json::to_vec(&cached).map_err(|_| "cannot encode source evidence")?,
    )
}

pub(super) fn gather(path: &std::path::Path, db: &ThreatDb, now: u64) -> FreshnessReport {
    let stats = db.stats();
    match gather_inner(
        path,
        stats.build_sequence,
        stats.format_version,
        stats.build_timestamp,
        now,
    ) {
        Ok(report) => report,
        Err(error) => FreshnessReport::unavailable(Some(stats.build_timestamp), now, Some(error)),
    }
}

fn gather_inner(
    path: &std::path::Path,
    sequence: u64,
    format: u32,
    built: u64,
    now: u64,
) -> Result<FreshnessReport, String> {
    let evidence = cache_path(format).ok_or("source evidence unavailable")?;
    let file = std::fs::File::open(evidence)
        .map_err(|_| "source evidence not cached; run 'tirith threat-db update'")?;
    let bytes = read_bounded_bytes(file, "cached source evidence", None, PROVENANCE_LIMIT * 2)?;
    let cached: CachedEvidence =
        serde_json::from_slice(&bytes).map_err(|_| "invalid cached source evidence")?;
    let db_bytes = read_bounded_bytes(
        std::fs::File::open(path).map_err(|_| "cannot read installed database")?,
        "installed database",
        None,
        MAX_DB_SIZE,
    )?;
    if db_bytes.get(12..20) != Some(built.to_le_bytes().as_slice()) {
        return Err("installed database changed while reading freshness evidence".into());
    }
    let key = VerifyingKey::from_bytes(VERIFY_KEY_BYTES)
        .map_err(|_| "invalid embedded verification key")?;
    let document = operations::verify_source_evidence(
        &serde_json::to_vec(&cached.integrity).map_err(|_| "invalid cached source integrity")?,
        &serde_json::to_vec(&cached.provenance).map_err(|_| "invalid cached source provenance")?,
        &key,
        sequence,
        format,
        &hex::encode(Sha256::digest(&db_bytes)),
    )?;
    operations::source_freshness(&document, built, now)
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct UpdateRecord {
    schema_version: u32,
    status: String,
    phase: String,
    failure_category: Option<String>,
    incident_key: Option<String>,
    first_failure_at: Option<u64>,
    consecutive_failures: u64,
    checked_at: u64,
    retained_sequence: Option<u64>,
    recovered_at: Option<u64>,
    next_action: String,
}

pub(super) fn last_update() -> Option<UpdateRecord> {
    let file =
        std::fs::File::open(policy::state_dir()?.join("threatdb-update-status.json")).ok()?;
    let bytes = read_bounded_bytes(file, "update status", None, 8192).ok()?;
    let record: UpdateRecord = serde_json::from_slice(&bytes).ok()?;
    (record.schema_version == 1).then_some(record)
}

pub(super) fn record(phase: &str, failure: Option<&str>) {
    let Some(path) = policy::state_dir().map(|state| state.join("threatdb-update-status.json"))
    else {
        return;
    };
    let previous = last_update();
    let record = build_update_record(
        previous.as_ref(),
        phase,
        failure,
        ThreatDb::cached().map(|db| db.build_sequence()),
        unix_now(),
    );
    if let Ok(bytes) = serde_json::to_vec(&record) {
        if let Err(error) = atomic_write(&path, &bytes) {
            eprintln!("tirith: cannot persist ThreatDB update status: {error}");
        }
    }
}

fn build_update_record(
    previous: Option<&UpdateRecord>,
    phase: &str,
    failure: Option<&str>,
    sequence: Option<u64>,
    now: u64,
) -> UpdateRecord {
    let category = failure.map(|message| {
        let message = message.to_ascii_lowercase();
        if message.contains("signature")
            || message.contains("sha-256")
            || message.contains("integrity")
        {
            "integrity"
        } else if message.contains("rollback") || message.contains("equivocation") {
            "rollback"
        } else if message.contains("429") {
            "rate_limit"
        } else if message.contains("parse")
            || message.contains("invalid")
            || message.contains("schema")
        {
            "validation"
        } else if message.contains("empty")
            || message.contains("no entries")
            || message.contains("feed(s)")
        {
            "completeness"
        } else if message.contains("http")
            || message.contains("fetch")
            || message.contains("download")
            || message.contains("transport")
        {
            "transport"
        } else {
            "operation"
        }
    });
    // Deduplication uses phase/category, never a URL, credential, package name,
    // or raw exception. The one fixed-size record replaces the previous record.
    let incident = category.map(|category| format!("{phase}:{category}"));
    let same = incident.is_some()
        && previous
            .as_ref()
            .is_some_and(|old| old.incident_key == incident);
    UpdateRecord {
        schema_version: 1,
        status: if failure.is_some() { if phase == "supplemental" { "partial" } else { "failed" } } else { "complete" }.into(),
        phase: phase.into(), failure_category: category.map(str::to_string), incident_key: incident,
        first_failure_at: if same { previous.as_ref().and_then(|old| old.first_failure_at) } else { failure.map(|_| now) },
        consecutive_failures: if same { previous.as_ref().map(|old| old.consecutive_failures.saturating_add(1)).unwrap_or(1) } else { u64::from(failure.is_some()) },
        checked_at: now,
        retained_sequence: sequence,
        recovered_at: if failure.is_none() && previous.as_ref().is_some_and(|old| old.incident_key.is_some()) { Some(now) }
            else { previous.as_ref().and_then(|old| old.recovered_at) },
        next_action: if failure.is_some() { "Check the failing phase and retry 'tirith threat-db update'; retained_sequence identifies any verified database still available." }
            else { "No update recovery is required." }.into(),
    }
}

pub(super) fn print_last_update(record: &Option<UpdateRecord>) {
    if let Some(record) = record {
        println!(
            "  last update:   {} (phase {}, retained sequence {:?})",
            record.status, record.phase, record.retained_sequence
        );
        if record.incident_key.is_some() {
            println!("  recovery:      {}", record.next_action);
        } else if record.recovered_at.is_some() {
            println!("  recovery:      prior failure recovered");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_failures_deduplicate_and_recovery_preserves_retained_generation() {
        let first = build_update_record(
            None,
            "primary",
            Some("signature verification failed"),
            Some(7),
            100,
        );
        let second = build_update_record(
            Some(&first),
            "primary",
            Some("different signature failure"),
            Some(7),
            200,
        );
        assert_eq!(second.incident_key, first.incident_key);
        assert_eq!(second.first_failure_at, Some(100));
        assert_eq!(second.consecutive_failures, 2);
        assert_eq!(second.retained_sequence, Some(7));
        let recovered = build_update_record(Some(&second), "complete", None, Some(8), 300);
        assert_eq!(recovered.status, "complete");
        assert_eq!(recovered.consecutive_failures, 0);
        assert_eq!(recovered.recovered_at, Some(300));
        assert_eq!(recovered.incident_key, None);
        let partial = build_update_record(
            Some(&recovered),
            "supplemental",
            Some("feed(s) failed"),
            Some(8),
            400,
        );
        assert_eq!(partial.status, "partial");
        assert_eq!(partial.retained_sequence, Some(8));
    }

    #[test]
    fn source_locations_use_only_the_signed_asset_generation() {
        let url = "https://github.com/sheeki03/tirith/releases/download/threatdb-current/tirith-threatdb-v2-123-2.dat";
        let (integrity, provenance) = source_urls(url).unwrap();
        assert!(integrity.ends_with("/threatdb-source-integrity-123-2.json"));
        assert!(provenance.ends_with("/threatdb-source-provenance-123-2.json"));
        for invalid in [
            "tirith-threatdb-123-x.dat",
            "tirith-threatdb-123-2-3.dat",
            "tirith-threatdb-v2.dat",
            "tirith-threatdb-123-2.dat?query=1",
        ] {
            assert!(source_urls(&format!("https://example.com/{invalid}")).is_none());
        }
    }
}
