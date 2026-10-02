//! Offline freshness evidence and bounded transport recovery for ThreatDB.
//!
//! Source ages are accepted only after the sidecar signature and both canonical
//! provenance digests bind them to the installed database. Upstream observations
//! describe a point in time; an old revision alone does not establish upstream lag.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const PROVENANCE_LIMIT: u64 = 1024 * 1024;
pub const SOURCE_IDS: [&str; 3] = [
    "ossf_malicious_packages",
    "datadog_malicious_software_packages",
    "ecosystems_typosquatting_dataset",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamObservation {
    pub pinned_commit: String,
    pub candidate_commit: String,
    pub candidate_timestamp: String,
    pub ahead_by: u64,
    pub max_lag_hours: u64,
    pub review_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamObservations {
    pub schema_version: u32,
    pub checked_at: String,
    pub sources: BTreeMap<String, UpstreamObservation>,
}

fn timestamp(value: &str) -> Result<u64, String> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .and_then(|time| u64::try_from(time.timestamp()).ok())
        .ok_or_else(|| "invalid timezone-aware ThreatDB timestamp".to_string())
}

fn digest(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl UpstreamObservations {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 || self.sources.len() != SOURCE_IDS.len() {
            return Err("unexpected upstream observation schema or source set".into());
        }
        let checked = timestamp(&self.checked_at)?;
        for source in SOURCE_IDS {
            let item = self
                .sources
                .get(source)
                .ok_or("missing upstream observation")?;
            if !digest(&item.pinned_commit, 20)
                || !digest(&item.candidate_commit, 20)
                || timestamp(&item.candidate_timestamp)? > checked
                || !(1..=8760).contains(&item.max_lag_hours)
                || item.review_required != (item.pinned_commit != item.candidate_commit)
                || (item.ahead_by != 0) != item.review_required
            {
                return Err(format!("inconsistent upstream observation for {source}"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceFreshness {
    pub source: String,
    pub revision: Option<String>,
    pub revision_age_seconds: Option<u64>,
    pub pin_selected_at: Option<String>,
    pub observation_age_seconds: Option<u64>,
    pub known_upstream_lag_seconds: Option<u64>,
    pub upstream_commits_ahead: Option<u64>,
    pub reviewed_pin_adoption_required: Option<bool>,
    pub lag_exceeds_reviewed_budget: Option<bool>,
    pub accepted: Option<u64>,
    pub rejected: Option<u64>,
    pub accepted_fraction: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FreshnessReport {
    /// The signed DB build time, retained as a publication-age proxy. Actual
    /// upload completion is not stamped into the immutable database.
    pub publication_age_seconds: Option<u64>,
    pub publication_time_basis: &'static str,
    pub clock_skew: bool,
    pub source_evidence: &'static str,
    pub source_evidence_error: Option<String>,
    pub sources: Vec<SourceFreshness>,
}

impl FreshnessReport {
    pub fn unavailable(build_timestamp: Option<u64>, now: u64, error: Option<String>) -> Self {
        Self {
            publication_age_seconds: build_timestamp.and_then(|built| now.checked_sub(built)),
            publication_time_basis: "signed_build_timestamp",
            clock_skew: build_timestamp.is_some_and(|built| built > now),
            source_evidence: "unavailable",
            source_evidence_error: error,
            sources: Vec::new(),
        }
    }
}

/// Validate signed source evidence for exactly one installed blob. A valid
/// signature for another generation, format, or hash cannot label this DB fresh.
pub fn verify_source_evidence(
    integrity: &[u8],
    provenance: &[u8],
    key: &VerifyingKey,
    sequence: u64,
    format: u32,
    db_sha256: &str,
) -> Result<Value, String> {
    if integrity.len() as u64 > PROVENANCE_LIMIT || provenance.len() as u64 > PROVENANCE_LIMIT {
        return Err("source evidence exceeds byte cap".into());
    }
    let mut sidecar: Value =
        serde_json::from_slice(integrity).map_err(|_| "invalid source-integrity JSON")?;
    let object = sidecar
        .as_object_mut()
        .ok_or("invalid source-integrity object")?;
    let encoded = object
        .remove("signature")
        .ok_or("missing source-integrity signature")?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(
            encoded
                .as_str()
                .ok_or("invalid source-integrity signature")?,
        )
        .map_err(|_| "invalid source-integrity signature encoding")?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| "invalid source-integrity signature length")?;
    let canonical = serde_json::to_vec(&sidecar).map_err(|_| "cannot encode source-integrity")?;
    key.verify_strict(&canonical, &signature)
        .map_err(|_| "source-integrity signature verification failed")?;
    if sidecar["manifest_version"] != 1 || sidecar["sequence"] != sequence {
        return Err("source-integrity schema or generation mismatch".into());
    }
    let hash_field = match format {
        1 => "v1_sha256",
        2 => "v2_sha256",
        _ => return Err("unsupported source-integrity database format".into()),
    };
    if sidecar[hash_field].as_str() != Some(db_sha256) {
        return Err("source-integrity does not bind the installed database".into());
    }
    let document: Value =
        serde_json::from_slice(provenance).map_err(|_| "invalid source provenance JSON")?;
    if document["schema_version"] != 2 || document["compiler_parse"]["schema_version"] != 1 {
        return Err("unsupported source provenance schema".into());
    }
    let mut source = document.clone();
    let source_object = source
        .as_object_mut()
        .ok_or("invalid source provenance object")?;
    let compiler = source_object
        .remove("compiler_parse")
        .ok_or("missing compiler metadata")?;
    source_object.remove("integrity_bindings");
    let mut source_bytes =
        serde_json::to_vec(&source).map_err(|_| "cannot encode source provenance")?;
    source_bytes.push(b'\n'); // fetch transaction uses jq -cS, including its newline
    let compiler_bytes =
        serde_json::to_vec(&compiler).map_err(|_| "cannot encode compiler metadata")?;
    for (field, bytes) in [
        ("source_transaction_sha256", &source_bytes),
        ("compiler_metadata_sha256", &compiler_bytes),
    ] {
        let actual = format!("{:x}", Sha256::digest(bytes));
        if sidecar[field].as_str() != Some(actual.as_str()) {
            return Err(format!("source evidence {field} integrity mismatch"));
        }
    }
    Ok(document)
}

pub fn source_freshness(document: &Value, built: u64, now: u64) -> Result<FreshnessReport, String> {
    let mut report = FreshnessReport::unavailable(Some(built), now, None);
    report.source_evidence = "signature_verified_for_installed_database";
    let observations = document["compiler_parse"]
        .get("upstream_observations")
        .filter(|value| !value.is_null())
        .map(|value| {
            serde_json::from_value::<UpstreamObservations>(value.clone())
                .map_err(|_| "invalid upstream observation schema".to_string())
        })
        .transpose()?;
    if let Some(observations) = &observations {
        observations.validate()?;
    }
    let parsers = document["compiler_parse"]["sources"]
        .as_object()
        .ok_or("missing source counts")?;
    if SOURCE_IDS
        .iter()
        .any(|source| !parsers.contains_key(*source))
    {
        return Err("source evidence is missing required parser coverage".into());
    }
    for (source, counts) in parsers {
        let data = &document[source];
        let revision = data["commit"].as_str();
        let revised = data["commit_timestamp"]
            .as_str()
            .map(timestamp)
            .transpose()?;
        let accepted = counts["accepted"]
            .as_u64()
            .ok_or("invalid accepted source count")?;
        let rejected = counts["rejected"]
            .as_u64()
            .ok_or("invalid rejected source count")?;
        let mut row = SourceFreshness {
            source: source.clone(),
            revision: revision.map(str::to_string),
            revision_age_seconds: revised.and_then(|time| now.checked_sub(time)),
            pin_selected_at: data["pin_selected_at"].as_str().map(str::to_string),
            observation_age_seconds: None,
            known_upstream_lag_seconds: None,
            upstream_commits_ahead: None,
            reviewed_pin_adoption_required: None,
            lag_exceeds_reviewed_budget: None,
            accepted: Some(accepted),
            rejected: Some(rejected),
            accepted_fraction: accepted
                .checked_add(rejected)
                .filter(|total| *total > 0)
                .map(|total| accepted as f64 / total as f64),
        };
        report.clock_skew |= revised.is_some_and(|time| time > now);
        if let Some(observations) = &observations {
            if let Some(observation) = observations.sources.get(source) {
                if revision != Some(observation.pinned_commit.as_str()) {
                    return Err(
                        "upstream observation does not describe the published source pin".into(),
                    );
                }
                let checked = timestamp(&observations.checked_at)?;
                let upstream = timestamp(&observation.candidate_timestamp)?;
                let revised = revised.ok_or("observed source lacks revision timestamp")?;
                if !observation.review_required && upstream != revised {
                    return Err(
                        "unchanged upstream observation has a different commit timestamp".into(),
                    );
                }
                let lag = upstream.saturating_sub(revised);
                row.observation_age_seconds = now.checked_sub(checked);
                row.known_upstream_lag_seconds = Some(lag);
                row.upstream_commits_ahead = Some(observation.ahead_by);
                row.reviewed_pin_adoption_required = Some(observation.review_required);
                row.lag_exceeds_reviewed_budget = Some(lag > observation.max_lag_hours * 3600);
                report.clock_skew |= checked > now;
            }
        }
        report.sources.push(row);
    }
    Ok(report)
}

/// Retry only transient status codes; caller still validates identity, schema,
/// size and integrity exactly once after receiving a successful response.
pub fn retry_delay(
    status: u16,
    retry_after: Option<&str>,
    attempt: u32,
    remaining: Duration,
    now: u64,
) -> Option<Duration> {
    if attempt >= 2 || !matches!(status, 408 | 429 | 500 | 502 | 503 | 504) {
        return None;
    }
    let seconds = match retry_after {
        Some(value) => value.trim().parse::<u64>().ok().or_else(|| {
            chrono::DateTime::parse_from_rfc2822(value)
                .ok()
                .and_then(|date| u64::try_from(date.timestamp()).ok())
                .map(|date| date.saturating_sub(now))
        })?,
        None => 1 << attempt,
    };
    let delay = Duration::from_secs(seconds);
    // Refuse an over-budget server delay instead of retrying before it permits.
    (delay < remaining).then_some(delay)
}

/// Bounded GET/HEAD transport recovery. Callers keep all successful-response
/// validation outside the retry loop. Unclassified connection/TLS errors fail
/// once; they are not assumed to be transient identity failures.
pub fn send_with_retry(
    request: reqwest::blocking::RequestBuilder,
    budget: Duration,
) -> Result<reqwest::blocking::Response, String> {
    let method = request
        .try_clone()
        .ok_or("transport request cannot be cloned safely")?
        .build()
        .map_err(|_| "invalid transport request")?
        .method()
        .clone();
    if method != reqwest::Method::GET && method != reqwest::Method::HEAD {
        return Err("ThreatDB recovery only supports idempotent GET and HEAD requests".into());
    }
    let deadline = std::time::Instant::now() + budget;
    let mut attempt = 0;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err("transport source deadline exhausted".into());
        }
        let next = request
            .try_clone()
            .ok_or("transport request cannot be retried safely")?;
        let result = next.timeout(remaining).send();
        let (status, retry_after) = match &result {
            Ok(response) => (
                response.status().as_u16(),
                response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok()),
            ),
            Err(error) if error.is_timeout() => (503, None),
            Err(_) => (0, None),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Some(delay) = retry_delay(
            status,
            retry_after,
            attempt,
            deadline.saturating_duration_since(std::time::Instant::now()),
            now,
        ) {
            drop(result);
            std::thread::sleep(delay);
            attempt += 1;
            continue;
        }
        // No reqwest Display here: it may include a supplemental feed API key.
        return result.map_err(|error| {
            if error.is_timeout() {
                "transport timed out".into()
            } else if error.is_connect() {
                "connection or server identity failed".into()
            } else {
                "transport request failed".into()
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn fixture() -> (Value, UpstreamObservations) {
        let mut sources = BTreeMap::new();
        let mut document =
            json!({"schema_version": 2, "compiler_parse": {"schema_version": 1, "sources": {}}});
        for source in SOURCE_IDS {
            sources.insert(
                source.to_string(),
                UpstreamObservation {
                    pinned_commit: "a".repeat(40),
                    candidate_commit: "a".repeat(40),
                    candidate_timestamp: "2020-01-01T00:00:00Z".into(),
                    ahead_by: 0,
                    max_lag_hours: 48,
                    review_required: false,
                },
            );
            document[source] =
                json!({"commit": "a".repeat(40), "commit_timestamp": "2020-01-01T05:30:00+05:30"});
            document["compiler_parse"]["sources"][source] = json!({"accepted": 100, "rejected": 5});
        }
        (
            document,
            UpstreamObservations {
                schema_version: 1,
                checked_at: "2026-01-01T00:00:00Z".into(),
                sources,
            },
        )
    }

    #[test]
    fn old_unchanged_upstream_is_current_and_pending_adoption_is_separate() {
        let (mut document, mut observations) = fixture();
        let row = observations.sources.get_mut(SOURCE_IDS[0]).unwrap();
        row.candidate_commit = "b".repeat(40);
        row.candidate_timestamp = "2025-12-31T00:00:00Z".into();
        row.ahead_by = 3;
        row.review_required = true;
        document["compiler_parse"]["upstream_observations"] =
            serde_json::to_value(observations).unwrap();
        let now = timestamp("2026-01-02T00:00:00Z").unwrap();
        let report = source_freshness(&document, now - 3600, now).unwrap();
        assert_eq!(report.publication_age_seconds, Some(3600));
        let old = report
            .sources
            .iter()
            .find(|row| row.source == SOURCE_IDS[1])
            .unwrap();
        assert!(old.revision_age_seconds.unwrap() > 365 * 86400);
        assert_eq!(old.known_upstream_lag_seconds, Some(0));
        assert_eq!(old.reviewed_pin_adoption_required, Some(false));
        let pending = report
            .sources
            .iter()
            .find(|row| row.source == SOURCE_IDS[0])
            .unwrap();
        assert_eq!(pending.reviewed_pin_adoption_required, Some(true));
        assert_eq!(pending.lag_exceeds_reviewed_budget, Some(true));
        assert_eq!(pending.observation_age_seconds, Some(86400));
    }

    #[test]
    fn missing_observation_is_unknown_and_future_timestamp_is_not_fresh() {
        let (document, _) = fixture();
        let report = source_freshness(&document, 200, 100).unwrap();
        assert!(report.clock_skew);
        assert_eq!(report.publication_age_seconds, None);
        assert!(report
            .sources
            .iter()
            .all(|row| row.known_upstream_lag_seconds.is_none()));
    }

    #[test]
    fn source_evidence_refuses_incomplete_coverage_and_inconsistent_observations() {
        let (mut document, observations) = fixture();
        document["compiler_parse"]["upstream_observations"] =
            serde_json::to_value(observations).unwrap();
        document["compiler_parse"]["upstream_observations"]["sources"][SOURCE_IDS[0]]
            ["candidate_timestamp"] = json!("2020-01-02T00:00:00Z");
        assert!(source_freshness(&document, 0, 2_000_000_000).is_err());
        document["compiler_parse"]
            .as_object_mut()
            .unwrap()
            .remove("upstream_observations");
        document["compiler_parse"]["sources"]
            .as_object_mut()
            .unwrap()
            .remove(SOURCE_IDS[0]);
        assert!(source_freshness(&document, 0, 2_000_000_000).is_err());
    }

    #[test]
    fn source_signature_binds_database_and_canonical_source_and_counts() {
        let (document, _) = fixture();
        let key = SigningKey::from_bytes(&[29; 32]);
        let mut source = document.clone();
        let compiler = source
            .as_object_mut()
            .unwrap()
            .remove("compiler_parse")
            .unwrap();
        let mut source_bytes = serde_json::to_vec(&source).unwrap();
        source_bytes.push(b'\n');
        let mut sidecar = json!({"manifest_version":1,"sequence":4,"v1_sha256":"abc",
            "source_transaction_sha256":format!("{:x}", Sha256::digest(source_bytes)),
            "compiler_metadata_sha256":format!("{:x}", Sha256::digest(serde_json::to_vec(&compiler).unwrap()))});
        let signature = key.sign(&serde_json::to_vec(&sidecar).unwrap());
        sidecar["signature"] =
            json!(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()));
        let integrity = serde_json::to_vec(&sidecar).unwrap();
        let data = serde_json::to_vec(&document).unwrap();
        assert!(
            verify_source_evidence(&integrity, &data, &key.verifying_key(), 4, 1, "abc").is_ok()
        );
        assert!(
            verify_source_evidence(&integrity, &data, &key.verifying_key(), 5, 1, "abc").is_err()
        );
        assert!(
            verify_source_evidence(&integrity, &data, &key.verifying_key(), 4, 2, "abc").is_err()
        );
        let mut tampered = document;
        tampered["compiler_parse"]["sources"][SOURCE_IDS[0]]["accepted"] = json!(1);
        assert!(verify_source_evidence(
            &integrity,
            &serde_json::to_vec(&tampered).unwrap(),
            &key.verifying_key(),
            4,
            1,
            "abc"
        )
        .is_err());
        assert!(verify_source_evidence(
            &integrity,
            &data,
            &SigningKey::from_bytes(&[30; 32]).verifying_key(),
            4,
            1,
            "abc"
        )
        .is_err());
    }

    #[test]
    fn retries_obey_status_server_backoff_attempts_and_deadline() {
        let budget = Duration::from_secs(20);
        for permanent in [200, 400, 401, 403, 404, 422] {
            assert_eq!(retry_delay(permanent, None, 0, budget, 0), None);
        }
        assert_eq!(
            retry_delay(429, Some("10"), 0, budget, 0),
            Some(Duration::from_secs(10))
        );
        assert_eq!(retry_delay(503, Some("30"), 0, budget, 0), None);
        assert_eq!(retry_delay(503, Some("bad"), 0, budget, 0), None);
        assert_eq!(retry_delay(503, None, 2, budget, 0), None);
        assert_eq!(retry_delay(503, None, 1, Duration::from_secs(2), 0), None);
        assert_eq!(
            retry_delay(429, Some("Thu, 01 Jan 1970 00:00:10 GMT"), 0, budget, 0),
            Some(Duration::from_secs(10))
        );
    }

    #[test]
    fn retry_transport_refuses_mutations_before_network() {
        let client = reqwest::blocking::Client::new();
        let error = send_with_retry(client.post("https://example.com/"), Duration::from_secs(1))
            .unwrap_err();
        assert!(error.contains("GET and HEAD"));
    }
}
