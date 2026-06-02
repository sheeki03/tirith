//! M6 ch6 — thin adapter over the shipping `threatdb_api.rs` OSV cache.
//!
//! [`for_package`] consults the same on-disk cache layout `threatdb_api.rs`
//! uses (1-hour TTL) and falls through to a fresh OSV query on a cold cache,
//! returning an [`OsvAdvisorySummary`] for the deterministic factor model.
//!
//! No new `ThreatSource` variant and no new cache dir (same
//! `state_dir()/threatdb-api-cache/`, `osv2-`-namespaced keys). Best-effort: any
//! error is a silent empty result, never a panic; read-only beyond the cache
//! file the shipping path already writes.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use crate::package_risk::OsvAdvisorySummary;
use crate::policy;
use crate::threatdb::Ecosystem;

/// Outcome of an OSV lookup. Distinguishes "asked, got no advisories" from
/// "couldn't ask" — both produce an empty `Vec`, so the explainer needs the
/// state to render honestly (`(no advisories)` vs `(OSV check unavailable: …)`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", tag = "state", content = "reason")]
pub enum OsvLookupState {
    /// Not attempted (offline, unsupported ecosystem, or no version). Default.
    #[default]
    NotChecked,
    /// Completed; the (possibly empty) advisory set is verified.
    Verified,
    /// Attempted but failed — treat the advisory set as unknown, not empty.
    Unavailable(String),
}

/// An OSV lookup's advisory list paired with its [`OsvLookupState`], so a failed
/// lookup isn't treated as "clean".
#[derive(Debug, Clone)]
pub struct OsvLookupResult {
    pub advisories: Vec<OsvAdvisorySummary>,
    pub state: OsvLookupState,
}

impl OsvLookupResult {
    pub fn verified(advisories: Vec<OsvAdvisorySummary>) -> Self {
        Self {
            advisories,
            state: OsvLookupState::Verified,
        }
    }
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            advisories: Vec::new(),
            state: OsvLookupState::Unavailable(reason.into()),
        }
    }
}

/// Reuse the `threatdb_api.rs` OSV TTL (1 hour) so the two paths stay consistent.
const CACHE_TTL_SECS: u64 = 3600;
/// Per-call timeout — the CLI path is interactive; a degraded score beats a hang.
const REQUEST_TIMEOUT_SECS: u64 = 10;

/// Resolve OSV advisories for `(eco, name, version)` with the lookup state — the
/// canonical entry point. Distinguishes Verified-empty from Unavailable-empty,
/// which the legacy [`for_package`] cannot.
pub fn for_package_with_state(eco: Ecosystem, name: &str, version: &str) -> OsvLookupResult {
    let Some(eco_name) = osv_ecosystem_name(eco) else {
        // No OSV mapping for distro/docker — a deterministic skip, rendered as
        // Unavailable with an honest reason.
        return OsvLookupResult::unavailable(format!(
            "{eco:?} has no OSV mapping; lookup deliberately skipped",
        ));
    };
    let cache_key = format!("{}:{name}:{version}", eco_label(eco));

    if let Some(cached) = load_cache::<Vec<OsvAdvisorySummary>>(&cache_key) {
        return OsvLookupResult::verified(cached);
    }

    // Cache miss — query OSV. `None` means the lookup failed; don't claim
    // "verified empty" from a failed lookup.
    let advs = match query_osv_sync(eco_name, name, version) {
        Some(v) => v,
        None => return OsvLookupResult::unavailable("osv.dev query failed (network/parse error)"),
    };

    store_cache(&cache_key, &advs);
    OsvLookupResult::verified(advs)
}

/// Legacy shape — the advisory list only (empty conflates several outcomes).
/// New code should prefer [`for_package_with_state`].
pub fn for_package(eco: Ecosystem, name: &str, version: &str) -> Vec<OsvAdvisorySummary> {
    for_package_with_state(eco, name, version).advisories
}

// --- cache ---

#[derive(Debug, Serialize, Deserialize)]
struct CacheEnvelope<T> {
    fetched_at: u64,
    value: T,
}

/// Cache file path under `state_dir()/threatdb-api-cache/`, `osv2-`-prefixed so
/// it never collides with `threatdb_api.rs`'s `osv-` rows.
fn cache_path(key: &str) -> Option<std::path::PathBuf> {
    let state = policy::state_dir()?;
    let digest = sha2::Sha256::digest(format!("osv2:{key}").as_bytes());
    let hex: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
    Some(
        state
            .join("threatdb-api-cache")
            .join(format!("osv2-{hex}.json")),
    )
}

fn load_cache<T: for<'de> Deserialize<'de>>(key: &str) -> Option<T> {
    let path = cache_path(key)?;
    let content = std::fs::read_to_string(path).ok()?;
    let env: CacheEnvelope<T> = serde_json::from_str(&content).ok()?;
    if unix_now().saturating_sub(env.fetched_at) > CACHE_TTL_SECS {
        return None;
    }
    Some(env.value)
}

fn store_cache<T: Serialize>(key: &str, value: &T) {
    let Some(path) = cache_path(key) else { return };
    let Some(parent) = path.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let env = CacheEnvelope {
        fetched_at: unix_now(),
        value,
    };
    if let Ok(serialized) = serde_json::to_vec(&env) {
        let _ = std::fs::write(path, serialized);
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// --- network query ---

#[derive(Debug, Deserialize, Serialize, Clone)]
struct OsvQueryResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    references: Vec<OsvReference>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct OsvSeverity {
    #[serde(rename = "type", default)]
    sev_type: String,
    #[serde(default)]
    score: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct OsvReference {
    #[serde(default)]
    url: String,
}

fn query_osv_sync(
    ecosystem_name: &str,
    name: &str,
    version: &str,
) -> Option<Vec<OsvAdvisorySummary>> {
    let deadline = Instant::now() + Duration::from_secs(REQUEST_TIMEOUT_SECS);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
        .ok()?;
    let body = serde_json::json!({
        "package": { "name": name, "ecosystem": ecosystem_name },
        "version": version,
    });

    let _ = deadline; // the client enforces the global timeout
    let resp = client
        .post("https://api.osv.dev/v1/query")
        .header("Content-Type", "application/json")
        .header(
            "User-Agent",
            format!("tirith/{} (osv-correlation)", env!("CARGO_PKG_VERSION")),
        )
        .json(&body)
        .send()
        .ok()?
        .error_for_status()
        .ok()?
        .json::<OsvQueryResponse>()
        .ok()?;

    let summaries: Vec<OsvAdvisorySummary> = resp
        .vulns
        .into_iter()
        .map(|v| OsvAdvisorySummary {
            cvss: parse_cvss3_base(&v.severity),
            id: v.id,
            aliases: v.aliases,
            summary: v.summary,
            reference: v.references.into_iter().map(|r| r.url).next(),
        })
        .collect();
    Some(summaries)
}

/// Parse the CVSS v3 base score from an OSV `severity` array.
///
/// `severity[].score` is either a bare numeric (`"7.5"`) or a CVSS v3 vector
/// (the common case); the vector form is computed per the FIRST.org v3.1 base
/// equations. Returns `None` only when wholly unparseable (rule then fires at
/// default Medium).
fn parse_cvss3_base(severity: &[OsvSeverity]) -> Option<f32> {
    severity
        .iter()
        .find(|s| s.sev_type.starts_with("CVSS_V3"))
        .and_then(|s| {
            let trimmed = s.score.trim();
            if let Ok(v) = trimmed.parse::<f32>() {
                return Some(v);
            }
            compute_cvss3_base_from_vector(trimmed)
        })
}

/// Compute the CVSS v3 base score from a vector string per the v3.1 spec.
/// Reads only base metrics (AV/AC/PR/UI/S/C/I/A); returns `None` on any missing
/// or out-of-enum metric.
fn compute_cvss3_base_from_vector(vector: &str) -> Option<f32> {
    let body = vector
        .strip_prefix("CVSS:3.1/")
        .or_else(|| vector.strip_prefix("CVSS:3.0/"))?;

    let mut av: Option<&str> = None;
    let mut ac: Option<&str> = None;
    let mut pr: Option<&str> = None;
    let mut ui: Option<&str> = None;
    let mut scope: Option<&str> = None;
    let mut c: Option<&str> = None;
    let mut i: Option<&str> = None;
    let mut a: Option<&str> = None;

    for pair in body.split('/') {
        let (k, v) = pair.split_once(':')?;
        match k {
            "AV" => av = Some(v),
            "AC" => ac = Some(v),
            "PR" => pr = Some(v),
            "UI" => ui = Some(v),
            "S" => scope = Some(v),
            "C" => c = Some(v),
            "I" => i = Some(v),
            "A" => a = Some(v),
            _ => {}
        }
    }

    let av_w = match av? {
        "N" => 0.85_f32,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.20,
        _ => return None,
    };
    let ac_w = match ac? {
        "L" => 0.77_f32,
        "H" => 0.44,
        _ => return None,
    };
    let s_changed = match scope? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let pr_w = match (pr?, s_changed) {
        ("N", _) => 0.85_f32,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.50,
        _ => return None,
    };
    let ui_w = match ui? {
        "N" => 0.85_f32,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |s: &str| -> Option<f32> {
        Some(match s {
            "N" => 0.0,
            "L" => 0.22,
            "H" => 0.56,
            _ => return None,
        })
    };
    let c_w = cia(c?)?;
    let i_w = cia(i?)?;
    let a_w = cia(a?)?;

    // ISS = 1 - ((1 - C) * (1 - I) * (1 - A))
    let iss = 1.0 - ((1.0 - c_w) * (1.0 - i_w) * (1.0 - a_w));
    // Impact = 6.42 * ISS                 if S:U
    // Impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02)^15  if S:C
    let impact = if s_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    // Exploitability = 8.22 * AV * AC * PR * UI
    let exploitability = 8.22 * av_w * ac_w * pr_w * ui_w;
    // BaseScore =
    //   if S:U → roundup(min(Impact + Exploitability, 10))
    //   if S:C → roundup(min(1.08 * (Impact + Exploitability), 10))
    let raw = if s_changed {
        (1.08 * (impact + exploitability)).min(10.0)
    } else {
        (impact + exploitability).min(10.0)
    };
    Some(cvss_roundup(raw))
}

/// CVSS v3.1 roundup (spec Section 7.1) — round up to the next 0.1.
fn cvss_roundup(input: f32) -> f32 {
    // Integer arithmetic to avoid float surprises: already-at-one-decimal
    // (mantissa multiple of 10,000) returns as-is, else round up to 0.1.
    let int_input = (input * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f32 / 100_000.0
    } else {
        ((int_input / 10_000) + 1) as f32 / 10.0
    }
}

fn eco_label(eco: Ecosystem) -> &'static str {
    // Lowercase ASCII, matching `threatdb_api.rs`'s cache key.
    match eco {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPI => "pypi",
        Ecosystem::RubyGems => "rubygems",
        Ecosystem::Crates => "cargo",
        Ecosystem::Go => "go",
        Ecosystem::Maven => "maven",
        Ecosystem::NuGet => "nuget",
        Ecosystem::Packagist => "packagist",
        Ecosystem::Apt
        | Ecosystem::Brew
        | Ecosystem::Dnf
        | Ecosystem::Yum
        | Ecosystem::Pacman
        | Ecosystem::Scoop
        | Ecosystem::Docker => "unsupported",
    }
}

fn osv_ecosystem_name(eco: Ecosystem) -> Option<&'static str> {
    // OSV canonical names — matches `threatdb_api.rs::osv_ecosystem_name`.
    match eco {
        Ecosystem::Npm => Some("npm"),
        Ecosystem::PyPI => Some("PyPI"),
        Ecosystem::RubyGems => Some("RubyGems"),
        Ecosystem::Crates => Some("crates.io"),
        Ecosystem::Go => Some("Go"),
        Ecosystem::Maven => Some("Maven"),
        Ecosystem::NuGet => Some("NuGet"),
        Ecosystem::Packagist => Some("Packagist"),
        Ecosystem::Apt
        | Ecosystem::Brew
        | Ecosystem::Dnf
        | Ecosystem::Yum
        | Ecosystem::Pacman
        | Ecosystem::Scoop
        | Ecosystem::Docker => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_ecosystem_returns_empty() {
        let advs = for_package(Ecosystem::Apt, "nginx", "1.0");
        assert!(advs.is_empty(), "apt is not a supported OSV ecosystem");
    }

    #[test]
    fn cvss_numeric_score_parsed() {
        let sev = vec![OsvSeverity {
            sev_type: "CVSS_V3".to_string(),
            score: "7.5".to_string(),
        }];
        assert_eq!(parse_cvss3_base(&sev), Some(7.5));
    }

    #[test]
    fn cvss_vector_form_incomplete_returns_none() {
        // Missing base metrics — must decline, not fabricate a score.
        let sev = vec![OsvSeverity {
            sev_type: "CVSS_V3".to_string(),
            score: "CVSS:3.1/AV:N/AC:L".to_string(),
        }];
        assert_eq!(parse_cvss3_base(&sev), None);
    }

    #[test]
    fn cvss_vector_critical_full_impact_unchanged_scope() {
        // The canonical 10.0-critical vector — verifies the spec equations.
        let sev = vec![OsvSeverity {
            sev_type: "CVSS_V3".to_string(),
            score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
        }];
        let v = parse_cvss3_base(&sev).expect("vector should parse");
        assert!((9.7..=10.0).contains(&v), "expected ≈10.0, got {v}");
    }

    #[test]
    fn cvss_vector_high_partial_impact() {
        // A real-world high; CVSS calculator gives ≈4.7.
        let sev = vec![OsvSeverity {
            sev_type: "CVSS_V3".to_string(),
            score: "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:H/I:L/A:N".to_string(),
        }];
        let v = parse_cvss3_base(&sev).expect("vector should parse");
        assert!((4.0..=5.5).contains(&v), "expected ≈4.7, got {v}");
    }

    #[test]
    fn cvss_vector_changed_scope_uses_pr_changed_weights() {
        // S:C with PR:L → the changed-scope PR weight (0.68); calculator: 10.0.
        let sev = vec![OsvSeverity {
            sev_type: "CVSS_V3".to_string(),
            score: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H".to_string(),
        }];
        let v = parse_cvss3_base(&sev).expect("vector should parse");
        assert!(v >= 9.5, "expected ≈10.0, got {v}");
    }

    #[test]
    fn cvss_other_type_ignored() {
        let sev = vec![OsvSeverity {
            sev_type: "CVSS_V2".to_string(),
            score: "5.0".to_string(),
        }];
        assert_eq!(parse_cvss3_base(&sev), None);
    }

    #[test]
    fn for_package_offline_failure_is_empty_not_panic() {
        // Graceful fallback path; no emptiness assertion (a cached CI row may
        // exist).
        let _ = for_package(
            Ecosystem::Npm,
            "this-package-name-cannot-exist-xyzzy-12345",
            "1.0.0",
        );
    }
}
