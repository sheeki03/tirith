//! Deterministic, fully explainable package provenance / maintainer-risk
//! scoring.
//!
//! `tirith package risk <ecosystem> <name>` scores a package as a fixed sum of
//! named, inspectable factors (like [`crate::scoring`] for URLs). There is **no
//! model, no learned weight, no classifier** — every score is reproducible by
//! hand. The final score is `min(100, sum)`; the clamp is reported as an
//! explicit factor so the breakdown always sums exactly to the score.
//!
//! Offline signals (always computed, **no network**): name-vs-popular (local
//! threat-DB), known-malicious typosquat, and — only when package content is
//! locally available (tirith never downloads it) — install/lifecycle-hook and
//! binary-blob presence.
//!
//! Registry-API provenance signals (`--online` only; see [`ApiProvenance`] /
//! [`api_factors`]) are a deterministic addition of named fixed-weight factors.
//! The [`ApiSignals`] enum is the seam: offline reports
//! [`ApiSignals::NotComputed`], an online run [`ApiSignals::Available`], and a
//! network/API failure degrades gracefully to [`ApiSignals::Unavailable`].
//! tirith NEVER reaches the network from `tirith check` or any hot path —
//! `--online` on `package risk` is the only entry point.
//!
//! This score is **advisory and standalone**: not a detection rule, produces no
//! [`Verdict`](crate::verdict::Verdict), changes no `Action`, exit code, or
//! audit log.

use serde::{Deserialize, Serialize};

use crate::threatdb::{Ecosystem, ThreatDb};

/// The maximum possible score. Scores are clamped here.
pub const MAX_SCORE: u32 = 100;

// M6 ch6 — weights for the seven new signal-driven factors (moderate).

/// The registry positively reports the package does not exist (HTTP 404).
/// Distinct from `ApiSignals::Unavailable` (unknown).
const PACKAGE_NOT_FOUND_WEIGHT: u32 = 18;
/// Snapshot-vs-snapshot diff shows maintainers were added or removed within
/// the recency window.
const MAINTAINER_CHANGE_RECENT_WEIGHT: u32 = 12;
/// Snapshot-vs-snapshot diff confirms a real ownership transfer (every prior
/// maintainer is gone). Superior signal to the one-response inferred flag.
const OWNERSHIP_TRANSFER_DIFF_WEIGHT: u32 = 18;
/// An active OSV advisory (any CVSS) for the requested version.
const OSV_ADVISORY_ACTIVE_WEIGHT: u32 = 18;
/// Dependency-confusion heuristic match.
const DEP_CONFUSION_WEIGHT: u32 = 18;
/// Install-script analysis found a network call / shell spawn.
const INSTALL_SCRIPT_NETWORK_WEIGHT: u32 = 12;
/// Registry-claimed repo URL did not verify (`Mismatch`).
const REPO_MISMATCH_WEIGHT: u32 = 18;

/// M6 ch6 — recency window: a snapshot diff is "recent" when the two snapshots
/// are less than this many days apart.
pub const MAINTAINER_CHANGE_RECENT_DAYS: u32 = 30;

// --- factor weights (all fixed, all inspectable) ---------------------------

/// A name one Levenshtein edit from a known-popular package — the classic
/// typosquat / slopsquat shape.
const NAME_NEAR_POPULAR_WEIGHT: u32 = 60;
/// A name that neither is nor resembles a known-popular package. Unknown is not
/// malicious — a deliberately small baseline.
const NAME_UNKNOWN_WEIGHT: u32 = 10;
/// The name is in the threat-DB's malicious-typosquat index — a confirmed bad
/// name. Additive on top of the near-popular term.
const KNOWN_MALICIOUS_TYPOSQUAT_WEIGHT: u32 = 30;
/// An install / lifecycle hook is present in locally-inspected package content.
const INSTALL_SCRIPT_WEIGHT: u32 = 15;
/// Compiled / native binary blobs are bundled in locally-inspected content.
const BINARY_BLOB_WEIGHT: u32 = 10;

// --- registry-API provenance factor weights (only on an `--online` run) ----
// Moderate: the offline name signal stays dominant; provenance corroborates.

/// Package itself very new (within [`VERY_NEW_PACKAGE_DAYS`]) — the textbook
/// freshly-uploaded typosquat shape.
const PACKAGE_VERY_NEW_WEIGHT: u32 = 25;
/// The *latest version* is very new (within [`VERY_NEW_VERSION_DAYS`]) on an
/// otherwise-older package — a weaker, smaller signal.
const LATEST_VERSION_VERY_NEW_WEIGHT: u32 = 8;
/// The registry lists an established package with zero maintainers — abandoned
/// ownership, a classic account-takeover precursor.
const OWNERSHIP_TRANSFER_WEIGHT: u32 = 20;
/// An abnormal version jump (e.g. `1.2.3` → `9.0.0`) — a hijacked release often
/// inflates the version to win a semver range.
const VERSION_SPIKE_WEIGHT: u32 = 15;
/// Very few downloads ([`LOW_DOWNLOAD_THRESHOLD`] or fewer) — near-zero
/// adoption is a weak signal.
const LOW_DOWNLOADS_WEIGHT: u32 = 10;
/// No source-repository URL, or one inconsistent with the package — provenance
/// cannot be traced to reviewable source.
const REPO_URL_MISSING_WEIGHT: u32 = 12;
/// The latest version is yanked / deprecated by the registry itself.
const YANKED_OR_DEPRECATED_WEIGHT: u32 = 18;

/// A package first published within this many days counts as "very new".
pub const VERY_NEW_PACKAGE_DAYS: u64 = 30;
/// A latest version published within this many days counts as "very new".
pub const VERY_NEW_VERSION_DAYS: u64 = 7;
/// At or below this download count, downloads are treated as "very low".
pub const LOW_DOWNLOAD_THRESHOLD: u64 = 100;

/// Risk-level buckets, fixed thresholds (same shape as `crate::scoring`).
pub fn risk_level(score: u32) -> &'static str {
    match score {
        0..=20 => "low",
        21..=50 => "medium",
        51..=75 => "high",
        _ => "critical",
    }
}

/// One named, inspectable contributor to a package-risk score.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RiskFactor {
    /// Stable machine identifier (e.g. `"name_vs_popular"`).
    pub id: &'static str,
    /// Human-readable label.
    pub label: String,
    /// Points this factor contributes. Always >= 0 except the `clamp` factor.
    pub points: i32,
    /// Plain-language explanation, written so a reader can verify it by hand.
    pub detail: String,
}

/// How the package name relates to the local threat-DB `popular` set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum NameVsPopular {
    /// The name *is* a known-popular package in this ecosystem.
    KnownPopular,
    /// The name is a near-miss of a known-popular package — a small edit
    /// distance away.
    NearPopular {
        /// The popular package the name resembles.
        popular_name: String,
        /// Levenshtein edit distance from `popular_name` — a small value (the
        /// near-miss classifier only reports close matches).
        distance: usize,
    },
    /// The name neither is, nor resembles, any known-popular package.
    Unknown,
}

/// Whether locally-available package content was inspected, and what it held.
///
/// `package risk` only inspects content the caller already has on disk — it
/// never downloads a package. When no local content is available, content
/// signals are simply absent from the score (not a network fetch).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ContentSignals {
    /// No local package directory was supplied or found — content signals were
    /// not evaluated. This is not a fetch and not a failure.
    NotInspected,
    /// A local package directory was inspected.
    Inspected {
        /// The inspected directory (for transparency in the explanation).
        path: String,
        /// An install / lifecycle hook was found (e.g. an npm `postinstall`
        /// script, or a PyPI `setup.py`).
        has_install_script: bool,
        /// Plain-language note on what install indicator matched, if any.
        install_script_detail: Option<String>,
        /// Compiled / native binary artifacts were found bundled in the
        /// package directory.
        has_binary_blob: bool,
        /// Plain-language note on what binary indicator matched, if any.
        binary_blob_detail: Option<String>,
    },
}

/// M6 ch6 — does the registry positively claim this package exists?
///
/// Distinct from [`ApiSignals::Unavailable`], which carries no positive
/// claim. Only a `--online` run that actually reached the registry can
/// resolve this to `Exists` or `NotFound`; every other path keeps it
/// `Unknown` (the honest no-data state).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PackageExistence {
    /// The registry responded successfully — the package exists.
    Exists,
    /// The registry responded HTTP 404 — the package positively does not
    /// exist. Policy rule `block_not_found` (ch7) gates Block on this.
    NotFound,
    /// No positive claim: the registry call was not made, failed before a
    /// response, or there is no adapter for the ecosystem.
    #[default]
    Unknown,
}

/// M6 ch6 — a registry's view of a maintainer at a point in time. Snapshot
/// store rows record `Vec<MaintainerRef>` per registry response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintainerRef {
    /// The maintainer's stable identifier in the registry (the npm "name",
    /// the PyPI "username", etc.). Lowercased for stable equality.
    pub id: String,
}

/// M6 ch6 — a snapshot-vs-snapshot diff of a package's maintainer set.
/// Produced by [`crate::registry_history::diff_two_snapshots`]; a `None`
/// diff (only one snapshot exists) means the recent-change rule cannot fire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MaintainerChangeHistory {
    /// Maintainers in the newer snapshot that were not in the older one.
    pub added: Vec<MaintainerRef>,
    /// Maintainers in the older snapshot that are not in the newer one.
    pub removed: Vec<MaintainerRef>,
    /// Number of whole days between the two snapshots, if both timestamps
    /// were captured. `None` if the older snapshot lacks a timestamp.
    pub transfer_within_days: Option<u32>,
}

impl MaintainerChangeHistory {
    /// `true` when the diff is non-empty and within the recency window.
    pub fn is_recent(&self) -> bool {
        if self.added.is_empty() && self.removed.is_empty() {
            return false;
        }
        match self.transfer_within_days {
            Some(d) => d <= MAINTAINER_CHANGE_RECENT_DAYS,
            None => false,
        }
    }

    /// `true` when every previous maintainer is gone and the new set is
    /// non-empty — a true ownership transfer (not just a co-maintainer add).
    ///
    /// From the diff alone this requires the `added`/`removed` sets to be fully
    /// disjoint by id. The stricter "all original maintainers retired" check
    /// lives in [`crate::registry_history::synthesize_transfer`], which sees the
    /// full snapshots.
    pub fn is_full_ownership_transfer(&self) -> bool {
        if self.removed.is_empty() || self.added.is_empty() {
            return false;
        }
        // Any shared id means a maintainer is in both snapshots — not cleared.
        self.added
            .iter()
            .all(|a| !self.removed.iter().any(|r| r.id == a.id))
            && self
                .removed
                .iter()
                .all(|r| !self.added.iter().any(|a| a.id == r.id))
    }
}

/// M6 ch6 — a single OSV advisory summary, surfaced from the shipping
/// `threatdb_api.rs` OSV cache (no new threat-DB feed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OsvAdvisorySummary {
    /// The OSV advisory ID (e.g. `GHSA-xxx-yyy-zzz`).
    pub id: String,
    /// Aliases — typically a `CVE-YYYY-NNNNN` plus the GHSA.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// Short, human-readable summary, when the advisory provided one.
    #[serde(default)]
    pub summary: Option<String>,
    /// CVSS v3 base score, when parseable. CVSS v3.0 and v3.1 both produce
    /// the same scale. `None` when the advisory lacks a CVSS string.
    #[serde(default)]
    pub cvss: Option<f32>,
    /// A reference URL (preferring the advisory's own canonical URL).
    #[serde(default)]
    pub reference: Option<String>,
}

impl OsvAdvisorySummary {
    /// `true` when the advisory's CVSS is at or above the High threshold.
    /// Used to escalate severity from Medium to High for `PackageOsvAdvisoryActive`.
    pub fn is_high_cvss(&self) -> bool {
        self.cvss.is_some_and(|c| c >= 7.0)
    }
}

/// M6 ch6 — dependency-confusion verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepConfusionVerdict {
    /// `true` when the heuristic believes the public-registry resolution
    /// could shadow an internal package.
    pub risk: bool,
    /// Plain-language note for the explanation; empty when `risk` is false.
    pub reason: String,
}

/// M6 ch6 — install-script analysis result. Read-only; the script is NEVER
/// executed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InstallScriptSignals {
    /// A network-call pattern (`curl`/`wget`/`fetch`/`http.get`/...) was
    /// matched in the script text.
    pub has_network_call: bool,
    /// A shell-spawn pattern was matched (e.g. `bash -c`, `sh -c`,
    /// `subprocess.run(["sh", ...])`).
    pub has_shell_spawn: bool,
    /// Free-form descriptions of the matches, lines included verbatim.
    /// Empty when neither flag is `true`.
    #[serde(default)]
    pub suspicious_patterns: Vec<String>,
}

impl InstallScriptSignals {
    /// `true` when at least one network or shell-spawn pattern matched.
    pub fn fires(&self) -> bool {
        self.has_network_call || self.has_shell_spawn
    }
}

/// M6 ch6 — repository-mismatch verdict, set only under `--online`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RepoMismatchVerdict {
    /// The repo-mismatch state for this package.
    pub state: RepoMismatchState,
    /// Plain-language reason, empty when `Unverifiable` was the default.
    #[serde(default)]
    pub reason: String,
}

/// State machine for the repo-mismatch check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RepoMismatchState {
    /// The registry-claimed URL resolved and the hosted manifest mentions
    /// this package name.
    Match,
    /// The URL is dead, parses as a non-git URL, or names a different package.
    Mismatch,
    /// No `--online` run, or the call was capped out, or the URL field was
    /// absent. Default; emits no finding.
    #[default]
    Unverifiable,
}

/// M6 ch6 — real ownership-transfer record, derived from a snapshot diff.
/// Distinct from the legacy `ApiProvenance::ownership_transferred` bool,
/// which is inferred from a single response (zero owners only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipTransfer {
    /// The maintainers that were active in the older snapshot.
    pub previous: Vec<MaintainerRef>,
    /// The maintainers active in the newer snapshot.
    pub current: Vec<MaintainerRef>,
    /// Days between the two snapshots when both timestamps are present.
    #[serde(default)]
    pub within_days: Option<u32>,
}

/// One registry-API provenance signal, as gathered from a registry response.
///
/// Each field is an *already-decided* boolean / value — the registry-specific
/// fetching and normalization (npm registry, PyPI JSON, crates.io) happens in
/// [`crate::registry_api`], so [`score_package`] stays a pure, total function
/// of its inputs. A `None` on an optional field means the registry did not
/// report that datum (it is then not scored — absence of a datum is not a
/// signal in itself).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ApiProvenance {
    /// Which registry API the data came from (`"npm"`, `"pypi"`,
    /// `"crates.io"`), for transparency in the explanation.
    pub source: String,
    /// Age of the package's *first* publication, in whole days, when the
    /// registry reported a creation timestamp.
    pub package_age_days: Option<u64>,
    /// Age of the *latest version*'s publication, in whole days, when known.
    pub latest_version_age_days: Option<u64>,
    /// `true` when the registry lists an established package with **zero**
    /// maintainers — the only ownership red flag a single registry document can
    /// show (one doc carries the current owner set, not its history). `None`
    /// when the API carries no maintainer field, so ownership is unknown.
    ///
    /// M6 ch6: superseded by the snapshot-diff `ownership_transfer` field below;
    /// kept for backward-compat, removed in a future cycle.
    #[deprecated(
        since = "0.4.0",
        note = "M6 ch6 — use the snapshot-vs-snapshot `ownership_transfer` field; \
                this inferred-from-one-response bool will be removed."
    )]
    pub ownership_transferred: Option<bool>,
    /// `true` when the latest version number is an abnormal jump from the
    /// previous one (a major-version spike). `None` when fewer than two
    /// versions exist, so no jump can be assessed.
    pub version_spike: Option<bool>,
    /// Total downloads over the registry's reported window, when available.
    pub recent_downloads: Option<u64>,
    /// `true` when the registry lists a usable source-repository URL,
    /// `false` when it lists none (or an unusable one). `None` when the
    /// registry API does not carry a repository field at all.
    pub has_source_repo: Option<bool>,
    /// `true` when the latest version is yanked / deprecated by the registry.
    pub yanked_or_deprecated: bool,
    /// The latest version string, purely for display in the explanation.
    pub latest_version: Option<String>,
    /// M6 ch6 — does the registry positively claim this package exists?
    /// Default `Unknown` — only a `--online` run that actually reached the
    /// registry resolves this to `Exists` or `NotFound`.
    #[serde(default)]
    pub package_existence: PackageExistence,
    /// M6 ch6 — snapshot-vs-snapshot maintainer-set diff. `None` when fewer than
    /// two snapshots exist (the diff cannot fire until a second `--online` run).
    #[serde(default)]
    pub maintainer_change_history: Option<MaintainerChangeHistory>,
    /// M6 ch6 — was the OSV lookup verified, unavailable, or not attempted?
    /// Distinguishes a verified-empty from a failed-lookup-empty result (both
    /// look identical to the score otherwise). Default `NotChecked` offline.
    #[serde(default)]
    pub osv_state: crate::osv_correlation::OsvLookupState,
    /// M6 ch6 — OSV advisories matching `(eco, name, version)`. Sourced from
    /// the shipping `threatdb_api.rs` OSV cache; no new feed.
    #[serde(default)]
    pub osv_advisories: Option<Vec<OsvAdvisorySummary>>,
    /// M6 ch6 — dependency-confusion heuristic verdict.
    #[serde(default)]
    pub dep_confusion: Option<DepConfusionVerdict>,
    /// M6 ch6 — install-script analysis signals (read-only; never executes).
    #[serde(default)]
    pub install_script_signals: Option<InstallScriptSignals>,
    /// M6 ch6 — registry-claimed-repo-URL verification under `--online`.
    #[serde(default)]
    pub repo_mismatch: Option<RepoMismatchVerdict>,
    /// M6 ch6 — real ownership-transfer record, derived from the snapshot
    /// diff above. Supersedes the inferred `ownership_transferred` flag.
    #[serde(default)]
    pub ownership_transfer: Option<OwnershipTransfer>,
    /// M6 ch6 — the registry-claimed repository URL when present and usable
    /// (https/ssh git host), so [`Self::repository_url_for_check`] / the
    /// `PackageRepoMismatch` rule have data without re-fetching. `None` when the
    /// API has no repository field or the value is empty / not a URL shape.
    #[serde(default)]
    pub repository_url: Option<String>,
}

impl ApiProvenance {
    /// The registry-claimed repository URL (from `repository_url`), or `None`
    /// when absent / not a recognized URL shape (per
    /// [`crate::registry_api::is_usable_repo_url`]).
    pub fn repository_url_for_check(&self) -> Option<String> {
        self.repository_url.clone()
    }
}

/// State of the registry-API-backed signals — the seam between always-on
/// offline signals and the opt-in `--online` registry signals.
///
/// * [`ApiSignals::NotComputed`] — the default; no `--online` (or forced
///   offline), so no API call was made.
/// * [`ApiSignals::Available`] — an `--online` run reached the registry; the
///   carried [`ApiProvenance`] drives the API factors.
/// * [`ApiSignals::Unavailable`] — `--online` requested but the call failed;
///   the score degrades to offline signals with an honest `reason`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
// M6 ch6 — boxing the ~340-byte `provenance` would ripple through every
// `Available { provenance }` match site; the enum is one-per-package on rare
// (offline-by-default) paths, so the cost is bounded.
#[allow(clippy::large_enum_variant)]
pub enum ApiSignals {
    /// Registry-API signals were not computed — offline run (the default).
    NotComputed {
        /// Why they were not computed.
        reason: String,
    },
    /// Registry-API signals were gathered from the registry.
    Available {
        /// The gathered provenance signals.
        provenance: ApiProvenance,
    },
    /// `--online` was requested but the registry call could not be completed;
    /// the score fell back to offline signals only.
    Unavailable {
        /// An honest, human-readable explanation of what went wrong.
        reason: String,
    },
}

impl ApiSignals {
    /// The default offline value: API signals are intentionally not computed.
    pub fn offline() -> Self {
        ApiSignals::NotComputed {
            reason: "registry-API signals are off by default; \
                     re-run `tirith package risk --online` to include them"
                .to_string(),
        }
    }

    /// API signals were requested (`--online`) but could not be gathered;
    /// the score used offline signals only.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        ApiSignals::Unavailable {
            reason: reason.into(),
        }
    }
}

/// A complete, reproducible explanation of a package-risk score.
///
/// Invariant: `factors.iter().map(|f| f.points).sum() == score as i32`.
#[derive(Debug, Clone, Serialize)]
pub struct RiskBreakdown {
    /// Ecosystem the lookup used (lowercase string, e.g. `"npm"`).
    pub ecosystem: String,
    /// The package name that was scored.
    pub name: String,
    /// Final risk score, 0..=100.
    pub score: u32,
    /// Risk level bucket derived from `score`.
    pub risk_level: &'static str,
    /// `true` when the local threat DB could not be loaded — name signals fall
    /// back to "unknown" and the caller should be told the DB is missing.
    pub threat_db_missing: bool,
    /// The name-vs-popular classification (always present).
    pub name_vs_popular: NameVsPopular,
    /// The exact malicious-typosquat name match, if the DB lists one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub malicious_typosquat_of: Option<String>,
    /// What local package content (if any) was inspected.
    pub content_signals: ContentSignals,
    /// State of the registry-API signals: [`ApiSignals::NotComputed`] on an
    /// offline run (the default), [`ApiSignals::Available`] on an `--online`
    /// run that reached the registry, or [`ApiSignals::Unavailable`] on an
    /// `--online` run that degraded — all three are reachable.
    pub api_signals: ApiSignals,
    /// The factors that sum to `score`, in display order.
    pub factors: Vec<RiskFactor>,
}

impl RiskBreakdown {
    /// Sum of all factor contributions.
    pub fn factor_sum(&self) -> i32 {
        self.factors.iter().map(|f| f.points).sum()
    }

    /// `true` iff the factors sum exactly to the final score — the
    /// reproducible-by-hand contract. Used by tests and a debug assert.
    pub fn verify(&self) -> bool {
        self.factor_sum() == self.score as i32
    }
}

/// Inputs to [`score_package`] — the raw signals, already gathered. Keeping
/// gathering (threat DB, filesystem, network) out of scoring lets
/// `score_package` be a pure, total function tests can drive without I/O.
#[derive(Debug, Clone)]
pub struct PackageSignals {
    pub ecosystem: Ecosystem,
    pub name: String,
    /// M6 ch6 — optional version from `<name>[@<version>]` CLI inputs, threaded
    /// to OSV correlation. `None` means no version specified.
    pub version: Option<String>,
    pub threat_db_missing: bool,
    pub name_vs_popular: NameVsPopular,
    /// `Some(popular_target)` when the threat DB lists this exact name as a
    /// known malicious typosquat.
    pub malicious_typosquat_of: Option<String>,
    pub content_signals: ContentSignals,
    /// The registry-API state to fold in; only [`ApiSignals::Available`] adds
    /// API factors. Defaults to [`ApiSignals::offline`].
    pub api: ApiSignals,
}

/// M6 ch6 — parse `<name>[@<version>]` into `(name, Option<version>)`. The
/// single source of truth for version-aware CLI parsing; a bare `<name>`
/// returns `(name, None)`.
///
/// Splits on the LAST `@` only, and only when followed by a version-shaped
/// token — so npm scoped packages disambiguate (`@org/util` → no version;
/// `@org/util@1.0` → `Some("1.0")`; `@org` → no version; `pkg@` → no version).
/// A version-shaped token starts with a digit / `v` / `~` / `^`; a path-segment
/// shape is rejected.
pub fn parse_name_and_version(input: &str) -> (String, Option<String>) {
    let s = input.trim();
    if s.is_empty() {
        return (String::new(), None);
    }
    let Some(last_at) = s.rfind('@') else {
        return (s.to_string(), None);
    };
    // `@` at position 0 is a scope sigil, not a version separator.
    if last_at == 0 {
        return (s.to_string(), None);
    }
    let (name, tail) = s.split_at(last_at);
    // `tail` starts with `@`; the version is everything after it.
    let version = &tail[1..];
    if version.is_empty() || !is_version_shaped(version) {
        // Not a version — give back the whole input as the name. This handles
        // a stray `@` at the end and pathological cases like `pkg@notaversion`.
        return (s.to_string(), None);
    }
    (name.to_string(), Some(version.to_string()))
}

/// `true` when `s` is shaped like a version specifier (numeric / `v` /
/// semver-range sigils). Conservative — rejects path-segment-like tails so
/// `@scope/name` does not get parsed as `name@<version>` with `<version> ==
/// "scope/name"`.
fn is_version_shaped(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // Reject anything that looks like a path segment.
    if s.contains('/') || s.contains('\\') || s.contains(' ') {
        return false;
    }
    let first = s.as_bytes()[0];
    first.is_ascii_digit() || matches!(first, b'v' | b'~' | b'^' | b'=' | b'>' | b'<' | b'*')
}

/// Compute the deterministic risk score and full factor breakdown from
/// already-gathered signals (offline factors always; API factors only when
/// [`PackageSignals::api`] is [`ApiSignals::Available`]).
///
/// A pure, total function — the single source of truth for the `package risk`
/// number. The returned breakdown always satisfies `breakdown.verify()`.
pub fn score_package(signals: &PackageSignals) -> RiskBreakdown {
    let mut factors: Vec<RiskFactor> = Vec::new();

    // Factor 1 — name vs. popular packages. The dominant term.
    let (name_points, name_label, name_detail) = match &signals.name_vs_popular {
        NameVsPopular::KnownPopular => (
            0,
            "Name vs. popular packages",
            format!(
                "'{}' is itself a known-popular {} package — the name is recognized, \
                 contributing 0 points.",
                signals.name, signals.ecosystem
            ),
        ),
        NameVsPopular::NearPopular {
            popular_name,
            distance,
        } => (
            NAME_NEAR_POPULAR_WEIGHT as i32,
            "Name vs. popular packages",
            format!(
                "'{}' is edit-distance {} from the known-popular {} package '{}' — \
                 the classic typosquat/slopsquat shape, contributing {} points.",
                signals.name, distance, signals.ecosystem, popular_name, NAME_NEAR_POPULAR_WEIGHT
            ),
        ),
        NameVsPopular::Unknown => {
            let db_note = if signals.threat_db_missing {
                " (the local threat DB is not installed, so the popular-package \
                 comparison could not run — install it for a sharper signal)"
            } else {
                ""
            };
            (
                NAME_UNKNOWN_WEIGHT as i32,
                "Name vs. popular packages",
                format!(
                    "'{}' neither is, nor closely resembles, any known-popular {} package{}. \
                     Unknown is not malicious — a small {}-point baseline only.",
                    signals.name, signals.ecosystem, db_note, NAME_UNKNOWN_WEIGHT
                ),
            )
        }
    };
    factors.push(RiskFactor {
        id: "name_vs_popular",
        label: name_label.to_string(),
        points: name_points,
        detail: name_detail,
    });

    // Factor 2 — known malicious typosquat (additive). The threat DB lists this
    // exact name as a malicious typosquat — a confirmed bad name.
    if let Some(target) = &signals.malicious_typosquat_of {
        factors.push(RiskFactor {
            id: "known_malicious_typosquat",
            label: "Known malicious typosquat".to_string(),
            points: KNOWN_MALICIOUS_TYPOSQUAT_WEIGHT as i32,
            detail: format!(
                "The local threat database lists '{}' as a known malicious typosquat of \
                 '{}' — an independent, confirmed bad-name match, contributing {} points.",
                signals.name, target, KNOWN_MALICIOUS_TYPOSQUAT_WEIGHT
            ),
        });
    }

    // Factors 3 & 4 — content signals, only when local content was inspected.
    match &signals.content_signals {
        ContentSignals::NotInspected => {
            // No content factors; recorded via `content_signals`, not a zero factor.
        }
        ContentSignals::Inspected {
            has_install_script,
            install_script_detail,
            has_binary_blob,
            binary_blob_detail,
            ..
        } => {
            if *has_install_script {
                let what = install_script_detail
                    .as_deref()
                    .unwrap_or("an install / lifecycle hook");
                factors.push(RiskFactor {
                    id: "install_script_present",
                    label: "Install / lifecycle script".to_string(),
                    points: INSTALL_SCRIPT_WEIGHT as i32,
                    detail: format!(
                        "The inspected package content contains {what} — a common \
                         malware-delivery vector, contributing {INSTALL_SCRIPT_WEIGHT} points."
                    ),
                });
            }
            if *has_binary_blob {
                let what = binary_blob_detail
                    .as_deref()
                    .unwrap_or("bundled binary artifacts");
                factors.push(RiskFactor {
                    id: "binary_blob_present",
                    label: "Bundled binary blob".to_string(),
                    points: BINARY_BLOB_WEIGHT as i32,
                    detail: format!(
                        "The inspected package content contains {what} — opaque compiled \
                         code that cannot be reviewed as source, contributing \
                         {BINARY_BLOB_WEIGHT} points."
                    ),
                });
            }
        }
    }

    // Factors 5+ — registry-API provenance, only when the run reached the
    // registry. Offline / degraded runs add no API factors (state still
    // recorded in `api_signals`).
    if let ApiSignals::Available { provenance } = &signals.api {
        factors.extend(api_factors(provenance));
    }

    // Sum and clamp. An over-100 sum is reported as an explicit negative
    // `clamp` factor so the breakdown still sums exactly to the score.
    let raw_sum: i32 = factors.iter().map(|f| f.points).sum();
    let score = raw_sum.clamp(0, MAX_SCORE as i32) as u32;
    if raw_sum > MAX_SCORE as i32 {
        let clamp = MAX_SCORE as i32 - raw_sum;
        factors.push(RiskFactor {
            id: "clamp",
            label: "Score cap".to_string(),
            points: clamp,
            detail: format!(
                "Factors summed to {raw_sum}; the score is capped at {MAX_SCORE}, \
                 so {clamp} points are removed."
            ),
        });
    }

    let breakdown = RiskBreakdown {
        ecosystem: signals.ecosystem.to_string(),
        name: signals.name.clone(),
        score,
        risk_level: risk_level(score),
        threat_db_missing: signals.threat_db_missing,
        name_vs_popular: signals.name_vs_popular.clone(),
        malicious_typosquat_of: signals.malicious_typosquat_of.clone(),
        content_signals: signals.content_signals.clone(),
        api_signals: signals.api.clone(),
        factors,
    };

    // Contract: factors sum exactly to the score ("reproducible by hand"). A
    // real `assert!` (not `debug_assert!`) so a violation is caught in release
    // too — `score_package` is off the hot path, so the compare is free.
    assert!(
        breakdown.verify(),
        "package-risk breakdown factors ({}) must sum to the final score ({})",
        breakdown.factor_sum(),
        breakdown.score,
    );

    breakdown
}

/// Derive the registry-API provenance factors from gathered [`ApiProvenance`].
/// Only signals the registry actually reported (a `Some` / `true`) produce a
/// factor; absence is not a signal. Pure function, exhaustively unit-tested.
#[allow(deprecated)] // legacy `ownership_transferred` read intentionally during M6 ch6 grace
pub fn api_factors(p: &ApiProvenance) -> Vec<RiskFactor> {
    let mut factors: Vec<RiskFactor> = Vec::new();

    // Package age. The package-level and latest-version-level signals are
    // mutually exclusive: the smaller version-level factor is added only when
    // the package itself is NOT very new.
    match p.package_age_days {
        Some(days) if days <= VERY_NEW_PACKAGE_DAYS => {
            factors.push(RiskFactor {
                id: "api_package_very_new",
                label: "Registry: package is very new".to_string(),
                points: PACKAGE_VERY_NEW_WEIGHT as i32,
                detail: format!(
                    "The {} registry reports this package was first published {days} day(s) \
                     ago (within the {VERY_NEW_PACKAGE_DAYS}-day 'very new' window) — the \
                     classic shape of a freshly-uploaded typosquat, contributing {} points.",
                    p.source, PACKAGE_VERY_NEW_WEIGHT
                ),
            });
        }
        _ => {
            if let Some(days) = p.latest_version_age_days {
                if days <= VERY_NEW_VERSION_DAYS {
                    factors.push(RiskFactor {
                        id: "api_latest_version_very_new",
                        label: "Registry: latest version is very new".to_string(),
                        points: LATEST_VERSION_VERY_NEW_WEIGHT as i32,
                        detail: format!(
                            "The {} registry reports the latest version was published {days} \
                             day(s) ago (within the {VERY_NEW_VERSION_DAYS}-day window). The \
                             package itself is established, so this is a small \
                             {LATEST_VERSION_VERY_NEW_WEIGHT}-point signal only.",
                            p.source
                        ),
                    });
                }
            }
        }
    }

    // Abandoned ownership — established package with no listed owners.
    if p.ownership_transferred == Some(true) {
        factors.push(RiskFactor {
            id: "api_ownership_transfer",
            label: "Registry: package has no listed owners".to_string(),
            points: OWNERSHIP_TRANSFER_WEIGHT as i32,
            detail: format!(
                "The {} registry lists this established package with zero maintainers / \
                 owners — an established package that has lost every listed owner is the \
                 detectable shape of an ownership transfer / account-takeover precursor, \
                 contributing {} points.",
                p.source, OWNERSHIP_TRANSFER_WEIGHT
            ),
        });
    }

    // Version spike — a hijacked release often ships an inflated version.
    if p.version_spike == Some(true) {
        let v = p.latest_version.as_deref().unwrap_or("the latest version");
        factors.push(RiskFactor {
            id: "api_version_spike",
            label: "Registry: abnormal version jump".to_string(),
            points: VERSION_SPIKE_WEIGHT as i32,
            detail: format!(
                "The {} registry's latest version ({v}) is an abnormal jump from the previous \
                 version — a hijacked release is often shipped with an inflated version number \
                 to win a semver range, contributing {} points.",
                p.source, VERSION_SPIKE_WEIGHT
            ),
        });
    }

    // Very low downloads — near-zero adoption is a (weak) signal.
    if let Some(dl) = p.recent_downloads {
        if dl <= LOW_DOWNLOAD_THRESHOLD {
            factors.push(RiskFactor {
                id: "api_low_downloads",
                label: "Registry: very low downloads".to_string(),
                points: LOW_DOWNLOADS_WEIGHT as i32,
                detail: format!(
                    "The {} registry reports only {dl} download(s) over its recent window \
                     (at or below the {LOW_DOWNLOAD_THRESHOLD} threshold) — near-zero adoption \
                     is a weak signal, contributing {} points.",
                    p.source, LOW_DOWNLOADS_WEIGHT
                ),
            });
        }
    }

    // Missing source-repository URL — provenance cannot be traced to source.
    if p.has_source_repo == Some(false) {
        factors.push(RiskFactor {
            id: "api_repo_url_missing",
            label: "Registry: no source-repository URL".to_string(),
            points: REPO_URL_MISSING_WEIGHT as i32,
            detail: format!(
                "The {} registry lists no usable source-repository URL for this package — its \
                 provenance cannot be traced back to reviewable source, contributing {} points.",
                p.source, REPO_URL_MISSING_WEIGHT
            ),
        });
    }

    // Yanked / deprecated latest version.
    if p.yanked_or_deprecated {
        factors.push(RiskFactor {
            id: "api_yanked_or_deprecated",
            label: "Registry: latest version yanked / deprecated".to_string(),
            points: YANKED_OR_DEPRECATED_WEIGHT as i32,
            detail: format!(
                "The {} registry marks the latest version as yanked or deprecated — the \
                 registry itself is signalling the release should not be used, contributing \
                 {} points.",
                p.source, YANKED_OR_DEPRECATED_WEIGHT
            ),
        });
    }

    // M6 ch6 — a registry-confirmed 404 (distinct from `Unknown`).
    if matches!(p.package_existence, PackageExistence::NotFound) {
        factors.push(RiskFactor {
            id: "api_package_not_found",
            label: "Registry: package not found".to_string(),
            points: PACKAGE_NOT_FOUND_WEIGHT as i32,
            detail: format!(
                "The {} registry positively reports no such package — HTTP 404, distinct from \
                 a transport failure or unsupported adapter. Contributing {} points.",
                p.source, PACKAGE_NOT_FOUND_WEIGHT
            ),
        });
    }

    // M6 ch6 — recent maintainer-set change between two snapshots.
    if let Some(hist) = &p.maintainer_change_history {
        if hist.is_recent() {
            factors.push(RiskFactor {
                id: "api_maintainer_change_recent",
                label: "Registry: maintainer set changed recently".to_string(),
                points: MAINTAINER_CHANGE_RECENT_WEIGHT as i32,
                detail: format!(
                    "Snapshot-vs-snapshot diff shows {} maintainer(s) added and {} removed within \
                     ~{} day(s). Contributing {} points.",
                    hist.added.len(),
                    hist.removed.len(),
                    hist.transfer_within_days.unwrap_or(0),
                    MAINTAINER_CHANGE_RECENT_WEIGHT
                ),
            });
        }
    }

    // M6 ch6 — real ownership transfer (every prior maintainer is gone).
    if let Some(t) = &p.ownership_transfer {
        if !t.previous.is_empty() && !t.current.is_empty() {
            let overlap = t
                .previous
                .iter()
                .any(|prev| t.current.iter().any(|cur| cur.id == prev.id));
            if !overlap {
                factors.push(RiskFactor {
                    id: "api_ownership_transfer_diff",
                    label: "Registry: ownership transferred (snapshot diff)".to_string(),
                    points: OWNERSHIP_TRANSFER_DIFF_WEIGHT as i32,
                    detail: format!(
                        "Snapshot diff: every previous maintainer is gone and a new set is in \
                         place. Contributing {} points.",
                        OWNERSHIP_TRANSFER_DIFF_WEIGHT
                    ),
                });
            }
        }
    }

    // M6 ch6 — OSV advisory active for the requested version.
    if let Some(advs) = &p.osv_advisories {
        if !advs.is_empty() {
            let ids: Vec<&str> = advs.iter().take(3).map(|a| a.id.as_str()).collect();
            factors.push(RiskFactor {
                id: "api_osv_advisory_active",
                label: "Registry: OSV advisory active for this version".to_string(),
                points: OSV_ADVISORY_ACTIVE_WEIGHT as i32,
                detail: format!(
                    "Found {} OSV advisory record(s) for this package@version: {}. Contributing \
                     {} points.",
                    advs.len(),
                    ids.join(", "),
                    OSV_ADVISORY_ACTIVE_WEIGHT
                ),
            });
        }
    }

    // M6 ch6 — dependency-confusion heuristic.
    if let Some(dc) = &p.dep_confusion {
        if dc.risk {
            factors.push(RiskFactor {
                id: "api_dep_confusion",
                label: "Registry: dependency-confusion shape".to_string(),
                points: DEP_CONFUSION_WEIGHT as i32,
                detail: format!(
                    "{} Contributing {} points.",
                    dc.reason, DEP_CONFUSION_WEIGHT
                ),
            });
        }
    }

    // M6 ch6 — install-script network/shell-spawn (offline heuristic).
    if let Some(iss) = &p.install_script_signals {
        if iss.fires() {
            factors.push(RiskFactor {
                id: "api_install_script_network",
                label: "Registry: install script makes a network call".to_string(),
                points: INSTALL_SCRIPT_NETWORK_WEIGHT as i32,
                detail: format!(
                    "Install-script analysis matched: net={} shell={} ({} pattern(s)). \
                     Contributing {} points.",
                    iss.has_network_call,
                    iss.has_shell_spawn,
                    iss.suspicious_patterns.len(),
                    INSTALL_SCRIPT_NETWORK_WEIGHT
                ),
            });
        }
    }

    // M6 ch6 — registry-claimed-repo URL mismatch (online-only verification).
    if let Some(rm) = &p.repo_mismatch {
        if matches!(rm.state, RepoMismatchState::Mismatch) {
            factors.push(RiskFactor {
                id: "api_repo_mismatch",
                label: "Registry: repo URL does not match the package".to_string(),
                points: REPO_MISMATCH_WEIGHT as i32,
                detail: format!(
                    "Repo-URL verification under --online returned Mismatch: {}. Contributing {} \
                     points.",
                    rm.reason, REPO_MISMATCH_WEIGHT
                ),
            });
        }
    }

    factors
}

/// Classify a package name against the threat-DB `popular` set.
///
/// Exact-match wins (`KnownPopular`); otherwise a one-edit near-miss
/// (`NearPopular`); otherwise `Unknown`. When `db` is `None` the threat DB is
/// not installed and every name is `Unknown`.
pub fn classify_name(db: Option<&ThreatDb>, eco: Ecosystem, name: &str) -> NameVsPopular {
    let Some(db) = db else {
        return NameVsPopular::Unknown;
    };
    if db.is_popular_package(eco, name) {
        return NameVsPopular::KnownPopular;
    }
    match db.check_popular_distance(eco, name) {
        Some((popular_name, distance)) => NameVsPopular::NearPopular {
            popular_name,
            distance,
        },
        None => NameVsPopular::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(name_vs_popular: NameVsPopular) -> PackageSignals {
        PackageSignals {
            ecosystem: Ecosystem::Npm,
            name: "test-pkg".to_string(),
            version: None,
            threat_db_missing: false,
            name_vs_popular,
            malicious_typosquat_of: None,
            content_signals: ContentSignals::NotInspected,
            api: ApiSignals::offline(),
        }
    }

    /// An `ApiProvenance` with every signal clean; tests flip one field each.
    fn clean_provenance() -> ApiProvenance {
        #[allow(deprecated)] // legacy `ownership_transferred` set here intentionally
        ApiProvenance {
            source: "npm".to_string(),
            package_age_days: Some(3650),
            latest_version_age_days: Some(365),
            ownership_transferred: Some(false),
            version_spike: Some(false),
            recent_downloads: Some(1_000_000),
            has_source_repo: Some(true),
            yanked_or_deprecated: false,
            latest_version: Some("4.18.2".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn known_popular_scores_zero() {
        let b = score_package(&signals(NameVsPopular::KnownPopular));
        assert_eq!(b.score, 0);
        assert_eq!(b.risk_level, "low");
        assert!(b.verify());
        // Exactly one factor: name_vs_popular at 0.
        assert_eq!(b.factors.len(), 1);
        assert_eq!(b.factors[0].id, "name_vs_popular");
        assert_eq!(b.factors[0].points, 0);
    }

    #[test]
    fn unknown_name_scores_small_baseline() {
        let b = score_package(&signals(NameVsPopular::Unknown));
        assert_eq!(b.score, NAME_UNKNOWN_WEIGHT);
        assert_eq!(b.risk_level, "low");
        assert!(b.verify());
    }

    #[test]
    fn near_popular_scores_high() {
        let b = score_package(&signals(NameVsPopular::NearPopular {
            popular_name: "react".to_string(),
            distance: 1,
        }));
        assert_eq!(b.score, NAME_NEAR_POPULAR_WEIGHT);
        assert_eq!(b.risk_level, "high");
        assert!(b.verify());
    }

    #[test]
    fn malicious_typosquat_adds_on_top_of_near_popular() {
        let mut s = signals(NameVsPopular::NearPopular {
            popular_name: "react".to_string(),
            distance: 1,
        });
        s.malicious_typosquat_of = Some("react".to_string());
        let b = score_package(&s);
        // 60 near-popular + 30 known-malicious-typosquat = 90.
        assert_eq!(
            b.score,
            NAME_NEAR_POPULAR_WEIGHT + KNOWN_MALICIOUS_TYPOSQUAT_WEIGHT
        );
        assert_eq!(b.risk_level, "critical");
        assert!(b.verify());
        assert!(b
            .factors
            .iter()
            .any(|f| f.id == "known_malicious_typosquat"));
    }

    #[test]
    fn install_script_and_binary_blob_are_additive() {
        let mut s = signals(NameVsPopular::Unknown);
        s.content_signals = ContentSignals::Inspected {
            path: "/tmp/node_modules/test-pkg".to_string(),
            has_install_script: true,
            install_script_detail: Some("a postinstall lifecycle script".to_string()),
            has_binary_blob: true,
            binary_blob_detail: Some("a bundled .node native addon".to_string()),
        };
        let b = score_package(&s);
        // 10 unknown + 15 install-script + 10 binary-blob = 35.
        assert_eq!(
            b.score,
            NAME_UNKNOWN_WEIGHT + INSTALL_SCRIPT_WEIGHT + BINARY_BLOB_WEIGHT
        );
        assert_eq!(b.risk_level, "medium");
        assert!(b.verify());
        assert!(b.factors.iter().any(|f| f.id == "install_script_present"));
        assert!(b.factors.iter().any(|f| f.id == "binary_blob_present"));
    }

    #[test]
    fn not_inspected_content_adds_no_factor() {
        let b = score_package(&signals(NameVsPopular::Unknown));
        assert!(!b
            .factors
            .iter()
            .any(|f| f.id == "install_script_present" || f.id == "binary_blob_present"));
        assert!(matches!(b.content_signals, ContentSignals::NotInspected));
    }

    #[test]
    fn score_is_clamped_with_explicit_clamp_factor() {
        // Worst case: near-popular (60) + malicious typosquat (30) +
        // install-script (15) + binary-blob (10) = 115 raw → clamps to 100.
        let mut s = signals(NameVsPopular::NearPopular {
            popular_name: "react".to_string(),
            distance: 1,
        });
        s.malicious_typosquat_of = Some("react".to_string());
        s.content_signals = ContentSignals::Inspected {
            path: "/tmp/p".to_string(),
            has_install_script: true,
            install_script_detail: None,
            has_binary_blob: true,
            binary_blob_detail: None,
        };
        let b = score_package(&s);
        assert_eq!(b.score, 100);
        assert_eq!(b.risk_level, "critical");
        let clamp = b
            .factors
            .iter()
            .find(|f| f.id == "clamp")
            .expect("clamp factor must be present when the raw sum exceeds 100");
        assert_eq!(clamp.points, -15);
        assert!(b.verify(), "even clamped, factors must sum to score");
    }

    #[test]
    fn api_signals_default_to_not_computed_offline() {
        let b = score_package(&signals(NameVsPopular::Unknown));
        assert!(matches!(b.api_signals, ApiSignals::NotComputed { .. }));
        // No API factor may appear on an offline run.
        assert!(!b.factors.iter().any(|f| f.id.starts_with("api_")));
    }

    #[test]
    fn unavailable_api_adds_no_factors_but_is_recorded() {
        let mut s = signals(NameVsPopular::Unknown);
        s.api = ApiSignals::unavailable("registry timed out");
        let b = score_package(&s);
        // Degrades to the offline score (unknown baseline only).
        assert_eq!(b.score, NAME_UNKNOWN_WEIGHT);
        assert!(b.verify());
        assert!(!b.factors.iter().any(|f| f.id.starts_with("api_")));
        match &b.api_signals {
            ApiSignals::Unavailable { reason } => assert!(reason.contains("timed out")),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn clean_provenance_adds_no_factors() {
        let mut s = signals(NameVsPopular::KnownPopular);
        s.api = ApiSignals::Available {
            provenance: clean_provenance(),
        };
        let b = score_package(&s);
        assert_eq!(b.score, 0, "a clean provenance must not raise the score");
        assert!(b.verify());
        assert!(!b.factors.iter().any(|f| f.id.starts_with("api_")));
    }

    #[test]
    fn very_new_package_adds_factor() {
        let mut p = clean_provenance();
        p.package_age_days = Some(3);
        let factors = api_factors(&p);
        let f = factors
            .iter()
            .find(|f| f.id == "api_package_very_new")
            .expect("very-new package must add a factor");
        assert_eq!(f.points, PACKAGE_VERY_NEW_WEIGHT as i32);
        // The latest-version factor is suppressed when the package is new.
        assert!(!factors
            .iter()
            .any(|f| f.id == "api_latest_version_very_new"));
    }

    #[test]
    fn very_new_latest_version_adds_smaller_factor_for_old_package() {
        let mut p = clean_provenance();
        p.package_age_days = Some(3650); // package is old
        p.latest_version_age_days = Some(2); // but a fresh release
        let factors = api_factors(&p);
        let f = factors
            .iter()
            .find(|f| f.id == "api_latest_version_very_new")
            .expect("very-new latest version must add a factor");
        assert_eq!(f.points, LATEST_VERSION_VERY_NEW_WEIGHT as i32);
        assert!(!factors.iter().any(|f| f.id == "api_package_very_new"));
    }

    #[test]
    #[allow(deprecated)]
    fn ownership_transfer_adds_factor() {
        let mut p = clean_provenance();
        p.ownership_transferred = Some(true);
        let factors = api_factors(&p);
        let f = factors
            .iter()
            .find(|f| f.id == "api_ownership_transfer")
            .expect("ownership transfer must add a factor");
        assert_eq!(f.points, OWNERSHIP_TRANSFER_WEIGHT as i32);
    }

    #[test]
    fn version_spike_adds_factor() {
        let mut p = clean_provenance();
        p.version_spike = Some(true);
        let f = api_factors(&p)
            .into_iter()
            .find(|f| f.id == "api_version_spike")
            .expect("version spike must add a factor");
        assert_eq!(f.points, VERSION_SPIKE_WEIGHT as i32);
    }

    #[test]
    fn low_downloads_adds_factor_at_threshold() {
        let mut p = clean_provenance();
        p.recent_downloads = Some(LOW_DOWNLOAD_THRESHOLD); // boundary: <=
        assert!(api_factors(&p).iter().any(|f| f.id == "api_low_downloads"));
        p.recent_downloads = Some(LOW_DOWNLOAD_THRESHOLD + 1);
        assert!(
            !api_factors(&p).iter().any(|f| f.id == "api_low_downloads"),
            "one above the threshold must not fire"
        );
    }

    #[test]
    fn missing_repo_url_adds_factor() {
        let mut p = clean_provenance();
        p.has_source_repo = Some(false);
        let f = api_factors(&p)
            .into_iter()
            .find(|f| f.id == "api_repo_url_missing")
            .expect("missing repo URL must add a factor");
        assert_eq!(f.points, REPO_URL_MISSING_WEIGHT as i32);
        // A registry that simply does not carry the field (None) must NOT fire.
        p.has_source_repo = None;
        assert!(!api_factors(&p)
            .iter()
            .any(|f| f.id == "api_repo_url_missing"));
    }

    #[test]
    fn yanked_or_deprecated_adds_factor() {
        let mut p = clean_provenance();
        p.yanked_or_deprecated = true;
        let f = api_factors(&p)
            .into_iter()
            .find(|f| f.id == "api_yanked_or_deprecated")
            .expect("yanked/deprecated must add a factor");
        assert_eq!(f.points, YANKED_OR_DEPRECATED_WEIGHT as i32);
    }

    #[test]
    fn api_factors_are_additive_and_breakdown_verifies() {
        // An unknown name (10) plus a fully-bad provenance.
        let mut s = signals(NameVsPopular::Unknown);
        #[allow(deprecated)]
        let p = ApiProvenance {
            source: "npm".to_string(),
            package_age_days: Some(1),
            latest_version_age_days: Some(1),
            ownership_transferred: Some(true),
            version_spike: Some(true),
            recent_downloads: Some(0),
            has_source_repo: Some(false),
            yanked_or_deprecated: true,
            latest_version: Some("9.9.9".to_string()),
            ..Default::default()
        };
        s.api = ApiSignals::Available { provenance: p };
        let b = score_package(&s);
        // 10 unknown + 25 + 20 + 15 + 10 + 12 + 18 = 110 raw → clamps to 100.
        assert_eq!(b.score, 100);
        assert_eq!(b.risk_level, "critical");
        assert!(b.verify(), "even with API factors, the breakdown must sum");
        let clamp = b
            .factors
            .iter()
            .find(|f| f.id == "clamp")
            .expect("worst-case API + name should clamp");
        assert_eq!(clamp.points, -10);
        // The package-level new factor fires; the version-level one is hidden.
        assert!(b.factors.iter().any(|f| f.id == "api_package_very_new"));
        assert!(!b
            .factors
            .iter()
            .any(|f| f.id == "api_latest_version_very_new"));
    }

    #[test]
    fn api_breakdown_verifies_across_provenance_combinations() {
        // Exhaustively flip every API signal — the breakdown invariant
        // (factors sum to score) must hold for every combination.
        for pkg_new in [false, true] {
            for ver_new in [false, true] {
                for owner in [false, true] {
                    for spike in [false, true] {
                        for low_dl in [false, true] {
                            for no_repo in [false, true] {
                                for yanked in [false, true] {
                                    #[allow(deprecated)]
                                    let p = ApiProvenance {
                                        source: "pypi".to_string(),
                                        package_age_days: Some(if pkg_new { 1 } else { 3650 }),
                                        latest_version_age_days: Some(if ver_new {
                                            1
                                        } else {
                                            3650
                                        }),
                                        ownership_transferred: Some(owner),
                                        version_spike: Some(spike),
                                        recent_downloads: Some(if low_dl { 0 } else { 999_999 }),
                                        has_source_repo: Some(!no_repo),
                                        yanked_or_deprecated: yanked,
                                        latest_version: Some("1.0.0".to_string()),
                                        ..Default::default()
                                    };
                                    let mut s = signals(NameVsPopular::NearPopular {
                                        popular_name: "react".to_string(),
                                        distance: 1,
                                    });
                                    s.api = ApiSignals::Available { provenance: p };
                                    let b = score_package(&s);
                                    assert!(
                                        b.verify(),
                                        "API breakdown must sum: score={} factor_sum={}",
                                        b.score,
                                        b.factor_sum()
                                    );
                                    assert!(b.score <= MAX_SCORE);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn every_breakdown_verifies_across_signal_combinations() {
        let name_options = [
            NameVsPopular::KnownPopular,
            NameVsPopular::Unknown,
            NameVsPopular::NearPopular {
                popular_name: "react".to_string(),
                distance: 1,
            },
        ];
        for nvp in &name_options {
            for typo in [None, Some("react".to_string())] {
                for install in [false, true] {
                    for blob in [false, true] {
                        for inspected in [false, true] {
                            let content = if inspected {
                                ContentSignals::Inspected {
                                    path: "/tmp/p".to_string(),
                                    has_install_script: install,
                                    install_script_detail: None,
                                    has_binary_blob: blob,
                                    binary_blob_detail: None,
                                }
                            } else {
                                ContentSignals::NotInspected
                            };
                            let s = PackageSignals {
                                ecosystem: Ecosystem::Npm,
                                name: "p".to_string(),
                                version: None,
                                threat_db_missing: false,
                                name_vs_popular: nvp.clone(),
                                malicious_typosquat_of: typo.clone(),
                                content_signals: content,
                                api: ApiSignals::offline(),
                            };
                            let b = score_package(&s);
                            assert!(
                                b.verify(),
                                "breakdown must sum to score: nvp={nvp:?} typo={typo:?} \
                                 install={install} blob={blob} inspected={inspected} \
                                 (score={}, factor_sum={})",
                                b.score,
                                b.factor_sum()
                            );
                            assert!(b.score <= MAX_SCORE);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn classify_name_returns_unknown_when_db_missing() {
        assert_eq!(
            classify_name(None, Ecosystem::Npm, "anything"),
            NameVsPopular::Unknown
        );
    }

    // --- M6 ch6 — version-aware parsing -----------------------------------

    #[test]
    fn parse_name_and_version_bare_name() {
        assert_eq!(parse_name_and_version("react"), ("react".to_string(), None),);
    }

    #[test]
    fn parse_name_and_version_with_version() {
        assert_eq!(
            parse_name_and_version("react@18.2.0"),
            ("react".to_string(), Some("18.2.0".to_string())),
        );
    }

    #[test]
    fn parse_name_and_version_scoped_no_version() {
        // The leading `@` is the scope sigil, not a version separator.
        assert_eq!(
            parse_name_and_version("@org/util"),
            ("@org/util".to_string(), None),
        );
    }

    #[test]
    fn parse_name_and_version_scoped_with_version_splits_on_last_at() {
        assert_eq!(
            parse_name_and_version("@org/util@1.2.3"),
            ("@org/util".to_string(), Some("1.2.3".to_string())),
        );
    }

    #[test]
    fn parse_name_and_version_bare_scope_only() {
        // `@org` — `@` is at position 0; no version separator.
        assert_eq!(parse_name_and_version("@org"), ("@org".to_string(), None),);
    }

    #[test]
    fn parse_name_and_version_trailing_at_is_not_a_version() {
        // `pkg@` — the version-shaped check rejects an empty tail.
        assert_eq!(parse_name_and_version("pkg@"), ("pkg@".to_string(), None),);
    }

    #[test]
    fn parse_name_and_version_doubled_at_splits_on_last() {
        // `pkg@@1.0` — only the LAST `@` is treated as the separator.
        assert_eq!(
            parse_name_and_version("pkg@@1.0"),
            ("pkg@".to_string(), Some("1.0".to_string())),
        );
    }

    #[test]
    fn parse_name_and_version_caret_range_accepted() {
        assert_eq!(
            parse_name_and_version("react@^18.0.0"),
            ("react".to_string(), Some("^18.0.0".to_string())),
        );
    }

    #[test]
    fn parse_name_and_version_v_prefix_accepted() {
        assert_eq!(
            parse_name_and_version("foo@v1.0"),
            ("foo".to_string(), Some("v1.0".to_string())),
        );
    }

    #[test]
    fn parse_name_and_version_non_version_tail_rejected() {
        // A tail that does not start with a version-shaped char is kept in the name.
        assert_eq!(
            parse_name_and_version("alice@example.com"),
            ("alice@example.com".to_string(), None),
        );
    }

    #[test]
    fn parse_name_and_version_empty_input() {
        assert_eq!(parse_name_and_version(""), (String::new(), None),);
        assert_eq!(parse_name_and_version("   "), (String::new(), None),);
    }

    // --- M6 ch6 — MaintainerChangeHistory ---------------------------------

    #[test]
    fn maintainer_change_history_recent_requires_diff_and_window() {
        let none_recent = MaintainerChangeHistory {
            added: vec![MaintainerRef {
                id: "eve".to_string(),
            }],
            removed: vec![],
            transfer_within_days: Some(MAINTAINER_CHANGE_RECENT_DAYS),
        };
        assert!(none_recent.is_recent());

        let outside_window = MaintainerChangeHistory {
            added: vec![MaintainerRef {
                id: "eve".to_string(),
            }],
            removed: vec![],
            transfer_within_days: Some(MAINTAINER_CHANGE_RECENT_DAYS + 1),
        };
        assert!(!outside_window.is_recent());

        let no_diff = MaintainerChangeHistory {
            added: vec![],
            removed: vec![],
            transfer_within_days: Some(1),
        };
        assert!(!no_diff.is_recent());
    }

    #[test]
    fn osv_advisory_high_cvss_threshold() {
        let high = OsvAdvisorySummary {
            id: "GHSA-1".to_string(),
            aliases: vec![],
            summary: None,
            cvss: Some(7.0),
            reference: None,
        };
        assert!(high.is_high_cvss());
        let medium = OsvAdvisorySummary {
            id: "GHSA-2".to_string(),
            aliases: vec![],
            summary: None,
            cvss: Some(6.9),
            reference: None,
        };
        assert!(!medium.is_high_cvss());
        let unknown = OsvAdvisorySummary {
            id: "GHSA-3".to_string(),
            aliases: vec![],
            summary: None,
            cvss: None,
            reference: None,
        };
        assert!(!unknown.is_high_cvss());
    }

    #[test]
    fn install_script_signals_fires_on_either_kind() {
        let mut s = InstallScriptSignals::default();
        assert!(!s.fires());
        s.has_network_call = true;
        assert!(s.fires());
        s.has_network_call = false;
        s.has_shell_spawn = true;
        assert!(s.fires());
    }

    #[test]
    fn package_not_found_adds_factor() {
        let p = ApiProvenance {
            source: "npm".to_string(),
            package_existence: PackageExistence::NotFound,
            ..Default::default()
        };
        let factors = api_factors(&p);
        assert!(factors.iter().any(|f| f.id == "api_package_not_found"));
    }

    #[test]
    fn osv_advisory_active_adds_factor() {
        let p = ApiProvenance {
            source: "npm".to_string(),
            osv_advisories: Some(vec![OsvAdvisorySummary {
                id: "GHSA-x".to_string(),
                aliases: vec!["CVE-2024-x".to_string()],
                summary: None,
                cvss: Some(8.0),
                reference: None,
            }]),
            ..Default::default()
        };
        let factors = api_factors(&p);
        assert!(factors.iter().any(|f| f.id == "api_osv_advisory_active"));
    }

    #[test]
    fn dep_confusion_adds_factor_when_risk_true() {
        let p = ApiProvenance {
            source: "npm".to_string(),
            dep_confusion: Some(DepConfusionVerdict {
                risk: true,
                reason: "internal name resolved on public registry".to_string(),
            }),
            ..Default::default()
        };
        assert!(api_factors(&p).iter().any(|f| f.id == "api_dep_confusion"));
    }

    #[test]
    fn dep_confusion_does_not_add_factor_when_risk_false() {
        let p = ApiProvenance {
            source: "npm".to_string(),
            dep_confusion: Some(DepConfusionVerdict {
                risk: false,
                reason: String::new(),
            }),
            ..Default::default()
        };
        assert!(!api_factors(&p).iter().any(|f| f.id == "api_dep_confusion"));
    }

    #[test]
    fn install_script_network_adds_factor_when_fires() {
        let p = ApiProvenance {
            source: "npm".to_string(),
            install_script_signals: Some(InstallScriptSignals {
                has_network_call: true,
                has_shell_spawn: false,
                suspicious_patterns: vec!["curl ...".to_string()],
            }),
            ..Default::default()
        };
        assert!(api_factors(&p)
            .iter()
            .any(|f| f.id == "api_install_script_network"));
    }

    #[test]
    fn repo_mismatch_adds_factor_on_mismatch() {
        let p = ApiProvenance {
            source: "npm".to_string(),
            repo_mismatch: Some(RepoMismatchVerdict {
                state: RepoMismatchState::Mismatch,
                reason: "hosted manifest names a different package".to_string(),
            }),
            ..Default::default()
        };
        assert!(api_factors(&p).iter().any(|f| f.id == "api_repo_mismatch"));
    }

    #[test]
    fn repo_mismatch_unverifiable_does_not_fire() {
        let p = ApiProvenance {
            source: "npm".to_string(),
            repo_mismatch: Some(RepoMismatchVerdict::default()),
            ..Default::default()
        };
        assert!(!api_factors(&p).iter().any(|f| f.id == "api_repo_mismatch"));
    }

    #[test]
    fn maintainer_change_recent_adds_factor() {
        let p = ApiProvenance {
            source: "npm".to_string(),
            maintainer_change_history: Some(MaintainerChangeHistory {
                added: vec![MaintainerRef {
                    id: "eve".to_string(),
                }],
                removed: vec![],
                transfer_within_days: Some(5),
            }),
            ..Default::default()
        };
        assert!(api_factors(&p)
            .iter()
            .any(|f| f.id == "api_maintainer_change_recent"));
    }

    #[test]
    fn ownership_transfer_diff_adds_factor_only_with_no_overlap() {
        let no_overlap = ApiProvenance {
            source: "npm".to_string(),
            ownership_transfer: Some(OwnershipTransfer {
                previous: vec![MaintainerRef {
                    id: "alice".to_string(),
                }],
                current: vec![MaintainerRef {
                    id: "eve".to_string(),
                }],
                within_days: Some(2),
            }),
            ..Default::default()
        };
        assert!(api_factors(&no_overlap)
            .iter()
            .any(|f| f.id == "api_ownership_transfer_diff"));

        let with_overlap = ApiProvenance {
            source: "npm".to_string(),
            ownership_transfer: Some(OwnershipTransfer {
                previous: vec![MaintainerRef {
                    id: "alice".to_string(),
                }],
                current: vec![
                    MaintainerRef {
                        id: "alice".to_string(),
                    },
                    MaintainerRef {
                        id: "eve".to_string(),
                    },
                ],
                within_days: Some(2),
            }),
            ..Default::default()
        };
        assert!(!api_factors(&with_overlap)
            .iter()
            .any(|f| f.id == "api_ownership_transfer_diff"));
    }
}
