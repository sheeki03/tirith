//! Deterministic, fully explainable package provenance / maintainer-risk
//! scoring.
//!
//! `tirith package risk <ecosystem> <name>` produces a risk score for a
//! package the same way [`crate::scoring`] scores a URL: as a fixed sum of
//! named, inspectable factors. There is **no model, no learned weight, no
//! statistical classifier** — every score is reproducible by hand from the
//! signals below.
//!
//! ## Offline signals (always computed)
//!
//! These are computed **without any network or registry-API call**:
//!
//! 1. **Name-vs-popular** — is the name a known-popular package, an unknown
//!    name, or a one-edit near-miss of a popular one? Sourced from the local
//!    threat-DB `popular` section ([`ThreatDb::is_popular_package`] and
//!    [`ThreatDb::check_popular_distance`]).
//! 2. **Known-malicious typosquat** — is the name in the threat-DB's
//!    `typosquat` index, i.e. a *confirmed* malicious typosquat
//!    ([`ThreatDb::check_typosquat`])? This is a stronger signal than a mere
//!    name resemblance.
//! 3. **Install-script / lifecycle-hook presence** — only when the package
//!    content is locally available (a `node_modules` / `site-packages`
//!    directory, or a path the caller supplies). tirith never downloads the
//!    package to obtain this.
//! 4. **Binary-blob presence** — compiled / native artifacts bundled inside
//!    the locally-available package content.
//!
//! ## Registry-API-backed signals (opt-in, off the hot path)
//!
//! `tirith package risk --online` additionally consults the package's
//! registry API (the npm registry, the PyPI JSON API, or the crates.io API,
//! selected by ecosystem) for *provenance* signals — see [`ApiProvenance`].
//! These are an explicit, deterministic **addition** to the same factor-sum
//! model: each one is a named factor with a fixed weight. They are reached
//! ONLY behind `--online`; the default is offline, and a network or API
//! failure degrades gracefully to the offline score with an honest
//! [`ApiSignals::Unavailable`]. tirith never reaches the network from
//! `tirith check` or any hot path — `--online` on `package risk` is the only
//! entry point.
//!
//! The seam is the [`ApiSignals`] enum: the offline path always reports
//! [`ApiSignals::NotComputed`]; an online run reports [`ApiSignals::Available`]
//! (or [`ApiSignals::Unavailable`] on degradation).
//!
//! ## The factor model
//!
//! The score is the sum of:
//!
//! - **Name vs. popular packages** — the dominant term. A name one edit from a
//!   known-popular package is the classic typosquat/slopsquat shape and scores
//!   high; a name that *is* a known-popular package scores 0; an unknown name
//!   gets a small baseline (unknown is not the same as malicious).
//! - **Known-malicious typosquat** — additive: the threat-DB independently
//!   lists this exact name as a malicious typosquat.
//! - **Install / lifecycle scripts** — additive, only when local content was
//!   inspected: an `install` / `postinstall` / `preinstall` hook (npm) or a
//!   `setup.py` with executable install logic (PyPI) is a common malware
//!   delivery vector.
//! - **Bundled binary blobs** — additive, only when local content was
//!   inspected.
//! - **Registry-API provenance** — additive, only on an `--online` run: a
//!   very new package or latest version, an ownership transfer, an abnormal
//!   version jump, very low downloads, a missing/inconsistent source-repo URL,
//!   and a yanked / deprecated latest version. Each is a separate named
//!   factor; see [`api_factors`].
//!
//! The final score is `min(100, sum)`. The clamp is reported as an explicit
//! factor when it bites, so the breakdown always sums exactly to the score.
//!
//! ## Relationship to the verdict
//!
//! This score is **advisory and standalone**. It is not a detection rule, it
//! does not produce a [`Verdict`](crate::verdict::Verdict), and it changes no
//! `Action`, exit code, or audit log. `tirith package risk` is an inspection
//! command.

use serde::Serialize;

use crate::threatdb::{Ecosystem, ThreatDb};

/// The maximum possible score. Scores are clamped here.
pub const MAX_SCORE: u32 = 100;

// --- factor weights (all fixed, all inspectable) ---------------------------

/// A name one Levenshtein edit from a known-popular package — the classic
/// typosquat / slopsquat shape.
const NAME_NEAR_POPULAR_WEIGHT: u32 = 60;
/// A name that does not resemble any known-popular package and is not itself
/// known-popular. Unknown is not malicious — this baseline is deliberately
/// small.
const NAME_UNKNOWN_WEIGHT: u32 = 10;
/// The name is in the threat-DB's malicious-typosquat index — a confirmed bad
/// name, not a mere resemblance. Additive on top of the near-popular term.
const KNOWN_MALICIOUS_TYPOSQUAT_WEIGHT: u32 = 30;
/// An install / lifecycle hook is present in locally-inspected package content.
const INSTALL_SCRIPT_WEIGHT: u32 = 15;
/// Compiled / native binary blobs are bundled in locally-inspected content.
const BINARY_BLOB_WEIGHT: u32 = 10;

// --- registry-API provenance factor weights (only on an `--online` run) ----
//
// These are deliberately moderate: the offline name signal stays the dominant
// term. A provenance signal corroborates — it rarely stands alone as proof.

/// The package itself is very new (first published within
/// [`VERY_NEW_PACKAGE_DAYS`]). A brand-new package is the textbook shape of a
/// freshly-uploaded typosquat / slopsquat.
const PACKAGE_VERY_NEW_WEIGHT: u32 = 25;
/// The package's *latest version* is very new (published within
/// [`VERY_NEW_VERSION_DAYS`]) even though the package itself is older — a
/// fresh release of an established package is a weaker, smaller signal.
const LATEST_VERSION_VERY_NEW_WEIGHT: u32 = 8;
/// The registry maintainer / owner set changed recently — an ownership
/// transfer, a classic account-takeover / hijack precursor.
const OWNERSHIP_TRANSFER_WEIGHT: u32 = 20;
/// The latest version number is an abnormal jump from the previous version
/// (e.g. `1.2.3` → `9.0.0`) — a hijacked release is often shipped with an
/// inflated version to win a semver range.
const VERSION_SPIKE_WEIGHT: u32 = 15;
/// The package has very few downloads ([`LOW_DOWNLOAD_THRESHOLD`] or fewer over
/// the reported window) — near-zero adoption is itself a (weak) signal.
const LOW_DOWNLOADS_WEIGHT: u32 = 10;
/// The registry lists no source-repository URL, or one inconsistent with the
/// package — provenance cannot be traced back to reviewable source.
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
    /// The name is one Levenshtein edit from a known-popular package.
    NearPopular {
        /// The popular package the name resembles.
        popular_name: String,
        /// Levenshtein edit distance (1 — `check_popular_distance` caps at 1).
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

/// One registry-API provenance signal, as gathered from a registry response.
///
/// Each field is an *already-decided* boolean / value — the registry-specific
/// fetching and normalization (npm registry, PyPI JSON, crates.io) happens in
/// [`crate::registry_api`], so [`score_package`] stays a pure, total function
/// of its inputs. A `None` on an optional field means the registry did not
/// report that datum (it is then not scored — absence of a datum is not a
/// signal in itself).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiProvenance {
    /// Which registry API the data came from (`"npm"`, `"pypi"`,
    /// `"crates.io"`), for transparency in the explanation.
    pub source: String,
    /// Age of the package's *first* publication, in whole days, when the
    /// registry reported a creation timestamp.
    pub package_age_days: Option<u64>,
    /// Age of the *latest version*'s publication, in whole days, when known.
    pub latest_version_age_days: Option<u64>,
    /// `true` when the registry maintainer / owner set changed within the
    /// observation window (an ownership transfer). `None` when the registry
    /// does not expose enough history to tell.
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
}

/// State of the registry-API-backed signals.
///
/// This enum is the seam between the always-on offline signals and the opt-in
/// `--online` registry signals:
///
/// * [`ApiSignals::NotComputed`] — the default. No `--online` was requested
///   (or `--offline` / `TIRITH_OFFLINE` forced offline), so no API call was
///   made. This is what every offline run reports.
/// * [`ApiSignals::Available`] — an `--online` run reached the registry and
///   gathered provenance. The carried [`ApiProvenance`] drives the API
///   factors.
/// * [`ApiSignals::Unavailable`] — an `--online` run was requested but the
///   registry call failed (offline, timeout, HTTP error, unparseable
///   response, unsupported ecosystem). The score degrades gracefully to the
///   offline signals; `reason` is an honest, human-readable explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
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
    /// Registry-API signals — always [`ApiSignals::NotComputed`] in this phase.
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

/// Inputs to [`score_package`] — the raw signals, already gathered.
///
/// Keeping signal gathering (which touches the threat DB, the filesystem, and
/// — for `api` — the network) out of the scoring function lets
/// `score_package` be a pure, total function of its inputs, so tests can
/// drive every factor combination directly without any I/O.
#[derive(Debug, Clone)]
pub struct PackageSignals {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub threat_db_missing: bool,
    pub name_vs_popular: NameVsPopular,
    /// `Some(popular_target)` when the threat DB lists this exact name as a
    /// known malicious typosquat.
    pub malicious_typosquat_of: Option<String>,
    pub content_signals: ContentSignals,
    /// The registry-API state to fold into the score:
    ///
    /// * [`ApiSignals::NotComputed`] — offline run; no API factors.
    /// * [`ApiSignals::Available`] — `--online` run; the carried
    ///   [`ApiProvenance`] adds API factors.
    /// * [`ApiSignals::Unavailable`] — `--online` requested but the call
    ///   failed; no API factors, the breakdown records the honest reason.
    ///
    /// Defaults to [`ApiSignals::offline`] so an offline caller is unchanged.
    pub api: ApiSignals,
}

impl PackageSignals {
    /// Construct offline-only signals — the registry-API state defaults to
    /// [`ApiSignals::NotComputed`]. The networked caller overwrites `api`.
    pub fn offline(
        ecosystem: Ecosystem,
        name: String,
        threat_db_missing: bool,
        name_vs_popular: NameVsPopular,
        malicious_typosquat_of: Option<String>,
        content_signals: ContentSignals,
    ) -> Self {
        PackageSignals {
            ecosystem,
            name,
            threat_db_missing,
            name_vs_popular,
            malicious_typosquat_of,
            content_signals,
            api: ApiSignals::offline(),
        }
    }
}

/// Compute the deterministic risk score and full factor breakdown from
/// already-gathered offline signals.
///
/// This is a pure, total function — the single source of truth for the
/// `package risk` number. The breakdown it returns always satisfies
/// `breakdown.verify()`.
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
            // No local content — no content factors. Recorded in the breakdown
            // via `content_signals`, not as a zero factor, to keep the factor
            // list to the signals that actually applied.
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

    // Factors 5+ — registry-API provenance, only on an `--online` run that
    // actually reached the registry. An offline run, or an `--online` run that
    // degraded, contributes no API factors (its state is still recorded in
    // `api_signals`, so the breakdown is honest about why).
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

    RiskBreakdown {
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
    }
}

/// Derive the registry-API provenance factors from gathered [`ApiProvenance`].
///
/// Each factor is named, fixed-weight, and explained so the reader can verify
/// it by hand — exactly like the offline factors. Only signals the registry
/// *actually reported* (a `Some`, or a `true`) produce a factor; a datum the
/// registry did not expose contributes nothing (absence is not a signal).
///
/// This is a pure function of its input — no I/O — so it is exhaustively
/// unit-tested below.
pub fn api_factors(p: &ApiProvenance) -> Vec<RiskFactor> {
    let mut factors: Vec<RiskFactor> = Vec::new();

    // Package age — a brand-new package is the textbook fresh-typosquat shape.
    // The package-level signal and the latest-version-level signal are
    // mutually exclusive: a very new *package* already covers a very new
    // latest version, so the smaller version-level factor is only added when
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

    // Ownership transfer — an account-takeover / hijack precursor.
    if p.ownership_transferred == Some(true) {
        factors.push(RiskFactor {
            id: "api_ownership_transfer",
            label: "Registry: ownership transferred".to_string(),
            points: OWNERSHIP_TRANSFER_WEIGHT as i32,
            detail: format!(
                "The {} registry shows the maintainer / owner set changed recently — an \
                 ownership transfer is a classic account-takeover precursor, contributing \
                 {} points.",
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
            threat_db_missing: false,
            name_vs_popular,
            malicious_typosquat_of: None,
            content_signals: ContentSignals::NotInspected,
            api: ApiSignals::offline(),
        }
    }

    /// An `ApiProvenance` with every signal "clean" (no factor fires). Tests
    /// flip exactly the field under test so each factor is isolated.
    fn clean_provenance() -> ApiProvenance {
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
}
