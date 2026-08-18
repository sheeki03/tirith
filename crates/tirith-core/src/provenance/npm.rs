//! npm signature / provenance attestation over an INSTALLED project (C17): the
//! pure, spawn-free half of `tirith pkg attest-npm`.
//!
//! What this module is: the closed contract table that says which npm versions
//! Tirith knows how to ask, the exact argv for each, the strict parser for the
//! answer, the `package-lock.json` and `node_modules` readers the answer is
//! bound to, and the receipt that records all of it. The spawn, the trusted
//! executable resolution, and the rendering live in `tirith`'s
//! `cli::npm_integrity`.
//!
//! # Why the contract table is CLOSED
//!
//! The one thing a security tool must never do is hand a speculative flag to a
//! program it has not characterized. `npm audit signatures` changed shape
//! between majors: on npm 11.17.0 `--json` alone emits `{"invalid":[],
//! "missing":[]}` while `--json --include-attestations` additionally emits a
//! `verified` array, and an unrecognized flag is currently only a warning
//! ("This will stop working in the next major version of npm"). Guessing which
//! form an unknown npm speaks turns this command into an arbitrary-argv
//! executor over a binary on the operator's PATH.
//!
//! So [`NPM_AUDIT_SIGNATURES_CONTRACTS`] is a fixed table: a version RANGE, the
//! exact argv, the expected JSON schema, whether attestation bundles are
//! available, and the committed stdout fixture that proves it. A version
//! outside every range returns [`NpmPartialReason::UnsupportedNpmVersion`]
//! AFTER version discovery and runs NO audit command. This is the same posture
//! [`crate::install_txn`] takes for an unknown npm flag: a declared coverage
//! gap, never a silent pass.
//!
//! # What a clean receipt does and does not say
//!
//! [`NPM_CLEAN_IS_NOT_BENIGN_CAVEAT`] is part of the output, not decoration.
//! A clean receipt means npm's own signature check passed over the registry's
//! keys. It is not a statement about the package's behavior, and Tirith did not
//! read one byte of any npm tarball, which is what
//! [`crate::provenance::npm_facts::NPM_BYTES_NOT_BOUND_CAVEAT`] (C13's wording,
//! reused verbatim) says.
//!
//! # The one binding that is cryptographic-adjacent
//!
//! [`bind_attested_subject`] compares the sha512 subject digest inside an
//! attestation's in-toto statement against the `integrity` SRI the project's
//! own `package-lock.json` pins. Those cover the same tarball bytes, so a
//! disagreement means the attestation is over DIFFERENT bytes than the lockfile
//! will install. That is the [`NpmPackageStatus::Invalid`] case that forces an
//! overall mismatch. Tirith still does not verify the Sigstore bundle itself
//! (no backend on the workspace MSRV; see
//! [`crate::provenance::pypi_integrity`]), so npm's verification is what the
//! receipt reports, and the receipt says so.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::mcp_lock::{parse_json_no_duplicates, StrictJsonError};
use crate::provenance::npm_facts::SriDigest;
use crate::version_intent::{ReleaseVersion, VersionConstraint};

/// The sentence a reader must not be able to misread a clean receipt without.
/// Stated once so the human and JSON renderings cannot drift.
pub const NPM_CLEAN_IS_NOT_BENIGN_CAVEAT: &str =
    "a clean receipt does not mean the package code is benign; it means npm's own registry \
     signature check passed";

/// Largest `npm --version` stdout accepted. A version line is a handful of
/// bytes; anything larger is not a version.
const MAX_VERSION_TEXT_BYTES: usize = 256;

/// Largest `package-lock.json` read for the binding. Real monorepo lockfiles
/// reach a few tens of megabytes; past this the receipt would be describing a
/// document Tirith refused to read completely, so it fails closed instead.
pub const MAX_LOCKFILE_BYTES: u64 = 64 * 1024 * 1024;

/// Largest decoded DSSE payload inspected for a subject digest. The payload is
/// a small in-toto statement; a larger one is not parsed.
const MAX_DSSE_PAYLOAD_BYTES: usize = 256 * 1024;

/// Most `node_modules` entries inventoried. Past this the inventory is capped
/// and the receipt cannot claim it accounted for everything.
pub const MAX_INSTALLED_PACKAGES: usize = 20_000;

/// Most directories the install-tree walk will OPEN, independent of how many
/// packages it finds.
///
/// [`MAX_INSTALLED_PACKAGES`] bounds what the walk pushes, which is not the same
/// thing as what it visits: an `@scope` directory recurses without pushing
/// anything, so a tree of nothing but scope directories can multiply the work at
/// every depth level while the package count stays at zero. This cap is what
/// makes the walk terminate on such a tree.
const MAX_TREE_DIRECTORIES: usize = 50_000;

/// Most `packages` entries a lockfile may declare.
///
/// [`MAX_LOCKFILE_BYTES`] bounds the document, not its element count, and every
/// entry becomes a record with several owned strings plus a reconciliation
/// lookup. A lockfile inside the byte cap can still declare hundreds of
/// thousands of entries, so the element count is capped too and an over-cap
/// document is refused rather than half-read.
pub const MAX_LOCKFILE_ENTRIES: usize = 50_000;

/// The public npm registry.
///
/// The audit launcher pins this host in hermetic public-registry mode. This
/// constant is an origin identity, not evidence that an entry omitted from
/// npm's JSON was audited: only an explicit audit bucket is positive evidence.
pub const PUBLIC_NPM_REGISTRY_HOST: &str = "registry.npmjs.org";
/// Canonical HTTPS origin paired with [`PUBLIC_NPM_REGISTRY_HOST`].
pub const PUBLIC_NPM_REGISTRY_ORIGIN: &str = "https://registry.npmjs.org/";

/// Most `attestationBundles` predicate types retained per package.
const MAX_PREDICATE_TYPES: usize = 8;

/// Most unaccounted entry names retained in the receipt. The COUNT is always
/// exact; only the name list is bounded.
const MAX_REPORTED_UNACCOUNTED: usize = 64;

// ---------------------------------------------------------------------------
// The closed contract table
// ---------------------------------------------------------------------------

/// The JSON shape one contract's argv produces. Named rather than inferred so
/// a new npm major cannot silently reuse an older parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmAuditJsonSchema {
    /// npm 11's `audit signatures --json --include-attestations`:
    /// `{"invalid": [...], "missing": [...], "verified": [...]}` where
    /// `verified` carries ONLY the packages that have a verified attestation
    /// (npm pushes to `verified` inside `if (attestations)`), so a package with
    /// a good registry signature and no provenance appears in none of the three
    /// arrays.
    BucketsWithAttestedVerified,
}

/// One supported npm version range and everything Tirith is allowed to do with
/// it. Every field is a compile-time constant: there is no interpolation into
/// the argv, so no project, lockfile, or environment value can reach the
/// command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NpmAuditSignaturesContract {
    /// Stable identifier recorded in the receipt.
    pub id: &'static str,
    /// The supported range, in [`VersionConstraint`] syntax.
    pub version_range: &'static str,
    /// The EXACT argv, without the program itself.
    pub argv: &'static [&'static str],
    /// The JSON shape [`parse_audit_report`] must apply.
    pub schema: NpmAuditJsonSchema,
    /// Whether this argv returns full attestation bundles (and therefore lets
    /// [`bind_attested_subject`] run).
    pub attestation_bundles_available: bool,
    /// The committed stdout fixture proving the schema, relative to
    /// `crates/tirith/tests/fixtures/npm_audit_signatures/`.
    pub fixture: &'static str,
}

/// Every npm version range Tirith will run an audit command against.
///
/// One entry. npm 11 is the only major whose `audit signatures` output shape
/// was captured from a real binary into a committed fixture (11.17.0, the
/// version this slice was developed against). npm 10 and older are deliberately
/// absent: their output schema was not captured, and the plan's rule is that a
/// range ships only when a fixture establishes its exact argv AND output
/// schema. Extrapolating a second range from documentation alone is exactly the
/// speculative probe this table exists to prevent.
///
/// Ranges must be non-overlapping and sorted ascending; the unit tests assert
/// both, so a future entry cannot silently shadow this one.
pub const NPM_AUDIT_SIGNATURES_CONTRACTS: &[NpmAuditSignaturesContract] =
    &[NpmAuditSignaturesContract {
        id: "npm-11-audit-signatures-include-attestations",
        version_range: ">=11.0.0,<12.0.0",
        argv: &["audit", "signatures", "--json", "--include-attestations"],
        schema: NpmAuditJsonSchema::BucketsWithAttestedVerified,
        attestation_bundles_available: true,
        fixture: "npm11_clean.json",
    }];

/// Select the contract for a probed npm version, or `None` when the version
/// falls outside every supported range.
///
/// Pure and spawn-free on purpose: the "does an audit command run at all?"
/// decision is one testable function call, so the no-speculative-probe rule is
/// provable without a process.
pub fn select_contract(version: &str) -> Option<&'static NpmAuditSignaturesContract> {
    let parsed = ReleaseVersion::parse(version)?;
    NPM_AUDIT_SIGNATURES_CONTRACTS.iter().find(|contract| {
        VersionConstraint::parse(contract.version_range)
            .is_some_and(|constraint| constraint.matches(&parsed))
    })
}

/// Extract the version string from `npm --version` stdout.
///
/// npm prints exactly one line. Returns `None` for empty output, output over
/// [`MAX_VERSION_TEXT_BYTES`], or a first line that is not a plain numeric
/// release version. A prerelease build (`12.0.0-pre.1`) deliberately fails to
/// parse and funnels to `UnsupportedNpmVersion` rather than being rounded down
/// into a supported range.
pub fn parse_npm_version(stdout: &str) -> Option<String> {
    if stdout.len() > MAX_VERSION_TEXT_BYTES {
        return None;
    }
    let first = stdout.lines().next()?.trim();
    // `ReleaseVersion::parse` is the gate: numeric segments only.
    ReleaseVersion::parse(first)?;
    Some(first.to_string())
}

// ---------------------------------------------------------------------------
// Per-package status
// ---------------------------------------------------------------------------

/// What Tirith can honestly say about one installed package.
///
/// Modelled on
/// [`crate::provenance::pypi_integrity::AttestationOutcome`]: one variant per
/// honest state, each carrying a short non-secret reason, with a stable
/// [`Self::label`] for receipts. Even [`Self::ProvenanceVerified`] is EVIDENCE:
/// it records that npm verified a publish attestation, never that the code is
/// safe to run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NpmPackageStatus {
    /// npm reported a verified provenance attestation for this package, and
    /// (when a lockfile SRI was available) the attestation's in-toto subject
    /// digest bound to it.
    ProvenanceVerified {
        /// The attestation predicate types npm returned, bounded.
        predicate_types: Vec<String>,
        /// Whether the attested subject digest was compared against the
        /// lockfile `integrity` SRI and agreed. `false` means no comparable
        /// digest was present, not that it disagreed (a disagreement is
        /// [`Self::Invalid`]).
        subject_bound: bool,
    },
    /// Legacy wire state for an explicitly reported verified registry signature
    /// with no provenance attestation.
    ///
    /// The currently supported npm JSON contract has no positive per-package
    /// signature-only bucket, so reconciliation never constructs this state.
    /// It remains deserializable for receipt compatibility and for a future
    /// contract that may add explicit membership. Absence from npm's buckets is
    /// always [`Self::NotAudited`].
    SignatureOnly {
        /// How the state was derived, spelled out so the receipt does not read
        /// as a per-package assertion npm never made.
        reason: String,
    },
    /// The registry provides signing keys but published no signature for this
    /// package (npm's `missing` bucket).
    Missing { reason: String },
    /// A signature, an attestation, or the attested subject digest FAILED
    /// (npm's `invalid` bucket, or a subject digest that did not bind to the
    /// lockfile SRI). The security-relevant negative state.
    Invalid {
        /// npm's error code (`EINTEGRITYSIGNATURE`, `EATTESTATIONVERIFY`) or
        /// Tirith's own `ESUBJECTINTEGRITY` for a binding failure.
        code: String,
        reason: String,
    },
    /// The package is installed and eligible, but no audit result covers it:
    /// the audit did not run, or the package is absent from the lockfile the
    /// audit was computed over.
    NotAudited { reason: String },
    /// The dependency does not come from a registry, so npm's signature audit
    /// does not apply to it at all (git, file, link, workspace). Kept explicit
    /// rather than dropped: a silently omitted dependency reads as coverage
    /// that was never attempted.
    UnsupportedSource {
        /// Which non-registry source kind this is.
        kind: NpmSourceKind,
        reason: String,
    },
}

impl NpmPackageStatus {
    /// Short, stable label for receipts and human output.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ProvenanceVerified { .. } => "provenance-verified",
            Self::SignatureOnly { .. } => "signature-only",
            Self::Missing { .. } => "missing",
            Self::Invalid { .. } => "invalid",
            Self::NotAudited { .. } => "not-audited",
            Self::UnsupportedSource { .. } => "unsupported-source",
        }
    }

    /// Whether npm verified a provenance attestation. Even `true` is evidence,
    /// never an authorization to run the code.
    pub fn is_provenance_verified(&self) -> bool {
        matches!(self, Self::ProvenanceVerified { .. })
    }

    /// Whether a registry signature covered this package (attested or not).
    pub fn is_signature_covered(&self) -> bool {
        matches!(
            self,
            Self::ProvenanceVerified { .. } | Self::SignatureOnly { .. }
        )
    }
}

/// Where a lockfile entry's bytes come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmSourceKind {
    /// Resolved from an HTTP(S) registry: the only kind npm audits.
    Registry,
    /// An HTTP(S) URL that is NOT a registry package path: a plain remote
    /// tarball. npm's `getValidPackageInfo` skips these (`!spec.registry`), so
    /// they are in none of its buckets and nothing in its report covers them.
    Remote,
    /// A git or git+ssh dependency.
    Git,
    /// A `file:` dependency.
    File,
    /// A `link: true` dependency (a symlink into the developer's filesystem).
    Link,
    /// A workspace member (the lockfile's own root, or a `packages` entry that
    /// resolves inside the project).
    Workspace,
    /// A resolved value Tirith could not classify. Never optimistically read as
    /// a registry.
    Unknown,
}

impl NpmSourceKind {
    /// Stable label matching the serde spelling.
    pub fn label(self) -> &'static str {
        match self {
            Self::Registry => "registry",
            Self::Remote => "remote",
            Self::Git => "git",
            Self::File => "file",
            Self::Link => "link",
            Self::Workspace => "workspace",
            Self::Unknown => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Overall outcome
// ---------------------------------------------------------------------------

/// Why a run could not reach a clean answer. Typed so the CLI, the receipt, and
/// the tests all name the same states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmPartialReason {
    /// The installed npm is outside every entry of the closed contract table.
    /// No audit command ran.
    UnsupportedNpmVersion,
    /// Offline mode was active, so nothing was resolved or spawned.
    Offline,
    /// This platform cannot resolve npm through the trusted-child mechanism.
    UnsupportedPlatform,
    /// npm could not be resolved as a trusted executable.
    NpmNotResolved,
    /// The audit command ran but did not produce a usable result.
    AuditCommandFailed,
    /// The audit command exceeded its wall-clock budget.
    Timeout,
    /// The audit command exceeded its stdout or stderr cap.
    OutputLimitExceeded,
    /// The audit stdout was not strict JSON.
    ParseFailure,
    /// The audit stdout carried a duplicate object key.
    DuplicateJsonKey,
    /// The audit stdout carried data after the top-level value.
    TrailingJsonData,
    /// The project has no `node_modules`, so there is no install tree to audit.
    MissingInstallTree,
    /// The project has no readable `package-lock.json` to bind to.
    MissingLockfile,
    /// The `package-lock.json` declares more entries than the reader accepts, so
    /// it was refused rather than half-read.
    LockfileTooLarge,
    /// The audited project carries an `.npmrc` that reconfigures what npm
    /// verifies and where it verifies it from. Running the audit under it would
    /// let the audited project configure its own audit, so no command ran.
    ProjectNpmrcOverride,
    /// The requested npm audit mode or its registry/TLS/proxy/auth binding was
    /// incomplete or unsafe, so no command ran.
    AuditConfigurationInvalid,
    /// At least one dependency is not from a registry.
    UnsupportedSource,
    /// At least one installed package has no lockfile entry.
    UnaccountedInstalledPackage,
    /// At least one eligible package has no registry signature.
    MissingSignature,
    /// At least one eligible package was not covered by the audit result.
    NotAudited,
    /// `--require-provenance` was set and at least one eligible package has a
    /// signature but no verified attestation.
    ProvenanceRequiredButAbsent,
    /// The install tree or lockfile was larger than the inventory budget, so
    /// the accounting is incomplete.
    CoverageCapped,
    /// The project declares no registry dependency at all, so there is nothing
    /// a signature audit could cover.
    NoEligiblePackages,
}

impl NpmPartialReason {
    /// Stable label matching the serde spelling.
    pub fn label(self) -> &'static str {
        match self {
            Self::UnsupportedNpmVersion => "unsupported_npm_version",
            Self::Offline => "offline",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::NpmNotResolved => "npm_not_resolved",
            Self::AuditCommandFailed => "audit_command_failed",
            Self::Timeout => "timeout",
            Self::OutputLimitExceeded => "output_limit_exceeded",
            Self::ParseFailure => "parse_failure",
            Self::DuplicateJsonKey => "duplicate_json_key",
            Self::TrailingJsonData => "trailing_json_data",
            Self::MissingInstallTree => "missing_install_tree",
            Self::MissingLockfile => "missing_lockfile",
            Self::LockfileTooLarge => "lockfile_too_large",
            Self::ProjectNpmrcOverride => "project_npmrc_override",
            Self::AuditConfigurationInvalid => "audit_configuration_invalid",
            Self::UnsupportedSource => "unsupported_source",
            Self::UnaccountedInstalledPackage => "unaccounted_installed_package",
            Self::MissingSignature => "missing_signature",
            Self::NotAudited => "not_audited",
            Self::ProvenanceRequiredButAbsent => "provenance_required_but_absent",
            Self::CoverageCapped => "coverage_capped",
            Self::NoEligiblePackages => "no_eligible_packages",
        }
    }
}

/// The overall answer for one project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum NpmAttestOutcome {
    /// Every eligible package carried a verified registry signature, none was
    /// invalid or missing, everything installed was accounted for, and (with
    /// `--require-provenance`) every eligible package carried a verified
    /// attestation. See [`NPM_CLEAN_IS_NOT_BENIGN_CAVEAT`].
    Clean,
    /// The run is honest but incomplete: something was not covered, not
    /// supported, or not reachable.
    Partial {
        reason: NpmPartialReason,
        detail: String,
    },
    /// A signature, an attestation, or a subject digest FAILED. The only state
    /// that is a negative finding rather than a coverage statement.
    Mismatch { detail: String },
}

impl NpmAttestOutcome {
    /// Stable label for receipts and human output.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Partial { .. } => "partial",
            Self::Mismatch { .. } => "mismatch",
        }
    }

    /// The process exit code this outcome maps to. `3` means Partial for THIS
    /// command; `tirith check` uses `3` for a warn acknowledgement, and the
    /// per-command codes in this repository are deliberately distinct.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Clean => 0,
            Self::Mismatch { .. } => 1,
            Self::Partial { .. } => 3,
        }
    }
}

/// Fold the per-package statuses into the overall outcome.
///
/// Precedence, worst first: an `Invalid` (a failed signature, attestation, or
/// subject binding) is a mismatch and dominates everything. Below that, every
/// non-covering state degrades to Partial, because "we could not check it" must
/// never render as "it checked out". `--require-provenance` adds one more
/// requirement on top of the default contract: a `SignatureOnly` package is no
/// longer sufficient.
pub fn overall_outcome(
    statuses: &[NpmPackageStatus],
    require_provenance: bool,
) -> NpmAttestOutcome {
    if statuses.is_empty() {
        return NpmAttestOutcome::Partial {
            reason: NpmPartialReason::NoEligiblePackages,
            detail: "the project declares no registry dependency for npm to audit".to_string(),
        };
    }

    let invalid = statuses
        .iter()
        .filter(|status| matches!(status, NpmPackageStatus::Invalid { .. }))
        .count();
    if invalid > 0 {
        return NpmAttestOutcome::Mismatch {
            detail: format!(
                "{invalid} package(s) failed npm's signature, attestation, or subject-digest check"
            ),
        };
    }

    let count = |predicate: fn(&NpmPackageStatus) -> bool| -> usize {
        statuses.iter().filter(|status| predicate(status)).count()
    };

    let missing = count(|status| matches!(status, NpmPackageStatus::Missing { .. }));
    if missing > 0 {
        return NpmAttestOutcome::Partial {
            reason: NpmPartialReason::MissingSignature,
            detail: format!("{missing} package(s) have no registry signature"),
        };
    }

    let not_audited = count(|status| matches!(status, NpmPackageStatus::NotAudited { .. }));
    if not_audited > 0 {
        return NpmAttestOutcome::Partial {
            reason: NpmPartialReason::NotAudited,
            detail: format!("{not_audited} package(s) were not covered by the audit result"),
        };
    }

    let unsupported = count(|status| matches!(status, NpmPackageStatus::UnsupportedSource { .. }));
    if unsupported > 0 {
        return NpmAttestOutcome::Partial {
            reason: NpmPartialReason::UnsupportedSource,
            detail: format!(
                "{unsupported} dependency/ies are not installed from a registry, so npm's \
                 signature audit does not cover them"
            ),
        };
    }

    if require_provenance {
        let signature_only =
            count(|status| matches!(status, NpmPackageStatus::SignatureOnly { .. }));
        if signature_only > 0 {
            return NpmAttestOutcome::Partial {
                reason: NpmPartialReason::ProvenanceRequiredButAbsent,
                detail: format!(
                    "--require-provenance is set and {signature_only} package(s) carry a registry \
                     signature but no verified attestation"
                ),
            };
        }
    }

    NpmAttestOutcome::Clean
}

/// Degrade a would-be [`NpmAttestOutcome::Clean`] when the accounting itself
/// was incomplete.
///
/// The per-package statuses cannot see a gap that sits ABOVE any package: an
/// inventory that hit its cap, a lockfile that hit its cap. Without this, a
/// truncated walk reports clean over a tree it never finished reading. A
/// Partial or Mismatch is left alone; a worse answer never gets better here.
pub fn apply_coverage_gap(outcome: NpmAttestOutcome, gap: Option<&str>) -> NpmAttestOutcome {
    match (outcome, gap) {
        (NpmAttestOutcome::Clean, Some(detail)) => NpmAttestOutcome::Partial {
            reason: NpmPartialReason::CoverageCapped,
            detail: detail.to_string(),
        },
        (outcome, _) => outcome,
    }
}

// ---------------------------------------------------------------------------
// package-lock.json
// ---------------------------------------------------------------------------

/// Why a lockfile could not be turned into a binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NpmLockfileError {
    /// The document is not strict JSON.
    Malformed,
    /// The document carries a duplicate object key.
    DuplicateKey,
    /// The document parsed but is not a `package-lock.json`.
    NotALockfile,
    /// The lockfile format version is not one this reader models.
    UnsupportedLockfileVersion(u64),
    /// The `packages` map declares more than [`MAX_LOCKFILE_ENTRIES`] entries.
    /// Refused rather than truncated: a partially read lockfile would leave the
    /// receipt binding to a subset it never says it read.
    TooManyEntries(usize),
    /// [`crate::ecosystem_scan`]'s hardened npm identity rules refused the
    /// document: its alias claims contradict each other, or a `packages` entry's
    /// declared identity disagrees with the tree that installs it. Refused
    /// rather than half-read, because every binding below depends on knowing
    /// which package each install location actually holds.
    ContradictoryIdentity,
}

impl std::fmt::Display for NpmLockfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "package-lock.json is not valid JSON"),
            Self::DuplicateKey => write!(f, "package-lock.json carries a duplicate object key"),
            Self::NotALockfile => write!(f, "the document is not a package-lock.json"),
            Self::UnsupportedLockfileVersion(version) => {
                write!(f, "unsupported package-lock.json lockfileVersion {version}")
            }
            Self::TooManyEntries(count) => write!(
                f,
                "package-lock.json declares {count} entries, past the {MAX_LOCKFILE_ENTRIES} this \
                 reader accepts"
            ),
            Self::ContradictoryIdentity => write!(
                f,
                "package-lock.json is internally contradictory about which package an install \
                 location holds"
            ),
        }
    }
}

/// One dependency the lockfile pins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmLockfileEntry {
    /// The `packages` key, which is the install location relative to the
    /// project root (`node_modules/@scope/name`). The primary reconciliation
    /// key, because npm's audit output uses the same value.
    pub location: String,
    /// The CANONICAL package name: the `name` an aliased entry declares, else
    /// the one its install location spells. This is the security target.
    pub name: String,
    /// The install location's spelling when it DIFFERS from the canonical name,
    /// which is what an npm alias (`npm i foo@npm:bar`) produces. Presentation
    /// only; every lookup uses `name`. Recorded rather than dropped so an
    /// aliased dependency is visible instead of silently renamed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Pinned version, when the entry declares one.
    pub version: Option<String>,
    /// Classified source.
    pub source: NpmSourceKind,
    /// The `integrity` SRI exactly as pinned, when present and parseable.
    pub integrity: Option<String>,
    /// The registry host the `resolved` URL names, with any userinfo redacted.
    pub registry_host: Option<String>,
    /// Whether the lockfile marks the entry dev-only.
    pub dev: bool,
}

/// The parts of a `package-lock.json` this slice binds to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmLockfile {
    /// The declared `lockfileVersion`.
    pub lockfile_version: u64,
    /// Every non-root entry, sorted by location.
    pub entries: Vec<NpmLockfileEntry>,
    /// The project's own name, when declared.
    pub root_name: Option<String>,
}

impl NpmLockfile {
    /// Entries npm's signature audit can cover.
    pub fn registry_entries(&self) -> impl Iterator<Item = &NpmLockfileEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.source == NpmSourceKind::Registry)
    }

    /// Sorted, de-duplicated registry hosts, for the receipt.
    pub fn registry_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self
            .registry_entries()
            .filter_map(|entry| entry.registry_host.clone())
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }
}

/// Parse the `packages` map of a lockfile v2/v3 document.
///
/// Deliberately narrow. [`crate::ecosystem_scan::parse_manifest`] already owns
/// the hardened npm identity rules (the alias-contradiction rejection at
/// `npm_lock_alias_claims`, the v2 identity check at `npm_lock_v2_identity`),
/// and this reader does NOT reimplement them: it CALLS that parser as a gate
/// and then reads only the fields it does not expose (`resolved`, `integrity`,
/// `link`, `dev`) plus the install-location key.
///
/// v1 lockfiles (a top-level `dependencies` map with no `packages`) are refused
/// rather than half-read: their entries have no install-location key, so they
/// cannot be reconciled against npm's audit output, which reports `location`.
pub fn parse_package_lock(text: &str) -> Result<NpmLockfile, NpmLockfileError> {
    let value = parse_json_no_duplicates(text).map_err(|error| match error {
        StrictJsonError::DuplicateObjectKey => NpmLockfileError::DuplicateKey,
        StrictJsonError::Malformed => NpmLockfileError::Malformed,
    })?;
    let object = value.as_object().ok_or(NpmLockfileError::NotALockfile)?;
    let lockfile_version = object
        .get("lockfileVersion")
        .and_then(|v| v.as_u64())
        .ok_or(NpmLockfileError::NotALockfile)?;
    if !(2..=3).contains(&lockfile_version) {
        return Err(NpmLockfileError::UnsupportedLockfileVersion(
            lockfile_version,
        ));
    }
    let packages = object
        .get("packages")
        .and_then(|v| v.as_object())
        .ok_or(NpmLockfileError::NotALockfile)?;
    if packages.len() > MAX_LOCKFILE_ENTRIES {
        return Err(NpmLockfileError::TooManyEntries(packages.len()));
    }

    // The identity gate, delegated rather than duplicated. `parse_manifest`
    // returns `None` for a lockfile whose alias claims contradict each other or
    // whose v2 `packages` identity disagrees with the tree, which is precisely
    // the case where "which package lives at this location" has no single
    // answer, and every binding below is keyed on that location.
    if crate::ecosystem_scan::parse_manifest(
        crate::ecosystem_scan::ManifestKind::NpmPackageLock,
        text,
    )
    .is_none()
    {
        return Err(NpmLockfileError::ContradictoryIdentity);
    }

    let root_name = packages
        .get("")
        .and_then(|root| root.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut entries = Vec::new();
    for (location, entry) in packages {
        // The empty key is the project root; it is a workspace member, not a
        // dependency, and npm's audit skips it.
        if location.is_empty() {
            continue;
        }
        let Some(entry) = entry.as_object() else {
            continue;
        };
        let location_name = package_name_from_location(location);
        let name = entry
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| location_name.clone())
            .unwrap_or_else(|| location.clone());
        // An install location that spells a DIFFERENT name than the entry
        // declares is npm's alias form. The declared name is the security
        // target; the location spelling is what a reader sees on disk.
        let alias = location_name.filter(|spelled| spelled != &name);
        let version = entry
            .get("version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let resolved = entry.get("resolved").and_then(|v| v.as_str());
        let link = entry.get("link").and_then(|v| v.as_bool()).unwrap_or(false);
        let source = classify_source(resolved, link, &name);
        let integrity = entry
            .get("integrity")
            .and_then(|v| v.as_str())
            .and_then(SriDigest::parse)
            .map(|sri| sri.canonical());
        let registry_host = if source == NpmSourceKind::Registry {
            resolved.and_then(registry_host_of)
        } else {
            None
        };
        let dev = entry.get("dev").and_then(|v| v.as_bool()).unwrap_or(false);
        entries.push(NpmLockfileEntry {
            location: location.clone(),
            name,
            alias,
            version,
            source,
            integrity,
            registry_host,
            dev,
        });
    }
    entries.sort_by(|a, b| a.location.cmp(&b.location));

    Ok(NpmLockfile {
        lockfile_version,
        entries,
        root_name,
    })
}

/// Derive a package name from a `node_modules/...` location key, handling one
/// level of `@scope`. Returns `None` for a key with no `node_modules` segment
/// (a workspace member path).
fn package_name_from_location(location: &str) -> Option<String> {
    let tail = location.rsplit_once("node_modules/")?.1;
    if tail.is_empty() {
        return None;
    }
    if let Some(rest) = tail.strip_prefix('@') {
        let mut parts = rest.splitn(3, '/');
        let scope = parts.next()?;
        let name = parts.next()?;
        if scope.is_empty() || name.is_empty() {
            return None;
        }
        return Some(format!("@{scope}/{name}"));
    }
    let name = tail.split('/').next()?;
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Classify a lockfile entry's source from `resolved`, `link`, and the entry's
/// canonical name.
///
/// Fails toward [`NpmSourceKind::Unknown`]: a `resolved` value that is not a
/// recognized scheme is never optimistically treated as a registry, because a
/// registry classification is what makes an entry ELIGIBLE for a clean answer.
///
/// An HTTP(S) URL alone is NOT enough to call an entry a registry dependency.
/// npm decides eligibility from the dependency SPEC, not from `resolved`:
/// `getValidPackageInfo` returns early on `!spec.registry`, and a dependency
/// declared as a bare tarball URL is `type: remote`, so npm never audits it and
/// it appears in none of its buckets. The structural tell in the lockfile is the
/// registry package path `<...>/<name>/-/<basename>`; anything else is
/// [`NpmSourceKind::Remote`].
fn classify_source(resolved: Option<&str>, link: bool, name: &str) -> NpmSourceKind {
    if link {
        return NpmSourceKind::Link;
    }
    let Some(resolved) = resolved.map(str::trim).filter(|s| !s.is_empty()) else {
        // A `packages` entry with no `resolved` is the project's own workspace
        // member (npm omits `resolved` for those).
        return NpmSourceKind::Workspace;
    };
    let lowered = resolved.to_ascii_lowercase();
    if lowered.starts_with("http://") || lowered.starts_with("https://") {
        if is_registry_package_url(resolved, name) {
            NpmSourceKind::Registry
        } else {
            NpmSourceKind::Remote
        }
    } else if lowered.starts_with("git+")
        || lowered.starts_with("git:")
        || lowered.starts_with("git@")
    {
        NpmSourceKind::Git
    } else if lowered.starts_with("file:") {
        NpmSourceKind::File
    } else if lowered.starts_with("workspace:") {
        NpmSourceKind::Workspace
    } else {
        NpmSourceKind::Unknown
    }
}

/// Whether a `resolved` URL is a registry PACKAGE path for `name`.
///
/// Every npm-protocol registry serves tarballs at `<prefix>/<name>/-/<file>`,
/// and the `-` separator segment is what distinguishes a package path from an
/// arbitrary URL that merely happens to end in `.tgz`. The name segments
/// immediately before the separator must spell the entry's canonical name, so a
/// URL cannot borrow another package's path shape.
///
/// Deliberately strict. A false negative degrades the entry to
/// [`NpmSourceKind::Remote`], which is a Partial and therefore honest; a false
/// positive would let an attacker-hosted tarball into the pool of entries a
/// clean answer covers.
fn is_registry_package_url(resolved: &str, name: &str) -> bool {
    let redacted = crate::receipt::redact_url_userinfo(resolved);
    let Ok(url) = url::Url::parse(&redacted) else {
        return false;
    };
    let Some(segments) = url.path_segments() else {
        return false;
    };
    let segments: Vec<&str> = segments.collect();
    let Some(separator) = segments.iter().rposition(|segment| *segment == "-") else {
        return false;
    };
    // The separator must be followed by a basename and preceded by the name.
    if separator + 1 >= segments.len() || segments[separator + 1].is_empty() {
        return false;
    }
    match name.strip_prefix('@').and_then(|rest| rest.split_once('/')) {
        Some((scope, bare)) => {
            if separator >= 2
                && segments[separator - 2] == format!("@{scope}")
                && segments[separator - 1] == bare
            {
                return true;
            }
            // Some registries percent-encode the scope separator into one path
            // segment, which `url` does not decode.
            separator >= 1
                && segments[separator - 1].eq_ignore_ascii_case(&format!("@{scope}%2f{bare}"))
        }
        None => separator >= 1 && segments[separator - 1] == name,
    }
}

/// The host (and port) of a resolved registry URL, with any userinfo redacted.
///
/// A `resolved` value of the form `https://user:pat@registry.example/...` is
/// realistic in a private-registry lockfile, so the credential must not survive
/// into the receipt. Only the host reaches the output; the path and any query
/// are dropped entirely.
fn registry_host_of(resolved: &str) -> Option<String> {
    let redacted = crate::receipt::redact_url_userinfo(resolved);
    let parsed = url::Url::parse(&redacted).ok()?;
    let host = parsed.host_str()?;
    Some(match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

// ---------------------------------------------------------------------------
// node_modules inventory
// ---------------------------------------------------------------------------

/// One package found on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledPackage {
    /// Location relative to the project root, in the same spelling the lockfile
    /// and npm's audit output use (`node_modules/@scope/name`).
    pub location: String,
    /// The name the installed `package.json` declares, when readable.
    pub name: Option<String>,
    /// The version the installed `package.json` declares, when readable.
    pub version: Option<String>,
}

/// The result of walking an install tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledInventory {
    /// Every package found, sorted by location.
    pub packages: Vec<InstalledPackage>,
    /// True when the walk hit [`MAX_INSTALLED_PACKAGES`], [`MAX_TREE_DIRECTORIES`],
    /// or a depth cap, so the inventory is not a complete statement about the
    /// tree.
    pub capped: bool,
    /// How many `node_modules` entries were symlinks the walk refused to follow.
    /// Non-zero means part of the tree was never read, which is a coverage gap
    /// rather than an empty subtree.
    pub symlinked_entries: usize,
}

/// Walk `<root>/node_modules` and inventory the installed packages.
///
/// Deliberately narrow, and deliberately NOT
/// [`crate::ecosystem_scan`]'s walker (`walk_node_modules` there is a private
/// fn reached only through the heavyweight `scan(&ScanRequest)` orchestration).
/// The rules here: one level of `@scope` expansion, nested `node_modules`
/// followed to a bounded depth, `.bin` / `.cache` / dotted entries skipped,
/// symlinked entries NEVER followed (an entry that points at its own ancestor
/// makes the walk unbounded), and hard entry, directory, and depth caps that set
/// [`InstalledInventory::capped`] rather than silently truncating.
///
/// Returns `None` when `<root>/node_modules` does not exist, which the caller
/// maps to [`NpmPartialReason::MissingInstallTree`] WITHOUT spawning anything.
pub fn walk_installed_tree(root: &Path) -> Option<InstalledInventory> {
    let node_modules = root.join("node_modules");
    if !node_modules.is_dir() {
        return None;
    }
    let mut walk = TreeWalk::default();
    collect_packages(&node_modules, "node_modules", 0, &mut walk);
    let mut packages = walk.packages;
    packages.sort_by(|a, b| a.location.cmp(&b.location));
    packages.dedup_by(|a, b| a.location == b.location);
    Some(InstalledInventory {
        packages,
        capped: walk.capped,
        symlinked_entries: walk.symlinked_entries,
    })
}

/// Mutable state threaded through [`collect_packages`].
///
/// `directories` is the budget that actually terminates the walk: the package
/// count cannot bound it, because a scope directory recurses without pushing a
/// package.
#[derive(Default)]
struct TreeWalk {
    packages: Vec<InstalledPackage>,
    capped: bool,
    symlinked_entries: usize,
    directories: usize,
}

/// How deep a nested `node_modules` chain is followed. npm hoists, so real
/// trees are shallow; the cap mirrors the depth discipline in
/// [`crate::ecosystem_scan`].
const MAX_TREE_DEPTH: usize = 8;

fn collect_packages(directory: &Path, prefix: &str, depth: usize, walk: &mut TreeWalk) {
    if depth > MAX_TREE_DEPTH {
        walk.capped = true;
        return;
    }
    if walk.directories >= MAX_TREE_DIRECTORIES {
        walk.capped = true;
        return;
    }
    walk.directories += 1;
    let Ok(entries) = std::fs::read_dir(directory) else {
        walk.capped = true;
        return;
    };
    for entry in entries.flatten() {
        if walk.packages.len() >= MAX_INSTALLED_PACKAGES {
            walk.capped = true;
            return;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            // A non-UTF-8 directory name cannot be matched against a lockfile
            // key, so it is a coverage gap rather than something to guess at.
            walk.capped = true;
            continue;
        };
        // `.bin` holds shims, `.cache` holds npm's own state, and neither is a
        // package. Every other dotted entry is npm bookkeeping too.
        if name.starts_with('.') {
            continue;
        }
        // `file_type()` reports the ENTRY, so a symlink never reads as the
        // directory it points at. A symlink under `node_modules` can point at
        // its own ancestor, and following it makes the walk unbounded no matter
        // how the package count is capped.
        let Ok(file_type) = entry.file_type() else {
            walk.capped = true;
            continue;
        };
        if file_type.is_symlink() {
            walk.symlinked_entries += 1;
            continue;
        }
        if !file_type.is_dir() {
            continue;
        }
        let path = entry.path();
        if let Some(scope) = name.strip_prefix('@') {
            if scope.is_empty() {
                continue;
            }
            // One level of scope expansion; a scope directory holds packages,
            // never a package itself.
            collect_packages(&path, &format!("{prefix}/{name}"), depth + 1, walk);
            continue;
        }
        let location = format!("{prefix}/{name}");
        let (declared_name, declared_version) = read_installed_manifest(&path);
        walk.packages.push(InstalledPackage {
            location: location.clone(),
            name: declared_name,
            version: declared_version,
        });
        let nested = path.join("node_modules");
        // Same rule as the entry loop: a nested `node_modules` that is itself a
        // symlink can point at an ancestor, and `is_dir()` would follow it.
        let nested_is_real_dir = std::fs::symlink_metadata(&nested)
            .map(|metadata| metadata.is_dir())
            .unwrap_or(false);
        if nested_is_real_dir {
            collect_packages(
                &nested,
                &format!("{location}/node_modules"),
                depth + 1,
                walk,
            );
        }
    }
}

/// Largest installed `package.json` read for its name and version.
const MAX_INSTALLED_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

/// Read the `name` and `version` an installed package declares. Any failure
/// yields `(None, None)`: the package is still inventoried by LOCATION, which
/// is the reconciliation key, so an unreadable manifest never makes a package
/// disappear from the accounting.
fn read_installed_manifest(package_dir: &Path) -> (Option<String>, Option<String>) {
    let manifest = package_dir.join("package.json");
    let Ok(bytes) = crate::util::read_regular_capped(&manifest, MAX_INSTALLED_MANIFEST_BYTES)
    else {
        return (None, None);
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return (None, None);
    };
    let Ok(value) = parse_json_no_duplicates(&text) else {
        return (None, None);
    };
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let version = value
        .get("version")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    (name, version)
}

// ---------------------------------------------------------------------------
// npm audit signatures output
// ---------------------------------------------------------------------------

/// One entry from npm's `invalid`, `missing`, or `verified` bucket.
///
/// The field set is exactly what npm 11's `lib/utils/verify-signatures.js`
/// pushes: `missing` carries `{integrity, location, name, registry, resolved,
/// version}`, `invalid` adds `{code, message, keyid, signature, predicateType,
/// type}`, and `verified` carries `{name, version, location, registry,
/// attestations, attestationBundles}`. Only the non-secret, bounded subset is
/// retained; npm's `message` can quote registry text, so it is truncated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmAuditEntry {
    pub name: String,
    pub version: Option<String>,
    pub location: Option<String>,
    pub registry: Option<String>,
    /// npm's error code, on `invalid` entries.
    pub code: Option<String>,
    /// The attestation predicate types, on `verified` entries.
    pub predicate_types: Vec<String>,
    /// The in-toto subject digests the attestation bundles assert, keyed by
    /// algorithm (`sha512`), lowercase hex.
    pub attested_digests: BTreeMap<String, String>,
}

/// npm's three buckets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NpmAuditReport {
    pub invalid: Vec<NpmAuditEntry>,
    pub missing: Vec<NpmAuditEntry>,
    pub verified: Vec<NpmAuditEntry>,
}

/// Why an audit stdout could not be turned into a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpmAuditParseError {
    /// Not JSON, or JSON with trailing data.
    Malformed,
    /// A duplicate object key: two different readers would disagree about the
    /// document, so it is refused rather than collapsed last-wins.
    DuplicateKey,
    /// The document is JSON but not the schema the contract declared.
    SchemaMismatch,
    /// The document was empty.
    Empty,
}

impl NpmAuditParseError {
    /// The Partial reason this parse failure maps to.
    pub fn partial_reason(self) -> NpmPartialReason {
        match self {
            Self::DuplicateKey => NpmPartialReason::DuplicateJsonKey,
            Self::Malformed | Self::SchemaMismatch | Self::Empty => NpmPartialReason::ParseFailure,
        }
    }

    /// A short, non-secret explanation.
    pub fn detail(self) -> &'static str {
        match self {
            Self::Malformed => {
                "npm's audit output was not strict JSON (malformed or trailing data)"
            }
            Self::DuplicateKey => "npm's audit output carried a duplicate JSON object key",
            Self::SchemaMismatch => {
                "npm's audit output did not match the schema this contract declared"
            }
            Self::Empty => "npm's audit output was empty",
        }
    }
}

/// Strictly parse npm's audit stdout into the three buckets.
///
/// Strict means [`parse_json_no_duplicates`]: a duplicate object key is
/// refused (two readers would disagree about the document) and trailing data
/// after the top-level value is refused (a second document appended to the
/// first must not be silently ignored). Both map to distinct Partial reasons.
pub fn parse_audit_report(
    stdout: &str,
    schema: NpmAuditJsonSchema,
) -> Result<NpmAuditReport, NpmAuditParseError> {
    if stdout.trim().is_empty() {
        return Err(NpmAuditParseError::Empty);
    }
    let value = parse_json_no_duplicates(stdout).map_err(|error| match error {
        StrictJsonError::DuplicateObjectKey => NpmAuditParseError::DuplicateKey,
        StrictJsonError::Malformed => NpmAuditParseError::Malformed,
    })?;
    let object = value
        .as_object()
        .ok_or(NpmAuditParseError::SchemaMismatch)?;

    match schema {
        NpmAuditJsonSchema::BucketsWithAttestedVerified => {
            // `invalid` and `missing` are required; `verified` is required for
            // this contract because the argv passes --include-attestations.
            let invalid = bucket(object, "invalid")?;
            let missing = bucket(object, "missing")?;
            let verified = bucket(object, "verified")?;
            Ok(NpmAuditReport {
                invalid,
                missing,
                verified,
            })
        }
    }
}

fn bucket(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<Vec<NpmAuditEntry>, NpmAuditParseError> {
    let array = object
        .get(key)
        .and_then(|v| v.as_array())
        .ok_or(NpmAuditParseError::SchemaMismatch)?;
    // Strict at the ELEMENT level, not just the bucket level. Dropping an
    // element that does not match the entry schema would empty the `invalid`
    // bucket one finding at a time, and an emptied `invalid` bucket is the most
    // positive answer this command can give. A shape Tirith does not model is a
    // refusal, the same way an unmodelled npm version is.
    let mut entries = Vec::with_capacity(array.len());
    for value in array {
        entries.push(parse_audit_entry(value).ok_or(NpmAuditParseError::SchemaMismatch)?);
    }
    Ok(entries)
}

fn parse_audit_entry(value: &serde_json::Value) -> Option<NpmAuditEntry> {
    let object = value.as_object()?;
    let name = object.get("name")?.as_str()?.to_string();
    let version = object
        .get("version")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let location = object
        .get("location")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let registry = object
        .get("registry")
        .and_then(|v| v.as_str())
        .map(crate::receipt::redact_url_userinfo);
    let code = object
        .get("code")
        .and_then(|v| v.as_str())
        .map(|s| crate::util::truncate_bytes(s, 128));

    let mut predicate_types = Vec::new();
    let mut attested_digests = BTreeMap::new();
    if let Some(bundles) = object.get("attestationBundles").and_then(|v| v.as_array()) {
        for bundle in bundles {
            if predicate_types.len() < MAX_PREDICATE_TYPES {
                if let Some(predicate) = bundle.get("predicateType").and_then(|v| v.as_str()) {
                    let predicate = crate::util::truncate_bytes(predicate, 256);
                    if !predicate_types.contains(&predicate) {
                        predicate_types.push(predicate);
                    }
                }
            }
            if let Some(payload) = bundle
                .get("bundle")
                .and_then(|b| b.get("dsseEnvelope"))
                .and_then(|d| d.get("payload"))
                .and_then(|p| p.as_str())
            {
                for (algorithm, digest) in subject_digests_of(payload) {
                    attested_digests.entry(algorithm).or_insert(digest);
                }
            }
        }
    }
    // The `attestations.provenance.predicateType` field is present even when
    // the bundles are not, so record it too rather than reporting an attested
    // package as carrying no predicate.
    if let Some(predicate) = object
        .get("attestations")
        .and_then(|a| a.get("provenance"))
        .and_then(|p| p.get("predicateType"))
        .and_then(|v| v.as_str())
    {
        let predicate = crate::util::truncate_bytes(predicate, 256);
        if !predicate_types.contains(&predicate) && predicate_types.len() < MAX_PREDICATE_TYPES {
            predicate_types.push(predicate);
        }
    }

    Some(NpmAuditEntry {
        name,
        version,
        location,
        registry,
        code,
        predicate_types,
        attested_digests,
    })
}

/// Decode one DSSE envelope payload and read its in-toto subject digests.
///
/// The payload is standard base64 over a small in-toto statement. Bounded at
/// [`MAX_DSSE_PAYLOAD_BYTES`] and parsed strictly; any failure yields no
/// digests, which downgrades the package to "attested but not subject-bound"
/// rather than fabricating a binding.
fn subject_digests_of(payload_b64: &str) -> Vec<(String, String)> {
    use base64::Engine as _;

    if payload_b64.len() > MAX_DSSE_PAYLOAD_BYTES {
        return Vec::new();
    }
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(payload_b64) else {
        return Vec::new();
    };
    if bytes.len() > MAX_DSSE_PAYLOAD_BYTES {
        return Vec::new();
    }
    let Ok(text) = String::from_utf8(bytes) else {
        return Vec::new();
    };
    let Ok(value) = parse_json_no_duplicates(&text) else {
        return Vec::new();
    };
    let Some(digest) = value
        .get("subject")
        .and_then(|s| s.as_array())
        .and_then(|subjects| subjects.first())
        .and_then(|subject| subject.get("digest"))
        .and_then(|d| d.as_object())
    else {
        return Vec::new();
    };
    digest
        .iter()
        .filter_map(|(algorithm, value)| {
            let hex = value.as_str()?;
            if hex.len() > 256 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            Some((algorithm.to_ascii_lowercase(), hex.to_ascii_lowercase()))
        })
        .collect()
}

/// The result of comparing an attested subject digest against a lockfile SRI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectBinding {
    /// Both sides carried a comparable digest and they agree.
    Bound,
    /// Both sides carried a comparable digest and they DISAGREE: the
    /// attestation covers different bytes than the lockfile pins.
    Mismatch,
    /// No comparable pair (no lockfile SRI, no attested digest for that
    /// algorithm, or an unparseable value). Never silently read as bound.
    NotComparable,
}

/// Compare an attestation's in-toto subject digest against the lockfile
/// `integrity` SRI for the same package.
///
/// npm's publish attestation names the tarball's sha512 as a hex string, and
/// the lockfile's SRI is `sha512-<base64>` over the SAME tarball, so the two
/// are directly comparable after decoding the SRI. A disagreement is the
/// artifact-swap / stale-attestation tell and is the one condition in this
/// slice that produces a mismatch from Tirith's own comparison rather than from
/// npm's report.
pub fn bind_attested_subject(
    attested: &BTreeMap<String, String>,
    lockfile_integrity: Option<&str>,
) -> SubjectBinding {
    use base64::Engine as _;

    let Some(sri) = lockfile_integrity.and_then(SriDigest::parse) else {
        return SubjectBinding::NotComparable;
    };
    let Some(expected) = attested.get(&sri.algorithm) else {
        return SubjectBinding::NotComparable;
    };
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(&sri.digest) else {
        return SubjectBinding::NotComparable;
    };
    let actual = hex::encode(raw);
    if actual.is_empty() || expected.is_empty() {
        return SubjectBinding::NotComparable;
    }
    if constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
        SubjectBinding::Bound
    } else {
        SubjectBinding::Mismatch
    }
}

/// Constant-time byte equality, seeded with a length-mismatch flag so neither
/// the length nor the first differing position leaks through timing. Mirrors
/// [`crate::provenance::pypi_integrity`]'s comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max = a.len().max(b.len());
    let mut diff: u8 = (a.len() != b.len()) as u8;
    for index in 0..max {
        diff |= a.get(index).copied().unwrap_or(0) ^ b.get(index).copied().unwrap_or(0);
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------

/// One package as the receipt records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmPackageRecord {
    /// Install location, the reconciliation key.
    pub location: String,
    /// Canonical package name: the security target, never the alias.
    pub name: String,
    /// The install location's spelling when it differs from the canonical name
    /// (an npm alias). Presentation only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Pinned version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// How the dependency is sourced.
    pub source: NpmSourceKind,
    /// The registry host the lockfile's `resolved` URL names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_host: Option<String>,
    /// The registry host NPM ITSELF reported for this package, when npm named
    /// it in one of its buckets.
    ///
    /// npm derives the registry it verifies against from CONFIG
    /// (`pickRegistry(spec, flatOptions)`), never from the lockfile's `resolved`
    /// URL, so this and [`Self::registry_host`] can disagree. Recording only the
    /// lockfile side would make the receipt an assertion about a host npm may
    /// never have contacted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_registry_host: Option<String>,
    /// The lockfile `integrity` SRI, canonical spelling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockfile_integrity: Option<String>,
    /// Whether the package is present in the install tree.
    pub installed: bool,
    /// The signature / provenance status.
    pub status: NpmPackageStatus,
}

/// What the reconciliation could and could not account for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmCoverage {
    /// Installed packages with a matching lockfile entry.
    pub accounted_installed: usize,
    /// Installed packages with NO lockfile entry. Each one is a hole in the
    /// binding, so a non-zero count forces Partial.
    pub unaccounted_installed: usize,
    /// The first [`MAX_REPORTED_UNACCOUNTED`] unaccounted locations, for the
    /// operator. The count above is always exact.
    pub unaccounted_locations: Vec<String>,
    /// Lockfile entries with a registry source.
    pub registry_entries: usize,
    /// Lockfile entries with a non-registry source.
    pub unsupported_source_entries: usize,
    /// True when the install-tree walk was capped.
    pub inventory_capped: bool,
    /// How many `node_modules` entries the walk refused to follow because they
    /// were symlinks, so part of the tree was never read.
    pub symlinked_entries_skipped: usize,
    /// Audit-report entries that matched no lockfile entry and no installed
    /// package. Each one is a statement npm made that the binding could not
    /// consume, so each one gets its own record rather than being discarded.
    pub unmatched_audit_entries: usize,
    /// Legacy schema field. Always false: absence from npm's audit buckets is
    /// never treated as positive signature evidence.
    #[serde(default)]
    pub signature_only_derived_by_subtraction: bool,
}

/// Everything the receipt needs about one project's packages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpmAssessment {
    pub records: Vec<NpmPackageRecord>,
    pub coverage: NpmCoverage,
}

impl NpmAssessment {
    /// The statuses, in record order, for [`overall_outcome`].
    pub fn statuses(&self) -> Vec<NpmPackageStatus> {
        self.records
            .iter()
            .map(|record| record.status.clone())
            .collect()
    }

    /// The coverage gap text for [`apply_coverage_gap`], when there is one.
    pub fn coverage_gap(&self) -> Option<String> {
        if self.coverage.inventory_capped {
            return Some(
                "the node_modules walk hit its entry, directory, or depth cap, so the inventory \
                 is not a complete statement about the install tree"
                    .to_string(),
            );
        }
        if self.coverage.symlinked_entries_skipped > 0 {
            return Some(format!(
                "{} node_modules entries are symlinks the walk refused to follow, so the \
                 inventory is not a complete statement about the install tree",
                self.coverage.symlinked_entries_skipped
            ));
        }
        None
    }

    /// Sorted, de-duplicated registry hosts NPM ITSELF reported, for the
    /// receipt. Distinct from the lockfile's hosts on purpose: the two disagree
    /// exactly when npm's config pointed it somewhere the lockfile does not
    /// name.
    pub fn audit_registry_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self
            .records
            .iter()
            .filter_map(|record| record.audit_registry_host.clone())
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }
}

/// One of npm's buckets, indexed for lookup and marked as it is consumed.
///
/// Two jobs. The index removes the linear scan `find_entry` used to do per
/// lockfile entry, which made reconciliation quadratic in two attacker-supplied
/// inputs. The consumption marks are what make it possible to assert, at the
/// end, that every statement npm made was accounted for; a dropped `invalid`
/// entry is a signature failure that reaches no one.
struct AuditBucket<'a> {
    entries: &'a [NpmAuditEntry],
    by_location: BTreeMap<&'a str, usize>,
    by_name_version: BTreeMap<String, usize>,
    consumed: Vec<bool>,
}

impl<'a> AuditBucket<'a> {
    fn new(entries: &'a [NpmAuditEntry]) -> Self {
        let mut by_location = BTreeMap::new();
        let mut by_name_version = BTreeMap::new();
        for (index, entry) in entries.iter().enumerate() {
            if let Some(location) = entry.location.as_deref() {
                // First wins, matching the previous `find` semantics; the
                // loser stays unconsumed and therefore still gets a record.
                by_location.entry(location).or_insert(index);
            }
            if let Some(version) = entry.version.as_deref() {
                by_name_version
                    .entry(format!("{}@{version}", entry.name))
                    .or_insert(index);
            }
        }
        Self {
            consumed: vec![false; entries.len()],
            entries,
            by_location,
            by_name_version,
        }
    }

    fn lookup(&self, location: &str, name: Option<&str>, version: Option<&str>) -> Option<usize> {
        self.by_location
            .get(location)
            .copied()
            .or_else(|| match (name, version) {
                (Some(name), Some(version)) => self
                    .by_name_version
                    .get(&format!("{name}@{version}"))
                    .copied(),
                _ => None,
            })
    }

    /// Claim the entry for one install location, keyed on `location` first and
    /// `name@version` second, and mark it consumed.
    ///
    /// A second claimant of the same entry is allowed here because both callers
    /// are the NEGATIVE and coverage buckets, where over-applying npm's verdict
    /// to a duplicate install of the same `name@version` errs toward reporting
    /// the failure rather than hiding it.
    fn take(
        &mut self,
        location: &str,
        name: Option<&str>,
        version: Option<&str>,
    ) -> Option<&'a NpmAuditEntry> {
        let index = self.lookup(location, name, version)?;
        self.consumed[index] = true;
        Some(&self.entries[index])
    }

    /// Claim the entry only if nothing has claimed it yet.
    ///
    /// For the `verified` bucket, where the opposite of [`Self::take`] is true:
    /// a POSITIVE result must not be borrowed by a second package just because
    /// it shares a `name@version` with the one npm actually named.
    fn take_fresh(
        &mut self,
        location: &str,
        name: Option<&str>,
        version: Option<&str>,
    ) -> Option<&'a NpmAuditEntry> {
        let index = self.lookup(location, name, version)?;
        if self.consumed[index] {
            return None;
        }
        self.consumed[index] = true;
        Some(&self.entries[index])
    }

    fn unconsumed(&self) -> impl Iterator<Item = &'a NpmAuditEntry> + '_ {
        self.entries
            .iter()
            .enumerate()
            .filter(|(index, _)| !self.consumed[*index])
            .map(|(_, entry)| entry)
    }
}

/// npm's three buckets, indexed together.
struct AuditIndex<'a> {
    invalid: AuditBucket<'a>,
    missing: AuditBucket<'a>,
    verified: AuditBucket<'a>,
}

impl<'a> AuditIndex<'a> {
    fn new(report: &'a NpmAuditReport) -> Self {
        Self {
            invalid: AuditBucket::new(&report.invalid),
            missing: AuditBucket::new(&report.missing),
            verified: AuditBucket::new(&report.verified),
        }
    }
}

/// The host npm reported for one audit entry, comparable with a lockfile host.
fn audit_host_of(entry: &NpmAuditEntry) -> Option<String> {
    entry.registry.as_deref().and_then(registry_host_of)
}

/// Reconcile the lockfile, the install tree, and npm's audit report into one
/// per-package ledger.
///
/// `audit` is `None` when no audit command ran (unsupported npm version,
/// offline, a spawn failure). Every eligible package is then `NotAudited`,
/// which is honest and forces Partial; it is never silently clean.
///
/// The accounting rules:
///
/// * every LOCKFILE entry gets a record, including the non-registry ones, so a
///   git or workspace dependency is explicit rather than dropped;
/// * every INSTALLED package with no lockfile entry is counted as unaccounted,
///   and npm's own verdict for it is honoured before it is called uncovered;
/// * every audit entry that matched NOTHING gets its own record, so a signature
///   failure npm reported can never be dropped on the floor;
/// * a registry entry npm did not name in `invalid`, `missing`, or `verified` is
///   `NotAudited`; omission is never positive evidence.
pub fn reconcile(
    lockfile: &NpmLockfile,
    inventory: &InstalledInventory,
    audit: Option<&NpmAuditReport>,
) -> NpmAssessment {
    let installed: BTreeMap<&str, &InstalledPackage> = inventory
        .packages
        .iter()
        .map(|package| (package.location.as_str(), package))
        .collect();

    let mut index = audit.map(AuditIndex::new);
    let mut records = Vec::new();
    let mut registry_entries = 0usize;
    let mut unsupported_source_entries = 0usize;
    // A set, not a Vec: a large monorepo install tree reaches tens of
    // thousands of entries, and a linear membership scan per installed package
    // would make the accounting quadratic in exactly the case where the
    // accounting matters most.
    let mut accounted_locations: std::collections::BTreeSet<&str> =
        std::collections::BTreeSet::new();

    for entry in &lockfile.entries {
        let is_installed = installed.contains_key(entry.location.as_str());
        if is_installed {
            accounted_locations.insert(entry.location.as_str());
        }
        let mut audit_registry_host = None;
        let status = if entry.source != NpmSourceKind::Registry {
            unsupported_source_entries += 1;
            NpmPackageStatus::UnsupportedSource {
                kind: entry.source,
                reason: format!(
                    "installed from a {} source, which npm's registry signature audit does not \
                     cover",
                    entry.source.label()
                ),
            }
        } else {
            registry_entries += 1;
            match index.as_mut() {
                None => NpmPackageStatus::NotAudited {
                    reason: "no audit command ran for this project".to_string(),
                },
                Some(index) => {
                    let (status, host) = status_from_index(index, entry);
                    audit_registry_host = host;
                    status
                }
            }
        };
        records.push(NpmPackageRecord {
            location: entry.location.clone(),
            name: entry.name.clone(),
            alias: entry.alias.clone(),
            version: entry.version.clone(),
            source: entry.source,
            registry_host: entry.registry_host.clone(),
            audit_registry_host,
            lockfile_integrity: entry.integrity.clone(),
            installed: is_installed,
            status,
        });
    }

    let mut unaccounted_locations = Vec::new();
    let mut unaccounted_installed = 0usize;
    for package in &inventory.packages {
        if accounted_locations.contains(package.location.as_str()) {
            continue;
        }
        unaccounted_installed += 1;
        if unaccounted_locations.len() < MAX_REPORTED_UNACCOUNTED {
            unaccounted_locations.push(package.location.clone());
        }
        // npm's verdict for this location is already parsed and sitting in the
        // report. Calling the package "not covered by the audit" without
        // looking would downgrade a tamper report into the bucket operators are
        // told to tolerate.
        let (status, audit_registry_host) = match index.as_mut() {
            None => (unaccounted_status(), None),
            Some(index) => status_for_unaccounted(index, package),
        };
        records.push(NpmPackageRecord {
            location: package.location.clone(),
            name: package
                .name
                .clone()
                .or_else(|| package_name_from_location(&package.location))
                .unwrap_or_else(|| package.location.clone()),
            // An unaccounted entry has no lockfile record, so there is no
            // declared name to compare the location spelling against.
            alias: None,
            version: package.version.clone(),
            source: NpmSourceKind::Unknown,
            registry_host: None,
            audit_registry_host,
            lockfile_integrity: None,
            installed: true,
            status,
        });
    }

    // Everything npm said that the binding could not consume. Nothing else in
    // this module walks the buckets, so without this an `invalid` entry whose
    // location matches no lockfile entry (a stale lockfile, a non-registry
    // classification, an npm location spelling Tirith did not model) would be
    // parsed, counted by nobody, and reported as clean.
    let mut unmatched_audit_entries = 0usize;
    if let Some(index) = index.as_ref() {
        for (entry, status) in index
            .invalid
            .unconsumed()
            .map(|entry| (entry, unmatched_invalid_status(entry)))
            .chain(
                index
                    .missing
                    .unconsumed()
                    .map(|entry| (entry, unmatched_missing_status())),
            )
            .chain(
                index
                    .verified
                    .unconsumed()
                    .map(|entry| (entry, unmatched_verified_status())),
            )
        {
            unmatched_audit_entries += 1;
            records.push(NpmPackageRecord {
                location: entry.location.clone().unwrap_or_else(|| entry.name.clone()),
                name: entry.name.clone(),
                alias: None,
                version: entry.version.clone(),
                source: NpmSourceKind::Unknown,
                registry_host: None,
                audit_registry_host: audit_host_of(entry),
                lockfile_integrity: None,
                installed: false,
                status,
            });
        }
    }

    records.sort_by(|a, b| a.location.cmp(&b.location));

    NpmAssessment {
        coverage: NpmCoverage {
            accounted_installed: accounted_locations.len(),
            unaccounted_installed,
            unaccounted_locations,
            registry_entries,
            unsupported_source_entries,
            inventory_capped: inventory.capped,
            symlinked_entries_skipped: inventory.symlinked_entries,
            unmatched_audit_entries,
            signature_only_derived_by_subtraction: false,
        },
        records,
    }
}

fn unaccounted_status() -> NpmPackageStatus {
    NpmPackageStatus::NotAudited {
        reason: "installed but absent from package-lock.json, so the audit result cannot be bound \
                 to it"
            .to_string(),
    }
}

fn unmatched_invalid_status(entry: &NpmAuditEntry) -> NpmPackageStatus {
    NpmPackageStatus::Invalid {
        code: entry.code.clone().unwrap_or_else(|| "EUNKNOWN".to_string()),
        reason: "npm reported an invalid registry signature or attestation for an install \
                 location this project's package-lock.json and node_modules do not account for"
            .to_string(),
    }
}

fn unmatched_missing_status() -> NpmPackageStatus {
    NpmPackageStatus::Missing {
        reason: "npm reported a missing registry signature for an install location this project's \
                 package-lock.json and node_modules do not account for"
            .to_string(),
    }
}

fn unmatched_verified_status() -> NpmPackageStatus {
    NpmPackageStatus::NotAudited {
        reason: "npm reported a verified attestation for an install location this project's \
                 package-lock.json and node_modules do not account for, so the result binds to \
                 nothing"
            .to_string(),
    }
}

/// Decide one registry entry's status from npm's buckets.
///
/// Bucket precedence is worst-first: `invalid` beats `missing` beats
/// `verified`. Absence from all three is `NotAudited`, even for an installed
/// package from the public registry.
///
/// Returns the status and the registry host NPM ITSELF named, which is not the
/// lockfile's: npm picks the registry from config, so a positive result against
/// a host the lockfile does not resolve from covers different bytes than the
/// ones this project installs.
fn status_from_index(
    index: &mut AuditIndex<'_>,
    entry: &NpmLockfileEntry,
) -> (NpmPackageStatus, Option<String>) {
    let name = Some(entry.name.as_str());
    let version = entry.version.as_deref();
    if let Some(found) = index.invalid.take(&entry.location, name, version) {
        // A negative verdict is never softened by a host disagreement.
        return (
            NpmPackageStatus::Invalid {
                code: found.code.clone().unwrap_or_else(|| "EUNKNOWN".to_string()),
                reason: "npm reported an invalid registry signature or attestation".to_string(),
            },
            audit_host_of(found),
        );
    }
    if let Some(found) = index.missing.take(&entry.location, name, version) {
        let host = audit_host_of(found);
        if let Some(status) = divergent_registry_status(entry, host.as_deref()) {
            return (status, host);
        }
        return (
            NpmPackageStatus::Missing {
                reason: "the registry provides signing keys but published no signature for this \
                         release"
                    .to_string(),
            },
            host,
        );
    }
    if let Some(found) = index.verified.take_fresh(&entry.location, name, version) {
        let host = audit_host_of(found);
        let binding = bind_attested_subject(&found.attested_digests, entry.integrity.as_deref());
        if binding == SubjectBinding::Mismatch {
            return (
                NpmPackageStatus::Invalid {
                    code: "ESUBJECTINTEGRITY".to_string(),
                    reason: "the attestation's in-toto subject digest does not match the \
                             integrity this package-lock.json pins, so the attestation covers \
                             different bytes"
                        .to_string(),
                },
                host,
            );
        }
        if let Some(status) = divergent_registry_status(entry, host.as_deref()) {
            return (status, host);
        }
        return (
            NpmPackageStatus::ProvenanceVerified {
                predicate_types: found.predicate_types.clone(),
                subject_bound: binding == SubjectBinding::Bound,
            },
            host,
        );
    }
    (
        NpmPackageStatus::NotAudited {
            reason: "npm did not name this package in an explicit invalid, missing, or verified \
                     audit bucket, so its signature status is unknown"
                .to_string(),
        },
        None,
    )
}

/// Refuse to read a positive npm result as covering this entry when npm named a
/// DIFFERENT registry than the lockfile resolves the package from.
///
/// npm's registry comes from config (`.npmrc`, environment, CLI), so a hostile
/// or merely misconfigured project can point the audit at a host that has
/// nothing to do with the bytes the lockfile pins.
fn divergent_registry_status(
    entry: &NpmLockfileEntry,
    audit_host: Option<&str>,
) -> Option<NpmPackageStatus> {
    let (lockfile_host, audit_host) = (entry.registry_host.as_deref()?, audit_host?);
    if lockfile_host == audit_host {
        return None;
    }
    Some(NpmPackageStatus::NotAudited {
        reason: format!(
            "npm audited this package against {audit_host}, which is not the {lockfile_host} the \
             package-lock.json resolves it from, so its result does not cover the pinned bytes"
        ),
    })
}

/// Decide the status of an INSTALLED package with no lockfile entry, honouring
/// whatever npm already said about that install location.
fn status_for_unaccounted(
    index: &mut AuditIndex<'_>,
    package: &InstalledPackage,
) -> (NpmPackageStatus, Option<String>) {
    let name = package.name.as_deref();
    let version = package.version.as_deref();
    if let Some(found) = index.invalid.take(&package.location, name, version) {
        return (
            NpmPackageStatus::Invalid {
                code: found.code.clone().unwrap_or_else(|| "EUNKNOWN".to_string()),
                reason: "npm reported an invalid registry signature or attestation for this \
                         installed package, which package-lock.json does not pin"
                    .to_string(),
            },
            audit_host_of(found),
        );
    }
    if let Some(found) = index.missing.take(&package.location, name, version) {
        return (
            NpmPackageStatus::Missing {
                reason: "npm reported a missing registry signature for this installed package, \
                         which package-lock.json does not pin"
                    .to_string(),
            },
            audit_host_of(found),
        );
    }
    if let Some(found) = index.verified.take_fresh(&package.location, name, version) {
        // No lockfile entry means no `integrity` to bind the attested subject
        // digest to, so this is a coverage statement, not a verified one.
        return (
            NpmPackageStatus::NotAudited {
                reason: "npm reported a verified attestation, but the package is absent from \
                         package-lock.json, so there is no pinned integrity to bind it to"
                    .to_string(),
            },
            audit_host_of(found),
        );
    }
    (unaccounted_status(), None)
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

/// Schema version of [`NpmProvenanceReceipt`].
pub const NPM_PROVENANCE_RECEIPT_SCHEMA: u32 = 2;

/// Stable discriminator so a reader can tell this envelope from the capsule and
/// browser-baseline receipts that share the same canonicalizer.
pub const NPM_PROVENANCE_RECEIPT_TYPE: &str = "npm_provenance";

/// The trusted executables the run actually used.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmToolIdentity {
    /// sha256 of the resolved npm image (or of the npm CLI script when npm is a
    /// shebang script). No path: a receipt is shareable and a path names the
    /// operator's machine layout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub npm_sha256: Option<String>,
    /// The version npm reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub npm_version: Option<String>,
    /// sha256 of the interpreter, when npm resolved to a script and Tirith
    /// resolved and bound its interpreter explicitly rather than letting the
    /// shebang pick one off PATH.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpreter_sha256: Option<String>,
    /// The interpreter's program NAME (`node`), never its path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpreter_name: Option<String>,
}

/// The registry/configuration boundary under which npm produced its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmAuditMode {
    /// Public npm audit with user/global config, proxies, and auth removed.
    HermeticPublicRegistry,
    /// Explicit operator-trusted private registry configuration.
    TrustedPrivateRegistry,
}

impl NpmAuditMode {
    /// Stable human-readable spelling.
    pub fn label(self) -> &'static str {
        match self {
            Self::HermeticPublicRegistry => "hermetic-public-registry",
            Self::TrustedPrivateRegistry => "trusted-private-registry",
        }
    }
}

/// Non-secret identities for every transport input that can change what npm
/// audits. The npm and Node executable identities live in [`NpmToolIdentity`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmAuditEnvironment {
    pub mode: NpmAuditMode,
    /// Canonical HTTPS registry origin, with no credentials, query, or fragment.
    pub registry_origin: String,
    /// Always true in a runnable mode. Kept explicit so a receipt cannot omit
    /// the TLS decision that authenticated the registry.
    pub strict_tls: bool,
    /// `system_roots` or a sha256 identity for an explicitly selected CA file.
    pub tls_ca_identity: String,
    /// `direct` or a sha256 identity for the credential-free proxy origin.
    pub proxy_identity: String,
    /// `none` in public mode or a metadata identity for the snapshotted private
    /// auth source. Never credential bytes, a credential hash, or a host path.
    pub auth_source_identity: String,
}

impl NpmAuditEnvironment {
    fn is_complete_and_safe(&self) -> bool {
        let Ok(url) = url::Url::parse(&self.registry_origin) else {
            return false;
        };
        let canonical_origin = url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/"
            && url.to_string() == self.registry_origin;
        if !canonical_origin
            || !self.strict_tls
            || self.auth_source_identity.is_empty()
            || !(self.tls_ca_identity == "system_roots"
                || is_sha256_identity(&self.tls_ca_identity))
            || !(self.proxy_identity == "direct" || is_sha256_identity(&self.proxy_identity))
        {
            return false;
        }
        match self.mode {
            NpmAuditMode::HermeticPublicRegistry => {
                self.registry_origin == PUBLIC_NPM_REGISTRY_ORIGIN
                    && self.tls_ca_identity == "system_roots"
                    && self.proxy_identity == "direct"
                    && self.auth_source_identity == "none"
            }
            NpmAuditMode::TrustedPrivateRegistry => {
                self.registry_origin != PUBLIC_NPM_REGISTRY_ORIGIN
                    && is_sha256_identity(&self.auth_source_identity)
            }
        }
    }
}

fn is_sha256_identity(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

/// The exact command the contract authorized, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmAuditInvocation {
    /// The contract id from [`NPM_AUDIT_SIGNATURES_CONTRACTS`].
    pub contract_id: String,
    /// The version range the contract covers.
    pub version_range: String,
    /// The exact argv, recorded verbatim. Safe to record in full because every
    /// element is a compile-time constant: nothing from the project, the
    /// lockfile, or the environment can appear here.
    pub argv: Vec<String>,
    /// Whether the argv returns attestation bundles.
    pub attestation_bundles_available: bool,
    /// Exact non-secret transport/configuration binding for this invocation.
    /// Absent only when deserializing a legacy schema-1 receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<NpmAuditEnvironment>,
    /// npm's own exit code, when the command ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Bounded, redacted npm stderr, when it wrote any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
}

/// What the receipt binds the answer to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmReceiptSubject {
    /// The lockfile file name (`package-lock.json`).
    pub lockfile_name: String,
    /// sha256 of the EXACT lockfile bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockfile_sha256: Option<String>,
    /// The lockfile's declared `lockfileVersion`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lockfile_version: Option<u64>,
    /// The project's own package name, when the lockfile declares one. Not a
    /// path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_name: Option<String>,
    /// Every registry host the lockfile resolves from, userinfo-redacted.
    pub registry_hosts: Vec<String>,
    /// Every registry host NPM ITSELF reported, userinfo-redacted.
    ///
    /// Empty when npm named no package in any bucket, which is the normal case
    /// for a project with no attestations and no failures. Recorded separately
    /// from [`Self::registry_hosts`] because npm picks its registry from config,
    /// not from the lockfile, so the two are different claims.
    #[serde(default)]
    pub audit_registry_hosts: Vec<String>,
    /// Whether the audited project carries its own `.npmrc`. npm reads it from
    /// the audit child's working directory, above the user and global config, so
    /// its presence means the audited project had a say in how it was audited.
    #[serde(default)]
    pub project_npmrc_present: bool,
    /// How many packages the install tree carried.
    pub installed_package_count: usize,
}

/// A content-addressed, optionally ed25519-signed npm provenance receipt.
///
/// Follows [`crate::browser_extensions::BrowserBaseline`] and
/// [`crate::capsule_receipt::CapsuleRunReceipt`] exactly: the same
/// canonicalizer ([`crate::audit::canonical_json_for_hash`]), the same content
/// address (sha256 over the canonical JSON with `receipt_id` and `signature`
/// blanked), and the same signing key and routine
/// ([`crate::audit::sign_canonical_bytes`]), so there is one signing path in
/// the product and no second crypto dependency.
///
/// It is NOT anchored in the audit hash chain. The chain's receipt anchors are
/// typed to the install-shaped [`crate::receipt::ArtifactScanReceipt`] and the
/// capsule receipt; widening one of them for a diagnostic attestation would
/// change a frozen contract for an unrelated slice. [`Self::audit_chain_anchored`]
/// records that plainly rather than leaving a reader to assume tamper evidence
/// this document does not have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmProvenanceReceipt {
    pub schema: u32,
    pub receipt_type: String,
    /// sha256 over the canonical JSON with `receipt_id` and `signature` blanked.
    pub receipt_id: String,
    pub created_at: String,
    pub tirith_version: String,
    pub engine_build_sha: String,
    /// [`crate::policy::Policy::security_projection_hash`], never the raw
    /// policy.
    pub policy_projection_hash: String,
    /// The overall answer.
    pub outcome: NpmAttestOutcome,
    /// Whether `--require-provenance` tightened the contract.
    pub require_provenance: bool,
    /// What the answer is bound to.
    pub subject: NpmReceiptSubject,
    /// Which npm ran, and how it was identified.
    pub tools: NpmToolIdentity,
    /// The exact authorized command, or `None` when no audit command ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation: Option<NpmAuditInvocation>,
    /// The per-package ledger.
    pub packages: Vec<NpmPackageRecord>,
    /// What was and was not accounted for.
    pub coverage: NpmCoverage,
    /// The honesty statements this receipt must never be read without.
    pub caveats: Vec<String>,
    /// Always `false` in this schema; see the type documentation.
    pub audit_chain_anchored: bool,
    /// Base64 ed25519 signature over the canonical JSON with `signature`
    /// blanked. `None` when no signing key is configured.
    pub signature: Option<String>,
}

/// Everything [`NpmProvenanceReceipt::new`] needs, grouped so the assembly site
/// reads as one record.
#[derive(Debug, Clone)]
pub struct NpmReceiptFacts {
    pub policy_projection_hash: String,
    pub outcome: NpmAttestOutcome,
    pub require_provenance: bool,
    pub subject: NpmReceiptSubject,
    pub tools: NpmToolIdentity,
    pub invocation: Option<NpmAuditInvocation>,
    pub assessment: NpmAssessment,
}

/// Why a receipt could not be assembled or saved.
#[derive(Debug)]
pub enum NpmReceiptError {
    /// The receipt is not internally consistent. Raised before any write.
    Invalid(String),
    /// Writing the receipt failed.
    Io(std::io::Error),
}

impl std::fmt::Display for NpmReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "refusing an invalid npm receipt: {reason}"),
            Self::Io(error) => write!(f, "npm receipt I/O failed: {error}"),
        }
    }
}

impl std::error::Error for NpmReceiptError {}

impl NpmProvenanceReceipt {
    /// Assemble, stamp the content address, and sign when a key is available.
    pub fn new(facts: NpmReceiptFacts) -> Self {
        let mut receipt = Self {
            schema: NPM_PROVENANCE_RECEIPT_SCHEMA,
            receipt_type: NPM_PROVENANCE_RECEIPT_TYPE.to_string(),
            receipt_id: String::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
            tirith_version: env!("CARGO_PKG_VERSION").to_string(),
            engine_build_sha: crate::receipt::engine_build_sha().to_string(),
            policy_projection_hash: facts.policy_projection_hash,
            outcome: facts.outcome,
            require_provenance: facts.require_provenance,
            subject: facts.subject,
            tools: facts.tools,
            invocation: facts.invocation,
            packages: facts.assessment.records,
            coverage: facts.assessment.coverage,
            caveats: vec![
                NPM_CLEAN_IS_NOT_BENIGN_CAVEAT.to_string(),
                crate::provenance::npm_facts::NPM_BYTES_NOT_BOUND_CAVEAT.to_string(),
                "npm performed its own network requests to the registry; those requests are \
                 outside tirith's fetch validator, redirect policy, and capsule broker"
                    .to_string(),
            ],
            audit_chain_anchored: false,
            signature: None,
        };
        receipt.receipt_id = receipt.compute_content_hash();
        receipt.signature =
            crate::audit::sign_canonical_bytes(receipt.signing_payload().as_bytes());
        receipt
    }

    /// The canonical JSON the signature covers: the whole receipt with the
    /// signature blanked and the content address PRESENT, so the signature
    /// binds the content address rather than floating free of it.
    pub fn signing_payload(&self) -> String {
        self.canonical_json(false)
    }

    /// Lowercase-hex sha256 of the canonical JSON with `receipt_id` and
    /// `signature` blanked.
    pub fn compute_content_hash(&self) -> String {
        crate::command_card::sha256_hex(self.canonical_json(true).as_bytes())
    }

    fn canonical_json(&self, blank_receipt_id: bool) -> String {
        let serialized = serde_json::to_value(self);
        debug_assert!(
            serialized.is_ok(),
            "npm provenance receipt failed to serialize; a field is not serializable"
        );
        let mut value = serialized.unwrap_or(serde_json::Value::Null);
        if let Some(object) = value.as_object_mut() {
            if blank_receipt_id {
                object.insert(
                    "receipt_id".to_string(),
                    serde_json::Value::String(String::new()),
                );
            }
            object.insert("signature".to_string(), serde_json::Value::Null);
        }
        crate::audit::canonical_json_for_hash(&value)
    }

    /// Whether the stored id still matches a recomputation over the content.
    pub fn content_hash_matches(&self) -> bool {
        self.receipt_id == self.compute_content_hash()
    }

    /// Verify the detached signature against an ed25519 public key. `false` for
    /// an absent, malformed, or non-verifying signature, so a caller cannot
    /// read "unsigned" as "verified".
    pub fn signature_verifies(&self, public_key: &[u8; 32]) -> bool {
        use base64::Engine as _;
        use ed25519_dalek::Verifier as _;

        let Some(encoded) = self.signature.as_deref() else {
            return false;
        };
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            return false;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&bytes) else {
            return false;
        };
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        key.verify(self.signing_payload().as_bytes(), &signature)
            .is_ok()
    }

    /// Every honesty invariant, checked before the receipt reaches a file.
    ///
    /// The load-bearing rule is the [`NpmAttestOutcome::Clean`] gate: a clean
    /// receipt requires an audit command to have actually run under a contract,
    /// every package to be signature-covered, and nothing to be unaccounted
    /// for. A receipt that claims otherwise cannot be written.
    pub fn validate(&self) -> Result<(), NpmReceiptError> {
        if self.schema != NPM_PROVENANCE_RECEIPT_SCHEMA {
            return Err(NpmReceiptError::Invalid(format!(
                "unsupported npm receipt schema {}",
                self.schema
            )));
        }
        if self.receipt_type != NPM_PROVENANCE_RECEIPT_TYPE {
            return Err(NpmReceiptError::Invalid(
                "receipt_type is not an npm provenance receipt".to_string(),
            ));
        }
        if !self.content_hash_matches() {
            return Err(NpmReceiptError::Invalid(
                "receipt_id does not match the canonical receipt content".to_string(),
            ));
        }
        if !self
            .caveats
            .iter()
            .any(|caveat| caveat == NPM_CLEAN_IS_NOT_BENIGN_CAVEAT)
        {
            return Err(NpmReceiptError::Invalid(
                "the receipt must carry the clean-is-not-benign caveat".to_string(),
            ));
        }
        if self.audit_chain_anchored {
            return Err(NpmReceiptError::Invalid(
                "this schema is never audit-chain anchored, so it cannot claim to be".to_string(),
            ));
        }
        if self.invocation.as_ref().is_some_and(|invocation| {
            !invocation
                .environment
                .as_ref()
                .is_some_and(NpmAuditEnvironment::is_complete_and_safe)
        }) {
            return Err(NpmReceiptError::Invalid(
                "an npm invocation requires a complete safe audit-environment binding".to_string(),
            ));
        }
        if matches!(self.outcome, NpmAttestOutcome::Clean) {
            // An exit code is the proof a process existed. `invocation` alone is
            // not: it also describes the command that WOULD have run.
            if !self
                .invocation
                .as_ref()
                .is_some_and(|invocation| invocation.exit_code.is_some())
            {
                return Err(NpmReceiptError::Invalid(
                    "a clean receipt requires an audit command to have run to completion under a \
                     contract"
                        .to_string(),
                ));
            }
            if self.subject.lockfile_sha256.is_none() {
                return Err(NpmReceiptError::Invalid(
                    "a clean receipt requires the lockfile digest it is bound to".to_string(),
                ));
            }
            if self.tools.npm_sha256.is_none() || self.tools.npm_version.is_none() {
                return Err(NpmReceiptError::Invalid(
                    "a clean receipt requires the exact npm executable digest and version"
                        .to_string(),
                ));
            }
            if self.tools.interpreter_name.is_some() != self.tools.interpreter_sha256.is_some() {
                return Err(NpmReceiptError::Invalid(
                    "a clean receipt must bind both the Node interpreter name and digest, or neither"
                        .to_string(),
                ));
            }
            if self.coverage.unaccounted_installed > 0 {
                return Err(NpmReceiptError::Invalid(
                    "a clean receipt cannot leave an installed package unaccounted for".to_string(),
                ));
            }
            if self.coverage.inventory_capped {
                return Err(NpmReceiptError::Invalid(
                    "a clean receipt cannot come from a capped install-tree walk".to_string(),
                ));
            }
            if let Some(record) = self
                .packages
                .iter()
                .find(|record| !record.status.is_signature_covered())
            {
                return Err(NpmReceiptError::Invalid(format!(
                    "a clean receipt cannot carry a {} package",
                    record.status.label()
                )));
            }
            if self.require_provenance
                && self
                    .packages
                    .iter()
                    .any(|record| !record.status.is_provenance_verified())
            {
                return Err(NpmReceiptError::Invalid(
                    "a --require-provenance clean receipt requires every package to carry a \
                     verified attestation"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Serialize for publication.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Validate, then write the receipt atomically at mode 0600.
    pub fn write_to(&self, path: &Path) -> Result<(), NpmReceiptError> {
        self.validate()?;
        crate::util::write_file_atomic_0600(path, self.to_json().as_bytes())
            .map_err(NpmReceiptError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry_entry(location: &str, name: &str, version: &str) -> NpmLockfileEntry {
        NpmLockfileEntry {
            location: location.to_string(),
            name: name.to_string(),
            alias: None,
            version: Some(version.to_string()),
            source: NpmSourceKind::Registry,
            integrity: Some("sha512-aaaa".to_string()),
            registry_host: Some("registry.npmjs.org".to_string()),
            dev: false,
        }
    }

    fn installed(locations: &[&str]) -> InstalledInventory {
        InstalledInventory {
            packages: locations
                .iter()
                .map(|location| InstalledPackage {
                    location: (*location).to_string(),
                    name: None,
                    version: None,
                })
                .collect(),
            capped: false,
            symlinked_entries: 0,
        }
    }

    // -- contract table ----------------------------------------------------

    #[test]
    fn every_contract_range_parses_and_the_table_is_sorted_and_disjoint() {
        let mut previous: Option<ReleaseVersion> = None;
        for contract in NPM_AUDIT_SIGNATURES_CONTRACTS {
            let constraint = VersionConstraint::parse(contract.version_range)
                .unwrap_or_else(|| panic!("range {} must parse", contract.version_range));
            assert!(
                !contract.id.is_empty() && !contract.fixture.is_empty(),
                "every contract declares an id and a fixture"
            );
            assert!(
                !contract.argv.is_empty(),
                "every contract declares a non-empty argv"
            );
            // The lower bound of each range, used for the ordering check.
            let lower = contract
                .version_range
                .split(',')
                .find_map(|clause| clause.trim().strip_prefix(">="))
                .and_then(ReleaseVersion::parse)
                .expect("every range declares a >= lower bound");
            assert!(constraint.matches(&lower), "the lower bound is in range");
            if let Some(previous) = previous.as_ref() {
                assert!(
                    &lower > previous,
                    "contract ranges must be sorted ascending and non-overlapping"
                );
            }
            previous = Some(lower);
        }
    }

    #[test]
    fn contract_argv_carries_no_shell_metacharacter_and_no_interpolation() {
        for contract in NPM_AUDIT_SIGNATURES_CONTRACTS {
            for arg in contract.argv {
                assert!(
                    !arg.bytes().any(|b| matches!(
                        b,
                        b';' | b'|'
                            | b'&'
                            | b'$'
                            | b'`'
                            | b'>'
                            | b'<'
                            | b'('
                            | b')'
                            | b'\n'
                            | b'\r'
                            | b'*'
                            | b'?'
                            | b'\''
                            | b'"'
                            | b'\\'
                    )),
                    "argv element {arg:?} must carry no shell metacharacter"
                );
                assert!(
                    !arg.contains('{') && !arg.contains('}'),
                    "argv element {arg:?} must not look interpolated"
                );
                assert!(arg.is_ascii(), "argv element {arg:?} must be ASCII");
            }
        }
    }

    #[test]
    fn the_npm_11_contract_argv_is_byte_exact() {
        let contract = select_contract("11.17.0").expect("npm 11.17.0 is covered");
        assert_eq!(
            contract.argv,
            &["audit", "signatures", "--json", "--include-attestations"]
        );
        assert_eq!(contract.id, "npm-11-audit-signatures-include-attestations");
        assert_eq!(
            contract.schema,
            NpmAuditJsonSchema::BucketsWithAttestedVerified
        );
        assert!(contract.attestation_bundles_available);
    }

    #[test]
    fn a_version_outside_every_range_selects_no_contract() {
        // npm 10 and older: no captured fixture, so no contract, so no audit
        // command. npm 12 and newer: same. This is the no-speculative-probe
        // gate, and it is a pure function so it needs no process to prove.
        for version in ["6.14.18", "8.19.4", "9.9.4", "10.9.2", "12.0.0", "99.0.0"] {
            assert!(
                select_contract(version).is_none(),
                "{version} must select no contract"
            );
        }
    }

    #[test]
    fn a_prerelease_or_unparseable_version_selects_no_contract() {
        for version in ["11.0.0-pre.1", "v11.0.0", "", "11.x", "not-a-version"] {
            assert!(
                select_contract(version).is_none(),
                "{version:?} must select no contract"
            );
        }
    }

    #[test]
    fn version_probe_output_is_bounded_and_numeric() {
        assert_eq!(parse_npm_version("11.17.0\n").as_deref(), Some("11.17.0"));
        assert_eq!(
            parse_npm_version("11.17.0\nextra\n").as_deref(),
            Some("11.17.0"),
            "only the first line is read"
        );
        assert!(parse_npm_version("").is_none());
        assert!(parse_npm_version("   \n").is_none());
        assert!(parse_npm_version("11.0.0-beta").is_none());
        assert!(parse_npm_version(&"9".repeat(300)).is_none());
    }

    // -- overall outcome matrix -------------------------------------------

    fn signature_only() -> NpmPackageStatus {
        NpmPackageStatus::SignatureOnly {
            reason: "derived".to_string(),
        }
    }

    fn provenance_verified() -> NpmPackageStatus {
        NpmPackageStatus::ProvenanceVerified {
            predicate_types: vec!["https://slsa.dev/provenance/v1".to_string()],
            subject_bound: true,
        }
    }

    #[test]
    fn all_signature_only_is_clean_by_default_and_partial_under_require_provenance() {
        let statuses = vec![signature_only(), signature_only()];
        assert_eq!(overall_outcome(&statuses, false), NpmAttestOutcome::Clean);
        match overall_outcome(&statuses, true) {
            NpmAttestOutcome::Partial { reason, .. } => {
                assert_eq!(reason, NpmPartialReason::ProvenanceRequiredButAbsent);
            }
            other => panic!("expected Partial, got {other:?}"),
        }
    }

    #[test]
    fn all_provenance_verified_is_clean_under_both_contracts() {
        let statuses = vec![provenance_verified(), provenance_verified()];
        assert_eq!(overall_outcome(&statuses, false), NpmAttestOutcome::Clean);
        assert_eq!(overall_outcome(&statuses, true), NpmAttestOutcome::Clean);
    }

    #[test]
    fn an_invalid_entry_is_a_mismatch_regardless_of_the_flag() {
        let statuses = vec![
            provenance_verified(),
            NpmPackageStatus::Invalid {
                code: "EINTEGRITYSIGNATURE".to_string(),
                reason: "bad".to_string(),
            },
        ];
        for require in [false, true] {
            assert!(
                matches!(
                    overall_outcome(&statuses, require),
                    NpmAttestOutcome::Mismatch { .. }
                ),
                "require_provenance={require}"
            );
        }
        assert_eq!(
            overall_outcome(&statuses, false).exit_code(),
            1,
            "a mismatch exits 1"
        );
    }

    #[test]
    fn a_subject_integrity_mismatch_is_a_mismatch() {
        let statuses = vec![NpmPackageStatus::Invalid {
            code: "ESUBJECTINTEGRITY".to_string(),
            reason: "the attestation covers different bytes".to_string(),
        }];
        assert!(matches!(
            overall_outcome(&statuses, false),
            NpmAttestOutcome::Mismatch { .. }
        ));
    }

    #[test]
    fn missing_not_audited_and_unsupported_source_are_never_clean() {
        let cases: Vec<(NpmPackageStatus, NpmPartialReason)> = vec![
            (
                NpmPackageStatus::Missing {
                    reason: "no signature".to_string(),
                },
                NpmPartialReason::MissingSignature,
            ),
            (
                NpmPackageStatus::NotAudited {
                    reason: "no audit ran".to_string(),
                },
                NpmPartialReason::NotAudited,
            ),
            (
                NpmPackageStatus::UnsupportedSource {
                    kind: NpmSourceKind::Git,
                    reason: "git".to_string(),
                },
                NpmPartialReason::UnsupportedSource,
            ),
        ];
        for (status, expected) in cases {
            let statuses = vec![provenance_verified(), status.clone()];
            for require in [false, true] {
                match overall_outcome(&statuses, require) {
                    NpmAttestOutcome::Partial { reason, .. } => assert_eq!(
                        reason,
                        expected,
                        "{} with require_provenance={require}",
                        status.label()
                    ),
                    other => panic!("expected Partial for {}, got {other:?}", status.label()),
                }
            }
        }
    }

    #[test]
    fn an_empty_ledger_is_partial_not_clean() {
        match overall_outcome(&[], false) {
            NpmAttestOutcome::Partial { reason, .. } => {
                assert_eq!(reason, NpmPartialReason::NoEligiblePackages);
            }
            other => panic!("expected Partial, got {other:?}"),
        }
    }

    #[test]
    fn a_capped_walk_downgrades_clean_but_never_upgrades_a_worse_answer() {
        let clean = NpmAttestOutcome::Clean;
        match apply_coverage_gap(clean, Some("capped")) {
            NpmAttestOutcome::Partial { reason, .. } => {
                assert_eq!(reason, NpmPartialReason::CoverageCapped);
            }
            other => panic!("expected Partial, got {other:?}"),
        }
        assert_eq!(
            apply_coverage_gap(NpmAttestOutcome::Clean, None),
            NpmAttestOutcome::Clean
        );
        let mismatch = NpmAttestOutcome::Mismatch {
            detail: "bad".to_string(),
        };
        assert_eq!(
            apply_coverage_gap(mismatch.clone(), Some("capped")),
            mismatch,
            "a mismatch is never softened by a coverage note"
        );
    }

    #[test]
    fn exit_codes_are_the_documented_triad() {
        assert_eq!(NpmAttestOutcome::Clean.exit_code(), 0);
        assert_eq!(
            NpmAttestOutcome::Mismatch {
                detail: String::new()
            }
            .exit_code(),
            1
        );
        assert_eq!(
            NpmAttestOutcome::Partial {
                reason: NpmPartialReason::Offline,
                detail: String::new()
            }
            .exit_code(),
            3
        );
    }

    // -- strict JSON -------------------------------------------------------

    #[test]
    fn duplicate_trailing_truncated_and_empty_map_to_distinct_failures() {
        let schema = NpmAuditJsonSchema::BucketsWithAttestedVerified;
        assert_eq!(
            parse_audit_report(
                r#"{"invalid":[],"invalid":[],"missing":[],"verified":[]}"#,
                schema
            ),
            Err(NpmAuditParseError::DuplicateKey)
        );
        assert_eq!(
            parse_audit_report(
                r#"{"invalid":[],"missing":[],"verified":[]} {"x":1}"#,
                schema
            ),
            Err(NpmAuditParseError::Malformed)
        );
        assert_eq!(
            parse_audit_report(r#"{"invalid":[],"missing":[]"#, schema),
            Err(NpmAuditParseError::Malformed)
        );
        assert_eq!(
            parse_audit_report("", schema),
            Err(NpmAuditParseError::Empty)
        );
        assert_eq!(
            parse_audit_report(r#"{"invalid":[],"missing":[]}"#, schema),
            Err(NpmAuditParseError::SchemaMismatch),
            "the include-attestations contract requires the verified bucket"
        );
        assert_eq!(
            NpmAuditParseError::DuplicateKey.partial_reason(),
            NpmPartialReason::DuplicateJsonKey
        );
        assert_eq!(
            NpmAuditParseError::Malformed.partial_reason(),
            NpmPartialReason::ParseFailure
        );
    }

    #[test]
    fn npm_usage_text_never_parses_as_a_clean_report() {
        // npm 11 only WARNS on an unknown flag today, but its own warning says
        // "This will stop working in the next major version of npm". When an
        // npm does hard-error, its usage text lands on stdout/stderr and must
        // become a Partial, never a silent clean.
        let usage = "Unknown argument: --include-attestations\n\nUsage: npm audit [fix|signatures]";
        assert!(
            parse_audit_report(usage, NpmAuditJsonSchema::BucketsWithAttestedVerified).is_err()
        );
    }

    // -- lockfile ----------------------------------------------------------

    const LOCKFILE: &str = r#"{
      "name": "demo",
      "lockfileVersion": 3,
      "packages": {
        "": {"name": "demo", "version": "1.0.0"},
        "node_modules/chalk": {
          "version": "5.4.1",
          "resolved": "https://registry.npmjs.org/chalk/-/chalk-5.4.1.tgz",
          "integrity": "sha512-zgVZuo2WcZgf"
        },
        "node_modules/@scope/pkg": {
          "version": "2.0.0",
          "resolved": "https://registry.example:8443/@scope/pkg/-/pkg-2.0.0.tgz",
          "integrity": "sha512-abcd"
        },
        "node_modules/from-git": {
          "version": "1.0.0",
          "resolved": "git+ssh://git@github.com/owner/repo.git#deadbeef"
        },
        "node_modules/from-file": {
          "version": "1.0.0",
          "resolved": "file:../sibling"
        },
        "node_modules/linked": {"resolved": "", "link": true},
        "packages/member": {"name": "member", "version": "0.1.0"}
      }
    }"#;

    #[test]
    fn the_lockfile_reader_classifies_every_source_explicitly() {
        let lockfile = parse_package_lock(LOCKFILE).expect("lockfile parses");
        assert_eq!(lockfile.lockfile_version, 3);
        assert_eq!(lockfile.root_name.as_deref(), Some("demo"));
        let by_location: BTreeMap<&str, &NpmLockfileEntry> = lockfile
            .entries
            .iter()
            .map(|entry| (entry.location.as_str(), entry))
            .collect();
        assert_eq!(
            by_location["node_modules/chalk"].source,
            NpmSourceKind::Registry
        );
        assert_eq!(
            by_location["node_modules/chalk"].registry_host.as_deref(),
            Some("registry.npmjs.org")
        );
        assert_eq!(
            by_location["node_modules/@scope/pkg"].name, "@scope/pkg",
            "the scoped name comes from the location key"
        );
        assert_eq!(
            by_location["node_modules/@scope/pkg"]
                .registry_host
                .as_deref(),
            Some("registry.example:8443"),
            "a non-default port is part of the host"
        );
        assert_eq!(
            by_location["node_modules/from-git"].source,
            NpmSourceKind::Git
        );
        assert_eq!(
            by_location["node_modules/from-file"].source,
            NpmSourceKind::File
        );
        assert_eq!(
            by_location["node_modules/linked"].source,
            NpmSourceKind::Link
        );
        assert_eq!(
            by_location["packages/member"].source,
            NpmSourceKind::Workspace,
            "a packages entry with no resolved is a workspace member"
        );
        assert_eq!(lockfile.registry_hosts().len(), 2);
    }

    #[test]
    fn a_credential_bearing_resolved_url_never_leaks_its_userinfo() {
        let text = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": {"name": "demo"},
            "node_modules/private": {
              "version": "1.0.0",
              "resolved": "https://deploy:s3cr3t-token@registry.example/private/-/private-1.0.0.tgz",
              "integrity": "sha512-aaaa"
            }
          }
        }"#;
        let lockfile = parse_package_lock(text).expect("lockfile parses");
        let hosts = lockfile.registry_hosts();
        assert_eq!(hosts, vec!["registry.example".to_string()]);
        let serialized = serde_json::to_string(&lockfile).expect("serializes");
        assert!(
            !serialized.contains("s3cr3t-token") && !serialized.contains("deploy:"),
            "no credential may survive into the lockfile projection: {serialized}"
        );
    }

    /// An npm alias (`npm i foo@npm:bar`) installs `bar` at `node_modules/foo`.
    /// The canonical name is the security target; the location spelling is
    /// recorded as the alias rather than being taken for the package.
    #[test]
    fn an_aliased_entry_records_the_canonical_name_and_the_location_spelling() {
        let text = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": {"name": "demo", "version": "1.0.0", "dependencies": {"foo": "npm:bar@^1.0.0"}},
            "node_modules/foo": {
              "name": "bar",
              "version": "1.0.0",
              "resolved": "https://registry.npmjs.org/bar/-/bar-1.0.0.tgz",
              "integrity": "sha512-aaaa"
            }
          }
        }"#;
        let lockfile = parse_package_lock(text).expect("an aliased lockfile parses");
        let entry = &lockfile.entries[0];
        assert_eq!(entry.location, "node_modules/foo");
        assert_eq!(entry.name, "bar", "the canonical target is the name");
        assert_eq!(entry.alias.as_deref(), Some("foo"));
    }

    /// A lockfile whose alias claims cannot be resolved has no single answer to
    /// "which package lives here", and every binding below is keyed on exactly
    /// that. The gate is delegated to `ecosystem_scan`'s hardened rules rather
    /// than reimplemented.
    #[test]
    fn a_lockfile_with_an_unresolvable_alias_claim_is_refused() {
        let text = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": {"name": "demo", "version": "1.0.0", "dependencies": {"foo": "npm:bar@^1.0.0"}}
          }
        }"#;
        assert_eq!(
            parse_package_lock(text).unwrap_err(),
            NpmLockfileError::ContradictoryIdentity
        );
    }

    #[test]
    fn the_lockfile_reader_refuses_what_it_cannot_reconcile() {
        assert_eq!(
            parse_package_lock("{").unwrap_err(),
            NpmLockfileError::Malformed
        );
        assert_eq!(
            parse_package_lock(r#"{"lockfileVersion":3,"lockfileVersion":3,"packages":{}}"#)
                .unwrap_err(),
            NpmLockfileError::DuplicateKey
        );
        assert_eq!(
            parse_package_lock(r#"{"lockfileVersion":1,"dependencies":{}}"#).unwrap_err(),
            NpmLockfileError::UnsupportedLockfileVersion(1),
            "a v1 lockfile has no install-location key to reconcile npm's audit output against"
        );
        assert_eq!(
            parse_package_lock(r#"{"name":"demo"}"#).unwrap_err(),
            NpmLockfileError::NotALockfile
        );
    }

    // -- reconciliation ----------------------------------------------------

    #[test]
    fn a_package_installed_but_absent_from_the_lockfile_is_unaccounted() {
        let lockfile = NpmLockfile {
            lockfile_version: 3,
            entries: vec![registry_entry("node_modules/a", "a", "1.0.0")],
            root_name: None,
        };
        let inventory = installed(&["node_modules/a", "node_modules/stowaway"]);
        let report = NpmAuditReport::default();
        let assessment = reconcile(&lockfile, &inventory, Some(&report));
        assert_eq!(assessment.coverage.unaccounted_installed, 1);
        assert_eq!(
            assessment.coverage.unaccounted_locations,
            vec!["node_modules/stowaway".to_string()]
        );
        match overall_outcome(&assessment.statuses(), false) {
            NpmAttestOutcome::Partial { reason, .. } => {
                assert_eq!(reason, NpmPartialReason::NotAudited);
            }
            other => panic!("expected Partial, got {other:?}"),
        }
    }

    #[test]
    fn no_audit_report_makes_every_registry_package_not_audited() {
        let lockfile = NpmLockfile {
            lockfile_version: 3,
            entries: vec![registry_entry("node_modules/a", "a", "1.0.0")],
            root_name: None,
        };
        let assessment = reconcile(&lockfile, &installed(&["node_modules/a"]), None);
        assert_eq!(assessment.records[0].status.label(), "not-audited");
        assert!(!matches!(
            overall_outcome(&assessment.statuses(), false),
            NpmAttestOutcome::Clean
        ));
    }

    #[test]
    fn a_git_dependency_stays_explicit_rather_than_being_dropped() {
        let mut git = registry_entry("node_modules/g", "g", "1.0.0");
        git.source = NpmSourceKind::Git;
        git.registry_host = None;
        let lockfile = NpmLockfile {
            lockfile_version: 3,
            entries: vec![git, registry_entry("node_modules/a", "a", "1.0.0")],
            root_name: None,
        };
        let report = NpmAuditReport::default();
        let assessment = reconcile(
            &lockfile,
            &installed(&["node_modules/a", "node_modules/g"]),
            Some(&report),
        );
        assert_eq!(assessment.records.len(), 2, "the git entry is not dropped");
        assert_eq!(assessment.coverage.unsupported_source_entries, 1);
        assert_eq!(assessment.coverage.unaccounted_installed, 0);
    }

    #[test]
    fn absence_from_every_audit_bucket_is_not_audited() {
        let lockfile = NpmLockfile {
            lockfile_version: 3,
            entries: vec![registry_entry("node_modules/a", "a", "1.0.0")],
            root_name: None,
        };
        let assessment = reconcile(
            &lockfile,
            &installed(&["node_modules/a"]),
            Some(&NpmAuditReport::default()),
        );
        assert_eq!(assessment.records[0].status.label(), "not-audited");
        assert!(!assessment.coverage.signature_only_derived_by_subtraction);
        assert!(matches!(
            overall_outcome(&assessment.statuses(), false),
            NpmAttestOutcome::Partial {
                reason: NpmPartialReason::NotAudited,
                ..
            }
        ));
    }

    #[test]
    fn a_capped_inventory_reports_a_coverage_gap() {
        let lockfile = NpmLockfile {
            lockfile_version: 3,
            entries: vec![registry_entry("node_modules/a", "a", "1.0.0")],
            root_name: None,
        };
        let mut inventory = installed(&["node_modules/a"]);
        inventory.capped = true;
        // Isolate the inventory-level gap: the package itself has explicit
        // positive audit membership, so omission/NotAudited is not a separate
        // and correctly higher-priority reason for Partial.
        let report = NpmAuditReport {
            verified: vec![audit_entry("a", "node_modules/a", "1.0.0", None)],
            ..NpmAuditReport::default()
        };
        let assessment = reconcile(&lockfile, &inventory, Some(&report));
        assert!(assessment.coverage_gap().is_some());
        let outcome = apply_coverage_gap(
            overall_outcome(&assessment.statuses(), false),
            assessment.coverage_gap().as_deref(),
        );
        assert!(matches!(
            outcome,
            NpmAttestOutcome::Partial {
                reason: NpmPartialReason::CoverageCapped,
                ..
            }
        ));
    }

    fn audit_entry(name: &str, location: &str, version: &str, code: Option<&str>) -> NpmAuditEntry {
        NpmAuditEntry {
            name: name.to_string(),
            version: Some(version.to_string()),
            location: Some(location.to_string()),
            registry: Some("https://registry.npmjs.org/".to_string()),
            code: code.map(str::to_string),
            predicate_types: Vec::new(),
            attested_digests: BTreeMap::new(),
        }
    }

    /// npm's `getValidPackageInfo` returns early on `!version`, so a lockfile
    /// entry with nothing on disk is in NONE of npm's buckets for a reason that
    /// has nothing to do with its signature. Subtracting from empty buckets and
    /// calling that "its registry signature verified" is a claim npm never made.
    #[test]
    fn neither_installed_nor_uninstalled_omissions_are_signature_verified() {
        let lockfile = NpmLockfile {
            lockfile_version: 3,
            entries: vec![
                registry_entry("node_modules/chalk", "chalk", "5.4.1"),
                registry_entry("node_modules/fsevents", "fsevents", "2.3.3"),
            ],
            root_name: None,
        };
        // Only chalk is on disk, as `npm ci --omit=dev` or a platform-specific
        // optional dependency leaves it.
        let assessment = reconcile(
            &lockfile,
            &installed(&["node_modules/chalk"]),
            Some(&NpmAuditReport::default()),
        );
        let by_location: BTreeMap<&str, &NpmPackageRecord> = assessment
            .records
            .iter()
            .map(|record| (record.location.as_str(), record))
            .collect();
        assert_eq!(
            by_location["node_modules/chalk"].status.label(),
            "not-audited"
        );
        assert_eq!(
            by_location["node_modules/fsevents"].status.label(),
            "not-audited",
            "an entry npm never audited cannot be reported as signature-verified"
        );
        assert!(!by_location["node_modules/fsevents"].installed);
        match overall_outcome(&assessment.statuses(), false) {
            NpmAttestOutcome::Partial { reason, .. } => {
                assert_eq!(reason, NpmPartialReason::NotAudited);
            }
            other => panic!("expected Partial, got {other:?}"),
        }
    }

    /// A registry that serves no signing keys produces neither a `missing` entry
    /// nor a verified count (`else if (keys.length)`), so absence from npm's
    /// buckets is not evidence there either.
    #[test]
    fn a_non_public_registry_host_is_never_signature_verified_by_omission() {
        let mut entry = registry_entry("node_modules/internal", "internal", "1.0.0");
        entry.registry_host = Some("npm.internal.example".to_string());
        let lockfile = NpmLockfile {
            lockfile_version: 3,
            entries: vec![entry],
            root_name: None,
        };
        let assessment = reconcile(
            &lockfile,
            &installed(&["node_modules/internal"]),
            Some(&NpmAuditReport::default()),
        );
        assert_eq!(assessment.records[0].status.label(), "not-audited");
        assert!(!matches!(
            overall_outcome(&assessment.statuses(), false),
            NpmAttestOutcome::Clean
        ));
    }

    /// npm reports the registry it took from CONFIG. When that is not the host
    /// the lockfile resolves the package from, npm's positive answer is about
    /// different bytes than the ones this project installs.
    #[test]
    fn a_verified_result_from_a_divergent_registry_is_not_a_verified_package() {
        let lockfile = NpmLockfile {
            lockfile_version: 3,
            entries: vec![registry_entry("node_modules/chalk", "chalk", "5.4.1")],
            root_name: None,
        };
        let mut verified = audit_entry("chalk", "node_modules/chalk", "5.4.1", None);
        verified.registry = Some("https://attacker.example/".to_string());
        let report = NpmAuditReport {
            verified: vec![verified],
            ..NpmAuditReport::default()
        };
        let assessment = reconcile(
            &lockfile,
            &installed(&["node_modules/chalk"]),
            Some(&report),
        );
        assert_eq!(assessment.records[0].status.label(), "not-audited");
        assert_eq!(
            assessment.records[0].audit_registry_host.as_deref(),
            Some("attacker.example"),
            "the receipt records where npm actually looked, not only where the lockfile points"
        );
        assert_eq!(
            assessment.audit_registry_hosts(),
            vec!["attacker.example".to_string()]
        );
    }

    /// An `invalid` entry that matches no lockfile entry and no installed
    /// package is still a signature failure npm reported. Dropping it turns the
    /// only negative outcome this command has into its most positive one.
    #[test]
    fn an_audit_finding_that_matches_nothing_still_reaches_the_ledger() {
        let lockfile = NpmLockfile {
            lockfile_version: 3,
            entries: vec![registry_entry("node_modules/chalk", "chalk", "5.4.1")],
            root_name: None,
        };
        let report = NpmAuditReport {
            invalid: vec![audit_entry(
                "leftpad",
                "node_modules/leftpad",
                "1.0.0",
                Some("EINTEGRITYSIGNATURE"),
            )],
            ..NpmAuditReport::default()
        };
        let assessment = reconcile(
            &lockfile,
            &installed(&["node_modules/chalk"]),
            Some(&report),
        );
        assert_eq!(assessment.coverage.unmatched_audit_entries, 1);
        let leftpad = assessment
            .records
            .iter()
            .find(|record| record.location == "node_modules/leftpad")
            .expect("the dropped finding must have its own record");
        match &leftpad.status {
            NpmPackageStatus::Invalid { code, .. } => assert_eq!(code, "EINTEGRITYSIGNATURE"),
            other => panic!("expected Invalid, got {other:?}"),
        }
        assert!(matches!(
            overall_outcome(&assessment.statuses(), false),
            NpmAttestOutcome::Mismatch { .. }
        ));
    }

    /// A lockfile entry Tirith classified as non-registry is never looked up in
    /// npm's buckets, so npm's verdict about it would otherwise vanish.
    #[test]
    fn an_audit_finding_for_a_non_registry_entry_is_not_swallowed() {
        let mut workspace = registry_entry("node_modules/semver", "semver", "7.8.5");
        workspace.source = NpmSourceKind::Workspace;
        workspace.registry_host = None;
        let lockfile = NpmLockfile {
            lockfile_version: 3,
            entries: vec![workspace],
            root_name: None,
        };
        let report = NpmAuditReport {
            invalid: vec![audit_entry(
                "semver",
                "node_modules/semver",
                "7.8.5",
                Some("EINTEGRITYSIGNATURE"),
            )],
            ..NpmAuditReport::default()
        };
        let assessment = reconcile(
            &lockfile,
            &installed(&["node_modules/semver"]),
            Some(&report),
        );
        assert!(
            matches!(
                overall_outcome(&assessment.statuses(), false),
                NpmAttestOutcome::Mismatch { .. }
            ),
            "npm called this package invalid; the answer cannot be a coverage note"
        );
    }

    /// An installed package with no lockfile entry is the one path that exists
    /// precisely because the lockfile is stale, which is exactly when npm's own
    /// verdict for it matters most.
    #[test]
    fn an_unaccounted_installed_package_honours_npms_verdict() {
        let lockfile = NpmLockfile {
            lockfile_version: 3,
            entries: vec![registry_entry("node_modules/chalk", "chalk", "5.4.1")],
            root_name: None,
        };
        let report = NpmAuditReport {
            invalid: vec![audit_entry(
                "evil",
                "node_modules/evil",
                "1.0.0",
                Some("EINTEGRITYSIGNATURE"),
            )],
            ..NpmAuditReport::default()
        };
        let assessment = reconcile(
            &lockfile,
            &installed(&["node_modules/chalk", "node_modules/evil"]),
            Some(&report),
        );
        assert_eq!(assessment.coverage.unaccounted_installed, 1);
        assert_eq!(
            assessment.coverage.unmatched_audit_entries, 0,
            "the finding was consumed by the installed package it names"
        );
        let evil = assessment
            .records
            .iter()
            .find(|record| record.location == "node_modules/evil")
            .expect("evil record");
        assert_eq!(evil.status.label(), "invalid");
        assert!(matches!(
            overall_outcome(&assessment.statuses(), false),
            NpmAttestOutcome::Mismatch { .. }
        ));
    }

    /// npm's `!spec.registry` skip: a dependency declared as a bare tarball URL
    /// is `type: remote`, never audited, and in none of npm's buckets.
    #[test]
    fn a_bare_remote_tarball_is_not_a_registry_source() {
        let text = r#"{
          "lockfileVersion": 3,
          "packages": {
            "": {"name": "demo", "version": "1.0.0"},
            "node_modules/payload": {
              "version": "1.0.0",
              "resolved": "https://cdn.attacker.test/payload.tgz",
              "integrity": "sha512-aaaa"
            },
            "node_modules/chalk": {
              "version": "5.4.1",
              "resolved": "https://registry.npmjs.org/chalk/-/chalk-5.4.1.tgz",
              "integrity": "sha512-bbbb"
            }
          }
        }"#;
        let lockfile = parse_package_lock(text).expect("lockfile parses");
        let by_location: BTreeMap<&str, &NpmLockfileEntry> = lockfile
            .entries
            .iter()
            .map(|entry| (entry.location.as_str(), entry))
            .collect();
        assert_eq!(
            by_location["node_modules/payload"].source,
            NpmSourceKind::Remote,
            "an arbitrary tarball URL is not a registry package path"
        );
        assert_eq!(
            by_location["node_modules/payload"].registry_host, None,
            "a remote tarball's host is not a registry the receipt may claim"
        );
        assert_eq!(
            by_location["node_modules/chalk"].source,
            NpmSourceKind::Registry
        );
        assert_eq!(
            lockfile.registry_hosts(),
            vec!["registry.npmjs.org".to_string()]
        );
    }

    /// A registry package path must spell the entry's own name, so one package
    /// cannot borrow another's URL shape.
    #[test]
    fn a_registry_package_url_must_name_its_own_package() {
        assert!(is_registry_package_url(
            "https://registry.npmjs.org/chalk/-/chalk-5.4.1.tgz",
            "chalk"
        ));
        assert!(is_registry_package_url(
            "https://artifactory.example/api/npm/virtual/chalk/-/chalk-5.4.1.tgz",
            "chalk"
        ));
        assert!(is_registry_package_url(
            "https://registry.npmjs.org/@scope/pkg/-/pkg-2.0.0.tgz",
            "@scope/pkg"
        ));
        assert!(!is_registry_package_url(
            "https://registry.npmjs.org/chalk/-/chalk-5.4.1.tgz",
            "lodash"
        ));
        assert!(!is_registry_package_url(
            "https://cdn.attacker.test/payload.tgz",
            "payload"
        ));
        assert!(!is_registry_package_url(
            "https://cdn.attacker.test/chalk/-/",
            "chalk"
        ));
    }

    /// A bucket element that does not match the entry schema empties the bucket
    /// one finding at a time, and an emptied `invalid` bucket is the most
    /// positive answer this command can give.
    #[test]
    fn a_malformed_bucket_element_is_refused_not_dropped() {
        let schema = NpmAuditJsonSchema::BucketsWithAttestedVerified;
        for body in [
            // npm's own `invalid` object literal, minus `name`.
            r#"{"invalid":[{"code":"EINTEGRITYSIGNATURE","location":"node_modules/chalk","version":"5.4.1"}],"missing":[],"verified":[]}"#,
            // A wrong-typed `name`.
            r#"{"invalid":[{"name":null,"code":"EINTEGRITYSIGNATURE","location":"node_modules/chalk"}],"missing":[],"verified":[]}"#,
            r#"{"invalid":[{"name":123,"code":"EINTEGRITYSIGNATURE"}],"missing":[],"verified":[]}"#,
            // A future field rename inside the contracted major range.
            r#"{"invalid":[{"pkgName":"chalk","code":"EINTEGRITYSIGNATURE"}],"missing":[],"verified":[]}"#,
            // A non-object element.
            r#"{"invalid":["node_modules/chalk"],"missing":[],"verified":[]}"#,
        ] {
            assert_eq!(
                parse_audit_report(body, schema),
                Err(NpmAuditParseError::SchemaMismatch),
                "a bucket element tirith cannot model must be refused: {body}"
            );
        }
        // The control: the same document with a well-formed element parses and
        // keeps the finding.
        let control = parse_audit_report(
            r#"{"invalid":[{"name":"chalk","code":"EINTEGRITYSIGNATURE","location":"node_modules/chalk"}],"missing":[],"verified":[]}"#,
            schema,
        )
        .expect("a well-formed invalid entry parses");
        assert_eq!(control.invalid.len(), 1);
    }

    /// The element count is capped, not only the byte count: a lockfile inside
    /// the 64 MiB budget can still declare hundreds of thousands of entries.
    #[test]
    fn a_lockfile_with_too_many_entries_is_refused() {
        let mut packages = String::from(r#""": {"name": "demo", "version": "1.0.0"}"#);
        for index in 0..=MAX_LOCKFILE_ENTRIES {
            packages.push_str(&format!(
                r#", "node_modules/p{index}": {{"version": "1.0.0", "resolved": "https://registry.npmjs.org/p{index}/-/p{index}-1.0.0.tgz"}}"#
            ));
        }
        let text = format!(r#"{{"lockfileVersion": 3, "packages": {{{packages}}}}}"#);
        assert!(
            matches!(
                parse_package_lock(&text),
                Err(NpmLockfileError::TooManyEntries(_))
            ),
            "an over-cap lockfile must be refused rather than half-read"
        );
    }

    // -- subject binding ---------------------------------------------------

    fn digests(algorithm: &str, hex: &str) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert(algorithm.to_string(), hex.to_string());
        map
    }

    #[test]
    fn a_matching_subject_digest_binds_and_a_differing_one_does_not() {
        use base64::Engine as _;
        let raw = [0xABu8; 64];
        let sri = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(raw)
        );
        let hex = hex::encode(raw);
        assert_eq!(
            bind_attested_subject(&digests("sha512", &hex), Some(&sri)),
            SubjectBinding::Bound
        );
        assert_eq!(
            bind_attested_subject(&digests("sha512", &"0".repeat(128)), Some(&sri)),
            SubjectBinding::Mismatch
        );
        assert_eq!(
            bind_attested_subject(&digests("sha512", &hex), None),
            SubjectBinding::NotComparable
        );
        assert_eq!(
            bind_attested_subject(&digests("sha256", &hex), Some(&sri)),
            SubjectBinding::NotComparable,
            "a different algorithm is not comparable, never silently bound"
        );
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abcd", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abce"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    // -- receipt -----------------------------------------------------------

    fn facts(outcome: NpmAttestOutcome, assessment: NpmAssessment) -> NpmReceiptFacts {
        NpmReceiptFacts {
            policy_projection_hash: "a".repeat(64),
            outcome,
            require_provenance: false,
            subject: NpmReceiptSubject {
                lockfile_name: "package-lock.json".to_string(),
                lockfile_sha256: Some("b".repeat(64)),
                lockfile_version: Some(3),
                project_name: Some("demo".to_string()),
                registry_hosts: vec!["registry.npmjs.org".to_string()],
                audit_registry_hosts: Vec::new(),
                project_npmrc_present: false,
                installed_package_count: 1,
            },
            tools: NpmToolIdentity {
                npm_sha256: Some("c".repeat(64)),
                npm_version: Some("11.17.0".to_string()),
                interpreter_sha256: Some("d".repeat(64)),
                interpreter_name: Some("node".to_string()),
            },
            invocation: Some(NpmAuditInvocation {
                contract_id: NPM_AUDIT_SIGNATURES_CONTRACTS[0].id.to_string(),
                version_range: NPM_AUDIT_SIGNATURES_CONTRACTS[0].version_range.to_string(),
                argv: NPM_AUDIT_SIGNATURES_CONTRACTS[0]
                    .argv
                    .iter()
                    .map(|arg| (*arg).to_string())
                    .collect(),
                attestation_bundles_available: true,
                environment: Some(NpmAuditEnvironment {
                    mode: NpmAuditMode::HermeticPublicRegistry,
                    registry_origin: "https://registry.npmjs.org/".to_string(),
                    strict_tls: true,
                    tls_ca_identity: "system_roots".to_string(),
                    proxy_identity: "direct".to_string(),
                    auth_source_identity: "none".to_string(),
                }),
                exit_code: Some(0),
                stderr: None,
            }),
            assessment,
        }
    }

    fn clean_assessment() -> NpmAssessment {
        let lockfile = NpmLockfile {
            lockfile_version: 3,
            entries: vec![registry_entry("node_modules/a", "a", "1.0.0")],
            root_name: None,
        };
        let report = NpmAuditReport {
            verified: vec![audit_entry("a", "node_modules/a", "1.0.0", None)],
            ..NpmAuditReport::default()
        };
        reconcile(&lockfile, &installed(&["node_modules/a"]), Some(&report))
    }

    #[test]
    fn a_fresh_receipt_is_content_addressed_and_valid() {
        let receipt = NpmProvenanceReceipt::new(facts(NpmAttestOutcome::Clean, clean_assessment()));
        assert_eq!(receipt.receipt_id.len(), 64);
        assert!(receipt.content_hash_matches());
        receipt.validate().expect("a coherent receipt validates");
        assert!(!receipt.audit_chain_anchored);
        assert!(receipt
            .caveats
            .iter()
            .any(|caveat| caveat == NPM_CLEAN_IS_NOT_BENIGN_CAVEAT));
        assert!(receipt
            .caveats
            .iter()
            .any(|caveat| caveat == crate::provenance::npm_facts::NPM_BYTES_NOT_BOUND_CAVEAT));
    }

    #[test]
    fn a_schema_one_receipt_without_an_environment_binding_still_deserializes() {
        let receipt = NpmProvenanceReceipt::new(facts(NpmAttestOutcome::Clean, clean_assessment()));
        let mut value = serde_json::to_value(receipt).expect("receipt JSON");
        value["schema"] = serde_json::json!(1);
        value["invocation"]
            .as_object_mut()
            .expect("invocation object")
            .remove("environment");
        let legacy: NpmProvenanceReceipt =
            serde_json::from_value(value).expect("schema-1 shape remains readable");
        assert!(legacy
            .invocation
            .as_ref()
            .is_some_and(|invocation| invocation.environment.is_none()));
        assert!(
            legacy.validate().is_err(),
            "schema 1 is readable, not current"
        );
    }

    #[test]
    fn tampering_with_any_field_breaks_the_content_address() {
        let baseline =
            NpmProvenanceReceipt::new(facts(NpmAttestOutcome::Clean, clean_assessment()));
        for mutate in [
            (|r: &mut NpmProvenanceReceipt| r.require_provenance = true) as fn(&mut _),
            |r: &mut NpmProvenanceReceipt| r.subject.lockfile_sha256 = Some("e".repeat(64)),
            |r: &mut NpmProvenanceReceipt| r.tools.npm_version = Some("10.0.0".to_string()),
            |r: &mut NpmProvenanceReceipt| r.coverage.unaccounted_installed = 3,
            |r: &mut NpmProvenanceReceipt| r.packages.clear(),
        ] {
            let mut tampered = baseline.clone();
            mutate(&mut tampered);
            assert!(
                !tampered.content_hash_matches(),
                "an edited receipt must not still match its content address"
            );
            assert!(tampered.validate().is_err());
        }
    }

    #[test]
    fn a_clean_receipt_cannot_be_written_without_the_evidence_it_claims() {
        // No invocation: nothing ran, so nothing verified.
        let mut no_run = facts(NpmAttestOutcome::Clean, clean_assessment());
        no_run.invocation = None;
        let receipt = NpmProvenanceReceipt::new(no_run);
        assert!(receipt.validate().is_err());

        // An invocation with no exit code: the command was authorized but no
        // process reached completion, so nothing verified.
        let mut no_exit = facts(NpmAttestOutcome::Clean, clean_assessment());
        if let Some(invocation) = no_exit.invocation.as_mut() {
            invocation.exit_code = None;
        }
        let receipt = NpmProvenanceReceipt::new(no_exit);
        assert!(
            receipt.validate().is_err(),
            "a clean receipt cannot rest on a command that never completed"
        );

        // An unaccounted installed package.
        let mut leaky = facts(NpmAttestOutcome::Clean, clean_assessment());
        leaky.assessment.coverage.unaccounted_installed = 1;
        let receipt = NpmProvenanceReceipt::new(leaky);
        assert!(receipt.validate().is_err());

        // --require-provenance with a signature-only package.
        let mut signature_only_assessment = clean_assessment();
        signature_only_assessment.records[0].status = signature_only();
        let mut strict = facts(NpmAttestOutcome::Clean, signature_only_assessment);
        strict.require_provenance = true;
        let receipt = NpmProvenanceReceipt::new(strict);
        assert!(receipt.validate().is_err());
    }

    #[test]
    fn a_partial_receipt_records_the_reason_and_still_validates() {
        let lockfile = NpmLockfile {
            lockfile_version: 3,
            entries: vec![registry_entry("node_modules/a", "a", "1.0.0")],
            root_name: None,
        };
        let assessment = reconcile(&lockfile, &installed(&["node_modules/a"]), None);
        let mut partial = facts(
            NpmAttestOutcome::Partial {
                reason: NpmPartialReason::UnsupportedNpmVersion,
                detail: "npm 10.9.2 is outside every supported contract range".to_string(),
            },
            assessment,
        );
        partial.invocation = None;
        let receipt = NpmProvenanceReceipt::new(partial);
        receipt.validate().expect("a partial receipt validates");
        let json = receipt.to_json();
        assert!(json.contains("unsupported_npm_version"), "{json}");
        assert!(json.contains("\"outcome\": \"partial\""), "{json}");
    }

    #[test]
    fn the_receipt_carries_no_absolute_path_and_no_secret_shaped_token() {
        let receipt = NpmProvenanceReceipt::new(facts(NpmAttestOutcome::Clean, clean_assessment()));
        let json = receipt.to_json();
        for line in json.lines() {
            assert!(
                !line.contains("\"/") && !line.contains("C:\\\\"),
                "a receipt must carry no absolute machine path: {line}"
            );
        }
        assert!(
            !crate::redact::looks_secret_shaped(&json),
            "the serialized receipt must not look secret-bearing"
        );
    }

    #[test]
    fn the_content_address_ignores_the_signature_field() {
        let mut receipt =
            NpmProvenanceReceipt::new(facts(NpmAttestOutcome::Clean, clean_assessment()));
        let before = receipt.compute_content_hash();
        receipt.signature = Some("not-a-real-signature".to_string());
        assert_eq!(receipt.compute_content_hash(), before);
        assert!(!receipt.signature_verifies(&[0u8; 32]));
    }
}
