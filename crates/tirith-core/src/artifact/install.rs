//! Install-from-digest planning for the package firewall (PR D4).
//!
//! D3 ([`crate::artifact::firewall`]) re-materialised every approved wheel into an
//! install transaction under its validated `*.whl` name and finalised one
//! [`Verdict`] the install gates on. D4 is the step that turns that into an actual,
//! contained `pip install` of EXACTLY those bytes:
//!
//! 1. **Re-bind immediately before launch** (cross-cutting invariant 4). The
//!    approval an operator gave was bound to a hash + threat-DB state at a point in
//!    time. Right before the install runs, [`rebind_for_install`] reloads the
//!    latest threat DB, RE-HASHES every quarantine blob (by re-running
//!    [`crate::artifact::firewall::firewall_resolved_set`], whose
//!    [`crate::artifact::quarantine::QuarantineTransaction::materialize_blob`] step
//!    re-hashes), reruns the hash indicators, and **invalidates the approval if any
//!    bound state changed**: a blob that was swapped/truncated/removed, a wheel
//!    that now matches a known-malicious hash, or a threat-DB sequence that advanced
//!    past the one the approval was bound to. Any of those refuses the install
//!    before a single byte is handed to pip.
//!
//! 2. **Generate `approved.txt`.** [`approved_requirements_text`] emits one
//!    `name @ file:///<abs-path>/<file>.whl --hash=sha256:<d>` line per
//!    materialised wheel. The `name` is the PEP 503-normalised distribution name
//!    parsed from the validated wheel filename; the URL is the `file://` URL of the
//!    immutable transaction copy D3 produced; the `--hash` is the approved digest.
//!    pip is thereby told to install ONLY those local files and to refuse any whose
//!    content does not hash to the pinned digest.
//!
//! 3. **The pip argv.** [`InstallCommand::pip_install_args`] is exactly the plan's
//!    pin: `-m pip install --isolated --no-index --no-deps --require-hashes
//!    --no-cache-dir --force-reinstall -r approved.txt`. `--force-reinstall` (or a
//!    fresh target) is mandatory: without it pip SKIPS a package whose version is
//!    already installed, so a re-verified install of a pinned version would no-op.
//!    `--no-index` + the `file://` references mean pip never touches the network;
//!    `--no-deps` because the resolver already produced a transitively-complete,
//!    fully-pinned set; `--isolated` + `--no-cache-dir` so no ambient pip config or
//!    cache can redirect the install.
//!
//! 4. **The capsule spec.** [`build_install_spec`] is a locked-down, **deny-all
//!    network** [`CapsuleSpec`]: the install needs no outbound traffic once the
//!    bytes are quarantined, so the source artifact is the only thing pip reads and
//!    the target environment is the only thing it writes. The transaction directory
//!    is granted READ (pip reads the `file://` wheels) and the target environment
//!    tree is granted WRITE (pip extracts into it). The credential subtrees stay
//!    denied, the environment is scrubbed of secrets, and conservative resource
//!    limits apply.
//!
//! # What lives here vs. the CLI crate
//!
//! This module is **pure / async-free**: it parses, composes the firewall, builds
//! the `approved.txt` text, the pip argv, and the spec, and decides whether the
//! re-bind passes. It does NOT spawn anything. The actual contained launch
//! (`tirith::cli::capsule::run_to_completion` under
//! `DegradedPolicy::FailClosed`) lives in the CLI crate (`pkg_install.rs`), because
//! the capsule launcher needs the OS backends and, on the enforcing path, **fails
//! closed under degraded coverage**. The grep-test the plan calls for (that the
//! install-from-digest path NEVER calls the uncontained `ProcessInstallRunner`)
//! holds by construction here: this module knows nothing about that runner, and the
//! CLI consumer goes only through the capsule seam.
//!
//! # The install invariant
//!
//! The plan's invariant is "the source artifact has the approved hash AND installed
//! files verify against installed RECORD (there is no 'installed artifact hash'
//! post-extraction)". D4 owns the FIRST half: [`rebind_for_install`] guarantees the
//! bytes handed to pip are the approved bytes (the firewall re-hash). The SECOND
//! half, verifying the installed files against their RECORD after extraction, is
//! D5's [`crate::verdict::RuleId::PythonInstalledIntegrityViolation`] fold over
//! [`crate::artifact::record::verify_installed_record`].
//!
//! # The D5 post-install seam
//!
//! [`verify_post_install_record`] is that second half. Once the contained pip
//! install has extracted EXACTLY the approved wheels into the target environment,
//! it re-reads the installed RECORD of each just-installed distribution and folds a
//! RECORD hash mismatch / missing file / duplicate-owned path into AT MOST ONE
//! [`crate::verdict::RuleId::PythonInstalledIntegrityViolation`] finding, finalised
//! through [`crate::escalation::finalize_static_verdict`] (cross-cutting invariant
//! 5). It reuses the B5 primitives verbatim
//! ([`crate::artifact::record::verify_installed_record`] for the lenient per-file
//! check and [`crate::artifact::record::index_distribution_ownership`] for the
//! duplicate-ownership multimap), so the installed-environment semantics cannot
//! drift from the `ecosystem scan --installed` path. It is install-SCOPED: it
//! verifies only the distributions this install named (matched by PEP 503 name),
//! never the whole pre-existing environment, so a venv's unrelated pre-installed
//! packages are not re-judged by an install.
//!
//! **Editable / conda -> no false positive.** Installed-environment drift is
//! legitimate for an editable install (a sparse RECORD, absent project files) and
//! for a non-pip installer (conda, a distro-managed or PEP 668 externally-managed
//! tree). [`verify_installed_record`] already flags both
//! ([`crate::artifact::record::InstalledRecordResult::editable`] /
//! `externally_managed`) and suppresses the missing-file signal for editable;
//! D5's fold goes further and DROPS every signal that originates from an editable
//! or externally-managed distribution before correlating, so neither can produce a
//! finding on its own. A real hash mismatch in an ordinary pip-installed
//! distribution still folds to the Medium finding.
//!
//! This stays in the pure core crate (it only reads the filesystem and assembles a
//! verdict); the CLI half (`pkg_install.rs`) calls it after the contained install
//! returns success and carries the verdict into the D6 receipt.

use std::path::{Path, PathBuf};

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};

use crate::artifact::firewall::firewall_resolved_set;
use crate::artifact::quarantine::QuarantineTransaction;
use crate::artifact::record::{
    index_distribution_ownership, verify_installed_record, EnvironmentLayout, FileVerification,
    OwnershipIndex,
};
use crate::artifact::resolver::ResolvedSet;
use crate::artifact::{ArtifactSignal, ArtifactSignalKind, DistributionIdentity};
use crate::location::SubjectLocation;
use crate::policy::Policy;
use crate::threatdb::{Ecosystem, ThreatDb};
use crate::verdict::{Evidence, Finding, RuleId, Severity, Timings, Verdict};

/// The characters a `file://` path segment must percent-encode. The base
/// `CONTROLS` set plus the bytes that are unsafe in a URL path or that pip's
/// requirement parser treats specially: space, quotes, `#`/`?` (URL delimiters),
/// `%` (so a literal `%` is not read as an escape), and the backslash. The forward
/// slash is intentionally NOT in the set: it is the path separator and is already
/// a single safe component boundary by the time we build the URL.
const FILE_URL_PATH_ENCODE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'#')
    .add(b'?')
    .add(b'{')
    .add(b'}')
    .add(b'|')
    .add(b'^')
    .add(b'%')
    .add(b'\\');

/// Why an install-from-digest could not be planned. Every variant is fail-closed:
/// the caller is left with NO installable plan, never a partially trusted one.
#[derive(Debug)]
pub enum InstallError {
    /// The re-bind firewall blocked: at least one quarantine blob no longer hashes
    /// to its approved digest (an integrity mismatch) or a wheel matched a
    /// known-malicious hash. The approved bytes are gone or now-malicious; the
    /// install must not proceed.
    RebindBlocked {
        /// The blocking firewall verdict (its findings name exactly why), so the
        /// caller can report the cause without re-running the firewall.
        verdict: Box<Verdict>,
        /// Whether at least one artifact failed the integrity re-bind (its blob did
        /// not re-hash to the approved digest), as opposed to a content/reputation
        /// finding. Lets a caller distinguish "the approved bytes are gone" from "a
        /// known-malicious hash matched".
        integrity_mismatch: bool,
    },
    /// The bound state the approval was tied to changed between approval and
    /// launch: the live threat-DB sequence advanced past the one the approval was
    /// bound to. A newer DB may know the artifact is malicious, so the approval is
    /// invalidated and must be re-issued against the current DB.
    BoundStateChanged {
        /// The threat-DB sequence the approval was bound to.
        approved_db_sequence: u64,
        /// The live threat-DB sequence at launch time.
        current_db_sequence: u64,
    },
    /// The re-bind firewall did not materialise the expected number of wheels (a
    /// blob vanished without even producing an integrity finding, e.g. the
    /// transaction directory was tampered with). Fail-closed: a short
    /// materialisation means the bytes are not all present.
    MaterializationShortfall {
        /// The number of artifacts the resolved set named.
        expected: usize,
        /// The number that materialised intact.
        materialized: usize,
    },
    /// A materialised wheel path could not be turned into a `name @ file://...`
    /// requirement line (a non-wheel filename slipped through, a path with no file
    /// name, or a non-absolute path that cannot be a `file://` URL). Fail-closed.
    BadArtifactPath(String),
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallError::RebindBlocked {
                verdict,
                integrity_mismatch,
            } => write!(
                f,
                "install re-bind refused: the firewall now blocks this set ({} finding(s){}); \
                 the approved bytes are gone or now match a known-malicious hash",
                verdict.findings.len(),
                if *integrity_mismatch {
                    ", integrity mismatch"
                } else {
                    ""
                }
            ),
            InstallError::BoundStateChanged {
                approved_db_sequence,
                current_db_sequence,
            } => write!(
                f,
                "install approval is stale: it was bound to threat-DB sequence {approved_db_sequence}, \
                 but the live DB is at sequence {current_db_sequence}; re-approve against the current DB"
            ),
            InstallError::MaterializationShortfall {
                expected,
                materialized,
            } => write!(
                f,
                "install re-bind materialised {materialized} of {expected} approved wheels; \
                 refusing to install an incomplete set"
            ),
            InstallError::BadArtifactPath(p) => {
                write!(f, "cannot build a file:// requirement for artifact path {p:?}")
            }
        }
    }
}

impl std::error::Error for InstallError {}

/// The exact pip command D4 runs inside the no-network capsule, plus the absolute
/// path of the `approved.txt` requirements file it reads.
///
/// Held as a small value so the CLI consumer can log the argv (secret-free: it is
/// only flags + the approved.txt path) into the D6 receipt and so the argv is unit
/// testable without spawning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallCommand {
    /// The absolute path of the generated `approved.txt` the install reads.
    pub approved_requirements_path: PathBuf,
}

impl InstallCommand {
    /// The `python -m pip install ...` argument vector (everything after the
    /// interpreter path), exactly the plan's pin:
    ///
    /// `-m pip install --isolated --no-index --no-deps --require-hashes
    /// --no-cache-dir --force-reinstall -r <approved.txt>`
    ///
    /// `--force-reinstall` is mandatory so pip does not silently skip a package
    /// whose version is already installed; `--no-index` + the `file://` references
    /// in `approved.txt` keep the install fully offline; `--require-hashes` makes
    /// pip refuse any file whose content does not hash to the pinned digest;
    /// `--no-deps` because the lock is transitively complete; `--isolated` +
    /// `--no-cache-dir` so no ambient pip config / cache can redirect it.
    ///
    /// The interpreter is invoked as `python -m pip` (never a PATH `pip` shim), the
    /// same hardening the D2 resolver uses; the caller supplies the resolved
    /// interpreter path as the program and these as its args.
    pub fn pip_install_args(&self) -> Vec<String> {
        let mut args = self.pip_install_args_without_requirements_path();
        args.push("-r".to_string());
        args.push(self.approved_requirements_path.display().to_string());
        args
    }

    /// The pinned install flags WITHOUT the trailing `-r <approved.txt>` (the
    /// security-relevant *semantics* of the command, with the per-run requirements
    /// path omitted). D7's [`InstallPlanDigest`] binds these so a change to the
    /// install flags re-binds the approval, while a per-run temp approved.txt path
    /// (which differs every invocation) does not perturb the digest. The full argv
    /// ([`Self::pip_install_args`]) is this plus `-r <path>`.
    pub fn pip_install_args_without_requirements_path(&self) -> Vec<String> {
        vec![
            "-m".to_string(),
            "pip".to_string(),
            "install".to_string(),
            "--isolated".to_string(),
            "--no-index".to_string(),
            "--no-deps".to_string(),
            "--require-hashes".to_string(),
            "--no-cache-dir".to_string(),
            "--no-input".to_string(),
            "--disable-pip-version-check".to_string(),
            "--force-reinstall".to_string(),
        ]
    }
}

/// A verified, ready-to-launch install-from-digest plan produced by
/// [`rebind_for_install`]. Every field is post-re-bind: the materialised paths are
/// the exact immutable copies that just re-hashed to their approved digests, the
/// `approved_requirements` text references only those paths, and the
/// [`CapsuleSpec`] is locked-down deny-all.
///
/// The CLI consumer writes [`Self::approved_requirements`] to disk inside the
/// transaction directory, sets [`InstallCommand::approved_requirements_path`] to
/// that location, and launches `python -m pip` with
/// [`InstallCommand::pip_install_args`] through the capsule under
/// [`crate::capsule`]'s fail-closed launcher.
#[derive(Debug, Clone)]
pub struct DigestInstallPlan {
    /// The `approved.txt` content: one `name @ file://... --hash=sha256:<d>` line
    /// per materialised wheel. The caller writes this verbatim.
    pub approved_requirements: String,
    /// The materialised `*.whl` paths the plan references (the immutable
    /// transaction copies). Parallel to the requirement lines, by input order.
    pub materialized: Vec<PathBuf>,
    /// The locked-down, deny-all-network capsule spec the install runs under.
    pub spec: crate::capsule::CapsuleSpec,
    /// The threat-DB sequence the (re-validated) plan is bound to, recorded so the
    /// caller can carry it into the D6 receipt.
    pub bound_db_sequence: u64,
}

/// Re-bind an approved resolved set against the live threat DB immediately before
/// install, returning a launch-ready [`DigestInstallPlan`] or refusing.
///
/// This is the enforcement of cross-cutting invariant 4 at the install edge:
///
/// 1. **Bound-state check.** If `live_db`'s [`ThreatDb::build_sequence`] advanced
///    past `approved_db_sequence`, the approval is stale (a newer DB might flag the
///    artifact) and the install is refused with [`InstallError::BoundStateChanged`].
///    Passing `live_db = None` means "no DB available now"; that is treated as
///    sequence `0`, so an approval bound to `0` still proceeds and one bound to a
///    real sequence is refused (the DB regressed/vanished, so fail closed).
/// 2. **Re-hash + re-inspect.** [`firewall_resolved_set`] re-materialises every
///    blob (re-hashing it) and re-runs the inspection + hash lookup against the
///    freshly-reloaded `policy` + `live_db`. A swapped/missing blob becomes a
///    Critical integrity finding; a now-known-malicious wheel becomes a Critical
///    reputation finding. Either makes the verdict block, and a blocking verdict
///    refuses with [`InstallError::RebindBlocked`].
/// 3. **Completeness.** Every named artifact must have materialised; a shortfall
///    refuses with [`InstallError::MaterializationShortfall`].
///
/// Only when all three pass does it build the `approved.txt` text (over the
/// just-materialised paths), the locked-down spec, and return the plan. The
/// `target_environment` is the environment tree pip will write into (granted write
/// in the spec); `extra_read_roots` are additional read roots the interpreter
/// needs to start (e.g. the interpreter's own prefix), granted read.
pub fn rebind_for_install(
    resolved: &ResolvedSet,
    txn: &QuarantineTransaction,
    policy: &Policy,
    live_db: Option<&ThreatDb>,
    approved_db_sequence: u64,
    target_environment: &Path,
    extra_read_roots: &[PathBuf],
) -> Result<DigestInstallPlan, InstallError> {
    // 1. Bound-state check: a DB that advanced past the approval's sequence (or that
    //    vanished when the approval was bound to a real sequence) invalidates it.
    let current_db_sequence = live_db.map(|db| db.build_sequence()).unwrap_or(0);
    if current_db_sequence != approved_db_sequence {
        return Err(InstallError::BoundStateChanged {
            approved_db_sequence,
            current_db_sequence,
        });
    }

    // 2. Re-hash + re-inspect against the freshly-reloaded policy + live DB. The
    //    firewall materialise step re-hashes each blob; a mismatch/missing blob is a
    //    Critical integrity finding and a known-malicious match is Critical too.
    let outcome = firewall_resolved_set(resolved, txn, policy, live_db);
    if outcome.is_block() {
        return Err(InstallError::RebindBlocked {
            integrity_mismatch: outcome.has_integrity_mismatch(),
            verdict: Box::new(outcome.verdict),
        });
    }

    // 3. Completeness: every named artifact must have materialised intact. (A clean
    //    verdict with a shortfall should be impossible, since a missing blob is an
    //    integrity Block, but we check explicitly so a non-blocking shortfall can
    //    never slip an incomplete set through.)
    if outcome.materialized.len() != resolved.artifacts.len() {
        return Err(InstallError::MaterializationShortfall {
            expected: resolved.artifacts.len(),
            materialized: outcome.materialized.len(),
        });
    }

    // Build the approved.txt text over the just-materialised paths. Each line pairs
    // the artifact's approved digest with the file:// URL of its immutable copy.
    let approved_requirements = approved_requirements_text(resolved, &outcome.materialized)?;
    let spec = build_install_spec(txn.dir(), target_environment, extra_read_roots);

    Ok(DigestInstallPlan {
        approved_requirements,
        materialized: outcome.materialized,
        spec,
        bound_db_sequence: current_db_sequence,
    })
}

/// Build the `approved.txt` requirements text for a resolved set whose wheels just
/// materialised at `materialized` (parallel to `resolved.artifacts`).
///
/// Each line is `name @ file:///<abs>/<file>.whl --hash=sha256:<digest>`:
///
/// * `name` is the PEP 503-normalised distribution name parsed from the validated
///   wheel filename ([`crate::artifact::archive::wheel_distribution_name`]). A
///   direct-reference requirement needs the project name so pip records the install
///   under the right distribution.
/// * the `file://` URL is the absolute, percent-encoded path of the immutable
///   transaction copy (the exact bytes D3 verified).
/// * the `--hash` is the approved sha256 the resolver pinned and the re-hash just
///   confirmed.
///
/// Returns [`InstallError::BadArtifactPath`] if a materialised path is not a
/// usable absolute `*.whl` (it always is by construction, but the function
/// fail-closes rather than emitting a malformed line).
pub fn approved_requirements_text(
    resolved: &ResolvedSet,
    materialized: &[PathBuf],
) -> Result<String, InstallError> {
    // Defensive: the caller pairs these by construction, but never emit a line for a
    // path we cannot match to an approved artifact.
    if materialized.len() != resolved.artifacts.len() {
        return Err(InstallError::MaterializationShortfall {
            expected: resolved.artifacts.len(),
            materialized: materialized.len(),
        });
    }
    let mut lines = String::new();
    for (artifact, path) in resolved.artifacts.iter().zip(materialized.iter()) {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| InstallError::BadArtifactPath(path.display().to_string()))?;
        // The materialised name is the validated wheel filename; derive the project
        // name from it. A non-wheel name here is a contract violation -> fail closed.
        let dist = crate::artifact::archive::wheel_distribution_name(file_name)
            .ok_or_else(|| InstallError::BadArtifactPath(path.display().to_string()))?;
        let url = file_url_for(path)?;
        lines.push_str(&format!(
            "{dist} @ {url} --hash=sha256:{}\n",
            artifact.sha256.to_ascii_lowercase()
        ));
    }
    Ok(lines)
}

/// Turn an absolute filesystem path into a `file://` URL with each component
/// percent-encoded ([`FILE_URL_PATH_ENCODE`]). Refuses a non-absolute path (a
/// `file://` URL must be absolute). On Windows the leading drive component yields a
/// `file:///C:/...` form; on Unix a leading `/` yields `file:///...`.
fn file_url_for(path: &Path) -> Result<String, InstallError> {
    if !path.is_absolute() {
        return Err(InstallError::BadArtifactPath(path.display().to_string()));
    }
    // Build the path portion from components, percent-encoding each Normal segment
    // and writing separators ourselves, so a component with a space or other unsafe
    // byte is encoded but the `/` separators are not.
    let mut encoded = String::new();
    for comp in path.components() {
        match comp {
            std::path::Component::RootDir => {
                // The leading `/` (Unix): the URL path starts with it.
            }
            std::path::Component::Prefix(prefix) => {
                // Windows drive / UNC prefix, e.g. `C:`. Encode its raw text.
                let raw = prefix.as_os_str().to_string_lossy();
                encoded.push('/');
                encoded.push_str(&utf8_percent_encode(&raw, FILE_URL_PATH_ENCODE).to_string());
            }
            std::path::Component::Normal(seg) => {
                let seg = seg
                    .to_str()
                    .ok_or_else(|| InstallError::BadArtifactPath(path.display().to_string()))?;
                encoded.push('/');
                encoded.push_str(&utf8_percent_encode(seg, FILE_URL_PATH_ENCODE).to_string());
            }
            // `.` / `..` / current-dir components cannot appear in an absolute,
            // canonical transaction path; reject to stay fail-closed.
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                return Err(InstallError::BadArtifactPath(path.display().to_string()));
            }
        }
    }
    // `file://` + the absolute path (which already begins with `/`), giving the
    // canonical three-slash `file:///abs/path` form.
    Ok(format!("file://{encoded}"))
}

/// Build the locked-down, **deny-all network** capsule spec for an install:
///
/// * deny-all network (an install needs no outbound traffic once quarantined),
/// * READ the transaction directory (pip reads the `file://` wheels there) and the
///   `extra_read_roots` an interpreter needs to start,
/// * WRITE the target environment tree (pip extracts into it; a write root implies
///   read),
/// * the default sensitive-subtree denies, a scrubbed environment with a temporary
///   HOME, minimal handle inheritance, and conservative resource limits.
///
/// The spec is what an enforcing launcher compares its achieved coverage against;
/// under degraded coverage the install fails closed (the launcher's job, in the CLI
/// crate). This function only describes the intent.
pub fn build_install_spec(
    transaction_dir: &Path,
    target_environment: &Path,
    extra_read_roots: &[PathBuf],
) -> crate::capsule::CapsuleSpec {
    let mut spec = crate::capsule::CapsuleSpec::locked_down();
    // Network: an install never needs egress once the bytes are quarantined.
    spec.network = crate::capsule::NetworkPolicy::DenyAll;
    // Write the environment pip installs into (implies read of it).
    spec.filesystem
        .write_roots
        .push(target_environment.to_path_buf());
    // Read the transaction dir (the file:// wheels + the approved.txt live here).
    spec.filesystem
        .read_roots
        .push(transaction_dir.to_path_buf());
    // Read roots the interpreter needs to start (its own prefix, stdlib, shared
    // libraries). The caller supplies these; we do not guess system paths here so
    // the spec stays host-independent and the CLI decides what the interpreter
    // needs.
    for root in extra_read_roots {
        spec.filesystem.read_roots.push(root.clone());
    }
    spec
}

// ---------------------------------------------------------------------------
// D5 — post-install RECORD verification
// ---------------------------------------------------------------------------

/// The outcome of the D5 post-install RECORD check over a contained install: the
/// finalised verdict the install gates on AFTER extraction, plus the coverage
/// counters the D6 receipt records (how many of the named distributions were
/// found and verified, how many had no RECORD at all, and how many RECORD-listed
/// files did not match their on-disk bytes).
///
/// Every field is post-extraction. The verdict carries AT MOST ONE
/// [`RuleId::PythonInstalledIntegrityViolation`] finding (cross-cutting invariant
/// 1: few user-facing findings, detail carried as evidence); a clean install
/// yields a no-finding `Allow` verdict.
#[derive(Debug, Clone)]
pub struct PostInstallIntegrity {
    /// The single finalised verdict over the just-installed distributions, via
    /// [`crate::escalation::finalize_static_verdict`]. `Allow` (no findings) when
    /// every named distribution verified, or when the only drift came from an
    /// editable / externally-managed (conda / distro) distribution.
    pub verdict: Verdict,
    /// How many of the install's named distributions were located in the target
    /// environment and had their RECORD verified.
    pub distributions_verified: usize,
    /// How many named distributions could not be located in the target
    /// environment's `site-packages` (no matching `.dist-info`). A COVERAGE GAP,
    /// not a violation: pip may install into a `site-packages` layout this check
    /// does not enumerate; the receipt records the shortfall rather than failing.
    pub distributions_not_found: usize,
    /// How many located distributions had NO RECORD file (a coverage gap per the
    /// installed-packages spec, never a violation).
    pub records_missing: usize,
    /// How many RECORD-listed files did not match their on-disk bytes across the
    /// verified distributions (the strong tamper signal).
    pub hash_mismatches: usize,
}

impl PostInstallIntegrity {
    /// Whether the post-install verdict blocks (a strict integrity policy upgraded
    /// the Medium finding to Block via `action_overrides`, applied inside
    /// [`crate::escalation::finalize_static_verdict`]). A convenience over
    /// `self.verdict.action`.
    pub fn is_block(&self) -> bool {
        matches!(self.verdict.action, crate::verdict::Action::Block)
    }
}

/// Verify the installed RECORD of the just-installed distributions in
/// `target_environment` and fold any integrity problem into a single verdict
/// (cross-cutting invariant: "installed files verify against installed RECORD").
///
/// `installed_names` are the PEP 503-normalised distribution names the install
/// landed (one per [`crate::artifact::resolver::ResolvedArtifact`]; build them with
/// [`installed_distribution_names`]). The check is install-SCOPED: it verifies ONLY
/// the `.dist-info` directories whose project name matches one of `installed_names`,
/// never the whole pre-existing environment, so a venv's unrelated pre-installed
/// packages are not re-judged.
///
/// For the matched distributions it:
/// 1. builds a duplicate-aware [`OwnershipIndex`] across them (so a path two of the
///    just-installed distributions both claim surfaces), via the B5
///    [`index_distribution_ownership`];
/// 2. verifies each one's RECORD LENIENTLY via the B5 [`verify_installed_record`]
///    (`allow_scheme_escape = false`: the post-install check never reads outside the
///    environment);
/// 3. DROPS every signal that originated from an editable or externally-managed
///    (conda / distro) distribution (editable / conda -> no false positive), then
/// 4. correlates the surviving signals into AT MOST ONE
///    [`RuleId::PythonInstalledIntegrityViolation`] (Medium; High when corroborated
///    by a duplicate-owned path), finalised through
///    [`crate::escalation::finalize_static_verdict`] so per-rule severity / action
///    overrides and paranoia filtering apply (a strict integrity policy upgrades the
///    action to Block).
///
/// Best-effort discovery: an unreadable `site-packages` or `.dist-info` contributes
/// a "not found" count, never a panic. A clean install returns an `Allow` verdict
/// with no findings.
pub fn verify_post_install_record(
    target_environment: &Path,
    installed_names: &[String],
    policy: &Policy,
) -> PostInstallIntegrity {
    let mut result = PostInstallIntegrity {
        verdict: crate::escalation::finalize_static_verdict(
            Vec::new(),
            policy,
            3,
            Timings::default(),
        ),
        distributions_verified: 0,
        distributions_not_found: 0,
        records_missing: 0,
        hash_mismatches: 0,
    };

    // Locate the `.dist-info` of each named distribution across every site-packages
    // root under the target environment. A name with no matching `.dist-info` is a
    // coverage gap (counted), not a violation.
    let mut matched: Vec<(PathBuf, PathBuf, DistributionIdentity)> = Vec::new();
    let sites = post_install_site_packages(target_environment);
    for name in installed_names {
        match locate_installed_dist_info(&sites, name) {
            Some((site, dist_info, identity)) => matched.push((site, dist_info, identity)),
            None => result.distributions_not_found += 1,
        }
    }

    if matched.is_empty() {
        // Nothing of ours was found to verify; the verdict stays the empty Allow.
        return result;
    }

    // 1. Ownership index across the just-installed distributions, so a path two of
    //    them both list (the duplicate-ownership / cross-distribution split) is a
    //    signal. An editable / externally-managed distribution still participates in
    //    the index (its presence is what makes a DUPLICATE meaningful), but a
    //    duplicate signal is dropped at the fold below if BOTH owners are
    //    editable / externally-managed.
    let mut index = OwnershipIndex::new();
    let mut suppressed_dists: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::new();
    for (_site, dist_info, identity) in &matched {
        index_distribution_ownership(dist_info, identity, &mut index);
    }

    // 2. Per-distribution lenient RECORD verification; collect the signals from the
    //    ordinary (non-editable, non-externally-managed) distributions only.
    let mut integrity_signals: Vec<ArtifactSignal> = Vec::new();
    for (site, dist_info, identity) in &matched {
        let record_result = verify_installed_record(
            dist_info,
            &EnvironmentLayout::for_site_packages(site.clone()),
            identity,
            false,
        );
        result.distributions_verified += 1;
        if record_result.record_missing {
            result.records_missing += 1;
        }
        for entry in &record_result.entries {
            if matches!(entry.verification, FileVerification::Mismatch { .. }) {
                result.hash_mismatches += 1;
            }
        }
        // Editable / conda -> no false positive: an editable or externally-managed
        // distribution legitimately drifts, so its per-file signals never fold into
        // a finding. Record its name so a duplicate-owned path it is a party to is
        // judged below (a duplicate is only suppressed when EVERY owner is exempt).
        if record_result.editable || record_result.externally_managed {
            suppressed_dists.insert(normalized_dist_name(identity));
            continue;
        }
        integrity_signals.extend(record_result.signals);
    }

    // 3. Duplicate-owned paths across the just-installed set -> a signal each, unless
    //    EVERY owner of the path is an editable / externally-managed distribution
    //    (then the duplicate is expected drift, not tampering).
    for (path, owners) in index.duplicates() {
        let all_exempt = owners
            .iter()
            .all(|o| suppressed_dists.contains(&normalized_dist_name_of(o)));
        if all_exempt {
            continue;
        }
        let owner_names: Vec<String> = owners.iter().map(|d| d.name.clone()).collect();
        integrity_signals.push(ArtifactSignal {
            kind: ArtifactSignalKind::DuplicateOwnedFile,
            location: SubjectLocation::installed(path_in_first_site(&matched, path.as_str())),
            evidence: format!(
                "installed path '{}' is owned by multiple just-installed distributions: {}",
                path,
                owner_names.join(", ")
            ),
            confidence: crate::artifact::EdgeConfidence::Medium,
        });
    }

    // 4. Fold the surviving signals into AT MOST ONE finding, finalised so policy
    //    overrides + paranoia apply (a strict integrity policy can force Block).
    let findings = post_install_integrity_findings(&integrity_signals);
    result.verdict =
        crate::escalation::finalize_static_verdict(findings, policy, 3, Timings::default());
    result
}

/// The PEP 503-normalised distribution names a resolved set installed, one per
/// artifact, derived from each validated wheel filename with the SAME normaliser
/// the resolver's `name @ file://...` line uses (so a `.dist-info` directory name
/// and an approved distribution name cannot drift). A wheel filename that does not
/// parse contributes nothing (it could not have produced an approved line either).
pub fn installed_distribution_names(resolved: &ResolvedSet) -> Vec<String> {
    let mut names: Vec<String> = resolved
        .artifacts
        .iter()
        .filter_map(|a| crate::artifact::archive::wheel_distribution_name(&a.wheel_filename))
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Discover EVERY installed distribution under a target environment, returning each
/// one's `(dist_info_dir, identity)`. Reuses the SAME [`post_install_site_packages`]
/// venv-layout enumeration the post-install check uses (so the provenance graph and
/// the integrity check see the same site roots), then lists every `<name>-<version>
/// .dist-info` in each. Unlike [`locate_installed_dist_info`], this is name-agnostic:
/// it enumerates the whole environment, for `tirith env graph` (PR F1). A malformed
/// `.dist-info` directory name is skipped; an unreadable site root contributes
/// nothing (best-effort, never panics). Results are sorted by `.dist-info` path for
/// determinism, and de-duplicated so the same distribution dir is not returned twice
/// when two enumerated site roots happen to overlap.
pub fn discover_installed_distributions(
    target_environment: &Path,
) -> Vec<(PathBuf, DistributionIdentity)> {
    let mut found: Vec<(PathBuf, DistributionIdentity)> = Vec::new();
    let mut seen: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    for site in post_install_site_packages(target_environment) {
        let Ok(rd) = std::fs::read_dir(&site) else {
            continue;
        };
        let mut dist_infos: Vec<PathBuf> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.ends_with(".dist-info"))
            })
            .collect();
        dist_infos.sort();
        for dist_info in dist_infos {
            if !seen.insert(dist_info.clone()) {
                continue;
            }
            if let Some((proj, version)) = dist_info_name_version(&dist_info) {
                found.push((
                    dist_info.clone(),
                    DistributionIdentity {
                        ecosystem: Ecosystem::PyPI,
                        name: proj,
                        version: Some(version),
                        dist_info_path: SubjectLocation::installed(dist_info),
                    },
                ));
            }
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// The `site-packages` roots under a target environment the post-install check
/// scans, mirroring the venv layouts pip installs into: `<env>/site-packages`,
/// `<env>/Lib/site-packages` (Windows venv), and `<env>/lib/python*/site-packages`
/// (POSIX venv). Only directories that exist are returned. Kept local to the
/// install edge (it enumerates a KNOWN target, not an arbitrary tree) so it does
/// not pull in the broad `ecosystem scan` filesystem walk.
fn post_install_site_packages(env: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = Vec::new();
    for c in [
        env.join("site-packages"),
        env.join("Lib").join("site-packages"),
    ] {
        if c.is_dir() {
            found.push(c);
        }
    }
    let lib = env.join("lib");
    if let Ok(rd) = std::fs::read_dir(&lib) {
        let mut subs: Vec<PathBuf> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("python"))
            })
            .collect();
        subs.sort();
        for s in subs {
            let sp = s.join("site-packages");
            if sp.is_dir() {
                found.push(sp);
            }
        }
    }
    found
}

/// Locate the `.dist-info` directory of `name` (PEP 503-normalised) across the
/// given `site-packages` roots, returning `(site, dist_info_dir, identity)`. A
/// distribution dir is `<project>-<version>.dist-info`; the project part is
/// normalised with the SAME PEP 503 normaliser used for `name`, so case / `-_.`
/// spelling differences between the wheel name and the on-disk dir name still
/// match. The first matching `.dist-info` (sites in order, then sorted dir names)
/// wins.
fn locate_installed_dist_info(
    sites: &[PathBuf],
    name: &str,
) -> Option<(PathBuf, PathBuf, DistributionIdentity)> {
    for site in sites {
        let Ok(rd) = std::fs::read_dir(site) else {
            continue;
        };
        let mut dist_infos: Vec<PathBuf> = rd
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.ends_with(".dist-info"))
            })
            .collect();
        dist_infos.sort();
        for dist_info in dist_infos {
            if let Some((proj, version)) = dist_info_name_version(&dist_info) {
                if crate::artifact::archive::normalize_project_name(&proj) == name {
                    return Some((
                        site.clone(),
                        dist_info.clone(),
                        DistributionIdentity {
                            ecosystem: Ecosystem::PyPI,
                            name: proj,
                            version: Some(version),
                            dist_info_path: SubjectLocation::installed(dist_info),
                        },
                    ));
                }
            }
        }
    }
    None
}

/// Parse `<project>-<version>.dist-info` -> `(project, version)` from the directory
/// name. The project name is returned VERBATIM (the caller normalises it for the
/// match); `None` for a malformed dir name.
fn dist_info_name_version(dist_info: &Path) -> Option<(String, String)> {
    let dir = dist_info.file_name()?.to_str()?;
    let stem = dir.strip_suffix(".dist-info")?;
    let idx = stem.rfind('-')?;
    let (name, version) = stem.split_at(idx);
    let version = &version[1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

/// The PEP 503-normalised name of a distribution identity, for the editable /
/// conda suppression set.
fn normalized_dist_name(dist: &DistributionIdentity) -> String {
    crate::artifact::archive::normalize_project_name(&dist.name)
}

/// Same as [`normalized_dist_name`] for a borrowed reference used in the duplicate
/// owner scan.
fn normalized_dist_name_of(dist: &DistributionIdentity) -> String {
    crate::artifact::archive::normalize_project_name(&dist.name)
}

/// Best-effort absolute location for a duplicate-owned path's signal: the path
/// joined under the FIRST matched site root (the signal location is for display /
/// evidence; the duplicate is a cross-distribution fact, not tied to one site).
fn path_in_first_site(matched: &[(PathBuf, PathBuf, DistributionIdentity)], rel: &str) -> PathBuf {
    matched
        .first()
        .map(|(site, _, _)| site.join(rel))
        .unwrap_or_else(|| PathBuf::from(rel))
}

/// Correlate the surviving post-install integrity signals into AT MOST ONE
/// [`RuleId::PythonInstalledIntegrityViolation`] finding (cross-cutting invariant
/// 1). Returns an empty vec when there is no signal (a clean install).
///
/// Severity is Medium by default (installed-environment drift is common). It rises
/// to High ONLY with a corroborator this post-install check can establish: a
/// duplicate-owned path across two just-installed distributions (a single file two
/// of the wheels both claim, the cross-distribution loader / payload split). A
/// strict integrity policy further upgrades the ACTION to Block via
/// `action_overrides`, applied by [`crate::escalation::finalize_static_verdict`];
/// this function does not itself force Block.
fn post_install_integrity_findings(signals: &[ArtifactSignal]) -> Vec<Finding> {
    if signals.is_empty() {
        return Vec::new();
    }
    use ArtifactSignalKind as K;

    let corroborated = signals.iter().any(|s| s.kind == K::DuplicateOwnedFile);
    let severity = if corroborated {
        Severity::High
    } else {
        Severity::Medium
    };

    // A compact evidence list: the distinct signal kinds, then each signal's detail.
    let mut kinds: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for s in signals {
        if let Ok(serde_json::Value::String(k)) = serde_json::to_value(s.kind) {
            kinds.insert(k);
        }
    }
    let mut evidence: Vec<Evidence> = vec![Evidence::Text {
        detail: format!(
            "correlated post-install integrity signals: {}",
            kinds.into_iter().collect::<Vec<_>>().join(", ")
        ),
    }];
    for s in signals {
        evidence.push(Evidence::Text {
            detail: s.evidence.clone(),
        });
    }

    let title = if corroborated {
        "Installed Python environment integrity violation (duplicate-owned path)".to_string()
    } else {
        "Installed Python environment integrity violation".to_string()
    };
    vec![Finding {
        rule_id: RuleId::PythonInstalledIntegrityViolation,
        severity,
        title,
        description: "After the contained install extracted the approved wheels, an installed \
             distribution failed a RECORD integrity check: a RECORD-listed file did not match its \
             on-disk bytes, a RECORD-listed file was missing, or a path was claimed by more than \
             one just-installed distribution. Editable installs and non-pip (conda / distro) \
             installers drift legitimately and are exempt, so this fires only on an ordinary \
             pip-installed distribution; it is Medium by default and rises with a corroborator \
             such as a duplicate-owned path. Reinstall the affected distribution from a trusted \
             source; set a strict integrity policy (action_overrides) to block on this."
            .to_string(),
        evidence,
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }]
}

// ---------------------------------------------------------------------------
// D7: the install-plan digest the operator approval binds to
// ---------------------------------------------------------------------------

/// The complete, hashable description of an install-from-digest plan that a
/// `tirith pkg approve` decision binds to (PR D7).
///
/// # Why an approval binds to a digest, not a SHA-set
///
/// An operator who approves an install is approving a WHOLE SITUATION, not just a
/// bag of artifact hashes. The same wheels installed into a different interpreter,
/// for a different platform, under a weaker policy, against an older threat-DB
/// sequence, or with a different install command is a DIFFERENT and possibly
/// dangerous operation. Binding the approval to the sorted SHA-set alone would let
/// any of those swap silently after approval. So the approval id is the content
/// hash of every binding input below (`plan_digest`), and the sorted SHA-set
/// ([`Self::artifact_set_label`]) is a human-readable DISPLAY LABEL only, never the
/// binding identity.
///
/// # The binding inputs (the plan's list)
///
/// The digest is `H(artifact hashes, normalized packages, target interpreter/env,
/// platform tags, install-command semantics, redacted policy-projection hash, DB
/// sequence, capsule backend, required coverage, expiry)`. Each is a field here; the
/// digest is the sha256 of the canonical JSON of all of them (with `plan_digest`
/// itself blanked, exactly as [`crate::receipt::ArtifactScanReceipt`] content-
/// addresses itself), through the SAME [`crate::audit::canonical_json_for_hash`] the
/// audit chain uses, so the digest is stable, order-independent over the sets it
/// sorts, and reproducible.
///
/// # Redaction
///
/// `policy_projection_hash` is [`crate::policy::Policy::security_projection_hash`]
/// (never the raw policy); `target_environment` and `interpreter` are recorded as
/// their plain paths because the digest is an operator-local binding token, not a
/// shared receipt (the receipt, [`crate::receipt::ArtifactScanReceipt`], stores no
/// paths). The digest is not persisted to a shared store by core; the CLI decides
/// where (if anywhere) to keep an approval record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallPlanDigest {
    /// The content-addressed binding id: the lowercase-hex sha256 of this struct's
    /// canonical JSON with `plan_digest` blanked. The value `tirith pkg approve`
    /// records and `tirith pkg install` re-derives and compares.
    pub plan_digest: String,
    /// Every approved artifact's sha256 (lowercase hex), sorted + de-duplicated.
    /// The bytes the install will extract.
    pub artifact_sha256: Vec<String>,
    /// The PEP 503-normalised distribution names the plan installs, sorted. Bound
    /// so a re-resolve to a different package set invalidates the approval even if a
    /// hash happens to collide in the label.
    pub normalized_packages: Vec<String>,
    /// The resolved target interpreter the install runs `python -m pip` with (its
    /// path). A different interpreter is a different operation.
    pub interpreter: String,
    /// The environment tree pip installs into (its path).
    pub target_environment: String,
    /// The platform tags the resolve targeted (e.g. the wheel ABI / platform tags),
    /// sorted. Empty when the resolve did not constrain them. Bound so an approval
    /// for one platform's wheels does not authorise another's.
    pub platform_tags: Vec<String>,
    /// The install-command semantics: the exact pinned pip argv
    /// ([`InstallCommand::pip_install_args`]) WITHOUT the trailing approved.txt path
    /// (which is install-run-specific), so the security-relevant flags are bound but
    /// a per-run temp path is not. A change to the install flags re-binds.
    pub install_command_semantics: Vec<String>,
    /// The redacted security-projection hash of the effective policy
    /// ([`crate::policy::Policy::security_projection_hash`]). A weaker policy after
    /// approval invalidates it.
    pub policy_projection_hash: String,
    /// The threat-DB build sequence the approval is bound to. The live DB advancing
    /// past this invalidates the approval (cross-cutting invariant 4), exactly as
    /// [`rebind_for_install`] enforces at launch.
    pub threat_db_sequence: u64,
    /// The capsule backend id the install must run under (`"landlock-seccomp"` /
    /// `"seatbelt"` / `"appcontainer"` / `"noop"`). An approval issued for a
    /// containing backend does not authorise a run on a NoOp host.
    pub capsule_backend: String,
    /// The per-capability coverage the install REQUIRES (the spec's
    /// [`crate::capsule::CapsuleSpec::required_coverage`]). Bound so an approval that
    /// demanded raw-network-deny cannot be redeemed against a spec that does not.
    pub required_coverage: crate::capsule::CapsuleCoverage,
    /// RFC 3339 UTC expiry. After this instant the approval is stale and
    /// [`Self::is_expired_at`] refuses it. An empty string means "no expiry"
    /// (the caller chose not to time-box it).
    pub expiry: String,
}

/// The binding inputs for an [`InstallPlanDigest`], everything except the derived
/// `plan_digest` itself. [`InstallPlanDigest::new`] takes this and stamps the hash,
/// keeping the long argument list to one named value.
#[derive(Debug, Clone)]
pub struct InstallPlanInputs {
    /// Every approved artifact's sha256 (any case / order; normalised by `new`).
    pub artifact_sha256: Vec<String>,
    /// The PEP 503-normalised distribution names (sorted by `new`).
    pub normalized_packages: Vec<String>,
    /// The resolved target interpreter path.
    pub interpreter: PathBuf,
    /// The environment tree pip installs into.
    pub target_environment: PathBuf,
    /// The platform tags the resolve targeted (sorted by `new`).
    pub platform_tags: Vec<String>,
    /// The pinned pip argv WITHOUT the trailing approved.txt path.
    pub install_command_semantics: Vec<String>,
    /// The redacted policy-projection hash.
    pub policy_projection_hash: String,
    /// The threat-DB sequence the approval binds to.
    pub threat_db_sequence: u64,
    /// The capsule backend id the install must run under.
    pub capsule_backend: String,
    /// The required per-capability coverage.
    pub required_coverage: crate::capsule::CapsuleCoverage,
    /// RFC 3339 UTC expiry, or empty for none.
    pub expiry: String,
}

impl InstallPlanDigest {
    /// Build a digest from its binding inputs and stamp the content-addressed
    /// `plan_digest`. The lists that have no meaningful order (artifact hashes,
    /// normalised package names, platform tags) are sorted + de-duplicated so two
    /// plans that differ only in input ordering bind to the SAME digest; the install
    /// argv is bound verbatim (its order is meaningful).
    pub fn new(inputs: InstallPlanInputs) -> Self {
        let mut artifact_sha256: Vec<String> = inputs
            .artifact_sha256
            .into_iter()
            .map(|h| h.to_ascii_lowercase())
            .collect();
        artifact_sha256.sort();
        artifact_sha256.dedup();
        let mut normalized_packages = inputs.normalized_packages;
        normalized_packages.sort();
        normalized_packages.dedup();
        let mut platform_tags = inputs.platform_tags;
        platform_tags.sort();
        platform_tags.dedup();

        let mut digest = InstallPlanDigest {
            plan_digest: String::new(),
            artifact_sha256,
            normalized_packages,
            interpreter: inputs.interpreter.display().to_string(),
            target_environment: inputs.target_environment.display().to_string(),
            platform_tags,
            install_command_semantics: inputs.install_command_semantics,
            policy_projection_hash: inputs.policy_projection_hash,
            threat_db_sequence: inputs.threat_db_sequence,
            capsule_backend: inputs.capsule_backend,
            required_coverage: inputs.required_coverage,
            expiry: inputs.expiry,
        };
        digest.plan_digest = digest.compute_plan_digest();
        digest
    }

    /// The lowercase-hex sha256 of this plan's canonical JSON with `plan_digest`
    /// blanked, so the id is a stable function of the binding inputs and never of
    /// itself. Computed through [`crate::audit::canonical_json_for_hash`], the same
    /// canonicaliser the receipt + audit chain use.
    pub fn compute_plan_digest(&self) -> String {
        let mut value = serde_json::to_value(self).unwrap_or(serde_json::Value::Null);
        if let Some(obj) = value.as_object_mut() {
            obj.insert(
                "plan_digest".to_string(),
                serde_json::Value::String(String::new()),
            );
        }
        let canon = crate::audit::canonical_json_for_hash(&value);
        use sha2::Digest as _;
        let mut h = sha2::Sha256::new();
        h.update(canon.as_bytes());
        let out = h.finalize();
        let mut s = String::with_capacity(64);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Whether the stored `plan_digest` matches a recomputation over the binding
    /// inputs. `tirith pkg install` compares the operator-approved digest against
    /// the digest of the plan it is ABOUT to run; a mismatch means the situation
    /// changed (different interpreter, policy, DB sequence, ...) and the install is
    /// refused. Two digests are equivalent iff their `plan_digest` strings match
    /// (the hash binds every field), so callers compare ids.
    pub fn digest_matches(&self) -> bool {
        self.plan_digest == self.compute_plan_digest()
    }

    /// A human-readable DISPLAY LABEL for the artifact set: the sorted sha256s
    /// joined, truncated for readability. NEVER the binding identity (that is
    /// `plan_digest`); shown in the approve/install UX so an operator recognises the
    /// set without reading the full hash list.
    pub fn artifact_set_label(&self) -> String {
        if self.artifact_sha256.is_empty() {
            return "<no artifacts>".to_string();
        }
        self.artifact_sha256
            .iter()
            .map(|h| crate::util::truncate_bytes(h, 12))
            .collect::<Vec<_>>()
            .join("+")
    }

    /// Whether this approval has expired at `now_rfc3339` (an RFC 3339 timestamp).
    /// An empty `expiry` means "no expiry" and never expires. A malformed `expiry`
    /// is treated as ALREADY EXPIRED (fail closed: an approval whose expiry cannot
    /// be parsed is not trusted). A malformed `now` is also fail-closed.
    pub fn is_expired_at(&self, now_rfc3339: &str) -> bool {
        if self.expiry.is_empty() {
            return false;
        }
        let (Ok(expiry), Ok(now)) = (
            chrono::DateTime::parse_from_rfc3339(&self.expiry),
            chrono::DateTime::parse_from_rfc3339(now_rfc3339),
        ) else {
            return true;
        };
        now >= expiry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::quarantine::QuarantineStore;
    use crate::artifact::resolver::ResolvedArtifact;
    use crate::capsule::NetworkPolicy;
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    use std::io::Write as _;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    /// Lowercase-hex SHA-256, the digest the resolver pins.
    fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        hex::encode(h.finalize())
    }

    /// The RECORD `sha256=<base64url-no-pad>` cell for a member body.
    fn record_sha256_cell(body: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(body);
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.finalize());
        format!("sha256={b64}")
    }

    /// Build an in-memory wheel zip from (member, body) pairs.
    fn build_wheel(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zw = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, body) in members {
            zw.start_file(*name, SimpleFileOptions::default()).unwrap();
            zw.write_all(body).unwrap();
        }
        zw.finish().unwrap().into_inner()
    }

    /// A benign wheel for `name` v1.0 whose RECORD correctly hashes every member,
    /// so the firewall inspection is clean. `salt` makes two byte-distinct wheels.
    fn benign_wheel(name: &str, salt: &str) -> Vec<u8> {
        let metadata =
            format!("Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\nSummary: {salt}\n\n");
        let wheel =
            b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n";
        let metadata_bytes = metadata.into_bytes();
        let record = format!(
            "{name}-1.0.dist-info/METADATA,{},{}\n\
             {name}-1.0.dist-info/WHEEL,{},{}\n\
             {name}-1.0.dist-info/RECORD,,\n",
            record_sha256_cell(&metadata_bytes),
            metadata_bytes.len(),
            record_sha256_cell(wheel),
            wheel.len(),
        );
        build_wheel(&[
            (
                &format!("{name}-1.0.dist-info/METADATA"),
                metadata_bytes.as_slice(),
            ),
            (&format!("{name}-1.0.dist-info/WHEEL"), wheel.as_slice()),
            (&format!("{name}-1.0.dist-info/RECORD"), record.as_bytes()),
        ])
    }

    /// A store + open transaction over a fresh temp root.
    fn store_with_txn(id: &str) -> (tempfile::TempDir, QuarantineStore, QuarantineTransaction) {
        let root = tempfile::tempdir().unwrap();
        let store = QuarantineStore::with_root(root.path().join("q")).unwrap();
        let txn = store.begin_transaction(id).unwrap();
        (root, store, txn)
    }

    // ── the pip argv ────────────────────────────────────────────────────────

    #[test]
    fn pip_install_args_are_the_pinned_flags() {
        let cmd = InstallCommand {
            approved_requirements_path: PathBuf::from("/q/txn/approved.txt"),
        };
        let args = cmd.pip_install_args();
        // The exact plan pin, in order: -m pip install + the hardening flags + -r.
        assert_eq!(args[0], "-m");
        assert_eq!(args[1], "pip");
        assert_eq!(args[2], "install");
        for flag in [
            "--isolated",
            "--no-index",
            "--no-deps",
            "--require-hashes",
            "--no-cache-dir",
            "--force-reinstall",
        ] {
            assert!(args.iter().any(|a| a == flag), "missing {flag}");
        }
        // It reads the approved.txt by path as the LAST argument after `-r`.
        let r_idx = args.iter().position(|a| a == "-r").unwrap();
        assert_eq!(args[r_idx + 1], "/q/txn/approved.txt");
        assert_eq!(r_idx + 1, args.len() - 1);
    }

    #[test]
    fn pip_install_uses_force_reinstall_so_an_existing_version_is_not_skipped() {
        // The plan calls force-reinstall out explicitly: without it pip no-ops a
        // package whose version is already installed, defeating a re-verified install.
        let cmd = InstallCommand {
            approved_requirements_path: PathBuf::from("/tmp/approved.txt"),
        };
        assert!(cmd
            .pip_install_args()
            .iter()
            .any(|a| a == "--force-reinstall"));
    }

    // ── file:// URL building ───────────────────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn file_url_is_absolute_three_slash_form() {
        let url =
            file_url_for(Path::new("/q/transactions/txn-1/demo-1.0-py3-none-any.whl")).unwrap();
        assert_eq!(
            url,
            "file:///q/transactions/txn-1/demo-1.0-py3-none-any.whl"
        );
    }

    #[test]
    #[cfg(unix)]
    fn file_url_percent_encodes_unsafe_bytes_but_not_separators() {
        // A space in a path component is encoded as %20; the `/` separators stay.
        let url = file_url_for(Path::new("/q/has space/demo-1.0-py3-none-any.whl")).unwrap();
        assert_eq!(url, "file:///q/has%20space/demo-1.0-py3-none-any.whl");
        // A literal percent is encoded so it is not read as an escape.
        let url2 = file_url_for(Path::new("/q/a%b/demo-1.0-py3-none-any.whl")).unwrap();
        assert!(url2.contains("a%25b"));
    }

    #[test]
    fn file_url_refuses_relative_path() {
        assert!(matches!(
            file_url_for(Path::new("relative/demo-1.0-py3-none-any.whl")),
            Err(InstallError::BadArtifactPath(_))
        ));
    }

    // ── approved.txt generation ────────────────────────────────────────────

    #[test]
    #[cfg(unix)]
    fn approved_requirements_text_pairs_name_url_and_hash() {
        let resolved = ResolvedSet {
            locked_requirements: String::new(),
            artifacts: vec![ResolvedArtifact {
                wheel_filename: "Flask-3.0.0-py3-none-any.whl".to_string(),
                sha256: "A".repeat(64), // upper-case input, must be lowercased
            }],
        };
        let materialized = vec![PathBuf::from("/q/txn-1/Flask-3.0.0-py3-none-any.whl")];
        let text = approved_requirements_text(&resolved, &materialized).unwrap();
        // PEP 503 name (flask, lower-cased), the file:// URL, and the lower-cased hash.
        assert_eq!(
            text,
            format!(
                "flask @ file:///q/txn-1/Flask-3.0.0-py3-none-any.whl --hash=sha256:{}\n",
                "a".repeat(64)
            )
        );
    }

    #[test]
    #[cfg(unix)]
    fn approved_requirements_text_one_line_per_artifact() {
        let resolved = ResolvedSet {
            locked_requirements: String::new(),
            artifacts: vec![
                ResolvedArtifact {
                    wheel_filename: "alpha-1.0-py3-none-any.whl".to_string(),
                    sha256: "a".repeat(64),
                },
                ResolvedArtifact {
                    wheel_filename: "beta-2.0-py3-none-any.whl".to_string(),
                    sha256: "b".repeat(64),
                },
            ],
        };
        let materialized = vec![
            PathBuf::from("/q/txn/alpha-1.0-py3-none-any.whl"),
            PathBuf::from("/q/txn/beta-2.0-py3-none-any.whl"),
        ];
        let text = approved_requirements_text(&resolved, &materialized).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.contains("alpha @ file:///q/txn/alpha-1.0-py3-none-any.whl --hash=sha256:"));
        assert!(text.contains("beta @ file:///q/txn/beta-2.0-py3-none-any.whl --hash=sha256:"));
    }

    #[test]
    fn approved_requirements_text_refuses_count_mismatch() {
        let resolved = ResolvedSet {
            locked_requirements: String::new(),
            artifacts: vec![ResolvedArtifact {
                wheel_filename: "alpha-1.0-py3-none-any.whl".to_string(),
                sha256: "a".repeat(64),
            }],
        };
        // Two paths for one artifact -> shortfall/mismatch, fail closed.
        let materialized = vec![PathBuf::from("/q/a.whl"), PathBuf::from("/q/b.whl")];
        assert!(matches!(
            approved_requirements_text(&resolved, &materialized),
            Err(InstallError::MaterializationShortfall { .. })
        ));
    }

    // ── the capsule spec ───────────────────────────────────────────────────

    #[test]
    fn install_spec_is_deny_all_and_confines_the_right_roots() {
        let txn_dir = PathBuf::from("/q/transactions/txn-1");
        let env = PathBuf::from("/venv");
        let prefix = PathBuf::from("/usr");
        let spec = build_install_spec(&txn_dir, &env, std::slice::from_ref(&prefix));
        // Deny-all network: an install needs no egress.
        assert!(matches!(spec.network, NetworkPolicy::DenyAll));
        // The target environment is writable; the txn dir + interpreter prefix are
        // read roots.
        assert!(spec.filesystem.write_roots.contains(&env));
        assert!(spec.filesystem.read_roots.contains(&txn_dir));
        assert!(spec.filesystem.read_roots.contains(&prefix));
        // The required coverage demands raw-net-deny but NOT the proxy (deny-all).
        let req = spec.required_coverage();
        assert!(req.network_raw_denied);
        assert!(!req.domain_proxy_enforced);
        // The credential subtrees stay denied (locked_down seeds deny_roots).
        assert_eq!(
            spec.filesystem.deny_roots,
            crate::capsule::deny_default_paths()
        );
        // The environment is scrubbed (no inherit, sensitive stripped) by default.
        assert!(!spec.environment.inherit);
        assert!(spec.environment.deny_sensitive);
    }

    // ── the re-bind ────────────────────────────────────────────────────────

    #[test]
    fn rebind_produces_a_plan_for_a_clean_set() {
        let bytes = benign_wheel("demo", "a");
        let digest = sha256_hex(&bytes);
        let filename = "demo-1.0-py3-none-any.whl";

        let (_root, store, txn) = store_with_txn("rebind-clean");
        store.ingest_bytes(&bytes, &digest).unwrap();
        let resolved = ResolvedSet {
            locked_requirements: String::new(),
            artifacts: vec![ResolvedArtifact {
                wheel_filename: filename.to_string(),
                sha256: digest.clone(),
            }],
        };

        let env = txn.dir().join("env"); // any path; just needs to be in the spec
        let plan = rebind_for_install(
            &resolved,
            &txn,
            &Policy::default(),
            None, // no DB
            0,    // approval bound to sequence 0
            &env,
            &[],
        )
        .expect("a clean set re-binds to a plan");

        assert_eq!(plan.materialized.len(), 1);
        assert!(plan.materialized[0].ends_with(filename));
        // The approved.txt references the materialised copy and the approved digest.
        assert!(plan.approved_requirements.contains("demo @ file://"));
        assert!(plan
            .approved_requirements
            .contains(&format!("--hash=sha256:{digest}")));
        assert!(matches!(
            plan.spec.network,
            crate::capsule::NetworkPolicy::DenyAll
        ));
        assert_eq!(plan.bound_db_sequence, 0);
    }

    #[test]
    fn rebind_refuses_a_swapped_blob() {
        // The integrity re-bind: a blob swapped between approval and install fails
        // the re-hash and the firewall blocks, so the install is refused.
        let approved = benign_wheel("demo", "a");
        let approved_digest = sha256_hex(&approved);
        let filename = "demo-1.0-py3-none-any.whl";

        let (_root, store, txn) = store_with_txn("rebind-swap");
        store.ingest_bytes(&approved, &approved_digest).unwrap();
        // Swap the blob bytes underneath the approved-digest path.
        let blob = store.blob_path(&approved_digest);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&blob, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(&blob, b"swapped bytes that do not match the digest").unwrap();

        let resolved = ResolvedSet {
            locked_requirements: String::new(),
            artifacts: vec![ResolvedArtifact {
                wheel_filename: filename.to_string(),
                sha256: approved_digest.clone(),
            }],
        };
        let env = txn.dir().join("env");
        let err = rebind_for_install(&resolved, &txn, &Policy::default(), None, 0, &env, &[])
            .expect_err("a swapped blob must refuse the install");
        match err {
            InstallError::RebindBlocked {
                verdict,
                integrity_mismatch,
            } => {
                assert!(
                    integrity_mismatch,
                    "a swapped blob is an integrity mismatch"
                );
                assert_eq!(verdict.action, crate::verdict::Action::Block);
                assert!(verdict.findings.iter().any(
                    |f| f.rule_id == crate::verdict::RuleId::ArtifactDownloadIntegrityMismatch
                ));
            }
            other => panic!("expected RebindBlocked, got {other:?}"),
        }
    }

    #[test]
    fn rebind_refuses_a_missing_blob() {
        let bytes = benign_wheel("demo", "a");
        let digest = sha256_hex(&bytes);
        let (_root, _store, txn) = store_with_txn("rebind-missing");
        // Deliberately do NOT ingest the blob.
        let resolved = ResolvedSet {
            locked_requirements: String::new(),
            artifacts: vec![ResolvedArtifact {
                wheel_filename: "demo-1.0-py3-none-any.whl".to_string(),
                sha256: digest,
            }],
        };
        let env = txn.dir().join("env");
        let err = rebind_for_install(&resolved, &txn, &Policy::default(), None, 0, &env, &[])
            .unwrap_err();
        // A missing blob is an integrity Block (RebindBlocked), never a silent allow.
        assert!(matches!(
            err,
            InstallError::RebindBlocked {
                integrity_mismatch: true,
                ..
            }
        ));
    }

    #[test]
    fn rebind_refuses_when_db_sequence_advanced() {
        // Bound-state invariant: an approval bound to DB sequence N is invalid once
        // the live DB is at a higher sequence (a newer DB might flag the artifact).
        let bytes = benign_wheel("demo", "a");
        let digest = sha256_hex(&bytes);
        let (_root, store, txn) = store_with_txn("rebind-seq");
        store.ingest_bytes(&bytes, &digest).unwrap();
        let resolved = ResolvedSet {
            locked_requirements: String::new(),
            artifacts: vec![ResolvedArtifact {
                wheel_filename: "demo-1.0-py3-none-any.whl".to_string(),
                sha256: digest,
            }],
        };
        let env = txn.dir().join("env");
        // No live DB (sequence 0) but the approval was bound to sequence 5 -> stale.
        let err = rebind_for_install(&resolved, &txn, &Policy::default(), None, 5, &env, &[])
            .unwrap_err();
        match err {
            InstallError::BoundStateChanged {
                approved_db_sequence,
                current_db_sequence,
            } => {
                assert_eq!(approved_db_sequence, 5);
                assert_eq!(current_db_sequence, 0);
            }
            other => panic!("expected BoundStateChanged, got {other:?}"),
        }
    }

    // ── D5: post-install RECORD verification ────────────────────────────────

    /// The RECORD `sha256=<base64url-no-pad>` cell for a body, as a CSV cell.
    fn record_cell(body: &[u8]) -> String {
        record_sha256_cell(body)
    }

    /// Write an installed distribution under `site`: the `.dist-info` dir, the named
    /// files on disk (relative to `site`), a RECORD listing each `(rel, optional
    /// body-for-hash)` row (a `None` body writes an empty hash/size cell), and any
    /// extra `.dist-info` files (`INSTALLER`, `direct_url.json`). Returns the
    /// `.dist-info` path.
    fn write_installed_dist(
        site: &Path,
        dist_name: &str,
        version: &str,
        files: &[(&str, &[u8])],
        record_rows: &[(&str, Option<&[u8]>)],
        extra_dist_info: &[(&str, &[u8])],
    ) -> PathBuf {
        let dist_info = site.join(format!("{dist_name}-{version}.dist-info"));
        std::fs::create_dir_all(&dist_info).unwrap();
        for (rel, body) in files {
            let p = site.join(rel);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(p, body).unwrap();
        }
        for (name, body) in extra_dist_info {
            std::fs::write(dist_info.join(name), body).unwrap();
        }
        let mut record = String::new();
        for (path, body) in record_rows {
            match body {
                Some(b) => {
                    record.push_str(&format!("{path},{},{}\n", record_cell(b), b.len()));
                }
                None => record.push_str(&format!("{path},,\n")),
            }
        }
        record.push_str(&format!("{dist_name}-{version}.dist-info/RECORD,,\n"));
        std::fs::write(dist_info.join("RECORD"), record).unwrap();
        dist_info
    }

    /// A `<env>/lib/python3.11/site-packages` directory under a fresh temp env.
    fn env_with_site(tmp: &Path) -> PathBuf {
        let site = tmp.join("lib").join("python3.11").join("site-packages");
        std::fs::create_dir_all(&site).unwrap();
        site
    }

    fn finding_count(verdict: &Verdict) -> usize {
        verdict
            .findings
            .iter()
            .filter(|f| f.rule_id == RuleId::PythonInstalledIntegrityViolation)
            .count()
    }

    #[test]
    fn installed_distribution_names_are_pep503_normalised() {
        let resolved = ResolvedSet {
            locked_requirements: String::new(),
            artifacts: vec![
                ResolvedArtifact {
                    wheel_filename: "Flask-3.0.0-py3-none-any.whl".to_string(),
                    sha256: "a".repeat(64),
                },
                ResolvedArtifact {
                    wheel_filename: "typing_extensions-4.9.0-py3-none-any.whl".to_string(),
                    sha256: "b".repeat(64),
                },
            ],
        };
        let names = installed_distribution_names(&resolved);
        // PEP 503: lower-cased, `_` collapsed to `-`.
        assert_eq!(
            names,
            vec!["flask".to_string(), "typing-extensions".to_string()]
        );
    }

    #[test]
    fn post_install_clean_distribution_yields_no_finding() {
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let body = b"def f():\n    return 1\n";
        write_installed_dist(
            &site,
            "demo",
            "1.0",
            &[("demo/mod.py", body)],
            &[("demo/mod.py", Some(body))],
            &[],
        );
        let res = verify_post_install_record(tmp.path(), &["demo".to_string()], &Policy::default());
        assert_eq!(res.distributions_verified, 1);
        assert_eq!(res.distributions_not_found, 0);
        assert_eq!(res.hash_mismatches, 0);
        assert_eq!(
            finding_count(&res.verdict),
            0,
            "a clean install has no finding"
        );
        assert!(!res.is_block());
    }

    #[test]
    fn post_install_record_hash_mismatch_folds_to_medium() {
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        // RECORD hashes the ORIGINAL bytes; the on-disk file is tampered.
        let original = b"original\n";
        write_installed_dist(
            &site,
            "demo",
            "1.0",
            &[("demo/mod.py", b"TAMPERED ON DISK\n")],
            &[("demo/mod.py", Some(original))],
            &[],
        );
        let res = verify_post_install_record(tmp.path(), &["demo".to_string()], &Policy::default());
        assert_eq!(res.hash_mismatches, 1);
        assert_eq!(
            finding_count(&res.verdict),
            1,
            "a real mismatch folds to one finding"
        );
        let f = res
            .verdict
            .findings
            .iter()
            .find(|f| f.rule_id == RuleId::PythonInstalledIntegrityViolation)
            .unwrap();
        assert_eq!(f.severity, Severity::Medium, "a bare mismatch is Medium");
    }

    #[test]
    fn post_install_editable_mismatch_is_not_a_false_positive() {
        // Editable / conda -> no FP: an editable distribution legitimately drifts, so
        // even a hash mismatch in it must NOT fold to a finding.
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let original = b"original editable\n";
        write_installed_dist(
            &site,
            "demo",
            "1.0",
            &[("demo/mod.py", b"DRIFTED editable bytes\n")],
            &[("demo/mod.py", Some(original))],
            // direct_url.json marks it editable.
            &[(
                "direct_url.json",
                br#"{"url":"file:///home/me/demo","dir_info":{"editable":true}}"#,
            )],
        );
        let res = verify_post_install_record(tmp.path(), &["demo".to_string()], &Policy::default());
        // The mismatch is still COUNTED (coverage), but never produces a finding.
        assert_eq!(res.distributions_verified, 1);
        assert_eq!(
            finding_count(&res.verdict),
            0,
            "an editable distribution's drift must not fold to a finding"
        );
        assert!(!res.is_block());
    }

    #[test]
    fn post_install_conda_installer_mismatch_is_not_a_false_positive() {
        // A non-pip installer (conda / distro) legitimately diverges; its mismatch
        // must not fold to a finding either.
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let original = b"original conda\n";
        write_installed_dist(
            &site,
            "demo",
            "1.0",
            &[("demo/mod.py", b"conda-rebuilt bytes\n")],
            &[("demo/mod.py", Some(original))],
            // INSTALLER names a non-pip installer.
            &[("INSTALLER", b"conda\n")],
        );
        let res = verify_post_install_record(tmp.path(), &["demo".to_string()], &Policy::default());
        assert_eq!(
            finding_count(&res.verdict),
            0,
            "a conda-installed distribution's drift must not fold to a finding"
        );
    }

    #[test]
    fn post_install_is_scoped_to_named_distributions_only() {
        // An UNRELATED, pre-installed distribution with a real mismatch must NOT be
        // verified: the install only judges the distributions it named. We install
        // `demo` cleanly and leave a tampered `other` in the same site-packages; only
        // `demo` is named, so `other`'s mismatch is never seen.
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let clean = b"clean\n";
        write_installed_dist(
            &site,
            "demo",
            "1.0",
            &[("demo/mod.py", clean)],
            &[("demo/mod.py", Some(clean))],
            &[],
        );
        let original = b"original other\n";
        write_installed_dist(
            &site,
            "other",
            "2.0",
            &[("other/mod.py", b"TAMPERED other\n")],
            &[("other/mod.py", Some(original))],
            &[],
        );
        let res = verify_post_install_record(tmp.path(), &["demo".to_string()], &Policy::default());
        // Only `demo` was verified; `other`'s tamper is invisible to this install.
        assert_eq!(res.distributions_verified, 1);
        assert_eq!(res.hash_mismatches, 0);
        assert_eq!(finding_count(&res.verdict), 0);
    }

    #[test]
    fn post_install_unfound_distribution_is_a_coverage_gap_not_a_finding() {
        let tmp = tempfile::tempdir().unwrap();
        env_with_site(tmp.path());
        // Name a distribution that was never installed.
        let res =
            verify_post_install_record(tmp.path(), &["ghost".to_string()], &Policy::default());
        assert_eq!(res.distributions_not_found, 1);
        assert_eq!(res.distributions_verified, 0);
        assert_eq!(
            finding_count(&res.verdict),
            0,
            "a not-found dist is a coverage gap"
        );
    }

    #[test]
    fn post_install_duplicate_owned_path_corroborates_to_high() {
        // Two just-installed distributions both list the SAME installed path (the
        // cross-distribution loader/payload split): the duplicate corroborates the
        // Medium default up to High.
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let shared = b"shared\n";
        write_installed_dist(
            &site,
            "alpha",
            "1.0",
            &[("shared/mod.py", shared)],
            &[("shared/mod.py", Some(shared))],
            &[],
        );
        // beta also lists the same path; the ownership index is built from RECORD
        // listings, and beta's own module is present too.
        write_installed_dist(
            &site,
            "beta",
            "1.0",
            &[("beta/mod.py", shared)],
            &[
                ("shared/mod.py", Some(shared)),
                ("beta/mod.py", Some(shared)),
            ],
            &[],
        );
        let res = verify_post_install_record(
            tmp.path(),
            &["alpha".to_string(), "beta".to_string()],
            &Policy::default(),
        );
        assert_eq!(finding_count(&res.verdict), 1);
        let f = res
            .verdict
            .findings
            .iter()
            .find(|f| f.rule_id == RuleId::PythonInstalledIntegrityViolation)
            .unwrap();
        assert_eq!(
            f.severity,
            Severity::High,
            "a duplicate-owned path across two installed distributions is High"
        );
    }

    #[test]
    fn post_install_duplicate_owned_path_suppressed_when_all_owners_exempt() {
        // If the ONLY distributions sharing a path are both editable / externally-
        // managed, the duplicate is expected drift, not tampering -> no finding.
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let shared = b"shared\n";
        write_installed_dist(
            &site,
            "alpha",
            "1.0",
            &[("shared/mod.py", shared)],
            &[("shared/mod.py", Some(shared))],
            &[("INSTALLER", b"conda\n")],
        );
        write_installed_dist(
            &site,
            "beta",
            "1.0",
            &[("beta/mod.py", shared)],
            &[
                ("shared/mod.py", Some(shared)),
                ("beta/mod.py", Some(shared)),
            ],
            &[("INSTALLER", b"conda\n")],
        );
        let res = verify_post_install_record(
            tmp.path(),
            &["alpha".to_string(), "beta".to_string()],
            &Policy::default(),
        );
        assert_eq!(
            finding_count(&res.verdict),
            0,
            "a duplicate between two conda distributions is expected drift, not a finding"
        );
    }

    #[test]
    fn post_install_strict_policy_upgrades_action_to_block() {
        // A strict integrity policy (action_overrides) upgrades the Medium finding's
        // ACTION to Block, applied inside finalize_static_verdict; the fold itself
        // never forces Block.
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let original = b"original\n";
        write_installed_dist(
            &site,
            "demo",
            "1.0",
            &[("demo/mod.py", b"TAMPERED\n")],
            &[("demo/mod.py", Some(original))],
            &[],
        );
        let mut policy = Policy::default();
        // action_overrides is keyed by the rule's wire string, valued "block".
        policy.action_overrides.insert(
            RuleId::PythonInstalledIntegrityViolation.to_string(),
            "block".to_string(),
        );
        let res = verify_post_install_record(tmp.path(), &["demo".to_string()], &policy);
        assert_eq!(finding_count(&res.verdict), 1);
        assert!(
            res.is_block(),
            "a strict integrity policy forces the post-install verdict to Block"
        );
    }

    #[test]
    fn post_install_matches_dist_info_with_different_name_spelling() {
        // The wheel name `typing_extensions` installs a `typing_extensions-*.dist-info`
        // dir; the name we scope by is the normalised `typing-extensions`. The match
        // must still find it (same PEP 503 normaliser both sides).
        let tmp = tempfile::tempdir().unwrap();
        let site = env_with_site(tmp.path());
        let body = b"x = 1\n";
        write_installed_dist(
            &site,
            "typing_extensions",
            "4.9.0",
            &[("typing_extensions.py", body)],
            &[("typing_extensions.py", Some(body))],
            &[],
        );
        let res = verify_post_install_record(
            tmp.path(),
            &["typing-extensions".to_string()],
            &Policy::default(),
        );
        assert_eq!(
            res.distributions_verified, 1,
            "the normalised name must match the on-disk dist-info spelling"
        );
        assert_eq!(res.distributions_not_found, 0);
    }

    // ── D7: InstallPlanDigest ────────────────────────────────────────────────

    /// A full set of binding inputs for a digest, every field populated so a test
    /// can mutate exactly one and observe the digest change.
    fn plan_inputs() -> InstallPlanInputs {
        InstallPlanInputs {
            artifact_sha256: vec!["b".repeat(64), "a".repeat(64)], // out of order
            normalized_packages: vec!["flask".to_string(), "click".to_string()],
            interpreter: PathBuf::from("/venv/bin/python"),
            target_environment: PathBuf::from("/venv"),
            platform_tags: vec!["py3-none-any".to_string()],
            install_command_semantics: InstallCommand {
                approved_requirements_path: PathBuf::from("/q/txn/approved.txt"),
            }
            .pip_install_args_without_requirements_path(),
            policy_projection_hash: "deadbeef".repeat(8),
            threat_db_sequence: 7,
            capsule_backend: "landlock-seccomp".to_string(),
            required_coverage: crate::capsule::CapsuleSpec::locked_down().required_coverage(),
            expiry: "2026-06-22T12:00:00+00:00".to_string(),
        }
    }

    #[test]
    fn plan_digest_is_content_addressed_and_stable() {
        let d = InstallPlanDigest::new(plan_inputs());
        // The id is the content hash with id blanked: reproducible and self-consistent.
        assert_eq!(d.plan_digest.len(), 64);
        assert!(d.digest_matches());
        assert_eq!(d.compute_plan_digest(), d.plan_digest);
        // The unordered lists were sorted + de-duplicated by `new`.
        assert_eq!(d.artifact_sha256, vec!["a".repeat(64), "b".repeat(64)]);
        assert_eq!(d.normalized_packages, vec!["click", "flask"]);
    }

    #[test]
    fn plan_digest_is_order_independent_over_the_sorted_sets() {
        // Two plans differing ONLY in the order they list artifacts / packages bind
        // to the SAME digest (the sets are sorted before hashing).
        let a = InstallPlanDigest::new(plan_inputs());
        let mut other = plan_inputs();
        other.artifact_sha256 = vec!["a".repeat(64), "b".repeat(64)]; // already sorted
        other.normalized_packages = vec!["flask".to_string(), "click".to_string()];
        let b = InstallPlanDigest::new(other);
        assert_eq!(a.plan_digest, b.plan_digest);
    }

    #[test]
    fn plan_digest_changes_when_any_bound_input_changes() {
        let base = InstallPlanDigest::new(plan_inputs());

        // Each of these is a DIFFERENT install situation and MUST re-bind the digest.
        type Mutator = Box<dyn Fn(&mut InstallPlanInputs)>;
        let mutate: Vec<(&str, Mutator)> = vec![
            (
                "different artifact hash",
                Box::new(|i: &mut InstallPlanInputs| i.artifact_sha256 = vec!["c".repeat(64)]),
            ),
            (
                "different package set",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.normalized_packages = vec!["evil".to_string()]
                }),
            ),
            (
                "different interpreter",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.interpreter = PathBuf::from("/other/python")
                }),
            ),
            (
                "different target env",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.target_environment = PathBuf::from("/other")
                }),
            ),
            (
                "different platform tags",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.platform_tags = vec!["cp311-cp311-manylinux".to_string()]
                }),
            ),
            (
                "different install command",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.install_command_semantics = vec!["-m".to_string(), "pip".to_string()]
                }),
            ),
            (
                "weaker policy",
                Box::new(|i: &mut InstallPlanInputs| i.policy_projection_hash = "0".repeat(64)),
            ),
            (
                "advanced DB sequence",
                Box::new(|i: &mut InstallPlanInputs| i.threat_db_sequence = 8),
            ),
            (
                "different capsule backend",
                Box::new(|i: &mut InstallPlanInputs| i.capsule_backend = "noop".to_string()),
            ),
            (
                "weaker required coverage",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.required_coverage = crate::capsule::CapsuleCoverage::NONE
                }),
            ),
            (
                "different expiry",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.expiry = "2027-01-01T00:00:00+00:00".to_string()
                }),
            ),
        ];

        for (label, f) in mutate {
            let mut inputs = plan_inputs();
            f(&mut inputs);
            let changed = InstallPlanDigest::new(inputs);
            assert_ne!(
                changed.plan_digest, base.plan_digest,
                "changing the {label} must re-bind the plan digest"
            );
        }
    }

    #[test]
    fn plan_digest_install_semantics_omit_the_per_run_approved_txt_path() {
        // The bound install argv carries the security-relevant flags but NOT the
        // per-run approved.txt path, so two runs writing approved.txt to different
        // temp dirs still bind to the same digest.
        let semantics = InstallCommand {
            approved_requirements_path: PathBuf::from("/q/txn-A/approved.txt"),
        }
        .pip_install_args_without_requirements_path();
        // The flags are present; no concrete approved.txt path is.
        assert!(semantics.iter().any(|a| a == "--require-hashes"));
        assert!(semantics.iter().any(|a| a == "--no-index"));
        assert!(!semantics.iter().any(|a| a.contains("approved.txt")));
        assert!(!semantics.iter().any(|a| a == "-r"));
    }

    #[test]
    fn artifact_set_label_is_a_display_label_not_the_binding() {
        let d = InstallPlanDigest::new(plan_inputs());
        let label = d.artifact_set_label();
        // The label is the truncated sorted hashes joined; it is NOT the binding id.
        assert!(label.contains(&"a".repeat(12)));
        assert!(label.contains(&"b".repeat(12)));
        assert_ne!(label, d.plan_digest, "the label must not be the digest");
    }

    #[test]
    fn plan_digest_roundtrips_through_json() {
        let d = InstallPlanDigest::new(plan_inputs());
        let json = serde_json::to_string(&d).unwrap();
        let back: InstallPlanDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
        assert!(back.digest_matches());
    }

    #[test]
    fn plan_digest_detects_an_edited_record() {
        // An attacker who edits a saved approval (e.g. swaps the interpreter) but
        // leaves the stored digest stale is caught: digest_matches() recomputes.
        let mut d = InstallPlanDigest::new(plan_inputs());
        d.interpreter = "/attacker/python".to_string();
        assert!(
            !d.digest_matches(),
            "an edited binding field with a stale digest must not validate"
        );
    }

    #[test]
    fn plan_digest_expiry_is_fail_closed() {
        let mut d = InstallPlanDigest::new(plan_inputs()); // expiry 2026-06-22T12:00
                                                           // Before expiry: live.
        assert!(!d.is_expired_at("2026-06-22T11:59:59+00:00"));
        // At/after expiry: expired.
        assert!(d.is_expired_at("2026-06-22T12:00:00+00:00"));
        assert!(d.is_expired_at("2026-06-23T00:00:00+00:00"));
        // A malformed expiry is treated as already expired (fail closed).
        d.expiry = "not-a-timestamp".to_string();
        assert!(d.is_expired_at("2026-06-22T11:00:00+00:00"));
        // An empty expiry never expires.
        d.expiry = String::new();
        assert!(!d.is_expired_at("2030-01-01T00:00:00+00:00"));
    }
}
