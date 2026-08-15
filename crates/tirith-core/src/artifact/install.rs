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
//! 2. **Generate `approved.txt`.** [`approved_requirements_text`] emits one local,
//!    hash-pinned wheel requirement per materialised wheel. Unix uses a strict
//!    `./<file>.whl` operand that is resolved only after `fchdir` to the retained
//!    transaction-directory capability; Windows uses an absolute `file://` URL
//!    while a no-delete-sharing directory handle pins that path. pip is thereby
//!    told to install only those local files and to refuse any whose content does
//!    not hash to the approved digest.
//!
//! 3. **The pip argv.** [`InstallCommand::pip_install_args`] is exactly the plan's
//!    pin: `-I -m pip install --isolated --no-index --no-deps --require-hashes
//!    --no-cache-dir --no-input --disable-pip-version-check --force-reinstall
//!    --upgrade --target <dedicated-target> -r <approved.txt>`. `--force-reinstall`
//!    (or a fresh target) is mandatory: without it pip SKIPS a package whose
//!    version is already installed, so a re-verified install of a pinned version
//!    would no-op. `--no-index` + local wheel
//!    references mean pip never touches the network; `--no-deps` because the
//!    resolver already produced a transitively-complete, fully-pinned set;
//!    `--isolated` + `--no-cache-dir` so no ambient pip config or cache can redirect
//!    the install; `--no-input` so a contained install never blocks on an
//!    interactive prompt; `--disable-pip-version-check` so pip skips its own
//!    network self-update check (which would otherwise reach out under a deny-all
//!    spec).
//!
//! 4. **The capsule spec.** [`build_install_spec`] is a locked-down, **deny-all
//!    network** [`CapsuleSpec`]: the install needs no outbound traffic once the
//!    bytes are quarantined, so the source artifact is the only thing pip reads and
//!    the target environment is the only thing it writes. The transaction directory
//!    is granted READ (pip reads the local wheels) and the target environment
//!    tree is granted WRITE (pip extracts into it). The credential subtrees stay
//!    denied, the environment is scrubbed of secrets, and conservative resource
//!    limits apply.
//!
//! # What lives here vs. the CLI crate
//!
//! This module is **pure / async-free**: it parses, composes the firewall, builds
//! the `approved.txt` text, the pip argv, and the spec, and decides whether the
//! re-bind passes. It does NOT spawn anything. The actual contained launch through
//! `tirith::cli::capsule::run_to_completion_bound_inputs` lives in the CLI crate
//! (`pkg_install.rs`), because the capsule launcher needs the OS backends. Enforcing
//! execution is x86_64 Linux-only; every other platform or architecture **fails
//! closed before pip starts**. The grep-test the plan calls for (that the
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

#[cfg(any(not(unix), test))]
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};

use crate::artifact::firewall::{firewall_resolved_set, FirewallOutcome};
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
#[cfg(any(not(unix), test))]
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
    /// A materialised wheel path could not be turned into a safe local requirement
    /// line (a non-wheel filename slipped through, a path had no file name, or the
    /// Windows path could not form an absolute `file://` URL). Fail-closed.
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
                write!(f, "cannot build a local requirement for artifact path {p:?}")
            }
        }
    }
}

impl std::error::Error for InstallError {}

/// The exact pip command D4 runs inside the no-network capsule, plus the path of
/// the `approved.txt` requirements file it reads.
///
/// Held as a small value so the CLI consumer can log the argv (secret-free: it is
/// only flags + the approved.txt path) into the D6 receipt and so the argv is unit
/// testable without spawning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallCommand {
    /// The generated `approved.txt` path. It is descriptor-cwd-relative on Unix
    /// and absolute beneath a path-pinned directory on Windows.
    pub approved_requirements_path: PathBuf,
    /// The exact dedicated directory passed to pip's `--target`. Enforcing
    /// callers bind this directory by capability at launch; the path remains in
    /// the approval semantics so changing the destination always re-binds.
    pub target_environment: PathBuf,
}

impl InstallCommand {
    /// The `python -I -m pip install ...` argument vector (everything after the
    /// interpreter path), exactly the plan's pin:
    ///
    /// `-I -m pip install --isolated --no-index --no-deps --require-hashes
    /// --no-cache-dir --no-input --disable-pip-version-check --force-reinstall
    /// --upgrade --target <dedicated-target> -r <approved.txt>`
    ///
    /// `--force-reinstall` is mandatory so pip does not silently skip a package
    /// whose version is already installed; `--no-index` + the local references
    /// in `approved.txt` keep the install fully offline; `--require-hashes` makes
    /// pip refuse any file whose content does not hash to the pinned digest;
    /// `--no-deps` because the lock is transitively complete; `--isolated` +
    /// `--no-cache-dir` so no ambient pip config / cache can redirect it;
    /// `--no-input` so the contained install never blocks on an interactive prompt;
    /// `--disable-pip-version-check` so pip skips its own network version self-check
    /// (which a deny-all spec would otherwise stall).
    ///
    /// The interpreter is invoked as `python -I -m pip` (never a PATH `pip` shim), the
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
            // `-I` prevents user-site, PYTHONPATH, and current-directory imports
            // from changing which root-managed pip tree the approval attested.
            "-I".to_string(),
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
            // pip target installs otherwise keep pre-existing destination entries
            // even when `--force-reinstall` is present. The enforcing surface uses
            // a fresh dedicated target, and keeps this flag pinned as defense in
            // depth against a target populated after approval.
            "--upgrade".to_string(),
            "--target".to_string(),
            self.target_environment.display().to_string(),
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
/// that location, and launches `python -I -m pip` with
/// [`InstallCommand::pip_install_args`] through the capsule under
/// [`crate::capsule`]'s fail-closed launcher.
#[derive(Debug, Clone)]
pub struct DigestInstallPlan {
    /// The `approved.txt` content: one capability-relative (Unix) or path-pinned
    /// absolute (Windows) local wheel plus `--hash=sha256:<d>` per materialised
    /// wheel. The caller writes this verbatim.
    pub approved_requirements: String,
    /// The materialised `*.whl` paths the plan references (the immutable
    /// transaction copies). Parallel to the requirement lines, by input order.
    pub materialized: Vec<PathBuf>,
    /// Approved lowercase SHA-256 digests parallel to [`Self::materialized`]. The
    /// Windows launcher re-hashes its read-share-only pinned file handles against
    /// these values immediately before process creation.
    pub materialized_sha256: Vec<String>,
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
    let outcome = require_complete_firewall_outcome(
        firewall_resolved_set(resolved, txn, policy, live_db),
        policy,
    )?;

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
    // the artifact's approved digest with its capability-safe local reference.
    let approved_requirements = approved_requirements_text(resolved, &outcome.materialized)?;
    let spec = build_install_spec(txn.dir(), target_environment, extra_read_roots);

    Ok(DigestInstallPlan {
        approved_requirements,
        materialized: outcome.materialized,
        materialized_sha256: resolved
            .artifacts
            .iter()
            .map(|artifact| artifact.sha256.to_ascii_lowercase())
            .collect(),
        spec,
        bound_db_sequence: current_db_sequence,
    })
}

/// Enforce the install edge independently of the firewall's verdict assembly.
/// The firewall normally emits a blocking `AnalysisIncomplete` finding for every
/// typed gap, but this second chokepoint prevents a future caller/finalizer drift
/// from turning incomplete artifact bytes into a launch-ready plan.
fn require_complete_firewall_outcome(
    mut outcome: FirewallOutcome,
    policy: &Policy,
) -> Result<FirewallOutcome, InstallError> {
    let coverage_gaps = outcome.set_inspection.all_coverage_gaps();
    crate::artifact::enforce_artifact_coverage_floor(
        &mut outcome.verdict,
        &coverage_gaps,
        Some(policy),
        true,
    );
    if outcome.is_block() || !coverage_gaps.is_empty() {
        return Err(InstallError::RebindBlocked {
            integrity_mismatch: outcome.has_integrity_mismatch(),
            verdict: Box::new(outcome.verdict),
        });
    }
    Ok(outcome)
}

/// Build the `approved.txt` requirements text for a resolved set whose wheels just
/// materialised at `materialized` (parallel to `resolved.artifacts`).
///
/// On Unix each line is `./<file>.whl --hash=sha256:<digest>`. The enforcing
/// launcher enters the transaction through its retained directory descriptor,
/// so both the requirements file and every wheel are resolved relative to that
/// exact directory identity rather than reopening an attacker-replaceable absolute
/// pathname. On Windows the no-delete-sharing directory handle pins the path, so
/// the line remains `name @ file:///<abs>/<file>.whl --hash=...`.
///
/// * `name` is the PEP 503-normalised distribution name parsed from the validated
///   wheel filename ([`crate::artifact::archive::wheel_distribution_name`]). A
///   direct-reference requirement needs the project name so pip records the install
///   under the right distribution.
/// * the Unix `./` path is only consumed with the held-directory cwd binding; the
///   Windows `file://` URL names the immutable transaction copy pinned by its held
///   directory handle.
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
        #[cfg(unix)]
        {
            // Keep the parse above as a defensive wheel/name validation even though
            // pip derives the distribution name from the relative wheel itself.
            let _ = dist;
            lines.push_str(&format!(
                "./{file_name} --hash=sha256:{}\n",
                artifact.sha256.to_ascii_lowercase()
            ));
        }
        #[cfg(not(unix))]
        {
            let url = file_url_for(path)?;
            lines.push_str(&format!(
                "{dist} @ {url} --hash=sha256:{}\n",
                artifact.sha256.to_ascii_lowercase()
            ));
        }
    }
    Ok(lines)
}

/// Turn an absolute filesystem path into a `file://` URL with each component
/// percent-encoded ([`FILE_URL_PATH_ENCODE`]). Refuses a non-absolute path (a
/// `file://` URL must be absolute). On Windows the leading drive component yields a
/// `file:///C:/...` form; on Unix a leading `/` yields `file:///...`.
#[cfg(any(not(unix), test))]
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
/// * READ the transaction directory (pip reads the local wheels there) and the
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
    // Read the transaction dir (the local wheels + approved.txt live here).
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
    /// environment's `site-packages` (no matching `.dist-info`). This is a coverage
    /// gap rather than proof of tampering, but enforcing callers must fail closed.
    pub distributions_not_found: usize,
    /// How many located distributions had NO RECORD file. This is a coverage gap
    /// rather than proof of tampering, but enforcing callers must fail closed.
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

    /// Whether the check established complete integrity coverage for at least one
    /// expected distribution. Enforcing install/verify surfaces use this in addition
    /// to the policy-level verdict so an empty Allow cannot mean success.
    pub fn is_complete(&self) -> bool {
        self.distributions_verified > 0
            && self.distributions_not_found == 0
            && self.records_missing == 0
    }
}

/// Exact distribution identity expected from one approved wheel. Enforcing
/// installs carry the version as well as the normalized project name so a clean
/// stale `.dist-info` directory cannot satisfy verification for a different
/// wheel version. Analysis-only `verify-env` callers may leave `version` empty by
/// using [`verify_post_install_record`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExpectedInstalledDistribution {
    pub name: String,
    pub version: Option<String>,
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
    let expected: Vec<ExpectedInstalledDistribution> = installed_names
        .iter()
        .map(|name| ExpectedInstalledDistribution {
            name: name.clone(),
            version: None,
        })
        .collect();
    verify_post_install_record_exact(target_environment, &expected, policy)
}

/// Version-exact enforcing variant of [`verify_post_install_record`]. Exactly one
/// `.dist-info` directory must match every expected name/version pair. Missing,
/// stale-version-only, and duplicate matches are coverage failures.
pub fn verify_post_install_record_exact(
    target_environment: &Path,
    expected_distributions: &[ExpectedInstalledDistribution],
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

    // Locate exactly one `.dist-info` for each approved distribution identity.
    let mut matched: Vec<(PathBuf, PathBuf, DistributionIdentity)> = Vec::new();
    let mut integrity_signals: Vec<ArtifactSignal> = Vec::new();
    let sites = post_install_site_packages(target_environment);
    for expected in expected_distributions {
        let located = locate_installed_dist_infos(&sites, expected);
        match located.as_slice() {
            [only] => matched.push(only.clone()),
            [] => result.distributions_not_found += 1,
            duplicates => {
                result.distributions_not_found += 1;
                integrity_signals.push(ArtifactSignal {
                    kind: ArtifactSignalKind::DuplicateOwnedFile,
                    location: SubjectLocation::installed(target_environment),
                    evidence: format!(
                        "expected exactly one installed {}{} but found {} matching .dist-info directories: {}",
                        expected.name,
                        expected
                            .version
                            .as_deref()
                            .map(|version| format!("=={version}"))
                            .unwrap_or_default(),
                        duplicates.len(),
                        duplicates
                            .iter()
                            .map(|(_, path, _)| path.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    confidence: crate::artifact::EdgeConfidence::High,
                });
            }
        }
    }

    if matched.is_empty() {
        result.verdict = crate::escalation::finalize_static_verdict(
            post_install_integrity_findings(&integrity_signals),
            policy,
            3,
            Timings::default(),
        );
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
/// artifact, derived from each validated wheel filename with the same normaliser
/// used while producing its approved local requirement (so a `.dist-info`
/// directory name and an approved distribution name cannot drift). A wheel
/// filename that does not parse contributes nothing (it could not have produced an
/// approved line either).
pub fn installed_distribution_names(resolved: &ResolvedSet) -> Vec<String> {
    let mut names: Vec<String> = installed_distribution_identities(resolved)
        .into_iter()
        .map(|identity| identity.name)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Exact normalized project name and version carried by each approved wheel.
/// Malformed filenames contribute nothing because they could not have crossed
/// archive identity validation or produced an approved requirement.
pub fn installed_distribution_identities(
    resolved: &ResolvedSet,
) -> Vec<ExpectedInstalledDistribution> {
    let mut identities: Vec<ExpectedInstalledDistribution> = resolved
        .artifacts
        .iter()
        .filter_map(|artifact| {
            let name = crate::artifact::archive::wheel_distribution_name(&artifact.wheel_filename)?;
            let stem = artifact.wheel_filename.strip_suffix(".whl").or_else(|| {
                artifact
                    .wheel_filename
                    .to_ascii_lowercase()
                    .ends_with(".whl")
                    .then_some(&artifact.wheel_filename[..artifact.wheel_filename.len() - 4])
            })?;
            let version = stem.split('-').nth(1)?.trim().to_ascii_lowercase();
            (!version.is_empty()).then_some(ExpectedInstalledDistribution {
                name,
                version: Some(version),
            })
        })
        .collect();
    identities.sort();
    identities.dedup();
    identities
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
    // pip `--target DIR` installs packages and `.dist-info` directories directly
    // in DIR. Keep that explicit-target layout alongside ordinary venv layouts.
    if env.is_dir() {
        found.push(env.to_path_buf());
    }
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

/// Locate every `.dist-info` directory matching an exact expected identity across
/// the given `site-packages` roots, returning `(site, dist_info_dir, identity)`. A
/// distribution dir is `<project>-<version>.dist-info`; the project part is
/// normalised with the SAME PEP 503 normaliser used for `name`, so case / `-_.`
/// spelling differences between the wheel name and the on-disk dir name still
/// match. Enforcing callers require exactly one result; silently taking the first
/// would let a stale clean version attest different newly installed bytes.
fn locate_installed_dist_infos(
    sites: &[PathBuf],
    expected: &ExpectedInstalledDistribution,
) -> Vec<(PathBuf, PathBuf, DistributionIdentity)> {
    let mut matches = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
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
                let name_matches =
                    crate::artifact::archive::normalize_project_name(&proj) == expected.name;
                let version_matches = expected.version.as_deref().is_none_or(|expected_version| {
                    version.trim().eq_ignore_ascii_case(expected_version.trim())
                });
                if name_matches && version_matches && seen.insert(dist_info.clone()) {
                    matches.push((
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
    matches.sort_by(|left, right| left.1.cmp(&right.1));
    matches
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
    /// SHA-256 of the exact interpreter bytes retained for the install. A path is
    /// not a content identity when an explicitly enrolled tool is user-writable.
    pub interpreter_sha256: String,
    /// The exact resolver executable used to produce the pinned wheel set.
    pub resolver: String,
    /// SHA-256 of the retained resolver executable bytes.
    pub resolver_sha256: String,
    /// Exact resolver version captured from the retained executable.
    #[serde(default)]
    pub resolver_version: String,
    /// Exact pip distribution version read from the bound metadata tree.
    #[serde(default)]
    pub package_manager_version: String,
    /// Canonical root-managed pip package directory selected by the interpreter.
    #[serde(default)]
    pub pip_tree_root: String,
    /// Deterministic digest over the pip package and matching dist-info trees.
    #[serde(default)]
    pub pip_tree_sha256: String,
    /// Version of the deterministic pip-tree attestation format.
    #[serde(default)]
    pub pip_tree_binding_version: u32,
    /// Maximum regular-file count accepted by the attestation algorithm.
    #[serde(default)]
    pub pip_tree_max_files: u64,
    /// Maximum aggregate regular-file bytes accepted by the attestation algorithm.
    #[serde(default)]
    pub pip_tree_max_bytes: u64,
    /// Maximum bytes accepted for any one pip-tree regular file.
    #[serde(default)]
    pub pip_tree_max_file_bytes: u64,
    /// Maximum UTF-8 bytes accepted for any pip-tree relative path.
    #[serde(default)]
    pub pip_tree_max_path_bytes: u64,
    /// Actual regular-file count incorporated into the attestation.
    #[serde(default)]
    pub pip_tree_files: u64,
    /// Actual aggregate regular-file bytes incorporated into the attestation.
    #[serde(default)]
    pub pip_tree_bytes: u64,
    /// The environment tree pip installs into (its path).
    pub target_environment: String,
    /// Stable filesystem identity of the already-existing target parent.
    #[serde(default)]
    pub target_parent_identity: String,
    /// Exact ordinary final component created beneath the bound parent.
    #[serde(default)]
    pub target_component: String,
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
    /// The task-gate ceiling in force when the plan was built
    /// ([`crate::task_boundary::ceiling_binding`]): the gate mode plus the
    /// effects it denied. Bound so an approval taken while the gate refused
    /// network egress cannot be redeemed once the operator has relaxed it, the
    /// same way `policy_projection_hash` binds the rest of the posture.
    ///
    /// It is a field of its own precisely because
    /// [`crate::policy::Policy::security_projection`] emits no `task_gate` key:
    /// the gate is the one posture dimension `policy_projection_hash` does not
    /// carry, so without this the digest would say nothing about it.
    ///
    /// `serde(default)` keeps an approval record written before this field
    /// existed loadable; its digest will simply no longer match, which is the
    /// fail-closed outcome (the operator re-approves).
    #[serde(default)]
    pub task_gate_binding: String,
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
    /// SHA-256 of the exact retained interpreter bytes.
    pub interpreter_sha256: String,
    /// The exact resolver executable path.
    pub resolver: PathBuf,
    /// SHA-256 of the exact retained resolver executable bytes.
    pub resolver_sha256: String,
    /// Exact resolver version captured from the retained executable.
    pub resolver_version: String,
    /// Exact pip distribution version read from bound metadata.
    pub package_manager_version: String,
    /// Canonical root-managed pip package directory.
    pub pip_tree_root: PathBuf,
    /// Deterministic pip package + dist-info tree digest.
    pub pip_tree_sha256: String,
    /// Pip-tree attestation format version.
    pub pip_tree_binding_version: u32,
    /// Pip-tree maximum regular-file count.
    pub pip_tree_max_files: u64,
    /// Pip-tree maximum aggregate bytes.
    pub pip_tree_max_bytes: u64,
    /// Pip-tree maximum bytes for one regular file.
    pub pip_tree_max_file_bytes: u64,
    /// Pip-tree maximum relative-path bytes.
    pub pip_tree_max_path_bytes: u64,
    /// Pip-tree actual regular-file count.
    pub pip_tree_files: u64,
    /// Pip-tree actual aggregate bytes.
    pub pip_tree_bytes: u64,
    /// The environment tree pip installs into.
    pub target_environment: PathBuf,
    /// Stable target-parent filesystem identity.
    pub target_parent_identity: String,
    /// Exact target final component.
    pub target_component: String,
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
    /// The task-gate ceiling this plan was built under.
    pub task_gate_binding: String,
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
            interpreter_sha256: inputs.interpreter_sha256.to_ascii_lowercase(),
            resolver: inputs.resolver.display().to_string(),
            resolver_sha256: inputs.resolver_sha256.to_ascii_lowercase(),
            resolver_version: inputs.resolver_version,
            package_manager_version: inputs.package_manager_version,
            pip_tree_root: inputs.pip_tree_root.display().to_string(),
            pip_tree_sha256: inputs.pip_tree_sha256.to_ascii_lowercase(),
            pip_tree_binding_version: inputs.pip_tree_binding_version,
            pip_tree_max_files: inputs.pip_tree_max_files,
            pip_tree_max_bytes: inputs.pip_tree_max_bytes,
            pip_tree_max_file_bytes: inputs.pip_tree_max_file_bytes,
            pip_tree_max_path_bytes: inputs.pip_tree_max_path_bytes,
            pip_tree_files: inputs.pip_tree_files,
            pip_tree_bytes: inputs.pip_tree_bytes,
            target_environment: inputs.target_environment.display().to_string(),
            target_parent_identity: inputs.target_parent_identity,
            target_component: inputs.target_component,
            platform_tags,
            install_command_semantics: inputs.install_command_semantics,
            policy_projection_hash: inputs.policy_projection_hash,
            threat_db_sequence: inputs.threat_db_sequence,
            capsule_backend: inputs.capsule_backend,
            required_coverage: inputs.required_coverage,
            task_gate_binding: inputs.task_gate_binding,
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

    /// A hash-valid/RECORD-valid wheel whose native member cannot be deeply
    /// parsed. This must never reach approved.txt or the capsule launch plan.
    fn incomplete_native_wheel() -> Vec<u8> {
        let native = b"not a parseable ELF/Mach-O/PE object";
        let metadata = b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n\n";
        let wheel =
            b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: false\nTag: cp311-none-any\n";
        let record = format!(
            "demo/_broken.abi3.so,{},{}\n\
             demo-1.0.dist-info/METADATA,{},{}\n\
             demo-1.0.dist-info/WHEEL,{},{}\n\
             demo-1.0.dist-info/RECORD,,\n",
            record_sha256_cell(native),
            native.len(),
            record_sha256_cell(metadata),
            metadata.len(),
            record_sha256_cell(wheel),
            wheel.len(),
        );
        build_wheel(&[
            ("demo/_broken.abi3.so", native),
            ("demo-1.0.dist-info/METADATA", metadata),
            ("demo-1.0.dist-info/WHEEL", wheel),
            ("demo-1.0.dist-info/RECORD", record.as_bytes()),
        ])
    }

    /// A store + open transaction over a fresh temp root.
    fn store_with_txn(id: &str) -> (tempfile::TempDir, QuarantineStore, QuarantineTransaction) {
        let root = tempfile::tempdir().unwrap();
        let store = QuarantineStore::with_root(root.path().join("q")).unwrap();
        let txn = store.begin_transaction(id).unwrap();
        (root, store, txn)
    }

    // ---- the pip argv --------------------------------------------------------

    #[test]
    fn pip_install_args_are_the_pinned_flags() {
        let cmd = InstallCommand {
            approved_requirements_path: PathBuf::from("/q/txn/approved.txt"),
            target_environment: PathBuf::from("/dedicated-target"),
        };
        let args = cmd.pip_install_args();
        // The exact plan pin, in order: -I -m pip install + hardening flags + -r.
        assert_eq!(args[0], "-I");
        assert_eq!(args[1], "-m");
        assert_eq!(args[2], "pip");
        assert_eq!(args[3], "install");
        for flag in [
            "--isolated",
            "--no-index",
            "--no-deps",
            "--require-hashes",
            "--no-cache-dir",
            "--force-reinstall",
            "--upgrade",
        ] {
            assert!(args.iter().any(|a| a == flag), "missing {flag}");
        }
        // It reads the approved.txt by path as the LAST argument after `-r`.
        let r_idx = args.iter().position(|a| a == "-r").unwrap();
        assert_eq!(args[r_idx + 1], "/q/txn/approved.txt");
        assert_eq!(r_idx + 1, args.len() - 1);
        let target_idx = args.iter().position(|a| a == "--target").unwrap();
        assert_eq!(args[target_idx + 1], "/dedicated-target");
    }

    #[test]
    fn pip_install_uses_force_reinstall_so_an_existing_version_is_not_skipped() {
        // The plan calls force-reinstall out explicitly: without it pip no-ops a
        // package whose version is already installed, defeating a re-verified install.
        let cmd = InstallCommand {
            approved_requirements_path: PathBuf::from("/tmp/approved.txt"),
            target_environment: PathBuf::from("/dedicated-target"),
        };
        assert!(cmd
            .pip_install_args()
            .iter()
            .any(|a| a == "--force-reinstall"));
    }

    // ---- file:// URL building ------------------------------------------------

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

    // ---- approved.txt generation ---------------------------------------------

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
        // The wheel is relative to the descriptor-bound transaction cwd and the
        // hash is lower-cased.
        assert_eq!(
            text,
            format!(
                "./Flask-3.0.0-py3-none-any.whl --hash=sha256:{}\n",
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
        assert!(text.contains("./alpha-1.0-py3-none-any.whl --hash=sha256:"));
        assert!(text.contains("./beta-2.0-py3-none-any.whl --hash=sha256:"));
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

    // ---- the capsule spec ----------------------------------------------------

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

    // ---- the re-bind ---------------------------------------------------------

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
        assert_eq!(plan.materialized_sha256, vec![digest.clone()]);
        // The approved.txt references the materialised copy and the approved digest.
        #[cfg(unix)]
        assert!(plan
            .approved_requirements
            .contains(&format!("./{filename} --hash=sha256:")));
        #[cfg(not(unix))]
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
    fn rebind_refuses_incomplete_native_analysis_before_plan_creation() {
        let bytes = incomplete_native_wheel();
        let digest = sha256_hex(&bytes);
        let (_root, store, txn) = store_with_txn("rebind-native-incomplete");
        store.ingest_bytes(&bytes, &digest).unwrap();
        let resolved = ResolvedSet {
            locked_requirements: String::new(),
            artifacts: vec![ResolvedArtifact {
                wheel_filename: "demo-1.0-py3-none-any.whl".to_string(),
                sha256: digest,
            }],
        };
        let env = txn.dir().join("env");
        let err = rebind_for_install(&resolved, &txn, &Policy::default(), None, 0, &env, &[])
            .expect_err("incomplete native analysis must not produce an install plan");
        match err {
            InstallError::RebindBlocked {
                verdict,
                integrity_mismatch,
            } => {
                assert!(!integrity_mismatch);
                assert_eq!(verdict.action, crate::verdict::Action::Block);
                assert!(verdict
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::AnalysisIncomplete));
            }
            other => panic!("expected RebindBlocked, got {other:?}"),
        }
    }

    #[test]
    fn install_edge_rejects_every_typed_coverage_gap_even_if_upstream_verdict_allows() {
        for kind in crate::scan::CoverageGapKind::ALL {
            let gap = crate::scan::CoverageGap {
                location: SubjectLocation::member(
                    "/quarantine/demo.whl",
                    format!("payload/{}.bin", kind.as_str()),
                ),
                kind,
                sha256: None,
            };
            let outcome = FirewallOutcome {
                verdict: Verdict::from_findings(Vec::new(), 3, Timings::default()),
                integrity_findings: Vec::new(),
                set_inspection: crate::artifact::inspect::ArtifactSetInspection {
                    members: Vec::new(),
                    cross_findings: Vec::new(),
                    gaps: vec![gap],
                },
                materialized: Vec::new(),
            };

            let error = match require_complete_firewall_outcome(outcome, &Policy::default()) {
                Ok(_) => panic!("every incomplete artifact outcome must fail before plan creation"),
                Err(error) => error,
            };
            match error {
                InstallError::RebindBlocked {
                    verdict,
                    integrity_mismatch,
                } => {
                    assert!(
                        !integrity_mismatch,
                        "{} is a coverage failure",
                        kind.as_str()
                    );
                    assert_eq!(
                        verdict.action,
                        crate::verdict::Action::Block,
                        "{} must retain the install Block floor",
                        kind.as_str()
                    );
                    assert!(verdict.findings.iter().any(|finding| {
                        finding.rule_id == RuleId::AnalysisIncomplete
                            && finding.description.contains(kind.as_str())
                    }));
                }
                other => panic!("{} returned the wrong error: {other:?}", kind.as_str()),
            }
        }
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

    // ---- D5: post-install RECORD verification --------------------------------

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
        assert!(res.is_complete());
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
        assert!(!res.is_complete());
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

    #[test]
    fn exact_post_install_verifies_pip_target_directory_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let body = b"installed directly by pip --target\n";
        write_installed_dist(
            tmp.path(),
            "demo",
            "1.0",
            &[("demo.py", body)],
            &[("demo.py", Some(body))],
            &[],
        );
        let expected = [ExpectedInstalledDistribution {
            name: "demo".to_string(),
            version: Some("1.0".to_string()),
        }];
        let result = verify_post_install_record_exact(tmp.path(), &expected, &Policy::default());
        assert_eq!(result.distributions_verified, 1);
        assert!(result.is_complete());
    }

    #[test]
    fn exact_post_install_rejects_stale_version_only() {
        let tmp = tempfile::tempdir().unwrap();
        write_installed_dist(tmp.path(), "demo", "0.9", &[], &[], &[]);
        let expected = [ExpectedInstalledDistribution {
            name: "demo".to_string(),
            version: Some("1.0".to_string()),
        }];
        let result = verify_post_install_record_exact(tmp.path(), &expected, &Policy::default());
        assert_eq!(result.distributions_verified, 0);
        assert_eq!(result.distributions_not_found, 1);
        assert!(!result.is_complete());
    }

    #[test]
    fn exact_post_install_rejects_duplicate_matching_dist_info() {
        let tmp = tempfile::tempdir().unwrap();
        write_installed_dist(tmp.path(), "demo", "1.0", &[], &[], &[]);
        let nested = env_with_site(tmp.path());
        write_installed_dist(&nested, "demo", "1.0", &[], &[], &[]);
        let expected = [ExpectedInstalledDistribution {
            name: "demo".to_string(),
            version: Some("1.0".to_string()),
        }];
        let result = verify_post_install_record_exact(tmp.path(), &expected, &Policy::default());
        assert_eq!(result.distributions_verified, 0);
        assert_eq!(result.distributions_not_found, 1);
        assert_eq!(finding_count(&result.verdict), 1);
    }

    #[test]
    fn resolved_distribution_identities_bind_wheel_versions() {
        let resolved = ResolvedSet {
            locked_requirements: String::new(),
            artifacts: vec![ResolvedArtifact {
                wheel_filename: "typing_extensions-4.9.0-py3-none-any.whl".to_string(),
                sha256: "a".repeat(64),
            }],
        };
        assert_eq!(
            installed_distribution_identities(&resolved),
            vec![ExpectedInstalledDistribution {
                name: "typing-extensions".to_string(),
                version: Some("4.9.0".to_string()),
            }]
        );
    }

    // ---- D7: InstallPlanDigest -----------------------------------------------

    /// A full set of binding inputs for a digest, every field populated so a test
    /// can mutate exactly one and observe the digest change.
    fn plan_inputs() -> InstallPlanInputs {
        InstallPlanInputs {
            artifact_sha256: vec!["b".repeat(64), "a".repeat(64)], // out of order
            normalized_packages: vec!["flask".to_string(), "click".to_string()],
            interpreter: PathBuf::from("/venv/bin/python"),
            interpreter_sha256: "c".repeat(64),
            resolver: PathBuf::from("/usr/bin/uv"),
            resolver_sha256: "d".repeat(64),
            resolver_version: "uv 1.2.3".to_string(),
            package_manager_version: "24.0".to_string(),
            pip_tree_root: PathBuf::from("/usr/lib/python3/site-packages/pip"),
            pip_tree_sha256: "e".repeat(64),
            pip_tree_binding_version: 1,
            pip_tree_max_files: 20_000,
            pip_tree_max_bytes: 256 * 1024 * 1024,
            pip_tree_max_file_bytes: 64 * 1024 * 1024,
            pip_tree_max_path_bytes: 4096,
            pip_tree_files: 120,
            pip_tree_bytes: 32_000,
            target_environment: PathBuf::from("/venv"),
            target_parent_identity: "linux-devino-v1:1:2".to_string(),
            target_component: "venv".to_string(),
            platform_tags: vec!["py3-none-any".to_string()],
            install_command_semantics: InstallCommand {
                approved_requirements_path: PathBuf::from("/q/txn/approved.txt"),
                target_environment: PathBuf::from("/venv"),
            }
            .pip_install_args_without_requirements_path(),
            policy_projection_hash: "deadbeef".repeat(8),
            threat_db_sequence: 7,
            capsule_backend: "landlock-seccomp".to_string(),
            required_coverage: crate::capsule::CapsuleSpec::locked_down().required_coverage(),
            task_gate_binding: "task_gate:v1:mode=off;denied=".to_string(),
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
                "different interpreter bytes",
                Box::new(|i: &mut InstallPlanInputs| i.interpreter_sha256 = "0".repeat(64)),
            ),
            (
                "different resolver",
                Box::new(|i: &mut InstallPlanInputs| i.resolver = PathBuf::from("/other/uv")),
            ),
            (
                "different resolver bytes",
                Box::new(|i: &mut InstallPlanInputs| i.resolver_sha256 = "0".repeat(64)),
            ),
            (
                "different resolver version",
                Box::new(|i: &mut InstallPlanInputs| i.resolver_version = "uv 9".to_string()),
            ),
            (
                "different pip version",
                Box::new(|i: &mut InstallPlanInputs| i.package_manager_version = "99".to_string()),
            ),
            (
                "different pip tree",
                Box::new(|i: &mut InstallPlanInputs| i.pip_tree_sha256 = "0".repeat(64)),
            ),
            (
                "different pip binding schema",
                Box::new(|i: &mut InstallPlanInputs| i.pip_tree_binding_version += 1),
            ),
            (
                "different pip binding limits",
                Box::new(|i: &mut InstallPlanInputs| i.pip_tree_max_file_bytes += 1),
            ),
            (
                "different target env",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.target_environment = PathBuf::from("/other")
                }),
            ),
            (
                "different target parent identity",
                Box::new(|i: &mut InstallPlanInputs| {
                    i.target_parent_identity = "linux-devino-v1:9:9".to_string()
                }),
            ),
            (
                "different target component",
                Box::new(|i: &mut InstallPlanInputs| i.target_component = "other".to_string()),
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
            target_environment: PathBuf::from("/venv"),
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
