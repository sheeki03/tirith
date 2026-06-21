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
//! [`crate::artifact::record::verify_installed_record`]; D4 deliberately stops at
//! the contained install and leaves that post-install seam to D5.

use std::path::{Path, PathBuf};

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

use crate::artifact::firewall::firewall_resolved_set;
use crate::artifact::quarantine::QuarantineTransaction;
use crate::artifact::resolver::ResolvedSet;
use crate::policy::Policy;
use crate::threatdb::ThreatDb;
use crate::verdict::Verdict;

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
            "-r".to_string(),
            self.approved_requirements_path.display().to_string(),
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
        let spec = build_install_spec(&txn_dir, &env, &[prefix.clone()]);
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
}
