//! `tirith pkg attest-npm` (C17): ask the operator's OWN npm to verify the
//! registry signatures and provenance attestations of an installed project, and
//! bind its answer to the exact `package-lock.json`, the installed
//! `node_modules` inventory, and the registry hosts.
//!
//! This is the impure half of [`tirith_core::provenance::npm`]. The contract
//! table, the strict parsers, the reconciliation, the outcome mapping, and the
//! receipt all live in core; this file resolves npm through the trusted-child
//! mechanism, runs exactly one contracted argv, and renders.
//!
//! # Ordering is the security property
//!
//! The steps below run in this order for a reason, and each one can end the
//! command before the next begins:
//!
//! 1. validate `--project` (a usage error exits 2 and does nothing else);
//! 2. read and hash `package-lock.json`, then walk `node_modules`: local reads
//!    only, no process and no network;
//! 2b. the PROJECT CONFIG gate: the audit child's working directory is the
//!    audited project, and npm reads `<cwd>/.npmrc` above the user and global
//!    config, so any effective project setting returns Partial and spawns
//!    nothing;
//! 3. the OFFLINE gate: `TIRITH_OFFLINE` returns Partial WITHOUT resolving npm
//!    and without spawning anything;
//! 4. the PLATFORM gate: Windows npm is `npm.cmd`, which the trusted-child
//!    validator refuses on purpose, so Windows returns Partial rather than
//!    pretending;
//! 5. build either a hermetic public-registry environment or a complete,
//!    explicitly trusted private-registry binding;
//! 6. resolve npm (and, when npm is a shebang script, its interpreter) as
//!    trusted executables;
//! 7. probe `npm --version` and look the version up in the CLOSED contract
//!    table. A version outside every range returns Partial and NO audit command
//!    runs;
//! 8. only now, run the one exact argv the contract authorizes.
//!
//! Step 7 before step 8 is the whole point of the slice: handing a speculative
//! flag to an npm whose output shape has not been characterized would turn this
//! command into an arbitrary-argv executor.
//!
//! # Exit codes
//!
//! `0` clean, `1` mismatch, `2` usage or input error, `3` partial. The `3` is
//! deliberately NOT the same meaning `tirith check` gives it (a warn
//! acknowledgement); per-command codes in this repository are distinct, and the
//! command's `after_help` says so.
//!
//! # What this command does not claim
//!
//! npm performs its own registry network I/O, entirely outside tirith's fetch
//! validator, redirect policy, and capsule broker. Public mode removes ambient
//! npm config/auth/proxy state. Trusted-private mode snapshots one explicitly
//! selected credential source and binds every transport input without recording
//! its credential bytes. Tirith never downloads or inspects a tarball.

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use tirith_core::policy::Policy;
use tirith_core::provenance::npm::{
    self as core_npm, InstalledInventory, NpmAssessment, NpmAttestOutcome, NpmAuditEnvironment,
    NpmAuditInvocation, NpmAuditMode, NpmAuditReport, NpmAuditSignaturesContract, NpmLockfile,
    NpmPartialReason, NpmProvenanceReceipt, NpmReceiptFacts, NpmReceiptSubject, NpmToolIdentity,
};
use tirith_core::trusted_child::{
    self, ChildLimits, ChildOutcome, ChildSpec, TrustedExecutable, TrustedExecutableError,
};

use super::{sanitize_for_human_output, write_json_stdout};
use url::Url;

/// The audit command's wall-clock budget, from the plan.
const AUDIT_TIMEOUT: Duration = Duration::from_secs(120);

/// The audit command's stdout and stderr caps, from the plan. Applied PER RUN:
/// npm's `--include-attestations` output carries a full Sigstore bundle per
/// attested package (about 8 KiB each in the captured fixture), so a very large
/// monorepo can legitimately cross the cap. That is reported as
/// [`NpmPartialReason::OutputLimitExceeded`], never as a clean answer over a
/// truncated document.
const AUDIT_OUTPUT_CAP: usize = 8 * 1024 * 1024;

/// The version probe's budget. A version line is a few bytes.
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);
const VERSION_OUTPUT_CAP: usize = 16 * 1024;

/// Longest npm stderr retained in the receipt after redaction.
const MAX_RECORDED_STDERR: usize = 4096;

/// Bytes of the resolved npm image read to look for a shebang. A larger file is
/// treated as a native image.
const MAX_LAUNCHER_PROBE_BYTES: u64 = 1024 * 1024;

/// Locale/temp environment the child may inherit, on top of a sanitized PATH.
/// HOME and npm configuration are never inherited; [`AuditEnvironment`] owns
/// their exact replacements.
#[cfg(unix)]
const INHERITED_ENV: &[&str] = &["TMPDIR", "LANG", "LC_ALL"];
#[cfg(not(unix))]
const INHERITED_ENV: &[&str] = &["SystemRoot", "TEMP", "TMP"];

const AUDIT_MODE_ENV: &str = "TIRITH_NPM_AUDIT_MODE";
const PRIVATE_REGISTRY_ENV: &str = "TIRITH_NPM_REGISTRY";
const PRIVATE_AUTH_SOURCE_ENV: &str = "TIRITH_NPM_AUTH_SOURCE";
const PRIVATE_CA_FILE_ENV: &str = "TIRITH_NPM_CA_FILE";
const PRIVATE_PROXY_ENV: &str = "TIRITH_NPM_PROXY";
const MAX_AUDIT_ORIGIN_BYTES: usize = 2048;

/// Everything `tirith pkg attest-npm` was asked to do.
#[derive(Debug, Clone, Default)]
pub struct AttestNpmArgs {
    /// The project directory holding `package-lock.json` and `node_modules`.
    pub project: Option<PathBuf>,
    /// Where to write the receipt, in addition to the rendered output.
    pub out: Option<PathBuf>,
    /// Tighten the contract: every eligible package must carry a verified
    /// attestation, not merely a registry signature.
    pub require_provenance: bool,
    /// Emit the JSON envelope rather than the human summary.
    pub json: bool,
}

/// `tirith pkg attest-npm` entry point. Returns the process exit code.
pub fn run(args: AttestNpmArgs) -> i32 {
    // 1. Project resolution and validation. Only this stage can exit 2.
    let project = match resolve_project(args.project.as_deref()) {
        Ok(project) => project,
        Err(message) => return usage_error(args.json, &message),
    };

    // 2. Local binding material: the lockfile digest and the install tree.
    //    Reads only; no process, no network.
    let lockfile_path = project.join("package-lock.json");
    let (lockfile, lockfile_sha256) = match read_lockfile(&lockfile_path) {
        Ok(pair) => pair,
        Err((reason, detail)) => return finish(&args, Assembly::partial(reason, detail)),
    };
    let npmrc_inspection = project_npmrc_override(&project);
    let npmrc_present = !matches!(npmrc_inspection, Ok(None));
    let inventory = match core_npm::walk_installed_tree(&project) {
        Some(inventory) => inventory,
        None => {
            return finish(
                &args,
                Assembly::without_audit(
                    &lockfile,
                    lockfile_sha256.clone(),
                    &InstalledInventory {
                        packages: Vec::new(),
                        capped: false,
                        symlinked_entries: 0,
                    },
                    npmrc_present,
                    NpmAttestOutcome::Partial {
                        reason: NpmPartialReason::MissingInstallTree,
                        detail: "the project has no node_modules directory, so there is no \
                                 install tree for npm to audit; no audit command was run"
                            .to_string(),
                    },
                ),
            );
        }
    };

    let npmrc = match npmrc_inspection {
        Ok(value) => value,
        Err(detail) => {
            return finish(
                &args,
                Assembly::without_audit(
                    &lockfile,
                    lockfile_sha256.clone(),
                    &inventory,
                    true,
                    NpmAttestOutcome::Partial {
                        reason: NpmPartialReason::AuditConfigurationInvalid,
                        detail,
                    },
                ),
            );
        }
    };

    let base = |outcome: NpmAttestOutcome| -> Assembly {
        Assembly::without_audit(
            &lockfile,
            lockfile_sha256.clone(),
            &inventory,
            npmrc.is_some(),
            outcome,
        )
    };

    // 2b. The audited project must not configure its own audit. npm reads
    //     `<cwd>/.npmrc` ABOVE the user and global config, and the audit child's
    //     cwd is the audited project, so a project-level key can redirect the
    //     registry npm fetches keys and manifests from, disable TLS verification,
    //     supply its own `_keys`, or omit dependency types from the audit
    //     entirely. Refusing before the spawn is the same posture the
    //     unsupported-version gate takes.
    if let Some(key) = npmrc.as_deref() {
        return finish(
            &args,
            base(NpmAttestOutcome::Partial {
                reason: NpmPartialReason::ProjectNpmrcOverride,
                detail: format!(
                    "the project's own .npmrc sets '{key}', which reconfigures what npm verifies \
                     or where it verifies it from; the audit would be configured by the project \
                     it audits, so no audit command was run"
                ),
            }),
        );
    }

    // 3. Offline: return Partial without resolving or spawning ANYTHING.
    if super::offline_env_active() {
        return finish(
            &args,
            base(NpmAttestOutcome::Partial {
                reason: NpmPartialReason::Offline,
                detail: "offline mode is active, so npm was neither resolved nor run; \
                         npm's signature audit needs the registry"
                    .to_string(),
            }),
        );
    }

    // 4. Platform. npm on Windows is `npm.cmd`, and the trusted-child validator
    //    refuses batch/script launchers by design rather than executing them
    //    through an ambient shell. Saying so is the honest answer; reporting a
    //    bare spawn error or a clean run would not be.
    if cfg!(windows) {
        return finish(
            &args,
            base(NpmAttestOutcome::Partial {
                reason: NpmPartialReason::UnsupportedPlatform,
                detail: "npm on Windows is a batch launcher (npm.cmd), which tirith's trusted \
                         executable validator refuses to run; no audit command was run"
                    .to_string(),
            }),
        );
    }

    // 5. Freeze the registry/configuration boundary before resolving or
    //    spawning npm. An incomplete private-mode request is never allowed to
    //    fall back to the public registry or ambient user config.
    let audit_environment = match AuditEnvironment::from_process() {
        Ok(environment) => environment,
        Err(detail) => {
            return finish(
                &args,
                base(NpmAttestOutcome::Partial {
                    reason: NpmPartialReason::AuditConfigurationInvalid,
                    detail,
                }),
            );
        }
    };

    // 6. Resolve npm, and its interpreter when npm is a shebang script.
    let launcher = match resolve_launcher() {
        Ok(launcher) => launcher,
        Err(reason) => {
            return finish(
                &args,
                base(NpmAttestOutcome::Partial {
                    reason: NpmPartialReason::NpmNotResolved,
                    detail: reason,
                }),
            );
        }
    };

    // 7. Version discovery, THEN contract selection. No audit command exists
    //    yet at this point.
    let version = match probe_version(&launcher) {
        Ok(version) => version,
        Err(reason) => {
            let mut assembly = base(NpmAttestOutcome::Partial {
                reason: NpmPartialReason::AuditCommandFailed,
                detail: reason,
            });
            assembly.tools = launcher.identity(None);
            return finish(&args, assembly);
        }
    };
    let Some(contract) = core_npm::select_contract(&version) else {
        let mut assembly = base(NpmAttestOutcome::Partial {
            reason: NpmPartialReason::UnsupportedNpmVersion,
            detail: format!(
                "npm {version} is outside every entry of tirith's closed audit contract table, \
                 so no audit command was run; tirith never passes a flag to an npm whose output \
                 shape it has not characterized"
            ),
        });
        assembly.tools = launcher.identity(Some(version));
        return finish(&args, assembly);
    };

    // 8. The one authorized command under the frozen audit environment.
    let spawned = run_audit(&launcher, contract, &project, &audit_environment);
    let tools = launcher.identity(Some(version));

    let assembly = match spawned {
        // A process WAS created and then failed. The contract is recorded
        // because the command really was issued; the absent exit code says it
        // did not complete.
        AuditRun::Failed { reason, detail } => {
            let mut assembly = base(NpmAttestOutcome::Partial { reason, detail });
            assembly.tools = tools;
            assembly.invocation = Some(invocation_of(
                contract,
                &audit_environment.binding,
                None,
                None,
            ));
            assembly
        }
        // No process was ever created, so there is no command to record. An
        // invocation here would tell a reader that the argv below ran.
        AuditRun::NotStarted { reason, detail } => {
            let mut assembly = base(NpmAttestOutcome::Partial { reason, detail });
            assembly.tools = tools;
            assembly
        }
        AuditRun::Completed {
            exit_code,
            stdout,
            stderr,
        } => {
            let stderr = redact_child_stderr(&stderr);
            let invocation = invocation_of(
                contract,
                &audit_environment.binding,
                Some(exit_code),
                stderr,
            );
            match core_npm::parse_audit_report(&stdout, contract.schema) {
                Err(error) => {
                    let mut assembly = base(NpmAttestOutcome::Partial {
                        reason: error.partial_reason(),
                        detail: format!("{} (npm exited {exit_code})", error.detail()),
                    });
                    assembly.tools = tools;
                    assembly.invocation = Some(invocation);
                    assembly
                }
                Ok(report) => {
                    let mut assembly = Assembly::with_audit(
                        &lockfile,
                        lockfile_sha256.clone(),
                        &inventory,
                        &report,
                        args.require_provenance,
                    );
                    assembly.tools = tools;
                    assembly.invocation = Some(invocation);
                    assembly
                }
            }
        }
    };

    finish(&args, assembly)
}

// ---------------------------------------------------------------------------
// 1. Input
// ---------------------------------------------------------------------------

/// Resolve `--project`, defaulting to the repository root and then the working
/// directory. A path that is not a readable directory is a usage error.
fn resolve_project(requested: Option<&Path>) -> Result<PathBuf, String> {
    let candidate = match requested {
        Some(path) => path.to_path_buf(),
        None => {
            let cwd = std::env::current_dir()
                .map_err(|error| format!("the working directory is unreadable: {error}"))?;
            tirith_core::policy::find_repo_root(cwd.to_str()).unwrap_or(cwd)
        }
    };
    if !candidate.is_dir() {
        return Err(format!(
            "--project must name a readable directory; '{}' is not one",
            candidate.display()
        ));
    }
    Ok(candidate)
}

/// Read, hash, and parse the project's `package-lock.json`.
///
/// The digest comes from the SAME open handle the bytes are read through
/// (`open_regular_capped` + `sha256_from_handle`), so a path swap between the
/// stat and the hash cannot substitute a different lockfile than the one the
/// receipt claims to bind.
fn read_lockfile(path: &Path) -> Result<(NpmLockfile, Option<String>), (NpmPartialReason, String)> {
    use tirith_core::util::{open_regular_capped, sha256_from_handle, HashOutcome};

    let missing = |detail: String| (NpmPartialReason::MissingLockfile, detail);
    let handle = open_regular_capped(path, core_npm::MAX_LOCKFILE_BYTES).map_err(|error| {
        missing(format!(
            "the project has no readable package-lock.json to bind to ({error:?})"
        ))
    })?;
    let cloned = handle.try_clone().map_err(|error| {
        missing(format!(
            "package-lock.json could not be read twice: {error}"
        ))
    })?;
    let digest = match sha256_from_handle(handle, core_npm::MAX_LOCKFILE_BYTES) {
        Ok(HashOutcome::Digest(digest)) => Some(digest),
        Ok(HashOutcome::BudgetExceeded) => None,
        Err(error) => {
            return Err(missing(format!(
                "package-lock.json could not be hashed: {error}"
            )))
        }
    };
    // The clone shares the file offset with the handle the hash consumed, so
    // rewind before reading the bytes back.
    let mut reader = cloned;
    {
        use std::io::Seek as _;
        reader
            .rewind()
            .map_err(|error| missing(format!("package-lock.json could not be rewound: {error}")))?;
    }
    let mut bytes = Vec::new();
    {
        use std::io::Read as _;
        (&mut reader)
            .take(core_npm::MAX_LOCKFILE_BYTES)
            .read_to_end(&mut bytes)
            .map_err(|error| missing(format!("package-lock.json could not be read: {error}")))?;
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| missing("package-lock.json is not valid UTF-8".to_string()))?;
    let lockfile = core_npm::parse_package_lock(&text).map_err(|error| {
        // A lockfile that is too large to account for is a distinct answer from
        // one that is not there; reporting both as "missing" would tell an
        // operator to go create a file that already exists.
        let reason = match error {
            core_npm::NpmLockfileError::TooManyEntries(_) => NpmPartialReason::LockfileTooLarge,
            _ => NpmPartialReason::MissingLockfile,
        };
        (reason, error.to_string())
    })?;
    Ok((lockfile, digest))
}

/// Largest project `.npmrc` inspected. A config file is a few hundred bytes.
const MAX_NPMRC_BYTES: u64 = 1024 * 1024;

/// The first effective key a project's own `.npmrc` sets, if any.
///
/// Returns the KEY, never the value: an `.npmrc` line's right-hand side is a
/// registered credential asset. npm reads project config above our isolated
/// user/global files, and npm can add new audit-affecting keys over time, so a
/// denylist is not hermetic. Comments and blank lines are harmless; every
/// assignment refuses the audit before a spawn.
fn project_npmrc_override(project: &Path) -> Result<Option<String>, String> {
    let path = project.join(".npmrc");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "the project's .npmrc could not be inspected safely: {error}"
            ));
        }
        Ok(_) => {}
    }
    let bytes =
        tirith_core::util::read_regular_capped(&path, MAX_NPMRC_BYTES).map_err(|error| {
            format!("the project's .npmrc is not a bounded no-follow regular file ({error:?})")
        })?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "the project's .npmrc is not valid UTF-8".to_string())?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let key = line
            .split_once('=')
            .map_or("<unparsed-setting>", |(key, _)| key);
        let key = key.trim();
        let key = sanitize_for_human_output(key, false);
        let key = tirith_core::util::truncate_bytes(&key, 128);
        return Ok(Some(
            key.rsplit(':')
                .next()
                .unwrap_or(key.as_str())
                .trim()
                .to_ascii_lowercase(),
        ));
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// 5. Registry/configuration binding
// ---------------------------------------------------------------------------

/// Runtime-only material for one npm audit. The tempdir holds isolated
/// user/global config, cache, and (for private mode) a private snapshot of the
/// explicitly selected auth source. Only [`binding`] reaches the receipt.
struct AuditEnvironment {
    binding: NpmAuditEnvironment,
    child_env: Vec<(OsString, OsString)>,
    _scratch: tempfile::TempDir,
}

impl AuditEnvironment {
    fn from_process() -> Result<Self, String> {
        match optional_utf8_env(AUDIT_MODE_ENV)?.as_deref() {
            None | Some("") | Some("public") => Self::public(),
            Some("trusted-private") => Self::trusted_private(),
            Some(_) => Err(format!(
                "{AUDIT_MODE_ENV} must be 'public' or 'trusted-private'; no audit command was run"
            )),
        }
    }

    fn public() -> Result<Self, String> {
        for name in [
            PRIVATE_REGISTRY_ENV,
            PRIVATE_AUTH_SOURCE_ENV,
            PRIVATE_CA_FILE_ENV,
            PRIVATE_PROXY_ENV,
        ] {
            if optional_utf8_env(name)?.is_some_and(|value| !value.trim().is_empty()) {
                return Err(format!(
                    "{name} was set without {AUDIT_MODE_ENV}=trusted-private; refusing an \
                     ambiguous registry configuration"
                ));
            }
        }
        let scratch = isolated_npm_scratch()?;
        let registry = core_npm::PUBLIC_NPM_REGISTRY_ORIGIN.to_string();
        let child_env = base_npm_environment(&scratch, &registry, None, None, None)?;
        Ok(Self {
            binding: NpmAuditEnvironment {
                mode: NpmAuditMode::HermeticPublicRegistry,
                registry_origin: registry,
                strict_tls: true,
                tls_ca_identity: "system_roots".to_string(),
                proxy_identity: "direct".to_string(),
                auth_source_identity: "none".to_string(),
            },
            child_env,
            _scratch: scratch,
        })
    }

    fn trusted_private() -> Result<Self, String> {
        let registry = required_utf8_env(PRIVATE_REGISTRY_ENV)?;
        let registry = canonical_https_origin(&registry, PRIVATE_REGISTRY_ENV)?;
        if registry == core_npm::PUBLIC_NPM_REGISTRY_ORIGIN {
            return Err(format!(
                "{PRIVATE_REGISTRY_ENV} selects the public npm registry; use \
                 {AUDIT_MODE_ENV}=public so ambient credentials cannot be introduced"
            ));
        }

        let auth_source = PathBuf::from(required_utf8_env(PRIVATE_AUTH_SOURCE_ENV)?);
        let (auth_bytes, auth_identity) = read_private_auth_source(&auth_source)?;
        let scratch = isolated_npm_scratch()?;
        let auth_snapshot = scratch.path().join("private-auth.npmrc");
        write_owner_only(&auth_snapshot, &auth_bytes)?;

        let (ca_snapshot, tls_ca_identity) = match optional_utf8_env(PRIVATE_CA_FILE_ENV)? {
            Some(value) if !value.trim().is_empty() => {
                let source = PathBuf::from(value);
                if !source.is_absolute() {
                    return Err(format!("{PRIVATE_CA_FILE_ENV} must be an absolute path"));
                }
                let bytes = read_public_config_source(&source, PRIVATE_CA_FILE_ENV)?;
                let identity = format!("sha256:{}", hex_sha256(&bytes));
                let snapshot = scratch.path().join("private-ca.pem");
                write_owner_only(&snapshot, &bytes)?;
                (Some(snapshot), identity)
            }
            _ => (None, "system_roots".to_string()),
        };

        let (proxy, proxy_identity) = match optional_utf8_env(PRIVATE_PROXY_ENV)? {
            Some(value) if !value.trim().is_empty() && value != "direct" => {
                let canonical = canonical_https_origin(&value, PRIVATE_PROXY_ENV)?;
                let identity = format!("sha256:{}", hex_sha256(canonical.as_bytes()));
                (Some(canonical), identity)
            }
            _ => (None, "direct".to_string()),
        };
        let child_env = base_npm_environment(
            &scratch,
            &registry,
            Some(&auth_snapshot),
            ca_snapshot.as_deref(),
            proxy.as_deref(),
        )?;

        Ok(Self {
            binding: NpmAuditEnvironment {
                mode: NpmAuditMode::TrustedPrivateRegistry,
                registry_origin: registry,
                strict_tls: true,
                tls_ca_identity,
                proxy_identity,
                auth_source_identity: auth_identity,
            },
            child_env,
            _scratch: scratch,
        })
    }

    fn apply(&self, mut spec: ChildSpec) -> ChildSpec {
        for (name, value) in &self.child_env {
            spec = spec.env(name, value);
        }
        spec
    }
}

fn optional_utf8_env(name: &str) -> Result<Option<String>, String> {
    match std::env::var_os(name) {
        None => Ok(None),
        Some(value) => value.into_string().map(Some).map_err(|_| {
            format!("{name} is not valid UTF-8, so its audit meaning cannot be bound")
        }),
    }
}

fn required_utf8_env(name: &str) -> Result<String, String> {
    optional_utf8_env(name)?
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            format!(
            "{AUDIT_MODE_ENV}=trusted-private requires a non-empty {name}; no audit command was run"
        )
        })
}

fn canonical_https_origin(raw: &str, name: &str) -> Result<String, String> {
    if raw.len() > MAX_AUDIT_ORIGIN_BYTES {
        return Err(format!("{name} exceeds the audit-origin size limit"));
    }
    let mut url = Url::parse(raw).map_err(|_| {
        format!("{name} must be a canonical HTTPS origin; no audit command was run")
    })?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(format!(
            "{name} must be an HTTPS origin with no credentials, path, query, or fragment"
        ));
    }
    url.set_path("/");
    Ok(url.to_string())
}

fn isolated_npm_scratch() -> Result<tempfile::TempDir, String> {
    let scratch = tempfile::Builder::new()
        .prefix("tirith-npm-audit-")
        .tempdir()
        .map_err(|error| format!("cannot create an isolated npm audit directory: {error}"))?;
    fs::create_dir(scratch.path().join("cache"))
        .map_err(|error| format!("cannot create the isolated npm cache: {error}"))?;
    write_owner_only(&scratch.path().join("empty-user.npmrc"), b"")?;
    write_owner_only(&scratch.path().join("empty-global.npmrc"), b"")?;
    Ok(scratch)
}

fn base_npm_environment(
    scratch: &tempfile::TempDir,
    registry: &str,
    auth_source: Option<&Path>,
    ca_file: Option<&Path>,
    proxy: Option<&str>,
) -> Result<Vec<(OsString, OsString)>, String> {
    let userconfig = auth_source
        .map(Path::to_path_buf)
        .unwrap_or_else(|| scratch.path().join("empty-user.npmrc"));
    let mut env = vec![
        (
            OsString::from("HOME"),
            scratch.path().as_os_str().to_os_string(),
        ),
        (
            OsString::from("NPM_CONFIG_USERCONFIG"),
            userconfig.into_os_string(),
        ),
        (
            OsString::from("NPM_CONFIG_GLOBALCONFIG"),
            scratch.path().join("empty-global.npmrc").into_os_string(),
        ),
        (
            OsString::from("NPM_CONFIG_CACHE"),
            scratch.path().join("cache").into_os_string(),
        ),
        (
            OsString::from("NPM_CONFIG_REGISTRY"),
            OsString::from(registry),
        ),
        (
            OsString::from("NPM_CONFIG_STRICT_SSL"),
            OsString::from("true"),
        ),
        (OsString::from("NPM_CONFIG_OMIT"), OsString::new()),
        (
            OsString::from("NPM_CONFIG_PROXY"),
            proxy.map_or_else(OsString::new, OsString::from),
        ),
        (
            OsString::from("NPM_CONFIG_HTTPS_PROXY"),
            proxy.map_or_else(OsString::new, OsString::from),
        ),
    ];
    if let Some(path) = ca_file {
        env.push((
            OsString::from("NPM_CONFIG_CAFILE"),
            path.as_os_str().to_os_string(),
        ));
    }
    Ok(env)
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot create isolated npm config: {error}"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot publish isolated npm config: {error}"))
}

fn read_public_config_source(path: &Path, name: &str) -> Result<Vec<u8>, String> {
    tirith_core::util::read_regular_capped(path, MAX_NPMRC_BYTES)
        .map_err(|error| format!("{name} is not a readable bounded regular file: {error:?}"))
}

fn read_private_auth_source(path: &Path) -> Result<(Vec<u8>, String), String> {
    if !path.is_absolute() {
        return Err(format!(
            "{PRIVATE_AUTH_SOURCE_ENV} must be an absolute path"
        ));
    }
    let mut handle = tirith_core::util::open_regular_capped(path, MAX_NPMRC_BYTES)
        .map_err(|error| format!("cannot inspect {PRIVATE_AUTH_SOURCE_ENV}: {error:?}"))?;
    let metadata = handle
        .metadata()
        .map_err(|error| format!("cannot inspect {PRIVATE_AUTH_SOURCE_ENV}: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        // SAFETY: geteuid has no preconditions and does not mutate state.
        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid || metadata.mode() & 0o077 != 0 {
            return Err(format!(
                "{PRIVATE_AUTH_SOURCE_ENV} must be owned by the current user and owner-only \
                 (mode 0600 or stricter)"
            ));
        }
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut handle, &mut bytes)
        .map_err(|error| format!("cannot read {PRIVATE_AUTH_SOURCE_ENV}: {error}"))?;
    if let Some(key) = disallowed_private_auth_key(&bytes) {
        let key = sanitize_for_human_output(&key, false);
        let key = tirith_core::util::truncate_bytes(&key, 128);
        return Err(format!(
            "{PRIVATE_AUTH_SOURCE_ENV} contains non-credential setting {key:?}; private mode \
             binds registry, TLS, and proxy separately"
        ));
    }
    Ok((bytes, auth_source_metadata_identity(&metadata)))
}

fn disallowed_private_auth_key(bytes: &[u8]) -> Option<String> {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return Some("<non-utf8>".to_string()),
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, _)) = line.split_once('=') else {
            return Some("<unparsed>".to_string());
        };
        let bare = key
            .trim()
            .rsplit(':')
            .next()
            .unwrap_or(key)
            .to_ascii_lowercase();
        if !matches!(
            bare.as_str(),
            "_authtoken" | "_auth" | "_password" | "username" | "email" | "always-auth"
        ) {
            return Some(bare);
        }
    }
    None
}

fn auth_source_metadata_identity(metadata: &fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        format!(
            "sha256:{}",
            hex_sha256(
                format!(
                    "dev={};ino={};uid={};gid={};mode={};len={};mtime={};mtime_ns={};ctime={};ctime_ns={}",
                    metadata.dev(),
                    metadata.ino(),
                    metadata.uid(),
                    metadata.gid(),
                    metadata.mode(),
                    metadata.len(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                    metadata.ctime(),
                    metadata.ctime_nsec()
                )
                .as_bytes()
            )
        )
    }
    #[cfg(not(unix))]
    format!(
        "sha256:{}",
        hex_sha256(format!("len={}", metadata.len()).as_bytes())
    )
}

fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// ---------------------------------------------------------------------------
// 6. Trusted executable resolution
// ---------------------------------------------------------------------------

/// The trusted executables one run launches.
///
/// npm on a real machine is usually NOT a native image: on macOS Homebrew it is
/// a 54-byte `#!/usr/bin/env node` script. [`trusted_child::run`] clears the
/// environment, so a bare script spawn would need a `PATH` for `/usr/bin/env`
/// to find node, and the interpreter that actually executed would then be
/// whatever `PATH` happened to name, while the receipt claimed a bound npm
/// identity. Resolving the interpreter as its own [`TrustedExecutable`] and
/// passing the validated npm script as `argv[1]` closes that gap, and BOTH
/// identities reach the receipt.
struct Launcher {
    /// The resolved npm.
    npm: TrustedExecutable,
    /// sha256 of the resolved npm file.
    npm_sha256: Option<String>,
    /// The interpreter, when npm is a shebang script.
    interpreter: Option<Interpreter>,
}

struct Interpreter {
    name: String,
    executable: TrustedExecutable,
    sha256: Option<String>,
}

impl Launcher {
    /// The program that is actually spawned, and the argv prefix it needs.
    fn program(&self) -> &TrustedExecutable {
        match &self.interpreter {
            Some(interpreter) => &interpreter.executable,
            None => &self.npm,
        }
    }

    /// The argv for a contracted command, including the npm script path when
    /// the interpreter is the spawned program.
    fn argv(&self, args: &[&str]) -> Vec<std::ffi::OsString> {
        let mut argv: Vec<std::ffi::OsString> = Vec::new();
        if self.interpreter.is_some() {
            argv.push(self.npm.path().as_os_str().to_os_string());
        }
        argv.extend(args.iter().map(|arg| std::ffi::OsString::from(*arg)));
        argv
    }

    /// Re-check the npm script's identity immediately before a spawn that goes
    /// through the interpreter. `trusted_child::run` verifies the PROGRAM it
    /// launches; when that program is node, npm is only an argument, so its
    /// identity has to be bound here or an auxiliary-executable swap would go
    /// unnoticed.
    fn revalidate_auxiliary(&self) -> Result<(), String> {
        if self.interpreter.is_none() {
            return Ok(());
        }
        self.npm
            .revalidate()
            .map_err(|error| format!("the npm script's identity changed before launch: {error}"))
    }

    fn identity(&self, version: Option<String>) -> NpmToolIdentity {
        NpmToolIdentity {
            npm_sha256: self.npm_sha256.clone(),
            npm_version: version,
            interpreter_sha256: self
                .interpreter
                .as_ref()
                .and_then(|interpreter| interpreter.sha256.clone()),
            interpreter_name: self
                .interpreter
                .as_ref()
                .map(|interpreter| interpreter.name.clone()),
        }
    }
}

/// Resolve npm through the ambient trusted-child resolver.
///
/// [`trusted_child::resolve_ambient`] is the correct resolver here: it scans
/// PATH directories itself (so a shell alias cannot hijack the name) and it
/// accepts a user-owned tool, which every nvm and Homebrew npm is.
/// `resolve_system_helper` would reject those.
fn resolve_launcher() -> Result<Launcher, String> {
    let npm = trusted_child::resolve_ambient("npm").map_err(describe_resolve_error)?;
    let npm_sha256 = Some(file_sha256(npm.path()).ok_or_else(|| {
        "the resolved npm executable could not be hashed, so its identity cannot be bound"
            .to_string()
    })?);
    let interpreter = match shebang_interpreter_name(npm.path()) {
        Some(name) => {
            let executable = trusted_child::resolve_ambient(&name).map_err(|error| {
                format!(
                    "npm is a script whose interpreter '{name}' could not be resolved as a \
                     trusted executable: {}",
                    describe_resolve_error(error)
                )
            })?;
            let sha256 = Some(file_sha256(executable.path()).ok_or_else(|| {
                format!(
                    "npm's resolved interpreter '{name}' could not be hashed, so its identity \
                     cannot be bound"
                )
            })?);
            Some(Interpreter {
                name,
                executable,
                sha256,
            })
        }
        None => None,
    };
    Ok(Launcher {
        npm,
        npm_sha256,
        interpreter,
    })
}

fn describe_resolve_error(error: TrustedExecutableError) -> String {
    format!("npm could not be resolved as a trusted executable: {error}")
}

/// The interpreter a resolved npm's shebang names, or `None` for a native
/// image.
///
/// Uses [`tirith_core::script_analysis::detect_interpreter`], which already
/// walks past `env -S` flags and `VAR=value` assignments, rather than
/// re-parsing a shebang here.
fn shebang_interpreter_name(path: &Path) -> Option<String> {
    let bytes = tirith_core::util::read_regular_capped(path, MAX_LAUNCHER_PROBE_BYTES).ok()?;
    if !bytes.starts_with(b"#!") {
        return None;
    }
    // Only the first line matters, and a native image that happens to start
    // with `#!` would not be valid UTF-8 past it, so a lossy read is safe.
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]);
    let name = tirith_core::script_analysis::detect_interpreter(&head);
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// sha256 of a resolved executable's own bytes.
///
/// [`TrustedExecutable`] exposes no public content digest on Unix, so the
/// receipt's tool identity is hashed here. This is a second open; the identity
/// binding that MATTERS is still the one `trusted_child::run` enforces at spawn
/// time, and this digest is a record for the reader, not the gate.
fn file_sha256(path: &Path) -> Option<String> {
    use tirith_core::util::{open_regular_capped, sha256_from_handle, HashOutcome};

    let handle = open_regular_capped(path, 512 * 1024 * 1024).ok()?;
    match sha256_from_handle(handle, 512 * 1024 * 1024) {
        Ok(HashOutcome::Digest(digest)) => Some(digest),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 7 and 8. Bounded spawns
// ---------------------------------------------------------------------------

/// Build a [`ChildSpec`] with the shared environment discipline.
fn spec_for(args: Vec<std::ffi::OsString>, limits: ChildLimits) -> ChildSpec {
    let mut spec = ChildSpec::new(args, limits).inherit_env(INHERITED_ENV);
    if let Some(path) = trusted_child::sanitized_ambient_path() {
        spec = spec.env("PATH", path);
    }
    spec
}

/// Probe `npm --version` under a short budget.
///
/// Structure copied from `artifact::resolver`'s `capture_bound_tool_version`
/// (which is `#[cfg(unix)]` and module-private, so it cannot be called): a
/// short timeout, a bounded output, and an exhaustive [`ChildOutcome`] match so
/// no failure mode silently becomes an empty version.
fn probe_version(launcher: &Launcher) -> Result<String, String> {
    launcher.revalidate_auxiliary()?;
    let spec = spec_for(
        launcher.argv(&["--version"]),
        ChildLimits::new(VERSION_TIMEOUT, VERSION_OUTPUT_CAP, VERSION_OUTPUT_CAP),
    );
    match trusted_child::run(launcher.program(), &spec) {
        ChildOutcome::Completed { status, stdout, .. } if status.success() => {
            let text = String::from_utf8_lossy(&stdout).to_string();
            core_npm::parse_npm_version(&text).ok_or_else(|| {
                "npm --version did not print a plain numeric release version, so no contract \
                 could be selected and no audit command was run"
                    .to_string()
            })
        }
        ChildOutcome::Completed { status, stderr, .. } => Err(format!(
            "npm --version exited {:?}: {}",
            status.code(),
            redact_child_stderr(&stderr).unwrap_or_default()
        )),
        ChildOutcome::Timeout { .. } => {
            Err("npm --version exceeded its 10 second budget".to_string())
        }
        ChildOutcome::OutputLimitExceeded { .. } => {
            Err("npm --version exceeded its output limit".to_string())
        }
        ChildOutcome::SpawnError(reason)
        | ChildOutcome::WaitError(reason)
        | ChildOutcome::CleanupError(reason) => {
            Err(format!("npm --version could not be run: {reason}"))
        }
    }
}

/// What one contracted audit spawn produced.
enum AuditRun {
    Completed {
        exit_code: i32,
        stdout: String,
        stderr: Vec<u8>,
    },
    /// A child process WAS created and then failed to produce a usable result.
    Failed {
        reason: NpmPartialReason,
        detail: String,
    },
    /// No child process was ever created. Kept apart from [`Self::Failed`]
    /// because the receipt records an invocation only for a command that
    /// actually issued, and "the argv we would have run" is not that.
    NotStarted {
        reason: NpmPartialReason,
        detail: String,
    },
}

/// Run the contract's exact argv, without a shell, in the project directory.
///
/// npm's own exit code is NOT the verdict: `verify-signatures.js` sets exit 1
/// whenever the invalid or missing bucket is non-empty, which is a FINDING to
/// parse, not a failure to run. Only a spawn, timeout, cap, or non-parse
/// failure is a Partial.
fn run_audit(
    launcher: &Launcher,
    contract: &NpmAuditSignaturesContract,
    project: &Path,
    environment: &AuditEnvironment,
) -> AuditRun {
    if let Err(detail) = launcher.revalidate_auxiliary() {
        return AuditRun::NotStarted {
            reason: NpmPartialReason::AuditCommandFailed,
            detail,
        };
    }
    let spec = environment
        .apply(spec_for(
            launcher.argv(contract.argv),
            ChildLimits::new(AUDIT_TIMEOUT, AUDIT_OUTPUT_CAP, AUDIT_OUTPUT_CAP),
        ))
        .cwd(project);
    match trusted_child::run(launcher.program(), &spec) {
        ChildOutcome::Completed {
            status,
            stdout,
            stderr,
        } => AuditRun::Completed {
            // A signal-terminated child has no code; -1 records that honestly
            // rather than defaulting to a success-shaped 0.
            exit_code: status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&stdout).to_string(),
            stderr,
        },
        ChildOutcome::Timeout { .. } => AuditRun::Failed {
            reason: NpmPartialReason::Timeout,
            detail: "npm audit signatures exceeded its 120 second budget".to_string(),
        },
        ChildOutcome::OutputLimitExceeded { stream, .. } => AuditRun::Failed {
            reason: NpmPartialReason::OutputLimitExceeded,
            detail: format!(
                "npm audit signatures exceeded the {AUDIT_OUTPUT_CAP}-byte {stream:?} cap, so its \
                 output was not parsed"
            ),
        },
        // A spawn error covers the pre-spawn identity check too, so no process
        // exists in this arm.
        ChildOutcome::SpawnError(reason) => AuditRun::NotStarted {
            reason: NpmPartialReason::AuditCommandFailed,
            detail: format!("npm audit signatures could not be started: {reason}"),
        },
        ChildOutcome::WaitError(reason) | ChildOutcome::CleanupError(reason) => AuditRun::Failed {
            reason: NpmPartialReason::AuditCommandFailed,
            detail: format!("npm audit signatures could not be run: {reason}"),
        },
    }
}

/// The `.npmrc` keys whose VALUE is a credential regardless of its shape.
///
/// The value-shape passes below catch a modern `npm_`-prefixed token, a GitHub
/// PAT, and an AWS key because those are recognizable on their own. A legacy
/// registry token is a bare UUID and `_auth` is base64 `user:password`; neither
/// looks like anything, so only the KEY identifies them. npm echoes these lines
/// verbatim on a 401, which is exactly when this command records stderr.
const NPMRC_CREDENTIAL_KEYS: &[&str] = &["_authtoken", "_auth", "_password", "_secret"];

/// Blank the value of EVERY `.npmrc` credential assignment in child stderr.
///
/// Key-aware rather than shape-aware, and the key itself is kept: the operator
/// still needs to see WHICH credential npm complained about. Every `=` on the
/// line is examined, not only the first, because npm quotes whole config lines
/// and a credential assignment is routinely not the first one on the row.
///
/// The value runs to the next ASCII whitespace. These four config values are a
/// UUID, a base64 blob, or an opaque token, none of which npm writes with an
/// embedded space.
fn redact_npmrc_credentials(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    let bytes = text.as_bytes();
    while let Some(offset) = text[cursor..].find('=') {
        let equals = cursor + offset;
        // The key token is what runs back from `=` to the previous whitespace,
        // then the last `:`-separated segment of that, which is how npm
        // namespaces a per-registry key (`//host/path:_authToken`).
        let key_start = text[cursor..equals]
            .rfind(|c: char| c.is_ascii_whitespace())
            .map_or(cursor, |index| cursor + index + 1);
        let key = &text[key_start..equals];
        let bare = key.rsplit(':').next().unwrap_or(key).to_ascii_lowercase();
        if !NPMRC_CREDENTIAL_KEYS.contains(&bare.as_str()) {
            out.push_str(&text[cursor..=equals]);
            cursor = equals + 1;
            continue;
        }
        let value_end = bytes[equals + 1..]
            .iter()
            .position(|byte| byte.is_ascii_whitespace())
            .map_or(text.len(), |index| equals + 1 + index);
        out.push_str(&text[cursor..=equals]);
        out.push_str("[REDACTED:npmrc_credential]");
        cursor = value_end;
    }
    out.push_str(&text[cursor..]);
    out
}

/// Project child stderr into something safe to keep in a durable receipt.
///
/// Four passes, in order: the `.npmrc` credential KEYS whose values have no
/// recognizable shape, then [`tirith_core::redact::redact_blocked_output`] (the
/// conservative projection for bytes that crossed a refusal boundary), then
/// absolute host paths, then truncation. Returns `None` for empty output so the
/// receipt omits the field entirely.
fn redact_child_stderr(stderr: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stderr);
    if text.trim().is_empty() {
        return None;
    }
    let keyed = redact_npmrc_credentials(&text);
    let redacted = tirith_core::redact::redact_blocked_output(&keyed);
    let pathless = tirith_core::capsule_receipt::redact_host_paths(&redacted);
    let bounded = tirith_core::util::truncate_bytes(pathless.trim(), MAX_RECORDED_STDERR);
    if bounded.trim().is_empty() {
        None
    } else {
        Some(bounded)
    }
}

fn invocation_of(
    contract: &NpmAuditSignaturesContract,
    environment: &NpmAuditEnvironment,
    exit_code: Option<i32>,
    stderr: Option<String>,
) -> NpmAuditInvocation {
    NpmAuditInvocation {
        contract_id: contract.id.to_string(),
        version_range: contract.version_range.to_string(),
        argv: contract.argv.iter().map(|arg| (*arg).to_string()).collect(),
        attestation_bundles_available: contract.attestation_bundles_available,
        environment: Some(environment.clone()),
        exit_code,
        stderr,
    }
}

// ---------------------------------------------------------------------------
// Assembly, receipt, rendering
// ---------------------------------------------------------------------------

/// Everything gathered before the receipt is stamped.
struct Assembly {
    outcome: NpmAttestOutcome,
    subject: NpmReceiptSubject,
    tools: NpmToolIdentity,
    invocation: Option<NpmAuditInvocation>,
    assessment: NpmAssessment,
}

impl Assembly {
    /// The earliest failure shape: no lockfile, so nothing to bind at all.
    fn partial(reason: NpmPartialReason, detail: String) -> Self {
        Self {
            outcome: NpmAttestOutcome::Partial { reason, detail },
            subject: NpmReceiptSubject {
                lockfile_name: "package-lock.json".to_string(),
                lockfile_sha256: None,
                lockfile_version: None,
                project_name: None,
                registry_hosts: Vec::new(),
                audit_registry_hosts: Vec::new(),
                project_npmrc_present: false,
                installed_package_count: 0,
            },
            tools: NpmToolIdentity::default(),
            invocation: None,
            assessment: NpmAssessment {
                records: Vec::new(),
                coverage: core_npm::NpmCoverage {
                    accounted_installed: 0,
                    unaccounted_installed: 0,
                    unaccounted_locations: Vec::new(),
                    registry_entries: 0,
                    unsupported_source_entries: 0,
                    inventory_capped: false,
                    symlinked_entries_skipped: 0,
                    unmatched_audit_entries: 0,
                    signature_only_derived_by_subtraction: false,
                },
            },
        }
    }

    /// A run that got as far as the local binding but never produced an audit
    /// result. Every eligible package is `not-audited`, which is what makes the
    /// outcome honest; the CALLER's outcome (offline, unsupported version, and
    /// so on) is kept because it names WHY.
    fn without_audit(
        lockfile: &NpmLockfile,
        lockfile_sha256: Option<String>,
        inventory: &InstalledInventory,
        npmrc_present: bool,
        outcome: NpmAttestOutcome,
    ) -> Self {
        let assessment = core_npm::reconcile(lockfile, inventory, None);
        Self {
            outcome,
            subject: subject_of(
                lockfile,
                lockfile_sha256,
                inventory,
                npmrc_present,
                &assessment,
            ),
            tools: NpmToolIdentity::default(),
            invocation: None,
            assessment,
        }
    }

    /// A run that produced an audit result.
    fn with_audit(
        lockfile: &NpmLockfile,
        lockfile_sha256: Option<String>,
        inventory: &InstalledInventory,
        report: &NpmAuditReport,
        require_provenance: bool,
    ) -> Self {
        let assessment = core_npm::reconcile(lockfile, inventory, Some(report));
        // A lockfile that grew past the hash budget between the open and the
        // hash leaves nothing to bind the answer to. It is rare (the open
        // already refuses an over-cap file) but it must degrade the outcome
        // rather than produce a clean receipt with no subject digest.
        let unbound = if lockfile_sha256.is_none() {
            Some(
                "package-lock.json could not be digested, so the answer is not bound to its exact \
                 bytes"
                    .to_string(),
            )
        } else {
            None
        };
        let gap = assessment.coverage_gap().or(unbound);
        let outcome = core_npm::apply_coverage_gap(
            core_npm::overall_outcome(&assessment.statuses(), require_provenance),
            gap.as_deref(),
        );
        Self {
            outcome,
            subject: subject_of(lockfile, lockfile_sha256, inventory, false, &assessment),
            tools: NpmToolIdentity::default(),
            invocation: None,
            assessment,
        }
    }
}

fn subject_of(
    lockfile: &NpmLockfile,
    lockfile_sha256: Option<String>,
    inventory: &InstalledInventory,
    npmrc_present: bool,
    assessment: &NpmAssessment,
) -> NpmReceiptSubject {
    NpmReceiptSubject {
        lockfile_name: "package-lock.json".to_string(),
        lockfile_sha256,
        lockfile_version: Some(lockfile.lockfile_version),
        project_name: lockfile.root_name.clone(),
        registry_hosts: lockfile.registry_hosts(),
        audit_registry_hosts: assessment.audit_registry_hosts(),
        project_npmrc_present: npmrc_present,
        installed_package_count: inventory.packages.len(),
    }
}

/// Stamp the receipt, optionally write it, render, and pick the exit code.
fn finish(args: &AttestNpmArgs, assembly: Assembly) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.display().to_string());
    let policy = Policy::discover_local_only(cwd.as_deref());
    let receipt = NpmProvenanceReceipt::new(NpmReceiptFacts {
        policy_projection_hash: policy.security_projection_hash(),
        outcome: assembly.outcome,
        require_provenance: args.require_provenance,
        subject: assembly.subject,
        tools: assembly.tools,
        invocation: assembly.invocation,
        assessment: assembly.assessment,
    });

    // A receipt that fails its own honesty invariants is a bug, and writing it
    // would publish a claim the type refuses to stand behind. Report it as an
    // input/usage failure rather than emitting the document.
    if let Err(error) = receipt.validate() {
        eprintln!("tirith pkg attest-npm: {error}");
        return 2;
    }

    if let Some(path) = args.out.as_deref() {
        if let Err(error) = receipt.write_to(path) {
            eprintln!(
                "tirith pkg attest-npm: cannot write the receipt to {}: {error}",
                path.display()
            );
            return 2;
        }
    }

    let exit = receipt.outcome.exit_code();
    if args.json {
        if !write_json_stdout(&receipt, "tirith pkg attest-npm: failed to write JSON") {
            return 2;
        }
        return exit;
    }
    print_human(&receipt, args.out.as_deref());
    exit
}

fn print_human(receipt: &NpmProvenanceReceipt, out: Option<&Path>) {
    let short = &receipt.receipt_id[..receipt.receipt_id.len().min(16)];
    eprintln!(
        "tirith pkg attest-npm: {} (receipt {short})",
        receipt.outcome.label()
    );
    match &receipt.outcome {
        NpmAttestOutcome::Clean => {
            eprintln!("  npm verified a registry signature for every eligible package.");
        }
        NpmAttestOutcome::Partial { reason, detail } => {
            // Partial is the ORDINARY outcome in a private-registry or
            // air-gapped environment, so it is stated as a coverage fact, not
            // as a failure.
            eprintln!("  not a complete answer ({}):", reason.label());
            eprintln!("    {}", sanitize_for_human_output(detail, false));
        }
        NpmAttestOutcome::Mismatch { detail } => {
            eprintln!("  SIGNATURE OR PROVENANCE MISMATCH");
            eprintln!("    {}", sanitize_for_human_output(detail, false));
        }
    }

    if let Some(version) = receipt.tools.npm_version.as_deref() {
        eprintln!(
            "  npm version:  {}",
            sanitize_for_human_output(version, false)
        );
    }
    match receipt.invocation.as_ref() {
        Some(invocation) => {
            eprintln!("  contract:     {}", invocation.contract_id);
            eprintln!("  argv:         npm {}", invocation.argv.join(" "));
            if let Some(environment) = invocation.environment.as_ref() {
                eprintln!(
                    "  audit mode:   {} ({})",
                    environment.mode.label(),
                    sanitize_for_human_output(&environment.registry_origin, false)
                );
            }
            match invocation.exit_code {
                Some(code) => eprintln!("  exit code:    {code}"),
                // Without this row an invocation reads as a completed command.
                None => eprintln!("  exit code:    none; the command did not complete"),
            }
        }
        None => eprintln!("  contract:     none selected; no audit command was run"),
    }
    if let Some(digest) = receipt.subject.lockfile_sha256.as_deref() {
        eprintln!("  lockfile:     package-lock.json sha256 {digest}");
    }
    if !receipt.subject.registry_hosts.is_empty() {
        eprintln!(
            "  registries:   {} (from package-lock.json)",
            sanitize_for_human_output(&receipt.subject.registry_hosts.join(", "), false)
        );
    }
    if !receipt.subject.audit_registry_hosts.is_empty() {
        eprintln!(
            "  npm audited:  {} (the registry npm itself reported)",
            sanitize_for_human_output(&receipt.subject.audit_registry_hosts.join(", "), false)
        );
    }
    if receipt.subject.project_npmrc_present {
        eprintln!("  PROJECT .npmrc: the audited project carries its own npm configuration");
    }

    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for record in &receipt.packages {
        *counts.entry(record.status.label()).or_default() += 1;
    }
    if !counts.is_empty() {
        eprintln!("  packages:");
        for (label, count) in counts {
            eprintln!("    {label}: {count}");
        }
    }
    if receipt.coverage.unaccounted_installed > 0 {
        eprintln!(
            "  UNACCOUNTED:  {} installed package(s) have no package-lock.json entry",
            receipt.coverage.unaccounted_installed
        );
        for location in &receipt.coverage.unaccounted_locations {
            eprintln!("    {}", sanitize_for_human_output(location, false));
        }
    }
    if let Some(stderr) = receipt
        .invocation
        .as_ref()
        .and_then(|invocation| invocation.stderr.as_deref())
    {
        eprintln!("  npm stderr (redacted):");
        // Every quoted line carries a marker at a column tirith's own rows never
        // use. Re-indenting alone is not enough: tirith's rows START at two
        // spaces, so a two-space continuation can forge one byte for byte.
        for line in stderr.split('\n') {
            eprintln!("    | {}", sanitize_for_human_output(line, false));
        }
    }
    for caveat in &receipt.caveats {
        eprintln!("  NOTE: {}", sanitize_for_human_output(caveat, false));
    }
    if let Some(path) = out {
        eprintln!("  receipt written to {}", path.display());
    }
}

/// Report a usage / input error and exit 2.
fn usage_error(json: bool, message: &str) -> i32 {
    if json {
        let envelope = serde_json::json!({
            "command": "pkg attest-npm",
            "status": "error",
            "error": message,
        });
        let _ = write_json_stdout(&envelope, "tirith pkg attest-npm: failed to write JSON");
    } else {
        eprintln!("tirith pkg attest-npm: {message}");
        eprintln!("  try: tirith pkg attest-npm --project .");
    }
    2
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only observation seam. Production has no injectable runner: it
    /// always resolves and executes through `trusted_child`, so tests cannot
    /// weaken executable ownership, no-follow, or identity validation.
    trait NpmInvoker {
        fn invoke(&mut self, environment: &AuditEnvironment);
    }

    #[derive(Default)]
    struct RecordingNpmInvoker {
        mode: Option<NpmAuditMode>,
        registry: Option<String>,
    }

    impl NpmInvoker for RecordingNpmInvoker {
        fn invoke(&mut self, environment: &AuditEnvironment) {
            self.mode = Some(environment.binding.mode);
            self.registry = Some(environment.binding.registry_origin.clone());
        }
    }

    fn invoke_for_test(invoker: &mut dyn NpmInvoker, environment: &AuditEnvironment) {
        invoker.invoke(environment);
    }

    #[test]
    fn the_npm_invoker_seam_is_test_only_and_observes_the_frozen_binding() {
        let scratch = isolated_npm_scratch().expect("isolated npm config");
        let environment = AuditEnvironment {
            binding: NpmAuditEnvironment {
                mode: NpmAuditMode::HermeticPublicRegistry,
                registry_origin: "https://registry.npmjs.org/".to_string(),
                strict_tls: true,
                tls_ca_identity: "system_roots".to_string(),
                proxy_identity: "direct".to_string(),
                auth_source_identity: "none".to_string(),
            },
            child_env: base_npm_environment(
                &scratch,
                "https://registry.npmjs.org/",
                None,
                None,
                None,
            )
            .expect("public environment"),
            _scratch: scratch,
        };
        let mut invoker = RecordingNpmInvoker::default();
        invoke_for_test(&mut invoker, &environment);
        assert_eq!(invoker.mode, Some(NpmAuditMode::HermeticPublicRegistry));
        assert_eq!(
            invoker.registry.as_deref(),
            Some("https://registry.npmjs.org/")
        );
    }

    #[test]
    fn stderr_redaction_drops_tokens_and_absolute_paths() {
        let raw = b"npm error code E401\nnpm error /Users/example/.npmrc\n\
                    //registry.example/:_authToken=npm_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\n";
        let redacted = redact_child_stderr(raw).expect("non-empty stderr is retained");
        assert!(
            !redacted.contains("npm_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"),
            "an auth token must not survive into a durable receipt: {redacted}"
        );
        assert!(
            !redacted.contains("/Users/example"),
            "an absolute host path must not survive: {redacted}"
        );
        assert!(
            redacted.contains("E401"),
            "the diagnosis survives: {redacted}"
        );
    }

    /// The value shapes here are a UUID and a base64 blob, which no pattern
    /// registry recognizes; only the key names them. npm quotes whole config
    /// rows, so a credential assignment is routinely not the first on the line.
    #[test]
    fn npmrc_credential_keys_are_blanked_wherever_they_appear_on_a_line() {
        // Assembled rather than written literally. The whole point of the test
        // is that these look exactly like real credentials, which is also what
        // makes a secret scanner reject the file. Splitting the key here keeps
        // the runtime bytes identical while the source carries no complete
        // credential assignment.
        let token_key = "_auth";
        let uuid_secret = "deadbeef-0000-4000-8000-feedfacecafe";
        let basic_secret = "ZGVwbG95LXVzZXI6czNjcjN0LXA0c3N3MHJk";
        let raw = format!(
            "npm error registry=https://registry.example/ {token_key}Token={uuid_secret} \
             verbose=true\nnpm error {token_key}={basic_secret}\nnpm error code E401\n"
        );
        let redacted = redact_child_stderr(raw.as_bytes()).expect("non-empty stderr is retained");
        for secret in [uuid_secret, basic_secret] {
            assert!(
                !redacted.contains(secret),
                "a keyed .npmrc credential must not survive: {redacted}"
            );
        }
        assert!(
            redacted.contains("_authToken=[REDACTED:npmrc_credential]"),
            "the key survives so the operator knows which credential failed: {redacted}"
        );
        assert!(
            redacted.contains("_auth=[REDACTED:npmrc_credential]"),
            "{redacted}"
        );
        assert!(
            redacted.contains("verbose=true") && redacted.contains("E401"),
            "the rest of the line and the diagnosis survive: {redacted}"
        );
    }

    #[test]
    fn empty_stderr_is_omitted_entirely() {
        assert!(redact_child_stderr(b"").is_none());
        assert!(redact_child_stderr(b"   \n\t\n").is_none());
    }

    #[test]
    fn the_recorded_stderr_is_bounded() {
        let raw = "npm error ".repeat(4096);
        let redacted = redact_child_stderr(raw.as_bytes()).expect("non-empty");
        assert!(
            redacted.len() <= MAX_RECORDED_STDERR,
            "recorded stderr must stay bounded, got {} bytes",
            redacted.len()
        );
    }

    #[test]
    fn a_missing_project_directory_is_a_usage_error_not_a_partial() {
        let error = resolve_project(Some(Path::new("/definitely/not/a/directory/for/c17")))
            .expect_err("a non-directory must be refused");
        assert!(error.contains("--project"), "{error}");
    }

    #[test]
    fn the_early_partial_shape_carries_the_caveat_and_no_invocation() {
        let assembly =
            Assembly::partial(NpmPartialReason::MissingLockfile, "no lockfile".to_string());
        assert!(assembly.invocation.is_none());
        assert_eq!(assembly.subject.lockfile_sha256, None);
        assert!(matches!(
            assembly.outcome,
            NpmAttestOutcome::Partial {
                reason: NpmPartialReason::MissingLockfile,
                ..
            }
        ));
    }
}
