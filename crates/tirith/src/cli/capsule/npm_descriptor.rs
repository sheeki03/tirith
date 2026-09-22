//! Closed ARM64 LocalLeafNoScriptsV1 launch. Generic private inputs stay refused.

use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::os::fd::FromRawFd as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::PathBuf;
use tirith_core::artifact::npm_install::{self, NpmArtifactOperand, PreparedNpmExecution};

pub(crate) const BOOTSTRAP: &[u8] = include_bytes!("../npm_sealed_bootstrap.cjs");
pub(crate) const MAX_MANIFEST: usize = 32 * 1024;
pub(crate) const MAX_BINDING: usize = 16 * 1024;
pub(crate) const SEALED: i32 =
    libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Content {
    pub fd: i32,
    pub sha256: String,
    pub size: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Artifact {
    pub fd: i32,
    pub package_name: String,
    pub sha256: String,
    pub size: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Directory {
    pub fd: i32,
    pub device: String,
    pub inode: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub fd: i32,
}
// Field declaration order is the canonical JS wire order. Do not serialize
// this through serde_json::Value (whose map ordering differs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub schema_version: u32,
    pub contract: String,
    pub runtime: Content,
    pub artifacts: Vec<Artifact>,
    pub target: Directory,
    pub cache: Directory,
    pub user_config: Config,
    pub global_config: Config,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeFile {
    pub content: Content,
    pub path: PathBuf,
    pub device: u64,
    pub inode: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub version: u32,
    pub node: Content,
    pub bootstrap: Content,
    pub binding: Content,
    pub inputs: Binding,
    pub target_path: PathBuf,
    pub cache_path: PathBuf,
    pub runtime_files: Vec<RuntimeFile>,
}

pub(crate) fn node_args(bootstrap_fd: i32, binding_fd: i32) -> Vec<OsString> {
    [
        "--max-old-space-size=128".to_string(),
        "--disable-wasm-trap-handler".into(),
        "--disable-sigusr1".into(),
        "--no-addons".into(),
        "--no-global-search-paths".into(),
        "--experimental-vfs".into(),
        "--input-type=commonjs".into(),
        "--eval".into(),
        format!("new Function('require', require('node:fs').readFileSync({bootstrap_fd},'utf8'))(require)"),
        "--".into(),
        binding_fd.to_string(),
    ].into_iter().map(OsString::from).collect()
}

pub(crate) fn fixed_environment(user_config_fd: i32) -> Vec<(String, String)> {
    vec![
        ("LANG".into(), "C".into()),
        ("LC_ALL".into(), "C".into()),
        ("NODE_DISABLE_COMPILE_CACHE".into(), "1".into()),
        (
            "OPENSSL_CONF".into(),
            format!("/proc/self/fd/{user_config_fd}"),
        ),
    ]
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn checked_binding_bytes(binding: &Binding) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(binding).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_BINDING {
        return Err("npm binding exceeds 16 KiB".into());
    }
    Ok(bytes)
}

fn package_name_is_closed(name: &str) -> bool {
    fn atom(value: &str) -> bool {
        value
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
    }
    if let Some(scoped) = name.strip_prefix('@') {
        scoped
            .split_once('/')
            .is_some_and(|(scope, leaf)| atom(scope) && atom(leaf))
    } else {
        atom(name)
    }
}

pub(crate) fn check_shape(manifest: &Manifest, internal: &[i32]) -> Result<(), String> {
    if manifest.version != 1
        || manifest.inputs.schema_version != 1
        || manifest.inputs.contract != npm_install::CONTRACT
        || manifest.runtime_files.len() != 9
        || manifest.inputs.artifacts.is_empty()
        || manifest.inputs.artifacts.len() > npm_install::MAX_ARTIFACTS
    {
        return Err("unsupported npm descriptor contract".into());
    }
    let b = &manifest.inputs;
    let mut descriptors = vec![
        manifest.node.fd,
        manifest.bootstrap.fd,
        manifest.binding.fd,
        b.runtime.fd,
        b.target.fd,
        b.cache.fd,
        b.user_config.fd,
        b.global_config.fd,
    ];
    descriptors.extend(b.artifacts.iter().map(|a| a.fd));
    descriptors.extend(manifest.runtime_files.iter().map(|a| a.content.fd));
    descriptors.extend_from_slice(internal);
    let mut seen = BTreeSet::new();
    if descriptors
        .iter()
        .any(|fd| !(3..256).contains(fd) || !seen.insert(*fd))
    {
        return Err("npm descriptors must be distinct in 3..255".into());
    }
    if b.target.device == b.cache.device && b.target.inode == b.cache.inode {
        return Err("npm target/cache capability alias".into());
    }
    for directory in [&b.target, &b.cache] {
        for n in [&directory.device, &directory.inode] {
            let parsed: u64 = n.parse().map_err(|_| "invalid npm directory identity")?;
            if parsed.to_string() != *n {
                return Err("noncanonical npm directory identity".into());
            }
        }
        if directory.inode == "0" {
            return Err("empty npm directory identity".into());
        }
    }
    let valid_hash = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let mut package_names = BTreeSet::new();
    let mut total = 0u64;
    for artifact in &b.artifacts {
        if !package_name_is_closed(&artifact.package_name)
            || artifact.package_name.len() > 214
            || !package_names.insert(&artifact.package_name)
            || !valid_hash(&artifact.sha256)
            || artifact.size == 0
            || artifact.size > 32 * 1024 * 1024
        {
            return Err("invalid bounded npm artifact identity".into());
        }
        total += artifact.size;
    }
    if total > 64 * 1024 * 1024
        || b.runtime.size < 12
        || b.runtime.size > 64 * 1024 * 1024
        || !valid_hash(&b.runtime.sha256)
        || manifest.bootstrap.size != BOOTSTRAP.len() as u64
        || manifest.bootstrap.sha256 != digest(BOOTSTRAP)
        || manifest.node.size == 0
        || manifest.node.size > 256 * 1024 * 1024
        || manifest.node.sha256 != npm_install::tools::NODE_SHA256
    {
        return Err("npm content closure mismatch".into());
    }
    let binding = checked_binding_bytes(b)?;
    if manifest.binding.size != binding.len() as u64 || manifest.binding.sha256 != digest(&binding)
    {
        return Err("npm sealed binding differs from native contract".into());
    }
    Ok(())
}

fn refuse(reason: impl Into<String>) -> CapsuleRefused {
    CapsuleRefused {
        backend_id: "landlock-seccomp",
        reason: reason.into(),
    }
}
fn effect(error: impl std::fmt::Display) -> CapsuleRefused {
    refuse(format!("sealed npm admission: {error}"))
}
fn preparation_effect(error: npm_install::NpmInstallRefusal) -> CapsuleRefused {
    refuse(format!("sealed npm preparation refused: {error:?}"))
}

fn reserve(
    spec: &mut CapsuleSpec,
    source: i32,
    held: &mut Vec<BoundTargetFd>,
) -> Result<i32, CapsuleRefused> {
    let fd = reserve_bound_target_fd(spec, source)?;
    let number = fd.inherited;
    spec.handles.extra_unix_fds.push(number);
    held.push(fd);
    Ok(number)
}

fn directory(fd: i32, file: &File) -> Result<Directory, CapsuleRefused> {
    let stat = file.metadata().map_err(effect)?;
    if !stat.is_dir() {
        return Err(refuse("npm directory capability changed type"));
    }
    Ok(Directory {
        fd,
        device: stat.dev().to_string(),
        inode: stat.ino().to_string(),
    })
}

/// Read from an owned retained file at explicit offsets. No shared seek cursor
/// or pathname reopening is used. The caller validates the expected digest.
fn seal_file(
    source: &File,
    size: u64,
    expected: &str,
    executable: bool,
) -> Result<File, CapsuleRefused> {
    let before = source.metadata().map_err(effect)?;
    if !before.is_file() || before.len() != size || size > 256 * 1024 * 1024 {
        return Err(refuse("npm retained input size/type changed"));
    }
    let base = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    let flags = if executable {
        base | libc::MFD_EXEC
    } else {
        base
    };
    let mut raw = unsafe { libc::memfd_create(c"tirith-npm-input".as_ptr(), flags) };
    if raw < 0 && executable && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL)
    {
        raw = unsafe { libc::memfd_create(c"tirith-npm-input".as_ptr(), base) };
    }
    if raw < 0 {
        return Err(effect(std::io::Error::last_os_error()));
    }
    let mut output = unsafe { File::from_raw_fd(raw) };
    let mut hash = Sha256::new();
    let mut offset = 0;
    let mut bytes = [0u8; 64 * 1024];
    while offset < size {
        let n = bytes.len().min((size - offset) as usize);
        let count = source.read_at(&mut bytes[..n], offset).map_err(effect)?;
        if count == 0 {
            return Err(refuse("npm retained input truncated during sealing"));
        }
        output.write_all(&bytes[..count]).map_err(effect)?;
        hash.update(&bytes[..count]);
        offset += count as u64;
    }
    let after = source.metadata().map_err(effect)?;
    if after.len() != size
        || after.dev() != before.dev()
        || after.ino() != before.ino()
        || format!("{:x}", hash.finalize()) != expected
    {
        return Err(refuse("npm retained input changed during sealing"));
    }
    seal_finish(output, executable)
}
fn seal_bytes(bytes: &[u8]) -> Result<File, CapsuleRefused> {
    if bytes.len() > 128 * 1024 {
        return Err(refuse("npm bootstrap/binding byte limit"));
    }
    let raw = unsafe {
        libc::memfd_create(
            c"tirith-npm-control".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if raw < 0 {
        return Err(effect(std::io::Error::last_os_error()));
    }
    let mut output = unsafe { File::from_raw_fd(raw) };
    output.write_all(bytes).map_err(effect)?;
    seal_finish(output, false)
}
fn seal_finish(mut file: File, executable: bool) -> Result<File, CapsuleRefused> {
    // This parent-held Node inode is only an immutable source. The nondumpable
    // child creates a separate private final inode, then validates exact0100
    // plus content/exec seals before execution. Data descriptors stay0400.
    if unsafe { libc::fchmod(file.as_raw_fd(), if executable { 0o100 } else { 0o400 }) } != 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALED) } < 0
    {
        return Err(effect(std::io::Error::last_os_error()));
    }
    file.rewind().map_err(effect)?;
    Ok(file)
}

fn authorize(
    parts: &crate::cli::package_checkpoint::AuthorizedInstallLaunchParts,
    prepared_operation: &tirith_core::task_boundary::BoundaryOperation<'_>,
) -> Result<(), CapsuleRefused> {
    // Both values are live capabilities, but that alone does not prove they
    // belong together. Check the checkpoint's sealed lease against the actual
    // preparation operation, never merely against its own stored envelope.
    parts
        .task_authorization
        .authorize_effect_at(prepared_operation, chrono::Utc::now())
        .map_err(effect)
}

pub(super) fn run(
    prepared: &mut PreparedNpmExecution<'_>,
    authorized: crate::cli::package_checkpoint::AuthorizedInstallLaunch,
    presentation: BoundOutputPresentation,
    validate_intent: &mut dyn FnMut() -> Result<(), String>,
) -> Result<CompletedNpmRun, CapsuleExecutionError> {
    let operation_id = prepared.operation_id().to_owned();
    let parts = authorized.into_parts();
    authorize(&parts, &prepared.operation())?;
    prepared.revalidate().map_err(preparation_effect)?;
    let completion_target = parts.target_handle.try_clone().map_err(effect)?;
    let target_stat = completion_target.metadata().map_err(effect)?;
    let completion_identity = (target_stat.dev(), target_stat.ino());
    matches_completed_npm_target(
        &completion_target,
        completion_identity,
        &parts.target_handle,
    )
    .map_err(effect)?;
    let libraries = prepared
        .clone_runtime_read_files()
        .map_err(preparation_effect)?;
    let identities = prepared.artifact_identities().map_err(preparation_effect)?;
    let inputs = prepared.clone_inputs().map_err(preparation_effect)?;
    let program = prepared.program().map_err(preparation_effect)?.clone();
    program.verify_identity().map_err(effect)?;
    let node_source = program
        .bound_launch_fd()
        .ok_or_else(|| refuse("npm Node image is not retained"))?;
    let duplicate = unsafe { libc::fcntl(node_source, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(effect(std::io::Error::last_os_error()).into());
    }
    let node_source = unsafe { File::from_raw_fd(duplicate) };
    let node_size = node_source.metadata().map_err(effect)?.len();
    let sealed_node = seal_file(
        &node_source,
        node_size,
        npm_install::tools::NODE_SHA256,
        true,
    )?;
    let mut spec = supervised_stdin_spec();
    spec.filesystem.read_roots = libraries.iter().map(|row| row.path.clone()).collect();
    spec.filesystem.write_roots = vec![parts.target_install_path.clone()];
    spec.environment.allow = fixed_environment(3)
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    let mut held = Vec::new();
    let node_fd = reserve(&mut spec, sealed_node.as_raw_fd(), &mut held)?;
    let target_fd = reserve(&mut spec, parts.target_handle.as_raw_fd(), &mut held)?;
    let target = directory(target_fd, &parts.target_handle)?;
    let mut home = create_parent_owned_temp_home(&mut spec)?;
    let cache_home = home
        .as_ref()
        .ok_or_else(|| refuse("npm cache capability is missing"))?;
    let cache_fd = cache_home
        .child_capability
        .as_ref()
        .ok_or_else(|| refuse("npm cache descriptor consumed"))?
        .inherited;
    let cache = directory(cache_fd, cache_home.directory.handle())?;
    let cache_path = cache_home.path().to_path_buf();
    let mut runtime_files = Vec::new();
    for row in libraries {
        let stat = row.file.metadata().map_err(effect)?;
        let fd = reserve(&mut spec, row.file.as_raw_fd(), &mut held)?;
        runtime_files.push(RuntimeFile {
            content: Content {
                fd,
                sha256: row.sha256,
                size: row.size,
            },
            path: row.path,
            device: stat.dev(),
            inode: stat.ino(),
        });
    }
    let mut runtime = None;
    let mut artifacts = Vec::new();
    let mut user_config = None;
    let mut global_config = None;
    for input in inputs {
        let size = input.file.metadata().map_err(effect)?.len();
        let sealed = seal_file(&input.file, size, &input.sha256, false)?;
        let fd = reserve(&mut spec, sealed.as_raw_fd(), &mut held)?;
        match input.name.as_str() {
            npm_install::runtime_pack::FILE_NAME => {
                if runtime
                    .replace(Content {
                        fd,
                        sha256: input.sha256,
                        size,
                    })
                    .is_some()
                {
                    return Err(refuse("duplicate npm runtime input").into());
                }
            }
            "npm-user.npmrc" if size == 0 => {
                user_config = Some(Config { fd });
            }
            "npm-global.npmrc" if size == 0 => {
                global_config = Some(Config { fd });
            }
            _ => {
                let identity = identities
                    .iter()
                    .find(|row| row.sha256 == input.sha256 && row.size == size)
                    .ok_or_else(|| refuse("unknown npm retained input"))?;
                if input.name != format!("npm-{}.tgz", identity.sha256) {
                    return Err(refuse("npm input name mismatch").into());
                }
                artifacts.push(Artifact {
                    fd,
                    package_name: identity.package_name.clone(),
                    sha256: input.sha256,
                    size,
                });
            }
        }
    }
    if artifacts.len() != identities.len() {
        return Err(refuse("npm artifact count changed").into());
    }
    let inputs = Binding {
        schema_version: 1,
        contract: npm_install::CONTRACT.into(),
        runtime: runtime.ok_or_else(|| refuse("npm runtime input missing"))?,
        artifacts,
        target,
        cache,
        user_config: user_config.ok_or_else(|| refuse("npm user config input missing"))?,
        global_config: global_config.ok_or_else(|| refuse("npm global config input missing"))?,
    };
    let bootstrap = seal_bytes(BOOTSTRAP)?;
    let bootstrap_fd = reserve(&mut spec, bootstrap.as_raw_fd(), &mut held)?;
    let binding_bytes = checked_binding_bytes(&inputs).map_err(effect)?;
    let binding = seal_bytes(&binding_bytes)?;
    let binding_fd = reserve(&mut spec, binding.as_raw_fd(), &mut held)?;
    let manifest = Manifest {
        version: 1,
        node: Content {
            fd: node_fd,
            sha256: npm_install::tools::NODE_SHA256.into(),
            size: node_size,
        },
        bootstrap: Content {
            fd: bootstrap_fd,
            sha256: digest(BOOTSTRAP),
            size: BOOTSTRAP.len() as u64,
        },
        binding: Content {
            fd: binding_fd,
            sha256: digest(&binding_bytes),
            size: binding_bytes.len() as u64,
        },
        inputs,
        target_path: parts.target_install_path.clone(),
        cache_path: cache_path.clone(),
        runtime_files,
    };
    let mut proof = LinuxLaunchProof::create(&mut spec)?;
    check_shape(
        &manifest,
        &[proof.status_fd, proof.ack_fd, proof.coverage_fd],
    )
    .map_err(effect)?;
    let manifest_json = serde_json::to_string(&manifest).map_err(effect)?;
    if manifest_json.len() > MAX_MANIFEST {
        return Err(refuse("native npm manifest exceeds bound").into());
    }
    let operands: Vec<_> = manifest
        .inputs
        .artifacts
        .iter()
        .map(|row| NpmArtifactOperand {
            sha256: row.sha256.clone(),
            operand: format!("/proc/self/fd/{}", row.fd).into(),
        })
        .collect();
    prepared
        .bind_layout(
            &cache_path,
            OsStr::new(&format!("/proc/self/fd/{target_fd}")),
            &parts.target_install_path,
            (
                manifest.inputs.target.device.parse().map_err(effect)?,
                manifest.inputs.target.inode.parse().map_err(effect)?,
            ),
            &operands,
        )
        .map_err(preparation_effect)?;
    authorize(&parts, &prepared.operation())?;
    let plan = supervised_stdin_plan(&spec, 0)?;
    let env = fixed_environment(manifest.inputs.user_config.fd);
    let mut command = linux_contained_command_os_with_npm_options(
        &plan.backend_spec,
        OsStr::new(npm_install::tools::NODE_PATH),
        &node_args(bootstrap_fd, binding_fd),
        Some(&env),
        &plan.backend_selected,
        None,
        home.as_mut(),
        None,
        None,
        Some(proof.status_fd),
        Some(proof.ack_fd),
        Some(proof.coverage_fd),
        proof.take_child_fds(),
        None,
        None,
        None,
        Some((
            manifest_json,
            node_fd,
            held.iter().map(|fd| fd.inherited).collect(),
        )),
    )?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    prepared.revalidate().map_err(preparation_effect)?;
    validate_intent().map_err(effect)?;
    authorize(&parts, &prepared.operation())?;
    let started = Instant::now();
    let mut child = command.spawn().map_err(effect)?;
    drop(command);
    let pid = child.id();
    let deadline = match started.checked_add(plan.limits.timeout) {
        Some(value) => value,
        None => {
            return Err(cleanup_refusal(
                &mut child,
                pid,
                &mut home,
                "deadline overflow before target authorization".into(),
                false,
            ))
        }
    };
    let mut coverage = match proof.confirm_coverage(deadline) {
        Ok(value) if !value.is_degraded_against(&plan.backend_spec.required_coverage()) => value,
        Ok(_) => {
            return Err(cleanup_refusal(
                &mut child,
                pid,
                &mut home,
                "native npm coverage incomplete before target authorization".into(),
                false,
            ))
        }
        Err(reason) => return Err(cleanup_refusal(&mut child, pid, &mut home, reason, false)),
    };
    match proof.confirm_target_exec_with(deadline, || {
        validate_intent()?;
        authorize(&parts, &prepared.operation()).map_err(|e| e.reason)?;
        prepared
            .before_target_resume()
            .map_err(|e| format!("{e:?}"))
    }) {
        Ok(()) => {}
        Err(TargetExecConfirmationError::BeforeAck(reason)) => {
            return Err(cleanup_refusal(&mut child, pid, &mut home, reason, false))
        }
        Err(TargetExecConfirmationError::AfterAck(reason)) => {
            return Err(cleanup_refusal(&mut child, pid, &mut home, reason, true))
        }
    }
    coverage.resource_limits_enforced = plan.effective_spec.resources.any_set();
    let mut limits = plan.limits;
    limits.timeout = deadline.saturating_duration_since(Instant::now());
    if limits.timeout.is_zero() {
        return Err(cleanup_refusal(
            &mut child,
            pid,
            &mut home,
            "npm wall deadline exhausted after ACK".into(),
            true,
        ));
    }
    let result = supervise_inherited_stdin_child(child, limits, &mut home);
    match result {
        Ok(output) => {
            let cache_cleanup = home
                .as_mut()
                .ok_or_else(|| refuse("npm cache ownership disappeared"))?
                .directory
                .cleanup_with_hook(|| {});
            if let Err(error) = cache_cleanup {
                return Err(CapsuleExecutionError::ExecutedTerminated {
                    backend_id: "landlock-seccomp",
                    termination: CapsuleTermination { kind: CapsuleTerminationKind::CleanupFailure,
                        reason: format!("npm child cleanup confirmed, but cache removal failed; residue retained: {error}"),
                        cleanup_confirmed: true },
                });
            }
            // `Ok` from the supervisor is only possible after the original
            // process group has exited, the guard is reaped and all I/O workers
            // have joined. A public outcome alone can never create this proof.
            let outcome = forward_bounded_child_output(
                CapsuleOutcome {
                    exit_code: output.status.code().unwrap_or(128),
                    backend_id: "landlock-seccomp",
                    coverage,
                    degraded: false,
                    termination: None,
                    ephemeral_home_cleanup_confirmed: Some(true),
                },
                &output.stdout,
                &output.stderr,
                presentation,
            );
            if let Some(termination) = &outcome.termination {
                return Err(CapsuleExecutionError::ExecutedTerminated {
                    backend_id: "landlock-seccomp",
                    termination: termination.clone(),
                });
            }
            if outcome.exit_code != 0 {
                return Err(CapsuleExecutionError::ExecutedTerminated {
                    backend_id: "landlock-seccomp",
                    termination: CapsuleTermination {
                        kind: CapsuleTerminationKind::UnsuccessfulExit,
                        reason: format!(
                            "contained npm exited unsuccessfully (status {})",
                            outcome.exit_code
                        ),
                        cleanup_confirmed: true,
                    },
                });
            }
            if outcome.degraded
                || outcome.ephemeral_home_cleanup_confirmed != Some(true)
                || outcome
                    .coverage
                    .is_degraded_against(&plan.effective_spec.required_coverage())
                || outcome
                    .coverage
                    .is_degraded_against(&CapsuleSpec::locked_down().required_coverage())
                || !outcome.coverage.egress_claim_is_coherent()
            {
                return Err(CapsuleExecutionError::ExecutedTerminated {
                    backend_id: "landlock-seccomp",
                    termination: CapsuleTermination {
                        kind: CapsuleTerminationKind::SupervisionIo,
                        reason: "npm completion lacks complete native containment evidence".into(),
                        cleanup_confirmed: true,
                    },
                });
            }
            matches_completed_npm_target(
                &completion_target,
                completion_identity,
                &parts.target_handle,
            )
            .map_err(|reason| CapsuleExecutionError::ExecutedTerminated {
                backend_id: "landlock-seccomp",
                termination: CapsuleTermination {
                    kind: CapsuleTerminationKind::SupervisionIo,
                    reason,
                    cleanup_confirmed: true,
                },
            })?;
            Ok(CompletedNpmRun {
                operation_id,
                target: completion_target,
                target_identity: completion_identity,
                outcome,
            })
        }
        Err(reason) => Err(CapsuleExecutionError::ExecutedTerminated {
            backend_id: "landlock-seccomp",
            termination: supervision_termination(reason),
        }),
    }
}

fn cleanup_refusal(
    child: &mut Child,
    pid: u32,
    home: &mut Option<HeldTempHome>,
    reason: String,
    ack: bool,
) -> CapsuleExecutionError {
    let (cleanup, _) = terminate_supervised_tree(child, pid);
    refusal_after_cleanup(home, reason, ack, cleanup)
}

fn refusal_after_cleanup(
    home: &mut Option<HeldTempHome>,
    reason: String,
    ack: bool,
    cleanup: bool,
) -> CapsuleExecutionError {
    preserve_temp_home_on_unconfirmed_cleanup(home, cleanup);
    let phase = if ack {
        "after resume ACK"
    } else {
        "before resume ACK; target code was not authorized"
    };
    let reason = format!("sealed npm {phase}: {reason}; child-tree cleanup succeeded={cleanup}");
    if ack || !cleanup {
        CapsuleExecutionError::ExecutedTerminated {
            backend_id: "landlock-seccomp",
            termination: CapsuleTermination {
                kind: if cleanup {
                    CapsuleTerminationKind::SupervisionIo
                } else {
                    CapsuleTerminationKind::CleanupFailure
                },
                reason,
                cleanup_confirmed: cleanup,
            },
        }
    } else {
        refuse(reason).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Manifest {
        let content = |fd| Content {
            fd,
            sha256: "a".repeat(64),
            size: 12,
        };
        let inputs = Binding {
            schema_version: 1,
            contract: npm_install::CONTRACT.into(),
            runtime: content(6),
            artifacts: vec![Artifact {
                fd: 11,
                package_name: "@scope/leaf".into(),
                sha256: "b".repeat(64),
                size: 20,
            }],
            target: Directory {
                fd: 7,
                device: "1".into(),
                inode: "2".into(),
            },
            cache: Directory {
                fd: 8,
                device: "1".into(),
                inode: "3".into(),
            },
            user_config: Config { fd: 9 },
            global_config: Config { fd: 10 },
        };
        let bytes = checked_binding_bytes(&inputs).unwrap();
        Manifest {
            version: 1,
            node: Content {
                fd: 3,
                sha256: npm_install::tools::NODE_SHA256.into(),
                size: 100,
            },
            bootstrap: Content {
                fd: 4,
                sha256: digest(BOOTSTRAP),
                size: BOOTSTRAP.len() as u64,
            },
            binding: Content {
                fd: 5,
                sha256: digest(&bytes),
                size: bytes.len() as u64,
            },
            inputs,
            target_path: "/target".into(),
            cache_path: "/cache".into(),
            runtime_files: (12..21)
                .map(|fd| RuntimeFile {
                    content: content(fd),
                    path: format!("/runtime/{fd}").into(),
                    device: 1,
                    inode: fd as u64,
                })
                .collect(),
        }
    }
    #[test]
    fn pre_ack_refusal_preserves_roots_when_cleanup_is_unknown() {
        // Inject the cleanup result, not a guessed PID or a native exit claim.
        // No child is created by this test; it verifies the actual root owner
        // and conservative result classification used after callback refusal.
        for ack in [false, true] {
            for cleanup in [false, true] {
                let mut spec = supervised_stdin_spec();
                let mut home = create_parent_owned_temp_home(&mut spec).unwrap();
                let path = home.as_ref().unwrap().path().to_path_buf();
                let error = refusal_after_cleanup(
                    &mut home,
                    "authority callback refused".into(),
                    ack,
                    cleanup,
                );
                match error {
                    CapsuleExecutionError::RefusedBeforeExec(_) => assert!(!ack && cleanup),
                    CapsuleExecutionError::ExecutedTerminated { termination, .. } => {
                        assert!(ack || !cleanup);
                        assert_eq!(termination.cleanup_confirmed, cleanup);
                        if !ack {
                            assert!(termination
                                .reason
                                .contains("target code was not authorized"));
                        }
                    }
                }
                assert_eq!(home.is_some(), cleanup);
                drop(home);
                assert_eq!(path.exists(), !cleanup);
                if !cleanup {
                    // This fixture never spawned a child and still owns the
                    // exact private root that production deliberately retained.
                    std::fs::remove_dir_all(path).unwrap();
                }
            }
        }
    }

    #[test]
    fn descriptor_binding_is_canonical_and_rejects_authority_aliases() {
        let good = sample();
        check_shape(&good, &[21, 22, 23]).unwrap();
        let text = String::from_utf8(checked_binding_bytes(&good.inputs).unwrap()).unwrap();
        assert!(text.starts_with("{\"schema_version\":1,\"contract\":\"LocalLeafNoScriptsV1\",\"runtime\":{\"fd\":6,\"sha256\":"));
        assert!(text.ends_with("\"user_config\":{\"fd\":9},\"global_config\":{\"fd\":10}}"));
        for mutate in [
            |m: &mut Manifest| m.inputs.global_config.fd = m.inputs.user_config.fd,
            |m: &mut Manifest| m.inputs.runtime.fd = 256,
            |m: &mut Manifest| m.inputs.target.fd = 2,
            |m: &mut Manifest| m.runtime_files[0].content.fd = 21,
            |m: &mut Manifest| m.inputs.cache.inode = m.inputs.target.inode.clone(),
            |m: &mut Manifest| m.inputs.target.device = "01".into(),
            |m: &mut Manifest| m.inputs.artifacts[0].package_name = "../escape".into(),
            |m: &mut Manifest| m.inputs.artifacts[0].size = 32 * 1024 * 1024 + 1,
            |m: &mut Manifest| m.bootstrap.sha256 = "c".repeat(64),
            |m: &mut Manifest| m.node.sha256 = "c".repeat(64),
        ] {
            let mut bad = good.clone();
            mutate(&mut bad);
            assert!(check_shape(&bad, &[21, 22, 23]).is_err());
        }
        let mut unknown = serde_json::to_value(&good).unwrap();
        unknown["unknown"] = true.into();
        assert!(serde_json::from_value::<Manifest>(unknown).is_err());
    }
    #[test]
    fn data_seals_prevent_mutation_and_preserve_empty_config() {
        let file = seal_bytes(b"").unwrap();
        let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
        assert!(seals >= 0 && seals & SEALED == SEALED);
        assert_eq!(file.metadata().unwrap().len(), 0);
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o400);
        assert!(file.write_at(b"x", 0).is_err());
        assert!(file.set_len(1).is_err());
    }
    #[test]
    fn closed_node_argv_and_environment_have_no_caller_payload() {
        let args = node_args(31, 47);
        assert_eq!(args.last(), Some(&OsString::from("47")));
        assert!(args.iter().any(|a| a == "--no-addons"));
        assert!(args.iter().any(|a| a == "--disable-sigusr1"));
        let env = fixed_environment(8);
        assert_eq!(env.len(), 4);
        assert_eq!(
            env.last(),
            Some(&("OPENSSL_CONF".into(), "/proc/self/fd/8".into()))
        );
    }
    #[test]
    fn native_launch_refuses_independently_authorized_checkpoint_from_another_operation() {
        use crate::cli::package_checkpoint::{EnvironmentCheckpoint, InstallTargetBinding};
        use tirith_core::artifact::resolver::ResolverRequest;
        use tirith_core::task_boundary::{
            package_envelope, BoundaryOperation, OwnedBoundary, PackageInstallPreparationBoundary,
            PackageOperationBinding,
        };
        let root = tempfile::tempdir().unwrap();
        let first_target = InstallTargetBinding::bind(&root.path().join("first")).unwrap();
        let second_target = InstallTargetBinding::bind(&root.path().join("second")).unwrap();
        let first_request = ResolverRequest::single("first==1.0");
        let second_request = ResolverRequest::single("second==1.0");
        let first_envelope = package_envelope(&PackageOperationBinding::new(
            "pip",
            &first_request,
            &[],
            &first_target.package_target_identity(),
        ))
        .unwrap();
        let second_envelope = package_envelope(&PackageOperationBinding::new(
            "pip",
            &second_request,
            &[],
            &second_target.package_target_identity(),
        ))
        .unwrap();
        fn operation(envelope: &tirith_core::task::TaskEnvelopeInput) -> BoundaryOperation<'_> {
            BoundaryOperation {
                boundary: OwnedBoundary::PackageInstallPreparation,
                envelope,
                adapter: tirith_core::task::IngressAdapter::Unattributed,
                boundary_effects: Default::default(),
            }
        }
        let first_operation = operation(&first_envelope);
        let second_operation = operation(&second_envelope);
        let permit = |operation: &BoundaryOperation<'_>| {
            tirith_core::task_boundary::prepare_locally_derived_boundary_authorization::<
                PackageInstallPreparationBoundary,
            >(
                operation,
                &tirith_core::web3_policy::TaskGatePolicy::default(),
                &tirith_core::task_analysis::TaskAnalysisContext::default(),
            )
            .unwrap()
            .consume_default_for_operation(operation, chrono::Utc::now())
            .unwrap()
        };
        // These are real independent one-shot checkpoint leases, not saved
        // DTOs or fabricated native-completion values. No child is launched.
        let mut first = EnvironmentCheckpoint::begin_authorized(
            &first_target,
            permit(&first_operation),
            "pip",
            &first_request,
            &[],
        )
        .unwrap();
        let mut second = EnvironmentCheckpoint::begin_authorized(
            &second_target,
            permit(&second_operation),
            "pip",
            &second_request,
            &[],
        )
        .unwrap();
        let first_parts = first.take_authorized_launch().unwrap().into_parts();
        let second_parts = second.take_authorized_launch().unwrap().into_parts();
        assert!(authorize(&first_parts, &first_operation).is_ok());
        assert!(authorize(&second_parts, &second_operation).is_ok());
        assert!(authorize(&first_parts, &second_operation).is_err());
        assert!(authorize(&second_parts, &first_operation).is_err());
        assert!(!first_target.target().exists());
        assert!(!second_target.target().exists());
        assert!(first.take_authorized_launch().is_err());
        assert!(second.take_authorized_launch().is_err());
    }
}
