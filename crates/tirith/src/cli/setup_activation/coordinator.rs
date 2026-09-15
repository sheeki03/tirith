//! Child-free coordinator. The main-thread self deadline must already be armed.
//! Private claims coordinate retries; only core hook/body proof grants an observation.
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tirith_core::execution_state::{
    self, activation_client_exchange, activation_server_receive, ActivationExchangeId,
    AuthenticatedShellContext, AutomaticVerificationStage, ShellReceiptChannel,
};

use crate::cli::control::identity::DirectoryIdentity;
use crate::cli::setup::activation_protocol::{Attempt, Failure, Frame, Id, Request, Stage};
use crate::cli::setup::change_plan::{
    FinishedActivationClaim, MutationService, PendingActivationClaim, RunningActivationClaim,
};

const REFUSED: &str = "automatic activation unavailable";
const MAX_REQUESTS: usize = 8;

fn failure() -> String {
    REFUSED.into()
}

fn actual_paths() -> Result<Vec<PathBuf>, String> {
    let target = crate::cli::shell_target::resolve_current()?;
    if target.shell != "zsh"
        || target.identity_source != "observed-ancestor-process"
        || target.unsupported_reason.is_some()
        || target.startup_mode == "no-profile"
    {
        return Err(failure());
    }
    crate::cli::shell_verification::configuration_paths(ShellReceiptChannel::Zsh)
}

pub(super) fn run(argv: &[OsString]) -> Result<(), String> {
    let values: Vec<_> = argv
        .iter()
        .map(|v| v.to_str().ok_or_else(failure))
        .collect::<Result<_, _>>()?;
    let modules_only = matches!(
        values.as_slice(),
        [_, "__setup-activation", "modules", "--channel", "zsh"]
    );
    let loaded = if modules_only {
        String::new()
    } else {
        crate::cli::shell_verification::read_fingerprint()?
    };
    // A real initialized shell supplies the registered session. Do not create
    // a fallback file/session merely because a discovery command was invoked.
    let session = tirith_core::session::env_session_id().ok_or_else(failure)?;
    let shell = execution_state::authenticate_shell_context(ShellReceiptChannel::Zsh, session)?;
    super::native_modules::qualify(&shell)?;
    if modules_only {
        return Ok(());
    }
    let config_paths = actual_paths()?;
    match values.as_slice() {
        [_, "__setup-activation", "broker", "--channel", "zsh", "--operation-id", op, "--attempt-id", attempt] => {
            broker(&shell, ids(op, attempt)?, &loaded, &config_paths)
        }
        [_, "__setup-activation", "relay", "--channel", "zsh", "--action", action, op, attempt, "--reason", reason] =>
        {
            let op = op.strip_prefix("--operation-id=").ok_or_else(failure)?;
            let attempt = attempt.strip_prefix("--attempt-id=").ok_or_else(failure)?;
            let request = Request::parse(action, op, attempt, reason).map_err(|_| failure())?;
            let frame = if request == Request::Discover {
                match MutationService::current()?.claim_automatic_activation(&shell, &loaded)? {
                    Some(owner) => Frame::Pending(ids(owner.operation_id(), owner.attempt_id())?),
                    None => Frame::None,
                }
            } else {
                relay(&shell, request, action, op, attempt, reason, &loaded)?
            };
            shell.revalidate()?;
            let encoded = frame.encode();
            Frame::decode(encoded.as_bytes()).map_err(|_| failure())?;
            std::io::stdout()
                .lock()
                .write_all(encoded.as_bytes())
                .map_err(|_| failure())
        }
        _ => Err(failure()),
    }
}

fn ids(operation: &str, attempt: &str) -> Result<Attempt, String> {
    Ok(Attempt {
        operation: Id::parse(operation).map_err(|_| failure())?,
        attempt: Id::parse(attempt).map_err(|_| failure())?,
    })
}

fn endpoint(ids: Attempt) -> Result<(PathBuf, PathBuf), String> {
    let scope = tirith_core::policy::state_dir().ok_or_else(failure)?;
    if !scope.is_absolute()
        || scope
            .components()
            .any(|v| matches!(v, std::path::Component::ParentDir))
    {
        return Err(failure());
    }
    let digest = format!(
        "{:x}",
        Sha256::digest(
            format!(
                "tirith-activation-endpoint-v1|{}|{}",
                ids.operation, ids.attempt
            )
            .as_bytes()
        )
    );
    let directory = scope.join("activation");
    let path = directory.join(&digest[..32]);
    // macOS sockaddr_un is the narrower supported native address. Never
    // truncate or move an overlong endpoint into a different authority root.
    use std::os::unix::ffi::OsStrExt;
    if path.as_os_str().as_bytes().len() >= 104 {
        return Err(failure());
    }
    Ok((scope, path))
}

fn socket_identity(path: &Path) -> Result<(u64, u64), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| failure())?;
    if !meta.file_type().is_socket()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
    {
        return Err(failure());
    }
    Ok((meta.dev(), meta.ino()))
}

struct EndpointOwner {
    listener: UnixListener,
    directory: DirectoryIdentity,
    path: PathBuf,
    identity: (u64, u64),
}

impl EndpointOwner {
    fn bind(ids: Attempt) -> Result<Self, String> {
        let (scope, path) = endpoint(ids)?;
        let parent = path.parent().ok_or_else(failure)?;
        crate::cli::setup::fs_helpers::ensure_private_directory(parent, &scope)?;
        let directory = DirectoryIdentity::capture(parent)?;
        // Existing endpoints are never removed or reused, including after a
        // crash. A new explicit setup provides a new operation and attempt.
        let listener = UnixListener::bind(&path).map_err(|_| failure())?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| failure())?;
        let owner = Self {
            listener,
            directory,
            identity: socket_identity(&path)?,
            path,
        };
        owner
            .listener
            .set_nonblocking(true)
            .map_err(|_| failure())?;
        owner.revalidate()?;
        Ok(owner)
    }

    fn revalidate(&self) -> Result<(), String> {
        self.directory.revalidate()?;
        if socket_identity(&self.path)? != self.identity {
            return Err(failure());
        }
        Ok(())
    }

    fn accept(&self, shell: &AuthenticatedShellContext) -> Result<UnixStream, String> {
        loop {
            shell.revalidate()?;
            self.revalidate()?;
            match self.listener.accept() {
                Ok((stream, _)) => return Ok(stream),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(_) => return Err(failure()),
            }
        }
    }
}

impl Drop for EndpointOwner {
    fn drop(&mut self) {
        // Best-effort cleanup inside the held private directory. A changed
        // entry is retained. No PID or discovered pathname is signal authority.
        if self.revalidate().is_ok() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn relay(
    shell: &AuthenticatedShellContext,
    request: Request,
    action: &str,
    op: &str,
    attempt: &str,
    reason: &str,
    loaded: &str,
) -> Result<Frame, String> {
    let ids = ids(op, attempt)?;
    let (_, path) = endpoint(ids)?;
    let started = Instant::now();
    let stream = loop {
        shell.revalidate()?;
        if started.elapsed() >= Duration::from_millis(800) {
            return Err(failure());
        }
        match std::fs::symlink_metadata(&path) {
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && matches!(request, Request::Start(_)) =>
            {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(_) => return Err(failure()),
            Ok(_) => {}
        }
        let directory = DirectoryIdentity::capture(path.parent().ok_or_else(failure)?)?;
        let identity = socket_identity(&path)?;
        let stream = UnixStream::connect(&path).map_err(|_| failure())?;
        directory.revalidate()?;
        if socket_identity(&path)? != identity {
            return Err(failure());
        }
        break stream;
    };
    let exchange = ActivationExchangeId::parse(op, attempt).map_err(|_| failure())?;
    let payload = format!("TAR1|{action}|{op}|{attempt}|{reason}|{loaded}\n");
    let reply = activation_client_exchange(stream, shell, &exchange, payload.as_bytes())
        .map_err(|_| failure())?;
    let frame = Frame::decode(&reply).map_err(|_| failure())?;
    match frame {
        Frame::Pending(actual)
        | Frame::Stage {
            attempt: actual, ..
        }
        | Frame::Failure {
            attempt: actual, ..
        } if actual == ids => Ok(frame),
        _ => Err(failure()),
    }
}

fn request_payload(bytes: &[u8], expected: Attempt, loaded: &str) -> Result<Request, String> {
    if bytes.len() > 512 {
        return Err(failure());
    }
    let line = std::str::from_utf8(bytes)
        .map_err(|_| failure())?
        .strip_suffix('\n')
        .ok_or_else(failure)?;
    let fields: Vec<_> = line.split('|').collect();
    let ["TAR1", action, op, attempt, reason, fingerprint] = fields.as_slice() else {
        return Err(failure());
    };
    if *fingerprint != loaded || ids(op, attempt)? != expected {
        return Err(failure());
    }
    let request = Request::parse(action, op, attempt, reason).map_err(|_| failure())?;
    if request == Request::Discover {
        return Err(failure());
    }
    Ok(request)
}

fn broker(
    shell: &AuthenticatedShellContext,
    ids: Attempt,
    loaded: &str,
    config_paths: &[PathBuf],
) -> Result<(), String> {
    let service = MutationService::current()?;
    let owner = service
        .claim_automatic_activation(shell, loaded)?
        .ok_or_else(failure)?;
    if owner.operation_id() != ids.operation.to_string()
        || owner.attempt_id() != ids.attempt.to_string()
    {
        return Err(failure());
    }
    let endpoint = EndpointOwner::bind(ids)?;
    let exchange =
        ActivationExchangeId::parse(&ids.operation.to_string(), &ids.attempt.to_string())
            .map_err(|_| failure())?;
    let mut pending: Option<PendingActivationClaim<'_>> = Some(owner);
    let mut running: Option<RunningActivationClaim<'_>> = None;
    let mut finished: Option<FinishedActivationClaim<'_>> = None;
    for _ in 0..MAX_REQUESTS {
        let stream = endpoint.accept(shell)?;
        let reply = activation_server_receive(stream, shell, &exchange).map_err(|_| failure())?;
        let request = request_payload(reply.request().map_err(|_| failure())?, ids, loaded)?;
        endpoint.revalidate()?;
        let mut complete = false;
        let frame = match request {
            Request::Start(_) => {
                if running.is_some() {
                    return Err(failure());
                }
                running = Some(
                    pending
                        .take()
                        .ok_or_else(failure)?
                        .start(config_paths, loaded)?,
                );
                Frame::Pending(ids)
            }
            Request::Next(_) => {
                let owner = running.as_mut().ok_or_else(failure)?;
                if owner.operation_id() != ids.operation.to_string()
                    || owner.attempt_id() != ids.attempt.to_string()
                {
                    return Err(failure());
                }
                let stage = match owner.issue_next()? {
                    AutomaticVerificationStage::Allowed => Stage::Allowed,
                    AutomaticVerificationStage::Blocked => Stage::Blocked,
                    AutomaticVerificationStage::Status => Stage::Status,
                    AutomaticVerificationStage::Restore => Stage::Restore,
                };
                Frame::Stage {
                    stage,
                    attempt: ids,
                    challenge: ids.attempt,
                }
            }
            Request::Restored(_) => {
                finished = Some(
                    running
                        .take()
                        .ok_or_else(failure)?
                        .finish_restored(loaded)?,
                );
                complete = true;
                Frame::Stage {
                    stage: Stage::Complete,
                    attempt: ids,
                    challenge: ids.attempt,
                }
            }
            Request::Cancel { reason, .. } => {
                if let Some(owner) = running.take() {
                    owner.abort()?;
                } else {
                    pending.take().ok_or_else(failure)?.cancel()?;
                }
                complete = true;
                Frame::Failure {
                    failure: Failure::Cancelled,
                    attempt: ids,
                    challenge: Some(ids.attempt),
                    reason,
                }
            }
            Request::Discover => return Err(failure()),
        };
        endpoint.revalidate()?;
        shell.revalidate()?;
        if let Some(owner) = &finished {
            owner.revalidate()?;
        }
        reply
            .reply(frame.encode().as_bytes())
            .map_err(|_| failure())?;
        if let Some(owner) = &finished {
            owner.revalidate()?;
        }
        if complete {
            return Ok(());
        }
    }
    Err(failure())
}

#[cfg(test)]
mod tests {
    use super::*;
    const OP: &str = "12345678-9abc-4def-8123-456789abcdef";
    const ATTEMPT: &str = "22345678-9abc-4def-8123-456789abcdef";

    #[test]
    fn request_payload_requires_exact_operation_fingerprint_and_closed_action() {
        let ids = ids(OP, ATTEMPT).unwrap();
        let loaded = "a".repeat(64);
        let good = format!("TAR1|next|{OP}|{ATTEMPT}|none|{loaded}\n");
        assert_eq!(
            request_payload(good.as_bytes(), ids, &loaded).unwrap(),
            Request::Next(ids)
        );
        for bad in [
            good.replace("next", "exec"),
            good.replace(OP, ATTEMPT),
            good.replace(&loaded, &"b".repeat(64)),
            format!("{good}\n"),
            good.replace("none", "deadline"),
            good.trim_end().into(),
            format!("{good}run"),
        ] {
            assert!(request_payload(bad.as_bytes(), ids, &loaded).is_err());
        }
    }

    #[test]
    fn socket_metadata_never_accepts_files_directories_or_symlinks() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("endpoint");
        std::fs::write(&path, []).unwrap();
        assert!(socket_identity(&path).is_err());
        assert!(socket_identity(temporary.path()).is_err());
        let alias = temporary.path().join("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(socket_identity(&alias).is_err());
    }
}
