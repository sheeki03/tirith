//! One authenticated activation request and reply over a supplied Unix stream.
//!
//! The CLI MUST arm its suspend-aware process deadline before entering this
//! module. The one-second cooperative I/O budget also covers the reply owner's
//! lifetime, but cannot interrupt capability or native process inspection.
//! This module creates no endpoint, file, child, thread, or output. Authentication
//! establishes capability knowledge and live native peer/context identity; it
//! does not authorize an activation stage or produce interception evidence.
//! A caller must validate the closed request grammar and its operation state.
//!
//! Credentials describe the socket's original peer. We reject descriptor
//! transfers whose observed peer is not a live sibling under the authenticated
//! shell, but make no proof against a cooperating capability/state owner, stolen
//! credentials, or an unobservable same-image exec. Native identity checks can
//! detect observable changes between samples, not lock another process in place.

use super::{
    shell_process_identity, AuthenticatedShellContext, ShellHookFamily, ShellProcessIdentity,
    TirithExecutableIdentity,
};
use hmac::{Hmac, Mac};
use sha2::{Digest as _, Sha256};
use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::fd::AsRawFd as _;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const MAGIC: &[u8; 8] = b"TIRACT01";
const DOMAIN: &[u8] = b"tirith-shell-activation-transport/v1\0";
const IO_BUDGET: Duration = Duration::from_secs(1);
const NONCE_LEN: usize = 32;
const TAG_LEN: usize = 32;
const HELLO_BODY_LEN: usize = 8 + 16 + 16 + NONCE_LEN + 32 + 32 + 32;
const HELLO_LEN: usize = HELLO_BODY_LEN + TAG_LEN;
const TRANSCRIPT_LEN: usize = HELLO_LEN + NONCE_LEN;
const REPLY_TRANSCRIPT_LEN: usize = TRANSCRIPT_LEN + TAG_LEN;
pub const ACTIVATION_REQUEST_CAP: usize = 512;
pub const ACTIVATION_REPLY_CAP: usize = 256;
type HmacSha256 = Hmac<Sha256>;
type Hash = [u8; 32];

/// Fixed, path-free error categories. No peer input or capability is formatted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ActivationTransportError {
    #[error("activation transport is unsupported on this platform")]
    Unsupported,
    #[error("activation transport identity is unavailable or changed")]
    Identity,
    #[error("activation transport authentication failed")]
    Authentication,
    #[error("activation transport frame is invalid")]
    Frame,
    #[error("activation transport payload exceeds its bound")]
    PayloadTooLarge,
    #[error("activation transport deadline expired")]
    Deadline,
    #[error("activation transport connection failed")]
    Connection,
    #[error("activation transport randomness is unavailable")]
    Randomness,
}
type Result<T> = std::result::Result<T, ActivationTransportError>;

/// Canonical, non-nil immutable operation and attempt identity. This is an
/// identifier, not authority to execute, resume, or retry an operation.
pub struct ActivationExchangeId {
    operation: [u8; 16],
    attempt: [u8; 16],
}

impl ActivationExchangeId {
    pub fn parse(operation: &str, attempt: &str) -> Result<Self> {
        fn canonical(value: &str) -> Result<[u8; 16]> {
            if value.len() != 36 {
                return Err(ActivationTransportError::Frame);
            }
            let id = uuid::Uuid::parse_str(value).map_err(|_| ActivationTransportError::Frame)?;
            if id.is_nil() || id.hyphenated().to_string() != value {
                return Err(ActivationTransportError::Frame);
            }
            Ok(*id.as_bytes())
        }
        Ok(Self {
            operation: canonical(operation)?,
            attempt: canonical(attempt)?,
        })
    }
}

/// Consume one connection, authenticate the server, send exactly one bounded
/// request, then return its authenticated bounded reply. The caller must arm
/// the outer suspend-aware deadline before calling this function.
pub fn activation_client_exchange(
    stream: UnixStream,
    context: &AuthenticatedShellContext,
    id: &ActivationExchangeId,
    request: &[u8],
) -> Result<Vec<u8>> {
    require_supported()?;
    check_payload(request, ACTIVATION_REQUEST_CAP)?;
    let mut io = BoundedIo::new(stream)?;
    let guard = ExchangeGuard::capture(context, &io)?;
    let binding = guard.binding(id, Role::Client)?;
    let hello = make_hello(context.secret.as_bytes(), &binding, fresh_nonce()?)?;
    io.write_all(&hello)?;
    let mut challenge = [0; NONCE_LEN + TAG_LEN];
    io.read_exact(&mut challenge)?;
    let transcript = accept_challenge(context.secret.as_bytes(), &hello, &challenge)?;
    guard.revalidate(&io)?;
    write_payload(
        &mut io,
        context.secret.as_bytes(),
        b"client-request",
        &transcript,
        request,
        ACTIVATION_REQUEST_CAP,
    )?;
    let reply_transcript = bind_request(context.secret.as_bytes(), &transcript, request);
    let reply = read_payload(
        &mut io,
        context.secret.as_bytes(),
        b"server-reply",
        &reply_transcript,
        ACTIVATION_REPLY_CAP,
    )?;
    guard.revalidate(&io)?;
    // The server remains in reply() until this authenticated terminal ACK. Its
    // live identity is checked AFTER the reply, BEFORE permitting server exit.
    io.write_all(&tag(
        context.secret.as_bytes(),
        b"client-complete",
        &reply_transcript,
        &reply,
    ))?;
    io.finish_writing()?;
    io.require_eof()?;
    // Do not require a live server after EOF: it is now permitted to exit. The
    // preceding post-payload check is the terminal native authentication point.
    Ok(reply)
}

/// Consume one connection and receive one authenticated request. Nothing is
/// executed here. The opaque owner keeps the creating context borrowed, refuses
/// inspection/reply after drift or expiry, and can send only one reply.
pub fn activation_server_receive<'a>(
    stream: UnixStream,
    context: &'a AuthenticatedShellContext,
    id: &ActivationExchangeId,
) -> Result<ActivationReplyOwner<'a>> {
    require_supported()?;
    let mut io = BoundedIo::new(stream)?;
    let guard = ExchangeGuard::capture(context, &io)?;
    let binding = guard.binding(id, Role::Server)?;
    let mut hello = [0; HELLO_LEN];
    io.read_exact(&mut hello)?;
    accept_hello(context.secret.as_bytes(), &binding, &hello)?;
    guard.revalidate(&io)?;
    let (challenge, transcript) =
        make_challenge(context.secret.as_bytes(), &hello, fresh_nonce()?)?;
    io.write_all(&challenge)?;
    let request = read_payload(
        &mut io,
        context.secret.as_bytes(),
        b"client-request",
        &transcript,
        ACTIVATION_REQUEST_CAP,
    )?;
    guard.revalidate(&io)?;
    let transcript = bind_request(context.secret.as_bytes(), &transcript, &request);
    Ok(ActivationReplyOwner {
        io,
        guard,
        transcript,
        request,
    })
}

/// Non-Clone, non-serializable and non-Send through the borrowed shell context.
/// Dropping it closes its supplied connection without sending a reply.
pub struct ActivationReplyOwner<'a> {
    io: BoundedIo,
    guard: ExchangeGuard<'a>,
    transcript: [u8; REPLY_TRANSCRIPT_LEN],
    request: Vec<u8>,
}

impl ActivationReplyOwner<'_> {
    /// Borrow authenticated bytes only after a fresh identity/deadline check.
    pub fn request(&self) -> Result<&[u8]> {
        self.guard.revalidate(&self.io)?;
        Ok(&self.request)
    }

    /// Consume this owner. Callers must finish their closed, authorized action
    /// within the original deadline, not start a fresh budget for replying.
    pub fn reply(mut self, reply: &[u8]) -> Result<()> {
        check_payload(reply, ACTIVATION_REPLY_CAP)?;
        self.guard.revalidate(&self.io)?;
        write_payload(
            &mut self.io,
            self.guard.context.secret.as_bytes(),
            b"server-reply",
            &self.transcript,
            reply,
            ACTIVATION_REPLY_CAP,
        )?;
        let mut acknowledgment = [0; TAG_LEN];
        self.io.read_exact(&mut acknowledgment)?;
        verify_tag(
            self.guard.context.secret.as_bytes(),
            b"client-complete",
            &self.transcript,
            reply,
            &acknowledgment,
        )?;
        // No second request is read. Trailing/pipelined data after the closed
        // ACK refuses; the application must reconcile its durable operation if
        // a completed action's response or ACK is lost.
        self.io.require_eof()?;
        // The client waits for server EOF here, so both endpoints remain live
        // through their post-payload checks. No peer check follows this close.
        self.guard.revalidate(&self.io)?;
        self.io.finish_writing()
    }
}

fn require_supported() -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(ActivationTransportError::Unsupported)
    }
}

#[derive(Clone, Copy)]
enum Role {
    Client,
    Server,
}

struct ExchangeGuard<'a> {
    context: &'a AuthenticatedShellContext,
    credentials: PeerCredentials,
    own: ProcessSnapshot,
    peer: ProcessSnapshot,
}

impl<'a> ExchangeGuard<'a> {
    fn capture(context: &'a AuthenticatedShellContext, io: &BoundedIo) -> Result<Self> {
        io.check_deadline()?;
        context
            .revalidate()
            .map_err(|_| ActivationTransportError::Identity)?;
        let credentials = peer_credentials(&io.stream)?;
        let own = process_snapshot(std::process::id())?;
        let peer = process_snapshot(credentials.pid)?;
        validate_pair(
            context.shell_pid,
            context.identity.effective_uid,
            &credentials,
            &own,
            &peer,
        )?;
        let guard = Self {
            context,
            credentials,
            own,
            peer,
        };
        guard.revalidate(io)?;
        Ok(guard)
    }

    fn revalidate(&self, io: &BoundedIo) -> Result<()> {
        io.check_deadline()?;
        self.context
            .revalidate()
            .map_err(|_| ActivationTransportError::Identity)?;
        let credentials = peer_credentials(&io.stream)?;
        let own = process_snapshot(std::process::id())?;
        let peer = process_snapshot(credentials.pid)?;
        validate_pair(
            self.context.shell_pid,
            self.context.identity.effective_uid,
            &credentials,
            &own,
            &peer,
        )?;
        if credentials != self.credentials || own != self.own || peer != self.peer {
            return Err(ActivationTransportError::Identity);
        }
        self.context
            .revalidate()
            .map_err(|_| ActivationTransportError::Identity)?;
        io.check_deadline()
    }

    fn binding(&self, id: &ActivationExchangeId, role: Role) -> Result<WireBinding> {
        let (client, server) = match role {
            Role::Client => (&self.own, &self.peer),
            Role::Server => (&self.peer, &self.own),
        };
        Ok(WireBinding {
            operation: id.operation,
            attempt: id.attempt,
            context: context_digest(self.context)?,
            client: client.digest(),
            server: server.digest(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PeerCredentials {
    pid: u32,
    uid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessSnapshot {
    pid: u32,
    parent: u32,
    birth: ShellProcessIdentity,
    image: Hash,
}

impl ProcessSnapshot {
    fn digest(&self) -> Hash {
        let mut hash = Sha256::new();
        hash.update(b"tirith-activation-native-peer/v1\0");
        hash.update(self.pid.to_be_bytes());
        hash.update(self.parent.to_be_bytes());
        hash.update(self.birth.effective_uid.to_be_bytes());
        hash_field(&mut hash, self.birth.start_fingerprint.as_bytes());
        hash.update(self.image);
        hash.finalize().into()
    }
}

fn validate_pair(
    shell_pid: u32,
    uid: u32,
    credentials: &PeerCredentials,
    own: &ProcessSnapshot,
    peer: &ProcessSnapshot,
) -> Result<()> {
    if own.pid <= 1
        || peer.pid <= 1
        || own.pid == peer.pid
        || credentials.pid != peer.pid
        || credentials.uid != uid
        || own.birth.effective_uid != uid
        || peer.birth.effective_uid != uid
        || own.parent != shell_pid
        || peer.parent != shell_pid
    {
        return Err(ActivationTransportError::Identity);
    }
    Ok(())
}

fn context_digest(context: &AuthenticatedShellContext) -> Result<Hash> {
    // The existing capability validates session identity. The extra transport
    // bound prevents an oversized inherited input becoming protocol work.
    if context.session_id.is_empty() || context.session_id.len() > 256 {
        return Err(ActivationTransportError::Identity);
    }
    let mut hash = Sha256::new();
    hash.update(b"tirith-activation-shell-context/v1\0");
    hash.update(context.shell_pid.to_be_bytes());
    hash.update(context.identity.effective_uid.to_be_bytes());
    hash_field(&mut hash, context.identity.start_fingerprint.as_bytes());
    hash.update([match context.family {
        ShellHookFamily::Zsh => 1,
        ShellHookFamily::Fish => 2,
        ShellHookFamily::Bash => 3,
    }]);
    hash_field(&mut hash, context.session_id.as_bytes());
    hash_executable(&mut hash, &context.executable);
    Ok(hash.finalize().into())
}

fn hash_field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn hash_executable(hash: &mut Sha256, identity: &TirithExecutableIdentity) {
    hash.update(identity.device.to_be_bytes());
    hash.update(identity.inode.to_be_bytes());
    hash.update(identity.size.to_be_bytes());
    hash.update(identity.owner_uid.to_be_bytes());
    hash.update(identity.mode.to_be_bytes());
    hash.update(identity.modified_seconds.to_be_bytes());
    hash.update(identity.modified_nanoseconds.to_be_bytes());
    hash.update(identity.changed_seconds.to_be_bytes());
    hash.update(identity.changed_nanoseconds.to_be_bytes());
}

fn process_snapshot(pid: u32) -> Result<ProcessSnapshot> {
    let first = shell_process_identity(pid).map_err(|_| ActivationTransportError::Identity)?;
    let (parent, image) = native_process_details(pid)?;
    let second = shell_process_identity(pid).map_err(|_| ActivationTransportError::Identity)?;
    let (second_parent, second_image) = native_process_details(pid)?;
    let last = shell_process_identity(pid).map_err(|_| ActivationTransportError::Identity)?;
    if first != second || second != last || parent != second_parent || image != second_image {
        return Err(ActivationTransportError::Identity);
    }
    Ok(ProcessSnapshot {
        pid,
        parent,
        birth: last,
        image,
    })
}

#[cfg(target_os = "linux")]
fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials> {
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::zeroed();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the output is an aligned ucred of exactly the advertised size.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 || length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(ActivationTransportError::Identity);
    }
    let credentials = unsafe { credentials.assume_init() };
    if credentials.pid <= 1 {
        return Err(ActivationTransportError::Identity);
    }
    Ok(PeerCredentials {
        pid: credentials.pid as u32,
        uid: credentials.uid,
    })
}

#[cfg(target_os = "macos")]
fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials> {
    let mut uid = 0;
    let mut gid = 0;
    let mut pid: libc::pid_t = 0;
    let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: all credential outputs are correctly sized live local values.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    let pid_result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut length,
        )
    };
    if result != 0
        || pid_result != 0
        || length as usize != std::mem::size_of::<libc::pid_t>()
        || pid <= 1
    {
        return Err(ActivationTransportError::Identity);
    }
    Ok(PeerCredentials {
        pid: pid as u32,
        uid,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peer_credentials(_: &UnixStream) -> Result<PeerCredentials> {
    Err(ActivationTransportError::Unsupported)
}

#[cfg(target_os = "linux")]
fn native_process_details(pid: u32) -> Result<(u32, Hash)> {
    use std::os::unix::fs::MetadataExt as _;
    use std::path::PathBuf;
    let root = PathBuf::from(format!("/proc/{pid}"));
    let status = super::read_linux_process_file(&root.join("status"), 64 * 1024)
        .map_err(|_| ActivationTransportError::Identity)?;
    let parent = status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|value| *value > 1)
        .ok_or(ActivationTransportError::Identity)?;
    // Intentionally follow only this kernel-provided proc executable link. No
    // pathname supplied by the socket peer is opened. This observes the mapped
    // executable inode even if its ordinary pathname was replaced or removed.
    let metadata =
        std::fs::metadata(root.join("exe")).map_err(|_| ActivationTransportError::Identity)?;
    if !metadata.is_file() {
        return Err(ActivationTransportError::Identity);
    }
    let identity = TirithExecutableIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        owner_uid: metadata.uid(),
        mode: metadata.mode(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    };
    let mut hash = Sha256::new();
    hash.update(b"linux-mapped-executable/v1\0");
    hash_executable(&mut hash, &identity);
    Ok((parent, hash.finalize().into()))
}

#[cfg(target_os = "macos")]
fn native_process_details(pid: u32) -> Result<(u32, Hash)> {
    use std::os::unix::ffi::OsStrExt as _;
    let pid = super::validate_shell_pid(pid).map_err(|_| ActivationTransportError::Identity)?;
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = std::mem::size_of::<libc::proc_bsdinfo>();
    // SAFETY: proc_pidinfo writes at most the advertised, correctly typed size.
    let count = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size as libc::c_int,
        )
    };
    if count != size as libc::c_int {
        return Err(ActivationTransportError::Identity);
    }
    let info = unsafe { info.assume_init() };
    if info.pbi_pid != pid as u32 || info.pbi_ppid <= 1 || info.pbi_status == libc::SZOMB {
        return Err(ActivationTransportError::Identity);
    }
    let mut path = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let length = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
    if length <= 0 || length as usize >= path.len() {
        return Err(ActivationTransportError::Identity);
    }
    let length = path
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(ActivationTransportError::Identity)?;
    if length == 0 || path[0] != b'/' {
        return Err(ActivationTransportError::Identity);
    }
    let path_bytes = &path[..length];
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(path_bytes));
    // macOS exposes the native image path here, not an owned mapped-vnode
    // descriptor. Path plus trusted current metadata detects observable drift;
    // a same-path same-image exec is outside this transport's stated proof.
    let identity =
        super::identity_for_launch_path(path).map_err(|_| ActivationTransportError::Identity)?;
    let mut hash = Sha256::new();
    hash.update(b"macos-native-image-path/v1\0");
    hash_field(&mut hash, path_bytes);
    hash_executable(&mut hash, &identity);
    Ok((info.pbi_ppid, hash.finalize().into()))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn native_process_details(_: u32) -> Result<(u32, Hash)> {
    Err(ActivationTransportError::Unsupported)
}

#[derive(Clone)]
struct WireBinding {
    operation: [u8; 16],
    attempt: [u8; 16],
    context: Hash,
    client: Hash,
    server: Hash,
}

fn fresh_nonce() -> Result<Hash> {
    let mut nonce = [0; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| ActivationTransportError::Randomness)?;
    if nonce == [0; NONCE_LEN] {
        return Err(ActivationTransportError::Randomness);
    }
    Ok(nonce)
}

fn mac_state(key: &[u8], role: &[u8], transcript: &[u8], payload: &[u8]) -> HmacSha256 {
    // HMAC-SHA256 accepts keys of any length. Only the private authenticated
    // context's existing 256-bit capability reaches this function in production.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(DOMAIN);
    for field in [role, transcript, payload] {
        mac.update(&(field.len() as u64).to_be_bytes());
        mac.update(field);
    }
    mac
}

fn tag(key: &[u8], role: &[u8], transcript: &[u8], payload: &[u8]) -> Hash {
    mac_state(key, role, transcript, payload)
        .finalize()
        .into_bytes()
        .into()
}

fn verify_tag(
    key: &[u8],
    role: &[u8],
    transcript: &[u8],
    payload: &[u8],
    supplied: &[u8],
) -> Result<()> {
    mac_state(key, role, transcript, payload)
        .verify_slice(supplied)
        .map_err(|_| ActivationTransportError::Authentication)
}

fn hello_body(binding: &WireBinding, nonce: Hash) -> [u8; HELLO_BODY_LEN] {
    let mut hello = [0; HELLO_BODY_LEN];
    let mut position = 0;
    for field in [
        MAGIC.as_slice(),
        binding.operation.as_slice(),
        binding.attempt.as_slice(),
        nonce.as_slice(),
        binding.context.as_slice(),
        binding.client.as_slice(),
        binding.server.as_slice(),
    ] {
        hello[position..position + field.len()].copy_from_slice(field);
        position += field.len();
    }
    hello
}

fn make_hello(key: &[u8], binding: &WireBinding, nonce: Hash) -> Result<[u8; HELLO_LEN]> {
    if nonce == [0; NONCE_LEN] {
        return Err(ActivationTransportError::Frame);
    }
    let body = hello_body(binding, nonce);
    let mut hello = [0; HELLO_LEN];
    hello[..HELLO_BODY_LEN].copy_from_slice(&body);
    hello[HELLO_BODY_LEN..].copy_from_slice(&tag(key, b"client-hello", &body, &[]));
    Ok(hello)
}

fn accept_hello(key: &[u8], binding: &WireBinding, hello: &[u8; HELLO_LEN]) -> Result<()> {
    let nonce: Hash = hello[40..72]
        .try_into()
        .map_err(|_| ActivationTransportError::Frame)?;
    if nonce == [0; NONCE_LEN] || hello[..HELLO_BODY_LEN] != hello_body(binding, nonce) {
        return Err(ActivationTransportError::Authentication);
    }
    verify_tag(
        key,
        b"client-hello",
        &hello[..HELLO_BODY_LEN],
        &[],
        &hello[HELLO_BODY_LEN..],
    )
}

fn make_challenge(
    key: &[u8],
    hello: &[u8; HELLO_LEN],
    nonce: Hash,
) -> Result<([u8; NONCE_LEN + TAG_LEN], [u8; TRANSCRIPT_LEN])> {
    if nonce == [0; NONCE_LEN] || nonce.as_slice() == &hello[40..72] {
        return Err(ActivationTransportError::Frame);
    }
    let mut transcript = [0; TRANSCRIPT_LEN];
    transcript[..HELLO_LEN].copy_from_slice(hello);
    transcript[HELLO_LEN..].copy_from_slice(&nonce);
    let mut challenge = [0; NONCE_LEN + TAG_LEN];
    challenge[..NONCE_LEN].copy_from_slice(&nonce);
    challenge[NONCE_LEN..].copy_from_slice(&tag(key, b"server-challenge", &transcript, &[]));
    Ok((challenge, transcript))
}

fn accept_challenge(
    key: &[u8],
    hello: &[u8; HELLO_LEN],
    challenge: &[u8; NONCE_LEN + TAG_LEN],
) -> Result<[u8; TRANSCRIPT_LEN]> {
    let nonce: Hash = challenge[..NONCE_LEN]
        .try_into()
        .map_err(|_| ActivationTransportError::Frame)?;
    let (_, transcript) = make_challenge(key, hello, nonce)?;
    verify_tag(
        key,
        b"server-challenge",
        &transcript,
        &[],
        &challenge[NONCE_LEN..],
    )?;
    Ok(transcript)
}

fn check_payload(payload: &[u8], cap: usize) -> Result<()> {
    if payload.len() > cap {
        Err(ActivationTransportError::PayloadTooLarge)
    } else {
        Ok(())
    }
}

fn bind_request(
    key: &[u8],
    transcript: &[u8; TRANSCRIPT_LEN],
    request: &[u8],
) -> [u8; REPLY_TRANSCRIPT_LEN] {
    let mut bound = [0; REPLY_TRANSCRIPT_LEN];
    bound[..TRANSCRIPT_LEN].copy_from_slice(transcript);
    bound[TRANSCRIPT_LEN..].copy_from_slice(&tag(key, b"client-request", transcript, request));
    bound
}

fn write_payload(
    io: &mut BoundedIo,
    key: &[u8],
    role: &[u8],
    transcript: &[u8],
    payload: &[u8],
    cap: usize,
) -> Result<()> {
    check_payload(payload, cap)?;
    let length = (payload.len() as u16).to_be_bytes();
    io.write_all(&length)?;
    io.write_all(payload)?;
    io.write_all(&tag(key, role, transcript, payload))
}

fn read_payload(
    io: &mut BoundedIo,
    key: &[u8],
    role: &[u8],
    transcript: &[u8],
    cap: usize,
) -> Result<Vec<u8>> {
    let mut length = [0; 2];
    io.read_exact(&mut length)?;
    let length = u16::from_be_bytes(length) as usize;
    if length > cap {
        return Err(ActivationTransportError::PayloadTooLarge);
    }
    let mut payload = vec![0; length];
    io.read_exact(&mut payload)?;
    let mut supplied = [0; TAG_LEN];
    io.read_exact(&mut supplied)?;
    verify_tag(key, role, transcript, &payload, &supplied)?;
    Ok(payload)
}

struct BoundedIo {
    stream: UnixStream,
    deadline: Instant,
}

impl BoundedIo {
    fn new(stream: UnixStream) -> Result<Self> {
        let deadline = Instant::now()
            .checked_add(IO_BUDGET)
            .ok_or(ActivationTransportError::Deadline)?;
        stream
            .set_nonblocking(true)
            .map_err(|_| ActivationTransportError::Connection)?;
        Ok(Self { stream, deadline })
    }

    fn check_deadline(&self) -> Result<()> {
        if Instant::now() >= self.deadline {
            Err(ActivationTransportError::Deadline)
        } else {
            Ok(())
        }
    }

    fn wait(&self, events: libc::c_short) -> Result<()> {
        loop {
            self.check_deadline()?;
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            let millis = remaining
                .as_millis()
                .saturating_add(1)
                .min(i32::MAX as u128) as i32;
            let mut item = libc::pollfd {
                fd: self.stream.as_raw_fd(),
                events,
                revents: 0,
            };
            // SAFETY: one live pollfd is passed with an absolute-budget-derived timeout.
            let result = unsafe { libc::poll(&mut item, 1, millis) };
            self.check_deadline()?;
            if result < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(ActivationTransportError::Connection);
            }
            if result == 0 {
                continue;
            }
            if item.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(ActivationTransportError::Connection);
            }
            if item.revents & events != 0
                || events == libc::POLLIN && item.revents & libc::POLLHUP != 0
            {
                return Ok(());
            }
            if item.revents & libc::POLLHUP != 0 {
                return Err(ActivationTransportError::Connection);
            }
        }
    }

    fn read_exact(&mut self, mut bytes: &mut [u8]) -> Result<()> {
        while !bytes.is_empty() {
            self.check_deadline()?;
            match self.stream.read(bytes) {
                Ok(0) => return Err(ActivationTransportError::Connection),
                Ok(count) => bytes = &mut bytes[count..],
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.wait(libc::POLLIN)?
                }
                Err(_) => return Err(ActivationTransportError::Connection),
            }
        }
        self.check_deadline()
    }

    fn write_all(&mut self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            self.check_deadline()?;
            match self.stream.write(bytes) {
                Ok(0) => return Err(ActivationTransportError::Connection),
                Ok(count) => bytes = &bytes[count..],
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.wait(libc::POLLOUT)?
                }
                Err(_) => return Err(ActivationTransportError::Connection),
            }
        }
        self.check_deadline()
    }

    fn finish_writing(&self) -> Result<()> {
        self.check_deadline()?;
        self.stream
            .shutdown(Shutdown::Write)
            .map_err(|_| ActivationTransportError::Connection)?;
        self.check_deadline()
    }

    fn require_eof(&mut self) -> Result<()> {
        loop {
            self.check_deadline()?;
            match self.stream.read(&mut [0; 1]) {
                Ok(0) => return self.check_deadline(),
                Ok(_) => return Err(ActivationTransportError::Frame),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    self.wait(libc::POLLIN)?
                }
                Err(_) => return Err(ActivationTransportError::Connection),
            }
        }
    }
}

#[cfg(test)]
#[path = "activation_transport_tests.rs"]
mod tests;
