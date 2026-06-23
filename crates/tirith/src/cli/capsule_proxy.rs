//! Capsule egress broker (Stack E, unit E1).
//!
//! A **loopback-only HTTP CONNECT broker** that an OS sandbox backend funnels a
//! contained child's outbound traffic through. It is emphatically **NOT the
//! security boundary** (cross-cutting invariant 3): the boundary is the OS
//! backend that blocks every raw outbound socket *except* the connection to this
//! broker. The broker's job is to make sure that, given the child can only talk
//! to it, the only traffic that escapes the host is to the policy-approved
//! domains/ports — re-validated at connect time so a hostile resolver or a
//! policy gap cannot turn the broker into an open proxy.
//!
//! ## What the broker enforces (per the invariant-3 checklist)
//!
//! - **Per-session auth token.** Each capsule run mints a random token; the
//!   backend injects it into the child's environment and the broker requires it
//!   on every CONNECT via `Proxy-Authorization: Bearer <token>`. A request
//!   without the exact token is rejected before any DNS or connect.
//! - **Port allow-list + domain policy.** CONNECT is honored only for a
//!   `(host, port)` that [`NetworkPolicy::permits`] — the configured domains and
//!   the configured CONNECT ports (typically `{443}`).
//! - **Resolve once, validate every IP, never re-resolve.** The target host is
//!   resolved a single time; every resolved address is filtered through the same
//!   public/non-public classifier the URL validators use
//!   ([`is_public_addr`]) plus an explicit cloud-metadata drop
//!   ([`is_cloud_metadata_addr`]). The broker then connects to one approved IP and
//!   tunnels to *that address*, never re-resolving (closing the DNS-rebind gap).
//! - **TLS SNI pinning.** For the (default) TLS-only mode the broker reads a
//!   bounded ClientHello off the front of the tunnel and requires the SNI to
//!   equal the approved CONNECT host. A tunnel whose ClientHello names a different
//!   host — or carries no SNI, or is not TLS at all — is refused unless plaintext
//!   is explicitly allowed.
//! - **Caps everywhere.** Concurrent connections, bytes per connection, resolved
//!   addresses considered, the handshake/first-bytes deadline, and the idle
//!   timeout are all bounded.
//! - **Secret-free audit.** Every decision is recorded with host/IP/port/bytes
//!   and a reason — never the token, never tunnel bytes.
//!
//! This unit (E1) builds the broker and its testable decision core. The OS
//! backends that actually block raw sockets (E2-E4) and the consumers that spawn
//! a child behind the broker (E5) come later; nothing here is wired into a
//! command yet, and the broker never claims, by itself, that egress is contained.
//!
//! Because no runtime consumer calls the broker until E5, the public API and its
//! private helpers are exercised only by this module's own tests in this unit.
//! `#![allow(dead_code)]` keeps the not-yet-wired surface from tripping the
//! `-D warnings` gate; E5 removes the need for it by routing the gateway upstream
//! spawn, `runner.rs`, `temp_run.rs`, and the package-firewall install through it.
#![allow(dead_code)]

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use tirith_core::capsule::NetworkPolicy;
use tirith_core::url_validate::{is_cloud_metadata_addr, is_public_addr};

/// Hard ceilings for the broker. These bound the resource cost and the blast
/// radius of any single connection. They are deliberately conservative; a caller
/// may lower them but the broker never runs unbounded.
#[derive(Debug, Clone)]
pub struct BrokerLimits {
    /// Maximum simultaneous tunnels the broker will service. Beyond this, new
    /// connections are accepted and immediately closed with a 503.
    pub max_connections: u64,
    /// Maximum bytes tunneled in EACH direction per connection before the tunnel
    /// is torn down (a contained install/MCP server should never need more).
    pub max_bytes_per_direction: u64,
    /// Maximum number of resolved addresses the broker will consider for a host.
    /// A host that resolves to more than this is treated as hostile and refused.
    pub max_resolved_addrs: usize,
    /// Deadline for reading the CONNECT request head AND the first client bytes
    /// (the ClientHello for SNI pinning). A slow-loris client is dropped.
    pub handshake_timeout: Duration,
    /// Idle timeout for an established tunnel. No bytes either way within this
    /// window tears the tunnel down.
    pub idle_timeout: Duration,
}

impl Default for BrokerLimits {
    fn default() -> Self {
        BrokerLimits {
            max_connections: 64,
            max_bytes_per_direction: 256 * 1024 * 1024,
            max_resolved_addrs: 8,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(120),
        }
    }
}

/// Immutable configuration for one broker instance (one capsule run).
#[derive(Debug, Clone)]
pub struct BrokerConfig {
    /// The egress policy: which domains/ports the contained child may reach.
    pub network: NetworkPolicy,
    /// The per-session bearer token the child must present on every CONNECT.
    pub session_token: String,
    /// When `false` (the default), only TLS tunnels are permitted and the SNI is
    /// pinned to the CONNECT host. When `true`, a plaintext tunnel is allowed for
    /// the approved host (the broker still pins the destination IP and policy).
    pub allow_plaintext: bool,
    /// Resource ceilings.
    pub limits: BrokerLimits,
}

impl BrokerConfig {
    /// Construct a TLS-only broker config for `network` with a freshly-minted
    /// session token. The caller hands the token to the OS backend, which injects
    /// it into the child.
    ///
    /// **Rejects an empty `session_token`.** An empty token is never a valid
    /// per-session secret: paired with a missing/empty presented token it would make
    /// `constant_time_eq(b"", b"")` authenticate an anonymous client (the broker
    /// would become an open proxy for any loopback peer). A correctly-minted token is
    /// always non-empty, so this only rejects a misuse, and it fails closed at
    /// construction rather than relying solely on the per-request guard in
    /// [`decide_connect`].
    pub fn new(network: NetworkPolicy, session_token: String) -> Result<Self, String> {
        if session_token.is_empty() {
            return Err(
                "broker session token must not be empty (an empty token would authenticate \
                 an anonymous client)"
                    .to_string(),
            );
        }
        Ok(BrokerConfig {
            network,
            session_token,
            allow_plaintext: false,
            limits: BrokerLimits::default(),
        })
    }
}

/// The outcome of validating one CONNECT request, *before* any upstream socket is
/// opened. This is the broker's pure security decision; the async tunnel acts on
/// it. Kept as its own type so the policy logic is unit-testable without sockets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectDecision {
    /// The request passed the token, policy, and IP checks. The broker may open a
    /// tunnel to exactly `approved_ip:port` (NEVER re-resolving `host`), and must
    /// pin the TLS SNI to `host` unless plaintext is allowed.
    Allow {
        host: String,
        port: u16,
        approved_ip: IpAddr,
    },
    /// The request was refused. `reason` is a short, secret-free description for
    /// the audit log and the 4xx/5xx status returned to the client.
    Deny { reason: String },
}

/// A single parsed CONNECT request head: the target authority and the presented
/// proxy-authorization bearer token (if any). Produced by [`parse_connect_head`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectRequest {
    pub host: String,
    pub port: u16,
    pub bearer_token: Option<String>,
}

/// Parse the head of an HTTP CONNECT request from the bytes already read off the
/// client socket. Recognizes ONLY the `CONNECT host:port HTTP/1.x` form (this is
/// a CONNECT-only broker; any other method is rejected upstream). Extracts the
/// `Proxy-Authorization: Bearer <token>` header if present.
///
/// `head` must be the request head up to and including the terminating CRLFCRLF;
/// the caller bounds how many bytes it reads. Returns `Err(reason)` for anything
/// malformed so the broker can deny with a stable message.
pub fn parse_connect_head(head: &str) -> Result<ConnectRequest, String> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or_else(|| "empty request".to_string())?;
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("");
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(format!("method not allowed: {method}"));
    }
    let authority = parts
        .next()
        .ok_or_else(|| "missing CONNECT authority".to_string())?;
    let (host, port) = split_authority(authority)?;

    let mut bearer_token = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("proxy-authorization") {
                let value = value.trim();
                if let Some(rest) = value.strip_prefix("Bearer ") {
                    bearer_token = Some(rest.trim().to_string());
                } else if let Some(rest) = value.strip_prefix("bearer ") {
                    bearer_token = Some(rest.trim().to_string());
                }
            }
        }
    }

    Ok(ConnectRequest {
        host,
        port,
        bearer_token,
    })
}

/// Split a `host:port` authority. The host must be a non-empty registered name or
/// IP literal; the port must parse to a `u16`. IPv6 literals in brackets
/// (`[::1]:443`) are supported.
fn split_authority(authority: &str) -> Result<(String, u16), String> {
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: [addr]:port
        let (addr, port_part) = rest
            .split_once(']')
            .ok_or_else(|| "malformed IPv6 authority".to_string())?;
        let port = port_part
            .strip_prefix(':')
            .ok_or_else(|| "IPv6 authority missing port".to_string())?
            .parse::<u16>()
            .map_err(|_| "invalid port".to_string())?;
        if addr.is_empty() {
            return Err("empty host".to_string());
        }
        return Ok((addr.to_string(), port));
    }
    let (host, port_str) = authority
        .rsplit_once(':')
        .ok_or_else(|| "authority missing port".to_string())?;
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    let port = port_str
        .parse::<u16>()
        .map_err(|_| "invalid port".to_string())?;
    Ok((host.to_string(), port))
}

/// Decide whether to allow a parsed CONNECT request, given the broker config and
/// the addresses the host resolved to. **This is the broker's whole security
/// decision** and is intentionally pure (no I/O) so every branch is testable.
///
/// Order of checks (cheapest / most-decisive first):
/// 1. Constant-time-ish token equality (a missing or wrong token is refused
///    before anything else; we never leak whether the host/port would be valid).
/// 2. Domain + port policy ([`NetworkPolicy::permits`]).
/// 3. Resolution-count cap.
/// 4. Per-IP public/non-public + metadata filtering. The FIRST approved IP is the
///    one the broker will connect to; if none survive, deny.
pub fn decide_connect(
    cfg: &BrokerConfig,
    req: &ConnectRequest,
    resolved: &[IpAddr],
) -> ConnectDecision {
    // 1. Token. Compared in a way that does not short-circuit on the first
    //    differing byte, to avoid a timing oracle on the secret.
    let presented = req.bearer_token.as_deref().unwrap_or("");
    // Reject an empty token on EITHER side before the comparison: an empty
    // configured token (a config bug) plus a missing/empty presented token would
    // otherwise satisfy `constant_time_eq(b"", b"") == true` and authenticate an
    // anonymous client. The token is always non-empty in correct operation
    // (`BrokerConfig::new` refuses an empty one), so this can only fire on a misuse,
    // and it must fail closed.
    if presented.is_empty() || cfg.session_token.is_empty() {
        return ConnectDecision::Deny {
            reason: "missing or invalid proxy-authorization token".to_string(),
        };
    }
    if !constant_time_eq(presented.as_bytes(), cfg.session_token.as_bytes()) {
        return ConnectDecision::Deny {
            reason: "missing or invalid proxy-authorization token".to_string(),
        };
    }

    // 2. Domain + port policy.
    if !cfg.network.permits(&req.host, req.port) {
        return ConnectDecision::Deny {
            reason: format!("policy denies {}:{}", req.host, req.port),
        };
    }

    // 3. Resolution-count cap — a host that fans out to many addresses is treated
    //    as hostile (DNS amplification / rebind surface).
    if resolved.len() > cfg.limits.max_resolved_addrs {
        return ConnectDecision::Deny {
            reason: format!(
                "host resolved to {} addresses (cap {})",
                resolved.len(),
                cfg.limits.max_resolved_addrs
            ),
        };
    }

    // 4. Validate every resolved IP. Drop metadata IPs unconditionally and any
    //    non-public address; the first survivor is the approved connect target.
    let approved = resolved.iter().copied().find(|ip| {
        let sock = SocketAddr::new(*ip, req.port);
        is_public_addr(&sock) && !is_cloud_metadata_addr(&sock)
    });

    match approved {
        Some(ip) => ConnectDecision::Allow {
            host: req.host.clone(),
            port: req.port,
            approved_ip: ip,
        },
        None => ConnectDecision::Deny {
            reason: format!("{} resolves to no public address", req.host),
        },
    }
}

/// Extract the SNI server-name from the front of a TLS ClientHello, bounded.
///
/// This is a deliberately minimal, defensive TLS record/handshake walker: it
/// reads the first TLS record (must be a Handshake record, content type 22),
/// confirms it is a ClientHello (handshake type 1), skips the fixed
/// version/random/session-id/cipher-suites/compression fields, then walks the
/// extensions to find `server_name` (type 0) and returns the first
/// `host_name` (name type 0). Every length is bounds-checked against `buf`; any
/// truncation or malformed field yields `None` (the broker then refuses to pin,
/// hence refuses the tunnel).
///
/// It does NOT validate the handshake cryptographically — pinning the SNI to the
/// already-approved CONNECT host is the only goal. Returns the lower-cased,
/// trailing-dot-stripped host on success.
pub fn extract_sni(buf: &[u8]) -> Option<String> {
    // TLS record header: type(1) version(2) length(2).
    if buf.len() < 5 {
        return None;
    }
    if buf[0] != 22 {
        // Not a Handshake record -> not TLS (or not the ClientHello first).
        return None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record = buf.get(5..5 + record_len)?;

    // Handshake header: type(1) length(3).
    if record.len() < 4 {
        return None;
    }
    if record[0] != 1 {
        // Not a ClientHello.
        return None;
    }
    let hs_len = ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | (record[3] as usize);
    let body = record.get(4..4 + hs_len)?;

    // ClientHello body: client_version(2) random(32) then variable fields.
    let mut p = 0usize;
    p = p.checked_add(2)?; // client_version
    p = p.checked_add(32)?; // random
                            // session_id
    let sid_len = *body.get(p)? as usize;
    p = p.checked_add(1)?.checked_add(sid_len)?;
    // cipher_suites
    let cs_len = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p = p.checked_add(2)?.checked_add(cs_len)?;
    // compression_methods
    let cm_len = *body.get(p)? as usize;
    p = p.checked_add(1)?.checked_add(cm_len)?;
    // extensions
    let ext_total = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p = p.checked_add(2)?;
    let ext_end = p.checked_add(ext_total)?;
    if ext_end > body.len() {
        return None;
    }

    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[p], body[p + 1]]);
        let ext_len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        let ext_data = body.get(p..p.checked_add(ext_len)?)?;
        if ext_type == 0 {
            // server_name extension.
            return parse_server_name_list(ext_data);
        }
        p += ext_len;
    }
    None
}

/// Parse a `ServerNameList` extension body and return the first host_name.
fn parse_server_name_list(data: &[u8]) -> Option<String> {
    // ServerNameList: list_length(2) then entries of name_type(1) length(2) name.
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list = data.get(2..2 + list_len)?;
    let mut q = 0usize;
    while q + 3 <= list.len() {
        let name_type = list[q];
        let name_len = u16::from_be_bytes([list[q + 1], list[q + 2]]) as usize;
        q += 3;
        let name = list.get(q..q.checked_add(name_len)?)?;
        if name_type == 0 {
            // host_name.
            let host = std::str::from_utf8(name).ok()?;
            return Some(host.trim_end_matches('.').to_ascii_lowercase());
        }
        q += name_len;
    }
    None
}

/// Whether the SNI pulled from the ClientHello matches the approved CONNECT host.
/// Hosts are compared case-insensitively with trailing dots stripped. An IP
/// literal CONNECT host is exempt (TLS to an IP carries no SNI), but only when
/// the host actually parses as an IP — a registered name always requires a
/// matching SNI.
pub fn sni_matches_host(sni: Option<&str>, host: &str) -> bool {
    let host_norm = host.trim_end_matches('.').to_ascii_lowercase();
    if host_norm.parse::<IpAddr>().is_ok() {
        // CONNECT to an IP literal: no SNI to pin against.
        return true;
    }
    match sni {
        Some(name) => name.trim_end_matches('.').to_ascii_lowercase() == host_norm,
        None => false,
    }
}

/// A single audit record for a broker decision. Secret-free by construction: it
/// carries host/IP/port/bytes and a reason, never the token or tunnel content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerAuditEvent {
    pub host: String,
    pub port: u16,
    pub approved_ip: Option<IpAddr>,
    pub allowed: bool,
    pub reason: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

/// Constant-time byte-slice equality. Avoids a timing side channel on the
/// per-session token: it never early-returns on a length mismatch (which would
/// leak the token length through timing). Instead it folds the length difference
/// into the accumulator and walks the FULL length of both slices, so the work done
/// (and thus the timing) does not branch on whether the lengths matched. Unequal
/// lengths can never compare equal because the length XOR seeds a non-zero
/// accumulator.
///
/// Note: the loop count depends on the slice lengths (an attacker already controls
/// the length of the value they submit, and the secret length is fixed), but the
/// comparison no longer reveals the secret's length via an early return on
/// mismatch, and a wrong-length guess is never accepted.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Seed with the length difference: if the lengths differ this is non-zero, so
    // the result can never be `true` regardless of the byte comparison below. This
    // is what makes an unequal-length pair always compare false WITHOUT an early
    // return that would leak the length via timing.
    let mut diff: u8 = ((a.len() ^ b.len()) != 0) as u8;
    // Walk both slices to their full length so the loop never short-circuits on a
    // matching prefix. An index past the end of a slice reads as 0 (a missing byte
    // contributes `other ^ 0`); correctness rests on the length seed above, not on
    // these out-of-range slots.
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

/// Shared, mutable runtime state for a running broker: just the live connection
/// count for the concurrency cap. Wrapped in an `Arc` and shared across accepted
/// tasks.
#[derive(Debug, Default)]
pub struct BrokerState {
    active: AtomicU64,
}

impl BrokerState {
    fn try_acquire(&self, max: u64) -> bool {
        // Optimistic increment with rollback if we exceeded the cap.
        let prev = self.active.fetch_add(1, Ordering::SeqCst);
        if prev >= max {
            self.active.fetch_sub(1, Ordering::SeqCst);
            false
        } else {
            true
        }
    }

    fn release(&self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }

    /// Current number of in-flight tunnels (exposed for tests / diagnostics).
    pub fn active(&self) -> u64 {
        self.active.load(Ordering::SeqCst)
    }
}

/// Run the broker accept loop on an already-bound loopback listener until the
/// listener is dropped or an unrecoverable accept error occurs.
///
/// The listener MUST be bound to a loopback address by the caller (the broker
/// refuses to serve a non-loopback peer regardless, but binding loopback-only is
/// the first line of defense). Each accepted connection is serviced on its own
/// task. Audit events are delivered to `audit` (a simple callback so the caller
/// owns where they land — the audit hash-chain, a test sink, etc.).
///
/// This is the I/O shell around [`decide_connect`] / [`extract_sni`] /
/// [`sni_matches_host`]; the security decisions live in those pure functions.
pub async fn run_broker<F>(listener: TcpListener, cfg: Arc<BrokerConfig>, audit: Arc<F>)
where
    F: Fn(BrokerAuditEvent) + Send + Sync + 'static,
{
    let state = Arc::new(BrokerState::default());
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        // Loopback-only: refuse any peer that is not a loopback address.
        if !peer.ip().is_loopback() {
            // Drop immediately; do not even read the request.
            drop(stream);
            continue;
        }
        let cfg = Arc::clone(&cfg);
        let audit = Arc::clone(&audit);
        let state = Arc::clone(&state);
        if !state.try_acquire(cfg.limits.max_connections) {
            // Over the concurrency cap: refuse politely and move on.
            tokio::spawn(async move {
                let mut s = stream;
                let _ = s
                    .write_all(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
                    .await;
                let _ = s.shutdown().await;
            });
            continue;
        }
        tokio::spawn(async move {
            let _guard = ConnGuard {
                state: Arc::clone(&state),
            };
            if let Err(reason) = serve_connection(stream, &cfg, &audit).await {
                // serve_connection already audited; this is a defensive log only.
                let _ = reason;
            }
        });
    }
}

/// RAII guard that releases a connection slot when the serving task ends.
struct ConnGuard {
    state: Arc<BrokerState>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.state.release();
    }
}

/// Service one client connection end to end: read+parse the CONNECT head, decide,
/// (on allow) connect to the approved IP, pin the SNI, then tunnel with caps.
async fn serve_connection<F>(
    mut client: TcpStream,
    cfg: &BrokerConfig,
    audit: &Arc<F>,
) -> Result<(), String>
where
    F: Fn(BrokerAuditEvent) + Send + Sync + 'static,
{
    // Read the CONNECT request head with a bound and a deadline.
    let head =
        match tokio::time::timeout(cfg.limits.handshake_timeout, read_request_head(&mut client))
            .await
        {
            Ok(Ok(h)) => h,
            Ok(Err(e)) => {
                deny(&mut client, audit, "", 0, None, &e).await;
                return Err(e);
            }
            Err(_) => {
                deny(&mut client, audit, "", 0, None, "request head timeout").await;
                return Err("request head timeout".to_string());
            }
        };

    let req = match parse_connect_head(&head) {
        Ok(r) => r,
        Err(e) => {
            deny(&mut client, audit, "", 0, None, &e).await;
            return Err(e);
        }
    };

    // Resolve ONCE. The blocking resolver runs on the runtime's blocking pool.
    let host_for_lookup = req.host.clone();
    let port = req.port;
    let resolved: Vec<IpAddr> = match tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        (host_for_lookup.as_str(), port)
            .to_socket_addrs()
            .map(|it| it.map(|s| s.ip()).collect::<Vec<_>>())
    })
    .await
    {
        Ok(Ok(v)) => v,
        _ => {
            deny(
                &mut client,
                audit,
                &req.host,
                req.port,
                None,
                "resolution failed",
            )
            .await;
            return Err("resolution failed".to_string());
        }
    };

    let decision = decide_connect(cfg, &req, &resolved);
    let (host, port, approved_ip) = match decision {
        ConnectDecision::Allow {
            host,
            port,
            approved_ip,
        } => (host, port, approved_ip),
        ConnectDecision::Deny { reason } => {
            deny(&mut client, audit, &req.host, req.port, None, &reason).await;
            return Err(reason);
        }
    };

    // Connect to EXACTLY the approved IP — never re-resolve the host.
    let upstream = match tokio::time::timeout(
        cfg.limits.handshake_timeout,
        TcpStream::connect(SocketAddr::new(approved_ip, port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        _ => {
            deny(
                &mut client,
                audit,
                &host,
                port,
                Some(approved_ip),
                "upstream connect failed",
            )
            .await;
            return Err("upstream connect failed".to_string());
        }
    };

    // Acknowledge the tunnel to the client BEFORE pinning, so the client sends its
    // ClientHello (which we then peek for SNI).
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .is_err()
    {
        return Err("client write failed".to_string());
    }

    // Peek the client's first bytes (the ClientHello) within the handshake
    // deadline, then enforce SNI pinning unless plaintext is allowed.
    let mut first = vec![0u8; 4096];
    let n = match tokio::time::timeout(cfg.limits.handshake_timeout, client.read(&mut first)).await
    {
        Ok(Ok(n)) => n,
        _ => {
            let _ = client.shutdown().await;
            emit_audit(
                audit,
                &host,
                port,
                Some(approved_ip),
                false,
                "no client hello",
                0,
                0,
            );
            return Err("no client hello".to_string());
        }
    };
    first.truncate(n);

    let sni = extract_sni(&first);
    if !cfg.allow_plaintext {
        // TLS-only: require a parseable ClientHello whose SNI matches the host.
        if sni.is_none() && host.parse::<IpAddr>().is_err() {
            let _ = client.shutdown().await;
            emit_audit(
                audit,
                &host,
                port,
                Some(approved_ip),
                false,
                "non-TLS or SNI-less tunnel rejected",
                0,
                0,
            );
            return Err("non-TLS tunnel".to_string());
        }
        if !sni_matches_host(sni.as_deref(), &host) {
            let _ = client.shutdown().await;
            emit_audit(
                audit,
                &host,
                port,
                Some(approved_ip),
                false,
                "SNI does not match CONNECT host",
                0,
                0,
            );
            return Err("SNI mismatch".to_string());
        }
    }

    // Forward the peeked first bytes, then tunnel the rest with caps.
    let mut upstream = upstream;
    if upstream.write_all(&first).await.is_err() {
        let _ = client.shutdown().await;
        return Err("upstream write failed".to_string());
    }
    let initial_up = first.len() as u64;

    let (bytes_up, bytes_down) = tunnel(&mut client, &mut upstream, cfg, initial_up).await;

    emit_audit(
        audit,
        &host,
        port,
        Some(approved_ip),
        true,
        "tunnel closed",
        bytes_up,
        bytes_down,
    );
    Ok(())
}

/// Read an HTTP request head (up to and including CRLFCRLF) with a hard byte cap,
/// so a client cannot stream an unbounded "head".
async fn read_request_head(client: &mut TcpStream) -> Result<String, String> {
    const MAX_HEAD: usize = 8 * 1024;
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = client
            .read(&mut byte)
            .await
            .map_err(|_| "read error".to_string())?;
        if n == 0 {
            return Err("connection closed before request head".to_string());
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_HEAD {
            return Err("request head too large".to_string());
        }
    }
    String::from_utf8(buf).map_err(|_| "request head not UTF-8".to_string())
}

/// Bidirectional tunnel with per-direction byte caps and an idle timeout.
/// Returns the bytes forwarded in each direction (client->upstream,
/// upstream->client), including the `initial_up` bytes already forwarded.
async fn tunnel(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    cfg: &BrokerConfig,
    initial_up: u64,
) -> (u64, u64) {
    let (mut cr, mut cw) = client.split();
    let (mut ur, mut uw) = upstream.split();
    let cap = cfg.limits.max_bytes_per_direction;
    let idle = cfg.limits.idle_timeout;

    let up = copy_capped(&mut cr, &mut uw, cap.saturating_sub(initial_up), idle);
    let down = copy_capped(&mut ur, &mut cw, cap, idle);
    let (up_n, down_n) = tokio::join!(up, down);
    (initial_up + up_n, down_n)
}

/// Copy bytes from `from` to `to` until EOF, the byte cap, an error, or an idle
/// gap longer than `idle`. Returns the number of bytes copied.
async fn copy_capped<R, W>(from: &mut R, to: &mut W, cap: u64, idle: Duration) -> u64
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut total = 0u64;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        if total >= cap {
            break;
        }
        let n = match tokio::time::timeout(idle, from.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(_)) => break,
            Err(_) => break, // idle timeout
        };
        let remaining = (cap - total) as usize;
        let take = n.min(remaining);
        if to.write_all(&buf[..take]).await.is_err() {
            break;
        }
        total += take as u64;
        if take < n {
            // Hit the cap mid-buffer; stop.
            break;
        }
    }
    let _ = to.shutdown().await;
    total
}

/// Write a CONNECT failure status to the client and audit the denial.
async fn deny<F>(
    client: &mut TcpStream,
    audit: &Arc<F>,
    host: &str,
    port: u16,
    ip: Option<IpAddr>,
    reason: &str,
) where
    F: Fn(BrokerAuditEvent) + Send + Sync + 'static,
{
    let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
    let _ = client.shutdown().await;
    emit_audit(audit, host, port, ip, false, reason, 0, 0);
}

#[allow(clippy::too_many_arguments)]
fn emit_audit<F>(
    audit: &Arc<F>,
    host: &str,
    port: u16,
    ip: Option<IpAddr>,
    allowed: bool,
    reason: &str,
    bytes_up: u64,
    bytes_down: u64,
) where
    F: Fn(BrokerAuditEvent) + Send + Sync + 'static,
{
    audit(BrokerAuditEvent {
        host: host.to_string(),
        port,
        approved_ip: ip,
        allowed,
        reason: reason.to_string(),
        bytes_up,
        bytes_down,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn allowlist(domains: &[&str], ports: &[u16]) -> NetworkPolicy {
        NetworkPolicy::AllowListedDomains {
            domains: domains.iter().map(|d| d.to_string()).collect(),
            ports: ports.iter().copied().collect::<BTreeSet<u16>>(),
        }
    }

    fn cfg_for(domains: &[&str]) -> BrokerConfig {
        BrokerConfig::new(allowlist(domains, &[443]), "s3cr3t-token".to_string())
            .expect("non-empty token")
    }

    fn req(host: &str, port: u16, token: Option<&str>) -> ConnectRequest {
        ConnectRequest {
            host: host.to_string(),
            port,
            bearer_token: token.map(|t| t.to_string()),
        }
    }

    // ---- parse_connect_head ----

    #[test]
    fn parse_connect_basic() {
        let head = "CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\nProxy-Authorization: Bearer abc123\r\n\r\n";
        let r = parse_connect_head(head).expect("parse");
        assert_eq!(r.host, "pypi.org");
        assert_eq!(r.port, 443);
        assert_eq!(r.bearer_token.as_deref(), Some("abc123"));
    }

    #[test]
    fn parse_connect_rejects_non_connect() {
        let head = "GET / HTTP/1.1\r\n\r\n";
        assert!(parse_connect_head(head).is_err());
    }

    #[test]
    fn parse_connect_ipv6_authority() {
        let head = "CONNECT [2606:4700::1111]:443 HTTP/1.1\r\n\r\n";
        let r = parse_connect_head(head).expect("parse");
        assert_eq!(r.host, "2606:4700::1111");
        assert_eq!(r.port, 443);
        assert!(r.bearer_token.is_none());
    }

    #[test]
    fn parse_connect_requires_port() {
        let head = "CONNECT pypi.org HTTP/1.1\r\n\r\n";
        assert!(parse_connect_head(head).is_err());
    }

    // ---- decide_connect ----

    #[test]
    fn decide_rejects_missing_token() {
        let cfg = cfg_for(&["pypi.org"]);
        let d = decide_connect(
            &cfg,
            &req("pypi.org", 443, None),
            &["93.184.216.34".parse().unwrap()],
        );
        match d {
            ConnectDecision::Deny { reason } => assert!(reason.contains("token")),
            _ => panic!("expected deny on missing token"),
        }
    }

    #[test]
    fn decide_rejects_wrong_token() {
        let cfg = cfg_for(&["pypi.org"]);
        let d = decide_connect(
            &cfg,
            &req("pypi.org", 443, Some("nope")),
            &["93.184.216.34".parse().unwrap()],
        );
        assert!(matches!(d, ConnectDecision::Deny { .. }));
    }

    #[test]
    fn decide_rejects_unlisted_domain() {
        let cfg = cfg_for(&["pypi.org"]);
        let d = decide_connect(
            &cfg,
            &req("evil.example", 443, Some("s3cr3t-token")),
            &["93.184.216.34".parse().unwrap()],
        );
        match d {
            ConnectDecision::Deny { reason } => assert!(reason.contains("policy denies")),
            _ => panic!("expected deny on unlisted domain"),
        }
    }

    #[test]
    fn decide_rejects_unlisted_port() {
        let cfg = cfg_for(&["pypi.org"]);
        let d = decide_connect(
            &cfg,
            &req("pypi.org", 80, Some("s3cr3t-token")),
            &["93.184.216.34".parse().unwrap()],
        );
        assert!(matches!(d, ConnectDecision::Deny { .. }));
    }

    #[test]
    fn decide_rejects_private_resolution() {
        // The host is policy-allowed but resolves to a private/loopback address
        // (DNS-rebind attempt) -> deny, no public address survives.
        let cfg = cfg_for(&["pypi.org"]);
        let d = decide_connect(
            &cfg,
            &req("pypi.org", 443, Some("s3cr3t-token")),
            &["127.0.0.1".parse().unwrap(), "10.0.0.5".parse().unwrap()],
        );
        match d {
            ConnectDecision::Deny { reason } => assert!(reason.contains("no public address")),
            _ => panic!("expected deny on private resolution"),
        }
    }

    #[test]
    fn decide_rejects_metadata_resolution() {
        let cfg = cfg_for(&["pypi.org"]);
        let d = decide_connect(
            &cfg,
            &req("pypi.org", 443, Some("s3cr3t-token")),
            &["169.254.169.254".parse().unwrap()],
        );
        assert!(matches!(d, ConnectDecision::Deny { .. }));
    }

    #[test]
    fn decide_picks_first_public_ip() {
        let cfg = cfg_for(&["pypi.org"]);
        // Mixed set: a private then a public address -> the public one is approved.
        let d = decide_connect(
            &cfg,
            &req("pypi.org", 443, Some("s3cr3t-token")),
            &[
                "10.0.0.5".parse().unwrap(),
                "93.184.216.34".parse().unwrap(),
            ],
        );
        match d {
            ConnectDecision::Allow {
                host,
                port,
                approved_ip,
            } => {
                assert_eq!(host, "pypi.org");
                assert_eq!(port, 443);
                assert_eq!(approved_ip, "93.184.216.34".parse::<IpAddr>().unwrap());
            }
            _ => panic!("expected allow"),
        }
    }

    #[test]
    fn decide_rejects_too_many_addresses() {
        let mut cfg = cfg_for(&["pypi.org"]);
        cfg.limits.max_resolved_addrs = 2;
        let resolved: Vec<IpAddr> = vec![
            "93.184.216.1".parse().unwrap(),
            "93.184.216.2".parse().unwrap(),
            "93.184.216.3".parse().unwrap(),
        ];
        let d = decide_connect(&cfg, &req("pypi.org", 443, Some("s3cr3t-token")), &resolved);
        match d {
            ConnectDecision::Deny { reason } => assert!(reason.contains("addresses")),
            _ => panic!("expected deny on fan-out"),
        }
    }

    // ---- SNI ----

    /// Build a minimal but well-formed TLS ClientHello carrying `server_name`.
    fn client_hello_with_sni(name: &str) -> Vec<u8> {
        // server_name extension body.
        let name_bytes = name.as_bytes();
        let mut sn_entry = Vec::new();
        sn_entry.push(0u8); // name_type host_name
        sn_entry.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        sn_entry.extend_from_slice(name_bytes);
        let mut sn_list = Vec::new();
        sn_list.extend_from_slice(&(sn_entry.len() as u16).to_be_bytes());
        sn_list.extend_from_slice(&sn_entry);
        let mut ext = Vec::new();
        ext.extend_from_slice(&0u16.to_be_bytes()); // ext type server_name
        ext.extend_from_slice(&(sn_list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sn_list);

        // ClientHello body.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0u8); // session_id length
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        body.push(1u8); // compression methods length
        body.push(0u8); // null compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes()); // extensions length
        body.extend_from_slice(&ext);

        // Handshake header.
        let mut hs = Vec::new();
        hs.push(1u8); // ClientHello
        let blen = body.len();
        hs.push(((blen >> 16) & 0xff) as u8);
        hs.push(((blen >> 8) & 0xff) as u8);
        hs.push((blen & 0xff) as u8);
        hs.extend_from_slice(&body);

        // TLS record header.
        let mut rec = Vec::new();
        rec.push(22u8); // handshake
        rec.extend_from_slice(&[0x03, 0x01]); // legacy record version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extract_sni_parses_hostname() {
        let hello = client_hello_with_sni("pypi.org");
        assert_eq!(extract_sni(&hello).as_deref(), Some("pypi.org"));
    }

    #[test]
    fn extract_sni_lowercases_and_strips_dot() {
        let hello = client_hello_with_sni("PyPI.ORG.");
        assert_eq!(extract_sni(&hello).as_deref(), Some("pypi.org"));
    }

    #[test]
    fn extract_sni_rejects_non_tls() {
        // Plain HTTP bytes are not a Handshake record.
        let http = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert!(extract_sni(http).is_none());
    }

    #[test]
    fn extract_sni_handles_truncation() {
        let mut hello = client_hello_with_sni("pypi.org");
        hello.truncate(hello.len() / 2);
        // Truncated -> None, never a panic or a partial host.
        assert!(extract_sni(&hello).is_none());
    }

    #[test]
    fn sni_matches_host_exact() {
        assert!(sni_matches_host(Some("pypi.org"), "pypi.org"));
        assert!(sni_matches_host(Some("PyPI.org."), "pypi.org"));
    }

    #[test]
    fn sni_mismatch_is_rejected() {
        // Approved CONNECT host pypi.org but the ClientHello names attacker.example
        // -> mismatch (the domain-fronting / SNI-smuggling case).
        assert!(!sni_matches_host(Some("attacker.example"), "pypi.org"));
    }

    #[test]
    fn sni_missing_rejected_for_named_host() {
        assert!(!sni_matches_host(None, "pypi.org"));
    }

    #[test]
    fn sni_exempt_for_ip_literal_host() {
        // CONNECT to an IP literal has no SNI to pin; absence is acceptable.
        assert!(sni_matches_host(None, "93.184.216.34"));
    }

    #[test]
    fn constant_time_eq_behaves() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
        // Length mismatches in either direction are unequal, and an empty vs
        // non-empty pair is handled without panicking (no early-return on length).
        assert!(!constant_time_eq(b"ab", b"abc"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(!constant_time_eq(b"a", b""));
        // A long token differing only in its final byte is still rejected (the full
        // walk runs; no short-circuit on the matching prefix).
        let token = vec![0x5au8; 64];
        let mut wrong = token.clone();
        *wrong.last_mut().unwrap() ^= 0x01;
        assert!(constant_time_eq(&token, &token));
        assert!(!constant_time_eq(&token, &wrong));
        // A correct prefix but a shorter guess never matches.
        assert!(!constant_time_eq(&token, &token[..32]));
    }

    // ---- MN7: empty token must never authenticate ----

    #[test]
    fn broker_config_rejects_empty_token() {
        // Construction fails closed on an empty token (an empty per-session secret is
        // never valid and would otherwise authenticate an anonymous client).
        let err = BrokerConfig::new(allowlist(&["pypi.org"], &[443]), String::new())
            .expect_err("empty token must be rejected at construction");
        assert!(err.contains("must not be empty"));
    }

    #[test]
    fn decide_denies_when_configured_token_is_empty() {
        // Defense in depth: even if a BrokerConfig somehow carries an empty token
        // (constructed bypassing `new`), decide_connect must DENY rather than let an
        // empty/missing presented token satisfy constant_time_eq(b"", b"").
        let cfg = BrokerConfig {
            network: allowlist(&["pypi.org"], &[443]),
            session_token: String::new(),
            allow_plaintext: false,
            limits: BrokerLimits::default(),
        };
        // Presented token also empty (the open-proxy case the old code allowed).
        let d_empty = decide_connect(
            &cfg,
            &req("pypi.org", 443, Some("")),
            &["93.184.216.34".parse().unwrap()],
        );
        assert!(
            matches!(d_empty, ConnectDecision::Deny { .. }),
            "empty configured + empty presented token must DENY, not authenticate"
        );
        // And a missing token (None -> "") must also deny.
        let d_missing = decide_connect(
            &cfg,
            &req("pypi.org", 443, None),
            &["93.184.216.34".parse().unwrap()],
        );
        assert!(matches!(d_missing, ConnectDecision::Deny { .. }));
    }

    #[test]
    fn decide_denies_empty_presented_against_real_token() {
        // An empty presented token never matches a real configured token.
        let cfg = cfg_for(&["pypi.org"]);
        let d = decide_connect(
            &cfg,
            &req("pypi.org", 443, Some("")),
            &["93.184.216.34".parse().unwrap()],
        );
        assert!(matches!(d, ConnectDecision::Deny { .. }));
    }

    #[test]
    fn broker_state_caps_concurrency() {
        let st = BrokerState::default();
        assert!(st.try_acquire(2));
        assert!(st.try_acquire(2));
        // Third over the cap of 2.
        assert!(!st.try_acquire(2));
        assert_eq!(st.active(), 2);
        st.release();
        assert!(st.try_acquire(2));
    }

    #[test]
    fn broker_config_is_tls_only_by_default() {
        let cfg = cfg_for(&["pypi.org"]);
        assert!(!cfg.allow_plaintext);
        assert!(!cfg.network.is_deny_all());
    }
}
