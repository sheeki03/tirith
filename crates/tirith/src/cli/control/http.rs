//! Strict loopback HTTP/1.1 transport for the local control service and the
//! `dashboard serve` report. The control API takes one request per
//! connection; the report may answer a bounded run of pipelined requests in
//! order (see [`read_next`]). Explicit lengths, fixed bounds, and an overall
//! read deadline. This is deliberately not a proxy or a general-purpose web
//! server.
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub(super) const MAX_BODY: usize = 16 * 1024;
pub(super) const MAX_RESPONSE: usize = 512 * 1024;
const MAX_HEADERS: usize = 8 * 1024;
/// Browsers send every cookie set for the loopback host (on any port) to the
/// report page, so its request head may be larger than the control API's.
const REPORT_HEADERS: usize = 64 * 1024;
const READ_DEADLINE: Duration = Duration::from_secs(3);
/// A loopback client sends its request head at once. A connection that is
/// still trickling headers after this bound gives its slot back early, so a
/// few slow clients cannot hold every slot for the whole request deadline.
pub(crate) const HEADER_DEADLINE: Duration = Duration::from_secs(1);
/// One browser session lasts this long from its own sign-in, never from the
/// service start, so reopening late in a service's life gets a full session.
pub(super) const SESSION_TTL: Duration = Duration::from_secs(3600);
/// A launch URL carries only a single-use code that expires quickly.
pub(super) const CODE_TTL: Duration = Duration::from_secs(120);
const MAX_CODES: usize = 4;
const MAX_SESSIONS: usize = 8;

/// Which request shapes a server accepts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rules {
    /// The control API: HTTP/1.1 GET, or POST with a JSON body.
    Control,
    /// The read-only `dashboard serve` report: any method token (RFC 9110
    /// methods are case-sensitive, so `get` is simply another method and gets
    /// the same decision), HTTP/1.0 or 1.1, origin-form or absolute-form
    /// targets (RFC 9112 section 3.2.2; the authority is kept in
    /// [`Request::authority`] for the caller to check), and `OPTIONS *`.
    /// The decision comes from the head alone: a body is never read, bounded
    /// or framed, so its headers (length, streaming, `Expect`) are not checked,
    /// and a repeated header keeps its first value. A request that may carry a
    /// body ends the connection. See [`linger`].
    Report,
}

impl Rules {
    fn head_limit(self) -> usize {
        match self {
            Self::Control => MAX_HEADERS,
            Self::Report => REPORT_HEADERS,
        }
    }
}

/// Response hardening and bounds.
pub(crate) struct ResponsePolicy {
    pub content_security_policy: &'static str,
    pub max_bytes: usize,
    pub deadline: Duration,
    /// The `Allow` value sent with a 405 (RFC 9110 section 15.5.6 requires
    /// one): the methods a client should use on this server.
    pub allow: &'static str,
    /// Send a `Date` header (RFC 9110 section 6.6.1) on every response.
    pub date: bool,
}

pub(super) const CONTROL_RESPONSE: ResponsePolicy = ResponsePolicy {
    content_security_policy: "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    max_bytes: MAX_RESPONSE,
    deadline: Duration::from_secs(3),
    allow: "GET, POST",
    date: false,
};

pub(crate) struct Request {
    pub method: String,
    /// The origin-form target (`/path?query`), also for an absolute-form
    /// request line, or `*` for `OPTIONS *`.
    pub target: String,
    /// The authority of an absolute-form request target
    /// (`GET http://authority/path`), which RFC 9112 makes the request's host.
    pub authority: Option<String>,
    /// The request line said `HTTP/1.0` (only [`Rules::Report`] allows it).
    pub http_1_0: bool,
    /// The head declares or might declare a body: a non-zero or repeated
    /// `Content-Length`, or any `Transfer-Encoding`. Such a body is never
    /// framed under [`Rules::Report`], so its connection cannot carry another
    /// request.
    pub may_have_body: bool,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }

    /// Whether the client asked to keep the connection open (RFC 9112
    /// section 9.3): HTTP/1.1 unless it sent `Connection: close`; HTTP/1.0
    /// only with `Connection: keep-alive`.
    pub fn wants_keep_alive(&self) -> bool {
        let has = |option: &str| {
            self.header("connection").is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case(option))
            })
        };
        if has("close") {
            return false;
        }
        !self.http_1_0 || has("keep-alive")
    }
}

#[derive(Debug)]
pub(crate) struct Error {
    pub status: u16,
    pub message: &'static str,
}

fn error(status: u16, message: &'static str) -> Error {
    Error { status, message }
}

fn remaining_within(start: Instant, deadline: Duration) -> Result<Duration, Error> {
    deadline
        .checked_sub(start.elapsed())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| error(408, "request deadline exceeded"))
}

/// Read one request. `authorize` gates the head before any body is read or
/// allocated, and decides again once the whole request is in; that final
/// decision (for example the credential's grant) is returned with it. Under
/// [`Rules::Report`] only the head is read and decided on.
pub(crate) fn read<T>(
    stream: &mut TcpStream,
    rules: Rules,
    authorize: impl Fn(&Request) -> Result<T, Error>,
) -> Result<(Request, T), Error> {
    read_next(stream, rules, &mut Vec::new(), authorize)
}

/// [`read`] for a connection that may carry more than one request: `carry`
/// holds bytes already received after the previous request's head (a
/// pipelined request) and, under [`Rules::Report`], receives the bytes that
/// follow this head. Each call has its own head deadline.
pub(crate) fn read_next<T>(
    stream: &mut TcpStream,
    rules: Rules,
    carry: &mut Vec<u8>,
    authorize: impl Fn(&Request) -> Result<T, Error>,
) -> Result<(Request, T), Error> {
    #[cfg(windows)]
    {
        // A Windows accepted socket can inherit the nonblocking listener's
        // mode. WouldBlock means wait, not immediate HTTP 408. Conversely,
        // Winsock leaves a blocking connection indeterminate after SO_RCVTIMEO
        // expires, so it cannot reliably carry the required response. Use an
        // absolute application deadline, then restore blocking response writes.
        stream
            .set_read_timeout(None)
            .map_err(|_| error(400, "cannot configure request deadline"))?;
        stream
            .set_nonblocking(true)
            .map_err(|_| error(400, "cannot configure request deadline"))?;
        let result = read_request(stream, rules, carry, authorize);
        stream
            .set_nonblocking(false)
            .map_err(|_| error(400, "cannot restore response socket mode"))?;
        result
    }
    #[cfg(not(windows))]
    {
        // Accepted sockets can inherit the listener's nonblocking mode (for
        // example on macOS). SO_RCVTIMEO only bounds blocking reads; otherwise
        // a temporarily empty receive buffer becomes an immediate HTTP 408.
        stream
            .set_nonblocking(false)
            .map_err(|_| error(400, "cannot configure request deadline"))?;
        read_request(stream, rules, carry, authorize)
    }
}

fn read_before_deadline(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    start: Instant,
    deadline: Duration,
    message: &'static str,
) -> Result<usize, Error> {
    #[cfg(windows)]
    loop {
        let wait = remaining_within(start, deadline)?;
        match stream.read(bytes) {
            Ok(count) => return Ok(count),
            Err(cause) if cause.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(cause) if cause.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(wait.min(Duration::from_millis(5)));
            }
            Err(_) => return Err(error(408, message)),
        }
    }
    #[cfg(not(windows))]
    loop {
        stream
            .set_read_timeout(Some(remaining_within(start, deadline)?))
            .map_err(|_| error(400, "cannot configure request deadline"))?;
        match stream.read(bytes) {
            Ok(count) => return Ok(count),
            Err(cause) if cause.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(error(408, message)),
        }
    }
}

fn read_request<T>(
    stream: &mut TcpStream,
    rules: Rules,
    carry: &mut Vec<u8>,
    authorize: impl Fn(&Request) -> Result<T, Error>,
) -> Result<(Request, T), Error> {
    let start = Instant::now();
    let head_limit = rules.head_limit();
    // Read the head in chunks rather than one byte per system call. Bytes
    // after the blank line already belong to the body (or, for the report,
    // to the next pipelined request).
    let mut buffer = vec![0; head_limit];
    let mut filled = carry.len().min(head_limit);
    buffer[..filled].copy_from_slice(&carry[..filled]);
    carry.clear();
    let head_end = loop {
        if let Some(end) = buffer[..filled]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            break end + 4;
        }
        if filled >= head_limit {
            return Err(error(431, "request headers exceed limit"));
        }
        let read = read_before_deadline(
            stream,
            &mut buffer[filled..],
            start,
            HEADER_DEADLINE,
            "request was incomplete or exceeded its deadline",
        )?;
        if read == 0 {
            return Err(error(
                408,
                "request was incomplete or exceeded its deadline",
            ));
        }
        filled += read;
    };
    let (mut request, length) = parse_headers(&buffer[..head_end], rules)?;
    // Reject unauthenticated writes before waiting for or allocating their body.
    let decision = authorize(&request)?;
    if rules == Rules::Report {
        carry.extend_from_slice(&buffer[head_end..filled]);
        return Ok((request, decision));
    }
    request.body.resize(length, 0);
    // A single request per connection: anything past the declared body is ignored.
    let early = (filled - head_end).min(length);
    request.body[..early].copy_from_slice(&buffer[head_end..head_end + early]);
    let mut consumed = early;
    while consumed < length {
        let read = read_before_deadline(
            stream,
            &mut request.body[consumed..],
            start,
            READ_DEADLINE,
            "request body exceeded its deadline",
        )?;
        if read == 0 {
            return Err(error(400, "request body is incomplete"));
        }
        consumed += read;
    }
    let decision = authorize(&request)?;
    Ok((request, decision))
}

fn parse_headers(bytes: &[u8], rules: Rules) -> Result<(Request, usize), Error> {
    if bytes.len() > rules.head_limit() || !bytes.ends_with(b"\r\n\r\n") {
        return Err(error(400, "invalid request headers"));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| error(400, "request headers must be ASCII"))?;
    if !text
        .bytes()
        .all(|byte| byte.is_ascii_graphic() || matches!(byte, b' ' | b'\r' | b'\n'))
    {
        return Err(error(400, "invalid request header bytes"));
    }
    let mut lines = text[..text.len() - 4].split("\r\n");
    let mut first = lines
        .next()
        .ok_or_else(|| error(400, "missing request line"))?
        .split(' ');
    let method = first.next().unwrap_or("");
    let target = first.next().unwrap_or("");
    let method_supported = match rules {
        Rules::Control => matches!(method, "GET" | "POST"),
        Rules::Report => {
            !method.is_empty() && method.len() <= 16 && method.bytes().all(is_token_byte)
        }
    };
    if !method_supported {
        // The report answers any method token with the report decision, so
        // its 405 names what it refuses, not the control API's method list.
        return Err(match rules {
            Rules::Control => error(405, "only GET and POST are supported"),
            Rules::Report => error(
                405,
                "the method must be a token of 1 to 16 bytes, such as GET or HEAD",
            ),
        });
    }
    let version = first.next();
    let version_supported = match version {
        Some("HTTP/1.1") => true,
        Some("HTTP/1.0") => rules == Rules::Report,
        _ => false,
    };
    let invalid_target = || error(400, "invalid request target or HTTP version");
    if !version_supported
        || first.next().is_some()
        || target.len() > 2048
        || target.contains(['#', '\r', '\n', '\\'])
    {
        return Err(invalid_target());
    }
    // `OPTIONS *` (asterisk-form) is the one target that is not a path.
    let asterisk = rules == Rules::Report && target == "*" && method == "OPTIONS";
    let (target, authority) = match rules {
        Rules::Report if !asterisk => split_absolute_form(target).ok_or_else(invalid_target)?,
        _ => (target.to_string(), None),
    };
    if !asterisk && (!target.starts_with('/') || target.starts_with("//")) {
        return Err(invalid_target());
    }
    let mut headers = BTreeMap::new();
    let mut repeated_length = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| error(400, "malformed header"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value.contains(['\r', '\n'])
        {
            return Err(error(400, "malformed header"));
        }
        let name = name.to_ascii_lowercase();
        if headers.contains_key(&name) {
            if rules == Rules::Report {
                repeated_length |= name == "content-length";
                continue;
            }
            return Err(error(400, "duplicate headers are not supported"));
        }
        headers.insert(name, value.trim().to_string());
    }
    let may_have_body = repeated_length
        || headers.contains_key("transfer-encoding")
        || headers.get("content-length").is_some_and(|value: &String| {
            !value.bytes().all(|byte| byte == b'0') || value.is_empty()
        });
    let request = Request {
        method: method.into(),
        target,
        authority,
        http_1_0: version == Some("HTTP/1.0"),
        may_have_body,
        headers,
        body: Vec::new(),
    };
    if rules == Rules::Report {
        return Ok((request, 0));
    }
    let headers = &request.headers;
    if headers.contains_key("transfer-encoding")
        || headers.contains_key("expect")
        || headers.contains_key("upgrade")
    {
        return Err(error(
            400,
            "streamed bodies, upgrades and expect are not supported",
        ));
    }
    let length = match headers.get("content-length") {
        Some(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            value
                .parse::<usize>()
                .map_err(|_| error(413, "request body exceeds limit"))?
        }
        Some(_) => return Err(error(400, "invalid content length")),
        None if method == "POST" => return Err(error(411, "content length is required")),
        None => 0,
    };
    if length > MAX_BODY {
        return Err(error(413, "request body exceeds limit"));
    }
    if method == "GET" && length != 0 {
        return Err(error(400, "GET cannot carry a body"));
    }
    if method == "POST"
        && !headers.get("content-type").is_some_and(|value| {
            value.eq_ignore_ascii_case("application/json")
                || value.eq_ignore_ascii_case("application/json; charset=utf-8")
        })
    {
        return Err(error(415, "a JSON request body is required"));
    }
    Ok((request, length))
}

/// An RFC 9110 `tchar` (the bytes a method token may use).
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Split an absolute-form target (`http://authority/path?query`, scheme in
/// any case, `http` or `https`) into its origin-form path and authority. An
/// origin-form target passes through unchanged. A missing authority, user
/// info (RFC 9110 section 4.2.4), or another scheme is refused.
fn split_absolute_form(target: &str) -> Option<(String, Option<String>)> {
    if target.starts_with('/') {
        return Some((target.to_string(), None));
    }
    let (scheme, rest) = target.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    // An empty path is `/` (RFC 9112 section 3.2.1), also before a query.
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    Some((path, Some(authority.to_string())))
}

/// How long a report connection stays open after its response to take what
/// the client is still sending.
const LINGER: Duration = Duration::from_millis(500);

/// After a [`Rules::Report`] response: half-close, then discard whatever the
/// client still sends (its unread body) for a short, bounded while, so closing
/// with unread bytes does not reset the connection before the client has read
/// the response. It runs after the response, so it never delays a decision.
pub(crate) fn linger(stream: &mut TcpStream) {
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let started = Instant::now();
    let mut discarded = 0;
    let mut scratch = [0; 4096];
    while discarded < REPORT_HEADERS + MAX_BODY {
        let Some(wait) = LINGER
            .checked_sub(started.elapsed())
            .filter(|wait| !wait.is_zero())
        else {
            return;
        };
        if stream.set_read_timeout(Some(wait)).is_err() {
            return;
        }
        match stream.read(&mut scratch) {
            Ok(0) => return,
            Ok(count) => discarded += count,
            Err(cause) if cause.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// What a valid credential may do. The CSRF value is bound to the credential.
pub(super) struct Grant {
    pub csrf: String,
    pub expires_in: Duration,
    /// The private-record service credential, used only by the local CLI.
    pub service: bool,
}

// Never print the CSRF value.
impl std::fmt::Debug for Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Grant")
            .field("expires_in", &self.expires_in)
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

/// One browser sign-in, created by exchanging a single-use launch code.
struct BrowserSession {
    token: String,
    csrf: String,
    expires: Instant,
}

struct Sessions {
    /// The service stays available until every credential it issued expired.
    deadline: Instant,
    codes: Vec<(String, Instant)>,
    browsers: Vec<BrowserSession>,
}

/// Two kinds of bearer credential:
/// - the service credential lives only in the private (0600) discovery record
///   and is used by the local CLI (probe, sign-in codes, drain before update);
/// - each browser gets its own session through a single-use, short-lived
///   code from the launch URL, so no reusable credential is ever placed in a
///   browser-launch command line.
///
/// Every request still needs the exact Host; writes still need the exact
/// Origin and the CSRF value bound to the same credential.
pub(super) struct Authorization {
    pub host: String,
    pub origin: String,
    token: String,
    csrf: String,
    sessions: std::sync::Mutex<Sessions>,
}

fn secret_eq(left: &str, right: &str) -> bool {
    super::super::dashboard::constant_time_eq(left.as_bytes(), right.as_bytes())
}

impl Authorization {
    pub fn new(port: u16, token: String, csrf: String, now: Instant) -> Self {
        Self {
            host: format!("127.0.0.1:{port}"),
            origin: format!("http://127.0.0.1:{port}"),
            token,
            csrf,
            sessions: std::sync::Mutex::new(Sessions {
                deadline: now + SESSION_TTL,
                codes: Vec::new(),
                browsers: Vec::new(),
            }),
        }
    }

    fn sessions(&self) -> Result<std::sync::MutexGuard<'_, Sessions>, Error> {
        self.sessions
            .lock()
            .map_err(|_| error(503, "dashboard sessions are unavailable"))
    }

    pub fn check_host(&self, request: &Request) -> Result<(), Error> {
        if request.header("host") != Some(self.host.as_str()) {
            return Err(error(403, "host does not match this service"));
        }
        Ok(())
    }

    fn check_site(&self, request: &Request) -> Result<(), Error> {
        if request
            .header("origin")
            .is_some_and(|origin| origin != self.origin)
            || request
                .header("sec-fetch-site")
                .is_some_and(|site| !matches!(site, "same-origin" | "none"))
        {
            return Err(error(403, "request origin is not this service"));
        }
        Ok(())
    }

    pub fn check(&self, request: &Request) -> Result<Grant, Error> {
        self.check_at(request, Instant::now())
    }

    fn check_at(&self, request: &Request, now: Instant) -> Result<Grant, Error> {
        self.check_host(request)?;
        self.check_site(request)?;
        let bearer = request
            .header("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .unwrap_or("");
        let grant = {
            let sessions = self.sessions()?;
            if secret_eq(bearer, &self.token) {
                if now >= sessions.deadline {
                    return Err(error(401, "session expired; reopen the dashboard"));
                }
                Grant {
                    csrf: self.csrf.clone(),
                    expires_in: sessions.deadline - now,
                    service: true,
                }
            } else {
                let mut matched = None;
                // Compare every session; do not stop at the first match.
                for session in &sessions.browsers {
                    if secret_eq(bearer, &session.token) {
                        matched = Some(session);
                    }
                }
                match matched {
                    Some(session) if now < session.expires => Grant {
                        csrf: session.csrf.clone(),
                        expires_in: session.expires - now,
                        service: false,
                    },
                    Some(_) => return Err(error(401, "session expired; reopen the dashboard")),
                    None => return Err(error(401, "dashboard authorization is required")),
                }
            }
        };
        if request.method == "POST" {
            if request.header("origin") != Some(self.origin.as_str()) {
                return Err(error(403, "writes require the exact service origin"));
            }
            if !request
                .header("x-tirith-csrf")
                .is_some_and(|value| secret_eq(value, &grant.csrf))
            {
                return Err(error(403, "write authorization is missing or stale"));
            }
        }
        Ok(grant)
    }

    /// The sign-in exchange has no bearer yet; the code in its body is the
    /// credential. It is still a same-origin write: exact Host and Origin.
    pub fn check_exchange(&self, request: &Request) -> Result<(), Error> {
        self.check_host(request)?;
        self.check_site(request)?;
        if request.method != "POST" || request.header("origin") != Some(self.origin.as_str()) {
            return Err(error(403, "sign-in requires the exact service origin"));
        }
        Ok(())
    }

    /// A fresh single-use code for one launch URL. The service stays up at
    /// least until the code expires.
    pub fn issue_code(&self, code: String, now: Instant) -> Result<Duration, Error> {
        let mut sessions = self.sessions()?;
        sessions.codes.retain(|(_, expires)| now < *expires);
        while sessions.codes.len() >= MAX_CODES {
            sessions.codes.remove(0);
        }
        sessions.codes.push((code, now + CODE_TTL));
        sessions.deadline = sessions.deadline.max(now + CODE_TTL);
        Ok(CODE_TTL)
    }

    /// Exchange a code once for a new browser session. A used, unknown or
    /// expired code is refused; the matched code is removed either way.
    pub fn exchange(
        &self,
        code: &str,
        token: String,
        csrf: String,
        now: Instant,
    ) -> Result<Grant, Error> {
        let mut sessions = self.sessions()?;
        let mut matched = None;
        for (index, (candidate, _)) in sessions.codes.iter().enumerate() {
            // Compare every candidate; do not stop at the first match.
            if secret_eq(code, candidate) {
                matched = Some(index);
            }
        }
        let refused = || {
            error(
                401,
                "this dashboard link was already used or has expired; run tirith dashboard again",
            )
        };
        let index = matched.ok_or_else(refused)?;
        let (_, expires) = sessions.codes.remove(index);
        if now >= expires {
            return Err(refused());
        }
        sessions.browsers.retain(|session| now < session.expires);
        while sessions.browsers.len() >= MAX_SESSIONS {
            sessions.browsers.remove(0);
        }
        let expires = now + SESSION_TTL;
        sessions.browsers.push(BrowserSession {
            token,
            csrf: csrf.clone(),
            expires,
        });
        sessions.deadline = sessions.deadline.max(expires);
        Ok(Grant {
            csrf,
            expires_in: SESSION_TTL,
            service: false,
        })
    }

    /// True once every issued credential has expired.
    pub fn expired(&self, now: Instant) -> bool {
        self.sessions
            .lock()
            .map(|sessions| now >= sessions.deadline)
            .unwrap_or(true)
    }
}

pub(super) fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    bytes: &[u8],
) -> std::io::Result<()> {
    respond_with(stream, status, content_type, &CONTROL_RESPONSE, bytes)
}

/// How a response is framed for the request it answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Framing {
    /// Answer with an `HTTP/1.0` status line (the request was HTTP/1.0).
    pub http_1_0: bool,
    /// A `HEAD` response: the same headers, including `Content-Length`, but
    /// no body (RFC 9110 section 9.3.2).
    pub head: bool,
    /// Keep the connection open for another request instead of announcing
    /// `Connection: close`.
    pub keep_alive: bool,
}

impl Framing {
    /// HTTP/1.1, a body, and `Connection: close`: every control response.
    pub const CLOSE: Self = Self {
        http_1_0: false,
        head: false,
        keep_alive: false,
    };
}

pub(crate) fn respond_with(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    policy: &ResponsePolicy,
    bytes: &[u8],
) -> std::io::Result<()> {
    respond_framed(stream, status, content_type, policy, bytes, Framing::CLOSE)
}

pub(crate) fn respond_framed(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    policy: &ResponsePolicy,
    bytes: &[u8],
    framing: Framing,
) -> std::io::Result<()> {
    if bytes.len() > policy.max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "control response exceeds limit",
        ));
    }
    let started = Instant::now();
    // Some errors are returned before read() normalizes the accepted socket.
    // SO_SNDTIMEO must apply to blocking writes so ordinary backpressure does
    // not truncate a response while its absolute deadline still has time left.
    stream.set_nonblocking(false)?;
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        _ => "Service Unavailable",
    };
    let version = if framing.http_1_0 { "1.0" } else { "1.1" };
    let connection = if framing.keep_alive {
        "keep-alive"
    } else {
        "close"
    };
    let mut headers = format!("HTTP/{version} {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: {connection}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Resource-Policy: same-origin\r\nCross-Origin-Opener-Policy: same-origin\r\nContent-Security-Policy: {}\r\n", bytes.len(), policy.content_security_policy);
    if status == 405 {
        headers.push_str(&format!("Allow: {}\r\n", policy.allow));
    }
    if policy.date {
        // IMF-fixdate (RFC 9110 section 5.6.7); chrono's names are English.
        let now = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT");
        headers.push_str(&format!("Date: {now}\r\n"));
    }
    headers.push_str("\r\n");
    let body = if framing.head { &[][..] } else { bytes };
    for mut remaining_bytes in [headers.as_bytes(), body] {
        while !remaining_bytes.is_empty() {
            let remaining = policy
                .deadline
                .checked_sub(started.elapsed())
                .filter(|value| !value.is_zero())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "control response deadline exceeded",
                    )
                })?;
            stream.set_write_timeout(Some(remaining))?;
            let written = stream.write(&remaining_bytes[..remaining_bytes.len().min(16 * 1024)])?;
            if written == 0 {
                return Err(std::io::ErrorKind::WriteZero.into());
            }
            remaining_bytes = &remaining_bytes[written..];
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(unix, windows))]
    #[test]
    fn receive_deadline_keeps_the_socket_usable_for_http_408() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        // An unfinished head is cut at the header deadline; an unfinished
        // body at the whole-request deadline.
        for (request, initially_nonblocking, minimum, maximum) in [
            ("GET / HTTP/1.1\r\nHost: loopback", true, HEADER_DEADLINE, READ_DEADLINE),
            ("POST /api/plans HTTP/1.1\r\nHost: loopback\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n ", false, READ_DEADLINE, Duration::from_secs(8)),
        ] {
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
            let address = listener.local_addr().unwrap();
            let client = std::thread::spawn(move || {
                let mut stream = TcpStream::connect(address).unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
                stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                stream.write_all(request.as_bytes()).unwrap();
                let mut response = String::new();
                let read_result = stream.read_to_string(&mut response);
                (response, read_result)
            });
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_nonblocking(initially_nonblocking).unwrap();
            let started = Instant::now();
            let result = read(&mut stream, Rules::Control, |_| Ok(()));
            let elapsed = started.elapsed();
            #[cfg(windows)]
            let read_timeout = stream.read_timeout();
            let status = result.as_ref().err().map(|error| error.status);
            let written = respond(&mut stream, status.unwrap_or(500), "text/plain", b"deadline");
            drop(stream);
            let (response, received) = client.join().expect("join bounded deadline client");
            assert_eq!(status, Some(408));
            assert!(elapsed >= minimum && elapsed < maximum, "{elapsed:?}");
            #[cfg(windows)]
            assert_eq!(read_timeout.unwrap(), None, "must not use Winsock SO_RCVTIMEO");
            assert!(written.is_ok(), "deadline response write: {written:?}");
            assert!(received.is_ok(), "deadline response read: {received:?}");
            assert!(response.starts_with("HTTP/1.1 408"), "{response:?}");
            assert!(response.ends_with("deadline"), "{response:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn nonblocking_accepted_socket_sends_the_complete_response_under_backpressure() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        use std::os::fd::AsRawFd;

        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        let accept_deadline = Instant::now() + Duration::from_secs(2);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < accept_deadline =>
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("bounded fixture accept failed: {error}"),
            }
        };
        // Linux does not inherit this flag from the listener; exercise the
        // macOS accepted-socket behavior on every Unix test host.
        stream.set_nonblocking(true).unwrap();
        let send_buffer: libc::c_int = 4096;
        // SAFETY: the socket and pointer remain valid for this call, and the
        // option length matches the initialized integer's size.
        let configured = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&send_buffer as *const libc::c_int).cast(),
                std::mem::size_of_val(&send_buffer) as libc::socklen_t,
            )
        };
        assert_eq!(configured, 0, "{}", std::io::Error::last_os_error());
        let receiver = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            let mut response = Vec::new();
            let result = client.read_to_end(&mut response);
            (response, result)
        });
        let body = vec![b'x'; MAX_RESPONSE];
        let started = Instant::now();
        let written = respond(&mut stream, 200, "application/json", &body);
        let elapsed = started.elapsed();
        drop(stream);
        let (response, received) = receiver.join().expect("join bounded response client");
        assert!(written.is_ok(), "response write: {written:?}");
        assert!(received.is_ok(), "response read: {received:?}");
        assert!(elapsed < Duration::from_secs(8), "{elapsed:?}");
        let header_end = response
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .expect("complete response headers")
            + 4;
        let headers = std::str::from_utf8(&response[..header_end]).unwrap();
        assert!(headers.starts_with(&format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        )));
        assert_eq!(&response[header_end..], body.as_slice());
    }

    // RFC 9110 section 15.5.6: a 405 response MUST carry `Allow`. The control
    // API accepts exactly GET and POST, says so, and (unlike the `dashboard
    // serve` report) does not add a `Date` header.
    #[cfg(any(unix, windows))]
    #[test]
    fn control_405_names_the_allowed_methods_over_a_raw_socket() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(8)))
                .unwrap();
            stream
                .write_all(b"PUT /api/state HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            response
        });
        let (mut stream, _) = listener.accept().unwrap();
        let Err(rejected) = read(&mut stream, Rules::Control, |_| Ok(())) else {
            panic!("PUT must be refused");
        };
        respond(
            &mut stream,
            rejected.status,
            "text/plain",
            rejected.message.as_bytes(),
        )
        .unwrap();
        drop(stream);
        let response = client.join().expect("join 405 client");
        assert!(
            response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
            "{response:?}"
        );
        let head = &response[..response.find("\r\n\r\n").expect("complete head") + 2];
        assert!(head.contains("\r\nAllow: GET, POST\r\n"), "{response:?}");
        assert!(
            !head.to_ascii_lowercase().contains("\r\ndate:"),
            "{response:?}"
        );
        assert!(response.ends_with("only GET and POST are supported"));
    }

    fn get(headers: &str) -> Request {
        parse_headers(
            format!("GET /api/state HTTP/1.1\r\n{headers}\r\n\r\n").as_bytes(),
            Rules::Control,
        )
        .unwrap()
        .0
    }
    fn auth(now: Instant) -> Authorization {
        Authorization::new(1234, "fixture-token".into(), "fixture-csrf".into(), now)
    }
    fn sign_in(auth: &Authorization, now: Instant, token: &str, csrf: &str) -> Grant {
        let code = format!("code-{token}");
        auth.issue_code(code.clone(), now).unwrap();
        auth.exchange(&code, token.into(), csrf.into(), now)
            .unwrap()
    }

    #[test]
    fn host_origin_bearer_and_expiry_are_all_required() {
        let now = Instant::now();
        let auth = auth(now);
        let valid = get("Host: 127.0.0.1:1234\r\nAuthorization: Bearer fixture-token");
        assert!(auth.check_at(&valid, now).unwrap().service);
        for headers in ["Host: evil.example\r\nAuthorization: Bearer fixture-token", "Host: 127.0.0.1:9999\r\nAuthorization: Bearer fixture-token",
            "Host: 127.0.0.1:1234", "Host: 127.0.0.1:1234\r\nAuthorization: Bearer bad",
            "Host: 127.0.0.1:1234\r\nAuthorization: Bearer fixture-token\r\nOrigin: http://evil.example",
            "Host: 127.0.0.1:1234\r\nAuthorization: Bearer fixture-token\r\nSec-Fetch-Site: cross-site"] {
            assert!(auth.check_at(&get(headers), now).is_err());
        }
        assert_eq!(
            auth.check_at(&valid, now + SESSION_TTL).unwrap_err().status,
            401
        );
        assert!(auth.expired(now + SESSION_TTL));
    }

    #[test]
    fn mutations_need_both_exact_origin_and_csrf() {
        let now = Instant::now();
        let auth = auth(now);
        let mut request = get("Host: 127.0.0.1:1234\r\nAuthorization: Bearer fixture-token");
        request.method = "POST".into();
        assert_eq!(auth.check_at(&request, now).unwrap_err().status, 403);
        request.headers.insert("origin".into(), auth.origin.clone());
        assert_eq!(auth.check_at(&request, now).unwrap_err().status, 403);
        request
            .headers
            .insert("x-tirith-csrf".into(), "fixture-csrf".into());
        assert!(auth.check_at(&request, now).is_ok());
    }

    #[test]
    fn launch_codes_are_single_use_short_lived_and_never_a_bearer() {
        let now = Instant::now();
        let auth = auth(now);
        auth.issue_code("one-time".into(), now).unwrap();
        // A code is not a bearer credential.
        let as_bearer = get("Host: 127.0.0.1:1234\r\nAuthorization: Bearer one-time");
        assert_eq!(auth.check_at(&as_bearer, now).unwrap_err().status, 401);
        let grant = auth
            .exchange("one-time", "browser-a".into(), "csrf-a".into(), now)
            .unwrap();
        assert!(!grant.service);
        assert_eq!(grant.csrf, "csrf-a");
        // Used once: a second exchange is refused.
        let replay = auth.exchange("one-time", "browser-b".into(), "csrf-b".into(), now);
        assert_eq!(replay.err().unwrap().status, 401);
        assert!(auth
            .exchange("never-issued", "browser-c".into(), "csrf-c".into(), now)
            .is_err());
        // An expired code is refused and removed.
        auth.issue_code("late".into(), now).unwrap();
        let expired = auth.exchange("late", "browser-d".into(), "csrf-d".into(), now + CODE_TTL);
        assert_eq!(expired.err().unwrap().status, 401);
        let session = get("Host: 127.0.0.1:1234\r\nAuthorization: Bearer browser-a");
        assert!(auth.check_at(&session, now).is_ok());
        let replayed = get("Host: 127.0.0.1:1234\r\nAuthorization: Bearer browser-b");
        assert!(auth.check_at(&replayed, now).is_err());
    }

    #[test]
    fn a_session_opened_late_in_the_service_life_gets_its_full_lifetime() {
        let start = Instant::now();
        let auth = auth(start);
        // Reopen one minute before the first hour would have ended.
        let late = start + SESSION_TTL - Duration::from_secs(60);
        let grant = sign_in(&auth, late, "browser-late", "csrf-late");
        assert_eq!(grant.expires_in, SESSION_TTL);
        let request = get("Host: 127.0.0.1:1234\r\nAuthorization: Bearer browser-late");
        let later = start + SESSION_TTL + Duration::from_secs(1800);
        let checked = auth.check_at(&request, later).unwrap();
        assert_eq!(checked.expires_in, late + SESSION_TTL - later);
        assert!(!auth.expired(later));
        // Each session expires on its own clock.
        assert_eq!(
            auth.check_at(&request, late + SESSION_TTL)
                .unwrap_err()
                .status,
            401
        );
        assert!(auth.expired(late + SESSION_TTL));
    }

    #[test]
    fn each_session_has_its_own_csrf_and_the_cap_evicts_the_oldest() {
        let now = Instant::now();
        let auth = auth(now);
        sign_in(&auth, now, "browser-a", "csrf-a");
        sign_in(&auth, now, "browser-b", "csrf-b");
        let mut write = get("Host: 127.0.0.1:1234\r\nAuthorization: Bearer browser-a");
        write.method = "POST".into();
        write.headers.insert("origin".into(), auth.origin.clone());
        write
            .headers
            .insert("x-tirith-csrf".into(), "csrf-b".into());
        assert_eq!(auth.check_at(&write, now).unwrap_err().status, 403);
        write
            .headers
            .insert("x-tirith-csrf".into(), "fixture-csrf".into());
        assert_eq!(auth.check_at(&write, now).unwrap_err().status, 403);
        write
            .headers
            .insert("x-tirith-csrf".into(), "csrf-a".into());
        assert!(auth.check_at(&write, now).is_ok());
        for index in 0..MAX_SESSIONS {
            sign_in(&auth, now, &format!("extra-{index}"), "csrf");
        }
        let oldest = get("Host: 127.0.0.1:1234\r\nAuthorization: Bearer browser-a");
        assert!(auth.check_at(&oldest, now).is_err());
        let newest = get(&format!(
            "Host: 127.0.0.1:1234\r\nAuthorization: Bearer extra-{}",
            MAX_SESSIONS - 1
        ));
        assert!(auth.check_at(&newest, now).is_ok());
    }

    #[test]
    fn sign_in_exchange_needs_exact_host_and_origin_but_no_bearer() {
        let auth = auth(Instant::now());
        let exchange = |headers: &str| {
            let mut request = parse_headers(
                format!("POST /api/session/exchange HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n{headers}\r\n\r\n")
                    .as_bytes(),
                Rules::Control,
            )
            .unwrap()
            .0;
            request.method = "POST".into();
            auth.check_exchange(&request)
        };
        assert!(exchange("Host: 127.0.0.1:1234\r\nOrigin: http://127.0.0.1:1234").is_ok());
        for headers in [
            "Host: 127.0.0.1:1234",
            "Host: 127.0.0.1:1234\r\nOrigin: http://evil.example",
            "Host: evil.example\r\nOrigin: http://127.0.0.1:1234",
            "Host: 127.0.0.1:1234\r\nOrigin: http://127.0.0.1:1234\r\nSec-Fetch-Site: cross-site",
        ] {
            assert!(exchange(headers).is_err(), "{headers}");
        }
    }

    #[test]
    fn head_and_body_in_one_segment_and_a_head_in_many_segments_both_parse() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        for chunks in [
            vec!["POST /api/plans HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"],
            vec!["POST /api/plans HTTP/1.1\r\nHo", "st: h\r\nContent-Type: application/json\r\nContent-Length: 2\r", "\n\r", "\n{", "}"],
        ] {
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
            let address = listener.local_addr().unwrap();
            let client = std::thread::spawn(move || {
                let mut stream = TcpStream::connect(address).unwrap();
                stream.set_nodelay(true).unwrap();
                for chunk in chunks {
                    stream.write_all(chunk.as_bytes()).unwrap();
                    std::thread::sleep(Duration::from_millis(20));
                }
                stream
            });
            let (mut stream, _) = listener.accept().unwrap();
            let (request, ()) = read(&mut stream, Rules::Control, |_| Ok(())).unwrap();
            drop(client.join().unwrap());
            assert_eq!(request.method, "POST");
            assert_eq!(request.header("host"), Some("h"));
            assert_eq!(request.body, b"{}");
        }
    }

    #[test]
    fn ambiguous_or_unbounded_http_requests_are_refused() {
        for bytes in [
            "GET / HTTP/1.1\r\nHost: one\r\nHost: two\r\n\r\n",
            "GET / HTTP/1.1\r\nHost : one\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 999999\r\nContent-Type: application/json\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n",
            "GET http://evil.example/ HTTP/1.1\r\nHost: one\r\n\r\n",
            "GET * HTTP/1.1\r\nHost: one\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: one\r\n folded\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 0\r\nContent-Type: text/plain\r\n\r\n",
        ] {
            assert!(
                parse_headers(bytes.as_bytes(), Rules::Control).is_err(),
                "{bytes:?}"
            );
            // The report never reads a body, so only a malformed head is
            // refused there; body framing and repeats are not, and an
            // absolute-form target is parsed (its authority is the
            // dashboard's to check).
            let malformed_head = bytes.contains("Host : ")
                || bytes.contains(" folded")
                || bytes.starts_with("GET * ");
            assert_eq!(
                parse_headers(bytes.as_bytes(), Rules::Report).is_err(),
                malformed_head,
                "{bytes:?}"
            );
        }
    }

    // The report decides from the head: a declared body is never waited for,
    // and a repeated header keeps its first value.
    #[test]
    fn the_report_rules_return_after_the_head() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .write_all(b"POST /?token=x HTTP/1.1\r\nHost: first\r\nHost: second\r\nContent-Length: 100\r\n\r\nabc")
                .unwrap();
            stream
        });
        let (mut stream, _) = listener.accept().unwrap();
        let started = Instant::now();
        let (request, ()) = read(&mut stream, Rules::Report, |_| Ok(())).unwrap();
        assert!(
            started.elapsed() < HEADER_DEADLINE,
            "{:?}",
            started.elapsed()
        );
        assert_eq!(request.header("host"), Some("first"));
        assert!(request.body.is_empty());
        drop(client.join().unwrap());
    }

    #[test]
    fn the_report_rules_accept_any_method_and_http_1_0_but_the_control_rules_do_not() {
        for bytes in [
            "HEAD /?token=x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            "GET /?token=x HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n",
            // RFC 9110 methods are case-sensitive: `get` is another method
            // token, which 0.4.2 also answered.
            "get /?token=x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            "M-SEARCH /?token=x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            "GET http://127.0.0.1/?token=x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            "OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            "POST /?token=x HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 3\r\n\r\n",
            "GET /?token=x HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 3\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 999999\r\n\r\n",
        ] {
            assert!(
                parse_headers(bytes.as_bytes(), Rules::Report).is_ok(),
                "{bytes:?}"
            );
            assert!(
                parse_headers(bytes.as_bytes(), Rules::Control).is_err(),
                "{bytes:?}"
            );
        }
        for bytes in [
            "G(T / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            "SEVENTEENCHARSXYZ / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            "GET / HTTP/2\r\nHost: 127.0.0.1\r\n\r\n",
            "GET * HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        ] {
            assert!(
                parse_headers(bytes.as_bytes(), Rules::Report).is_err(),
                "{bytes:?}"
            );
        }
        let cookies = format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: {}\r\n\r\n",
            "a".repeat(16 * 1024)
        );
        assert!(parse_headers(cookies.as_bytes(), Rules::Report).is_ok());
        assert!(parse_headers(cookies.as_bytes(), Rules::Control).is_err());
    }

    fn report(bytes: &str) -> Result<Request, Error> {
        parse_headers(bytes.as_bytes(), Rules::Report).map(|(request, _)| request)
    }

    // RFC 9112 section 3.2.2: an origin server accepts absolute-form. The
    // target becomes origin-form and its authority is kept for the host check.
    #[test]
    fn report_absolute_form_targets_become_origin_form_with_their_authority() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        for (target, path, authority) in [
            ("http://127.0.0.1:9/?token=x", "/?token=x", "127.0.0.1:9"),
            ("HTTP://localhost/a/b", "/a/b", "localhost"),
            ("https://127.0.0.1:9", "/", "127.0.0.1:9"),
            ("http://127.0.0.1:9?token=x", "/?token=x", "127.0.0.1:9"),
            ("http://evil.example/?token=x", "/?token=x", "evil.example"),
        ] {
            let request = report(&format!("GET {target} HTTP/1.1\r\nHost: h\r\n\r\n"))
                .unwrap_or_else(|e| panic!("{target}: {e:?}"));
            assert_eq!(request.target, path, "{target}");
            assert_eq!(request.authority.as_deref(), Some(authority), "{target}");
            assert!(parse_headers(
                format!("GET {target} HTTP/1.1\r\nHost: h\r\n\r\n").as_bytes(),
                Rules::Control
            )
            .is_err());
        }
        let origin = report("GET /?token=x HTTP/1.1\r\nHost: h\r\n\r\n").unwrap();
        assert_eq!(origin.authority, None);
        let options = report("OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n").unwrap();
        assert_eq!((options.target.as_str(), options.authority), ("*", None));
        for target in [
            "http://u@127.0.0.1/",
            "http:///path",
            "ftp://127.0.0.1/",
            "http://127.0.0.1//x",
            "127.0.0.1/",
            "//127.0.0.1/",
        ] {
            assert_eq!(
                report(&format!("GET {target} HTTP/1.1\r\nHost: h\r\n\r\n"))
                    .err()
                    .map(|e| e.status),
                Some(400),
                "{target}"
            );
        }
    }

    #[test]
    fn report_requests_know_their_version_persistence_and_possible_body() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let r = |head: &str| report(&format!("{head}\r\n\r\n")).unwrap();
        let plain = r("GET / HTTP/1.1\r\nHost: h");
        assert!(!plain.http_1_0 && plain.wants_keep_alive() && !plain.may_have_body);
        assert!(!r("GET / HTTP/1.1\r\nConnection: Keep-Alive, CLOSE").wants_keep_alive());
        let old = r("GET / HTTP/1.0\r\nHost: h");
        assert!(old.http_1_0 && !old.wants_keep_alive());
        assert!(r("GET / HTTP/1.0\r\nConnection: keep-alive").wants_keep_alive());
        assert!(!r("GET / HTTP/1.1\r\nContent-Length: 0").may_have_body);
        assert!(!r("GET / HTTP/1.1\r\nContent-Length: 000").may_have_body);
        for head in [
            "POST / HTTP/1.1\r\nContent-Length: 3",
            "POST / HTTP/1.1\r\nContent-Length: x",
            "POST / HTTP/1.1\r\nContent-Length:",
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked",
            "POST / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 5",
        ] {
            assert!(r(head).may_have_body, "{head:?}");
        }
    }

    // Pipelined requests that arrive in one segment are read one after the
    // other: the bytes after a head are carried to the next read.
    #[test]
    fn report_reads_pipelined_requests_in_order_through_the_carry() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            stream
                .write_all(b"GET /one HTTP/1.1\r\nHost: a\r\n\r\nHEAD /two HTTP/1.1\r\nHost: b\r\n\r\nGET /thr")
                .unwrap();
            std::thread::sleep(Duration::from_millis(50));
            stream.write_all(b"ee HTTP/1.1\r\nHost: c\r\n\r\n").unwrap();
            stream
        });
        let (mut stream, _) = listener.accept().unwrap();
        let mut carry = Vec::new();
        let mut seen = Vec::new();
        for _ in 0..3 {
            let (request, ()) =
                read_next(&mut stream, Rules::Report, &mut carry, |_| Ok(())).unwrap();
            seen.push((
                request.method,
                request.target,
                request.headers["host"].clone(),
            ));
        }
        assert_eq!(
            seen,
            [
                ("GET".into(), "/one".into(), "a".into()),
                ("HEAD".into(), "/two".into(), "b".into()),
                ("GET".into(), "/three".into(), "c".into()),
            ]
        );
        assert!(carry.is_empty());
        drop(client.join().unwrap());
    }

    fn framed(framing: Framing) -> Vec<u8> {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let (mut stream, _) = listener.accept().unwrap();
        respond_framed(
            &mut stream,
            200,
            "text/html",
            &CONTROL_RESPONSE,
            b"hello",
            framing,
        )
        .unwrap();
        drop(stream);
        client.join().unwrap()
    }

    #[test]
    fn responses_answer_in_the_request_version_and_head_gets_headers_only() {
        let text = |bytes: Vec<u8>| String::from_utf8(bytes).unwrap();
        let plain = text(framed(Framing::CLOSE));
        assert!(plain.starts_with("HTTP/1.1 200 OK\r\n"), "{plain:?}");
        assert!(plain.contains("\r\nConnection: close\r\n"));
        assert!(plain.ends_with("\r\n\r\nhello"));
        let old = text(framed(Framing {
            http_1_0: true,
            ..Framing::CLOSE
        }));
        assert!(old.starts_with("HTTP/1.0 200 OK\r\n"), "{old:?}");
        let head = text(framed(Framing {
            head: true,
            keep_alive: true,
            ..Framing::CLOSE
        }));
        assert!(head.contains("\r\nContent-Length: 5\r\n"), "{head:?}");
        assert!(head.contains("\r\nConnection: keep-alive\r\n"), "{head:?}");
        assert!(head.ends_with("\r\n\r\n"), "{head:?}");
    }
}
