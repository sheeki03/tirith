//! Strict loopback HTTP/1.1 transport for the local control service. One request
//! per connection, explicit lengths, fixed bounds, and an overall read deadline.
//! This is deliberately not a proxy or a general-purpose web server.
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub(super) const MAX_BODY: usize = 16 * 1024;
const MAX_HEADERS: usize = 8 * 1024;
const READ_DEADLINE: Duration = Duration::from_secs(3);

pub(super) struct Request {
    pub method: String,
    pub target: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

#[derive(Debug)]
pub(super) struct Error {
    pub status: u16,
    pub message: &'static str,
}

fn error(status: u16, message: &'static str) -> Error {
    Error { status, message }
}

fn remaining(start: Instant) -> Result<Duration, Error> {
    READ_DEADLINE
        .checked_sub(start.elapsed())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| error(408, "request deadline exceeded"))
}

pub(super) fn read(
    stream: &mut TcpStream,
    authorize: impl Fn(&Request) -> Result<(), Error>,
) -> Result<Request, Error> {
    let start = Instant::now();
    let mut headers = Vec::with_capacity(1024);
    loop {
        if headers.len() >= MAX_HEADERS {
            return Err(error(431, "request headers exceed limit"));
        }
        stream
            .set_read_timeout(Some(remaining(start)?))
            .map_err(|_| error(400, "cannot configure request deadline"))?;
        let mut byte = [0];
        stream
            .read_exact(&mut byte)
            .map_err(|_| error(408, "request was incomplete or exceeded its deadline"))?;
        headers.push(byte[0]);
        if headers.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let (mut request, length) = parse_headers(&headers)?;
    // Reject unauthenticated writes before waiting for or allocating their body.
    authorize(&request)?;
    request.body.resize(length, 0);
    let mut consumed = 0;
    while consumed < length {
        stream
            .set_read_timeout(Some(remaining(start)?))
            .map_err(|_| error(400, "cannot configure request deadline"))?;
        let read = stream
            .read(&mut request.body[consumed..])
            .map_err(|_| error(408, "request body exceeded its deadline"))?;
        if read == 0 {
            return Err(error(400, "request body is incomplete"));
        }
        consumed += read;
    }
    authorize(&request)?;
    Ok(request)
}

fn parse_headers(bytes: &[u8]) -> Result<(Request, usize), Error> {
    if bytes.len() > MAX_HEADERS || !bytes.ends_with(b"\r\n\r\n") {
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
    if !matches!(method, "GET" | "POST") {
        return Err(error(405, "only GET and POST are supported"));
    }
    if first.next() != Some("HTTP/1.1")
        || first.next().is_some()
        || !target.starts_with('/')
        || target.starts_with("//")
        || target.len() > 2048
        || target.contains(['#', '\r', '\n', '\\'])
    {
        return Err(error(400, "invalid request target or HTTP version"));
    }
    let mut headers = BTreeMap::new();
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
        if headers
            .insert(name.to_ascii_lowercase(), value.trim().to_string())
            .is_some()
        {
            return Err(error(400, "duplicate headers are not supported"));
        }
    }
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
    Ok((
        Request {
            method: method.into(),
            target: target.into(),
            headers,
            body: Vec::new(),
        },
        length,
    ))
}

pub(super) struct Authorization {
    pub host: String,
    pub origin: String,
    pub token: String,
    pub csrf: String,
    pub issued: Instant,
    pub lifetime: Duration,
}

impl Authorization {
    pub fn check_host(&self, request: &Request) -> Result<(), Error> {
        if request.header("host") != Some(self.host.as_str()) {
            return Err(error(403, "host does not match this service"));
        }
        Ok(())
    }

    pub fn check(&self, request: &Request) -> Result<(), Error> {
        self.check_host(request)?;
        if self.issued.elapsed() >= self.lifetime {
            return Err(error(401, "session expired; reopen the dashboard"));
        }
        if request
            .header("origin")
            .is_some_and(|origin| origin != self.origin)
            || request
                .header("sec-fetch-site")
                .is_some_and(|site| !matches!(site, "same-origin" | "none"))
        {
            return Err(error(403, "request origin is not this service"));
        }
        let bearer = request
            .header("authorization")
            .and_then(|value| value.strip_prefix("Bearer "));
        if !bearer.is_some_and(|value| {
            super::super::dashboard::constant_time_eq(value.as_bytes(), self.token.as_bytes())
        }) {
            return Err(error(401, "dashboard authorization is required"));
        }
        if request.method == "POST" {
            if request.header("origin") != Some(self.origin.as_str()) {
                return Err(error(403, "writes require the exact service origin"));
            }
            if !request.header("x-tirith-csrf").is_some_and(|value| {
                super::super::dashboard::constant_time_eq(value.as_bytes(), self.csrf.as_bytes())
            }) {
                return Err(error(403, "write authorization is missing or stale"));
            }
        }
        Ok(())
    }
}

pub(super) fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    bytes: &[u8],
) -> std::io::Result<()> {
    if bytes.len() > 512 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "control response exceeds limit",
        ));
    }
    let started = Instant::now();
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
    let headers = format!("HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCross-Origin-Resource-Policy: same-origin\r\nCross-Origin-Opener-Policy: same-origin\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'\r\n\r\n", bytes.len());
    for mut remaining_bytes in [headers.as_bytes(), bytes] {
        while !remaining_bytes.is_empty() {
            let remaining = Duration::from_secs(3)
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
    fn get(headers: &str) -> Request {
        parse_headers(format!("GET /api/state HTTP/1.1\r\n{headers}\r\n\r\n").as_bytes())
            .unwrap()
            .0
    }
    fn auth() -> Authorization {
        Authorization {
            host: "127.0.0.1:1234".into(),
            origin: "http://127.0.0.1:1234".into(),
            token: "fixture-token".into(),
            csrf: "fixture-csrf".into(),
            issued: Instant::now(),
            lifetime: Duration::from_secs(60),
        }
    }

    #[test]
    fn host_origin_bearer_and_expiry_are_all_required() {
        let auth = auth();
        let valid = get("Host: 127.0.0.1:1234\r\nAuthorization: Bearer fixture-token");
        assert!(auth.check(&valid).is_ok());
        for headers in ["Host: evil.example\r\nAuthorization: Bearer fixture-token", "Host: 127.0.0.1:9999\r\nAuthorization: Bearer fixture-token",
            "Host: 127.0.0.1:1234", "Host: 127.0.0.1:1234\r\nAuthorization: Bearer bad",
            "Host: 127.0.0.1:1234\r\nAuthorization: Bearer fixture-token\r\nOrigin: http://evil.example",
            "Host: 127.0.0.1:1234\r\nAuthorization: Bearer fixture-token\r\nSec-Fetch-Site: cross-site"] {
            assert!(auth.check(&get(headers)).is_err());
        }
        let expired = Authorization {
            lifetime: Duration::ZERO,
            ..auth
        };
        assert_eq!(expired.check(&valid).unwrap_err().status, 401);
    }

    #[test]
    fn mutations_need_both_exact_origin_and_csrf() {
        let auth = auth();
        let mut request = get("Host: 127.0.0.1:1234\r\nAuthorization: Bearer fixture-token");
        request.method = "POST".into();
        assert_eq!(auth.check(&request).unwrap_err().status, 403);
        request.headers.insert("origin".into(), auth.origin.clone());
        assert_eq!(auth.check(&request).unwrap_err().status, 403);
        request
            .headers
            .insert("x-tirith-csrf".into(), auth.csrf.clone());
        assert!(auth.check(&request).is_ok());
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
            "GET / HTTP/1.1\r\nHost: one\r\n folded\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 0\r\nContent-Type: text/plain\r\n\r\n",
        ] {
            assert!(
                parse_headers(bytes.as_bytes()).is_err(),
                "accepted {bytes:?}"
            );
        }
    }
}
