//! Connect-time DNS guard — SSRF backstop for DNS rebinding.
//!
//! The URL validators in [`crate::url_validate`] resolve a host and reject
//! non-public destinations *before* a request is dispatched. That check and the
//! socket connect are two separate DNS lookups, so a hostile resolver can
//! answer "public" at validation time and "127.0.0.1" at connect time (classic
//! DNS rebinding), and it does not cover the addresses reqwest picks for each
//! redirect hop.
//!
//! [`SsrfGuardResolver`] closes that gap: installed via
//! `ClientBuilder::dns_resolver`, it is the resolver reqwest actually connects
//! through, so every address that reaches `connect()` — initial request and
//! every redirect hop — is filtered through the same public/non-public
//! classifier the validators use ([`crate::url_validate::is_public_addr`]).
//!
//! Note: tirith-core does not depend on `tokio` directly, so the blocking
//! `to_socket_addrs` lookup runs inline inside the returned future rather than
//! on a `spawn_blocking` worker. reqwest's blocking client drives this resolver
//! on its dedicated internal runtime, where a short synchronous DNS lookup is
//! acceptable (it is the same call the validators already make on the blocking
//! path).

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// reqwest DNS resolver that validates the complete answer set with the same
/// classifier as URL preflight. A fetch resolver snapshots the operator's narrow
/// host/CIDR policy; a server resolver accepts globally reachable addresses only.
pub struct SsrfGuardResolver {
    mode: ResolverMode,
    lookup: Arc<LookupFn>,
}

type LookupFn = dyn Fn(&str) -> Result<Vec<SocketAddr>, String> + Send + Sync;

#[derive(Clone)]
enum ResolverMode {
    PublicOnly,
    Fetch(Result<crate::url_validate::PrivateFetchPolicy, String>),
    /// Unit-test-only transport mapping for loopback HTTP fixtures. Adversarial
    /// resolver tests use `PublicOnly` so the real connect-time policy is still
    /// exercised; this variant is absent from every non-test library build.
    #[cfg(test)]
    FixtureUnchecked,
}

impl Resolve for SsrfGuardResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        let mode = self.mode.clone();
        let lookup = Arc::clone(&self.lookup);
        Box::pin(async move {
            let resolved = lookup(&host).map_err(|reason| {
                Box::new(std::io::Error::other(reason)) as Box<dyn std::error::Error + Send + Sync>
            })?;
            let addresses: Vec<std::net::IpAddr> =
                resolved.iter().map(std::net::SocketAddr::ip).collect();
            let decision = validate_answer_set(&mode, &host, &addresses);
            if let Err(reason) = decision {
                let error = std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("ssrf_guard: {reason}"),
                );
                return Err(Box::new(error) as Box<dyn std::error::Error + Send + Sync>);
            }

            Ok(Box::new(resolved.into_iter()) as Addrs)
        })
    }
}

fn validate_answer_set(
    mode: &ResolverMode,
    host: &str,
    addresses: &[std::net::IpAddr],
) -> Result<(), String> {
    match mode {
        ResolverMode::PublicOnly => {
            crate::url_validate::validate_resolved_destination(host, addresses, None)
        }
        ResolverMode::Fetch(Ok(policy)) => {
            crate::url_validate::validate_resolved_destination(host, addresses, Some(policy))
        }
        ResolverMode::Fetch(Err(reason)) => Err(reason.clone()),
        #[cfg(test)]
        ResolverMode::FixtureUnchecked => Ok(()),
    }
}

/// Strict [`SsrfGuardResolver`] (public destinations only) for server clients,
/// installed via `ClientBuilder::dns_resolver`.
pub fn ssrf_guard_resolver() -> Arc<SsrfGuardResolver> {
    Arc::new(SsrfGuardResolver {
        mode: ResolverMode::PublicOnly,
        lookup: Arc::new(system_lookup),
    })
}

/// Resolver for user fetch paths. It snapshots `TIRITH_PRIVATE_FETCH_ALLOW` and
/// fails every lookup if that policy is invalid. The legacy broad
/// `TIRITH_ALLOW_PRIVATE_FETCH=1` flag grants no access.
pub fn fetch_resolver() -> Arc<SsrfGuardResolver> {
    Arc::new(SsrfGuardResolver {
        mode: ResolverMode::Fetch(crate::url_validate::private_fetch_policy_from_env()),
        lookup: Arc::new(system_lookup),
    })
}

fn system_lookup(host: &str) -> Result<Vec<SocketAddr>, String> {
    // Port 0 is fine: reqwest's connector replaces it with the request port; the
    // guard only needs the IP identities returned by DNS.
    (host, 0u16)
        .to_socket_addrs()
        .map(|addresses| addresses.collect())
        .map_err(|error| error.to_string())
}

/// Per-instance resolver seam for hermetic connect-time rebinding tests. It is
/// unavailable outside tests that explicitly enable `test-network-seams`, so
/// production callers cannot replace system DNS or weaken the policy.
#[cfg(any(test, feature = "test-network-seams"))]
#[doc(hidden)]
pub fn fetch_resolver_with_lookup_for_test<F>(lookup: F) -> Arc<SsrfGuardResolver>
where
    F: Fn(&str) -> Result<Vec<SocketAddr>, String> + Send + Sync + 'static,
{
    Arc::new(SsrfGuardResolver {
        mode: ResolverMode::Fetch(Ok(crate::url_validate::PrivateFetchPolicy::default())),
        lookup: Arc::new(lookup),
    })
}

/// Strict server-resolver seam for hermetic DNS-rebinding tests. Unlike the
/// fixture resolver below, this applies the production public-only policy to
/// the injected connect-time answer.
#[cfg(test)]
#[doc(hidden)]
pub fn ssrf_guard_resolver_with_lookup_for_test<F>(lookup: F) -> Arc<SsrfGuardResolver>
where
    F: Fn(&str) -> Result<Vec<SocketAddr>, String> + Send + Sync + 'static,
{
    Arc::new(SsrfGuardResolver {
        mode: ResolverMode::PublicOnly,
        lookup: Arc::new(lookup),
    })
}

/// Test-only DNS mapping used to connect a public-looking hostname to a local
/// scripted HTTP fixture. It proves request shape, redirect behavior, and proxy
/// bypass without granting production code a private-destination escape hatch.
#[cfg(test)]
#[doc(hidden)]
pub fn fixture_resolver_with_lookup_for_test<F>(lookup: F) -> Arc<SsrfGuardResolver>
where
    F: Fn(&str) -> Result<Vec<SocketAddr>, String> + Send + Sync + 'static,
{
    Arc::new(SsrfGuardResolver {
        mode: ResolverMode::FixtureUnchecked,
        lookup: Arc::new(lookup),
    })
}

fn blocking_client_builder_with_resolver(
    resolver: Arc<SsrfGuardResolver>,
) -> reqwest::blocking::ClientBuilder {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .dns_resolver(resolver)
}

/// Shared production builder for server clients. Keeping proxy disablement and
/// connect-time DNS enforcement in one constructor prevents individual sinks
/// from silently regressing to reqwest's ambient proxy behavior.
pub(crate) fn server_client_builder() -> reqwest::blocking::ClientBuilder {
    blocking_client_builder_with_resolver(ssrf_guard_resolver()).redirect(server_redirect_policy())
}

/// Shared production builder for user-fetch clients. Callers retain their own
/// purpose-specific redirect policy while inheriting no-proxy + guarded DNS.
pub(crate) fn fetch_client_builder() -> reqwest::blocking::ClientBuilder {
    blocking_client_builder_with_resolver(fetch_resolver())
}

#[cfg(test)]
pub(crate) fn server_client_builder_with_resolver_for_test(
    resolver: Arc<SsrfGuardResolver>,
) -> reqwest::blocking::ClientBuilder {
    blocking_client_builder_with_resolver(resolver).redirect(server_redirect_policy())
}

#[cfg(test)]
pub(crate) fn fetch_client_builder_with_resolver_for_test(
    resolver: Arc<SsrfGuardResolver>,
) -> reqwest::blocking::ClientBuilder {
    blocking_client_builder_with_resolver(resolver)
}

/// Maximum redirect hops the server clients will follow before giving up.
/// reqwest's implicit default would silently follow up to 10 hops into
/// anywhere; the server paths cap at 5 and re-validate every hop.
const SERVER_MAX_REDIRECTS: usize = 5;

/// Decide whether a server client should follow one redirect hop.
///
/// This is the testable core of [`server_redirect_policy`], shared by every
/// server client (policy fetch, audit upload, license refresh, webhook
/// delivery). It enforces two things on every hop:
///
/// 1. The hop count stays under [`SERVER_MAX_REDIRECTS`] — `prior_hops` is the
///    number of redirects already followed (reqwest's `attempt.previous().len()`).
/// 2. The redirect target re-passes [`crate::url_validate::validate_server_url`],
///    so an open redirect cannot bounce a request from a public host into a
///    private/loopback/metadata destination.
///
/// Returns `Ok(())` to follow the hop, or `Err(reason)` to abort the request.
pub fn server_redirect_decision(target_url: &str, prior_hops: usize) -> Result<(), String> {
    if prior_hops >= SERVER_MAX_REDIRECTS {
        return Err("too many redirects".to_string());
    }
    crate::url_validate::validate_server_url(target_url)
}

/// Shared redirect policy for the server clients: re-validate every redirect
/// target and cap the hop count. The decision lives in
/// [`server_redirect_decision`] so it can be unit-tested without driving a real
/// HTTP redirect; this just adapts that decision onto reqwest's `Attempt` API.
pub fn server_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        match server_redirect_decision(attempt.url().as_str(), attempt.previous().len()) {
            Ok(()) => attempt.follow(),
            Err(e) => attempt.error(e),
        }
    })
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::ffi::OsString;
    use std::io::{Read as _, Write as _};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    const FIXTURE_DEADLINE: Duration = Duration::from_secs(3);

    pub(crate) struct EnvironmentRestore {
        previous: Vec<(&'static str, Option<OsString>)>,
        _global: tirith_test_support::GlobalStateGuard,
    }

    impl EnvironmentRestore {
        pub(crate) fn new() -> Self {
            Self {
                previous: Vec::new(),
                _global: tirith_test_support::GlobalStateGuard::new()
                    .expect("isolate process-global test state"),
            }
        }

        pub(crate) fn set(&mut self, name: &'static str, value: Option<&str>) {
            self.previous.push((name, std::env::var_os(name)));
            // SAFETY: `_global` owns the shared process-global lock for this
            // wrapper's full lifetime.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }

        pub(crate) fn install_ambient_proxy(&mut self, proxy_url: &str) {
            for name in [
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "http_proxy",
                "https_proxy",
                "all_proxy",
            ] {
                self.set(name, Some(proxy_url));
            }
            self.set("NO_PROXY", Some(""));
            self.set("no_proxy", Some(""));
        }
    }

    impl Drop for EnvironmentRestore {
        fn drop(&mut self) {
            for (name, value) in self.previous.drain(..).rev() {
                // SAFETY: `_global` is still alive while this Drop
                // implementation restores every wrapper-specific value.
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(name, value),
                        None => std::env::remove_var(name),
                    }
                }
            }
        }
    }

    pub(crate) fn http_response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        )
        .into_bytes();
        for (name, value) in headers {
            response.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(body);
        response
    }

    fn request_is_complete(request: &[u8]) -> bool {
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let header_end = header_end + 4;
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        request.len() >= header_end + content_length
    }

    pub(crate) struct ScriptedHttpServer {
        address: SocketAddr,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        stop: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<Result<(), String>>>,
    }

    impl ScriptedHttpServer {
        pub(crate) fn start(responses: Vec<Vec<u8>>) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind HTTP fixture");
            listener
                .set_nonblocking(true)
                .expect("make HTTP fixture nonblocking");
            let address = listener.local_addr().expect("read HTTP fixture address");
            let requests = Arc::new(Mutex::new(Vec::new()));
            let worker_requests = Arc::clone(&requests);
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stop);
            let worker = thread::spawn(move || {
                let deadline = Instant::now() + FIXTURE_DEADLINE;
                let expected = responses.len();
                for response in responses {
                    let mut accepted = None;
                    while !worker_stop.load(Ordering::Acquire) && Instant::now() < deadline {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                accepted = Some(stream);
                                break;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(5));
                            }
                            Err(error) => return Err(format!("accept HTTP fixture: {error}")),
                        }
                    }
                    let Some(mut stream) = accepted else {
                        if worker_stop.load(Ordering::Acquire) {
                            return Ok(());
                        }
                        return Err(format!(
                            "HTTP fixture received fewer than {expected} requests before deadline"
                        ));
                    };
                    // `accept(2)` on BSD/Darwin creates the connected socket
                    // with the listener's properties. The listener must be
                    // nonblocking so the worker can observe `stop`, but request
                    // reads must block until bytes arrive. Otherwise an inherited
                    // `O_NONBLOCK` can yield an immediate `WouldBlock`; the old
                    // fixture then recorded an empty request and sent a success
                    // response, producing false wire-contract failures (and
                    // occasionally malformed redirect exchanges).
                    stream.set_nonblocking(false).map_err(|error| {
                        format!("make accepted HTTP fixture stream blocking: {error}")
                    })?;
                    stream
                        .set_read_timeout(Some(Duration::from_millis(500)))
                        .map_err(|error| format!("set fixture read timeout: {error}"))?;
                    let mut request = Vec::new();
                    loop {
                        let mut chunk = [0u8; 4096];
                        match stream.read(&mut chunk) {
                            Ok(0) => {
                                return Err(format!(
                                    "HTTP fixture peer closed before a complete request (received {} bytes)",
                                    request.len()
                                ))
                            }
                            Ok(read) => {
                                request.extend_from_slice(&chunk[..read]);
                                if request_is_complete(&request) {
                                    break;
                                }
                            }
                            Err(error)
                                if matches!(
                                    error.kind(),
                                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                                ) =>
                            {
                                return Err(format!(
                                    "HTTP fixture timed out before a complete request (received {} bytes)",
                                    request.len()
                                ));
                            }
                            Err(error) => return Err(format!("read HTTP fixture: {error}")),
                        }
                    }
                    worker_requests
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(request);
                    stream
                        .write_all(&response)
                        .map_err(|error| format!("write HTTP fixture: {error}"))?;
                    stream
                        .flush()
                        .map_err(|error| format!("flush HTTP fixture: {error}"))?;
                }
                Ok(())
            });
            Self {
                address,
                requests,
                stop,
                worker: Some(worker),
            }
        }

        pub(crate) fn address(&self) -> SocketAddr {
            self.address
        }

        pub(crate) fn finish(mut self) -> Vec<Vec<u8>> {
            let result = self
                .worker
                .take()
                .expect("HTTP fixture worker")
                .join()
                .expect("join HTTP fixture");
            result.expect("HTTP fixture completed");
            let requests = self
                .requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            requests
        }
    }

    impl Drop for ScriptedHttpServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    pub(crate) struct ProxyTrap {
        address: SocketAddr,
        hit: Arc<AtomicBool>,
        stop: Arc<AtomicBool>,
        worker: Option<thread::JoinHandle<()>>,
    }

    impl ProxyTrap {
        pub(crate) fn start() -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind proxy trap");
            listener
                .set_nonblocking(true)
                .expect("make proxy trap nonblocking");
            let address = listener.local_addr().expect("read proxy trap address");
            let hit = Arc::new(AtomicBool::new(false));
            let worker_hit = Arc::clone(&hit);
            let stop = Arc::new(AtomicBool::new(false));
            let worker_stop = Arc::clone(&stop);
            let worker = thread::spawn(move || {
                let deadline = Instant::now() + FIXTURE_DEADLINE;
                while !worker_stop.load(Ordering::Acquire) && Instant::now() < deadline {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            worker_hit.store(true, Ordering::Release);
                            let _ = stream.write_all(
                                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            );
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                address,
                hit,
                stop,
                worker: Some(worker),
            }
        }

        pub(crate) fn url(&self) -> String {
            format!("http://{}", self.address)
        }

        pub(crate) fn finish(mut self) -> bool {
            self.stop.store(true, Ordering::Release);
            if let Some(worker) = self.worker.take() {
                worker.join().expect("join proxy trap");
            }
            self.hit.load(Ordering::Acquire)
        }
    }

    impl Drop for ProxyTrap {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::url_validate::{is_cloud_metadata_addr, is_public_addr, PrivateFetchPolicy};
    use std::net::{IpAddr, SocketAddr};

    fn sock(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 0)
    }

    fn ips(values: &[&str]) -> Vec<IpAddr> {
        values.iter().map(|value| value.parse().unwrap()).collect()
    }

    #[test]
    fn environment_restore_wrapper_restores_custom_keys_with_shared_guard() {
        const KEY: &str = "TIRITH_SSRF_GUARD_RESTORE_TEST";
        let previous = std::env::var_os(KEY);
        {
            let mut restore = super::test_support::EnvironmentRestore::new();
            restore.set(KEY, Some("temporary-value"));
            assert_eq!(std::env::var(KEY).as_deref(), Ok("temporary-value"));
        }

        // Reacquire the same global lock before observing process state. The
        // shared guard does not manage this wrapper-specific key itself.
        let _verification = tirith_test_support::GlobalStateGuard::new()
            .expect("reacquire process-global test state");
        assert_eq!(std::env::var_os(KEY), previous);
    }

    #[cfg(unix)]
    #[test]
    fn guarded_client_builders_ignore_ambient_proxies_and_keep_direct_routes_working() {
        use super::test_support::{
            http_response, EnvironmentRestore, ProxyTrap, ScriptedHttpServer,
        };
        use std::time::Duration;

        let fixture = ScriptedHttpServer::start(vec![
            http_response("200 OK", &[], b"server-direct"),
            http_response("200 OK", &[], b"fetch-direct"),
        ]);
        let proxy = ProxyTrap::start();
        let mut restore = EnvironmentRestore::new();
        restore.install_ambient_proxy(&proxy.url());

        let address = fixture.address();
        let resolver = super::fixture_resolver_with_lookup_for_test(move |host| {
            if host != "guarded-direct.example.test" {
                return Err(format!("unexpected fixture host: {host}"));
            }
            Ok(vec![address])
        });
        let server_client = super::server_client_builder_with_resolver_for_test(resolver.clone())
            .timeout(Duration::from_secs(1))
            .build()
            .expect("build guarded server client");
        let fetch_client = super::fetch_client_builder_with_resolver_for_test(resolver)
            .timeout(Duration::from_secs(1))
            .build()
            .expect("build guarded fetch client");
        let base = format!(
            "http://guarded-direct.example.test:{}",
            fixture.address().port()
        );

        let server_body = server_client
            .get(format!("{base}/server"))
            .send()
            .expect("server client takes the direct route")
            .text()
            .expect("read server response");
        let fetch_body = fetch_client
            .get(format!("{base}/fetch"))
            .send()
            .expect("fetch client takes the direct route")
            .text()
            .expect("read fetch response");

        assert_eq!(server_body, "server-direct");
        assert_eq!(fetch_body, "fetch-direct");
        assert_eq!(fixture.finish().len(), 2);
        assert!(
            !proxy.finish(),
            "guarded clients must not delegate destination resolution to ambient proxies"
        );
    }

    #[test]
    fn test_guard_filter_rejects_loopback() {
        assert!(!is_public_addr(&sock("127.0.0.1")));
        assert!(!is_public_addr(&sock("::1")));
    }

    #[test]
    fn test_guard_filter_rejects_private() {
        assert!(!is_public_addr(&sock("10.0.0.1")));
        assert!(!is_public_addr(&sock("192.168.0.1")));
        assert!(!is_public_addr(&sock("172.16.0.1")));
    }

    #[test]
    fn test_guard_filter_rejects_link_local_and_metadata() {
        assert!(!is_public_addr(&sock("169.254.1.1")));
        assert!(!is_public_addr(&sock("169.254.169.254")));
        assert!(!is_public_addr(&sock("fe80::1")));
    }

    #[test]
    fn test_guard_filter_accepts_public() {
        assert!(is_public_addr(&sock("93.184.216.34")));
        assert!(is_public_addr(&sock("2607:f8b0:4004:800::200e")));
    }

    #[test]
    fn test_resolver_constructs() {
        let _r = super::ssrf_guard_resolver();
    }

    #[test]
    fn test_strict_resolver_rejects_mixed_public_private_answer_set() {
        let result = super::validate_answer_set(
            &super::ResolverMode::PublicOnly,
            "mixed.example",
            &ips(&["93.184.216.34", "10.0.0.8"]),
        );
        assert!(
            result.is_err(),
            "one private DNS answer must reject the set"
        );
    }

    #[test]
    fn test_fetch_resolver_honors_exact_host_and_cidr_only() {
        let host_policy = PrivateFetchPolicy::parse("registry.internal").unwrap();
        let mode = super::ResolverMode::Fetch(Ok(host_policy));
        assert!(
            super::validate_answer_set(&mode, "registry.internal", &ips(&["10.42.0.8"])).is_ok()
        );
        assert!(
            super::validate_answer_set(&mode, "sibling.internal", &ips(&["10.42.0.8"])).is_err()
        );

        let cidr_policy = PrivateFetchPolicy::parse("10.42.0.0/24").unwrap();
        let mode = super::ResolverMode::Fetch(Ok(cidr_policy));
        assert!(super::validate_answer_set(&mode, "any.internal", &ips(&["10.42.0.8"])).is_ok());
        assert!(super::validate_answer_set(&mode, "any.internal", &ips(&["10.42.1.8"])).is_err());
    }

    #[test]
    fn test_fetch_resolver_rejects_immutable_ranges_even_for_approved_host() {
        let policy = PrivateFetchPolicy::parse("registry.internal").unwrap();
        let mode = super::ResolverMode::Fetch(Ok(policy));
        for address in [
            "169.254.1.1",
            "fe80::1",
            "169.254.170.2",
            "169.254.170.23",
            "168.63.129.16",
            "100.100.100.200",
            "fd00:ec2::254",
            "fd20:ce::254",
            "64:ff9b:1::a9fe:a9fe",
            "fec0::1",
        ] {
            assert!(
                super::validate_answer_set(&mode, "registry.internal", &ips(&[address])).is_err(),
                "{address} must remain denied"
            );
        }
    }

    #[test]
    fn test_fetch_resolver_rejects_public_plus_link_local_for_approved_host() {
        let policy = PrivateFetchPolicy::parse("registry.internal").unwrap();
        let mode = super::ResolverMode::Fetch(Ok(policy));
        let result = super::validate_answer_set(
            &mode,
            "registry.internal",
            &ips(&["93.184.216.34", "169.254.1.1"]),
        );
        assert!(
            result.is_err(),
            "a forbidden answer must reject the whole set"
        );
    }

    #[test]
    fn test_fetch_resolver_invalid_policy_fails_closed() {
        let mode = super::ResolverMode::Fetch(Err("invalid allowlist".to_string()));
        assert!(
            super::validate_answer_set(&mode, "example.com", &ips(&["93.184.216.34"])).is_err()
        );
    }

    #[test]
    fn test_metadata_adapter_matches_expanded_control_plane_set() {
        for address in [
            "169.254.169.254",
            "169.254.170.2",
            "169.254.170.23",
            "169.254.0.23",
            "100.100.100.200",
            "168.63.129.16",
            "fd00:ec2::254",
            "fd20:ce::254",
            "::ffff:168.63.129.16",
            "64:ff9b::169.254.170.2",
        ] {
            assert!(is_cloud_metadata_addr(&sock(address)), "{address}");
        }
    }

    // server_redirect_decision: the testable core of the shared server redirect
    // policy. Pins both the per-hop SSRF re-validation and the hop cap — neither
    // is reachable from the existing tests, which never drive a real redirect.

    #[test]
    fn test_server_redirect_rejects_private_target() {
        // An open redirect bouncing a public request into loopback must be
        // refused even on the first hop (prior_hops = 0).
        let result = super::server_redirect_decision("http://127.0.0.1/x", 0);
        assert!(result.is_err(), "redirect to loopback must be rejected");
    }

    #[test]
    fn test_server_redirect_rejects_over_hop_cap() {
        // A public target is fine on its own, but 5 prior hops trips the cap.
        let result = super::server_redirect_decision("https://8.8.8.8/api", 5);
        assert!(result.is_err(), "hop count at the cap must be rejected");
        assert!(result.unwrap_err().contains("too many redirects"));
    }

    #[test]
    fn test_server_redirect_allows_public_under_cap() {
        // HTTPS public target, hop count under the cap → follow.
        let result = super::server_redirect_decision("https://8.8.8.8/api", 4);
        assert!(
            result.is_ok(),
            "public target under the cap must be followed"
        );
    }
}
