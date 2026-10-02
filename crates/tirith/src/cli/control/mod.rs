//! Owner-scoped local controls. The browser supplies typed intent or a stored
//! operation ID; it cannot select a write path, shell command, or policy source.
mod api;
pub(crate) mod http;
pub(crate) mod identity;
mod lifecycle;
mod peer;
pub(crate) use lifecycle::quiesce_for_update;

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use tirith_core::history::HistoryReader;

const IDLE_TTL: Duration = Duration::from_secs(1800);
const MAX_CONNECTIONS: usize = 8;
/// Upper bound for a read to wait on the one startup Runtime resolution. It
/// exceeds the policy client's own connect plus total timeout.
const RUNTIME_PATTERNS_WAIT: Duration = Duration::from_secs(16);

/// DLP patterns seen in full Runtime resolutions (which may contact a remote
/// policy server). Read-only endpoints never resolve Runtime themselves; they
/// redact with these plus a fresh no-network resolution. The set only grows.
#[derive(Default)]
struct RuntimePatterns {
    resolved: bool,
    patterns: Vec<String>,
    /// ThreatDB refresh interval from the latest full Runtime resolution.
    refresh_interval_hours: Option<u64>,
}

struct Service {
    record: lifecycle::ServiceRecord,
    auth: http::Authorization,
    history: HistoryReader,
    last_activity: Mutex<Instant>,
    runtime_patterns: Mutex<RuntimePatterns>,
    runtime_resolved: Condvar,
    admission: Mutex<()>,
    quiescing: AtomicBool,
    connections: AtomicUsize,
    directory_identity: identity::DirectoryIdentity,
    binary_identity: identity::BinaryIdentity,
    project_anchor: tirith_core::util::ContainedAtomicFile,
    project_anchor_path: std::path::PathBuf,
}

impl Service {
    fn revalidate_project(&self) -> Result<(), String> {
        let root = std::path::Path::new(&self.record.cwd);
        if self
            .project_anchor
            .matches_visible(root, &self.project_anchor_path)
            .unwrap_or(false)
        {
            Ok(())
        } else {
            Err("The service project directory changed; reopen the dashboard.".into())
        }
    }

    /// The one authorization decision for a request: static assets need the
    /// exact Host, the sign-in exchange its same-origin write checks, and every
    /// other route a credential whose grant is handed to the API.
    fn authorize(&self, request: &http::Request) -> Result<Option<http::Grant>, http::Error> {
        if request.method == "GET"
            && matches!(request.target.as_str(), "/" | "/app.js" | "/app.css")
        {
            self.auth.check_host(request).map(|()| None)
        } else if request.target == EXCHANGE {
            self.auth.check_exchange(request).map(|()| None)
        } else {
            self.auth.check(request).map(Some)
        }
    }

    /// Record what read-only routes need from a full Runtime resolution.
    fn observe_runtime(
        &self,
        snapshot: &tirith_core::policy_snapshot::EffectivePolicySnapshot,
        patterns: &[String],
    ) {
        if let Ok(mut runtime) = self.runtime_patterns.lock() {
            for pattern in patterns
                .iter()
                .chain(snapshot.policy.dlp_custom_patterns.iter())
            {
                if !runtime.patterns.contains(pattern) {
                    runtime.patterns.push(pattern.clone());
                }
            }
            runtime.refresh_interval_hours = Some(snapshot.policy.threat_intel.auto_update_hours);
            runtime.resolved = true;
        }
        self.runtime_resolved.notify_all();
    }

    /// Runtime DLP patterns and ThreatDB interval for a read-only response,
    /// after the startup resolution finished (or its bounded wait passed).
    fn runtime_view(&self) -> (Vec<String>, Option<u64>) {
        let Ok(guard) = self.runtime_patterns.lock() else {
            return (Vec::new(), None);
        };
        match self
            .runtime_resolved
            .wait_timeout_while(guard, RUNTIME_PATTERNS_WAIT, |runtime| !runtime.resolved)
        {
            Ok((mut runtime, _)) => {
                // Wait at most once: later reads use whatever is known.
                runtime.resolved = true;
                (runtime.patterns.clone(), runtime.refresh_interval_hours)
            }
            Err(_) => (Vec::new(), None),
        }
    }

    /// Exchange a single-use launch code for a new browser session.
    fn exchange(&self, request: &http::Request) -> (u16, serde_json::Value) {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Exchange {
            code: String,
        }
        let Ok(body) = serde_json::from_slice::<Exchange>(&request.body) else {
            return (
                400,
                serde_json::json!({"error": "request does not match the endpoint schema"}),
            );
        };
        if self.quiescing.load(Ordering::Acquire) {
            return (
                503,
                serde_json::json!({"error": "the local service is closing; run tirith dashboard again"}),
            );
        }
        let token = lifecycle::secret();
        match self.auth.exchange(
            &body.code,
            token.clone(),
            lifecycle::secret(),
            Instant::now(),
        ) {
            Ok(grant) => (
                200,
                serde_json::json!({"schema_version": 1, "kind": "dashboard_session",
                "token": token, "csrf": grant.csrf,
                "expires_in_seconds": grant.expires_in.as_secs(),
                "service_id": self.record.service_id, "version": self.record.version}),
            ),
            Err(error) => (error.status, serde_json::json!({"error": error.message})),
        }
    }

    fn handle(&self, mut stream: TcpStream) {
        let result = http::read(&mut stream, http::Rules::Control, |request| {
            self.authorize(request)
        });
        let (request, grant) = match result {
            Ok(read) => read,
            Err(error) => {
                let _ = http::respond(
                    &mut stream,
                    error.status,
                    "text/plain; charset=utf-8",
                    error.message.as_bytes(),
                );
                return;
            }
        };
        let asset = match (request.method.as_str(), request.target.as_str()) {
            ("GET", "/") => Some((
                "text/html; charset=utf-8",
                include_bytes!("assets/index.html").as_slice(),
            )),
            ("GET", "/app.js") => Some((
                "text/javascript; charset=utf-8",
                include_bytes!("assets/app.js").as_slice(),
            )),
            ("GET", "/app.css") => Some((
                "text/css; charset=utf-8",
                include_bytes!("assets/app.css").as_slice(),
            )),
            _ => None,
        };
        if let Some((content_type, bytes)) = asset {
            let _ = http::respond(&mut stream, 200, content_type, bytes);
            return;
        }
        if let Ok(mut activity) = self.last_activity.lock() {
            *activity = Instant::now();
        }
        let (status, result) = match grant {
            Some(grant) => api::dispatch(self, &request, &grant),
            None if request.method == "POST" && request.target == EXCHANGE => {
                self.exchange(&request)
            }
            None => (
                404,
                serde_json::json!({"error": "unknown local control endpoint"}),
            ),
        };
        let bytes = serde_json::to_vec(&result)
            .unwrap_or_else(|_| b"{\"error\":\"response encoding failed\"}".to_vec());
        if bytes.len() > http::MAX_RESPONSE {
            let _ = http::respond(
                &mut stream,
                413,
                "application/json",
                b"{\"error\":\"response exceeds limit; narrow the query\"}",
            );
        } else {
            let _ = http::respond(&mut stream, status, "application/json", &bytes);
        }
    }
}

const EXCHANGE: &str = "/api/session/exchange";

/// A service identity is public routing context, never a bearer credential.
pub(crate) fn parse_required_service_id(value: &str) -> Result<String, String> {
    if !tirith_core::util::is_uuid(value) || value == uuid::Uuid::nil().to_string() {
        return Err("required service identity must be a canonical non-nil UUID".into());
    }
    Ok(value.to_string())
}

pub(crate) fn open(no_browser: bool, json: bool, required_service_id: Option<&str>) -> i32 {
    match lifecycle::launch(required_service_id).and_then(|record| {
        // The URL carries only a fresh single-use code, never the service
        // credential: browser launchers expose their arguments to other users.
        let url = lifecycle::sign_in_url(&record)?;
        Ok((record, url))
    }) {
        Ok((record, url)) => {
            let browser_opened = !no_browser && lifecycle::open_browser(&url).is_ok();
            if json {
                if !super::write_json_stdout(
                    &serde_json::json!({"schema_version": 1,
                    "kind": "dashboard_launch", "url": url, "browser_opened": browser_opened,
                    "service_id": record.service_id, "version": record.version,
                    "authorization": "private_fragment", "single_use_code": true,
                    "code_expires_in_seconds": http::CODE_TTL.as_secs(),
                    "protection_changed": false}),
                    "tirith dashboard: failed to write launch result",
                ) {
                    return 1;
                }
            } else {
                println!("Tirith dashboard: {url}");
                if !browser_opened && !no_browser {
                    eprintln!("The browser did not open; use the local URL above.");
                }
                if !browser_opened {
                    eprintln!(
                        "The link signs in once and expires in {} minutes; run tirith dashboard again for a new one.",
                        http::CODE_TTL.as_secs() / 60
                    );
                }
            }
            0
        }
        Err(error) => {
            eprintln!(
                "tirith dashboard: {}",
                tirith_core::output::sanitize_human_field(&error, &[])
            );
            1
        }
    }
}

/// Invoked only as a child of the launcher. Startup identity is not a secret;
/// credentials are generated here and written through the private boundary.
pub(crate) fn serve(startup_id: &str) -> i32 {
    let result = (|| -> Result<(), String> {
        if !tirith_core::util::is_uuid(startup_id) {
            return Err("invalid startup identity".into());
        }
        lifecycle::require_unprivileged()?;
        let paths = lifecycle::Paths::current()?;
        paths.prepare()?;
        let directory_identity = paths.identity()?;
        let _service_lock =
            super::setup::fs_helpers::try_lock_operation(&paths.service_lock, &paths.scope)?
                .ok_or("a local control service is already running")?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .map_err(|_| "cannot bind local dashboard")?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "cannot configure local listener")?;
        let port = listener
            .local_addr()
            .map_err(|_| "cannot read local listener address")?
            .port();
        let binary_identity = identity::BinaryIdentity::capture_current()?;
        let record = lifecycle::ServiceRecord::new(startup_id, port, &binary_identity)?;
        let project_root = std::path::Path::new(&record.cwd);
        // The retained-directory witness must not depend on a project file.
        // This unique logical leaf is never created, read, or published.
        let project_anchor_path =
            project_root.join(format!(".tirith-control-anchor-{}", uuid::Uuid::new_v4()));
        let project_anchor = tirith_core::util::ContainedAtomicFile::prepare(
            project_root,
            &project_anchor_path,
            false,
        )
        .map_err(|_| "cannot retain the dashboard project directory")?;
        let history_path =
            tirith_core::audit::audit_log_path().ok_or("audit log location unavailable")?;
        let service = Arc::new(Service {
            auth: http::Authorization::new(
                port,
                record.token.clone(),
                lifecycle::secret(),
                Instant::now(),
            ),
            history: HistoryReader::new(history_path),
            last_activity: Mutex::new(Instant::now()),
            runtime_patterns: Mutex::new(RuntimePatterns::default()),
            runtime_resolved: Condvar::new(),
            admission: Mutex::new(()),
            quiescing: AtomicBool::new(false),
            connections: AtomicUsize::new(0),
            record,
            directory_identity,
            binary_identity,
            project_anchor,
            project_anchor_path,
        });
        {
            // One full Runtime resolution (it may contact a remote policy
            // server) off the accept loop, so reads redact with its patterns.
            let worker = Arc::clone(&service);
            let spawned = std::thread::Builder::new()
                .name("tirith-control-policy".into())
                .spawn(move || {
                    let _capture = tirith_core::policy::PolicyDiagnosticCapture::start_silent();
                    let snapshot = tirith_core::policy_snapshot::EffectivePolicySnapshot::resolve(
                        Some(&worker.record.cwd),
                        tirith_core::policy_snapshot::ResolutionMode::Runtime,
                    );
                    let patterns = tirith_core::policy::captured_policy_dlp_patterns_or(
                        &snapshot.policy.dlp_custom_patterns,
                    );
                    worker.observe_runtime(&snapshot, &patterns);
                });
            if spawned.is_err() {
                return Err("cannot start the dashboard policy reader".into());
            }
        }
        paths.publish(&service.record, &service.directory_identity)?;
        let mut last_identity_check = Instant::now();
        loop {
            let idle = service
                .last_activity
                .lock()
                .map(|last| last.elapsed() >= IDLE_TTL)
                .unwrap_or(true);
            let expired = service.auth.expired(Instant::now());
            // Writes revalidate identity synchronously at admission. Idle
            // detection need not stat/hash the process and ancestors ten
            // times per second while the dashboard is untouched.
            if last_identity_check.elapsed() >= Duration::from_secs(5) {
                if service.binary_identity.revalidate().is_err()
                    || service.directory_identity.revalidate().is_err()
                    || service.revalidate_project().is_err()
                {
                    service.quiescing.store(true, Ordering::Release);
                }
                last_identity_check = Instant::now();
            }
            if idle || expired {
                service.quiescing.store(true, Ordering::Release);
            }
            if service.quiescing.load(Ordering::Acquire)
                && super::setup::change_plan::active_job_count() == 0
                && service.connections.load(Ordering::Acquire) == 0
            {
                break;
            }
            match listener.accept() {
                Ok((stream, peer)) => {
                    // Another account's process is refused before it can take
                    // a connection slot, where the platform can tell.
                    if !peer.ip().is_loopback() || !peer::same_user(&stream) {
                        continue;
                    }
                    if service
                        .connections
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                            (count < MAX_CONNECTIONS).then_some(count + 1)
                        })
                        .is_err()
                    {
                        // Closing immediately bounds overload work and socket lifetime.
                        drop(stream);
                        continue;
                    }
                    let service = Arc::clone(&service);
                    let worker = Arc::clone(&service);
                    if std::thread::Builder::new()
                        .name("tirith-control".into())
                        .spawn(move || {
                            struct Permit(Arc<Service>);
                            impl Drop for Permit {
                                fn drop(&mut self) {
                                    self.0.connections.fetch_sub(1, Ordering::AcqRel);
                                }
                            }
                            let permit = Permit(worker);
                            permit.0.handle(stream);
                        })
                        .is_err()
                    {
                        service.connections.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100))
                }
                Err(_) => return Err("local dashboard listener failed".into()),
            }
        }
        // Leave a private, probeable stale record. A later launcher holds the
        // launch lock and replaces it only after obtaining a new service lock.
        Ok(())
    })();
    if result.is_ok() {
        0
    } else {
        1
    }
}
