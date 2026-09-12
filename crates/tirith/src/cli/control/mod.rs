//! Owner-scoped local controls. The browser supplies typed intent or a stored
//! operation ID; it cannot select a write path, shell command, or policy source.
mod api;
mod http;
pub(crate) mod identity;
mod lifecycle;
pub(crate) mod lifecycle_worker;
pub(crate) use lifecycle::quiesce_for_update;

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tirith_core::history::HistoryReader;

const SESSION_TTL: Duration = Duration::from_secs(3600);
const IDLE_TTL: Duration = Duration::from_secs(1800);
const MAX_CONNECTIONS: usize = 8;

struct Service {
    record: lifecycle::ServiceRecord,
    auth: http::Authorization,
    history: Mutex<HistoryReader>,
    aggregate: Mutex<tirith_core::history_aggregate::HistoryAggregate>,
    last_activity: Mutex<Instant>,
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

    fn authorize(&self, request: &http::Request) -> Result<(), http::Error> {
        if request.method == "GET"
            && matches!(request.target.as_str(), "/" | "/app.js" | "/app.css")
        {
            self.auth.check_host(request)
        } else {
            self.auth.check(request)
        }
    }

    fn handle(&self, mut stream: TcpStream) {
        let result = http::read(&mut stream, |request| self.authorize(request));
        let request = match result {
            Ok(request) => request,
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
        let (status, result) = api::dispatch(self, &request);
        let bytes = serde_json::to_vec(&result)
            .unwrap_or_else(|_| b"{\"error\":\"response encoding failed\"}".to_vec());
        if bytes.len() > 512 * 1024 {
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

pub(crate) fn open(no_browser: bool, json: bool) -> i32 {
    match lifecycle::launch() {
        Ok(record) => {
            let url = record.browser_url();
            let browser_opened = !no_browser && lifecycle::open_browser(&url).is_ok();
            if json {
                if !super::write_json_stdout(
                    &serde_json::json!({"schema_version": 1,
                    "kind": "dashboard_launch", "url": url, "browser_opened": browser_opened,
                    "service_id": record.service_id, "version": record.version,
                    "authorization": "private_fragment", "protection_changed": false}),
                    "tirith dashboard: failed to write launch result",
                ) {
                    return 1;
                }
            } else {
                println!("Tirith dashboard: {url}");
                if !browser_opened && !no_browser {
                    eprintln!("The browser did not open; use the local URL above.");
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
        uuid::Uuid::parse_str(startup_id).map_err(|_| "invalid startup identity")?;
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
            auth: http::Authorization {
                host: format!("127.0.0.1:{port}"),
                origin: format!("http://127.0.0.1:{port}"),
                token: record.token.clone(),
                csrf: lifecycle::secret(),
                issued: Instant::now(),
                lifetime: SESSION_TTL,
            },
            history: Mutex::new(HistoryReader::new(history_path.clone())),
            aggregate: Mutex::new(tirith_core::history_aggregate::HistoryAggregate::new(
                history_path,
            )),
            last_activity: Mutex::new(Instant::now()),
            admission: Mutex::new(()),
            quiescing: AtomicBool::new(false),
            connections: AtomicUsize::new(0),
            record,
            directory_identity,
            binary_identity,
            project_anchor,
            project_anchor_path,
        });
        paths.publish(&service.record, &service.directory_identity)?;
        let mut last_identity_check = Instant::now();
        loop {
            let idle = service
                .last_activity
                .lock()
                .map(|last| last.elapsed() >= IDLE_TTL)
                .unwrap_or(true);
            let expired = service.auth.issued.elapsed() >= SESSION_TTL;
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
                    if !peer.ip().is_loopback() {
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
