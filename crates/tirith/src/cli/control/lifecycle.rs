use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::super::setup::fs_helpers;
use serde::{Deserialize, Serialize};

pub(super) const PROTOCOL: u32 = 1;

// Never derive Debug: the record contains a private bearer credential and cwd.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServiceRecord {
    pub protocol: u32,
    pub service_id: String,
    pub startup_id: String,
    pub pid: u32,
    pub port: u16,
    pub version: String,
    pub binary_sha256: String,
    pub cwd: String,
    pub token: String,
    pub created_at: i64,
}

pub(super) fn secret() -> String {
    // Independent random UUIDs provide 244 random bits with the workspace's
    // OS-backed UUID implementation; formatting has no token semantics.
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn cwd() -> Result<String, String> {
    std::env::current_dir()
        .map_err(|_| "cannot resolve dashboard project directory")?
        .into_os_string()
        .into_string()
        .map_err(|_| "dashboard project path must be UTF-8".into())
}

impl ServiceRecord {
    pub fn new(
        startup_id: &str,
        port: u16,
        binary: &super::identity::BinaryIdentity,
    ) -> Result<Self, String> {
        Ok(Self {
            protocol: PROTOCOL,
            service_id: uuid::Uuid::new_v4().to_string(),
            startup_id: startup_id.into(),
            pid: std::process::id(),
            port,
            version: env!("CARGO_PKG_VERSION").into(),
            binary_sha256: binary.sha256().into(),
            cwd: cwd()?,
            token: secret(),
            created_at: chrono::Utc::now().timestamp(),
        })
    }

    pub fn browser_url(&self) -> String {
        format!("http://127.0.0.1:{}/#token={}", self.port, self.token)
    }

    fn validate(&self) -> Result<(), String> {
        if self.port == 0
            || self.token.len() != 64
            || !self.token.bytes().all(|b| b.is_ascii_hexdigit())
            || self.binary_sha256.len() != 64
            || !self.binary_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || uuid::Uuid::parse_str(&self.service_id).is_err()
            || uuid::Uuid::parse_str(&self.startup_id).is_err()
            || !std::path::Path::new(&self.cwd).is_absolute()
        {
            return Err("invalid private service discovery record".into());
        }
        Ok(())
    }
}

pub(super) struct Paths {
    pub scope: PathBuf,
    root: PathBuf,
    record: PathBuf,
    launch_lock: PathBuf,
    pub service_lock: PathBuf,
}

impl Paths {
    pub fn current() -> Result<Self, String> {
        let target = super::super::shell_target::resolve_for_shell("unknown")?;
        super::super::shell_target::require_personal_writer(&target)?;
        let scope =
            tirith_core::policy::state_dir().ok_or("cannot locate private service state")?;
        if !scope.is_absolute()
            || scope
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err("service state must be an absolute path without parent traversal".into());
        }
        let root = scope.join("control/v1");
        Ok(Self {
            record: root.join("service.json"),
            launch_lock: root.join("launch.lock"),
            service_lock: root.join("service.lock"),
            scope,
            root,
        })
    }

    pub fn prepare(&self) -> Result<(), String> {
        fs_helpers::ensure_private_directory(&self.root, &self.scope)
    }

    pub fn identity(&self) -> Result<super::identity::DirectoryIdentity, String> {
        super::identity::DirectoryIdentity::capture(&self.root)
    }

    fn read(&self) -> Result<Option<ServiceRecord>, String> {
        let snapshot = fs_helpers::read_snapshot_scoped(&self.record, &self.scope)?;
        snapshot.require_private()?;
        let Some(bytes) = snapshot.bytes else {
            return Ok(None);
        };
        if bytes.len() > 16 * 1024 {
            return Err("service discovery exceeds limit".into());
        }
        let record: ServiceRecord =
            serde_json::from_slice(&bytes).map_err(|_| "service discovery is malformed")?;
        record.validate()?;
        Ok(Some(record))
    }

    pub fn publish(
        &self,
        record: &ServiceRecord,
        identity: &super::identity::DirectoryIdentity,
    ) -> Result<(), String> {
        let bytes =
            serde_json::to_string(record).map_err(|_| "cannot encode private service record")?;
        identity.revalidate()?;
        fs_helpers::transactional_update_checked(
            &self.record,
            &self.scope,
            false,
            |snapshot| {
                snapshot.require_private()?;
                let update = fs_helpers::FileUpdate::write_text(bytes.clone(), 0o600);
                #[cfg(unix)]
                let update = update.with_exact_mode();
                Ok(update)
            },
            || identity.revalidate(),
        )?;
        Ok(())
    }
}

/// Held by the updater until replacement and post-update verification finish.
/// Launch and lifetime locks close the quiesce-to-replacement race.
pub(crate) struct ServiceUpdateGuard {
    _launch: fs_helpers::PlatformLock,
    _service: fs_helpers::PlatformLock,
    identity: super::identity::DirectoryIdentity,
}

impl ServiceUpdateGuard {
    pub(crate) fn revalidate(&self) -> Result<(), String> {
        self.identity.revalidate()
    }
}

pub(crate) fn quiesce_for_update() -> Result<ServiceUpdateGuard, String> {
    let paths = Paths::current()?;
    paths.prepare()?;
    let identity = paths.identity()?;
    let launch = fs_helpers::try_lock_operation(&paths.launch_lock, &paths.scope)?
        .ok_or("a dashboard launch is in progress; retry update after it completes")?;
    identity.revalidate()?;
    if let Some(service) = fs_helpers::try_lock_operation(&paths.service_lock, &paths.scope)? {
        return Ok(ServiceUpdateGuard {
            _launch: launch,
            _service: service,
            identity,
        });
    }
    let record = paths.read()?.ok_or(
        "a local service holds the lifetime lock without valid discovery; wait for it to close",
    )?;
    if record.protocol != PROTOCOL {
        return Err(
            "the running service uses an unsupported control protocol; close it before updating"
                .into(),
        );
    }
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|_| "cannot initialize local update coordination")?;
    let origin = format!("http://127.0.0.1:{}", record.port);
    let session = client
        .get(format!("{origin}/api/session"))
        .bearer_auth(&record.token)
        .send()
        .map_err(|_| "cannot reach the active service; wait for it to close before updating")?;
    if !session.status().is_success() {
        return Err("service session expired or unavailable; wait for its active jobs to finish before updating".into());
    }
    let mut bytes = Vec::new();
    session
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "service handshake failed")?;
    if bytes.len() > 16 * 1024 {
        return Err("service handshake exceeds limit".into());
    }
    let session: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| "invalid service handshake")?;
    if session["protocol"] != PROTOCOL
        || session["service_id"] != record.service_id
        || session["binary_sha256"] != record.binary_sha256
    {
        return Err("service identity changed; refresh before updating".into());
    }
    let csrf = session["csrf"]
        .as_str()
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("service write authorization is unavailable")?;
    identity.revalidate()?;
    let response = client
        .post(format!("{origin}/api/quiesce"))
        .bearer_auth(&record.token)
        .header("Origin", &origin)
        .header("X-Tirith-CSRF", csrf)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .map_err(|_| "service drain request failed; no binary was replaced")?;
    if !response.status().is_success() {
        return Err("service refused drain; no binary was replaced".into());
    }
    let started = Instant::now();
    loop {
        identity.revalidate()?;
        if let Some(service) = fs_helpers::try_lock_operation(&paths.service_lock, &paths.scope)? {
            return Ok(ServiceUpdateGuard {
                _launch: launch,
                _service: service,
                identity,
            });
        }
        if started.elapsed() >= Duration::from_secs(10) {
            return Err(
                "service is still draining active jobs; retry update after they finish".into(),
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn probe(record: &ServiceRecord) -> Result<bool, String> {
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .build()
        .map_err(|_| "cannot initialize local service client")?;
    let response = match client
        .get(format!("http://127.0.0.1:{}/api/session", record.port))
        .bearer_auth(&record.token)
        .send()
    {
        Ok(response) => response,
        Err(_) => return Ok(false),
    };
    if !response.status().is_success() {
        return Ok(false);
    }
    let mut bytes = Vec::new();
    response
        .take(16 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read local service handshake")?;
    if bytes.len() > 16 * 1024 {
        return Ok(false);
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Ok(false);
    };
    Ok(value["service_id"] == record.service_id
        && value["protocol"] == PROTOCOL
        && value["binary_sha256"] == record.binary_sha256
        && value["quiescing"] == false)
}

pub(super) fn launch() -> Result<ServiceRecord, String> {
    require_unprivileged()?;
    let paths = Paths::current()?;
    paths.prepare()?;
    let directory_identity = paths.identity()?;
    let started = Instant::now();
    let _launch_lock = loop {
        if let Some(lock) = fs_helpers::try_lock_operation(&paths.launch_lock, &paths.scope)? {
            break lock;
        }
        if started.elapsed() > Duration::from_secs(10) {
            return Err("another dashboard launch is still in progress; retry".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let binary_identity = super::identity::BinaryIdentity::capture_current()?;
    let exe = binary_identity.path();
    let digest = binary_identity.sha256();
    let project = cwd()?;
    directory_identity.revalidate()?;
    if let Some(record) = paths.read()? {
        if probe(&record)? {
            if record.protocol != PROTOCOL
                || record.version != env!("CARGO_PKG_VERSION")
                || record.binary_sha256 != digest
            {
                return Err("a different dashboard version is running; close its service from Settings before reopening".into());
            }
            if record.cwd != project {
                return Err("the dashboard is attached to another project; close its service from Settings before opening this project".into());
            }
            directory_identity.revalidate()?;
            binary_identity.revalidate()?;
            return Ok(record);
        }
    }
    // A failed probe does not authorize killing a PID or replacing a live
    // service. Its independent lifetime lock is authoritative.
    let Some(service_lock) = fs_helpers::try_lock_operation(&paths.service_lock, &paths.scope)?
    else {
        return Err(
            "dashboard service is busy, expired, or draining; retry after its active jobs finish"
                .into(),
        );
    };
    drop(service_lock);
    let startup_id = uuid::Uuid::new_v4().to_string();
    directory_identity.revalidate()?;
    binary_identity.revalidate()?;
    let mut command = Command::new(exe);
    command
        .args(["dashboard", "control-serve", "--startup-id", &startup_id])
        .current_dir(&project)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Fixed native detach operation; no shell and no user-supplied program.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000 | 0x00000200); // no window, new process group
    }
    let mut child = command
        .spawn()
        .map_err(|_| "cannot start the local dashboard service")?;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(15) {
        directory_identity.revalidate()?;
        if child
            .try_wait()
            .map_err(|_| "cannot inspect service startup")?
            .is_some()
        {
            return Err("local dashboard service stopped during startup".into());
        }
        if let Some(record) = paths.read()? {
            if record.startup_id == startup_id
                && record.binary_sha256 == digest
                && record.cwd == project
                && probe(&record)?
            {
                directory_identity.revalidate()?;
                binary_identity.revalidate()?;
                return Ok(record);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("dashboard startup timed out; retry to reconnect if startup completes".into())
}

pub(super) fn require_unprivileged() -> Result<(), String> {
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        return Err("open the dashboard as your normal user, without sudo".into());
    }
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(|_| "cannot inspect dashboard token")?;
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0;
        let result = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            )
        };
        let _ = unsafe { CloseHandle(token) };
        result.map_err(|_| "cannot inspect dashboard elevation")?;
        if elevation.TokenIsElevated != 0 {
            return Err("open the dashboard from a normal, non-administrator terminal".into());
        }
    }
    Ok(())
}

pub(super) fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let result = Command::new("/usr/bin/open")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let result = Command::new("xdg-open")
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    #[cfg(unix)]
    return result
        .map(|_| ())
        .map_err(|_| "default browser could not be launched".into());
    #[cfg(windows)]
    {
        use windows::core::PCWSTR;
        use windows::Win32::UI::Shell::ShellExecuteW;
        let operation: Vec<u16> = "open\0".encode_utf16().collect();
        let target: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
        let result = unsafe {
            ShellExecuteW(
                None,
                PCWSTR(operation.as_ptr()),
                PCWSTR(target.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
            )
        };
        if result.0 as usize > 32 {
            Ok(())
        } else {
            Err("default browser could not be launched".into())
        }
    }
}
