//! Actual child service and loopback transport, with private disposable roots.
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::process::Command;
use std::time::Duration;
use tirith_test_support::GlobalStateGuard;

struct Service {
    port: u16,
    token: String,
    csrf: String,
}

impl Service {
    fn raw(&self, request: &str) -> String {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(40)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }
    fn request(&self, method: &str, path: &str, body: Option<Value>) -> (u16, Value) {
        let content = body.map(|value| value.to_string()).unwrap_or_default();
        let response = self.raw(&format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nOrigin: http://127.0.0.1:{}\r\nX-Tirith-CSRF: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", self.port,self.token,self.port,self.csrf,content.len(),content));
        let status = response.split_whitespace().nth(1).unwrap().parse().unwrap();
        let body = response.split_once("\r\n\r\n").unwrap().1;
        (
            status,
            serde_json::from_str(body).unwrap_or_else(|_| json!({"text":body})),
        )
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        // Best effort shutdown must not panic while another assertion unwinds.
        if let Ok(mut stream) = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port)) {
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let request = format!("POST /api/quiesce HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nOrigin: http://127.0.0.1:{}\r\nX-Tirith-CSRF: {}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}", self.port,self.token,self.port,self.csrf);
            let _ = stream.write_all(request.as_bytes());
        }
    }
}

fn launch(state: &GlobalStateGuard) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirith"));
    state.apply_to_command(&mut command);
    let output = command
        .current_dir(&state.roots().cwd)
        .args(["dashboard", "--no-browser", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

/// The single-use code from a launch URL.
fn launch_code(launch: &Value) -> (u16, String) {
    let url = url::Url::parse(launch["url"].as_str().unwrap()).unwrap();
    let code = url
        .fragment()
        .and_then(|fragment| fragment.strip_prefix("code="))
        .unwrap_or_else(|| panic!("launch URL must carry a sign-in code: {url}"));
    (url.port().unwrap(), code.into())
}

/// Sign in the way the page does: exchange the code once, same origin.
fn exchange(port: u16, code: &str, origin: Option<&str>) -> (u16, Value) {
    let body = json!({ "code": code }).to_string();
    let origin = origin
        .map(|origin| format!("Origin: {origin}\r\n"))
        .unwrap_or_default();
    let probe = Service {
        port,
        token: String::new(),
        csrf: String::new(),
    };
    let response = probe.raw(&format!("POST /api/session/exchange HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{origin}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()));
    std::mem::forget(probe);
    let status = response.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = response.split_once("\r\n\r\n").unwrap().1;
    (
        status,
        serde_json::from_str(body).unwrap_or_else(|_| json!({"text":body})),
    )
}

fn service(state: &GlobalStateGuard) -> (Service, Value) {
    let launch = launch(state);
    let (port, code) = launch_code(&launch);
    let (status, session) = exchange(port, &code, Some(&format!("http://127.0.0.1:{port}")));
    assert_eq!(status, 200, "{session}");
    let service = Service {
        port,
        token: session["token"].as_str().unwrap().into(),
        csrf: session["csrf"].as_str().unwrap().into(),
    };
    let (status, current) = service.request("GET", "/api/session", None);
    assert_eq!(status, 200);
    assert_eq!(current["csrf"], session["csrf"]);
    (service, launch)
}

/// The private-record service credential (owner-only file), as the CLI uses it.
fn service_credential(state: &GlobalStateGuard) -> Service {
    launch(state);
    let path = tirith_core::policy::state_dir()
        .unwrap()
        .join("control/v1/service.json");
    let record: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut service = Service {
        port: record["port"].as_u64().unwrap() as u16,
        token: record["token"].as_str().unwrap().into(),
        csrf: String::new(),
    };
    let (status, session) = service.request("GET", "/api/session", None);
    assert_eq!(status, 200, "{session}");
    service.csrf = session["csrf"].as_str().unwrap().into();
    service
}

fn state() -> GlobalStateGuard {
    let mut state = GlobalStateGuard::new().unwrap();
    state.remove_env("SUDO_USER");
    state.remove_env("SUDO_UID");
    state.remove_env("TIRITH_POLICY_ROOT");
    state.set_env("TIRITH_OFFLINE", "1");
    state
}

#[test]
fn activity_starts_with_newest_checks_and_pages_older_without_shifting_on_append() {
    let state = state();
    let path = tirith_core::audit::audit_log_path().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let record = |index: usize| {
        format!(
            "{}\n",
            json!({"timestamp":"2026-09-12T00:00:00Z", "action":"Block", "command_redacted":format!("check-{index}")})
        )
    };
    let original = (0..600).map(record).collect::<String>();
    std::fs::write(&path, &original).unwrap();
    let (server, _) = service(&state);
    let (status, newest) = server.request("POST", "/api/history", Some(json!({"limit":100})));
    assert_eq!(status, 200);
    assert_eq!(
        newest["events"][0]["record"]["command_redacted"],
        "check-500"
    );
    assert_eq!(
        newest["events"][99]["record"]["command_redacted"],
        "check-599"
    );
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(record(600).as_bytes())
        .unwrap();
    let (status, older) = server.request(
        "POST",
        "/api/history",
        Some(json!({"cursor":newest["next_cursor"], "limit":100})),
    );
    assert_eq!(status, 200);
    assert_eq!(
        older["events"][0]["record"]["command_redacted"],
        "check-400"
    );
    assert_eq!(
        older["events"][99]["record"]["command_redacted"],
        "check-499"
    );
    let (status, refreshed) = server.request("POST", "/api/history", Some(json!({"limit":100})));
    assert_eq!(status, 200);
    assert_eq!(
        refreshed["events"][99]["record"]["command_redacted"],
        "check-600"
    );
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        format!("{original}{}", record(600))
    );
}

#[test]
fn launch_url_carries_only_a_single_use_code_and_each_reopen_gets_a_fresh_session() {
    let state = state();
    let first = launch(&state);
    let (port, code) = launch_code(&first);
    assert!(code.len() == 64 && code.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(first["single_use_code"], true);
    let record_path = tirith_core::policy::state_dir()
        .unwrap()
        .join("control/v1/service.json");
    let record: Value = serde_json::from_slice(&std::fs::read(record_path).unwrap()).unwrap();
    let service_token = record["token"].as_str().unwrap();
    // The reusable credential never appears in the URL given to a browser launcher.
    assert!(!first["url"].as_str().unwrap().contains(service_token));
    assert_ne!(code, service_token);
    let origin = format!("http://127.0.0.1:{port}");
    // A code is not a bearer credential.
    let as_bearer = Service {
        port,
        token: code.clone(),
        csrf: String::new(),
    };
    assert_eq!(as_bearer.request("GET", "/api/state", None).0, 401);
    std::mem::forget(as_bearer);
    // The exchange is a same-origin write.
    assert_eq!(exchange(port, &code, None).0, 403);
    assert_eq!(
        exchange(port, &code, Some("http://attacker.example")).0,
        403
    );
    let (status, session) = exchange(port, &code, Some(&origin));
    assert_eq!(status, 200, "{session}");
    assert_ne!(session["token"], service_token);
    assert!(session["expires_in_seconds"].as_u64().unwrap() > 3500);
    // Used once.
    assert_eq!(exchange(port, &code, Some(&origin)).0, 401);
    let browser = Service {
        port,
        token: session["token"].as_str().unwrap().into(),
        csrf: session["csrf"].as_str().unwrap().into(),
    };
    assert_eq!(browser.request("GET", "/api/state", None).0, 200);
    // Only the private launcher credential can mint codes.
    assert_eq!(
        browser
            .request("POST", "/api/session/code", Some(json!({})))
            .0,
        403
    );
    // Reopening reuses the service but issues a new code and a new session.
    let second = launch(&state);
    assert_eq!(first["service_id"], second["service_id"]);
    let (_, second_code) = launch_code(&second);
    assert_ne!(code, second_code);
    let (status, reopened) = exchange(port, &second_code, Some(&origin));
    assert_eq!(status, 200, "{reopened}");
    assert_ne!(reopened["token"], session["token"]);
    assert_ne!(reopened["csrf"], session["csrf"]);
    assert!(reopened["expires_in_seconds"].as_u64().unwrap() > 3500);
    assert_eq!(browser.request("GET", "/api/state", None).0, 200);
}

#[test]
fn read_only_routes_never_resolve_the_remote_policy() {
    // Every remote fetch attempt reports itself in the route's diagnostics.
    // A loopback policy server is refused before any connection, so this
    // fixture observes attempts without network access.
    let mut state = state();
    state.set_env("TIRITH_SERVER_URL", "https://127.0.0.1:1");
    state.set_env("TIRITH_API_KEY", "fixture-remote-policy-key");
    let server = service_credential(&state);
    // Routes that nest their own diagnostic capture report it in a
    // route-specific field (`policy_diagnostics` for the tuning review), so
    // look at the whole response.
    let attempted = |value: &Value| value.to_string().contains("remote policy fetch");
    let mut resolved_remote = Vec::new();
    for (method, path, body) in [
        ("GET", "/api/jobs", None),
        ("GET", "/api/state", None),
        ("GET", "/api/integrations", None),
        ("GET", "/api/activity/summary", None),
        ("GET", "/api/freshness", None),
        ("GET", "/api/policy/tuning", None),
        ("GET", "/api/exceptions", None),
        (
            "POST",
            "/api/exceptions/explain",
            Some(json!({"target": "example-cli.dev", "scope": "user"})),
        ),
        ("POST", "/api/history", Some(json!({"limit": 10}))),
        (
            "POST",
            "/api/operations",
            Some(json!({"operation_id": uuid::Uuid::new_v4().to_string(), "action": "status"})),
        ),
    ] {
        let (status, value) = server.request(method, path, body);
        assert!(
            status == 200 || path == "/api/operations",
            "{path}: {value}"
        );
        if attempted(&value) {
            resolved_remote.push(format!("{path}: {value}"));
        }
    }
    assert!(
        resolved_remote.is_empty(),
        "read-only routes resolved the remote policy:\n{}",
        resolved_remote.join("\n")
    );
    // The effective-policy view still resolves Runtime, which also shows the
    // fixture would have seen an attempt.
    let (status, policy) = server.request("GET", "/api/policy", None);
    assert_eq!(status, 200, "{policy}");
    assert!(attempted(&policy), "{policy}");
}

/// With a legacy remote policy server configured, the exception views use
/// the service's latest full Runtime resolution. Once a local input changed
/// (here the user policy), that snapshot no longer revalidates, and every
/// list/explain answered 409 "refresh the list" until something called
/// GET /api/policy. They now resolve again and show the current rows.
#[test]
fn exception_views_follow_local_policy_edits_with_a_legacy_remote_server() {
    let mut state = state();
    state.set_env("TIRITH_SERVER_URL", "https://127.0.0.1:1");
    state.set_env("TIRITH_API_KEY", "fixture-remote-policy-key");
    let server = service_credential(&state);
    let (status, before) = server.request("GET", "/api/exceptions", None);
    assert_eq!(status, 200, "{before}");
    assert!(!before.to_string().contains("example-cli.dev"), "{before}");
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("policy.yaml"),
        "allowlist:\n  - example-cli.dev\n",
    )
    .unwrap();
    for attempt in 0..2 {
        let (status, after) = server.request("GET", "/api/exceptions", None);
        assert_eq!(status, 200, "attempt {attempt}: {after}");
        assert!(
            after.to_string().contains("example-cli.dev"),
            "attempt {attempt}: {after}"
        );
    }
    let (status, explain) = server.request(
        "POST",
        "/api/exceptions/explain",
        Some(json!({"target": "example-cli.dev", "scope": "user"})),
    );
    assert_eq!(status, 200, "{explain}");
}

#[test]
fn real_service_reuses_identity_and_rejects_unauthorized_mutations() {
    let state = state();
    let (server, first) = service(&state);
    let second = launch(&state);
    assert_eq!(first["service_id"], second["service_id"]);
    let asset = server.raw(&format!(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        server.port
    ));
    assert!(asset.starts_with("HTTP/1.1 200"));
    assert!(asset.contains("Content-Security-Policy:"));
    assert!(!asset.contains(&server.token));
    assert!(!asset.contains("unsafe-inline"));
    for request in [
        "GET /api/policy HTTP/1.1\r\nHost: attacker.example\r\n\r\n".to_string(),
        format!("POST /api/plans HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n",server.port),
        format!("POST /api/plans HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nOrigin: http://attacker.example\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n",server.port,server.token),
        format!("POST /api/plans HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 999999999\r\n\r\n",server.port),
    ] { let response = server.raw(&request); assert!(!response.starts_with("HTTP/1.1 200")); assert!(!response.starts_with("HTTP/1.1 408"), "unauthorized/oversized body should be refused before reading it"); }
    assert!(!tirith_core::policy::config_dir()
        .unwrap()
        .join("policy.yaml")
        .exists());
    assert!(!tirith_core::policy::state_dir()
        .unwrap()
        .join("operations")
        .exists());
}

#[test]
fn browser_profile_plan_is_read_only_until_apply_and_retries_keep_identity() {
    let state = state();
    let (server, _) = service(&state);
    let id = uuid::Uuid::new_v4().to_string();
    let request = json!({"kind":"profile","operation_id":id,"profile":"balanced"});
    let (status, plan) = server.request("POST", "/api/plans", Some(request.clone()));
    assert_eq!(status, 200, "{plan}");
    assert_eq!(plan["applied"], false);
    assert_eq!(plan["operation"]["operation_id"], id);
    let path = tirith_core::policy::config_dir()
        .unwrap()
        .join("policy.yaml");
    assert!(!path.exists());
    let (status, retry) = server.request("POST", "/api/plans", Some(request));
    assert_eq!(status, 200, "{retry}");
    assert_eq!(retry["operation"]["operation_id"], id);
    assert_eq!(retry["reused"], true);
    let (status, result) = server.request(
        "POST",
        "/api/operations",
        Some(json!({"operation_id":id,"action":"apply"})),
    );
    assert_eq!(status, 200, "{result}");
    let started = std::time::Instant::now();
    loop {
        let (status, result) = server.request(
            "POST",
            "/api/operations",
            Some(json!({"operation_id":id,"action":"status"})),
        );
        assert_eq!(status, 200, "{result}");
        if result["state"] == "completed" {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "operation did not complete: {result}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let policy: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(
        policy["protection_profile"]["name"].as_str(),
        Some("balanced")
    );
    // The inventory row carries the recovery flag next to the stored state so
    // a reopened dashboard can still label retained recovery material.
    let (status, jobs) = server.request("GET", "/api/jobs", None);
    assert_eq!(status, 200, "{jobs}");
    let row = jobs["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|job| job["operation_id"] == id)
        .cloned()
        .unwrap();
    assert_eq!(row["state"], "completed", "{row}");
    assert_eq!(row["recovery"], cfg!(windows), "{row}");
    let (status, changed_intent) = server.request(
        "POST",
        "/api/plans",
        Some(json!({"kind":"profile","operation_id":id,"profile":"strict"})),
    );
    assert_eq!(status, 409, "{changed_intent}");
}

#[test]
fn no_change_request_remains_immutable_after_policy_drift() {
    let state = state();
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    let path = config.join("policy.yml");
    std::fs::write(&path, "strict_warn: true\n").unwrap();
    let (server, _) = service(&state);
    let id = uuid::Uuid::new_v4().to_string();
    let payload = json!({"kind":"personal_setting","operation_id":id,"change":{"setting":"strict_warn","value":true}});
    let (status, first) = server.request("POST", "/api/plans", Some(payload.clone()));
    assert_eq!(status, 200, "{first}");
    assert_eq!(first["unchanged"], true);
    assert_eq!(first["operation"]["no_op"], true);
    assert_eq!(first["operation"]["operation_id"], id);
    std::fs::write(&path, "strict_warn: false\n").unwrap();
    let (status, retry) = server.request("POST", "/api/plans", Some(payload.clone()));
    assert_eq!(status, 200, "{retry}");
    assert_eq!(retry["operation"]["no_op"], true);
    let (status, applied) = server.request(
        "POST",
        "/api/operations",
        Some(json!({"operation_id":id,"action":"apply"})),
    );
    assert_eq!(status, 200, "{applied}");
    assert_eq!(applied["no_op"], true);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "strict_warn: false\n"
    );
    let mut changed = payload;
    changed["change"]["value"] = false.into();
    assert_eq!(server.request("POST", "/api/plans", Some(changed)).0, 409);
    let (status, jobs) = server.request("GET", "/api/jobs", None);
    assert_eq!(status, 200, "{jobs}");
    assert!(jobs["operations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|job| job["operation_id"] == id));
    assert_eq!(
        server
            .request(
                "POST",
                "/api/settings/preview",
                Some(json!({"setting":"strict_warn"}))
            )
            .0,
        409
    );
}

#[test]
fn trickled_body_hits_overall_deadline_without_saving_a_plan() {
    let state = state();
    let (server, _) = service(&state);
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, server.port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let header=format!("POST /api/plans HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nOrigin: http://127.0.0.1:{}\r\nX-Tirith-CSRF: {}\r\nContent-Type: application/json\r\nContent-Length: 16000\r\n\r\n",server.port,server.token,server.port,server.csrf);
    stream.write_all(header.as_bytes()).unwrap();
    let start = std::time::Instant::now();
    let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let uploader_finished = std::sync::Arc::clone(&finished);
    let mut upload = stream.try_clone().unwrap();
    let uploader = std::thread::spawn(move || {
        let mut sent = 0;
        for _ in 0..10 {
            if uploader_finished.load(std::sync::atomic::Ordering::Acquire)
                || upload.write_all(b" ").is_err()
            {
                break;
            }
            sent += 1;
            std::thread::sleep(Duration::from_millis(400));
        }
        sent
    });
    // Observe the server's response while uploading, as a full-duplex HTTP
    // client does. Further writes after the deadline/close can independently
    // reset the connection and discard queued response bytes on Windows.
    let mut response = String::new();
    let read_result = stream.read_to_string(&mut response);
    finished.store(true, std::sync::atomic::Ordering::Release);
    let sent = uploader.join().expect("join bounded trickle uploader");
    assert!(
        response.starts_with("HTTP/1.1 408"),
        "unexpected deadline response after {sent} body bytes: {response:?}; read: {read_result:?}"
    );
    assert!(start.elapsed() < Duration::from_secs(8));
    let (status, jobs) = server.request("GET", "/api/jobs", None);
    assert_eq!(status, 200, "{jobs}");
    assert!(jobs["operations"].as_array().unwrap().is_empty());
    let config = tirith_core::policy::config_dir().unwrap();
    assert!(!config.join("policy.yaml").exists());
    assert!(!config.join("policy.yml").exists());
}

#[test]
fn explicit_project_review_is_inert_and_revalidates_retained_files() {
    let state = state();
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    let policy = config.join("policy.yaml");
    std::fs::write(&policy, "dlp_custom_patterns:\n  - 'package\\.json'\n").unwrap();
    let path = state.roots().cwd.join("package.json");
    let bytes = br#"{"name":"fixture","scripts":{"install":"touch must-not-exist"}}"#;
    std::fs::write(&path, bytes).unwrap();
    let (server, _) = service(&state);
    let (status, report) = server.request(
        "POST",
        "/api/project/review",
        Some(json!({"paths":["package.json"]})),
    );
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["executed"], false);
    assert_eq!(report["coverage"]["selected_files"], 1);
    assert_eq!(report["changed_files"], 0);
    assert!(!report["files"][0]["path"]
        .as_str()
        .unwrap()
        .contains("package.json"));
    assert!(!state.roots().cwd.join("must-not-exist").exists());
    let replacement = path.with_extension("replacement");
    std::fs::write(&replacement, bytes).unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    std::fs::write(&policy, "{}\n").unwrap();
    let (status, refreshed) = server.request(
        "POST",
        "/api/project/revalidate",
        Some(json!({"report_id":report["report_id"]})),
    );
    assert_eq!(status, 200, "{refreshed}");
    assert_eq!(refreshed["changed_files"], 1);
    assert!(!refreshed["files"][0]["path"]
        .as_str()
        .unwrap()
        .contains("package.json"));
    assert_eq!(
        refreshed["files"][0]["observation_id"],
        report["files"][0]["observation_id"]
    );
    for invalid in [
        json!({"paths":["../outside"]}),
        json!({"paths":[],"root":"/tmp"}),
    ] {
        assert_eq!(
            server
                .request("POST", "/api/project/review", Some(invalid))
                .0,
            409
        );
    }
    let (_, jobs) = server.request("GET", "/api/jobs", None);
    assert!(jobs["operations"].as_array().unwrap().is_empty());
}

#[test]
fn threatdb_refresh_is_a_guarded_write_and_lifecycle_writes_are_gone() {
    let state = state();
    let (server, _) = service(&state);
    // The isolated fixture redirects both ThreatDB paths, so the guarded
    // refresh must refuse before any network access or database write.
    let (status, refused) = server.request("POST", "/api/threatdb/refresh", Some(json!({})));
    assert_eq!(status, 409, "{refused}");
    assert!(
        refused["error"].as_str().unwrap().contains("redirected"),
        "{refused}"
    );
    assert!(!state.roots().threatdb.exists());
    // The browser cannot request force or any other mode.
    let (status, refused) = server.request(
        "POST",
        "/api/threatdb/refresh",
        Some(json!({"force": true})),
    );
    assert_eq!(status, 409, "{refused}");
    // Same origin and CSRF checks as every other write; both are refused
    // before the body is read, so none is sent.
    let response = server.raw(&format!("POST /api/threatdb/refresh HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nOrigin: http://127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n", server.port, server.token, server.port));
    assert!(!response.starts_with("HTTP/1.1 200"), "{response}");
    let response = server.raw(&format!("POST /api/threatdb/refresh HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nOrigin: http://attacker.example\r\nX-Tirith-CSRF: {}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n", server.port, server.token, server.csrf));
    assert!(!response.starts_with("HTTP/1.1 200"), "{response}");
    // Browser binary update/rollback is removed; the read-only views remain.
    for (path, body) in [
        (
            "/api/lifecycle/prepare",
            json!({"operation_id":uuid::Uuid::new_v4().to_string(),"action":"update"}),
        ),
        (
            "/api/lifecycle/operation",
            json!({"operation_id":uuid::Uuid::new_v4().to_string(),"action":"apply"}),
        ),
    ] {
        let (status, value) = server.request("POST", path, Some(body));
        assert_eq!(status, 409, "{value}");
        assert_eq!(value["error"], "unknown local control endpoint");
    }
    let (status, lifecycle) = server.request("GET", "/api/lifecycle", None);
    assert_eq!(status, 200, "{lifecycle}");
    let (status, freshness) = server.request("GET", "/api/freshness", None);
    assert_eq!(status, 200, "{freshness}");
    assert!(freshness["refresh_interval_hours"].is_u64(), "{freshness}");
    // The Settings view shows copyable commands and one refresh button, and
    // offers no browser update or rollback.
    let asset = server.raw(&format!(
        "GET /app.js HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        server.port
    ));
    assert!(asset.starts_with("HTTP/1.1 200"));
    for present in [
        "Refresh threat DB now",
        "/api/threatdb/refresh",
        "tirith threat-db update",
        "'tirith update'",
        "'tirith update --rollback'",
        "Copy command",
    ] {
        assert!(asset.contains(present), "{present}");
    }
    for absent in [
        "/api/lifecycle/prepare",
        "/api/lifecycle/operation",
        "Check and review update",
        "Review saved rollback",
        "Apply reviewed lifecycle change",
    ] {
        assert!(!asset.contains(absent), "{absent}");
    }
}

#[test]
fn browser_npm_inspection_and_comparison_are_project_scoped_and_inert() {
    let state = state();
    let archive =
        include_bytes!("../../tirith-core/tests/fixtures/npm/npm-11.19.0-portable-pax.tgz");
    std::fs::write(state.roots().cwd.join("package.tgz"), archive).unwrap();
    std::fs::write(state.roots().cwd.join("previous.tgz"), archive).unwrap();
    let (server, _) = service(&state);
    let (status, report) = server.request(
        "POST",
        "/api/artifacts/npm",
        Some(json!({"action":"inspect","path":"package.tgz"})),
    );
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["kind"], "npm_inspection");
    assert_eq!(report["selection"]["executed"], false);
    assert_eq!(
        report["artifacts"][0]["artifact"]["sha256"],
        "769755af559bda513cfe86d6c433bf8e6c0b2431dbb24955393e0dc69eeb2c0f"
    );
    let (status, comparison) = server.request(
        "POST",
        "/api/artifacts/npm",
        Some(json!({"action":"compare","old_path":"previous.tgz","new_path":"package.tgz"})),
    );
    assert_eq!(status, 200, "{comparison}");
    assert_eq!(comparison["kind"], "npm_comparison");
    assert_eq!(comparison["same_artifact"], true);
    assert_eq!(
        comparison["old_artifact"]["sha256"],
        comparison["new_artifact"]["sha256"]
    );
    for query in [
        json!({"action":"inspect","path":"../outside.tgz"}),
        json!({"action":"inspect","path":"/tmp/outside.tgz"}),
        json!({"action":"inspect","path":"package.tgz","root":"/tmp"}),
        json!({"action":"install","path":"package.tgz"}),
    ] {
        assert_eq!(
            server.request("POST", "/api/artifacts/npm", Some(query)).0,
            409
        );
    }
    assert!(!state.roots().cwd.join("node_modules").exists());
    assert!(!state.roots().cwd.join("package-lock.json").exists());
    let (_, jobs) = server.request("GET", "/api/jobs", None);
    assert!(jobs["operations"].as_array().unwrap().is_empty());
}

#[test]
fn real_service_reports_writer_failure_even_when_no_history_record_was_saved() {
    let mut state = state();
    state.set_env("TIRITH_LOG", "1");
    let log = tirith_core::audit::audit_log_path().unwrap();
    std::fs::create_dir_all(&log).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirith"));
    state.apply_to_command(&mut command);
    let checked = command
        .current_dir(&state.roots().cwd)
        .args([
            "check",
            "--json",
            "--shell",
            "posix",
            "--no-daemon",
            "--",
            "echo inert",
        ])
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(String::from_utf8_lossy(&checked.stderr).contains("audit append failed"));
    let (server, _) = service(&state);
    for (method, path, body) in [
        ("GET", "/api/state", None),
        ("POST", "/api/history", Some(json!({"limit":10}))),
    ] {
        let (status, report) = server.request(method, path, body);
        assert_eq!(status, 200, "{report}");
        let health = &report["audit_recording"];
        assert_eq!(health["state"], "failure_observed", "{report}");
        assert_eq!(health["source"], "private_failure_notice");
        assert_eq!(health["claims_current_success"], false);
        assert_eq!(health["detects_all_losses"], false);
        assert!(health["detail"]
            .as_str()
            .unwrap()
            .contains("may be incomplete"));
        assert!(!health.to_string().contains("destination_binding"));
        assert!(!health.to_string().contains(&log.display().to_string()));
    }
}
