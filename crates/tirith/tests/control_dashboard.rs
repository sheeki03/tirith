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

fn service(state: &GlobalStateGuard) -> (Service, Value) {
    let launch = launch(state);
    let url = url::Url::parse(launch["url"].as_str().unwrap()).unwrap();
    let mut service = Service {
        port: url.port().unwrap(),
        token: url
            .fragment()
            .unwrap()
            .strip_prefix("token=")
            .unwrap()
            .into(),
        csrf: String::new(),
    };
    let (status, session) = service.request("GET", "/api/session", None);
    assert_eq!(status, 200);
    service.csrf = session["csrf"].as_str().unwrap().into();
    (service, launch)
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
    for _ in 0..10 {
        if stream.write_all(b" ").is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    assert!(
        response.starts_with("HTTP/1.1 408"),
        "unexpected deadline response: {response}"
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
fn failed_lifecycle_apply_retry_returns_saved_state_without_starting_work() {
    let state = state();
    let (server, _) = service(&state);
    let id = uuid::Uuid::new_v4().to_string();
    let (status, prepared) = server.request(
        "POST",
        "/api/lifecycle/prepare",
        Some(json!({"operation_id":id,"action":"rollback"})),
    );
    // This fixture has no saved compatible rollback. Preparation is local and
    // leaves a durable failed request; retrying apply must not start a worker.
    assert_eq!(status, 409, "{prepared}");
    let (status, saved) = server.request(
        "POST",
        "/api/lifecycle/operation",
        Some(json!({"operation_id":id,"action":"status"})),
    );
    assert_eq!(status, 200, "prepared={prepared}; saved={saved}");
    assert_eq!(saved["phase"], "refresh_required");
    let (status, retry) = server.request(
        "POST",
        "/api/lifecycle/operation",
        Some(json!({"operation_id":id,"action":"apply"})),
    );
    assert_eq!(status, 200, "{retry}");
    assert_eq!(retry["phase"], saved["phase"]);
    assert_eq!(retry["published"], false);
    let (status, support) = server.request(
        "POST",
        "/api/support/preview",
        Some(json!({"operation_ids":[id],"incident_ids":[]})),
    );
    assert_eq!(status, 200, "{support}");
    assert_eq!(support["operations"][0]["availability"], "available");
    assert_eq!(
        support["operations"][0]["content"]["operation"]["operation_id"],
        id
    );
    assert_eq!(
        support["operations"][0]["content"]["operation"]["phase"],
        retry["phase"]
    );
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
