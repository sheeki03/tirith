//! Explicit instrumented coordination fixture, never signed-update qualification.
//! Run only as the single ignored test in the owned external fixture process.
use super::*;
use crate::cli::setup::change_plan::{
    active_job_count, Edit, JobState, MutationService, OperationKind, RequestedChange,
    ServiceFixtureWorkerGate,
};
use serde_json::{json, Value};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::mpsc::{self, Receiver};
use std::thread::JoinHandle;
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};

const ROOT_ENV: &str = "TIRITH_TEST_CONTROL_COORDINATION_ROOT";

/// The exact serve invocation is retained, and its completion acknowledgement
/// must arrive before join. A failed fixture never removes its external root.
struct NativeService {
    record: Option<ServiceRecord>,
    done: Receiver<i32>,
    thread: Option<JoinHandle<()>>,
    gate: Option<ServiceFixtureWorkerGate>,
}

impl NativeService {
    fn start(paths: &Paths) -> Self {
        let startup = uuid::Uuid::new_v4().to_string();
        let selected = startup.clone();
        let (finished, done) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let result = super::super::serve(&selected);
            let _ = finished.send(result);
        });
        let mut owner = Self {
            record: None,
            done,
            thread: Some(thread),
            gate: None,
        };
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                !owner.thread.as_ref().unwrap().is_finished(),
                "service exited during startup"
            );
            if let Some(record) = paths.read().unwrap() {
                if record.startup_id == startup {
                    assert_eq!(record.pid, std::process::id());
                    assert_eq!(record.protocol, PROTOCOL);
                    assert_eq!(
                        record.binary_sha256,
                        super::super::identity::BinaryIdentity::capture_current()
                            .unwrap()
                            .sha256()
                    );
                    owner.record = Some(record);
                    return owner;
                }
            }
            assert!(Instant::now() < until, "native service startup deadline");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn request(&self, path: &str, body: Option<Value>) -> Result<(u16, Value), String> {
        let record = self
            .record
            .as_ref()
            .ok_or("no authenticated service record")?;
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .map_err(|e| e.to_string())?;
        let origin = format!("http://127.0.0.1:{}", record.port);
        let request = if let Some(body) = body {
            let (_, session) = self.request("/api/session", None)?;
            let csrf = session["csrf"].as_str().ok_or("missing service CSRF")?;
            client
                .post(format!("{origin}{path}"))
                .header("Origin", &origin)
                .header("X-Tirith-CSRF", csrf)
                .header("Content-Type", "application/json")
                .body(body.to_string())
        } else {
            client.get(format!("{origin}{path}"))
        };
        let response = request
            .bearer_auth(&record.token)
            .send()
            .map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 64 * 1024 {
            return Err("fixture response exceeded cap".into());
        }
        let value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        Ok((status, value))
    }

    fn session(&self) -> Value {
        let (status, value) = self.request("/api/session", None).unwrap();
        assert_eq!(status, 200);
        value
    }

    fn finish(&mut self) -> Result<(), String> {
        drop(self.gate.take()); // RAII release before waiting for the worker/service.
        let Some(thread) = self.thread.as_ref() else {
            return Ok(());
        };
        if !thread.is_finished() && self.record.is_some() {
            // Failure is retained, but still await the actual service result.
            let _ = self.request("/api/quiesce", Some(json!({})));
        }
        let code = self
            .done
            .recv_timeout(Duration::from_secs(15))
            .map_err(|_| "native service completion was not observed before deadline")?;
        self.thread
            .take()
            .unwrap()
            .join()
            .map_err(|_| "native service thread panicked")?;
        if code != 0 {
            return Err("native service returned failure".into());
        }
        Ok(())
    }
}

impl Drop for NativeService {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            // No join without acknowledgement, no TempDir destructor, and no
            // claimed thread cleanup on timeout. The owned outer process caps
            // this explicitly isolated fixture and retains its failed root.
            eprintln!("SERVICE_COORDINATION_CLEANUP_UNPROVEN: {error}");
        }
    }
}

fn refusal() -> String {
    match quiesce_for_update() {
        Ok(_) => panic!("updater coordination unexpectedly admitted the fixture"),
        Err(error) => error,
    }
}

fn mutate_discovery(paths: &Paths, update: impl FnOnce(&mut ServiceRecord)) {
    let mut record = paths.read().unwrap().unwrap();
    update(&mut record);
    paths.publish(&record, &paths.identity().unwrap()).unwrap();
}

#[test]
#[ignore = "requires the owned, isolated native service fixture runner; no public release claim"]
fn pending_job_quiesce_and_identity_native_fixture() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "ordinary native owner required"
    );
    assert_eq!(unsafe { libc::geteuid() }, unsafe { libc::getuid() });
    let root = PathBuf::from(std::env::var_os(ROOT_ENV).expect("explicit fixture root required"));
    assert!(root.is_absolute());
    assert_eq!(root.canonicalize().unwrap(), root);
    let metadata = std::fs::symlink_metadata(&root).unwrap();
    assert!(metadata.is_dir() && metadata.uid() == unsafe { libc::geteuid() });
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    assert_eq!(std::env::current_dir().unwrap(), root.join("project"));
    for (key, suffix) in [
        ("HOME", "home"),
        ("XDG_CONFIG_HOME", "home/.config"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_STATE_HOME", "state"),
        ("TIRITH_POLICY_ROOT", "organization"),
    ] {
        assert_eq!(
            std::env::var_os(key).unwrap(),
            root.join(suffix).as_os_str()
        );
    }
    assert_eq!(
        active_job_count(),
        0,
        "fixture must run alone in its process"
    );
    let paths = Paths::current().unwrap();
    paths.prepare().unwrap();
    let mut service = NativeService::start(&paths);
    let id = uuid::Uuid::new_v4().to_string();
    let target = root.join("home/coordination-settings.json");
    // Match the real API's project-scoped Runtime snapshot. A None scope is
    // intentionally incompatible with this service and must remain refused.
    let service_cwd = service.record.as_ref().unwrap().cwd.clone();
    assert_eq!(PathBuf::from(&service_cwd), root.join("project"));
    let policy = EffectivePolicySnapshot::resolve(Some(&service_cwd), ResolutionMode::Runtime);
    assert_eq!(policy.resolution_cwd(), Some(service_cwd.as_str()));
    let mutations = MutationService::current().unwrap();
    mutations
        .plan(
            &id,
            OperationKind::SetProfile,
            vec![RequestedChange {
                target: target.clone(),
                scope_root: root.join("home"),
                edit: Edit::JsonField {
                    pointer: "/fixture/value".into(),
                    value: Some(json!("applied")),
                },
                activation: false,
                description: "Instrumented service coordination fixture".into(),
            }],
            &policy,
        )
        .unwrap();
    service.gate = Some(ServiceFixtureWorkerGate::new(&id));
    let (status, _) = service
        .request(
            "/api/operations",
            Some(json!({"operation_id": id, "action": "apply"})),
        )
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(mutations.status(&id).unwrap().state, JobState::Running);
    assert_eq!(active_job_count(), 1);
    assert!(!target.exists());
    let old_service = service.record.as_ref().unwrap().service_id.clone();
    let original_digest = service.record.as_ref().unwrap().binary_sha256.clone();

    // These are stale discovery metadata controls against the real live
    // service. They do not counterfeit an old protocol or another binary.
    mutate_discovery(&paths, |record| record.protocol = PROTOCOL + 1);
    assert!(refusal().contains("unsupported control protocol"));
    assert_eq!(service.session()["quiescing"], false);
    assert!(!target.exists());
    mutate_discovery(&paths, |record| {
        record.protocol = PROTOCOL;
        record.binary_sha256 = "0".repeat(64);
    });
    assert!(refusal().contains("service identity changed"));
    assert_eq!(service.session()["quiescing"], false);
    assert!(!target.exists());
    mutate_discovery(&paths, |record| {
        record.binary_sha256 = original_digest.clone()
    });
    let selected = launch(Some(&old_service)).unwrap();
    assert_eq!(selected.service_id, old_service);
    assert_eq!(selected.binary_sha256, original_digest);

    let started = Instant::now();
    assert!(refusal().contains("still draining active jobs"));
    let drain_seconds = started.elapsed().as_secs_f64();
    assert!(drain_seconds >= 10.0);
    assert_eq!(service.session()["quiescing"], true);
    assert_eq!(service.session()["active_jobs"], 1);
    assert_eq!(active_job_count(), 1);
    assert!(!target.exists());
    let (status, value) = service
        .request(
            "/api/operations",
            Some(json!({"operation_id": id, "action": "apply"})),
        )
        .unwrap();
    assert_ne!(status, 200);
    assert!(value.to_string().contains("service is draining"));
    assert!(launch(Some(&old_service)).is_err());
    service.finish().unwrap();
    assert_eq!(active_job_count(), 0);
    assert_eq!(mutations.status(&id).unwrap().state, JobState::Completed);
    let applied: Value = serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
    assert_eq!(applied["fixture"]["value"], "applied");
    let guard = quiesce_for_update().unwrap();
    guard.revalidate().unwrap();
    assert!(
        fs_helpers::try_lock_operation(&paths.service_lock, &paths.scope)
            .unwrap()
            .is_none()
    );
    assert!(
        fs_helpers::try_lock_operation(&paths.launch_lock, &paths.scope)
            .unwrap()
            .is_none()
    );
    drop(guard);
    assert!(launch(Some(&old_service)).is_err()); // Never starts a replacement.

    let mut fresh = NativeService::start(&paths);
    let new_service = fresh.record.as_ref().unwrap().service_id.clone();
    assert_ne!(new_service, old_service);
    assert!(launch(Some(&old_service)).is_err());
    assert_eq!(launch(Some(&new_service)).unwrap().service_id, new_service);
    fresh.finish().unwrap();
    assert_eq!(active_job_count(), 0);
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(&target).unwrap()).unwrap(),
        applied
    );
    assert!(root.join("project").is_dir());
    println!(
        "\nTIRITH_SERVICE_COORDINATION_RESULT {}",
        json!({
            "schema_version": 1,
            "scope": "instrumented_native_worker_service_coordination",
            "passed": true,
            "test_process_pid": std::process::id(),
            "binary_sha256": original_digest,
            "old_service_id": old_service,
            "fresh_service_id": new_service,
            "drain_refusal_seconds": drain_seconds,
            "admitted_worker_observed": true,
            "stale_protocol_refused_before_quiesce": true,
            "stale_binary_refused_before_quiesce": true,
            "pending_job_drain_refused": true,
            "new_mutations_refused_while_draining": true,
            "worker_finished_before_service_exit": true,
            "both_service_threads_acknowledged_and_joined": true,
            "update_guard_holds_launch_and_lifetime_locks": true,
            "fresh_service_identity_required": true,
            "same_test_binary_for_both_service_instances": true,
            "signed_update_verified": false,
            "binary_replacement_verified": false,
            "final_byte_coverage": false
        })
    );
}
