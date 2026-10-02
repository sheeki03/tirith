//! Explicit harmless controls, excluded from ordinary integration test counts.
use super::*;

fn native_complete(value: &serde_json::Value) -> bool {
    [
        "leader_reaped",
        "original_group_exited",
        "original_session_exited",
        "reaped_after_native_observation",
    ]
    .into_iter()
    .all(|key| value["native"][key] == true)
        && value["native"]["errors"]
            .as_array()
            .is_some_and(Vec::is_empty)
}

#[test]
#[ignore = "explicit owned native PTY qualification control"]
fn natural_close_retains_fixture_until_owner_drop_and_is_idempotent() {
    let env = IsolatedEnv::new();
    let root = env.fixture.root.as_ref().unwrap().path().to_path_buf();
    let mut session = PtySession::spawn(&env, Path::new("/bin/sh"), &["-i"]);
    session.send_line("printf 'OWNER_READY\\n'");
    session.expect("OWNER_READY");
    drop(env);
    assert!(root.is_dir(), "actual owner must retain fixture lifetime");
    session.close();
    session.close();
    let reports = session.fixture.reports.lock().unwrap();
    assert_eq!(
        reports.len(),
        1,
        "second close must neither signal nor reap"
    );
    assert!(native_complete(&reports[0]));
    assert_eq!(reports[0]["native_eof"], true);
    assert_eq!(reports[0]["reader_joined"], true);
    drop(reports);
    drop(session);
    assert!(!root.exists());
}

#[test]
#[ignore = "explicit owned native PTY qualification control"]
fn disconnected_reader_channel_does_not_release_live_leader_ownership() {
    let env = IsolatedEnv::new();
    // A finite real child retains its actual PTY/session. Inject only the
    // driver's disconnected output channel: redirecting stdio does not prove
    // native PTY EOF while a controlling-session leader remains live on macOS.
    let mut session = PtySession::spawn(&env, Path::new("/bin/sh"), &["-c", "sleep 2"]);
    let (sender, disconnected) = mpsc::channel();
    drop(sender);
    session.rx = disconnected;
    session.pump(Duration::ZERO);
    assert!(session.output_closed);
    assert!(
        !session.closed,
        "output channel closure must not release the owner"
    );
    assert!(
        !session.child.exited().unwrap(),
        "actual finite child must still be retained and live"
    );
    // Echo input through the real PTY after disconnecting the receiver, so
    // the reader acknowledges the failed send before group termination. A
    // disconnected channel alone cannot determine a later native EOF result.
    session.send_raw(b"CHANNEL_DISCONNECTED\r");
    session.reader_end = Some(
        session
            .reader_done
            .recv_timeout(Duration::from_secs(1))
            .expect("reader must acknowledge its disconnected output channel"),
    );
    assert!(!session.reader_end.as_ref().unwrap().native_eof);
    assert!(!session.child.exited().unwrap());
    session.finish(false);
    let reports = env.fixture.reports.lock().unwrap();
    assert_eq!(reports.len(), 1);
    assert!(native_complete(&reports[0]));
    assert_eq!(
        reports[0]["native_eof"], false,
        "injected channel closure is not native EOF"
    );
    assert_eq!(reports[0]["reader_joined"], true);
    assert_eq!(
        reports[0]["passed"], false,
        "unknown native EOF must refuse qualification"
    );
}

#[test]
#[ignore = "explicit owned native PTY qualification control"]
fn post_spawn_setup_failure_cleans_owner_and_retains_failed_root() {
    let env = IsolatedEnv::new();
    let root = env.fixture.root.as_ref().unwrap().path().to_path_buf();
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PtySession::spawn_with_setup(&env, Path::new("/bin/sh"), &["-c", "sleep 2"], || {
            panic!("injected post-spawn setup failure")
        })
    }));
    assert!(failed.is_err());
    let reports = env.fixture.reports.lock().unwrap();
    assert_eq!(reports.len(), 1);
    assert!(native_complete(&reports[0]));
    assert_eq!(
        reports[0]["native_eof"], false,
        "no reader means no invented EOF"
    );
    assert_eq!(reports[0]["passed"], false);
    drop(reports);
    drop(env);
    assert!(
        root.is_dir(),
        "failed fixture must remain available for inspection"
    );
    // Deliberately retain the injected-failure root as reported evidence.
}

#[test]
#[ignore = "explicit owned native PTY qualification control"]
fn forced_reader_stop_does_not_invent_eof() {
    let env = IsolatedEnv::new();
    let root = env.fixture.root.as_ref().unwrap().path().to_path_buf();
    let mut session = PtySession::spawn(&env, Path::new("/bin/sh"), &["-c", "sleep 2"]);
    session.reader_stop.store(true, Ordering::Release);
    session.reader_end = Some(
        session
            .reader_done
            .recv_timeout(Duration::from_secs(1))
            .expect("forced reader stop must acknowledge completion"),
    );
    assert!(!session.reader_end.as_ref().unwrap().native_eof);
    assert!(!session.child.exited().unwrap());
    session.finish(false);
    let reports = env.fixture.reports.lock().unwrap();
    assert!(native_complete(&reports[0]));
    assert_eq!(reports[0]["reader_joined"], true);
    assert_eq!(reports[0]["native_eof"], false);
    assert_eq!(reports[0]["passed"], false);
    drop(reports);
    drop(session);
    drop(env);
    assert!(root.is_dir());
}

#[test]
#[ignore = "explicit owned native PTY qualification control"]
fn owned_termination_drains_real_eof_before_reader_stop_and_reap() {
    let env = IsolatedEnv::new();
    let root = env.fixture.root.as_ref().unwrap().path().to_path_buf();
    let mut session = PtySession::spawn(&env, Path::new("/bin/sh"), &["-c", "sleep 2"]);
    assert!(!session.child.exited().unwrap());
    assert!(session.reader_end.is_none());
    session.finish(false);
    let reports = env.fixture.reports.lock().unwrap();
    assert_eq!(reports.len(), 1);
    let report = &reports[0];
    assert!(native_complete(report));
    assert_eq!(report["graceful_exit_requested"], false);
    assert_eq!(report["leader_exited_before_reader_drain"], false);
    assert_eq!(
        report["original_group_stop_requested_before_reader_drain"],
        true
    );
    assert_eq!(report["reader_stop_fallback"], false);
    assert_eq!(report["native_eof"], true);
    assert_eq!(report["reader_joined"], true);
    assert_eq!(report["passed"], true);
    drop(reports);
    drop(session);
    drop(env);
    assert!(
        !root.exists(),
        "fully observed forced cleanup permits fixture removal"
    );
}
