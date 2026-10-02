use super::*;
use crate::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};

fn fixture() -> (tirith_test_support::GlobalStateGuard, std::path::PathBuf) {
    let mut state = tirith_test_support::GlobalStateGuard::new().unwrap();
    for name in ["TIRITH_SERVER_URL", "TIRITH_API_KEY"] {
        state.remove_env(name);
    }
    let config = crate::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    (state, config)
}

fn snapshot(state: &tirith_test_support::GlobalStateGuard) -> EffectivePolicySnapshot {
    EffectivePolicySnapshot::resolve(state.roots().cwd.to_str(), ResolutionMode::Runtime)
}

#[test]
fn bounded_runtime_retains_valid_overlay_and_setup_replay_semantics() {
    let (state, config) = fixture();
    std::fs::write(config.join("allowlist"), "allowed.example\n").unwrap();
    std::fs::write(config.join("blocklist"), "blocked.example\n").unwrap();
    let ordinary = snapshot(&state);
    ordinary.revalidate_inputs().unwrap();
    let scoped = {
        let _scope = BoundedRuntimePolicyInputs::enter();
        let scoped = snapshot(&state);
        assert_eq!(scoped.resolution_mode, ResolutionMode::Runtime);
        assert!(scoped.policy.allowlist.contains(&"allowed.example".into()));
        assert!(scoped.policy.blocklist.contains(&"blocked.example".into()));
        assert_eq!(
            scoped.private_replay_guard(),
            ordinary.private_replay_guard()
        );
        scoped.revalidate_inputs().unwrap();
        scoped
    };
    scoped.revalidate_inputs().unwrap();
    // A retained bounded snapshot must not revert to the ordinary uncapped
    // reader after the scope ends, including on a later growth race.
    std::fs::File::create(config.join("blocklist"))
        .unwrap()
        .set_len(USER_LIST_CAP + 1)
        .unwrap();
    assert!(scoped.revalidate_inputs().is_err());
}

#[test]
fn bounded_runtime_refuses_oversize_without_silently_dropping_a_blocklist() {
    let (state, config) = fixture();
    let path = config.join("blocklist");
    std::fs::File::create(&path)
        .unwrap()
        .set_len(USER_LIST_CAP + 1)
        .unwrap();
    let refused = {
        let _scope = BoundedRuntimePolicyInputs::enter();
        assert!(matches!(
            crate::policy_snapshot::read_input(&path, InputReader::UserList),
            Err(OpenRegularError::TooLarge)
        ));
        let refused = snapshot(&state);
        assert!(refused.revalidate_inputs().is_err());
        assert_eq!(refused.policy.path.as_deref(), Some("fail-closed"));
        assert!(!refused.policy.allow_bypass_env);
        assert!(refused.policy.custom_rules.iter().any(|rule| {
            rule.id == "tirith-effective-policy-unavailable"
                && rule.action == Some(crate::verdict::Action::Block)
        }));
        let context = crate::engine::AnalysisContext {
            input: "echo inert".into(),
            shell: crate::tokenize::ShellType::Posix,
            scan_context: crate::extract::ScanContext::Exec,
            raw_bytes: None,
            interactive: true,
            cwd: state.roots().cwd.to_str().map(str::to_owned),
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
            card_ref: None,
            clipboard_source: crate::clipboard::ClipboardSourceState::AbsentOrInvalid,
        };
        let (verdict, _) = crate::engine::analyze_returning_policy(&context);
        assert_eq!(verdict.action, crate::verdict::Action::Block);
        assert!(!verdict.bypass_available);
        // Fixing the pathname cannot erase an in-flight operation's refusal.
        std::fs::write(&path, "blocked.example\n").unwrap();
        let _nested = BoundedRuntimePolicyInputs::enter();
        assert!(snapshot(&state).revalidate_inputs().is_err());
        assert_eq!(
            Policy::discover(state.roots().cwd.to_str()).path.as_deref(),
            Some("fail-closed")
        );
        refused
    };
    assert!(refused.revalidate_inputs().is_err());
    snapshot(&state).revalidate_inputs().unwrap();
}

#[test]
fn bounded_runtime_accepts_absence_and_exact_bound_but_refuses_invalid_utf8() {
    let (state, config) = fixture();
    {
        let _scope = BoundedRuntimePolicyInputs::enter();
        snapshot(&state).revalidate_inputs().unwrap();
        let mut comment = vec![b'x'; USER_LIST_CAP as usize];
        comment[0] = b'#';
        std::fs::write(config.join("allowlist"), comment).unwrap();
        snapshot(&state).revalidate_inputs().unwrap();
        std::fs::write(config.join("blocklist"), [0xff]).unwrap();
        let invalid = snapshot(&state);
        assert!(invalid.revalidate_inputs().is_err());
        assert_eq!(invalid.policy.path.as_deref(), Some("fail-closed"));
    }
    // Preserve the existing ordinary runtime reader/invalid-UTF8 treatment.
    assert!(matches!(user_list_reader(), InputReader::UserList));
    let ordinary = snapshot(&state);
    assert_ne!(ordinary.policy.path.as_deref(), Some("fail-closed"));
}

#[cfg(unix)]
#[test]
fn bounded_runtime_refuses_fifo_and_directory_and_preserves_regular_symlink() {
    use std::os::unix::ffi::OsStrExt;
    let (state, config) = fixture();
    let list = config.join("blocklist");
    let name = std::ffi::CString::new(list.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    {
        let _scope = BoundedRuntimePolicyInputs::enter();
        assert!(snapshot(&state).revalidate_inputs().is_err());
    }
    std::fs::remove_file(&list).unwrap();
    std::fs::create_dir(&list).unwrap();
    {
        let _scope = BoundedRuntimePolicyInputs::enter();
        assert!(snapshot(&state).revalidate_inputs().is_err());
    }
    std::fs::remove_dir(&list).unwrap();
    let target = config.join("regular-list");
    std::fs::write(&target, "blocked.example\n").unwrap();
    std::os::unix::fs::symlink(&target, &list).unwrap();
    let ordinary = snapshot(&state);
    let _scope = BoundedRuntimePolicyInputs::enter();
    let scoped = snapshot(&state);
    scoped.revalidate_inputs().unwrap();
    assert_eq!(
        scoped.private_replay_guard(),
        ordinary.private_replay_guard()
    );
}

#[test]
fn bounded_runtime_diagnostics_are_not_formatted_even_in_nested_capture() {
    struct MustNotFormat;
    impl std::fmt::Display for MustNotFormat {
        fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            panic!("silent diagnostics must not format private input")
        }
    }
    let ordinary = PolicyDiagnosticCapture::start();
    {
        let _scope = BoundedRuntimePolicyInputs::enter();
        let nested = PolicyDiagnosticCapture::start();
        super::super::emit_policy_diagnostic(format_args!("{MustNotFormat}"));
        assert!(nested.drain().is_empty());
    }
    super::super::emit_policy_diagnostic(format_args!("ordinary diagnostic restored"));
    assert_eq!(ordinary.drain(), vec!["ordinary diagnostic restored"]);
}
