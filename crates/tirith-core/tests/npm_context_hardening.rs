//! Static argv strings only. Never execute any of these fixture commands.
use tirith_core::clipboard::ClipboardSourceState;
use tirith_core::engine::{analyze_force_full_returning_policy, AnalysisContext};
use tirith_core::extract::{extract_urls, ScanContext};
use tirith_core::parse::UrlLike;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Action, RuleId};
use tirith_test_support::GlobalStateGuard;

#[test]
fn remote_path_uri_is_data_not_a_replacement_remote() {
    let _guard = GlobalStateGuard::new().unwrap();
    let cases = [
        "git clone git@4.1.0.11:https://registry.npmjs.org/repo.git",
        "scp 'git@4.1.0.11:https://registry.npmjs.org/file' ./file",
        "rsync 'git@4.1.0.11:https://registry.npmjs.org/file' ./file",
        "env git clone git@4.1.0.11:https://registry.npmjs.org/repo.git",
        "sudo scp 'git@4.1.0.11:https://registry.npmjs.org/file' ./file",
        "command rsync 'git@4.1.0.11:https://registry.npmjs.org/file' ./file",
    ];
    for input in cases {
        let urls = extract_urls(input, ShellType::Posix);
        assert!(
            urls.iter().any(|u| {
                matches!(&u.parsed, UrlLike::Scp { host, path, .. }
                if host == "4.1.0.11" && path.starts_with("https://registry.npmjs.org/"))
                    && u.raw.starts_with("git@4.1.0.11:")
                    && u.segment_index == 0
                    && u.in_sink_context
            }),
            "remote lost: {input}: {urls:?}"
        );
        assert!(
            !urls
                .iter()
                .any(|u| u.parsed.host() == Some("registry.npmjs.org")),
            "remote path mistaken for a second destination: {input}: {urls:?}"
        );
        let ctx = AnalysisContext {
            input: input.into(),
            shell: ShellType::Posix,
            scan_context: ScanContext::Exec,
            raw_bytes: None,
            interactive: false,
            cwd: Some(std::env::current_dir().unwrap().display().to_string()),
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
            card_ref: None,
            clipboard_source: ClipboardSourceState::AbsentOrInvalid,
        };
        let verdict = analyze_force_full_returning_policy(&ctx).0;
        assert!(verdict.tier_reached >= 3, "{input}: {verdict:?}");
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::RawIpUrl),
            "{input}: {verdict:?}"
        );
        assert_ne!(verdict.action, Action::Allow, "{input}: {verdict:?}");
    }
}

#[test]
fn package_prefixed_urls_and_scp_controls_have_explicit_metadata() {
    // Expected raw, host, path, kind, sink and segment: no inferred byte spans.
    let cases = [
        (
            "npm view vitest@http://4.1.0.11/a",
            "http://4.1.0.11/a",
            "4.1.0.11",
            "/a",
            false,
        ),
        (
            "npm info alias@npm:pkg@https://4.1.0.11/b",
            "https://4.1.0.11/b",
            "4.1.0.11",
            "/b",
            false,
        ),
        (
            "npm show @scope/pkg@http://4.1.0.11/c",
            "http://4.1.0.11/c",
            "4.1.0.11",
            "/c",
            false,
        ),
        (
            "npm v alias@npm:pkg@http://4.1.0.11/d",
            "http://4.1.0.11/d",
            "4.1.0.11",
            "/d",
            false,
        ),
        (
            "git clone git@github.com:user/repo.git",
            "git@github.com:user/repo.git",
            "github.com",
            "user/repo.git",
            true,
        ),
        (
            "scp git@github.com:user/repo.git ./repo",
            "git@github.com:user/repo.git",
            "github.com",
            "user/repo.git",
            true,
        ),
        (
            "rsync git@github.com:user/repo.git ./repo",
            "git@github.com:user/repo.git",
            "github.com",
            "user/repo.git",
            true,
        ),
    ];
    for (input, raw, host, path, scp) in cases {
        let urls = extract_urls(input, ShellType::Posix);
        assert!(
            urls.iter().any(|u| {
                u.raw == raw
                    && u.parsed.host() == Some(host)
                    && u.parsed.path() == Some(path)
                    && u.segment_index == 0
                    && u.in_sink_context
                    && matches!(
                        (&u.parsed, scp),
                        (UrlLike::Scp { .. }, true) | (UrlLike::Standard { .. }, false)
                    )
            }),
            "missing destination: {input}: {urls:?}"
        );
        if !scp {
            assert!(
                !urls
                    .iter()
                    .any(|u| matches!(&u.parsed, UrlLike::Scp { .. })),
                "package URL reinterpreted as SCP: {input}: {urls:?}"
            );
        }
    }
}

#[test]
fn unrelated_destinations_are_not_hidden_by_registry_spec() {
    let cases = [
        ("npm view vitest@4.1.11 --registry http://4.1.0.11/a", "http://4.1.0.11/a", "4.1.0.11", "/a", 0),
        ("npm info vitest@4.1.11 version --registry=https://4.1.0.11/b", "https://4.1.0.11/b", "4.1.0.11", "/b", 0),
        ("npm show vitest@4.1.11 unknown.selector=http://4.1.0.11/c", "http://4.1.0.11/c", "4.1.0.11", "/c", 0),
        ("npm v vitest@4.1.11 --mystery http://4.1.0.11/d", "http://4.1.0.11/d", "4.1.0.11", "/d", 0),
        ("npm view vitest@4.1.11 --registry https://registry.npmjs.org | curl https://4.1.0.11/e", "https://4.1.0.11/e", "4.1.0.11", "/e", 1),
        ("npm view vitest@4.1.11 --registry https://registry.npmjs.org; git clone http://4.1.0.11/f", "http://4.1.0.11/f", "4.1.0.11", "/f", 1),
    ];
    for (input, raw, host, path, segment) in cases {
        let urls = extract_urls(input, ShellType::Posix);
        assert!(
            urls.iter().any(|u| u.raw == raw
                && u.parsed.host() == Some(host)
                && u.parsed.path() == Some(path)
                && matches!(u.parsed, UrlLike::Standard { .. })
                && u.segment_index == segment
                && u.in_sink_context),
            "unrelated URL lost: {input}: {urls:?}"
        );
    }
}
