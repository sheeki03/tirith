//! Client authority agreement for curl's empty hexadecimal component family.
//! Pure extraction/policy tests: no resolver, process launch, DNS or transfers.
use tirith_core::extract::ScanContext;
use tirith_core::parse::UrlLike;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::RuleId;
use tirith_core::{engine, extract, parse, policy::Policy, rules};

#[test]
fn curl_empty_hex_dns_authorities_keep_scheme_port_userinfo_and_path() {
    for scheme in ["http", "HTTP", "https", "ftp", "sftp"] {
        for host in [
            "0x7f.0x",
            "0X7F.0X",
            "127.0x",
            "0x.1",
            "0x7f.%30x",
            "%30x7f.0x",
        ] {
            let raw =
                format!("{scheme}://trusted.example:password@{host}:8080/path?q=secret#fragment");
            let input = format!("curl --url '{raw}'");
            let urls = extract::extract_urls(&input, ShellType::Posix);
            assert_eq!(urls.len(), 1, "{input}: {urls:?}");
            let parsed = &urls[0].parsed;
            let expected = host.to_ascii_lowercase().replace("%30", "0");
            assert_eq!(
                parsed.host().map(str::to_ascii_lowercase),
                Some(expected),
                "{input}"
            );
            assert_eq!(parsed.raw_host(), Some(host), "{input}");
            assert_eq!(
                parsed.scheme(),
                Some(scheme.to_ascii_lowercase().as_str()),
                "{input}"
            );
            assert_eq!(parsed.port(), Some(8080), "{input}");
            assert_eq!(parsed.userinfo(), Some("trusted.example"), "{input}");
            assert_eq!(parsed.path(), Some("/path"), "{input}");
            assert_eq!(urls[0].raw, raw);
            assert!(rules::hostname::check(parsed, &Policy::default())
                .iter()
                .any(|f| f.rule_id == RuleId::UserinfoTrick));
            if scheme.eq_ignore_ascii_case("http") {
                assert!(rules::transport::check(parsed, true)
                    .iter()
                    .any(|f| f.rule_id == RuleId::PlainHttpToSink));
            }
        }
    }
}

#[test]
fn curl_schemeless_empty_hex_retains_dns_and_schemeless_warning() {
    for host in ["0x7f.0x", "127.0x", "0x.1", "0x7f.%30x"] {
        for option in ["", "--url ", "--url=", "--proxy=", "-x", "-svx", "-- "] {
            let raw = format!("user:password@{host}:8080/path");
            let input = format!("curl {option}'{raw}'");
            let urls = extract::extract_urls(&input, ShellType::Posix);
            assert_eq!(urls.len(), 1, "{input}: {urls:?}");
            assert_eq!(
                urls[0].parsed.host(),
                Some(host.replace("%30", "0").as_str())
            );
            assert!(matches!(urls[0].parsed, UrlLike::SchemelessHostPath { .. }));
            assert!(rules::transport::check(&urls[0].parsed, true)
                .iter()
                .any(|f| f.rule_id == RuleId::SchemelessToSink));
            assert!(!urls[0].parsed.raw_str().contains("password"));
        }
    }
}

#[test]
fn curl_policy_dns_deny_cannot_be_overridden_by_numeric_loopback_allow() {
    for destination in [
        "http://0x7f.0x/path",
        "0x7f.0x/path",
        "http://127.0x/path",
        "http://0x7f.%30x/path",
    ] {
        let dns_host = if destination.contains("127.0x") {
            "127.0x"
        } else {
            "0x7f.0x"
        };
        let input = format!("curl '{destination}'");
        let findings = rules::command::check_network_policy(
            &input,
            ShellType::Posix,
            &[dns_host.into()],
            &["127.0.0.0/8".into(), "127.0.0.0".into()],
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == RuleId::CommandNetworkDeny),
            "{input}: {findings:?}"
        );
        let allowed = rules::command::check_network_policy(
            &input,
            ShellType::Posix,
            &[dns_host.into()],
            &[dns_host.into()],
        );
        assert!(
            allowed.is_empty(),
            "an exact DNS allow remains valid: {input}"
        );
    }
}

#[test]
fn dsl_observes_curl_dns_host_and_real_http_scheme() {
    let input = "curl http://0x7f.0x/path";
    let extracted = extract::extract_urls(input, ShellType::Posix);
    let backing =
        engine::build_dsl_backing(input, ShellType::Posix, ScanContext::Exec, &extracted, None);
    let context = backing.as_eval_context(None, None);
    assert_eq!(context.urls.len(), 1);
    assert_eq!(context.urls[0].host, "0x7f.0x");
    assert_eq!(context.urls[0].scheme, "http");
}

#[test]
fn generic_parser_and_other_clients_retain_existing_numeric_semantics() {
    let raw = "http://0x7f.0x/path";
    let generic = parse::parse_url(raw);
    assert!(matches!(generic, UrlLike::Standard { .. }));
    assert_eq!(generic.host(), Some("127.0.0.0"));
    let wget = extract::extract_urls(&format!("wget {raw}"), ShellType::Posix);
    assert_eq!(wget[0].parsed.host(), generic.host());
    for scheme in ["http", "https", "ftp", "sftp"] {
        let urls =
            extract::extract_urls(&format!("curl {scheme}://0x7f.0x1/path"), ShellType::Posix);
        assert_eq!(urls[0].parsed.host(), Some("127.0.0.1"));
    }
}

#[test]
fn ordinary_unparsed_failures_do_not_gain_unvalidated_url_controls() {
    for raw in [
        "not a URL",
        "http://host:999999/path",
        "http://[::1/path",
        "http://%zz/path",
    ] {
        let value = parse::parse_url(raw);
        assert!(matches!(value, UrlLike::Unparsed { .. }), "{raw}");
        assert_eq!(value.scheme(), None, "{raw}");
        assert_eq!(value.port(), None, "{raw}");
        assert_eq!(value.userinfo(), None, "{raw}");
    }
    let valid = UrlLike::Unparsed {
        raw: "HTTP://trusted.example:password@github.com:8080/path".into(),
        raw_host: Some("github.com".into()),
        raw_path: Some("/path".into()),
    };
    assert_eq!(valid.scheme(), Some("http"));
    assert_eq!(valid.port(), Some(8080));
    let findings = rules::hostname::check(&valid, &Policy::default());
    assert!(findings.iter().any(|f| f.rule_id == RuleId::UserinfoTrick));
    assert!(findings
        .iter()
        .any(|f| f.rule_id == RuleId::NonStandardPort));
    let encoded = serde_json::to_value(&valid).unwrap();
    assert_eq!(encoded["type"], "unparsed");
    let restored: UrlLike = serde_json::from_value(encoded).unwrap();
    assert_eq!(restored.scheme(), Some("http"));
    assert_eq!(restored.host(), Some("github.com"));
    assert_eq!(restored.userinfo(), Some("trusted.example"));
}

#[test]
fn nested_curl_dns_authority_replaces_only_its_generic_fallback() {
    for input in [
        "sh -c 'curl http://0x7f.0x/path'",
        "sh -c 'curl sftp://0x7f.0x/path'",
        "echo \"$(curl http://0x7f.0x/path)\"",
        "curl --data \"$(curl http://0x7f.0x/path)\" https://example.com/",
    ] {
        let urls = extract::extract_urls(input, ShellType::Posix);
        assert!(
            urls.iter().any(|url| url.parsed.host() == Some("0x7f.0x")),
            "{input}: {urls:?}"
        );
        assert!(
            !urls
                .iter()
                .any(|url| url.parsed.host() == Some("127.0.0.0")),
            "{input}: {urls:?}"
        );
    }
    for input in [
        "wget http://0x7f.0x/path; sh -c 'curl http://0x7f.0x/path'",
        "sh -c 'wget http://0x7f.0x/path; curl http://0x7f.0x/path'",
        "echo 'http://0x7f.0x/path' \"$(curl http://0x7f.0x/path)\"",
    ] {
        let urls = extract::extract_urls(input, ShellType::Posix);
        assert!(
            urls.iter().any(|url| url.parsed.host() == Some("0x7f.0x")),
            "{input}: {urls:?}"
        );
        assert!(
            urls.iter()
                .any(|url| url.parsed.host() == Some("127.0.0.0")),
            "independent generic URL remains: {input}: {urls:?}"
        );
    }
    let inert = extract::extract_urls("echo '$(curl http://0x7f.0x/path)'", ShellType::Posix);
    assert!(
        inert.iter().all(|url| url.parsed.host() != Some("0x7f.0x")),
        "literal data is not a curl invocation: {inert:?}"
    );
}

#[test]
fn curl_empty_hex_authority_accepts_default_and_empty_ports_without_losing_controls() {
    for raw in [
        "http://user.name@0x7f.0x:/path",
        "http://user.name@0x7f.0x:80/path",
        "https://user.name@0x7f.0x:443/path",
    ] {
        let urls = extract::extract_urls(&format!("curl '{raw}'"), ShellType::Posix);
        assert_eq!(urls.len(), 1, "{raw}: {urls:?}");
        let value = &urls[0].parsed;
        assert_eq!(value.host(), Some("0x7f.0x"));
        assert_eq!(value.raw_host(), Some("0x7f.0x"));
        assert_eq!(
            value.port(),
            None,
            "default/empty ports retain Standard's accessor semantics"
        );
        assert_eq!(value.userinfo(), Some("user.name"));
        assert!(rules::hostname::check(value, &Policy::default())
            .iter()
            .any(|finding| finding.rule_id == RuleId::UserinfoTrick));
    }
}

#[test]
fn nested_shell_delimiter_does_not_consume_independent_parenthesis_url_data() {
    let input = "echo 'http://0x7f.0x/path)' \"$(curl http://0x7f.0x/path)\"";
    let urls = extract::extract_urls(input, ShellType::Posix);
    assert!(
        urls.iter()
            .any(|url| url.parsed.host() == Some("0x7f.0x") && url.parsed.path() == Some("/path")),
        "{urls:?}"
    );
    assert!(
        urls.iter().any(
            |url| url.parsed.host() == Some("127.0.0.0") && url.parsed.path() == Some("/path)")
        ),
        "literal closing parenthesis remains URL data: {urls:?}"
    );
}
