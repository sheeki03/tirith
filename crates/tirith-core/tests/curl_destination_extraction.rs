//! curl's URL operands use URL authority syntax; nc/scp keep their own grammar.

use tirith_core::extract::extract_urls;
use tirith_core::parse::UrlLike;
use tirith_core::tokenize::ShellType;

#[test]
fn curl_bare_ipv6_and_numeric_userinfo_are_url_authorities() {
    for (raw, expected) in [
        ("[2001:db8::1]", "[2001:db8::1]"),
        ("[2001:0db8:0000:0000:0000:0000:0000:0001]", "[2001:db8::1]"),
        ("user@134744072:8080/path", "8.8.8.8"),
        ("user@0x08080808:8080/path", "8.8.8.8"),
        ("user@010.010.010.010:8080/path", "8.8.8.8"),
        ("user@8.526344:8080/path", "8.8.8.8"),
        ("user:password@0x08080808:8080/path", "8.8.8.8"),
        ("user@8.8.8.8:8080/path", "8.8.8.8"),
        ("user@host.example:8080/path", "host.example"),
        ("[::1]", "[::1]"),
    ] {
        for option in ["", "--url ", "--url=", "-- "] {
            let input = format!("curl -sv {option}'{raw}'");
            let urls = extract_urls(&input, ShellType::Posix);
            assert_eq!(urls.len(), 1, "{input}: {urls:?}");
            assert_eq!(urls[0].raw, raw, "{input}");
            assert_eq!(urls[0].parsed.host(), Some(expected), "{input}");
            assert!(matches!(urls[0].parsed, UrlLike::SchemelessHostPath { .. }));
            assert!(urls[0].in_sink_context);
        }
    }
}

#[test]
fn curl_option_values_cannot_turn_into_scp_or_schemeless_destinations() {
    for options in [
        "--local-port 8080",
        "--local-port=8080",
        "--output user@134744072:8080/path",
        "--output=user@134744072:8080/path",
        "-ouser@134744072:8080/path",
        "--header user@134744072:8080/path",
        "--data user:password@134744072:8080/path",
        "--data '[2001:db8::1]'",
    ] {
        let input = format!("curl {options} https://example.com/");
        let urls = extract_urls(&input, ShellType::Posix);
        assert_eq!(urls.len(), 1, "{input}: {urls:?}");
        assert_eq!(urls[0].parsed.host(), Some("example.com"));
    }
    // -H is consumed as -d's value; the following word is a real URL operand.
    let urls = extract_urls("curl -d -H user@134744072:8080/path", ShellType::Posix);
    assert_eq!(urls.len(), 1, "{urls:?}");
    assert_eq!(urls[0].parsed.host(), Some("8.8.8.8"));
}

#[test]
fn curl_connection_mappings_are_not_schemeless_url_operands() {
    let input = "curl --resolve example.com:443:192.0.2.10 --connect-to example.com:443:198.51.100.10:8443 https://example.com/";
    let urls = extract_urls(input, ShellType::Posix);
    assert_eq!(urls.len(), 1, "{urls:?}");
    assert_eq!(urls[0].parsed.host(), Some("example.com"));
}

#[test]
fn port_numbers_remain_urls_only_in_curl_url_positions() {
    for input in [
        "nc 203.0.113.10 8080",
        "ncat 203.0.113.10 8082",
        "netcat 2001:db8::1 8080",
        "printf '%s' '[2001:db8::1]'",
        "echo 8080 134744072",
        "cp 8080 8082",
    ] {
        assert!(extract_urls(input, ShellType::Posix).is_empty(), "{input}");
    }
    let urls = extract_urls("curl --local-port 8080 8082", ShellType::Posix);
    assert_eq!(urls.len(), 1, "{urls:?}");
    assert_eq!(urls[0].raw, "8082");
    assert_eq!(urls[0].parsed.host(), Some("0.0.31.146"));
    let urls = extract_urls("curl 203.0.113.10 8080", ShellType::Posix);
    assert_eq!(urls.len(), 2, "{urls:?}");
}

#[test]
fn remote_copy_commands_keep_scp_paths() {
    for input in [
        "scp user@134744072:8080/path destination",
        "rsync -av user@134744072:8080/path destination",
        "git clone user@134744072:8080/path",
    ] {
        let urls = extract_urls(input, ShellType::Posix);
        assert_eq!(urls.len(), 1, "{input}: {urls:?}");
        // The generic parser has always left undotted SCP hosts unparsed.
        // Preserve that exact baseline instead of normalizing the integer as
        // curl does or silently broadening SCP parsing in this correction.
        assert_eq!(urls[0].raw, "user@134744072:8080/path");
        assert!(
            matches!(&urls[0].parsed, UrlLike::Unparsed { raw, raw_host, raw_path }
            if raw == "user@134744072:8080/path" && raw_host.is_none() && raw_path.is_none())
        );
    }
    for command in ["scp", "rsync -av", "git clone"] {
        for host in ["8.8.8.8", "host.example"] {
            let input = format!("{command} user@{host}:8080/path destination");
            let urls = extract_urls(&input, ShellType::Posix);
            assert_eq!(urls.len(), 1, "{input}: {urls:?}");
            assert!(
                matches!(&urls[0].parsed, UrlLike::Scp { user, host: actual, path }
                if user.as_deref() == Some("user") && actual == host && path == "8080/path")
            );
        }
    }
    // The same spelling with a nonnumeric "port" is not a curl URL, and curl
    // does not reinterpret it as SCP's remote path shorthand.
    assert!(extract_urls("curl user@host.example:repo/path", ShellType::Posix).is_empty());
}

#[test]
fn curl_explicit_scp_and_sftp_urls_still_expose_their_host() {
    for scheme in ["http", "https", "ftp", "scp", "sftp"] {
        let raw = format!("{scheme}://user@8.8.8.8:22/path");
        for prefix in ["", "--url ", "--url=", "--proxy=", "-x", "-svx"] {
            let input = format!("curl {prefix}'{raw}'");
            let urls = extract_urls(&input, ShellType::Posix);
            assert_eq!(urls.len(), 1, "{input}: {urls:?}");
            assert_eq!(urls[0].raw, raw, "{input}");
            assert_eq!(urls[0].parsed.host(), Some("8.8.8.8"));
            assert_eq!(urls[0].parsed.scheme(), Some(scheme));
            assert!(matches!(urls[0].parsed, UrlLike::Standard { .. }));
        }
    }
}

#[test]
fn wrapped_curl_and_executable_substitutions_keep_destination_context() {
    for input in [
        "env curl 'user@134744072:8080/path'",
        "sh -c 'curl user@134744072:8080/path'",
        "curl --data \"$(curl user@134744072:8080/path)\" https://example.com/",
    ] {
        let urls = extract_urls(input, ShellType::Posix);
        assert!(
            urls.iter().any(|url| url.parsed.host() == Some("8.8.8.8")
                && url.in_sink_context
                && matches!(url.parsed, UrlLike::SchemelessHostPath { .. })),
            "{input}: {urls:?}"
        );
    }
}

#[test]
fn curl_scheme_suffix_filter_preserves_independent_and_embedded_urls() {
    for input in [
        "curl sftp://user@8.8.8.8:22/path ftp://user@8.8.8.8:22/path",
        "curl --url=sftp://user@8.8.8.8:22/path --header 'Location: ftp://user@8.8.8.8:22/path'",
        "curl -xsftp://user@8.8.8.8:22/path --data 'see ftp://user@8.8.8.8:22/path'",
    ] {
        let urls = extract_urls(input, ShellType::Posix);
        assert_eq!(urls.len(), 2, "{input}: {urls:?}");
        for scheme in ["ftp", "sftp"] {
            assert_eq!(
                urls.iter()
                    .filter(|url| url.parsed.scheme() == Some(scheme))
                    .count(),
                1,
                "{input}: {urls:?}"
            );
        }
    }
}

#[test]
fn curl_non_special_schemes_normalize_numeric_hosts_without_changing_components() {
    for scheme in ["sftp", "scp", "ftps", "smtp", "ssh"] {
        for (host, canonical) in [
            ("134744072", "8.8.8.8"),
            ("0x08080808", "8.8.8.8"),
            ("010.010.010.010", "8.8.8.8"),
            ("8.526344", "8.8.8.8"),
            ("8080", "0.0.31.144"),
            ("0x0", "0.0.0.0"),
            ("0x00.1", "0.0.0.1"),
            ("0x", "0x"),
            ("0X", "0X"),
            ("0x.1", "0x.1"),
            ("8.0x", "8.0x"),
            ("0x7f.0x", "0x7f.0x"),
            ("0x.0x.0x.0x", "0x.0x.0x.0x"),
            ("host.example", "host.example"),
            ("4294967296", "4294967296"),
            ("8.8.8.8.", "8.8.8.8."),
        ] {
            let raw = format!("{scheme}://user:password@{host}:8022/path?x=1#part");
            let urls = extract_urls(&format!("curl '{raw}'"), ShellType::Posix);
            assert_eq!(urls.len(), 1, "{raw}: {urls:?}");
            assert_eq!(urls[0].raw, raw);
            assert_eq!(urls[0].parsed.host(), Some(canonical), "{raw}");
            assert_eq!(urls[0].parsed.raw_host(), Some(host));
            let UrlLike::Standard { parsed, .. } = &urls[0].parsed else {
                panic!("{urls:?}")
            };
            assert_eq!(parsed.scheme(), scheme);
            assert_eq!(parsed.username(), "user");
            assert_eq!(parsed.password(), Some("password"));
            assert_eq!(parsed.port(), Some(8022));
            assert_eq!(parsed.path(), "/path");
            assert_eq!(parsed.query(), Some("x=1"));
            assert_eq!(parsed.fragment(), Some("part"));
        }
    }
}

#[test]
fn curl_scheme_slashes_preserve_authority_and_component_boundaries() {
    for scheme in ["http", "HTTP", "https", "ftp", "sftp"] {
        for slashes in ["/", "//", "///"] {
            let raw = format!("{scheme}:{slashes}user:password@134744072:8080/path?x=1#part");
            for option in ["", "--url ", "--url=", "--proxy=", "-x", "-svx", "-- "] {
                let input = format!("curl {option}'{raw}'");
                let urls = extract_urls(&input, ShellType::Posix);
                assert_eq!(urls.len(), 1, "{input}: {urls:?}");
                assert_eq!(urls[0].raw, raw);
                assert_eq!(urls[0].parsed.host(), Some("8.8.8.8"), "{input}");
                assert_eq!(urls[0].parsed.raw_host(), Some("134744072"));
                assert_eq!(
                    urls[0].parsed.scheme(),
                    Some(scheme.to_ascii_lowercase().as_str())
                );
                assert_eq!(urls[0].parsed.userinfo(), Some("user"));
                assert_eq!(urls[0].parsed.port(), Some(8080));
                assert_eq!(urls[0].parsed.path(), Some("/path"));
            }
        }
    }
}

#[test]
fn curl_paths_userinfo_and_non_destination_values_do_not_replace_the_host() {
    for slashes in ["/", "//", "///"] {
        for raw in [
            format!("https:{slashes}169.254.169.254@example.com/path"),
            format!("https:{slashes}example.com:8443/path/http://169.254.169.254/x"),
            format!("https:{slashes}example.com/path?next=http://169.254.169.254/x"),
        ] {
            for input in [
                format!("curl '{raw}'"),
                format!("env -S 'curl {raw}'"),
                format!("sh -c 'curl {raw}'"),
                format!("echo \"$(curl '{raw}')\""),
            ] {
                let urls = extract_urls(&input, ShellType::Posix);
                assert!(
                    urls.iter()
                        .any(|url| url.parsed.host() == Some("example.com")),
                    "{input}: {urls:?}"
                );
                assert!(
                    urls.iter()
                        .all(|url| url.parsed.host() != Some("169.254.169.254")),
                    "{input}: {urls:?}"
                );
            }
        }
        for option in ["--header", "--data", "--output", "--user"] {
            let input =
                format!("curl {option} 'http:{slashes}169.254.169.254/x' https://example.com/");
            let findings = tirith_core::rules::command::check(
                &input,
                ShellType::Posix,
                None,
                tirith_core::extract::ScanContext::Exec,
            );
            assert!(
                findings.iter().all(
                    |finding| finding.rule_id != tirith_core::verdict::RuleId::MetadataEndpoint
                ),
                "{input}: {findings:?}"
            );
            let denied = tirith_core::rules::command::check_network_policy(
                &input,
                ShellType::Posix,
                &["169.254.0.0/16".into()],
                &[],
            );
            assert!(denied.is_empty(), "{input}: {denied:?}");
        }
    }
    let urls = extract_urls("curl http:////169.254.169.254/x", ShellType::Posix);
    assert!(
        urls.iter().all(|url| url.parsed.host().is_none()),
        "{urls:?}"
    );
}

#[test]
fn curl_slash_normalization_is_not_a_generic_url_or_remote_path_rule() {
    let generic = tirith_core::parse::parse_url("sftp:/user@host.example:22/path");
    assert_eq!(generic.host(), None);
    for input in [
        "git clone git@github.com:http://4.1.0.11/repo.git",
        "env -S 'git clone git@github.com:http://4.1.0.11/repo.git'",
        "scp git@github.com:http://4.1.0.11/repo.git destination",
        "rsync -a git@github.com:http://4.1.0.11/repo.git destination",
    ] {
        let urls = extract_urls(input, ShellType::Posix);
        assert!(
            urls.iter().any(|url| {
                url.parsed.host() == Some("github.com")
                    && url.parsed.path() == Some("http://4.1.0.11/repo.git")
                    && matches!(url.parsed, UrlLike::Scp { .. })
            }),
            "{input}: {urls:?}"
        );
        assert!(
            urls.iter().all(|url| url.parsed.host() != Some("4.1.0.11")),
            "{input}: {urls:?}"
        );
    }
}
