//! Numeric URL operands remain destinations; diagnostics preserve their spelling.

use tirith_core::clipboard::ClipboardSourceState;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Evidence, Finding, RuleId, Severity, Verdict};
use tirith_test_support::GlobalStateGuard;

fn analyze(input: &str) -> Verdict {
    engine::analyze(&AnalysisContext {
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
    })
}

fn raw_ip_findings(verdict: &Verdict) -> Vec<&Finding> {
    verdict
        .findings
        .iter()
        .filter(|finding| finding.rule_id == RuleId::RawIpUrl)
        .collect()
}

fn assert_raw_evidence(finding: &Finding, expected: &str) {
    assert!(
        matches!(finding.evidence.as_slice(), [Evidence::Url { raw }] if raw == expected),
        "expected URL evidence {expected:?}: {finding:?}"
    );
}

#[test]
fn numeric_destinations_show_original_host_and_canonical_address() {
    let _state = GlobalStateGuard::new().unwrap();
    // curl accepts every non-option operand as a URL, including values in the
    // port range. These normalizations also match libcurl's offline URL API.
    for (raw, canonical) in [
        ("8080", "0.0.31.144"),
        ("8082", "0.0.31.146"),
        ("65535", "0.0.255.255"),
        ("65536", "0.1.0.0"),
        ("134744072", "8.8.8.8"),
        ("0x08080808", "8.8.8.8"),
        ("01002004010", "8.8.8.8"),
        ("010.010.010.010", "8.8.8.8"),
        ("8.526344", "8.8.8.8"),
        ("8.8.2056", "8.8.8.8"),
    ] {
        for scheme in ["", "http://"] {
            let operand = format!("{scheme}{raw}");
            let verdict = analyze(&format!("curl -sv {operand}"));
            let findings = raw_ip_findings(&verdict);
            assert_eq!(findings.len(), 1, "{operand}: {verdict:?}");
            let finding = findings[0];
            assert_eq!(finding.severity, Severity::Medium);
            assert_eq!(
                finding.description,
                format!("URL host '{raw}' is interpreted as IP address {canonical} instead of a domain name")
            );
            assert_raw_evidence(finding, raw);
            let schemeless: Vec<_> = verdict
                .findings
                .iter()
                .filter(|finding| finding.rule_id == RuleId::SchemelessToSink)
                .collect();
            assert_eq!(
                schemeless.len(),
                usize::from(scheme.is_empty()),
                "{operand}"
            );
            if let Some(finding) = schemeless.first() {
                assert_raw_evidence(finding, &operand);
            }
        }
    }
}

#[test]
fn separate_numeric_operand_is_not_a_port_for_the_previous_url() {
    let _state = GlobalStateGuard::new().unwrap();
    for (raw, canonical) in [("8080", "0.0.31.144"), ("8082", "0.0.31.146")] {
        let verdict = analyze(&format!("curl -sv 203.0.113.10 {raw}"));
        let findings = raw_ip_findings(&verdict);
        assert_eq!(findings.len(), 2, "{verdict:?}");
        let numeric = findings
            .iter()
            .find(|finding| finding.description.contains(canonical))
            .unwrap();
        assert_raw_evidence(numeric, raw);
        let dotted = findings
            .iter()
            .find(|finding| finding.description.contains("203.0.113.10"))
            .unwrap();
        assert_eq!(
            dotted.description,
            "URL points to IP address 203.0.113.10 instead of a domain name"
        );
        assert_raw_evidence(dotted, "203.0.113.10");
    }
}

#[test]
fn actual_option_values_are_consumed_but_following_urls_remain_visible() {
    let _state = GlobalStateGuard::new().unwrap();
    for options in [
        "--local-port 8080",
        "--local-port=8080",
        "--connect-timeout 8080",
        "--output 8080",
        "-o8080",
    ] {
        let verdict = analyze(&format!("curl {options} https://example.com"));
        assert!(
            raw_ip_findings(&verdict).is_empty(),
            "{options}: {verdict:?}"
        );
        assert!(
            verdict
                .findings
                .iter()
                .all(|finding| finding.rule_id != RuleId::SchemelessToSink),
            "{options}: {verdict:?}"
        );
    }
    for command in ["curl --local-port 8080 8082", "curl --url 8082"] {
        let verdict = analyze(command);
        let findings = raw_ip_findings(&verdict);
        assert_eq!(findings.len(), 1, "{command}: {verdict:?}");
        assert_raw_evidence(findings[0], "8082");
    }
}

#[test]
fn explicit_port_stays_attached_to_its_host() {
    let _state = GlobalStateGuard::new().unwrap();
    let verdict = analyze("curl -sv http://203.0.113.10:8080/");
    let findings = raw_ip_findings(&verdict);
    assert_eq!(findings.len(), 1, "{verdict:?}");
    assert_raw_evidence(findings[0], "203.0.113.10");
    assert!(verdict
        .findings
        .iter()
        .all(|finding| finding.rule_id != RuleId::SchemelessToSink));
}

#[test]
fn schemeless_host_evidence_excludes_userinfo_port_and_path() {
    let _state = GlobalStateGuard::new().unwrap();
    for operand in [
        "0x08080808:8081/payload?x=1#part",
        "user@0x08080808/payload?x=1#part",
        "//0x08080808:8081/payload?x=1#part",
    ] {
        let verdict = analyze(&format!("curl -sv '{operand}'"));
        let findings = raw_ip_findings(&verdict);
        assert_eq!(findings.len(), 1, "{verdict:?}");
        assert_raw_evidence(findings[0], "0x08080808");
        let schemeless = verdict
            .findings
            .iter()
            .find(|finding| finding.rule_id == RuleId::SchemelessToSink)
            .unwrap();
        assert_raw_evidence(schemeless, operand.strip_prefix("user@").unwrap_or(operand));
    }
}

#[test]
fn ipv6_spelling_is_preserved_and_loopback_exemptions_are_unchanged() {
    let _state = GlobalStateGuard::new().unwrap();
    let raw = "[2001:0db8:0000:0000:0000:0000:0000:0001]";
    for operand in [format!("{raw}:8080/"), format!("http://{raw}/")] {
        let verdict = analyze(&format!("curl -sv '{operand}'"));
        let findings = raw_ip_findings(&verdict);
        assert_eq!(findings.len(), 1, "{verdict:?}");
        assert_eq!(findings[0].description, format!("URL host '{raw}' is interpreted as IPv6 address [2001:db8::1] instead of a domain name"));
        assert_raw_evidence(findings[0], raw);
    }
    for raw in [
        "127.0.0.1",
        "2130706433",
        "0x7f000001",
        "0177.0.0.1",
        "[::1]",
        "[::ffff:127.0.0.1]",
    ] {
        let verdict = analyze(&format!("curl -sv 'http://{raw}/'"));
        assert!(raw_ip_findings(&verdict).is_empty(), "{raw}: {verdict:?}");
    }
}

#[test]
fn malformed_percent_userinfo_never_enters_raw_ip_diagnostics() {
    let _state = GlobalStateGuard::new().unwrap();
    let canary = "q7z9canary";
    for userinfo in [
        "user:q7z9canary%",
        "user:q7z9canary%x",
        "user:q7z9canary%%",
        "user%40name:q7z9canary",
    ] {
        for scheme in ["", "//", "https://"] {
            let operand = format!("{scheme}{userinfo}@0x08080808:8080/path");
            let verdict = analyze(&format!("curl '{operand}'"));
            let findings = raw_ip_findings(&verdict);
            assert_eq!(findings.len(), 1, "{operand}: {verdict:?}");
            assert_raw_evidence(findings[0], "0x08080808");
            assert_eq!(findings[0].description, "URL host '0x08080808' is interpreted as IP address 8.8.8.8 instead of a domain name");
            assert!(!serde_json::to_string(findings[0]).unwrap().contains(canary));
            if scheme != "https://" {
                let schemeless = verdict
                    .findings
                    .iter()
                    .find(|finding| finding.rule_id == RuleId::SchemelessToSink)
                    .unwrap();
                let prefix = if scheme == "//" { "//" } else { "" };
                assert_raw_evidence(schemeless, &format!("{prefix}0x08080808:8080/path"));
            }
        }
    }
}

#[test]
fn explicit_curl_non_special_schemes_keep_numeric_ip_detection() {
    let _state = GlobalStateGuard::new().unwrap();
    for scheme in ["sftp", "scp", "ftps", "smtp"] {
        for raw in ["134744072", "0x08080808", "010.010.010.010", "8.526344"] {
            let operand = format!("{scheme}://user:password@{raw}:8022/path");
            let verdict = analyze(&format!("curl '{operand}'"));
            let findings = raw_ip_findings(&verdict);
            assert_eq!(findings.len(), 1, "{operand}: {verdict:?}");
            assert_raw_evidence(findings[0], raw);
            assert_eq!(findings[0].description,
                format!("URL host '{raw}' is interpreted as IP address 8.8.8.8 instead of a domain name"));
            assert!(!serde_json::to_string(findings[0])
                .unwrap()
                .contains("password"));
            assert!(verdict
                .findings
                .iter()
                .all(|finding| finding.rule_id != RuleId::SchemelessToSink));
        }
        let verdict = analyze(&format!("curl '{scheme}://2130706433/path'"));
        assert!(raw_ip_findings(&verdict).is_empty(), "{verdict:?}");
        for domain in ["0x", "0X", "0x.1", "8.0x", "0x7f.0x", "0x.0x.0x.0x"] {
            let verdict = analyze(&format!("curl '{scheme}://{domain}/path'"));
            assert!(raw_ip_findings(&verdict).is_empty(), "{verdict:?}");
        }
    }
}
