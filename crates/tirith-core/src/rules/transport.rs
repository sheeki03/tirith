use crate::parse::UrlLike;
use crate::rules::shared::is_loopback_host;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Run transport rules against a parsed URL.
pub fn check(url: &UrlLike, in_sink_context: bool) -> Vec<Finding> {
    check_with_raw_url(url, in_sink_context, None)
}

/// Use the extracted operand for schemeless evidence; raw_str() reconstructs
/// this variant from its normalized host and can otherwise hide numeric syntax.
pub(crate) fn check_with_raw_url(
    url: &UrlLike,
    in_sink_context: bool,
    raw_url: Option<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_plain_http_to_sink(url, in_sink_context, &mut findings);
    check_shortened_url(url, &mut findings);

    if matches!(url, UrlLike::SchemelessHostPath { .. }) && in_sink_context {
        findings.push(Finding {
            rule_id: RuleId::SchemelessToSink,
            severity: Severity::Medium,
            title: "Schemeless URL in sink context".to_string(),
            description:
                "URL without explicit scheme passed to a command that downloads/executes content"
                    .to_string(),
            evidence: vec![Evidence::Url {
                raw: raw_url
                    .map(schemeless_evidence)
                    .unwrap_or_else(|| url.raw_str()),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }

    findings
}

// Keep the original destination spelling without introducing userinfo that the
// previous host+path evidence omitted. Query/path text was already retained.
fn schemeless_evidence(raw: &str) -> String {
    let authority_start = if raw.starts_with("//") { 2 } else { 0 };
    let tail_start = raw[authority_start..]
        .find(['/', '?', '#'])
        .map(|offset| authority_start + offset)
        .unwrap_or(raw.len());
    match raw[authority_start..tail_start].rfind('@') {
        Some(at) => format!(
            "{}{}",
            &raw[..authority_start],
            &raw[authority_start + at + 1..]
        ),
        None => raw.to_string(),
    }
}

fn check_plain_http_to_sink(url: &UrlLike, in_sink: bool, findings: &mut Vec<Finding>) {
    if let Some(scheme) = url.scheme() {
        if scheme == "http" && in_sink {
            // Loopback traffic never leaves the machine — no MITM risk.
            if let Some(host) = url.host() {
                if is_loopback_host(host) {
                    return;
                }
            }
            findings.push(Finding {
                rule_id: RuleId::PlainHttpToSink,
                severity: Severity::High,
                title: "Plain HTTP URL in execution context".to_string(),
                description: format!(
                    "URL '{}' uses unencrypted HTTP and is being passed to a command that downloads or executes content. An attacker on the network could modify the content.",
                    url.raw_str()
                ),
                evidence: vec![Evidence::Url { raw: url.raw_str() }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }
}

fn check_shortened_url(url: &UrlLike, findings: &mut Vec<Finding>) {
    if let Some(host) = url.host() {
        if crate::rules::shared::is_url_shortener(host) {
            findings.push(Finding {
                rule_id: RuleId::ShortenedUrl,
                severity: Severity::Medium,
                title: "Shortened URL detected".to_string(),
                description: format!(
                    "URL uses shortener '{host}' which hides the actual destination"
                ),
                evidence: vec![Evidence::Url { raw: url.raw_str() }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }
}

fn strip_quotes_simple(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Check command arguments for insecure TLS flags according to the resolved
/// client's option grammar. In particular, curl permits boolean short options
/// to be clustered, but the remainder of a cluster becomes data as soon as an
/// option that consumes a value is reached.
pub fn check_insecure_flags(client: &str, args: &[String], in_sink: bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut options_ended = false;
    let mut value_consumed = false;

    for arg in args {
        let clean = strip_quotes_simple(arg);
        if options_ended {
            continue;
        }
        if value_consumed {
            value_consumed = false;
            continue;
        }
        if clean == "--" {
            options_ended = true;
            continue;
        }

        let disables_verification = if client.eq_ignore_ascii_case("curl") {
            let short_options = scan_curl_short_options(&clean);
            value_consumed = short_options.consumes_next;
            clean == "--insecure" || short_options.enables_insecure
        } else if client.eq_ignore_ascii_case("wget") {
            clean == "--no-check-certificate"
        } else {
            false
        };
        if disables_verification {
            let severity = if in_sink {
                Severity::High
            } else {
                Severity::Medium
            };
            findings.push(Finding {
                rule_id: RuleId::InsecureTlsFlags,
                severity,
                title: "Insecure TLS flag detected".to_string(),
                description: format!(
                    "Flag '{arg}' disables TLS certificate verification, allowing MITM attacks"
                ),
                evidence: vec![Evidence::CommandPattern {
                    pattern: "insecure TLS flag".to_string(),
                    matched: arg.to_string(),
                }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }

    findings
}

#[derive(Default)]
struct CurlShortOptionScan {
    enables_insecure: bool,
    consumes_next: bool,
}

// curl's documented short options are partitioned by whether they consume a
// value. Only options in these lists are valid cluster members. Source: the
// curl online man page's current option table (https://curl.se/docs/manpage.html).
const CURL_BOOLEAN_SHORT_OPTIONS: &[char] = &[
    '#', '0', '1', '2', '3', '4', '6', ':', 'B', 'G', 'I', 'J', 'L', 'M', 'N', 'O', 'R', 'S', 'V',
    'Z', 'a', 'f', 'g', 'i', 'j', 'k', 'l', 'n', 'p', 'q', 's', 'v',
];

const CURL_VALUE_SHORT_OPTIONS: &[char] = &[
    'A', 'b', 'c', 'C', 'd', 'D', 'e', 'E', 'F', 'H', 'h', 'K', 'm', 'o', 'P', 'Q', 'r', 't', 'T',
    'u', 'U', 'w', 'x', 'X', 'y', 'Y', 'z',
];

fn scan_curl_short_options(argument: &str) -> CurlShortOptionScan {
    if !argument.starts_with('-') || argument.starts_with("--") || argument.len() < 2 {
        return CurlShortOptionScan::default();
    }

    let mut scan = CurlShortOptionScan::default();
    let mut options = argument[1..].chars().peekable();
    while let Some(option) = options.next() {
        if CURL_BOOLEAN_SHORT_OPTIONS.contains(&option) {
            scan.enables_insecure |= option == 'k';
            continue;
        }
        if CURL_VALUE_SHORT_OPTIONS.contains(&option) {
            // Any remaining bytes are this option's attached value, not more
            // options. Without an attached value, the next argv item is data.
            scan.consumes_next = options.peek().is_none();
            break;
        }

        // curl rejects unknown short options. Discard any earlier `-k` from
        // this invalid cluster because curl would fail before making a request.
        return CurlShortOptionScan::default();
    }
    scan
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schemeless_evidence_preserves_destination_without_credentials() {
        for raw in [
            "user:password@0x08080808:8080/path?x=1",
            "user%40name:password@0x08080808:8080/path?x=1",
        ] {
            assert_eq!(schemeless_evidence(raw), "0x08080808:8080/path?x=1");
            assert_eq!(
                schemeless_evidence(&format!("//{raw}")),
                "//0x08080808:8080/path?x=1"
            );
        }
        assert_eq!(schemeless_evidence("8080"), "8080");
        assert_eq!(schemeless_evidence("8080/path@name"), "8080/path@name");
    }

    #[test]
    fn test_quoted_insecure_flags() {
        let args = vec!["\"-k\"".to_string(), "https://example.com".to_string()];
        let findings = check_insecure_flags("curl", &args, true);
        assert!(!findings.is_empty(), "should detect -k even when quoted");
    }

    #[test]
    fn test_single_quoted_insecure_flags() {
        let args = vec!["'-k'".to_string()];
        let findings = check_insecure_flags("curl", &args, true);
        assert!(
            !findings.is_empty(),
            "should detect -k even when single-quoted"
        );
    }

    #[test]
    fn test_unquoted_insecure_flags_still_work() {
        let args = vec!["-k".to_string()];
        let findings = check_insecure_flags("curl", &args, true);
        assert!(!findings.is_empty());
    }

    #[test]
    fn curl_boolean_short_option_clusters_detect_insecure() {
        for cluster in ["-skL", "-Lvk", "-ksS"] {
            let findings = check_insecure_flags("curl", &[cluster.to_string()], true);
            assert_eq!(findings.len(), 1, "cluster should enable -k: {cluster}");
            assert_eq!(findings[0].rule_id, RuleId::InsecureTlsFlags);
            assert_eq!(findings[0].severity, Severity::High);
        }
    }

    #[test]
    fn curl_insecure_is_detected_around_every_boolean_short_option() {
        for option in CURL_BOOLEAN_SHORT_OPTIONS {
            for cluster in [format!("-{option}k"), format!("-k{option}")] {
                let findings = check_insecure_flags("curl", std::slice::from_ref(&cluster), true);
                assert_eq!(
                    findings.len(),
                    1,
                    "documented boolean cluster should enable -k: {cluster}"
                );
                assert_eq!(findings[0].rule_id, RuleId::InsecureTlsFlags);
                assert_eq!(findings[0].severity, Severity::High);
            }
        }
    }

    #[test]
    fn curl_unknown_short_options_invalidate_the_entire_cluster() {
        for unknown in ['W', '!', '@', '='] {
            for argument in [
                format!("-{unknown}k"),
                format!("-k{unknown}"),
                format!("-s{unknown}k"),
                format!("-ks{unknown}"),
            ] {
                let findings = check_insecure_flags("curl", std::slice::from_ref(&argument), true);
                assert!(
                    findings.is_empty(),
                    "invalid curl cluster must not elevate: {argument}"
                );
            }
        }
    }

    #[test]
    fn curl_attached_values_are_not_reparsed_as_short_options() {
        for argument in ["-ok", "-Ask", "-dkey=k", "-Xk", "-Kconfig-k", "-Hk"] {
            let findings = check_insecure_flags("curl", &[argument.to_string()], true);
            assert!(
                findings.is_empty(),
                "attached value must not be parsed as a -k flag: {argument}"
            );
        }
    }

    #[test]
    fn every_curl_value_short_option_stops_cluster_parsing() {
        for option in CURL_VALUE_SHORT_OPTIONS {
            let attached_k_value = format!("-{option}k");
            assert!(
                check_insecure_flags("curl", std::slice::from_ref(&attached_k_value), true)
                    .is_empty(),
                "attached value must not be reparsed as -k: {attached_k_value}"
            );

            let separate_value = vec![format!("-{option}"), "-k".to_string()];
            assert!(
                check_insecure_flags("curl", &separate_value, true).is_empty(),
                "separate value must not be reparsed as -k: {separate_value:?}"
            );

            let attached_value_then_insecure = vec![format!("-{option}value"), "-k".to_string()];
            assert_eq!(
                check_insecure_flags("curl", &attached_value_then_insecure, true).len(),
                1,
                "an attached value must leave the following -k active: {attached_value_then_insecure:?}"
            );

            let insecure_before_value = vec![format!("-k{option}"), "-k".to_string()];
            assert_eq!(
                check_insecure_flags("curl", &insecure_before_value, true).len(),
                1,
                "-k before a value option must be detected while its next argv remains data: {insecure_before_value:?}"
            );
        }
    }

    #[test]
    fn curl_separate_short_option_values_are_not_reparsed_as_flags() {
        for args in [
            vec!["-o".to_string(), "-k".to_string()],
            vec!["-sH".to_string(), "-k".to_string()],
        ] {
            let findings = check_insecure_flags("curl", &args, true);
            assert!(
                findings.is_empty(),
                "separate option value must not be parsed as -k: {args:?}"
            );
        }

        let attached_value_then_real_flag = vec!["-Hheader".to_string(), "-k".to_string()];
        assert_eq!(
            check_insecure_flags("curl", &attached_value_then_real_flag, true).len(),
            1,
            "an attached value must not consume the following real option"
        );
    }

    #[test]
    fn option_terminator_and_non_curl_clusters_do_not_enable_insecure() {
        let after_terminator = vec!["--".to_string(), "-k".to_string()];
        assert!(check_insecure_flags("curl", &after_terminator, true).is_empty());
        assert!(check_insecure_flags("wget", &["-skL".to_string()], true).is_empty());
        assert!(check_insecure_flags("scp", &["--insecure".to_string()], true).is_empty());
    }

    #[test]
    fn wrapped_curl_cluster_uses_resolved_client_grammar() {
        for (command, shell) in [
            (
                "env MODE=safe curl -skL https://example.com/archive.tgz",
                crate::tokenize::ShellType::Posix,
            ),
            (
                r"C:\Windows\System32\curl.exe -skL https://example.com/archive.tgz",
                crate::tokenize::ShellType::PowerShell,
            ),
        ] {
            let findings = crate::rules::command::check(
                command,
                shell,
                None,
                crate::extract::ScanContext::Exec,
            );
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule_id == RuleId::InsecureTlsFlags),
                "resolved curl cluster should be blocked: {command}: {findings:?}"
            );
        }
    }

    #[test]
    fn plain_http_loopback_suppressed_regardless_of_host_casing() {
        // PlainHttpToSink must NOT fire for a loopback host in sink context. The
        // url crate already lowercases the host of a Standard http URL, but the
        // suppression now relies on is_loopback_host being case-insensitive
        // internally, so this holds for any input casing of the loopback name.
        for raw in [
            "http://localhost:3000/x",
            "http://LOCALHOST:3000/x",
            "http://Localhost/y",
            "http://127.0.0.1/a",
            "http://app.LocalHost/b",
        ] {
            let url = crate::parse::parse_url(raw);
            let findings = check(&url, true);
            assert!(
                !findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::PlainHttpToSink),
                "PlainHttpToSink should be suppressed for loopback host: {raw}"
            );
        }
        // A genuine remote http host in sink context still fires.
        let remote = crate::parse::parse_url("http://evil.example/x");
        assert!(
            check(&remote, true)
                .iter()
                .any(|f| f.rule_id == RuleId::PlainHttpToSink),
            "PlainHttpToSink should fire for a remote http host"
        );
    }
}
