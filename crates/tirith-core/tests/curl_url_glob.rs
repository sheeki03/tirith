//! curl expands `[...]` ranges and `{...}` sets in a URL unless `-g` /
//! `--globoff` is given, so a globbed host reaches every host it expands to.
//! Pure extraction/policy tests: no resolver, process launch or transfers.
use tirith_core::extract::{self, ScanContext};
use tirith_core::policy::Policy;
use tirith_core::rules;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::RuleId;

fn command_rules(input: &str) -> Vec<RuleId> {
    rules::command::check(input, ShellType::Posix, None, ScanContext::Exec)
        .into_iter()
        .map(|finding| finding.rule_id)
        .collect()
}

fn denied(input: &str, deny: &[&str], allow: &[&str]) -> Vec<RuleId> {
    let deny: Vec<String> = deny.iter().map(|entry| entry.to_string()).collect();
    let allow: Vec<String> = allow.iter().map(|entry| entry.to_string()).collect();
    rules::command::check_network_policy(input, ShellType::Posix, &deny, &allow)
        .into_iter()
        .map(|finding| finding.rule_id)
        .collect()
}

#[test]
fn globbed_metadata_and_private_hosts_are_checked() {
    for (input, rule) in [
        (
            "curl 'http://169.254.169.[254-254]/latest/meta-data/'",
            RuleId::MetadataEndpoint,
        ),
        (
            "curl 'http://169.254.169.25[4-4]/latest/meta-data/'",
            RuleId::MetadataEndpoint,
        ),
        (
            "curl '169.254.169.[254-254]/latest/meta-data/'",
            RuleId::MetadataEndpoint,
        ),
        (
            "curl -s 'http://100.100.100.[200-200]/latest/meta-data/'",
            RuleId::MetadataEndpoint,
        ),
        (
            "curl 'http://169.254.169.{254,1}/latest/'",
            RuleId::MetadataEndpoint,
        ),
        (
            "curl 'http://{169.254.169.254,example.com}/latest/'",
            RuleId::MetadataEndpoint,
        ),
        (
            "curl --url 'http://{example.com,169.254.169.254}/x'",
            RuleId::MetadataEndpoint,
        ),
        (
            "curl --url='http://169.254.169.[250-254:2]/x'",
            RuleId::MetadataEndpoint,
        ),
        (
            "curl 'http://10.0.0.[1-5]/admin'",
            RuleId::PrivateNetworkAccess,
        ),
        (
            "curl 'http://{10.0.0.1,10.0.0.2}/admin'",
            RuleId::PrivateNetworkAccess,
        ),
        (
            "curl '{http,https}://192.168.0.[01-10]/'",
            RuleId::PrivateNetworkAccess,
        ),
        (
            "curl 'http://172.[16-16].0.1:8080/'",
            RuleId::PrivateNetworkAccess,
        ),
    ] {
        assert!(
            command_rules(input).contains(&rule),
            "{input}: {:?}",
            command_rules(input)
        );
    }
}

#[test]
fn globbed_hosts_reach_the_url_rules() {
    let urls = extract::extract_urls(
        "curl 'http://169.254.169.[254-254]/latest/meta-data/'",
        ShellType::Posix,
    );
    let hosts: Vec<_> = urls.iter().filter_map(|url| url.parsed.host()).collect();
    assert!(hosts.contains(&"169.254.169.254"), "{urls:?}");
    let raw_ip = urls.iter().any(|url| {
        rules::hostname::check(&url.parsed, &Policy::default())
            .iter()
            .any(|finding| finding.rule_id == RuleId::RawIpUrl)
    });
    assert!(raw_ip, "{urls:?}");

    let urls = extract::extract_urls(
        "curl 'https://{evil-domain.example,www.example.com}/x'",
        ShellType::Posix,
    );
    let hosts: Vec<_> = urls.iter().filter_map(|url| url.parsed.host()).collect();
    assert!(hosts.contains(&"evil-domain.example"), "{urls:?}");
    assert!(hosts.contains(&"www.example.com"), "{urls:?}");
}

#[test]
fn network_deny_matches_any_globbed_host_and_allow_must_cover_all() {
    let deny = ["10.0.0.0/8", "blocked.example"];
    for input in [
        "curl 'https://10.0.0.[5-5]/admin'",
        "curl 'https://blocked.exampl[e-e]/x'",
        "curl 'https://{blocked.example,x}/x'",
        "curl --url 'https://{blocked.example,x}/x'",
        "curl --url='https://{x,10.0.0.9}/x'",
        "curl 'https://{allowed.example,blocked.example}/x'",
    ] {
        assert!(
            denied(input, &deny, &["allowed.example"]).contains(&RuleId::CommandNetworkDeny),
            "{input}"
        );
    }
    // Every expansion allowed: the operand is allowed.
    assert!(denied(
        "curl 'https://{blocked.example,10.0.0.1}/x'",
        &deny,
        &["blocked.example", "10.0.0.1"]
    )
    .is_empty());
    // Plain spellings keep their verdicts.
    assert!(denied("curl https://10.0.0.5/admin", &deny, &[]).contains(&RuleId::CommandNetworkDeny));
    assert!(denied("curl https://example.com/x", &deny, &[]).is_empty());
}

#[test]
fn globbing_off_reads_the_operand_literally() {
    for input in [
        "curl -g 'http://169.254.169.[254-254]/latest/meta-data/'",
        "curl --globoff 'http://169.254.169.[254-254]/latest/meta-data/'",
        "curl -sg 'http://169.254.169.[254-254]/latest/meta-data/'",
        "curl 'http://169.254.169.[254-254]/latest/meta-data/' -g",
    ] {
        let rules = command_rules(input);
        assert!(
            !rules.contains(&RuleId::MetadataEndpoint),
            "{input}: {rules:?}"
        );
        assert!(
            !rules.contains(&RuleId::AnalysisIncomplete),
            "{input}: {rules:?}"
        );
        assert!(
            denied(input, &["169.254.0.0/16"], &[]).is_empty(),
            "{input}"
        );
    }
    // `--no-globoff` turns globbing back on; `-g` as an option's value does not
    // turn it off.
    for input in [
        "curl -g --no-globoff 'http://169.254.169.[254-254]/x'",
        "curl -H -g 'http://169.254.169.[254-254]/x'",
        "curl -og 'http://169.254.169.[254-254]/x'",
    ] {
        assert!(
            command_rules(input).contains(&RuleId::MetadataEndpoint),
            "{input}: {:?}",
            command_rules(input)
        );
    }
}

#[test]
fn globs_curl_reads_as_text_or_after_the_host_change_nothing() {
    for input in [
        "curl 'http://[::1]:8080/x'",
        "curl 'http://example.com/a[1-3].txt'",
        "curl 'http://example.com/{a,b}/x'",
        "curl 'http://example.com/x?filter[name]=1'",
        "curl 'http://example.com/\\[1-2\\]'",
    ] {
        let rules = command_rules(input);
        assert!(
            !rules.contains(&RuleId::AnalysisIncomplete)
                && !rules.contains(&RuleId::MetadataEndpoint)
                && !rules.contains(&RuleId::PrivateNetworkAccess),
            "{input}: {rules:?}"
        );
    }
}

#[test]
fn host_globs_too_large_or_unreadable_fail_closed() {
    for input in [
        "curl 'http://10.[0-255].[0-255].1/'",
        "curl 'http://host[1-100].example:[8000-8010]/'",
        "curl 'http://{a,{b,c}}.example/'",
        "curl 'http://host[1-].example/'",
        "curl 'http://host}.example/'",
    ] {
        let rules = command_rules(input);
        assert!(
            rules.contains(&RuleId::AnalysisIncomplete),
            "{input}: {rules:?}"
        );
        assert!(
            denied(input, &["blocked.example"], &[]).contains(&RuleId::AnalysisIncomplete),
            "{input}"
        );
    }

    // Many globbed operands share one budget per command.
    let many = format!("curl {}", vec!["'http://h[1-64].example/'"; 20].join(" "));
    assert!(command_rules(&many).contains(&RuleId::AnalysisIncomplete));
    assert!(denied(&many, &["blocked.example"], &[]).contains(&RuleId::AnalysisIncomplete));
    let few = format!("curl {}", vec!["'http://h[1-64].example/'"; 16].join(" "));
    assert!(!command_rules(&few).contains(&RuleId::AnalysisIncomplete));
}

#[test]
fn an_unreadable_operand_does_not_hide_a_later_denied_one() {
    // The deny check goes on past an operand whose host glob tirith cannot
    // read, in the same command and in later commands.
    for input in [
        "curl 'https://{{x}}/a' https://blocked.example/x",
        "curl 'https://{{x}}/a'; curl https://blocked.example/x",
        "curl 'https://h[10-99].github.com/' https://blocked.example/x",
        "curl 'https://h[10-99].github.com/'; curl https://blocked.example/x",
        "curl 'https://h{a,b,c,d,e,f,g,h}{a,b,c,d,e,f,g,h}{a,b}.github.com/' https://blocked.example/x",
    ] {
        let rules = denied(input, &["blocked.example"], &["github.com"]);
        assert!(
            rules.contains(&RuleId::CommandNetworkDeny),
            "{input}: {rules:?}"
        );
        assert!(
            rules.contains(&RuleId::AnalysisIncomplete),
            "{input}: {rules:?}"
        );
    }
}

#[test]
fn shell_expansions_in_an_operand_are_not_curl_globs() {
    // The shell replaces these before curl runs (written out, curl would
    // reject them), so they are not unreadable host globs.
    for input in [
        "curl \"${URLS[@]}\"",
        "curl -fsS \"http://${NODES[$i]}:9200/_cluster/health\"",
        "curl \"https://${HOSTS[0]}/health\"",
        "curl -sS \"${API[base]}/v1/status\"",
        "curl \"$hosts[1]/x\"",
        "curl \"http://10.0.0.$[i+1]/\"",
        "curl \"http://${x/[a-z]/y}/\"",
    ] {
        let rules = command_rules(input);
        assert!(
            !rules.contains(&RuleId::AnalysisIncomplete),
            "{input}: {rules:?}"
        );
        assert!(
            denied(input, &["blocked.example"], &[]).is_empty(),
            "{input}"
        );
    }
    // A curl glob beside shell text is still expanded.
    let input = "curl \"http://${CRED[0]}@{169.254.169.254,example.com}/latest/\"";
    assert!(
        command_rules(input).contains(&RuleId::MetadataEndpoint),
        "{input}: {:?}",
        command_rules(input)
    );
    let input = "curl \"https://${CRED[0]}@{blocked.example,x}/x\"";
    assert!(denied(input, &["blocked.example"], &[]).contains(&RuleId::CommandNetworkDeny));
    // `$` text curl reads as written keeps curl's reading (single quotes).
    let input = "curl 'http://${x@,}169.254.169.254/latest/'";
    assert!(command_rules(input).contains(&RuleId::MetadataEndpoint));
    // With `x` unset, the shells pass `{169.254.169.254,a}` to curl.
    let input = "curl \"http://${x:-{169.254.169.254,a}}/latest/\"";
    assert!(command_rules(input).contains(&RuleId::AnalysisIncomplete));
}

#[test]
fn a_glob_that_completes_the_scheme_separator_reaches_its_host() {
    // curl takes one to three slashes after `scheme:`.
    for (input, rule) in [
        (
            "curl 'http:/{/169.254.169.254,}/latest/meta-data/'",
            RuleId::MetadataEndpoint,
        ),
        (
            "curl 'http:/{/169.254.169.254}/x'",
            RuleId::MetadataEndpoint,
        ),
        (
            "curl 'http:///{169.254.169.254,x}/latest/'",
            RuleId::MetadataEndpoint,
        ),
        (
            "curl 'http:/{/10.0.0.1,}/admin'",
            RuleId::PrivateNetworkAccess,
        ),
        (
            "curl 'http:/{/,}h[1-65].example/'",
            RuleId::AnalysisIncomplete,
        ),
    ] {
        assert!(
            command_rules(input).contains(&rule),
            "{input}: {:?}",
            command_rules(input)
        );
    }
    for input in [
        "curl 'https:/{/blocked.example,}/x'",
        "curl 'https:///{blocked.example,x}/x'",
    ] {
        assert!(
            denied(input, &["blocked.example"], &[]).contains(&RuleId::CommandNetworkDeny),
            "{input}"
        );
    }
    // Globs after a schemeless host are still path globs.
    for input in [
        "curl 'example.com/a[1-100].txt'",
        "curl '{a,b}.example.com/[1-100].txt'",
    ] {
        let rules = command_rules(input);
        assert!(
            !rules.contains(&RuleId::AnalysisIncomplete),
            "{input}: {rules:?}"
        );
    }
}

#[test]
fn wrapped_curl_globs_are_read_like_direct_ones() {
    for input in [
        "sudo curl 'http://169.254.169.[0-255]/latest/meta-data/'",
        "env curl 'http://169.254.169.[0-255]/latest/meta-data/'",
        "nohup curl 'http://169.254.169.[0-255]/latest/meta-data/'",
        "command curl 'http://169.254.169.[0-255]/latest/meta-data/'",
    ] {
        let rules = command_rules(input);
        assert!(
            rules.contains(&RuleId::AnalysisIncomplete),
            "{input}: {rules:?}"
        );
    }
    for (input, rule) in [
        (
            "sudo curl 'http://169.254.169.[254-254]/latest/'",
            RuleId::MetadataEndpoint,
        ),
        (
            "env curl 'http://10.0.0.[1-2]/admin'",
            RuleId::PrivateNetworkAccess,
        ),
        ("sudo curl https://10.0.0.1/", RuleId::PrivateNetworkAccess),
        (
            "sudo curl http://169.254.169.254/latest/meta-data/",
            RuleId::MetadataEndpoint,
        ),
    ] {
        assert!(
            command_rules(input).contains(&rule),
            "{input}: {:?}",
            command_rules(input)
        );
    }
    let input = "sudo curl -g 'http://169.254.169.[0-255]/latest/meta-data/'";
    assert!(!command_rules(input).contains(&RuleId::AnalysisIncomplete));
}
