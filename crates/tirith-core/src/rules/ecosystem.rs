use once_cell::sync::Lazy;
use regex::Regex;

use crate::parse::UrlLike;
use crate::util::levenshtein;
use crate::verdict::{
    web3_address_evidence, web3_endpoint_evidence, Evidence, Finding, RuleId, Severity,
};

/// Run ecosystem-specific rules.
pub fn check(url: &UrlLike) -> Vec<Finding> {
    check_with_extraction_index(url, None)
}

pub(crate) fn check_with_extraction_index(
    url: &UrlLike,
    extraction_index: Option<usize>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_docker_untrusted_registry(url, &mut findings);
    check_pip_url_install(url, &mut findings);
    check_npm_url_install(url, &mut findings);
    check_web3_rpc(url, extraction_index, &mut findings);
    check_web3_address_in_url(url, extraction_index, &mut findings);
    check_git_typosquat(url, &mut findings);

    findings
}

fn check_docker_untrusted_registry(url: &UrlLike, findings: &mut Vec<Finding>) {
    if let UrlLike::DockerRef {
        registry: Some(reg),
        image,
        ..
    } = url
    {
        let trusted = [
            "docker.io",
            "ghcr.io",
            "gcr.io",
            "quay.io",
            "registry.k8s.io",
            "mcr.microsoft.com",
            "public.ecr.aws",
        ];
        let reg_lower = reg.to_lowercase();
        if !trusted
            .iter()
            .any(|t| reg_lower == *t || reg_lower.ends_with(&format!(".{t}")))
        {
            findings.push(Finding {
                rule_id: RuleId::DockerUntrustedRegistry,
                severity: Severity::Medium,
                title: "Docker image from untrusted registry".to_string(),
                description: format!("Image '{image}' pulled from non-standard registry '{reg}'"),
                evidence: vec![Evidence::Url { raw: url.raw_str() }],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            });
        }
    }
}

fn check_pip_url_install(url: &UrlLike, findings: &mut Vec<Finding>) {
    if let Some(path) = url.path() {
        if path.contains("/simple/") {
            if let Some(host) = url.host() {
                if host != "pypi.org"
                    && host != "files.pythonhosted.org"
                    && !host.ends_with(".pypi.org")
                {
                    findings.push(Finding {
                        rule_id: RuleId::PipUrlInstall,
                        severity: Severity::Medium,
                        title: "Python package from non-PyPI source".to_string(),
                        description: format!("Package URL points to '{host}' instead of PyPI"),
                        evidence: vec![Evidence::Url { raw: url.raw_str() }],
                        human_view: None,
                        agent_view: None,
                        mitre_id: None,
                        custom_rule_id: None,
                    });
                }
            }
        }
    }
}

fn check_npm_url_install(url: &UrlLike, findings: &mut Vec<Finding>) {
    if let Some(path) = url.path() {
        if path.ends_with(".tgz") || path.contains("/npm/") {
            if let Some(host) = url.host() {
                if host != "registry.npmjs.org"
                    && host != "npmjs.com"
                    && !host.ends_with(".npmjs.org")
                {
                    findings.push(Finding {
                        rule_id: RuleId::NpmUrlInstall,
                        severity: Severity::Medium,
                        title: "npm package from non-registry source".to_string(),
                        description: format!(
                            "Package URL points to '{host}' instead of npm registry"
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
    }
}

fn check_web3_rpc(url: &UrlLike, extraction_index: Option<usize>, findings: &mut Vec<Finding>) {
    let Some(endpoint) = crate::sensitive_assets::rpc_endpoint_summary(&url.raw_str()) else {
        return;
    };
    let recognized_path = matches!(
        endpoint.path_class,
        crate::sensitive_assets::RpcPathClass::Rpc
            | crate::sensitive_assets::RpcPathClass::JsonRpc
            | crate::sensitive_assets::RpcPathClass::Versioned
    ) || (endpoint.provider
        == crate::sensitive_assets::RpcProvider::QuickNode
        && endpoint.path_class != crate::sensitive_assets::RpcPathClass::Root);
    let credential_bearing =
        endpoint.credential_class != crate::sensitive_assets::RpcCredentialClass::Public;
    if endpoint.is_hosted_provider() && (recognized_path || credential_bearing) {
        findings.push(Finding {
            rule_id: RuleId::Web3RpcEndpoint,
            severity: Severity::Low,
            title: "Web3 RPC endpoint detected".to_string(),
            description: format!(
                "URL appears to be a Web3 RPC endpoint on provider host '{}'",
                endpoint.host
            ),
            evidence: vec![web3_endpoint_evidence(&endpoint, extraction_index)],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
}

static ETH_ADDRESS_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(?:^|[^0-9a-f])0x[0-9a-f]{40}(?:$|[^0-9a-f])").unwrap());

pub(crate) fn url_contains_web3_address(raw: &str) -> bool {
    ETH_ADDRESS_RE.is_match(raw)
}

fn check_web3_address_in_url(
    url: &UrlLike,
    extraction_index: Option<usize>,
    findings: &mut Vec<Finding>,
) {
    let raw = url.raw_str();
    if url_contains_web3_address(&raw) {
        findings.push(Finding {
            rule_id: RuleId::Web3AddressInUrl,
            severity: Severity::Low,
            title: "Ethereum address found in URL".to_string(),
            description: "URL contains what appears to be an Ethereum wallet address. This may indicate a cryptocurrency-related operation.".to_string(),
            evidence: vec![web3_address_evidence(extraction_index)],
            human_view: None,
            agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
        });
    }
}

fn check_git_typosquat(url: &UrlLike, findings: &mut Vec<Finding>) {
    if let Some(path) = url.path() {
        if let Some(host) = url.host() {
            let host_lower = host.to_lowercase();
            if !(host_lower == "github.com"
                || host_lower == "gitlab.com"
                || host_lower == "bitbucket.org")
            {
                return;
            }
            let segments: Vec<&str> = path
                .trim_start_matches('/')
                .trim_end_matches(".git")
                .split('/')
                .collect();
            if segments.len() >= 2 {
                let owner = segments[0].to_lowercase();
                let repo = segments[1].to_lowercase();
                for &(pop_owner, pop_repo) in crate::data::POPULAR_REPOS {
                    let po = pop_owner.to_lowercase();
                    let pr = pop_repo.to_lowercase();
                    // Single-edit typosquat: one half is one edit off, the other verbatim.
                    if (owner == po && levenshtein(&repo, &pr) == 1)
                        || (repo == pr && levenshtein(&owner, &po) == 1)
                    {
                        findings.push(Finding {
                            rule_id: RuleId::GitTyposquat,
                            severity: Severity::Medium,
                            title: "Possible git repository typosquat".to_string(),
                            description: format!(
                                "Repository '{}/{}' is one edit from popular repo '{}/{}'",
                                segments[0], segments[1], pop_owner, pop_repo
                            ),
                            evidence: vec![Evidence::Url { raw: url.raw_str() }],
                            human_view: None,
                            agent_view: None,
                            mitre_id: None,
                            custom_rule_id: None,
                        });
                        return;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_url;

    fn has_rule(raw: &str, rule: RuleId) -> bool {
        check(&parse_url(raw))
            .iter()
            .any(|finding| finding.rule_id == rule)
    }

    #[test]
    fn web3_rpc_provider_hosts_use_exact_or_dot_suffix_boundaries() {
        for url in [
            "https://infura.io/v3/token",
            "https://mainnet.infura.io/v3/token",
            "https://eth-mainnet.g.alchemy.com/v2/token",
            "https://rpc.chainstack.com/v1/token",
            "https://snowy-white-lake.solana-mainnet.quiknode.pro/token",
            "https://snowy-white-lake.solana-mainnet.quiknode.pro./providerToken123456789",
            "https://node.quicknode.com/anything",
        ] {
            assert!(has_rule(url, RuleId::Web3RpcEndpoint), "{url}");
        }
        for url in [
            "https://evilinfura.io/v3/token",
            "https://infura.io.evil.example/v3/token",
            "https://alchemy.com.evil.example/v2/token",
            "https://example.com/v3/token",
            "https://infura.io/not-v3/token",
        ] {
            assert!(!has_rule(url, RuleId::Web3RpcEndpoint), "{url}");
        }
    }

    #[test]
    fn web3_rpc_rule_and_secret_classifier_share_the_hosted_provider_catalog() {
        let secret = "providerToken123456789";
        for (_suffix, url) in crate::sensitive_assets::hosted_rpc_provider_credential_urls(secret) {
            assert!(has_rule(&url, RuleId::Web3RpcEndpoint), "{url}");
            let summary = crate::sensitive_assets::rpc_endpoint_summary(&url).unwrap();
            assert_ne!(
                summary.credential_class,
                crate::sensitive_assets::RpcCredentialClass::Public,
                "{url}"
            );
        }
    }

    #[test]
    fn web3_address_requires_hex_token_boundaries() {
        let address = "0x1111111111111111111111111111111111111111";
        assert!(has_rule(
            &format!("https://example.com/address/{address}?chain=1"),
            RuleId::Web3AddressInUrl
        ));
        assert!(!has_rule(
            &format!("https://example.com/0{address}"),
            RuleId::Web3AddressInUrl
        ));
        assert!(!has_rule(
            &format!("https://example.com/{address}f"),
            RuleId::Web3AddressInUrl
        ));
    }

    #[test]
    fn web3_rpc_finding_retains_only_typed_secret_free_endpoint_evidence() {
        let address = format!("0x{}", "ab".repeat(20));
        let raw = format!(
            "https://user:pass@mainnet.infura.io/v3/providerToken123456789/{address}?api_key=hunter2#fragment"
        );
        let findings = check(&crate::parse::parse_url(&raw));
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == RuleId::Web3RpcEndpoint)
            .expect("Web3 RPC finding");
        assert!(matches!(
            finding.evidence.as_slice(),
            [Evidence::Text { detail }] if detail.starts_with("tirith:v1:web3_endpoint;")
        ));
        let json = serde_json::to_string(finding).unwrap();
        let debug = format!("{finding:?}");
        for canary in ["user:pass", "providerToken123456789", "hunter2", "fragment"] {
            assert!(!json.contains(canary), "{json}");
            assert!(!debug.contains(canary), "{debug}");
        }
        assert!(json.contains("provider=infura"), "{json}");
        assert!(json.contains("versioned"), "{json}");
        assert!(json.contains("multiple"), "{json}");
        let address_finding = findings
            .iter()
            .find(|finding| finding.rule_id == RuleId::Web3AddressInUrl)
            .expect("Web3 address finding");
        assert!(matches!(
            address_finding.evidence.as_slice(),
            [Evidence::Text { detail }] if detail.starts_with("tirith:v1:web3_address;")
        ));
        let json = serde_json::to_string(address_finding).unwrap();
        assert!(!json.contains(&address), "{json}");
        assert!(!json.contains("providerToken123456789"), "{json}");
    }
}
