use once_cell::sync::Lazy;
use regex::Regex;

use crate::parse::UrlLike;
use crate::util::levenshtein;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Run ecosystem-specific rules.
pub fn check(url: &UrlLike) -> Vec<Finding> {
    let mut findings = Vec::new();

    check_docker_untrusted_registry(url, &mut findings);
    check_pip_url_install(url, &mut findings);
    check_npm_url_install(url, &mut findings);
    check_web3_rpc(url, &mut findings);
    check_web3_address_in_url(url, &mut findings);
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
                    });
                }
            }
        }
    }
}

fn check_web3_rpc(url: &UrlLike, findings: &mut Vec<Finding>) {
    if let Some(path) = url.path() {
        if path.contains("/v1/") || path.contains("/rpc") || path.contains("/jsonrpc") {
            if let Some(host) = url.host() {
                let web3_indicators = [
                    "infura.io",
                    "alchemy.com",
                    "moralis.io",
                    "chainstack.com",
                    "getblock.io",
                ];
                if web3_indicators.iter().any(|ind| host.contains(ind)) {
                    findings.push(Finding {
                        rule_id: RuleId::Web3RpcEndpoint,
                        severity: Severity::Low,
                        title: "Web3 RPC endpoint detected".to_string(),
                        description: format!("URL appears to be a Web3 RPC endpoint on '{host}'"),
                        evidence: vec![Evidence::Url { raw: url.raw_str() }],
                    });
                }
            }
        }
    }
}

static ETH_ADDRESS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"0x[0-9a-fA-F]{40}").unwrap());

fn check_web3_address_in_url(url: &UrlLike, findings: &mut Vec<Finding>) {
    let raw = url.raw_str();
    if ETH_ADDRESS_RE.is_match(&raw) {
        findings.push(Finding {
            rule_id: RuleId::Web3AddressInUrl,
            severity: Severity::Low,
            title: "Ethereum address found in URL".to_string(),
            description: "URL contains what appears to be an Ethereum wallet address. This may indicate a cryptocurrency-related operation.".to_string(),
            evidence: vec![Evidence::Url { raw }],
        });
    }
}

fn check_git_typosquat(url: &UrlLike, findings: &mut Vec<Finding>) {
    // Check if a git clone URL references a popular repo with a typosquatted name
    if let Some(path) = url.path() {
        if let Some(host) = url.host() {
            let host_lower = host.to_lowercase();
            // Only check on known git hosting platforms
            if !(host_lower == "github.com"
                || host_lower == "gitlab.com"
                || host_lower == "bitbucket.org")
            {
                return;
            }
            // Extract owner/repo from path like /owner/repo or /owner/repo.git
            let segments: Vec<&str> = path
                .trim_start_matches('/')
                .trim_end_matches(".git")
                .split('/')
                .collect();
            if segments.len() >= 2 {
                let owner = segments[0].to_lowercase();
                let repo = segments[1].to_lowercase();
                // Check against popular repos
                for &(pop_owner, pop_repo) in crate::data::POPULAR_REPOS {
                    let po = pop_owner.to_lowercase();
                    let pr = pop_repo.to_lowercase();
                    // Check if either owner or repo is within edit distance 1
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
                        });
                        return;
                    }
                }
            }
        }
    }
}
