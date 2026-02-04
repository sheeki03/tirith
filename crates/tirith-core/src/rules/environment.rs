use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Trait for environment variable access (enables deterministic testing).
pub trait EnvSnapshot {
    fn get(&self, key: &str) -> Option<String>;
}

/// Real environment implementation.
pub struct RealEnv;

impl EnvSnapshot for RealEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

/// Test environment implementation.
#[cfg(test)]
pub struct TestEnv {
    pub vars: std::collections::HashMap<String, String>,
}

#[cfg(test)]
impl EnvSnapshot for TestEnv {
    fn get(&self, key: &str) -> Option<String> {
        self.vars.get(key).cloned()
    }
}

/// Check environment variables for proxy settings.
pub fn check(env: &dyn EnvSnapshot) -> Vec<Finding> {
    let mut findings = Vec::new();

    let proxy_vars = [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ];

    for var in &proxy_vars {
        if let Some(val) = env.get(var) {
            if !val.is_empty() {
                findings.push(Finding {
                    rule_id: RuleId::ProxyEnvSet,
                    severity: Severity::Low,
                    title: format!("Proxy environment variable {var} is set"),
                    description: format!(
                        "Environment variable {} is set to '{}'. Traffic may be intercepted by the proxy.",
                        var,
                        redact_value(&val)
                    ),
                    evidence: vec![Evidence::EnvVar {
                        name: var.to_string(),
                        value_preview: redact_value(&val),
                    }],
                });
            }
        }
    }

    findings
}

fn redact_value(val: &str) -> String {
    let prefix = crate::util::truncate_bytes(val, 20);
    if prefix.len() == val.len() {
        val.to_string()
    } else {
        format!("{prefix}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_proxy() {
        let env = TestEnv {
            vars: std::collections::HashMap::new(),
        };
        let findings = check(&env);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_http_proxy_set() {
        let mut vars = std::collections::HashMap::new();
        vars.insert(
            "HTTP_PROXY".to_string(),
            "http://proxy.corp:8080".to_string(),
        );
        let env = TestEnv { vars };
        let findings = check(&env);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, RuleId::ProxyEnvSet);
    }
}
