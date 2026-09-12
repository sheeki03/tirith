//! One policy resolution for enforcement and diagnostic consumers.
//!
//! A runtime snapshot includes the same overlays, in the same order, as the
//! engine. It is a read of current policy, not an execution permit or a
//! revision-bound change plan. Remote discovery may fetch and refresh its cache.

use crate::policy::Policy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionMode {
    Runtime,
    /// Compatibility diagnostic: no remote request and no separate list,
    /// trust, or context-label files. Runtime incident restrictions still apply.
    LocalOnly,
}

/// Deliberately not serializable: policy contains credentials. Output consumers
/// must construct a redacted display projection, keeping protocol fields intact.
#[derive(Debug, Clone)]
pub struct EffectivePolicySnapshot {
    pub policy: Policy,
    pub resolution_mode: ResolutionMode,
    /// Existing non-secret enforcement-posture digest. This is not an input
    /// revision: it cannot detect all file, credential, or freshness changes.
    pub policy_posture_sha256: String,
}

impl EffectivePolicySnapshot {
    pub fn resolve(cwd: Option<&str>, mode: ResolutionMode) -> Self {
        let policy = match mode {
            ResolutionMode::Runtime => resolve_runtime_policy(cwd),
            ResolutionMode::LocalOnly => Policy::discover_local_only(cwd),
        };
        let policy_posture_sha256 = policy.enforcement_projection_hash();
        Self {
            policy,
            resolution_mode: mode,
            policy_posture_sha256,
        }
    }
}

/// The engine and runtime diagnostics share this exact sequence. Keep digest
/// generation and display serialization out of the command hot path.
pub(crate) fn resolve_runtime_policy(cwd: Option<&str>) -> Policy {
    let mut policy = Policy::discover(cwd);
    policy.load_user_lists();
    policy.load_org_lists(cwd);
    policy.load_trust_entries(cwd);
    policy.load_context_labels(cwd);
    policy.load_ssh_host_labels(cwd);
    policy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FailMode, PolicyScope};
    use tirith_test_support::GlobalStateGuard;

    #[test]
    fn runtime_includes_overlays_and_preserves_repository_tightening() {
        let state = GlobalStateGuard::new().unwrap();
        let root = state.roots().policy.join(".tirith");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("policy.yaml"), "allow_bypass_env: true\n").unwrap();
        let cwd = &state.roots().cwd;
        std::fs::create_dir_all(cwd.join(".git")).unwrap();
        std::fs::create_dir_all(cwd.join(".tirith")).unwrap();
        std::fs::write(
            cwd.join(".tirith/policy.yaml"),
            "allow_bypass_env: true\nallowlist: [hostile.example]\n",
        )
        .unwrap();
        std::fs::write(cwd.join(".tirith/allowlist"), "also-hostile.example\n").unwrap();
        std::fs::write(cwd.join(".tirith/blocklist"), "blocked.example\n").unwrap();
        std::fs::write(
            cwd.join(".tirith/context-labels.yaml"),
            "production: critical\n",
        )
        .unwrap();
        std::fs::write(
            cwd.join(".tirith/ssh-host-labels.yaml"),
            "host: production\n",
        )
        .unwrap();
        let config = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("allowlist"), "user.example\n").unwrap();
        std::fs::write(config.join("blocklist"), "user-blocked.example\n").unwrap();
        std::fs::write(
            config.join("trust.json"),
            r#"{"version":1,"entries":[
                {"pattern":"trusted.example","rule_id":"shortened_url"},
                {"pattern":"expired.example","ttl_expires":"2000-01-01T00:00:00Z"}
            ]}"#,
        )
        .unwrap();

        let snapshot = EffectivePolicySnapshot::resolve(cwd.to_str(), ResolutionMode::Runtime);
        let policy = &snapshot.policy;
        assert_eq!(policy.scope, PolicyScope::Org);
        assert_eq!(policy.path.as_deref(), root.join("policy.yaml").to_str());
        assert!(!policy.allow_bypass_env);
        assert!(policy.neutralized_fields.contains(&"allowlist"));
        assert_eq!(policy.allowlist, ["user.example"]);
        assert!(policy.is_blocklisted("blocked.example"));
        assert!(policy.is_blocklisted("user-blocked.example"));
        assert!(policy.is_allowlisted_for_rule("shortened_url", "trusted.example"));
        assert_eq!(policy.context_labels.get("production").unwrap(), "critical");
        assert_eq!(policy.ssh_host_labels.get("host").unwrap(), "production");
        assert_eq!(
            snapshot.policy_posture_sha256,
            policy.enforcement_projection_hash()
        );
    }

    #[test]
    fn offline_diagnostic_does_not_query_remote_or_claim_list_overlays() {
        let mut state = GlobalStateGuard::new().unwrap();
        // HTTP is refused before opening a socket. Runtime resolution must
        // select fail-closed; the offline diagnostic must never take this path.
        state.set_env("TIRITH_SERVER_URL", "http://127.0.0.1:1");
        state.set_env("TIRITH_API_KEY", "fixture-key");
        std::fs::create_dir_all(state.roots().policy.join(".tirith")).unwrap();
        std::fs::write(
            state.roots().policy.join(".tirith/policy.yaml"),
            "fail_mode: open\npolicy_fetch_fail_mode: closed\n",
        )
        .unwrap();
        let config = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("blocklist"), "overlay.example\n").unwrap();

        let offline = EffectivePolicySnapshot::resolve(None, ResolutionMode::LocalOnly);
        assert_eq!(offline.policy.fail_mode, FailMode::Open);
        assert!(!offline.policy.is_blocklisted("overlay.example"));
        let runtime = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert_eq!(runtime.policy.fail_mode, FailMode::Closed);
        assert!(runtime
            .policy
            .custom_rules
            .iter()
            .any(|rule| rule.id == "tirith-effective-policy-unavailable"));
        assert!(runtime.policy.is_blocklisted("overlay.example"));
    }

    #[test]
    fn snapshot_is_not_reloaded_after_a_policy_edit() {
        let state = GlobalStateGuard::new().unwrap();
        std::fs::create_dir_all(state.roots().policy.join(".tirith")).unwrap();
        let path = state.roots().policy.join(".tirith/policy.yaml");
        std::fs::write(&path, "allow_bypass_env: true\n").unwrap();
        let before = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        std::fs::write(&path, "allow_bypass_env: false\n").unwrap();
        let after = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert!(before.policy.allow_bypass_env);
        assert!(!after.policy.allow_bypass_env);
        assert_ne!(before.policy_posture_sha256, after.policy_posture_sha256);
    }
}
