//! Trusted `web3_guard` and `task_gate` policy (C07).
//!
//! These two sections decide what Web3 and untrusted-task activity is
//! permitted. Everything here is written around one invariant: **a repository
//! may tighten, never authorize**. A checked-in `.tirith/policy.yaml` is
//! attacker-controlled in exactly the threat model this stack exists for, so no
//! field it supplies may widen a grant, name a trusted network, introduce a
//! signer, or relax an action.
//!
//! The merge is therefore not a field-wise overwrite. Each field carries a
//! documented direction:
//!
//! - grant-bearing collections (networks, aliases, allowed signers, approval key
//!   IDs) RESET under repo scope, because their presence is authorization;
//! - denial collections UNION, because more denial is strictly safer;
//! - actions and modes take the STRICTER value on a total lattice;
//! - resource ceilings take the MINIMUM.
//!
//! [`Web3GuardPolicy::merge_repo_scoped`] and [`TaskGatePolicy::merge_repo_scoped`]
//! implement precisely that, and `policy.rs` calls them from
//! `sanitize_repo_scoped`. The property test in this module proves the
//! resulting effect set is always a subset of the trusted one.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::effects::CommandEffectKind;

/// Chain family. Closed on purpose: an unknown family cannot be introduced by
/// configuration, so a network definition can never describe something the
/// analyzer has no grammar for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3Family {
    Evm,
    Solana,
}

/// How much damage an operation can do. Ordered so a comparison means
/// "at least as critical as".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3Criticality {
    ReadOnly,
    SignerExposure,
    StateChanging,
}

/// What to do about an observation. This is a total lattice ordered from most
/// permissive to most restrictive; [`Web3GuardAction::stricter`] is what makes
/// repo merging safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3GuardAction {
    Allow,
    Warn,
    RequireApproval,
    Block,
}

impl Web3GuardAction {
    /// The more restrictive of two actions. Total, commutative, idempotent.
    pub fn stricter(self, other: Self) -> Self {
        self.max(other)
    }
}

/// Signer kinds a policy is allowed to *trust*.
///
/// Deliberately excludes every raw-secret and environment-bearing kind: a
/// policy that could allowlist `RawPrivateKey` would legitimize pasting a key
/// into argv, which is the exact practice this stack detects. Validation
/// rejects those spellings rather than silently dropping them, so an operator
/// cannot believe they allowed something they did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedSignerKind {
    HardwareWallet,
    KeystoreFile,
    KeypairFile,
    AccountAlias,
    UnlockedNode,
}

/// Whether an endpoint match covers subdomains.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SubdomainPolicy {
    /// Only this exact host. The default, because widening to subdomains is a
    /// decision an operator should have to write down.
    #[default]
    ExactHost,
    /// This host and any subdomain of it.
    HostAndSubdomains,
}

/// A structured endpoint matcher.
///
/// There is no free-form regex or URL string anywhere in this policy. A regex
/// allowlist is where endpoint policies usually fail: `https://rpc.example` as
/// a pattern happily matches `https://rpc.example.attacker.tld`. Fixed fields
/// with an explicit subdomain decision cannot express that mistake.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RpcMatcher {
    pub scheme: String,
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub subdomains: SubdomainPolicy,
}

impl RpcMatcher {
    pub fn matches_origin(&self, scheme: &str, host: &str, port: Option<u16>) -> bool {
        if !self.scheme.eq_ignore_ascii_case(scheme) {
            return false;
        }
        let host_ok = if self.subdomains == SubdomainPolicy::HostAndSubdomains {
            host.eq_ignore_ascii_case(&self.host)
                || host
                    .len()
                    .checked_sub(self.host.len())
                    .and_then(|split| split.checked_sub(1))
                    .is_some_and(|boundary| {
                        host.as_bytes().get(boundary) == Some(&b'.')
                            && host[boundary + 1..].eq_ignore_ascii_case(&self.host)
                    })
        } else {
            host.eq_ignore_ascii_case(&self.host)
        };
        if !host_ok {
            return false;
        }
        self.port
            .is_none_or(|expected| effective_rpc_port(scheme, port) == Some(expected))
    }

    /// Does this matcher cover the given observed endpoint?
    ///
    /// Host comparison is ASCII-case-insensitive and, for the subdomain form,
    /// anchored on a label boundary so `evil-example.test` cannot satisfy a
    /// matcher for `example.test`.
    pub fn matches(&self, scheme: &str, host: &str, port: Option<u16>, path: Option<&str>) -> bool {
        if !self.matches_origin(scheme, host, port) {
            return false;
        }
        match (&self.path_prefix, path) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(prefix), Some(path)) => {
                path == prefix
                    || (path.starts_with(prefix.as_str())
                        && (prefix.ends_with('/')
                            || path.as_bytes().get(prefix.len()) == Some(&b'/')))
            }
        }
    }
}

fn effective_rpc_port(scheme: &str, port: Option<u16>) -> Option<u16> {
    port.or_else(|| match scheme.to_ascii_lowercase().as_str() {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        _ => None,
    })
}

/// Chain identity, kept separate from the human-facing name so a repo cannot
/// rename a network into a trusted one.
///
/// Untagged with disjoint field names so a policy file reads as a plain map
/// (`identity: { evm_chain_id: 1 }`) rather than YAML tag syntax.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum NetworkIdentity {
    /// EVM chain ID, the only identity that distinguishes a fork from mainnet.
    Evm { evm_chain_id: u64 },
    /// Solana cluster moniker plus genesis hash.
    Solana {
        solana_cluster: String,
        solana_genesis: String,
    },
}

impl NetworkIdentity {
    pub fn family(&self) -> Web3Family {
        match self {
            Self::Evm { .. } => Web3Family::Evm,
            Self::Solana { .. } => Web3Family::Solana,
        }
    }
}

/// A named network an operator trusts, with the endpoints that speak for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedNetwork {
    pub name: String,
    pub family: Web3Family,
    pub identity: NetworkIdentity,
    #[serde(default)]
    pub endpoints: Vec<RpcMatcher>,
}

/// Trusted Web3 policy.
///
/// Every collection here is grant-bearing except the two `deny_*` lists and the
/// three `action_*` fields; see the module docs for why that split drives the
/// repo merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Web3GuardPolicy {
    /// Networks the operator trusts. Naming a network is authorization.
    pub networks: Vec<TrustedNetwork>,

    /// Per-tool selector aliases (`tool -> alias -> network name`), so
    /// `--network prod` can be bound without a free-form string match.
    pub selector_aliases: BTreeMap<String, BTreeMap<String, String>>,

    /// Signer kinds permitted to sign. Empty means "none declared", which is
    /// not the same as "all allowed": consumers treat an empty allow list as
    /// having granted nothing.
    pub allowed_signers: BTreeSet<TrustedSignerKind>,

    /// Require a signed command card for state-changing operations.
    pub require_command_card: bool,

    /// Approval key IDs trusted to sign a command card.
    pub command_card_key_ids: BTreeSet<String>,

    /// Endpoints that are always refused, even if a network names them.
    pub deny_rpc: Vec<RpcMatcher>,

    /// Destination identifiers that are always refused.
    pub deny_destinations: BTreeSet<String>,

    /// An endpoint no trusted network claims.
    pub action_unclassified_rpc: Web3GuardAction,

    /// The analyzer could not finish; the command may do more than we can see.
    pub action_incomplete_analysis: Web3GuardAction,

    /// `hardhat run` against a production selector is arbitrary code, not a
    /// declared deployment, so it gets its own decision rather than being
    /// silently treated as either safe or as a deploy.
    pub action_ambiguous_hardhat_production_run: Web3GuardAction,
}

impl Default for Web3GuardPolicy {
    fn default() -> Self {
        Self {
            networks: Vec::new(),
            selector_aliases: BTreeMap::new(),
            allowed_signers: BTreeSet::new(),
            require_command_card: false,
            command_card_key_ids: BTreeSet::new(),
            deny_rpc: Vec::new(),
            deny_destinations: BTreeSet::new(),
            // Defaults are observational. C07 ships the vocabulary; the slice
            // that wires rules decides when to raise these.
            action_unclassified_rpc: Web3GuardAction::Warn,
            action_incomplete_analysis: Web3GuardAction::Warn,
            action_ambiguous_hardhat_production_run: Web3GuardAction::Warn,
        }
    }
}

impl Web3GuardPolicy {
    /// Is this policy inert (nothing declared, all actions at the default)?
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// Fold a repository-supplied guard into a trusted one, keeping only what
    /// tightens. Returns the YAML keys that were neutralized so the operator
    /// can be told exactly what was ignored.
    ///
    /// Idempotent: merging an already-merged result changes nothing, because
    /// every operation is either a reset, a union, or a max.
    pub fn merge_repo_scoped(&mut self, repo: Web3GuardPolicy) -> Vec<&'static str> {
        let mut neutralized = Vec::new();

        // Grant-bearing: presence IS authorization, so a repo value is dropped
        // entirely rather than merged.
        if !repo.networks.is_empty() {
            neutralized.push("web3_guard.networks");
        }
        if !repo.selector_aliases.is_empty() {
            neutralized.push("web3_guard.selector_aliases");
        }
        if !repo.allowed_signers.is_empty() {
            neutralized.push("web3_guard.allowed_signers");
        }
        if !repo.command_card_key_ids.is_empty() {
            neutralized.push("web3_guard.command_card_key_ids");
        }
        // `require_command_card` is deliberately NOT recorded. It defaults to
        // `false`, so a repo that merely omits it looks identical to one that
        // asked to switch it off, and reporting that as an ignored weakening
        // would fire on almost every tightening-only repo policy. The trusted
        // value survives regardless via the `|=` below. This mirrors the same
        // decision made for `allow_bypass_env` in `sanitize_repo_scoped`.

        // Tightening: denials union. Bounded because `deny_rpc` is a
        // repo-controlled `Vec` and this dedup is a linear scan, so an
        // unbounded list would make every policy load quadratic in
        // attacker-chosen input.
        for matcher in repo.deny_rpc {
            if self.deny_rpc.len() >= MAX_DENY_RPC {
                break;
            }
            if !self.deny_rpc.contains(&matcher) {
                self.deny_rpc.push(matcher);
            }
        }
        for destination in repo.deny_destinations {
            if self.deny_destinations.len() >= MAX_DENY_DESTINATIONS {
                break;
            }
            self.deny_destinations.insert(destination);
        }

        // Tightening: a repo may only raise an action, never lower it.
        self.action_unclassified_rpc = self
            .action_unclassified_rpc
            .stricter(repo.action_unclassified_rpc);
        self.action_incomplete_analysis = self
            .action_incomplete_analysis
            .stricter(repo.action_incomplete_analysis);
        self.action_ambiguous_hardhat_production_run = self
            .action_ambiguous_hardhat_production_run
            .stricter(repo.action_ambiguous_hardhat_production_run);
        self.require_command_card |= repo.require_command_card;

        neutralized
    }

    /// Is this signer kind permitted? An empty allow list grants nothing.
    pub fn permits_signer(&self, kind: TrustedSignerKind) -> bool {
        self.allowed_signers.contains(&kind)
    }

    /// Is this endpoint explicitly denied?
    pub fn denies_rpc(
        &self,
        scheme: &str,
        host: &str,
        port: Option<u16>,
        path: Option<&str>,
    ) -> bool {
        self.deny_rpc
            .iter()
            .any(|matcher| matcher.matches(scheme, host, port, path))
    }

    /// The trusted network claiming this endpoint, if any. A denial always
    /// wins, so a denied endpoint is never classified.
    pub fn classify_rpc(
        &self,
        scheme: &str,
        host: &str,
        port: Option<u16>,
        path: Option<&str>,
    ) -> Option<&TrustedNetwork> {
        if self.denies_rpc(scheme, host, port, path) {
            return None;
        }
        self.networks.iter().find(|network| {
            network
                .endpoints
                .iter()
                .any(|matcher| matcher.matches(scheme, host, port, path))
        })
    }
}

/// How hard the task gate pushes. Ordered from inert to strictest.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TaskGateMode {
    /// The default. C07 ships the vocabulary only; turning the gate on is an
    /// operator decision made in a later slice, so the default stays inert.
    #[default]
    Off,
    Observe,
    Enforce,
}

impl TaskGateMode {
    pub fn stricter(self, other: Self) -> Self {
        self.max(other)
    }
}

/// Trusted policy for untrusted-task handling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TaskGatePolicy {
    pub mode: TaskGateMode,

    /// Effects that may only proceed with verified provenance.
    pub effects_requiring_verified_provenance: BTreeSet<CommandEffectKind>,

    /// Effects refused outright when the task came from an untrusted source.
    pub effects_denied_for_untrusted_sources: BTreeSet<CommandEffectKind>,

    /// What to do when analysis is incomplete at an owned boundary.
    pub action_incomplete_analysis: Web3GuardAction,
}

impl Default for TaskGatePolicy {
    fn default() -> Self {
        Self {
            mode: TaskGateMode::Off,
            effects_requiring_verified_provenance: BTreeSet::new(),
            effects_denied_for_untrusted_sources: BTreeSet::new(),
            action_incomplete_analysis: Web3GuardAction::Warn,
        }
    }
}

impl TaskGatePolicy {
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// Fold a repository-supplied gate into a trusted one, keeping only what
    /// tightens. Every field here is restriction-shaped, so unlike the guard
    /// there is nothing to reset: a stricter mode, more required provenance,
    /// and more denied effects are all safe to accept.
    pub fn merge_repo_scoped(&mut self, repo: TaskGatePolicy) -> Vec<&'static str> {
        let mut neutralized = Vec::new();
        if repo.mode < self.mode && repo.mode != TaskGateMode::default() {
            neutralized.push("task_gate.mode");
        }
        self.mode = self.mode.stricter(repo.mode);
        self.effects_requiring_verified_provenance
            .extend(repo.effects_requiring_verified_provenance);
        self.effects_denied_for_untrusted_sources
            .extend(repo.effects_denied_for_untrusted_sources);
        self.action_incomplete_analysis = self
            .action_incomplete_analysis
            .stricter(repo.action_incomplete_analysis);
        neutralized
    }

    /// Effects this policy permits for a task, given whether its provenance was
    /// verified and whether its source is trusted.
    ///
    /// This is the function the monotonicity property is stated over: merging a
    /// hostile repo policy must never grow this set.
    pub fn allowed_effects(
        &self,
        candidate: &BTreeSet<CommandEffectKind>,
        provenance_verified: bool,
        source_trusted: bool,
    ) -> BTreeSet<CommandEffectKind> {
        candidate
            .iter()
            .copied()
            .filter(|effect| {
                if !source_trusted && self.effects_denied_for_untrusted_sources.contains(effect) {
                    return false;
                }
                if !provenance_verified
                    && self.effects_requiring_verified_provenance.contains(effect)
                {
                    return false;
                }
                true
            })
            .collect()
    }
}

/// A validation problem in a trusted policy section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Web3PolicyIssue {
    pub field: String,
    pub message: String,
}

fn issue(field: &str, message: impl Into<String>) -> Web3PolicyIssue {
    Web3PolicyIssue {
        field: field.to_string(),
        message: message.into(),
    }
}

/// Limits that keep a policy document bounded. A policy is parsed before it is
/// trusted, so its own size must not be an attack surface.
pub const MAX_NETWORKS: usize = 64;
pub const MAX_ENDPOINTS_PER_NETWORK: usize = 32;
pub const MAX_SELECTOR_ALIASES: usize = 256;
pub const MAX_POLICY_STRING_BYTES: usize = 253;
/// Denial lists are repo-controlled and merged on every policy load, so they
/// carry their own ceiling. Without one, a checked-in policy could make each
/// intercepted command pay a quadratic dedup over tens of thousands of
/// attacker-chosen entries.
pub const MAX_DENY_RPC: usize = 1024;
pub const MAX_DENY_DESTINATIONS: usize = 4096;

/// Validate a trusted `web3_guard`. Rejections are explicit so an operator is
/// never left believing a malformed definition took effect.
pub fn validate_web3_guard(guard: &Web3GuardPolicy) -> Vec<Web3PolicyIssue> {
    let mut issues = Vec::new();

    if guard.networks.len() > MAX_NETWORKS {
        issues.push(issue(
            "web3_guard.networks",
            format!("more than {MAX_NETWORKS} networks"),
        ));
    }

    let mut seen_names: BTreeSet<&str> = BTreeSet::new();
    let mut seen_identities: Vec<&NetworkIdentity> = Vec::new();
    for network in &guard.networks {
        let field = format!("web3_guard.networks.{}", network.name);
        if network.name.is_empty() || network.name.len() > MAX_POLICY_STRING_BYTES {
            issues.push(issue(&field, "network name is empty or too long"));
        }
        if !seen_names.insert(network.name.as_str()) {
            issues.push(issue(&field, "duplicate network name"));
        }
        // A name that claims one family while its identity describes another
        // would let a Solana alias resolve an EVM chain ID.
        if network.identity.family() != network.family {
            issues.push(issue(&field, "family does not match the network identity"));
        }
        if seen_identities.contains(&&network.identity) {
            issues.push(issue(&field, "duplicate network identity"));
        }
        seen_identities.push(&network.identity);

        if let NetworkIdentity::Evm { evm_chain_id: 0 } = network.identity {
            issues.push(issue(&field, "chain id 0 is not a valid EVM network"));
        }
        if let NetworkIdentity::Solana {
            solana_cluster: cluster,
            solana_genesis: genesis,
        } = &network.identity
        {
            if cluster.is_empty() || genesis.is_empty() {
                issues.push(issue(&field, "solana cluster and genesis are required"));
            }
        }
        if network.endpoints.len() > MAX_ENDPOINTS_PER_NETWORK {
            issues.push(issue(&field, "too many endpoints"));
        }
        for endpoint in &network.endpoints {
            issues.extend(validate_matcher(endpoint, &field));
        }
    }

    // Semantically overlapping endpoints speaking for different networks are
    // ambiguous, which is exactly where a fork gets mistaken for mainnet. A
    // structural equality check is insufficient: an exact host overlaps a
    // parent `host_and_subdomains` matcher, an omitted port overlaps every
    // explicit port, and nested path prefixes can cover the same request.
    for (index, network) in guard.networks.iter().enumerate() {
        for other in guard.networks.iter().skip(index + 1) {
            if network.endpoints.iter().any(|endpoint| {
                other
                    .endpoints
                    .iter()
                    .any(|candidate| rpc_matchers_overlap(endpoint, candidate))
            }) {
                issues.push(issue(
                    "web3_guard.networks",
                    format!(
                        "endpoint coverage overlaps between '{}' and '{}'",
                        network.name, other.name
                    ),
                ));
            }
        }
    }

    let alias_count: usize = guard.selector_aliases.values().map(BTreeMap::len).sum();
    if alias_count > MAX_SELECTOR_ALIASES {
        issues.push(issue(
            "web3_guard.selector_aliases",
            format!("more than {MAX_SELECTOR_ALIASES} aliases"),
        ));
    }
    for (tool, aliases) in &guard.selector_aliases {
        for (alias, network) in aliases {
            if !seen_names.contains(network.as_str()) {
                issues.push(issue(
                    &format!("web3_guard.selector_aliases.{tool}.{alias}"),
                    "alias names a network that is not defined",
                ));
            }
        }
    }

    if guard.deny_rpc.len() > MAX_DENY_RPC {
        issues.push(issue(
            "web3_guard.deny_rpc",
            format!("more than {MAX_DENY_RPC} denied endpoints"),
        ));
    }
    if guard.deny_destinations.len() > MAX_DENY_DESTINATIONS {
        issues.push(issue(
            "web3_guard.deny_destinations",
            format!("more than {MAX_DENY_DESTINATIONS} denied destinations"),
        ));
    }
    for matcher in guard.deny_rpc.iter().take(MAX_DENY_RPC) {
        issues.extend(validate_matcher(matcher, "web3_guard.deny_rpc"));
    }

    if guard.require_command_card && guard.command_card_key_ids.is_empty() {
        issues.push(issue(
            "web3_guard.command_card_key_ids",
            "a required command card has no trusted approval key ids",
        ));
    }

    issues
}

fn validate_matcher(matcher: &RpcMatcher, field: &str) -> Vec<Web3PolicyIssue> {
    let mut issues = Vec::new();
    if !matches!(
        matcher.scheme.to_ascii_lowercase().as_str(),
        "http" | "https" | "ws" | "wss"
    ) {
        issues.push(issue(
            field,
            "endpoint scheme must be http, https, ws, or wss",
        ));
    }
    if matcher.host.is_empty() || matcher.host.len() > MAX_POLICY_STRING_BYTES {
        issues.push(issue(field, "endpoint host is empty or too long"));
    }
    // Userinfo, query, and fragment cannot appear in a structured matcher, so
    // reject the punctuation that would smuggle them in through the host field.
    if matcher.host.contains(['@', '/', '?', '#', ':', ' ', '\\']) {
        issues.push(issue(
            field,
            "endpoint host must not contain userinfo, port, path, query, or fragment",
        ));
    }
    if matcher.host.eq_ignore_ascii_case("localhost")
        && matcher.subdomains == SubdomainPolicy::HostAndSubdomains
    {
        issues.push(issue(field, "localhost cannot be matched with subdomains"));
    }
    if let Some(prefix) = &matcher.path_prefix {
        if !prefix.starts_with('/') {
            issues.push(issue(field, "endpoint path prefix must start with '/'"));
        }
        if prefix.contains(['?', '#']) {
            issues.push(issue(
                field,
                "endpoint path prefix must not contain a query or fragment",
            ));
        }
    }
    issues
}

fn rpc_matchers_overlap(left: &RpcMatcher, right: &RpcMatcher) -> bool {
    left.scheme.eq_ignore_ascii_case(&right.scheme)
        && ports_overlap(left.port, right.port)
        && host_scopes_overlap(left, right)
        && path_scopes_overlap(left.path_prefix.as_deref(), right.path_prefix.as_deref())
}

fn ports_overlap(left: Option<u16>, right: Option<u16>) -> bool {
    left.is_none() || right.is_none() || left == right
}

fn host_scopes_overlap(left: &RpcMatcher, right: &RpcMatcher) -> bool {
    matcher_covers_host(left, &right.host) || matcher_covers_host(right, &left.host)
}

fn matcher_covers_host(matcher: &RpcMatcher, host: &str) -> bool {
    host.eq_ignore_ascii_case(&matcher.host)
        || (matcher.subdomains == SubdomainPolicy::HostAndSubdomains
            && host.len() > matcher.host.len()
            && host
                .get(..host.len() - matcher.host.len())
                .is_some_and(|prefix| prefix.ends_with('.'))
            && host[host.len() - matcher.host.len()..].eq_ignore_ascii_case(&matcher.host))
}

fn path_scopes_overlap(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (None, _) | (_, None) => true,
        (Some(left), Some(right)) => {
            path_prefix_covers(left, right) || path_prefix_covers(right, left)
        }
    }
}

fn path_prefix_covers(prefix: &str, path: &str) -> bool {
    path == prefix
        || (path.starts_with(prefix)
            && (prefix.ends_with('/') || path.as_bytes().get(prefix.len()) == Some(&b'/')))
}

/// Validate a trusted `task_gate`.
pub fn validate_task_gate(gate: &TaskGatePolicy) -> Vec<Web3PolicyIssue> {
    let mut issues = Vec::new();
    // An enforcing gate that constrains nothing is almost certainly a mistake,
    // and silently enforcing nothing is the failure mode operators do not
    // notice.
    if gate.mode == TaskGateMode::Enforce
        && gate.effects_requiring_verified_provenance.is_empty()
        && gate.effects_denied_for_untrusted_sources.is_empty()
    {
        issues.push(issue(
            "task_gate",
            "enforce mode declares no provenance requirement and no denied effect",
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evm_network(name: &str, chain: u64, host: &str) -> TrustedNetwork {
        TrustedNetwork {
            name: name.to_string(),
            family: Web3Family::Evm,
            identity: NetworkIdentity::Evm {
                evm_chain_id: chain,
            },
            endpoints: vec![RpcMatcher {
                scheme: "https".to_string(),
                host: host.to_string(),
                port: None,
                path_prefix: None,
                subdomains: SubdomainPolicy::ExactHost,
            }],
        }
    }

    fn all_effects() -> BTreeSet<CommandEffectKind> {
        [
            CommandEffectKind::PackageInstall,
            CommandEffectKind::PersistenceChange,
            CommandEffectKind::PolicyChange,
            CommandEffectKind::SecretRead,
            CommandEffectKind::NetworkEgress,
            CommandEffectKind::FilesystemWrite,
            CommandEffectKind::ResourceEscalation,
            CommandEffectKind::Web3Write,
            CommandEffectKind::Web3SignerUse,
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn subdomain_matching_is_anchored_on_a_label_boundary() {
        let exact = RpcMatcher {
            scheme: "https".into(),
            host: "example.test".into(),
            port: None,
            path_prefix: None,
            subdomains: SubdomainPolicy::ExactHost,
        };
        assert!(exact.matches("https", "example.test", None, None));
        assert!(!exact.matches("https", "rpc.example.test", None, None));
        assert!(!exact.matches("http", "example.test", None, None));

        let wide = RpcMatcher {
            subdomains: SubdomainPolicy::HostAndSubdomains,
            ..exact.clone()
        };
        assert!(wide.matches("https", "example.test", None, None));
        assert!(wide.matches("https", "rpc.example.test", None, None));
        // The classic allowlist bypass: a suffix that is not a label boundary.
        assert!(!wide.matches("https", "evil-example.test", None, None));
        assert!(!wide.matches("https", "example.test.attacker.tld", None, None));
    }

    #[test]
    fn explicit_default_ports_match_omitted_and_explicit_spellings() {
        for (scheme, default_port) in [("http", 80), ("https", 443), ("ws", 80), ("wss", 443)] {
            let matcher = RpcMatcher {
                scheme: scheme.into(),
                host: "rpc.example".into(),
                port: Some(default_port),
                path_prefix: None,
                subdomains: SubdomainPolicy::ExactHost,
            };
            assert!(matcher.matches_origin(scheme, "rpc.example", None));
            assert!(matcher.matches_origin(scheme, "rpc.example", Some(default_port)));
            assert!(!matcher.matches_origin(scheme, "rpc.example", Some(default_port + 1)));
        }

        let nondefault = RpcMatcher {
            scheme: "https".into(),
            host: "rpc.example".into(),
            port: Some(8443),
            path_prefix: None,
            subdomains: SubdomainPolicy::ExactHost,
        };
        assert!(!nondefault.matches_origin("https", "rpc.example", None));
        assert!(nondefault.matches_origin("https", "rpc.example", Some(8443)));
    }

    #[test]
    fn validation_rejects_semantically_overlapping_network_endpoints() {
        let mut parent = evm_network("parent", 1, "example.test");
        parent.endpoints[0].subdomains = SubdomainPolicy::HostAndSubdomains;
        parent.endpoints[0].path_prefix = Some("/rpc".into());
        let mut child = evm_network("child", 10, "rpc.example.test");
        child.endpoints[0].port = Some(443);
        child.endpoints[0].path_prefix = Some("/rpc/mainnet".into());
        let guard = Web3GuardPolicy {
            networks: vec![parent, child],
            ..Web3GuardPolicy::default()
        };
        assert!(validate_web3_guard(&guard).iter().any(|issue| {
            issue.field == "web3_guard.networks" && issue.message.contains("overlaps")
        }));

        let disjoint = Web3GuardPolicy {
            networks: vec![
                evm_network("one", 1, "one.example.test"),
                evm_network("two", 10, "two.example.test"),
            ],
            ..Web3GuardPolicy::default()
        };
        assert!(!validate_web3_guard(&disjoint)
            .iter()
            .any(|issue| issue.message.contains("overlaps")));
    }

    #[test]
    fn a_repo_guard_cannot_introduce_trust() {
        let mut trusted = Web3GuardPolicy {
            networks: vec![evm_network("prod", 1, "rpc.trusted.test")],
            allowed_signers: [TrustedSignerKind::HardwareWallet].into_iter().collect(),
            action_unclassified_rpc: Web3GuardAction::Warn,
            ..Web3GuardPolicy::default()
        };
        let hostile = Web3GuardPolicy {
            networks: vec![evm_network("prod", 1, "rpc.attacker.test")],
            selector_aliases: [(
                "cast".to_string(),
                [("prod".to_string(), "prod".to_string())]
                    .into_iter()
                    .collect(),
            )]
            .into_iter()
            .collect(),
            allowed_signers: [TrustedSignerKind::UnlockedNode].into_iter().collect(),
            command_card_key_ids: ["attacker-key".to_string()].into_iter().collect(),
            action_unclassified_rpc: Web3GuardAction::Allow,
            ..Web3GuardPolicy::default()
        };

        let neutralized = trusted.merge_repo_scoped(hostile);

        // Nothing the repo named became trusted.
        assert!(trusted
            .classify_rpc("https", "rpc.attacker.test", None, None)
            .is_none());
        assert!(!trusted.permits_signer(TrustedSignerKind::UnlockedNode));
        assert!(trusted.command_card_key_ids.is_empty());
        assert!(trusted.selector_aliases.is_empty());
        // The relaxed action did not take effect.
        assert_eq!(trusted.action_unclassified_rpc, Web3GuardAction::Warn);
        assert!(neutralized.contains(&"web3_guard.networks"));
        assert!(neutralized.contains(&"web3_guard.allowed_signers"));
    }

    #[test]
    fn a_repo_guard_may_tighten() {
        let mut trusted = Web3GuardPolicy {
            networks: vec![evm_network("prod", 1, "rpc.trusted.test")],
            action_incomplete_analysis: Web3GuardAction::Warn,
            ..Web3GuardPolicy::default()
        };
        let repo = Web3GuardPolicy {
            deny_rpc: vec![RpcMatcher {
                scheme: "https".into(),
                host: "rpc.trusted.test".into(),
                port: None,
                path_prefix: None,
                subdomains: SubdomainPolicy::ExactHost,
            }],
            action_incomplete_analysis: Web3GuardAction::Block,
            require_command_card: true,
            ..Web3GuardPolicy::default()
        };

        trusted.merge_repo_scoped(repo);

        // A denial the repo added is honored, and it outranks the trusted
        // network that names the same endpoint.
        assert!(trusted.denies_rpc("https", "rpc.trusted.test", None, None));
        assert!(trusted
            .classify_rpc("https", "rpc.trusted.test", None, None)
            .is_none());
        assert_eq!(trusted.action_incomplete_analysis, Web3GuardAction::Block);
        assert!(trusted.require_command_card);
    }

    #[test]
    fn repo_merge_is_idempotent() {
        let base = Web3GuardPolicy {
            networks: vec![evm_network("prod", 1, "rpc.trusted.test")],
            ..Web3GuardPolicy::default()
        };
        let repo = Web3GuardPolicy {
            deny_destinations: ["0xdead".to_string()].into_iter().collect(),
            action_incomplete_analysis: Web3GuardAction::Block,
            ..Web3GuardPolicy::default()
        };

        let mut once = base.clone();
        once.merge_repo_scoped(repo.clone());
        let mut twice = once.clone();
        twice.merge_repo_scoped(repo);
        assert_eq!(once, twice);
    }

    #[test]
    fn a_hostile_repo_gate_can_never_widen_the_effect_set() {
        // The plan's stated property:
        //   allowed_effects(merge(trusted, hostile_repo)) is a subset of
        //   allowed_effects(trusted)
        let trusted = TaskGatePolicy {
            mode: TaskGateMode::Enforce,
            effects_requiring_verified_provenance: [
                CommandEffectKind::Web3Write,
                CommandEffectKind::PackageInstall,
            ]
            .into_iter()
            .collect(),
            effects_denied_for_untrusted_sources: [CommandEffectKind::PolicyChange]
                .into_iter()
                .collect(),
            action_incomplete_analysis: Web3GuardAction::Block,
        };

        let hostile_variants = [
            // Try to turn the gate off.
            TaskGatePolicy {
                mode: TaskGateMode::Off,
                ..TaskGatePolicy::default()
            },
            // Try to drop every requirement by declaring none.
            TaskGatePolicy::default(),
            // Try to relax the incomplete-analysis action.
            TaskGatePolicy {
                mode: TaskGateMode::Observe,
                action_incomplete_analysis: Web3GuardAction::Allow,
                ..TaskGatePolicy::default()
            },
        ];

        let candidate = all_effects();
        for hostile in hostile_variants {
            let mut merged = trusted.clone();
            merged.merge_repo_scoped(hostile);
            for provenance in [false, true] {
                for source_trusted in [false, true] {
                    let merged_allowed =
                        merged.allowed_effects(&candidate, provenance, source_trusted);
                    let trusted_allowed =
                        trusted.allowed_effects(&candidate, provenance, source_trusted);
                    assert!(
                        merged_allowed.is_subset(&trusted_allowed),
                        "repo merge widened the effect set: {merged_allowed:?} vs {trusted_allowed:?}"
                    );
                }
            }
            assert!(merged.mode >= trusted.mode);
            assert!(merged.action_incomplete_analysis >= trusted.action_incomplete_analysis);
        }
    }

    #[test]
    fn a_repo_gate_may_tighten() {
        let mut trusted = TaskGatePolicy {
            mode: TaskGateMode::Observe,
            ..TaskGatePolicy::default()
        };
        trusted.merge_repo_scoped(TaskGatePolicy {
            mode: TaskGateMode::Enforce,
            effects_denied_for_untrusted_sources: [CommandEffectKind::Web3Write]
                .into_iter()
                .collect(),
            ..TaskGatePolicy::default()
        });
        assert_eq!(trusted.mode, TaskGateMode::Enforce);
        let allowed = trusted.allowed_effects(&all_effects(), true, false);
        assert!(!allowed.contains(&CommandEffectKind::Web3Write));
    }

    #[test]
    fn validation_rejects_incoherent_trusted_definitions() {
        let guard = Web3GuardPolicy {
            networks: vec![
                TrustedNetwork {
                    name: "a".into(),
                    // Family says Solana, identity says EVM.
                    family: Web3Family::Solana,
                    identity: NetworkIdentity::Evm { evm_chain_id: 1 },
                    endpoints: vec![RpcMatcher {
                        scheme: "https".into(),
                        host: "shared.test".into(),
                        port: None,
                        path_prefix: None,
                        subdomains: SubdomainPolicy::ExactHost,
                    }],
                },
                TrustedNetwork {
                    name: "a".into(),
                    family: Web3Family::Evm,
                    identity: NetworkIdentity::Evm { evm_chain_id: 0 },
                    endpoints: vec![RpcMatcher {
                        scheme: "ftp".into(),
                        host: "user@host/path".into(),
                        port: None,
                        path_prefix: Some("no-slash".into()),
                        subdomains: SubdomainPolicy::ExactHost,
                    }],
                },
            ],
            selector_aliases: [(
                "cast".to_string(),
                [("x".to_string(), "undefined-network".to_string())]
                    .into_iter()
                    .collect(),
            )]
            .into_iter()
            .collect(),
            require_command_card: true,
            ..Web3GuardPolicy::default()
        };

        let issues = validate_web3_guard(&guard);
        let messages = issues
            .iter()
            .map(|issue| issue.message.as_str())
            .collect::<Vec<_>>()
            .join(" | ");
        for expected in [
            "family does not match",
            "duplicate network name",
            "chain id 0",
            "scheme must be",
            "userinfo",
            "path prefix must start",
            "not defined",
            "no trusted approval key ids",
        ] {
            assert!(
                messages.contains(expected),
                "validation missed '{expected}': {messages}"
            );
        }
    }

    #[test]
    fn denial_lists_are_bounded_against_a_repo_controlled_flood() {
        // `deny_rpc` dedup is a linear scan, so an unbounded repo list would
        // make every policy load quadratic in attacker-chosen input.
        let flood = Web3GuardPolicy {
            deny_rpc: (0..MAX_DENY_RPC + 50)
                .map(|index| RpcMatcher {
                    scheme: "https".into(),
                    host: format!("h{index}.test"),
                    port: None,
                    path_prefix: None,
                    subdomains: SubdomainPolicy::ExactHost,
                })
                .collect(),
            deny_destinations: (0..MAX_DENY_DESTINATIONS + 50)
                .map(|index| format!("0x{index}"))
                .collect(),
            ..Web3GuardPolicy::default()
        };
        let issues = validate_web3_guard(&flood);
        let messages = issues
            .iter()
            .map(|issue| issue.message.as_str())
            .collect::<Vec<_>>()
            .join(" | ");
        assert!(messages.contains("denied endpoints"), "{messages}");
        assert!(messages.contains("denied destinations"), "{messages}");

        let mut merged = Web3GuardPolicy::default();
        merged.merge_repo_scoped(flood);
        assert!(merged.deny_rpc.len() <= MAX_DENY_RPC);
        assert!(merged.deny_destinations.len() <= MAX_DENY_DESTINATIONS);
    }

    #[test]
    fn an_omitted_card_requirement_is_not_reported_as_neutralized() {
        // `require_command_card` defaults to false, so a repo that merely omits
        // it must not be reported as having tried to switch it off.
        let mut trusted = Web3GuardPolicy {
            require_command_card: true,
            ..Web3GuardPolicy::default()
        };
        let neutralized = trusted.merge_repo_scoped(Web3GuardPolicy {
            deny_destinations: ["0xdead".to_string()].into_iter().collect(),
            ..Web3GuardPolicy::default()
        });
        assert!(
            !neutralized.contains(&"web3_guard.require_command_card"),
            "omission was reported as an ignored weakening: {neutralized:?}"
        );
        assert!(trusted.require_command_card, "trusted value must survive");
    }

    #[test]
    fn an_enforcing_gate_that_constrains_nothing_is_rejected() {
        let issues = validate_task_gate(&TaskGatePolicy {
            mode: TaskGateMode::Enforce,
            ..TaskGatePolicy::default()
        });
        assert_eq!(issues.len(), 1);
        assert!(validate_task_gate(&TaskGatePolicy::default()).is_empty());
    }
}
