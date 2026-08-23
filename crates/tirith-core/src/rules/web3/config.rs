//! Bounded, static-only configuration readers for Web3 selectors.
//!
//! Every read is no-follow, regular-file-only, and capped. No JavaScript or
//! TypeScript is imported, and environment interpolation is limited to an exact
//! `${NAME}` token resolved through the caller-provided view.

use super::model::{
    retained_value_is_secret, NetworkEvidence, RoleTaggedSigner, RpcPathClass,
    RpcPathMatchOutcomes, RpcPathMatcherValidationError, RpcReferenceV2, SelectorReference,
    SelectorSource, SignerKindV2, SignerReferenceV2, SignerRole, TrustedRpcPathPrefix,
};
use crate::effects::{CompletenessV2 as Completeness, IncompleteReasonV2 as IncompleteReason};
use crate::util::OpenRegularError;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const MAX_CONFIG_BYTES: u64 = 256 * 1024;
pub const MAX_ALIAS_RESOLUTIONS: usize = 128;
pub const MAX_CONTEXT_SELECTORS: usize = 128;
pub const MAX_SELECTOR_BYTES: usize = 16 * 1024;

/// Filesystem and environment inputs are explicit so parsing never reads the
/// process environment, home directory, or network implicitly.
#[derive(Clone, Default)]
pub struct Web3ParseContext {
    pub cwd: Option<PathBuf>,
    pub environment: BTreeMap<String, String>,
    pub ambient_selectors: BTreeMap<String, String>,
    pub foundry_config_path: Option<PathBuf>,
    pub solana_config_path: Option<PathBuf>,
    pub anchor_config_path: Option<PathBuf>,
    pub static_config_enabled: bool,
}

impl std::fmt::Debug for Web3ParseContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Web3ParseContext")
            .field("cwd", &self.cwd)
            .field("environment_count", &self.environment.len())
            .field("ambient_selector_count", &self.ambient_selectors.len())
            .field("foundry_config_path", &self.foundry_config_path)
            .field("solana_config_path", &self.solana_config_path)
            .field("anchor_config_path", &self.anchor_config_path)
            .field("static_config_enabled", &self.static_config_enabled)
            .finish()
    }
}

impl Web3ParseContext {
    pub fn without_filesystem() -> Self {
        Self::default()
    }

    pub fn for_cwd(cwd: impl Into<PathBuf>) -> Self {
        Self {
            cwd: Some(cwd.into()),
            static_config_enabled: true,
            ..Self::default()
        }
    }
}

#[derive(Clone, Default)]
pub struct Web3ParseContextV2 {
    pub cwd: Option<PathBuf>,
    pub environment: BTreeMap<String, String>,
    pub ambient_selectors: BTreeMap<String, String>,
    pub foundry_config_path: Option<PathBuf>,
    pub solana_config_path: Option<PathBuf>,
    pub anchor_config_path: Option<PathBuf>,
    pub trusted_rpc_path_prefixes: Option<Vec<TrustedRpcPathPrefix>>,
    pub static_config_enabled: bool,
}

impl std::fmt::Debug for Web3ParseContextV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Web3ParseContextV2")
            .field("cwd", &self.cwd)
            .field("environment_count", &self.environment.len())
            .field("ambient_selector_count", &self.ambient_selectors.len())
            .field("foundry_config_path", &self.foundry_config_path)
            .field("solana_config_path", &self.solana_config_path)
            .field("anchor_config_path", &self.anchor_config_path)
            .field(
                "trusted_rpc_path_prefix_count",
                &self.trusted_rpc_path_prefixes.as_ref().map(Vec::len),
            )
            .field("static_config_enabled", &self.static_config_enabled)
            .finish()
    }
}

impl Web3ParseContextV2 {
    pub fn without_filesystem() -> Self {
        Self::default()
    }

    pub fn for_cwd(cwd: impl Into<PathBuf>) -> Self {
        Self {
            cwd: Some(cwd.into()),
            static_config_enabled: true,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct StaticSelectors {
    pub rpc: Option<RpcReferenceV2>,
    pub network: NetworkEvidence,
    pub signers: Vec<RoleTaggedSigner>,
    pub completeness: Completeness,
}

fn add_read_gap(completeness: &mut Completeness, error: OpenRegularError) {
    completeness.add(match error {
        OpenRegularError::NotFound => IncompleteReason::ConfigMissing,
        OpenRegularError::NotRegularFile => IncompleteReason::ConfigNotRegular,
        OpenRegularError::TooLarge => IncompleteReason::ConfigBytesExceeded,
        OpenRegularError::Io(_) => IncompleteReason::ConfigIo,
    });
}

fn read_config(path: &Path, completeness: &mut Completeness) -> Option<String> {
    let bytes = match crate::util::read_text_no_follow_capped(path, MAX_CONFIG_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            add_read_gap(completeness, error);
            return None;
        }
    };
    match String::from_utf8(bytes) {
        Ok(text) => Some(text),
        Err(_) => {
            completeness.add(IncompleteReason::ConfigMalformed);
            None
        }
    }
}

fn nearest_file(cwd: &Path, name: &str) -> Option<PathBuf> {
    cwd.ancestors()
        .take(MAX_ALIAS_RESOLUTIONS)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.exists())
}

fn config_path(explicit: &Option<PathBuf>, cwd: Option<&Path>, name: &str) -> Option<PathBuf> {
    explicit
        .clone()
        .or_else(|| cwd.and_then(|root| nearest_file(root, name)))
}

fn exact_environment_reference(value: &str) -> Option<&str> {
    value
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
        .filter(|name| {
            !name.is_empty()
                && name.chars().enumerate().all(|(index, ch)| {
                    ch == '_' || ch.is_ascii_alphabetic() || (index > 0 && ch.is_ascii_digit())
                })
        })
}

fn resolve_static_value(
    value: &str,
    environment: &BTreeMap<String, String>,
    completeness: &mut Completeness,
) -> Option<String> {
    if let Some(name) = exact_environment_reference(value.trim()) {
        return environment
            .get(name)
            .filter(|value| value.len() <= MAX_SELECTOR_BYTES)
            .cloned()
            .or_else(|| {
                completeness.add(
                    if environment
                        .get(name)
                        .is_some_and(|value| value.len() > MAX_SELECTOR_BYTES)
                    {
                        IncompleteReason::SelectorBytesExceeded
                    } else {
                        IncompleteReason::UnresolvedIndirection
                    },
                );
                None
            });
    }
    if value.len() > MAX_SELECTOR_BYTES {
        completeness.add(IncompleteReason::SelectorBytesExceeded);
        return None;
    }
    if value.contains("${") || value.contains('$') || value.contains('`') {
        completeness.add(IncompleteReason::UnresolvedIndirection);
        return None;
    }
    Some(value.to_string())
}

pub(crate) fn rpc_reference(
    value: &str,
    source: SelectorSource,
    span: Option<crate::effects::SourceSpan>,
    trusted_path_prefixes: Option<&[TrustedRpcPathPrefix]>,
    completeness: &mut Completeness,
) -> RpcReferenceV2 {
    if value.len() > MAX_SELECTOR_BYTES {
        completeness.add(IncompleteReason::SelectorBytesExceeded);
        completeness.add(IncompleteReason::UnresolvedIndirection);
        return RpcReferenceV2 {
            scheme: None,
            host: None,
            port: None,
            path: None,
            path_class: RpcPathClass::Unknown,
            path_match_outcomes: RpcPathMatchOutcomes::default(),
            alias: None,
            source: SelectorSource::Unresolved,
            span,
        };
    }
    let parsed = value
        .split_once("://")
        .filter(|(scheme, remainder)| {
            matches!(
                scheme.to_ascii_lowercase().as_str(),
                "http" | "https" | "ws" | "wss"
            ) && !remainder.is_empty()
                // WHATWG parsing accepts and normalizes extra slashes and
                // backslashes. RPC evidence requires the literal spelling to
                // contain exactly `scheme://` followed by an authority.
                && !remainder.starts_with('/')
                && !remainder.starts_with('\\')
                && !remainder.contains('\\')
                && !remainder.chars().any(char::is_whitespace)
                && remainder
                    .split(['/', '?', '#'])
                    .next()
                    .is_some_and(|authority| !authority.is_empty())
        })
        .and_then(|_| url::Url::parse(value).ok())
        .filter(|url| url.host_str().is_some());
    if let Some(url) = parsed {
        let host = url.host_str().map(|host| host.to_ascii_lowercase());
        if host.as_deref().is_some_and(retained_value_is_secret) {
            completeness.add(IncompleteReason::UnresolvedIndirection);
            return RpcReferenceV2 {
                scheme: None,
                host: None,
                port: None,
                path: None,
                path_class: RpcPathClass::Unknown,
                path_match_outcomes: RpcPathMatchOutcomes::default(),
                alias: None,
                source: SelectorSource::Unresolved,
                span,
            };
        }
        let first_path_segment = url
            .path_segments()
            .and_then(|mut segments| segments.find(|segment| !segment.is_empty()));
        let path_class = match first_path_segment {
            None => RpcPathClass::Root,
            Some("rpc") => RpcPathClass::Rpc,
            Some("v1" | "v2" | "v3") => RpcPathClass::VersionedApi,
            Some(_) => RpcPathClass::RedactedNonRoot,
        };
        let path = match (path_class, first_path_segment) {
            (RpcPathClass::Root, _) => Some("/".to_string()),
            (RpcPathClass::Rpc, _) => Some("/rpc".to_string()),
            (RpcPathClass::VersionedApi, Some(version)) => Some(format!("/{version}")),
            _ => None,
        };
        let path_match_outcomes = match trusted_path_prefixes {
            None if path_class == RpcPathClass::Root => RpcPathMatchOutcomes::default(),
            None => {
                completeness.add(IncompleteReason::RpcPathMatcherContextMissing);
                RpcPathMatchOutcomes::default()
            }
            Some(matchers) => match RpcPathMatchOutcomes::compare(
                matchers,
                url.scheme(),
                host.as_deref().unwrap_or_default(),
                url.port(),
                raw_url_path(value),
                url.path(),
            ) {
                Ok((outcomes, truncated)) => {
                    if truncated {
                        completeness.add(IncompleteReason::RpcPathMatcherBudgetExceeded);
                    }
                    outcomes
                }
                Err(RpcPathMatcherValidationError::BudgetExceeded) => {
                    completeness.add(IncompleteReason::RpcPathMatcherBudgetExceeded);
                    RpcPathMatchOutcomes::default()
                }
                Err(
                    RpcPathMatcherValidationError::Invalid
                    | RpcPathMatcherValidationError::Ambiguous,
                ) => {
                    completeness.add(IncompleteReason::RpcPathMatcherInvalid);
                    RpcPathMatchOutcomes::default()
                }
            },
        };
        return RpcReferenceV2 {
            scheme: Some(url.scheme().to_ascii_lowercase()),
            host,
            port: url.port(),
            path,
            path_class,
            path_match_outcomes,
            alias: None,
            source,
            span,
        };
    }
    if value.contains("://") {
        completeness.add(IncompleteReason::UnresolvedIndirection);
        return RpcReferenceV2 {
            scheme: None,
            host: None,
            port: None,
            path: None,
            path_class: RpcPathClass::Unknown,
            path_match_outcomes: RpcPathMatchOutcomes::default(),
            alias: None,
            source: SelectorSource::Unresolved,
            span,
        };
    }
    let safe_alias = (!value.is_empty()
        && !value.contains("://")
        && !retained_value_is_secret(value)
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')))
    .then(|| value.to_string());
    let source = if safe_alias.is_some() {
        source
    } else {
        completeness.add(IncompleteReason::UnresolvedIndirection);
        SelectorSource::Unresolved
    };
    RpcReferenceV2 {
        scheme: None,
        host: None,
        port: None,
        path: None,
        path_class: RpcPathClass::Unknown,
        path_match_outcomes: RpcPathMatchOutcomes::default(),
        alias: safe_alias,
        source,
        span,
    }
}

/// Return the path spelling supplied by the caller, without query/fragment.
/// This is consumed transiently by trusted policy probes and never retained in
/// a fact. Comparing it with `Url::path()` catches dot-segment and encoding
/// normalizations that would otherwise let policy and execution see different
/// paths.
fn raw_url_path(value: &str) -> &str {
    let Some((_, remainder)) = value.split_once("://") else {
        return "/";
    };
    let Some(path_start) = remainder.find('/') else {
        return "/";
    };
    let path = &remainder[path_start..];
    let end = path.find(['?', '#']).unwrap_or(path.len());
    &path[..end]
}

fn toml_string(value: &toml::Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.as_table()?.get("endpoint")?.as_str())
}

pub(crate) fn foundry_selectors(
    context: &Web3ParseContextV2,
    selected_profile: Option<&str>,
    requested_rpc_alias: Option<&str>,
) -> StaticSelectors {
    let mut result = StaticSelectors::default();
    if !context.static_config_enabled {
        return result;
    }
    let Some(path) = config_path(
        &context.foundry_config_path,
        context.cwd.as_deref(),
        "foundry.toml",
    ) else {
        return result;
    };
    let Some(content) = read_config(&path, &mut result.completeness) else {
        return result;
    };
    let document: toml::Value = match toml::from_str(&content) {
        Ok(document) => document,
        Err(_) => {
            result.completeness.add(IncompleteReason::ConfigMalformed);
            return result;
        }
    };

    let aliases = document
        .get("rpc_endpoints")
        .and_then(toml::Value::as_table);
    if aliases.is_some_and(|aliases| aliases.len() > MAX_ALIAS_RESOLUTIONS) {
        result
            .completeness
            .add(IncompleteReason::AliasResolutionBudgetExceeded);
    }

    let profile = selected_profile.unwrap_or("default");
    let profile_key = |name: &str| {
        document
            .get("profile")
            .and_then(|value| value.get(name))
            .and_then(|value| value.get("eth_rpc_url"))
            .and_then(toml_string)
    };
    // Foundry layers every profile over `[profile.default]`, so a profile that
    // does not restate `eth_rpc_url` still resolves to the default profile's
    // endpoint. Without the fallback a `--profile prod` send reported a clean
    // localhost tool-default while the real configuration named a live network.
    let profile_rpc = profile_key(profile).or_else(|| {
        if profile == "default" {
            None
        } else {
            profile_key("default")
        }
    });
    // A named profile that is absent from the document entirely is not the same
    // as one that inherits: the operator selected something this file cannot
    // describe, so the selector is an analysis gap rather than a resolved value.
    if profile != "default"
        && document
            .get("profile")
            .and_then(|value| value.get(profile))
            .is_none()
    {
        result.completeness.add(IncompleteReason::ConfigMissing);
    }
    let candidate = requested_rpc_alias.or(profile_rpc);
    let Some(candidate) = candidate else {
        return result;
    };

    let resolved_alias = aliases
        .and_then(|aliases| {
            aliases
                .iter()
                .take(MAX_ALIAS_RESOLUTIONS)
                .find(|(name, _)| *name == candidate)
        })
        .and_then(|(_, value)| toml_string(value));
    let value = resolved_alias.unwrap_or(candidate);
    if let Some(resolved) =
        resolve_static_value(value, &context.environment, &mut result.completeness)
    {
        result.rpc = Some(rpc_reference(
            &resolved,
            SelectorSource::StaticConfig,
            None,
            context.trusted_rpc_path_prefixes.as_deref(),
            &mut result.completeness,
        ));
    }
    result
}

fn yaml_string<'a>(mapping: &'a serde_yaml::Mapping, name: &str) -> Option<&'a str> {
    mapping
        .get(serde_yaml::Value::String(name.to_string()))
        .and_then(serde_yaml::Value::as_str)
}

pub(crate) fn solana_selectors(
    context: &Web3ParseContextV2,
    include_rpc: bool,
    include_signer: bool,
) -> StaticSelectors {
    let mut result = StaticSelectors::default();
    if !context.static_config_enabled {
        return result;
    }
    let Some(path) = context.solana_config_path.as_deref() else {
        return result;
    };
    let Some(content) = read_config(path, &mut result.completeness) else {
        return result;
    };
    let document: serde_yaml::Value = match serde_yaml::from_str(&content) {
        Ok(document) => document,
        Err(_) => {
            result.completeness.add(IncompleteReason::ConfigMalformed);
            return result;
        }
    };
    let Some(mapping) = document.as_mapping() else {
        result.completeness.add(IncompleteReason::ConfigMalformed);
        return result;
    };
    if include_rpc {
        if let Some(value) = yaml_string(mapping, "json_rpc_url") {
            if let Some(resolved) =
                resolve_static_value(value, &context.environment, &mut result.completeness)
            {
                result.rpc = Some(rpc_reference(
                    &resolved,
                    SelectorSource::StaticConfig,
                    None,
                    context.trusted_rpc_path_prefixes.as_deref(),
                    &mut result.completeness,
                ));
            }
        }
    }
    if include_signer {
        if let Some(value) = yaml_string(mapping, "keypair_path") {
            if let Some(resolved) =
                resolve_static_value(value, &context.environment, &mut result.completeness)
            {
                let signer = SignerReferenceV2::reference(
                    SignerKindV2::KeypairFile,
                    SelectorSource::StaticConfig,
                    None,
                    Some(resolved),
                );
                if signer.kind() == SignerKindV2::Unknown
                    || signer.source() == SelectorSource::Unresolved
                {
                    result
                        .completeness
                        .add(IncompleteReason::UnresolvedIndirection);
                }
                result.signers.push(RoleTaggedSigner {
                    role: SignerRole::Keypair,
                    signer,
                });
            }
        }
    }
    result
}

pub(crate) fn anchor_selectors(context: &Web3ParseContextV2) -> StaticSelectors {
    let mut result = StaticSelectors::default();
    if !context.static_config_enabled {
        return result;
    }
    let Some(path) = config_path(
        &context.anchor_config_path,
        context.cwd.as_deref(),
        "Anchor.toml",
    ) else {
        return result;
    };
    let Some(content) = read_config(&path, &mut result.completeness) else {
        return result;
    };
    let document: toml::Value = match toml::from_str(&content) {
        Ok(document) => document,
        Err(_) => {
            result.completeness.add(IncompleteReason::ConfigMalformed);
            return result;
        }
    };
    let provider = document.get("provider");
    if let Some(cluster) = provider
        .and_then(|value| value.get("cluster"))
        .and_then(toml::Value::as_str)
    {
        if let Some(cluster) =
            resolve_static_value(cluster, &context.environment, &mut result.completeness)
        {
            let rpc = rpc_reference(
                &cluster,
                SelectorSource::StaticConfig,
                None,
                context.trusted_rpc_path_prefixes.as_deref(),
                &mut result.completeness,
            );
            result.network.network = Some(SelectorReference {
                value: if rpc.source == SelectorSource::Unresolved {
                    "unresolved".to_string()
                } else {
                    rpc.alias
                        .clone()
                        .unwrap_or_else(|| "custom_rpc".to_string())
                },
                source: rpc.source,
                span: rpc.span,
            });
            result.rpc = Some(rpc);
        }
    }
    if let Some(wallet) = provider
        .and_then(|value| value.get("wallet"))
        .and_then(toml::Value::as_str)
    {
        if let Some(resolved) =
            resolve_static_value(wallet, &context.environment, &mut result.completeness)
        {
            let signer = SignerReferenceV2::reference(
                SignerKindV2::KeypairFile,
                SelectorSource::StaticConfig,
                None,
                Some(resolved),
            );
            if signer.kind() == SignerKindV2::Unknown
                || signer.source() == SelectorSource::Unresolved
            {
                result
                    .completeness
                    .add(IncompleteReason::UnresolvedIndirection);
            }
            result.signers.push(RoleTaggedSigner {
                role: SignerRole::Wallet,
                signer,
            });
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::super::model::{
        RpcPathMatcherId, MAX_RETAINED_RPC_PATH_MATCH_OUTCOMES, MAX_TRUSTED_RPC_PATH_MATCHERS,
    };
    use super::*;

    #[test]
    fn rpc_reference_discards_url_secrets() {
        let mut completeness = Completeness::complete();
        let reference = rpc_reference(
            "https://alice:hunter2@RPC.Example/shortcred?api_key=secret#token",
            SelectorSource::ExplicitFlag,
            None,
            None,
            &mut completeness,
        );
        let json = serde_json::to_string(&reference).unwrap();
        assert!(json.contains("rpc.example"));
        for secret in [
            "alice",
            "hunter2",
            "shortcred",
            "api_key",
            "secret",
            "token",
        ] {
            assert!(!json.contains(secret), "leaked {secret}: {json}");
        }
        assert_eq!(reference.path_class, RpcPathClass::RedactedNonRoot);
        assert!(completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::RpcPathMatcherContextMissing));

        let mut completeness = Completeness::complete();
        let reviewed = rpc_reference(
            "https://rpc.example/v3/even-short-secrets-are-never-retained",
            SelectorSource::ExplicitFlag,
            None,
            None,
            &mut completeness,
        );
        assert_eq!(reviewed.path_class, RpcPathClass::VersionedApi);
        assert!(!serde_json::to_string(&reviewed)
            .unwrap()
            .contains("even-short-secrets"));
    }

    #[test]
    fn rpc_path_prefix_matching_is_transient_structured_and_private() {
        let secret_path = "tenant/short-credential/key";
        let allow_a = RpcPathMatcherId::new(1);
        let allow_b = RpcPathMatcherId::new(2);
        assert!(TrustedRpcPathPrefix::new(allow_a, "relative/path").is_none());
        let trusted = vec![
            TrustedRpcPathPrefix::new(allow_a, "/v3/tenant").unwrap(),
            TrustedRpcPathPrefix::new(allow_b, "/v2").unwrap(),
        ];
        let mut completeness = Completeness::complete();
        let reference = rpc_reference(
            &format!("https://rpc.example/v3/{secret_path}?api_key=query-secret"),
            SelectorSource::ExplicitFlag,
            None,
            Some(&trusted),
            &mut completeness,
        );
        assert!(completeness.is_complete());
        assert_eq!(reference.trusted_path_outcome(allow_a), Some(true));
        assert_eq!(reference.trusted_path_outcome(allow_b), Some(false));
        assert_eq!(
            reference.trusted_path_outcome(RpcPathMatcherId::new(999)),
            None
        );

        let json = serde_json::to_string(&reference).unwrap();
        assert!(json.contains(r#""matcher_id":1"#));
        assert!(json.contains(r#""matcher_id":2"#));
        let debug = format!("{reference:?}");
        for secret in [
            "tenant",
            "short-credential",
            "query-secret",
            "api_key",
            "prefix_digests",
            "sha256",
        ] {
            assert!(!json.contains(secret), "JSON leaked {secret}: {json}");
            assert!(!debug.contains(secret), "Debug leaked {secret}: {debug}");
        }
        let round_trip: RpcReferenceV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(round_trip, reference);
        assert_eq!(round_trip.trusted_path_outcome(allow_a), Some(true));

        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash as _, Hasher as _};
        let mut original_hash = DefaultHasher::new();
        reference.hash(&mut original_hash);
        let mut round_trip_hash = DefaultHasher::new();
        round_trip.hash(&mut round_trip_hash);
        assert_eq!(original_hash.finish(), round_trip_hash.finish());
    }

    #[test]
    fn rpc_path_prefix_digest_budget_is_explicit_and_private() {
        let matchers = (0..=MAX_TRUSTED_RPC_PATH_MATCHERS)
            .map(|index| {
                TrustedRpcPathPrefix::new(
                    RpcPathMatcherId::new(u64::try_from(index).unwrap()),
                    "/private",
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let mut completeness = Completeness::complete();
        let reference = rpc_reference(
            "https://rpc.example/private-segment?token=query-secret",
            SelectorSource::ExplicitFlag,
            None,
            Some(&matchers),
            &mut completeness,
        );
        assert!(reference.path_match_outcomes.as_slice().is_empty());
        assert!(completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::RpcPathMatcherBudgetExceeded));
        let json = serde_json::to_string(&reference).unwrap();
        assert!(!json.contains("private-segment"));
        assert!(!json.contains("query-secret"));
        let round_trip: RpcReferenceV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(round_trip, reference);
    }

    #[test]
    fn rpc_path_matcher_aggregate_bytes_are_bounded() {
        let large_prefix = format!("/{}", "x".repeat(16 * 1024 - 1));
        let matchers = (0..17)
            .map(|index| {
                TrustedRpcPathPrefix::new(RpcPathMatcherId::new(index), large_prefix.clone())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(matchers.len() < MAX_TRUSTED_RPC_PATH_MATCHERS);
        let mut completeness = Completeness::complete();
        let reference = rpc_reference(
            "https://rpc.example/private",
            SelectorSource::ExplicitFlag,
            None,
            Some(&matchers),
            &mut completeness,
        );
        assert!(reference.path_match_outcomes.as_slice().is_empty());
        assert!(completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::RpcPathMatcherBudgetExceeded));
    }

    #[test]
    fn rpc_path_match_outcome_seq_rejects_2049_before_collection_growth() {
        assert!(serde_json::from_str::<RpcPathMatcherId>(r#""unbounded-string""#).is_err());
        assert!(serde_json::from_str::<RpcPathMatcherId>("-1").is_err());

        let exact_limit = format!(
            "[{}]",
            (0..MAX_TRUSTED_RPC_PATH_MATCHERS)
                .map(|index| format!(r#"{{"matcher_id":{index},"matched":false}}"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        let exact_limit =
            serde_json::from_str::<RpcPathMatchOutcomes>(&exact_limit).expect("2,048 outcomes");
        assert_eq!(exact_limit.as_slice().len(), MAX_TRUSTED_RPC_PATH_MATCHERS);

        let encoded = format!(
            "[{}]",
            (0..=MAX_TRUSTED_RPC_PATH_MATCHERS)
                .map(|index| format!(r#"{{"matcher_id":{index},"matched":false}}"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(serde_json::from_str::<RpcPathMatchOutcomes>(&encoded).is_err());

        let duplicate = r#"[{"matcher_id":7,"matched":true},{"matcher_id":7,"matched":false}]"#;
        assert!(serde_json::from_str::<RpcPathMatchOutcomes>(duplicate).is_err());
    }

    #[test]
    fn supplied_root_path_matchers_are_evaluated_transiently() {
        let root = RpcPathMatcherId::new(10);
        let versioned = RpcPathMatcherId::new(11);
        let trusted = vec![
            TrustedRpcPathPrefix::new(root, "/").unwrap(),
            TrustedRpcPathPrefix::new(versioned, "/v3").unwrap(),
        ];
        let mut completeness = Completeness::complete();
        let reference = rpc_reference(
            "https://rpc.example",
            SelectorSource::ExplicitFlag,
            None,
            Some(&trusted),
            &mut completeness,
        );
        assert!(completeness.is_complete());
        assert_eq!(reference.path_class, RpcPathClass::Root);
        assert_eq!(reference.trusted_path_outcome(root), Some(true));
        assert_eq!(reference.trusted_path_outcome(versioned), Some(false));
        let json = serde_json::to_string(&reference).unwrap();
        assert!(!json.contains("rpc-path.invalid"));
        assert!(!json.contains("/v3"));
    }

    #[test]
    fn raw_and_canonical_path_disagreement_is_incomplete() {
        let id = RpcPathMatcherId::new(41);
        let matchers = vec![TrustedRpcPathPrefix::for_origin(
            id,
            "/private",
            "https",
            "rpc.example",
            None,
            false,
        )
        .unwrap()];
        let mut completeness = Completeness::complete();
        let reference = rpc_reference(
            "https://rpc.example/trusted/../private",
            SelectorSource::ExplicitFlag,
            None,
            Some(&matchers),
            &mut completeness,
        );
        assert_eq!(reference.trusted_path_outcome(id), None);
        assert!(completeness
            .gaps()
            .any(|gap| gap == IncompleteReason::RpcPathMatcherInvalid));
    }

    #[test]
    fn path_probe_retention_is_scoped_to_the_observed_origin() {
        let mut matchers = (0..100)
            .map(|index| {
                TrustedRpcPathPrefix::for_origin(
                    RpcPathMatcherId::new(index),
                    "/private",
                    "https",
                    "unrelated.example",
                    None,
                    false,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let relevant = RpcPathMatcherId::new(100);
        matchers.push(
            TrustedRpcPathPrefix::for_origin(
                relevant,
                "/private",
                "https",
                "rpc.example",
                None,
                false,
            )
            .unwrap(),
        );
        let mut completeness = Completeness::complete();
        let reference = rpc_reference(
            "https://rpc.example/private",
            SelectorSource::ExplicitFlag,
            None,
            Some(&matchers),
            &mut completeness,
        );
        assert!(completeness.is_complete());
        assert_eq!(reference.trusted_path_outcome(relevant), Some(true));
        assert_eq!(reference.path_match_outcomes.as_slice().len(), 1);
    }

    #[test]
    fn path_probe_origin_uses_effective_default_port() {
        let id = RpcPathMatcherId::new(150);
        let matcher = TrustedRpcPathPrefix::for_origin(
            id,
            "/private",
            "https",
            "rpc.example",
            Some(443),
            false,
        )
        .unwrap();
        for url in [
            "https://rpc.example/private",
            "https://rpc.example:443/private",
        ] {
            let mut completeness = Completeness::complete();
            let reference = rpc_reference(
                url,
                SelectorSource::ExplicitFlag,
                None,
                Some(std::slice::from_ref(&matcher)),
                &mut completeness,
            );
            assert!(completeness.is_complete());
            assert_eq!(reference.trusted_path_outcome(id), Some(true));
        }
    }

    #[test]
    fn duplicate_and_over_retained_relevant_path_probes_fail_closed() {
        let duplicate_a = RpcPathMatcherId::new(201);
        let duplicate_b = RpcPathMatcherId::new(202);
        let duplicate = [duplicate_a, duplicate_b]
            .into_iter()
            .map(|id| {
                TrustedRpcPathPrefix::for_origin(
                    id,
                    "/private",
                    "https",
                    "rpc.example",
                    None,
                    false,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let mut complete = Completeness::complete();
        let reference = rpc_reference(
            "https://rpc.example/private",
            SelectorSource::ExplicitFlag,
            None,
            Some(&duplicate),
            &mut complete,
        );
        assert_eq!(reference.trusted_path_outcome(duplicate_a), Some(true));
        assert_eq!(reference.trusted_path_outcome(duplicate_b), Some(true));

        let same_id = vec![
            TrustedRpcPathPrefix::for_origin(
                RpcPathMatcherId::new(250),
                "/private",
                "https",
                "rpc.example",
                None,
                false,
            )
            .unwrap(),
            TrustedRpcPathPrefix::for_origin(
                RpcPathMatcherId::new(250),
                "/other",
                "https",
                "rpc.example",
                None,
                false,
            )
            .unwrap(),
        ];
        let mut duplicate_id = Completeness::complete();
        let reference = rpc_reference(
            "https://rpc.example/private",
            SelectorSource::ExplicitFlag,
            None,
            Some(&same_id),
            &mut duplicate_id,
        );
        assert!(reference.path_match_outcomes.as_slice().is_empty());
        assert!(duplicate_id
            .gaps()
            .any(|gap| gap == IncompleteReason::RpcPathMatcherInvalid));

        let relevant = (0..=MAX_RETAINED_RPC_PATH_MATCH_OUTCOMES)
            .map(|index| {
                TrustedRpcPathPrefix::for_origin(
                    RpcPathMatcherId::new(300 + index as u64),
                    "/private",
                    "https",
                    "rpc.example",
                    None,
                    false,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let mut incomplete = Completeness::complete();
        let reference = rpc_reference(
            "https://rpc.example/private",
            SelectorSource::ExplicitFlag,
            None,
            Some(&relevant),
            &mut incomplete,
        );
        assert_eq!(
            reference.path_match_outcomes.as_slice().len(),
            MAX_RETAINED_RPC_PATH_MATCH_OUTCOMES
        );
        assert!(incomplete
            .gaps()
            .any(|gap| gap == IncompleteReason::RpcPathMatcherBudgetExceeded));
    }

    #[test]
    fn path_prefixes_are_segment_bounded() {
        let id = RpcPathMatcherId::new(500);
        let matcher =
            TrustedRpcPathPrefix::for_origin(id, "/rpc", "https", "rpc.example", None, false)
                .unwrap();
        for (url, matched) in [
            ("https://rpc.example/rpc", true),
            ("https://rpc.example/rpc/v1", true),
            ("https://rpc.example/rpc2", false),
        ] {
            let mut completeness = Completeness::complete();
            let reference = rpc_reference(
                url,
                SelectorSource::ExplicitFlag,
                None,
                Some(std::slice::from_ref(&matcher)),
                &mut completeness,
            );
            assert!(completeness.is_complete());
            assert_eq!(reference.trusted_path_outcome(id), Some(matched));
        }
    }

    #[test]
    fn rpc_path_class_deserialization_is_backward_and_forward_tolerant() {
        let constructed_secret = RpcReferenceV2 {
            scheme: Some("https".to_string()),
            host: Some("rpc.example".to_string()),
            port: None,
            path: Some("/manually-constructed-secret".to_string()),
            path_class: RpcPathClass::RedactedNonRoot,
            path_match_outcomes: RpcPathMatchOutcomes::default(),
            alias: None,
            source: SelectorSource::ExplicitFlag,
            span: None,
        };
        assert!(!serde_json::to_string(&constructed_secret)
            .unwrap()
            .contains("manually-constructed-secret"));
        assert!(!format!("{constructed_secret:?}").contains("manually-constructed-secret"));

        let mut encoded = serde_json::to_value(RpcReferenceV2 {
            scheme: Some("https".to_string()),
            host: Some("rpc.example".to_string()),
            port: None,
            path: Some("/rpc".to_string()),
            path_class: RpcPathClass::Rpc,
            path_match_outcomes: RpcPathMatchOutcomes::default(),
            alias: None,
            source: SelectorSource::ExplicitFlag,
            span: None,
        })
        .unwrap();
        encoded.as_object_mut().unwrap().remove("path_class");
        let legacy: RpcReferenceV2 = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(legacy.path_class, RpcPathClass::Rpc);
        assert_eq!(legacy.path.as_deref(), Some("/rpc"));

        encoded.as_object_mut().unwrap().remove("path");
        let legacy_missing_path: RpcReferenceV2 = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(legacy_missing_path.path_class, RpcPathClass::Unknown);
        assert!(legacy_missing_path.path.is_none());

        encoded.as_object_mut().unwrap().insert(
            "path".to_string(),
            serde_json::Value::String("/v3/private-secret".to_string()),
        );
        let legacy_versioned: RpcReferenceV2 = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(legacy_versioned.path_class, RpcPathClass::VersionedApi);
        assert_eq!(legacy_versioned.path.as_deref(), Some("/v3"));
        assert!(!serde_json::to_string(&legacy_versioned)
            .unwrap()
            .contains("private-secret"));

        let mut alias = encoded.clone();
        alias.as_object_mut().unwrap().insert(
            "alias".to_string(),
            serde_json::Value::String("devnet".to_string()),
        );
        let legacy_alias: RpcReferenceV2 = serde_json::from_value(alias).unwrap();
        assert_eq!(legacy_alias.path_class, RpcPathClass::Unknown);
        assert!(legacy_alias.path.is_none());

        encoded.as_object_mut().unwrap().insert(
            "path_class".to_string(),
            serde_json::Value::String("future_versioned_path".to_string()),
        );
        let future: RpcReferenceV2 = serde_json::from_value(encoded).unwrap();
        assert_eq!(future.path_class, RpcPathClass::Unknown);
        assert!(future.path.is_none());
    }

    #[test]
    fn exact_environment_reference_is_deliberately_narrow() {
        assert_eq!(exact_environment_reference("${RPC_URL}"), Some("RPC_URL"));
        assert_eq!(exact_environment_reference("https://${RPC_URL}"), None);
        assert_eq!(exact_environment_reference("${NOT-AN-ENV}"), None);
    }
}
