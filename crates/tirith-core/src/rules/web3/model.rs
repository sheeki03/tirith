use crate::effects::{
    CommandEffects, CommandEffectsV2, Completeness, CompletenessV2, IncompleteReasonV2, SourceSpan,
};
use serde::de::{Error as _, IgnoredAny, SeqAccess, Visitor};
use serde::ser::SerializeStruct as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::io::Read;
use std::marker::PhantomData;

pub const MAX_TRUSTED_RPC_PATH_MATCHERS: usize = 2048;
pub const MAX_TRUSTED_RPC_MATCHER_BYTES: usize = 256 * 1024;
const MAX_TRUSTED_RPC_PATH_PREFIX_BYTES: usize = 16 * 1024;
pub(crate) const MAX_RETAINED_RPC_PATH_MATCH_OUTCOMES: usize = 64;
const MAX_WEB3_WIRE_STRING_BYTES: usize = 16 * 1024;
pub(crate) const MAX_WEB3_WIRE_COMMANDS: usize = 256;
const MAX_WEB3_WIRE_SIGNERS: usize = 16;
const MAX_WEB3_WIRE_DESTINATIONS: usize = 256;
const MAX_WEB3_WIRE_SAFETY_FLAGS: usize = 64;
pub const MAX_WEB3_PARSE_RESULT_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_WEB3_ENVELOPE_KEY_BYTES: usize = 64;
const MAX_WEB3_JSON_DEPTH: usize = 128;
const MAX_SECRET_QUOTE_LAYERS: usize = 16;

struct BoundedString<const MAX: usize>(String);

struct BoundedStringVisitor<const MAX: usize>;

impl<const MAX: usize> BoundedStringVisitor<MAX> {
    fn checked<E>(value: &str) -> Result<String, E>
    where
        E: serde::de::Error,
    {
        if value.len() > MAX {
            return Err(E::custom("Web3 wire string exceeds the byte budget"));
        }
        Ok(value.to_string())
    }
}

impl<'de, const MAX: usize> Visitor<'de> for BoundedStringVisitor<MAX> {
    type Value = BoundedString<MAX>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a string of at most {MAX} bytes")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Self::checked(value).map(BoundedString)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Self::checked(value).map(BoundedString)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() > MAX {
            return Err(E::custom("Web3 wire string exceeds the byte budget"));
        }
        Ok(BoundedString(value))
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BoundedString<MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_string(BoundedStringVisitor::<MAX>)
    }
}

struct BoundedVec<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> Default for BoundedVec<T, MAX> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

struct BoundedVecVisitor<T, const MAX: usize>(PhantomData<T>);

impl<'de, T, const MAX: usize> Visitor<'de> for BoundedVecVisitor<T, MAX>
where
    T: Deserialize<'de>,
{
    type Value = BoundedVec<T, MAX>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a sequence of at most {MAX} Web3 items")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX));
        loop {
            if values.len() == MAX {
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom(
                        "Web3 wire sequence exceeds the item budget",
                    ));
                }
                break;
            }
            let Some(value) = sequence.next_element::<T>()? else {
                break;
            };
            values.push(value);
        }
        Ok(BoundedVec(values))
    }
}

impl<'de, T, const MAX: usize> Deserialize<'de> for BoundedVec<T, MAX>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedVecVisitor::<T, MAX>(PhantomData))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3ToolFamily {
    Cast,
    Forge,
    Hardhat,
    Solana,
    Anchor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3Operation {
    Send,
    Create,
    Call,
    Balance,
    Code,
    MakeTransaction,
    Script,
    IgnitionDeploy,
    PluginDeploy,
    RunScript,
    ProgramDeploy,
    ProgramShow,
    ProgramDump,
    Query,
    AnchorDeploy,
    Build,
    Test,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3OperationV2 {
    Send,
    Create,
    Call,
    Balance,
    Code,
    MakeTransaction,
    Script,
    IgnitionDeploy,
    PluginDeploy,
    RunScript,
    ProgramDeploy,
    ProgramShow,
    ProgramDump,
    Query,
    Address,
    AnchorDeploy,
    Build,
    Test,
    Unknown,
}

impl From<Web3Operation> for Web3OperationV2 {
    fn from(operation: Web3Operation) -> Self {
        match operation {
            Web3Operation::Send => Self::Send,
            Web3Operation::Create => Self::Create,
            Web3Operation::Call => Self::Call,
            Web3Operation::Balance => Self::Balance,
            Web3Operation::Code => Self::Code,
            Web3Operation::MakeTransaction => Self::MakeTransaction,
            Web3Operation::Script => Self::Script,
            Web3Operation::IgnitionDeploy => Self::IgnitionDeploy,
            Web3Operation::PluginDeploy => Self::PluginDeploy,
            Web3Operation::RunScript => Self::RunScript,
            Web3Operation::ProgramDeploy => Self::ProgramDeploy,
            Web3Operation::ProgramShow => Self::ProgramShow,
            Web3Operation::ProgramDump => Self::ProgramDump,
            Web3Operation::Query => Self::Query,
            Web3Operation::AnchorDeploy => Self::AnchorDeploy,
            Web3Operation::Build => Self::Build,
            Web3Operation::Test => Self::Test,
            Web3Operation::Unknown => Self::Unknown,
        }
    }
}

impl From<Web3OperationV2> for Web3Operation {
    fn from(operation: Web3OperationV2) -> Self {
        match operation {
            Web3OperationV2::Send => Self::Send,
            Web3OperationV2::Create => Self::Create,
            Web3OperationV2::Call => Self::Call,
            Web3OperationV2::Balance => Self::Balance,
            Web3OperationV2::Code => Self::Code,
            Web3OperationV2::MakeTransaction => Self::MakeTransaction,
            Web3OperationV2::Script => Self::Script,
            Web3OperationV2::IgnitionDeploy => Self::IgnitionDeploy,
            Web3OperationV2::PluginDeploy => Self::PluginDeploy,
            Web3OperationV2::RunScript => Self::RunScript,
            Web3OperationV2::ProgramDeploy => Self::ProgramDeploy,
            Web3OperationV2::ProgramShow => Self::ProgramShow,
            Web3OperationV2::ProgramDump => Self::ProgramDump,
            Web3OperationV2::Query | Web3OperationV2::Address => Self::Query,
            Web3OperationV2::AnchorDeploy => Self::AnchorDeploy,
            Web3OperationV2::Build => Self::Build,
            Web3OperationV2::Test => Self::Test,
            Web3OperationV2::Unknown => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3WriteMode {
    StateChanging,
    PotentialWrite,
    DryRun,
    NoChainWrite,
    ReadOnly,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectorSource {
    ExplicitFlag,
    LeadingEnvironment,
    AmbientEnvironment,
    StaticConfig,
    ToolDefault,
    Positional,
    Unresolved,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SelectorReference {
    pub value: String,
    pub source: SelectorSource,
    pub span: Option<SourceSpan>,
}

impl fmt::Debug for SelectorReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secret = retained_value_is_secret(&self.value);
        let value = if secret {
            "<redacted>"
        } else {
            self.value.as_str()
        };
        let source = if secret {
            SelectorSource::Unresolved
        } else {
            self.source
        };
        formatter
            .debug_struct("SelectorReference")
            .field("value", &value)
            .field("source", &source)
            .field("span", &self.span)
            .finish()
    }
}

impl Serialize for SelectorReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let secret = retained_value_is_secret(&self.value);
        let value = if secret {
            "<redacted>"
        } else {
            self.value.as_str()
        };
        let source = if secret {
            SelectorSource::Unresolved
        } else {
            self.source
        };
        let mut state = serializer.serialize_struct("SelectorReference", 3)?;
        state.serialize_field("value", value)?;
        state.serialize_field("source", &source)?;
        state.serialize_field("span", &self.span)?;
        state.end()
    }
}

#[derive(Deserialize)]
struct SelectorReferenceWire {
    value: BoundedString<MAX_WEB3_WIRE_STRING_BYTES>,
    source: SelectorSource,
    #[serde(default)]
    span: Option<SourceSpan>,
}

impl<'de> Deserialize<'de> for SelectorReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SelectorReferenceWire::deserialize(deserializer)?;
        let secret = retained_value_is_secret(&wire.value.0);
        Ok(Self {
            value: if secret {
                "<redacted>".to_string()
            } else {
                wire.value.0
            },
            source: if secret {
                SelectorSource::Unresolved
            } else {
                wire.source
            },
            span: wire.span,
        })
    }
}

/// Caller-supplied, trusted policy input for one RPC URL path prefix. The raw
/// prefix is used only while parsing an observed URL and is never copied into a
/// command fact, serialized, or rendered by `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustedRpcPathPrefix {
    id: RpcPathMatcherId,
    raw_prefix: String,
    canonical_prefix: String,
    origin: Option<TrustedRpcOrigin>,
}

#[derive(Clone, PartialEq, Eq)]
struct TrustedRpcOrigin {
    scheme: String,
    host: String,
    port: Option<u16>,
    subdomains: bool,
}

impl TrustedRpcPathPrefix {
    pub fn new(id: RpcPathMatcherId, prefix: impl Into<String>) -> Option<Self> {
        let prefix = prefix.into();
        if prefix.len() > MAX_TRUSTED_RPC_PATH_PREFIX_BYTES {
            return None;
        }
        Some(Self {
            id,
            canonical_prefix: canonical_path(&prefix)?,
            raw_prefix: prefix,
            origin: None,
        })
    }

    /// Construct a path probe scoped to one RPC origin. Policy compilation uses
    /// this form so unrelated path-bearing endpoints cannot consume the bounded
    /// outcome budget for the endpoint currently being parsed.
    pub(crate) fn for_origin(
        id: RpcPathMatcherId,
        prefix: impl Into<String>,
        scheme: impl Into<String>,
        host: impl Into<String>,
        port: Option<u16>,
        subdomains: bool,
    ) -> Option<Self> {
        let mut matcher = Self::new(id, prefix)?;
        matcher.origin = Some(TrustedRpcOrigin {
            scheme: scheme.into(),
            host: host.into(),
            port,
            subdomains,
        });
        Some(matcher)
    }

    pub fn id(&self) -> RpcPathMatcherId {
        self.id
    }

    pub(crate) fn prefix_len(&self) -> usize {
        self.raw_prefix.len() + self.canonical_prefix.len()
    }

    fn matches_origin(&self, scheme: &str, host: &str, port: Option<u16>) -> bool {
        let Some(origin) = self.origin.as_ref() else {
            return true;
        };
        if !origin.scheme.eq_ignore_ascii_case(scheme)
            || origin
                .port
                .is_some_and(|expected| effective_rpc_port(scheme, port) != Some(expected))
        {
            return false;
        }
        host.eq_ignore_ascii_case(&origin.host)
            || (origin.subdomains
                && host.len() > origin.host.len()
                && host
                    .get(..host.len() - origin.host.len())
                    .is_some_and(|prefix| prefix.ends_with('.'))
                && host[host.len() - origin.host.len()..].eq_ignore_ascii_case(&origin.host))
    }

    fn matches_raw_and_canonical(&self, raw_path: &str, canonical_path: &str) -> Option<bool> {
        let raw = path_prefix_matches(raw_path, &self.raw_prefix);
        let canonical = path_prefix_matches(canonical_path, &self.canonical_prefix);
        (raw == canonical).then_some(raw)
    }
}

fn path_prefix_matches(path: &str, prefix: &str) -> bool {
    path == prefix
        || (path.starts_with(prefix)
            && (prefix.ends_with('/') || path.as_bytes().get(prefix.len()) == Some(&b'/')))
}

fn effective_rpc_port(scheme: &str, port: Option<u16>) -> Option<u16> {
    port.or_else(|| match scheme.to_ascii_lowercase().as_str() {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        _ => None,
    })
}

impl fmt::Debug for TrustedRpcPathPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedRpcPathPrefix")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Fixed-width opaque identifier supplied by trusted policy code. Numeric
/// deserialization prevents an attacker-controlled per-item string allocation
/// before the surrounding sequence budget is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RpcPathMatcherId(u64);

impl RpcPathMatcherId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

struct RpcPathMatcherIdVisitor;

impl<'de> Visitor<'de> for RpcPathMatcherIdVisitor {
    type Value = RpcPathMatcherId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a fixed-width unsigned RPC path matcher ID")
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(RpcPathMatcherId(value))
    }
}

impl<'de> Deserialize<'de> for RpcPathMatcherId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_u64(RpcPathMatcherIdVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RpcPathMatchOutcome {
    pub matcher_id: RpcPathMatcherId,
    pub matched: bool,
}

/// Bounded, nonsecret outcomes for caller-supplied trusted matcher IDs. The
/// decoder accepts the public context ceiling, while parser-produced facts
/// retain only a small prefix and mark the parse incomplete when more trusted
/// comparisons were supplied. This keeps the complete result wire-bounded.
#[derive(Clone, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct RpcPathMatchOutcomes(Vec<RpcPathMatchOutcome>);

impl RpcPathMatchOutcomes {
    pub fn as_slice(&self) -> &[RpcPathMatchOutcome] {
        &self.0
    }

    pub fn outcome_for(&self, matcher_id: RpcPathMatcherId) -> Option<bool> {
        self.0
            .iter()
            .find(|outcome| outcome.matcher_id == matcher_id)
            .map(|outcome| outcome.matched)
    }

    pub(crate) fn compare(
        matchers: &[TrustedRpcPathPrefix],
        scheme: &str,
        host: &str,
        port: Option<u16>,
        raw_path: &str,
        canonical_path: &str,
    ) -> Result<(Self, bool), RpcPathMatcherValidationError> {
        let relevant = matchers
            .iter()
            .filter(|matcher| matcher.matches_origin(scheme, host, port))
            .collect::<Vec<_>>();
        if relevant.len() > MAX_TRUSTED_RPC_PATH_MATCHERS
            || relevant
                .iter()
                .try_fold(0usize, |total, matcher| {
                    total.checked_add(matcher.prefix_len())
                })
                .is_none_or(|total| total > MAX_TRUSTED_RPC_MATCHER_BYTES)
        {
            return Err(RpcPathMatcherValidationError::BudgetExceeded);
        }
        let mut ids = BTreeSet::new();
        let mut outcomes =
            Vec::with_capacity(relevant.len().min(MAX_RETAINED_RPC_PATH_MATCH_OUTCOMES));
        for matcher in relevant.iter().copied() {
            if !ids.insert(matcher.id) {
                return Err(RpcPathMatcherValidationError::Invalid);
            }
            let matched = matcher
                .matches_raw_and_canonical(raw_path, canonical_path)
                .ok_or(RpcPathMatcherValidationError::Ambiguous)?;
            if outcomes.len() < MAX_RETAINED_RPC_PATH_MATCH_OUTCOMES {
                outcomes.push(RpcPathMatchOutcome {
                    matcher_id: matcher.id,
                    matched,
                });
            }
        }
        let truncated = relevant.len() > outcomes.len();
        Ok((Self(outcomes), truncated))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RpcPathMatcherValidationError {
    BudgetExceeded,
    Invalid,
    Ambiguous,
}

impl fmt::Debug for RpcPathMatchOutcomes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RpcPathMatchOutcomes")
            .field(&self.0)
            .finish()
    }
}

struct RpcPathMatchOutcomesVisitor;

impl<'de> Visitor<'de> for RpcPathMatchOutcomesVisitor {
    type Value = RpcPathMatchOutcomes;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded sequence of trusted RPC path matcher outcomes")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let capacity = sequence
            .size_hint()
            .unwrap_or(0)
            .min(MAX_TRUSTED_RPC_PATH_MATCHERS);
        let mut outcomes = Vec::with_capacity(capacity);
        let mut ids = BTreeSet::new();
        loop {
            if outcomes.len() == MAX_TRUSTED_RPC_PATH_MATCHERS {
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom(
                        "too many trusted RPC path matcher outcomes",
                    ));
                }
                break;
            }
            let Some(outcome) = sequence.next_element::<RpcPathMatchOutcome>()? else {
                break;
            };
            if !ids.insert(outcome.matcher_id) {
                return Err(A::Error::custom("duplicate trusted RPC path matcher ID"));
            }
            outcomes.push(outcome);
        }
        Ok(RpcPathMatchOutcomes(outcomes))
    }
}

impl<'de> Deserialize<'de> for RpcPathMatchOutcomes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(RpcPathMatchOutcomesVisitor)
    }
}

/// Schema-v1 RPC shape retained exactly for 0.3.3 source compatibility.
/// Serialization and Debug sanitize the legacy raw `path` field.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RpcReference {
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub path: Option<String>,
    pub alias: Option<String>,
    pub source: SelectorSource,
    pub span: Option<SourceSpan>,
}

impl fmt::Debug for RpcReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = public_retained_value(self.scheme.as_deref());
        let host = public_retained_value(self.host.as_deref());
        let alias = public_retained_value(self.alias.as_deref());
        let redacted = (self.scheme.is_some() && scheme.is_none())
            || (self.host.is_some() && host.is_none())
            || (self.alias.is_some() && alias.is_none());
        let source = if redacted {
            SelectorSource::Unresolved
        } else {
            self.source
        };
        let class = self
            .path
            .as_deref()
            .map(classify_legacy_rpc_path)
            .unwrap_or(RpcPathClass::Unknown);
        formatter
            .debug_struct("RpcReference")
            .field("scheme", &scheme)
            .field("host", &host)
            .field("port", &self.port)
            .field("path", &public_rpc_path(self.path.as_deref(), class))
            .field("alias", &alias)
            .field("source", &source)
            .field("span", &self.span)
            .finish()
    }
}

impl Serialize for RpcReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let scheme = public_retained_value(self.scheme.as_deref());
        let host = public_retained_value(self.host.as_deref());
        let alias = public_retained_value(self.alias.as_deref());
        let redacted = (self.scheme.is_some() && scheme.is_none())
            || (self.host.is_some() && host.is_none())
            || (self.alias.is_some() && alias.is_none());
        let source = if redacted {
            SelectorSource::Unresolved
        } else {
            self.source
        };
        let literal_url = scheme.is_some() && host.is_some() && self.alias.is_none();
        let class = if literal_url {
            self.path
                .as_deref()
                .map(classify_legacy_rpc_path)
                .unwrap_or(RpcPathClass::Unknown)
        } else {
            RpcPathClass::Unknown
        };
        let path = literal_url
            .then(|| public_rpc_path(self.path.as_deref(), class))
            .flatten();
        let mut state = serializer.serialize_struct("RpcReference", 7)?;
        state.serialize_field("scheme", &scheme)?;
        state.serialize_field("host", &host)?;
        state.serialize_field("port", &self.port)?;
        state.serialize_field("path", &path)?;
        state.serialize_field("alias", &alias)?;
        state.serialize_field("source", &source)?;
        state.serialize_field("span", &self.span)?;
        state.end()
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RpcReferenceV2 {
    /// URL scheme, if the selector was a literal URL.
    pub scheme: Option<String>,
    /// Lowercase host only. URL userinfo, query, and fragment are never stored.
    pub host: Option<String>,
    pub port: Option<u16>,
    /// Compatibility view of the former raw path field. Only public, bounded
    /// representatives such as `/`, `/rpc`, or `/v3` are retained; arbitrary
    /// provider paths are redacted to `None`.
    pub path: Option<String>,
    /// Hashless, closed classification of the path. Arbitrary path components
    /// frequently contain provider credentials and are never retained.
    pub path_class: RpcPathClass,
    /// Matched/unmatched outcomes for caller-supplied trusted matcher IDs. No
    /// observed path or reversible comparison oracle is retained.
    pub path_match_outcomes: RpcPathMatchOutcomes,
    /// Alias or unresolved selector name. Literal URL text is never retained.
    pub alias: Option<String>,
    pub source: SelectorSource,
    pub span: Option<SourceSpan>,
}

impl fmt::Debug for RpcReferenceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = public_retained_value(self.scheme.as_deref());
        let host = public_retained_value(self.host.as_deref());
        let alias = public_retained_value(self.alias.as_deref());
        let redacted = (self.scheme.is_some() && scheme.is_none())
            || (self.host.is_some() && host.is_none())
            || (self.alias.is_some() && alias.is_none());
        let source = if redacted {
            SelectorSource::Unresolved
        } else {
            self.source
        };
        let literal_url = scheme.is_some() && host.is_some() && self.alias.is_none();
        let path_class = if literal_url {
            self.path_class
        } else {
            RpcPathClass::Unknown
        };
        let path = literal_url
            .then(|| public_rpc_path(self.path.as_deref(), path_class))
            .flatten();
        let empty_outcomes = RpcPathMatchOutcomes::default();
        let path_match_outcomes = if literal_url {
            &self.path_match_outcomes
        } else {
            &empty_outcomes
        };
        formatter
            .debug_struct("RpcReferenceV2")
            .field("scheme", &scheme)
            .field("host", &host)
            .field("port", &self.port)
            .field("path", &path)
            .field("path_class", &path_class)
            .field("path_match_outcomes", path_match_outcomes)
            .field("alias", &alias)
            .field("source", &source)
            .field("span", &self.span)
            .finish()
    }
}

impl Serialize for RpcReferenceV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let scheme = public_retained_value(self.scheme.as_deref());
        let host = public_retained_value(self.host.as_deref());
        let alias = public_retained_value(self.alias.as_deref());
        let redacted = (self.scheme.is_some() && scheme.is_none())
            || (self.host.is_some() && host.is_none())
            || (self.alias.is_some() && alias.is_none());
        let source = if redacted {
            SelectorSource::Unresolved
        } else {
            self.source
        };
        let literal_url = scheme.is_some() && host.is_some() && self.alias.is_none();
        let path_class = if literal_url {
            self.path_class
        } else {
            RpcPathClass::Unknown
        };
        let path = literal_url
            .then(|| public_rpc_path(self.path.as_deref(), path_class))
            .flatten();
        let empty_outcomes = RpcPathMatchOutcomes::default();
        let path_match_outcomes = if literal_url {
            &self.path_match_outcomes
        } else {
            &empty_outcomes
        };
        let mut state = serializer.serialize_struct("RpcReferenceV2", 9)?;
        state.serialize_field("scheme", &scheme)?;
        state.serialize_field("host", &host)?;
        state.serialize_field("port", &self.port)?;
        state.serialize_field("path", &path)?;
        state.serialize_field("path_class", &path_class)?;
        state.serialize_field("path_match_outcomes", path_match_outcomes)?;
        state.serialize_field("alias", &alias)?;
        state.serialize_field("source", &source)?;
        state.serialize_field("span", &self.span)?;
        state.end()
    }
}

#[derive(Deserialize)]
struct RpcReferenceWire {
    #[serde(default)]
    scheme: Option<BoundedString<MAX_WEB3_WIRE_STRING_BYTES>>,
    #[serde(default)]
    host: Option<BoundedString<MAX_WEB3_WIRE_STRING_BYTES>>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    path: Option<BoundedString<MAX_WEB3_WIRE_STRING_BYTES>>,
    #[serde(default)]
    path_class: Option<RpcPathClass>,
    #[serde(default)]
    path_match_outcomes: RpcPathMatchOutcomes,
    #[serde(default)]
    alias: Option<BoundedString<MAX_WEB3_WIRE_STRING_BYTES>>,
    source: SelectorSource,
    #[serde(default)]
    span: Option<SourceSpan>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcReferenceV1Wire {
    #[serde(default)]
    scheme: Option<BoundedString<MAX_WEB3_WIRE_STRING_BYTES>>,
    #[serde(default)]
    host: Option<BoundedString<MAX_WEB3_WIRE_STRING_BYTES>>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    path: Option<BoundedString<MAX_WEB3_WIRE_STRING_BYTES>>,
    #[serde(default)]
    alias: Option<BoundedString<MAX_WEB3_WIRE_STRING_BYTES>>,
    source: SelectorSource,
    #[serde(default)]
    span: Option<SourceSpan>,
}

fn classify_legacy_rpc_path(path: &str) -> RpcPathClass {
    let Some(path) = canonical_path(path) else {
        return RpcPathClass::Unknown;
    };
    let first = path.split('/').find(|segment| !segment.is_empty());
    match first {
        None => RpcPathClass::Root,
        Some("rpc") => RpcPathClass::Rpc,
        Some("v1" | "v2" | "v3") => RpcPathClass::VersionedApi,
        Some(_) => RpcPathClass::RedactedNonRoot,
    }
}

fn public_rpc_path(path: Option<&str>, path_class: RpcPathClass) -> Option<String> {
    match path_class {
        RpcPathClass::Root => Some("/".to_string()),
        RpcPathClass::Rpc => Some("/rpc".to_string()),
        RpcPathClass::VersionedApi => path.and_then(canonical_path).and_then(|path| {
            path.split('/')
                .find(|segment| matches!(*segment, "v1" | "v2" | "v3"))
                .map(|segment| format!("/{segment}"))
        }),
        RpcPathClass::RedactedNonRoot | RpcPathClass::Unknown => None,
    }
}

impl<'de> Deserialize<'de> for RpcReferenceV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RpcReferenceWire::deserialize(deserializer)?;
        let mut source = wire.source;
        let (scheme, next_source) =
            sanitize_optional_retained_value(wire.scheme.map(|value| value.0), source);
        source = next_source;
        let (host, next_source) =
            sanitize_optional_retained_value(wire.host.map(|value| value.0), source);
        source = next_source;
        let input_path = wire.path.map(|value| value.0);
        let raw_alias = wire.alias.map(|value| value.0);
        let alias_was_present = raw_alias.is_some();
        let (alias, next_source) = sanitize_optional_retained_value(raw_alias, source);
        source = next_source;
        let literal_url = scheme.is_some() && host.is_some() && !alias_was_present;
        let path_class = if literal_url {
            wire.path_class.unwrap_or_else(|| {
                input_path
                    .as_deref()
                    .map(classify_legacy_rpc_path)
                    .unwrap_or(RpcPathClass::Unknown)
            })
        } else {
            RpcPathClass::Unknown
        };
        let path = literal_url
            .then(|| public_rpc_path(input_path.as_deref(), path_class))
            .flatten();
        let path_match_outcomes = if literal_url {
            wire.path_match_outcomes
        } else {
            RpcPathMatchOutcomes::default()
        };
        Ok(Self {
            scheme,
            host,
            port: wire.port,
            path,
            path_class,
            path_match_outcomes,
            alias,
            source,
            span: wire.span,
        })
    }
}

impl RpcReferenceV2 {
    pub fn trusted_path_outcome(&self, matcher_id: RpcPathMatcherId) -> Option<bool> {
        self.path_match_outcomes.outcome_for(matcher_id)
    }
}

impl From<RpcReferenceV2> for RpcReference {
    fn from(reference: RpcReferenceV2) -> Self {
        let (scheme, source) = sanitize_optional_retained_value(reference.scheme, reference.source);
        let (host, source) = sanitize_optional_retained_value(reference.host, source);
        let (alias, source) = sanitize_optional_retained_value(reference.alias, source);
        Self {
            scheme,
            host,
            port: reference.port,
            path: reference.path,
            alias,
            source,
            span: reference.span,
        }
    }
}

impl From<RpcReference> for RpcReferenceV2 {
    fn from(reference: RpcReference) -> Self {
        let alias_was_present = reference.alias.is_some();
        let (scheme, source) = sanitize_optional_retained_value(reference.scheme, reference.source);
        let (host, source) = sanitize_optional_retained_value(reference.host, source);
        let (alias, source) = sanitize_optional_retained_value(reference.alias, source);
        let literal_url = scheme.is_some() && host.is_some() && !alias_was_present;
        let path_class = if literal_url {
            reference
                .path
                .as_deref()
                .map(classify_legacy_rpc_path)
                .unwrap_or(RpcPathClass::Unknown)
        } else {
            RpcPathClass::Unknown
        };
        let path = literal_url
            .then(|| public_rpc_path(reference.path.as_deref(), path_class))
            .flatten();
        Self {
            scheme,
            host,
            port: reference.port,
            path,
            path_class,
            path_match_outcomes: RpcPathMatchOutcomes::default(),
            alias,
            source,
            span: reference.span,
        }
    }
}

impl<'de> Deserialize<'de> for RpcReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RpcReferenceV1Wire::deserialize(deserializer)?;
        let mut source = wire.source;
        let (scheme, next_source) =
            sanitize_optional_retained_value(wire.scheme.map(|value| value.0), source);
        source = next_source;
        let (host, next_source) =
            sanitize_optional_retained_value(wire.host.map(|value| value.0), source);
        source = next_source;
        let raw_alias = wire.alias.map(|value| value.0);
        let alias_was_present = raw_alias.is_some();
        let (alias, next_source) = sanitize_optional_retained_value(raw_alias, source);
        source = next_source;
        let literal_url = scheme.is_some() && host.is_some() && !alias_was_present;
        let path = literal_url
            .then(|| {
                let input = wire.path.map(|value| value.0);
                let class = input
                    .as_deref()
                    .map(classify_legacy_rpc_path)
                    .unwrap_or(RpcPathClass::Unknown);
                public_rpc_path(input.as_deref(), class)
            })
            .flatten();
        Ok(Self {
            scheme,
            host,
            port: wire.port,
            path,
            alias,
            source,
            span: wire.span,
        })
    }
}

fn canonical_path(path: &str) -> Option<String> {
    if !path.starts_with('/') || path.contains('?') || path.contains('#') {
        return None;
    }
    url::Url::parse(&format!("https://rpc-path.invalid{path}"))
        .ok()
        .map(|url| url.path().to_string())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcPathClass {
    Root,
    Rpc,
    VersionedApi,
    RedactedNonRoot,
    #[serde(other)]
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEvidence {
    pub network: Option<SelectorReference>,
    pub chain: Option<SelectorReference>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerKind {
    RawPrivateKey,
    RawKeypair,
    Mnemonic,
    KeypairFile,
    Keystore,
    Ledger,
    Trezor,
    AwsKms,
    UnlockedNode,
    AccountAlias,
    Unknown,
}

impl SignerKind {
    pub fn is_raw_secret(self) -> bool {
        matches!(
            self,
            Self::RawPrivateKey | Self::RawKeypair | Self::Mnemonic
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerKindV2 {
    RawPrivateKey,
    RawKeypair,
    Mnemonic,
    KeypairFile,
    Keystore,
    Ledger,
    Trezor,
    AwsKms,
    UnlockedNode,
    AccountAlias,
    Stdin,
    Prompt,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerRole {
    Default,
    Keypair,
    Authority,
    FeePayer,
    ProgramId,
    Wallet,
}

impl SignerKindV2 {
    pub fn is_raw_secret(self) -> bool {
        matches!(
            self,
            Self::RawPrivateKey | Self::RawKeypair | Self::Mnemonic
        )
    }
}

impl From<SignerKind> for SignerKindV2 {
    fn from(kind: SignerKind) -> Self {
        match kind {
            SignerKind::RawPrivateKey => Self::RawPrivateKey,
            SignerKind::RawKeypair => Self::RawKeypair,
            SignerKind::Mnemonic => Self::Mnemonic,
            SignerKind::KeypairFile => Self::KeypairFile,
            SignerKind::Keystore => Self::Keystore,
            SignerKind::Ledger => Self::Ledger,
            SignerKind::Trezor => Self::Trezor,
            SignerKind::AwsKms => Self::AwsKms,
            SignerKind::UnlockedNode => Self::UnlockedNode,
            SignerKind::AccountAlias => Self::AccountAlias,
            SignerKind::Unknown => Self::Unknown,
        }
    }
}

impl From<SignerKindV2> for SignerKind {
    fn from(kind: SignerKindV2) -> Self {
        match kind {
            SignerKindV2::RawPrivateKey => Self::RawPrivateKey,
            SignerKindV2::RawKeypair => Self::RawKeypair,
            SignerKindV2::Mnemonic => Self::Mnemonic,
            SignerKindV2::KeypairFile => Self::KeypairFile,
            SignerKindV2::Keystore => Self::Keystore,
            SignerKindV2::Ledger => Self::Ledger,
            SignerKindV2::Trezor => Self::Trezor,
            SignerKindV2::AwsKms => Self::AwsKms,
            SignerKindV2::UnlockedNode => Self::UnlockedNode,
            SignerKindV2::AccountAlias => Self::AccountAlias,
            SignerKindV2::Stdin | SignerKindV2::Prompt | SignerKindV2::Unknown => Self::Unknown,
        }
    }
}

/// A signer reference with a structural serialization firewall. Raw secret
/// kinds cannot retain a `reference` value, and custom `Debug`/`Serialize`
/// defensively omit it even if construction invariants are changed later.
#[derive(Clone, PartialEq, Eq)]
pub struct SignerReferenceV2 {
    kind: SignerKindV2,
    source: SelectorSource,
    span: Option<SourceSpan>,
    reference: Option<String>,
}

const SIGNER_REFERENCE_PROJECTION_PREFIX: &str = "sha256:";

pub(crate) fn signer_reference_projection_digest(value: &str) -> Option<&str> {
    let digest = value.strip_prefix(SIGNER_REFERENCE_PROJECTION_PREFIX)?;
    (digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(digest)
}

pub(crate) fn privacy_project_signer_reference(value: &str) -> String {
    use sha2::{Digest as _, Sha256};

    if let Some(digest) = signer_reference_projection_digest(value) {
        return format!(
            "{SIGNER_REFERENCE_PROJECTION_PREFIX}{}",
            digest.to_ascii_lowercase()
        );
    }
    format!(
        "{SIGNER_REFERENCE_PROJECTION_PREFIX}{:x}",
        Sha256::digest(value.as_bytes())
    )
}

#[derive(Deserialize)]
struct SignerReferenceV2Wire {
    kind: SignerKindV2,
    source: SelectorSource,
    #[serde(default)]
    span: Option<SourceSpan>,
    #[serde(default)]
    reference: Option<BoundedString<MAX_WEB3_WIRE_STRING_BYTES>>,
}

impl SignerReferenceV2 {
    pub(crate) fn raw(
        kind: SignerKindV2,
        source: SelectorSource,
        span: Option<SourceSpan>,
    ) -> Self {
        debug_assert!(kind.is_raw_secret());
        Self {
            kind,
            source,
            span,
            reference: None,
        }
    }

    pub(crate) fn reference(
        kind: SignerKindV2,
        source: SelectorSource,
        span: Option<SourceSpan>,
        reference: Option<String>,
    ) -> Self {
        if kind == SignerKindV2::KeypairFile {
            match reference.as_deref() {
                Some("-") => {
                    return Self {
                        kind: SignerKindV2::Stdin,
                        source,
                        span,
                        reference: None,
                    }
                }
                Some(value) if value.eq_ignore_ascii_case("ASK") => {
                    return Self {
                        kind: SignerKindV2::Prompt,
                        source,
                        span,
                        reference: None,
                    }
                }
                _ => {}
            }
        }
        if let Some(raw_kind) = reference.as_deref().and_then(classify_raw_signer_value) {
            return Self::raw(raw_kind, source, span);
        }
        if let Some(scheme) = reference.as_deref().and_then(signer_uri_scheme) {
            if let Some(uri) = reference.as_deref().and_then(parse_signer_uri) {
                if let Some(uri_kind) = classify_signer_uri(&uri) {
                    return Self {
                        kind: uri_kind,
                        source,
                        span,
                        reference: None,
                    };
                }
                return Self {
                    kind: SignerKindV2::Unknown,
                    source: SelectorSource::Unresolved,
                    span,
                    reference: public_signer_uri(&uri),
                };
            }
            return Self {
                kind: SignerKindV2::Unknown,
                source: SelectorSource::Unresolved,
                span,
                reference: public_signer_scheme(scheme),
            };
        }
        debug_assert!(!kind.is_raw_secret());
        Self {
            kind,
            source,
            span,
            reference,
        }
    }

    /// Preserve a caller-proven literal kind without applying the generic
    /// signer-value grammar. Some CLI flags are path-only even when the path
    /// happens to look like a hardware URI, stdin marker, or prompt sentinel.
    /// Raw-secret-shaped reference text is still discarded defensively.
    pub(crate) fn literal_reference(
        kind: SignerKindV2,
        source: SelectorSource,
        span: Option<SourceSpan>,
        reference: Option<String>,
    ) -> Self {
        debug_assert!(!kind.is_raw_secret());
        let reference = reference
            .filter(|value| signer_uri_scheme(value).is_none())
            .filter(|value| classify_raw_signer_value(value).is_none());
        Self {
            kind,
            source,
            span,
            reference,
        }
    }

    pub fn kind(&self) -> SignerKindV2 {
        self.kind
    }

    pub fn source(&self) -> SelectorSource {
        self.source
    }

    pub fn span(&self) -> Option<SourceSpan> {
        self.span
    }

    pub fn nonsecret_reference(&self) -> Option<&str> {
        (!self.kind.is_raw_secret())
            .then_some(self.reference.as_deref())
            .flatten()
    }

    pub(crate) fn replace_span(&mut self, span: SourceSpan) {
        self.span = Some(span);
    }
}

fn signer_uri_scheme(value: &str) -> Option<&str> {
    let value = value.trim();
    let delimiter = value.find(':')?;
    let scheme = &value[..delimiter];
    if scheme.is_empty()
        || !scheme
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
        // A single-letter prefix is a Windows drive designator, including the
        // drive-relative `C:wallet.json` spelling.
        || scheme.len() == 1
    {
        return None;
    }
    Some(scheme)
}

fn supported_signer_uri_scheme(scheme: &str) -> bool {
    matches!(
        scheme.to_ascii_lowercase().as_str(),
        "usb"
            | "vault"
            | "pkcs11"
            | "aws-kms"
            | "gcp-kms"
            | "azure-kms"
            | "kms"
            | "http"
            | "https"
            | "file"
    )
}

fn parse_signer_uri(value: &str) -> Option<url::Url> {
    let value = value.trim();
    let scheme = signer_uri_scheme(value)?;
    let remainder = value.get(scheme.len() + 1..)?;
    if !remainder.starts_with("//") || !supported_signer_uri_scheme(scheme) {
        return None;
    }
    url::Url::parse(value).ok()
}

fn classify_signer_uri(parsed: &url::Url) -> Option<SignerKindV2> {
    match (
        parsed.scheme(),
        parsed.host_str().map(str::to_ascii_lowercase),
    ) {
        ("usb", Some(device)) if device == "ledger" => Some(SignerKindV2::Ledger),
        ("usb", Some(device)) if device == "trezor" => Some(SignerKindV2::Trezor),
        _ => None,
    }
}

fn public_signer_uri(parsed: &url::Url) -> Option<String> {
    // Never project attacker-controlled authority text. Even a hostname can be
    // a credential or tenant identifier. Only fixed labels for reviewed,
    // non-sensitive scheme classes cross the serialization boundary.
    match parsed.scheme().to_ascii_lowercase().as_str() {
        "vault" => Some("vault:".to_string()),
        "pkcs11" => Some("pkcs11:".to_string()),
        "aws-kms" | "gcp-kms" | "azure-kms" | "kms" => Some("kms:".to_string()),
        "http" | "https" => Some("network:".to_string()),
        "file" => Some("file:".to_string()),
        _ => None,
    }
}

fn public_signer_scheme(scheme: &str) -> Option<String> {
    match scheme.to_ascii_lowercase().as_str() {
        "vault" => Some("vault:".to_string()),
        "pkcs11" => Some("pkcs11:".to_string()),
        "aws-kms" | "gcp-kms" | "azure-kms" | "kms" => Some("kms:".to_string()),
        "http" | "https" => Some("network:".to_string()),
        "file" => Some("file:".to_string()),
        _ => None,
    }
}

fn normalized_secret_candidate(value: &str) -> Result<&str, ()> {
    if value.len() > MAX_WEB3_WIRE_STRING_BYTES {
        return Err(());
    }
    let mut candidate = value.trim();
    for _ in 0..MAX_SECRET_QUOTE_LAYERS {
        let bytes = candidate.as_bytes();
        let balanced =
            bytes.len() >= 2 && matches!(bytes[0], b'\'' | b'"') && bytes.last() == bytes.first();
        if !balanced {
            return Ok(candidate);
        }
        candidate = candidate[1..candidate.len() - 1].trim();
    }
    let bytes = candidate.as_bytes();
    if bytes.len() >= 2 && matches!(bytes[0], b'\'' | b'"') && bytes.last() == bytes.first() {
        Err(())
    } else {
        Ok(candidate)
    }
}

/// Does `value` base58-decode to exactly 64 bytes, the size of an exported
/// ed25519 Solana secret key?
///
/// This is the textual form wallets export and users paste, so it must reach
/// the raw-secret firewall. A 32-byte public key decodes to a different length
/// and is unaffected, which keeps ordinary addresses and program ids readable.
/// The length envelope is checked before decoding so adversarial argv cannot
/// make the decode work scale with operand length.
fn base58_decodes_to_secret_key(value: &str) -> bool {
    const SECRET_KEY_BYTES: usize = 64;
    // 64 bytes is 87..=88 base58 characters; leading zero bytes shorten the
    // text, so accept from the byte count upward and let the decode decide.
    if !(SECRET_KEY_BYTES..=88).contains(&value.len()) || !value.is_ascii() {
        return false;
    }
    // Same alphabet as the pubkey decoder in `parse.rs`; kept local so this
    // security chokepoint does not depend on the command parser.
    let base58_value = |character: u8| {
        b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
            .iter()
            .position(|candidate| *candidate == character)
            .and_then(|value| u32::try_from(value).ok())
    };
    let leading_zeroes = value.bytes().take_while(|byte| *byte == b'1').count();
    let mut decoded_le = [0u8; SECRET_KEY_BYTES];
    let mut decoded_len = 0usize;
    for character in value.bytes() {
        let Some(mut carry) = base58_value(character) else {
            return false;
        };
        for byte in &mut decoded_le[..decoded_len] {
            let expanded = u32::from(*byte) * 58 + carry;
            *byte = (expanded & 0xff) as u8;
            carry = expanded >> 8;
        }
        while carry > 0 {
            if decoded_len == decoded_le.len() {
                return false;
            }
            decoded_le[decoded_len] = (carry & 0xff) as u8;
            decoded_len += 1;
            carry >>= 8;
        }
    }
    leading_zeroes.saturating_add(decoded_len) == SECRET_KEY_BYTES
}

fn classify_raw_signer_value(value: &str) -> Option<SignerKindV2> {
    // A candidate that exceeds the public string budget or quote-layer budget
    // is not safe to retain as a public signer reference. Classify it into a
    // raw-secret kind so every existing constructor fails closed without an
    // unbounded normalization pass.
    let trimmed = match normalized_secret_candidate(value) {
        Ok(candidate) => candidate,
        Err(()) => return Some(SignerKindV2::RawPrivateKey),
    };
    let possible_hex_key = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if possible_hex_key.len() == 64 && possible_hex_key.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Some(SignerKindV2::RawPrivateKey);
    }
    if plausible_solana_numeric_secret_array(trimmed) {
        return Some(SignerKindV2::RawKeypair);
    }
    if base58_decodes_to_secret_key(trimmed) {
        return Some(SignerKindV2::RawKeypair);
    }
    let words = trimmed.split_whitespace().collect::<Vec<_>>();
    if matches!(words.len(), 12 | 15 | 18 | 21 | 24)
        && words
            .iter()
            .all(|word| word.chars().all(|ch| ch.is_ascii_alphabetic()))
    {
        return Some(SignerKindV2::Mnemonic);
    }
    None
}

pub(crate) fn retained_value_is_secret(value: &str) -> bool {
    classify_raw_signer_value(value).is_some()
}

fn public_retained_value(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !retained_value_is_secret(value))
}

fn sanitize_optional_retained_value(
    value: Option<String>,
    source: SelectorSource,
) -> (Option<String>, SelectorSource) {
    if value.as_deref().is_some_and(retained_value_is_secret) {
        (None, SelectorSource::Unresolved)
    } else {
        (value, source)
    }
}

fn plausible_solana_numeric_secret_array(value: &str) -> bool {
    // Shell quoting, truncation, or a damaged copy/paste can drop either JSON
    // bracket while leaving the 32/64 comma-delimited byte shape intact.
    let body = value.strip_prefix('[').unwrap_or(value);
    let body = body.strip_suffix(']').unwrap_or(body);
    let slots = body.split(',').collect::<Vec<_>>();
    let elements = slots
        .iter()
        .copied()
        .map(str::trim)
        .filter(|element| !element.is_empty())
        .collect::<Vec<_>>();
    // A damaged 32/64-byte array commonly gains or loses a delimiter, an
    // element, or its closing bracket. Never downgrade those near-shapes to a
    // filesystem path merely because the malformed input is not exactly 32 or
    // 64 well-formed tokens.
    if !(30..=66).contains(&slots.len()) && !(30..=66).contains(&elements.len()) {
        return false;
    }
    let numeric = elements
        .iter()
        .filter(|element| {
            let digits = element
                .strip_prefix('+')
                .or_else(|| element.strip_prefix('-'))
                .unwrap_or(element);
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
        .count();
    // Eight numeric slots inside an otherwise array-shaped 30-66-slot value is
    // enough evidence to fail closed. The remaining slots may be missing,
    // out-of-range, truncated, or replaced by malformed byte tokens.
    numeric >= 8
}

impl fmt::Debug for SignerReferenceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reference = self
            .reference
            .as_deref()
            .map(privacy_project_signer_reference);
        let mut value = formatter.debug_struct("SignerReferenceV2");
        value
            .field("kind", &self.kind)
            .field("source", &self.source)
            .field("span", &self.span);
        if !self.kind.is_raw_secret() {
            value.field("reference", &reference);
        }
        value.finish()
    }
}

impl Serialize for SignerReferenceV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let reference = (!self.kind.is_raw_secret())
            .then(|| {
                self.reference
                    .as_deref()
                    .map(privacy_project_signer_reference)
            })
            .flatten();
        let include_reference = reference.is_some();
        let mut state = serializer
            .serialize_struct("SignerReferenceV2", if include_reference { 4 } else { 3 })?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("source", &self.source)?;
        state.serialize_field("span", &self.span)?;
        if include_reference {
            state.serialize_field("reference", &reference)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for SignerReferenceV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SignerReferenceV2Wire::deserialize(deserializer)?;
        let reference = wire.reference.map(|value| value.0);
        if wire.kind.is_raw_secret() {
            return Ok(Self::raw(wire.kind, wire.source, wire.span));
        }
        if let Some(projected) = reference
            .as_deref()
            .and_then(signer_reference_projection_digest)
        {
            return Ok(Self {
                kind: wire.kind,
                source: wire.source,
                span: wire.span,
                reference: Some(format!(
                    "{SIGNER_REFERENCE_PROJECTION_PREFIX}{}",
                    projected.to_ascii_lowercase()
                )),
            });
        }
        if wire.kind == SignerKindV2::Unknown {
            let reference = reference.filter(|reference| {
                matches!(
                    reference.as_str(),
                    "vault:" | "pkcs11:" | "kms:" | "network:" | "file:"
                )
            });
            return Ok(Self {
                kind: SignerKindV2::Unknown,
                source: SelectorSource::Unresolved,
                span: wire.span,
                reference,
            });
        }
        Ok(Self::reference(
            wire.kind,
            wire.source,
            wire.span,
            reference,
        ))
    }
}

/// Schema-v1 signer shape and kind set retained for exhaustive source and wire
/// compatibility. New signer classes live only in `SignerKindV2`.
#[derive(Clone, PartialEq, Eq)]
pub struct SignerReference {
    kind: SignerKind,
    source: SelectorSource,
    span: Option<SourceSpan>,
    reference: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignerReferenceV1Wire {
    kind: SignerKind,
    source: SelectorSource,
    #[serde(default)]
    span: Option<SourceSpan>,
    #[serde(default)]
    reference: Option<BoundedString<MAX_WEB3_WIRE_STRING_BYTES>>,
}

impl SignerReference {
    pub fn kind(&self) -> SignerKind {
        self.kind
    }

    pub fn source(&self) -> SelectorSource {
        self.source
    }

    pub fn span(&self) -> Option<SourceSpan> {
        self.span
    }

    pub fn nonsecret_reference(&self) -> Option<&str> {
        (!self.kind.is_raw_secret())
            .then_some(self.reference.as_deref())
            .flatten()
    }
}

impl fmt::Debug for SignerReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reference = self
            .reference
            .as_deref()
            .map(privacy_project_signer_reference);
        let mut value = formatter.debug_struct("SignerReference");
        value
            .field("kind", &self.kind)
            .field("source", &self.source)
            .field("span", &self.span);
        if !self.kind.is_raw_secret() {
            value.field("reference", &reference);
        }
        value.finish()
    }
}

impl Serialize for SignerReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let reference = (!self.kind.is_raw_secret())
            .then(|| {
                self.reference
                    .as_deref()
                    .map(privacy_project_signer_reference)
            })
            .flatten();
        let include_reference = reference.is_some();
        let mut state = serializer
            .serialize_struct("SignerReference", if include_reference { 4 } else { 3 })?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("source", &self.source)?;
        state.serialize_field("span", &self.span)?;
        if include_reference {
            state.serialize_field("reference", &reference)?;
        }
        state.end()
    }
}

impl<'de> Deserialize<'de> for SignerReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SignerReferenceV1Wire::deserialize(deserializer)?;
        if wire.kind.is_raw_secret() {
            return Ok(Self {
                kind: wire.kind,
                source: wire.source,
                span: wire.span,
                reference: None,
            });
        }
        if let Some(projected) = wire
            .reference
            .as_ref()
            .map(|value| value.0.as_str())
            .and_then(signer_reference_projection_digest)
        {
            return Ok(Self {
                kind: wire.kind,
                source: wire.source,
                span: wire.span,
                reference: Some(format!(
                    "{SIGNER_REFERENCE_PROJECTION_PREFIX}{}",
                    projected.to_ascii_lowercase()
                )),
            });
        }
        if wire.kind == SignerKind::Unknown {
            return Ok(Self {
                kind: SignerKind::Unknown,
                source: SelectorSource::Unresolved,
                span: wire.span,
                reference: wire.reference.map(|value| value.0).filter(|reference| {
                    matches!(
                        reference.as_str(),
                        "vault:" | "pkcs11:" | "kms:" | "network:" | "file:"
                    )
                }),
            });
        }
        Ok(SignerReferenceV2::reference(
            wire.kind.into(),
            wire.source,
            wire.span,
            wire.reference.map(|value| value.0),
        )
        .into())
    }
}

impl From<SignerReferenceV2> for SignerReference {
    fn from(reference: SignerReferenceV2) -> Self {
        let new_only = matches!(reference.kind, SignerKindV2::Stdin | SignerKindV2::Prompt);
        Self {
            kind: reference.kind.into(),
            source: if new_only {
                SelectorSource::Unresolved
            } else {
                reference.source
            },
            span: reference.span,
            reference: (!new_only).then_some(reference.reference).flatten(),
        }
    }
}

impl From<SignerReference> for SignerReferenceV2 {
    fn from(reference: SignerReference) -> Self {
        Self {
            kind: reference.kind.into(),
            source: reference.source,
            span: reference.span,
            reference: reference.reference,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleTaggedSigner {
    pub role: SignerRole,
    pub signer: SignerReferenceV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationKind {
    Address,
    Contract,
    Program,
    ProgramIdFile,
    Authority,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DestinationReference {
    pub kind: DestinationKind,
    pub value: Option<String>,
    pub source: SelectorSource,
    pub span: Option<SourceSpan>,
}

impl fmt::Debug for DestinationReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = public_retained_value(self.value.as_deref()).map(|value| {
            if self.kind == DestinationKind::ProgramIdFile {
                privacy_project_signer_reference(value)
            } else {
                value.to_string()
            }
        });
        let source = if self.value.is_some() && value.is_none() {
            SelectorSource::Unresolved
        } else {
            self.source
        };
        formatter
            .debug_struct("DestinationReference")
            .field("kind", &self.kind)
            .field("value", &value)
            .field("source", &source)
            .field("span", &self.span)
            .finish()
    }
}

impl Serialize for DestinationReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = public_retained_value(self.value.as_deref()).map(|value| {
            if self.kind == DestinationKind::ProgramIdFile {
                privacy_project_signer_reference(value)
            } else {
                value.to_string()
            }
        });
        let source = if self.value.is_some() && value.is_none() {
            SelectorSource::Unresolved
        } else {
            self.source
        };
        let mut state = serializer.serialize_struct("DestinationReference", 4)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("value", &value)?;
        state.serialize_field("source", &source)?;
        state.serialize_field("span", &self.span)?;
        state.end()
    }
}

#[derive(Deserialize)]
struct DestinationReferenceWire {
    kind: DestinationKind,
    #[serde(default)]
    value: Option<BoundedString<MAX_WEB3_WIRE_STRING_BYTES>>,
    source: SelectorSource,
    #[serde(default)]
    span: Option<SourceSpan>,
}

impl<'de> Deserialize<'de> for DestinationReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = DestinationReferenceWire::deserialize(deserializer)?;
        let (value, source) =
            sanitize_optional_retained_value(wire.value.map(|value| value.0), wire.source);
        Ok(Self {
            kind: wire.kind,
            value,
            source,
            span: wire.span,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Script,
    IgnitionModule,
    ContractBytecode,
    SolanaProgram,
    AnchorWorkspace,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ArtifactReference {
    pub kind: ArtifactKind,
    pub value: Option<String>,
    pub source: SelectorSource,
    pub span: Option<SourceSpan>,
}

impl fmt::Debug for ArtifactReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = public_retained_value(self.value.as_deref());
        let source = if self.value.is_some() && value.is_none() {
            SelectorSource::Unresolved
        } else {
            self.source
        };
        formatter
            .debug_struct("ArtifactReference")
            .field("kind", &self.kind)
            .field("value", &value)
            .field("source", &source)
            .field("span", &self.span)
            .finish()
    }
}

impl Serialize for ArtifactReference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = public_retained_value(self.value.as_deref());
        let source = if self.value.is_some() && value.is_none() {
            SelectorSource::Unresolved
        } else {
            self.source
        };
        let mut state = serializer.serialize_struct("ArtifactReference", 4)?;
        state.serialize_field("kind", &self.kind)?;
        state.serialize_field("value", &value)?;
        state.serialize_field("source", &source)?;
        state.serialize_field("span", &self.span)?;
        state.end()
    }
}

#[derive(Deserialize)]
struct ArtifactReferenceWire {
    kind: ArtifactKind,
    #[serde(default)]
    value: Option<BoundedString<MAX_WEB3_WIRE_STRING_BYTES>>,
    source: SelectorSource,
    #[serde(default)]
    span: Option<SourceSpan>,
}

impl<'de> Deserialize<'de> for ArtifactReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ArtifactReferenceWire::deserialize(deserializer)?;
        let (value, source) =
            sanitize_optional_retained_value(wire.value.map(|value| value.0), wire.source);
        Ok(Self {
            kind: wire.kind,
            value,
            source,
            span: wire.span,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3SafetyFlag {
    Broadcast,
    Resume,
    DryRun,
    NoSend,
    Offline,
    Unlocked,
    Force,
    SkipSimulation,
    SkipPreflight,
    Final,
    UseRpc,
    Slow,
    Verify,
}

/// Schema-v1 command facts retained exactly for source compatibility with
/// callers that construct this public type with a struct literal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Web3CommandFacts {
    pub tool: Web3ToolFamily,
    pub operation: Web3Operation,
    pub write_mode: Web3WriteMode,
    pub network: NetworkEvidence,
    pub rpc: Option<RpcReference>,
    pub signer: Option<SignerReference>,
    pub destination: Option<DestinationReference>,
    pub artifact: Option<ArtifactReference>,
    pub safety_flags: Vec<Web3SafetyFlag>,
    pub source_span: SourceSpan,
    pub completeness: Completeness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Web3CommandFactsV2 {
    pub tool: Web3ToolFamily,
    pub operation: Web3OperationV2,
    pub write_mode: Web3WriteMode,
    pub network: NetworkEvidence,
    pub rpc: Option<RpcReferenceV2>,
    /// Legacy single-signer projection retained for wire compatibility.
    pub signer: Option<SignerReferenceV2>,
    pub signers: Vec<RoleTaggedSigner>,
    pub destination: Option<DestinationReference>,
    pub destinations: Vec<DestinationReference>,
    pub artifact: Option<ArtifactReference>,
    pub safety_flags: Vec<Web3SafetyFlag>,
    pub source_span: SourceSpan,
    pub completeness: CompletenessV2,
}

impl Web3CommandFactsV2 {
    pub fn signer(&self, role: SignerRole) -> Option<&SignerReferenceV2> {
        self.signers
            .iter()
            .find(|tagged| tagged.role == role)
            .map(|tagged| &tagged.signer)
    }
}

fn projected_signer(signers: &[RoleTaggedSigner]) -> Option<SignerReferenceV2> {
    [
        SignerRole::Default,
        SignerRole::Keypair,
        SignerRole::Wallet,
        SignerRole::Authority,
        SignerRole::FeePayer,
        SignerRole::ProgramId,
    ]
    .into_iter()
    .find_map(|role| {
        signers
            .iter()
            .find(|tagged| tagged.role == role)
            .map(|tagged| tagged.signer.clone())
    })
}

impl Serialize for Web3CommandFactsV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let signer = projected_signer(&self.signers).or_else(|| self.signer.clone());
        let destination = self
            .destinations
            .first()
            .cloned()
            .or_else(|| self.destination.clone());
        let mut state = serializer.serialize_struct("Web3CommandFactsV2", 13)?;
        state.serialize_field("tool", &self.tool)?;
        state.serialize_field("operation", &self.operation)?;
        state.serialize_field("write_mode", &self.write_mode)?;
        state.serialize_field("network", &self.network)?;
        state.serialize_field("rpc", &self.rpc)?;
        state.serialize_field("signer", &signer)?;
        state.serialize_field("signers", &self.signers)?;
        state.serialize_field("destination", &destination)?;
        state.serialize_field("destinations", &self.destinations)?;
        state.serialize_field("artifact", &self.artifact)?;
        state.serialize_field("safety_flags", &self.safety_flags)?;
        state.serialize_field("source_span", &self.source_span)?;
        state.serialize_field("completeness", &self.completeness)?;
        state.end()
    }
}

#[derive(Deserialize)]
struct Web3CommandFactsV2Wire {
    tool: Web3ToolFamily,
    operation: Web3OperationV2,
    write_mode: Web3WriteMode,
    network: NetworkEvidence,
    #[serde(default)]
    rpc: Option<RpcReferenceV2>,
    #[serde(default)]
    signer: Option<SignerReferenceV2>,
    #[serde(default)]
    signers: BoundedVec<RoleTaggedSigner, MAX_WEB3_WIRE_SIGNERS>,
    #[serde(default)]
    destination: Option<DestinationReference>,
    #[serde(default)]
    destinations: BoundedVec<DestinationReference, MAX_WEB3_WIRE_DESTINATIONS>,
    #[serde(default)]
    artifact: Option<ArtifactReference>,
    safety_flags: BoundedVec<Web3SafetyFlag, MAX_WEB3_WIRE_SAFETY_FLAGS>,
    source_span: SourceSpan,
    completeness: CompletenessV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Web3CommandFactsV1Wire {
    tool: Web3ToolFamily,
    operation: Web3Operation,
    write_mode: Web3WriteMode,
    network: NetworkEvidence,
    #[serde(default)]
    rpc: Option<RpcReference>,
    #[serde(default)]
    signer: Option<SignerReference>,
    #[serde(default)]
    destination: Option<DestinationReference>,
    #[serde(default)]
    artifact: Option<ArtifactReference>,
    safety_flags: BoundedVec<Web3SafetyFlag, MAX_WEB3_WIRE_SAFETY_FLAGS>,
    source_span: SourceSpan,
    completeness: Completeness,
}

impl<'de> Deserialize<'de> for Web3CommandFactsV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = Web3CommandFactsV2Wire::deserialize(deserializer)?;
        let mut signers = wire.signers.0;
        if signers.is_empty() {
            if let Some(signer) = wire.signer.clone() {
                signers.push(RoleTaggedSigner {
                    role: SignerRole::Default,
                    signer,
                });
            }
        } else {
            let mut roles = BTreeSet::new();
            if signers.iter().any(|tagged| !roles.insert(tagged.role)) {
                return Err(D::Error::custom("duplicate Web3 signer role"));
            }
            if wire.signer.is_some() && wire.signer != projected_signer(&signers) {
                return Err(D::Error::custom(
                    "conflicting legacy and schema-v2 signer projections",
                ));
            }
            signers.sort_by_key(|tagged| tagged.role);
        }
        let signer = projected_signer(&signers);

        let mut destinations = wire.destinations.0;
        if destinations.is_empty() {
            if let Some(destination) = wire.destination.clone() {
                destinations.push(destination);
            }
        } else if wire.destination.is_some() && wire.destination.as_ref() != destinations.first() {
            return Err(D::Error::custom(
                "conflicting legacy and schema-v2 destination projections",
            ));
        }
        let destination = destinations.first().cloned();

        Ok(Self {
            tool: wire.tool,
            operation: wire.operation,
            write_mode: wire.write_mode,
            network: wire.network,
            rpc: wire.rpc,
            signer,
            signers,
            destination,
            destinations,
            artifact: wire.artifact,
            safety_flags: wire.safety_flags.0,
            source_span: wire.source_span,
            completeness: wire.completeness,
        })
    }
}

impl<'de> Deserialize<'de> for Web3CommandFacts {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = Web3CommandFactsV1Wire::deserialize(deserializer)?;
        Ok(Self {
            tool: wire.tool,
            operation: wire.operation,
            write_mode: wire.write_mode,
            network: wire.network,
            rpc: wire.rpc,
            signer: wire.signer,
            destination: wire.destination,
            artifact: wire.artifact,
            safety_flags: wire.safety_flags.0,
            source_span: wire.source_span,
            completeness: wire.completeness,
        })
    }
}

impl From<Web3CommandFactsV2> for Web3CommandFacts {
    fn from(facts: Web3CommandFactsV2) -> Self {
        Self {
            tool: facts.tool,
            operation: facts.operation.into(),
            write_mode: facts.write_mode,
            network: facts.network,
            rpc: facts.rpc.map(Into::into),
            signer: facts.signer.map(Into::into),
            destination: facts.destination,
            artifact: facts.artifact,
            safety_flags: facts.safety_flags,
            source_span: facts.source_span,
            completeness: facts.completeness.into(),
        }
    }
}

impl From<Web3CommandFacts> for Web3CommandFactsV2 {
    fn from(facts: Web3CommandFacts) -> Self {
        let mut completeness: CompletenessV2 = facts.completeness.clone().into();
        completeness.add(IncompleteReasonV2::LegacyProjectionIncomplete);
        let signer = facts.signer.map(SignerReferenceV2::from);
        let signers = signer
            .clone()
            .map(|signer| {
                vec![RoleTaggedSigner {
                    role: SignerRole::Default,
                    signer,
                }]
            })
            .unwrap_or_default();
        let destinations = facts.destination.clone().into_iter().collect();
        Self {
            tool: facts.tool,
            operation: facts.operation.into(),
            write_mode: facts.write_mode,
            network: facts.network,
            rpc: facts.rpc.map(Into::into),
            signer,
            signers,
            destination: facts.destination,
            destinations,
            artifact: facts.artifact,
            safety_flags: facts.safety_flags,
            source_span: facts.source_span,
            completeness,
        }
    }
}

/// Schema-v1 parse result retained exactly for source and legacy-wire
/// compatibility. The bounded JSON decode APIs interpret a missing result
/// discriminator as v1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Web3ParseResult {
    pub commands: Vec<Web3CommandFacts>,
    pub effects: CommandEffects,
    pub completeness: Completeness,
}

pub const WEB3_PARSE_RESULT_SCHEMA_V1: u16 = 1;
pub const WEB3_PARSE_RESULT_SCHEMA_V2: u16 = 2;

/// Error returned by the allocation-bounded JSON entry points for Web3 parse
/// results. Generic serde deserialization of already-materialized nested Web3
/// types is not an untrusted-input boundary; callers must use these APIs for
/// bytes received from files, IPC, or the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Web3JsonDecodeCategory {
    Envelope,
    Syntax,
    UnsupportedSchema,
    StringBudgetExceeded,
    SchemaV1Wire,
    SchemaV2Wire,
}

impl Web3JsonDecodeCategory {
    const fn sanitized_label(self) -> &'static str {
        match self {
            Self::Envelope => "invalid_envelope",
            Self::Syntax => "invalid_syntax",
            Self::UnsupportedSchema => "unsupported_schema",
            Self::StringBudgetExceeded => "string_budget_exceeded",
            Self::SchemaV1Wire => "invalid_schema_v1",
            Self::SchemaV2Wire => "invalid_schema_v2",
        }
    }
}

#[derive(Debug)]
pub enum Web3JsonDecodeError {
    InputBytesExceeded { limit: usize },
    Io(std::io::Error),
    InvalidUtf8(std::str::Utf8Error),
    InvalidJson(String),
}

impl fmt::Display for Web3JsonDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputBytesExceeded { limit } => {
                write!(
                    formatter,
                    "Web3 parse result exceeds the {limit}-byte JSON budget"
                )
            }
            Self::Io(error) => write!(formatter, "failed to read Web3 parse result JSON: {error}"),
            Self::InvalidUtf8(error) => {
                write!(formatter, "Web3 parse result is not UTF-8: {error}")
            }
            Self::InvalidJson(category) => {
                write!(formatter, "invalid Web3 parse result JSON ({category})")
            }
        }
    }
}

impl std::error::Error for Web3JsonDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::InvalidUtf8(error) => Some(error),
            Self::InputBytesExceeded { .. } | Self::InvalidJson(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Web3ParseResultV2 {
    pub commands: Vec<Web3CommandFactsV2>,
    pub effects: CommandEffectsV2,
    pub completeness: CompletenessV2,
}

enum DecodedWeb3ParseResult {
    V1(Web3ParseResult),
    V2(Web3ParseResultV2),
}

#[derive(Default)]
struct RawWeb3Envelope {
    schema_version: Option<u16>,
    commands: Option<std::ops::Range<usize>>,
    effects: Option<std::ops::Range<usize>>,
    completeness: Option<std::ops::Range<usize>>,
}

fn skip_json_whitespace(bytes: &[u8], mut index: usize) -> usize {
    while bytes
        .get(index)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    {
        index += 1;
    }
    index
}

fn json_hex_value(byte: u8) -> Option<u16> {
    match byte {
        b'0'..=b'9' => Some(u16::from(byte - b'0')),
        b'a'..=b'f' => Some(u16::from(byte - b'a') + 10),
        b'A'..=b'F' => Some(u16::from(byte - b'A') + 10),
        _ => None,
    }
}

fn json_code_unit(bytes: &[u8], index: usize) -> Option<u16> {
    let mut value = 0u16;
    for offset in 0..4 {
        value = value.checked_mul(16)?;
        value = value.checked_add(json_hex_value(*bytes.get(index + offset)?)?)?;
    }
    Some(value)
}

fn decoded_json_escape(bytes: &[u8], index: usize) -> Result<(char, usize), &'static str> {
    let escaped = *bytes.get(index).ok_or("incomplete JSON escape")?;
    if matches!(
        escaped,
        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't'
    ) {
        let value = match escaped {
            b'b' => '\u{0008}',
            b'f' => '\u{000c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            other => char::from(other),
        };
        return Ok((value, index + 1));
    }
    if escaped != b'u' {
        return Err("invalid JSON escape");
    }
    let first = json_code_unit(bytes, index + 1).ok_or("invalid JSON unicode escape")?;
    let mut end = index + 5;
    let scalar = if (0xd800..=0xdbff).contains(&first) {
        if bytes.get(end..end + 2) != Some(b"\\u") {
            return Err("unpaired JSON high surrogate");
        }
        let second = json_code_unit(bytes, end + 2).ok_or("invalid JSON low surrogate")?;
        if !(0xdc00..=0xdfff).contains(&second) {
            return Err("unpaired JSON high surrogate");
        }
        end += 6;
        0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
    } else if (0xdc00..=0xdfff).contains(&first) {
        return Err("unpaired JSON low surrogate");
    } else {
        u32::from(first)
    };
    char::from_u32(scalar)
        .map(|value| (value, end))
        .ok_or("invalid JSON unicode scalar")
}

fn parse_bounded_json_key(raw: &str, start: usize) -> Result<(String, usize), &'static str> {
    let bytes = raw.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return Err("Web3 envelope key is not a JSON string");
    }
    let mut key = String::new();
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return Ok((key, index + 1)),
            b'\\' => {
                let (value, end) = decoded_json_escape(bytes, index + 1)?;
                if key.len().saturating_add(value.len_utf8()) > MAX_WEB3_ENVELOPE_KEY_BYTES {
                    return Err("Web3 envelope key exceeds the byte budget");
                }
                key.push(value);
                index = end;
            }
            byte if byte < 0x20 => return Err("control byte in JSON string"),
            byte if byte.is_ascii() => {
                if key.len() == MAX_WEB3_ENVELOPE_KEY_BYTES {
                    return Err("Web3 envelope key exceeds the byte budget");
                }
                key.push(char::from(byte));
                index += 1;
            }
            _ => {
                let value = raw
                    .get(index..)
                    .and_then(|tail| tail.chars().next())
                    .ok_or("invalid UTF-8 in JSON string")?;
                if key.len().saturating_add(value.len_utf8()) > MAX_WEB3_ENVELOPE_KEY_BYTES {
                    return Err("Web3 envelope key exceeds the byte budget");
                }
                key.push(value);
                index += value.len_utf8();
            }
        }
    }
    Err("unterminated Web3 envelope key")
}

fn raw_json_string_end(raw: &str, start: usize) -> Result<usize, &'static str> {
    let bytes = raw.as_bytes();
    if bytes.get(start) != Some(&b'"') {
        return Err("expected JSON string");
    }
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return Ok(index + 1),
            b'\\' => {
                let (_, end) = decoded_json_escape(bytes, index + 1)?;
                index = end;
            }
            byte if byte < 0x20 => return Err("control byte in JSON string"),
            byte if byte.is_ascii() => index += 1,
            _ => {
                let value = raw
                    .get(index..)
                    .and_then(|tail| tail.chars().next())
                    .ok_or("invalid UTF-8 in JSON string")?;
                index += value.len_utf8();
            }
        }
    }
    Err("unterminated JSON string")
}

fn raw_json_value_end(raw: &str, start: usize) -> Result<usize, &'static str> {
    let bytes = raw.as_bytes();
    let start = skip_json_whitespace(bytes, start);
    match bytes.get(start).copied() {
        Some(b'"') => raw_json_string_end(raw, start),
        Some(open @ (b'{' | b'[')) => {
            let mut stack = [0u8; MAX_WEB3_JSON_DEPTH];
            let mut depth = 1usize;
            stack[0] = if open == b'{' { b'}' } else { b']' };
            let mut index = start + 1;
            while index < bytes.len() {
                match bytes[index] {
                    b'"' => index = raw_json_string_end(raw, index)?,
                    next @ (b'{' | b'[') => {
                        if depth == stack.len() {
                            return Err("Web3 JSON nesting exceeds the depth budget");
                        }
                        stack[depth] = if next == b'{' { b'}' } else { b']' };
                        depth += 1;
                        index += 1;
                    }
                    close @ (b'}' | b']') => {
                        if stack.get(depth - 1) != Some(&close) {
                            return Err("mismatched Web3 JSON delimiter");
                        }
                        depth -= 1;
                        index += 1;
                        if depth == 0 {
                            return Ok(index);
                        }
                    }
                    _ => index += 1,
                }
            }
            Err("unterminated Web3 JSON container")
        }
        Some(_) => {
            let mut index = start;
            while bytes
                .get(index)
                .is_some_and(|byte| !matches!(byte, b',' | b'}' | b']'))
            {
                index += 1;
            }
            let end = raw[..index].trim_end().len();
            (end > start)
                .then_some(end)
                .ok_or("missing Web3 JSON value")
        }
        None => Err("missing Web3 JSON value"),
    }
}

fn record_raw_web3_field(
    selected: &mut Option<std::ops::Range<usize>>,
    range: std::ops::Range<usize>,
    name: &'static str,
) -> Result<(), &'static str> {
    if selected.is_some() {
        return Err(match name {
            "commands" => "duplicate Web3 commands field",
            "effects" => "duplicate Web3 effects field",
            _ => "duplicate Web3 completeness field",
        });
    }
    *selected = Some(range);
    Ok(())
}

fn parse_raw_web3_envelope(raw: &str) -> Result<RawWeb3Envelope, &'static str> {
    if raw.len() > MAX_WEB3_PARSE_RESULT_JSON_BYTES {
        return Err("Web3 parse result exceeds the raw JSON byte budget");
    }
    let bytes = raw.as_bytes();
    let mut index = skip_json_whitespace(bytes, 0);
    if bytes.get(index) != Some(&b'{') {
        return Err("Web3 parse result must be a JSON object");
    }
    index += 1;
    let mut envelope = RawWeb3Envelope::default();
    loop {
        index = skip_json_whitespace(bytes, index);
        if bytes.get(index) == Some(&b'}') {
            index += 1;
            break;
        }
        let (key, key_end) = parse_bounded_json_key(raw, index)?;
        index = skip_json_whitespace(bytes, key_end);
        if bytes.get(index) != Some(&b':') {
            return Err("missing colon after Web3 envelope key");
        }
        let value_start = skip_json_whitespace(bytes, index + 1);
        let value_end = raw_json_value_end(raw, value_start)?;
        match key.as_str() {
            "schema_version" => {
                if envelope.schema_version.is_some() {
                    return Err("duplicate Web3 schema_version field");
                }
                let value = raw
                    .get(value_start..value_end)
                    .ok_or("invalid Web3 schema version range")?
                    .trim();
                if value.len() > 5 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err("invalid Web3 schema version");
                }
                envelope.schema_version = Some(
                    value
                        .parse::<u16>()
                        .map_err(|_| "invalid Web3 schema version")?,
                );
            }
            "commands" => {
                record_raw_web3_field(&mut envelope.commands, value_start..value_end, "commands")?
            }
            "effects" => {
                record_raw_web3_field(&mut envelope.effects, value_start..value_end, "effects")?
            }
            "completeness" => record_raw_web3_field(
                &mut envelope.completeness,
                value_start..value_end,
                "completeness",
            )?,
            _ => {}
        }
        index = skip_json_whitespace(bytes, value_end);
        match bytes.get(index) {
            Some(b',') => index += 1,
            Some(b'}') => {
                index += 1;
                break;
            }
            _ => return Err("invalid Web3 envelope member boundary"),
        }
    }
    if skip_json_whitespace(bytes, index) != bytes.len() {
        return Err("trailing data after Web3 parse result");
    }
    Ok(envelope)
}

fn bounded_json_string_end(
    raw: &str,
    start: usize,
    max_decoded_bytes: usize,
) -> Result<usize, &'static str> {
    let bytes = raw.as_bytes();
    let mut decoded = 0usize;
    let mut index = start + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => return Ok(index + 1),
            b'\\' => {
                let (value, end) = decoded_json_escape(bytes, index + 1)?;
                decoded = decoded.saturating_add(value.len_utf8());
                index = end;
            }
            byte if byte < 0x20 => return Err("control byte in JSON string"),
            byte if byte.is_ascii() => {
                decoded = decoded.saturating_add(1);
                index += 1;
            }
            _ => {
                let value = raw
                    .get(index..)
                    .and_then(|tail| tail.chars().next())
                    .ok_or("invalid UTF-8 in JSON string")?;
                decoded = decoded.saturating_add(value.len_utf8());
                index += value.len_utf8();
            }
        }
        if decoded > max_decoded_bytes {
            return Err("Web3 JSON string exceeds the decoded byte budget");
        }
    }
    Err("unterminated JSON string")
}

fn preflight_web3_json_strings(raw: &str) -> Result<(), &'static str> {
    let bytes = raw.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            index = bounded_json_string_end(raw, index, MAX_WEB3_WIRE_STRING_BYTES)?;
        } else {
            index += 1;
        }
    }
    Ok(())
}

fn raw_web3_field<'a>(
    raw: &'a str,
    range: Option<std::ops::Range<usize>>,
    name: &'static str,
) -> Result<&'a str, String> {
    let range = range.ok_or_else(|| format!("missing field `{name}`"))?;
    raw.get(range)
        .ok_or_else(|| "invalid Web3 envelope field range".to_string())
}

fn validate_web3_result_schema(schema_version: Option<u16>) -> Result<u16, Web3JsonDecodeCategory> {
    match schema_version.unwrap_or(WEB3_PARSE_RESULT_SCHEMA_V1) {
        version @ (WEB3_PARSE_RESULT_SCHEMA_V1 | WEB3_PARSE_RESULT_SCHEMA_V2) => Ok(version),
        _ => Err(Web3JsonDecodeCategory::UnsupportedSchema),
    }
}

fn validate_complete_web3_json_syntax(raw: &str) -> Result<(), Web3JsonDecodeCategory> {
    let mut deserializer = serde_json::Deserializer::from_str(raw);
    IgnoredAny::deserialize(&mut deserializer).map_err(|_| Web3JsonDecodeCategory::Syntax)?;
    deserializer
        .end()
        .map_err(|_| Web3JsonDecodeCategory::Syntax)
}

fn decode_raw_web3_result(raw: &str) -> Result<DecodedWeb3ParseResult, Web3JsonDecodeCategory> {
    let envelope = parse_raw_web3_envelope(raw).map_err(|_| Web3JsonDecodeCategory::Envelope)?;
    let schema = validate_web3_result_schema(envelope.schema_version)?;
    // Schema extraction remains allocation-bounded and precedes this full
    // grammar pass, preserving version-first rejection. `IgnoredAny` validates
    // every unknown field and strict JSON number form without materializing a
    // generic value tree.
    validate_complete_web3_json_syntax(raw)?;
    let commands = raw_web3_field(raw, envelope.commands, "commands")
        .map_err(|_| Web3JsonDecodeCategory::Envelope)?;
    let effects = raw_web3_field(raw, envelope.effects, "effects")
        .map_err(|_| Web3JsonDecodeCategory::Envelope)?;
    let completeness = raw_web3_field(raw, envelope.completeness, "completeness")
        .map_err(|_| Web3JsonDecodeCategory::Envelope)?;
    for field in [commands, effects, completeness] {
        preflight_web3_json_strings(field)
            .map_err(|_| Web3JsonDecodeCategory::StringBudgetExceeded)?;
    }
    match schema {
        WEB3_PARSE_RESULT_SCHEMA_V1 => {
            let commands = serde_json::from_str::<
                BoundedVec<Web3CommandFacts, MAX_WEB3_WIRE_COMMANDS>,
            >(commands)
            .map_err(|_| Web3JsonDecodeCategory::SchemaV1Wire)?
            .0;
            let effects = serde_json::from_str::<CommandEffects>(effects)
                .map_err(|_| Web3JsonDecodeCategory::SchemaV1Wire)?;
            let completeness = serde_json::from_str::<Completeness>(completeness)
                .map_err(|_| Web3JsonDecodeCategory::SchemaV1Wire)?;
            Ok(DecodedWeb3ParseResult::V1(Web3ParseResult {
                commands,
                effects,
                completeness,
            }))
        }
        WEB3_PARSE_RESULT_SCHEMA_V2 => {
            let commands = serde_json::from_str::<
                BoundedVec<Web3CommandFactsV2, MAX_WEB3_WIRE_COMMANDS>,
            >(commands)
            .map_err(|_| Web3JsonDecodeCategory::SchemaV2Wire)?
            .0;
            let effects = serde_json::from_str::<CommandEffectsV2>(effects)
                .map_err(|_| Web3JsonDecodeCategory::SchemaV2Wire)?;
            let completeness = serde_json::from_str::<CompletenessV2>(completeness)
                .map_err(|_| Web3JsonDecodeCategory::SchemaV2Wire)?;
            Ok(DecodedWeb3ParseResult::V2(Web3ParseResultV2 {
                commands,
                effects,
                completeness,
            }))
        }
        _ => unreachable!("validated above"),
    }
}

fn read_web3_json_bounded<R: Read>(reader: R) -> Result<Vec<u8>, Web3JsonDecodeError> {
    let mut limited = reader.take((MAX_WEB3_PARSE_RESULT_JSON_BYTES + 1) as u64);
    let mut bytes = Vec::new();
    limited
        .read_to_end(&mut bytes)
        .map_err(Web3JsonDecodeError::Io)?;
    if bytes.len() > MAX_WEB3_PARSE_RESULT_JSON_BYTES {
        return Err(Web3JsonDecodeError::InputBytesExceeded {
            limit: MAX_WEB3_PARSE_RESULT_JSON_BYTES,
        });
    }
    Ok(bytes)
}

impl Web3ParseResultV2 {
    /// Decode an untrusted JSON byte slice after enforcing the envelope byte
    /// cap and schema/string preflights before nested serde allocation.
    pub fn from_json_slice_bounded(input: &[u8]) -> Result<Self, Web3JsonDecodeError> {
        if input.len() > MAX_WEB3_PARSE_RESULT_JSON_BYTES {
            return Err(Web3JsonDecodeError::InputBytesExceeded {
                limit: MAX_WEB3_PARSE_RESULT_JSON_BYTES,
            });
        }
        let raw = std::str::from_utf8(input).map_err(Web3JsonDecodeError::InvalidUtf8)?;
        decode_raw_web3_result(raw)
            .map(|decoded| match decoded {
                DecodedWeb3ParseResult::V1(result) => result.into(),
                DecodedWeb3ParseResult::V2(result) => result,
            })
            .map_err(|category| {
                Web3JsonDecodeError::InvalidJson(category.sanitized_label().to_string())
            })
    }

    /// Decode untrusted JSON from a reader while reading at most one byte past
    /// the public cap. No serde deserializer sees the input before this bound.
    pub fn from_json_reader_bounded<R: Read>(reader: R) -> Result<Self, Web3JsonDecodeError> {
        let bytes = read_web3_json_bounded(reader)?;
        Self::from_json_slice_bounded(&bytes)
    }
}

impl Web3ParseResult {
    /// Decode either the legacy v1 wire shape or the versioned v2 shape and
    /// project the bounded result into the source-compatible v1 model.
    pub fn from_json_slice_bounded(input: &[u8]) -> Result<Self, Web3JsonDecodeError> {
        if input.len() > MAX_WEB3_PARSE_RESULT_JSON_BYTES {
            return Err(Web3JsonDecodeError::InputBytesExceeded {
                limit: MAX_WEB3_PARSE_RESULT_JSON_BYTES,
            });
        }
        let raw = std::str::from_utf8(input).map_err(Web3JsonDecodeError::InvalidUtf8)?;
        decode_raw_web3_result(raw)
            .map(|decoded| match decoded {
                DecodedWeb3ParseResult::V1(result) => result,
                DecodedWeb3ParseResult::V2(result) => result.into(),
            })
            .map_err(|category| {
                Web3JsonDecodeError::InvalidJson(category.sanitized_label().to_string())
            })
    }

    pub fn from_json_reader_bounded<R: Read>(reader: R) -> Result<Self, Web3JsonDecodeError> {
        let bytes = read_web3_json_bounded(reader)?;
        Self::from_json_slice_bounded(&bytes)
    }
}

impl Serialize for Web3ParseResultV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Web3ParseResultV2", 4)?;
        state.serialize_field("schema_version", &WEB3_PARSE_RESULT_SCHEMA_V2)?;
        state.serialize_field("commands", &self.commands)?;
        state.serialize_field("effects", &self.effects)?;
        state.serialize_field("completeness", &self.completeness)?;
        state.end()
    }
}

impl From<Web3ParseResultV2> for Web3ParseResult {
    fn from(result: Web3ParseResultV2) -> Self {
        Self {
            commands: result.commands.into_iter().map(Into::into).collect(),
            effects: result.effects.into(),
            completeness: result.completeness.into(),
        }
    }
}

impl From<Web3ParseResult> for Web3ParseResultV2 {
    fn from(result: Web3ParseResult) -> Self {
        let mut completeness: CompletenessV2 = result.completeness.into();
        completeness.add(IncompleteReasonV2::LegacyProjectionIncomplete);
        Self {
            commands: result.commands.into_iter().map(Into::into).collect(),
            effects: result.effects.into(),
            completeness,
        }
    }
}

#[cfg(test)]
mod privacy_tests {
    use super::*;

    #[test]
    fn signer_reference_debug_and_wire_use_stable_privacy_projection() {
        let raw = "/Users/alice/.config/solana/id.json";
        let signer = SignerReferenceV2::literal_reference(
            SignerKindV2::KeypairFile,
            SelectorSource::ExplicitFlag,
            None,
            Some(raw.to_string()),
        );

        let debug = format!("{signer:?}");
        let json = serde_json::to_string(&signer).unwrap();
        assert!(!debug.contains(raw));
        assert!(!json.contains(raw));
        let projected = privacy_project_signer_reference(raw);
        assert!(debug.contains(&projected));
        assert!(json.contains(&projected));

        let decoded: SignerReferenceV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.kind(), SignerKindV2::KeypairFile);
        assert_eq!(decoded.nonsecret_reference(), Some(projected.as_str()));
    }

    #[test]
    fn keypair_reference_classifies_runtime_sentinels_but_literal_paths_do_not() {
        for (value, expected) in [
            ("-", SignerKindV2::Stdin),
            ("ASK", SignerKindV2::Prompt),
            ("ask", SignerKindV2::Prompt),
        ] {
            let signer = SignerReferenceV2::reference(
                SignerKindV2::KeypairFile,
                SelectorSource::ExplicitFlag,
                None,
                Some(value.to_string()),
            );
            assert_eq!(signer.kind(), expected);
            assert!(signer.nonsecret_reference().is_none());
        }
        let literal = SignerReferenceV2::literal_reference(
            SignerKindV2::KeypairFile,
            SelectorSource::ExplicitFlag,
            None,
            Some("ASK".to_string()),
        );
        assert_eq!(literal.kind(), SignerKindV2::KeypairFile);
        assert_eq!(literal.nonsecret_reference(), Some("ASK"));
    }

    #[test]
    fn legacy_signer_and_program_id_destination_do_not_serialize_credential_paths() {
        let raw = "C:\\wallets\\program-authority.json";
        let signer: SignerReference = SignerReferenceV2::literal_reference(
            SignerKindV2::KeypairFile,
            SelectorSource::ExplicitFlag,
            None,
            Some(raw.to_string()),
        )
        .into();
        let destination = DestinationReference {
            kind: DestinationKind::ProgramIdFile,
            value: Some(raw.to_string()),
            source: SelectorSource::ExplicitFlag,
            span: None,
        };

        for rendered in [
            format!("{signer:?}"),
            serde_json::to_string(&signer).unwrap(),
            format!("{destination:?}"),
            serde_json::to_string(&destination).unwrap(),
        ] {
            assert!(
                !rendered.contains("program-authority.json"),
                "credential path leaked: {rendered}"
            );
            assert!(rendered.contains("sha256:"));
        }
    }
}
