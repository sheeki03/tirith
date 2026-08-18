//! Secret-safe semantic effects inferred from commands.
//!
//! Effects describe capability, not authorization.  Policy code may consume
//! these values later, but this module deliberately does not emit findings or
//! make allow/deny decisions.

use serde::de::{Error as _, IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

const MAX_DESERIALIZED_COMPLETENESS_GAPS: usize = 64;
pub const MAX_COMMAND_EFFECTS: usize = 512;

/// A byte span in the original command.  The source bytes are intentionally not
/// retained: secret-bearing arguments are represented only by type and span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SourceSpan {
    pub start: usize,
    pub end: usize,
}

impl SourceSpan {
    pub fn new(start: usize, end: usize) -> Self {
        Self {
            start,
            end: end.max(start),
        }
    }
}

/// Typed reasons why semantic analysis could not be complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncompleteReason {
    SegmentBudgetExceeded,
    WrapperDepthExceeded,
    PackageRunnerDepthExceeded,
    ArgumentCountExceeded,
    ArgumentBytesExceeded,
    ConfigBytesExceeded,
    AliasResolutionBudgetExceeded,
    ContextSelectorBudgetExceeded,
    SelectorBytesExceeded,
    MissingFlagValue,
    ConflictingSelector,
    UnknownOption,
    AmbiguousSubcommand,
    UnresolvedIndirection,
    IncompleteQuoting,
    DynamicConfigUnsupported,
    ConfigMissing,
    ConfigNotRegular,
    ConfigMalformed,
    ConfigIo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncompleteReasonV2 {
    InputBytesExceeded,
    EffectBudgetExceeded,
    SegmentBudgetExceeded,
    WrapperDepthExceeded,
    PackageRunnerDepthExceeded,
    ArgumentCountExceeded,
    ArgumentBytesExceeded,
    ConfigBytesExceeded,
    AliasResolutionBudgetExceeded,
    ContextSelectorBudgetExceeded,
    SelectorBytesExceeded,
    RpcPathMatcherContextMissing,
    RpcPathMatcherBudgetExceeded,
    RpcPathMatcherInvalid,
    MissingFlagValue,
    ConflictingSelector,
    UnknownOption,
    AmbiguousSubcommand,
    UnresolvedIndirection,
    ExecutionContextChanged,
    WorkingDirectoryUnresolved,
    SignerMissing,
    DynamicExecutionUnsupported,
    /// A schema-v1 fact was projected into v2. V1 cannot represent the exact
    /// ordered signer/destination sets required by v2 enforcement, so the
    /// projection is diagnostic-only even when the legacy producer reported
    /// complete analysis.
    LegacyProjectionIncomplete,
    IncompleteQuoting,
    DynamicConfigUnsupported,
    ConfigMissing,
    ConfigNotRegular,
    ConfigMalformed,
    ConfigIo,
}

impl From<IncompleteReason> for IncompleteReasonV2 {
    fn from(reason: IncompleteReason) -> Self {
        match reason {
            IncompleteReason::SegmentBudgetExceeded => Self::SegmentBudgetExceeded,
            IncompleteReason::WrapperDepthExceeded => Self::WrapperDepthExceeded,
            IncompleteReason::PackageRunnerDepthExceeded => Self::PackageRunnerDepthExceeded,
            IncompleteReason::ArgumentCountExceeded => Self::ArgumentCountExceeded,
            IncompleteReason::ArgumentBytesExceeded => Self::ArgumentBytesExceeded,
            IncompleteReason::ConfigBytesExceeded => Self::ConfigBytesExceeded,
            IncompleteReason::AliasResolutionBudgetExceeded => Self::AliasResolutionBudgetExceeded,
            IncompleteReason::ContextSelectorBudgetExceeded => Self::ContextSelectorBudgetExceeded,
            IncompleteReason::SelectorBytesExceeded => Self::SelectorBytesExceeded,
            IncompleteReason::MissingFlagValue => Self::MissingFlagValue,
            IncompleteReason::ConflictingSelector => Self::ConflictingSelector,
            IncompleteReason::UnknownOption => Self::UnknownOption,
            IncompleteReason::AmbiguousSubcommand => Self::AmbiguousSubcommand,
            IncompleteReason::UnresolvedIndirection => Self::UnresolvedIndirection,
            IncompleteReason::IncompleteQuoting => Self::IncompleteQuoting,
            IncompleteReason::DynamicConfigUnsupported => Self::DynamicConfigUnsupported,
            IncompleteReason::ConfigMissing => Self::ConfigMissing,
            IncompleteReason::ConfigNotRegular => Self::ConfigNotRegular,
            IncompleteReason::ConfigMalformed => Self::ConfigMalformed,
            IncompleteReason::ConfigIo => Self::ConfigIo,
        }
    }
}

impl From<IncompleteReasonV2> for IncompleteReason {
    fn from(reason: IncompleteReasonV2) -> Self {
        match reason {
            IncompleteReasonV2::InputBytesExceeded => Self::ArgumentBytesExceeded,
            IncompleteReasonV2::EffectBudgetExceeded => Self::ArgumentCountExceeded,
            IncompleteReasonV2::SegmentBudgetExceeded => Self::SegmentBudgetExceeded,
            IncompleteReasonV2::WrapperDepthExceeded => Self::WrapperDepthExceeded,
            IncompleteReasonV2::PackageRunnerDepthExceeded => Self::PackageRunnerDepthExceeded,
            IncompleteReasonV2::ArgumentCountExceeded => Self::ArgumentCountExceeded,
            IncompleteReasonV2::ArgumentBytesExceeded => Self::ArgumentBytesExceeded,
            IncompleteReasonV2::ConfigBytesExceeded => Self::ConfigBytesExceeded,
            IncompleteReasonV2::AliasResolutionBudgetExceeded => {
                Self::AliasResolutionBudgetExceeded
            }
            IncompleteReasonV2::ContextSelectorBudgetExceeded => {
                Self::ContextSelectorBudgetExceeded
            }
            IncompleteReasonV2::SelectorBytesExceeded => Self::SelectorBytesExceeded,
            IncompleteReasonV2::RpcPathMatcherBudgetExceeded => Self::ContextSelectorBudgetExceeded,
            IncompleteReasonV2::MissingFlagValue => Self::MissingFlagValue,
            IncompleteReasonV2::ConflictingSelector => Self::ConflictingSelector,
            IncompleteReasonV2::UnknownOption => Self::UnknownOption,
            IncompleteReasonV2::AmbiguousSubcommand => Self::AmbiguousSubcommand,
            IncompleteReasonV2::IncompleteQuoting => Self::IncompleteQuoting,
            IncompleteReasonV2::DynamicConfigUnsupported => Self::DynamicConfigUnsupported,
            IncompleteReasonV2::ConfigMissing => Self::ConfigMissing,
            IncompleteReasonV2::ConfigNotRegular => Self::ConfigNotRegular,
            IncompleteReasonV2::ConfigMalformed => Self::ConfigMalformed,
            IncompleteReasonV2::ConfigIo => Self::ConfigIo,
            IncompleteReasonV2::RpcPathMatcherContextMissing
            | IncompleteReasonV2::RpcPathMatcherInvalid
            | IncompleteReasonV2::UnresolvedIndirection
            | IncompleteReasonV2::ExecutionContextChanged
            | IncompleteReasonV2::WorkingDirectoryUnresolved
            | IncompleteReasonV2::SignerMissing
            | IncompleteReasonV2::DynamicExecutionUnsupported
            | IncompleteReasonV2::LegacyProjectionIncomplete => Self::UnresolvedIndirection,
        }
    }
}

/// Completeness travels with facts and effects so an unparsed command can never
/// be mistaken for a proven-clean command.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Completeness {
    gaps: BTreeSet<IncompleteReason>,
}

struct BoundedIncompleteReasons(Vec<IncompleteReason>);

struct BoundedIncompleteReasonsVisitor;

impl<'de> Visitor<'de> for BoundedIncompleteReasonsVisitor {
    type Value = BoundedIncompleteReasons;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded sequence of incompleteness reasons")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(
            sequence
                .size_hint()
                .unwrap_or(0)
                .min(MAX_DESERIALIZED_COMPLETENESS_GAPS),
        );
        loop {
            if values.len() == MAX_DESERIALIZED_COMPLETENESS_GAPS {
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom("too many incompleteness reasons"));
                }
                break;
            }
            let Some(value) = sequence.next_element::<IncompleteReason>()? else {
                break;
            };
            values.push(value);
        }
        Ok(BoundedIncompleteReasons(values))
    }
}

impl<'de> Deserialize<'de> for BoundedIncompleteReasons {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedIncompleteReasonsVisitor)
    }
}

#[derive(Deserialize)]
struct CompletenessWire {
    gaps: BoundedIncompleteReasons,
}

impl<'de> Deserialize<'de> for Completeness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CompletenessWire::deserialize(deserializer)?;
        Ok(Self {
            gaps: wire.gaps.0.into_iter().collect(),
        })
    }
}

impl Completeness {
    pub fn complete() -> Self {
        Self {
            gaps: BTreeSet::new(),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }

    pub fn gaps(&self) -> impl ExactSizeIterator<Item = IncompleteReason> + '_ {
        self.gaps.iter().copied()
    }

    pub fn add(&mut self, reason: IncompleteReason) {
        self.gaps.insert(reason);
    }

    pub fn merge(&mut self, other: &Self) {
        self.gaps.extend(other.gaps.iter().copied());
    }
}

impl Default for Completeness {
    fn default() -> Self {
        Self::complete()
    }
}

impl fmt::Debug for Completeness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Completeness")
            .field("complete", &self.is_complete())
            .field("gaps", &self.gaps)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct CompletenessV2 {
    gaps: BTreeSet<IncompleteReasonV2>,
}

impl CompletenessV2 {
    pub fn complete() -> Self {
        Self {
            gaps: BTreeSet::new(),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }

    pub fn gaps(&self) -> impl ExactSizeIterator<Item = IncompleteReasonV2> + '_ {
        self.gaps.iter().copied()
    }

    pub fn add(&mut self, reason: IncompleteReasonV2) {
        self.gaps.insert(reason);
    }

    pub fn merge(&mut self, other: &Self) {
        self.gaps.extend(other.gaps.iter().copied());
    }
}

impl Default for CompletenessV2 {
    fn default() -> Self {
        Self::complete()
    }
}

impl fmt::Debug for CompletenessV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletenessV2")
            .field("complete", &self.is_complete())
            .field("gaps", &self.gaps)
            .finish()
    }
}

struct BoundedIncompleteReasonsV2(Vec<IncompleteReasonV2>);

struct BoundedIncompleteReasonsV2Visitor;

impl<'de> Visitor<'de> for BoundedIncompleteReasonsV2Visitor {
    type Value = BoundedIncompleteReasonsV2;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded sequence of schema-v2 incompleteness reasons")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(
            sequence
                .size_hint()
                .unwrap_or(0)
                .min(MAX_DESERIALIZED_COMPLETENESS_GAPS),
        );
        loop {
            if values.len() == MAX_DESERIALIZED_COMPLETENESS_GAPS {
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom(
                        "too many schema-v2 incompleteness reasons",
                    ));
                }
                break;
            }
            let Some(value) = sequence.next_element::<IncompleteReasonV2>()? else {
                break;
            };
            values.push(value);
        }
        Ok(BoundedIncompleteReasonsV2(values))
    }
}

impl<'de> Deserialize<'de> for BoundedIncompleteReasonsV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedIncompleteReasonsV2Visitor)
    }
}

#[derive(Deserialize)]
struct CompletenessV2Wire {
    gaps: BoundedIncompleteReasonsV2,
}

impl<'de> Deserialize<'de> for CompletenessV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CompletenessV2Wire::deserialize(deserializer)?;
        Ok(Self {
            gaps: wire.gaps.0.into_iter().collect(),
        })
    }
}

impl From<Completeness> for CompletenessV2 {
    fn from(completeness: Completeness) -> Self {
        Self {
            gaps: completeness.gaps.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<CompletenessV2> for Completeness {
    fn from(completeness: CompletenessV2) -> Self {
        Self {
            gaps: completeness.gaps.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandEffectKind {
    PackageInstall,
    PersistenceChange,
    PolicyChange,
    SecretRead,
    NetworkEgress,
    FilesystemWrite,
    ResourceEscalation,
    Web3Write,
    Web3SignerUse,
}

/// Whether the effect can be enforced depends on the boundary at which it is
/// evaluated; semantic parsing itself never upgrades this value to authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryCapability {
    ObserveOnly,
    BoundaryDependent,
    Enforceable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectEvidenceKind {
    CommandOperation,
    CommandFlag,
    StaticConfig,
    ExistingCommandFact,
}

/// Evidence contains provenance metadata only.  In particular, there is no
/// string field into which a private key, mnemonic, or credential can leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EffectEvidence {
    pub kind: EffectEvidenceKind,
    pub span: Option<SourceSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandEffect {
    pub kind: CommandEffectKind,
    pub source: EffectEvidence,
    pub enforceability: BoundaryCapability,
    pub completeness: Completeness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandEffectV2 {
    pub kind: CommandEffectKind,
    pub source: EffectEvidence,
    pub enforceability: BoundaryCapability,
    pub completeness: CompletenessV2,
}

impl From<CommandEffect> for CommandEffectV2 {
    fn from(effect: CommandEffect) -> Self {
        Self {
            kind: effect.kind,
            source: effect.source,
            enforceability: effect.enforceability,
            completeness: effect.completeness.into(),
        }
    }
}

impl From<CommandEffectV2> for CommandEffect {
    fn from(effect: CommandEffectV2) -> Self {
        Self {
            kind: effect.kind,
            source: effect.source,
            enforceability: effect.enforceability,
            completeness: effect.completeness.into(),
        }
    }
}

/// The aggregate has a custom `Debug` implementation so future evidence
/// additions do not accidentally print source text by deriving recursively.
#[derive(Clone, Default, PartialEq, Eq, Serialize)]
pub struct CommandEffects {
    effects: Vec<CommandEffect>,
    completeness: Completeness,
}

struct BoundedCommandEffects(Vec<CommandEffect>);

struct BoundedCommandEffectsVisitor;

impl<'de> Visitor<'de> for BoundedCommandEffectsVisitor {
    type Value = BoundedCommandEffects;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded sequence of command effects")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values =
            Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_COMMAND_EFFECTS));
        loop {
            if values.len() == MAX_COMMAND_EFFECTS {
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom("too many command effects"));
                }
                break;
            }
            let Some(value) = sequence.next_element::<CommandEffect>()? else {
                break;
            };
            values.push(value);
        }
        Ok(BoundedCommandEffects(values))
    }
}

impl<'de> Deserialize<'de> for BoundedCommandEffects {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedCommandEffectsVisitor)
    }
}

#[derive(Deserialize)]
struct CommandEffectsWire {
    effects: BoundedCommandEffects,
    completeness: Completeness,
}

impl<'de> Deserialize<'de> for CommandEffects {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CommandEffectsWire::deserialize(deserializer)?;
        Ok(Self {
            effects: wire.effects.0,
            completeness: wire.completeness,
        })
    }
}

impl CommandEffects {
    pub fn new(effects: Vec<CommandEffect>, completeness: Completeness) -> Self {
        Self {
            effects,
            completeness,
        }
    }

    pub fn effects(&self) -> &[CommandEffect] {
        &self.effects
    }

    pub fn completeness(&self) -> &Completeness {
        &self.completeness
    }
}

impl fmt::Debug for CommandEffects {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandEffects")
            .field(
                "effect_kinds",
                &self
                    .effects
                    .iter()
                    .map(|effect| effect.kind)
                    .collect::<Vec<_>>(),
            )
            .field("completeness", &self.completeness)
            .finish()
    }
}

#[derive(Clone, Default, PartialEq, Eq, Serialize)]
pub struct CommandEffectsV2 {
    effects: Vec<CommandEffectV2>,
    completeness: CompletenessV2,
}

impl CommandEffectsV2 {
    pub fn new(effects: Vec<CommandEffectV2>, completeness: CompletenessV2) -> Self {
        Self {
            effects,
            completeness,
        }
    }

    pub fn effects(&self) -> &[CommandEffectV2] {
        &self.effects
    }

    pub fn completeness(&self) -> &CompletenessV2 {
        &self.completeness
    }
}

impl fmt::Debug for CommandEffectsV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandEffectsV2")
            .field(
                "effect_kinds",
                &self
                    .effects
                    .iter()
                    .map(|effect| effect.kind)
                    .collect::<Vec<_>>(),
            )
            .field("completeness", &self.completeness)
            .finish()
    }
}

struct BoundedCommandEffectsV2(Vec<CommandEffectV2>);

struct BoundedCommandEffectsV2Visitor;

impl<'de> Visitor<'de> for BoundedCommandEffectsV2Visitor {
    type Value = BoundedCommandEffectsV2;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded sequence of schema-v2 command effects")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values =
            Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_COMMAND_EFFECTS));
        loop {
            if values.len() == MAX_COMMAND_EFFECTS {
                if sequence.next_element::<IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom("too many schema-v2 command effects"));
                }
                break;
            }
            let Some(value) = sequence.next_element::<CommandEffectV2>()? else {
                break;
            };
            values.push(value);
        }
        Ok(BoundedCommandEffectsV2(values))
    }
}

impl<'de> Deserialize<'de> for BoundedCommandEffectsV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedCommandEffectsV2Visitor)
    }
}

#[derive(Deserialize)]
struct CommandEffectsV2Wire {
    effects: BoundedCommandEffectsV2,
    completeness: CompletenessV2,
}

impl<'de> Deserialize<'de> for CommandEffectsV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CommandEffectsV2Wire::deserialize(deserializer)?;
        Ok(Self {
            effects: wire.effects.0,
            completeness: wire.completeness,
        })
    }
}

impl From<CommandEffects> for CommandEffectsV2 {
    fn from(effects: CommandEffects) -> Self {
        Self {
            effects: effects.effects.into_iter().map(Into::into).collect(),
            completeness: effects.completeness.into(),
        }
    }
}

impl From<CommandEffectsV2> for CommandEffects {
    fn from(effects: CommandEffectsV2) -> Self {
        Self {
            effects: effects.effects.into_iter().map(Into::into).collect(),
            completeness: effects.completeness.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completeness_is_deterministic_and_deduplicated() {
        let mut value = Completeness::complete();
        value.add(IncompleteReason::MissingFlagValue);
        value.add(IncompleteReason::ConfigMalformed);
        value.add(IncompleteReason::MissingFlagValue);
        assert_eq!(value.gaps().count(), 2);
        assert_eq!(
            serde_json::to_string(&value).unwrap(),
            r#"{"gaps":["missing_flag_value","config_malformed"]}"#
        );
    }

    #[test]
    fn debug_contains_only_typed_effect_evidence() {
        let effects = CommandEffects::new(
            vec![CommandEffect {
                kind: CommandEffectKind::Web3SignerUse,
                source: EffectEvidence {
                    kind: EffectEvidenceKind::CommandFlag,
                    span: Some(SourceSpan::new(20, 86)),
                },
                enforceability: BoundaryCapability::BoundaryDependent,
                completeness: Completeness::complete(),
            }],
            Completeness::complete(),
        );
        let rendered = format!("{effects:?}");
        assert!(rendered.contains("Web3SignerUse"));
        assert!(!rendered.contains("20"));
    }

    #[test]
    fn schema_v2_reasons_round_trip_and_project_into_the_unchanged_v1_set() {
        let mut v2 = CompletenessV2::complete();
        v2.add(IncompleteReasonV2::DynamicExecutionUnsupported);
        v2.add(IncompleteReasonV2::RpcPathMatcherBudgetExceeded);
        let json = serde_json::to_string(&v2).unwrap();
        let decoded: CompletenessV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, v2);

        let v1 = Completeness::from(v2);
        assert!(v1
            .gaps()
            .any(|gap| gap == IncompleteReason::UnresolvedIndirection));
        assert!(v1
            .gaps()
            .any(|gap| gap == IncompleteReason::ContextSelectorBudgetExceeded));

        let too_many = serde_json::json!({
            "gaps": vec!["unresolved_indirection"; MAX_DESERIALIZED_COMPLETENESS_GAPS + 1]
        });
        assert!(serde_json::from_value::<CompletenessV2>(too_many).is_err());
    }
}
