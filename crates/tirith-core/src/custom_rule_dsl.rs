//! M13 ch4 — the custom-rule DSL (semantic predicates).
//!
//! A custom rule in `.tirith/policy.yaml` carries EITHER a `pattern:` regex
//! ([`crate::rules::custom`]) XOR a `when:` clause — a boolean tree of semantic
//! predicates evaluated against the engine's already-extracted analysis data
//! (URLs, command tokens, packages, scanned file path).
//!
//! # Shape
//!
//! ```yaml
//! when:
//!   all:
//!     - command.has_pipeline_to: [sh, bash, zsh]
//!     - url.reputation: unknown
//!     - url.domain_not_in: [company.com, github.com]
//! ```
//!
//! `all` / `any` / `not` are the logical combinators; everything else is a leaf
//! predicate. The serde representation is a key-dispatched (externally tagged)
//! enum — each YAML key maps to exactly one [`WhenClause`] variant — implemented
//! by hand below to avoid the ambiguity an `#[serde(untagged)]` tree would carry.
//!
//! Each leaf binds to REAL extracted data carried in [`DslEvalContext`], filled
//! by the engine from the same extraction the production rules ran.
//!
//! ## v1 limitations (parsed, but REJECTED by the validators)
//!
//! * `agent.kind` / `mcp.tool` — no scan context wires up an "agent kind" or
//!   "current MCP tool" signal ([`DslEvalContext::agent_kind`] / `mcp_tool` are
//!   hard-coded `None`), so such a clause would load yet never match — a dead
//!   rule. Both are rejected up front (see [`clause_uses_unsupported_predicate`]);
//!   for per-agent control use `agent_rules`.
//! * `url.reputation` / `package.reputation` — bound to the LOCAL signed
//!   threat-DB + known-domains table; NO network lookup at eval time. With no DB
//!   loaded, `malicious` is `false` and everything is `unknown` (fail-open). With
//!   a DB, `package.reputation` is a real tri-state (see [`PkgReputation`]).
//! * `package.*` — packages come from [`crate::rules::threatintel::extract_packages`]
//!   (install/add commands plus Docker image refs as the `docker` ecosystem).

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};

use regex::Regex;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

use crate::extract::ScanContext;

/// One node of a `when:` clause — serialized as a single-key YAML mapping whose
/// key (`all`/`any`/`not` or a leaf predicate name) selects the variant and
/// whose value is its payload. `Serialize`/`Deserialize` are hand-written below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhenClause {
    /// Logical AND. Empty list is vacuously true.
    All(Vec<WhenClause>),
    /// Logical OR. Empty list is vacuously false.
    Any(Vec<WhenClause>),
    /// Logical negation.
    Not(Box<WhenClause>),

    /// `command.has_pipeline_to: [sh, bash, ...]` — a `|`-pipeline whose
    /// resolved interpreter is one of the named shells/interpreters.
    CommandHasPipelineTo(Vec<String>),
    /// `command.uses_sudo: true` — the command escalates via `sudo`.
    CommandUsesSudo(bool),
    /// `command.cwd_in: [paths]` — cwd is at/under one of the listed paths.
    CommandCwdIn(Vec<String>),

    /// `url.host: <h>` — an extracted URL's canonical host equals `<h>`.
    UrlHost(String),
    /// `url.host_matches: <regex>` — an extracted URL's host matches the regex.
    UrlHostMatches(String),
    /// `url.scheme: <s>` — an extracted URL's scheme equals `<s>`.
    UrlScheme(String),
    /// `url.reputation: known|unknown|malicious`.
    UrlReputation(Reputation),
    /// `url.domain_not_in: [domains]` — at least one extracted URL whose host
    /// is NOT at/under any listed registrable domain.
    UrlDomainNotIn(Vec<String>),

    /// `package.ecosystem: <e>` — an extracted package in ecosystem `<e>`.
    PackageEcosystem(String),
    /// `package.name_matches: <regex>` — an extracted package name matches.
    PackageNameMatches(String),
    /// `package.reputation: known|unknown|malicious`.
    PackageReputation(Reputation),

    /// `file.path_matches: <regex>` — the scanned file path matches the regex.
    FilePathMatches(String),

    /// `agent.kind: <k>` — parsed but REJECTED at validate (no signal wired; use
    /// `agent_rules`).
    AgentKind(String),
    /// `mcp.tool: <t>` — parsed but REJECTED at validate (no signal wired).
    McpTool(String),
}

impl WhenClause {
    /// The YAML key (predicate / combinator name) for this node.
    pub fn key(&self) -> &'static str {
        match self {
            WhenClause::All(_) => "all",
            WhenClause::Any(_) => "any",
            WhenClause::Not(_) => "not",
            WhenClause::CommandHasPipelineTo(_) => "command.has_pipeline_to",
            WhenClause::CommandUsesSudo(_) => "command.uses_sudo",
            WhenClause::CommandCwdIn(_) => "command.cwd_in",
            WhenClause::UrlHost(_) => "url.host",
            WhenClause::UrlHostMatches(_) => "url.host_matches",
            WhenClause::UrlScheme(_) => "url.scheme",
            WhenClause::UrlReputation(_) => "url.reputation",
            WhenClause::UrlDomainNotIn(_) => "url.domain_not_in",
            WhenClause::PackageEcosystem(_) => "package.ecosystem",
            WhenClause::PackageNameMatches(_) => "package.name_matches",
            WhenClause::PackageReputation(_) => "package.reputation",
            WhenClause::FilePathMatches(_) => "file.path_matches",
            WhenClause::AgentKind(_) => "agent.kind",
            WhenClause::McpTool(_) => "mcp.tool",
        }
    }
}

impl Serialize for WhenClause {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        let key = self.key();
        match self {
            WhenClause::All(v) | WhenClause::Any(v) => map.serialize_entry(key, v)?,
            WhenClause::Not(v) => map.serialize_entry(key, v)?,
            WhenClause::CommandHasPipelineTo(v)
            | WhenClause::CommandCwdIn(v)
            | WhenClause::UrlDomainNotIn(v) => map.serialize_entry(key, v)?,
            WhenClause::CommandUsesSudo(b) => map.serialize_entry(key, b)?,
            WhenClause::UrlHost(s)
            | WhenClause::UrlHostMatches(s)
            | WhenClause::UrlScheme(s)
            | WhenClause::PackageEcosystem(s)
            | WhenClause::PackageNameMatches(s)
            | WhenClause::FilePathMatches(s)
            | WhenClause::AgentKind(s)
            | WhenClause::McpTool(s) => map.serialize_entry(key, s)?,
            WhenClause::UrlReputation(r) | WhenClause::PackageReputation(r) => {
                map.serialize_entry(key, r)?
            }
        }
        map.end()
    }
}

/// Max nesting depth of a `when:` clause tree, enforced DURING deserialization
/// so a hostile deeply-nested `{not: {not: …}}` cannot stack-overflow the
/// validators (DoS). Root clause is depth 1; children are one deeper.
const MAX_CLAUSE_DEPTH: usize = 64;

/// A [`DeserializeSeed`] threading the nesting depth through the recursive
/// `all`/`any`/`not` cases so [`MAX_CLAUSE_DEPTH`] is enforced as the tree is
/// built (before the recursion can overflow the stack).
struct ClauseSeed {
    depth: usize,
}

impl<'de> de::DeserializeSeed<'de> for ClauseSeed {
    type Value = WhenClause;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        if self.depth > MAX_CLAUSE_DEPTH {
            return Err(de::Error::custom(format!(
                "when-clause nesting too deep (max {MAX_CLAUSE_DEPTH})"
            )));
        }
        deserializer.deserialize_map(ClauseVisitor { depth: self.depth })
    }
}

/// Deserializes a `Vec<WhenClause>` (the `all` / `any` children), each element
/// carrying the parent's `depth`.
struct ClauseVecSeed {
    depth: usize,
}

impl<'de> de::DeserializeSeed<'de> for ClauseVecSeed {
    type Value = Vec<WhenClause>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        struct VecVisitor {
            depth: usize,
        }
        impl<'de> Visitor<'de> for VecVisitor {
            type Value = Vec<WhenClause>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a sequence of when-clause nodes")
            }
            fn visit_seq<S: de::SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
                let mut out = Vec::new();
                while let Some(clause) = seq.next_element_seed(ClauseSeed { depth: self.depth })? {
                    out.push(clause);
                }
                Ok(out)
            }
        }
        deserializer.deserialize_seq(VecVisitor { depth: self.depth })
    }
}

/// Map visitor for a single clause node; carries `depth` so its recursive
/// values are deserialized at `depth + 1`.
struct ClauseVisitor {
    depth: usize,
}

impl<'de> Visitor<'de> for ClauseVisitor {
    type Value = WhenClause;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a single-key when-clause mapping (e.g. `url.scheme: https`)")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<WhenClause, M::Error> {
        let key: String = map
            .next_key()?
            .ok_or_else(|| de::Error::custom("when-clause must have exactly one key"))?;

        macro_rules! val {
            ($t:ty) => {{
                let v: $t = map.next_value()?;
                v
            }};
        }
        let child_depth = self.depth + 1;

        let clause = match key.as_str() {
            "all" => WhenClause::All(map.next_value_seed(ClauseVecSeed { depth: child_depth })?),
            "any" => WhenClause::Any(map.next_value_seed(ClauseVecSeed { depth: child_depth })?),
            "not" => WhenClause::Not(Box::new(
                map.next_value_seed(ClauseSeed { depth: child_depth })?,
            )),
            "command.has_pipeline_to" => WhenClause::CommandHasPipelineTo(val!(Vec<String>)),
            "command.uses_sudo" => WhenClause::CommandUsesSudo(val!(bool)),
            "command.cwd_in" => WhenClause::CommandCwdIn(val!(Vec<String>)),
            "url.host" => WhenClause::UrlHost(val!(String)),
            "url.host_matches" => WhenClause::UrlHostMatches(val!(String)),
            "url.scheme" => WhenClause::UrlScheme(val!(String)),
            "url.reputation" => WhenClause::UrlReputation(val!(Reputation)),
            "url.domain_not_in" => WhenClause::UrlDomainNotIn(val!(Vec<String>)),
            "package.ecosystem" => WhenClause::PackageEcosystem(val!(String)),
            "package.name_matches" => WhenClause::PackageNameMatches(val!(String)),
            "package.reputation" => WhenClause::PackageReputation(val!(Reputation)),
            "file.path_matches" => WhenClause::FilePathMatches(val!(String)),
            "agent.kind" => WhenClause::AgentKind(val!(String)),
            "mcp.tool" => WhenClause::McpTool(val!(String)),
            other => {
                return Err(de::Error::custom(format!(
                    "unknown when-clause predicate: '{other}'"
                )))
            }
        };

        // A clause node is exactly one predicate.
        if map.next_key::<String>()?.is_some() {
            return Err(de::Error::custom(
                "when-clause node must have exactly one key (wrap multiple in `all:`/`any:`)",
            ));
        }
        Ok(clause)
    }
}

impl<'de> Deserialize<'de> for WhenClause {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        de::DeserializeSeed::deserialize(ClauseSeed { depth: 1 }, deserializer)
    }
}

/// Reputation tri-state shared by `url.reputation` and `package.reputation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reputation {
    Known,
    Unknown,
    Malicious,
}

/// Tri-state-plus package reputation, derived once by the engine from the LOCAL
/// signed threat-DB. The four states are kept distinct so `package.reputation:
/// unknown` stays reachable with a DB loaded (CodeRabbit M13 finding C); `NoDb`
/// and `Unknown` both satisfy the `unknown` predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgReputation {
    /// No threat-DB loaded — cannot classify (fail-open).
    NoDb,
    /// DB loaded; package in neither the malicious nor the known-popular index.
    Unknown,
    /// DB loaded; package is a known-popular package and not malicious.
    Known,
    /// DB loaded; package is flagged malicious.
    Malicious,
}

/// A package reference as seen by the DSL evaluator (ecosystem + name).
#[derive(Debug, Clone)]
pub struct DslPackage<'a> {
    /// Lowercase ecosystem name (`npm`, `pypi`, `crates.io`, `docker`, ...).
    pub ecosystem: String,
    /// Package / image name.
    pub name: &'a str,
    /// Reputation classification computed once by the engine from the local DB.
    pub reputation: PkgReputation,
}

/// A URL reference as seen by the DSL evaluator (host + scheme + reputation).
#[derive(Debug, Clone)]
pub struct DslUrl<'a> {
    /// Canonical (post-IDNA) host, lowercased by the engine.
    pub host: &'a str,
    /// URL scheme (`https`, `http`, `git`, ...); empty for schemeless refs.
    pub scheme: &'a str,
    /// Reputation classification computed once by the engine.
    pub reputation: Reputation,
}

/// References to the already-extracted analysis data the predicates evaluate
/// against. The engine builds this only when a DSL rule exists, so the no-DSL
/// hot path pays nothing.
#[derive(Debug, Default)]
pub struct DslEvalContext<'a> {
    /// Interpreter names that appear as a `|`-pipeline target, sudo/env-aware
    /// resolved and lowercased (e.g. `["bash"]` for `curl ... | sudo bash`).
    pub pipeline_targets: BTreeSet<String>,
    /// Whether any command segment escalates via `sudo`.
    pub uses_sudo: bool,
    /// The current working directory, if known.
    pub cwd: Option<&'a str>,
    /// Extracted URLs with host + scheme + reputation.
    pub urls: Vec<DslUrl<'a>>,
    /// Extracted packages with ecosystem + name + reputation.
    pub packages: Vec<DslPackage<'a>>,
    /// Path of the file being scanned (FileScan context).
    pub file_path: Option<&'a str>,
    /// Current agent kind (v1: usually `None` on the exec/paste hot path).
    pub agent_kind: Option<&'a str>,
    /// Current MCP tool (v1: usually `None` on the exec/paste hot path).
    pub mcp_tool: Option<&'a str>,
}

/// The set of [`ScanContext`]s in which a clause CAN be fully evaluated — every
/// fact it references is populated by [`build_dsl_backing`] for that context.
/// The clause's satisfiable-context set (CodeRabbit M13 round-9 R9-1).
///
/// Computed PER CLAUSE so combinators compose correctly (an earlier flatten was
/// unsound, e.g. it accepted `all(command.*, file.*)` for `[exec, file]` though
/// no single scan has both):
/// * leaf → contexts where that fact exists (`command.*`/`url.*`/`package.*` →
///   {Exec, Paste}; `file.path_matches` → {FileScan}).
/// * `all` → INTERSECTION; `any` → UNION; `not(child)` → the child's set.
///
/// `agent.kind`/`mcp.tool` contribute EMPTY but are rejected up front by
/// [`clause_uses_unsupported_predicate`]; their empty set only serves as the
/// any/not identity. An empty `all`/`any` needs no facts → universal set.
///
/// Validity (shared by `policy validate` / `rule validate` /
/// [`crate::rules::custom::compile_rules`]):
/// 1. EMPTY satisfiable set → UNSATISFIABLE (facts from contexts that never
///    co-occur), rejected.
/// 2. Otherwise valid iff `declared ∩ satisfiable ≠ ∅`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextSet {
    exec: bool,
    paste: bool,
    file: bool,
}

impl ContextSet {
    /// The empty set — no context can evaluate the clause.
    pub const EMPTY: ContextSet = ContextSet {
        exec: false,
        paste: false,
        file: false,
    };
    /// The universal set — the `all`-intersection identity, and what fact-free
    /// vacuous combinators yield.
    pub const ALL: ContextSet = ContextSet {
        exec: true,
        paste: true,
        file: true,
    };

    fn from_contexts(ctxs: &[ScanContext]) -> ContextSet {
        let mut s = ContextSet::EMPTY;
        for c in ctxs {
            s.insert(*c);
        }
        s
    }

    fn insert(&mut self, c: ScanContext) {
        match c {
            ScanContext::Exec => self.exec = true,
            ScanContext::Paste => self.paste = true,
            ScanContext::FileScan => self.file = true,
        }
    }

    fn contains(&self, c: ScanContext) -> bool {
        match c {
            ScanContext::Exec => self.exec,
            ScanContext::Paste => self.paste,
            ScanContext::FileScan => self.file,
        }
    }

    /// Set INTERSECTION (used to compose `all`).
    fn intersect(self, other: ContextSet) -> ContextSet {
        ContextSet {
            exec: self.exec && other.exec,
            paste: self.paste && other.paste,
            file: self.file && other.file,
        }
    }

    /// Set UNION (used to compose `any`).
    fn union(self, other: ContextSet) -> ContextSet {
        ContextSet {
            exec: self.exec || other.exec,
            paste: self.paste || other.paste,
            file: self.file || other.file,
        }
    }

    /// `true` when no context can evaluate the clause (UNSATISFIABLE).
    pub fn is_empty(&self) -> bool {
        !self.exec && !self.paste && !self.file
    }

    /// `true` when `declared ∩ satisfiable ≠ ∅` — at least one declared context
    /// can actually evaluate the clause.
    pub fn intersects_declared(&self, declared: &[ScanContext]) -> bool {
        declared.iter().any(|c| self.contains(*c))
    }

    /// The contexts in this set, in stable order (exec, paste, file). Used by
    /// [`compile_rules`](crate::rules::custom::compile_rules) to store a DSL
    /// rule's CLAMPED runtime contexts.
    pub fn to_contexts(self) -> Vec<ScanContext> {
        let mut v = Vec::new();
        if self.exec {
            v.push(ScanContext::Exec);
        }
        if self.paste {
            v.push(ScanContext::Paste);
        }
        if self.file {
            v.push(ScanContext::FileScan);
        }
        v
    }

    /// The contexts in this set, in stable order, as lowercase names — for
    /// error text (e.g. "exec or paste").
    fn names(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.exec {
            v.push("exec");
        }
        if self.paste {
            v.push("paste");
        }
        if self.file {
            v.push("file");
        }
        v
    }

    /// Human-readable description of the contexts that CAN evaluate this clause,
    /// for the coverage-error text (e.g. "exec or paste").
    pub fn describe(&self) -> String {
        let names = self.names();
        if names.is_empty() {
            // Defensive: unsatisfiable clauses are reported via their own message.
            "(no scan context)".to_string()
        } else {
            names.join(" or ")
        }
    }
}

/// Compute the [`ContextSet`] in which a clause can be FULLY evaluated.
///
/// Combinators compose by set algebra (round-9 R9-1): `all` → INTERSECTION,
/// `any` → UNION, `not(child)` → the child's set. Empty combinators follow their
/// `evaluate` truth value, not just the set identity: empty `all` is vacuously
/// TRUE → universal set; empty `any` is vacuously FALSE → EMPTY (round-10 R10-1).
/// `agent.kind`/`mcp.tool` yield EMPTY but are rejected earlier for a loaded rule.
pub fn satisfiable_contexts(clause: &WhenClause) -> ContextSet {
    use ScanContext::{Exec, FileScan, Paste};
    match clause {
        // INTERSECTION (empty `all` is vacuously true → universal set).
        WhenClause::All(cs) => cs
            .iter()
            .map(satisfiable_contexts)
            .fold(ContextSet::ALL, ContextSet::intersect),
        // UNION; empty `any` is vacuously FALSE → EMPTY so it is rejected as a
        // dead rule rather than mislabeled runnable (round-10 R10-1).
        WhenClause::Any(cs) => cs
            .iter()
            .map(satisfiable_contexts)
            .fold(ContextSet::EMPTY, ContextSet::union),
        // `not(child)` returns the CHILD's set, NOT the complement — the round-15
        // clamp: `not(file.path_matches)` stays {FileScan} only, never a
        // `not(file)` exec false-positive.
        //
        // The one divergence is degenerate EMPTY combinators nested under `Not`,
        // whose set identity and `evaluate` truth value disagree, and this must
        // hold at ANY nesting depth (R21): `not(not(any: []))` is constant-FALSE
        // → EMPTY, not ALL. So peel the chain of `Not`s (count `k`) to the
        // innermost non-`Not` node and apply the parity table (R17-1):
        //   * innermost `any: []` (const-FALSE): EMPTY if k even, ALL if odd.
        //   * innermost `all: []` (const-TRUE):  ALL if k even, EMPTY if odd.
        //   * other innermost node: its own set, regardless of `k`.
        WhenClause::Not(_) => {
            let mut k: u32 = 0;
            let mut inner = clause;
            while let WhenClause::Not(c) = inner {
                k += 1;
                inner = c.as_ref();
            }
            let even = k % 2 == 0;
            match inner {
                // constant-FALSE innermost.
                WhenClause::Any(cs) if cs.is_empty() => {
                    if even {
                        ContextSet::EMPTY
                    } else {
                        ContextSet::ALL
                    }
                }
                // constant-TRUE innermost.
                WhenClause::All(cs) if cs.is_empty() => {
                    if even {
                        ContextSet::ALL
                    } else {
                        ContextSet::EMPTY
                    }
                }
                // Non-degenerate innermost: child's set, parity-independent.
                other => satisfiable_contexts(other),
            }
        }

        // `command.*` list predicates: an EMPTY list can never match, so it
        // yields EMPTY (a dead rule, rejected) rather than mislabeling itself
        // runnable (round-24); a NON-empty list is evaluable in Exec OR Paste.
        WhenClause::CommandHasPipelineTo(patterns) => {
            if patterns.is_empty() {
                ContextSet::EMPTY
            } else {
                ContextSet::from_contexts(&[Exec, Paste])
            }
        }
        WhenClause::CommandCwdIn(paths) => {
            if paths.is_empty() {
                ContextSet::EMPTY
            } else {
                ContextSet::from_contexts(&[Exec, Paste])
            }
        }
        // `command.uses_sudo` is a bool — always satisfiable in Exec OR Paste.
        WhenClause::CommandUsesSudo(_) => ContextSet::from_contexts(&[Exec, Paste]),

        // `url.*` / `package.*` are evaluable in Exec OR Paste; `build_dsl_backing`
        // extracts both for every non-`FileScan` context (round-3 R3-1).
        WhenClause::UrlHost(_)
        | WhenClause::UrlHostMatches(_)
        | WhenClause::UrlScheme(_)
        | WhenClause::UrlReputation(_)
        | WhenClause::UrlDomainNotIn(_) => ContextSet::from_contexts(&[Exec, Paste]),

        WhenClause::PackageEcosystem(_)
        | WhenClause::PackageNameMatches(_)
        | WhenClause::PackageReputation(_) => ContextSet::from_contexts(&[Exec, Paste]),

        // `file.path_matches` is evaluable only in FileScan.
        WhenClause::FilePathMatches(_) => ContextSet::from_contexts(&[FileScan]),

        // No scan context wires up these signals → EMPTY (rejected earlier for a
        // loaded rule; the empty set only serves as the any/not identity).
        WhenClause::McpTool(_) | WhenClause::AgentKind(_) => ContextSet::EMPTY,
    }
}

/// The SINGLE context-resolution model shared by every DSL consumer (round-15
/// coherence): [`compile_rules`](crate::rules::custom::compile_rules), `policy
/// validate`, and `rule validate` all call this rather than re-deriving contexts.
///
/// Returns `declared ∩ satisfiable_contexts(clause)`. `compile_rules` stores this
/// clamped set as the rule's runtime contexts, so the clause is only ever
/// evaluated where every fact it reads is populated (without the clamp,
/// `not(file.path_matches)` declared `[exec, file]` would false-positive in Exec
/// where `file_path` is `None`). Both validators treat NON-EMPTY as valid — the
/// same condition under which `compile_rules` keeps the rule.
///
/// Does NOT pre-screen the unsatisfiable / unsupported-predicate cases; callers
/// report those with dedicated messages first.
pub fn resolve_runtime_contexts(declared: &[ScanContext], clause: &WhenClause) -> Vec<ScanContext> {
    let satisfiable = satisfiable_contexts(clause);
    ContextSet::from_contexts(declared)
        .intersect(satisfiable)
        .to_contexts()
}

/// Scan a clause tree for a predicate that parses but can NEVER match because no
/// scan context wires up its signal. Returns a user-facing reason for the first
/// such predicate, or `None`. Today: `mcp.tool` and `agent.kind` (both backed by
/// a hard-coded `None` in [`DslEvalContext`]). Both validators reject such a rule
/// rather than load a dead one (round-3 R3-3 / round-8 R8-1).
pub fn clause_uses_unsupported_predicate(clause: &WhenClause) -> Option<&'static str> {
    match clause {
        WhenClause::All(cs) | WhenClause::Any(cs) => {
            cs.iter().find_map(clause_uses_unsupported_predicate)
        }
        WhenClause::Not(c) => clause_uses_unsupported_predicate(c),
        WhenClause::McpTool(_) => Some(
            "mcp.tool is not supported yet (no MCP-tool signal is wired into any \
             scan context, so the predicate can never match)",
        ),
        WhenClause::AgentKind(_) => Some(
            "agent.kind is not supported in DSL `when:` clauses yet (no agent-kind \
             signal is wired into the scan context; use `agent_rules` for per-agent \
             control)",
        ),
        _ => None,
    }
}

/// Validate that every regex inside a clause compiles, returning the first
/// error (with the offending predicate named). `Ok(())` when all are valid.
pub fn validate_regexes(clause: &WhenClause) -> Result<(), String> {
    match clause {
        WhenClause::All(cs) | WhenClause::Any(cs) => {
            for c in cs {
                validate_regexes(c)?;
            }
            Ok(())
        }
        WhenClause::Not(c) => validate_regexes(c),
        WhenClause::UrlHostMatches(p) => check_regex("url.host_matches", p),
        WhenClause::PackageNameMatches(p) => check_regex("package.name_matches", p),
        WhenClause::FilePathMatches(p) => check_regex("file.path_matches", p),
        _ => Ok(()),
    }
}

fn check_regex(field: &str, pattern: &str) -> Result<(), String> {
    // Cap measured in CHARACTERS, not UTF-8 bytes (round-26) — mirrors the
    // char-count cap in `rules::custom::compile_rules`.
    if pattern.chars().count() > 1024 {
        return Err(format!(
            "{field}: regex too long ({} chars, max 1024)",
            pattern.chars().count()
        ));
    }
    Regex::new(pattern)
        .map(|_| ())
        .map_err(|e| format!("{field}: invalid regex: {e}"))
}

thread_local! {
    /// Per-thread compiled-regex cache for the DSL `*_matches` predicates,
    /// avoiding recompiling the same pattern on every `evaluate()`.
    static REGEX_CACHE: RefCell<HashMap<String, Regex>> = RefCell::new(HashMap::new());
}

/// Compile `pat` once per thread and return a cheap clone of the cached `Regex`.
/// `None` if it fails to compile (validated patterns never hit that path).
fn cached_regex(pat: &str) -> Option<Regex> {
    REGEX_CACHE.with(|cache| {
        if let Some(re) = cache.borrow().get(pat) {
            return Some(re.clone());
        }
        match Regex::new(pat) {
            Ok(re) => {
                cache.borrow_mut().insert(pat.to_string(), re.clone());
                Some(re)
            }
            Err(_) => None,
        }
    })
}

/// Evaluate a `when:` clause against the extracted analysis data.
pub fn evaluate(clause: &WhenClause, ctx: &DslEvalContext) -> bool {
    match clause {
        WhenClause::All(cs) => cs.iter().all(|c| evaluate(c, ctx)),
        WhenClause::Any(cs) => cs.iter().any(|c| evaluate(c, ctx)),
        WhenClause::Not(c) => !evaluate(c, ctx),

        WhenClause::CommandHasPipelineTo(shells) => {
            let wanted: BTreeSet<String> = shells.iter().map(|s| s.to_lowercase()).collect();
            ctx.pipeline_targets.iter().any(|t| wanted.contains(t))
        }
        WhenClause::CommandUsesSudo(want) => ctx.uses_sudo == *want,
        WhenClause::CommandCwdIn(paths) => match ctx.cwd {
            Some(cwd) => paths.iter().any(|p| path_is_under(cwd, p)),
            None => false,
        },

        WhenClause::UrlHost(h) => {
            let h = h.to_lowercase();
            ctx.urls.iter().any(|u| u.host.eq_ignore_ascii_case(&h))
        }
        WhenClause::UrlHostMatches(pat) => match cached_regex(pat) {
            Some(re) => ctx.urls.iter().any(|u| re.is_match(u.host)),
            None => false,
        },
        WhenClause::UrlScheme(s) => ctx.urls.iter().any(|u| u.scheme.eq_ignore_ascii_case(s)),
        WhenClause::UrlReputation(rep) => ctx.urls.iter().any(|u| u.reputation == *rep),
        WhenClause::UrlDomainNotIn(domains) => {
            // Fires when at least one extracted URL's host is outside every
            // listed domain. With no URLs there is nothing outside the list.
            ctx.urls
                .iter()
                .any(|u| !domains.iter().any(|d| host_is_under_domain(u.host, d)))
        }

        WhenClause::PackageEcosystem(e) => {
            let e = normalize_ecosystem(e);
            ctx.packages
                .iter()
                .any(|p| normalize_ecosystem(&p.ecosystem) == e)
        }
        WhenClause::PackageNameMatches(pat) => match cached_regex(pat) {
            Some(re) => ctx.packages.iter().any(|p| re.is_match(p.name)),
            None => false,
        },
        WhenClause::PackageReputation(rep) => ctx.packages.iter().any(|p| match rep {
            Reputation::Malicious => p.reputation == PkgReputation::Malicious,
            Reputation::Known => p.reputation == PkgReputation::Known,
            // `unknown` = no DB loaded, or loaded but the package is in neither index.
            Reputation::Unknown => {
                matches!(p.reputation, PkgReputation::NoDb | PkgReputation::Unknown)
            }
        }),

        WhenClause::FilePathMatches(pat) => match (&ctx.file_path, cached_regex(pat)) {
            (Some(path), Some(re)) => re.is_match(path),
            _ => false,
        },

        WhenClause::AgentKind(k) => ctx.agent_kind.is_some_and(|a| a.eq_ignore_ascii_case(k)),
        WhenClause::McpTool(t) => ctx.mcp_tool.is_some_and(|m| m.eq_ignore_ascii_case(t)),
    }
}

/// Normalize an ecosystem alias to its canonical [`crate::threatdb::Ecosystem`]
/// display string when recognized, else lowercase it — so `crates`/`cargo`
/// match `crates.io`.
fn normalize_ecosystem(s: &str) -> String {
    match crate::threatdb::Ecosystem::from_name(s) {
        Some(e) => e.to_string(),
        None => s.to_lowercase(),
    }
}

/// Heuristic: does this look like a Windows path? `true` for a leading drive
/// letter (`C:…`, incl. drive-RELATIVE `C:rel`) or a `//`-rooted/UNC path. Used
/// ONLY for case-normalization (Windows is case-insensitive) — NOT for
/// root-containment, where drive-relative forms must be excluded; use
/// [`is_windows_absolute_path`] there.
fn looks_like_windows_path(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return true;
    }
    s.starts_with("//")
}

/// `true` only when `s` is an ABSOLUTE Windows path: drive letter + `:` +
/// separator (`C:/…`, `c:\…`) or a leading `//` UNC root. Unlike
/// [`looks_like_windows_path`], rejects drive-RELATIVE forms — both bare `C:` and
/// `C:relative` are relative to the drive's cwd, so neither is root-contained
/// (round-20, correcting round-19 which wrongly accepted bare `C:`).
fn is_windows_absolute_path(s: &str) -> bool {
    let bytes = s.as_bytes();
    // Drive ROOT requires drive letter, `:`, AND a separator (accept both forms
    // independent of the back-slash→`/` pre-pass).
    if bytes.len() > 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return bytes[2] == b'/' || bytes[2] == b'\\';
    }
    s.starts_with("//")
}

/// Normalize a path for lexical "is-under" matching: back-slashes → `/`, and
/// (only when [`looks_like_windows_path`]) lowercased. POSIX paths keep case.
fn normalize_for_lexical_path_match(s: &str) -> String {
    let slashed = s.replace('\\', "/");
    if looks_like_windows_path(&slashed) {
        slashed.to_lowercase()
    } else {
        slashed
    }
}

/// `true` when `path` is `base` or a descendant — compared as `/`-separated
/// component sequences (lexical, no filesystem access), so `/home/x` is under
/// `/home` but `/home-other` is not. Windows paths are back-slash-normalized and
/// case-folded (findings B/R1); POSIX paths stay case-sensitive.
fn path_is_under(path: &str, base: &str) -> bool {
    let path = normalize_for_lexical_path_match(path);
    let base = normalize_for_lexical_path_match(base);
    // Trim the BASE only, to detect the root sentinel `cwd_in: ["/"]` (trims to
    // empty). The absolute-path check below runs on the UNTRIMMED `path` because
    // trimming would turn a bare drive ROOT `c:/` into `c:`, which
    // `is_windows_absolute_path` rejects (round-25).
    let base_trimmed = base.trim_end_matches('/');
    if base_trimmed.is_empty() {
        // Root sentinel contains every ABSOLUTE path. Strict
        // `is_windows_absolute_path` (not the looser `looks_like_windows_path`)
        // so drive-relative `c:rel` is NOT root-contained (round-15/19).
        return path.starts_with('/') || is_windows_absolute_path(&path);
    }
    // Non-root base: trim the path too so `/home/user/` and `/home/user` match.
    let path = path.trim_end_matches('/');
    if path == base_trimmed {
        return true;
    }
    path.strip_prefix(base_trimmed)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// `true` when `host` equals `domain` or is a sub-domain of it
/// (`api.github.com` is under `github.com`, but `notgithub.com` is not).
/// Case-insensitive; a leading dot on `domain` is tolerated.
fn host_is_under_domain(host: &str, domain: &str) -> bool {
    let host = host.trim_end_matches('.').to_lowercase();
    let domain = domain
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_lowercase();
    if domain.is_empty() {
        return false;
    }
    if host == domain {
        return true;
    }
    host.strip_suffix(&domain)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seven shipping example DSL rules must all load via `Policy` with a
    /// valid pattern-XOR-when shape, valid regexes, and a context that covers
    /// each clause.
    #[test]
    fn test_seven_example_dsl_rules_round_trip() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("tests")
            .join("fixtures")
            .join("custom_rules_dsl.yaml");
        let yaml = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

        // Strict parser so a fixture typo is a hard test failure.
        let policy = crate::policy::Policy::try_parse_yaml(&yaml)
            .unwrap_or_else(|e| panic!("fixture parse error: {e}"));
        assert_eq!(
            policy.custom_rules.len(),
            7,
            "fixture must define exactly 7 DSL rules"
        );

        for rule in &policy.custom_rules {
            rule.validate_shape()
                .unwrap_or_else(|e| panic!("rule '{}' bad shape: {e}", rule.id));
            let when = rule
                .when
                .as_ref()
                .unwrap_or_else(|| panic!("rule '{}' should be a DSL rule", rule.id));
            validate_regexes(when).unwrap_or_else(|e| panic!("rule '{}' bad regex: {e}", rule.id));

            let declared = parse_test_contexts(&rule.context);
            let satisfiable = satisfiable_contexts(when);
            assert!(
                !satisfiable.is_empty(),
                "rule '{}' clause is unsatisfiable (needs facts from contexts that never co-occur)",
                rule.id
            );
            assert!(
                satisfiable.intersects_declared(&declared),
                "rule '{}' context {:?} cannot evaluate the clause (evaluable in: {})",
                rule.id,
                rule.context,
                satisfiable.describe()
            );
        }

        // The acceptance rule fires on the documented input shape.
        let accept = policy
            .custom_rules
            .iter()
            .find(|r| r.id == "block-unknown-curl-to-shell")
            .expect("acceptance rule present");
        let clause = accept.when.as_ref().unwrap();
        let mut ctx = DslEvalContext::default();
        ctx.pipeline_targets.insert("bash".to_string());
        ctx.urls.push(DslUrl {
            host: "evil.example",
            scheme: "https",
            reputation: Reputation::Unknown,
        });
        assert!(evaluate(clause, &ctx));
    }

    fn parse_test_contexts(context: &[String]) -> Vec<ScanContext> {
        context
            .iter()
            .filter_map(|c| match c.as_str() {
                "exec" => Some(ScanContext::Exec),
                "paste" => Some(ScanContext::Paste),
                "file" => Some(ScanContext::FileScan),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_acceptance_example_round_trips() {
        let yaml = r#"
all:
  - command.has_pipeline_to: [sh, bash, zsh]
  - url.reputation: unknown
  - url.domain_not_in: [company.com, github.com]
"#;
        let clause: WhenClause = serde_yaml::from_str(yaml).expect("parse");
        let out = serde_yaml::to_string(&clause).expect("serialize");
        let clause2: WhenClause = serde_yaml::from_str(&out).expect("reparse");
        assert_eq!(clause, clause2);

        match &clause {
            WhenClause::All(cs) => {
                assert_eq!(cs.len(), 3);
                assert!(matches!(cs[0], WhenClause::CommandHasPipelineTo(_)));
                assert!(matches!(
                    cs[1],
                    WhenClause::UrlReputation(Reputation::Unknown)
                ));
                assert!(matches!(cs[2], WhenClause::UrlDomainNotIn(_)));
            }
            _ => panic!("expected All"),
        }
    }

    #[test]
    fn test_acceptance_example_fires() {
        let yaml = r#"
all:
  - command.has_pipeline_to: [sh, bash, zsh]
  - url.reputation: unknown
  - url.domain_not_in: [company.com, github.com]
"#;
        let clause: WhenClause = serde_yaml::from_str(yaml).unwrap();

        let mut ctx = DslEvalContext::default();
        ctx.pipeline_targets.insert("bash".to_string());
        ctx.urls.push(DslUrl {
            host: "evil.example",
            scheme: "https",
            reputation: Reputation::Unknown,
        });
        assert!(evaluate(&clause, &ctx), "evil-domain curl|bash should fire");

        // github.com is allow-listed -> domain_not_in false -> `all` false.
        let mut ctx2 = DslEvalContext::default();
        ctx2.pipeline_targets.insert("bash".to_string());
        ctx2.urls.push(DslUrl {
            host: "github.com",
            scheme: "https",
            reputation: Reputation::Unknown,
        });
        assert!(!evaluate(&clause, &ctx2), "github.com should not fire");
    }

    #[test]
    fn test_not_and_any() {
        let yaml = r#"
any:
  - command.uses_sudo: true
  - not:
      url.scheme: https
"#;
        let clause: WhenClause = serde_yaml::from_str(yaml).unwrap();

        // Has sudo -> any() true.
        let ctx = DslEvalContext {
            uses_sudo: true,
            ..Default::default()
        };
        assert!(evaluate(&clause, &ctx));

        // No sudo, https URL -> not(scheme https) false -> any() false.
        let mut ctx2 = DslEvalContext::default();
        ctx2.urls.push(DslUrl {
            host: "x.com",
            scheme: "https",
            reputation: Reputation::Known,
        });
        assert!(!evaluate(&clause, &ctx2));

        // No sudo, http URL -> not(scheme https) true -> any() true.
        let mut ctx3 = DslEvalContext::default();
        ctx3.urls.push(DslUrl {
            host: "x.com",
            scheme: "http",
            reputation: Reputation::Known,
        });
        assert!(evaluate(&clause, &ctx3));
    }

    #[test]
    fn test_deeply_nested_clause_is_rejected_with_depth_error() {
        // DoS (round-20): nesting must be depth-bounded DURING deserialization so
        // a hostile policy cannot stack-overflow `policy validate`. Build a tree
        // nested well past the cap.
        let over = MAX_CLAUSE_DEPTH + 5;
        let mut yaml = String::new();
        for _ in 0..over {
            yaml.push_str("not: {");
        }
        yaml.push_str("url.scheme: https");
        for _ in 0..over {
            yaml.push('}');
        }
        let err = serde_yaml::from_str::<WhenClause>(&yaml)
            .expect_err("a clause nested past the cap must be REJECTED, not parsed");
        let msg = err.to_string();
        assert!(
            msg.contains("nesting too deep"),
            "expected the depth error, got: {msg}"
        );

        // A tree AT the cap still parses: K wrappers occupy depths 1..=K and the
        // leaf is at K+1, so the boundary is (MAX_CLAUSE_DEPTH - 1) wrappers.
        let at_cap_wrappers = MAX_CLAUSE_DEPTH - 1;
        let mut ok = String::new();
        for _ in 0..at_cap_wrappers {
            ok.push_str("not: {");
        }
        ok.push_str("url.scheme: https");
        for _ in 0..at_cap_wrappers {
            ok.push('}');
        }
        serde_yaml::from_str::<WhenClause>(&ok)
            .expect("a clause nested exactly at the cap must still parse");
    }

    // round-4 N5: the per-thread regex cache must be transparent — repeated
    // evaluation of the same rule keeps identical match/non-match semantics.
    #[test]
    fn test_host_matches_regex_cache_preserves_semantics() {
        let clause = WhenClause::UrlHostMatches(r"\.evil\.com$".to_string());

        let mut hit = DslEvalContext::default();
        hit.urls.push(DslUrl {
            host: "a.evil.com",
            scheme: "https",
            reputation: Reputation::Unknown,
        });
        let mut miss = DslEvalContext::default();
        miss.urls.push(DslUrl {
            host: "good.com",
            scheme: "https",
            reputation: Reputation::Known,
        });

        // Repeat to exercise the cache hit path; the verdict must stay stable.
        for _ in 0..3 {
            assert!(evaluate(&clause, &hit), "matching host should fire");
            assert!(
                !evaluate(&clause, &miss),
                "non-matching host should not fire"
            );
        }
    }

    #[test]
    fn test_satisfiable_command_needs_exec_or_paste() {
        // round-3 R3-1: `command.*` evaluates on BOTH exec and paste, so a
        // `[paste]` command rule must validate; FileScan still does not.
        let clause = WhenClause::CommandUsesSudo(true);
        let sat = satisfiable_contexts(&clause);
        assert!(!sat.is_empty());
        assert!(sat.intersects_declared(&[ScanContext::Exec]));
        assert!(sat.intersects_declared(&[ScanContext::Paste]));
        assert!(!sat.intersects_declared(&[ScanContext::FileScan]));
    }

    #[test]
    fn test_satisfiable_empty_list_command_predicate_is_unsatisfiable() {
        // round-24: an empty-list `command.*` predicate can never match, so it
        // yields the EMPTY satisfiable set (dead rule, rejected) rather than
        // mislabeling itself runnable.
        for clause in [
            WhenClause::CommandHasPipelineTo(vec![]),
            WhenClause::CommandCwdIn(vec![]),
        ] {
            let sat = satisfiable_contexts(&clause);
            assert!(
                sat.is_empty(),
                "an empty-list command predicate must be unsatisfiable (EMPTY set), got {sat:?} for {clause:?}"
            );
            assert!(
                !sat.intersects_declared(&[
                    ScanContext::Exec,
                    ScanContext::Paste,
                    ScanContext::FileScan,
                ]),
                "empty-list command predicate must not intersect any declared context: {clause:?}"
            );
            // Agrees with `evaluate`: even a populated ctx never matches.
            let mut ctx = DslEvalContext {
                uses_sudo: true,
                cwd: Some("/home/user/repo"),
                ..Default::default()
            };
            ctx.pipeline_targets.insert("bash".to_string());
            assert!(
                !evaluate(&clause, &ctx),
                "empty-list command predicate must never fire, even on a populated ctx: {clause:?}"
            );
            // `resolve_runtime_contexts` clamps it to empty under default
            // [exec, paste] — so `compile_rules`/validators reject it.
            assert!(
                resolve_runtime_contexts(&[ScanContext::Exec, ScanContext::Paste], &clause)
                    .is_empty(),
                "empty-list command predicate under default [exec, paste] must resolve empty: {clause:?}"
            );
        }
    }

    #[test]
    fn test_satisfiable_nonempty_list_command_predicate_is_exec_or_paste() {
        // Companion to the empty-list check: a NON-empty list is still evaluable
        // in Exec OR Paste (never FileScan).
        for clause in [
            WhenClause::CommandHasPipelineTo(vec!["bash".to_string()]),
            WhenClause::CommandCwdIn(vec!["/home/user/repo".to_string()]),
        ] {
            let sat = satisfiable_contexts(&clause);
            assert!(
                !sat.is_empty(),
                "a non-empty-list command predicate must be satisfiable: {clause:?}"
            );
            assert!(
                sat.intersects_declared(&[ScanContext::Exec]),
                "non-empty-list command predicate must be evaluable in exec: {clause:?}"
            );
            assert!(
                sat.intersects_declared(&[ScanContext::Paste]),
                "non-empty-list command predicate must be evaluable in paste: {clause:?}"
            );
            assert!(
                !sat.intersects_declared(&[ScanContext::FileScan]),
                "non-empty-list command predicate must NOT be evaluable in file: {clause:?}"
            );
        }
    }

    #[test]
    fn test_satisfiable_url_needs_exec_or_paste() {
        let clause = WhenClause::UrlReputation(Reputation::Unknown);
        let sat = satisfiable_contexts(&clause);
        assert!(sat.intersects_declared(&[ScanContext::Exec]));
        assert!(sat.intersects_declared(&[ScanContext::Paste]));
        assert!(!sat.intersects_declared(&[ScanContext::FileScan]));
    }

    #[test]
    fn test_satisfiable_package_needs_exec_or_paste() {
        // Regression (round-1 finding A + round-3 R3-1): `package.*` is evaluable
        // in Exec OR Paste, never FileScan. Cover all three package predicates.
        for clause in [
            WhenClause::PackageEcosystem("npm".to_string()),
            WhenClause::PackageNameMatches("^left-pad$".to_string()),
            WhenClause::PackageReputation(Reputation::Malicious),
        ] {
            let sat = satisfiable_contexts(&clause);
            assert!(
                sat.intersects_declared(&[ScanContext::Exec]),
                "package predicate must be evaluable in exec: {clause:?}"
            );
            assert!(
                sat.intersects_declared(&[ScanContext::Paste]),
                "package predicate must be evaluable in paste (round-3 R3-1): {clause:?}"
            );
            assert!(
                !sat.intersects_declared(&[ScanContext::FileScan]),
                "package predicate must NOT be evaluable in file (no package facts there): {clause:?}"
            );
        }
    }

    #[test]
    fn test_satisfiable_file_needs_filescan() {
        let clause = WhenClause::FilePathMatches(r"\.env$".to_string());
        let sat = satisfiable_contexts(&clause);
        assert!(sat.intersects_declared(&[ScanContext::FileScan]));
        assert!(!sat.intersects_declared(&[ScanContext::Exec]));
    }

    #[test]
    fn test_satisfiable_all_command_and_file_is_empty_unsatisfiable() {
        // round-9 R9-1: `all(command.*, file.*)` is UNSATISFIABLE — no single scan
        // has both, so {Exec, Paste} ∩ {FileScan} is empty. The old flatten
        // wrongly accepted it for `[exec, file]`.
        let clause = WhenClause::All(vec![
            WhenClause::CommandUsesSudo(true),
            WhenClause::FilePathMatches(r"x".to_string()),
        ]);
        let sat = satisfiable_contexts(&clause);
        assert!(
            sat.is_empty(),
            "all(command, file) must be unsatisfiable (empty intersection), got {sat:?}"
        );
        assert!(!sat.intersects_declared(&[ScanContext::Exec, ScanContext::FileScan]));
    }

    #[test]
    fn test_satisfiable_any_command_or_file_is_union() {
        // round-9 R9-1: `any(command.*, file.*)` is evaluable wherever EITHER
        // branch is — the UNION {Exec, Paste, FileScan}. The old flatten wrongly
        // rejected it for `[exec]`.
        let clause = WhenClause::Any(vec![
            WhenClause::CommandUsesSudo(true),
            WhenClause::FilePathMatches(r"\.env$".to_string()),
        ]);
        let sat = satisfiable_contexts(&clause);
        assert!(!sat.is_empty());
        assert!(
            sat.intersects_declared(&[ScanContext::Exec]),
            "any(command, file) must be evaluable under [exec] (command branch)"
        );
        assert!(
            sat.intersects_declared(&[ScanContext::Paste]),
            "any(command, file) must be evaluable under [paste] (command branch)"
        );
        assert!(
            sat.intersects_declared(&[ScanContext::FileScan]),
            "any(command, file) must be evaluable under [file] (file branch)"
        );
    }

    #[test]
    fn test_satisfiable_empty_any_is_unsatisfiable() {
        // round-10 R10-1: empty `any: []` is vacuously FALSE → EMPTY so the
        // validators reject it as a dead rule.
        let any_empty = WhenClause::Any(vec![]);
        let sat = satisfiable_contexts(&any_empty);
        assert!(
            sat.is_empty(),
            "empty `any: []` must be unsatisfiable (EMPTY set), got {sat:?}"
        );
        assert!(!sat.intersects_declared(&[
            ScanContext::Exec,
            ScanContext::Paste,
            ScanContext::FileScan,
        ]));
        // Matches `evaluate`: empty `any` is false on any context.
        assert!(
            !evaluate(&any_empty, &DslEvalContext::default()),
            "empty `any` must evaluate to false"
        );
    }

    #[test]
    fn test_satisfiable_empty_all_is_universal_and_vacuously_true() {
        // round-10 R10-1 companion: empty `all: []` is vacuously TRUE → universal
        // set (contrasts with empty `any` above).
        let all_empty = WhenClause::All(vec![]);
        let sat = satisfiable_contexts(&all_empty);
        assert!(
            !sat.is_empty(),
            "empty `all: []` must be satisfiable (universal set), got {sat:?}"
        );
        assert!(sat.intersects_declared(&[ScanContext::Exec]));
        assert!(sat.intersects_declared(&[ScanContext::Paste]));
        assert!(sat.intersects_declared(&[ScanContext::FileScan]));
        // Matches `evaluate`: empty `all` is true.
        assert!(
            evaluate(&all_empty, &DslEvalContext::default()),
            "empty `all` must evaluate to true (vacuous)"
        );
    }

    #[test]
    fn test_satisfiable_not_preserves_child_set() {
        // The round-15 clamp: `not(child)` keeps the child's set, so
        // `not(file.path_matches)` is evaluable ONLY in FileScan, not the
        // complement {Exec, Paste} (which would be a `not(file)` exec
        // false-positive).
        let clause = WhenClause::Not(Box::new(WhenClause::FilePathMatches(r"x".to_string())));
        let sat = satisfiable_contexts(&clause);
        assert_eq!(
            sat,
            ContextSet::from_contexts(&[ScanContext::FileScan]),
            "not(file.path_matches) must yield {{FileScan}} only (round-15 clamp preserved)"
        );
        assert!(sat.intersects_declared(&[ScanContext::FileScan]));
        assert!(!sat.intersects_declared(&[ScanContext::Exec]));
    }

    #[test]
    fn test_satisfiable_not_of_degenerate_empty_combinators_follow_truth_value() {
        // R17-1: the only `Not` divergence from the child's set is the two
        // degenerate directly-nested EMPTY combinators:
        //   * `not(any: [])` == constant-TRUE → ALL.
        //   * `not(all: [])` == constant-FALSE → EMPTY.
        // A blanket "complement" was NOT applied (it would reintroduce the
        // round-15 `not(file)` exec false-positive).
        let not_empty_any = WhenClause::Not(Box::new(WhenClause::Any(vec![])));
        assert_eq!(
            satisfiable_contexts(&not_empty_any),
            ContextSet::ALL,
            "not(any: []) is constant-true -> ALL"
        );
        assert!(
            evaluate(&not_empty_any, &DslEvalContext::default()),
            "not(any: []) must evaluate to true"
        );

        let not_empty_all = WhenClause::Not(Box::new(WhenClause::All(vec![])));
        assert_eq!(
            satisfiable_contexts(&not_empty_all),
            ContextSet::EMPTY,
            "not(all: []) is constant-false -> EMPTY (unsatisfiable)"
        );
        assert!(
            !evaluate(&not_empty_all, &DslEvalContext::default()),
            "not(all: []) must evaluate to false"
        );

        // A NON-degenerate `not(any: [...])` still returns the child's set, not ALL.
        let not_nonempty_any = WhenClause::Not(Box::new(WhenClause::Any(vec![
            WhenClause::CommandUsesSudo(true),
        ])));
        assert_eq!(
            satisfiable_contexts(&not_nonempty_any),
            ContextSet::from_contexts(&[ScanContext::Exec, ScanContext::Paste]),
            "not(any: [command.*]) keeps the child's {{Exec, Paste}} set (non-degenerate)"
        );
    }

    #[test]
    fn test_satisfiable_nested_not_follows_parity_of_evaluate() {
        // R21: nested `Not` must be evaluate-consistent at ANY depth. The old
        // one-level match let `not(not(any: []))` wrongly return ALL instead of
        // EMPTY. Peel the chain and apply the parity table (`any:[]`=const-false,
        // `all:[]`=const-true, each `Not` flips). Assert the set AND that it
        // agrees with `evaluate`.
        let ctx = DslEvalContext::default();

        // Build `Not^n(inner)`.
        fn wrap_not(inner: WhenClause, n: u32) -> WhenClause {
            let mut c = inner;
            for _ in 0..n {
                c = WhenClause::Not(Box::new(c));
            }
            c
        }

        // innermost `any: []` is const-FALSE: EMPTY at even depth, ALL at odd.
        let c = wrap_not(WhenClause::Any(vec![]), 1);
        assert_eq!(
            satisfiable_contexts(&c),
            ContextSet::ALL,
            "not(any: []) is constant-true -> ALL (k=1)"
        );
        assert!(evaluate(&c, &ctx), "not(any: []) evaluates true");

        // k=2: not(not(any: [])) -> EMPTY (the R21 bug: old code returned ALL).
        let c = wrap_not(WhenClause::Any(vec![]), 2);
        assert_eq!(
            satisfiable_contexts(&c),
            ContextSet::EMPTY,
            "not(not(any: [])) is constant-false -> EMPTY (k=2, the R21 bug)"
        );
        assert!(!evaluate(&c, &ctx), "not(not(any: [])) evaluates false");

        // k=3 -> ALL.
        let c = wrap_not(WhenClause::Any(vec![]), 3);
        assert_eq!(
            satisfiable_contexts(&c),
            ContextSet::ALL,
            "not^3(any: []) is constant-true -> ALL (k=3)"
        );
        assert!(evaluate(&c, &ctx), "not^3(any: []) evaluates true");

        // innermost `all: []` is const-TRUE: ALL at even depth, EMPTY at odd.
        let c = wrap_not(WhenClause::All(vec![]), 1);
        assert_eq!(
            satisfiable_contexts(&c),
            ContextSet::EMPTY,
            "not(all: []) is constant-false -> EMPTY (k=1)"
        );
        assert!(!evaluate(&c, &ctx), "not(all: []) evaluates false");

        // k=2 -> ALL.
        let c = wrap_not(WhenClause::All(vec![]), 2);
        assert_eq!(
            satisfiable_contexts(&c),
            ContextSet::ALL,
            "not(not(all: [])) is constant-true -> ALL (k=2)"
        );
        assert!(evaluate(&c, &ctx), "not(not(all: [])) evaluates true");

        // A real leaf keeps its family at every depth (`Not` returns the child's
        // set, not the complement) — the round-15 clamp.
        let file_family = ContextSet::from_contexts(&[ScanContext::FileScan]);
        let leaf = || WhenClause::FilePathMatches(r"secrets".to_string());

        let c = wrap_not(leaf(), 1);
        assert_eq!(
            satisfiable_contexts(&c),
            file_family,
            "not(file.path_matches) keeps the leaf's {{FileScan}} family (k=1)"
        );
        let c = wrap_not(leaf(), 2);
        assert_eq!(
            satisfiable_contexts(&c),
            file_family,
            "not(not(file.path_matches)) keeps the leaf's {{FileScan}} family (k=2)"
        );
        // And a deeper chain over the leaf stays clamped too.
        let c = wrap_not(leaf(), 3);
        assert_eq!(
            satisfiable_contexts(&c),
            file_family,
            "not^3(file.path_matches) still keeps the leaf's {{FileScan}} family"
        );
    }

    #[test]
    fn test_satisfiable_all_within_one_family_intersects_to_that_family() {
        // An `all` of two {Exec, Paste} predicates stays {Exec, Paste}, so a
        // `[exec]` rule is accepted (regression for fixture rules 1-4 and 7).
        let clause = WhenClause::All(vec![
            WhenClause::CommandUsesSudo(true),
            WhenClause::UrlReputation(Reputation::Unknown),
        ]);
        let sat = satisfiable_contexts(&clause);
        assert!(sat.intersects_declared(&[ScanContext::Exec]));
        assert!(sat.intersects_declared(&[ScanContext::Paste]));
        assert!(!sat.intersects_declared(&[ScanContext::FileScan]));
    }

    #[test]
    fn test_resolve_runtime_contexts_clamps_and_unifies() {
        // round-15: `resolve_runtime_contexts` returns `declared ∩ satisfiable`.
        // Cover the load-bearing cases.
        use ScanContext::{Exec, FileScan, Paste};

        // `command.*` under default [exec, paste] resolves to both.
        let cmd = WhenClause::CommandUsesSudo(true);
        assert_eq!(
            resolve_runtime_contexts(&[Exec, Paste], &cmd),
            vec![Exec, Paste],
            "command.* under default [exec, paste] resolves to {{exec, paste}}"
        );

        // `file.path_matches` under default [exec, paste] resolves to EMPTY —
        // a dead no-context file rule, rejected (round-15 rule.rs:338).
        let file = WhenClause::FilePathMatches(r"\.env$".into());
        assert!(
            resolve_runtime_contexts(&[Exec, Paste], &file).is_empty(),
            "file rule under default [exec, paste] resolves empty -> rejected"
        );

        // The same file rule declared `[file]` resolves to {file} — accepted.
        assert_eq!(
            resolve_runtime_contexts(&[FileScan], &file),
            vec![FileScan],
            "explicit [file] file rule resolves to {{file}}"
        );

        // The clamp: `not(file.path_matches)` declared `[exec, file]` resolves to
        // {file} only, dropping the exec context where the fact is absent.
        let not_file = WhenClause::Not(Box::new(file.clone()));
        assert_eq!(
            resolve_runtime_contexts(&[Exec, FileScan], &not_file),
            vec![FileScan],
            "not(file.*) declared [exec, file] clamps to {{file}}"
        );

        // An explicit empty declared list always resolves empty (no default fires
        // for a present-but-empty list at this layer).
        assert!(
            resolve_runtime_contexts(&[], &cmd).is_empty(),
            "explicit empty declared context resolves empty -> rejected"
        );
    }

    #[test]
    fn test_satisfiable_agent_kind_is_empty() {
        // `agent.kind` / `mcp.tool` have an EMPTY satisfiable set (rejected
        // earlier; the empty set only serves as the any/not identity).
        assert!(satisfiable_contexts(&WhenClause::AgentKind("claude-code".to_string())).is_empty());
        assert!(satisfiable_contexts(&WhenClause::McpTool("read_file".to_string())).is_empty());
    }

    #[test]
    fn test_validate_regexes_catches_bad() {
        let bad = WhenClause::UrlHostMatches(r"(unclosed".to_string());
        assert!(validate_regexes(&bad).is_err());
        let good = WhenClause::UrlHostMatches(r"github\.com$".to_string());
        assert!(validate_regexes(&good).is_ok());
    }

    #[test]
    fn test_check_regex_length_cap_counts_chars_not_bytes() {
        // round-26: the 1024 cap is measured in CHARACTERS, not UTF-8 bytes. 600
        // 'é' (2 bytes each) is 600 chars / 1200 bytes — under the char cap, over
        // a byte cap — so it must be ACCEPTED.
        let multibyte = "é".repeat(600);
        assert_eq!(multibyte.chars().count(), 600, "600 chars");
        assert!(multibyte.len() > 1024, "but >1024 bytes");
        assert!(
            validate_regexes(&WhenClause::UrlHostMatches(multibyte)).is_ok(),
            "a <=1024-CHAR regex must pass even when its byte length exceeds 1024"
        );

        // A >1024-CHAR pattern is still rejected, with the message reporting the
        // CHAR count (1025).
        let over = "a".repeat(1025);
        assert_eq!(over.chars().count(), 1025, "1025 chars");
        let err = validate_regexes(&WhenClause::UrlHostMatches(over))
            .expect_err("a >1024-CHAR regex must be rejected by the char-count cap");
        assert!(
            err.contains("1025 chars"),
            "error must report the CHAR count (got: {err})"
        );
    }

    #[test]
    fn test_unsupported_predicate_detects_mcp_tool_and_agent_kind() {
        // round-3 R3-3 + round-8 R8-1: the helper must flag both `mcp.tool` and
        // `agent.kind` (nested too) and NOT flag any satisfiable predicate.
        let bare = WhenClause::McpTool("read_file".to_string());
        let reason = clause_uses_unsupported_predicate(&bare).expect("mcp.tool must be flagged");
        assert!(
            reason.contains("mcp.tool") && reason.contains("not supported"),
            "reason must name mcp.tool clearly: {reason}"
        );

        // `agent.kind` is also rejected (round-8 R8-1), pointing at `agent_rules`.
        let agent = WhenClause::AgentKind("claude-code".to_string());
        let agent_reason =
            clause_uses_unsupported_predicate(&agent).expect("agent.kind must be flagged (R8-1)");
        assert!(
            agent_reason.contains("agent.kind")
                && agent_reason.contains("not supported")
                && agent_reason.contains("agent_rules"),
            "reason must name agent.kind + point at agent_rules: {agent_reason}"
        );

        // Buried under all/any/not — still detected (mcp.tool).
        let nested = WhenClause::All(vec![
            WhenClause::CommandUsesSudo(true),
            WhenClause::Any(vec![
                WhenClause::UrlScheme("https".to_string()),
                WhenClause::Not(Box::new(WhenClause::McpTool("x".to_string()))),
            ]),
        ]);
        assert!(clause_uses_unsupported_predicate(&nested).is_some());

        // Buried under all/any/not — still detected (agent.kind).
        let nested_agent = WhenClause::All(vec![
            WhenClause::CommandUsesSudo(true),
            WhenClause::AgentKind("claude-code".to_string()),
        ]);
        assert!(clause_uses_unsupported_predicate(&nested_agent).is_some());

        // Ordinary, satisfiable predicates are NOT flagged.
        assert!(clause_uses_unsupported_predicate(&WhenClause::CommandUsesSudo(true)).is_none());
        assert!(clause_uses_unsupported_predicate(&WhenClause::All(vec![
            WhenClause::UrlScheme("https".to_string()),
            WhenClause::CommandUsesSudo(true),
        ]))
        .is_none());
    }

    #[test]
    fn test_path_is_under() {
        assert!(path_is_under("/home/user/proj", "/home/user"));
        assert!(path_is_under("/home/user", "/home/user"));
        assert!(!path_is_under("/home/user-other", "/home/user"));
        assert!(path_is_under("/anything", "/"));
        assert!(!path_is_under("relative/path", "/abs"));
    }

    #[test]
    fn test_path_is_under_root_sentinel_matches_windows_absolutes() {
        // round-15: the root sentinel `cwd_in: ["/"]` must contain ANY absolute
        // path — Windows drive-letter and UNC absolutes too, not just POSIX.
        assert!(
            path_is_under(r"C:\repo\sub", "/"),
            "Windows drive-letter absolute must be root-contained"
        );
        assert!(
            path_is_under("C:/repo/sub", "/"),
            "forward-slash Windows drive absolute must be root-contained"
        );
        assert!(
            path_is_under(r"\\host\share\x", "/"),
            "UNC absolute must be root-contained"
        );
        // A POSIX absolute is still root-contained.
        assert!(path_is_under("/home/x", "/"));
        // An empty path and a relative path are NOT root-contained.
        assert!(
            !path_is_under("", "/"),
            "empty path is not absolute, so not root-contained"
        );
        assert!(
            !path_is_under("relative/sub", "/"),
            "relative path is not root-contained"
        );
    }

    #[test]
    fn test_path_is_under_root_sentinel_rejects_drive_relative() {
        // round-20 (correcting round-19): only genuinely-absolute Windows paths
        // (drive + separator) are root-contained; bare `C:` and `C:relative` are
        // drive-RELATIVE and must NOT be.
        assert!(
            path_is_under("C:/x", "/"),
            "drive-letter absolute (with separator) is root-contained"
        );
        assert!(
            path_is_under(r"C:\x", "/"),
            "drive-letter absolute (back-slash) is root-contained"
        );
        // Bare `C:` is drive-RELATIVE (NOT absolute) — round-20 correction:
        assert!(
            !path_is_under("C:", "/"),
            "bare drive `C:` (no separator) is drive-relative, NOT absolute, so \
             NOT root-contained"
        );
        // And `C:relative` is likewise drive-RELATIVE, so NOT root-contained:
        assert!(
            !path_is_under("C:relative", "/"),
            "drive-relative `C:relative` (no separator after the colon) is NOT \
             absolute and must not be root-contained"
        );
        // And a bare relative path is still not root-contained:
        assert!(
            !path_is_under("relative", "/"),
            "bare relative path is not root-contained"
        );
    }

    #[test]
    fn test_path_is_under_root_sentinel_untrimmed_bare_roots() {
        // round-25: the sentinel's absolute check runs on the UNTRIMMED values —
        // trimming would turn bare drive root `C:/` into `C:` (rejected as
        // drive-relative), wrongly excluding `C:/` and `C:\`.
        assert!(path_is_under("/x", "/"), "POSIX absolute is root-contained");
        assert!(
            path_is_under("/", "/"),
            "bare POSIX root `/` is root-contained"
        );
        assert!(
            path_is_under("C:/", "/"),
            "bare Windows drive ROOT `C:/` (trailing slash) is absolute and \
             root-contained — the round-25 regression"
        );
        assert!(
            path_is_under("C:/x", "/"),
            "Windows drive absolute `C:/x` is root-contained"
        );
        assert!(
            path_is_under(r"C:\", "/"),
            "bare Windows drive ROOT `C:\\` (back-slash) is absolute and \
             root-contained — the round-25 regression"
        );
        // FALSE cases — drive-RELATIVE and bare-relative are NOT root-contained:
        assert!(
            !path_is_under("C:", "/"),
            "bare drive `C:` (no separator) is drive-relative, NOT root-contained"
        );
        assert!(
            !path_is_under("foo/bar", "/"),
            "bare relative path is NOT root-contained"
        );
    }

    #[test]
    fn test_path_is_under_non_root_base_unaffected_by_reorder() {
        // round-25: the empty-base reorder must NOT change non-root prefix
        // matching — descendants match, sibling-prefix sharers do not.
        assert!(
            path_is_under("/home/user/x", "/home/user"),
            "descendant of a real base still matches"
        );
        assert!(
            path_is_under("/home/user", "/home/user"),
            "the base itself still matches"
        );
        assert!(
            !path_is_under("/home/other", "/home/user"),
            "a sibling under a different leaf is NOT under the base"
        );
        // Trailing-slash on either side still matches (trimmed for the prefix
        // compare AFTER the sentinel check).
        assert!(
            path_is_under("/home/user/", "/home/user"),
            "trailing-slash path still matches the base"
        );
        assert!(
            path_is_under("/home/user/x", "/home/user/"),
            "trailing-slash base still matches a descendant"
        );
    }

    #[test]
    fn test_is_windows_absolute_path() {
        // Drive-letter ABSOLUTES require a SEPARATOR after the colon.
        assert!(is_windows_absolute_path("C:/x"));
        assert!(is_windows_absolute_path(r"C:\x"));
        assert!(is_windows_absolute_path("c:/x")); // lower-case drive letter
        assert!(is_windows_absolute_path("//host/share"));
        // Verbatim `\\?\C:\x` is backslash-normalized to `//?/C:/x` first, caught
        // by the leading `//` UNC arm.
        assert!(is_windows_absolute_path("//?/C:/x"));
        // round-20: bare `C:` and `C:relative` (no separator) are drive-RELATIVE,
        // NOT absolute.
        assert!(!is_windows_absolute_path("C:"));
        assert!(!is_windows_absolute_path("C:relative"));
        assert!(!is_windows_absolute_path("/home/x")); // POSIX, handled by starts_with('/')
        assert!(!is_windows_absolute_path("relative"));
        assert!(!is_windows_absolute_path(""));
        // The looser `looks_like_windows_path` DOES match both — why the strict
        // variant is needed for the sentinel.
        assert!(looks_like_windows_path("C:"));
        assert!(looks_like_windows_path("C:relative"));
    }

    #[test]
    fn test_path_is_under_windows_separators() {
        // Regression (finding B): Windows back-slashed paths are normalized so a
        // base matches its descendant.
        assert!(path_is_under(r"C:\repo\sub", r"C:\repo"));
        assert!(path_is_under(r"C:\repo", r"C:\repo"));
        assert!(path_is_under(r"C:\repo\deep\nested", r"C:\repo"));
        // Mixed separators still match (a `/`-form base, back-slashed path).
        assert!(path_is_under(r"C:\repo\sub", "C:/repo"));
        // A sibling that merely shares a prefix is NOT under the base.
        assert!(!path_is_under(r"C:\repo-other\sub", r"C:\repo"));
        // POSIX behavior is unchanged.
        assert!(path_is_under("/home/x/y", "/home/x"));
        assert!(!path_is_under("/home-other", "/home"));
    }

    #[test]
    fn test_path_is_under_windows_case_insensitive() {
        // Regression (finding R1): a case-insensitive Windows file system matches
        // across case.
        assert!(path_is_under(r"c:\repo\sub", r"C:\repo"));
        assert!(path_is_under(r"C:\Repo\Sub", r"c:\repo"));
        assert!(path_is_under(r"c:/repo/sub", "C:/REPO"));
        // UNC / `//`-rooted paths are also treated as case-insensitive.
        assert!(path_is_under(r"\\Server\Share\Dir", r"\\server\share"));
        // A case-only-differing sibling is still NOT under the base.
        assert!(!path_is_under(r"C:\repo-other\sub", r"c:\repo"));
        // POSIX paths stay CASE-SENSITIVE: `/Home` is not a parent of `/home/x`.
        assert!(!path_is_under("/home/x", "/Home"));
        assert!(!path_is_under("/Home/x", "/home"));
    }

    #[test]
    fn test_host_is_under_domain() {
        assert!(host_is_under_domain("api.github.com", "github.com"));
        assert!(host_is_under_domain("github.com", "github.com"));
        assert!(host_is_under_domain("github.com", ".github.com"));
        assert!(!host_is_under_domain("notgithub.com", "github.com"));
        assert!(!host_is_under_domain("github.com.evil.com", "github.com"));
    }

    #[test]
    fn test_package_predicates() {
        let yaml = r#"
all:
  - package.ecosystem: npm
  - package.name_matches: "^left-pad$"
  - package.reputation: malicious
"#;
        let clause: WhenClause = serde_yaml::from_str(yaml).unwrap();
        let mut ctx = DslEvalContext::default();
        ctx.packages.push(DslPackage {
            ecosystem: "npm".to_string(),
            name: "left-pad",
            reputation: PkgReputation::Malicious,
        });
        assert!(evaluate(&clause, &ctx));

        // Not malicious -> reputation predicate false.
        let mut ctx2 = DslEvalContext::default();
        ctx2.packages.push(DslPackage {
            ecosystem: "npm".to_string(),
            name: "left-pad",
            reputation: PkgReputation::Known,
        });
        assert!(!evaluate(&clause, &ctx2));
    }

    #[test]
    fn test_package_reputation_tristate() {
        // Regression (finding C): `unknown`/`known`/`malicious` must each be
        // independently matchable, incl. `unknown` with a DB loaded.
        let unknown_clause = WhenClause::PackageReputation(Reputation::Unknown);
        let known_clause = WhenClause::PackageReputation(Reputation::Known);
        let malicious_clause = WhenClause::PackageReputation(Reputation::Malicious);

        let cases = [
            // No DB loaded -> unknown only.
            (PkgReputation::NoDb, true, false, false),
            // DB loaded but package absent from both indices -> unknown only.
            (PkgReputation::Unknown, true, false, false),
            // Known-popular package -> known only.
            (PkgReputation::Known, false, true, false),
            // Malicious hit -> malicious only.
            (PkgReputation::Malicious, false, false, true),
        ];
        for (rep, want_unknown, want_known, want_malicious) in cases {
            let mut ctx = DslEvalContext::default();
            ctx.packages.push(DslPackage {
                ecosystem: "npm".to_string(),
                name: "some-pkg",
                reputation: rep,
            });
            assert_eq!(
                evaluate(&unknown_clause, &ctx),
                want_unknown,
                "unknown predicate for {rep:?}"
            );
            assert_eq!(
                evaluate(&known_clause, &ctx),
                want_known,
                "known predicate for {rep:?}"
            );
            assert_eq!(
                evaluate(&malicious_clause, &ctx),
                want_malicious,
                "malicious predicate for {rep:?}"
            );
        }
    }

    #[test]
    fn test_ecosystem_alias_round_trip() {
        // `crates`/`cargo` should match the canonical `crates.io`.
        let clause = WhenClause::PackageEcosystem("cargo".to_string());
        let mut ctx = DslEvalContext::default();
        ctx.packages.push(DslPackage {
            ecosystem: "crates.io".to_string(),
            name: "serde",
            reputation: PkgReputation::Unknown,
        });
        assert!(evaluate(&clause, &ctx));
    }
}
