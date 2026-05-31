//! M13 ch4 — the custom-rule DSL (semantic predicates).
//!
//! A custom rule in `.tirith/policy.yaml` may carry EITHER a `pattern:` regex
//! (the M-earlier [`crate::rules::custom`] path) OR a `when:` clause — a small
//! boolean tree of semantic predicates evaluated against the engine's
//! already-extracted analysis data (URLs, command tokens, packages, the scanned
//! file path). The two are mutually exclusive: a rule has EXACTLY ONE of them.
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
//! `all` / `any` / `not` are the logical combinators; everything else is a
//! leaf predicate. The serde representation is a **key-dispatched** (externally
//! tagged) enum — each YAML key maps to exactly one [`WhenClause`] variant — so
//! the shape round-trips without the ambiguity an `#[serde(untagged)]` tree
//! would carry (`url.host` vs `url.host_matches` would otherwise both try to
//! deserialize a bare string).
//!
//! # Predicate -> data binding (v1)
//!
//! Each leaf binds to REAL extracted data carried in [`DslEvalContext`], which
//! the engine fills from the same extraction the production rules already ran:
//!
//! | Predicate                  | Binds to                                                              |
//! |----------------------------|-----------------------------------------------------------------------|
//! | `command.has_pipeline_to`  | a `|`-pipeline segment whose resolved interpreter (sudo/env-aware) is in the list |
//! | `command.uses_sudo`        | any segment whose resolved leader is `sudo`                           |
//! | `command.cwd_in`           | `ctx.cwd` is at/under one of the listed paths                          |
//! | `url.host`                 | any extracted URL's canonical host equals (case-insensitive)           |
//! | `url.host_matches`         | any extracted URL's host matches the regex                             |
//! | `url.scheme`               | any extracted URL's scheme equals (case-insensitive)                   |
//! | `url.reputation`           | `known` = built-in known-domains table; `malicious` = threat-DB hostname hit; `unknown` = neither |
//! | `url.domain_not_in`        | at least one extracted URL whose host is NOT at/under any listed domain |
//! | `package.ecosystem`        | an extracted install package in that ecosystem                          |
//! | `package.name_matches`     | an extracted package whose name matches the regex                       |
//! | `package.reputation`       | `malicious` = threat-DB package hit; `known` = known-popular package the DB vouches for; `unknown` = no DB, or a DB that lists the package in neither index |
//! | `file.path_matches`        | `ctx.file_path` matches the regex                                       |
//! | `agent.kind`               | parsed but REJECTED at validate (see v1 limitation)                     |
//! | `mcp.tool`                 | parsed but REJECTED at validate (see v1 limitation)                     |
//!
//! ## v1 limitations (parsed, but REJECTED by the validators)
//!
//! * **`agent.kind` / `mcp.tool`** — the exec/paste hot path
//!   ([`crate::engine::analyze`]) has NO structured "current agent kind" or
//!   "current MCP tool" in scope (agent/MCP signals live in separate flows:
//!   `mcpdrift` runs over lockfiles in FileScan, agent governance lives in the
//!   `agent_rules` / `AgentMatcher` flow, and agent annotations are rich-text
//!   `agent_view` enrichment). `DslEvalContext::agent_kind` / `mcp_tool` are
//!   hard-coded `None` on every engine path, so a DSL clause using either
//!   predicate would validate and load yet NEVER match — a dead rule. Both
//!   predicates are therefore REJECTED up front by `policy validate` and `rule
//!   validate` (see [`clause_uses_unsupported_predicate`]); they are still
//!   parsed so the error is precise. For per-agent control, use `agent_rules`
//!   (CodeRabbit M13 round-3 R3-3 for `mcp.tool`, round-8 R8-1 for
//!   `agent.kind`).
//! * **`url.reputation` / `package.reputation`** — bound to the LOCAL signed
//!   threat-DB + built-in known-domains table reachable on the hot path; NO
//!   network lookup happens at eval time (matching the rest of the engine's
//!   local-first hot path). When no threat-DB is loaded, `malicious` is `false`
//!   and every host/package is `unknown` (fail-open, never blocks the user).
//!   When a DB IS loaded, `package.reputation` is a real tri-state (see
//!   [`PkgReputation`]): `malicious` for a threat-DB hit, `known` for a
//!   known-popular package the DB vouches for, and `unknown` for a package the
//!   DB lists in neither index — so `unknown` stays reachable with a DB loaded.
//! * **`package.*`** — packages come from [`crate::rules::threatintel::extract_packages`]
//!   (install/add commands: pip/npm/yarn/pnpm/bun/npx/cargo/gem/go/composer/dotnet),
//!   plus Docker image refs surfaced as the `docker` ecosystem. A command with
//!   no recognized install leader yields no packages, so `package.*` is `false`.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};

use regex::Regex;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

use crate::extract::ScanContext;

/// One node of a `when:` clause — a **key-dispatched** node: serialized as a
/// single-key YAML mapping whose key (`all`, `any`, `not`, or a leaf predicate
/// name like `command.has_pipeline_to`) selects exactly one variant and whose
/// value is that variant's payload.
///
/// `serde`'s built-in externally-tagged enum representation uses YAML `!tag`
/// syntax under `serde_yaml` 0.9, which is NOT the `{ key: value }` mapping the
/// policy shape uses — so `Serialize`/`Deserialize` are implemented by hand
/// below to produce/consume single-key maps. The variant set and payloads are
/// otherwise an ordinary enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhenClause {
    /// All sub-clauses must match (logical AND). Empty list is vacuously true.
    All(Vec<WhenClause>),
    /// Any sub-clause must match (logical OR). Empty list is vacuously false.
    Any(Vec<WhenClause>),
    /// The sub-clause must NOT match (logical negation).
    Not(Box<WhenClause>),

    // ---- command.* leaves ----
    /// `command.has_pipeline_to: [sh, bash, ...]` — a `|`-pipeline whose
    /// resolved interpreter is one of the named shells/interpreters.
    CommandHasPipelineTo(Vec<String>),
    /// `command.uses_sudo: true` — the command escalates via `sudo`.
    CommandUsesSudo(bool),
    /// `command.cwd_in: [paths]` — the current working directory is at/under
    /// one of the listed paths.
    CommandCwdIn(Vec<String>),

    // ---- url.* leaves ----
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

    // ---- package.* leaves ----
    /// `package.ecosystem: <e>` — an extracted package in ecosystem `<e>`.
    PackageEcosystem(String),
    /// `package.name_matches: <regex>` — an extracted package name matches.
    PackageNameMatches(String),
    /// `package.reputation: known|unknown|malicious`.
    PackageReputation(Reputation),

    // ---- file.* leaves ----
    /// `file.path_matches: <regex>` — the scanned file path matches the regex.
    FilePathMatches(String),

    // ---- agent.* / mcp.* leaves ----
    /// `agent.kind: <k>` — parsed but REJECTED at validate (no agent-kind signal
    /// is wired into the scan context; use `agent_rules`). See module docs.
    AgentKind(String),
    /// `mcp.tool: <t>` — the current MCP tool equals `<t>` (v1: only when a
    /// caller sets it; see module docs).
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

impl<'de> Deserialize<'de> for WhenClause {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ClauseVisitor;

        impl<'de> Visitor<'de> for ClauseVisitor {
            type Value = WhenClause;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a single-key when-clause mapping (e.g. `url.scheme: https`)")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<WhenClause, M::Error> {
                let key: String = map
                    .next_key()?
                    .ok_or_else(|| de::Error::custom("when-clause must have exactly one key"))?;

                // Helper macros to deserialize the value as a concrete type.
                macro_rules! val {
                    ($t:ty) => {{
                        let v: $t = map.next_value()?;
                        v
                    }};
                }

                let clause = match key.as_str() {
                    "all" => WhenClause::All(val!(Vec<WhenClause>)),
                    "any" => WhenClause::Any(val!(Vec<WhenClause>)),
                    "not" => WhenClause::Not(Box::new(val!(WhenClause))),
                    "command.has_pipeline_to" => {
                        WhenClause::CommandHasPipelineTo(val!(Vec<String>))
                    }
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

                // Reject a second key — a clause node is exactly one predicate.
                if map.next_key::<String>()?.is_some() {
                    return Err(de::Error::custom(
                        "when-clause node must have exactly one key (wrap multiple in `all:`/`any:`)",
                    ));
                }
                Ok(clause)
            }
        }

        deserializer.deserialize_map(ClauseVisitor)
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
/// signed threat-DB.
///
/// The earlier `Option<bool>` collapsed two genuinely different states — "DB
/// loaded but this package is absent" and "no DB loaded" — onto `Some(false)` /
/// `None` in a way that made `package.reputation: unknown` unreachable once a DB
/// was loaded and mislabeled every unseen package as `known` (CodeRabbit M13
/// finding C). The four states are now distinct so the predicate maps them
/// correctly:
///
/// * [`NoDb`](PkgReputation::NoDb) — no threat-DB was loaded; nothing can be
///   classified (fail-open). The `unknown` predicate matches here.
/// * [`Unknown`](PkgReputation::Unknown) — a DB IS loaded but this package
///   appears in neither the malicious index nor the known-popular index. The
///   `unknown` predicate matches.
/// * [`Known`](PkgReputation::Known) — a DB is loaded and this package is in the
///   known-popular (good) index and NOT flagged malicious. The `known`
///   predicate matches.
/// * [`Malicious`](PkgReputation::Malicious) — the threat-DB flags this package
///   (a `check_package` hit). The `malicious` predicate matches.
///
/// `NoDb` and `Unknown` are kept separate (rather than collapsed) so callers /
/// future predicates can tell "we have no data source" from "we looked and it
/// isn't notable"; both currently satisfy the `unknown` predicate.
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
///
/// Mirrors the fields of [`crate::rules::threatintel::PackageRef`] the
/// predicates need; the engine builds these from the same extractor.
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
/// against. Borrows everything — the engine builds this only when at least one
/// DSL rule exists, so the no-DSL hot path pays nothing.
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

/// The set of [`ScanContext`]s in which a clause CAN be fully evaluated — i.e.
/// every fact the clause references is populated by [`build_dsl_backing`] for
/// that context. This is the clause's **satisfiable-context set** (CodeRabbit
/// M13 round-9 R9-1).
///
/// Drives the tier-1 validation invariant. The old `RequiredTriggerSet`
/// flattened every leaf's context family into one conjunction-of-disjunctions,
/// which was unsound for combinators:
///
/// * `all(command.uses_sudo, file.path_matches)` was wrongly ACCEPTED for
///   `context: [exec, file]` — but NO single scan populates BOTH command facts
///   and a file path, so the rule could never fire (a dead rule).
/// * `any(command.uses_sudo, file.path_matches)` was wrongly REJECTED for
///   `context: [exec]` — but the `command.*` branch IS evaluable there.
///
/// The set is now computed PER CLAUSE so combinators compose correctly:
/// * leaf → the contexts where that fact exists (`command.*`/`url.*`/`package.*`
///   → {Exec, Paste}; `file.path_matches` → {FileScan}).
/// * `all(children)` → INTERSECTION (the whole AND can only be evaluated where
///   EVERY child can).
/// * `any(children)` → UNION (the OR is evaluable wherever ANY child is).
/// * `not(child)` → the child's set (negation doesn't change evaluability).
///
/// `agent.kind` and `mcp.tool` contribute the EMPTY set (no scan context wires
/// up their signal), but they are rejected up front by
/// [`clause_uses_unsupported_predicate`] BEFORE this is ever consulted for a
/// loaded rule — so a loaded rule never sees their empty contribution. Their
/// empty set here only matters as the identity for `any`/`not` composition.
///
/// An empty `all`/`any` combinator needs no facts and so is evaluable in EVERY
/// context (the universal set) — a degenerate case that keeps a vacuous clause
/// from being mislabeled unsatisfiable.
///
/// Validity then has two parts (see `policy_validate` / `rule validate` /
/// [`crate::rules::custom::compile_rules`], which all route through here):
/// 1. An EMPTY satisfiable set means the clause needs facts from contexts that
///    never co-occur in a single scan (e.g. `command.*` AND `file.*`) — it can
///    never match and is rejected as UNSATISFIABLE.
/// 2. Otherwise the rule is valid iff the DECLARED context set intersects the
///    satisfiable set (`declared ∩ satisfiable ≠ ∅`): at least one declared
///    context can actually evaluate the clause.
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
    /// The universal set — every context can evaluate the clause (used as the
    /// `all`-intersection identity and for fact-free vacuous combinators).
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

    /// `true` when no context can evaluate the clause (UNSATISFIABLE — needs
    /// facts from contexts that never co-occur in a single scan).
    pub fn is_empty(&self) -> bool {
        !self.exec && !self.paste && !self.file
    }

    /// `true` when the rule's DECLARED contexts share at least one context with
    /// this satisfiable set — i.e. at least one declared context can actually
    /// evaluate the clause. (`declared ∩ satisfiable ≠ ∅`.)
    pub fn intersects_declared(&self, declared: &[ScanContext]) -> bool {
        declared.iter().any(|c| self.contains(*c))
    }

    /// The contexts in this set, in a stable order, as lowercase names — for
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
            // Unsatisfiable clauses are reported via their own dedicated message,
            // never through this coverage path, so this is defensive only.
            "(no scan context)".to_string()
        } else {
            names.join(" or ")
        }
    }
}

/// Compute the [`ContextSet`] in which a clause can be FULLY evaluated — the set
/// of scan contexts where every fact the clause references is populated.
///
/// Combinators compose by set algebra so `all`/`any`/`not` keep their proper
/// semantics (CodeRabbit M13 round-9 R9-1):
/// * `all(children)` → INTERSECTION (evaluable only where EVERY child is).
/// * `any(children)` → UNION (evaluable wherever ANY child is).
/// * `not(child)` → the child's set (negation doesn't change evaluability).
///
/// Empty combinators follow their `evaluate` truth value, not just the set
/// identity, so a dead clause is reported as such:
/// * An empty `all` is vacuously TRUE in `evaluate`, so it yields the universal
///   set (it can be evaluated anywhere) — the intersection identity coincides.
/// * An empty `any` is vacuously FALSE in `evaluate` (it can never match), so it
///   yields the EMPTY set — the union identity — and is rejected as
///   unsatisfiable rather than mislabeled runnable (CodeRabbit M13 round-10
///   R10-1).
///
/// `agent.kind` / `mcp.tool` yield the empty set, but they are rejected by
/// [`clause_uses_unsupported_predicate`] before this is consulted for a loaded
/// rule.
pub fn satisfiable_contexts(clause: &WhenClause) -> ContextSet {
    use ScanContext::{Exec, FileScan, Paste};
    match clause {
        // INTERSECTION: an empty `all` is vacuously true and fact-free, so it is
        // evaluable in every context (intersection identity = universal set).
        WhenClause::All(cs) => cs
            .iter()
            .map(satisfiable_contexts)
            .fold(ContextSet::ALL, ContextSet::intersect),
        // UNION: an empty `any` is the union identity (EMPTY). It is also
        // VACUOUSLY FALSE in `evaluate` (`[].iter().any(..)` is `false`), so it
        // can never match in any context — a dead rule. Returning EMPTY here makes
        // the satisfiability check reject/drop it (consistent with the round-9
        // empty-satisfiable-set rejection), rather than mislabeling it runnable.
        // Real `any` clauses always have children, so this only guards the
        // degenerate empty case (CodeRabbit M13 round-10 R10-1). Contrast `all`:
        // an empty `all` is vacuously TRUE in `evaluate`, so its identity (ALL)
        // is correct above.
        WhenClause::Any(cs) => cs
            .iter()
            .map(satisfiable_contexts)
            .fold(ContextSet::EMPTY, ContextSet::union),
        WhenClause::Not(c) => satisfiable_contexts(c),

        // `command.*` is evaluable in Exec OR Paste. `build_dsl_backing`
        // populates `pipeline_targets`, `uses_sudo`, AND `cwd` for EVERY
        // non-`FileScan` context (CodeRabbit M13 round-3 R3-1); FileScan never
        // extracts command facts.
        WhenClause::CommandHasPipelineTo(_)
        | WhenClause::CommandUsesSudo(_)
        | WhenClause::CommandCwdIn(_) => ContextSet::from_contexts(&[Exec, Paste]),

        // `url.*` is evaluable in Exec OR Paste (URLs are extracted in both).
        WhenClause::UrlHost(_)
        | WhenClause::UrlHostMatches(_)
        | WhenClause::UrlScheme(_)
        | WhenClause::UrlReputation(_)
        | WhenClause::UrlDomainNotIn(_) => ContextSet::from_contexts(&[Exec, Paste]),

        // `package.*` is evaluable in Exec OR Paste — `build_dsl_backing`
        // extracts package facts off the command line for every non-`FileScan`
        // context (round-3 R3-1); FileScan never populates `packages`.
        WhenClause::PackageEcosystem(_)
        | WhenClause::PackageNameMatches(_)
        | WhenClause::PackageReputation(_) => ContextSet::from_contexts(&[Exec, Paste]),

        // `file.path_matches` is evaluable only in FileScan (the only context
        // that sets `file_path`).
        WhenClause::FilePathMatches(_) => ContextSet::from_contexts(&[FileScan]),

        // `mcp.tool` / `agent.kind`: no scan context wires up their signal, so
        // their satisfiable set is EMPTY. Both are rejected up front by
        // `clause_uses_unsupported_predicate` (round-3 R3-3 / round-8 R8-1)
        // BEFORE this is consulted for a loaded rule; the empty set here only
        // serves as the identity for `any`/`not` composition.
        WhenClause::McpTool(_) | WhenClause::AgentKind(_) => ContextSet::EMPTY,
    }
}

/// Scan a clause tree for a predicate that is parsed and type-checked but can
/// NEVER match because no scan context wires up the signal it reads. Returns a
/// clear, user-facing reason for the FIRST such predicate found, or `None` when
/// every predicate is satisfiable.
///
/// Two predicates are unsupported today, both because their backing field in
/// [`DslEvalContext`] is hard-coded `None` on every engine path:
///
/// * **`mcp.tool`** — [`DslEvalContext::mcp_tool`] is always `None` (the
///   exec/paste hot path has no current-MCP-tool in scope, and the FileScan path
///   scans file content, not a live tool invocation).
/// * **`agent.kind`** — [`DslEvalContext::agent_kind`] is always `None` (the
///   exec/paste hot path has no structured "current agent kind"; agent control
///   lives in the separate `agent_rules` / `AgentMatcher` flow from M13 chunk 5,
///   which is the supported way to gate per agent). A DSL `agent.kind` clause
///   would validate and load yet be a permanent no-op, so it is rejected rather
///   than left as a dead rule (CodeRabbit M13 round-8 R8-1).
///
/// Both validators (`policy validate` and `rule validate`) call this and REJECT
/// such a rule rather than silently accept a dead rule (CodeRabbit M13 round-3
/// R3-3 for `mcp.tool`; round-8 R8-1 for `agent.kind`).
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
    if pattern.len() > 1024 {
        return Err(format!(
            "{field}: regex too long ({} chars, max 1024)",
            pattern.len()
        ));
    }
    Regex::new(pattern)
        .map(|_| ())
        .map_err(|e| format!("{field}: invalid regex: {e}"))
}

thread_local! {
    /// Per-thread compiled-regex cache for the DSL `*_matches` predicates.
    /// Patterns are already validated at load (`validate_regexes`), so this only
    /// avoids recompiling the SAME pattern on every `evaluate()` (which the hot
    /// path calls once per command / file when a DSL rule runs). Cloning a
    /// compiled `Regex` is cheap (it is `Arc`-backed), so the cache hands back a
    /// clone and never lends a borrow across the match.
    static REGEX_CACHE: RefCell<HashMap<String, Regex>> = RefCell::new(HashMap::new());
}

/// Compile `pat` once per thread and return a (cheap) clone of the cached
/// `Regex`. Returns `None` if the pattern fails to compile — identical
/// behavior to the previous inline `Regex::new(pat)` (a bad pattern yields no
/// match), and validated patterns never hit that path.
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
            // Fires when AT LEAST ONE extracted URL's host is outside every
            // listed registrable domain — the "talking to a domain we didn't
            // allow" shape. With no URLs there is nothing outside the list.
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
            // `known` = a known-popular package the DB vouches for (and which is
            // not flagged malicious).
            Reputation::Known => p.reputation == PkgReputation::Known,
            // `unknown` = either no DB loaded, OR a DB is loaded but the package
            // is in neither the malicious nor the known-popular index. Both are
            // "we can't vouch for this", which is what `unknown` means.
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
/// display string when recognized; otherwise lowercase the input. This lets
/// `crates`/`cargo` match `crates.io`, etc.
fn normalize_ecosystem(s: &str) -> String {
    match crate::threatdb::Ecosystem::from_name(s) {
        Some(e) => e.to_string(),
        None => s.to_lowercase(),
    }
}

/// Heuristic: does this look like a Windows path? `true` for a leading
/// drive-letter spec (`C:\…`, `c:/…`) or a UNC/`//`-rooted path. Windows file
/// systems are case-insensitive, so such paths are lowercased before lexical
/// comparison; POSIX paths are left untouched because they ARE case-sensitive.
fn looks_like_windows_path(s: &str) -> bool {
    let bytes = s.as_bytes();
    // Drive letter: `X:` followed by a separator (or end of string).
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return true;
    }
    // UNC / double-separator root (already back-slash-normalized to `/`).
    s.starts_with("//")
}

/// Normalize a path for purely-lexical "is-under" matching: back-slashes →
/// `/`, and (only when [`looks_like_windows_path`]) lowercased so a
/// case-insensitive Windows file system matches `C:\repo` against
/// `c:\repo\sub`. POSIX paths keep their case.
fn normalize_for_lexical_path_match(s: &str) -> String {
    let slashed = s.replace('\\', "/");
    if looks_like_windows_path(&slashed) {
        slashed.to_lowercase()
    } else {
        slashed
    }
}

/// `true` when `path` is `base` or a descendant of it. Both are compared as
/// `/`-separated component sequences (purely lexical — no filesystem access),
/// so `/home/x` is under `/home` but `/home-other` is not.
///
/// Windows back-slashes are normalized to `/` first, and Windows-looking paths
/// are lowercased, so `cwd_in: ["C:\\repo"]` matches `c:\\repo\\sub` on a
/// case-insensitive file system (CodeRabbit M13 findings B/R1). POSIX paths
/// remain case-sensitive — `/Home` is NOT a parent of `/home/x`.
fn path_is_under(path: &str, base: &str) -> bool {
    let path = normalize_for_lexical_path_match(path);
    let base = normalize_for_lexical_path_match(base);
    let path = path.trim_end_matches('/');
    let base = base.trim_end_matches('/');
    if base.is_empty() {
        // `cwd_in: ["/"]` — root contains everything.
        return path.starts_with('/');
    }
    if path == base {
        return true;
    }
    path.strip_prefix(base)
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

    /// The seven shipping example DSL rules
    /// (`tests/fixtures/custom_rules_dsl.yaml`) must all load via `Policy`, have
    /// a valid pattern-XOR-when shape, valid inner regexes, and a declared
    /// context that covers each clause's required triggers.
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

        // Use the strict parser so a fixture typo is a hard test failure
        // (the production `load_from_yaml` warn-and-defaults to empty).
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
        // Re-serialize and re-parse to prove a clean round-trip.
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

        // A github.com URL is in the allow list -> domain_not_in is false ->
        // whole `all` is false.
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

        // No sudo, only an https URL -> not(scheme https) is false, sudo is
        // false -> any() false.
        let mut ctx2 = DslEvalContext::default();
        ctx2.urls.push(DslUrl {
            host: "x.com",
            scheme: "https",
            reputation: Reputation::Known,
        });
        assert!(!evaluate(&clause, &ctx2));

        // No sudo, a plain http URL -> not(scheme https) is true -> any() true.
        let mut ctx3 = DslEvalContext::default();
        ctx3.urls.push(DslUrl {
            host: "x.com",
            scheme: "http",
            reputation: Reputation::Known,
        });
        assert!(evaluate(&clause, &ctx3));
    }

    // CodeRabbit M13 round-4 N5: `*_matches` predicates compile their regex
    // through a per-thread cache instead of recompiling on every `evaluate()`.
    // Repeated evaluation of the SAME `url.host_matches` rule must keep identical
    // match / non-match semantics across calls (the cache is transparent).
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

        // Evaluate repeatedly to exercise the cache hit path; the verdict is
        // stable and the cache never flips a match into a non-match.
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
        // CodeRabbit M13 round-3 R3-1: `command.*` predicates evaluate on BOTH
        // exec and paste input (`build_dsl_backing` fills pipeline/sudo/cwd for
        // every non-FileScan context), so a `[paste]` command rule must validate.
        // FileScan still does not (it never extracts command facts).
        let clause = WhenClause::CommandUsesSudo(true);
        let sat = satisfiable_contexts(&clause);
        assert!(!sat.is_empty());
        assert!(sat.intersects_declared(&[ScanContext::Exec]));
        assert!(sat.intersects_declared(&[ScanContext::Paste]));
        assert!(!sat.intersects_declared(&[ScanContext::FileScan]));
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
        // Regression (CodeRabbit M13 round-1 finding A + round-3 R3-1):
        // `package.*` is evaluable in Exec OR Paste — the engine's
        // `build_dsl_backing` extracts package facts off the command line for
        // every non-FileScan context (both exec and paste), so a `[paste]`
        // package rule sees its data at runtime and must validate. FileScan is
        // still rejected (it never populates `DslEvalContext::packages`, so a
        // `context: [file]` package rule would be dead at runtime). Cover all
        // three package predicates.
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
        // CodeRabbit M13 round-9 R9-1: `all(command.*, file.*)` is UNSATISFIABLE —
        // NO single scan populates BOTH command facts and a file path, so the
        // INTERSECTION of {Exec, Paste} and {FileScan} is empty. The old flatten
        // wrongly ACCEPTED this for `context: [exec, file]` (a dead rule).
        let clause = WhenClause::All(vec![
            WhenClause::CommandUsesSudo(true),
            WhenClause::FilePathMatches(r"x".to_string()),
        ]);
        let sat = satisfiable_contexts(&clause);
        assert!(
            sat.is_empty(),
            "all(command, file) must be unsatisfiable (empty intersection), got {sat:?}"
        );
        // Even declaring both contexts cannot rescue it — no single scan has both.
        assert!(!sat.intersects_declared(&[ScanContext::Exec, ScanContext::FileScan]));
    }

    #[test]
    fn test_satisfiable_any_command_or_file_is_union() {
        // CodeRabbit M13 round-9 R9-1: `any(command.*, file.*)` is evaluable
        // wherever EITHER branch is — the UNION {Exec, Paste, FileScan}. The old
        // flatten wrongly REJECTED this for `context: [exec]` even though the
        // command branch is evaluable there. It must be ACCEPTED for `[exec]` AND
        // for `[file]`.
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
        // CodeRabbit M13 round-10 R10-1: a degenerate empty `any: []` is VACUOUSLY
        // FALSE in `evaluate` (`[].iter().any(..)` is `false`), so it can never
        // match — a dead rule. `satisfiable_contexts` must return EMPTY so the
        // validators/compile reject/drop it as unsatisfiable, consistent with the
        // round-9 empty-satisfiable-set rejection.
        let any_empty = WhenClause::Any(vec![]);
        let sat = satisfiable_contexts(&any_empty);
        assert!(
            sat.is_empty(),
            "empty `any: []` must be unsatisfiable (EMPTY set), got {sat:?}"
        );
        // No declared context can rescue it — it is dead everywhere.
        assert!(!sat.intersects_declared(&[
            ScanContext::Exec,
            ScanContext::Paste,
            ScanContext::FileScan,
        ]));
        // And the satisfiability verdict matches `evaluate`: an empty `any` is
        // false on a fully-empty context (it would be false on ANY context).
        assert!(
            !evaluate(&any_empty, &DslEvalContext::default()),
            "empty `any` must evaluate to false"
        );
    }

    #[test]
    fn test_satisfiable_empty_all_is_universal_and_vacuously_true() {
        // CodeRabbit M13 round-10 R10-1 (companion check): an empty `all: []` is
        // VACUOUSLY TRUE in `evaluate` (`[].iter().all(..)` is `true`), so the
        // intersection identity (ALL) is the correct satisfiable set — it is
        // evaluable in every context. This contrasts with empty `any` above and
        // must be left as-is.
        let all_empty = WhenClause::All(vec![]);
        let sat = satisfiable_contexts(&all_empty);
        assert!(
            !sat.is_empty(),
            "empty `all: []` must be satisfiable (universal set), got {sat:?}"
        );
        assert!(sat.intersects_declared(&[ScanContext::Exec]));
        assert!(sat.intersects_declared(&[ScanContext::Paste]));
        assert!(sat.intersects_declared(&[ScanContext::FileScan]));
        // The satisfiability verdict matches `evaluate`: an empty `all` is true.
        assert!(
            evaluate(&all_empty, &DslEvalContext::default()),
            "empty `all` must evaluate to true (vacuous)"
        );
    }

    #[test]
    fn test_satisfiable_not_preserves_child_set() {
        // `not(child)` keeps the child's evaluability — negation only flips the
        // verdict, it doesn't change which context has the facts.
        let clause = WhenClause::Not(Box::new(WhenClause::FilePathMatches(r"x".to_string())));
        let sat = satisfiable_contexts(&clause);
        assert!(sat.intersects_declared(&[ScanContext::FileScan]));
        assert!(!sat.intersects_declared(&[ScanContext::Exec]));
    }

    #[test]
    fn test_satisfiable_all_within_one_family_intersects_to_that_family() {
        // `all(command.*, command.*)` and `all(command.*, url.*)` both stay in
        // {Exec, Paste}: the intersection of two {Exec, Paste} sets is itself
        // {Exec, Paste}, so a `[exec]` rule is accepted (regression for the
        // 7-rule fixture rules 1-4 and 7, which are intra-{exec,paste} `all`s).
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
    fn test_satisfiable_agent_kind_is_empty() {
        // `agent.kind` / `mcp.tool` have an EMPTY satisfiable set (no scan wires
        // up their signal). They are rejected by
        // `clause_uses_unsupported_predicate` BEFORE this is consulted for a
        // loaded rule, so the empty set only serves as the any/not identity.
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
    fn test_unsupported_predicate_detects_mcp_tool_and_agent_kind() {
        // CodeRabbit M13 round-3 R3-3 + round-8 R8-1: `mcp.tool` AND `agent.kind`
        // are parsed + type-checked but no scan context populates `mcp_tool` /
        // `agent_kind`, so they can never match. The helper must flag BOTH (nested
        // inside combinators too) and NOT flag any satisfiable predicate.
        let bare = WhenClause::McpTool("read_file".to_string());
        let reason = clause_uses_unsupported_predicate(&bare).expect("mcp.tool must be flagged");
        assert!(
            reason.contains("mcp.tool") && reason.contains("not supported"),
            "reason must name mcp.tool clearly: {reason}"
        );

        // `agent.kind` is now also rejected (round-8 R8-1), with a message that
        // names the predicate and points at `agent_rules`.
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
    fn test_path_is_under_windows_separators() {
        // Regression (CodeRabbit M13 finding B): Windows back-slashed paths must
        // be normalized so `cwd_in: ["C:\\repo"]` matches a descendant.
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
        // Regression (CodeRabbit M13 finding R1): a case-insensitive Windows
        // file system must match `cwd_in: ["C:\\repo"]` against `c:\repo\sub`.
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
        // Regression (CodeRabbit M13 finding C): `unknown`, `known`, and
        // `malicious` must all be independently matchable, including `unknown`
        // when a DB is loaded but the package is absent from both indices.
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
