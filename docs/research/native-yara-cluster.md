# Spike 5c: native YARA, signature-base, TLSH, and capa cluster

Status: research spike, go/no-go decision record. No `native-yara` feature, no
`yara-x` dependency, no scanner is added in this PR. The closure checks below were
run against throwaway crates in scratch space, never committed.

Question under test: can tirith add native YARA scanning (via `yara-x`) on MSRV
1.83, and where would signature-base, TLSH fuzzy hashing, and capa capability
definitions plug in if it could?

External facts checked 2026-07-16. tirith behaviour claims cite the file and line
read on branch `security/spikes` (PR3 tip, commit bb95bd40).

## The in-tree note, and why it is now stale

`crates/tirith-core/Cargo.toml:28-37` records the original deferral:

> native-yara (yara-x): DEFERRED by the PR-0 dependency spike, NOT wired here.
> The plan pencilled in `native-yara = ["dep:yara-x"]` with yara-x 0.14, but on the
> current registry yara-x 0.14 requires `intaglio >= 1.10`, and intaglio 1.10 (its
> lowest available release) bumped its MSRV to Rust 1.85. yara-x 0.14 also pulls
> `ar_archive_writer` (Rust 1.88) and a newer `time` (1.88) transitively.

The conclusion (defer, no yara-x on 1.83) is still correct and is in fact
reinforced below. But the specific blocker analysis has drifted from what the
registry and resolver actually do now, and should not be trusted as-is. Two
corrections, both empirical (see Closure checks):

1. intaglio 1.10 is not the blocker and is not the lowest release. Per the
   crates.io sparse index (`index.crates.io/in/ta/intaglio`, 2026-07-16),
   intaglio 1.10.0 declares rust-version 1.76, and 1.11.0 and 1.12.0 declare 1.81.
   intaglio only reaches an MSRV of 1.85 at 1.13.1. The MSRV-aware resolver, given
   yara-x 0.14 and a 1.83 target, selects intaglio 1.12.0, which is 1.83
   compatible. Likewise it downgrades `ar_archive_writer` to 0.5.1 and `time` to
   0.3.45, both 1.83 compatible. So none of the three crates the comment names is
   the actual blocker.
2. The real irreducible blocker for yara-x 0.14 on 1.83 is `ignore 0.4.29`, which
   requires the `edition2024` cargo feature and declares no rust-version, so the
   MSRV-aware resolver cannot downgrade it and it fails to parse under cargo 1.83.

This document supersedes that comment's blocker detail. (I did not edit the
comment, since PR5 changes no existing file; flagged for the lead to refresh in a
later PR.)

## yara-x version landscape

From the crates.io sparse index (`index.crates.io/ya/ra/yara-x`, 2026-07-16). The
crate has moved from the 0.x line the plan referenced to a 1.x line, and its own
declared MSRV has climbed well past 1.83:

| yara-x version | declared rust-version | 1.83 self-compatible |
|----------------|-----------------------|----------------------|
| 0.13.0 | 1.81 | yes |
| 0.14.0 | 1.82 | yes |
| 0.15.0 | 1.85 | no |
| 1.14.0 | 1.89 | no |
| 1.16.0 | 1.91 | no |
| 1.19.0 (latest) | 1.91 | no |

So yara-x self-declares an MSRV above 1.83 from 0.15.0 onward, and the entire
current 1.x line needs 1.89 to 1.91. Only yara-x 0.14 and earlier declare a self
MSRV at or below 1.83, and those are blocked by their transitive closure anyway.

## Closure checks (empirical, on Rust 1.83)

Method: a throwaway crate depending on the target yara-x version, with
`rust-version = "1.83"`, lockfile generated with the MSRV-aware resolver
(`CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo +stable generate-lockfile`,
which gives the closure its best possible shot at a 1.83-compatible resolution),
then `cargo +1.83 build`. Toolchains: `cargo 1.83.0 (5ffbef321 2024-10-29)`,
resolver run under `cargo 1.95.0`.

| Target | Result on 1.83 | First blocker |
|--------|----------------|---------------|
| yara-x 0.13.0, default features | fails to build | `ignore 0.4.29` requires `edition2024` (same blocker as 0.14; yara-x 0.13.0's own MSRV is 1.81, but the closure still pulls the un-downgradable `ignore`) |
| yara-x 0.14.0, default features | fails to build | `ignore 0.4.29` requires `edition2024` (no rust-version, un-downgradable) |
| yara-x 0.14.0, `default-features = false` | fails to build | `ignore 0.4.29` requires `edition2024` (feature-trimming does not remove it) |
| yara-x 1.19.0 (latest), default features | fails to build | yara-x 1.19.0 itself declares 1.91; closure pulls cranelift and wasmtime 0.130/43.x (all rust-version 1.91) |

Detail:

- yara-x 0.13.0, the lowest release whose own MSRV (1.81) sits at or below 1.83,
  still fails. The MSRV-aware resolver pulls the same `ignore 0.4.29`, which
  requires the `edition2024` cargo feature and declares no rust-version, so it
  cannot be downgraded and the build fails at manifest-parse time on cargo 1.83.
  A low self-declared MSRV does not help: the `ignore` blocker is shared across
  the 0.x line, so testing 0.13.0 confirms the no-go rather than opening a gap.
- yara-x 0.14 best shot. The resolver downgraded intaglio to 1.12.0,
  `ar_archive_writer` to 0.5.1, `time` to 0.3.45, `indexmap` to 2.13.1, `home` to
  0.5.11, `uuid` to 1.20.0, and others, all to 1.83-compatible versions. It could
  not downgrade `ignore` below 0.4.29, and `ignore 0.4.29` uses the `edition2024`
  cargo feature (stabilised in cargo 1.85) while declaring no rust-version, so the
  build fails at manifest-parse time on cargo 1.83. There is no 1.83-compatible
  closure for yara-x 0.14.
- Feature trimming does not help. The `default-features = false` variant hits the
  same `ignore 0.4.29` blocker, because `ignore` is pulled by yara-x's core
  module/rule loading, not by an optional feature.
- yara-x latest (1.19.0) is a harder no. It self-declares rust-version 1.91, eight
  minor releases above tirith's MSRV, and drags in the cranelift and wasmtime
  code-generation stack (versions 0.130.2 and 43.0.2, all declaring 1.91). It is
  not a candidate on 1.83 under any resolver.

Conclusion: no version of yara-x builds on MSRV 1.83 today, and the gap is
widening, not closing, as yara-x's own MSRV climbs.

## Integration sketch, if the MSRV gate clears

Three candidate inputs are often grouped with "native YARA", but they decouple.
Only signature-base actually needs the yara-x engine; TLSH and capa do not.

### signature-base (YARA rules) - blocked with yara-x

- What: a large corpus of YARA detection rules
  (`github.com/Neo23x0/signature-base`).
- License: Detection Rule License (DRL) 1.1 as of 2021-08-13, with individual
  rules able to declare a different license in their metadata (repo README,
  checked 2026-07-16). DRL 1.1 requires attribution. This is a `reference-only`
  or attribution-required `feed`-class input, never vendored without attribution
  and a license review.
- Where it would plug: a YARA scan pass would run in the artifact inspection
  pipeline alongside native triage, for example a new step in
  `crates/tirith-core/src/artifact/inspect.rs`, feeding findings into the same
  `Verdict` the native pass uses. It requires a YARA engine, which means yara-x,
  which is blocked. So signature-base is gated on the yara-x MSRV problem above
  and, separately, on a DRL-1.1 license review.

### TLSH fuzzy hashing (fast-tlsh) - not blocked by yara-x

- What: TLSH locality-sensitive hashing, so near-duplicate malicious artifacts
  cluster even when their exact SHA-256 differs.
- Crate: `fast-tlsh`, "Library to generate / parse / compare TLSH locality
  sensitive hashes", license `Apache-2.0 OR MIT`, pure Rust, latest 0.1.10, which
  declares rust-version 1.70 (crates.io and `index.crates.io/fa/st/fast-tlsh`,
  2026-07-16). Its self MSRV (1.70) is well under 1.83; its full transitive
  closure on 1.83 still needs the standard check before adoption.
- Where it would plug: adjacent to the existing exact-hash lookup.
  `crates/tirith-core/src/artifact/correlate.rs:292` `artifact_hash_indicator`
  already decodes an inspection's SHA-256 and queries the v2 hash indices via
  `ThreatDb::check_artifact_sha256` (`correlate.rs:304`) and `check_file_sha256`
  (`correlate.rs:327`). A TLSH digest would sit beside that exact digest: compute
  the fuzzy hash of the same buffer, and on a cold exact-hash miss, compare
  against a set of known-malicious TLSH digests within a distance threshold. This
  is independent of yara-x and could be evaluated on its own merits.

### capa-rules (capability definitions) - not blocked by yara-x, not YARA

- What: capa's capability rules
  (`github.com/mandiant/capa-rules`), license Apache-2.0, checked 2026-07-16.
  These are capa's own YAML capability-definition format (a mixture of OpenIOC,
  YARA-like, and YAML constructs), not standard YARA rules and not consumed by a
  YARA engine.
- Where they would inform tirith: the existing native import-execution-chain and
  behaviour tagging, not a new engine. tirith already correlates native-module
  behaviour into `RuleId::NativeImportExecutionChain` (Critical) in
  `crates/tirith-core/src/artifact/native.rs`: `triage_native` (`native.rs:310`)
  builds the correlated finding, which fires only on the full conjunction of an
  execution entry, a danger capability, a spawn-or-loader import, and corroboration
  (predicates at `native.rs:222`, `:245`, `:256`, `:275`; conjunction documented at
  `native.rs:1095`). The capability tokens tirith recognises live in
  `crates/tirith-core/src/artifact/pth.rs:317` `capability_haystacks` (subprocess
  and network capability token sets at `pth.rs:257` and `:271`). capa's
  capability definitions are a curated, Apache-licensed taxonomy that could inform
  and expand those token sets and the conjunction, as an `oracle` or
  `reference-only` input (study the definitions, write tirith's own tags), with no
  yara-x dependency and no YARA rules involved.

## Recommendation

No-go for native YARA on MSRV 1.83. No `native-yara` feature, no `yara-x`
dependency, no YARA scanner. The engine simply does not build on 1.83 under any
current version or feature set, and yara-x's own MSRV is moving away from 1.83.

Gating conditions for revisiting native YARA (any one unblocks the engine, then
signature-base still needs its license review):

1. Workspace MSRV rises to 1.85, which would clear yara-x 0.15's self MSRV
   (closure permitting a fresh check), or
2. Workspace MSRV rises to 1.91, which the current 1.x line (through 1.19.0)
   requires, or
3. A yara-x line ships with a genuinely 1.83-compatible closure (including a
   transitive `ignore` that does not require `edition2024`). None exists today.

Two decoupled sub-tracks are NOT blocked by the yara-x gate and can be assessed
independently, each on its own spike:

- TLSH fuzzy hashing via `fast-tlsh` (permissive, self MSRV 1.70), plugging in
  beside the exact-hash lookup at `artifact/correlate.rs:292`. Precondition: a
  1.83 closure check on `fast-tlsh` and its dependencies.
- capa capability definitions (Apache-2.0) informing the existing behaviour tagging
  at `artifact/native.rs:310` and `artifact/pth.rs:317`, as ideas not vendored
  rules. No new runtime dependency required.

Neither sub-track ships in this PR; both are recorded here so a future decision does
not re-conflate them with the blocked YARA engine.
