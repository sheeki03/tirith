# Spike 5a: offline RustSec advisory audit

Status: research spike, go/no-go decision record. No shipped feature, no new
runtime dependency. The reproducible probe used to produce the corpus numbers
below lives in `tools/rustsec-probe/` (a standalone crate, detached from the
tirith workspace by an empty `[workspace]` table, so it never enters the product
build).

Question under test: should tirith consult a local snapshot of the RustSec
advisory database so that `Cargo.lock` scans report known-vulnerable crates when
the machine is offline or the OSV cache is cold?

All external facts were checked on 2026-07-16. All claims about tirith's current
behaviour cite the file and line I read on branch `security/spikes` (based on the
PR3 tip, commit bb95bd40).

## Evidence base

| Input | Value |
|-------|-------|
| advisory-db checkout | `github.com/rustsec/advisory-db` commit `9f3e138091487e69144f536d36976e427a7a3307`, committed 2026-07-13 (shallow clone, 2026-07-16) |
| Rust toolchain | `rustc 1.83.0 (90b35a623 2024-11-26)`, `cargo 1.83.0 (5ffbef321 2024-10-29)` |
| toml crate | `=0.8.23`, the exact version the workspace `Cargo.lock` resolves (root `Cargo.lock`: `toml` 0.8.23; declared as `toml = "0.8"` at `crates/tirith-core/Cargo.toml:66`) |
| probe | `tools/rustsec-probe/`, run as `cargo +1.83 run --release -- <advisory-db>` |

## Q1. Does the corpus parse with the in-tree toml 0.8 on Rust 1.83?

Yes, completely. The probe walks every `.md` file, extracts the leading
fenced front matter (RustSec's advisory format is a TOML code block, tagged
`toml`, at the top of a Markdown file, confirmed against `EXAMPLE_ADVISORY.md` and
every advisory in the checkout), and parses it into a typed serde model with
`toml 0.8.23`.

Probe output on the checkout above:

```text
markdown files walked      : 1167
advisories (toml fence)    : 1161
parsed OK                  : 1161
parse errors               : 0
distinct affected packages : 878
```

1161 of 1161 advisories parse with zero errors. The 6 non-advisory Markdown files
(`README.md`, `EXAMPLE_ADVISORY.md`, `CONTRIBUTING.md`, and similar) have no
leading TOML fence and are skipped, not errors.

One build note that matters for any future feature. A fresh `cargo +1.83`
resolution of even this tiny `toml + serde` closure fails, because cargo 1.83's
default resolver greedily selects the newest semver-compatible transitive deps
and pulls `indexmap 2.14.0`, which now requires the `edition2024` cargo feature
(stabilised in cargo 1.85). The workspace avoids this only because its committed
`Cargo.lock` pins `indexmap 2.13.0`. The probe's committed `Cargo.lock` was
generated with the MSRV-aware resolver (`CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback`)
so it pins `indexmap 2.13.1` and builds cleanly on 1.83. Lesson: any offline
RustSec feature must lock its transitive deps to 1.83-compatible versions and
keep the lockfile committed, exactly as the workspace already does.

## Q2. License and attribution

Source: `advisory-db/LICENSE.txt` and `advisory-db/LICENSES/` in the checkout
above.

- The database's own data is dedicated to the public domain under
  Creative Commons Zero 1.0 (CC0-1.0). `LICENSE.txt`: "All code and data in the
  RustSec advisory database repository are dedicated to the public domain ...
  available under Creative Commons Zero 1.0 Universal license".
- Exception: content adapted from the GitHub Security Advisory (GHSA) database is
  under Creative Commons Attribution 4.0 International (CC-BY-4.0), which requires
  attribution. `LICENSE.txt`: "Additional content is adapted from GitHub Security
  Advisory, and is available under Creative Commons Attribution 4.0 International".
- The two license texts ship in the repo at `LICENSES/CC0-1.0.txt` and
  `LICENSES/CC-BY-4.0.txt`.

The CC-BY-4.0 entries are self-identifying: they set `license = "CC-BY-4.0"` in
the advisory front matter. The probe counted them:

```text
license CC-BY-4.0 (GHSA)   : 20
license CC0/other explicit : 57
license unset (CC0 default): 1084
```

Attribution handling if this ships: vendor both `LICENSES/*.txt` files and a
NOTICE crediting "RustSec Advisory Database (CC0-1.0)" and, for the CC-BY-4.0
subset, "GitHub Security Advisory database (CC-BY-4.0)". Because the CC-BY subset
is small and flagged per record, the safest and simplest policy is to attribute
the whole snapshot to both sources in one NOTICE rather than track attribution
per advisory. This is a `fixture`/`feed` class input under the CLAUDE.md
third-party gate: permissive, redistributable, attribution recorded.

## Q3. Route (a) direct TOML parse vs route (b) the rustsec crate

Current `rustsec` crate versions and their declared MSRV, from the crates.io
sparse index (`index.crates.io/ru/st/rustsec`, 2026-07-16):

| rustsec version | declared rust-version | 1.83 compatible by declaration |
|-----------------|-----------------------|-------------------------------|
| 0.30.1 | 1.73 | yes |
| 0.30.2 | 1.81 | yes |
| 0.30.4 | 1.85 | no |
| 0.31.0 | 1.85 | no |
| 0.32.0 | 1.85 | no |
| 0.33.0 (latest) | 1.88 | no |

The plan's numbers hold: the latest `rustsec` (0.33.0) declares 1.88, and 0.30.2
is the last release declaring an MSRV at or below 1.83 (1.81). Note there is no
0.30.3; 0.30.2 jumps straight to 0.30.4 (which moved to 1.85).

But the declared MSRV is not the closure MSRV. I tested route (b) empirically:
a throwaway crate depending on `rustsec = "=0.30.2"`, lockfile generated with the
MSRV-aware resolver targeting rust-version 1.83, then `cargo +1.83 build`. The
resolver downgraded a large set of deps to 1.83-compatible versions, but the
build still fails:

```text
error: failed to parse manifest at `.../clru-0.6.3/Cargo.toml`
Caused by:
  feature `edition2024` is required
```

`clru 0.6.3` (pulled transitively through the `rustsec` crate's `gix`/git
machinery) requires the `edition2024` cargo feature and declares no rust-version,
so the MSRV-aware resolver cannot downgrade it and it fails to even parse under
cargo 1.83. Route (b) does not build on MSRV 1.83 today.

Route (a), a direct TOML parse with the in-tree `toml 0.8.23`, builds and parses
100% of the corpus on 1.83 (Q1). It also avoids the `rustsec` crate's heavy
`gix`/network closure entirely, which tirith does not need: tirith already fetches
its data through the threat-DB CI pipeline, not at runtime.

Decision on Q3: route (a), direct TOML. Route (b) is disqualified on MSRV alone,
and would add a large dependency surface for functionality (git fetch, semver
matching) tirith can do itself.

## Q4. Value metric: what does `--offline` currently lose?

The right metric is not "new advisory ids versus OSV". RustSec already flows into
OSV.dev, and tirith already queries OSV live, so when online there is nothing new
to gain. The value is entirely in the offline and cold-cache case.

tirith's OSV integration is network-only, on all three surfaces that use it:

- Runtime command enrichment (`tirith check` and the shell hook path):
  `crates/tirith-core/src/threatdb_api.rs:38` `enrich_command` gates on
  `config.osv_enabled` (`threatdb_api.rs:44` and `:70`) and calls `query_osv`
  (`threatdb_api.rs:286`), which checks a 1-hour cache (`threatdb_api.rs:293`) and
  otherwise POSTs to `https://api.osv.dev/v1/query` (`threatdb_api.rs:308`). With
  the cache cold and no network, the query returns `None` and no
  `RuleId::ThreatOsvVulnerable` (High, built at `threatdb_api.rs:579`) or
  `RuleId::ThreatCisaKev` (`threatdb_api.rs:605`) finding is produced.
- Single-package assessment (`tirith package`):
  `crates/tirith-core/src/osv_correlation.rs:67` `for_package_with_state` shares
  the same cache and live query; on a cold cache with no network it returns
  `OsvLookupState::Unavailable` (`osv_correlation.rs:85`). Called from
  `crates/tirith/src/cli/package.rs:594`.
- Ecosystem scan (`tirith ecosystem scan`): registry-API correlation runs only
  under `--online` and only when not forced offline
  (`crates/tirith/src/cli/ecosystem.rs:108`:
  `use_online = online && !offline && !super::offline_env_active()`), and the
  offline mode resolves to no API signals
  (`crates/tirith-core/src/ecosystem_scan.rs:3428`:
  `OnlineMode::Off => ApiSignals::offline()`). Those API signals are registry
  provenance (deps.dev style), not vulnerability advisories, so `ecosystem scan`
  produces no advisory findings at all, online or offline.

The offline threat DB that ships with tirith carries reputation and typosquat
IoCs, not CVE or advisory data, so it does not fill this gap.

Quantified loss for the crates.io ecosystem: offline, tirith produces advisory
findings on zero crates. The advisory-db snapshot covers 878 distinct crates
across 1141 RUSTSEC advisories (Q1 and Q6). An offline RustSec store would let a
`Cargo.lock` scan report the subset of those whose resolved version is affected,
with no network and no OSV cache. This is net-new capability for
`tirith ecosystem scan` on crates (which has no advisory path at all today) and a
recovery of the OSV advisory signal for the offline runtime and package paths,
scoped to crates.

## Q5. Dedup design and the concrete hook point

An offline RustSec lookup must never double-report a vulnerability that the live
OSV path also reports (for example an online scan with a warm cache).

Canonical key. Every OSV vuln for a Rust crate carries the RUSTSEC id as its
`id` and the CVE and GHSA ids as `aliases`
(`crates/tirith-core/src/osv_correlation.rs:160-170`: `OsvVuln { id, aliases, .. }`;
`threatdb_api.rs` builds its finding from `advisory.id` at `:566` and reads
`aliases` at `:504`). The advisory-db TOML carries the same identifiers: `id`
(RUSTSEC-*) plus optional `aliases` (CVE-*, GHSA-*), confirmed by the probe
(783 advisories carry at least one alias; 583 CVE and 904 GHSA alias occurrences).
So the dedup key is the normalized advisory-id set: the RUSTSEC id when present,
otherwise the sorted alias set. Merging the offline and live findings on this key
collapses the two representations of one vulnerability into one finding.

Hook point. The existing `Cargo.lock` parse is
`crates/tirith-core/src/ecosystem_scan.rs:3379` `parse_cargo_lock`, which emits one
`DeclaredDependency { ecosystem: Ecosystem::Crates, version: <resolved> }` per
`[[package]]` (installed-mode read at `ecosystem_scan.rs:2101-2117`). Each declared
dependency is scored in `assess_dependency`
(`crates/tirith-core/src/ecosystem_scan.rs:3414`), called from the per-dependency
loop at `ecosystem_scan.rs:1868`. That is the attach point: for a
`Ecosystem::Crates` dependency with a concrete version, consult the offline store
and, on a match, emit an advisory finding folded into the same `Verdict`. It runs
regardless of `OnlineMode` because the store is local, exactly like the threat DB
consultation already is. The dedup merge on the canonical key is applied where the
offline finding and any live OSV finding meet (the runtime path already dedups
within OSV on `osv:{eco}:{name}:{version}` at `threatdb_api.rs:76`; the merged path
would key on the advisory-id set instead).

## Q6. Corpus summary from the probe run

advisory-db commit `9f3e138091487e69144f536d36976e427a7a3307`, dated 2026-07-13.
Probe run on `rustc 1.83.0` with `toml 0.8.23`.

| Metric | Count |
|--------|-------|
| Markdown files walked | 1167 |
| Advisories (leading toml fence) | 1161 |
| Parsed OK | 1161 |
| Parse errors | 0 |
| Distinct affected packages | 878 |
| id = RUSTSEC-* | 1141 |
| id = CVE-* (the `rust/` toolchain and std advisories) | 20 |
| Withdrawn (`withdrawn` field set) | 13 |
| Informational (`informational` field set) | 452 |
| Advisories with at least one alias | 783 |
| Alias occurrences `CVE-*` / `GHSA-*` / other | 583 / 904 / 6 |
| With `patched` ranges | 704 |
| With `unaffected` ranges | 223 |
| With neither (informational-style) | 432 |

Withdrawn advisories. A withdrawn advisory sets `withdrawn = "YYYY-MM-DD"` in its
`[advisory]` table (schema in `EXAMPLE_ADVISORY.md`). The store must exclude any
record where that field is present, so a retracted advisory never fires. 13 in the
current corpus.

Version-range semantics. `patched` and `unaffected` are arrays of comma-separated
semver comparator sets (for example `[">= 1.2.3, < 1.3.0", ">= 1.3.4"]`). A version
is affected when it satisfies none of the `patched` ranges and none of the
`unaffected` ranges. The probe classified the leading comparator of every range
token in the corpus:

```text
version-range operators seen:
  <     : 366
  <=    : 19
  =     : 7
  >     : 25
  >=    : 874
  ^     : 38
  bare  : 29
unrecognized range tokens  : 0
```

Every token uses a standard semver comparator (`>=`, `<`, `<=`, `>`, `=`, `^`, or a
bare version). Zero unrecognized expressions. So a standard semver `VersionReq`
matcher covers the entire corpus, and there are no exotic version expressions to
special-case. One caveat for whoever builds the matcher: a bare version (the 29
`bare` tokens above) is not an exact match. In Cargo / semver `VersionReq` grammar
`1.2.3` means `^1.2.3` (caret), so those tokens must be matched as caret ranges,
not pinned versions, or a later compatible patched release would be misreported as
still vulnerable. Counted by effective semantics rather than raw token shape, the
29 `bare` and 38 `^` tokens are all caret ranges (67 total). This matters because
tirith already depends on nothing for semver matching today; a small hand-rolled
comparator or a single permissive semver crate (subject to its own 1.83 closure
check) would suffice.

MSRV proof on 1.83: the probe compiles and runs under `cargo +1.83` (build time
about 40 seconds, release profile) and is `cargo +1.83 fmt` and
`cargo +1.83 clippy --all-targets -- -D warnings` clean. The committed
`tools/rustsec-probe/Cargo.lock` pins the closure to 1.83-compatible versions.

## Q7. Recommendation

Go, deferred to its own feature PR, implemented as a sister offline store consulted
by ecosystem scan. Not a new IoC `ThreatSource`: advisories are version-scoped
vulnerability records, not host or hash IoCs, and they do not fit the
`ThreatSource` hostname/IP routing model
(`crates/tirith-core/src/rules/threatintel.rs:627` and `:658`).

Why go: the parse is proven (1161/1161 on 1.83 with the in-tree toml), the license
is clean and redistributable with attribution, the value is real and precisely
scoped (offline advisory findings for crates, which today are zero), the version
grammar is fully standard, and the dedup key and hook point are identified.

Gating conditions for the feature PR (all required before it ships):

1. Data delivery through the existing threat-DB CI pipeline, not a runtime fetch.
   The snapshot is compiled into the signed DB (or a sibling signed artifact) with
   its commit SHA and date recorded, so clients never hit the network for it and
   the freshness is auditable.
2. Withdrawn advisories excluded at compile time (drop any record with a
   `withdrawn` field).
3. Attribution vendored: both `LICENSES/*.txt` and a NOTICE crediting RustSec
   (CC0-1.0) and GitHub Security Advisory (CC-BY-4.0).
4. Dedup on the canonical advisory-id set so the offline path never double-reports
   with the live OSV path.
5. A semver matcher chosen and closure-checked on 1.83 (or hand-rolled), given the
   corpus uses only standard comparators.
6. Scope v1 to `Ecosystem::Crates` with a concrete resolved version (the
   `Cargo.lock` path). Manifest-range matching and other ecosystems are follow-ups.

Alternative considered and rejected for v1: shipping an OSV snapshot instead of a
RustSec snapshot. OSV is broader but far larger and would duplicate the live OSV
path's schema; the crates-scoped RustSec corpus is small (about 1.2k records),
self-contained, and exactly matches the one ecosystem where tirith has an offline
advisory gap. Revisit an OSV snapshot only if offline advisory coverage is wanted
for npm/PyPI/other ecosystems.
