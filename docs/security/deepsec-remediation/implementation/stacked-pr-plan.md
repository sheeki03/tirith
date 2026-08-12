# Three-PR stacked implementation plan

## Decision

The remediation program uses exactly three implementation PRs. The current
roadmap PR is documentation-only and is stacked on PR #174. After it, the fix
stack is:

```text
PR #174 (`security/spikes`)
  -> roadmap PR (`codex/deepsec-remediation-plan`)
      -> R1 critical boundaries (`codex/deepsec-r1-critical-boundaries`)
          -> R2 remaining security hardening (`codex/deepsec-r2-security-hardening`)
              -> R3 reliability and convergence (`codex/deepsec-r3-reliability-convergence`)
```

No additional remediation PRs are planned. The earlier subsystem packages are
retained only as internal commit groups, test filters, and ledger workstreams
inside R1-R3.

## Execution update — 2026-08-12

The three entries above remain the logical ownership and accounting tracks.
For reviewability, the live implementation was divided into eight ordered merge
units without changing which track owns a root:

```text
R1: #183 -> #184 -> #185 -> #186 -> #179
R2: #187 -> #180
R3: #181
```

The documentation/parent chain is `#173 -> #174 -> #177` before those units.
Each merge unit inherits the validation and closure contract of its logical
track. A green later unit does not waive a failed earlier unit, and every child
must be re-authenticated after its parent merges. Current receipts and blockers
are maintained in [`../MERGE-CHECKPOINT.md`](../MERGE-CHECKPOINT.md); exact
continuation steps are in [`../HANDOVER.md`](../HANDOVER.md).

This is intentionally a large-PR strategy. To keep it auditable, every PR has an
ordered commit series, commit-level validation checkpoints, a machine-readable
root ledger, and a final exact-head revalidation. A root is not closed merely
because its internal workstream commit landed.

## Source and scope

The plan is anchored to product revision
`e1ec47ef9f43e32872a550522067a680ff659e6e` and the evidence hashes in
[`../context.md`](../context.md). The source report declares 482 actionable
roots. Review promotes `repo-0476` to an independent P3 root, producing 483
reviewed implementation obligations.

Reviewed priority totals are:

| Priority | Roots |
| --- | ---: |
| P0 | 15 |
| P1 | 164 |
| P2 | 205 |
| P3 | 99 |
| Total | 483 |

The exact R1/R2/R3 ownership for every row is in
[`../remediation-map.json`](../remediation-map.json). Holds, accepted design,
false-positive, already-fixed, and duplicate receipts are not assigned a product
fix obligation, but duplicate rows inherit the PR that owns their canonical
root so their regression coverage is not lost.

| Implementation PR | Actionable roots | Duplicate coverage rows |
| --- | ---: | ---: |
| R1 | 209 | 41 |
| R2 | 186 | 14 |
| R3 | 88 | 5 |
| **Total** | **483** | **60** |

## Shared rules for all three PRs

- Refresh the live parent SHA before coding and after every parent update.
- Keep the PR draft until every internal batch and its checkpoint passes.
- Do not rewrite already-reviewed internal commits except when rebasing the
  entire child after its parent merges.
- Use one contiguous commit group per `ownerPackage` and prefix commit subjects
  with its code, for example `r1-fnd:` or `r2-net:`.
- Each root keeps a focused regression. Shared controls do not collapse distinct
  sink obligations.
- Before a package starts, derive the private umbrella-duplicate checklist for
  its duplicate rows from the hashed evidence snapshot. The public map carries
  only the primary canonical root; private exact-SHA closure evidence must cover
  every additional sink described by the receipt.
- Additive migrations use dual-read/single-write and an explicit compatibility
  window. Never reinterpret incomplete or corrupt state as clean.
- The private `.deepsec/` report, receipts, payloads, and PoCs stay out of Git and
  CI logs. Public tests use inert sentinels and local fake services.
- A failed earlier security gate blocks the PR regardless of later green style
  or integration checks.

## Internal package catalog

The ledger's `ownerPackage` is one of the 15 commit-batch codes below, never
just the enclosing PR. The machine-readable definitions, dependencies, and
arithmetic are in [`../package-catalog.json`](../package-catalog.json).
Packages are review checkpoints inside R1-R3; they are not additional branches
or PRs.

| Code | Internal scope | Actions | Duplicates | Depends on |
| --- | --- | ---: | ---: | --- |
| R1-FND | Prerequisite control spine | 60 | 16 | — |
| R1-ART | Critical artifact and supply boundaries | 31 | 8 | R1-FND |
| R1-CMD | Critical command and policy boundaries | 71 | 9 | R1-FND |
| R1-OUT | Critical output, secret, and egress boundaries | 19 | 3 | R1-FND |
| R1-PLT | Critical platform, state, and containment | 28 | 5 | R1-FND, R1-OUT |
| R2-CMP | Completeness and resource hardening | 47 | 1 | R1-FND |
| R2-CMD | Command, rule, and policy hardening | 31 | 4 | R1-CMD, R2-CMP |
| R2-IO | Filesystem and state hardening | 31 | 1 | R1-PLT, R2-CMP |
| R2-NET | Network, MCP, and output hardening | 37 | 5 | R1-OUT, R1-PLT, R2-CMP |
| R2-SUP | Supply and release hardening | 40 | 3 | R1-ART, R2-CMP, R2-NET |
| R3-CORE | Core contract reliability | 26 | 3 | All R2 packages |
| R3-PLT | Cross-platform launcher reliability | 12 | 2 | R1-PLT, R2-IO, R3-CORE |
| R3-CLI | CLI output and portability | 45 | 0 | R1-OUT, R2-IO, R3-CORE |
| R3-CI | Hermetic CI, fuzz, and benchmark enforcement | 3 | 0 | R2-SUP, R3-PLT, R3-CLI |
| R3-INT | Schema integration and exact-head revalidation | 2 | 0 | R3-CI |

Every package ends in a commit-level checkpoint. A package may use several
commits while under review, but it is squashed or kept as one contiguous commit
series before the enclosing PR leaves draft. Cross-package changes must name
both package codes and pass both checkpoints.

## R1 — Critical boundaries and P0/P1 closure

- Branch: `codex/deepsec-r1-critical-boundaries`
- Base: `codex/deepsec-remediation-plan`
- Scope: 209 actionable roots and 41 duplicate coverage rows.
- Owns: every reviewed P0 and P1 root, plus any lower-priority prerequisite that
  must be complete before those roots can be honestly closed.
- Merge condition: all R1-owned roots verified at one exact head SHA.

R1 creates the shared security boundaries and immediately migrates all critical
and high-severity consumers. Lower-priority prerequisite roots move into R1 when
they define test isolation, completeness, version ordering, safe I/O, process
supervision, parser identity, display/secret types, egress, or per-dimension
containment needed by a P0/P1 fix. They are not left open behind a supposedly
closed high-severity consumer.

### R1 internal packages

#### R1-FND — Prerequisite control spine

First build one test-owned HOME/XDG/AppData environment, remove ambient
credentials and endpoints, and add an owned-child deadline helper that kills and
reaps complete process trees. Then land these foundations in order:

1. typed completeness and per-dimension resource outcomes, extending existing
   `CoverageGap`;
2. trusted absolute executables, minimal environments, and bounded child
   supervision;
3. Unix and Windows root-contained, no-follow transactional I/O;
4. canonical raw-plus-structured command/argv identity with explicit parse
   completeness;
5. raw, secret, redacted, and format-safe values plus streaming terminal state;
6. connect-time DNS/redirect/proxy/metadata guarded HTTP;
7. stable-lock, validate-before-publish state transactions.

This package owns 60 action roots and 16 duplicate rows, including the explicit
30 P2/P3 prerequisites. Its checkpoint requires real user state to remain
byte-identical, no ambient endpoint access, no orphaned children, a reference
consumer for every foundation, failure-injection coverage, MSRV/platform
checks, and no adapter that converts incomplete/unavailable into clean.

#### R1-ART — Critical artifact and supply boundaries

Migrate the 31 action roots and 8 duplicate rows covering archive identity,
Windows collision rules, wheel/native completeness, startup templates, resolver
trust, PEP 508 and ecosystem version identity, exact-byte downloaded-script
execution, install provenance, ThreatDB publication, and release provenance.
Close each assigned P0/P1 at its real source-to-sink path.

Checkpoint: private reproducer and legitimate control, alternate archive/path/
version/redirect cases, signed publication round-trip, and a release dry run.

#### R1-CMD — Critical command and policy boundaries

Migrate 71 action roots and 9 duplicate rows across effective policy,
fail-closed resolution, validator/runtime parity, approval and trust matching,
command/wrapper parsing, PowerShell, SSH, sudo, containers, CI/config, prompt,
PDF, clipboard, threat intelligence, and gateway request authorization.

Checkpoint: parser/executor differential and property suites, option/wrapper
negative controls, policy compatibility fixtures, tier-one parity, and no root
left at `control_ready` without its exact consumer migration.

#### R1-OUT — Critical output, secret, and egress boundaries

Migrate 19 action roots and 3 duplicate rows covering terminal/Markdown/HTML/
CSV/JSON boundaries, persistent credential/audit/webhook/receipt secrets, MCP
output transforms, guarded egress, redirect/proxy/DNS binding, and public-safe
projections.

Checkpoint: streaming split/cap tests, secret-absence assertions, structured
collision/reanalysis tests, fake DNS/HTTP/proxy fixtures, and valid-output
controls through every migrated sink.

#### R1-PLT — Critical platform, state, and containment

After R1-FND and R1-OUT, migrate 28 action roots and 5 duplicate rows across
Linux/macOS/Windows containment, deny roots, descriptors, ioctl/DACL/temp-home/
cwd/environment behavior, checkpoint and setup writers, policy/trust stores,
transactional state, installers, and high-severity workflow/service boundaries.

Checkpoint: native negative capability probes, I/O race and crash injection,
Windows reparse/DACL tests, state-generation recovery, platform CI, and exact
launcher observation of cwd/environment/argv.

R1 may leave draft only when all five package checkpoints pass, every R1-owned
root is verified at one head SHA, targeted revalidation is bound to that SHA,
and a synthetic merge with current `main` passes the same gates.

### R1 compatibility and rollback

R1 is large, so compatibility changes are additive inside the same PR. Policy,
lockfile, coverage, receipt, state, and ThreatDB changes keep legacy readers and
new writers separated by explicit version gates. Roll back consumer commits in
reverse order before reverting a foundation. A migrated network or process
consumer may become unavailable during rollback; it never falls back to an
unguarded client or inherited-PATH execution.

## R2 — Remaining P2 security hardening

- Branch: `codex/deepsec-r2-security-hardening`
- Base: R1
- Scope: 186 actionable roots and 14 duplicate coverage rows.
- Owns: every reviewed P2 root not pulled into R1 as a prerequisite.
- Merge condition: all R2-owned roots verified at one exact head SHA and R1
  remains green after the complete diff.

R2 finishes medium-severity security work using the already-landed R1
foundations. It must not add parallel parsers, HTTP clients, sanitizers, atomic
writers, coverage models, or state protocols.

### R2 internal packages

#### R2-CMP — Analysis completeness and bounded work

Migrate remaining scan, ecosystem, artifact, provenance, IaC, AI, MCP, output,
DNS, manifest, deobfuscation, archive, parser, and enrichment consumers to typed
gaps and shared byte/count/depth/time budgets.

Acceptance:

- every requested subject becomes data or an explicit gap;
- `require_complete` and exit behavior match across CLI, MCP, AI, JSON, and
  SARIF;
- adversarial inputs remain within deterministic memory/work ceilings.

#### R2-CMD — Policy, identity, and detection hardening

Complete package/registry identity, URL/host/path canonicalization, context
precedence/cache invalidation, custom rule logic, policy projection binding,
repository scope restrictions, hook/alias/config parsing, rule reachability, and
remaining detection bypasses.

Acceptance:

- validator and runtime consume the same parsed policy representation;
- registry-equivalent identities and non-equivalent controls are covered;
- parser/executor differential and property suites pass for every supported
  dialect and platform.

#### R2-NET — Network, MCP, output, and secret migrations

Finish guarded-client migration, body/cardinality/rate/concurrency bounds, MCP
envelope/blob/metadata coverage, terminal/Markdown/CSV/DOT renderers, public
receipt projections, redaction contracts, and structured post-transform
reanalysis.

Acceptance:

- no unguarded migrated client remains;
- no active terminal controls or persisted secret values appear in sink tests;
- transformed structured data rejects collisions and is revalidated before
  forwarding.

#### R2-IO — Filesystem, state, and platform hardening

Finish checkpoint integrity, audit/receipt/spool state, taint/session/pending and
registry history, setup/profile/devcontainer/hygiene writers, per-platform
containment, Windows ACLs/reparse points, and truthful status/coverage outputs.

Acceptance:

- deterministic multi-process and race tests pass;
- corrupt/stale/incomplete generations fail closed while preserving
  last-known-good state;
- each claimed containment dimension has a native negative capability probe.

#### R2-SUP — Supply chain, workflows, and services

Finish ThreatDB feed/schema/range/provenance/resource work, updater/status
identity, release and container reproducibility, workflow permissions, benchmark
enforcement, and license-service security controls whose deployment evidence is
available.

Acceptance:

- mandatory feed failure prevents signing/publishing;
- signed sequence and encoded lengths are monotonic and checked;
- release asset set equals checksum/signature/provenance set;
- unresolved `repo-0446` remains an explicit hold rather than an assumed code
  fix.

### R2 final gate

- every R2 root is revalidated at the R2 head SHA;
- R1 and R2 ledger states agree with the diff;
- current-main synthetic merge and all R1/R2 gates pass;
- machine schemas and compatibility windows are documented;
- no new private evidence is tracked or logged.

Rollback R2 by internal group in reverse order. Shared R1 foundations remain;
do not reintroduce local unguarded alternatives.

## R3 — P3 reliability, contracts, and final convergence

- Branch: `codex/deepsec-r3-reliability-convergence`
- Base: R2
- Scope: 88 actionable roots and 5 duplicate coverage rows.
- Owns: every remaining reviewed P3 root plus final integration assurance.
- Merge condition: the entire 549-row ledger reaches a terminal, evidenced state
  at one convergence SHA.

R3 is not a cosmetic cleanup. The P3 queue contains test isolation, process
cleanup, signed-state integrity, portability, race, output-contract, and
operational defects that can invalidate confidence in higher-severity fixes.

### R3 internal packages

#### R3-CORE — Transactional and bounded operational state

Finish audit/report queries, checkpoint inventories, registry/taint/session
JSONL, quarantine GC, canary mutation confirmation, webhook payloads, ThreatDB
status/health, dashboard/export reliability, and remaining durable state
contracts.

#### R3-PLT — Cross-platform process, shell, and setup reliability

Complete signal/process-tree handling, cwd/argv/environment propagation,
PowerShell/cmd setup, shell-profile concurrency, capability cache identity,
runtime alias honesty, self-update ownership, and Windows parity.

`repo-0475` and promoted root `repo-0476` both remain distinct tests inside the
same Windows launcher package: cwd and environment overlays must each be carried
through the pure plan and observed by the contained child.

#### R3-CLI — CLI and machine-output contracts

Unify one-document versioned JSON envelopes, stdout ownership, checked
serialization/write/flush, exit-code parity, interactive approval, remediation
commands, intent/shell selection, and human/machine status consistency.

#### R3-CI — CI, fuzz, benchmarks, and documentation

Make benchmark execution failures authoritative, add missing artifact/parser
fuzz targets to required matrices, retain hermetic test isolation, verify all
machine schemas, update compatibility/release documentation, and ensure the
public ledger contains no evidence detail.

#### R3-INT — Full convergence

At one exact R3 head SHA:

1. Validate all 549 rows: 483 reviewed roots closed, 60 duplicates tied to their
   verified canonical/umbrella evidence, 3 holds explicitly resolved or still
   approved as holds, 2 no-fix decisions preserved, and 1 already-fixed row
   regression-locked.
2. Run focused, package, isolated workspace, MSRV, clippy, format, dependency,
   signing, license-server, and all-platform suites.
3. Run parser differential/property/fuzz, I/O race/failure, fake network,
   output invariant, containment capability, release dry-run, and performance
   threshold suites.
4. Build and test a synthetic merge with the then-current `main`.
5. Run targeted revalidation for every R3 root and a fresh complete full scan for
   the combined R1-R3 state.
6. Bind the scan and ledger to the convergence SHA and confirm zero unassigned
   regressions.

Only this checkpoint permits a claim that the adjudicated queue is remediated.

## Per-root closure contract

Every root, in whichever PR owns it, must pass these gates in order:

1. Reproduce the current defect or encode it through the real boundary.
2. Record the violated invariant and legitimate behavior to preserve.
3. Implement the narrowest complete repository-native fix.
4. Rerun the original condition and prove it no longer reproduces.
5. Rerun the legitimate control through the same interface.
6. Perform a change-aware bypass review with an alternate malicious input and
   sibling/direct-caller trace.
7. For inherited duplicate rows, satisfy the private, evidence-hash-bound
   umbrella checklist rather than assuming the primary root is sufficient.
8. Run focused, owning-package, platform, formatting, lint, MSRV, dependency,
   and integration gates.
9. Revalidate at the exact PR head SHA.

The public ledger progresses through:

```text
queued -> reproduced -> control_ready -> migrated -> verified -> closed
```

`control_ready` is never a closure state.

## Merge procedure

The review stack and the landing sequence are different. R1 may be opened on the
roadmap branch so its diff contains product work only, but product code must
never be merged into the documentation branch. Land and retarget in this order:

1. Land PR #174's complete predecessor chain bottom-up, ending with PR #174.
2. Rebase/retarget the documentation-only roadmap PR onto the resulting default
   branch head, rerun its checks, and merge it.
3. Rebase/retarget R1 onto the landed roadmap commit, verify that its diff is
   product code plus its own tests only, rerun the complete R1 gate, and merge.
4. Rebase/retarget and merge R2 onto landed R1, then R3 onto landed R2, rerunning
   each complete child gate after every SHA change.

If any parent is squash-merged, rebase the child onto the landed squash SHA:

```text
git rebase --onto <landed-parent-sha> <old-parent-tip> <child-branch>
git push --force-with-lease
```

Do not create another integration PR. Use only an ephemeral local/convergence
branch for current-main synthetic testing. Before each merge, GitHub's displayed
base must be the landed parent branch/default branch, never an unmerged roadmap
or implementation branch.

## Holds and non-fixes

- `repo-0037`: macOS supported-host runtime evidence required before code.
- `repo-0244`: policy owner must define approval precedence before code.
- `repo-0446`: deployed edge/WAF/load-shedding evidence required before code.
- `repo-0128`: accepted path-keyed taint identity for v1.
- `repo-0485`: current route unreachable; future activation must add a gap gate.
- `repo-0326`: already fixed; retain reachability regression.

These rows do not justify a fourth PR. If a hold is resolved while R1-R3 is open,
it joins the severity-appropriate existing PR. If resolved afterward, it requires
a new user-approved task because the explicit three-PR cap has been exhausted.
