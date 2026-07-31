# DeepSec remediation program

Status: implementation plan only. This document does not claim that any finding
has been fixed.

This program turns the adjudicated DeepSec inventory at
`e1ec47ef9f43e32872a550522067a680ff659e6e` into reviewable, dependency-aware
remediation stacks. The plan PR itself is stacked directly on PR #174
(`security/spikes`). Product-code remediation starts only after the evidence
ledger and validation harness are in place.

## Decision

We should fix the queue in exactly three stacked implementation PRs. Shared
foundations and subsystem groups remain internal commit batches, not additional
branches or PRs. A shared primitive may make many fixes possible, but an
individual root closes only when its exact sink has migrated, its regression
test passes, and exact-head revalidation shows that the original path no longer
reproduces.

The source report declares 482 actionable canonical roots. Source review found
one duplicate-classification error: `repo-0476` includes Windows environment
overlay loss that a cwd-only `repo-0475` patch cannot close. The reviewed queue
therefore contains 483 implementation obligations. This changes planning
accounting, not the immutable source report.

| Queue state | Source report | Reviewed plan |
| --- | ---: | ---: |
| Actionable roots | 482 | 483 |
| Duplicate rows | 61 | 60 |
| Evidence holds | 3 | 3 |
| Accepted design / false positive | 2 | 2 |
| Already fixed | 1 | 1 |
| Total adjudicated rows | 549 | 549 |

The source priority labels remain 15 P0, 164 P1, 204 P2, and 99 P3. Scheduling
is dependency-aware rather than a blind priority sort. In particular, hermetic
tests, completeness types, version ordering, safe I/O, and containment coverage
must sometimes land before the P0/P1 consumer that depends on them. The detailed
stack is in [the implementation plan](implementation/stacked-pr-plan.md).

## Source identity and disclosure boundary

The evidence inventory, hashes, drift check, and known adjudication caveats are
recorded in [context.md](context.md). The private `.deepsec/` report, receipts,
reproduction details, and attacker-controlled payloads are intentionally not in
this PR. The repository root ignores `/.deepsec/` to prevent accidental staging.

The committed machine ledger contains only stable IDs, coarse modules, package
ownership, status, and source/reviewed dispositions. Public regression tests
must use inert sentinels, fake executables, local fake DNS/HTTP servers, and
synthetic archives. Exact exploit evidence belongs in private revalidation
artifacts and must not be printed into CI logs.

## Architecture choice

The recommended design is incremental consolidation behind owned, typed
boundaries:

- typed completeness and per-dimension resource outcomes;
- trusted, bounded child-process execution;
- descriptor-relative contained and transactional filesystem I/O;
- one canonical command and argument representation;
- explicit raw, secret, and human-display-safe values;
- connect-time destination enforcement for HTTP, redirects, proxies, and DNS;
- transactional security state with evidence-backed coverage claims.

Local patches remain necessary while consumers migrate. A service rewrite or a
new privileged daemon is not justified by the current evidence and would add a
larger operational and compatibility surface. The design tradeoffs are expanded
in [hardening.md](hardening.md) and the linked proposals.

## Stack topology

The public plan PR is a child of PR #174. The implementation sequence is:

```text
PR #174
  -> plan and sanitized ledger
  -> R1: foundations plus all P0/P1 closure
  -> R2: remaining P2 security hardening
  -> R3: remaining P3 reliability plus convergence
```

The three PRs are intentionally large. Each uses ordered internal commit groups,
commit-level validation checkpoints, and ledger filters so reviewers can audit
one subsystem at a time without creating more PRs. R2 bases on R1 and R3 bases
on R2; every child reruns its complete gate after a parent SHA changes.

| Implementation PR | Actionable roots | Duplicate coverage rows |
| --- | ---: | ---: |
| R1 — critical boundaries | 209 | 41 |
| R2 — remaining security hardening | 186 | 14 |
| R3 — reliability and convergence | 88 | 5 |
| **Total** | **483** | **60** |

## Closure contract

A root progresses through these states:

```text
queued -> reproduced -> control_ready -> migrated -> verified -> closed
```

`control_ready` is not closure. Each root requires all of the following:

1. The current vulnerable or unreliable path is reproduced, or encoded in a
   regression test through the real boundary.
2. The security/reliability invariant and legitimate compatibility behavior are
   recorded before implementation.
3. The exact sink or call site is migrated to the shared control.
4. The malicious case no longer reproduces and a legitimate control still
   works through the same interface.
5. Change-aware bypass review covers an alternate input class and sibling sink.
6. Focused tests, owning-package tests, formatting, clippy, MSRV 1.83, platform
   CI, and applicable dependency checks pass.
7. Targeted DeepSec revalidation is tied to the exact commit SHA.

Every track tip must be tested in a synthetic merge with current `main`. Final
convergence additionally requires the complete sanitized-ledger verifier, an
isolated workspace suite, all supported operating systems, and a fresh full scan
at the exact convergence SHA.

## Holds and explicit non-fixes

The plan does not silently turn uncertainty into code:

- `repo-0037` stays on hold until a supported-host macOS runtime PoC proves the
  claimed service-mediated escape. If proved, use the smallest Mach-service
  allowlist that preserves supported behavior.
- `repo-0244` stays on hold until the policy owner defines approval-rule
  precedence: ordered first match or strictest applicable match.
- `repo-0446` stays on hold until deployed ingress, WAF, load shedding, and
  concurrency controls are inspected.
- `repo-0128` remains an accepted exact-path taint identity for v1. Rename- or
  content-stable taint is a separately designed enhancement.
- `repo-0485` remains suppressed because the reported prebuilt-artifact route is
  unreachable in the compile-time corpus surface.
- `repo-0326` remains closed with its existing tier-one reachability regression.

## Operating rules

- Keep only one of R1, R2, or R3 active for merge at a time; internal subsystem
  batches are commits and test checkpoints, not PRs.
- Merge each stack bottom-up. After a squash merge, rebase descendants with
  `rebase --onto` and rerun all gates because every SHA changed.
- Use additive schema changes, dual-read/single-write migrations, and explicit
  compatibility windows for policy, lockfile, receipt, coverage, and ThreatDB
  formats.
- Roll back leaf migrations before foundations. Never silently restore a
  fail-open path to make rollback easier.
- Do not mix OS sandbox backends, release YAML, parser semantics, and policy
  semantics in one internal commit group or review checkpoint. The three-PR cap
  necessarily places several such groups in one PR, but they remain separately
  reviewable and separately gated.
- Do not count the current green CI as sufficient: the default workspace suite
  is non-hermetic, benchmark enforcement is advisory, and fuzz coverage is not a
  required per-PR gate.

## Plan artifacts

- [Evidence context](context.md)
- [Hardening portfolio](hardening.md)
- [Stacked implementation plan](implementation/stacked-pr-plan.md)
- [Sanitized remediation map](remediation-map.json) — 549-row ownership ledger
- [Internal package catalog](package-catalog.json) — 15 commit-batch definitions
- [Locked ledger manifest](ledger-manifest.json) — source and artifact hashes
- [Structured hardening decision](hardening.json)
- [Plan validator](validate_plan.py) — consistency and disclosure-safety checks
