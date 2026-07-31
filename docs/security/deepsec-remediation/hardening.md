# Security Hardening Review: Tirith DeepSec remediation

## Evidence Basis

This review is derived from a 549-row adjudicated finding collection at product
revision `e1ec47ef9f43e32872a550522067a680ff659e6e`, followed by a seven-band
source re-review and an independent stack-architecture pass. The immutable
source report declares 482 actionable roots; the reviewed ledger contains 483
because `repo-0476` requires a Windows environment-overlay fix independent of
the cwd-only root to which it was originally marked duplicate.

The evidence identity, hashes, live stack snapshot, static-review boundary, and
classification caveats are in [context.md](context.md). Private findings and
reproduction payloads are intentionally excluded from this distributable
portfolio. IDs below are paired with short reader-facing control descriptions;
the sanitized [remediation map](remediation-map.json) provides complete
ownership accounting.

## Constraints

We are using a balanced change profile: security closure comes first, followed
by legitimate compatibility, reliability, repository convention, and minimal
scope. No measured performance or memory budget was supplied, so every expected
resource effect remains source-derived or hypothetical until its package runs
the benchmark specified in the implementation plan.

The principal constraints are:

- Rust 1.83 MSRV;
- a large open predecessor stack and current-main drift;
- cross-platform behavior on Linux, macOS, and Windows;
- no telemetry assumption for rollout decisions;
- public-repository disclosure minimization;
- additive, reversible migrations for policy, state, lockfile, receipt,
  coverage, and ThreatDB schemas;
- exactly three stacked implementation PRs, using internal commit groups for
  foundations and subsystems.

## Opportunity Portfolio

| Opportunity | Evidence | Options | Recommendation | Proposal |
| --- | --- | --- | --- | --- |
| Canonical analysis and completeness | Parser/fast-path disagreement, incomplete install/scan/artifact outcomes (`repo-0042`, `repo-0049`, `repo-0129`, `repo-0336`, `repo-0399`) | Sink-local guards; owned command IR plus typed outcomes | Use owned representations incrementally; retain tactical guards during migration | [Proposal](proposals/canonical-analysis.md) |
| Capability-owned privileged effects | Untrusted child selection, connect-time egress, path-selected deletion, repository writer containment (`repo-0018`, `repo-0014`, `repo-0040`, `repo-0271`, `repo-0397`) | Local validation; trusted child/network/filesystem capabilities | Build small owned capability APIs and migrate sinks individually | [Proposal](proposals/effect-capabilities.md) |
| Typed safe output and secret lifecycle | Pre-redaction persistence, terminal-state overflow, structured-key collision, Markdown data encoding (`repo-0029`, `repo-0046`, `repo-0058`, `repo-0161`) | Per-sink escaping; typed raw/secret/display values | Use typed values with format-specific encoders and post-transform reanalysis | [Proposal](proposals/safe-output.md) |
| Proof-carrying security state | Coverage overstatement, provisional-state poisoning, audit generation drift, aggregate containment flags, nontransactional taint, omitted scan gaps (`repo-0033`, `repo-0044`, `repo-0196`, `repo-0258`, `repo-0343`, `repo-0469`) | Local locks and booleans; versioned state machines with explicit evidence | Use explicit states, stable locks, transactions, and per-dimension coverage | [Proposal](proposals/proof-carrying-state.md) |

## Recommendation Summary

I recommend the incremental structural option in all four opportunities. The
evidence does not justify a service rewrite or another ambient privileged
daemon. It does justify moving repeated controls behind APIs that make unsafe
states difficult to express: one analysis outcome, one command representation,
one trusted child supervisor, one connect-time egress client, contained I/O
handles, typed output values, and transactional state generations.

The attractive part of sink-local patches is their short path to one closure.
We should continue to use them where a shared abstraction would be artificial.
What gives me pause is the recurrence pattern: callers already disagree about
parsing, completeness, path identity, output safety, and state truth. Local-only
fixes would preserve that ownership drift and force reviewers to reconstruct the
same boundary for every future caller.

The structural recommendation is conditional. If a foundation cannot preserve
MSRV, platform behavior, or the hot-path performance threshold established by
its package, the correct fallback is a smaller shared helper plus explicit
consumer contracts—not a silent local bypass. If future runtime evidence shows
that process/service isolation is necessary for a parser or feed, that isolated
component should be proposed separately with its own operational budget.

## Next Decisions

The current decisions needed before implementation are concrete:

- approve the three-PR ownership and the internal foundation order in the
  [stacked implementation plan](implementation/stacked-pr-plan.md);
- define initial latency, allocation, and binary-size thresholds for R1-FND's
  completeness, child-process, command-IR, output, and egress controls;
- define approval-rule precedence before releasing `repo-0244` from hold;
- provide supported-host macOS evidence for `repo-0037`;
- inspect deployed edge controls for `repo-0446`;
- decide the compatibility window for each serialized schema before its first
  writer changes;
- confirm that exact revalidation evidence will be stored privately and tied to
  commit SHAs while the public ledger carries only closure metadata.
