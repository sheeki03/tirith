# DeepSec remediation evidence context

## Evidence snapshot

| Property | Value |
| --- | --- |
| Target repository | `sheeki03/tirith` |
| Target branch | `security/spikes` |
| Target revision | `e1ec47ef9f43e32872a550522067a680ff659e6e` |
| PR snapshot | PR #174 head, based on `security/feed-digitalside` |
| Adjudicated rows | 549 |
| Individual receipts | 549 |
| Evidence collection artifacts | 551 |
| Deterministic collection SHA-256 | `78b14d301abfb978492b2451fec26b7f748e52e84c15c9eeb0725a57f062490a` |
| Source report JSON SHA-256 | `a8fb73905e26755c1fff3143723faa2fd4da25df20f98a4405aebd21c20d0dc5` |
| Source report Markdown SHA-256 | `2b4949f45a0b561b98e1967dad86718060d8a683cc0cf8e33cff585bd4cc9f54` |
| Source product drift at planning start | none |

The source report is a completed DeepSec 2.2.9 adjudication generated with
`gpt-5.6-sol` at `xhigh`. Its recorded isolated CLI integration, core, signing,
and license-server suites passed. Its default workspace run was non-hermetic and
is evidence for the test-isolation work, not proof that any finding is fixed.

## Live stack snapshot

At planning time, PR #174 was still open at the target revision and its base was
`security/feed-digitalside` at
`4cb2c0ee0bcc95ff1e5d1643f64a7d2974a01cf8`. Current `origin/main` was
`ca0065fe3ec5921a915e63e1d7663b1988f8c0c0`; the merge base was
`a78e1464ec73b43df5b3c68eeccbc1e8bbdeaaed`, and the divergence was 39
main-only commits versus 328 PR-head-only commits. A synthetic merge-tree was
clean. This is topology evidence, not a merge-readiness verdict.

The plan branch therefore starts directly from PR #174 as requested. Before any
implementation branch is cut, fetch the live PR head and compare it with this
snapshot. If code relevant to a finding has drifted, revalidate and update the
package contract before coding.

## Review method and boundary

The 549 rows were partitioned into seven non-overlapping ID bands. Each band was
statically traced against the exact target revision for disposition, source and
sink, violated invariant, shared-control fit, package boundary, dependencies,
regression gates, compatibility, and rollout risk. A separate architecture pass
challenged sequencing and stack topology.

This planning review did not run 549 live exploit reproductions. Runtime proof
is deliberately a per-root prerequisite in the implementation closure contract.
Rows whose current security boundary could not be established remain held or
are explicitly marked as classification caveats; the plan does not convert a
static suspicion into a claim of remediation.

## Source-ledger integrity notes

The source report passes its stated 549-row count checks, but planning found two
important metadata limitations:

1. All 61 source `duplicateOf` links resolve to actionable roots, but 59 of the
   duplicate rows retain a different `canonicalGroupId`. The plan therefore uses
   `duplicateOf` for source traceability and never uses `canonicalGroupId` for
   ownership or counts.
2. `repo-0476` is not fully closed by the recorded `repo-0475` root. The latter
   covers Windows cwd propagation; the former also covers environment-overlay
   propagation. The reviewed plan promotes `repo-0476` to an independent P3
   reliability obligation, producing 483 reviewed roots and 60 duplicates.

Some duplicate rows are umbrella descriptions that require more than one sink
to close. The public ledger intentionally records only the primary
`canonicalRoot` and sanitized internal package; it does not claim to enumerate
those additional paths. Before coding each package, the implementer must derive
a private duplicate-coverage checklist from the source receipt, key it by
duplicate ID plus the evidence-collection hash above, and retain it with the
private exact-SHA revalidation artifacts. A duplicate receipt closes only when
every path on that checklist is covered, not merely when its primary root lands.

## Priority adjustments without source mutation

The immutable source priorities remain useful for traceability, but the stack
pulls prerequisite and misclassified integrity work forward. Examples include:

- hermetic test and child-process cleanup before relying on full-suite results;
- explicit completeness before P0 artifact enforcement;
- version ordering correctness before exact-version blocking;
- secure I/O before checkpoint, policy, trust, and setup writer migrations;
- per-dimension containment coverage before claiming OS sandbox enforcement;
- validator/schema migration before policy matcher and fail-closed changes;
- signed ThreatDB sequence, receipt signing, and database encoding integrity
  before ordinary P3 reliability cleanup.

Security-versus-reliability label corrections do not remove work. They change
which track owns the root and how early its gate must run.

## Distribution boundary

The source report, receipts, evidence excerpts, PoCs, and attacker payloads stay
outside version control. Distributable artifacts contain only IDs, coarse
modules, invariants, package assignments, gates, and status. This allows public
engineering review without publishing a ready-made exploit catalog for
unpatched paths.

The following fields are forbidden in `remediation-map.json`: finding titles,
descriptions, recommendations copied from the source report, attacker input,
preconditions, evidence, counterevidence, proof text, or local filesystem paths.
`validate_plan.py` enforces the committed schema and scans distributable JSON for
those keys. It also binds the exact per-ID map and 15-package catalog through
raw-byte and canonical-JSON hashes in `ledger-manifest.json`; the manifest hash
is locked in the validator. Aggregate-preserving owner or duplicate-target swaps
therefore fail validation. A deliberate ledger change requires re-derivation
from the private hashed source and visible updates to both the manifest and its
validator lock.
