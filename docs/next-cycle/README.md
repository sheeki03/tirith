# Next-cycle implementation progress

Implementation starts from current main at Tirith **0.4.2**,
`7fd35101568bb06ee0d361dc1d4a4d193c5f60fd`, on
`codex/next-cycle-foundations`. The original 0.4.1 workspace and its local changes
are preserved. No package version, release tag, personal configuration or remote
publication was changed.

The implementation plan covers all ten cycle workstreams. Its dependency and
release-gate separation remains appropriate. Initial inspection confirmed the
reported policy-reporting, message, redaction, onboarding, trust-expiry and
shell-target inconsistencies. It also identified existing ThreatDB fixes and
large regression corpora to reuse. See the [baseline inventory](baseline.md) and
[acceptance matrix](acceptance-matrix.md).

## Work-package progress

| Package | Status | Implemented work and remaining boundary |
| --- | --- | --- |
| WP00 | In progress | Baseline revision, toolchain, package/schema/fixture inventory and acceptance matrix recorded. New packaged measurements, full 0.4.2 fixtures and native qualification remain open. |
| WP01 | In progress | Shared runtime policy resolver; explicit runtime CLI view; source/scope from the same resolved object; safe display projection and declared evidence gaps. Full field provenance, input revisions, profile identity and fetch/expiry metadata remain open. |
| WP02 | In progress | Distinct confirmation label, honest incomplete/warn-only messages and scoped exception-review guidance. Pure evaluation and structured causal/recovery contracts remain open. |
| WP03 | In progress | Schema-selected MCP redaction and compatibility regressions; protocol fields survive broad custom patterns. Remaining CLI/signed/export/browser boundaries stay open. |
| WP09 | In progress | Correct repeated blocked-check counts and truthful no-suggestion/writable-target guidance. Frozen simulation, examples and feedback depend on the preceding contracts. |
| WP04–WP08, WP10–WP27 | Pending | Inventory/design context recorded where applicable; no complete work package or release gate claimed. WP09's isolated reporting fixes were pulled forward without introducing new mutation authority. |

Detailed contracts:

- [Policy snapshot and CLI compatibility](policy-snapshot.md)
- [Decision messages and tuning](decision-messages.md)
- [Output privacy and versioning](output-contracts.md)

## Review and validation

Independent review covered the combined production diff and new tests. It found
and prompted fixes for strict-warning acknowledgement wording, private data in
dynamic policy map keys, and quadratic collision numbering. The final follow-up
found no remaining substantive issues. Review did not substitute for tests.

See [verification.md](verification.md) for the exact local checks and limits.
G0 remains open, as do G1–G3. This slice neither adds automatic recommended setup
nor claims new native host enforcement, installed-package certification, a full
preview contract, or a browser mutation service.

Next implementation priority is to complete WP01's provenance/revision capture
inside the resolver, extend WP03 to the remaining machine boundaries, and then
establish frozen evaluation and shared shell-target evidence before profile or
setup mutations. New field/schema contracts need tests before browser controls
consume them.
