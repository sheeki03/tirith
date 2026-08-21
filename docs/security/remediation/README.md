# Security remediation ledger

`source-index.json` is the immutable 135-row source ledger. `findings.json` is the canonical remediation-root ledger. `main.md` is a generated human view and must never be edited by hand.

## Source accounting

| Source | Rows | Deterministic extraction |
|---|---:|---|
| `stack` | 26 | Numbered findings at source lines 23, 25, 29, 31, 33, 37, 39, 41, 43, 45, 48, 52, 54, 56, 58, 60, 62, 64, 66, 68, 72, 74, 76, 78, 80, 82 |
| `addendum` | 1 | The complete immutable npm-harness addendum |
| `additional` | 41 | High lines 5–33 odd; medium lines 37–83 odd; low lines 87 and 89 |
| `original` | 67 | Critical line 7; high lines 11–31 odd; medium bullets 37–46, 50–55, 59–65, 69–75, 79–89; lower-priority bullets 93–106 |

The total is `26 + 1 + 41 + 67 = 135`. Immediate stack blockers, report coverage notes, dependency-scan totals, validation summaries, and recommendations are report context—not additional source rows.

IDs are allocated in the fixed report order `stack`, `addendum`, `additional`, `original`: `STACK-001..026`, `ADDENDUM-001`, `ADDITIONAL-001..041`, and `ORIGINAL-001..067`. Their global ledger ordinals are 1–26, 27, 28–68, and 69–135.

Every source-to-root mapping records its source ID, canonical root ID, mapping type, mapped claims, affected seams, and a nonempty rationale. Canonical source rows use `related` with the fixed rationale “Canonical source row owns this remediation root.” Four exact duplicates share roots rather than creating extra remediation work:

- `ORIGINAL-001` inherits `STACK-001`.
- `ORIGINAL-014` inherits `STACK-002`.
- `ORIGINAL-042` inherits `ADDITIONAL-011`.
- `ORIGINAL-048` inherits `ADDITIONAL-035`.

That produces 131 initial canonical roots. Partial overlaps remain separate unless claim-level evidence proves identity. A compound source row may later list multiple `mapped_claims` or an explicit `partial_overlap` mapping without changing the immutable 135-row count.

Every root has exactly one implementation owner. The four existing layers own `pr-197`, `pr-198`, `pr-201`, and `pr-199`; remaining roots are partitioned across `poststack-gateway-runtime`, `poststack-mcp-identity`, `poststack-network-license`, `poststack-artifact-analysis`, `poststack-state-integrity`, `poststack-user-integrations`, `poststack-containment-daemon`, and `poststack-release-convergence`. The importer and independent validator contain separate total maps and reject missing, duplicate, or reassigned ownership.

## Commands

```sh
# One-time import only; refuses to overwrite established IDs.
python3 docs/security/remediation/manage.py bootstrap

# Generate the human view.
python3 docs/security/remediation/render_main.py

# Independent structural, provenance, lifecycle, and freshness checks.
# `--base-ref` is required: append-only enforcement is the only check that
# rejects deleted findings, rewritten history, and a mutated source index, so
# the validator refuses to skip it silently. Locally, where there is nothing to
# diff against, say so explicitly with `--allow-missing-base`.
python3 docs/security/remediation/validate_ledger.py --structural --allow-missing-base

# In a PR, protect append-only history and mappings against the base instead.
python3 docs/security/remediation/validate_ledger.py --structural --base-ref origin/main

# The owning branch binds all owned findings to an explicit reviewed code candidate.
# A later checked-out HEAD may add only tracker/evidence files.
python3 docs/security/remediation/validate_ledger.py --layer poststack-state-integrity --candidate-sha "$CANDIDATE_SHA" --base-ref origin/main --evidence-bundle /path/to/downloaded-evidence.json

# The settled stack binds every root to the exact release candidate and downloaded CI artifact.
python3 docs/security/remediation/validate_ledger.py --release-candidate --candidate-sha "$CANDIDATE_SHA" --evidence-bundle /path/to/downloaded-evidence.json

# Final verification requires the configured committed closure bundle.
python3 docs/security/remediation/validate_ledger.py --merged-main --candidate-sha "$CANDIDATE_SHA" --evidence-bundle docs/security/closure-evidence.json
```

The release gate deliberately does not claim CI success. Required CI and release workflows must separately pass for the exact candidate.

## State model

Lifecycle is strictly:

`confirmed_open → reproduced → implemented → layer_verified → stack_verified → ready_to_merge → merged_verified`

`reopened`, `invalidated`, and `regressed` are append-only history events that lower lifecycle; they are never lifecycle values. Active blockers are separate `blocked_*` records. Resolution route is independently one of `local`, `upstream_candidate`, or `upstream_verified`.

Advancement is gated by progressively stronger evidence. Implementation requires fix commits and regression-test locators. Every verification attempt binds its base, head, synthetic merge tree, workflow revision, platform/toolchain, command, outcome, external log or attestation, and a subject-tree hash. Layer verification requires exact-head passed focused, benign, and adversarial attempts; stack verification adds platform evidence; ready-to-merge and merged verification additionally require exact-head performance, UX, packaging, review, and release attempts. Failed or `blocked_native` attempts are retained but never satisfy a transition. Migrated consumers are retained alongside regression-test locators.

The validator computes the synthetic merge using `git merge-tree --write-tree BASE CANDIDATE` and hashes sorted `<mode> <object> <path>` entries from that tree, excluding exactly `main.md`, `docs/security/remediation/**`, and `docs/security/closure-evidence.json`. Every layer, release-candidate, and merged-main invocation requires an explicit full `--candidate-sha`. That candidate must be an ancestor of the checked-out HEAD, and the candidate and checkout must have identical non-tracker subject trees; this permits a later ledger/evidence commit without silently changing the reviewed code candidate.

The synthetic merge must also have a non-tracker subject-tree delta from the evidence bundle's base, and `BASE..CANDIDATE` must contain at least one fix commit recorded for the selected owner (or the release ledger in aggregate). Empty or tracker-only validation layers therefore cannot advance lifecycle. The validator also rejects conflicts, stale hashes, stale fix/verification commits after a rebase, missing external evidence, and non-passing/neutral/skipped/cancelled evidence. It enforces append-only history and source mappings when `--base-ref` is supplied.

Layer and release-candidate modes accept a downloaded external evidence bundle at any explicit file path. Merged-main mode alone requires the configured committed `docs/security/closure-evidence.json`. The minimal versioned bundle schema is `evidence-bundle.schema.json`; its payload digest and checks are independently rebound to the exact candidate and ledger attempts.

## Evidence and source immutability

The archived source reports are normalized only to UTF-8/LF with one terminal newline. The index records both the original attachment digest and normalized-copy digest. Generated evidence paths are repo-relative; absolute local paths and file URIs are rejected. Historical report prose is not rendered into `main.md`.

The original report's final 14 bullets are explicitly labeled “Lower-priority bugs and hardening,” not a severity. Their source severity remains unnormalized; their canonical roots start as `untriaged` until severity is assigned with evidence. The addendum likewise has no stated severity and starts `untriaged`.
