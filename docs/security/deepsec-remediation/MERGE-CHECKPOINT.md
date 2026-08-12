# Security merge checkpoint

Checkpoint date: 2026-08-12

This is the operator-facing status record for the security merge program. It
distinguishes work that is merged to `main`, work that is implemented but still
behind a gate, and work that has not yet been integrated. A pull request is not
marked complete merely because its source exists or its branch builds locally.

## Non-negotiable merge rule

No pull request in this stack is merged while a required security, dependency,
formatting, lint, MSRV, platform, or test gate is failing. Advisories are fixed
at the dependency or implementation boundary; they are not silenced with audit
or deny-list exceptions. Draft pull requests become ready only after their live
head has been rebased or integrated, reviewed, and validated.

## Checkpoint summary

| Group | Pull requests | State at this checkpoint |
| --- | --- | --- |
| ThreatDB and artifact foundations | #150-#157, #159-#162 | Merged to `main` |
| Executive-verdict integration | #164 | Merged to `main` |
| Follow-on hardening | #169-#172 | Merged to `main` |
| Feed and research follow-ons | #173, #174 | Merged to `main` |
| DeepSec plan | #177 | Documentation integrated; checkpoint and handover being added before readiness review |
| DeepSec R1 | #183, #184, #185, #186, #179 | Not yet merged; must be integrated and gated in this order |
| DeepSec R2 | #187, #180 | Not yet merged; must follow all R1 units |
| DeepSec R3 | #181 | Not yet merged; final convergence unit |

PR #158 does not exist in the requested A/B sequence. It is intentionally not
invented or treated as an unmerged obligation.

## Merged receipts

These are GitHub merge commit receipts, not merely branch-head hashes.

| PR | Scope | Merge commit |
| ---: | --- | --- |
| #150 | OpenSSF malicious-package indicator parsing and MAL confidence | `b0ebf00c77928b59b49e21ed29c1746f0c568a54` |
| #151 | Version intent and constraint-aware package assessment; RustSec/MSRV remediation | `d54ec01f4bb3a96a6ec4c96eb31dd1623f4167c0` |
| #152 | Typed scan outcomes, coverage gaps, and file classification | `52039e6e91de367d5aee9abbe79f0df1f723fc7b` |
| #153 | Artifact subject/signal model and policy seam | `ee9e7241f7916a6a10794b86d809ed8f19cefaec` |
| #154 | Hardened streaming wheel reader | `a88c743f8aee8c22336e102dda4d4c244b3ac07b` |
| #155 | Wheel/installed RECORD integrity and ownership index | `62dc3393eb897986359e01e0588c936ff3b6a052` |
| #156 | Python startup-hook execution analysis | `0df4fbb258252a8c90deebf91318cb3cb0a55ac7` |
| #157 | Native binary triage and import-chain correlation | `b59213fbb1846ad4f2c70edce14ea3411016f412` |
| #159 | Artifact inspection wiring and cross-distribution correlation | `52511f5619f57f06efcdb0f4d1b5d6fa358cf030` |
| #160 | ThreatDB v2 format, indices, writer, and dual manifest | `a0def1cb36f44a2e253b9d9a5f3100971f109ce5` |
| #161 | Staged v2 rollout and non-telemetry gating | `bf14ac2404e6712ac24eb08419e7ec14a21f2b0f` |
| #162 | Signed v2 asset/index publication | `4c83aec02291af6b021409e7fd5cd4d188f8fd1c` |
| #164 | Package firewall, runtime capsule, MCP gateway, and integrated executive verdict | `9c72dad8f91b0127f09b53456ddb9c17167eadb5` |
| #169 | PDF preflight and decoded object-graph depth guard | `e5490709946380aab9bce128d80a103ba838bb55` |
| #170 | Human CLI output sanitization and exact chmod display safety | `e5dfec91f1fa1440d026b60681be3738dae11320` |
| #171 | Structural GitHub Actions security checks | `99c48b18f45d4fc0dd0573dea492d0f11c4bdeb4` |
| #172 | Reverse-shell/inline-interpreter detection and credential coverage | `6809951c286b74268354a5250f1e2ca299d4dd0b` |
| #173 | DigitalSide gated threat-feed source | `24a20824f3e0c5b4db3c0393a32409000b7d84b9` |
| #174 | Offline RustSec, Web3 phishing, and native YARA research decisions | `7db3bed6c5d38b4433e37495da1b0af8010aae33` |

## RustSec and MSRV remediation

The dependency gate was repaired before the feature stack was merged:

- Workspace MSRV moved from Rust 1.83 to Rust 1.88 and CI now tests 1.88.
- `lopdf` moved from 0.34 to 0.44; PDF reads and decoded object traversal remain
  bounded rather than relying on the dependency upgrade alone.
- The vulnerable `rust-s3` 0.35 dependency chain was removed. R2 backup uses an
  in-tree, bounded SigV4 request path over the existing HTTP/HMAC primitives.
- Stale `home`, `time`, and `base64ct` pins were removed or relaxed to the
  supported dependency graph.
- `.cargo/audit.toml` and `deny.toml` contain no advisory ignores.
- At the remediated exact head, workspace tests, strict workspace Clippy,
  `cargo deny`, and `cargo audit` passed; audit reported zero vulnerabilities.

This is the new baseline for every descendant. Documentation or CI referring to
MSRV 1.83 is historical and must not be used as the current gate.

## How the completed work was integrated

1. Each pull request was rebased or reconstructed on its actual parent instead
   of assuming an old green result remained valid.
2. Conflicts were resolved as semantic unions: newer completeness, bounded-work,
   and privacy controls were preserved alongside the feature being integrated.
3. Focused regressions were run for the changed boundary, followed by formatting
   and strict Clippy where applicable.
4. Required GitHub checks were observed on the exact pushed head. Review threads
   were either fixed and resolved or the pull request remained blocked.
5. GitHub's merge result and merge commit were read back before the item was
   recorded as complete in this file.

## Work still open

### Immediate

1. Finish #177's documentation union, validate the sanitized ledger and links,
   make it ready for review, and merge only on a green exact head.

### DeepSec implementation order

1. R1: #183 -> #184 -> #185 -> #186 -> #179.
2. R2: #187 -> #180.
3. R3: #181.

Two known items require explicit source correction during that sequence:

- #185: transactional retries must not duplicate diagnostics or externally
  visible side effects.
- #187: pip constraint files constrain already-declared packages; they must not
  be promoted into dependency declarations.

These are not the only review obligations. Each live head still requires a
fresh diff review, unresolved-thread check, parent-drift check, focused tests,
and the repository's complete required gate set.

## Final convergence gate

After #181, refresh `main` and record one final exact SHA. At that SHA:

- run the isolated workspace suite and focused DeepSec regressions;
- run strict Clippy and formatting on the supported Rust toolchain;
- run `cargo audit` and `cargo deny` with zero ignored advisories;
- require all supported GitHub platform jobs to pass;
- validate `remediation-map.json`, `package-catalog.json`, and the locked ledger;
- confirm no draft or requested pull request remains open/unmerged; and
- update this checkpoint from in-progress states to final merge receipts.

Until those conditions hold, the program is in progress rather than complete.
