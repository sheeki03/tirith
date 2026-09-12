# Next-cycle baseline and regression inventory

Inventory date: 2026-09-12. Baseline: Tirith **0.4.2**, commit
`7fd35101568bb06ee0d361dc1d4a4d193c5f60fd`.

This is the initial WP00 inventory for the ten-point cycle plan and its WP00–WP27
implementation plan. It records source inspection, existing fixtures and open
verification work. It does **not** close WP00, G0, or any release gate. Later
changes should reference the stable finding and acceptance IDs below and record
results against their own immutable revision. Findings here describe the baseline,
even when a later change fixes them.

## Revision and toolchain

| Item | Observed evidence |
|---|---|
| Implementation branch | `codex/next-cycle-foundations`, isolated from the original workspace |
| HEAD and local `origin/main` | Both `7fd35101568bb06ee0d361dc1d4a4d193c5f60fd` after `git fetch origin main` on 2026-09-12; the remote returned this commit |
| Workspace package | Version `0.4.2`, edition `2021`, declared Rust minimum `1.83` in [`Cargo.toml`](../../Cargo.toml) |
| Manifest SHA-256 | `75d39fef80763be9be399f53785ac6b6789a6d168f9f3d7a78749b383a459143` |
| Lockfile SHA-256 | `1a86c7dadffdabb92423b71436bc903f06d0795826125aaeb36277f93b910a0f` |
| Inventory host | `Darwin 27.0.0 arm64`; `rustc 1.98.0 (88d9e12ae 2026-08-18)`; `cargo 1.98.0 (797e8a9bc 2026-08-05)` |
| Default features | Empty for CLI/core; artifact hash checks are unconditional. `artifact-hash-lookup` is a compatibility feature |
| Optional verification | `sigstore-attestations` has no backend dependency wired; native YARA is deferred. Neither feature name nor provenance parsing establishes cryptographic verification |
| Test evidence collected here | Source/fixture inventory only; no application builds, tests, benchmark runs, installed-package trials or native-host certification were performed for this document |

Reproduce revision metadata from the implementation checkout:

```sh
git rev-parse HEAD refs/remotes/origin/main
git status --short
git show 7fd35101568bb06ee0d361dc1d4a4d193c5f60fd:Cargo.toml
git show 7fd35101568bb06ee0d361dc1d4a4d193c5f60fd:Cargo.lock | shasum -a 256
rustc --version
cargo --version
uname -srm
```

Use `git show <baseline>:<path>` for historical source comparisons; a working-tree
file may already contain next-cycle fixes. A local remote-tracking ref is not a
claim about today's live GitHub main.

## Revalidated findings

“Confirmed” means the relevant baseline source path was inspected; it is not a
new exploit demonstration. “Already fixed/present” means preserve existing
behavior and regressions. “Design-only” is a proposed contract, not a reported
current defect. “Unverified” identifies evidence still needed.

| ID | Baseline classification | Finding and source | Follow-up |
|---|---|---|---|
| F01 | Confirmed | [`onboard.rs`](../../crates/tirith/src/cli/onboard.rs), `recommend`: CI presence can choose `ci-strict`; apply invokes repository `policy::init`. [`individual.yaml`](../../crates/tirith/assets/policy_templates/individual.yaml) enables interactive bypass, which repo sanitization in [`policy.rs`](../../crates/tirith-core/src/policy.rs) neutralizes | WP01, WP05, WP10: personal profile behavior and trusted scope |
| F02 | Confirmed | [`cli/policy.rs`](../../crates/tirith/src/cli/policy.rs), `gather_effective`/`effective`, uses `discover_local_only`; runtime `Policy::discover` has remote replacement and failure behavior. `RemotePolicyCacheEnvelope` has schema, origin/credential fingerprint and YAML, but no fetch timestamp | WP01: shared runtime snapshot and honest remote freshness |
| F03 | Confirmed | [`engine.rs`](../../crates/tirith-core/src/engine.rs), `retain_by_paranoia`, retains Medium-and-above for both levels 1 and 2 | WP02, WP05: do not equate the slider with a profile action matrix |
| F04 | Confirmed | [`output.rs`](../../crates/tirith-core/src/output.rs) renders Warn and WarnAck as `WARNING`; the first eligible URL/domain recovery line says “To allow” without enumerating remaining blockers | WP02: acknowledgement-specific wording and bounded recovery claims |
| F05 | Confirmed | [`audit_tune.rs`](../../crates/tirith-core/src/audit_tune.rs) omits downgrade suggestions when `blocked > 0`; [`cli/policy.rs`](../../crates/tirith/src/cli/policy.rs) can say an empty suggestion list means policy is well matched | WP09: distinguish observations, evidence gaps and recommendations |
| F06 | Confirmed | [`onboard.rs`](../../crates/tirith/src/cli/onboard.rs), `apply`, prints the init line and manual editing guidance. Managed writes already exist separately in [`setup/shell_profile.rs`](../../crates/tirith/src/cli/setup/shell_profile.rs) | WP10: connect existing managed setup; avoid building a second writer |
| F07 | Confirmed | `profile_for_shell` in [`setup/shell_profile.rs`](../../crates/tirith/src/cli/setup/shell_profile.rs) hardcodes several home-relative targets and does not use XDG/ZDOTDIR. [`doctor.rs`](../../crates/tirith/src/cli/doctor.rs) checks other PowerShell/Nushell paths | WP04: shared target resolver; native Windows, login shells and custom roots still require tests |
| F08 | Confirmed | [`setup/fs_helpers.rs`](../../crates/tirith/src/cli/setup/fs_helpers.rs), `PlatformTransaction::lock`, uses blocking `lock_exclusive` and explicitly leaves measured timeout work open. [`cli/dashboard.rs`](../../crates/tirith/src/cli/dashboard.rs), `serve`, handles accepted requests in the synchronous serve loop | WP06, WP13: measured bounded operations before browser writes |
| F09 | Confirmed | [`cli/trust.rs`](../../crates/tirith/src/cli/trust.rs), `is_expired`, treats malformed RFC3339 as not expired; core `merge_trust_store` skips malformed timestamps | WP07: one expiry validator for display and enforcement |
| F10 | Confirmed | [`cli/trust.rs`](../../crates/tirith/src/cli/trust.rs), `last`, accepts bare `y` for domain-wide/all-rule trust. Core `merge_trust_store` reads selected entry fields from JSON and ignores unknown fields | WP07, WP08: narrow defaults; a new project field in the old store cannot safely convey project scope |
| F11 | Confirmed with existing mitigation | [`prompt_status.rs`](../../crates/tirith/src/cli/prompt_status.rs) maps `TIRITH_STATUS=blocks` to `guarded`; a configured hook with missing live signal already has `ConfiguredUnknown` health semantics. This is not versioned native enforcement evidence | WP04, WP11: preserve generic status exits; add explicit verified-blocking requirements |
| F12 | Confirmed | [`redact.rs`](../../crates/tirith-core/src/redact.rs), `redact_json_strings`, visits all string values. [`mcp/dispatcher.rs`](../../crates/tirith-core/src/mcp/dispatcher.rs), `sanitize_json_rpc_response`, applies it to result/error-data objects | WP03: field-aware boundaries that retain sensitive-content redaction and protocol identity |
| F13 | Confirmed | [`dashboard.rs`](../../crates/tirith-core/src/dashboard.rs), `build_audit_summary`, reads the full file with a 64 MiB cap and maps read failure to `None`; [`audit.rs`](../../crates/tirith-core/src/audit.rs) bounds append storage to 256 MiB | WP12, WP17: bounded queries, truthful coverage and integrity-preserving retention |
| F14 | Confirmed | [`selfupdate.rs`](../../crates/tirith-core/src/selfupdate.rs), `InstallMethod`, lacks dedicated Chocolatey/Nix/mise/asdf variants. Unknown remains conservatively non-replaceable | WP15: improve channel recognition without broadening self-replacement |
| F15 | Already fixed/present | 0.4.2 [release notes](../release-notes-0.4.2.md), ThreatDB source fetch fixtures and [`threatdb.rs`](../../crates/tirith-core/src/threatdb.rs) include octet-stream metadata validation and same-second/path-aware reload fixes | WP16: extend operational reporting; do not reschedule these as missing fixes |
| F16 | Already present; documentation mismatch confirmed | [`web3_gate.rs`](../../crates/tirith-core/src/rules/web3_gate.rs) consults `deny_destinations`, incomplete-analysis and ambiguous-Hardhat actions, and required command cards; [coverage prose](../enforcement-coverage.md) calls these inactive | WP18: reconcile each claim with reachable code before adding duplicate enforcement |
| F17 | Already present | [`task.rs`](../../crates/tirith-core/src/task.rs), `infer_effects_detailed_with_context`, extracts npm install/exec effects and keeps package execution incomplete; local Python release comparison exists in [`artifact/release_diff.rs`](../../crates/tirith-core/src/artifact/release_diff.rs) | WP20–WP24: reuse these foundations; npm archive inspection is separate work |
| F18 | Design-only | Versioned personal profiles, immutable change plans/idempotent operation IDs, project-grant envelope, browser mutation authorization, segmented history, and hash-bound npm installation are proposed contracts | Resolve and verify the corresponding WP designs before exposing them |
| F19 | Unverified | Exact 0.4.2 installed-host results, channel availability, publication completion, end-to-end latency/resource distributions, a first automatic-setup certified set and beginner pilot evidence were not collected here | WP00, WP11, WP15–WP19 remain open |

This is a revalidation of named findings, not an exhaustive repository audit. In
particular, cache expiry in long-running consumers, recovery under partial writes,
and channel-specific upgrade journeys need runtime evidence.

## Public contracts and reusable fixtures

The authoritative command inventory is `Commands` and `COMMANDS_BY_CATEGORY` in
[`main.rs`](../../crates/tirith/src/main.rs), covered by help/category tests.
[`capability-manifest.toml`](../capability-manifest.toml) generates the public
[capability matrix](../capability-matrix.md). Existing command groups already
include onboarding/setup, policy/trust, status/doctor, dashboard, package/project
inspection, receipts and updates; the plan connects and corrects these surfaces.

| Contract or corpus | Baseline evidence to retain | Remaining capture/review |
|---|---|---|
| Check JSON and exits | [`output.rs`](../../crates/tirith-core/src/output.rs): schema 3; [`c00_cli_compatibility.rs`](../../crates/tirith/tests/c00_cli_compatibility.rs), [`cli-contracts.toml`](../../tests/fixtures/c00/cli-contracts.toml) freeze representative keys/actions/exits | New snapshots for affected 0.4.2 paths; migrations must be explicit |
| Policy and signed data | [`c00/contracts.toml`](../../tests/fixtures/c00/contracts.toml), legacy policy YAML, command-card signing JSON; [`c00_contracts.rs`](../../crates/tirith-core/tests/c00_contracts.rs) freezes policy projection, signatures and ThreatDB v1/v2 bytes | These fixtures originate at **0.3.3/post-r3**, as their README states. They are not a complete 0.4.2 capture |
| Trust store | Core `policy.rs` and CLI `trust.rs` tests cover user/repo scope, malformed entries, TTL and protected writes | Frozen complete 0.4.2 legacy reader/new-grant compatibility fixture still needed before new grant writes |
| MCP | [`mcp/types.rs`](../../crates/tirith-core/src/mcp/types.rs) supports `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`; C00 freezes default tools. MCP lock format is 8 in [`mcp_lock.rs`](../../crates/tirith-core/src/mcp_lock.rs) | Separate protocol-owned strings, secret content, signed documents and display views |
| Dashboard/task | Dashboard snapshot schema 1; task supports envelope versions 1/2 and decision projection schema 1 | These do not imply a browser write API or universal schema negotiation |
| Shell receipts | [`execution_state/shell_receipt.rs`](../../crates/tirith-core/src/execution_state/shell_receipt.rs): receipt/capability schema 3, capability anchor schema 1, legacy receipt 1/2 handling; dedicated tests and PTY ledger assertions | Complete compatibility capture at execution boundaries; actual host observation remains separate |
| Legitimate/malicious command pairs | [`shell_false_positive_regressions.rs`](../../crates/tirith-core/tests/shell_false_positive_regressions.rs) covers shell snapshots, local package patterns, paths, aliases and nested execution; [`bypass_regression.rs`](../../crates/tirith-core/tests/bypass_regression.rs), [`golden_fixtures.rs`](../../crates/tirith-core/tests/golden_fixtures.rs) and [`tests/fixtures`](../../tests/fixtures) supply nearby controls | Extend these suites for confirmed new precision cases; do not duplicate known cases |
| Inert execution markers | [`shell_conformance.rs`](../../crates/tirith/tests/shell_conformance.rs) asserts allowed once/blocked never, warning behavior, ledger counts, and npm launcher delivery; [`owned_boundary_enforcement.rs`](../../crates/tirith/tests/owned_boundary_enforcement.rs) checks refusal before side effects | Reuse the isolated PTY environments and markers for installed-package journeys |
| npm/artifacts | [`npm_audit_signatures`](../../crates/tirith/tests/fixtures/npm_audit_signatures), installed node_modules/browser fixtures, npm registry tests and existing wheel/artifact tests | npm signature metadata/receipts do not certify inspected or installed tarball bytes |

## Packaging, host evidence and measurements

Advertised installation paths in the baseline README include standalone release
archives, Homebrew, Cargo, npm, Debian/RPM packages, AUR, Nix, Scoop, Chocolatey,
mise and asdf. The [release workflow](../../.github/workflows/release.yml) contains
publication jobs for crates, Homebrew, npm, Scoop, Docker, Debian/RPM, Chocolatey
and AUR. A checked-in job is not proof of channel publication or acceptance.
Checked-in npm `package.json` versions are `0.3.2` build templates; inspect the
generated package at release time instead of rewriting them as a release fix.

Release build targets are macOS arm64/x86_64, Linux x86_64 GNU, Linux arm64
GNU/musl, and Windows x86_64 MSVC. Native artifact smoke jobs list macOS arm64,
Linux x86_64 GNU and Windows x86_64 MSVC, with additional Linux runtime jobs.
Cross-compilation does not certify native shell enforcement.

The [CI workflow](../../.github/workflows/ci.yml) declares stable workspace tests
on Linux/macOS/Windows, Linux Rust 1.83 workspace tests, stable fmt/clippy,
ThreatDB/workflow fixtures, dependency checks and a Linux Bash 5.3 shell job.
The [historical integration evidence](../release-evidence-web3-task-boundary.md)
explicitly refers to an older macOS branch tip; its counts and timings must not
be relabelled as 0.4.2 results. [Agent E2E](../../mcp/clients/E2E-CHECKLIST.md)
has unfilled version/pass cells. The PTY suite skips unavailable/old shells and
has ignored PowerShell/Nushell stubs. See the [acceptance matrix](acceptance-matrix.md)
for the first qualification target and open gates.

[`benches/budgets.txt`](../../crates/tirith-core/benches/budgets.txt) records
historical Apple arm64 measurements and per-Criterion-iteration ceilings. For
example, `tier1_no_match` covers ten inputs per iteration. These units are not
packaged startup or shell p95. The benchmark workflow checks absolute ceilings
and separately alerts at 115% relative change. No new numeric SLO is chosen here.

WP00 still needs measured packaged startup, cold/warm database, complete shell
hook, standalone/daemon, large policy/history/repo and concurrent-session paths.
Record OS/hardware/shell/binary digest, exact command, warmup, sample count,
iteration unit, p50/p95, memory/CPU/disk and contention. Proposed initial reference
environments are this macOS arm64 host for local characterization and one pinned
Linux x86_64 runner for shell/backend qualification; exact images and shell
versions must accompany results. Windows measurements remain a separate gate.

WP00 completion requires the missing 0.4.2 compatibility captures, measured
baselines, immutable test artifacts and a genuinely qualified setup matrix.
This inventory intentionally keeps those items open.
