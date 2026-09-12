# Implementation verification

Run date: 2026-09-12. Source: the reviewed foundation implementation on
`codex/next-cycle-foundations`, based on
`7fd35101568bb06ee0d361dc1d4a4d193c5f60fd` (0.4.2).
Host: macOS / Darwin 27.0.0 arm64, Rust 1.98.0, Cargo 1.98.0.

All Cargo commands ran from the implementation checkout with
a shared `CARGO_TARGET_DIR` to reuse existing dependencies.
Subprocess integration tests use test-owned user, policy, audit and cache roots.
The existing build directory is not an installed/released package. No changes
were made to the user's source edits in the original checkout.

| Check | Result |
| --- | --- |
| `cargo test --locked -p tirith-core --lib policy_snapshot::tests -- --test-threads=1` | Passed: 3 tests. These are included again in the combined 151-test run below, not counted twice. |
| `cargo test --locked -p tirith-core --lib mcp:: -- --test-threads=1` | Passed: 219 tests; no ignored tests in this selection. |
| `cargo test --locked -p tirith-core --lib -- output::tests audit_tune::tests redact::tests policy_snapshot::tests force_full_runner_evaluates_regex_rule_and_returns_effective_policy --test-threads=1 --quiet` | Passed: 151 tests; no ignored tests in this selection. |
| `cargo test --locked -p tirith --test policy_effective_snapshot --test policy_tune_decisions --test c00_cli_compatibility --test help_snapshots -- --test-threads=1 --quiet` | Passed: 5 policy-snapshot, 3 tuning, 2 legacy compatibility and 209 help tests. |
| `cargo test --locked -p tirith --bin tirith cli::policy::tests -- --test-threads=1 --quiet` | Passed: 23 tests, including the 5,000-key collision regression. |
| `cargo test --locked -p tirith-core --test c00_contracts --test policy_integration -- --test-threads=1 --quiet` | Passed: 5 frozen core contracts and 46 policy integration tests. |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | Passed with no warnings. |
| `cargo fmt --all --check` and `git diff --check` | Passed. |
| Documentation relative links | Checked; all existing targets resolve. |
| Independent code review and follow-up | Completed; strict-warning wording, dynamic map-key privacy and collision complexity findings fixed, no remaining substantive findings. |

The selected runs cover **663 distinct passing tests**, with no failures or
ignored tests in those selections. The initial three snapshot tests are counted
once. Filtered-out tests are outside this evidence.

These are targeted source and CLI regression checks on this host. They do not
replace the full workspace suite, Rust 1.83 checks, Linux/Windows tests,
installed-package/real-agent certification, performance measurement, or release
artifact checks. The snapshot tests explicitly exercise deterministic remote
transport refusal, not a live authenticated policy service. Complete remote
freshness/revision and native host evidence remains open in the acceptance
matrix. No release gate is closed by this record.

## Subsequent implementation checks (in progress)

The earlier 663-test result applies only to the foundation commit `6b83e302`.
The larger working-tree implementation has separate partial evidence:

- Core profile selection/ownership tests: 7 passed.
- Core trust grant tests: 6 passed before later identity strengthening.
- Core evaluation/output/contracts/escalation/session selection: 189 passed,
  one new evaluation fixture failed because it expected `pipe_to_interpreter`
  for a curl pipeline. The fixture now correctly expects `curl_pipe_shell`;
  the correction is pending recompilation and rerun.
- Bounded history selection: 16 passed (five new history tests and eleven
  registry-history tests). This includes a 300 MiB source, oversized-line
  forward progress, partial appends, retry identity and source replacement.
  Later timestamp/filter spelling changes are pending rerun.
- Core snapshot selection: 10 passed and one fixture used a nonexistent policy
  field. The fixture now changes `scan.require_complete`; later cache and
  operator-destination tests are pending recompilation.
- ThreatDB Python operational recovery tests, source watcher tests, transactional
  fetch fixtures and actionlint passed before the final compiled test batch.
- Packaged shell certificate Python tests: four passed, including ambiguous
  archive entry identities; native Bash/Zsh/Fish script syntax checks passed.
- Embedded dashboard JavaScript passes `node --check`. The service and browser
  workflows are not yet qualified by that syntax check.

A consolidated `cargo check --locked --workspace --all-targets` is in progress
for the full working tree. Complete current-revision core/CLI/service tests,
Clippy, formatting, native platform checks and browser evidence remain required.

## Current working-tree checkpoint (2026-09-12)

The core library executable built before the latest npm/aggregate additions ran
its complete suite: **5,812 passed, 2 ignored, 0 failed**, in 364.56 seconds.
The log is `/tmp/tirith-cycle-core-full-runtime.log`; this does not certify later
source edits or native platforms absent from that run. The captured working
inputs and manifest for the corresponding control build are kept in the local
evidence directory `control-build-inputs`.

The associated workspace all-target check passed. Selected current core tests
(159/159), real control-service integration tests (2/2), bounded history CLI tests
(2/2), and policy simulation integration tests (3/3) passed. The profile suite
exposed an undo failure after unrelated personal-policy edits, and a unit test
still assumed denial could not create a coordination lock. Both now have source
fixes, awaiting relink and regression execution.

Chromium exercised all six pages against the real candidate, hostile history
rendering, profile preview/apply/undo, and scoped exception add/explain/revoke.
The narrow-layout assertion found overflow from long project paths; wrapping is
fixed in source and awaits the next browser run. No complete browser pass is
claimed from a run that ended on that assertion. Subsequent browser tests also
cover reopening saved operations and owned shell setup/undo.

## Integrated CLI checkpoint before retention and lifecycle adapters

The `integrated-cli-build-inputs` source manifest identifies the candidate with
CLI SHA-256 `482e05633bb37099ea2f507b7ed15fdc9edcf96f20272e8af5baa641852321cb`.
On this candidate:

| Selection | Result |
| --- | --- |
| Shared operation, profile/settings, control, trust, lifecycle and npm unit tests | 63 passed |
| Profile lifecycle subprocess tests | 8 passed |
| npm inspection/comparison subprocess tests | 2 passed |
| History subprocess tests | 2 passed |
| Policy simulation subprocess tests | 3 passed |
| Selected core npm, aggregate and self-update tests | 67 passed on the corresponding core build |
| Packaged macOS Bash/Zsh/Fish shell checkpoint | 27 passed: 17 Bash, 4 Zsh, 6 Fish |
| Control subprocess suite | 3 passed; one service startup timed out under concurrent hashing load |
| Isolated rerun of that control test | Passed |
| Chromium dashboard launch | Timed out before browser workflow assertions; no browser pass claimed |

Native sampling identified repeated software SHA-256 hashing of the large debug
test executable during retained-identity checks. The development/test profile
now optimizes only the SHA dependency; release compilation and exact-byte
identity requirements are unchanged. This change requires a new candidate and
reverification and is not a release performance measurement.

The new retention, reviewed rollout, support selection/export, feedback,
private-file edit, lifecycle worker and ARM production changes have later
source manifests. The first combined typecheck found four adapter compile
errors; the second found one optional undo-document test assignment. These were
fixed before the `private-export-test-build-inputs` linked test build. Runtime
results for that checkpoint are recorded below; the earlier counts do not certify it.

Independent review of those adapters also found and corrected custom DLP/home
replacement ordering, missing selected-history projection, excessive RFC3339
fraction storage, scope mismatch for CLI audit apply, empty compensation reuse
and privacy-mode drift on feedback writes. Support exports now use the shared
policy/task-authorized private-file operation rather than a direct writer.
Regression fixtures for these fixes passed on the linked candidate below.

No native Windows/Nushell/PowerShell qualification, real-agent certification,
beginner pilot, published release, or full G0–G3 completion is claimed here.

## Private export and retained lifecycle test checkpoint

The `private-export-test-build-inputs` capture linked successfully in 5m 57s.
Candidate CLI SHA-256:
`e811d8cc999dd24294c6f30e22a62a413aee2170a0d48c48c17f441f990cc270`.
All **198 selected tests passed** on the captured macOS candidate:

- 84 core npm/aggregate/update/retention/rollout/task-family tests (4.56s).
- 85 CLI control/operation/private-file/shell/profile/trust/lifecycle/support
  unit tests (77.52s).
- 4 support export, 3 feedback, 3 rollout, 8 profile lifecycle, 2 history,
  3 simulation, 2 npm CLI and 4 real service subprocess tests.

The four service tests completed in 12.91s, including the startup case that
previously timed out. This is a debug candidate observation, not a general
performance guarantee. Existing unused legacy trust/doctor helpers still emit
warnings and must be reconciled before the final strict Clippy check.

The first expanded Chromium run reached audit rotation after profile,
exception, feedback and support-download workflows. Rotation refused the
synthetic unchained history tail as required. The browser fixture now appends a
real `hook-event` audit-writer record before rotation. After also correcting the
test's wrapping-label dropdown selector, the expanded browser run passed all
12 workflows. Evidence is `private-export-browser-final-fixture/browser-results.json`
with wide/narrow screenshots. This includes feedback apply/undo, selected support
download, exact audit rotation/undo, impact review across activation/undo, saved
operation recovery, shell setup/undo and zero narrow-screen horizontal overflow.
No browser JavaScript errors were observed.

The full core test binary from this same capture subsequently passed **5,862
tests**, with **two ignored and zero failures**, in 504.41 seconds. This does
not include later project review, caller-shell verification, archive controls,
or signing-drift changes, which require the next captured build.

Later review identified additional work before release: signing-key drift
guards for retention, partial-publication cancellation reporting, idempotent
lifecycle apply responses and the native ARM initial-breakpoint resume path.
Passing this checkpoint does not close those findings or certify later edits.

## Published 0.4.2 baseline and legacy trust compatibility

The published `tirith-aarch64-apple-darwin.tar.gz` from tag `v0.4.2` was
retrieved separately from the implementation build. Its SHA-256 is
`551f9a6ebf58344e7d0aa06bcc78d7a4f2f7b44b8011be563e0a91976cc9c4df`
and matches the published checksum document. Cosign verified that document
against the GitHub Actions issuer and the exact release-workflow identity
`https://github.com/sheeki03/tirith/.github/workflows/release.yml@refs/tags/v0.4.2`.
The extracted executable SHA-256 is
`873d8834902dbc47f339f79088d0a839f8932f5a8c34dcaedacb60fa6f2d0922`.

Eight isolated baseline commands captured version, help, unconfigured status,
quick doctor, effective policy, a clean check, a blocked pipe-to-shell check and
an empty trust listing. The unconfigured status exit and blocked-command exit
were preserved as expected failures, not relabelled as healthy states. Neither
check executed its input command.

Five compatibility assertions passed against that actual old executable and
the `e811d8cc999dd24294c6f30e22a62a413aee2170a0d48c48c17f441f990cc270`
candidate. A newly created one-hour, rule-specific project grant allowed the
candidate's enrolled project and blocked its sibling. The released 0.4.2
executable blocked both. It also continued blocking when the new grant envelope
was copied into the legacy trust-store location. Evidence is retained in
`baseline-0.4.2-macos/contracts.json`, `signature-verification.log` and
`legacy-trust-compatibility.json`. These checks do not replace the remaining
copy/move, worktree, expiry, native-platform and final-candidate matrix.

## Native Linux ARM production launcher checkpoint

The captured source snapshot
`5c4d99e5e0cdca59a1a7705b1ccce4efb6cfbd5193c62290009cd7d425937645`
built with Rust 1.83 on native Linux aarch64. The resulting GNU executable
SHA-256 is `b9427f237c665b6ceef7adb7b6bf78d2aaa4872051ac4075d7872a3d94588237`.
Nine production-launcher cases passed as UID 65534 on Linux 6.12.76 aarch64:
clean execution, child exit propagation, network and io_uring denial,
namespace/ptrace denial, project/outside-file isolation, secret-environment
removal, memory/file-descriptor limits, fork/wait and inherited-handle closure,
and bounded-output termination. Cases combine related assertions; every case
confirmed required coverage and cleanup. The exact case list, receipts and
fixture image identity are retained in `wp27/production/qualification-v2.json`.
No emulator was used. Cancellation, musl, release-artifact qualification and
later source revisions remain separate evidence requirements.

## Shell trace and inherited-export regressions

The standalone native shell suite passed **96/96 cases** with no failures on
system Bash 3.2, current Bash, Zsh and Fish, against both source and embedded
hook copies. Controlled fake capabilities were used throughout. The assertions
cover tracing enabled/disabled, verifier and ordinary receipt callbacks, full
hook registration and inherited exported placeholders. Each relevant body ran
exactly once, capability/raw hook state remained absent from trace output,
ordinary child processes inherited no capability, and caller tracing state was
restored. Evidence is `tirith-shell-trace-final.jsonl`.

The preceding 64-case callback-only suite had exposed 32 trace failures before
the fix. Expanded source-registration cases additionally exposed 16 inherited
export failures before explicit unexporting was added. These are shell-source
regressions; they do not replace actual receipt/caller-shell PTY tests on the
next linked executable. A later independent status-proof review also required
a fresh intercepted status command for every verified result; its newly added
core regression still awaits the next candidate.
