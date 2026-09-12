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

## Integrated review and resource measurements

The integrated `reviewed-shell-cache-browser-lifetime-inputs` snapshot passed
`cargo fmt --all --check` and strict
`cargo clippy --workspace --all-targets --locked -- -D warnings` (6m31s).
This includes the bounded cache capture, retained project-root checks, fresh
shell-status proof and complete npm/privacy diagnostic capture. A corrected
failed-rollback integration fixture then passed its targeted Clippy check.
The subsequent offline-probe and Linux readiness additions are included in
commit `71070bbbb02a3a6e5f96d335a048e92a7f048679`; their complete linked
recertification is in progress.

The exact ARM readiness policy and tests from source snapshot
`7d9788bfe34462c745b252038ac6d045265d08d940759fc82f9620c882b5d317`
compiled with Rust 1.83 and passed six native tests as UID 65534. They exercised
eventfd/epoll readiness, polling and timers while retaining socket, io_uring,
namespace and arbitrary-signal denial. These are isolated production-policy
tests; the complete launcher and interruption cases require separate results.

`scripts/measure-local-control.py` accepts `--binary`, `--output`, `--samples`,
`--history-rows` and an optional `--baseline` executable. It measures identical
version, quick-doctor, local-policy and ordinary-check commands against both
executables, alternating order, plus candidate-only policy/profile and service
requests. The report records exact executable hashes, first and subsequent
samples, median/p95 distributions and enforced history/response bounds. First
samples do not imply cold OS caches. Ambient host contention is uncontrolled,
and debug-versus-release ratios do not define release regression budgets.

A three-sample runner validation against the previously linked `e811d8cc`
candidate and signed 0.4.2 baseline passed all eleven measurements and bounds
with a 10,000-row, 3,940,000-byte history fixture. It is recorded in
`performance-runner-checkpoint.json`; final packaged resource measurements,
peak memory/CPU/allocation measurements and reviewed budgets remain pending.

## Linked offline-readiness candidate and follow-up regressions

The `offline-probe-readiness-test-build-inputs` capture linked successfully in
10m52s. Its executable SHA-256 is
`b2ba2d23c8091eaac111cbaefa3fa877617d2716aca20be808a92db838f360de`.
The selected core/CLI/integration run passed 173 tests and failed seven. The
failures identified root anchoring to a linked manifest, newest-record selection
in busy small logs, and fresh recommended-setup policy discovery, plus three
fixture problems (canonical pip version, stale-shell refusal precedence and
explicit history logging). These are recorded failures, not a passing candidate.
Fixes and expanded regressions await integrated recertification.

The same executable passed all 17 actual Chromium workflows in
`offline-readiness-browser-expanded-details/browser-results.json`, including
retained-root project review, npm inspection/comparison, six pages, hostile text,
feedback apply/undo, tuning, profiles, exceptions, saved operations, selected
support download, rotation/undo, segment export and irreversible deletion,
impact activation/undo, shell setup and combined setup with an existing policy.
Screenshots were visually inspected; no browser JavaScript errors occurred.
An expanded busy-history browser case is prepared for the next candidate.

The new history module, SHA-256
`84f252f14a7a3bd2c79b2d9eab9f6ea5aefe89f3cd92bc46dce4e177b13dcb79`,
passed ten isolated native tests linked against the frozen dependency graph.
They cover newest selection, forward compatibility, older pages, append/retry,
filter/direction invalidation, split-record recovery and progress over giant
records. Evidence is in `history-module-current`; this does not replace the
integrated CLI/API/browser run.

CI on `71070bbbb` passed strict Clippy, formatting, dependency policy, installer
fixtures, native ARM GNU/musl qualification and the performance workflow. Native
Linux/macOS/MSRV tests found the recommended-setup and completion-generation
regressions; Windows compilation found retained-handle thread ownership and an
unconditional Unix permission API. The Bash hook job found a fixture mutation
blocked by the actual hook. The release check found its read-only ARM job missing
from the validation-job classification. Fuzz preflight found one missing direct
dependency edge in its lockfile. Each failure is being fixed and rerun; none is
waived by the passing jobs.

## Resource runner validation and corrective candidate

The resource runner now accepts `--resources`. Each measured command runs under
one fresh wrapper that collects kernel child CPU time and peak RSS; the timed
interval excludes wrapper startup. CPU and memory records stay attached to the
same command and candidate/baseline role. Detached service memory, concurrent
process-tree totals and allocator activity are explicitly not measured by this
method. The fixture report records regular-file bytes before and after the run.

The retained `b2ba2d23` checkpoint passed a three-sample resource-runner check
with 10,000 history rows and all eleven request/response bounds. Fixture growth
was 2,481 bytes. A second self-comparison using the same executable for both
roles confirmed three separate resource samples per role for all four paired
commands; fixture growth was 4,362 bytes. Every completed-child RSS sample was
positive and CPU samples were nonnegative. Reports are
`resource-runner-checkpoint.json` and `resource-runner-self-comparison.json`.
The final checked runner SHA-256 is
`dcdd99ab38209aac758894ebdbc62b4d6ed88a2dacf5b400f866f2a547d4bc82`.
These validate the measurement tool; concurrent compilation made host contention
uncontrolled and these samples establish no release regression budget.

The `history-setup-native-fixes-inputs` capture passed formatting and strict
workspace/all-targets Clippy in 11m49s. Its selected test executables were linked
for integrated runtime verification. The capture includes a separately
hashed shell-conformance supplement: native Zsh binding changes now prepare the
helper-drift fixture without asking the active security hook to execute a
command it correctly blocks.

## History, setup and native-target corrective candidate

The corrected source capture linked in 16m20s. Candidate SHA-256 is
`11fde156220c6e9bf2cbfd7e26af0b7929b3850bc6c3cdabbdbb37f38bc04172`.
The focused run initially passed 307 tests and found one error in a newly added
feedback test: apply returns the stored operation status, whereas the test read
the dry-run preview shape. The corrected test now checks completed state, the
persisted event UUID and expectation, and unchanged audit bytes. All four feedback
tests passed on the same candidate. The reconciled selection passes **308 tests**
with no failures or ignored tests; the initial failure report and separately
hashed test supplement are retained. The complete core suite passed **5,892 tests**
with two existing ignored tests; the complete CLI unit suite passed **1,899 tests**
with two existing ignored tests. Both had zero failures. The report collector
initially selected an embedded child-test summary; the retained raw logs and
`*-verified-results.json` reconcile counts against the final anchored libtest
result without rerunning or discarding the original reports.

Five actual native caller-shell cases passed on this candidate: Bash allow/block
verification, Bash interceptor removal, Fish verification, Zsh helper replacement
and Zsh disabled interception. These confirm the full Darwin executable-identity
fix and actual helper-drift preparation. Packaged Bash/Zsh/Fish qualification
separately passed 32 cases. Four additional cases passed: three controlling-terminal
confirmation/refusal cases and the npm launcher across all three shells. Native
Claude 2.1.268 baseline checks passed allowed, blocked and explicitly disabled
cases; the binary and each executed configuration stayed unchanged. These results
do not qualify the separately prepared guarded-hook changes.

The first browser attempt reached the combined three-step setup but exceeded its
40-second fixture wait while two steps were applied and the third was applying.
The fixture now allows a bounded 120-second wait for combined apply/undo and
records both elapsed times; this is not a release latency budget. A second attempt
correctly refused mutation after a test relink replaced the build-path executable
identity. Final browser recertification uses a retained candidate outside Cargo's
mutable output path. Both failed attempts remain recorded; neither is counted as
a successful browser run. A third retained-binary attempt passed fourteen checks
but remained at a planned impact operation after Apply; its request timeline was
not recorded and the cause remains unresolved. The instrumented focused five-flow
reproduction passed impact apply/undo, shell setup, combined setup and narrow
layout with actual operation transitions recorded. The full instrumented run subsequently passed all **eighteen workflows** on the
retained candidate, including busy-history pagination, impact review and combined
setup. Binary identity remained unchanged. That pass does not erase the earlier
intermittent result: independent review found same-operation stale-response and
dialog-replacement races. A guarded UI and deterministic delayed-response
regressions are being prepared as a separate correction.

## Bounded npm-reader fuzz checkpoint

The npm artifact reader completed **36,320 executions in 301 seconds** with
AddressSanitizer, eleven inert seeds, a 256 KiB input ceiling, a 1 GiB RSS limit
and a ten-second per-input timeout. No crash artifact was produced; final reported
RSS was 453 MiB. The source was exactly `71070bbbb` plus the one-line fuzz lockfile
dependency correction. The isolated development build used Rust nightly
`1.100.0-nightly (0fc141305 2026-09-11)` and cargo-fuzz 0.13.2; the workflow uses
its separately pinned nightly. `npm-fuzz-71070/qualification.json` preserves the
source/lock/target hashes, seed hashes, executable identity, corpus and full log.
This is bounded fuzz evidence, not an exhaustive claim or a closed G2 gate.

A separate allocation-counter prototype linked against the corrective candidate's
core dependency graph and passed its known-layout counter self-check plus six
isolated three-sample workloads. It records thread-local Rust allocation requests
and full reallocation request sizes, excluding native allocation bypasses, other
threads, children and live-heap size. The 10,000-record fixture was 4,360,000 bytes.
Evidence is `allocation-runner-prototype-v2`; the production benchmark registration
and release-profile measurements remain pending.

## Corrective checkpoint CI follow-up

Checkpoint `13e18ca8` passes formatting, Clippy, dependency policy, Bash hooks,
Linux/macOS install scripts, action-runtime checks, artifact transport and the
existing performance gate. The Linux/MSRV CLI unit suites pass 1,957 tests with
two existing ignores; macOS passes 1,899 with two existing ignores. Their later
C00 compatibility test rejects an added recovery field in legacy schema-3 command
JSON. The frozen fixture is retained; a separate opt-in schema-4 recovery format
is being prepared so ordinary JSON retains its existing shape.

Windows now compiles and reaches native tests, finding 47 CLI unit failures.
Many share private journal-directory ACL validation, and one finds an in-place
binary edit that metadata-only validation missed. These are open defects under
investigation, not permission checks to waive. The test workflow now uses
`--no-fail-fast` to report later executable failures in the same run while still
failing the required check.

### Retained audit-health, Claude and dashboard candidate

The next development candidate, SHA-256
`a70b8eba427c8cfbc20287c94102d0da59ce7d44a01e2f0e388f1baddcae156f`,
was retained before additional compatibility/native corrections. Its source
capture is `health-claude-ui-inputs` on `13e18ca88e6c923c1c2df547741735bb17dda930`;
the candidate manifest pins all seventeen linked test/benchmark executables.
This is a development executable, not a signed release artifact.

All eighteen complete browser journeys passed using its embedded assets and
real local service. The five separate delayed-response cases also passed with
no source override. The old embedded candidate failed the stale planned-status
negative control, demonstrating that the new response-order assertions detect
the original defect. Real Claude Code dispatch passed all nine configured-hook
and explicit boundary controls; the three boundary controls document behavior
outside the protection claim rather than expanding its scope.

The selected Rust runtime run completed with 310 passing tests and six failures.
Three failure-notice unit fixtures timed out on the shared filesystem-root setup
lock; the cross-process fixture then found no persisted notice. A generation
change was refused with a newly bounded snapshot error that the older assertion
did not recognize. The concurrent audit writer test assumed every call succeeds
and discarded its results; bounded lock waiting now explicitly reports refused
appends. These failures are retained as evidence and require correction or an
appropriately isolated verification of the documented contention behavior.
Passing browser or host tests do not substitute for those checks.

On pushed commit `13e18ca8`, the separate Fuzz, Benchmarks, Release workflow and
both native ARM containment checks completed successfully. The ordinary CI
workflow failed for legacy command JSON compatibility and native Windows
storage/identity/fixture defects described above. Release workflow success on a
branch is not evidence that a release was published. The next candidate preserves
the legacy schema and adds explicit schema-4 recovery selection, atomically
private Windows storage, and a retained executable write lease.


### Compatibility and private-storage candidate

The next retained native macOS development executable has SHA-256
`181aa10334856a5d6947e933c6b943086d5cdbb012d213b696917a0808a474ae`.
Its source capture is `compat-health-native-inputs-v2` on `13e18ca8`; its manifest
pins the CLI and eighteen linked harnesses. Unregistered npm installation drafts
are explicitly excluded from the compiled graph. All registered Rust input
hashes matched the capture before the executable and harnesses were retained.
The selected build completed in 13 minutes 21 seconds without warnings.
Strict workspace/all-target Clippy passed on these same registered sources in
4 minutes 20 seconds; formatting and diff checks passed.

All **385 focused checks passed**, with zero failures or ignores: 144 selected
core checks, 186 selected CLI checks, four compatibility checks, nine dashboard
API checks, five history checks, four feedback checks, eight profile lifecycle
checks, three local rollout checks, three tuning checks, two project-review
checks, four support-bundle checks and thirteen release-security checks. This
includes the schema-3/schema-4 compatibility correction and the audit-notice,
concurrent-writer and generation-change regressions that failed on the preceding
candidate. The production notice lock budget remains 25 milliseconds; the tests
exercise bounded refusal and use a longer explicit budget only for positive
unit-fixture creation. The cross-process integration retries the actual inert
check and verifies the unchanged verdict on every attempt.

The same source contains native Windows ownership/DACL and binary write-lease
corrections. A macOS pass does not validate those Windows branches; the next
native CI run must do so. Linux private-input namespace corrections have separate
primitive evidence, while the actual wheel pipeline remains under qualification.
The update dry-run side effect found during the lifecycle audit is a separate
pending correction and is not included in this executable.

### Receipt, npm staging and combined agent setup candidate

Retained macOS ARM development binary
`f703dad659d12899330f6c214ded5363f45dc6381d13afe5245fbe8190752f2e`
was built from `npm-receipt-claude-inputs-v2` on `24be3f28`. Its manifest pins
the CLI and fourteen test executables. The linked build completed in 14 minutes
44 seconds without warnings. Registered npm staging, runtime-pack models,
checkpoint extraction and schema-3 npm receipt types are included; npm execution
qualification still refuses installation.

The complete core unit suite passed **5,931 tests**, with two existing ignores.
The complete CLI unit suite passed **1,925 tests**, with two existing ignores.
Eleven selected integration targets passed **258 tests**, including frozen
contracts, freshly private saved receipts, explicit npm ecosystem routing,
tuning, profiles, rollout, feedback, dashboard transport, shell helpers and help.
The separate 502-case CLI integration executable recorded **498 passes, three
failures and one existing ignore**. The failures were the generated capability
table, an inherited-status assertion that expected a verified-looking prompt,
and a receipt error-message compatibility substring. The table was regenerated
with this exact compiled renderer and its isolated check passed. The other two
corrections require the next linked candidate. Earlier failures remain retained.

Real recommended setup, followed by actual host dispatch, passed all nine
configured-hook and explicit boundary cases on this binary. Every case used
the installed command and default user settings; there was no replacement of
the candidate command after setup. Allowed commands executed once; policy
blocks, missing interpreter/checker, hook crash and checker deadline cases
executed no marker. The three controls demonstrate limitations: disabled hooks,
a shorter host timeout and an unmatched tool each executed once. The deadline
case observed exactly one actual check start. A separate real MCP-only run
reported the candidate server connected while the policy-denied Bash marker
still executed once, confirming that tool availability alone is not interception.
These are named native host controls, not a beginner pilot or release certificate.

The first combined run exceeded its 120-second setup deadline under concurrent
test load. That failure is retained separately. A diagnostic allowed case with
a longer bound completed setup in 45.86 seconds, and the subsequent complete
nine-case run passed using the original bound. Profiling found full executable
rehashing at every shell mutation callback. A later correction retains native
input handles during each operation and rehashes when an operation resumes;
its whole-setup performance and integrated regressions require a new build.

The lifecycle dry-run regression passed with logging both enabled and disabled:
the fixture's files and directories were unchanged. PowerShell 7.6.6 native
testing against this binary and a separately pinned corrected hook passed 22
cases across redirected processes, real-terminal noninteractive invocations,
Enter and paste handling, missing checker/storage, unexpected checker exits,
recovery and exact multiline text. This is hook-source qualification on Unix,
not proof of a Windows terminal or a final packaged hook. A quick-exit Darwin
PTY cleanup failure was retained and fixed in the repeatable runner.

The Windows CI runner now inventories the actual compiled workspace harnesses
and runs the dashboard's nine tests under a disposable real standard account.
Its parser, inventory, result and process-bound contracts passed 26 local
checks. Native Windows logon, token, job, ACL and account cleanup remain unrun
until the next Windows job. Product refusal to start an elevated dashboard and
protected storage ACL checks are preserved.

### Retained shell input and packaged PowerShell candidate

Development binary `39f6acc9929cdb53fcd0f9a0b4d82187aadf8e6b50af54058085d40812e09d3a`
and nine linked test executables are retained under `retained-inputs-native-v3`.
The source capture is `retained-inputs-powershell-inputs-v3` on `24be3f28`; all
captured Rust and embedded asset hashes matched after linking. Strict workspace
Clippy with all targets and warnings denied passed on those sources.

All **445 selected tests passed**, with one existing ignore: 133 CLI unit tests,
274 core unit tests, five core compatibility contracts, four CLI compatibility
contracts, three receipt privacy cases, six shell helpers, eight profile lifecycle
cases, nine real dashboard API cases and the three corrected CLI integration
failures from the preceding candidate. The core selection's nested subprocess
results are not counted again. These tests include retained native input handles,
changed paths/content/permissions, resume rehashing, exact lease/precondition
binding and owned undo after an executable change.

The exact binary passed all eighteen complete embedded-browser workflows and
five separate delayed-response cases without a source-asset override. The
PowerShell hook materialized by this binary matched the reviewed hook digest
`9a8e1ef63e8d4a83618ffdda33ed3932037c30bc0d9300466059b1f53a14a35e`;
all 22 native Unix PowerShell 7.6.6 cases passed using those extracted bytes.
Native Windows terminal behavior remains separate.

The repeatable actual-host runner passed all nine recommended-setup cases, the
MCP-only boundary and retained-host reload observation on the same binary. It
used the native macOS ARM host 2.1.268 and normal isolated user settings. Complete
setup operations took 6.933–24.918 seconds under the unchanged 120-second bound;
these measurements include process cleanup and are not release performance
budgets or a controlled before/after comparison. Every requested setup step
completed and every executable, interpreter, alias and harness postcheck matched.
In the reload case, the next turn 0.003 seconds after publication omitted the
hook and executed once. The same host blocked after a policy recheck, 2.107
seconds after publication; a fresh host also blocked. This does not establish
immediate or universal hot reload. The evidence manifest is
`claude-repeatable-native-v3`, digest
`a4efd68cd64b22467fafe6a721523fd6ac12c337378136b97c16a95af8da6edd`.

The repeatable mixed-audit runner passed six native cases against the signed
official macOS 0.4.2 baseline: signed and unsigned sequential rotation, two mixed
concurrent-writer bursts, and an actual legacy descriptor held across completed
rotation. The rotator was paused only after observed lock ownership, the old
writer's open log descriptor was observed before truncation, and the unchanged
rotator resumed. Active inode identity remained stable, retained archive bytes
matched exactly, and both clients verified the archived and active chains. Undo
after later appends and rotation without the signing key refused without changing
the active log. Public fixture signing keys were removed after each case.
The runner and its 20 process/format/cleanup fixtures are registered under
`tools/qualification`; fixture results do not substitute for native client tests.

Subsequent public receipt-reader consolidation and private-input execution
qualification refusal have independent source review. A native package-backend
investigation invalidated the assumption
that read-only private mounts establish complete input-lifetime protection
against another same-user process. The experimental metadata/uv extensions are
not registered. Package execution is restricted at public and hidden
launch boundaries; ordinary capsules and static inspection retain separate
capability requirements. No earlier package primitive result qualifies this
unresolved boundary.

### Public receipt APIs and package qualification refusal

Development binary
`1a72833d6d2f8b3dffa13a57259c3b73c8856cc96661bf2937ceab89b0a6a936`
and seven linked test executables are retained under
`receipt-qualification-native-v4`, with source capture
`receipt-qualification-inputs-v4`. Strict workspace/all-target Clippy passed.
The captured core source hashes matched after linking; CLI sources matched
when its executables were retained, before the subsequent help-copy changes.

All **349 selected tests passed**, with one existing ignore: 253 core receipt
tests, 72 CLI package/checkpoint/receipt tests, twelve public package/inspection
and hidden-launch integration cases, five core compatibility contracts, four
CLI compatibility contracts and three receipt privacy cases. Nested subprocess
results are not counted again. Direct public Rust readers now share record,
inventory and cache bounds and requested identity checks; tests include wrong
embedded IDs, oversized records/inventories, symbolic links, mixed historical
schemas and cached-byte changes. Inspection remains separate from signature or
content verification and publication authority.

Valid public package-install requests refuse before resolver/network,
quarantine, checkpoint and execution effects in both supported output formats.
Private hidden launcher operands also refuse. Opt-in flags and administrator
access do not bypass qualification; ordinary capsule parsing and static artifact
inspection retain their own contracts. The focused refusal is also proposed
against current main in [PR 254](https://github.com/sheeki03/tirith/pull/254).
The cycle candidate results do not certify that separate branch.

The Windows runner now creates current-account children suspended, assigns them
to an owned kill-on-close Job, and resumes only after assignment. Both success
and expected-refusal results require confirmed leader reaping, an empty Job,
complete output drainage and no process/cleanup errors or descendant leak.
Independent review and 45 portable parser/process contracts passed, including
nineteen cleanup-result regressions. Native Windows process, token, handle-list,
logon, ACL and account cleanup behavior still requires the platform CI run.

The subsequent help-only CLI candidate
`7823f71e6a2523163241a49e47daf37a7cc44e1336a08e0bb87002f419822ad4`
retains source capture `help-claims-inputs-v5`; all captured Rust and embedded
asset hashes matched after linking. The complete help suite and selected public
package refusal, hidden launcher and static inspection integration checks passed.
No package execution path was enabled by the help/documentation corrections.

A repeat of the six native mixed-audit cases on candidate `1a72833` passed five;
the unsigned held-writer case failed when its native descriptor observer exceeded
the unchanged three-second deadline during compilation load. That failed report
is retained separately from subsequent runs. Observation timeout does not count
as a completed descriptor-crossing proof.
