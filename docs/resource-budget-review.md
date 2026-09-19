# Reviewing resource budgets

The evaluator supplies bounded validation and explicit reviewed-limit enforcement.
It does not choose thresholds. No new resource budget is enabled by this change;
the existing Criterion gate remains in place. This work covers the declared
serial CLI, HTTP and instrumented-core workloads, not all WP17 requirements.

## Two distinct outcomes

```sh
python3 scripts/check-resource-budgets.py --local-report resource-local-control.json --allocation-report resource-allocations.json --context resource-context.json --validate-only --output resource-evaluation.json
python3 scripts/check-resource-budgets.py --local-report resource-local-control.json --allocation-report resource-allocations.json --context resource-context.json --build-provenance resource-build-provenance.json --budget /absolute/path/reviewed-v2-budget.json --output resource-evaluation.json
```

`--validate-only` returns exit 0 and `validated_unbudgeted` for valid data. It never
reports a budget pass. Evaluation requires the release context and a budget whose
explicit status is `reviewed`: exit 0 means every selected limit passed; exit 1
means at least one was exceeded; exit 2 means an invalid/incomplete report,
unreviewed budget, incompatible host/workload/producer, unavailable resource,
unknown/duplicate metric, missing raw latency samples or insufficient samples.
The JSON result records report/context/budget/build-provenance hashes, each selected observation
and limit, and the number of unbudgeted metrics. A pass covers selected metrics only.

The parser rejects duplicate JSON keys, nonfinite/negative values, booleans in
numeric fields, impossible counts, oversized reports and unknown workload sets.
Raw counters and times are retained and summaries recomputed. Service CPU counters
must be monotonic, errors must be empty, and sampled memory maxima must match the
samples. Host architecture must agree between reports. The context must match
both report hashes and executable identities. Historical latency summaries can
be inventoried but cannot enforce a latency budget without retained raw samples.

## Budget document, version 2

Allocation reports and contexts remain schema v1. Local characterization accepts
historical schema v1 and owned-service schema v2. Historical `--validate-only` needs no new
provenance file and never enforces a budget. If supplied during validation,
`--build-provenance` must occur once and have a matching context. Enforcement
accepts only budget v2 with that input; v1 budgets refuse with an explicit migration
error. They are never silently promoted. Test limits are synthetic; the pinned
six-limit candidate below remains `draft` and cannot enforce a pass.
The exact required fields are:

| Field | Required contents |
| --- | --- |
| `schema_version`, `status` | `2`, `reviewed`; drafts refuse enforcement |
| `review`, `scope` | Review reference and the precise measured capability covered |
| `host`, `runner` | Exact context objects: OS/kernel/architecture, runner label/image/version, CPU model and logical CPU count |
| `producer_sha256` | Exact local measurement script and allocation-source hashes from reviewed context |
| `native_helper_sha256` | Required only when the local report is schema v2: exact owned-process helper hash, also recorded in the report. Historical schema-v1 budgets omit this field. |
| `history_fixture` | Exact `local` and `allocation` fixture row/byte objects |
| `workload_samples` | Exact local and allocation workload sample counts |
| `build_contract` | Exact `build_profile: "release"`, full `rustc_verbose` and `cargo_verbose`, `build_manifest_sha256` for root Cargo.toml/Cargo.lock, and repository `workflow_path` |
| `baseline_evidence` | At least three distinct `{run_id, context_sha256, source_revision, build_profile: "release", derivation, build_provenance_sha256, runner_boot_id}` records, maximum 100; run/context/provenance hashes and canonical nonzero boot UUIDs must be distinct |
| `limits` | 1–512 unique `{metric, unit, maximum, minimum_samples, rationale}` records |

Baseline references are review inputs, not authenticated merely by appearing in
JSON. The reviewer must retrieve their immutable contexts and reports, verify
hashes, source and workflow provenance, and inspect derivation. Three distinct
references are a structural minimum, not a statistical claim of adequate power.
Runner/producer changes require compatibility review and a new budget; there is
no wildcard host match or automatic rebaseline.

Build provenance retains its existing schema v1 and exact fields. Enforcement
requires clean tracked source, empty admission issues, matching source/run/release
profile/runner/sample identities, a canonical boot UUID, consistent workflow/event
revision, and matching compiler/build contract. A frozen reference must carry all
its cohort/tree/class/manifest expectations and satisfy them; an ordinary run
must have none of those expectations and measure its event source. Product source,
source tree, run, boot and workflow revision may advance consistently; the
measurement producers, compiler/Cargo output, root manifests, workflow path and
runner class may not change without compatibility review. Numeric type coercion
does not make a different contract equal. Extra/missing fields, duplicate JSON
keys, repeated provenance options and non-regular/linked/oversized inputs refuse.

These are checks of recorded facts, not host attestation. Schema-v1 provenance
does not independently record ambient build flags, every member manifest or
workflow file content; the reviewer must continue checking the actual workflow
and build inputs. Root manifest or lockfile changes require review even when a
product version change is otherwise legitimate. Baseline hashes remain review
references, not downloaded or authenticated by the evaluator.

Metric identifiers are listed by validation output. Examples include
`local.ordinary_check.latency_ms.p95`, `local.ordinary_check.cpu_ms.median`,
`local.ordinary_check.peak_rss_bytes.max`, and
`allocation.analysis_clean.requested_bytes.max`. Counters also expose separate
`subsequent` distributions. Units are respectively `ms`, `ms`, `bytes`, and
`bytes`; allocation event counts use `calls`. Instrumented durations use `ns`
and are explicitly named `instrumented_ns`. No arbitrary JSON pointer or unit
conversion is accepted. Requested metrics must exist and meet minimum samples.

`service.sampled_max_rss_bytes` is a sampled lower bound, not a kernel peak.
`service.cpu_observed_ms` is CPU during the measured service interval, not a
whole-process-tree total or fixed-duration utilization. Limits on those values
must account for the interval and fixed workload size. Service launch has one
observation per report, so it cannot satisfy a multi-sample limit. Existing
per-command RUSAGE_CHILDREN limits exclude service work and wrapper startup as
documented in the source report. The schema-v2 direct-start observation has no
completed-child CPU/RSS measurement: its service is still alive. Launcher reuse
retains its own completed-child resource sample.

## Existing release-profile evidence

PR 250's completed Performance job supplies one Linux x86_64 release-profile run:
[run 34695423009](https://github.com/sheeki03/tirith/actions/runs/34695423009/job/103557968455),
source `24be3f28a9c0fab85ce4962576f11f821df7eccd`, artifact ID `10298508642`.
The downloaded ZIP matches GitHub's artifact SHA-256
`3b05fc34472c57cfc35f4f261aff04e9c638b6c5f49d7b8fc156158bf62606be`.

| Input | SHA-256 |
| --- | --- |
| Local-control report | `45b92a1301bd1a380995c90d0a119032edc0c0b13f00235eb688df93da16af40` |
| Allocation report | `6cb94ac4431d47f1a96e255bd49654e3037b551ea3f78c89af2ea5e206168d94` |
| Measured CLI | `623ea62b38cc222ae502e387b9ab44b65358fde9b7170a60442c0fe74aeb4036` |
| Instrumented core harness | `2f95faa4f4775eacccbf2341e648479d559ec9ae2baaa9af5f7593803133f4d4` |

The report records Linux `6.17.0-1022-azure`, ten samples per repeated workload,
250,000 local history rows and 10,000 allocation-fixture rows. For orientation,
ordinary-check median/p95 were 81.415/224.024 ms; maximum completed-child RSS was
41,062,400 bytes. These are observations, not proposed ceilings. The core report
contains large first-sample allocation effects, so a median alone would omit
material initialization cost.

This is one CI run, not a published install or independent runner-variance study.
It lacks raw CLI/HTTP timings and the new CPU/image context. It can validate the
legacy schema and establish retained provenance, but cannot activate the new
latency gate. Local macOS debug measurements are useful diagnostics and are not
used to derive release thresholds. CI artifact retention is limited; preserve
this hash-verified evidence before relying on it as a long-term review reference.

## Pinned EPYC 7763 draft

[pr250-epyc7763-v2.draft.json](resource-budgets/pr250-epyc7763-v2.draft.json) records
six proposed byte ceilings with explicit 23–45% growth headroom. Status stays
`draft` pending review and actual injected-growth qualification. No workflow
invocation was changed. These are coarse regression limits, not timing guarantees.

The three [run 34709899626](https://github.com/sheeki03/tirith/actions/runs/34709899626)
attempts measured source `150e753a0adf8f9f13c8cc2b38f7a9325de40d91`, tree
`53123b9d0aa615d4135ce6c42f37abe6a5cdca16`, with Rust/Cargo 1.98.1 and LLVM 22.1.8.
All used Linux `6.17.0-1022-azure`, Ubuntu image `20260907.300.1`, EPYC 7763/four
logical CPUs, 100 samples, 250,000 local history rows (98,500,000 bytes), and 10,000
allocation history rows (4,360,000 bytes). Distinct native boot UUIDs, context and
provenance hashes are pinned in the draft. The actual workflow merge revision
`76e6b5ebd6fe05398aed43d38e8e003d79a60209` explicitly selected that older source;
it differs intentionally from both measured source and API PR head.

| Attempt / artifact ID | Retained ZIP SHA256, matched against GitHub API digest |
| --- | --- |
| 1 / 10302818712 | `39da04ffc040767bac371c0dd0944b2ba0d5a3e14093982aaa66949d381b679d` |
| 2 / 10303013611 | `c24714cd6df5a5fe02621d58d9bca1539f408a693e74df5126a117497ae5c79b` |
| 3 / 10303414140 | `e04df70d221d6d7d50c712819e88570a6dad5c71e03cbf277d615cc381aa17e0` |

Each archive contains the five expected reports/context/provenance files, whose
retained bytes and hashes were checked. Raw metrics recompute identically. Source
manifests and both producers were retrieved at the immutable measurement revision
and matched to Git blob/SHA256 identities. Recorded executable hashes match across
attempts; executable bytes are not retained in those artifacts, and build caches
were allowed. These are separate recorded boots/measurement executions, not proof
of different physical hosts or three independent clean compiler builds.

| Metric suffix (all units bytes) | Observed maximum | Draft ceiling |
| --- | ---: | ---: |
| `allocation.analysis_clean.requested_bytes.max` | 48,293,210 | 67,108,864 |
| `allocation.analysis_clean.subsequent.requested_bytes.max` | 106,269 | 131,072 |
| `allocation.analysis_url_pipeline.requested_bytes.max` | 72,048,388 | 100,663,296 |
| `allocation.analysis_url_pipeline.subsequent.requested_bytes.max` | 1,652,946 | 2,097,152 |
| `allocation.history_recent_100.requested_bytes.max` | 8,692,440 | 12,582,912 |
| `local.ordinary_check.peak_rss_bytes.max` | 41,046,016 | 50,331,648 |

All allocation count sequences match across the three attempts; ordinary-check
RSS spread is 0.10%. Whole-workload maxima retain large incremental initialization
costs that medians/p95 omit, while subsequent maxima separately constrain repeated
cost. Workloads share one ordered instrumented process, so first samples are not
fresh-process cold startup. Requested bytes count successful allocator requests
on one thread, including full realloc sizes; they are not live heap. RSS is the
completed-child kernel maximum for the exact CLI command, not whole-tree memory.

No new latency or service limits are proposed: ordinary-check first invocations
take 182–200 ms versus subsequent medians 77–81 ms, CLI-version p95 varies 32.74%,
and no OS cache was cleared. Service RSS is sampled; service CPU is quantized in
whole seconds over about 50 seconds and excludes startup/children. Three closely
spaced attempts do not establish long-term timing confidence. Keep unrelated
runner cohorts and failed/class-refused observations separate with their reasons.

## Next baseline and threshold review

1. Collect a release-profile reference on a pinned runner class, preserving source,
   workflow, context, report and executable hashes. Repeat independent jobs on
   multiple runner instances, recording CPU/image differences; do not pool unlike
   classes. Use enough within-run samples to resolve the chosen percentile, and
   enough independent runs to characterize runner variation. Ten samples make
   nearest-rank p95 the maximum and cannot give precise tail estimates.
2. Separate first-invocation and subsequent samples. Retain failed and outlying
   runs with their causes. Do not discard slow runs merely to obtain a budget.
   Compare a frozen baseline executable using identical argv/fixtures and
   alternating order where supported; self-comparison is a harness check, not a
   regression baseline. Allocation harnesses must share the reviewed measurement
   source and build settings. Record cold-cache workloads separately.
3. For each selected metric, retain per-run estimates and between-run spread,
   choose a justified noise allowance and an explicit tolerable regression, and
   document how those produce the ceiling. Review the largest observed first-run
   memory/allocation cost separately from steady-state cost. No automatic formula
   promotes an observed maximum into a safe or adequate threshold.
4. Exercise the evaluator against retained passing data, a known intentional
   slowdown, missing samples, identity changes and near-boundary fixtures. Review
   the coverage omissions, then change the CI invocation from `--validate-only`
   to an explicit checked-in reviewed budget path. Do not use an optional missing
   budget file to silently skip intended enforcement.

Full installed shell/agent operations, cold/warm DB, daemon/standalone comparisons,
concurrent sessions, native Windows resource accounting, disk I/O and final
release-artifact qualification remain separate work. No native product probes, publications, telemetry, performance optimizations or
threshold activation were performed for the tooling changes.


## Owned local service reports (local schema v2)

`measure-local-control.py` now requires the adjacent repository helper
`tools/qualification/mixed_audit_native.py` and a native Python/platform with
`os.waitid`, `WNOWAIT` and supported process-group observation. Unsupported
runtimes refuse before launching workloads; macOS system Python 3.9 is unsupported.
Python `-O`/`PYTHONOPTIMIZE` is refused because fixture assertions are required.

The producer starts the fixed `dashboard control-serve --startup-id <uuid>`
command as its retained direct child. Before HTTP/session or public-launcher
reuse, it opens bounded private discovery with `O_NOFOLLOW|O_NONBLOCK`, validates
regular-file ownership/mode/link count, and matches PID, startup ID, binary hash,
project and service identity. Neither discovery nor `ps` grants signal authority.
The sampled PID is the retained child. Diagnostics and credentials are omitted
from the retained lifecycle report, including failure paths.

Reuse invokes `dashboard --no-browser --json --require-service-id <uuid>`.
This option accepts only a canonical, non-nil UUID, supports `dashboard` and
`dashboard open`, and checks the private discovery and authenticated live service
identity, version, binary and project. Missing, dead or mismatched services refuse
before the launcher can start any service. A service exit after its handshake
cannot trigger replacement; the producer rechecks its retained child/discovery
and refuses the report. Ordinary dashboard launch without this option preserves
its existing start-or-reuse behavior. Older binaries without the option refuse
this new producer; they remain usable through the unchanged CLI baseline path.

Two distinct one-observation measurements replace `service_launch`:

- `service_direct_start`: elapsed time from owned direct spawn through validated
  discovery and an authenticated session. No completed-child resource sample.
- `service_launcher_reuse`: elapsed time and optional completed-child CPU/RSS for
  the public launcher reusing that already running service.

The six existing CLI workloads, per-command fresh RUSAGE wrappers, baseline
alternation, allocation producer, HTTP/history workloads and fixture sizes keep
their existing logic. Service sampling begins after launcher reuse; its RSS
remains a sampled lower bound and CPU remains display-precision cumulative time.
After `Job` returns and its retained handle is stored, discovery and service
workloads have a 1,200-second self alarm, bounded HTTP calls/output/sampling and
a separate bounded cleanup phase. The 12-second discovery deadline starts before
Job construction and rejects excess elapsed time once construction returns.
Authenticated session establishment follows discovery with its separate
40-second HTTP timeout; the 12 seconds do not bound complete readiness.
The shared helper does not offer an interruptible Job/Popen-construction timeout;
an arbitrary external interruption within that existing acquisition window is
not qualified here. The producer never arms its alarm in that window, refuses an
already-active alarm before workloads/creation, and changes no child signal mask.

Every path after retained Job assignment attempts quiesce when authenticated, then uses
only the retained native child to observe exit and clean its group. A draining
response alone is insufficient. A completed report requires exit 0, no native
helper failure, and all four facts: leader reaped, group signaled or absent,
group members observed exited while the leader was retained, and output EOF.
Unexpected service exit, forced timeout cleanup, incomplete sampling or any
missing cleanup fact refuses the measurement. The sampler must actually join for
a completed report (`sampler_joined: true`); a three-second join timeout is an
explicit failure. Its background thread reads only `ps`, with no Job or pipe
access, so refusal cleanup does not race mutable native-helper state. Discovery
is checked on the main thread before and after successful sampling. Failure
reports retain the known facts and remain ineligible as completed measurements.
The helper observes its owned process group, not descendants that deliberately
leave that group; this fixture selects the fixed service route without detached
replacement, and does not qualify arbitrary child behavior or full process trees.

Before workloads, the producer pins its own file hash and the native helper hash.
A changed file at report emission refuses the run; `harness_sha256` retains the
initial source hash, and schema v2 requires `harness_unchanged_during_run: true`.
These detect source changes during measurement, not host attestation or proof of
the compiler inputs. External expected source/tree and manifest checks remain
necessary, including when adding a dependency already present transitively.

The changed producer and helper dependency require new compatibility review and
new current-source control measurements. The EPYC 7763 schema-v1 draft and its
three references remain historical; this change neither activates nor reuses
that budget for new reports. Future enforcement of local schema v2 must pin both
the producer and native helper hashes. The validator preserves schema-v1 metric
names and introduces distinct direct-start/reuse names only for v2, so historical
launch measurements cannot silently be compared to reuse measurements.

`python3 scripts/test-measure-local-control.py` runs synthetic predicate/failure
fixtures without launching any candidate or native Job. Adding `--native` enables
two bounded inert Python-child cleanup fixtures; they are process-helper tests,
not Tirith service or resource qualification. Actual direct service startup,
launcher reuse, cleanup and current-source distributions still require native
candidate runs, with externally expected source/tree binding. Do not relabel a
frozen reference workflow rerun as a candidate growth experiment.
