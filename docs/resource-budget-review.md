# Reviewing resource budgets

The evaluator supplies bounded validation and explicit reviewed-limit enforcement.
It does not choose thresholds. No new resource budget is enabled by this change;
the existing Criterion gate remains in place. This work covers the declared
serial CLI, HTTP and instrumented-core workloads, not all WP17 requirements.

## Two distinct outcomes

```sh
python3 scripts/check-resource-budgets.py --local-report resource-local-control.json --allocation-report resource-allocations.json --context resource-context.json --validate-only --output resource-evaluation.json
python3 scripts/check-resource-budgets.py --local-report resource-local-control.json --allocation-report resource-allocations.json --context resource-context.json --budget /absolute/path/reviewed-budget.json --output resource-evaluation.json
```

`--validate-only` returns exit 0 and `validated_unbudgeted` for valid data. It never
reports a budget pass. Evaluation requires the release context and a budget whose
explicit status is `reviewed`: exit 0 means every selected limit passed; exit 1
means at least one was exceeded; exit 2 means an invalid/incomplete report,
unreviewed budget, incompatible host/workload/producer, unavailable resource,
unknown/duplicate metric, missing raw latency samples or insufficient samples.
The JSON result records report/context/budget hashes, each selected observation
and limit, and the number of unbudgeted metrics. A pass covers selected metrics only.

The parser rejects duplicate JSON keys, nonfinite/negative values, booleans in
numeric fields, impossible counts, oversized reports and unknown workload sets.
Raw counters and times are retained and summaries recomputed. Service CPU counters
must be monotonic, errors must be empty, and sampled memory maxima must match the
samples. Host architecture must agree between reports. The context must match
both report hashes and executable identities. Historical latency summaries can
be inventoried but cannot enforce a latency budget without retained raw samples.

## Budget document, version 1

No example numerical ceilings are provided: copy actual reviewed limits, not a
placeholder. The test suite uses conspicuously synthetic fixture limits only.
The exact required fields are:

| Field | Required contents |
| --- | --- |
| `schema_version`, `status` | `1`, `reviewed`; drafts refuse enforcement |
| `review`, `scope` | Review reference and the precise measured capability covered |
| `host`, `runner` | Exact context objects: OS/kernel/architecture, runner label/image/version, CPU model and logical CPU count |
| `producer_sha256` | Exact local measurement script and allocation-source hashes from reviewed context |
| `history_fixture` | Exact `local` and `allocation` fixture row/byte objects |
| `workload_samples` | Exact local and allocation workload sample counts |
| `baseline_evidence` | At least three distinct `{run_id, context_sha256, source_revision, build_profile: "release", derivation}` records, maximum 100 |
| `limits` | 1–512 unique `{metric, unit, maximum, minimum_samples, rationale}` records |

Baseline references are review inputs, not authenticated merely by appearing in
JSON. The reviewer must retrieve their immutable contexts and reports, verify
hashes, source and workflow provenance, and inspect derivation. Three distinct
references are a structural minimum, not a statistical claim of adequate power.
Runner/producer changes require compatibility review and a new budget; there is
no wildcard host match or automatic rebaseline.

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
per-command RUSAGE_CHILDREN limits exclude detached service work and wrapper
startup as documented in the source report.

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
release-artifact qualification remain separate work. This patch adds no probes,
publications, telemetry, performance optimizations or ungrounded thresholds.
