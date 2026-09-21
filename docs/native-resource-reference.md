# Native resource reference collection

This explicit dispatch mode in the existing Benchmarks workflow collects a new
macOS ARM cohort. Ordinary Linux PR/main jobs and the resource evaluator keep
their existing behavior. It does not
activate a resource budget. The retained historical Linux URL-first experiment
remains valid for its original cohort; the five Linux class refusals remain
refusals. A new cohort never relabels those attempts.

The current [GitHub runner specifications](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
list `macos-15` as a standard native three-core M1 runner. The collector requires
Darwin/ARM64 and an actual `Apple M1` CPU identity, records the native boot UUID,
kernel, image/version and CPU count, and rechecks all these facts between roles.
The current [macOS 15 ARM image manifest](https://github.com/actions/runner-images/blob/main/images/macos/macos-15-arm64-Readme.md)
lists Python 3.14.7 and Rust/Cargo 1.98.1. The collector still checks the actual
runtime and toolchain before using them.
The label is not an image-version attestation: an image/kernel change creates an
incompatible cohort that needs review. There is no automatic retry or automatic
replacement of expected host facts with the observed host.

## Collect three final-source baselines

Finish the product corrections, commit the source, and dispatch the existing `Benchmarks` workflow three times at that same immutable workflow/event revision with
`native_resource_experiment=baseline` and an empty protocol. Each dispatch is one native baseline
execution. Do not manufacture three run IDs from repetitions inside one job.
The reviewer requires three distinct run/context/provenance identities and real
native boot UUIDs. A baseline has no preapproved reference class; it reports
`baseline_collected_unbudgeted`, never a budget pass.

The workflow pins Rust 1.98.1 and uses the same local-control/allocation producers
and owned-process helper as the main workflow. It records all tracked Cargo and
toolchain/configuration manifest hashes, the source revision/tree before and
after compilation and measurement, producer/helper/checker identities, verbose
Rust/Cargo identities, Cargo JSON artifact records, executable hashes, Python
identity and 100 raw samples. Cargo artifacts are bound to the exact checkout
manifest and source file. Compiled dependencies can be reused within one job;
the records do not claim independent clean compiler builds or host attestation.

For each downloaded artifact, verify the archive against GitHub's reported
artifact digest and verify the extracted file bytes. Keep failed attempts and
off-class observations with their reasons. Then run the read-only review:

```text
python3 scripts/review-native-resource-baselines.py \
  --evidence /absolute/run-one/evidence \
  --evidence /absolute/run-two/evidence \
  --evidence /absolute/run-three/evidence \
  --output /absolute/new-baseline-review.json
```

This refuses mixed source/build/producer/helper/host cohorts and duplicate boots.
It also requires identical recorded Python versions and executable SHA-256 values;
resolved executable paths may differ between independent jobs. Collection rechecks
the Python executable identity after measurement and before returning a role.
It recomputes the six byte metrics and records per-run maxima/spread. It does not
choose a limit, mark a budget reviewed, or turn three runs into a statistical
confidence claim. Preserve its result alongside the downloaded artifacts.

## Review thresholds and immutable growth variants

Create a new schema-v2 budget using this cohort's exact contract and three actual
baseline evidence records. Set each ceiling only after reviewing the measured
maxima, runner variation and the tolerable regression. Do not copy Linux RSS
ceilings or observed host fields into an old reviewed budget. Keep the initial
new document `draft`; an independent review can approve its explicit six byte
ceilings for isolated detector qualification. This still does not activate CI.

The unchanged evaluator requires exact native host/runner, build, source producer,
helper and fixture contracts. The new budget's workflow path is
`sheeki03/tirith/.github/workflows/bench.yml`. The existing workflow is already
registered on the default branch, so this explicit mode can run from the reviewed
cycle branch before merging. No new workflow registration is needed.
All repeated workloads have 100 samples and subsequent distributions have 99.
The six supported metrics and predeclared mutation doses remain:

| Experiment | Selected byte metric | Dose |
| --- | --- | ---: |
| clean_first | allocation.analysis_clean.requested_bytes.max | 33,554,432 |
| clean_subsequent | allocation.analysis_clean.subsequent.requested_bytes.max | 32,768 |
| url_first | allocation.analysis_url_pipeline.requested_bytes.max | 33,554,432 |
| url_subsequent | allocation.analysis_url_pipeline.subsequent.requested_bytes.max | 524,288 |
| history_requests | allocation.history_recent_100.requested_bytes.max | 4,194,304 |
| ordinary_rss | local.ordinary_check.peak_rss_bytes.max | 16,777,216 |

Port the previously reviewed zero-dose/control and growth mutations onto the
exact final baseline source. Each variant may change only the declared product
file; producers, manifests, checker, helper and all other files must be unchanged.
Review the actual mutation and confirm its selector matches the unchanged
producer order. The allocation must be real, page-touched and retained for the
intended lifetime. These temporary mutation commits are qualification inputs and
must not be merged into product source. If a newly justified threshold needs a
different injected dose, review and update the protocol/collector before running
the experiment; do not adapt the dose to make a failed attempt pass.

Commit a reviewed protocol with exactly these fields:

```text
schema_version: 1
status: reviewed
review: concrete retained review reference
cohort: explicit new native cohort name
base_revision: full immutable final-source commit
base_tree: exact Git tree
budget_path: tracked path to the separately reviewed schema-v2 budget
budget_sha256: SHA-256 of its exact file bytes
checker_sha256: SHA-256 of scripts/check-resource-budgets.py
python_runtime: version and sha256 copied exactly from the baseline review contract
experiments:
  <one of the six experiment names>:
    control: {revision: <commit>, tree: <tree>, source_sha256: <product-file SHA-256>}
    growth: {revision: <commit>, tree: <tree>, source_sha256: <product-file SHA-256>}
```

The protocol must contain genuine reviewed values; the shape above is not a
completed manifest. Both variant commits must be present in the fetched Git
history. It is valid for the workflow/controller commit to be newer than its
explicitly selected product variant; the provenance records both and requires
the reviewed source tree, manifests and native cohort. The workflow rejects a
different class before Cargo or product measurements. The base and both variant
trees are verified before collection; only the reviewed one-file mutations are
admitted.
The closed `python_runtime` object contains exactly `version` and `sha256` from
the baseline review contract. Both pair roles must match it before any build;
independent installation paths may differ.

Every retained baseline revision in the reviewed budget must equal the protocol
base revision. That immutable commit must resolve to the declared base tree, so
matching compilers and producer hashes cannot substitute an unrelated product base.

## Run each pair in one allocated job

Dispatch the existing Benchmarks workflow once per experiment using
`native_resource_experiment=<name>` and
`native_resource_protocol=<tracked protocol path>`. Leave
`collect_pinned_reference=false`; mixed native/legacy reference modes refuse. The
collector builds/measures control, then growth, serially on the same retained
native boot. It requires identical boot, runner, class, run, workflow and compiler
facts for the pair. Separate boot identity is required across baseline runs;
identical boot identity is required within a growth pair. Neither is substituted
for the other. A CPU selected for another Actions job is irrelevant to this pair.

The control must pass all six explicitly reviewed ceilings. Growth must exceed
exactly its selected ceiling, have a distinct relevant executable hash, and meet
the predeclared raw allocation delta or sustained RSS condition. Other selected
workloads must stay within the allowed delta. The existing strict evaluator is
called for both roles. A failure stays refused; no result or budget is rewritten.
All six experiments must qualify for this new cohort, even though the historical
Linux URL-first result remains separately valid.

The workflow attempts to upload source/build/host records, raw producer reports,
Cargo logs and the final result even after failure. The existing local producer
owns its service and reports real cleanup facts. This collector's tool-process
timeout handling does not claim arbitrary compiler descendant cleanup or cleanup
after an external job interruption. GitHub job cancellation can prevent artifact
upload; inspect the actual job result rather than assuming retention succeeded.

## Activate only after concrete review

After the three final-source baselines and six growth results are retained and
reviewed, add an explicit Mac resource gate using the reviewed budget path and
100 samples. Pass `--build-provenance` to the unchanged evaluator. A draft budget,
missing review, mismatch or missing file must fail, never silently skip the gate.
Keep the ordinary Linux Criterion gate unchanged. Do not enforce the Mac budget
against Linux reports. Image/compiler/producer/manifest changes require a new
compatibility review and budget; there is no wildcard runner class.

This lane covers the six selected byte metrics. Full hook/host-adapter time,
cold/warm database work, daemon/standalone behavior, concurrency, disk growth,
cache invalidation, Windows accounting and final release-artifact qualification
remain separate WP17 requirements.
