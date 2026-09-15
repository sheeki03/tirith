# Resource measurements

The Performance CI job retains two JSON reports alongside the existing Criterion
results. Criterion's absolute budgets remain enforced. Resource reports
characterize one runner and the recorded executable bytes. The resource evaluator
validates metric and provenance contracts, but no allocation, memory or timing
threshold is enabled until independent release measurements support reviewed limits.

`resource-allocations.json` comes from the `resource_counts` core benchmark. A
thread-local counter wraps Rust's `System` global allocator for each measured
workload. It counts successful allocation, zeroed allocation, reallocation and
deallocation requests. Requested bytes include the full new size of each
reallocation, rather than its increase over the previous size. A direct
allocation/reallocation/deallocation self-check runs before measurement. Fixture
setup, result serialization and report publication occur outside the counter.

The allocation report covers clean scanning, complete analysis, a URL pipeline,
obfuscated output, custom policy and recent history. It uses disposable policy,
cache and history roots. It does not measure native allocations that bypass the
Rust global allocator, other threads, children, live heap size, CLI startup or a
complete interactive shell/agent operation. Its instrumented elapsed times are
not interchangeable with ordinary CLI timings. Process and OS caches are not
reset, and neither report claims a cold-cache sample.

`resource-local-control.json` runs the release CLI and read-only local control
routes against an isolated 250,000-row history fixture. `--resources` uses a fresh
Python wrapper for each CLI command and collects `RUSAGE_CHILDREN` after that
command completes. It records completed-child user/system CPU and the kernel's
maximum resident set size in bytes. The measured interval excludes the wrapper's
own startup. Peak RSS is the largest completed child's peak, not the sum of a
simultaneous process tree. In particular, the launcher sample does not account
for a detached dashboard service that remains alive after launch.

On Linux and macOS, a separate `service_resources` series observes only the new
fixture service between the launch response and quiesce. The sampler checks its
private service ID and binary hash, then samples the recorded PID's RSS and
cumulative CPU time at nominal 250-ms intervals, up to 4,800 samples. It checks
the PID's unchanged `ps lstart` value, whose start-time precision is one second;
this is a measurement consistency check, not a kernel process capability. No
process arguments or service credentials enter the report. The observed maximum
RSS is a lower bound on peak memory, and CPU is the difference between the first
and last cumulative samples at the platform's display precision. These values
exclude service startup and children. Unexpected identity changes or sampler
errors are reported rather than silently treated as complete coverage. Other
platforms report this sampler as unsupported.

The CLI report also records request latency, response limits, history inspection
bounds and fixture file sizes. File sizes describe only regular files in the
private fixture; they are not disk I/O counters or an estimate of a user's data.
Optional baseline comparisons use identical supported CLI arguments, alternate
candidate/baseline order and record both executable hashes. They do not create a
universal performance target. CLI and HTTP distributions retain their original
ordered timing samples. Their p95 uses the nearest-rank definition; this corrects
the prior upward index at sample counts divisible by twenty. First and subsequent
samples remain separate. Instrumented core timings retain their historical
upper-middle p50 field; the evaluator's explicitly named median is recomputed
from raw samples. These statistics are not interchangeable.

CI records a same-job context manifest with report/source/executable hashes,
release profile, source revision, run attempt, kernel, architecture, runner image,
CPU model and logical CPU count. It validates finite numeric values, integer count
types, sample counts, summaries against raw samples, complete known workloads,
resource availability, service sampling errors and cross-report identity. Missing
or malformed metrics fail the validation step. Reports remain bounded to one MiB.
The context records provenance; it is not a signature or independent attestation
of a compiler or machine. Workflow/source review must establish its origin.

Without a reviewed budget, the result is explicitly `validated_unbudgeted`, never
a resource-budget pass. CI retains the context and evaluation with the two source
reports, without repository write permission or automatic baseline publication.
See [resource budget review](resource-budget-review.md) for the enforcement format,
available evidence and remaining baseline work.

Run the same characterization locally with explicit output paths:

```sh
cargo bench --locked -p tirith-core --bench resource_counts -- --output /absolute/path/resource-allocations.json --samples 10
cargo build --release --locked -p tirith --bin tirith
python3 scripts/measure-local-control.py --binary /absolute/path/target/release/tirith --output /absolute/path/resource-local-control.json --resources --samples 10 --history-rows 250000
```
