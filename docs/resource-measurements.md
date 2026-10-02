# Resource measurements

The Performance CI job (`.github/workflows/bench.yml`, ubuntu-latest) has two
absolute gates:

- Criterion timing ceilings for the `perf` benchmark, checked by
  `scripts/check-bench-budgets.sh` against `crates/tirith-core/benches/budgets.txt`.
- Allocation ceilings for the `resource_counts` benchmark, checked by the
  benchmark itself against `crates/tirith-core/benches/resource_ceilings.json`.

## What `resource_counts` measures

A thread-local counter wraps Rust's `System` global allocator for each measured
workload. It counts successful allocation, zeroed allocation, reallocation and
deallocation requests. Requested bytes include the full new size of each
reallocation, not only its increase. A direct allocation/reallocation/deallocation
self-check runs before measurement. Fixture setup and report writing happen
outside the counter.

The workloads are clean tier-1 scanning, full analysis of a clean command, a URL
pipeline, obfuscated tool output, analysis with a custom policy, and reading the
100 most recent records of a 10,000-row history file. They use disposable
policy, cache and history roots and never read the operator's own state.

Limits:

- It does not see native allocations that bypass the Rust global allocator,
  other threads, child processes, live heap size, CLI startup, or a whole
  interactive shell or agent operation.
- Its elapsed times are instrumented. They are reported, never gated, and are not
  comparable with ordinary CLI timings.
- Process and OS caches are not reset; no sample is a cold-cache claim.

## The ceilings

`resource_ceilings.json` holds, for every workload, an `allocation_requests`
ceiling (allocation + zeroed allocation + reallocation calls) and a
`requested_bytes` ceiling. The gate compares the largest of the samples of each
workload with its ceilings. It fails when a value is above its ceiling, when a
measured workload has no ceiling, or when a ceiling names a workload that was not
measured.

The ceilings are about 25% above measured values, rounded up. Allocation counts
are close to deterministic, so the headroom absorbs small differences between
operating systems, architectures, toolchains and dependency versions without
pinning any of them. Nothing in CI compares hashes of `Cargo.toml`, `Cargo.lock`,
the compiler or the runner image. The source revision, `rustc -Vv`, `cargo -V`
and the runner image are uploaded as an artifact (`resource-provenance.txt`) for
reference only.

When a change makes a workload allocate more on purpose, measure it, set the
ceiling about 25% above the new value, and say why in the commit.

## Run it locally

```sh
cargo bench --locked -p tirith-core --bench resource_counts -- \
  --output /absolute/path/resource-allocations.json \
  --ceilings "$PWD/crates/tirith-core/benches/resource_ceilings.json"
```

Cargo runs the benchmark from the `crates/tirith-core` directory, so pass
absolute paths. `--samples` (3 to 100, default 10) sets the samples per workload.
