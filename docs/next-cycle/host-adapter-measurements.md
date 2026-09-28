# Actual host adapter measurements

`scripts/measure-claude-adapter.py` measures one explicitly selected macOS ARM
Claude/Python/Tirith tuple. It requires an ordinary release-profile product,
the qualified host harness, absolute input paths and exact SHA-256 pins.
Use `--help` for the required product, host, invocation alias, interpreter,
runtime, harness and fresh output-directory arguments. Keep the original
repository harness layout so its pinned native ownership helper is available.
The producer does not install tools or change personal settings.

Four serial private fixtures run actual recommended setup, start a fresh host,
perform one unmeasured allow/block warmup pair, then collect six measured pairs.
This produces exactly 24 allow and 24 block samples. Every pair has independent
ordinary-checker preflights; every host turn requires matching tool/result IDs,
hook events, successful host completion and the correct once/never marker effect.
Failure stops collection without replacement samples or automatic retry.

The report retains raw monotonic nanoseconds, command hashes, action/batch labels
and nearest-rank p50/p95. Turn time starts immediately before sending and ends
when the successful result returns. It includes finite ownership checks during
output collection. Preflight and final semantic checks are outside that interval.
Setup including owned cleanup and startup through no-tool initialization have
separate four-sample distributions; their p95 is the observed maximum.

The provider is scripted and local. Results include actual host, hook, checker,
tool handling and fixture-provider work; they exclude remote model inference
and remote service latency. No synthetic overhead is obtained by subtracting
standalone results. CPU/RSS observations cover only the retained direct host,
with explicit native display units and sampled RSS rather than a kernel peak
or descendant total. Fixture growth is recorded separately.

The fixed envelope is 600 seconds, 75 planned children with a hard limit of 96,
four serial hosts and 29 requests per provider within its 32-request cap.
Cleanup remains available after work-budget failure and visits every retained
child. Evidence is capped at 256 MiB plus a bounded result, with entry and free
space checks. The private output is retained for review; input generations and
hashes are checked before and after. Managed host configuration refuses admission.
Observed storage bounds are not filesystem quotas, and cleanup of owned process
groups does not certify arbitrary escaped groups after a kernel/process failure.

Run the sixteen pure controls with:

```sh
python3 scripts/test-measure-claude-adapter.py
```

The first real measurement and its exact source/artifact identities are in
[verification](verification.md#september-28-repeated-actual-claude-adapter-measurements).
The existing six allocation/RSS regression limits remain the reviewed CI gate;
these host observations do not establish a universal latency budget.
