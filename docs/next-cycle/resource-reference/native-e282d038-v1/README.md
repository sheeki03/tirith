# Native resource budgets

The ordinary `bench.yml` job measures its current event source and enforces six
byte budgets on the reviewed macOS ARM runner. Admission and post-collection
checks require the same runner image, CPU class, compiler, Python runtime,
measurement tools, producers, workloads and build contract. Changed or missing
evidence fails with a retained diagnostic; it does not silently replace the
reference or widen a limit.

Three independent baseline boots at source
`e282d038519848caa8328cf32aa05a05daa502d2` established the reference. Six later
control/growth pairs each passed every limit for the control and exceeded only
the intended limit for the growth variant. Independent review rehashed the six
original archives and 246 extracted files, then recomputed their raw metrics and
deltas. The variants remain on isolated qualification branches.

| Measurement | Maximum bytes | Control bytes | Growth bytes | Qualification run |
| --- | ---: | ---: | ---: | --- |
| Clean analysis, including first call | 67,108,864 | 48,307,398 | 81,861,830 | [36338492904](https://github.com/sheeki03/tirith/actions/runs/36338492904) |
| Clean analysis, subsequent calls | 131,072 | 120,397 | 153,165 | [36338496133](https://github.com/sheeki03/tirith/actions/runs/36338496133) |
| URL pipeline, including first call | 100,663,296 | 72,060,275 | 105,614,707 | [36338499259](https://github.com/sheeki03/tirith/actions/runs/36338499259) |
| URL pipeline, subsequent calls | 2,097,152 | 1,670,678 | 2,194,966 | [36338503185](https://github.com/sheeki03/tirith/actions/runs/36338503185) |
| Recent-history allocation requests | 12,582,912 | 8,692,440 | 12,886,744 | [36338506423](https://github.com/sheeki03/tirith/actions/runs/36338506423) |
| Ordinary command peak RSS | 50,331,648 | 44,138,496 | 61,390,848 | [36338509243](https://github.com/sheeki03/tirith/actions/runs/36338509243) |

The allocation producer performs 100 clean analyses, 100 URL analyses and 100
history requests. Subsequent-call limits cover samples 1 through 99. All 100
grown RSS observations exceeded its limit; paired median growth was 17,186,816
bytes. Allocation counts measure requested bytes, not live heap. These checks do
not certify shell-hook latency, other platforms, fleet performance or a release.

Evidence and configuration:

- [threshold-review.json](threshold-review.json) identifies the three original
  baseline archives, their 63 rehashed files and the threshold derivation.
- [budget.json](budget.json), [protocol.json](protocol.json) and
  [variants.json](variants.json) preserve the exact detector-qualification inputs.
  Their historical descriptions do not indicate current activation status.
- [activation-review.json](activation-review.json) records the completed six
  pairs, immutable source/run/artifact identities and independent activation
  decision. The first ordinary CI execution remains a separate result.
- [active-budget.json](active-budget.json) retains the six qualified ceilings
  and adds their activation rationale.
- [admission.json](admission.json) binds that active budget to the unchanged
  measurement tools and reviewed Python executable/version.

The job retains admission, measurement, confirmation and enforcement records for
90 days, including failures. When a runner image or measurement contract changes,
review the new cohort before changing the admission record. A later commit is
measured as its own event source; it is never reported as the original baseline.
