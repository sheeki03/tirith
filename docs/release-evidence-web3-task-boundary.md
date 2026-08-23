# Release evidence: `codex/web3-task-boundary`

Measured on the branch tip, on the machine named below. This file records what
was actually run, so the release owner can tell which gates still need running
somewhere else rather than re-deriving that from a summary.

Nothing here substitutes for the CI matrix. Every measurement below is from a
single macOS arm64 host, and the gates that exist precisely because one host
cannot speak for the others are listed as still open at the end.

## Host and tree

| Field | Value |
|---|---|
| Branch | `codex/web3-task-boundary` |
| Tip at measurement | `fbc5ef97` (C20) |
| Host | macOS, aarch64-apple-darwin |
| Toolchains present | stable, nightly, 1.83.0 |

## Gates closed here, with numbers

| Gate | Command | Result |
|---|---|---|
| Workspace suite | `cargo test --workspace` | exit 0, 35 binaries, **8,094 passed, 0 failed**, 12 ignored |
| MSRV, matching CI's job | `cargo +1.83 test --workspace --locked` | exit 0, 35 binaries, **8,094 passed, 0 failed** |
| MSRV compile, all targets | `cargo +1.83 check --workspace --all-targets` | exit 0 |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0, zero warnings |
| Format | `cargo fmt --all --check` | exit 0 |
| Windows cross-compile | `cargo check -p tirith --target x86_64-pc-windows-gnu` | exit 0 |
| Linux cross-compile | `cargo check -p tirith-core --target x86_64-unknown-linux-gnu` | exit 0 |
| Dependency and licence | `cargo deny check` | **advisories ok, bans ok, licenses ok, sources ok** |
| Criterion budgets | `cargo bench --bench perf -- --output-format bencher` then `scripts/check-bench-budgets.sh` | **all 23 benchmarks inside their absolute budgets**, worst case 23% of budget |
| Fuzz smoke, every registered target | `cargo +nightly fuzz run <target> -- -max_total_time=20` | **12 of 12 targets, exit 0, zero crashes** |

### Fuzz detail

Twenty seconds per target, which is a smoke duration and not a campaign. Run
counts vary by how much work each input does, which is why the slower targets
execute fewer cases in the same wall time, not because they were cut short.

| Target | Runs | Crashes |
|---|---:|---:|
| `url_parser` | 26,250 | 0 |
| `tokenizer_posix` | 30,129 | 0 |
| `tokenizer_fish` | 23,115 | 0 |
| `tokenizer_powershell` | 27,447 | 0 |
| `extractor` | 16,288 | 0 |
| `normalizer` | 29,479 | 0 |
| `byte_scanner` | 31,652 | 0 |
| `artifact_wheel` | 27,561 | 0 |
| `npm_command` | 21,449 | 0 |
| `task_envelope` | 776 | 0 |
| `workflow_artifact` | 5,614 | 0 |
| `web3_command` | 10,229 | 0 |

`artifact_wheel` is worth a note: it was registered in `fuzz/Cargo.toml` but
absent from the workflow matrix, so it had never run in CI at all. C19 added it
to the matrix, and this is its first recorded smoke.

### Binary size

`cargo build --release -p tirith` produces a 28.3 MiB `tirith` on this host.
Recorded as a datum, not a verdict: there is no prior figure in the repository
to compare against, so the release owner should diff it against the last
released artifact rather than treat this number as a pass.

## Suite stability

The suite was run repeatedly rather than once, because a green single run says
little about a suite that spawns real shells.

- `shell_conformance` alone: 4 consecutive runs, 21 passed each, 0 failures.
- Full workspace: 3 consecutive runs green after the C19 isolation work.

One test remains load-sensitive and is NOT fixed:
`session_warnings::tests::surfaced_correlation_not_re_emitted_while_source_events_live`
failed once in eight full-workspace runs. It is pre-existing, last modified by
C04, and already carries its own mitigation for exactly this. Fixing it properly
needs a time-injection seam in production code, which is a behaviour change and
therefore a slice of its own.

## A lint result that is not a gate, recorded so nobody re-discovers it

`cargo +1.83 clippy --workspace --all-targets -- -D warnings` reports 13 lint
errors. This is NOT a CI gate: the MSRV job runs `cargo test --workspace
--locked`, and `cargo +1.83 check --workspace --all-targets` passes, so the code
compiles cleanly at the MSRV. The 13 are lint-only differences between the 1.83
and stable clippy versions. Stable clippy, which CI does gate on, is clean.

## Still open, and belonging to the release owner

These are not claimed by this branch and were not run here.

- Pause and independently verify the disabled state of the scheduled ThreatDB
  workflow, run the shadow build and the `@solana/web3.js` boundary regression,
  then re-enable and monitor one deliberate run.
- Retarget onto the post-predecessor-stack `main` tip and recompute the merge
  tree, then review whatever conflict resolution that produces.
- The full CI matrix on the final tree: Linux, macOS, and Windows. Everything
  above is one macOS host, and several capabilities in this branch are
  Linux-only by construction, so their enforcing paths have never executed.
- Release-owner sign-off on the merge window and on the rollback playbook in
  `docs/web3-task-rollout.md`.

Do not squash before that review. The per-slice commits are what make an
emergency revert surgical.
