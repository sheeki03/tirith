# Foundation-slice verification

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
