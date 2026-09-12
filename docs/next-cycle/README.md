# Next-cycle implementation progress

Implementation is based on main at Tirith **0.4.2**,
`7fd35101568bb06ee0d361dc1d4a4d193c5f60fd`, in the isolated
`codex/next-cycle-foundations` checkout. The original 0.4.1 checkout and its
uncommitted edits remain preserved. The package version remains 0.4.2 until a
separate release decision. This is an implementation record, not release evidence.

The complete WP00–WP27 scope remains active. No work package or G0–G3 release
gate is declared complete. Native qualification, real beginner pilots, final
packaged measurements, and publication evidence cannot be inferred from source
changes or substituted with simulated success.

| Package | Current implementation and remaining work |
| --- | --- |
| WP00 | Baseline, schema/fixture inventory and acceptance matrix recorded. Signed macOS 0.4.2 baseline commands and five old/new scoped-grant compatibility assertions passed. Wider fixtures and packaged performance measurements remain. |
| WP01 | Runtime snapshots capture field provenance, input revisions, private replay guards, authority, neutralized preferences, trust expiry and remote-cache evidence. Mutations refuse unconditioned remote authority. Broader runtime/native verification remains. |
| WP02 | Frozen evaluation separates observed facts from pure policy evaluation and preserves combined blockers and incomplete evidence. Runtime threat enrichment capture and complete equivalence evidence remain. |
| WP03 | Producer-selected CLI/core/MCP projections preserve typed protocol values under broad DLP; signed documents remain separate. Complete signed/export/service boundary audit remains. |
| WP04 | Shared native shell/operator targets and evidence grades are implemented. Caller-shell attestation core is registered; actual helper/PTY integration is in progress. Configured and inherited states do not imply observed blocking. Native Windows/PowerShell/Nushell qualification remains. |
| WP05 | Comfortable/Balanced/Strict versioned personal presets preserve unknown settings/manual overrides; reset touches owned values. CLI and browser use shared preparation. Broader corpus and end-to-end verification remain. |
| WP06 | Shared durable plan/apply/status/cancel/undo service, exact preimages, typed intent, task authorization, conflicts, compensation and bounded workers implemented. Async admission, fresh undo baselines, and bounded saved-operation inventory are implemented; expanded crash and native Windows checks remain. |
| WP07 | Stable scoped/expiring grants, retained project identities, legacy migration, CLI lifecycle and typed browser preparation implemented. Five actual 0.4.2/new-client compatibility assertions passed; native/copy/move/expiry and final-candidate evidence remain. |
| WP08 | Existing one-operation receipts retained; recovery uses the actual shell bypass parser and distinguishes unsupported syntax/hard blocks. Native recovery journeys remain. |
| WP09 | Frozen simulation and private reversible expectation labels passed earlier tests. Bounded CLI/browser tuning now reads selected annotations and redacted examples, without replay or automatic approval; expanded regressions await the next candidate. |
| WP10 | Combined personal profile/shell setup is registered through `setup recommended` and browser plans; new tests await the next capture. Selected agents refuse until their native automatic setup scope is certified. Multi-host qualification and current-shell verification remain. |
| WP11 | Packaged-byte runner passed 32 native Bash/Zsh/Fish checks on the corrective macOS debug candidate; four additional terminal/npm-launcher checks and three actual Claude baseline checks passed separately. Other native installed packages/hosts and final candidate recertification remain. |
| WP12 | Bounded history and incremental aggregates preserve attribution, limits and invalidation. Same-inode retention passed core/CLI/browser tests. Exact segment export and acknowledged irreversible deletion are now registered; new signing-drift/cancellation guards and append-failure health need final verification. |
| WP13 | Embedded local service, strict HTTP/auth/origin/CSRF bounds, typed routes, exact-version discovery, identity guards and quiesce implemented. Integrated workspace typecheck passes and real transport tests passed at the preceding checkpoint; expanded browser/security/lifecycle evidence remains. |
| WP14 | Six embedded pages expose typed shell/profile/settings/exception plans, saved jobs, feedback, support preview/download, retention, impact reviews and lifecycle actions. Seventeen real-browser workflows passed on the offline-readiness candidate, including project review, combined setup with an existing policy, and archive controls. Busy-history paging and final recertification remain. |
| WP15 | Channel/privilege guidance, exact signed compatibility, candidate binding, rollback receipts and a durable lifecycle store/retained worker handshake are registered. Native publication/crash/reopen and rollback/removal evidence remains. |
| WP16 | Signed source evidence, freshness dimensions, publication/parser guards, transient recovery and incident records implemented. Final compiled and publication-path verification remains. |
| WP17 | Native sampling found debug-build SHA cost in repeated executable guards. The development SHA dependency is optimized while retaining exact checks. A bounded isolated measurement runner is prepared; new candidate measurements and release comparisons remain. |
| WP18 | Selected support preview and private task-authorized export passed linked tests with fresh privacy/output bounds. Read-only lifecycle selection is newly registered. Six user journeys and documentation reconciliation remain. |
| WP19 | Final-byte installed/native acceptance, beginner pilot and release/channel evidence remain. No substituted evidence is claimed. |
| WP20 | Retained-identity project review is registered through CLI and browser using existing dependency/hook/AI/MCP analyzers. Explicit coverage, whole-entry privacy limits and no tooling execution are enforced; core/CLI/API/browser regressions await the next capture. |
| WP21 | Bounded npm ustar/PAX/gzip reader, exact identities and hostile/real npm corpus are registered; 22 reader tests passed in the prior integrated selection. A bounded 301-second AddressSanitizer run completed 36,320 executions without a crash on the pinned source checkpoint. Final packaged candidate and broader fuzz qualification remain. |
| WP22 | Offline metadata/script/code/native observations and private JSON/SARIF CLI projections are registered and selected CLI checks passed. Explicit project-scoped browser detail is now registered; transport/browser and final corpus evidence await the next candidate. |
| WP23 | npm comparison and CLI bind hashes and qualify analyzer/coverage differences; eight core comparisons and two combined CLI tests passed previously. Explicit project-scoped browser comparison is now registered; browser and final G2 evidence await the next candidate. |
| WP24 | Conservative pip/Cargo command-family models are registered with explicit incomplete dynamic effects and new fixtures. Linked tests and capability qualification remain. |
| WP25 | Bounded impact reports, exception ownership/expiry and local activation/undo are registered through CLI/browser with immutable journal attachments and shared freshness checks. Remote publication/fleet adoption remain explicitly unavailable; linked acceptance remains. |
| WP26 | LocalLeafNoScriptsV1 defines a pinned, zero-transitive local artifact contract. Retained capture/staging/verification foundation is being drafted separately; launcher integration and native execution qualification remain. |
| WP27 | Native Linux aarch64 deny-all filter is registered; native primitive/filter probes passed. Both GNU and musl launchers built with Rust 1.83 and each passed sixteen native unprivileged containment/runtime/interruption cases. Native ARM GNU/musl CI checks also passed on 71070bbbb. Final integrated release-artifact qualification remains. |

The focused privilege changes are reviewed separately in
[PR 251](https://github.com/sheeki03/tirith/pull/251) and
[PR 252](https://github.com/sheeki03/tirith/pull/252). The latest revision removes
sudo package suggestions as well as hard dependencies and describes privileged
approval availability separately from ordinary protection. Exact heads
`356981b8` and `3dce8f2d` each have 53 passed checks, 12 expected skips and no
failures. These separate PR results do not certify the larger cycle branch.

Contracts and evidence:

- [Baseline inventory](baseline.md) and [acceptance matrix](acceptance-matrix.md)
- [Policy snapshots](policy-snapshots.md) and [profile ownership](protection-profiles.md)
- [Output contracts](output-contracts.md), [trust grants](trust-grants.md), [recovery](recovery.md)
- [Shell targets](shell-targets.md), [bounded history](history.md), [ThreatDB operations](threatdb-operations.md)
- [Dashboard design](dashboard-design.md) and [verification](verification.md)
