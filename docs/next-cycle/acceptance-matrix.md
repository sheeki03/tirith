# Next-cycle acceptance matrix

Baseline revision: `7fd35101568bb06ee0d361dc1d4a4d193c5f60fd` (0.4.2).
See [baseline.md](baseline.md) for source findings and fixture provenance.

Every row below is **open**. Existing tests are starting points, not an assertion
that they passed at this revision or satisfy all scenarios. A completion record
must name code revision, OS/toolchain/host versions, exact command, result artifact,
skips and expected versus observed side effects. Keep local source tests, native
host tests and final packaged-release evidence separate. No PR or CI run was
attached by this inventory.

| Case | Work packages / gate | Scenario and expected result | Expected side effects | Required evidence / reusable starting point |
|---|---|---|---|---|
| A00 | WP00 / G0 | Replay frozen contracts at the recorded base; distinguish 0.3.3 legacy fixtures from new 0.4.2 captures | Test-owned roots only; no personal configuration changes | [C00 core](../../crates/tirith-core/tests/c00_contracts.rs), [C00 CLI](../../crates/tirith/tests/c00_cli_compatibility.rs), help snapshots; new trust/receipt/surface captures |
| A01 | WP01 / G0 | User/repo/organization/remote/incident composition yields one frozen effective result; repo weakening stays neutralized; remote replacement is preserved | Resolution/preview cannot write policy or execute a command; remote fetch evidence is labelled accurately | [Policy integration](../../crates/tirith-core/tests/policy_integration.rs), core policy tests; new revision/provenance/race tests |
| A02 | WP02 / G0 | Repeated preview is stable; Warn, WarnAck, Block and incomplete analysis are distinguishable; resolving one finding leaves independent blockers | No receipt consumption, execution, session escalation or warning history added by preview | [Safe-command tests](../../crates/tirith-core/tests/safe_command_integration.rs), output/engine tests; explicit mutation counters and multi-blocker controls |
| A03 | WP03 / G0 | Broad custom patterns match action/ID/schema strings; machine identity remains valid and sensitive payloads remain redacted; canonical signatures remain verifiable | No secret disclosure or malformed protocol projection | Redaction/verdict/MCP tests, C00 signing and machine contracts; typed boundary cases, old-client responses |
| A04 | WP04 / G0 | Resolve intended user and actual startup target across Bash login/non-login, ZDOTDIR/XDG, Fish, Nushell, Windows PowerShell 5.1/7 and Unix PowerShell | Read-only discovery; unsupported/unknown targets stay unchanged and cannot claim blocking | Setup/doctor unit fixtures plus actual native startup and fresh/nested-shell probes |
| A05 | WP05 / G0 | Versioned Comfortable/Balanced/Strict action matrix passes paired corpus; CI/MCP detection cannot select personal strictness; personal preference cannot bypass mandatory restrictions | Preview has no write; applying later uses the shared writer and preserves unowned settings | Existing policy templates, [paired shell corpus](../../crates/tirith-core/tests/shell_false_positive_regressions.rs); reviewed matrix and migration fixture |
| A06 | WP06 / G1 | Stale owned-field preimage or changed policy is refused; same operation ID + same input returns one outcome; different operator/kind/payload conflicts | At most one commit; unrelated edits survive; cancellation reports any committed steps | Setup transaction/helpers tests; fault after each write, two editors, held lock, response loss, disk/read-only and Windows recovery tests |
| A07 | WP07 / G1 | Malformed/expired/revoked grants agree in CLI/enforcement; expiry shortening changes the identified grant; remaining broader grants are shown | Exact target/rule scope; no global authority when 0.4.2 reads a new project grant | Core/CLI trust tests, [bypass regressions](../../crates/tirith-core/tests/bypass_regression.rs); old-binary/new-envelope and daemon expiry tests |
| A08 | WP08 / G1 | One-use authorization binds exact command/context/policy/session; concurrent consumer, replay, changed CWD/policy and hard block are refused | Authorized command executes once only at its owned boundary; unrelated next command remains protected | Shell receipt tests and [PTY conformance](../../crates/tirith/tests/shell_conformance.rs); pre-binary storage failure and native bypass tests |
| A09 | WP09 / G1 | Simulation uses frozen context; no tuning suggestion is not proof of no interruptions; redacted history is not claimed as exact re-analysis | Labels are review signals, not trust grants; preview has no execution/session writes | audit_tune/CLI policy tests and representative redacted/hostile log fixtures |
| A10 | WP10–WP11 / G1 | Disclosed recommended setup produces a trusted personal profile and managed shell target; fresh-shell verification distinguishes configured, pending, observed blocking and failure | Allowed inert marker appears once; blocked marker never appears; optional failures remain visible | Managed setup plus existing PTY marker harness; native installed-package run for each advertised row below |
| A11 | WP11 / G1 | Selected agent enforces through its actual tool path, survives expected errors, and reports alternatives/disabled registration honestly | Clean operation once; blocked marker absent; MCP-only registration claims only explicit checking | [Real-agent E2E checklist](../../mcp/clients/E2E-CHECKLIST.md), actual version/config/result evidence; mocked adapters alone insufficient |
| A12 | WP12 / G1 | Bounded paginated history distinguishes empty, unreadable, partial/corrupt; rotation preserves chain/segment identity and original attribution across writer versions | No double count after restart; rebuildable indexes; logging/storage failure visible | audit/aggregator/dashboard tests; cap-sized logs, truncation, concurrency, mixed-version rotation and disk exhaustion |
| A13 | WP13 / G1 | Authenticated local service validates exact origin/Host/CSRF, request caps, expiry and client compatibility; opening works without requiring a browser for protection | Only allowlisted operations; no arbitrary command execution or filesystem editing; bounded cancellable jobs | Current dashboard read-only HTTP tests extended with adversarial requests, stale service and concurrent client tests |
| A14 | WP14 / G1 | CLI/browser read back identical effective policy, grant scope, override reasons, activity coverage and operation outcome | Hostile activity rendered inert; UI confirmation cannot grant otherwise-forbidden authority | Cross-interface contract and browser journeys using the same fixtures/revisions |
| A15 | WP15 / G1 | All advertised channels recognized conservatively; upgrades/reloads/rollback/removal preserve ownership and reject unsupported format downgrade | Package-owned files never self-replaced; modified user fields retained; data deletion separate | [Release-security tests](../../crates/tirith/tests/release_security.rs), selfupdate/setup tests, native old→new→rollback journeys per channel |
| A16 | WP16 / G1 | Distinguish publication/source/upstream lag; transient retry bounded; malformed identity/signature/replay/incomplete feed retains verified previous generation | No incomplete publication; no rollback; cold client verifies final published bytes | [Fetch fixtures](../../.github/scripts/test-fetch-threatdb-sources.sh), source-pin/transition tests, ThreatDB reload/signature tests plus publication artifacts |
| A17 | WP17 / G1 | Packaged startup and full host latency meet measured reference distributions; memory/CPU/disk/contention and cache invalidation recorded | Expired/revoked authority never survives a cache for performance; no hidden telemetry requirement | Criterion is an existing component benchmark only; new end-to-end harness with p50/p95/sample units and resource data |
| A18 | WP18–WP19 / G1 | Docs/capability examples match actual behavior; final package checks and consented beginner pilot complete activation/recovery/upgrade/removal | No mandatory account/browser; support export stays local until deliberately shared | Capability/help sync tests, final artifact digests, channel status report, beginner journey records |
| A20 | WP20 / G2 | Unified project review identifies inspected/skipped/unsupported surfaces; operation explanation labels unknown effects | No execution of project tooling; no automatic private-tree scan from dashboard startup | Existing dependency/hook/AI/MCP/project checks with modified-project and incomplete-coverage fixtures |
| A21 | WP21–WP22 / G2 | Exact npm tarball digest, bounded compressed/decompressed bytes, counts and work; traversal/link/collision/duplicate/malformed inputs refused or accurately reported | No lifecycle/project code executed; no unearned safe/clean claim | Existing wheel reader patterns and npm metadata fixtures plus new malicious/legitimate archive corpus |
| A23 | WP23 / G2 | Compare exact inspected releases; report newly introduced execution shape and identity changes; analysis-coverage change is distinct from risk delta | Read-only comparison; same common artifact contract | [Python release diff](../../crates/tirith-core/src/artifact/release_diff.rs) plus npm-specific comparison fixtures |
| A24 | WP24–WP25 / G3 | Additional task effects retain explicit completeness; team rollout preserves trusted restrictions and exception ownership/expiry | No inferred grant from task text or automatic broadening of personal policy | Existing task provenance/boundary tests plus reviewed rollout and bounded grammar contracts |
| A26 | WP26–WP27 / G3 | Hash-bound npm installation and another containment backend each pass independent resolver/authority/native enforcement/escape/refusal gates | Exact approved artifact closure only; unsupported hosts fail closed before execution; recovery demonstrated | Separate capability decision, final native artifact tests and rollback/cancellation evidence; inspection cannot close this row |

## First automatic-setup qualification matrix

No platform/host is certified for the proposed automatic journey by this inventory.
The first **candidate** is Linux x86_64 with Bash 5.3, using the existing pinned
Bash CI job and PTY harness. It must pass A04, A06–A08, A10, A15 and final package
checks before being advertised. This narrow starting point is a qualification
decision, not a reduction of existing manual workflows.

| Surface | Existing source evidence | Next-cycle status and missing proof |
|---|---|---|
| Linux x86_64, Bash 5.3 | Dedicated CI job builds pinned Bash 5.3; enter/preexec and PTY marker/receipt tests exist | Candidate only; capture exact patch version and installed-package default setup, fresh-shell, upgrade/removal and failure results |
| macOS arm64, Zsh | Native PTY protocol-v3 delivery tests and current inventory host | Manual workflow retained; no packaged automatic setup result recorded |
| Linux/macOS, Fish | PTY allow/block/warn/noninteractive tests | Manual workflow retained; exact shell versions and installed fresh-shell target paths unverified |
| Other Bash versions/startup modes | Version-gated PTY suite; fallback/capability tests | Conditional until tested; missing/old shell skips must be listed |
| PowerShell 5.1/7, Unix PowerShell | Trusted helper probes and config tests; ignored PTY follow-up stub | No next-cycle native blocking certification; target resolution and interception evidence required |
| Nushell | Hook/config source; ignored PTY follow-up stub | No next-cycle native blocking certification |
| Real agents and MCP clients | Adapter tests and unfilled E2E checklist | No selected agent certified here; record actual host version, enabled configuration, invocation and refusal separately |
| Linux containment | Existing x86_64 release enforcement; native ARM GNU candidate passes nine installed-binary cases | ARM musl, cancellation and final release-artifact qualification remain separate gates; see containment-aarch64.md |

## Reproducible starting commands

Run relevant targeted suites first from the chosen immutable checkout. These
commands are an inventory, **not commands executed for this document**. Capture
stdout/stderr, exit status and skipped tests with environment metadata. The CLI
tests provide isolated config/data roots; do not replace them with personal
profile mutations.

```sh
cargo test -p tirith-core --locked --test c00_contracts --test policy_integration --test bypass_regression --test shell_false_positive_regressions
cargo test -p tirith --locked --test c00_cli_compatibility --test help_snapshots --test owned_boundary_enforcement
cargo test -p tirith --locked --test bash_preexec_enforce --test bash_hook_exports --test shell_conformance -- --nocapture
cargo test -p tirith --locked capability_matrix_is_in_sync
bash .github/scripts/test-fetch-threatdb-sources.sh
bash .github/scripts/test-threatdb-manifest-transition.sh
python3 .github/scripts/test_threatdb_source_pins.py
```

For a final implementation candidate, use the repository's stable
`cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace --locked`, and Rust 1.83 workspace checks; native and
release jobs remain separate requirements. Criterion's existing reproducible path
is `cargo bench --bench perf -- --output-format bencher` followed by
`scripts/check-bench-budgets.sh` on the captured output; do not convert its means
or iteration ceilings into an end-to-end percentile guarantee.

G0 remains open until WP00–WP05 and their compatibility evidence are complete.
G1 additionally requires WP06–WP19 for the advertised setup matrix, including
upgrade, storage, recovery, security, performance and the final beginner journey.
G2/G3 are separate gates and do not postpone completion of the daily-use milestone.
