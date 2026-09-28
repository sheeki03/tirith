# Next-cycle implementation progress

Implementation is based on main at Tirith **0.4.2**,
`7fd35101568bb06ee0d361dc1d4a4d193c5f60fd`, in the isolated
`codex/next-cycle-foundations` checkout. The original 0.4.1 checkout and its
uncommitted edits remain preserved. The package version remains 0.4.2 until a
separate release decision. This is an implementation record, not release evidence.

The complete WP00–WP27 scope remains active. Status applies to the stated
capability and recorded revision: `review` means implementation and evidence are
available for acceptance review; `in progress` identifies concrete unfinished
work; `verified` is limited to its named native contract. G1 release acceptance
still requires its beginner pilot and channel/upgrade evidence. G0, G2 and
capability-specific G3 review do not require unrelated production deployments
or expansion beyond the advertised setup matrix.

The September 28 checkpoint `e282d038` passes all five PR workflows and the
complete local workspace suite. Its actual macOS ARM PR package passes 32 native
Bash/Zsh/Fish cases, three fresh Zsh activation sessions, three removal cases,
24 browser journeys and eight response-order checks. Windows standard-account
dashboard checks and both canonical ARM containment archives also pass. Exact
bytes, source identities and remaining limits are recorded in
[verification](verification.md#september-28-combined-source-e282d038).

The later `d0213a22` checkpoint passes release builds, native ARM, fuzz and
benchmark workflows, including the ordinary CI resource gate. Main CI passes
Windows PowerShell 7 target resolution but exposes separate Linux runtime-copy
and Windows PowerShell 5.1 startup failures. At `cd062069`, Linux native target
resolution passes and Windows PowerShell 5.1 starts and matches its native
profile; its separate ancestor command-line query still refuses qualification.
Four numeric lifecycle cases and matched
standalone/daemon measurements pass on its unchanged compiler-source closure.
See the [platform results](verification.md#september-28-d0213a22-platform-follow-up).

The corrected `aa88c7ae` checkpoint passes all five ordinary workflows. Windows
passes all 60 workspace harnesses, including nine standard-account dashboard
cases and all three new reader/writer coordination regressions. PowerShell
5.1 and 7 pass native profile and process-query checks; Linux and macOS pass
both target cases. See the [current native results](verification.md#september-28-aa88c7ae-native-corrections-pass).

A subsequent Linux-only correction admits absent ACLs on tmpfs only through a
descriptor bound to already validated metadata and a complete attribute listing.
All five ordinary workflows pass at `83468789`, including all eight new native
tmpfs controls and three existing ACL controls on GNU ARM. The ordinary GNU
package also passes the actual service-worker replacement and fresh-service
composition, saved retry and cleanup. This same-version synthetic-history check
complements the separate numeric macOS update/rollback cases; final official
channel acceptance remains under WP19. Other filesystem types and metadata-free
ACL callers retain their existing refusal behavior.

The [acceptance reconciliation](completion-review.md) maps all 24 acceptance
rows and six user routes to the reviewed source. It identifies concrete open
boundaries and supersedes earlier generic requests for more corpus, historical
schemas or storage tests where applicable evidence already exists.

| Package | Status | Current implementation and remaining work |
| --- | --- | --- |
| WP00 | review | Baseline, schema inventory and acceptance matrix recorded. Signed macOS 0.4.2 baseline commands, five scoped-grant assertions and 32 paired policy/trust/shell-mode/receipt reader cases passed. A00 source/evidence reconciliation is complete for review; final release acceptance remains separate. |
| WP01 | review | Runtime snapshots capture field provenance, input revisions, private replay guards, authority, neutralized preferences, trust expiry and remote-cache evidence. Mutations refuse unconditioned remote authority. A01 maps the unchanged paths to retained policy/HTTPS and browser evidence. |
| WP02 | review | Frozen evaluation separates observed facts from pure policy evaluation and preserves combined blockers and incomplete evidence. Capture includes available cached threat enrichment and reports unavailable runtime/session/baseline evidence. A02 maps the evaluation regressions and browser preview/impact evidence to the current paths. |
| WP03 | review | Producer-selected CLI/core/MCP projections preserve typed protocol values under broad DLP; signed documents remain separate. Saved receipts now have bounded typed reads, fresh display redaction and explicit canonical-output refusal when privacy requires a projection; the shared public Rust reader and CLI privacy/identity/limit cases passed on candidate 1a72833. A03 maps typed machine, signing, export and hostile-data browser controls to the current paths. |
| WP04 | review | Shared native shell/operator targets and evidence grades are implemented. Authenticated helper completion now projects canonical status through a one-use core proof; five actual Bash/Zsh/Fish terminal cases and 48 other proof/status checks passed on candidate fad9af58. Configured/inherited state and saved success do not promote ordinary status or dashboard reads. Automatic fresh-shell verification passes for the retained macOS Zsh tuple with default job control enabled. At aa88c7ae, native Windows PowerShell 5.1/7 profile and process-query checks pass, as do Linux/macOS default and private-XDG profile cases, with unchanged profiles and verified cleanup. Automatic receipt adapters outside the advertised matrix remain unavailable; implementing every adapter is not a completion prerequisite. |
| WP05 | review | Comfortable/Balanced/Strict versioned personal presets preserve unknown settings/manual overrides; reset touches owned values. CLI and browser use shared preparation. A05 maps the current preset and browser controls, including mandatory restrictions and manual ownership. |
| WP06 | review | Shared durable plan/apply/status/cancel/undo, exact preimages, typed intent, conflicts, compensation and bounded workers are implemented. Fourteen native process-death/storage cases pass again on the e282d038 development candidate, with every requested stopped boundary observed and owned cleanup verified. Signed audit recovery and actual HFS+/APFS ENOSPC cases also pass; the actual Linux service-worker composition also passes under WP15. |
| WP07 | review | Stable scoped/expiring grants, retained project identities, legacy migration, CLI lifecycle and typed browser preparation implemented. Five actual 0.4.2/new-client compatibility assertions pass. One retained d0213a22 daemon now passes real one-minute expiry, renewal and revocation with unchanged store bytes through expiry and all seven child cleanups verified. A07 source and expiry evidence are mapped for review. |
| WP08 | review | Existing one-operation receipts retained; recovery uses the actual shell bypass parser and distinguishes unsupported syntax/hard blocks. A08 maps actual packaged shell receipt/warning behavior and boundary regressions for supported execution surfaces. |
| WP09 | review | Frozen simulation and private reversible expectation labels passed earlier tests. Bounded CLI/browser tuning now reads selected annotations and redacted examples, without replay or automatic approval. Selected CLI and complete browser tuning/annotation/impact workflows passed; A09 maps their unchanged current paths. |
| WP10 | review | Combined personal profile/shell setup is registered through `setup recommended` and browser plans; the complete browser run passed profile/shell apply and undo. Narrow macOS ARM Claude setup is integrated. The exact 2.1.283 tuple passes all nine combined hook controls, MCP-only control and retained-host reload on the actual 6e79b3dd macOS ARM PR package, with all 35 owned-child cleanup records verified. A fresh host is required after setup; numeric binary replacement and official release acceptance remain separate. Other selected agents remain unavailable until qualified. Three fresh default-MONITOR macOS Zsh sessions pass automatic verification on the actual e282d038 PR package. The optional TTY menu routes protection, profiles, recent blocks, exceptions, integrations and maintenance to existing typed inspections/previews; seven menu cases pass. Qualification follows the declared host/version matrix; additional hosts are separate extensions. |
| WP11 | review | The actual e282d038 macOS ARM PR package passes all 32 native Bash/Zsh/Fish checks, with 33 original PTY groups/sessions and actual pipe EOF verified; earlier debug and four additional terminal/npm-launcher checks remain separately recorded. Nine actual Claude configured-hook and boundary controls pass on the actual e282d038 package through explicit setup; combined setup for newly qualified 2.1.283 also passes all eleven recorded cases on the actual 6e79b3dd macOS ARM PR package. A11 maps the recorded tuples and unchanged current hook paths; final official package acceptance remains separate. |
| WP12 | review | Bounded history and incremental aggregates preserve attribution, limits and invalidation. Same-inode retention passed core/CLI/browser tests and six signed/unsigned native mixed-version cases, including a real 0.4.2 descriptor held across rotation. Exact export, irreversible deletion and append-failure reporting are registered. A12 includes signed rotation recovery and actual full-volume refusals; final release verification remains separate. |
| WP13 | review | Embedded local service, strict HTTP/auth/origin/CSRF bounds, typed routes, exact-version discovery, identity guards and quiesce implemented. Real transport checks and eighteen complete browser workflows passed on retained candidates. A13 maps local service controls and bounded operations; the production update-worker composition is recorded under WP15. |
| WP14 | review | Six embedded pages expose typed shell/profile/settings/exception plans, saved jobs, feedback, support preview/download, retention, impact reviews and lifecycle actions. Shared per-field authority, source and apply/undo readback include scalar, severity and profile-owned fields. Managed controls are disabled with reasons; repository constraints remain visible. The September 28 combined browser candidate passes 24 recorded full-journey checks and eight response-order/ownership checks, including large policies, narrow layouts and stale readback. Both verify owned-service cleanup. Strict Clippy, five HTTP cases, four frozen-reader groups and nine profile cases pass; final platform/release recertification remains. |
| WP15 | review | Channel/privilege guidance, exact signed compatibility, candidate binding, rollback receipts and a durable lifecycle store/retained worker handshake are registered. Native macOS ARM ordinary 0.4.2→0.4.3→0.4.2 fixture-key replacement and three observed process-death/reopen cases pass on the d0213a22 compiler closure, with configuration preserved, no replay and all 44 registered direct-child cleanup records verified. Retained/fresh Zsh loaded versions and reload guidance agree. The actual e282d038 macOS PR package also passes three owned removal scenarios. Actual retained/fresh Claude also passes ten turns across numeric update/rollback with all 41 child cleanups verified. The ordinary 83468789 GNU ARM package now passes actual service → worker → replacement → fresh-service composition, rotated authentication, saved retry and exact-container cleanup using same-version packages and synthetic prior history. This complements the separate macOS numeric/reload evidence; final official package/channel acceptance remains under WP19. |
| WP16 | review | Signed source evidence, freshness dimensions, publication/parser guards, transient recovery and incident records implemented. Publication validation now checks duplicate/type/identity disagreements before retrying propagation lag; reports preserve partial-upload and later-failure uncertainty. The ordinary d0213a22 product now passes actual cold-cache v1 acquisition and independent real primary/fallback verification. This legacy generation lacks source evidence, correctly reported unavailable. Signed v2/provenance and controlled publisher recovery remain operational acceptance. |
| WP17 | review | Bounded CLI/CPU/RSS/service sampling and instrumented allocation counting are implemented. Three independent Apple M1 (Virtual) baselines now pass on e282d038, with independently verified raw samples and zero allocation spread. Six historical detector pairs remain separately qualified on 415565d3. All six original e282d038 control/growth pairs pass independent raw-sample review: every control passes and every regression fails only its intended byte ceiling. Ordinary native PR CI now measures the current event source and enforces those six limits after cohort/build/runtime/tool admission and post-collection confirmation. Nine gate controls, fifteen collector controls and 36 checker controls pass. The first ordinary PR gate passes on 6e79b3dd; independent raw-sample recomputation and the unchanged checker reproduce all six passing limits. The retained September 21 release product passes 600 native Zsh allow/block frames, including 200 paired rounds with overlapping outstanding requests. The d0213a22 ordinary product also passes matched standalone/direct-daemon characterization with the genuine signed DB, 1/256-rule policies and flat/nested repositories: independent review recomputes 22 distributions, matches 1,604 decisions and verifies all 552 owned-child cleanup records. Four actual Claude hosts now add 24 allow and 24 block timing samples, with real tool/hook semantics, all 75 child cleanups verified, direct-host CPU/RSS observations and raw nearest-rank distributions. These local-provider timings remain separate from remote model latency and the six enforced byte limits. |
| WP18 | review | Selected support preview and private task-authorized export passed linked tests with fresh privacy/output bounds. Documentation now reconciles support preview, actual user-store paths, profile/removal commands and optional privileged approval. All seventeen isolated command smoke checks pass with explicit partial/absent outcomes. All six routes have mapped observed components; final official package and consented beginner acceptance remain under WP19. |
| WP19 | in progress | Final-byte installed/native acceptance, beginner pilot and release/channel evidence remain. No substituted evidence is claimed. |
| WP20 | review | Retained-identity project review is registered through CLI and browser using existing dependency/hook/AI/MCP analyzers. Explicit coverage, whole-entry privacy limits and no tooling execution are enforced; selected core/CLI/API and complete browser workflows passed on retained development candidates. A20 maps the current bounded project-review contract for G2 review. |
| WP21 | review | Bounded npm ustar/PAX/gzip reader, exact identities and hostile/real npm corpus are registered; 22 reader tests passed in the prior integrated selection. A bounded 301-second AddressSanitizer run completed 36,320 executions without a crash on the pinned source checkpoint. A21 maps the unchanged reader and its corpus/fuzz evidence; no unspecified longer fuzz campaign is required. |
| WP22 | review | Offline metadata/script/code/native observations and private JSON/SARIF CLI projections are registered and selected CLI checks passed. Explicit project-scoped browser detail is now registered; transport/browser workflows passed on the retained candidate; A21 maps the applicable corpus and current paths for G2 review. |
| WP23 | review | npm comparison and CLI bind hashes and qualify analyzer/coverage differences; eight core comparisons and two combined CLI tests passed previously. Explicit project-scoped browser comparison is now registered; the complete browser comparison passed on the retained candidate; A23 maps the unchanged comparison and coverage contract for G2 review. |
| WP24 | review | Conservative pip/Cargo command-family models are registered with explicit incomplete dynamic effects and new fixtures. All six combined task-family integration cases pass, including mixed known effects and unknown siblings. A24 maps the current inference contract; this conservative increment does not execute pip or Cargo installs. |
| WP25 | review | Optional bring-your-own server, authenticated authority/client protocol, explicit local enrollment, reviewed CLI/browser publication and bounded rollback are implemented. Thirty-five real HTTPS/browser cases cover exact-intent lost-response recovery, stale reports, partial adoption and offline withdrawal. Linux client/server tests pass on 5aa893e6; the Windows workspace and standard-account dashboard suite pass on 415565d3. A24 maps the unchanged optional server protocol; an external production deployment is not required for its capability review. Publication never proves fleet adoption. |
| WP26 | in progress | LocalLeafMaterializeV1 implements bounded local dependency-free/script-free npm artifact materialization, fresh signed threat/policy/task checks, immutable review journals and explicit recovery/undo. Native Linux core and CLI writer/recovery tests pass on 5aa893e6. Install preparation captures actual signed threat data, requires a complete artifact Allow decision and retains its authority for revalidation; 45 focused core tests pass. Separate installation review registers immutable review intents, a descriptor-based native launcher, a publication coordinator and signed completion milestones for fresh reconfirmation of an unchanged published tree. The auditable sealed bootstrap and its pure controls pass. Actual integrated native launch, publication and interruption behavior still require qualification. Private undo after a restart preserves uncertain ownership and remains refused, as allowed by the recovery contract. Production use requires a genuine signed v2 threat feed; explicitly labelled test-authority evidence may exercise native transaction mechanics without publishing one. No package code executes through materialization, and npm/Python package execution remains disabled. These are implementation and external-evidence gaps as well as native qualification work. |
| WP27 | verified at 6e79b3dd | Native Linux aarch64 deny-all filter is registered; native primitive/filter probes passed. Both GNU and musl launchers built with Rust 1.83 and each passed sixteen native unprivileged containment/runtime/interruption cases. Native ARM GNU/musl CI checks also passed on 13e18ca8. Both canonical GNU/musl ARM PR release archives at e282d038 and 6e79b3dd pass all sixteen native cases as UID65534, including parent/guard interruption and confirmed cleanup. This closes the selected native backend contract on those exact PR bytes. An eventual official release must bind its own artifact identities; it is not a prerequisite for this capability review. |

The focused privilege changes are reviewed separately in
[PR 251](https://github.com/sheeki03/tirith/pull/251) and
[PR 252](https://github.com/sheeki03/tirith/pull/252). The latest revision removes
sudo package suggestions as well as hard dependencies and describes privileged
approval availability separately from ordinary protection. Exact heads
`356981b8` and `3dce8f2d` each have 53 passed checks, 12 expected skips and no
failures. These separate PR results do not certify the larger cycle branch.
The focused private-input execution refusal in
[PR 254](https://github.com/sheeki03/tirith/pull/254), exact head `0f679ac4`, also
has 53 passing checks and 12 expected skips. On cycle commit `897bad30`, Linux,
macOS and Rust 1.83 workspace jobs passed; Windows detected and cleaned up a
surviving build descendant and refused qualification. The later `c3445508` run
compiles Windows successfully and passes the native standard-account dashboard
checks with cleanup. Its workspace result still fails a parser regression and a
Windows path fixture; these remain distinct from the earlier build failure.
The later `415565d3` run passes all sixty Windows workspace harnesses, including
nine dashboard checks under a standard account, plus six noninteractive
PowerShell cases. Native ARM GNU/musl and all six PR release target builds also
pass, as do npm assembly and the release compatibility gate. On the later `094c72a9` run, Unix PTY tests pass; release builds, native ARM,
fuzz and benchmark workflows also pass. CI still fails one stale receipt-schema
fixture across platforms and six Linux setup tests because full test debug
information makes the actual CLI harness exceed the unchanged 512 MiB binary
identity bound. Corrections use declared receipt readers and line-table
test debug information. All five workflows pass on `87c0fdee`, including Linux,
macOS, Windows and Rust 1.83 CI, six release target builds, native ARM, fuzzing
and benchmarks. The later `2cde4cee` passes release builds, native ARM, fuzz and benchmark
workflows. Its CI fails three lints, two Linux legacy state-path fixtures and a
Windows POSIX metadata fixture. Those corrections are integrated in e282d038,
which passes all five workflows and the complete local workspace suite. The Windows standard-account dashboard cases pass separately.
September 27 also integrates the fish parent-umask fix for #265 (153 native
fixture cases passed) and conservative Unix virtual-filesystem discovery for
#266 (405 policy-selected tests passed). Neither result qualifies a final
release. These are source/debug and PR package results, not official release or
interactive Windows shell certification. See [verification](verification.md) for
retained evidence.

Contracts and evidence:

- [Baseline inventory](baseline.md) and [acceptance matrix](acceptance-matrix.md)
- [Beginner pilot procedure and blank record](beginner-pilot.md)
- [Policy snapshots](policy-snapshots.md) and [profile ownership](protection-profiles.md)
- [Output contracts](output-contracts.md), [trust grants](trust-grants.md), [recovery](recovery.md)
- [Shell targets](shell-targets.md), [bounded history](history.md), [ThreatDB operations](threatdb-operations.md)
- [Dashboard design](dashboard-design.md) and [verification](verification.md)
