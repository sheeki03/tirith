# Implementation acceptance reconciliation

This review maps the implementation plan's 24 acceptance rows and six everyday
journeys to `aa88c7ae902d392b7d51b54bb44acdfb6dbccc3c` and its reviewed
Linux tmpfs correction at `83468789faa4fcb604177420ef5c3bb4c467e141`.
The matrix groups WP19/22/25/27; its absent A19/A22/A25 numbers are intentional.
The `2d723b0f` correction changes the Windows process query. Subsequent fixes cover
Windows snapshot/writer coordination, lifecycle pipe framing/failure reporting
and the Linux protected-exec prerequisite. All five ordinary workflows now
pass at both checkpoints, including the corrected Windows native paths. Actual
Linux service-worker composition passes at `83468789`. The later corrected
npm source at `bd9d5068`, with the isolated qualified platform gate in
`24048758`, passes the complete supported native transaction/CLI contract as
recorded in verification. Its production feed prerequisite remains open.

All 660 retained ordinary `d0213a22` compiler inputs were compared with their
Git blobs and `aa88c7ae`: 649 are unchanged, eleven differ, and the
three recorded absent inputs remain absent. The differences cover trusted
Windows child startup, shell targets, Windows snapshot coordination, lifecycle
transport/diagnostics and the protected Linux exec prerequisite. No retained
compiler input was added or removed. Source-binding SHA-256:
`d701be016e9bdd1bdf2fe9fdb9856c54eeb65f2a597a6186ba3543a63acc6f61`.
This comparison supports reuse of unchanged-path evidence; it does not relabel
a historical executable as a new build.

The later `83468789` capture contains 661 paths: 659 are identical to `aa88c7ae`,
`trusted_child.rs` changes and `trusted_child/tmpfs_acl.rs` is added. The new
native ACL controls and full Linux worker composition pass on the ordinary GNU
package. The actual PR build uses merge `e8541cf1`, whose only captured-input
difference from the head is main's daily, test-included ThreatDB manifest. Both
exact source inventories and that difference are retained in verification.

The preceding `ad0b69ca` review rehashes 41 retained receipts/documents. Its report SHA-256 is
`56322c66493fa90d9fdf2d0a6cd9e509f00ecf550b0569bd79ec3083dde76cb9`.
Exact runs, binaries, sample units and limitations remain in
[verification](verification.md). Earlier unchecked inventory notes describe
their original checkpoint and are superseded by later applicable results.

| Acceptance scope | Review disposition |
| --- | --- |
| A00–A03, A05: baseline, policy, pure evaluation, privacy, profiles | Implementation and applicable compatibility/core/browser evidence mapped |
| A04: shell targets | Corrected Windows 5.1/7 product queries and Linux/macOS default/private-XDG targets pass at aa88c7ae; automatic adapter scope remains explicit |
| A06–A14: durable operations, trust, recovery, tuning, setup, hosts, history, local service and browser | Supported operations and advertised host tuples mapped; worker handoff is tracked once under A15 |
| A15: lifecycle | Numeric macOS update/rollback, three observed death boundaries, retained/fresh Zsh and Claude, and owned removal mapped; actual GNU ARM service-worker replacement, fresh authentication, saved retry and cleanup also pass. Final official channel acceptance remains under WP19 |
| A16: ThreatDB | Actual empty-cache acquisition and primary/fallback verification of the production-signed v1 generation mapped; publisher recovery and signed source-provenance publication remain operational acceptance |
| A17: performance | Recorded shell/host/daemon distributions, CPU/RSS/disk observations, natural trust expiry and the six existing byte limits mapped |
| A18: documentation and release use | Six routes and seventeen command smoke checks mapped; consented beginner pilot and final package/channel acceptance remain open |
| A20, A21, A23: project/npm inspection and comparison | Bounded no-execution readers, corpus/fuzz, exact identities and CLI/browser evidence mapped for G2 review |
| A24: task modelling and optional team server | Conservative effects and 35 actual HTTPS/browser cases mapped; publication does not prove fleet adoption |
| A26: npm installation and selected ARM backend | GNU/musl backend qualified on the recorded canonical PR archives. The narrow GNU Linux AArch64 npm contract passes exact installation, cancellation, post-completion unwinds, lifecycle suppression, implicit-build refusal and public CLI history/retry checks with an explicitly isolated key. Ordinary use still requires production-signed v2 data; general npm/Python execution stays disabled. (Historical: the local-leaf npm routes were retired before release.) |

The six [everyday routes](user-journeys.md) have concrete observed components:
recommended terminal setup, actual agent hook/reload behavior,
read-only project inspection, narrow interruption recovery, numeric replacement,
and ownership-preserving removal. These compose with the unchanged current
paths. Final official artifact and beginner observations remain separate from
those automated observations. The upgrade route now includes the actual Linux
service-to-worker-to-replacement-service result with same-version packages and
synthetic prior history; it does not relabel that check as a numeric upgrade or
an observed macOS dashboard composition.

No unspecified longer fuzz campaign, additional historical schema, new agent
adapter, external fleet deployment or universal latency threshold is added by
this reconciliation. G0 has its corrected A04 evidence for review; G1 retains
A16/A18 and final WP19 release acceptance;
G2 has no newly identified implementation gap; G3 stays separate by capability.
Neither this review nor a passing PR build authorizes or establishes an official
release or a completed human pilot.
