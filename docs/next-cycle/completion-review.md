# Implementation acceptance reconciliation

This review maps the implementation plan's 24 acceptance rows and six everyday
journeys to `aa88c7ae902d392b7d51b54bb44acdfb6dbccc3c`. The matrix groups
WP19/22/25/27; its absent A19/A22/A25 numbers are intentional. The later
`2d723b0f` correction changes the Windows process query. Subsequent fixes cover
Windows snapshot/writer coordination, lifecycle pipe framing/failure reporting
and the Linux protected-exec prerequisite. All five ordinary workflows now
pass at `aa88c7ae`, including the corrected Windows native paths. Actual npm
execution and service-worker composition retain their separate open checks.

All 660 retained ordinary `d0213a22` compiler inputs were compared with their
Git blobs and the review revision: 649 are unchanged, eleven differ, and the
three recorded absent inputs remain absent. The differences cover trusted
Windows child startup, shell targets, Windows snapshot coordination, lifecycle
transport/diagnostics and the protected Linux exec prerequisite. No retained
compiler input was added or removed. Source-binding SHA-256:
`d701be016e9bdd1bdf2fe9fdb9856c54eeb65f2a597a6186ba3543a63acc6f61`.
This comparison supports reuse of unchanged-path evidence; it does not relabel
a historical executable as a new build.

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
| A15: lifecycle | Numeric update/rollback, three observed death boundaries, retained/fresh Zsh and Claude, and owned removal mapped; actual production worker handoff remains open |
| A16: ThreatDB | Actual empty-cache acquisition and primary/fallback verification of the production-signed v1 generation mapped; publisher recovery and signed source-provenance publication remain operational acceptance |
| A17: performance | Recorded shell/host/daemon distributions, CPU/RSS/disk observations, natural trust expiry and the six existing byte limits mapped |
| A18: documentation and release use | Six routes and seventeen command smoke checks mapped; consented beginner pilot and final package/channel acceptance remain open |
| A20, A21, A23: project/npm inspection and comparison | Bounded no-execution readers, corpus/fuzz, exact identities and CLI/browser evidence mapped for G2 review |
| A24: task modelling and optional team server | Conservative effects and 35 actual HTTPS/browser cases mapped; publication does not prove fleet adoption |
| A26: npm installation and selected ARM backend | GNU/musl backend qualified on the recorded canonical PR archives; integrated npm execution remains unqualified and its gate remains closed |

The six [everyday routes](user-journeys.md) have concrete observed components:
recommended terminal setup/fresh activation, actual agent hook/reload behavior,
read-only project inspection, narrow interruption recovery, numeric replacement,
and ownership-preserving removal. These compose with the unchanged current
paths. Final official artifact and beginner observations remain separate from
those automated observations. The upgrade route additionally needs the actual
service-to-worker-to-replacement-service result.

No unspecified longer fuzz campaign, additional historical schema, new agent
adapter, external fleet deployment or universal latency threshold is added by
this reconciliation. G0 has its corrected A04 evidence for review; G1 retains A15/A16/A18;
G2 has no newly identified implementation gap; G3 stays separate by capability.
Neither this review nor a passing PR build authorizes or establishes an official
release or a completed human pilot.
