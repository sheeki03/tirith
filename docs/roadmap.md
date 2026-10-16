# Roadmap

This roadmap separates published behavior, the unmerged 0.5.0 integration
candidate, and later capabilities that are not current release commitments.
Presence in the repository or a pull request is not the same as availability
in a package-manager release.

The [capability matrix](capability-matrix.md) is the per-command companion: it
records what each command inspects and whether policy fully governs that
surface. It is generated from the versioned
[`capability-manifest.toml`](capability-manifest.toml) and guarded by a CI test.

## Published foundation: 0.3.3

The earlier 0.3.3 release established the shell, CLI, policy, and
threat-intelligence foundation:

- interactive zsh, bash, fish, PowerShell, and nushell integrations with
  explicit blocking/warn-only/degraded states;
- command, paste, URL, repository, AI-config, terminal-output, and hidden
  content analysis;
- signed ThreatDB v1 package/domain/IP reputation and optional runtime
  enrichment with a hard offline boundary;
- policy, trust, custom rules, warning accumulation, audit/export, doctor,
  daemon, LSP, GitHub Action, pre-commit, and SARIF surfaces;
- initial agent integrations, MCP server/gateway, configuration locking, caller
  origin, and workstation/persistence guards;
- signed release checksums, package-manager-aware updates, provenance display,
  and self-verification.

See the historical [0.3.3 changelog](../CHANGELOG.md#033---2026-06-19) for the
exact release contents.

## Published: 0.4.0

These capabilities shipped in 0.4.0:

- **Python artifact pipeline:** typed coverage outcomes, byte/magic
  classification, a hardened streaming wheel reader, RECORD/ownership
  integrity, startup-hook analysis, native ELF/Mach-O/PE triage, execution
  chains, artifact-set correlation, and `package inspect` product wiring.
- **Python package firewall:** quarantine, exact digest binding, enrolled
  resolver identity, native approval authority, contained hash-pinned pip
  installation, environment verification, provenance graphs, release diffs,
  PyPI attestation binding, and receipts. Enforcement is x86_64 Linux only.
  The next release (0.5.0) removes the pip resolve, quarantine, firewall and
  approval-issuance pipeline: `pkg install` and `pkg approve` refuse with
  `private_input_execution_unqualified`, while inspection, environment
  verification, provenance graphs, release diffs and reading existing receipts
  remain.
- **ThreatDB v2:** artifact/file hashes, malicious URLs, campaign and behavior
  indices, signed dual-format publication, monotonic rollback protection, and a
  staged v1/v2 cutover.
- **Detection expansion:** structural GitHub Actions findings, reverse shells,
  suspicious inline interpreters, additional credential formats, PDF depth and
  compressed-stream guards, and safe terminal rendering.
- **Systemic hardening:** supervised execution, transactional setup/install and
  state publication, no-follow/retained-handle identity checks, bounded
  network/feed/MCP/artifact work, centralized redaction, private audit/receipt
  state, license-event ordering, and immutable release inputs.

### Additional 0.4.0 capabilities

The release also includes:

- bounded Web3 command grammar and `web3_guard` policy for Cast, Forge,
  Hardhat, Solana, and Anchor;
- untrusted task envelopes, `task_gate`, diagnostic `task check`, and the
  preview-gated MCP task tool;
- fail-closed `capsule run --preset untrusted-project` on supported x86_64
  Linux hosts;
- cross-workflow CI artifact-flow analysis, Chromium-family extension audit,
  npm provenance receipts, and build/deployment receipts;
- sensitive wallet/secret/path handling and extended exfiltration correlation;
- bounded MCP structured output, blob, MIME, URI, redaction, descriptor, and
  source/config identity controls;
- 19 named `tirith setup` hosts, including blocking Prime Agent, OMP, Cline,
  and OpenHands hooks, a Windows PowerShell Cline wrapper, and Prime Agent
  IPython execution-vector extraction;
- order-independent package enrichment with typed incomplete outcomes instead
  of timeout-derived malicious-package warnings;
- GLIBC 2.28 Linux release compatibility, canonical Debian/RPM bytes, and
  expanded crates/npm/container/Chocolatey/AUR publication gates.

The [0.4.0 release notes](release-notes-0.4.0.md) are the detailed feature,
upgrade, compatibility, and limitation inventory.

## Published: 0.4.1

A patch release on the same line. It adds no command and changes no schema. The
one behavioural change is that bash enter mode now delivers and blocks, so an
ordinary bash install blocks instead of only warning; the remaining entries fix
silent downgrades to legacy mode through symlinked installs and zsh prompt
frameworks, correct several misleading advisories, recognize safely owned
Hermes installs as self-replaceable, and move ThreatDB source pinning onto one
reviewed manifest with a proposal-only watcher. The
[0.4.1 release notes](release-notes-0.4.1.md) carry the upgrade guidance.

## Published: 0.4.2

A reliability and performance patch. It fixes NixOS helper resolution, npm
shell receipt activation, several ordinary-command false positives, ThreatDB
publication and cache reloads, and misleading update/diagnostic messages.
Custom-rule compilation, regex retention, recent-log reads, and legacy session
correlation perform less repeated work. The
[0.4.2 release notes](release-notes-0.4.2.md) describe the fixes and upgrade steps.

## Unreleased: 0.5.0

Implemented on the integration stack after 0.4.2, not merged or published. The
[changelog](../CHANGELOG.md#unreleased) is the full list. The release must be
`0.5.0` because it removes and changes `tirith-core` library API; development
binaries still report the previous workspace version until the release cutover.

- **Added:** versioned protection profiles and typed personal settings with
  reviewable, undoable operations; reviewed profile rollouts and
  `policy simulate`; `tirith setup recommended` and `setup shell`; scoped,
  expiring trust grants; the authenticated local dashboard; hook freshness and
  current-shell verification in `status` and `doctor`; `tirith review` for
  project files; npm tarball inspection and release comparison; team policy.
- **Removed:** the pip resolve, quarantine, firewall and approval-issuance
  pipeline and the private-input launcher (`pkg install` and `pkg approve`
  refuse), plus `tirith-core` library API listed in the changelog.

### Retained build scope

These are the ten retained workstreams, not ten new products. The owner-approved
cutover replaces automatic activation with hook freshness/manual verification,
and the menu with task-oriented help. npm install/materialize, pip execution,
the private-input launcher, pinned Claude setup, and browser binary
update/rollback are removed. Team policy, automatic refresh/offline grace, and
the guarded dashboard ThreatDB refresh button remain.

| Workstream | Implemented candidate surface | Remaining qualification or delivery boundary |
|---|---|---|
| 1. Profiles and effective policy | [Comfortable/Balanced/Strict and typed settings](profiles-and-settings.md), effective-source explanation, comment-preserving plans and exact-byte undo | Mandatory organization/team restrictions cannot be weakened by personal settings |
| 2. Explanation and precision | `explain`, [frozen policy simulation/rollouts](policy-rollouts.md), recovery advice, audit feedback and tuning | Feedback is a review label, not trust; incomplete intelligence is not a clean result |
| 3. Onboarding and complete CLI | `setup recommended`, manual `setup shell`, task-oriented help, [optional authenticated dashboard](dashboard.md) | No account or browser required for protection; activation is not proof of blocking |
| 4. Narrow recovery | [Scoped/expiring trust grants](trust-grants.md), revoke/expiry/diff/gc, owned shell receipts and operation recovery | Exact scope, replay and remaining blockers still apply; disabled package execution cannot be approved back on |
| 5. Honest surface status | Hook freshness in `status`/`doctor`, [caller-shell blocking challenges](caller-shell-verification.md), agent adapters and the separate Hermes plugin | Loaded/current and observed blocking are distinct; native certification is per host/version/platform |
| 6. Installation lifecycle | Channel-aware install/update/rollback/removal, ownership and persisted-format checks, [release gates](release-checklist.md) | Final merged bytes, platform/package assembly and registry publication remain required; binary updates stay in the terminal |
| 7. Threat intelligence operations | [Freshness and bounded retries](threatdb-freshness.md), verified cache recovery, guarded dashboard refresh, [team policy refresh/grace](team-policy.md) | Production signing/feed rollout is separate from source tests; stale/incomplete data remains visible |
| 8. Performance and durable history | Allocation ceilings, bounded recent history, pagination, reviewed audit retention/export/deletion | x86_64 allocation ceilings passed the existing agent-workload CI; the final changed tree still needs its own CI. Component counts are not universal end-to-end latency promises |
| 9. Privacy and interfaces | Redacted machine contracts, typed schema-4 recovery, task guides and [user journeys](user-journeys.md) | Schema-3/4 execution consumers must honor `requires_approval`, including strict-warning acknowledgement; an absent/invalid flag is not permission |
| 10. Extended project protection | [Read-only project review](project-review.md), [exact npm tarball inspection/diff](npm-inspection.md), bounded task effects, team adoption, Linux AArch64 containment | Inspection is not installation authorization; arbitrary notebook interception/full Web3/browser monitoring remain later work |

### Issue and integration closure

All entries below concern candidate implementation, not merged issues or shipped
packages. The current stack is [Tirith #250](https://github.com/sheeki03/tirith/pull/250)
→ [#274](https://github.com/sheeki03/tirith/pull/274)
→ [#275](https://github.com/sheeki03/tirith/pull/275), plus
[Hermes plugin #1](https://github.com/sheeki03/hermes-plugin-tirith/pull/1).
Existing green CI belongs to those recorded commits, not later local fixes.

| Report | Candidate resolution and limits |
|---|---|
| #249 | Native packages no longer require/recommend sudo for ordinary protection; privileged helper installation remains explicit and optional |
| #255 | Curl option roles and both DNS/numeric host readings are retained; ambiguous spellings do not acquire blanket trust |
| #257 | Fresh interactive sessions have independent identity; stale receipts recover without losing replay protection |
| #260 | Literal bracket conditions and bounded arithmetic work; executable substitutions remain inspected |
| #261 | Android clipboard/errno portability and compile coverage are present; no claim of physical-device qualification or compatible prebuilt installer |
| #264 | Literal command indirection and safe Python data pipelines work within documented scope; dynamic rebinding, inspect mode and downloaded inline Python/Node source remain guarded |
| #265 | Fish capture restores the caller's umask, including failure/interruption paths |
| #266 | Proven-absent virtual-filesystem names are ignored conservatively; the reported KDE environment still needs native reproduction |
| #269 | Default version and oldest publication metadata are retained before bounding/caching versions; the original retained prefix is not arbitrarily overwritten |
| #270 | Shell redirections are not package operands; a legitimate uncached package still produces an incomplete-intelligence warning |
| #271 | Tagged private-registry trust uses the registry authority, not an SCP interpretation of the tag colon; attacker suffix/path hosts remain untrusted |
| #273 | Fish multiline capture and receipt comparison use the same newline-preserving collection |
| #276 proposal | Exact literal npm view/info/show/v selectors are handled independently; real registry URLs and wrapper/SCP destinations remain inspected. No contributor PR merge is required |
| Hermes integration | Explicit approval and warning acknowledgement precede filters; bounded prompts retain command/CWD; overlapping/unknown input fails closed by default, elapsed time cannot confirm delivery, and reused provider IDs are scoped to the request lifecycle |

The scanner still provides bounded evidence, not a promise that every attack is
prevented. Ordinary warnings run by default. The corpus reports proposed
decisions separately from execution, failed checks and database-dependent rows
that are not asserted without intelligence.

### Hermes delivery

The plugin is implemented in
[`sheeki03/hermes-plugin-tirith`](https://github.com/sheeki03/hermes-plugin-tirith),
requires the 0.5.0 check contract, and does not install Tirith. Local native
verification covers the 0.21.5 canary source and current stable Hermes 0.21.7;
Windows native host qualification and final cross-platform candidate CI remain
separate. Callback-order/expiry checks are lifecycle simulations with the real
scanner, not executed concurrent-shell exploits.

Ship Tirith 0.5.0, publish the reviewed plugin tree, then submit a catalog entry
with its final immutable commit. Until then, neither the catalog command nor an
unpinned install from the placeholder default branch is a valid release path.
Do not promise automatic migration: the
[latest maintainer direction](https://github.com/sheeki03/tirith/issues/272#issuecomment-6057907776)
withdraws the v50 migration pointer and asks for catalog-based discovery.

### Release acceptance still external

- Merge/review the full stack and run the required platform, package assembly
  and host matrices on the exact final tree; publish and verify each channel.
- Complete production ThreatDB signing/feed rollout on the final released
  artifacts. A local cache/default-version smoke does not close that gate.
- Qualify physical Android/Windows and the reported virtual filesystem only
  when those environments are available; do not relabel compile tests as
  device evidence.
- Record a consented beginner activation/recovery/upgrade/removal pilot.
  Source implementation or generated examples cannot substitute for participants.


## Publication contract

A release is cut only from the final default-branch tree after the cross-platform
and package-assembly gates pass on that exact commit. Known issues are
explicitly deferred in the changelog, and publication uses the protected,
single-use tag workflow. Registry state is verified independently after the
workflow completes; Chocolatey moderation and Homebrew core bottle publication
may lag and are reported separately.

## Later

- Broader containment beyond Linux (x86_64 and AArch64 are supported today)
  without weakening the current fail-closed capability contract.
- Kernel/runtime interception for arbitrary Python and notebook process
  creation; source-level IPython extraction cannot provide that guarantee.
- Broader host certification and recurring real-agent end-to-end tests across
  every supported integration and platform.
- Expanded task-effect modelling and complete audit coverage at every owned
  irreversible transition.
- Full Web3 command coverage, live command-card authoring/enforcement, and
  activation or removal of currently inert policy fields.
- Continuous browser/deployment monitoring and reproducible-build workflows,
  if added as explicit products rather than inferred from point-in-time
  receipts.
