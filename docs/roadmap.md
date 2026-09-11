# Roadmap

This roadmap separates published behavior, code already merged after the last
release, and capabilities that exist only on the current integration stack.
Presence in the repository or a pull request is not the same as availability
in a package-manager release.

The [capability matrix](capability-matrix.md) is the per-command companion: it
records what each command inspects and whether policy fully governs that
surface. It is generated from the versioned
[`capability-manifest.toml`](capability-manifest.toml) and guarded by a CI test.

## Published foundation: 0.3.3

The latest published release line established the current shell, CLI, policy,
and threat-intelligence foundation:

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

## Publication contract

A release is cut only from the final default-branch tree after the cross-platform
and package-assembly gates pass on that exact commit. Known issues are
explicitly deferred in the changelog, and publication uses the protected,
single-use tag workflow. Registry state is verified independently after the
workflow completes; Chocolatey moderation and Homebrew core bottle publication
may lag and are reported separately.

## Later

- Broader containment beyond x86_64 Linux without weakening the current
  fail-closed capability contract.
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
