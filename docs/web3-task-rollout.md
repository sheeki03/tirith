# Rollout and rollback: the Web3 and untrusted-task boundary

This is the operator runbook for the release that adds the Web3 command guard,
the untrusted-task boundary, and the explicit audit and receipt commands. It
names who does what, what each stage must prove before the next one starts, and
exactly how to back out.

The companion documents are
[enforcement coverage](enforcement-coverage.md) for what each capability can
actually do, and [compatibility](compatibility.md) for the surface contracts.

## Roles

| Role | Owns |
|---|---|
| **Release owner** | the merge window, the ThreatDB workflow procedure, and the sign-off on this playbook |
| **Operator** | the user or org policy: whether `web3_guard` and `task_gate` are configured at all, and at what mode |
| **Repository** | may tighten. It can never authorize, name a trusted network, introduce a signer, relax an action, or loosen the task-gate mode |

## What is on by default

No new GATE becomes active, and no new configuration is required. But the Web3
detection rules are NOT gated on configuration, so an unconfigured installation
does get new findings after upgrade. A release owner must plan for that.

Measured on an installation with no policy file at all
(`"policy_path_used": null`):

| Command shape | Result |
|---|---|
| `cast send <addr> --value 1ether --rpc-url <endpoint> --keystore <path>` | **`warn`**, `web3_state_changing_command` MEDIUM |
| `cast send <addr> --unlocked --from <addr> --rpc-url <endpoint>` | **`warn`**, `web3_state_changing_command` MEDIUM |
| `forge script script/Deploy.s.sol --broadcast --rpc-url <endpoint>` | **`warn`**, `web3_state_changing_command` MEDIUM |
| `solana program deploy <path>` | **`warn`**, `web3_state_changing_command` MEDIUM |
| `anchor deploy --provider.cluster mainnet` | **`warn`**, `web3_state_changing_command` MEDIUM |
| `cast send <addr> --private-key <hex>` | `block`, `web3_signer_risk` CRITICAL plus the pre-existing `private_key_exposed` CRITICAL |
| `cast send <addr> --mnemonic "<words>"` | `block`, same pair |
| `cast send <addr> "transfer(address,uint256)" <addr> 1` (no endpoint, no signer) | `allow`, no findings |
| `cast call ...`, `solana transfer ... --keypair <path>` | `allow`, no findings |
| `npx hardhat run scripts/deploy.js --network mainnet` | `allow`, no findings |
| `forge create ...` | `allow`, no findings (no grammar arm; see the known limits) |

The practical upgrade impact is a new MEDIUM warn on the state-changing shapes
the grammar recognizes: `cast send` against an endpoint, `forge script
--broadcast`, `solana program deploy`, and `anchor deploy`. Foundry, Solana, and
Anchor users will see it on routine work, so Stage 1 below is a burn-in for that,
not a no-op. Hardhat `run` and `solana transfer` as probed do not trigger it.

`web3_signer_risk` reaches CRITICAL and blocks for raw key and mnemonic material
in argv. That is a new finding rather than a new refusal: the pre-existing
`private_key_exposed` rule already blocked those exact commands, so the change is
a clearer reason, not a newly forbidden operation.

Quieting it takes a USER or ORG policy. A repo-scoped `.tirith/policy.yaml`
cannot do it: `severity_overrides` is weakening, so it is neutralized. `tirith
check` warns on stderr that the field was ignored, `tirith policy effective`
lists `severity_overrides` under "Neutralized", and the finding stays MEDIUM at
action `warn`. In `~/.config/tirith/policy.yaml` or the org policy root, the
same override takes effect and the command returns `allow`:

```yaml
severity_overrides:
  web3_state_changing_command: low
```

Everything else in this release is genuinely inert until configured:

- `task_gate.mode` defaults to `off`, and an `off` gate does not even write an
  audit line.
- `web3_guard` defaults to no networks, no signers, no denials, and every action
  at `warn`. With no trusted networks declared, the unclassified-endpoint path
  does not fire at all.
- The seven curated `tirith policy init --template` policies mention neither
  `web3_guard` nor `task_gate`, so scaffolding a policy does not opt anyone in.
- `tirith_check_task` is absent from the default MCP `tools/list` and is refused
  by name without `TIRITH_MCP_PREVIEW=1`.
- `tirith task check`, `tirith capsule run`, `tirith browser audit`,
  `tirith pkg attest-npm`, and the four `tirith attest` subcommands never run
  implicitly. They are explicit commands with no daemon, no background monitor,
  and no scheduler.

What IS active immediately, because it is correctness rather than new authority:
ThreatDB publication correctness, byte-based content dispatch, exclusive PDF
routing, the global finding and output budgets, mandatory secret redaction,
repo-policy sanitation, and the Web3 detection findings themselves.

## Stage 0: before merge (release owner)

1. **Pause the scheduled ThreatDB workflow** and independently verify the
   disabled state. The workflow is `.github/workflows/threatdb.yml` on a
   `15 4 * * *` cron. It must not run against the corrected compiler until the
   shadow build has been reviewed.
2. **Keep the signed last-known-good database active** for clients throughout.
3. **Run one full shadow ThreatDB build** against pinned live-shape snapshots.
   Record per-source accepted, rejected, withdrawn, and unresolved counts, and
   the pinned source revisions.
4. **Run the `@solana/web3.js` boundary regression.** `1.95.5` clear, `1.95.6`
   malicious, `1.95.7` malicious, `1.95.8` clear. A patched version falsely
   blocked is a release stop, not a bug report.
5. **Verify backward compatibility loads:** a pre-existing policy, a v1 command
   card, a v1 and a v2 database, the frozen default MCP tool list, and legacy
   receipts.
6. **Confirm PR CI needs no new external network.**
7. **Re-enable the workflow only after** source revision, count, and signing
   verification, then trigger and monitor one deliberate verification run.
   Disable again on drift.

**No new live feed and no new database format is enabled by this release.** No
Polkadot, MISP, PhishTank, ScamSniffer, or Chainabuse channel is activated, and
no ThreatDB v3 asset exists to shadow v2. What the compiler gained is
correctness on sources that were already in the workflow, the existing typosquat
input path wired through end to end, and a bounded, pinned package-version
snapshot fetched inside the same audited source transaction. Every one of those
is attributed in `NOTICE`.

## Stage 1: merge with safe defaults

Merge with everything above at its default. No gate becomes active without an
operator asking for it.

Do not skip burn-in here. As "What is on by default" records, the Web3 detection
rules are live on upgrade, so `cast send` against an endpoint, `forge script
--broadcast`, `solana program deploy`, and `anchor deploy` start returning a
MEDIUM `web3_state_changing_command` warn. Budget for that support load, and
have the user-scope `severity_overrides` snippet ready before you ship.

Confirm on the merged build:

- `tirith policy effective` on an installation with no `web3_guard` or
  `task_gate` section prints the inert defaults;
- `tirith mcp-server` advertises the frozen six-tool default list (seven on
  Unix, with `tirith_fetch_cloaking`), and not `tirith_check_task`;
- `tirith --help` lists `task`, `capsule`, and `attest`, and
  `every_command_is_categorized` passes.

## Stage 2: observation burn-in (operator)

Turn the boundary on in a recording mode and read what comes back.

```yaml
# user or org scope only
task_gate:
  mode: observe
```

**Know what observe mode actually records before you plan around it.** Exactly
one of the nine owned boundaries writes anything:
`BoundaryAssessment::is_recordable()` (`crates/tirith-core/src/task_boundary.rs:203`)
has a single production caller, `crates/tirith/src/cli/gateway.rs:3214`, and
`write_task_boundary_audit` is defined and called only there (`gateway.rs:4227`).
So `gateway_forward` produces audit-chain lines, and `package_approval`,
`package_resolve`, `package_install_preparation`, `package_manager_network`,
`package_manager_execution`, `remote_script_run`, `config_write`, and
`capsule_preset_run` produce nothing at all, in any mode. Running
`tirith pkg approve` under `mode: observe` creates no audit file anywhere.

The records that do exist land in the standard audit chain, so read them with
`tirith audit` (and note `TIRITH_LOG=0` disables that chain entirely). For the
other eight boundaries there is nothing to read, so plan the burn-in around the
gateway, or instrument the boundaries you care about outside tirith. Adding
records at the other eight is a behaviour change and therefore a future slice.

Optionally declare `web3_guard` networks and signers so the endpoint and signer
rules have something to compare against. Leave every `action_*` at `warn`.

Collect only privacy-safe aggregates: rule id, version, and action; the source
TRUST CLASS rather than source content; the secret TYPE, never a value, hash, or
prefix; the sink class; the Web3 tool, operation, and production or test class;
capability requested, allowed, and denied with a reason code; whether the parser
was complete; boundary requested versus achieved; the tier reached and elapsed
time; whether an evidence or work budget was hit; and the ThreatDB per-source
counters with the pinned revision.

Do not record wallet addresses, signer identifiers, mnemonics or their hashes,
raw RPC paths or credentials, raw commands, raw wallet or browser paths, task
bodies or source content, browser cookies, storage, or preferences, or build
source text. The redaction contract already keeps these out of tirith's own
surfaces; an aggregation pipeline built on top must not reintroduce them.

### Promotion gate: observe to enforce

Do not promote until all of these hold:

- no verified secret material in any output or persistent artifact;
- no false production-policy block in the reviewed corpus or in real use;
- no material wallet-path false-positive cluster;
- the incomplete rate is understood per tool and per boundary. Only the gateway
  can supply this from records; for the other eight boundaries it has to come
  from `tirith task check` against representative commands, or from your own
  instrumentation;
- CLI, MCP, and gateway decisions agree;
- hot-path budgets are met;
- every enforcing backend reports its required controls achieved;
- the operator has actually configured trusted networks, signers, and RPC
  matchers wherever production enforcement is wanted. An enforcing gate over an
  empty policy is not a security posture. Command-card keys are deliberately NOT
  on this list: no surface checks a Web3 card, so configuring
  `command_card_key_ids` adds nothing to a promotion decision.

## Stage 3: owned-boundary enforcement (operator)

Enable in this order, one step at a time, with burn-in between:

1. raw signer material and secret exfiltration stay enforced (they already are,
   through the existing block-level findings);
2. gateway config, persistence, and package effects;
3. the package and install boundary;
4. the run and capsule boundary, where the backend reports achieved
   containment;
5. production Web3 network and signer requirements. There is no card
   requirement to enable: `require_command_card` is inert and no surface checks
   a Web3 card, so this step is `networks`, `allowed_signers`, and `deny_rpc`
   only;
6. the precise CI artifact-poisoning finding as a merge or release policy
   signal, if wanted.

```yaml
task_gate:
  mode: enforce
  effects_denied_for_untrusted_sources: [policy_change, package_install]
  action_incomplete_analysis: warn   # see the two notes below
```

**`action_incomplete_analysis: block` is narrower than it sounds, in both
directions.** Effect inference models the Web3 shell grammar and nothing else,
so nearly every ordinary SHELL command is incomplete. But the action only
applies when the assessment is incomplete
(`crates/tirith-core/src/task_boundary.rs:325-330`), and the four boundaries
that submit package or config-write envelopes always assess as complete
(`crates/tirith-core/src/task.rs:638-652`). So `block` refuses unmodelled shell
at five boundaries (`capsule_preset_run`, `gateway_forward`, `remote_script_run`
covering both `tirith run <url>` and `tirith install url <URL>`,
`package_manager_network`, and `package_manager_execution`) and changes nothing
at `pkg approve`, the two `pkg install` stages, or config writes. That is a real
protection with a real cost, not a setting that breaks everything. Start at
`warn`, measure your own incomplete rate on the five shell boundaries, and
decide.

**`effects_denied_for_untrusted_sources` denies the effect unconditionally.**
The name suggests it discriminates by origin; at these boundaries it cannot.
`SourceKind::is_trusted` returns `false` for every kind
(`crates/tirith-core/src/task.rs:71-73`) and every owned boundary passes
`IngressAdapter::Unattributed`, so the effect is filtered out on every call,
including the operator's own typed commands. With the snippet above,
`tirith pkg approve pip requests` refuses with "task gate denied these effects at
this boundary: package_install", and `tirith policy init` refuses with "task gate
refused this configuration write". Under `mode: observe` both are allowed, so the
mode is the only variable. Enable it deliberately, knowing it turns off those
commands for everyone on the host.

## Rollback

### Code and policy

- A trusted user or org policy reduces `task_gate.mode` from `enforce` to
  `observe` or `off`, and lowers any `web3_guard` action, at any time. A
  repository policy cannot.
- **Disabling enforcement never disables redaction, output caps, content
  dispatch, or feed correctness.** Those are not gated on any mode.
- Preview MCP advertisement is withdrawn by unsetting `TIRITH_MCP_PREVIEW`. The
  existing tool set is untouched.
- The explicit browser, npm, and receipt commands can be withheld from templates
  and internal documentation while receipt VERIFICATION continues to work on
  disk. Verification is read-only and does not depend on creation being enabled.
- Legacy policy parsing remains available. Tirith does not auto-write a
  schema-upgraded policy, so a binary rollback does not strand a user who never
  enabled the features.

### ThreatDB

- Retain the C01 correctness commit during any feature rollback. It is a
  publication-correctness fix, not part of the Web3 boundary.
- **Never repoint clients at a lower signed sequence.** Correct a bad source by
  publishing a NEW higher-sequence signed database that omits or withdraws the
  bad claim.
- Keep the last-known-good source snapshots and the immutable artifacts.
- Publication is already blocked when source counts collapse or explode, or when
  the Solana canary changes unexpectedly.
- There is no v3 asset to shadow v2 in this release.

### Receipts and preview surfaces

- Receipt verification stays read-only even when receipt creation is disabled.
- An unsupported newer receipt schema fails explicitly rather than being
  half-read.
- **Remove no user evidence during rollback.** Receipts already written are the
  operator's.
- The browser, npm, and attest commands have no background monitor or daemon to
  unwind.
- Untrusted-project ephemeral roots are cleaned or retained under the existing
  recoverable-failure policy, and the receipt reports which, with the location
  stated safely.

### Revert granularity

The stack is one commit per slice on purpose, so emergency response can retain
ThreatDB correctness, retain output safety, retain redaction, revert Web3
enforcement without removing Web3 detection, revert the task adapters without
removing the task diagnostics, disable one receipt or audit workstream
independently, and revert a documentation claim together with the feature commit
it describes. Do not squash before the security review and release window.

## Rollback triggers

Reduce enforcement or stop the release immediately on any of these:

- verified secret material in any output or persistent artifact;
- a production state-changing command incorrectly allowed under a complete
  trusted policy;
- a patched package falsely blocked, `@solana/web3.js@1.95.8` especially;
- a feed source-count collapse or explosion, or parser and schema drift;
- an MCP, CLI, or gateway decision divergence;
- a repository policy shown to enlarge authority;
- provenance receipt forgery, replay, or binding bypass;
- the capsule preset executing when a required control is unavailable;
- Tier-1 p95 over 2 ms, or a material hot-path regression;
- unbounded PDF, output, receipt, browser, or build resource behaviour;
- the browser audit reading prohibited private data;
- an SSRF, cross-origin, or private-network escape in deployment verification.

## See also

- [Enforcement coverage](enforcement-coverage.md)
- [Compatibility](compatibility.md)
- [Release checklist](release-checklist.md)
- [ThreatDB v2 rollout](threatdb-v2-rollout.md), the separate database-format playbook
