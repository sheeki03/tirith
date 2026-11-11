# Threat Model

This document describes Tirith 0.5.x.

## Assets

- **Developer machines**: workstations where commands are typed and scripts are executed
- **Shell sessions**: interactive shells (zsh, bash, fish, PowerShell) where pasted/typed commands run. Nushell is supported in warn-only mode.
- **Agent sessions**: coding-agent hosts whose shell tool calls an installed adapter checks before they run, and MCP traffic routed through `tirith gateway run`
- **Credentials and keys**: SSH keys, API tokens, cloud credentials accessible from the shell
- **Source code**: repositories cloned and modified on the machine
- **Tirith's own configuration and state**: policy files, trust grants, the installed shell hooks and agent adapters, execution receipts, the audit log and the threat database. Weakening any of these weakens every check that depends on it.

## Threat Actors

- **Malicious website operators**: craft copy-paste instructions with hidden payloads
- **Typosquatters**: register domains similar to popular packages/repos
- **Supply chain attackers**: compromise package registries, Docker registries, or Git repos
- **Social engineers**: convince developers to run commands via chat, email, or forum posts
- **Prompt-injected or misbehaving coding agents**: an agent that follows instructions hidden in a repository, a web page or tool output, and issues the resulting commands or MCP calls. Every agent tool call is untrusted input. The identity a caller reports (`TIRITH_INTEGRATION`, MCP `clientInfo`) is recorded for the audit log and is never treated as proof of who is calling.
- **Malicious or compromised MCP servers and clients**: both ends of `tirith gateway run` are untrusted. Requests are checked before they are forwarded. Tool output is inspected only when output filtering is enabled (`--filter-output` or the secure profile).
- **Hostile repositories**: a cloned repository can ship its own `.tirith/` files and can be the working directory of a shell or an agent. A repository-scoped policy may tighten checks and cannot weaken them (see Trust Boundaries).
- **Network attackers on Tirith's own channels**: someone able to tamper with the threat-database download or a release download.
- **A website open in the user's browser** while the local dashboard is running: it can send requests to a loopback port. The dashboard requires a session obtained from a single-use sign-in code, and a CSRF value on changes (see [the dashboard guide](dashboard.md)).
- **Another process running as the same user**: it can edit or delete Tirith's files, hooks and state, and preventing that is out of scope. The audit log's hash chain is the one control aimed at this actor, and it provides detection, not prevention.

## Attack Vectors Covered

The table lists representative vectors, not every rule. `tirith explain --list`
prints all of them (245 rule IDs in 0.5.0).

| Vector | Detection | Rules |
|--------|-----------|-------|
| Homoglyph/punycode domains | IDN analysis, confusable table | `confusable_domain`, `punycode_domain`, `mixed_script_in_label` |
| curl\|bash / wget\|sh, a download piped into `source` / `.` or `busybox sh` | Command shape analysis | `curl_pipe_shell`, `wget_pipe_shell`, `pipe_to_interpreter` |
| ANSI escape injection in a paste or a checked command (CRLF line endings exempt) | Byte scanning | `ansi_escapes`, `control_chars` |
| Bidi/zero-width Unicode tricks | Byte scanning | `bidi_controls`, `zero_width_chars` |
| Hidden newlines in paste | Content analysis | `hidden_multiline` |
| URL shortener obfuscation | Domain matching | `shortened_url` |
| Raw IP URLs | Host analysis | `raw_ip_url` |
| HTTP to sink commands | Scheme analysis | `plain_http_to_sink` |
| Docker untrusted registry | Ecosystem rules | `docker_untrusted_registry` |
| Git typosquatting | Levenshtein distance | `git_typosquat` |
| Double-encoded paths | Normalization | `double_encoding` |
| On-chain writes from a compromised or careless command | Bounded Cast / Forge / Hardhat / Solana / Anchor grammar | `web3_state_changing_command` |
| Signer material on the command line | Same grammar, signer KIND only | `web3_signer_risk` |
| An RPC endpoint or signer the operator did not trust | `web3_guard` comparison | `web3_network_policy_violation` |
| Wallet, keystore, or seed material flowing to a remote sink | Source-to-sink dataflow over the reviewed asset catalog | `data_exfiltration`, `credential_file_sweep` |
| A project secret file or an environment dump sent to another machine (curl, wget, scp, rsync, netcat, socat) | Source-to-sink dataflow | `data_exfiltration` |
| Downloaded output used as program source (`python3 -c "$(curl …)"`, `eval "$(curl …)"`) | Command shape analysis | `interpreter_suspicious_inline_exec`, `curl_pipe_shell` |
| A line the shell would run differently from how it reads (history expansion that rewrites it, text after `#` when zsh `interactivecomments` is off) or input past the analysis limits | Reported as incomplete instead of allowed | `analysis_incomplete` |
| Prompt injection in files and in MCP tool output, including obfuscated forms | Seed matching over the raw text and its deobfuscated variants | `ignore_previous_instructions`, `prompt_injection_in_output`, `prompt_injection_obfuscated` |
| MCP tool output that carries a secret to a remote endpoint | Output filter, when enabled | `output_data_exfiltration` |
| CI build-artifact poisoning across workflows | Repository post-pass over `.github/workflows/` | `workflow_artifact_poisoning` |

## Explicit Non-Goals

- **Runtime sandboxing of arbitrary shell commands by default**: tirith does not
  sandbox or contain the commands a user runs in their shell. The shell hook is a
  detection layer, not a containment boundary. There is one narrow, opt-in
  exception (see "Tirith-launched runtime containment" below): live
  `tirith run` on Linux (`--capsule` remains a legacy spelling),
  `tirith temp-run --capsule` and `tirith gateway run --capsule` route the
  program they launch through an OS containment capsule where the host can
  enforce it. Contained
  `tirith pkg install` execution is currently disabled pending private-input
  qualification. This is an explicit, per-invocation choice for tirith-launched
  processes, not blanket containment of the shell.
- **Network monitoring**: tirith does not inspect network traffic after command execution
- **Malware detection**: tirith analyzes command structure, not payload content.
  The exceptions are commands that hand it content to inspect: `tirith run`,
  `tirith scan`, `tirith pkg inspect` and the MCP output filter apply static
  rules to that content. Tirith does not execute content to observe its
  behaviour.
- **Privileged attacker defense**: a root/admin user can bypass tirith trivially
- **Anti-debugging**: tirith does not resist analysis or reverse engineering
- **Strict PowerShell execution proof**: the PowerShell hook can block during
  PSReadLine preflight, but mutable history is not treated as trusted evidence
  that an accepted command executed
- **Task-gate enforcement outside tirith-owned transitions**: `tirith task
  check` and the `tirith_check_task` MCP tool are diagnostic preflight. They
  report what a task envelope would be allowed to do; they execute nothing and
  they stop nothing, and both declare `enforceability: observe_only` so the
  limit is visible in their own output rather than only in this document. An
  arbitrary shell, or an MCP client that does not route through `tirith gateway
  run`, can ignore them entirely. The task gate ENFORCES at exactly nine
  tirith-owned boundaries, and nowhere else:
  - the MCP gateway's upstream forward, before pending registration
    (`gateway_forward`);
  - `tirith install <manager>`, before registry network and before the manager
    is spawned (`package_manager_network`, `package_manager_execution`);
  - `tirith run <url>` and `tirith install url <URL>`, before download and
    launch (`remote_script_run`). Both spellings reach the same runner, so both
    are gated;
  - `tirith fetch` and its MCP tool, before the cloaking probe set runs
    (`fetch_cloaking`);
  - a tirith-owned configuration write, before the final atomic rename
    (`config_write`). This covers every `.tirith/` file tirith publishes: the
    policy, the commands manifest, the MCP lock (from `tirith mcp lock` and
    from the gateway's descriptor approval alike), and the MCP policy scaffold;
  - `tirith verify-self`, before it creates private state and contacts the
    release origin (`verify_self`);
  - `tirith update`, before it contacts the release origin and updates or
    rolls back, and the dashboard's "Refresh threat DB now", before it
    refreshes the threat database (`self_update`);
  - `tirith capsule run --preset untrusted-project`, before the untrusted
    project is copied into the held ephemeral directory and before anything is
    spawned (`capsule_preset_run`).

  `tirith pkg approve` and `tirith pkg install` refuse before any of them. Their
  `package_approval`, `package_resolve` and `package_install_preparation`
  tokens are kept only so receipts, schemas and policies that name them keep
  parsing; no code evaluates them.

  Two consequences are stated rather than papered over. First, the `tirith run`
  download itself lives in `tirith-core`'s runner, so the gate sits in the CLI:
  a program that links `tirith-core` and calls `runner::run` directly is not
  gated. Second, only writes tirith itself performs are covered; a shell
  redirection into an agent config, or any other host write that does not pass
  through tirith, is not intercepted.
- **Task-gate coverage of general shell**: task effect inference models the
  Web3 command grammar and reports every other shell segment as INCOMPLETE.
  With `task_gate.mode: enforce`, `action_incomplete_analysis: block` therefore
  refuses nearly every unmodelled shell command at the five boundaries that
  submit a shell envelope. It also refuses the narrative actions that MCP tool
  calls the gateway cannot model, `tirith verify-self`,
  `tirith update --dry-run` and the dashboard's ThreatDB refresh submit. It
  changes nothing at config writes, `tirith fetch`, or a real `tirith update`
  or rollback, which always assess as complete. `warn` is the default. `effects_denied_for_untrusted_sources` is the alternative, but it
  denies the named effect on EVERY call at every owned boundary, including
  commands the operator typed, because no source at these boundaries is ever
  trusted.
- **Web3 command cards as a general approval mechanism**: the `web3_guard`
  policy is enforced. A resolved denied destination blocks, an unresolved one
  follows `action_incomplete_analysis`, `require_command_card` blocks a
  state-changing operation that no card matches, and `command_card_key_ids`
  restricts which keys may sign a card. Exact approval still refuses when the
  executable identity is unbound, the facts are incomplete, or an artifact
  recheck is unavailable, and schema-1 cards cannot authorize a Web3
  operation. See [enforcement coverage](enforcement-coverage.md) and the
  [Web3 guide](security/web3-command-guard.md).
- **On-chain analysis**: the Web3 guard reads command GRAMMAR. It does not read
  chain state, simulate or dry-run a transaction, resolve an ENS name, score an
  address or a counterparty, audit a contract, watch a mempool, or attribute an
  on-chain incident. An unrecognized RPC endpoint is reported as unclassified
  and says in so many words that this is not a claim the host is malicious.
- **An npm artifact firewall**: tirith parses npm command grammar and registry
  identity facts, and it can ask the project's own npm to report its signature
  and provenance state. [Local npm inspection](npm-inspection.md) hashes the exact
  supplied tarball bytes and reports bounded static evidence without downloading
  it, writing its contents to disk, or executing package code. Captured hashes
  identify the inspected bytes, not a later mutable path or a verified publisher, and do not authorize
  installation. `tirith pkg install` is disabled for both npm and Python on every
  host pending private-input execution qualification.
- **Browser forensics or monitoring**: `tirith browser audit` is an explicit,
  one-shot, read-only integrity audit of extension SOURCE trees for Chrome,
  Chromium, Brave, and Edge. It never reads cookies, history, saved passwords,
  Local Storage, IndexedDB, extension storage, wallet databases, or
  `Local State`, so it cannot see browsing data or the signed-in account. It
  never removes, quarantines, or watches anything, has no daemon, and attributes
  no infostealer. Firefox and XPI are refused by name.
- **Reproducible builds**: `tirith attest build` records the bytes of two named
  trees at one moment. Tirith does not run the build, does not observe the
  compiler, and cannot say the output was produced from the source. Two receipts
  over the same source with different outputs are both valid receipts. A
  deployment receipt likewise proves only that the routes it fetched returned
  those bytes at that timestamp; it is not continuous monitoring and says
  nothing about routes it did not fetch.

### `tirith temp-run` is file isolation, NOT a sandbox

`tirith temp-run` (M10 ch6; the `sandbox-dir` word is a hidden alias) runs a
command in a fresh `mkdtemp` working directory and diffs the files it touched.
This does **not** contradict the runtime-sandboxing non-goal above, and the
command says so loudly on every surface — help text, every human output banner,
and a machine-readable `"isolation_kind": "file_only_not_a_sandbox"` field in
its JSON envelope:

> file isolation only; not a sandbox. The command runs with full user
> privileges and can read your keychain, ssh keys, AWS creds, and the network.
> Use this for filesystem-impact preview ONLY.

The ONLY thing `temp-run` changes is the working directory, so files the
command *writes* land in the temp dir instead of polluting your tree. It is a
file-isolation workflow for previewing filesystem impact, not a containment
boundary. A malicious command run under plain `temp-run` (without `--capsule`)
can still read every secret on the machine, reach the network, and modify
anything outside the temp dir (e.g. `$HOME`) exactly as it could if run directly.
`--strip-env` trims the child environment to a small allowlist (HOME, PATH, USER,
LANG, TERM) as a convenience, but a trimmed environment is likewise not a
security control.

### Tirith-launched runtime containment (the capsule)

The blanket "no kernel sandboxing" stance has one deliberate, scoped exception.
tirith ships an OS containment capsule that a handful of tirith-launched
surfaces can route their child process through. Linux (Landlock + seccomp) is
the enforcing backend. The macOS (Seatbelt) and Windows (AppContainer + Job
Object) backends exist, but neither can enforce every resource limit in the
locked-down specification these surfaces request, so both report degraded
coverage: an enforcing surface refuses there, and a best-effort surface runs
the program uncontained and says so. In 0.5.0 nothing is contained on macOS or
Windows.

- On Linux, every live `tirith run` runs the exact reviewed bytes from a sealed
  anonymous descriptor under containment (deny-network, scrubbed environment,
  resource limits). Live remote-script execution refuses before download on
  every non-Linux host; `--no-exec` remains inspection-only on Unix.
- `tirith temp-run --capsule` additionally contains the previewed command on
  Linux, on top of the temp-dir file isolation. On macOS and Windows it runs
  the command uncontained and reports that.
- `tirith gateway run --capsule` spawns the upstream MCP server contained
  (deny-network) on Linux and refuses on macOS. `tirith gateway run` itself is
  Unix-only.
- `tirith pkg install` currently refuses on every host before resolver,
  quarantine, checkpoint, or package execution. Its private named-input backend
  has not been qualified for immutable inputs throughout the complete target
  lifetime against another process owned by the same user. Generic capsule
  coverage does not establish that additional guarantee.
- `tirith capsule run --preset untrusted-project` copies an untrusted project
  into a held ephemeral directory and runs an exact argv there. It is
  enforceable on native x86_64 and AArch64 Linux with usable Landlock and
  seccomp. Hosts missing any required control refuse before anything is copied
  or spawned, with no degraded fallback.
  Domain allow-listing is not offered by the preset, because
  `domain_proxy_enforced` is false in every backend.

The capsule is **honest about what it enforces**. Every backend reports a
per-capability coverage ledger and never claims a control it did not apply. The
loopback egress broker is a broker, NOT the boundary: domain-egress is only
claimed where the OS backend blocks raw outbound sockets except to the broker.
Enabled enforcing surfaces (the contained gateway and Linux live `tirith run`)
**fail closed** when the host backend cannot deliver the required containment;
`temp-run --capsule` is a best-effort hardening that runs uncontained, and says
so, when the backend reports degraded coverage, which is always the case on
macOS and Windows. `tirith doctor` reports the per-platform capsule coverage.
See `docs/capsule.md` for the full model. Containment of arbitrary,
non-tirith-launched shell commands remains a non-goal.

## Trust Boundaries

1. **Interactive shell hook to Tirith**: preflight still receives the command
   text selected by the shell hook. Protocol-v3 bash/zsh/fish receipts
   additionally bind each use to a live parent PID/start identity, effective
   user, shell family, session, and pinned Tirith executable. Tirith owns any
   approval or warning acknowledgement before it returns the already-armed
   bearer. Their durable `ShellBoundaryUnresolved` transition is conservative
   correlation evidence, not proof that every command component executed.
   PowerShell has preflight interception without strict receipts.
2. **Linux launcher to target**: confirmed execution requires a kernel
   stopped-`exec` observation, a durable stopped-unresolved transition, one
   exact ACK+EOF, successful detach/resume, terminal `RESUMED`+EOF, and a
   durable upgrade of that same transition. Failure aborts the process tree
   before the stable execution-lock owner is dropped.
3. **Gateway to upstream MCP server**: each guarded request gets an unguessable
   internal proxy ID. A durably forwarded request is unresolved; only an exact,
   structurally valid result correlated to that proxy ID upgrades it to
   confirmed gateway evidence. Timeout, cancellation, partial write, and EOF
   retain unresolved/tombstoned state rather than claiming execution.
4. **Agent host to adapter to Tirith**: an adapter is a file `tirith setup`
   writes into the host's hook configuration. It passes the host's reported
   command string to `tirith check` and maps the result back to the host:
   the exit code and the JSON `requires_approval` field decide between allow,
   ask and deny. Three limits follow. Tirith analyzes the string the host
   reports, so a host that runs something else is outside this boundary. A
   host that does not run its hook, or runs the tool when its hook fails, is
   not stopped by Tirith. Upgrading the binary does not rewrite installed
   adapters; `tirith doctor` marks outdated ones STALE and
   `tirith setup <host> --force` refreshes them. With `TIRITH_FAIL_OPEN=1` an
   adapter allows a call when no verdict could be produced; a known block,
   acknowledgement or deferred block stays denied.
5. **Tirith binary to analysis engine**: the binary trusts the core library; no sandboxing between components
6. **Policy sources**: trust depends on where a policy was loaded from.
   - User (`~/.config/tirith/policy.yaml`), organization
     (`TIRITH_POLICY_ROOT`) and remote-server policies are trusted.
   - A repository policy (`.tirith/policy.yaml` found by walking up to the
     `.git` boundary) is untrusted. It may tighten checks. Fields that
     suppress findings, change severities, re-enable the `TIRITH=0` bypass, or
     send data elsewhere (allowlists, severity overrides, bypass flags,
     webhooks, policy-server settings) are reset before it is merged.
   - The repository command manifest (`.tirith/commands.yaml`) can add
     findings and can suppress one informational rule; it cannot remove an
     engine finding. A legacy repository `.tirith/trust.json` is not honored
     automatically.
   - A team policy applies only after the user activates a saved connection
     on that device (see [team policy](team-policy.md)).
   - `TIRITH_POLICY_ROOT` and the other `TIRITH_*` variables are read from the
     process environment, so whoever controls that environment controls them.
7. **Audit log**: append-only JSONL with file locking. Each entry records the
   hash of the previous entry, and entries are signed when an audit key is
   configured (off by default). `tirith audit verify` checks the chain, and
   `--expected-head` anchors it against truncation. This detects modification;
   it does not prevent a local attacker from deleting the log.
8. **Local services**: `tirith daemon` listens on a Unix socket in a private
   (0700) per-user directory and checks the peer's credentials. The dashboard
   listens on loopback, requires a single-use sign-in code, and on Linux drops
   connections from other ordinary accounts. Both are opt-in and neither is a
   boundary against the same user.
9. **Update channels**: the threat database is Ed25519-signed, verified on
   download and on load against a key compiled into the binary, and refused
   when its build sequence is not newer than the installed one
   (`tirith threat-db update --force` bypasses that rollback check).
   `tirith update` applies to standalone installs only: it verifies the
   downloaded release before replacing the executable and never modifies an
   install that a package manager owns. Package-manager installs rely on that
   package manager's own verification.

## License Tier Verification

Licensing is a legacy code path (see the Licence section of the README). It is
described here because the verification code still ships.

Ed25519 signatures verify tier claims in license tokens. Key rotation is supported via a `kid` (key ID) field that maps to the embedded public key ring.

- The public verification key is committed to source; the private signing key is held in release infrastructure only.
- Tier checks are honor-system for self-built binaries — users who build from source can patch out checks. Official releases enforce signed tokens.
- Historical v0.2.x releases accepted both signed and legacy unsigned tokens during the transition period. v0.3.0+ releases require signed tokens only (`SignedOnly` enforcement mode).
- All detection rules run regardless of tier (ADR-13). Tiers gate enrichment depth (rendered scanning, cloaking detection, checkpoints, audit reports), not security detection coverage.

## Bypass Mechanism

tirith supports `TIRITH=0` as a per-command prefix to bypass checks. Bypasses are logged to the audit trail with `bypass_requested: true`. Organizations can disable this with `allow_bypass_env: false` in policy.

Three limits apply by default:

- A non-interactive check, which is how agent adapters call Tirith, does not
  honor the bypass unless `allow_bypass_env_noninteractive: true` is set
  (default `false`).
- A repository-scoped policy cannot enable either setting.
- MCP gateway analysis never honors the bypass.
