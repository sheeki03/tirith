# Threat Model

## Assets

- **Developer machines**: workstations where commands are typed and scripts are executed
- **Shell sessions**: interactive shells (zsh, bash, fish, PowerShell) where pasted/typed commands run
- **Credentials and keys**: SSH keys, API tokens, cloud credentials accessible from the shell
- **Source code**: repositories cloned and modified on the machine

## Threat Actors

- **Malicious website operators**: craft copy-paste instructions with hidden payloads
- **Typosquatters**: register domains similar to popular packages/repos
- **Supply chain attackers**: compromise package registries, Docker registries, or Git repos
- **Social engineers**: convince developers to run commands via chat, email, or forum posts

## Attack Vectors Covered

| Vector | Detection | Rules |
|--------|-----------|-------|
| Homoglyph/punycode domains | IDN analysis, confusable table | `confusable_domain`, `punycode_domain`, `mixed_script_in_label` |
| curl\|bash / wget\|sh | Command shape analysis | `curl_pipe_shell`, `wget_pipe_shell`, `pipe_to_interpreter` |
| ANSI escape injection in paste | Byte scanning | `ansi_escapes`, `control_chars` |
| Bidi/zero-width Unicode tricks | Byte scanning | `bidi_controls`, `zero_width_chars` |
| Hidden newlines in paste | Content analysis | `hidden_multiline` |
| URL shortener obfuscation | Domain matching | `shortened_url` |
| Raw IP URLs | Host analysis | `raw_ip_url` |
| HTTP to sink commands | Scheme analysis | `plain_http_to_sink` |
| Docker untrusted registry | Ecosystem rules | `docker_untrusted_registry` |
| Git typosquatting | Levenshtein distance | `git_typosquat` |
| Double-encoded paths | Normalization | `double_encoding` |

## Explicit Non-Goals

- **Runtime sandboxing of arbitrary shell commands by default**: tirith does not
  sandbox or contain the commands a user runs in their shell. The shell hook is a
  detection layer, not a containment boundary. There is one narrow, opt-in
  exception (see "Opt-in runtime containment" below): the Linux-only live
  every live `tirith run` (`--capsule` remains a legacy spelling),
  `tirith temp-run --capsule`, `tirith gateway run --capsule`, and (future) `tirith
  pkg install` surfaces route the program they launch through an OS containment
  capsule. This is an explicit, per-invocation choice for tirith-launched
  processes, not blanket containment of the shell.
- **Network monitoring**: tirith does not inspect network traffic after command execution
- **Malware detection**: tirith analyzes command structure, not payload content (except via `run`)
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
  run`, can ignore them entirely. The task gate ENFORCES at exactly five
  tirith-owned irreversible transitions, and nowhere else:
  - the MCP gateway's upstream forward, before pending registration;
  - `tirith pkg approve` / `tirith pkg install`, before resolver network and
    again before install preparation;
  - `tirith install <manager>`, before registry network and before the manager
    is spawned;
  - `tirith run <url>` and `tirith install url <URL>`, before download and
    launch. Both spellings reach the same runner, so both are gated;
  - a tirith-owned configuration write, before the final atomic rename. This
    covers every `.tirith/` file tirith publishes: the policy, the commands
    manifest, the MCP lock (from `tirith mcp lock` and from the gateway's
    descriptor approval alike), and the MCP policy scaffold.

  Two consequences are stated rather than papered over. First, the `tirith run`
  download itself lives in `tirith-core`'s runner, so the gate sits in the CLI:
  a program that links `tirith-core` and calls `runner::run` directly is not
  gated. Second, only writes tirith itself performs are covered; a shell
  redirection into an agent config, or any other host write that does not pass
  through tirith, is not intercepted.
- **Task-gate coverage of general shell**: task effect inference models the
  Web3 command grammar and reports every other shell segment as INCOMPLETE.
  That is honest about coverage, but it means `task_gate.mode: enforce` combined
  with `action_incomplete_analysis: block` refuses nearly every guarded command,
  because nearly every guarded command is incompletely modelled. Leave
  `action_incomplete_analysis` at its `warn` default and express enforcement
  through `effects_denied_for_untrusted_sources` instead.

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
tirith ships an OS containment capsule (Landlock + seccomp on Linux, Seatbelt on
macOS, an AppContainer + Job Object on Windows) that a handful of
tirith-launched surfaces can route their child process through:

- On Linux, every live `tirith run` runs the exact reviewed bytes from a sealed
  anonymous descriptor under containment (deny-network, scrubbed environment,
  resource limits). Live remote-script execution refuses before download on
  every non-Linux host; `--no-exec` remains inspection-only on Unix.
- `tirith temp-run --capsule` additionally contains the previewed command, on top
  of the temp-dir file isolation.
- `tirith gateway run --capsule` spawns the upstream MCP server contained
  (deny-network).
- `tirith pkg install` (a later milestone) installs only inside the capsule.

The capsule is **honest about what it enforces**. Every backend reports a
per-capability coverage ledger and never claims a control it did not apply. The
loopback egress broker is a broker, NOT the boundary: domain-egress is only
claimed where the OS backend blocks raw outbound sockets except to the broker.
Enforcing surfaces (`pkg install`, the contained gateway, and Linux
live `tirith run`)
**fail closed** when the host backend cannot deliver the required containment;
`temp-run --capsule` is a best-effort hardening that runs uncontained, and says
so, when no backend is available. `tirith doctor` reports the real per-platform
capsule coverage. See `docs/capsule.md` for the full model. Containment of
arbitrary, non-tirith-launched shell commands remains a non-goal.

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
4. **Tirith binary to analysis engine**: the binary trusts the core library; no sandboxing between components
5. **Policy files**: tirith trusts YAML policy files found on disk (user-level and org-level)
6. **Audit log**: append-only with file locking; does not prevent deletion by a local attacker

## License Tier Verification

Ed25519 signatures verify tier claims in license tokens. Key rotation is supported via a `kid` (key ID) field that maps to the embedded public key ring.

- The public verification key is committed to source; the private signing key is held in release infrastructure only.
- Tier checks are honor-system for self-built binaries — users who build from source can patch out checks. Official releases enforce signed tokens.
- Historical v0.2.x releases accepted both signed and legacy unsigned tokens during the transition period. v0.3.0+ releases require signed tokens only (`SignedOnly` enforcement mode).
- All detection rules run regardless of tier (ADR-13). Tiers gate enrichment depth (rendered scanning, cloaking detection, checkpoints, audit reports), not security detection coverage.

## Bypass Mechanism

tirith supports `TIRITH=0` as a per-command prefix to bypass checks. Bypasses are logged to the audit trail with `bypass_requested: true`. Organizations can disable this with `allow_bypass_env: false` in policy.
