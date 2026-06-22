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
  exception (see "Opt-in runtime containment" below): the `tirith run --capsule`,
  `tirith temp-run --capsule`, `tirith gateway run --capsule`, and (future) `tirith
  pkg install` surfaces route the program they launch through an OS containment
  capsule. This is an explicit, per-invocation choice for tirith-launched
  processes, not blanket containment of the shell.
- **Network monitoring**: tirith does not inspect network traffic after command execution
- **Malware detection**: tirith analyzes command structure, not payload content (except via `run`)
- **Privileged attacker defense**: a root/admin user can bypass tirith trivially
- **Anti-debugging**: tirith does not resist analysis or reverse engineering

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

### Opt-in runtime containment (the capsule)

The blanket "no kernel sandboxing" stance has one deliberate, opt-in exception.
tirith ships an OS containment capsule (Landlock + seccomp on Linux, Seatbelt on
macOS, an AppContainer + Job Object on Windows) that a handful of
tirith-launched surfaces can route their child process through:

- `tirith run --capsule` runs the downloaded script contained (deny-network,
  scrubbed environment, resource limits, filesystem confined to the script's
  cache dir).
- `tirith temp-run --capsule` additionally contains the previewed command, on top
  of the temp-dir file isolation.
- `tirith gateway run --capsule` spawns the upstream MCP server contained
  (deny-network).
- `tirith pkg install` (a later milestone) installs only inside the capsule.

The capsule is **honest about what it enforces**. Every backend reports a
per-capability coverage ledger and never claims a control it did not apply. The
loopback egress broker is a broker, NOT the boundary: domain-egress is only
claimed where the OS backend blocks raw outbound sockets except to the broker.
Enforcing surfaces (`pkg install`, the contained gateway, `tirith run --capsule`)
**fail closed** when the host backend cannot deliver the required containment;
`temp-run --capsule` is a best-effort hardening that runs uncontained, and says
so, when no backend is available. `tirith doctor` reports the real per-platform
capsule coverage. See `docs/capsule.md` for the full model. Containment of
arbitrary, non-tirith-launched shell commands remains a non-goal.

## Trust Boundaries

1. **Shell hook to tirith binary**: the hook passes the command string; tirith trusts the hook to provide the actual command
2. **tirith binary to analysis engine**: the binary trusts the core library; no sandboxing between components
3. **Policy files**: tirith trusts YAML policy files found on disk (user-level and org-level)
4. **Audit log**: append-only with file locking; does not prevent deletion by a local attacker

## License Tier Verification

Ed25519 signatures verify tier claims in license tokens. Key rotation is supported via a `kid` (key ID) field that maps to the embedded public key ring.

- The public verification key is committed to source; the private signing key is held in release infrastructure only.
- Tier checks are honor-system for self-built binaries — users who build from source can patch out checks. Official releases enforce signed tokens.
- Historical v0.2.x releases accepted both signed and legacy unsigned tokens during the transition period. v0.3.0+ releases require signed tokens only (`SignedOnly` enforcement mode).
- All detection rules run regardless of tier (ADR-13). Tiers gate enrichment depth (rendered scanning, cloaking detection, checkpoints, audit reports), not security detection coverage.

## Bypass Mechanism

tirith supports `TIRITH=0` as a per-command prefix to bypass checks. Bypasses are logged to the audit trail with `bypass_requested: true`. Organizations can disable this with `allow_bypass_env: false` in policy.
