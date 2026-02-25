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

- **Runtime sandboxing**: tirith does not sandbox or contain executed commands
- **Network monitoring**: tirith does not inspect network traffic after command execution
- **Malware detection**: tirith analyzes command structure, not payload content (except via `run`)
- **Privileged attacker defense**: a root/admin user can bypass tirith trivially
- **Anti-debugging**: tirith does not resist analysis or reverse engineering

## Trust Boundaries

1. **Shell hook to tirith binary**: the hook passes the command string; tirith trusts the hook to provide the actual command
2. **tirith binary to analysis engine**: the binary trusts the core library; no sandboxing between components
3. **Policy files**: tirith trusts YAML policy files found on disk (user-level and org-level)
4. **Audit log**: append-only with file locking; does not prevent deletion by a local attacker

## License Tier Verification

Ed25519 signatures verify tier claims in license tokens. Key rotation is supported via a `kid` (key ID) field that maps to the embedded public key ring.

- The public verification key is committed to source; the private signing key is held in release infrastructure only.
- Tier checks are honor-system for self-built binaries — users who build from source can patch out checks. Official releases enforce signed tokens.
- v0.2.x releases accept both signed and legacy unsigned tokens (transition period). v0.3.0+ releases require signed tokens only (`SignedOnly` enforcement mode).
- All detection rules run regardless of tier (ADR-13). Tiers gate enrichment depth (rendered scanning, cloaking detection, checkpoints, audit reports), not security detection coverage.

## Bypass Mechanism

tirith supports `TIRITH=0` as a per-command prefix to bypass checks. Bypasses are logged to the audit trail with `bypass_requested: true`. Organizations can disable this with `allow_bypass_env: false` in policy.
