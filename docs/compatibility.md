# Compatibility and Stability

## Stability Tiers

Tirith subcommands fall into two stability tiers:

- **Stable** — flags, exit codes, and output format will not change in a
  backwards-incompatible way within a major version.
- **Experimental** — surface may change without notice while the command and
  its schema are still being shaped.

## Per-Command Stability Matrix

This table reflects the **current** state of each subcommand. It is descriptive,
not a promise of future classification — see "Graduation criteria" below for
what an experimental command must satisfy to move to stable.

| Command | Stability | Notes |
|---------|-----------|-------|
| `check` | Stable | Analyze a command before execution. Integration-critical (shell hooks, MCP). |
| `paste` | Stable | Analyze pasted content. |
| `score` | Stable | Risk-score a URL (`--explain` shows the deterministic factor breakdown). |
| `diff` | Stable | Compare a URL against known-good patterns. |
| `why` | Stable | Explain the last triggered rule. |
| `receipt` | Stable | Manage execution receipts. |
| `init` | Stable | Initialize shell hooks. |
| `scan` | Experimental | File/directory scanning for hidden content and config poisoning. Integration-critical (CI, MCP). |
| `doctor` | Experimental | Installation and configuration diagnostics. Integration-critical. |
| `run` | Experimental | Remote-script inspection on Unix; live execution is Linux-only, sealed-descriptor-bound, and refused before download elsewhere. |
| `fetch` | Experimental | Server-side cloaking detection (Unix only). |
| `checkpoint` | Experimental | File checkpoint and rollback. |
| `gateway` | Experimental | MCP gateway proxy for AI-agent security. |
| `setup` | Experimental | Configure tirith for AI coding tools. |
| `policy` | Experimental | Policy `init` / `validate` / `test` / `tune`. |
| `trust` | Experimental | Manage trusted patterns: `add` / `list` / `explain` / `diff` / `remove` / `gc`. Narrow scope and a 30-day TTL by default; scope visualization, per-entry `explain`, and a `diff` trail. |
| `warnings` | Experimental | Show accumulated session warnings. |
| `threat-db` | Experimental | Threat-DB `update` / `status` / `explain` / `sources` / `health` / `diff`. |
| `daemon` | Experimental | Background daemon (Unix only). |
| `audit` | Experimental | Audit log export, stats, and compliance reports. |
| `activate` | Experimental | License key activation. |
| `license` | Experimental | License status and management. |
| `mcp-server` | Experimental | MCP server mode (JSON-RPC over stdio). |
| `lab` | Experimental | Adversarial training corpus runner. Offline. `--filter` narrows by tag; `--score` adds a 0-100 risk score per scenario. |
| `task check` | Preview | Diagnostic task-envelope assessment. Reports what an envelope would be allowed to do; executes, fetches, resolves, and writes nothing, and declares `enforceability: observe_only`. |
| `capsule run` | Experimental | Fail-closed contained run of an untrusted project. Enforceable on x86_64 Linux only; every other host refuses before anything is copied or spawned, with no degraded fallback. |
| `browser audit` | Experimental | Read-only Chromium-family extension integrity audit. Chrome, Chromium, Brave, and Edge; Firefox and XPI are refused by name. |
| `pkg attest-npm` | Experimental | Point-in-time npm signature and provenance receipt over an installed project. |
| `attest` | Experimental | Point-in-time build and deployment receipts (`build`, `verify-build`, `deployment`, `verify-deployment`). |
| `completions` | Experimental | Shell completion generation (hidden). |
| `manpage` | Experimental | Man page generation (hidden). |

**Preview** is a tier below Experimental: the command is diagnostic, its output
is advisory rather than an enforcement decision, and its schema may change
without a deprecation cycle. `task check` is the only command at this tier.

The MCP tools exposed by `mcp-server` (`tirith_check_command`, `tirith_check_url`,
`tirith_check_paste`, `tirith_scan_file`, `tirith_scan_directory`,
`tirith_verify_mcp_config`, `tirith_fetch_cloaking`) are also treated as an
integration-critical surface for graduation purposes.

### The default MCP tool list is a frozen contract

`tools/list` on a default `tirith mcp-server` returns exactly the six tools
above, plus `tirith_fetch_cloaking` on Unix, in that order. The list is pinned
by a contract test, because clients cache it and a tool that appears
unannounced changes what an agent believes it may call.

A new tool therefore cannot simply be added to it. `tirith_check_task` is
**preview-gated**: it is absent from the default list, and a client that learned
the name elsewhere and called it anyway is refused BY NAME with
`tirith_check_task is a preview tool; set TIRITH_MCP_PREVIEW=1 to enable it`.

```bash
TIRITH_MCP_PREVIEW=1 tirith mcp-server   # advertises the preview tool too
```

Every object in the preview tool's input schema is
`additionalProperties: false`, so a client cannot smuggle an unmodelled field
past the bounded envelope parser.

## Graduation Criteria

An experimental command graduates to **stable** only once it satisfies all of
the following:

- **Stable JSON schema** — the `--format json` output has a fixed, documented
  schema. `schema_version` is emitted, and existing fields are not removed or
  retyped within a major version.
- **Golden snapshot tests** — representative inputs are covered by golden
  snapshot tests so output drift is caught in CI.
- **Versioned config/policy migration** — any config or policy keys the command
  reads have a defined migration path; format changes are versioned, not silent.
- **Exit-code compatibility promise** — the command's exit codes are documented
  and committed to (see "Exit Codes" below).
- **`--format json` consistency** — the JSON output is consistent with the
  shared output conventions used by the already-stable commands.
- **Backward-compatible MCP tool schemas** — for commands exposed through the
  MCP server, the corresponding tool input/output schemas evolve only in a
  backward-compatible way.
- **CLI deprecation policy** — flags and behaviors are removed only through a
  documented deprecation cycle, never abruptly.

These criteria are prioritised for the **experimental** integration-critical
surface — `scan`, `doctor`, and the MCP tools — because CI pipelines and AI
agents depend on them most directly. (`check` is already Stable; the
already-stable commands are held to these same guarantees as maintenance
invariants.) Other experimental commands graduate after that surface is locked
down.

## Exit Codes

Exit codes are stable:

| Code | Meaning |
|------|---------|
| 0    | Allow (no issues found) |
| 1    | Block (high/critical severity findings) |
| 2    | Warn (medium/low severity findings) |
| 3    | WarnAck — acknowledgement required (warn-ack hook protocol) |

Exit code 3 is the warn-ack hook protocol path used by shell hooks under strict
warn mode, not the normal direct-CLI contract. Non-hook callers should not
normally see exit code 3.

### Per-command exit codes are deliberately distinct

The table above is the `tirith check` contract. It is not shared. Commands that
report evidence rather than a verdict define their own codes, and each says so
in its own `--help`, so a script must read the contract for the command it
calls rather than assuming the check ladder.

| Command | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| `task check` | nothing denied, analysis complete | something denied, incomplete, or the envelope was partly rejected | usage or input error | not used |
| `capsule run` | contained, child exited 0 | a tirith decision: refused before launch, terminated after it, or a receipt that could not be recorded or anchored | usage or input error | contained, but the child exited non-zero |
| `browser audit` | no drift, and any JSON write succeeded | drift, including partial coverage with a baseline | usage error, or a JSON write failure with no drift | not used |
| `pkg attest-npm` | `clean` | `mismatch` | usage or input error | `partial` |
| `attest *` | `clean` | `mismatch` | usage or input error | `partial` |

The `3` for `pkg attest-npm` and `attest` is `partial` (incomplete evidence),
NOT a warn acknowledgement. Reusing `3` across unrelated meanings would be worse
than making the codes distinct, because a script that already handles `3` as
"acknowledge and continue" would treat incomplete evidence as an accepted
warning.

## JSON Output

- `schema_version` is emitted in all JSON output (currently version 3)
- Version 3 changes: added `Info` severity level (maps to `Allow` action), added `httpie_pipe_shell` and `xh_pipe_shell` rule IDs
- JSON fields are additive only: new fields may appear in any release
- Existing fields will not be removed or change type within a major version
- The `findings` array structure is stable
- Evidence types may be extended (e.g., `homoglyph_analysis` with detailed character info)

## Rule IDs

- Rule IDs (e.g., `curl_pipe_shell`, `punycode_domain`) are stable identifiers
- Rule wording (title, description) may change
- New rules may be added in any release
- Rules will not be removed within a major version (they may be deprecated)

## Policy Format

- Both `policy.yaml` and `policy.yml` extensions are accepted (`.yaml` preferred)
- Policy format is additive: new keys may appear
- Existing keys will not change semantics within a major version
- `web3_guard` and `task_gate` are new top-level sections. Both are optional and
  both default to inert, so a policy written before they existed loads and
  behaves identically. See
  [web3 command guard](security/web3-command-guard.md) and
  [task envelope](task-envelope.md) for the field references
- Tirith does not auto-write a schema-upgraded policy file, so rolling a binary
  back does not strand a user who never enabled the new sections

## Document schemas

Content-addressed documents carry their own schema and format versions, so an
older binary reading a newer document fails explicitly instead of half-reading
it.

| Document | Schema field | Notes |
|---|---|---|
| Command card | `schema_version` | Defaults to 1 and is SKIPPED when it equals 1, so a v1 card's signing bytes are byte-identical to what they were before schema 2 existed and every checked-in v1 signature still verifies. `web3` is likewise omitted when unset |
| Browser extension baseline | `schema` plus an independent `format_version` | The hashing rules version is separate so a stale baseline reports one `schema_upgrade_required` entry rather than phantom drift on every extension |
| npm provenance receipt | `schema` | |
| Build receipt | `schema` | |
| Deployment receipt | `schema` | |
| Capsule run receipt | `schema` | |

All five share an envelope core (`schema`, `receipt_type`, content-addressed
`receipt_id`, `created_at`, `tirith_version`, `coverage`, `signature`), one
canonicalizer, and one signing routine. The capsule, npm, build, and deployment
receipts additionally carry `engine_build_sha`, `policy_projection_hash`,
`status`, `subject`, and `evidence`; the npm, build, and deployment receipts
carry `caveats`, which `validate` refuses to let a document drop.

Only the capsule run receipt is ELIGIBLE for anchoring in the audit hash chain,
because it is the only one written to a tirith-owned store. It is anchored when
an audit chain is configured, and left unanchored otherwise, including under
`TIRITH_LOG=0`; the run prints which happened. The other four say
`audit_chain_anchored: false` and refuse to claim otherwise, because they are
written to an operator-chosen path that the chain's anchor constructor cannot
accept.

## PowerShell parity

The following detection rules apply when `--shell powershell` is passed to
`tirith check` or when the shell hook detects a PowerShell session:

| Rule ID | Behavior detected |
|---------|-------------------|
| `base64_decode_execute` | `powershell -EncodedCommand <base64>` and `-enc` / `-ec` aliases |
| `pipe_to_interpreter` | `iwr url \| iex`, `irm url \| iex`, and full `Invoke-WebRequest` / `Invoke-RestMethod` forms |
| `ps_set_execution_policy_bypass` | `Set-ExecutionPolicy Bypass`, `powershell -ExecutionPolicy Bypass`, the `-ep` alias, and valid unambiguous `-ex…` prefixes |
| `ps_defender_exclusion` | `Add-MpPreference -ExclusionPath`, `-ExclusionProcess`, or `-ExclusionExtension`, including valid unambiguous parameter prefixes |
| `ps_inline_download_execute` | `iex (iwr https://…)` — inline download-execute form where `iex` is the leading command |

`tirith run` and `tirith fetch` are not exposed on Windows and do not apply to
PowerShell workflows. On Unix, `run --no-exec` is inspection-only; live
remote-script execution is Linux-only. `tirith check`, `tirith paste`, `tirith
score`, and the shell hook work on Windows with `pwsh`.

`tirith doctor --compat` reports PowerShell hook health when `pwsh`
(PowerShell 7+) or `powershell` (Windows PowerShell 5.1) is found on PATH:
PSReadLine availability and the current `TIRITH_STATUS` value exported by
the hook.
