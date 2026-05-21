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
| `score` | Stable | Risk-score a URL. |
| `diff` | Stable | Compare a URL against known-good patterns. |
| `why` | Stable | Explain the last triggered rule. |
| `receipt` | Stable | Manage execution receipts. |
| `init` | Stable | Initialize shell hooks. |
| `scan` | Experimental | File/directory scanning for hidden content and config poisoning. Integration-critical (CI, MCP). |
| `doctor` | Experimental | Installation and configuration diagnostics. Integration-critical. |
| `run` | Experimental | Safe script download/execute (Unix only). |
| `fetch` | Experimental | Server-side cloaking detection (Unix only). |
| `checkpoint` | Experimental | File checkpoint and rollback. |
| `gateway` | Experimental | MCP gateway proxy for AI-agent security. |
| `setup` | Experimental | Configure tirith for AI coding tools. |
| `policy` | Experimental | Policy `init` / `validate` / `test`. |
| `trust` | Experimental | Manage trusted patterns (allowlist entries with TTL and scoping). |
| `warnings` | Experimental | Show accumulated session warnings. |
| `threat-db` | Experimental | Manage the threat intelligence database. |
| `daemon` | Experimental | Background daemon (Unix only). |
| `audit` | Experimental | Audit log export, stats, and compliance reports. |
| `activate` | Experimental | License key activation. |
| `license` | Experimental | License status and management. |
| `mcp-server` | Experimental | MCP server mode (JSON-RPC over stdio). |
| `completions` | Experimental | Shell completion generation (hidden). |
| `manpage` | Experimental | Man page generation (hidden). |

The MCP tools exposed by `mcp-server` (`tirith_check_command`, `tirith_check_url`,
`tirith_check_paste`, `tirith_scan_file`, `tirith_scan_directory`,
`tirith_verify_mcp_config`, `tirith_fetch_cloaking`) are also treated as an
integration-critical surface for graduation purposes.

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
