# Agent Governance — Design

This document is the **design spike** for Milestone 4 item 8 of the tirith
roadmap (*"Agent governance — per-agent identity + policy"*). It is the first
artifact of that work; it lands **before** any enforcement code. Subsequent
chunks (CLI surface, policy schema, per-agent gating) build on the decisions
recorded here.

The companion code is observation-only:

- `crates/tirith-core/src/agent_origin.rs` — the [`AgentOrigin`](#agentorigin)
  type and the CLI-side environment resolver.
- `crates/tirith-core/src/verdict.rs` — `Verdict.agent_origin: Option<AgentOrigin>`.
- `crates/tirith-core/src/audit.rs` — `AuditEntry.agent_origin: Option<AgentOrigin>`,
  populated from `Verdict.agent_origin` by `log_verdict_with_raw`.
- `crates/tirith-core/src/mcp/origin.rs` — per-MCP-session origin store,
  populated by the dispatcher from `initialize.clientInfo`.
- `crates/tirith/src/cli/check.rs`, `paste.rs`, `gateway.rs` — populate
  the origin on the verdict before it reaches the audit layer.

Nothing in chunk 1 gates a verdict, changes an [`Action`], or adds a `RuleId`.

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

### What we are not doing in chunk 1

Chunk 1 is observation-only. There is **no** policy enforcement decision
driven by `AgentOrigin`. No `Verdict.action` is changed by origin. No new
`RuleId` is added. The on-disk policy schema is not bumped. We add a field
to `Verdict` and `AuditEntry` — both serde-default-on-parse so old log
entries still load — and populate it from the CLI / MCP / gateway paths.

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

## 5. CLI surface (preview, not built in this chunk)

The roadmap names four commands. They are **planned** for chunk 2+; chunk 1
ships no new subcommand. Documented here so a reviewer can see where the
design is going.

### `tirith agent sessions`

Lists per-origin counts from the audit log over a recent window. Output (planned):

```
$ tirith agent sessions --since=24h
ORIGIN                          COUNT  LAST SEEN
agent (claude-code 1.2.3)         412  2026-05-22 14:30
mcp (Cursor 0.42)                 188  2026-05-22 14:28
human (interactive)                73  2026-05-22 13:55
ci (github-actions)                12  2026-05-22 09:00
gateway                             0  -
```

Pure read from `~/.local/share/tirith/log.jsonl`. Already feasible with
chunk 1 in place — `audit_aggregator::read_log` returns `AuditRecord`s,
which now carry `agent_origin`. The command is a thin layer on top.

### `tirith agent explain <origin-spec>`

Drilldown on one origin: what variants of it have been seen, how their
verdicts split across Allow / Warn / Block, which rules they hit most
often. Useful for "is this agent hitting `curl_pipe_shell` a lot?".

### `tirith agent policy init`

Scaffolds a starter agent-governance policy at
`.tirith/agent-policy.yaml.example`. The schema is **not yet defined** —
that's chunk 2 work. Likely shape (sketch, not contract):

```yaml
# .tirith/agent-policy.yaml
agent_policy:
  # When an origin matches, apply these per-rule overrides.
  - match: { kind: agent, tool: claude-code }
    severity_overrides:
      curl_pipe_shell: block
  - match: { kind: mcp, client_name: Cursor }
    require_approval_for: [base64_decode_execute]
  - match: { kind: ci }
    fail_mode: closed
```

The match shape is the open question for chunk 2 — see
[§7](#7-open-questions--decisions-deferred).

### `tirith agent allow <origin-spec> <rule>`

Convenience for adding an `allowlist` entry scoped to an origin. Probably
ships as part of the existing `tirith trust` family rather than a fresh
subcommand — leaving that decision for the chunk-2 design.

## 6. Out of scope for chunk 1

- Any policy enforcement driven by `AgentOrigin`. No `Action` is changed; no
  `RuleId` is added; no `tirith.lock` file (mcp or otherwise) gains an
  agent-origin field.
- The `tirith agent ...` subcommands listed above.
- The agent-policy YAML schema.
- Any change to `TIRITH_INTEGRATION` semantics (it's already used by hooks;
  we read it, we don't redefine it).
- Synthesizing an origin onto hook telemetry entries. The `integration`
  field stays the hook telemetry's identifier; `agent_origin` stays `None`
  for `entry_type = "hook_telemetry"`.
- A signed / cryptographically-attested agent identity. That belongs with
  the broader supply-chain work in M5 and is not a chunk-1 / chunk-2
  artifact.
- **Fixing the engine's bypass-path double-log.** When `TIRITH=0` is
  honored, the engine emits an audit line **inside** `analyze_returning_policy`
  (before the CLI gets a chance to set origin), then the CLI emits a second
  line with the origin populated. The first line has `agent_origin: None`;
  the second has it set. This is a pre-existing duplication (M3 introduced
  the engine-side log for the daemon path) and is out of scope for chunk 1
  — chunk 2's "wire origin everywhere" pass picks it up.

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

*Chunk 1 ships the design, the type, the field, and the populate-only
plumbing. Chunk 2 is where this becomes governance.*
