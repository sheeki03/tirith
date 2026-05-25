# MCP output filter (M7 ch4)

Tirith ships two opt-in surfaces for routing MCP tool results through the
output-direction analyzer before they reach the calling agent:

- `tirith gateway run --filter-output` — filters every guarded-tool response
  returned by an upstream MCP server the gateway is proxying.
- `tirith mcp-server --sanitize-tool-output` — filters every tool result the
  tirith MCP server itself produces before sending it back to the client.

Both flags are **opt-in**. Default behavior (no flag) preserves the
pre-M7-ch4 pass-through. The chunk-4 commit is `feat(gateway,mcp):
--filter-output + --sanitize-tool-output (M7 ch4)`.

## Protocol contract

For every tool-call response, the filter runs the result's `content[].text`
through `engine::analyze_output` (M7 ch1) and applies exactly one of three
transforms based on the verdict's `Action`:

| Action  | Wire change                                                  | `isError` |
| ------- | ------------------------------------------------------------ | --------- |
| `Block` | `content` replaced with single placeholder text item         | `true`    |
| `Warn`  | `[tirith: WARNING …]` text item prepended; existing items sanitized in place | preserved |
| `Allow` | pass through unchanged                                       | preserved |

### Block placeholder shape

```json
{
  "content": [
    {
      "type": "text",
      "text": "[tirith: tool output blocked — see audit log entry <event_id> for details]"
    }
  ],
  "isError": true
}
```

The `<event_id>` is a UUIDv4 the filter generates per call and writes to a
JSONL audit line on stderr. Operators correlate the agent-facing message with
the audit entry by matching the `event_id` field.

### Why MCP `isError: true` and not a JSON-RPC error envelope

The MCP convention is:

- **JSON-RPC error envelope** (`{ "error": { ... } }`) signals **transport /
  protocol failure** — the server could not handle the request at all.
- **Tool result with `isError: true`** signals **tool-level failure** — the
  tool ran (or, here, was filtered) and produced an error-shaped result the
  calling agent should surface or recover from.

A content-policy block is the second case: the tool's response was valid
JSON-RPC, but its content was unsafe. Returning a JSON-RPC error would
mislead MCP clients into reporting a protocol problem and might trigger
retry logic that masks the security event. The `isError: true` path leaves
the request envelope intact (id is preserved, server stays connected) and
lets the calling agent record the failure cleanly.

The sanitized placeholder replaces all content — including any non-text
items siblings of a malicious payload — so a steg-style image cannot ride
through a block decision on the back of a text rule firing.

### Warn behavior

`Warn` keeps the original content's structure (no item count change beyond
the prepended notice). Each text item is byte-sanitized:

- ANSI / OSC / APC / DCS escape sequences stripped.
- Bare CR (display-overwriting) dropped; CRLF preserved.
- C0 controls (except `\t` / `\n`) and DEL dropped.
- Zero-width characters stripped: `U+200B`, `U+200C`, `U+200D`, `U+2060`,
  `U+FEFF`.

The prepended notice has the shape:

```json
{
  "type": "text",
  "text": "[tirith: WARNING — N findings; see audit log entry <event_id>]"
}
```

## Fail-mode

The two surfaces use different defaults:

- `tirith gateway run --filter-output` — `fail_mode_closed = false`. An
  analysis truncation past `MAX_SCAN_BYTES` (1 MiB) with no fired findings
  passes through. Stricter behavior is the gateway's own `policy.fail_mode:
  closed`; the output filter inherits its lane.
- `tirith mcp-server --sanitize-tool-output` — `fail_mode_closed = true`.
  Truncation degrades to Block. Stricter than the gateway default because the
  calling agent is the highest-privilege consumer of these results.

## Scan cap and large payloads

`MAX_SCAN_BYTES = 1 MiB`. The filter concatenates text items (joined with a
NUL separator so a multi-item OSC payload split across items is not joined
back into a single sequence) and analyzes the first 1 MiB. The remainder is
never dropped — it remains in the unfiltered `content` items (warn path) or
is replaced wholesale by the placeholder (block path). The `truncated` flag
on the audit line records that scanning was incomplete.

Performance: sub-millisecond per call for payloads under the cap on typical
agent output. The output ruleset is byte-stream-oriented and does not
allocate per character.

## Rule set

The filter inherits the M7 ch1 output ruleset:

- `output_osc52_clipboard_write` — High (Block)
- `output_terminal_hyperlink_mismatch` — High (Block)
- `output_hidden_text` — Medium (Warn)
- `output_fake_prompt` — Medium (Warn)
- `output_title_manipulation` — Info (Allow — audited only)
- `output_clear_screen` — Info (Allow — audited only)

Plain SGR colour passes (legitimate agents use it). Only the dangerous subset
above triggers.

## Audit format

Both surfaces emit one JSONL line per filter pass to **stderr**:

```json
{
  "ts": "2026-05-25T00:00:00.000Z",
  "kind": "gateway_output_filter",
  "decision": "block",
  "event_id": "<uuid>",
  "rule_ids": ["output_osc52_clipboard_write"],
  "findings_count": 1,
  "highest_severity": "HIGH",
  "elapsed_ms": 0.42,
  "truncated": false,
  "fail_mode_triggered": false,
  "agent_origin": {"kind": "gateway"}
}
```

The dispatcher emits `kind: "mcp_output_filter"` (no `agent_origin`; the MCP
server's origin is captured separately via `clientInfo` on `initialize`).

The placeholder text the agent sees cites the `event_id` so the operator can
grep the audit stream for the matching line.
