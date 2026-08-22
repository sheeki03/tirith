# MCP output filter (M7 ch4)

Tirith ships two surfaces for routing MCP output through the
output-direction analyzer before they reach the calling agent:

- `tirith gateway run --filter-output` — filters every guarded-tool response
  returned by an upstream MCP server the gateway is proxying.
- `tirith mcp-server` — filters every tool result and `resources/read` body the
  tirith MCP server itself produces before sending it back to the client. This
  is the secure default; `--unsafe-unsanitized-tool-output` is an explicit
  legacy compatibility escape hatch.

Gateway filtering remains an explicit flag outside the secure profile. The
local MCP server filters by default because its calling agent is a privileged
consumer and repository-derived resource text is untrusted output.

## Protocol contract

For every tool-call response, the filter runs the result's `content[].text`
through `engine::analyze_output` (M7 ch1) and applies exactly one of three
transforms based on the verdict's `Action`:

| Action  | Wire change                                                  | `isError` |
| ------- | ------------------------------------------------------------ | --------- |
| `Block` | `content` replaced with single placeholder text item         | `true`    |
| `Warn`  | `[tirith: WARNING …]` text item prepended; existing items sanitized in place | preserved |
| `Allow` | structure preserved; forwarded strings sanitized in place    | preserved |

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

A Block decision is final once the filter is engaged: the gateway's
`policy.fail_mode` governs separate response-lifecycle failures and never turns
a detected injection or a malformed guarded tool result into an allow. Which
findings block is a severity question, not a fail-mode one — Critical and High
findings block and have their content replaced, Medium and Low findings warn
and keep sanitized content, per the two sections above.
`tirith mcp-server` engages the filter for tool and resource-read output by
default. Only the explicitly named `--unsafe-unsanitized-tool-output`
compatibility flag disables that local-server boundary.

## Scan cap and large payloads

The streaming analyzer scans all accepted content and structured string leaves;
there is no per-call prefix that can leave a suffix uninspected. Transport limits
bound bytes before filtering (the gateway uses its configured
`max_message_bytes`, and the local dispatcher caps a JSON-RPC line). Independent
depth, node, logical-leaf, total string-byte, cumulative analyzer-work,
cumulative decode-candidate, and repeated structural-work budgets bound hostile
JSON layouts and repeated endpoint rescans.
Exceeding a budget produces a High `analysis_incomplete` block instead of
truncating, partially scanning, or silently forwarding the result. Logical leaf
endpoints receive their own prompt/exfil checkpoint so padded encodings, word
boundaries, and anchored policy seeds retain end-of-leaf semantics. The
continuous analyzer advances at those same boundaries, so terminal state and
attacks split across leaves remain detectable without inventing longer context
or losing a finding that exists only at an intermediate endpoint.

The final presentation is also bounded and replaced by compact safe metadata
when necessary. The audit `truncated` field refers to presentation bounding,
not an incomplete security scan; structural analysis refusal is represented by
the `analysis_incomplete` rule.

Performance is bounded by the transport and structural-work limits rather than
by silently truncating input. The output ruleset is byte-stream-oriented and
does not invoke network I/O.

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
