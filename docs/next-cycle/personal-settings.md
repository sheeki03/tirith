# Personal settings and profile ownership

`tirith policy setting` and the Protection page prepare the same typed operation.
They derive the current operator's policy destination, preserve `policy.yml`
precedence, and retain the original document and effective authority before
preparing a change. A browser cannot choose a destination path or send arbitrary
file contents.

Examples to verify against the candidate:

```sh
tirith policy setting strict_warn true --dry-run --json
tirith policy setting strict_warn true --json
tirith policy setting rule_severity HIGH --rule raw_ip_url --dry-run --json
tirith policy setting paranoia 4 --dry-run --json
tirith policy setting strict_warn reset --json
tirith policy effective --runtime --json
```

Boolean controls cover warning acknowledgement, interactive and noninteractive
bypass, complete scan coverage, environment/context/executable/repository-hook
and baseline checks, and MCP injection redaction. Additional typed controls cover
open/closed failure handling, sensitivity levels 1–4, and a canonical rule's
severity. Unsupported fields, values, rules and paths are refused.

A setting is an explicit personal override, including when its value equals the
current profile default. Applying it removes that field from the profile's
ownership marker. Changing or resetting the profile subsequently preserves the
explicit preference. Resetting the individual setting removes the personal
value; the resolver determines the resulting inherited value.

The preview shows personal before/after values, the current effective value and
its source, and whether personal policy can affect that field. A selected
organization or remote policy can replace personal policy even when that source
omits the field and the effective value comes from built-in defaults. The browser
disables those managed personal controls and explains where to make the change.
Repository and incident constraints are shown separately; they do not imply that
personal policy has lost authority. Rejected repository preferences and omitted
provenance details remain explicit.

Known rules without a severity override show “No policy override”; that is not
a claim about the rule's built-in severity. The shared CLI/API `control` display
and runtime `personal_controls` inventory preserve canonical setting and rule
identities while redacting source paths and explanations.
Compound values above 16 KiB are explicitly omitted from field summaries; the
effective policy details retain the full redacted value within the normal
response limit. An omitted value is never presented as an unset override.
If field summaries would make a browser policy response exceed its total limit,
the response omits that inventory and says so. Advanced controls then remain
unavailable; full policy details and field-specific profile previews stay
accessible. CLI effective-policy output retains its inventory.

The proposed personal values do not predict the final effective result. After
apply or undo, the browser reads current policy again and shows the resolver's
values and sources. A later operation or closed dialog discards an older
readback. Other policy changes may have occurred in the meantime. For the CLI,
run `tirith policy effective --runtime --json` after the operation. Warning
presentation never becomes approval for an independent hard block.

Every change has a saved operation ID. `tirith policy operation ID --action undo`
and Settings → Saved changes and recovery use the shared journal. Undo checks
owned postimages and fresh authorization, preserves unrelated changes made before
undo preparation, and refuses a concurrent change to its compensation baseline.
It never restores an entire stale policy document over newer user settings.
