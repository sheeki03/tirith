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

The preview shows the personal before/after values and current effective value.
It does not claim to have simulated every stronger source. Organization, remote,
repository and incident restrictions retain authority, and a saved preference
can be overridden. After applying, refresh the effective policy view to see what
actually takes effect. Warning presentation never becomes an approval for an
independent hard block.

Every change has a saved operation ID. `tirith policy operation ID --action undo`
and Settings → Saved changes and recovery use the shared journal. Undo checks
owned postimages and fresh authorization, preserves unrelated changes made before
undo preparation, and refuses a concurrent change to its compensation baseline.
It never restores an entire stale policy document over newer user settings.
