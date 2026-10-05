# Profiles and personal settings

A protection profile is a named, versioned set of personal policy settings. A
personal setting changes one field of your own policy. Both are previewed
first, saved as an undoable operation, and edit only the fields they own in
your policy file.

## Pick a profile

| Behavior | Comfortable v1 | Balanced v1 | Strict v1 |
| --- | --- | --- | --- |
| Existing High/Critical findings | Block retained | Block retained | Block retained |
| `non_standard_port`, `non_ascii_path` | Low | Low | Built-in Medium |
| `raw_ip_url` alone | Low | Medium advisory | Medium acknowledgement |
| `shortened_url`, `package_repo_mismatch` when not already blocked | Advisory | Selected confirmation, 120 seconds, timeout blocks | Warning acknowledgement |
| Other Medium findings | Advisory | Advisory | Warning acknowledgement |
| `analysis_incomplete`, `wrapper_chain_too_deep` | Existing behavior | Existing behavior | Action override blocks |
| Internal failure | Open | Open | Closed |
| Interactive environment bypass | Permitted | Permitted | Disabled |
| Noninteractive environment bypass | Disabled | Disabled | Disabled |
| Scan complete coverage | Existing default | Existing default | Required |

Balanced is the default for `tirith setup recommended` and the recommendation
of `tirith onboard`.

1. Preview the profile:

   ```sh
   tirith policy profile balanced --dry-run --json
   ```

2. Apply it, and keep the returned operation ID:

   ```sh
   tirith policy profile balanced --json
   ```

3. To remove the settings the profile added, run
   `tirith policy profile reset --dry-run`, then without `--dry-run`.

To measure a profile against your own commands before activating it, use a
[reviewed rollout](policy-rollouts.md). In the dashboard, use the Protection
page.

## Change one setting

```sh
tirith policy setting strict_warn true --dry-run --json
tirith policy setting strict_warn true
tirith policy setting rule_severity HIGH --rule raw_ip_url --dry-run --json
tirith policy setting paranoia 4 --dry-run --json
tirith policy setting strict_warn reset
```

Available settings:

- on/off: warning acknowledgement, interactive and noninteractive bypass,
  complete scan coverage, environment, context, executable, repository-hook and
  baseline checks, and MCP injection redaction;
- open/closed handling of internal failures;
- sensitivity levels 1 to 4 (`paranoia`);
- the severity of one canonical rule (`rule_severity --rule RULE`).

Without `--json`, the command prints a short summary: the preview, or the
operation ID, its state and how to inspect it.

The preview shows your before/after value, the current effective value and its
source, and whether your personal policy can affect that field at all.

A setting is an explicit personal override, even when it equals the profile
default. Switching or resetting the profile keeps it. `reset` on the setting
removes your value, and the value is inherited again.

## Check the result and undo

1. Run `tirith policy effective --runtime --json` to see the resulting values
   and their sources. (The dashboard reads them again after apply and undo.)
2. To undo, run `tirith policy operation OPERATION_ID --action undo`, or use
   Settings → Saved changes and recovery in the dashboard.

Saving edits only the lines of the owned fields: comments, blank lines, key
order, quoting, indentation and CRLF line endings elsewhere in the policy file
are kept. Undo restores the exact original bytes when the file still holds
exactly what the change wrote; otherwise it restores only the owned fields and
keeps your later edits.

## Limits

- Profiles change rule actions and severities only. They do not change named
  `scan.profiles`, which integrations are set up, or how output looks. The
  legacy `paranoia` field is held at 1 by all three profiles.
- Every profile keeps unrelated detection, repository tightening, organization
  and remote policy restrictions, and incident restrictions. A finding that is
  already blocked stays blocked and cannot become approvable.
- Balanced uses per-rule approval and does not turn on global `strict_warn`. A
  caller without an interactive approval prompt refuses a pending
  confirmation; Strict's acknowledgements likewise depend on what the actual
  surface can ask.
- `package_repo_mismatch` needs the package analysis that emits it; a profile
  does not invent online evidence.
- An organization or remote policy can replace personal policy for a field,
  even when it does not set that field. The preview says so, and the dashboard
  disables those controls and explains where to make the change.
- Proposed personal values do not predict the final effective value; check
  `tirith policy effective --runtime` after the change. A warning setting never
  approves an independent hard block.
- A field inside a structure that cannot be edited in place safely (a
  flow-style `{...}` parent, an anchor or alias, tab indentation, or several
  YAML documents) is refused before anything is saved; the error shows the
  change as a diff of that field to make by hand. A leading `---`, a trailing
  `...` document-end marker and other fields written in flow style (also when
  their closing `]` or `}` is in the key's column) are kept as they are.
- Undo checks fresh authorization, refuses a concurrent change to what it would
  restore, and never writes an old policy document over newer settings.
- Unsupported fields, values, rules and paths are refused. Compound values
  above 16 KiB are left out of field summaries and marked as omitted, not as
  unset.
- Shipped v1 profiles never change; a behavior change needs a new version. There
  is no automatic profile promotion and no observe-only profile.
