# Reviewed profile rollouts

A profile rollout measures what a [protection profile](profiles-and-settings.md)
would do to commands you choose, saves that report with the profile change,
and waits for you to activate it. It changes local policy files only. To publish
a policy to a team's devices, use [team policy](team-policy.md).

## Prepare a rollout

```sh
tirith policy rollout prepare balanced --command 'curl https://example-tool.sh/x' --json
```

- Repeat `--command` for each representative workflow.
- `--shell` selects the command grammar and `--interactive` models an
  interactive prompt.
- `--scope user` (the default) changes your personal policy. See
  [Organization scope](#organization-scope) for `--scope org`.
- To retry after a lost response, pass the same `--operation-id UUID`. An
  identical retry returns the original report, including a no-change outcome;
  a different request at the same UUID is refused.

Preparing runs none of the commands and does not activate the profile. The
response contains the operation UUID.

## Review, activate and undo

```sh
tirith policy rollout show UUID --json
tirith policy rollout activate UUID --json
tirith policy rollout undo UUID --json
```

The dashboard's Protection page offers the same steps ("Prepare impact
review").

For each workflow the report shows the captured decision, the proposed
decision, the rule IDs and any unavailable evidence. Both decisions come from
the same frozen evaluation under the current and the proposed policy, with no
second command run, network request or history write. The report also lists
your stable trust grants by UUID with their scope, owner evidence, expiry and
eligibility.

`show --json` adds `live.impact_observation`: whether the review is recent,
stale or future-dated, how many captured expiry times have passed since the
review, and how many recorded client timestamps are stale, future-dated or
missing.

Undo uses the retained-target transaction and keeps unrelated edits where the
ownership contract allows.

## Organization scope

For an existing local organization policy (`TIRITH_POLICY_ROOT/.tirith/policy.yaml`,
or the existing `policy.yml`):

```sh
tirith policy rollout prepare balanced --scope org --command 'echo ready' --json
```

The dashboard has the same authority selector. Explicit organization settings
that already exist stay as custom overrides of the profile.

## Limits

- Up to 32 workflows per rollout, at most 4096 bytes per command and 64 KiB in
  total. Stored reports are capped at 128 workflows, 512 exceptions, 1024 client
  observations, 32 rule IDs per workflow and 256 KiB.
- Shell, interaction and session facts in a preview never authorize execution;
  session evidence is always reported unavailable.
- A review 24 hours old or older, or one with a future timestamp, cannot be
  activated. Changing policy inputs before activation requires a new review.
- Detector-policy changes and unresolved organization, repository or incident
  composition are reported as unavailable impact, never as a made-up tightening
  or relaxation.
- Grant eligibility is not permission to run a command. Legacy, invalid or
  over-limit grant inventory is reported incomplete. Expired grants stay
  expired; a review never renews or approves an exception.
- Organization scope only edits the existing authority file; it never creates
  or selects a new organization root. It works only for an ordinary POSIX
  operator who owns the root, the `.tirith` directory and a regular, singly
  linked policy file; the root must be absolute without parent traversal, and
  none of these may be a symlink or group/world-writable. Root, a real/effective
  UID mismatch, and sudo acting for another user are refused. Windows
  organization writes are not available.
- Organization undo restores the original document only while the whole
  managed document still equals what activation published; any newer managed
  edit refuses the undo and is left untouched. Its grant inventory covers only
  this operator's grants, not every team member's.
- Activating a local profile updates no other device and records no client
  acknowledgement. A supplied client report cannot prove adoption.
- When a remote policy server (`policy_server_url`) is the configured
  authority, the rollout refuses to write: a fetched remote policy has no
  revision precondition that could authorize a local change.
- Older clients that do not know the organization operation kind cannot replay
  it; the concrete policy fields stay readable.
- Reports contain typed fields, UUIDs, counts and timestamps only. Raw commands,
  labels, grant patterns, owner names and reasons are not stored in them, and
  destinations and diagnostics are redacted again on every read.
