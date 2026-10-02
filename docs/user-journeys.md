# Everyday workflows

Use these steps to protect a terminal or an agent, review a project, deal with a
block, upgrade and remove Tirith. Run `tirith version --provenance` to identify
the binary you are using.

Run `tirith` (or `tirith onboard` on first use) to see the common tasks.
`tirith -h` shows the same short task list, and `tirith --help` adds every
command by category. The list only prints commands; it never runs them. In
scripts, call the commands directly, for example `tirith status --json` or
`tirith audit recent --limit 25 --json`.

## Find the right command

Every command below inspects or previews unless it says otherwise. Changes need
their own explicit command.

- **Check protection:** run `tirith status`. Add `--require-verified-blocking`
  to succeed only on fresh evidence of blocking. `tirith status` and
  `tirith doctor` also say whether this terminal's loaded hook is current.
  `tirith doctor --verify-shell` prints the harmless checks to run in the
  actual shell.
- **Change profile:** run `tirith policy profile NAME --dry-run` to preview a
  profile. To compare it against your own commands first, prepare a rollout
  (`tirith policy rollout prepare --help`), inspect it with
  `tirith policy rollout show OPERATION_ID`, then run
  `tirith policy rollout activate OPERATION_ID`. `tirith policy rollout undo
  OPERATION_ID` undoes it. See [profiles and settings](profiles-and-settings.md)
  and [profile rollouts](policy-rollouts.md).
- **See recent activity:** `tirith audit recent --action block` lists recent
  blocks. `tirith why` explains the last one and `tirith explain --help`
  documents a rule. `tirith audit feedback --help` records whether you intended
  an operation; feedback is a review signal and never grants trust.
- **Resolve an exception:** `tirith trust explain PATTERN` shows an entry's
  scope and expiry. `tirith trust add --help` lists the narrow target, rule,
  expiry and reason options. `tirith trust revoke GRANT_ID` revokes one grant
  and reports any broader permissions that remain. See
  [trust grants](trust-grants.md).
- **Set up shells and agents:** `tirith setup recommended --help` covers the
  shell, profile and agent choices. `--plan-only` saves a review;
  `tirith policy operation OPERATION_ID` inspects it and `--action apply`
  applies it. Open a fresh terminal when asked, then verify the actual shell.
- **Open the dashboard:** run `tirith dashboard`. See [dashboard](dashboard.md).
- **Join a team policy:** see [team policy](team-policy.md).
- **Upgrade:** `tirith update --dry-run` previews the update (network access);
  `tirith update` starts the confirmed workflow. See [Upgrade](#upgrade).
- **Support and retention:** `tirith doctor --bundle` saves a reviewed support
  bundle privately and uploads nothing. `tirith audit rotate` saves a retention
  plan; `tirith audit rotate --operation-id OPERATION_ID --apply` applies it.
- **Remove shell hooks:** `tirith setup shell --remove --dry-run` previews
  removal; `tirith setup shell --remove` applies it. See [Remove](#remove).

## Protect a terminal

1. Install Tirith through your chosen channel. Ordinary installation, checks and
   shell protection need no sudo; see
   [installation permissions](install-privileges.md).
2. Preview, then apply personal setup as the intended user:

   ```sh
   tirith setup recommended --scope user --shell zsh --dry-run
   tirith setup recommended --scope user --shell zsh
   ```

   Choose `bash`, `zsh` or `fish`. The default profile is Balanced; add
   `--profile comfortable` or `--profile strict` to pick another one. Explicit
   manual settings are kept.
3. To review before applying, add `--plan-only --json`. Keep the operation UUID
   for status, retry, cancellation or owned undo:

   ```sh
   tirith policy operation OPERATION_UUID
   tirith policy operation OPERATION_UUID --action apply
   ```

   Cancel a pending plan or undo an applied change only when you mean to; these
   are alternatives, not follow-up steps:

   ```sh
   tirith policy operation OPERATION_UUID --action cancel
   tirith policy operation OPERATION_UUID --action undo
   ```

4. Open a fresh terminal. Run `tirith status` to confirm the loaded hook is
   `current`.
5. Run `tirith doctor --verify-shell` and follow its exact harmless challenge
   commands to observe blocking in this shell. See
   [caller-shell verification](caller-shell-verification.md).

For another shell variant, run `tirith setup shell --shell NAME --dry-run`,
then the same command without `--dry-run`.

## Protect an agent

1. Select the actual host and scope explicitly, preview, then apply:

   ```sh
   tirith setup codex --scope user --dry-run
   tirith setup codex --scope user
   ```

   For Codex this sets up the MCP gateway. Check the
   [host integration matrix](../mcp/clients/mcp-only-agents.md) for the
   selected host, scope and required restart.
2. Restart the host and run a harmless check through it. Inspect the returned
   decision.

To set up the Claude Code Bash hook together with your shell, in the same
undoable plan:

```sh
tirith setup recommended --scope user --shell zsh --agent claude-code --dry-run
tirith setup recommended --scope user --shell zsh --agent claude-code
```

This writes the same hook script and `~/.claude/settings.json` handler as
`tirith setup claude-code`, so the two commands are interchangeable. Undoing the
operation (`tirith policy operation OPERATION_UUID --action undo`) removes only
the owned handler. If the plan created the hook script, undo leaves it as an
empty file; either setup command replaces that file without `--force`. If the
settings already run the Tirith hook but the script is missing, recommended
setup refuses; run `tirith setup claude-code` to restore it first. Reload
Claude Code after applying, then verify the hook.

## Inspect a project

Run from the project you want to review:

```sh
tirith review --json
tirith review --path package.json --path .mcp.json --json
tirith pkg inspect ./package.tgz --format json
tirith pkg diff ./old-package.tgz ./new-package.tgz --format json
```

Read the report before deciding what needs more review: exit status 2 can
accompany a complete report when findings or coverage gaps remain. The
dashboard's Overview page offers the same review and can recheck retained file
identities. For npm, `tirith install npm <pkg>` analyzes the request before
running npm. See [project review](project-review.md) and
[npm inspection](npm-inspection.md).

## Resolve an interruption

1. Read the recorded decision and every contributing finding:

   ```sh
   tirith audit recent --limit 20 --json
   tirith why --format json
   tirith policy tune --from-audit --format json
   ```

   Tuning reads at most 500 recent records within a 2 MiB history read and
   selects at most 50 private expectation records. It shows recurring blockers
   even when no relaxation is supported. With no audit history it reports
   `availability: absent`, exits 1 and suggests nothing.
2. Simulate the actual command. Historical examples are redacted, so supply
   the representative command yourself:

   ```sh
   tirith policy simulate 'echo representative-command' --shell posix --interactive --json
   ```

3. If a profile change fits, preview it and then apply it:

   ```sh
   tirith policy profile balanced --dry-run --json
   tirith policy profile balanced --json
   ```

   Use `comfortable` or `strict` instead of `balanced` as needed; `reset`
   removes profile-owned settings. Keep the operation UUID for status or undo.
4. Or add an exact rule-and-target exception after reviewing its constraints,
   for example `tirith trust add URL --rule RULE --ttl 1h`.
   `tirith trust explain URL` explains eligibility.

## Upgrade

```sh
tirith version --provenance
tirith update --dry-run
```

Use the owning package manager's update command for package-managed
installations. A self-replaceable personal installation can use `tirith update`;
a saved rollback uses `tirith update --rollback`. Review the candidate identity
and compatibility first. After replacement, open a new terminal (status then
reports the loaded hook as `current` again) and reload agent integrations.

The dashboard's Settings page shows the exact upgrade and rollback command for
your installation channel to copy into a terminal. Its "Refresh threat DB now"
button runs the same signed update as `tirith threat-db update`.

## Remove

1. Remove owned startup blocks before deleting the CLI:

   ```sh
   tirith setup shell --shell zsh --remove --dry-run
   tirith setup shell --shell zsh --remove
   ```

2. Review and remove any `tirith init` lines you added by hand, including in
   custom shell roots; managed removal keeps them.
3. Open a fresh terminal so the old hook is no longer loaded.
4. Remove Tirith through its owning package manager, or delete its user-owned
   standalone binary.
5. Remove agent integrations using the steps for that host in
   [uninstall](uninstall.md).

## Review local data before sharing or deleting

- Preview a support bundle:
  `tirith doctor --bundle --bundle-preview --bundle-incident EVENT_UUID --json`.
  Add `--bundle-operation OPERATION_UUID` to include a saved setup operation.
  Drop `--bundle-preview` to save the freshly redacted selection privately.
  Nothing is uploaded; review the file before sharing it. The dashboard has the
  same selection and download flow.
- Plan audit rotation with `tirith audit rotate`. Its saved operation UUID
  identifies the retained segment.
- `tirith audit export-segment --segment-id UUID` prepares an exact private
  archive copy (not a redacted support report).
- `tirith audit delete-segment --segment-id UUID --acknowledge-irreversible`
  prepares deletion; add `--apply` only when you mean to delete. Deletion keeps a
  checkpoint and tombstone, leaves the active log intact, and has no undo.

## Limits

- Configured files, a current loaded hook and observed blocking are separate
  facts. Only `tirith doctor --verify-shell` (or
  `tirith status --require-verified-blocking`) observes blocking, and that
  evidence covers only the shell it ran in and expires.
- Native PowerShell and Nushell verification is not implied by successful
  configuration.
- MCP covers only the calls a host routes through it; it does not block native
  terminal tools. A diagnostic child process or a warn-only host does not prove
  that an integration can withhold an operation.
- Recommended setup can include Claude Code only, and only on macOS and Linux
  with a trusted `python3`; on Windows it refuses (use
  `tirith setup claude-code`). It refuses before changing anything when Claude
  managed settings are present, `CLAUDE_CONFIG_DIR` points elsewhere, hooks are
  disabled, the existing hook script was edited by hand, or the owned handler
  was customized. Use `tirith setup <tool>` for other hosts.
- Project review does not discover every workspace, start MCP servers, run hooks
  or install dependencies. Package inspection and comparison never authorize an
  installation, and `tirith pkg install` stays disabled on every host: flags,
  sudo and administrator access cannot enable it. `tirith pkg approve` issues no
  approvals, so installing sudo or the protected helper does not enable it.
- An expected-operation label does not make an operation safe or approved. A
  trust grant is only eligible where policy allows it; other restrictions can
  still block. Explicit manual settings and organization, remote, project and
  incident restrictions still apply after a profile change.
- The dashboard never replaces the binary and never asks for credentials or
  elevates. A protected system destination or an installed privileged helper
  can need administrator action.
- Uninstalling the binary does not delete local history or recovery data.
  Shared administrator-owned helper and key material needs the documented
  administrator cleanup once no user needs it.
- A support bundle's selection is bounded; an unavailable incident does not
  prove that the event never happened.
