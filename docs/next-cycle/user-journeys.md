# Everyday workflows in the next-cycle candidate

These commands describe the unreleased cycle candidate based on 0.4.2. Use
`tirith version --provenance` to identify the binary being tested. Native
certification and release acceptance are tracked in [verification](verification.md).

On first use, run `tirith onboard`. Run `tirith --help` to see all commands by
category. Scripts and redirected sessions use the same direct commands, such as
`tirith status --json` or `tirith audit recent --limit 25 --json`.

## Protect a terminal

Install Tirith through your chosen channel, then run personal setup as the
intended user. Ordinary installation, checks and shell protection need no sudo.
Package-manager system directories still follow their own administrator rules;
see [installation permissions](../install-privileges.md).

```sh
tirith setup recommended --scope user --shell zsh --dry-run
tirith setup recommended --scope user --shell zsh
```

Choose `bash`, `zsh` or `fish` for the supported initial personal setup scope.
If `package_approval` is unavailable, ordinary checks and shell protection still
work. `tirith pkg approve` issues no approvals in this release, so installing
sudo or the protected helper does not enable it.

The default profile is Balanced. `--profile comfortable` or `--profile strict`
changes the reviewed selection while preserving explicit manual settings.
`--plan-only --json` saves a review without applying it. Keep the operation UUID
for status, retry, cancellation or owned undo:

```sh
tirith policy operation OPERATION_UUID
tirith policy operation OPERATION_UUID --action apply
```

Cancel a pending plan or undo an applied, owned change only when that is your
intended action; these are alternatives, not follow-up setup steps:

```sh
tirith policy operation OPERATION_UUID --action cancel
tirith policy operation OPERATION_UUID --action undo
```

Open a fresh terminal after setup. Run `tirith doctor --verify-shell` for the
current-shell instructions, then follow the exact harmless challenge commands.
Configured files, loaded versions and observed blocking are separate facts.
An unsupported or incomplete verification must not be reported as active
blocking. Evidence applies only to that shell and expires; see the
[verification protocol](../caller-shell-verification.md).

For a different supported shell variant, use `tirith setup shell --shell NAME
--dry-run` followed by its explicit setup command. Native PowerShell and Nushell
verification coverage is not implied by successful configuration.

## Protect an agent

Select the actual host and scope explicitly. For example:

```sh
tirith setup codex --scope user --dry-run
tirith setup codex --scope user
```

For Codex, this sets up the MCP gateway. MCP only covers calls the host routes
through it; it does not establish blocking for native terminal tools. Consult
the [host integration matrix](../../mcp/clients/mcp-only-agents.md) for the
selected host, scope and required restart.

Restart the host and inspect its configured hook or MCP integration. Run a
harmless check through that actual host and inspect its returned decision.
Only an integration that can withhold the real operation may report observed
blocking. A diagnostic child process or a warn-only host does not establish
that capability. Personal setup can also configure the Claude Code Bash hook in
the same undoable plan:

```sh
tirith setup recommended --scope user --shell zsh --agent claude-code --dry-run
tirith setup recommended --scope user --shell zsh --agent claude-code
```

This writes the same hook script and `~/.claude/settings.json` handler as
`tirith setup claude-code`, so the two commands can be used interchangeably,
and undoing the operation (`tirith policy operation OPERATION_UUID --action undo`)
removes only the owned handler. If the plan created the hook script, undo leaves
it as an empty file; either setup command replaces that file without `--force`.
It needs a trusted `python3`
and works on macOS and Linux; on Windows it refuses, so run
`tirith setup claude-code` there. Setup refuses, before changing anything, when
Claude managed settings are present, `CLAUDE_CONFIG_DIR` points elsewhere,
hooks are disabled, the existing hook script was edited by hand, or the owned
handler was customized. Reload Claude Code after applying, then verify the hook:
saved configuration does not prove a running agent is protected. Claude Code is
the only agent that personal setup can include; use the explicit
`tirith setup <tool>` workflow for other hosts. An MCP connection alone does not
intercept terminal commands.

## Inspect a project

Run from the project you intend to review:

```sh
tirith review --json
tirith review --path package.json --path .mcp.json --json
tirith pkg inspect ./package.tgz --format json
tirith pkg diff ./old-package.tgz ./new-package.tgz --format json
```

Project review examines known surfaces or the selected relative files. It does
not recursively discover every workspace, start an MCP server, run hooks or
install dependencies. Missing, unsupported and oversized content has explicit
coverage states. Exit status 2 can accompany a collected report when findings
or coverage gaps remain; read the report before deciding what needs more review.
The browser's Overview page offers the same explicit review
and can recheck retained file identities. Package inspection and comparison
report exact artifact identity where available, with bounded static evidence;
neither authorizes installation. `pkg install` remains disabled on every host;
flags, sudo and administrator access cannot enable that unqualified backend.
For npm, `tirith install npm <pkg>` analyzes the request before running npm.

## Resolve an interruption

Read the recorded decision and all contributing findings before choosing a
change. The Activity page shows recorded checks and supports expectation
labels; an expected operation is not automatically safe or approved.

```sh
tirith audit recent --limit 20 --json
tirith why --format json
tirith policy tune --from-audit --format json
tirith policy simulate 'echo representative-command' --shell posix --interactive --json
```

Tuning reads at most 500 recent records within a 2 MiB history read, and selects
at most 50 private expectation records. It shows recurring blockers even when
no relaxation is supported. Redacted historical examples are references, so
supply the actual representative command explicitly for simulation. With no
audit history, tuning reports `availability: absent` and exits with status 1; it
does not suggest or apply a policy change.

Preview a personal profile change, then apply it only if the reviewed changes
fit the intended workflow:

```sh
tirith policy profile balanced --dry-run --json
tirith policy profile balanced --json
```

Use `comfortable` or `strict` instead of `balanced` when appropriate; `reset`
removes profile-owned settings. Explicit manual settings and organization,
remote, project and incident restrictions can still apply. Keep the returned
operation UUID for status or owned undo.

Use an exact rule-and-target exception only after reviewing its effective
constraints. For example, `tirith trust add URL --rule RULE
--ttl 1h` records an expiring grant where the current policy permits it;
`tirith trust explain URL` explains eligibility. Other restrictions may still
block the operation. Use the actual execution boundary's supported one-use
acknowledgement when that is the applicable recovery choice.

## Upgrade

```sh
tirith version --provenance
tirith update --dry-run
```

Package-managed installations use the owning manager's update command. A
self-replaceable personal installation can use `tirith update`; a supported
saved rollback uses `tirith update --rollback`. Review candidate identity and
compatibility first. The dashboard's Settings view shows the exact command for
your installation channel to copy into a terminal; it does not replace the
binary. Its "Refresh threat DB now" button runs the same signed update as
`tirith threat-db update` and refuses redirected database paths, an
administrator-owned data directory, the root account and a remote policy that
forbids local changes. Reopen the service and reload relevant integrations after
replacement. A protected system destination or previously installed privileged
helper may require administrator action; the dashboard does not request
credentials or silently elevate.

## Remove

Remove owned startup blocks before deleting the CLI:

```sh
tirith setup shell --shell zsh --remove --dry-run
tirith setup shell --shell zsh --remove
```

Managed removal preserves manually added `tirith init` lines. Review and remove
those lines separately from the actual startup files, including custom shell
roots. Open a fresh terminal so the old loaded hook is no longer active. Then
remove Tirith through its owning package manager or delete its user-owned
standalone binary. Remove actual agent integrations
using the steps for that host in [uninstall](../uninstall.md). Review local
history and recovery data separately; uninstalling a binary does not imply
deletion of those records. Shared administrator-owned helper and key material
requires the documented administrator cleanup after its users are gone.

## Review local data before sharing or deleting

`tirith doctor --bundle --bundle-preview --bundle-incident EVENT_UUID --json`
previews selected diagnostics. Add `--bundle-operation OPERATION_UUID` to include
a saved setup operation. Keep `--bundle` and omit `--bundle-preview`
to save the freshly redacted selection privately; nothing is uploaded. Review
the resulting file before deliberately sharing it. Selection is bounded and an
unavailable incident is not evidence that the event never happened. The
dashboard has the same selection and fresh-redaction download flow.

Audit rotation is reviewed with `tirith audit rotate`. Its saved operation UUID
identifies the retained segment. `tirith audit export-segment --segment-id UUID`
prepares an exact private archive copy, which is different from a redacted
support report. `tirith audit delete-segment --segment-id UUID
--acknowledge-irreversible` prepares deletion; add `--apply` only when you intend
to apply the reviewed operation. Deletion preserves a checkpoint and tombstone,
leaves the active log intact, and has no undo. See [audit retention](audit-retention.md).

The local dashboard uses an expiring secret URL and browser CSRF protection.
Keep that URL private and reopen with `tirith dashboard` after expiry. Closing a
tab does not cancel accepted jobs; inspect the saved operation before retrying.
