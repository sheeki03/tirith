# Everyday workflows in the next-cycle candidate

These commands describe the unreleased cycle candidate based on 0.4.2. Use
`tirith version --provenance` to identify the binary being tested. Native
certification and release acceptance are tracked in [verification](verification.md).

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
The default profile is Balanced. `--profile comfortable` or `--profile strict`
changes the reviewed selection while preserving explicit manual settings.
`--plan-only --json` saves a review without applying it. Keep the operation UUID
for status, retry, cancellation or owned undo:

```sh
tirith policy operation OPERATION_UUID
tirith policy operation OPERATION_UUID --action apply
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

Restart the host and inspect its configured hook or MCP integration. Run a
harmless check through that actual host and inspect its returned decision.
Only an integration that can withhold the real operation may report observed
blocking. A diagnostic child process or a warn-only host does not establish
that capability. The current combined personal setup supports a narrow native
Claude host and interpreter tuple on macOS ARM:

```sh
tirith setup recommended --scope user --shell zsh --agent claude-code --dry-run
tirith setup recommended --scope user --shell zsh --agent claude-code
```

Setup checks the actual host, interpreter and owned configuration before applying
the reviewed operation. Start a fresh host after publication: an existing host
can miss the hook on its next turn. The supported tuple and actual host evidence
are recorded in [Claude qualification](claude-native-evidence.md). Other combined
agent selections remain unavailable; use their explicit workflow with its
documented limits. An MCP connection alone does not intercept terminal commands.

## Inspect a project

Run from the project you intend to review:

```sh
tirith review --json
tirith review --path package.json --path .mcp.json --json
tirith pkg inspect ./package.tgz --json
tirith pkg diff ./old-package.tgz ./new-package.tgz --json
```

Project review examines known surfaces or the selected relative files. It does
not recursively discover every workspace, start an MCP server, run hooks or
install dependencies. Missing, unsupported and oversized content has explicit
coverage states. The browser's Overview page offers the same explicit review
and can recheck retained file identities. Package inspection and comparison
report exact artifact identity where available, with bounded static evidence;
neither authorizes installation.

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
supply the actual representative command explicitly for simulation.

Use a profile change or an exact rule-and-target exception only after reviewing
its effective constraints. For example, `tirith trust add URL --rule RULE
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
compatibility first. In the dashboard, Settings offers explicit update and
database checks, followed by a separately reviewed apply action. Retain its
operation UUID if the response is lost. Reopen the service and reload relevant
integrations after replacement. A protected system destination or previously
installed privileged helper may require administrator action; the dashboard
does not request credentials or silently elevate.

## Remove

Remove owned startup blocks before deleting the CLI:

```sh
tirith setup shell --shell zsh --remove --dry-run
tirith setup shell --shell zsh --remove
```

Reload the shell, then remove Tirith through its owning package manager or
delete its user-owned standalone binary. Remove actual agent integrations
using the steps for that host in [uninstall](../uninstall.md). Review local
history and recovery data separately; uninstalling a binary does not imply
deletion of those records. Shared administrator-owned helper and key material
requires the documented administrator cleanup after its users are gone.

## Review local data before sharing or deleting

`tirith doctor --bundle-preview --bundle-incident EVENT_UUID --json` previews
selected diagnostics. Add `--bundle-operation OPERATION_UUID` to include a
saved setup or lifecycle operation. `--bundle` saves the freshly redacted
selection privately; nothing is uploaded. The dashboard has the same selection
and fresh-redaction download flow.

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
