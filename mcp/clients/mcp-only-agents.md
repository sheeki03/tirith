# Agent integrations

Tirith has a named setup path for 19 agent hosts. Depending on the host, setup
installs a blocking pre-execution hook or plugin, an MCP gateway, cooperative
MCP tools, or a combination of those layers.

The distinction matters. MCP makes Tirith's check and scan tools *available* to
the agent; it does **not** force the agent to call Tirith before running a
shell command. A pre-execution hook does: the host asks Tirith first and
honours a refusal. Where a host offers both, setup installs both, and it writes
the hook **before** the MCP entry so that a partial failure leaves the half that
can refuse a command.

The table is the authoritative quick comparison and deliberately includes the
earlier integrations as well as the hosts added for 0.4.0. An MCP-only row is
not an automatic command gate. A hook/plugin row is automatic only after the
host has loaded the artifact and honors its documented refusal contract.

Three of these hosts fail **open** on their own side: Grok Build, Cline, and
OpenHands all let the tool run when a hook errors or times out. Tirith's adapter
is fail-closed (it denies on its own errors unless `TIRITH_FAIL_OPEN=1`), but it
cannot compensate for a host that ignores a crashed hook. The Cline and
OpenHands wrappers, and the Gemini CLI, Kiro and Copilot CLI hook commands,
check that the pinned Python interpreter still exists and answer with the
host's deny when it does not (unless `TIRITH_FAIL_OPEN=1`), so a moved
interpreter does not silently switch the guard off. Prime Agent and OMP
block when a handler throws, so a guard crash fails closed there.

Every setup command stores the validated absolute path of the running `tirith`
binary. Existing unrelated configuration is preserved, writes are contained
and transactional, changed files receive a backup, user-level files are kept
private, and `--dry-run`, `--force`, and repeat runs are supported.

## Hook and plugin decision contract

Every installed hook or plugin passes the command to `tirith check --json` and
applies the same rules; only the host's deny shape differs (a JSON decision, a
`{block: true}` return, or exit 2):

- Exit 0 from tirith: allow (the host's own rules apply), unless the JSON
  has `requires_approval: true`, then deny.
- Exit 1: deny (block finding). `TIRITH_FAIL_OPEN` does not apply.
- Exit 2: warn. A warning is never an approval: by default
  (`TIRITH_HOOK_WARN_ACTION=allow`) the hook answers exactly as for a clean
  command, with no permission decision (Grok Build: no stdout, findings on
  stderr; Cline: `cancel: false` with the findings in `contextModification`;
  OpenHands: the findings in `additionalContext`, no `decision`). Set
  `TIRITH_HOOK_WARN_ACTION=deny` to block. `ask` asks the user where the host
  has a confirmation prompt (Claude Code, VS Code, Cursor, Copilot CLI) and is
  denied with interactive-shell guidance elsewhere. Any other value blocks and
  names the valid values (`allow`, `ask`, `deny`).
- `requires_approval: true` on exit 0 or 2 (a policy `approval_rules` match,
  or `strict_warn`): always deny, regardless of `TIRITH_HOOK_WARN_ACTION` and
  `TIRITH_FAIL_OPEN`. Agent hooks have no channel to collect approval or
  acknowledgement; retry the command from a Tirith-protected interactive shell.
- Exit 3 (mandatory warning acknowledgement): always deny.
- Exit 4 (deferred block from `TIRITH_DEFER=1` / `tirith check --defer`,
  recorded for `tirith pending`): always deny, regardless of
  `TIRITH_FAIL_OPEN`.
- Missing or invalid JSON, or a non-boolean `requires_approval`, on exit 0 or
  2: checker error -- deny unless `TIRITH_FAIL_OPEN=1`. Exit 2 with
  `TIRITH_HOOK_WARN_ACTION` set to anything but `allow` stays denied.
- Any other exit code, timeout, or missing binary: deny unless
  `TIRITH_FAIL_OPEN=1`.

`TIRITH_FAIL_OPEN=1` covers checker errors only; it never overrides a block, a
deferred block, or a required approval or acknowledgement. A `TIRITH=0` bypass
that user or org policy honors (`allow_bypass_env_noninteractive: true`, since
hooks run non-interactively) exits 0 with `"action": "allow"`,
`"bypass_honored": true` and `"requires_approval": false`, so the hook allows
it. Because the hook runs on the agent's behalf, that grant extends to the
agent itself: it can prefix `TIRITH=0` to any command and skip every check,
including blocks, `approval_rules` and `strict_warn`. Enable
`allow_bypass_env_noninteractive` only for trusted automation.

After upgrading the tirith binary, re-run `tirith setup <tool> --force` with
the same `--scope` you used originally, so installed hooks and plugins pick up
the new checks. `tirith doctor` flags an installed adapter that differs from
the current embedded asset.

## Supported clients

| Client | Enforcement | Setup command | Supported scope and config | Verification |
|---|---|---|---|---|
| Claude Code | Hook; optional MCP | `tirith setup claude-code --with-mcp` | Project default: `.claude/settings.json` and `.claude/hooks/`; user: `~/.claude/`. Project MCP uses `.mcp.json`; user MCP is merged into Claude settings | `tirith doctor`, then ask Claude to run a known-blocked and a clean command |
| OpenAI Codex | MCP gateway; optional zsh guard | `tirith setup codex` | User only. Registers a generation-bound Tirith gateway through `codex mcp`; `--install-zshenv` adds the non-interactive zsh path | `codex mcp get tirith-gateway`; run `scripts/codex-upgrade-smoke.sh` and a native-shell block check |
| GitHub Copilot CLI | Hook | `tirith setup copilot-cli` | Project only: repo-root `.github/hooks/tirith-security.json` plus its pinned Python hook. Copilot loads it only when launched from that repo root | Start Copilot at the repo root; test one blocked `bash` call and one clean call |
| Cursor | Hook + MCP gateway | `tirith setup cursor` | Project default or user: `.cursor/hooks.json`, hook asset, and `mcp.json`; `--install-zshenv` adds the non-interactive zsh path | `tirith doctor`, restart Cursor, and perform host-shaped hook and MCP checks |
| Gemini CLI | Hook; optional MCP | `tirith setup gemini-cli --with-mcp` | Project default: `.gemini/`; user: `$GEMINI_CLI_HOME/.gemini`, otherwise `~/.gemini` | Restart Gemini CLI; test `run_shell_command` allow/deny and list MCP tools when enabled |
| Kiro CLI | Agent-scoped hook | `tirith setup kiro` | Project default or user: `.kiro/hooks/` plus `.kiro/agents/tirith-security.json`. The hook applies only when that agent/config is loaded | Launch `kiro-cli --agent tirith-security` (or merge the hook into the chosen agent), then test allow/deny |
| OpenClaw | Plugin hook | `tirith setup openclaw` | Project default: `.openclaw/extensions/tirith-security`; user: `$OPENCLAW_STATE_DIR`, legacy `$CLAWDBOT_STATE_DIR`, or `~/.openclaw` | Restart OpenClaw; test `exec`/`bash` allow and deny with the actual host/shell configuration |
| Pi CLI | Hook | `tirith setup pi-cli` | Project default: `.pi/extensions/`; user: `$PI_CODING_AGENT_DIR`, otherwise `~/.pi/agent/extensions/` | Start Pi with the extension loaded; test one blocked and one clean `bash` call |
| VS Code | Workspace hook + MCP gateway | `tirith setup vscode` | Project only: `.vscode/settings.json`, `.vscode/hooks/`, and `.vscode/mcp.json`; `--install-zshenv` adds the non-interactive zsh path | Reload the workspace and perform host-shaped hook and MCP checks |
| Windsurf | Hook + MCP gateway | `tirith setup windsurf` | User only: `~/.codeium/windsurf/hooks.json`, hook asset, and `mcp_config.json`; `--install-zshenv` adds the non-interactive zsh path | Restart Windsurf; test a Cascade command and the registered MCP gateway |
| Grok Build | Hook + MCP | `tirith setup grok-build` | Project: `<invocation-cwd>/.grok/config.toml` plus trusted `<git-root>/.grok/hooks/tirith.json`; user: `$GROK_HOME`, otherwise `~/.grok` | `grok mcp doctor tirith`; `/hooks` |
| OMP (Oh My Pi) | Hook + MCP | `tirith setup omp` | User only. Root: `~/${PI_CONFIG_DIR:-.omp}`; named profile: `<root>/profiles/<name>/agent/mcp.json`; default: `$PI_CODING_AGENT_DIR/mcp.json`, otherwise `<root>/agent/mcp.json`. Guard: `hooks/pre/tirith-guard.ts` beside that `mcp.json`, which is where OMP discovers hooks (its agent directory, profile-aware) | `/mcp test tirith` |
| OpenCode | MCP only | `tirith setup opencode` | Project: the rootmost existing project `.opencode/opencode.json(c)`, otherwise the invocation directory's `opencode.json(c)`; user: `$OPENCODE_CONFIG_DIR/opencode.json(c)`, then `$OPENCODE_CONFIG`, otherwise `${XDG_CONFIG_HOME:-~/.config}/opencode/opencode.json(c)` | `opencode mcp list` |
| Vercel Labs fx | MCP only | `tirith setup fx` | Trusted user profile only: `~/.fx/mcp.json` | `/mcp reload`, then `/mcp list` |
| Prime Agent | Hook + MCP | `tirith setup prime-agent` | User only: non-empty `$PRIME_AGENT_CODING_AGENT_DIR/settings.json`, otherwise `~/.prime/agent/settings.json`; exact `~` and `~/...` values expand from HOME. Guard: `<agent dir>/extensions/tirith-guard.ts` | `prime-agent mcp get tirith` |
| Cline | Hook + MCP | `tirith setup cline` | User only: `$CLINE_MCP_SETTINGS_PATH`; then `$CLINE_DATA_DIR/settings/cline_mcp_settings.json`; then `$CLINE_DIR/data/settings/cline_mcp_settings.json`; otherwise `~/.cline/data/settings/cline_mcp_settings.json`. Hook: `<Documents>/Cline/Hooks/PreToolUse` (POSIX) or `PreToolUse.ps1` (Windows), with Documents resolved the way Cline resolves it (`xdg-user-dir DOCUMENTS` on Linux, the MyDocuments special folder on Windows, `~/Documents` otherwise) | Restart Cline, enable hooks in settings, open MCP Servers |
| Roo Code | MCP only | `tirith setup roo-code` | Project only: `<cwd>/.roo/mcp.json`; run setup from the intended workspace root | Confirm `tirith` is connected in MCP Servers |
| Continue | MCP only | `tirith setup continue` | Project-owned block only: `<cwd>/.continue/mcpServers/tirith.yaml`; run setup from the intended workspace root | Switch to Agent mode and confirm Tirith tools are present |
| OpenHands CLI | Hook + MCP | `tirith setup openhands` | MCP is user only: non-empty absolute `$OPENHANDS_PERSISTENCE_DIR/mcp.json` without surrounding whitespace, otherwise `~/.openhands/mcp.json` when unset. Hooks follow the two locations the SDK searches: `--scope user` writes `~/.openhands/hooks.json`, `--scope project` writes `<work dir>/.openhands/hooks.json` where the work dir is `$OPENHANDS_WORK_DIR`, otherwise the current directory | `openhands mcp get tirith`; restart active conversations |

Use `--scope user` for Grok Build or OpenCode when a user-wide
registration is wanted. The other commands select their only safe documented
scope by default. `fx` here means the open-source Vercel Labs agent at
[`fx.sh`](https://fx.sh), not Factory Droid.

Prime Agent setup uses its generic MCP runtime, which documents local `stdio`
servers and executes only user-level `mcpServers` entries. It does not use the
separate authored Python `McpIntegration` wrapper API; that API currently
accepts only remote HTTP servers. Tirith therefore writes no project Prime
configuration and rejects `--scope project`. An explicitly empty
`PRIME_AGENT_CODING_AGENT_DIR` selects the default; exact `~` and `~/...`
forms receive the same HOME expansion as the host before contained writes.

OpenCode setup targets the current stable `opencode` schema. It does not write
the separate beta `opencode2` configuration shape. OMP and Pi CLI are also
different integrations: OMP receives MCP tools, while existing
[`tirith setup pi-cli`](pi-cli.md) installs Pi's real blocking `tool_call`
extension.

OMP setup follows `OMP_PROFILE`, then legacy `PI_PROFILE`; an explicitly empty
`OMP_PROFILE` selects the default profile. Named profiles ignore
`PI_CODING_AGENT_DIR`; both named and default profiles derive their base from
the home-relative `PI_CONFIG_DIR` when it is set. User setup also removes
`tirith` from that profile's higher-precedence `disabledServers` list in the
same file transaction. Project setup is deliberately refused: OMP deep-merges
project settings from built-in and provider-specific discovery directories,
and any later `mcp.enableProjectConfig: false` can suppress a newly written
project MCP file. A contained setup writer cannot safely establish that entire
effective state. Use the profile-aware user registration and verify the
intended launch with `/mcp list` or `/mcp test tirith` from the target project.
`mcp.enableProjectConfig: false` filters only project entries and cannot
suppress the user Tirith registration; when project configs are enabled, a
same-name project `.omp/mcp.json` can intentionally shadow it. OMP also
loads path/profile variables from the launch directory, active agent,
active config-root, and home `.env` files. For a named profile the active
config-root dotenv is `<base>/profiles/<name>/.env`, not `<base>/.env`; the
default profile uses the base root. Bun additionally autoloads the launch
directory's `.env`, `.env.<mode>`, `.env.local` outside test mode, then
`.env.<mode>.local`. Bun selects `BUN_ENV` when it is defined (including an
empty value), otherwise `NODE_ENV`; exact `production` and `test` select those
modes, while every other value selects `development`. When the
corresponding process variable is unset, setup refuses such a dotenv definition
rather than guessing a target; export the intended `OMP_PROFILE`/`PI_PROFILE`,
`PI_CONFIG_DIR`, `PI_CODING_AGENT_DIR`, or `PI_CONFIG_FILES` explicitly and
rerun setup. Named profiles ignore coding-agent-directory variables, including
dotenv definitions. For the default profile, an explicitly empty
`PI_CODING_AGENT_DIR` or empty mirrored `OMP_CODING_AGENT_DIR` dotenv value is
absent and selects the default `<root>/agent` directory. OMP mirrors `OMP_*`
aliases to `PI_*` only in the plain
`.env` files it parses itself; Bun-only mode/local files must use the canonical
`PI_*` name (while `OMP_PROFILE` remains the canonical profile selector).

OpenCode setup models the inspectable local/environment load chain. It targets
the rootmost existing project `.opencode` layer when present and preflights
ordinary project files, every later `.opencode` directory from the invocation
directory through the worktree, `~/.opencode`, `OPENCODE_CONFIG_DIR`, and
`OPENCODE_CONFIG_CONTENT` as their positions require. Project setup also
refuses when `OPENCODE_DISABLE_PROJECT_CONFIG` is enabled. Organization remote
configuration, managed configuration files, and macOS managed preferences can
load after these layers and are intentionally not treated as locally
inspectable; `opencode mcp list` remains required to verify the administrator
and organization effective result.

Grok project setup writes the MCP entry at the directory where setup is
invoked, matching Grok's project CLI and making it the deepest effective
`.grok/config.toml` for that working directory. The executable hook assets live
at the Git root, which is the host's project-hook boundary. User setup removes
`tirith` from the user `disabled_mcp_servers` list in the same TOML transaction;
project setup refuses before publishing either artifact while that user-level
deny remains active.

## Trust and enforcement boundary

An MCP registration is cooperative. The host decides whether to advertise,
approve, and call the registered tools. It cannot be described as a command
guard unless the host has an effective pre-tool hook that invokes Tirith and
can deny execution. Keep Tirith's shell integration, a supported blocking agent
hook, CI scanning, or another enforcement layer enabled where automatic
coverage is required.

On POSIX systems, Grok Build setup also installs a `PreToolUse` hook matching
its Bash-compatible terminal tool. The adapter handles Grok's native
`pre_tool_use` / `run_terminal_command` envelope and returns its documented
allow/deny decision. Project MCP config resolves at the invocation directory
while hook discovery resolves at the Git root; both still require explicit
folder trust. Grok's contract is fail-open if the hook process itself errors or
exceeds the host timeout, and the hook observes host-provided command text; it
is therefore a useful blocking layer, not a standalone security boundary. On
Windows, Tirith installs only the MCP registration until Grok exposes a
shell-grammar signal that setup can verify.

Setup records the validated absolute Python interpreter in Grok's hook command.
It does not leave a bare `python3` for the repository runtime to resolve; re-run
setup if that interpreter moves.

### The Pi-family guard

Pi CLI, Prime Agent, and OMP expose the same blocking `tool_call` event and the
same `{ block: true, reason }` veto, so they install one shared extension that
differs only in the integration label it reports. Prime and OMP additionally
block when the handler *throws*, which makes a guard crash fail closed on those
two hosts.

Prime Agent also exposes an `ipython` tool, and a notebook cell can reach a
shell through several syntaxes at once. The guard collects every vector it can
recognise rather than stopping at the first: `!cmd`, `!!cmd`, assignment from
`!cmd` (including `obj.attr = !cmd`), `%system` / `%sx`, the `%%bash` / `%%sh`
/ `%%script <shell>` cell magics (with `%%script` options parsed, so
`--out captured` is not mistaken for the interpreter), backslash-continued
lines joined first, `get_ipython().system(...)` and its `run_line_magic` /
`run_cell_magic` forms, and the Python-level `os.*`, `subprocess.*`, and
`pty.spawn` calls with each API's real argument shape (`execl` and `spawn*`
take an argv, `subprocess.run` takes a string or a list). Aliases such as
`import subprocess as sp` and `from os import system` are remembered across
cells, because the kernel is persistent. Comments and string bodies are lexed
rather than pattern-matched, so a commented-out call is not a vector and a `#`
inside a string does not truncate a line.

The reconstruction follows execution semantics rather than source appearance:
`exec*`/`spawn*` omit Python's synthetic `argv[0]`; canonical API identity
survives a `from ... import ... as ...` alias; and `subprocess shell=True`
treats its command as shell syntax while `shell=False` preserves a string as
one executable pathname. Unicode identifiers are tokenized and NFKC-normalized
like Python, eight-digit Unicode escapes are decoded, and named or malformed
escapes are unresolved instead of silently changed. A backslash inside a
Python comment never joins the next line. Unknown line/cell magics and
non-shell `%%script` interpreters are also unresolved, while
`%%script /usr/bin/env bash` is recognized as a shell cell.

Recovered commands are sent to `tirith check` over stdin as one script, so the
engine makes every security decision and the extension makes none. An argv
list is rendered with POSIX quoting, so `["printf", "%s", "a | b"]` reaches
the engine as the single argument it is rather than as a pipeline.

OMP also exposes process execution outside `bash`. The guard checks the exact
application and argv supplied to `hub(op: "start")`. It blocks by default when
the event does not contain the full command: arbitrary `eval` code; `hub`
restart or process input; non-empty `hub` launch environments (which can carry
runtime or loader preloads); and mutating `debug` actions. Debug launches are
also uninspectable because OMP starts a configured debugger adapter whose
command is absent from the event. Read-only `hub` and `debug` operations remain
available. `TIRITH_HOOK_UNRESOLVED_ACTION=warn` is an explicit opt-out from
this fail-closed boundary.

A vector whose command is computed at runtime cannot be shown to the engine:
an IPython `{expr}` or `$var` expansion, an f-string, a concatenation with a
variable, a non-literal argv element. These are **blocked by default** rather
than approximated, because half a command line means something other than the
command that will run; `TIRITH_HOOK_UNRESOLVED_ACTION=warn` opts out and turns
them into a stderr warning. The same applies to a cell too large to inspect.

What this cannot do, stated plainly: source-level extraction cannot prove
arbitrary Python safe. A wrapper function defined in an earlier cell, a
`getattr` or `__import__` indirection, or a third-party package that spawns a
process will not be recognised as a vector. The guard raises the cost of the
obvious routes and refuses the unreadable ones; it is not a sandbox.

`tests/ipython-vector-extraction.mjs` runs the exact shipped bytes of the guard
against every syntax above.

### Cline and OpenHands

Neither host can pass environment to a hook: Cline runs a bare executable named
exactly `PreToolUse`, and an OpenHands hook definition has no `env` field. Both
therefore get a small generated `#!/bin/sh` wrapper that `exec`s the shared
adapter with the right protocol baked in, installed alongside it and mode 0755.

Cline hooks are inert until hooks are enabled in Cline's settings, and Cline
runs the tool when a hook fails, so a hook that cannot start is not a block.
Cline runs a `PreToolUse` executable on POSIX and a `PreToolUse.ps1` through
PowerShell on Windows; setup installs the right one for the platform. The
Windows script is the counterpart of the POSIX wrapper: it forwards Cline's
stdin and stdout through the same Python adapter. Setup validates `python3`
(or `python` on Windows) and bakes that interpreter's absolute path into both
wrappers; re-run setup if it moves. An untrusted repository or temporary PATH
shadow makes setup fail closed and is never executed.

The adapter accepts both Cline's current `run_commands` batch and its legacy
`execute_command` event. It decodes and bounds every batch member, refuses
malformed or empty command data, and checks the applicable POSIX, PowerShell,
and Cmd interpretations when the event does not identify one authoritative
shell. A denial in any applicable grammar denies the tool call. Every other
intentional Cline path emits an explicit JSON allow envelope; empty stdout is
reserved for no outcome and is never Tirith's representation of allow.

OpenHands searches exactly two places for `hooks.json`: the working directory
it was started in (`OPENHANDS_WORK_DIR`, otherwise the current directory, with
no parent walk) and `~/.openhands`. Setup writes to whichever the scope names,
and merges into an existing file rather than replacing it, so hooks the
repository already has survive. The hook command is shell-quoted, because
OpenHands runs it through a shell. A denial exits 2, the only exit code that
host treats as a block; any other non-zero exit is logged and the tool runs.

OpenHands can also send `is_input=true` text directly to a process left running
by an earlier terminal call. That event does not identify whether the process
is a shell, Python, Node, a debugger, or something else, so treating the text
as a new POSIX command would inspect the wrong language. Tirith blocks non-empty
persistent-process input by default. Empty output polls and the exact `C-c`,
`C-d`, and `C-z` control tokens remain available; a newline is blocked because
it can execute already buffered input. `TIRITH_HOOK_UNRESOLVED_ACTION=warn`
explicitly opts out and surfaces the limitation in `additionalContext`.

Repository-local MCP files also execute the configured command when the agent
loads that project. Review project configuration before trusting a repository.
Tirith setup never adds an automatic-approval list for its MCP tools.
Prime Agent, OMP, Vercel Labs fx, Cline, Roo Code, and OpenHands load their
respective `.json` files with strict JSON parsers; setup rejects comments or
trailing commas instead of mutating a file the host itself cannot load.
Prime Agent alone treats a zero-byte settings file as `{}`; Cline trims its
settings before the same empty-state fallback. Whitespace-only Prime files and
blank fx, Roo Code, and OpenHands files remain errors.
OpenCode's documented JSONC files remain comment- and trailing-comma-aware.
OpenHands uses `OPENHANDS_PERSISTENCE_DIR` verbatim. Tirith refuses a defined
empty, relative, or whitespace-padded value rather than writing a cwd-relative
or whitespace-literal registry; unset the variable to select `~/.openhands`.

## Deferred open-source clients

| Client or capability | Status | Reason |
|---|---|---|
| OMP project scope | Deferred; profile-aware user MCP and the user-scope guard are supported above | OMP deep-merges project settings from multiple built-in and provider-specific discovery roots. A later provider can set `mcp.enableProjectConfig: false`, so writing only `.omp/mcp.json` cannot guarantee an effective registration. |
| Goose | Deferred for automated setup | Goose documents stdio extensions in shared `~/.config/goose/config.yaml`, but safely editing arbitrary YAML while preserving comments, anchors, duplicate-key diagnostics, and unrelated extension state needs a dedicated contained YAML merger. Tirith does not reserialize that user file. |
| Aider | Unsupported | Current Aider documentation exposes model/tool configuration but no native MCP client registry or blocking pre-tool hook suitable for Tirith setup. |
| Roo Code blocking hook | MCP only | Roo's stable project MCP file is documented; no equivalent stable blocking pre-tool setup contract was found. |
| Continue user-global YAML mutation | Project block supported above | Continue supports a dedicated workspace MCP-block directory, which lets Tirith own one file. Its global `config.yaml` may contain anchors, comments, and secret references, so setup leaves it untouched. |

## Primary contracts

These contracts were rechecked on **2026-08-21**. Repository-backed surfaces
below are pinned to the inspected contract revision; live documentation
surfaces were retrieved on that date. The inspected contract revisions were Grok Build
`19d42e35c07a`, OMP 17.4.1 `9350b7990d26`, OpenCode `1b937c860b6f`
(`dev`), Vercel Labs fx 0.0.4 `9898c6dd706c`, Prime Agent 0.7.4
`35103cb420ab`, Pi CLI 0.84.2 `f4585b8bec58`, Cline `fb60f9e5fdb1`, Roo
Code `b867ec914575`, Continue `5522c6f44ca0`, and OpenHands CLI
`954f2ba646e8`. Prime commit `848081edb1f` was an earlier inspected 0.7.4
snapshot; the contract used here is pinned above.

- [Prime Agent generic MCP servers and authored-wrapper distinction](https://github.com/PrimeIntellect-ai/prime-agent/blob/35103cb420ab8bdc8dbf9a8015aa40eb92652f5c/packages/coding-agent/docs/mcp-integrations.md#generic-mcp-servers)
- [Prime Agent generic MCP stdio settings type](https://github.com/PrimeIntellect-ai/prime-agent/blob/35103cb420ab8bdc8dbf9a8015aa40eb92652f5c/packages/coding-agent/src/core/settings-manager.ts#L105-L126), [strict settings parser](https://github.com/PrimeIntellect-ai/prime-agent/blob/35103cb420ab8bdc8dbf9a8015aa40eb92652f5c/packages/coding-agent/src/core/settings-manager.ts#L381-L393), and [user-only settings manager](https://github.com/PrimeIntellect-ai/prime-agent/blob/35103cb420ab8bdc8dbf9a8015aa40eb92652f5c/packages/coding-agent/src/core/settings-manager.ts#L1210-L1221)
- [Pi CLI executable extension trust and locations](https://github.com/badlogic/pi-mono/blob/f4585b8bec581d005cbb1edfc07edfcce723d0ae/packages/coding-agent/docs/extensions.md#extension-locations) and [blocking `tool_call` contract](https://github.com/badlogic/pi-mono/blob/f4585b8bec581d005cbb1edfc07edfcce723d0ae/packages/coding-agent/docs/extensions.md#tool_call)
- [Grok Build MCP config chain and CLI scopes](https://github.com/xai-org/grok-build/blob/19d42e35c07a9c9244f03f6df0c4c353f970d4f9/crates/codegen/xai-grok-pager/docs/user-guide/07-mcp-servers.md#cli-management) and [loader precedence](https://github.com/xai-org/grok-build/blob/19d42e35c07a9c9244f03f6df0c4c353f970d4f9/crates/codegen/xai-grok-shell/src/util/config/mcp.rs#L205-L217)
- [Grok Build hooks](https://github.com/xai-org/grok-build/blob/19d42e35c07a9c9244f03f6df0c4c353f970d4f9/crates/codegen/xai-grok-pager/docs/user-guide/10-hooks.md)
- [Grok Build user enable semantics](https://github.com/xai-org/grok-build/blob/19d42e35c07a9c9244f03f6df0c4c353f970d4f9/crates/codegen/xai-grok-shell/src/util/config/mcp.rs#L904-L1000)
- [OMP MCP profiles and enable/disable overrides](https://github.com/can1357/oh-my-pi/blob/9350b7990d26ebf69a604edc82d8558ef04adf30/docs/mcp-config.md), [settings/profile precedence](https://github.com/can1357/oh-my-pi/blob/9350b7990d26ebf69a604edc82d8558ef04adf30/docs/config-usage.md#4-settings-resolution-model), [heterogeneous project settings merge](https://github.com/can1357/oh-my-pi/blob/9350b7990d26ebf69a604edc82d8558ef04adf30/packages/coding-agent/src/config/settings.ts#L1358-L1415), [dotenv path/profile precedence](https://github.com/can1357/oh-my-pi/blob/9350b7990d26ebf69a604edc82d8558ef04adf30/docs/environment-variables.md#resolution-model-and-precedence), [OMP launch-dotenv handling](https://github.com/can1357/oh-my-pi/blob/9350b7990d26ebf69a604edc82d8558ef04adf30/packages/utils/src/env.ts#L50-L105), [Bun dotenv autoload contract](https://bun.com/docs/runtime/environment-variables#setting-environment-variables), [dotenv loader and directory refresh](https://github.com/can1357/oh-my-pi/blob/9350b7990d26ebf69a604edc82d8558ef04adf30/packages/utils/src/env.ts#L185-L223), and [strict JSON MCP loader](https://github.com/can1357/oh-my-pi/blob/9350b7990d26ebf69a604edc82d8558ef04adf30/packages/coding-agent/src/mcp/config-writer.ts#L37-L52)
- [OpenCode local, environment, organization, and managed load order](https://github.com/anomalyco/opencode/blob/1b937c860b6fd8a83e69f916b1236515aa17ea0d/packages/opencode/src/config/config.ts#L398-L488), [ordered config directories](https://github.com/anomalyco/opencode/blob/1b937c860b6fd8a83e69f916b1236515aa17ea0d/packages/opencode/src/config/paths.ts#L23-L40), [upward traversal order](https://github.com/anomalyco/opencode/blob/1b937c860b6fd8a83e69f916b1236515aa17ea0d/packages/core/src/fs-util.ts#L168-L180), and [XDG-backed global path](https://github.com/anomalyco/opencode/blob/1b937c860b6fd8a83e69f916b1236515aa17ea0d/packages/core/src/global.ts#L1-L31)
- [Vercel Labs fx MCP](https://fx.sh/docs/capabilities/mcp) and [strict JSON loader](https://github.com/vercel-labs/fx/blob/9898c6dd706c40c9631e39b110fcbc97d56169bd/src/builtins/mcp.zig#L479-L497)
- [Cline MCP settings path fallback](https://github.com/cline/cline/blob/fb60f9e5fdb1dc7c3f4861cffaf04fc5fa2eca6c/apps/vscode/src/hosts/vscode/mcp-settings-legacy-migration.ts#L254-L265), [strict settings loader](https://github.com/cline/cline/blob/fb60f9e5fdb1dc7c3f4861cffaf04fc5fa2eca6c/apps/vscode/src/services/mcp/McpHub.ts#L201-L216), [configuration](https://docs.cline.bot/getting-started/config), and [hooks](https://docs.cline.bot/customization/hooks)
- [Roo Code project `.roo/mcp.json` scope](https://github.com/RooCodeInc/Roo-Code/blob/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16/apps/docs/docs/features/mcp/using-mcp-in-roo.mdx#L22-L41) and [strict project loader](https://github.com/RooCodeInc/Roo-Code/blob/b867ec9145750d0ae1ff7f02d35406e9bf2a0b16/src/services/mcp/McpHub.ts#L302-L387)
- [Continue configuration](https://docs.continue.dev/customize/deep-dives/configuration) and [pinned workspace `.continue/mcpServers/*.yaml` block contract](https://github.com/continuedev/continue/blob/5522c6f44ca0ac3528b37244818fbfa39b5af470/docs/customize/deep-dives/mcp.mdx#L24-L90)
- [OpenHands persistence directory](https://github.com/All-Hands-AI/OpenHands-CLI/blob/954f2ba646e8d749261a8f2b2b7e3031fa39be9f/openhands_cli/locations.py#L5-L12), [MCP registry path and strict file loader](https://github.com/All-Hands-AI/OpenHands-CLI/blob/954f2ba646e8d749261a8f2b2b7e3031fa39be9f/openhands_cli/mcp/mcp_utils.py#L15-L66), and [MCP servers](https://docs.openhands.dev/openhands/usage/cli/mcp-servers)
- [Goose configuration files](https://github.com/aaif-goose/goose/blob/45b322c1df30295caaceb23a8a043fc9fa032527/documentation/docs/guides/config-files.md)
- [Aider documentation](https://aider.chat/docs/)
