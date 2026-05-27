# Wiring `tirith prompt-status` into your shell prompt

`tirith prompt-status` is a fast status emitter designed to be called from
your shell prompt on every redraw. It shows the operator's current
protection posture (`guarded` / `warn-only` / `degraded` / `off`) plus
the currently-active kubernetes / AWS / SSH / sudo context — at a glance.

This doc is the manual-install reference. `tirith init --shell <name>
--prompt-status` does the same thing automatically for the four supported
shells; reach for the snippets below when you'd rather hand-edit your
rc file, or for shells that the auto-install path can't safely splice
(like nushell).

For the longer "what is `TIRITH_STATUS`" companion piece — the
non-exported shell variable that the **shell hook itself** sets — see
`docs/prompt-status.md`. The two docs serve different needs:

| Doc                          | Audience                                            |
|------------------------------|-----------------------------------------------------|
| `docs/prompt-status.md`      | Just want the protection level? Read `TIRITH_STATUS`. |
| `docs/prompt-integration.md` | Want **everything** — protection + context + sudo + ssh — in one line? Run `tirith prompt-status` from your prompt. |

## Output forms

```sh
$ tirith prompt-status --short
[tirith:guarded][aws:prod][kube:payments-prod]

$ tirith prompt-status
tirith: guarded; aws: prod; kube: payments-prod; sudo: session active

$ tirith prompt-status --json
{"schema_version":1,"protection_mode":"guarded","contexts":{"aws":"prod","kube":"payments-prod"},"ssh_remote":false,"sudo_active":true}
```

The JSON envelope is the stable interface — `schema_version` is pinned
at `1` and additive fields are allowed without bumping it; structural
changes will bump the version. Use the JSON form from external prompt
renderers (Starship, oh-my-zsh themes) that want to do their own
formatting.

## Auto-install (recommended)

`tirith init --shell <name> --prompt-status` emits the rc-file snippet
for your shell. It's intended to be `eval`-ed at the same point you
already `eval` `tirith init`:

```sh
# ~/.zshrc — single line that loads both the hook and the prompt
eval "$(tirith init --shell zsh --prompt-status)"
```

The snippet is idempotent: a guard variable
(`_TIRITH_PROMPT_STATUS_LOADED`, `$global:_TIRITH_PROMPT_STATUS_LOADED`,
etc.) prevents double-wrapping if your rc file is re-sourced.

## Manual install — per shell

### zsh

```zsh
# ~/.zshrc
setopt PROMPT_SUBST
PROMPT='$(tirith prompt-status --short) '"$PROMPT"
```

**Use single quotes** around `$(tirith prompt-status --short)`. With
double quotes, the command substitution happens once when `PROMPT` is
assigned — your prompt then shows a frozen status. With single quotes
zsh defers the substitution to prompt-render time.

### bash

```bash
# ~/.bashrc
PS1='$(tirith prompt-status --short) '"$PS1"
```

Same quoting rule as zsh: single quotes around the substitution.

### fish

```fish
# ~/.config/fish/config.fish
function fish_right_prompt
    tirith prompt-status --short
end
```

The right prompt keeps tirith's status out of the way of your main
prompt. If you'd rather have it on the left, override `fish_prompt`
instead and prepend the substitution.

### PowerShell

```powershell
# $PROFILE
function global:prompt {
    $line = (& tirith prompt-status --short) 2>$null
    "$line PS $($executionContext.SessionState.Path.CurrentLocation)> "
}
```

If you already have a `prompt` function (oh-my-posh, starship, etc.),
prefix its output rather than replacing it.

### nushell

Nushell doesn't have an `eval`-able prompt-wrapper, so the auto-install
path emits a doc pointer. Wire it manually:

```nu
# ~/.config/nushell/config.nu
$env.PROMPT_COMMAND = {|| $"(tirith prompt-status --short) ($env.PWD)> "}
```

### Starship

Starship runs as a separate process and doesn't share the parent
shell's `TIRITH_STATUS` non-exported variable. For starship users,
invoke `tirith prompt-status --json` from a starship custom module and
template the fields you care about.

## Latency

On a warm cache (the common case — every prompt redraw within 30s of
the previous one), `prompt-status` reads a single JSON file from
`$XDG_RUNTIME_DIR/tirith/` (Linux) or `state_dir()` (macOS) and exits.
Measured cold-cache latency on a M-series Mac is around 10 ms; warm
cache is sub-millisecond plus the binary startup overhead (~10 ms in
total for the `tirith` invocation itself).

If you find the binary-startup overhead distracting on a slow box, a
future plan is to ship `tirith prompt-status` as a static no-fork
helper. For v1 the milestone is "doesn't measurably slow down a
prompt".

## Cache semantics

- **Location:** `$XDG_RUNTIME_DIR/tirith/prompt-<uid>.cache` when XDG
  runtime dir is set, else `state_dir()/prompt-<uid>.cache`. The
  per-uid suffix avoids collisions on multi-user systems.
- **Perms:** `0700` on the parent dir, `0600` on the file. Protection
  state is per-user information; we don't want it visible to other
  users.
- **TTL:** 30 seconds. After a `kubectx` swap your prompt may lag for
  up to 30s before re-detecting; `tirith context status` always
  bypasses the cache.
- **Invalidation:** delete the cache file. The next `prompt-status`
  invocation refreshes from authoritative sources.

## What `prompt-status` detects (and what it doesn't)

| Source                          | Detected? |
|---------------------------------|-----------|
| `TIRITH_STATUS` env var         | yes       |
| `TIRITH_SSH_REMOTE` env var     | yes       |
| Sudo-session file (M8 ch4)      | yes       |
| Kubeconfig `current-context`    | yes       |
| AWS `AWS_PROFILE` / default     | yes       |
| `gcloud config list`            | **no** — too slow for the prompt budget; use `tirith context status` |
| `az account show`               | **no** — too slow for the prompt budget; use `tirith context status` |

The gcloud / az shell-outs are skipped specifically because they can
take 100ms – 1.5s in the worst case and would blow the prompt latency
budget. The richer detection still runs from `tirith context status`
and from the engine hot path when a `gcloud …` / `az …` command is
actually invoked.

## Honest scope

`prompt-status` is operator-trust, not adversary-resistant. The labels
file, the kubeconfig, the AWS env vars are all user-writable — an
attacker who already has shell access can re-label any context. This
is a fast operational indicator, not a security boundary.
