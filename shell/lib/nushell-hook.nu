# tirith nushell hook
# LIMITATION: Cannot block execution — warn-only mode
# Add to config.nu:  source ~/.local/share/tirith/shell/lib/nushell-hook.nu

# Interactive-only: the hook intercepts commands typed at a prompt, so it must
# be a complete no-op in a non-interactive nushell (`nu -c …`, `nu script.nu`).
# Nushell does not load `config.nu` for those by default, but guarding on
# `$nu.is-interactive` makes the no-op explicit and survives a config sourced
# another way.
#
# TIRITH_STATUS — note on nushell: the other tirith hooks expose a small
# non-exported `TIRITH_STATUS` shell variable for an opt-in prompt segment.
# Nushell has no session-persistent variable that is both readable by a later
# prompt closure and *not* inherited by child processes — anything in `$env`
# is exported to externals, and a non-interactive child has no tirith
# protection, so an inherited status would misrepresent it. The nushell hook
# therefore deliberately does NOT set a `TIRITH_STATUS` variable;
# `docs/prompt-status.md` accordingly has no nushell snippet. nushell is
# warn-only regardless (its `pre_execution` hook cannot abort a command).
if (($nu.is-interactive) and (not ('_TIRITH_NU_LOADED' in $env))) {
    $env._TIRITH_NU_LOADED = true

    # M8 ch2 — surface "this shell is on the remote side of an SSH session"
    # to `tirith prompt-status` (planned for M8 ch6) and any other
    # downstream consumer. Set NOW so chunk 6 can read it without a
    # follow-up hook patch. Nushell's `$env` is auto-exported to externals,
    # which is exactly what we want here: a child `tirith` invocation
    # should see TIRITH_SSH_REMOTE.
    if (not ('TIRITH_SSH_REMOTE' in $env)) and (
        ('SSH_CONNECTION' in $env) or ('SSH_CLIENT' in $env) or ('SSH_TTY' in $env)
    ) {
        $env.TIRITH_SSH_REMOTE = "1"
    }

    # M9 ch4 — record a shell-start environment snapshot for `tirith env diff`.
    # Exec a hidden tirith subcommand that reads ITS OWN inherited environment
    # (nushell's `$env` is auto-exported to externals) and writes ONLY variable
    # names + an 8-char value-hash prefix (never raw values, never a recoverable
    # hash) to <state-dir>/env_snapshot.json. No value crosses an argv boundary
    # or a temp file. The write is a sub-millisecond single env read; it runs
    # once per session (guarded above). Errors are swallowed so a missing binary
    # never disrupts the shell.
    try {
        ^tirith env snapshot | complete | ignore
    }

    # Defensively initialize pre_execution if absent/null (fresh configs may lack it)
    let existing = ($env.config.hooks.pre_execution? | default [])

    $env.config.hooks.pre_execution = ($existing | append {||
            # Reentrancy guard (safety — pre_execution shouldn't recurse,
            # but guard prevents issues if Nushell behavior changes)
            if ('_TIRITH_NU_RUNNING' in $env) and $env._TIRITH_NU_RUNNING { return }

            let cmd = (commandline)
            if ($cmd | is-empty) { return }

            # Skip tirith's own commands (engine also guards via is_self_invocation,
            # but this avoids spawning a subprocess entirely)
            let first_word = ($cmd | split row ' ' | first)
            if ($first_word == "tirith") or ($first_word | str ends-with "/tirith") { return }

            $env._TIRITH_NU_RUNNING = true
            try {
                let result = (with-env {_TIRITH_HOOK: "1"} { do { ^tirith check --non-interactive --interactive --shell posix -- $cmd } | complete })
                $env._TIRITH_NU_RUNNING = false

                if $result.exit_code != 0 {
                    print -e $"(ansi red_bold)tirith warning:(ansi reset) security concerns detected"
                    if ($result.stderr | is-not-empty) {
                        print -e $result.stderr
                    }
                    print -e $"(ansi yellow_dimmed)Nushell cannot block execution. Review the command above.(ansi reset)"
                }
            } catch {
                $env._TIRITH_NU_RUNNING = false
            }
        }
    )
}

# ── tirith output wrap (M7 ch1) ─────────────────────────────────────────────
# Opt-in output-direction wrapper. Commented out by default in this embedded
# hook copy; `tirith output wrap on` writes an active copy of the function
# into the user's shell-profile separately. This block is kept here as the
# canonical source so a user reading the hook understands the surface area.
#
# Scope honesty: this wraps INDIVIDUAL commands invoked via `tirith-out
# <cmd>`. It does NOT intercept output from anything run outside the wrapper.
#
# def tirith-output-guard-wrap [...cmd] {
#     if ($cmd | length) == 0 {
#         print --stderr 'tirith-output-guard-wrap: usage: tirith-out <cmd> [args...]'
#         return 2
#     }
#     run-external $cmd.0 ...($cmd | skip 1) | tirith view --max-bytes 16777216 -
# }
# alias tirith-out = tirith-output-guard-wrap
