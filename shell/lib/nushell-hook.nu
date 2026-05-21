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
                let result = (do { ^tirith check --non-interactive --interactive --shell posix -- $cmd } | complete)
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
