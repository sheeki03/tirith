# tirith nushell hook
# LIMITATION: Cannot block execution — warn-only mode
# Add to config.nu:  source ~/.local/share/tirith/shell/lib/nushell-hook.nu

# Guard against double-loading
if not ('_TIRITH_NU_LOADED' in $env) {
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
