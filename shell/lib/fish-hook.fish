# tirith fish hook
# Binds Enter to check commands before execution.

# Guard against double-loading (session-local only).
# If inherited from environment (exported by attacker/parent), ignore it.
if set -q _TIRITH_FISH_LOADED
    if set -q -x _TIRITH_FISH_LOADED
        set -e _TIRITH_FISH_LOADED  # Inherited from env — ignore and load fresh
    else
        return  # Set in this session — genuine double-source guard
    end
end
set -g _TIRITH_FISH_LOADED 1

# Output helper: use stderr for Warp terminal (which doesn't display /dev/tty properly),
# otherwise use /dev/tty for proper terminal output that doesn't mix with command output.
# Allow override via TIRITH_OUTPUT=stderr for terminals that hide /dev/tty.
function _tirith_output
    if test "$TIRITH_OUTPUT" = "stderr"; or test "$TERM_PROGRAM" = "WarpTerminal"
        printf '%s\n' "$argv[1]" >&2
    else
        printf '%s\n' "$argv[1]" >/dev/tty
    end
end

# Save original key bindings function BEFORE defining our new one
if functions -q fish_user_key_bindings; and not functions -q _tirith_original_fish_user_key_bindings
    functions -c fish_user_key_bindings _tirith_original_fish_user_key_bindings
end

# Wrap fish_clipboard_paste to intercept clipboard paste operations
if functions -q fish_clipboard_paste; and not functions -q _tirith_original_fish_clipboard_paste
    functions -c fish_clipboard_paste _tirith_original_fish_clipboard_paste

    function fish_clipboard_paste
        set -l content (_tirith_original_fish_clipboard_paste | string collect)

        if test -z "$content"
            return
        end

        set -l tmpfile (mktemp)
        echo -n "$content" | tirith paste --shell fish >$tmpfile 2>&1
        set -l rc $status
        set -l output (cat $tmpfile | string collect)
        rm -f $tmpfile

        if test $rc -eq 0
            # Allow: fall through to echo
        else if test $rc -eq 2
            if test -n "$output"
                _tirith_output ""
                _tirith_output "$output"
                commandline -f repaint
            end
            # Warn: fall through to echo
        else
            # Block or unexpected: discard
            _tirith_output ""
            _tirith_output "paste> $content"
            if test -n "$output"
                _tirith_output "$output"
            end
            if test $rc -ne 1
                _tirith_output "tirith: unexpected exit code $rc — paste blocked for safety"
            end
            commandline -f repaint
            return
        end

        echo -n "$content"
    end
end

function _tirith_check_command
    set -l cmd (commandline)

    # Empty input: execute normally
    if test -z "$cmd"
        commandline -f execute
        return
    end

    # Run tirith check, use temp file to prevent tty leakage
    set -l tmpfile (mktemp)
    tirith check --non-interactive --shell fish -- "$cmd" >$tmpfile 2>&1
    set -l rc $status
    set -l output (cat $tmpfile | string collect)
    rm -f $tmpfile

    if test $rc -eq 0
        commandline -f execute
    else if test $rc -eq 2
        _tirith_output ""
        _tirith_output "command> $cmd"
        if test -n "$output"
            _tirith_output "$output"
        end
        commandline -f execute
    else if test $rc -eq 1
        # Block: tirith intentionally blocked
        _tirith_output ""
        _tirith_output "command> $cmd"
        if test -n "$output"
            _tirith_output "$output"
        end
        commandline -r ""
    else
        # Unexpected rc: warn + execute (fail-open to avoid terminal breakage)
        _tirith_output ""
        if test -n "$output"
            _tirith_output "$output"
        end
        _tirith_output "tirith: unexpected exit code $rc — running unprotected"
        commandline -f execute
    end
end

function _tirith_bind_enter
    # Default/emacs mode
    bind \r _tirith_check_command
    bind \n _tirith_check_command
    # Vi insert mode
    bind -M insert \r _tirith_check_command 2>/dev/null
    bind -M insert \n _tirith_check_command 2>/dev/null
    # Vi default/normal mode (no -m insert to avoid Ghostty input freeze)
    bind -M default \r _tirith_check_command 2>/dev/null
    bind -M default \n _tirith_check_command 2>/dev/null
    # Vi replace mode (no -m insert to avoid Ghostty input freeze)
    bind -M replace \r _tirith_check_command 2>/dev/null
    bind -M replace \n _tirith_check_command 2>/dev/null
end

# Bind immediately
_tirith_bind_enter

# Hook into fish_user_key_bindings for any future rebinds
function fish_user_key_bindings
    if functions -q _tirith_original_fish_user_key_bindings
        _tirith_original_fish_user_key_bindings
    end
    _tirith_bind_enter
end
