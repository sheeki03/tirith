# tirith fish hook
# Binds Enter to check commands before execution.

# Guard against double-loading
if set -q _TIRITH_FISH_LOADED
    return
end
set -g _TIRITH_FISH_LOADED 1

# Save original key bindings function BEFORE defining our new one
# This must happen before we define fish_user_key_bindings below,
# otherwise we'd copy our own function and cause infinite recursion.
if functions -q fish_user_key_bindings; and not functions -q _tirith_original_fish_user_key_bindings
    functions -c fish_user_key_bindings _tirith_original_fish_user_key_bindings
end

# Wrap fish_clipboard_paste to intercept all clipboard paste operations
# Covers: Ctrl+V, Ctrl+Y, and any custom bindings using fish_clipboard_paste
# NOTE: Terminal-level paste (right-click, middle-click) uses fish's internal
# __fish_paste and is NOT intercepted to avoid breakage on fish updates.
if functions -q fish_clipboard_paste; and not functions -q _tirith_original_fish_clipboard_paste
    functions -c fish_clipboard_paste _tirith_original_fish_clipboard_paste

    # Only define wrapper if we successfully copied the original
    function fish_clipboard_paste
        # Get clipboard content via original function
        # Use string collect to preserve newlines (set -l splits on newlines)
        set -l content (_tirith_original_fish_clipboard_paste | string collect)

        if test -z "$content"
            return
        end

        # Check with tirith paste, use temp file to prevent tty leakage
        set -l tmpfile (mktemp)
        echo -n "$content" | tirith paste --shell fish >$tmpfile 2>&1
        set -l rc $status
        set -l output (cat $tmpfile | string collect)
        rm -f $tmpfile

        if test $rc -eq 1
            # Blocked - show what was pasted, then warning
        printf '\npaste> %s\n%s\n' "$content" "$output" >/dev/tty
            return
        else if test $rc -eq 2
            # Warn - show warning, continue with paste
            if test -n "$output"
                printf '\n%s\n' "$output" >/dev/tty
            end
        end

        # Allowed - output the content for insertion
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

    if test $rc -eq 1
        # Block: show what was blocked, then warning, clear line
        printf '\ncommand> %s\n%s\n' "$cmd" "$output" >/dev/tty
        commandline -r ""
        commandline -f repaint
    else if test $rc -eq 2
        # Warn: show warning then execute
        printf '\ncommand> %s\n%s\n' "$cmd" "$output" >/dev/tty
        commandline -f execute
    else
        # Allow: execute normally
        commandline -f execute
    end
end

# Bind Enter for command check in modes that execute commands (supports vi keybindings)
# This is done immediately when sourced, not waiting for fish_user_key_bindings
function _tirith_bind_enter
    # Default/emacs mode
    bind \r _tirith_check_command
    bind \n _tirith_check_command
    # Vi insert mode
    bind -M insert \r _tirith_check_command 2>/dev/null
    bind -M insert \n _tirith_check_command 2>/dev/null
    # Vi default/normal mode - use -m insert to return to insert after execution
    bind -M default -m insert \r _tirith_check_command 2>/dev/null
    bind -M default -m insert \n _tirith_check_command 2>/dev/null
    # Vi replace mode - also executes commands (return to insert after execute)
    bind -M replace -m insert \r _tirith_check_command 2>/dev/null
    bind -M replace -m insert \n _tirith_check_command 2>/dev/null
end

# Bind immediately
_tirith_bind_enter

# Also hook into fish_user_key_bindings for any future rebinds
function fish_user_key_bindings
    # Call original user key bindings if they existed
    if functions -q _tirith_original_fish_user_key_bindings
        _tirith_original_fish_user_key_bindings
    end

    # Re-bind Enter after user's bindings
    _tirith_bind_enter
end
