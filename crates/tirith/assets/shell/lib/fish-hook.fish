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

        # Check with tirith (stderr stays on stderr for warnings)
        echo -n "$content" | tirith paste --shell fish
        set -l rc $status

        if test $rc -eq 1
            # Blocked - return nothing (paste is suppressed)
            return
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

    # Run tirith check. Binary prints warnings/blocks directly to stderr.
    tirith check --interactive --shell fish -- "$cmd"
    set -l rc $status

    if test $rc -eq 1
        # Block: clear the line
        commandline -r ""
        commandline -f repaint
    else
        # Allow (0) or Warn (2): execute normally
        # Warn message already printed to stderr by the binary
        commandline -f execute
    end
end

function fish_user_key_bindings
    # Call original user key bindings if they existed
    if functions -q _tirith_original_fish_user_key_bindings
        _tirith_original_fish_user_key_bindings
    end

    # Override Enter for command check
    bind \r _tirith_check_command
    bind \n _tirith_check_command
end
