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

# NOTE: Only intercepts Ctrl+V paste. Right-click and middle-click paste
# bypass this check — fish does not expose a hookable paste event.
function _tirith_check_paste
    # Read clipboard content
    set -l pasted (fish_clipboard_paste 2>/dev/null)

    if test -n "$pasted"
        # Check with tirith paste
        echo -n "$pasted" | tirith paste --shell fish
        set -l rc $status

        if test $rc -eq 1
            # Block: discard paste
            return
        end
    end

    # Allow: insert pasted content
    commandline -i -- "$pasted"
end

function fish_user_key_bindings
    # Call original user key bindings if they existed
    if functions -q _tirith_original_fish_user_key_bindings
        _tirith_original_fish_user_key_bindings
    end

    # Override Enter
    bind \r _tirith_check_command
    bind \n _tirith_check_command

    # Paste interception (Ctrl+V only)
    bind \cv _tirith_check_paste
end
