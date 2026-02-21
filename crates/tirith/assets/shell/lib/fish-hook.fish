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

# Session tracking: generate ID per shell session if not inherited
if not set -q TIRITH_SESSION_ID
    set -gx TIRITH_SESSION_ID (printf '%x-%x' %self (date +%s))
end

# Output helper: write to stderr by default (ADR-7).
# Override via TIRITH_OUTPUT=tty to write to /dev/tty instead.
function _tirith_output
    if test "$TIRITH_OUTPUT" = "tty"
        printf '%s\n' "$argv[1]" >/dev/tty
    else
        printf '%s\n' "$argv[1]" >&2
    end
end

# ─── Approval workflow helpers (ADR-7) ───

function _tirith_parse_approval
    set -g _tirith_ap_required "no"
    set -g _tirith_ap_timeout 0
    set -g _tirith_ap_fallback "block"
    set -g _tirith_ap_rule ""
    set -g _tirith_ap_desc ""

    if not test -r "$argv[1]"
        _tirith_output "tirith: warning: approval file missing or unreadable, failing closed"
        command rm -f "$argv[1]"  # ADR-7: delete on all paths
        set -g _tirith_ap_required "yes"
        set -g _tirith_ap_fallback "block"
        return 1
    end

    set -l valid_keys 0
    for line in (cat "$argv[1]")
        set -l parts (string split -m1 = "$line")
        if test (count $parts) -ge 2
            switch $parts[1]
                case TIRITH_REQUIRES_APPROVAL
                    set -g _tirith_ap_required $parts[2]
                    set valid_keys (math $valid_keys + 1)
                case TIRITH_APPROVAL_TIMEOUT
                    set -g _tirith_ap_timeout $parts[2]
                case TIRITH_APPROVAL_FALLBACK
                    set -g _tirith_ap_fallback $parts[2]
                case TIRITH_APPROVAL_RULE
                    set -g _tirith_ap_rule $parts[2]
                case TIRITH_APPROVAL_DESCRIPTION
                    set -g _tirith_ap_desc $parts[2]
            end
        end
    end

    command rm -f "$argv[1]"

    if test $valid_keys -eq 0
        _tirith_output "tirith: warning: approval file corrupt, failing closed"
        set -g _tirith_ap_required "yes"
        set -g _tirith_ap_fallback "block"
        return 1
    end
    return 0
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

    # Run tirith check with approval workflow (stdout=approval file path, stderr=human output)
    set -l errfile (mktemp)
    set -l approval_path (tirith check --approval-check --non-interactive --interactive --shell fish -- "$cmd" 2>$errfile)
    set -l rc $status
    set -l output (cat $errfile | string collect)
    rm -f $errfile

    if test $rc -eq 0
        # Allow: no output
    else if test $rc -eq 2
        _tirith_output ""
        _tirith_output "command> $cmd"
        if test -n "$output"
            _tirith_output "$output"
        end
    else if test $rc -eq 1
        _tirith_output ""
        _tirith_output "command> $cmd"
        if test -n "$output"
            _tirith_output "$output"
        end
    else
        # Unexpected rc: warn + execute (fail-open to avoid terminal breakage)
        _tirith_output ""
        if test -n "$output"
            _tirith_output "$output"
        end
        _tirith_output "tirith: unexpected exit code $rc — running unprotected"
        test -n "$approval_path"; and command rm -f "$approval_path"
        commandline -f execute
        return
    end

    # Approval workflow: runs for ALL exit codes (0, 1, 2).
    # For rc=1 (block), approval gives user a chance to override.
    if test -n "$approval_path"
        _tirith_parse_approval "$approval_path"
        if test "$_tirith_ap_required" = "yes"
            _tirith_output "tirith: approval required for $_tirith_ap_rule"
            if test -n "$_tirith_ap_desc"
                _tirith_output "  $_tirith_ap_desc"
            end
            set -l response ""
            if test "$_tirith_ap_timeout" -gt 0
                # Fish read has no timeout flag; delegate to bash read -t
                set -l timeout_s $_tirith_ap_timeout
                if command -q bash
                    set response (bash -c 'read -t '"$timeout_s"' -p "Approve? ('"$timeout_s"'s timeout) [y/N] " r </dev/tty 2>/dev/null && echo "$r" || echo ""')
                else
                    # Fallback: blocking read (no timeout support without bash)
                    read -P "Approve? [y/N] " response
                end
            else
                read -P "Approve? [y/N] " response
            end
            if string match -qi 'y*' -- "$response"
                # Approved: fall through to execute
            else
                switch $_tirith_ap_fallback
                    case allow
                        _tirith_output "tirith: approval not granted — fallback: allow"
                    case warn
                        _tirith_output "tirith: approval not granted — fallback: warn"
                    case '*'
                        _tirith_output "tirith: approval not granted — fallback: block"
                        commandline -r ""
                        return
                end
            end
        else if test $rc -eq 1
            # Approval not required but command was blocked: honor block
            commandline -r ""
            return
        end
    else if test $rc -eq 1
        # No approval file: honor block
        commandline -r ""
        return
    end

    commandline -f execute
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
