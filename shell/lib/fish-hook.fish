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

# M8 ch2 — surface "this shell is on the remote side of an SSH session" to
# `tirith prompt-status` (planned for M8 ch6) and any other downstream
# consumer. Set NOW so chunk 6 can read it without a follow-up hook patch.
# Standard SSH env vars: SSH_CONNECTION, SSH_CLIENT, SSH_TTY.
if not set -q TIRITH_SSH_REMOTE
    and begin
        set -q SSH_CONNECTION
        or set -q SSH_CLIENT
        or set -q SSH_TTY
    end
    set -gx TIRITH_SSH_REMOTE 1
end

# M9 ch4 — record a shell-start environment snapshot for `tirith env diff`.
# Exec a hidden tirith subcommand that reads ITS OWN inherited environment and
# writes ONLY variable names + an 8-char value-hash prefix (never raw values,
# never a recoverable hash) to <state-dir>/env_snapshot.json. The child
# inherits this shell's exported env, so no value crosses an argv boundary or a
# temp file. Interactive-only and backgrounded so it never blocks the prompt.
if status is-interactive
    command tirith env snapshot >/dev/null 2>&1 &
    disown 2>/dev/null
end

# Output helper: write to stderr by default.
# Override via TIRITH_OUTPUT=tty to write to /dev/tty instead.
function _tirith_output
    if test "$TIRITH_OUTPUT" = "tty"
        printf '%s\n' $argv >/dev/tty
    else
        printf '%s\n' $argv >&2
    end
end

function _tirith_escape_preview
    string escape -- $argv[1]
end


function _tirith_parse_approval
    set -g _tirith_ap_required "no"
    set -g _tirith_ap_timeout 0
    set -g _tirith_ap_fallback "block"
    set -g _tirith_ap_rule ""
    set -g _tirith_ap_desc ""

    if not test -r "$argv[1]"
        _tirith_output "tirith: warning: approval file missing or unreadable, failing closed"
        command rm -f "$argv[1]"  # delete on all paths
        set -g _tirith_ap_required "yes"
        set -g _tirith_ap_fallback "block"
        return 1
    end

    set -l valid_keys 0
    while read -l line
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
    end < "$argv[1]"

    command rm -f "$argv[1]"

    if test $valid_keys -eq 0
        _tirith_output "tirith: warning: approval file corrupt, failing closed"
        set -g _tirith_ap_required "yes"
        set -g _tirith_ap_fallback "block"
        return 1
    end
    return 0
end


function _tirith_parse_warn_ack
    set -g _tirith_wa_findings 0
    set -g _tirith_wa_max_severity ""

    if not test -r "$argv[1]"
        command rm -f "$argv[1]"
        return 1
    end

    while read -l line
        set -l parts (string split -m1 = "$line")
        if test (count $parts) -ge 2
            switch $parts[1]
                case TIRITH_WARN_ACK_FINDINGS
                    set -g _tirith_wa_findings $parts[2]
                case TIRITH_WARN_ACK_MAX_SEVERITY
                    set -g _tirith_wa_max_severity $parts[2]
            end
        end
    end < "$argv[1]"

    command rm -f "$argv[1]"
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
        echo -n "$content" | env _TIRITH_HOOK=1 tirith paste --shell fish --interactive >$tmpfile 2>&1
        set -l rc $status
        set -l output (string collect < $tmpfile)
        command rm -f $tmpfile

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
            set -l escaped_content (_tirith_escape_preview "$content")
            _tirith_output ""
            _tirith_output "paste> $escaped_content"
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

    # Run tirith check with approval workflow (stdout=approval file path, stderr=human output).
    # Redirect both stdout and stderr to temp files instead of using command substitution —
    # fish 4.0+ changed terminal mode handling for external commands in key bindings,
    # and command substitution (set -l x (cmd)) can hang in that context.
    set -l outfile (mktemp)
    set -l errfile (mktemp)
    env _TIRITH_HOOK=1 tirith check --approval-check --non-interactive --interactive --shell fish -- "$cmd" >$outfile 2>$errfile
    set -l rc $status
    # Read stdout lines: line 1 = approval path, line 2 = warn-ack path (exit code 3 only)
    set -l approval_path ""
    set -l warn_ack_path ""
    if test -s $outfile
        set -l _stdout_lines (string split \n < $outfile)
        if test (count $_stdout_lines) -ge 1
            set approval_path $_stdout_lines[1]
        end
        if test (count $_stdout_lines) -ge 2
            set warn_ack_path $_stdout_lines[2]
        end
    end
    set -l output ""
    if test -s $errfile
        set output (string collect < $errfile)
    end
    command rm -f $outfile $errfile

    if test $rc -eq 0
        # Allow: no output
    else if test $rc -eq 2; or test $rc -eq 3
        set -l escaped_cmd (_tirith_escape_preview "$cmd")
        _tirith_output ""
        _tirith_output "command> $escaped_cmd"
        if test -n "$output"
            _tirith_output "$output"
        end
    else if test $rc -eq 1
        set -l escaped_cmd (_tirith_escape_preview "$cmd")
        _tirith_output ""
        _tirith_output "command> $escaped_cmd"
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
        test -n "$warn_ack_path"; and command rm -f "$warn_ack_path"
        commandline -f execute
        return
    end

    # Approval workflow: runs for ALL exit codes (0, 1, 2, 3).
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
                        test -n "$warn_ack_path"; and command rm -f "$warn_ack_path"
                        commandline -r ""
                        commandline -f repaint
                        return 1
                end
            end
        else if test $rc -eq 1
            # Approval not required but command was blocked: honor block
            test -n "$warn_ack_path"; and command rm -f "$warn_ack_path"
            commandline -r ""
            commandline -f repaint
            return 1
        end
    else if test $rc -eq 1
        # No approval file: honor block
        commandline -r ""
        commandline -f repaint
        return 1
    end

    # Warn-ack workflow (exit code 3): strict_warn requires explicit acknowledgement
    if test $rc -eq 3; and test -n "$warn_ack_path"
        _tirith_parse_warn_ack "$warn_ack_path"
        set -l response ""
        read -P "tirith: proceed with $_tirith_wa_findings warning(s)? [y/N] " response
        if string match -qi 'y*' -- "$response"
            # Acknowledged: fall through to execute
        else
            _tirith_output "tirith: warnings not acknowledged — command blocked"
            commandline -r ""
            commandline -f repaint
            return 1
        end
    else if test -n "$warn_ack_path"
        command rm -f "$warn_ack_path"
    end

    commandline -f execute
end

function _tirith_bind_enter
    # Default/emacs mode — bind both the legacy escape codes (\r/\n) and
    # the symbolic 'enter' name so the hook fires regardless of whether
    # the terminal uses the kitty keyboard protocol (fish 4.0+).
    bind \r _tirith_check_command
    bind \n _tirith_check_command
    bind enter _tirith_check_command 2>/dev/null  # fish 4.0+ symbolic name
    # Vi insert mode
    bind -M insert \r _tirith_check_command 2>/dev/null
    bind -M insert \n _tirith_check_command 2>/dev/null
    bind -M insert enter _tirith_check_command 2>/dev/null
    # Vi default/normal mode (no -m insert to avoid Ghostty input freeze)
    bind -M default \r _tirith_check_command 2>/dev/null
    bind -M default \n _tirith_check_command 2>/dev/null
    bind -M default enter _tirith_check_command 2>/dev/null
    # Vi replace mode (no -m insert to avoid Ghostty input freeze)
    bind -M replace \r _tirith_check_command 2>/dev/null
    bind -M replace \n _tirith_check_command 2>/dev/null
    bind -M replace enter _tirith_check_command 2>/dev/null
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

# TIRITH_STATUS: a small public contract a user can reference in their prompt
# (fish_prompt / fish_right_prompt) to surface tirith's live protection level
# (see docs/prompt-status.md). tirith prints NOTHING per-prompt — it only sets
# the variable; wiring it into a prompt is opt-in. The fish hook binds Enter to
# a check that can discard a blocked command, so its protection level is always
# `blocks`; fish has no runtime-degrade path. Interactive-only, so a
# non-interactive `source` (a script, `fish -c`) sets no status var —
# conformance invariant (g).
#
# `set -g` (global) and deliberately NOT `set -gx` (global + exported): the
# prompt runs in THIS interactive shell, which reads a global variable fine,
# and a non-interactive child process has no tirith protection — so it must not
# inherit a status that would misrepresent it.
if status is-interactive
    set -g TIRITH_STATUS blocks
end

# ── tirith output wrap (M7 ch1) ─────────────────────────────────────────────
# Opt-in output-direction wrapper. Commented out by default in this embedded
# hook copy; `tirith output wrap on` writes an active copy of the function
# into the user's shell-profile separately. This block is kept here as the
# canonical source so a user reading the hook understands the surface area.
#
# Scope honesty: this wraps INDIVIDUAL commands invoked via `tirith-out
# <cmd>`. It does NOT intercept output from anything run outside the wrapper.
#
# function tirith-output-guard-wrap
#     if test (count $argv) -eq 0
#         echo 'tirith-output-guard-wrap: usage: tirith-out <cmd> [args...]' >&2
#         return 2
#     end
#     $argv 2>&1 | tirith view --max-bytes 16777216 -
# end
# alias tirith-out 'tirith-output-guard-wrap'
