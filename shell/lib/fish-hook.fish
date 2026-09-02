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
    set -gx TIRITH_SESSION_ID (builtin printf '%x-%x-%x-%x' \
        "$fish_pid" (builtin random) (builtin random) (builtin random))
end

# Pin the executable before any repository command can mutate PATH. Refuse an
# interactive hook when fish cannot resolve an absolute executable path.
set -g _TIRITH_BIN (command -s tirith 2>/dev/null)
if not string match -q '/*' -- "$_TIRITH_BIN"; or not test -x "$_TIRITH_BIN"
    if status is-interactive
        printf '%s\n' 'tirith: executable not found; fish hooks disabled' >&2
        set -g TIRITH_STATUS off
        return
    end
    set -g _TIRITH_BIN tirith
end

# Protocol-v3 callbacks run after arbitrary commands may have changed PATH.
# Pin every external helper they use to a fixed system location now, and only
# advertise receipt support when the complete helper set is available.
set -g _TIRITH_MKTEMP_BIN ""
if test -f /usr/bin/mktemp; and test -x /usr/bin/mktemp
    set -g _TIRITH_MKTEMP_BIN /usr/bin/mktemp
else if test -f /bin/mktemp; and test -x /bin/mktemp
    set -g _TIRITH_MKTEMP_BIN /bin/mktemp
end
set -g _TIRITH_RM_BIN ""
if test -f /bin/rm; and test -x /bin/rm
    set -g _TIRITH_RM_BIN /bin/rm
else if test -f /usr/bin/rm; and test -x /usr/bin/rm
    set -g _TIRITH_RM_BIN /usr/bin/rm
end
set -g _TIRITH_WC_BIN ""
if test -f /usr/bin/wc; and test -x /usr/bin/wc
    set -g _TIRITH_WC_BIN /usr/bin/wc
else if test -f /bin/wc; and test -x /bin/wc
    set -g _TIRITH_WC_BIN /bin/wc
end
set -g _TIRITH_ENV_BIN ""
if test -f /usr/bin/env; and test -x /usr/bin/env
    set -g _TIRITH_ENV_BIN /usr/bin/env
else if test -f /bin/env; and test -x /bin/env
    set -g _TIRITH_ENV_BIN /bin/env
end
set -g _TIRITH_SH_BIN ""
if test -f /bin/sh; and test -x /bin/sh
    set -g _TIRITH_SH_BIN /bin/sh
else if test -f /usr/bin/sh; and test -x /usr/bin/sh
    set -g _TIRITH_SH_BIN /usr/bin/sh
end
set -g _TIRITH_BASH_TIMEOUT_BIN ""
if test -f /bin/bash; and test -x /bin/bash
    set -g _TIRITH_BASH_TIMEOUT_BIN /bin/bash
else if test -f /usr/bin/bash; and test -x /usr/bin/bash
    set -g _TIRITH_BASH_TIMEOUT_BIN /usr/bin/bash
end
set -g _TIRITH_V3_HELPERS_READY 1
for helper in "$_TIRITH_MKTEMP_BIN" "$_TIRITH_RM_BIN" "$_TIRITH_WC_BIN" \
        "$_TIRITH_ENV_BIN" "$_TIRITH_SH_BIN"
    if not string match -q '/*' -- "$helper"; or not test -f "$helper"; or not test -x "$helper"
        set -g _TIRITH_V3_HELPERS_READY 0
    end
end

# Receipt protocol state. Registration itself happens further down, after the
# capture-file helpers are defined.
set -g _TIRITH_RECEIPT_PROTOCOL 0
set -g _TIRITH_RECEIPT_INSTANCE ""
set -g _TIRITH_RECEIPT_REGISTER_ERROR ""
set -g _TIRITH_RECEIPT_SHELL_PID "$fish_pid"
set -g _TIRITH_RECEIPT_FAMILY fish

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
    command "$_TIRITH_BIN" env snapshot >/dev/null 2>&1 &
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

function _tirith_receipt_consume_at
    set -l token "$argv[1]"
    set -l command_text "$argv[2]"
    set -l original_cwd "$argv[3]"
    test $_TIRITH_V3_HELPERS_READY -eq 1; or return 1
    test -n "$token"; and test -n "$original_cwd"; or return 1
    builtin printf '%s\n%s' "$token" "$command_text" | command "$_TIRITH_ENV_BIN" \
        _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
        _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
        _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
        _TIRITH_RECEIPT_CWD="$original_cwd" \
        _TIRITH_BIN="$_TIRITH_BIN" \
        "$_TIRITH_SH_BIN" -c 'cd "$_TIRITH_RECEIPT_CWD" 2>/dev/null || exit 1; exec "$_TIRITH_BIN" __execution-receipt consume --channel fish' \
        >/dev/null
end

function _tirith_receipt_reconcile_at
    set -l token "$argv[1]"
    set -l original_cwd "$argv[2]"
    test $_TIRITH_V3_HELPERS_READY -eq 1; or return 1
    test -n "$token"; and test -n "$original_cwd"; or return 1
    builtin printf '%s' "$token" | command "$_TIRITH_ENV_BIN" \
        _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
        _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
        _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
        _TIRITH_RECEIPT_CWD="$original_cwd" \
        _TIRITH_BIN="$_TIRITH_BIN" \
        "$_TIRITH_SH_BIN" -c 'cd "$_TIRITH_RECEIPT_CWD" 2>/dev/null || exit 1; exec "$_TIRITH_BIN" __execution-receipt reconcile --channel fish' \
        >/dev/null 2>&1
end

function _tirith_receipt_discard_at
    set -l token "$argv[1]"
    set -l original_cwd "$argv[2]"
    test $_TIRITH_V3_HELPERS_READY -eq 1; or return 1
    test -n "$token"; and test -n "$original_cwd"; or return 1
    builtin printf '%s' "$token" | command "$_TIRITH_ENV_BIN" \
        _TIRITH_RECEIPT_INSTANCE="$_TIRITH_RECEIPT_INSTANCE" \
        _TIRITH_RECEIPT_SHELL_PID="$_TIRITH_RECEIPT_SHELL_PID" \
        _TIRITH_RECEIPT_FAMILY="$_TIRITH_RECEIPT_FAMILY" \
        _TIRITH_RECEIPT_CWD="$original_cwd" \
        _TIRITH_BIN="$_TIRITH_BIN" \
        "$_TIRITH_SH_BIN" -c 'cd "$_TIRITH_RECEIPT_CWD" 2>/dev/null || exit 1; exec "$_TIRITH_BIN" __execution-receipt discard --channel fish' \
        >/dev/null 2>&1
end

function _tirith_unresolved_receipt_cleanup
    set -l token "$_TIRITH_UNRESOLVED_RECEIPT"
    set -l original_cwd "$_TIRITH_UNRESOLVED_RECEIPT_CWD"
    test -n "$token"; or return 0
    if _tirith_receipt_reconcile_at "$token" "$original_cwd"
        or _tirith_receipt_discard_at "$token" "$original_cwd"
        set -e _TIRITH_UNRESOLVED_RECEIPT _TIRITH_UNRESOLVED_RECEIPT_CWD
        return 0
    end
    return 1
end

function _tirith_receipt_discard_or_retain
    set -l token "$argv[1]"
    set -l original_cwd "$argv[2]"
    test -n "$token"; and test -n "$original_cwd"; or return 1
    if _tirith_receipt_discard_at "$token" "$original_cwd"
        return 0
    end
    if not set -q _TIRITH_UNRESOLVED_RECEIPT; or test -z "$_TIRITH_UNRESOLVED_RECEIPT"
        set -g _TIRITH_UNRESOLVED_RECEIPT "$token"
        set -g _TIRITH_UNRESOLVED_RECEIPT_CWD "$original_cwd"
    end
    return 1
end

function _tirith_v3_new_capture_file
    if not string match -q '/*' -- "$_TIRITH_MKTEMP_BIN"; or \
            not string match -q '/*' -- "$_TIRITH_RM_BIN"
        return 1
    end
    set -l file (umask 077; command "$_TIRITH_MKTEMP_BIN")
    set -l create_status $status
    if test $create_status -ne 0; or test -z "$file"; or not test -f "$file"; or test -L "$file"; or not test -O "$file"
        if test -n "$file"
            command "$_TIRITH_RM_BIN" -f -- "$file" 2>/dev/null
        end
        return 1
    end
    builtin printf '%s\n' "$file"
end

function _tirith_v3_remove_capture_files
    if not string match -q '/*' -- "$_TIRITH_RM_BIN"; or test (count $argv) -eq 0
        return 1
    end
    command "$_TIRITH_RM_BIN" -f -- $argv
end

function _tirith_v3_cleanup_registration_files
    for file in $argv
        if test -n "$file"
            _tirith_v3_remove_capture_files "$file" >/dev/null 2>&1
        end
    end
    return 0
end

# Protocol-v3 registration. The Rust side binds the receipt capability to its
# immediate parent pid, so tirith must run as a direct child of this shell.
# Register with a plain redirected foreground command rather than a command
# substitution, matching the bash and zsh hooks, and keep the failure reason
# for the status warning below instead of discarding it.
if status is-interactive
    and test $_TIRITH_V3_HELPERS_READY -eq 1
    and test (command "$_TIRITH_BIN" __execution-receipt capability 2>/dev/null) = "TIRITH_EXECUTION_RECEIPT_PROTOCOL=3"
    set -l register_out (_tirith_v3_new_capture_file)
    set -l out_status $status
    set -l register_err (_tirith_v3_new_capture_file)
    set -l err_status $status
    if test $out_status -eq 0; and test $err_status -eq 0
        and test -n "$register_out"; and test -n "$register_err"
        command "$_TIRITH_BIN" __execution-receipt register \
            --family fish --shell-pid "$_TIRITH_RECEIPT_SHELL_PID" \
            >"$register_out" 2>"$register_err"
        read -g _TIRITH_RECEIPT_INSTANCE <"$register_out"
        if string match -rq '^[0-9a-f]{64}$' -- "$_TIRITH_RECEIPT_INSTANCE"
            set -g _TIRITH_RECEIPT_PROTOCOL 3
        else
            set -g _TIRITH_RECEIPT_INSTANCE ""
            read -g _TIRITH_RECEIPT_REGISTER_ERROR <"$register_err"
        end
        _tirith_v3_cleanup_registration_files "$register_out" "$register_err"
    else
        _tirith_v3_cleanup_registration_files "$register_out" "$register_err"
    end
end

function _tirith_receipt_exit --on-event fish_exit
    _tirith_unresolved_receipt_cleanup
end


function _tirith_parse_approval
    set -g _tirith_ap_required "no"
    set -g _tirith_ap_timeout 0
    set -g _tirith_ap_fallback "block"
    set -g _tirith_ap_rule ""
    set -g _tirith_ap_desc ""

    if not test -r "$argv[1]"
        _tirith_output "tirith: warning: approval file missing or unreadable, failing closed"
        _tirith_v3_remove_capture_files "$argv[1]" >/dev/null 2>&1  # delete on all paths
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

    _tirith_v3_remove_capture_files "$argv[1]" >/dev/null 2>&1

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
        _tirith_v3_remove_capture_files "$argv[1]" >/dev/null 2>&1
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

    _tirith_v3_remove_capture_files "$argv[1]" >/dev/null 2>&1
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

        set -l tmpfile (_tirith_v3_new_capture_file)
        set -l capture_status $status
        if test $capture_status -ne 0
            _tirith_output "tirith: secure paste capture unavailable; paste blocked for safety"
            commandline -f repaint
            return
        end
        set -lx _TIRITH_HOOK 1
        builtin printf '%s' "$content" \
            | command "$_TIRITH_BIN" paste --shell fish --interactive >$tmpfile 2>&1
        set -l rc $status
        set -l output (string collect < $tmpfile)
        if not _tirith_v3_remove_capture_files "$tmpfile" >/dev/null 2>&1
            _tirith_output "tirith: secure paste capture cleanup failed; paste blocked for safety"
            commandline -f repaint
            return
        end

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

        builtin printf '%s' "$content"
    end
end

function _tirith_check_command
    set -l cmd (commandline)

    # Never create or deliver a second receipt while recovery of an older one is
    # unresolved. Reconciliation/discard runs in the original working directory.
    if test $_TIRITH_RECEIPT_PROTOCOL -eq 3; and not _tirith_unresolved_receipt_cleanup
        _tirith_output "tirith: execution receipt remains unresolved; command not accepted"
        commandline -f repaint
        return 1
    end

    # Empty input: execute normally
    if test -z "$cmd"
        commandline -f execute
        return
    end

    # Run tirith check with approval workflow (stdout=approval file path, stderr=human output).
    # Redirect both stdout and stderr to temp files instead of using command substitution —
    # fish 4.0+ changed terminal mode handling for external commands in key bindings,
    # and command substitution (set -l x (cmd)) can hang in that context.
    set -l outfile ""
    set -l errfile ""
    if test $_TIRITH_RECEIPT_PROTOCOL -eq 3
        set outfile (_tirith_v3_new_capture_file)
        set -l outfile_status $status
        set -l errfile_status 1
        if test $outfile_status -eq 0
            set errfile (_tirith_v3_new_capture_file)
            set errfile_status $status
        end
        if test $outfile_status -ne 0; or test $errfile_status -ne 0
            if test -n "$outfile"
                _tirith_v3_remove_capture_files "$outfile" >/dev/null 2>&1
            end
            _tirith_output "tirith: secure execution-receipt capture unavailable; command blocked"
            commandline -r ""
            commandline -f repaint
            return 1
        end
        set -lx _TIRITH_HOOK 1
        set -lx _TIRITH_RECEIPT_INSTANCE "$_TIRITH_RECEIPT_INSTANCE"
        set -lx _TIRITH_RECEIPT_SHELL_PID "$_TIRITH_RECEIPT_SHELL_PID"
        set -lx _TIRITH_RECEIPT_FAMILY "$_TIRITH_RECEIPT_FAMILY"
        command "$_TIRITH_BIN" check --approval-check --non-interactive --interactive --shell fish \
            --execution-receipt fish -- "$cmd" >$outfile 2>$errfile
    else
        set outfile (_tirith_v3_new_capture_file)
        set -l outfile_status $status
        set -l errfile_status 1
        if test $outfile_status -eq 0
            set errfile (_tirith_v3_new_capture_file)
            set errfile_status $status
        end
        if test $outfile_status -ne 0; or test $errfile_status -ne 0
            if test -n "$outfile"
                _tirith_v3_remove_capture_files "$outfile" >/dev/null 2>&1
            end
            _tirith_output "tirith: secure preflight capture unavailable; command blocked"
            commandline -r ""
            commandline -f repaint
            return 1
        end
        set -lx _TIRITH_HOOK 1
        command "$_TIRITH_BIN" check --approval-check --non-interactive --interactive --shell fish \
            -- "$cmd" >$outfile 2>$errfile
    end
    set -l rc $status

    if test $_TIRITH_RECEIPT_PROTOCOL -eq 3
        set -l output ""
        if test -s "$errfile"
            set output (string collect < "$errfile")
        end

        set -l receipt_prefix "TIRITH_EXECUTION_RECEIPT="
        set -l receipt_line ""
        set -l receipt_token ""
        set -l receipt_cwd "$PWD"
        set -l stdout_bytes (command "$_TIRITH_WC_BIN" -c < "$outfile" 2>/dev/null | string trim)
        set -l stdout_lines (command "$_TIRITH_WC_BIN" -l < "$outfile" 2>/dev/null | string trim)
        set -l first_line_status 1
        set -l frame_valid 0
        read receipt_line < "$outfile"
        set first_line_status $status

        if string match -q "$receipt_prefix*" -- "$receipt_line"
            set -l candidate_token (string replace "$receipt_prefix" "" -- "$receipt_line")
            if string match -rq '^[0-9a-f]{64}$' -- "$candidate_token"
                set receipt_token "$candidate_token"
            end
        end

        if test $rc -eq 0; or test $rc -eq 2
            if test $first_line_status -eq 0
                and test "$stdout_bytes" = 90
                and test "$stdout_lines" = 1
                and string match -rq '^TIRITH_EXECUTION_RECEIPT=[0-9a-f]{64}$' -- "$receipt_line"
                set frame_valid 1
            end
        end

        if test $frame_valid -eq 1
            if not _tirith_v3_remove_capture_files "$outfile" "$errfile"
                _tirith_receipt_discard_or_retain "$receipt_token" "$receipt_cwd" >/dev/null 2>&1
                _tirith_output "tirith: execution-receipt capture cleanup failed; command blocked"
                commandline -f repaint
                return 1
            end
            set -l precommit_cmd (commandline | string collect)
            if test "$precommit_cmd" != "$cmd"
                _tirith_receipt_discard_or_retain "$receipt_token" "$receipt_cwd" >/dev/null 2>&1
                _tirith_output "tirith: command changed before receipt commit; command not executed — press Enter for a fresh check"
                commandline -f repaint
                return 1
            end
            if not _tirith_receipt_consume_at "$receipt_token" "$cmd" "$receipt_cwd"
                if _tirith_receipt_reconcile_at "$receipt_token" "$receipt_cwd"
                    _tirith_output "tirith: receipt recovery completed but cannot authorize replay; command not executed — press Enter for a fresh check"
                else
                    _tirith_receipt_discard_or_retain "$receipt_token" "$receipt_cwd" >/dev/null 2>&1
                    _tirith_output "tirith: execution receipt could not be committed; command not executed — press Enter for a fresh check"
                end
                commandline -f repaint
                return 1
            end
            if test $rc -eq 2
                set -l v3_escaped_cmd (_tirith_escape_preview "$cmd")
                _tirith_output ""
                _tirith_output "command> $v3_escaped_cmd"
                if test -n "$output"
                    _tirith_output "$output"
                end
            end
            set -l postcommit_cmd (commandline | string collect)
            if test "$postcommit_cmd" != "$cmd"
                _tirith_output "tirith: command changed after receipt commit; command not executed with conservative unresolved line-acceptance evidence"
                commandline -f repaint
                return 1
            end
            commandline -f execute
            return
        end

        if test $rc -eq 1; and test "$stdout_bytes" = 0
            _tirith_v3_remove_capture_files "$outfile" "$errfile" >/dev/null 2>&1
            set -l v3_blocked_cmd (_tirith_escape_preview "$cmd")
            _tirith_output ""
            _tirith_output "command> $v3_blocked_cmd"
            if test -n "$output"
                _tirith_output "$output"
            end
            commandline -r ""
            commandline -f repaint
            return 1
        end

        # Any other status/stdout pairing is a malformed v3 frame. If its first
        # line contains a syntactically valid token, retire it before blocking.
        if test -n "$receipt_token"
            _tirith_receipt_discard_or_retain "$receipt_token" "$receipt_cwd" >/dev/null 2>&1
        end
        _tirith_v3_remove_capture_files "$outfile" "$errfile" >/dev/null 2>&1
        set -l v3_malformed_cmd (_tirith_escape_preview "$cmd")
        _tirith_output ""
        _tirith_output "command> $v3_malformed_cmd"
        if test -n "$output"
            _tirith_output "$output"
        end
        _tirith_output "tirith: invalid execution-receipt response; command blocked"
        commandline -r ""
        commandline -f repaint
        return 1
    end

    # Legacy protocol-off behavior: stdout carries approval metadata paths, and
    # the shell owns the historical prompt/fallback workflow below.
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
    if not _tirith_v3_remove_capture_files "$outfile" "$errfile" >/dev/null 2>&1
        _tirith_output "tirith: secure preflight capture cleanup failed; command blocked"
        commandline -r ""
        commandline -f repaint
        return 1
    end

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
        test -n "$approval_path"; and _tirith_v3_remove_capture_files "$approval_path" >/dev/null 2>&1
        test -n "$warn_ack_path"; and _tirith_v3_remove_capture_files "$warn_ack_path" >/dev/null 2>&1
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
                # Fish read has no timeout flag; delegate to a pinned system Bash.
                set -l timeout_s $_tirith_ap_timeout
                if test -n "$_TIRITH_BASH_TIMEOUT_BIN"
                    set response (command "$_TIRITH_BASH_TIMEOUT_BIN" -c \
                        'read -r -t "$1" -p "Approve? (${1}s timeout) [y/N] " response </dev/tty 2>/dev/null && printf "%s\n" "$response" || :' \
                        tirith-approval "$timeout_s")
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
                        test -n "$warn_ack_path"; and _tirith_v3_remove_capture_files "$warn_ack_path" >/dev/null 2>&1
                        commandline -r ""
                        commandline -f repaint
                        return 1
                end
            end
        else if test $rc -eq 1
            # Approval not required but command was blocked: honor block
            test -n "$warn_ack_path"; and _tirith_v3_remove_capture_files "$warn_ack_path" >/dev/null 2>&1
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
        _tirith_v3_remove_capture_files "$warn_ack_path" >/dev/null 2>&1
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
    if test $_TIRITH_RECEIPT_PROTOCOL -eq 3
        set -g TIRITH_STATUS blocks
    else
        set -g TIRITH_STATUS degraded
        _tirith_output "tirith: execution receipts unavailable; shell protection is running in legacy mode"
        if test -n "$_TIRITH_RECEIPT_REGISTER_ERROR"
            _tirith_output "$_TIRITH_RECEIPT_REGISTER_ERROR"
        end
    end
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
