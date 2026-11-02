# Tirith guard for non-interactive zsh command runs (`zsh -lc ...`).
# Skipped when:
#   - TIRITH_ZSHENV_SKIP=1 (explicit disable)
#   - VSCODE_RESOLVING_ENVIRONMENT is set (IDE shell env probe — not a
#     real command; the IDE strips this var from the resolved env so it
#     cannot be abused to bypass the guard for actual commands)
# Uses a single compound condition (no `return`) so later .zshenv lines
# always load — the IDE resolves the full environment (PATH, etc.).
if [[ -n "${ZSH_EXECUTION_STRING:-}" \
   && "${TIRITH_ZSHENV_SKIP:-}" != "1" \
   && -z "${VSCODE_RESOLVING_ENVIRONMENT:-}" ]]; then

  # Setup replaces the assignment below with a zsh-quoted absolute path.
  # Do not honor runtime path overrides: the guard must reach the exact
  # executable that setup verified, independent of an untrusted PATH/env.
  _tirith_bin=__TIRITH_BIN__

  if [[ ! -f "$_tirith_bin" || ! -x "$_tirith_bin" ]]; then
    builtin print -r -- "tirith: configured binary is unavailable — command blocked for safety" >&2
    exit 1
  fi

  # The legacy approval-check channel returns a private metadata file on stdout
  # and human findings on stderr. Keep the command in quoted argv: that channel
  # intentionally does not consume command text from stdin.
  _tirith_approval_output=$("$_tirith_bin" check --approval-check --non-interactive --shell posix -- "$ZSH_EXECUTION_STRING")
  _tirith_rc=$?
  _tirith_approval_file="${_tirith_approval_output%%$'\n'*}"
  _tirith_approval_required=""
  _tirith_approval_keys=0
  _tirith_approval_valid=0

  # Read the actual private regular file through a nonblocking, no-follow fd,
  # not a path that can turn into a symlink/FIFO between inspection and reading.
  builtin typeset -A _tirith_approval_stat
  if [[ "$_tirith_approval_file" == /*/tirith-approval-*.env ]] \
     && builtin zmodload -F zsh/system b:sysopen b:sysread 2>/dev/null \
     && builtin zmodload -F zsh/stat b:zstat 2>/dev/null \
     && builtin sysopen -r -o cloexec,nofollow,nonblock \
        -u _tirith_approval_fd "$_tirith_approval_file" 2>/dev/null; then
    if builtin zstat -H _tirith_approval_stat -f "$_tirith_approval_fd" 2>/dev/null \
       && [[ "${_tirith_approval_stat[uid]}" -eq "$EUID" \
          && "${_tirith_approval_stat[mode]}" -eq 33152 \
          && "${_tirith_approval_stat[nlink]}" -eq 1 \
          && "${_tirith_approval_stat[size]}" -gt 0 \
          && "${_tirith_approval_stat[size]}" -le 1024 ]] \
       && builtin sysread -i "$_tirith_approval_fd" -s 1025 \
          -c _tirith_approval_bytes _tirith_approval_content 2>/dev/null \
       && [[ $_tirith_approval_bytes -eq "${_tirith_approval_stat[size]}" ]]; then
      # 33152 is S_IFREG | 0600, the emitter's owner-only tempfile contract.
      # Metadata remains data: never source/eval descriptions or yes/no values.
      while IFS='=' builtin read -r _tirith_key _tirith_value; do
        if [[ "$_tirith_key" == "TIRITH_REQUIRES_APPROVAL" ]]; then
          _tirith_approval_keys=$((_tirith_approval_keys + 1))
          _tirith_approval_required="$_tirith_value"
        fi
      done <<< "$_tirith_approval_content"
      if [[ $_tirith_approval_keys -eq 1 \
         && ( "$_tirith_approval_required" == "yes" || "$_tirith_approval_required" == "no" ) \
         && "$_tirith_approval_output" == "$_tirith_approval_file" ]]; then
        _tirith_approval_valid=1
      fi
    fi
    builtin exec {_tirith_approval_fd}<&-
  fi

  # Clean both approval and optional strict-warning files with zsh's native
  # file builtin; a repository-controlled PATH must not select an rm helper.
  if builtin zmodload -F zsh/files b:zf_rm 2>/dev/null; then
    _tirith_metadata_files=0
    while IFS= builtin read -r _tirith_metadata_file; do
      _tirith_metadata_files=$((_tirith_metadata_files + 1))
      if [[ $_tirith_metadata_files -gt 2 ]]; then
        _tirith_approval_valid=0
        break
      fi
      if [[ "$_tirith_metadata_file" == /*/tirith-approval-*.env \
         || "$_tirith_metadata_file" == /*/tirith-warnack-*.env ]]; then
        if ! builtin zf_rm -f -- "$_tirith_metadata_file"; then
          builtin print -r -- "tirith: approval metadata cleanup failed — command blocked for safety" >&2
          exit 1
        fi
      fi
    done <<< "$_tirith_approval_output"
  else
    builtin print -r -- "tirith: native approval metadata cleanup unavailable — command blocked for safety" >&2
    exit 1
  fi

  if [[ $_tirith_rc -eq 1 ]]; then
    exit 1
  elif [[ $_tirith_rc -ne 0 && $_tirith_rc -ne 2 ]]; then
    builtin print -r -- "tirith: unexpected exit code $_tirith_rc — command blocked for safety" >&2
    exit 1
  elif [[ $_tirith_approval_valid -ne 1 ]]; then
    builtin print -r -- "tirith: invalid approval metadata — command blocked for safety" >&2
    exit 1
  elif [[ "$_tirith_approval_required" == "yes" ]]; then
    builtin print -r -- "tirith: command requires policy approval. Non-interactive zsh cannot request approval; ask your operator to review the command in an approval-capable Tirith integration." >&2
    exit 1
  fi

  builtin unset _tirith_bin _tirith_rc _tirith_approval_output _tirith_approval_file \
    _tirith_approval_required _tirith_approval_keys _tirith_approval_valid \
    _tirith_approval_stat _tirith_approval_fd _tirith_approval_bytes _tirith_approval_content \
    _tirith_key _tirith_value _tirith_metadata_file _tirith_metadata_files
fi
