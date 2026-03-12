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

  # __TIRITH_BIN__ is replaced at setup time by resolve_tirith_bin()
  _tirith_bin="${TIRITH_BIN:-__TIRITH_BIN__}"

  if [[ ! -x "$(command -v "$_tirith_bin" 2>/dev/null)" ]]; then
    echo "tirith: $_tirith_bin not found — command blocked for safety" >&2
    exit 1
  fi

  _tirith_tmp=$(mktemp 2>/dev/null) || {
    echo "tirith: could not create temp file — command blocked for safety" >&2
    exit 1
  }

  "$_tirith_bin" check --non-interactive --shell posix -- "$ZSH_EXECUTION_STRING" >"$_tirith_tmp" 2>&1
  _tirith_rc=$?

  if [[ $_tirith_rc -eq 0 ]]; then
    rm -f "$_tirith_tmp"
  elif [[ $_tirith_rc -eq 1 ]]; then
    cat "$_tirith_tmp" >&2
    rm -f "$_tirith_tmp"
    exit 1
  elif [[ $_tirith_rc -eq 2 ]]; then
    cat "$_tirith_tmp" >&2
    rm -f "$_tirith_tmp"
  else
    cat "$_tirith_tmp" >&2
    echo "tirith: unexpected exit code $_tirith_rc" >&2
    rm -f "$_tirith_tmp"
    exit 1
  fi

  unset _tirith_bin _tirith_tmp _tirith_rc
fi
