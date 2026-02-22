if [[ -n "${ZSH_EXECUTION_STRING:-}" ]]; then
  # Skip guard if explicitly disabled
  if [[ "${TIRITH_ZSHENV_SKIP:-}" = "1" ]]; then
    return 0 2>/dev/null || true
  fi

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
