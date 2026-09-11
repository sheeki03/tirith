#!/usr/bin/env sh
# tirith shell hook loader
# Loads the appropriate hook based on the current shell.
# Usage: eval "$(tirith init)" or `. /path/to/tirith.sh`

_tirith_detect_shell() {
  if [ -n "${ZSH_VERSION:-}" ]; then
    echo "zsh"
  elif [ -n "${BASH_VERSION:-}" ]; then
    echo "bash"
  elif [ -n "${FISH_VERSION:-}" ]; then
    echo "fish"
  elif [ -n "${PSVersionTable:-}" ]; then
    echo "powershell"
  else
    echo "unknown"
  fi
}

_tirith_shell="$(_tirith_detect_shell)"

# This file is sourced: in Bash, $0 still identifies the caller, and zsh's
# FUNCTION_ARGZERO option can change it too. Locate the source itself, without
# invoking PATH helpers or allowing CDPATH to alter the captured directory.
case "$_tirith_shell" in
  bash) _tirith_source="${BASH_SOURCE[0]}" ;;
  zsh) _tirith_source="${(%):-%x}" ;;
  *) return 0 ;;
esac
case "$_tirith_source" in
  */*) _tirith_dir="${_tirith_source%/*}" ;;
  *) _tirith_dir="." ;;
esac
_tirith_dir="$(CDPATH= builtin cd -P -- "$_tirith_dir" && builtin pwd)" || return 1

case "$_tirith_shell" in
  zsh)
    . "${_tirith_dir}/lib/zsh-hook.zsh"
    ;;
  bash)
    . "${_tirith_dir}/lib/bash-hook.bash"
    ;;
  fish)
    # Fish sources differently; this path is for documentation.
    # Users should: source /path/to/shell/lib/fish-hook.fish
    echo "tirith: For fish, run: source ${_tirith_dir}/lib/fish-hook.fish" >&2
    ;;
  *)
    # Unknown shell or PowerShell (which uses .ps1 sourcing)
    ;;
esac

unset _tirith_dir _tirith_shell _tirith_source
