#!/usr/bin/env sh
# tirith shell hook loader
# Sources the appropriate hook based on the current shell.
# Usage: eval "$(tirith init)" or source this file directly.

_tirith_detect_shell() {
  if [ -n "$ZSH_VERSION" ]; then
    echo "zsh"
  elif [ -n "$BASH_VERSION" ]; then
    echo "bash"
  elif [ -n "$FISH_VERSION" ]; then
    echo "fish"
  elif [ -n "$PSVersionTable" ]; then
    echo "powershell"
  else
    echo "unknown"
  fi
}

_tirith_dir="$(cd "$(dirname "$0")" && pwd)"

_tirith_shell="$(_tirith_detect_shell)"

case "$_tirith_shell" in
  zsh)
    source "${_tirith_dir}/lib/zsh-hook.zsh"
    ;;
  bash)
    source "${_tirith_dir}/lib/bash-hook.bash"
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

unset _tirith_dir _tirith_shell
