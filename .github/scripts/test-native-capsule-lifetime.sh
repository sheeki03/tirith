#!/usr/bin/env bash
# Run only in the isolated native Linux CI job, after building this checkout.
set -euo pipefail
umask 077
if [[ $# != 1 || $(uname -s) != Linux ]]; then
  echo 'usage: test-native-capsule-lifetime.sh BUILT_NATIVE_TIRITH (Linux)' >&2
  exit 2
fi
if [[ $(id -u) == 0 ]]; then
  echo 'lifetime acceptance requires an unprivileged operator' >&2
  exit 2
fi
binary=$(realpath -- "$1")
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
cc -O2 -Wall -Wextra -Werror "$script_dir/native-capsule-cancellation.c" -o "$fixture/probe"
for scenario in before_exec parent_term parent_kill guard_kill; do
  run="$fixture/$scenario"
  mkdir -p "$run/project" "$run/home" "$run/config" "$run/data" "$run/state"
  printf 'protected original\n' > "$run/project/README.md"
  cp "$fixture/probe" "$run/project/cancel-probe"
  (
    cd "$run/project"
    HOME="$run/home" XDG_CONFIG_HOME="$run/config" XDG_DATA_HOME="$run/data" XDG_STATE_HOME="$run/state" \
      TIRITH_OFFLINE=1 TIRITH_LOG=0 "$fixture/probe" "$scenario" "$binary" "$run/project"
    test -z "$(find "$run/project" -name 'tirith-qualification-running-*.pid' -print -quit)"
    test "$(cat "$run/project/README.md")" = 'protected original'
  )
done
