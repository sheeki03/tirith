#!/bin/sh
# Regression test for scripts/install.sh install_package_approval_helper.
#
# The bug: several failure paths inside install_package_approval_helper called
# `err`, which does `exit 1`. The function is invoked as
#
#   if ! install_package_approval_helper "$archive" "$sha"; then
#     restore_package_approval_helper "$helper_backup" "$helper_had_previous" || true
#
# so the caller depends on getting a non-zero RETURN in order to put the
# previous helper back. Exiting from inside the function skipped that restore
# entirely and left the machine with neither the new helper nor the old one.
#
# The discriminator below is exact: the call runs in a subshell that prints a
# sentinel AFTER it. If the function exits, the subshell dies first and the
# sentinel never appears; if it returns, the sentinel carries the status.
#
# Every case here fails during argument validation, which happens before the
# first `run_root`, so nothing privileged is invoked on any runner.
#
# Plain POSIX sh; no bats/bash dependency. Works on Linux and macOS runners.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="$REPO_ROOT/scripts/install.sh"

if [ ! -f "$INSTALL_SH" ]; then
  echo "fatal: cannot locate install.sh at $INSTALL_SH" >&2
  exit 2
fi

work="$(mktemp -d 2>/dev/null || mktemp -d -t tirith-test)"
trap 'rm -rf "$work"' EXIT INT TERM

archive="$work/release.tar.gz"
: > "$archive"

# TIRITH_INSTALL_SH_LIB=1 sources install.sh as a library without running main.
TIRITH_INSTALL_SH_LIB=1 . "$INSTALL_SH"

failures=0

# Returns "rc=<status>" when the function RETURNS, and empty when it EXITS.
call_helper() {
  ( install_package_approval_helper "$archive" "$1" >/dev/null 2>&1
    printf 'rc=%s' "$?" ) || true
}

check_returns() {
  label="$1"
  sha="$2"
  observed="$(call_helper "$sha")"
  case "$observed" in
    "")
      echo "FAIL [$label]: helper exited the shell instead of returning;" >&2
      echo "      the caller's restore_package_approval_helper would be skipped" >&2
      failures=$((failures + 1))
      ;;
    rc=0)
      echo "FAIL [$label]: helper reported success for invalid input" >&2
      failures=$((failures + 1))
      ;;
    *)
      echo "ok [$label]: helper returned non-zero ($observed)"
      ;;
  esac
}

check_returns "empty sha256"       ""
check_returns "non-hex sha256"     "zzzz567890123456789012345678901234567890123456789012345678901234"
check_returns "uppercase sha256"   "ABCD567890123456789012345678901234567890123456789012345678901234"
check_returns "short sha256"       "abcd"
check_returns "long sha256"        "abcd5678901234567890123456789012345678901234567890123456789012345"

# The shell reaching this line at all is itself part of the assertion: a
# stray `exit` anywhere above would have killed the test run.
if [ "$failures" -ne 0 ]; then
  echo "$failures case(s) failed" >&2
  exit 1
fi

echo "all install_package_approval_helper return-path tests passed"
