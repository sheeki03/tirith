#!/bin/sh
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="$REPO_ROOT/scripts/install.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir -p "$work/fixture" "$work/payload"
printf '#!/bin/sh\nprintf "tirith fixture\\n"\n' > "$work/payload/tirith"
tar czf "$work/fixture/release.tar.gz" -C "$work/payload" tirith
(
  # shellcheck disable=SC1090
  TIRITH_INSTALL_SH_LIB=1 . "$INSTALL_SH"
  printf '%s  release.tar.gz\n' "$(sha256_file "$work/fixture/release.tar.gz")"
) > "$work/fixture/checksums.txt"

run_install_case() {
  CASE_DIR="$work/$1" FIXTURE_DIR="$work/fixture" INSTALL_SH="$INSTALL_SH" \
    FAIL_INSTALL="$2" sh -c '
    set -eu
    TIRITH_INSTALL_SH_LIB=1 . "$INSTALL_SH"
    mkdir -p "$CASE_DIR/bin"
    INSTALL_DIR="$CASE_DIR/bin"
    PAIRED_HELPER_DEST="$CASE_DIR/helper"
    TIRITH_INSTALL_APPROVAL_HELPER=0
    detect_platform() { TARGET=x86_64-unknown-linux-gnu; ARCHIVE=release.tar.gz; }
    resolve_version() { VERSION=v9.9.9; }
    resolve_latest_version() { :; }
    download_url() { printf "%s/%s\n" "$FIXTURE_DIR" "$1"; }
    fetch() { cp "$1" "$2"; }
    verify_cosign() { :; }
    run_root() { printf "unexpected elevation\n" > "$CASE_DIR/elevated"; return 1; }
    install_package_approval_helper() {
      printf "unexpected helper installation\n" > "$CASE_DIR/helper-attempted"
      return 1
    }
    if [ "$FAIL_INSTALL" = 1 ]; then
      printf "old-main\n" > "$INSTALL_DIR/tirith"
      install() {
        case "$3" in
          */tirith) return 1 ;;
          *) command install "$@" ;;
        esac
      }
    fi
    main
  '
}

run_install_case fresh 0 > "$work/fresh.log"
cmp "$work/payload/tirith" "$work/fresh/bin/tirith"
test ! -e "$work/fresh/elevated"
test ! -e "$work/fresh/helper-attempted"
grep -q 'Native package approval is unavailable' "$work/fresh.log"
if run_install_case failed 1 > "$work/failed.log" 2>&1; then
  echo 'failed installation unexpectedly succeeded' >&2
  exit 1
fi
test "$(cat "$work/failed/bin/tirith")" = old-main
test ! -e "$work/failed/elevated"
test ! -e "$work/failed/helper-attempted"

CASE_DIR="$work/selection" INSTALL_SH="$INSTALL_SH" sh -c '
  set -eu
  TIRITH_INSTALL_SH_LIB=1 . "$INSTALL_SH"
  mkdir -p "$CASE_DIR"
  PAIRED_HELPER_DEST="$CASE_DIR/helper"
  TARGET=x86_64-unknown-linux-gnu
  id() { printf "0\n"; }
  TIRITH_INSTALL_APPROVAL_HELPER=0
  select_package_approval_helper
  test "$PAIRED_HELPER_MANAGED" = 0
  TIRITH_INSTALL_APPROVAL_HELPER=1
  select_package_approval_helper
  test "$PAIRED_HELPER_MANAGED" = 1
  TIRITH_INSTALL_APPROVAL_HELPER=0
  for path in "$PAIRED_HELPER_DEST" "${PAIRED_HELPER_DEST}.tirith-previous" \
      "${PAIRED_HELPER_DEST}.tirith-previous.absent"; do
    touch "$path"
    select_package_approval_helper
    test "$PAIRED_HELPER_MANAGED" = 1
    rm "$path"
  done
  ln -s "$CASE_DIR/missing" "$PAIRED_HELPER_DEST"
  select_package_approval_helper
  test "$PAIRED_HELPER_MANAGED" = 1
  rm "$PAIRED_HELPER_DEST"
  TARGET=aarch64-unknown-linux-gnu
  select_package_approval_helper
  test "$PAIRED_HELPER_MANAGED" = 0
  if (TIRITH_INSTALL_APPROVAL_HELPER=1; select_package_approval_helper) 2>/dev/null; then
    exit 1
  fi
  if (TIRITH_INSTALL_APPROVAL_HELPER=yes; select_package_approval_helper) 2>/dev/null; then
    exit 1
  fi
'

if [ "$(id -u)" -ne 0 ]; then
  CASE_DIR="$work/inaccessible" INSTALL_SH="$INSTALL_SH" sh -c '
    set -eu
    TIRITH_INSTALL_SH_LIB=1 . "$INSTALL_SH"
    mkdir -p "$CASE_DIR/grandparent/parent"
    PAIRED_HELPER_DEST="$CASE_DIR/grandparent/parent/helper"
    touch "$PAIRED_HELPER_DEST"
    chmod 000 "$CASE_DIR/grandparent"
    trap '\''chmod 700 "$CASE_DIR/grandparent"'\'' EXIT HUP INT TERM
    package_approval_helper_state_present
    TARGET=x86_64-unknown-linux-gnu
    TIRITH_INSTALL_APPROVAL_HELPER=0
    id() { printf "0\n"; }
    select_package_approval_helper
    test "$PAIRED_HELPER_MANAGED" = 1
  '
fi

echo 'PASS: fresh installation and rollback avoid elevation; existing helper state remains paired'
