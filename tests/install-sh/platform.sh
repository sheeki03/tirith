#!/bin/sh
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="$REPO_ROOT/scripts/install.sh"

check_platform() {
  result="$(INSTALL_SH="$INSTALL_SH" CASE_OS="$1" CASE_ARCH="$2" \
    CASE_GLIBC="$3" CASE_LDD="$4" CASE_LONG_BIT="${6:-64}" sh -c '
    set -eu
    TIRITH_INSTALL_SH_LIB=1 . "$INSTALL_SH"
    uname() { case "$1" in -s) printf "%s\n" "$CASE_OS" ;; -m) printf "%s\n" "$CASE_ARCH" ;; esac; }
    getconf() {
      case "$1" in
        GNU_LIBC_VERSION) [ "$CASE_GLIBC" != unavailable ] || return 1; printf "%s\n" "$CASE_GLIBC" ;;
        LONG_BIT) printf "%s\n" "$CASE_LONG_BIT" ;;
        *) return 1 ;;
      esac
    }
    ldd() { printf "%s\n" "$CASE_LDD" >&2; return 1; }
    fetch() { echo "unexpected download" >&2; exit 99; }
    run_root() { echo "unexpected elevation" >&2; exit 99; }
    detect_platform
    printf "%s\n" "$TARGET"
  ' 2>&1)" && status=0 || status=$?
  if [ "$5" = refused ]; then
    test "$status" -eq 1
    case "$result" in *"cargo install tirith"*) ;; *) printf "%s\n" "$result" >&2; exit 1 ;; esac
    case "$result" in *"no administrator privileges"*) ;; *) exit 1 ;; esac
    case "$result" in *"unexpected download"*|*"unexpected elevation"*) exit 1 ;; esac
  else
    test "$status" -eq 0
    test "$result" = "$5"
  fi
}

check_platform Linux x86_64 'glibc 2.28' unused x86_64-unknown-linux-gnu
check_platform Linux aarch64 'glibc 2.39' unused aarch64-unknown-linux-gnu
check_platform Linux x86_64 'glibc 2.28' unused refused 32
check_platform Linux aarch64 'glibc 2.39' unused refused 32
check_platform Linux x86_64 'glibc 2.28' unused refused unknown
check_platform Linux aarch64 unavailable 'musl libc (aarch64)' aarch64-unknown-linux-musl
check_platform Linux arm64 unavailable 'musl libc (aarch64)' aarch64-unknown-linux-musl
check_platform Linux x86_64 unavailable 'musl libc (x86_64)' refused
check_platform Linux aarch64 unavailable 'unrecognized libc' refused
check_platform Linux x86_64 'not glibc' 'ldd missing' refused
check_platform Darwin arm64 unavailable unused aarch64-apple-darwin
check_platform Darwin x86_64 unavailable unused x86_64-apple-darwin
printf '%s\n' 'PASS: release selection retains Linux libc and refuses unavailable targets before effects'
