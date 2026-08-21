#!/bin/sh
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="$REPO_ROOT/scripts/install.sh"
work="$(mktemp -d 2>/dev/null || mktemp -d -t tirith-paired-test)"
trap 'rm -rf "$work"' EXIT HUP INT TERM

run_rollback_case() {
  case_dir="$1"
  trigger="$2"
  mkdir -p "$case_dir/runtime"
  CASE_DIR="$case_dir" INSTALL_SH="$INSTALL_SH" TRIGGER="$trigger" sh -c '
    set -eu
    TIRITH_INSTALL_SH_LIB=1 . "$INSTALL_SH"
    run_root() { "$@"; }
    TARGET=x86_64-unknown-linux-gnu
    PAIRED_TMPDIR="$CASE_DIR/runtime"
    PAIRED_MAIN_DEST="$CASE_DIR/main"
    PAIRED_HELPER_DEST="$CASE_DIR/helper"
    PAIRED_MAIN_HAD_PREVIOUS=1
    PAIRED_HELPER_HAD_PREVIOUS=1
    PAIRED_MAIN_BACKUP="$CASE_DIR/runtime/main.previous"
    PAIRED_HELPER_BACKUP="$CASE_DIR/runtime/helper.previous"
    printf "old-main\n" > "$PAIRED_MAIN_BACKUP"
    printf "old-helper\n" > "$PAIRED_HELPER_BACKUP"
    PAIRED_MAIN_PREVIOUS_SHA256="$(sha256_file "$PAIRED_MAIN_BACKUP")"
    PAIRED_HELPER_PREVIOUS_SHA256="$(sha256_file "$PAIRED_HELPER_BACKUP")"
    printf "new-main\n" > "$PAIRED_MAIN_DEST"
    printf "new-helper\n" > "$PAIRED_HELPER_DEST"
    PAIRED_ROLLBACK_ARMED=1
    install_paired_traps
    if [ "$TRIGGER" = signal ]; then
      kill -TERM "$$"
    fi
    exit 1
  '
}

fails=0

failure_case="$work/failure"
if run_rollback_case "$failure_case" failure; then
  echo "not ok 1 injected failure unexpectedly succeeded" >&2
  fails=$((fails + 1))
elif [ "$(cat "$failure_case/main")" = "old-main" ] && \
     [ "$(cat "$failure_case/helper")" = "old-helper" ]; then
  echo "ok 1 injected failure restores and verifies both binaries"
else
  echo "not ok 1 injected failure did not restore both binaries" >&2
  fails=$((fails + 1))
fi

signal_case="$work/signal"
if run_rollback_case "$signal_case" signal; then
  echo "not ok 2 TERM unexpectedly succeeded" >&2
  fails=$((fails + 1))
elif [ "$(cat "$signal_case/main")" = "old-main" ] && \
     [ "$(cat "$signal_case/helper")" = "old-helper" ]; then
  echo "ok 2 TERM routes through paired rollback"
else
  echo "not ok 2 TERM did not restore both binaries" >&2
  fails=$((fails + 1))
fi

# A failed first restoration must not short-circuit the second restoration.
both_case="$work/both-attempted"
mkdir -p "$both_case/runtime"
if CASE_DIR="$both_case" INSTALL_SH="$INSTALL_SH" sh -c '
  set -eu
  TIRITH_INSTALL_SH_LIB=1 . "$INSTALL_SH"
  run_root() { "$@"; }
  TARGET=x86_64-unknown-linux-gnu
  PAIRED_TMPDIR="$CASE_DIR/runtime"
  PAIRED_MAIN_DEST="$CASE_DIR/main"
  PAIRED_HELPER_DEST="$CASE_DIR/helper"
  PAIRED_MAIN_HAD_PREVIOUS=1
  PAIRED_HELPER_HAD_PREVIOUS=1
  PAIRED_MAIN_BACKUP="$CASE_DIR/runtime/missing-main.previous"
  PAIRED_HELPER_BACKUP="$CASE_DIR/helper.previous"
  PAIRED_MAIN_PREVIOUS_SHA256=unreachable
  printf "old-helper\n" > "$PAIRED_HELPER_BACKUP"
  PAIRED_HELPER_PREVIOUS_SHA256="$(sha256_file "$PAIRED_HELPER_BACKUP")"
  printf "new-main\n" > "$PAIRED_MAIN_DEST"
  printf "new-helper\n" > "$PAIRED_HELPER_DEST"
  PAIRED_ROLLBACK_ARMED=1
  install_paired_traps
  exit 1
'; then
  echo "not ok 3 failed restoration unexpectedly succeeded" >&2
  fails=$((fails + 1))
elif [ "$(cat "$both_case/helper")" = "old-helper" ]; then
  echo "ok 3 helper restoration is attempted after main restoration failure"
else
  echo "not ok 3 helper restoration was short-circuited" >&2
  fails=$((fails + 1))
fi

[ "$fails" -eq 0 ] || exit 1
echo "PASS: paired installer rollback is stateful across failure and signals"
