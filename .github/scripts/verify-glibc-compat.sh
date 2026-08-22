#!/usr/bin/env bash
# Verify every ELF beneath a release/package root has the expected architecture
# and does not reference a GLIBC symbol newer than the declared compatibility
# ceiling. This intentionally scans by ELF magic instead of executable mode so
# a packaging-mode regression cannot hide an ELF from the check.

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <x86_64|aarch64> <max-glibc-version> <root>" >&2
  exit 2
fi

expected_arch="$1"
max_glibc="$2"
scan_root="$3"
readelf_bin="${READELF:-readelf}"

if [[ ! -d "$scan_root" ]]; then
  echo "ERROR: ELF scan root is not a directory: $scan_root" >&2
  exit 1
fi
if ! command -v "$readelf_bin" >/dev/null 2>&1; then
  echo "ERROR: readelf is required for the GLIBC compatibility check" >&2
  exit 1
fi

case "$expected_arch" in
  x86_64) expected_machine='Advanced Micro Devices X86-64' ;;
  aarch64) expected_machine='AArch64' ;;
  *)
    echo "ERROR: unsupported expected architecture: $expected_arch" >&2
    exit 2
    ;;
esac

file_list=$(mktemp)
trap 'rm -f -- "$file_list"' EXIT
# Keep `find` in the main shell's error path. A process-substitution failure is
# otherwise not reflected in the `while` command's status and could turn an
# unreadable package subtree into a partial scan that appears successful.
find "$scan_root" -type f -print0 > "$file_list"

# `-type f` is false for a symlink, so the scan above walks straight past one.
# A link whose target lives inside the tree is still covered (the target is
# itself a regular file the scan reaches), but a link pointing outside it names
# a binary this check never inspects while the package still ships the path.
# Refuse rather than report a clean scan over an unverifiable entry.
# Compare canonical paths on both sides: `readlink -f` always answers with an
# absolute path, so matching it against a relative `$scan_root` would reject
# every ordinary in-tree `libfoo.so -> libfoo.so.1` a real package ships.
canonical_root=$(cd -- "$scan_root" && pwd -P)
# Same discipline as the file list above: a process substitution's exit status
# is invisible to `set -e`, so a `find` that failed part-way would leave this
# loop short and the scan looking clean. Materialize the list first.
link_list=$(mktemp)
trap 'rm -f -- "$file_list" "$link_list"' EXIT
find "$scan_root" -type l -print0 > "$link_list"
escaping_links=0
while IFS= read -r -d '' link; do
  target=$(readlink -f -- "$link" 2>/dev/null || true)
  case "$target" in
    "$canonical_root"/*) continue ;;
  esac
  echo "ERROR: $link resolves outside $canonical_root (to '${target:-unresolvable}') and cannot be verified" >&2
  escaping_links=$((escaping_links + 1))
done < "$link_list"
if [[ $escaping_links -gt 0 ]]; then
  exit 1
fi

elf_count=0
while IFS= read -r -d '' candidate; do
  magic=$(LC_ALL=C od -An -tx1 -N4 -- "$candidate" | tr -d '[:space:]')
  [[ "$magic" == "7f454c46" ]] || continue
  elf_count=$((elf_count + 1))

  header=$(LC_ALL=C "$readelf_bin" --file-header --wide -- "$candidate")
  machine=$(sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p' <<<"$header")
  if [[ "$machine" != "$expected_machine" ]]; then
    echo "ERROR: $candidate has ELF machine '$machine'; expected '$expected_machine'" >&2
    exit 1
  fi

  version_info=$(LC_ALL=C "$readelf_bin" --version-info --wide -- "$candidate")
  versions=$(grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' <<<"$version_info" || true)
  if [[ -z "$versions" ]]; then
    echo "ERROR: GNU release ELF has no versioned GLIBC requirements: $candidate" >&2
    exit 1
  fi
  highest=$(sed 's/^GLIBC_//' <<<"$versions" | sort -uV | tail -n1)
  newest=$(printf '%s\n%s\n' "$max_glibc" "$highest" | sort -V | tail -n1)
  if [[ "$newest" != "$max_glibc" ]]; then
    echo "ERROR: $candidate requires GLIBC_$highest, newer than GLIBC_$max_glibc" >&2
    exit 1
  fi
  printf 'verified %s: arch=%s max_glibc=%s\n' "$candidate" "$expected_arch" "$highest"
done < "$file_list"

if [[ $elf_count -eq 0 ]]; then
  echo "ERROR: no ELF files found beneath $scan_root" >&2
  exit 1
fi

echo "verified $elf_count ELF file(s) beneath $scan_root against GLIBC_$max_glibc"
