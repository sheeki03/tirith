#!/usr/bin/env bash
# Qualify only the exact executable from one produced release archive. No
# candidate binary is executed until archive shape and native ELF identity pass.
set -euo pipefail
umask 077
if [[ $# != 4 ]]; then
  echo 'usage: test-native-arm-artifact.sh ARCHIVE TARGET SOURCE_SHA256 OUTPUT_DIR' >&2
  exit 2
fi
archive=$1
target=$2
source_sha256=$3
output=$4
case "$target" in
  aarch64-unknown-linux-gnu|aarch64-unknown-linux-musl) ;;
  *) echo 'unsupported native artifact target' >&2; exit 2 ;;
esac
if [[ ! "$source_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  echo 'invalid source snapshot digest' >&2
  exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$output"
output=$(cd -- "$output" && pwd)
archive=$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' "$archive")
python3 - "$archive" "$output/tirith" <<'PY'
import pathlib, shutil, sys, tarfile
archive, destination = map(pathlib.Path, sys.argv[1:])
if not archive.is_file() or not 0 < archive.stat().st_size <= 512 * 1024 * 1024:
    raise SystemExit('archive byte limit exceeded')
with tarfile.open(archive, 'r:gz') as bundle:
    matches = []
    declared_bytes = 0
    for count, member in enumerate(bundle, start=1):
        declared_bytes += member.size
        if count > 4096 or declared_bytes > 1024 * 1024 * 1024:
            raise SystemExit('archive member limit exceeded')
        if member.name == 'tirith':
            matches.append(member)
    if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= 512 * 1024 * 1024:
        raise SystemExit('archive needs exactly one bounded regular tirith executable')
    with bundle.extractfile(matches[0]) as source, destination.open('xb') as output:
        shutil.copyfileobj(source, output, length=1024 * 1024)
    if destination.stat().st_size != matches[0].size:
        raise SystemExit('archive executable size changed')
destination.chmod(0o755)
PY
# Parse ELF headers and compile the inert fixture inside the pinned native
# container, keeping the runner's host toolchain out of artifact interpretation.
docker run --rm --network none --cpus 1 --memory 256m --pids-limit 64 \
  -v "$script_dir:/fixtures:ro" -v "$output:/output" \
  rust:1.83-slim-bookworm@sha256:200f14b0b84ac302774ef5963119f7d949fcf72bd24b365f5ddb829b254c9594 \
  sh -c 'readelf -h /output/tirith > /output/elf-header.txt && readelf -l /output/tirith > /output/elf-program-headers.txt && cc -O2 -Wall -Wextra -Werror /fixtures/native-capsule-probe.c -o /output/probe && cc -O2 -Wall -Wextra -Werror /fixtures/native-capsule-cancellation.c -o /output/cancel-probe'
if ! grep -Eq 'Machine:[[:space:]]+AArch64' "$output/elf-header.txt"; then
  echo 'artifact is not an ARM64 executable' >&2
  exit 1
fi
if [[ "$target" == aarch64-unknown-linux-musl ]] && grep -q 'Requesting program interpreter' "$output/elf-program-headers.txt"; then
  echo 'musl artifact unexpectedly needs a dynamic interpreter' >&2
  exit 1
fi
artifact_sha256=$(sha256sum "$archive" | cut -d ' ' -f 1)
python3 "$script_dir/qualify-native-capsule.py" \
  --binary "$output/tirith" --probe "$output/probe" --cancellation-probe "$output/cancel-probe" \
  --snapshot-sha256 "$source_sha256" --artifact-sha256 "$artifact_sha256" \
  --target "$target" --output "$output/qualification.json"
