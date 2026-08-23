#!/usr/bin/env bash

# Fetch every required threat-database source as one fail-closed transaction.
# Jobs write only below a private staging directory. The complete source set is
# exposed to the compiler with one same-filesystem rename after every PID has
# been waited successfully and every expected output has been validated.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)

OUTPUT_ROOT=${THREATDB_FETCH_OUTPUT_DIR:-/tmp}
FINAL_DIR="$OUTPUT_ROOT/tirith-threatdb-sources"

# Reviewed immutable upstream revisions. The workflow mirrors these values and
# every clone is verified against them before it becomes compiler-visible.
OSSF_MP_REF=${THREATDB_OSSF_MP_REF:-1ea2762d5fb415aef003a244d5aa83c5fc48cc6e}
DD_MP_REF=${THREATDB_DD_MP_REF:-ef4a781d476cd6eb89c8517ff9adbb54a5cfa8cc}
TYPOSQUAT_REF=${THREATDB_TYPOSQUAT_REF:-fd0bde98d200efe5c282a07edc4c68fba13252c6}
COMPILER_BIN=${THREATDB_COMPILER_BIN:-./target/release/tirith-threatdb-compile}
WEB3_ANCHOR_FILE=${THREATDB_WEB3_ANCHOR_FILE:-$REPO_ROOT/crates/tirith/assets/data/web3_package_anchors.csv}

# Transfer limits for the mutable feed downloads (repo-0241): bounded connect
# and total transfer times, and a hard response-size cap so a hostile or broken
# upstream cannot exhaust the runner or suppress the daily update.
CURL_CONNECT_TIMEOUT_SECONDS=15
CURL_MAX_TIME_SECONDS=120
FEODO_MAX_BYTES=$((16 * 1024 * 1024))
CISA_KEV_MAX_BYTES=$((64 * 1024 * 1024))
OSSF_MAX_FILES=50000
OSSF_MAX_BYTES=$((256 * 1024 * 1024))
DATADOG_MANIFEST_MAX_BYTES=$((64 * 1024 * 1024))
TYPOSQUAT_MAX_BYTES=$((4 * 1024 * 1024))

mkdir -p -- "$OUTPUT_ROOT"
if [ -e "$FINAL_DIR" ]; then
  echo "::error::threatdb source destination already exists: $FINAL_DIR" >&2
  exit 1
fi

pids=()
labels=()

cleanup() {
  local pid
  # `${array[@]}` is an error for an empty array under Bash 3.2 + `set -u`;
  # the `${array+...}` guard keeps the cleanup portable to macOS as well as CI.
  for pid in ${pids+"${pids[@]}"}; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  for pid in ${pids+"${pids[@]}"}; do
    wait "$pid" 2>/dev/null || true
  done
  rm -rf -- "$STAGING_DIR"
}

STAGING_DIR=$(mktemp -d "$OUTPUT_ROOT/.tirith-threatdb-fetch.XXXXXX")
trap cleanup EXIT
STAGED_SOURCES="$STAGING_DIR/sources"
mkdir -p -- "$STAGED_SOURCES"
# Provenance is part of the same atomic directory rename as every compiler
# input. No source tree can become visible without its exact revisions/hashes.
PINS_FILE="$STAGED_SOURCES/source-provenance.json"

FETCH_TIMEOUT_SECONDS=${THREATDB_FETCH_TIMEOUT_SECONDS:-180}
case "$FETCH_TIMEOUT_SECONDS" in
  ''|*[!0-9]*|0)
    echo "::error::THREATDB_FETCH_TIMEOUT_SECONDS must be a positive integer" >&2
    exit 1
    ;;
esac
TRANSACTION_TIMEOUT_SECONDS=${THREATDB_TRANSACTION_TIMEOUT_SECONDS:-600}
case "$TRANSACTION_TIMEOUT_SECONDS" in
  ''|*[!0-9]*|0)
    echo "::error::THREATDB_TRANSACTION_TIMEOUT_SECONDS must be a positive integer" >&2
    exit 1
    ;;
esac
THREATDB_TRANSACTION_DEADLINE_EPOCH=$(($(date +%s) + TRANSACTION_TIMEOUT_SECONDS))

TIMEOUT_BIN=${THREATDB_FETCH_TIMEOUT_BIN:-}
if [ -z "$TIMEOUT_BIN" ]; then
  TIMEOUT_BIN=$(command -v timeout 2>/dev/null || command -v gtimeout 2>/dev/null || true)
fi
if [ -z "$TIMEOUT_BIN" ] || [ ! -x "$TIMEOUT_BIN" ]; then
  echo "::error::GNU timeout is required for bounded threatdb source fetches" >&2
  exit 1
fi

# Background INSIDE the function: `run_fetch ... &` would record this shell's
# subshell PID, so cleanup would kill the subshell and orphan `timeout` and its
# fetch child, which then keeps writing into a staging tree cleanup just removed.
# `$!` set here is visible to the caller.
remaining_timeout_seconds() {
  local remaining
  remaining=$((THREATDB_TRANSACTION_DEADLINE_EPOCH - $(date +%s)))
  if (( remaining <= 0 )); then
    echo "::error::threatdb source transaction exceeded ${TRANSACTION_TIMEOUT_SECONDS}s deadline" >&2
    return 1
  fi
  if (( remaining < FETCH_TIMEOUT_SECONDS )); then
    printf '%s\n' "$remaining"
  else
    printf '%s\n' "$FETCH_TIMEOUT_SECONDS"
  fi
}

run_bounded() {
  local timeout_seconds
  timeout_seconds=$(remaining_timeout_seconds) || return 1
  "$TIMEOUT_BIN" --signal=TERM --kill-after=10s "${timeout_seconds}s" "$@"
}

run_fetch() {
  local timeout_seconds
  timeout_seconds=$(remaining_timeout_seconds) || return 1
  "$TIMEOUT_BIN" --signal=TERM --kill-after=10s "${timeout_seconds}s" "$@" &
}

run_source_git_step() {
  local label=$1
  local step=$2
  local status
  shift 2
  if run_bounded "$@"; then
    return 0
  else
    status=$?
    echo "::error::${label}: ${step} failed or timed out (exit ${status})" >&2
    return "$status"
  fi
}

materialize_git_source() {
  local label=$1
  local repo=$2
  local ref=$3
  shift 3

  # A blobless partial clone may contact the promisor remote during checkout or
  # sparse expansion. Keep every such operation inside both the per-source cap
  # and the single transaction deadline; nothing here writes outside staging.
  run_source_git_step "$label" "reviewed revision fetch" \
    git -C "$repo" fetch --depth 1 origin "$ref"
  run_source_git_step "$label" "reviewed revision checkout" \
    git -C "$repo" checkout --detach "$ref"
  run_source_git_step "$label" "sparse materialization" \
    git -C "$repo" sparse-checkout set --no-cone "$@"
}

content_sha256() {
  local root=$1
  shift
  (
    cd -- "$root"
    find "$@" -type f -print0 \
      | LC_ALL=C sort -z \
      | while IFS= read -r -d '' file; do
          printf '%s\0' "$file"
          sha256sum "$file" | cut -d' ' -f1 | tr -d '\n'
          printf '\0'
        done
  ) | sha256sum | cut -d' ' -f1
}

run_fetch git clone --depth 1 --filter=blob:none --sparse --no-checkout \
  https://github.com/ossf/malicious-packages.git \
  "$STAGED_SOURCES/ossf-mp"
pids+=("$!")
labels+=("OpenSSF malicious-packages")

run_fetch git clone --depth 1 --filter=blob:none --sparse --no-checkout \
  https://github.com/DataDog/malicious-software-packages-dataset.git \
  "$STAGED_SOURCES/dd-mp"
pids+=("$!")
labels+=("DataDog malicious-software-packages-dataset")

run_fetch git clone --depth 1 --filter=blob:none --sparse --no-checkout \
  https://github.com/ecosyste-ms/typosquatting-dataset.git \
  "$STAGED_SOURCES/typosquats"
pids+=("$!")
labels+=("ecosyste.ms typosquatting-dataset")

run_fetch curl -sSfL \
  --connect-timeout="$CURL_CONNECT_TIMEOUT_SECONDS" \
  --max-time="$CURL_MAX_TIME_SECONDS" \
  --max-filesize="$FEODO_MAX_BYTES" \
  https://feodotracker.abuse.ch/downloads/ipblocklist.txt \
  -o "$STAGED_SOURCES/feodo.txt"
pids+=("$!")
labels+=("Feodo Tracker")

run_fetch curl -sSfL \
  --connect-timeout="$CURL_CONNECT_TIMEOUT_SECONDS" \
  --max-time="$CURL_MAX_TIME_SECONDS" \
  --max-filesize="$CISA_KEV_MAX_BYTES" \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json \
  -o "$STAGED_SOURCES/cisa-kev.json"
pids+=("$!")
labels+=("CISA KEV")

failed=0
for index in "${!pids[@]}"; do
  if wait "${pids[$index]}"; then
    echo "Fetched ${labels[$index]}"
  else
    status=$?
    echo "::error::failed to fetch ${labels[$index]} (exit $status)" >&2
    failed=1
  fi
done
pids=()
if (( failed != 0 )); then
  exit 1
fi

if [ ! -s "$WEB3_ANCHOR_FILE" ]; then
  echo "::error::required Web3 anchor input is missing or empty: $WEB3_ANCHOR_FILE" >&2
  exit 1
fi

if [ ! -d "$STAGED_SOURCES/ossf-mp/.git" ] ||
   [ ! -d "$STAGED_SOURCES/dd-mp/.git" ] ||
   [ ! -d "$STAGED_SOURCES/typosquats/.git" ] ||
   [ ! -s "$STAGED_SOURCES/feodo.txt" ] ||
   [ ! -s "$STAGED_SOURCES/cisa-kev.json" ]; then
  echo "::error::one or more required threatdb sources is empty or incomplete" >&2
  exit 1
fi

# Fetch and detach at each reviewed object, then materialize only its reviewed
# compiler inputs and attribution files. Checkout and sparse expansion can both
# lazy-fetch blobs, so the helper bounds and labels every network-capable step.
materialize_git_source \
  "OpenSSF malicious-packages" \
  "$STAGED_SOURCES/ossf-mp" "$OSSF_MP_REF" \
  /osv/ /LICENSE /README.md
materialize_git_source \
  "DataDog malicious-software-packages-dataset" \
  "$STAGED_SOURCES/dd-mp" "$DD_MP_REF" \
  /samples/npm/manifest.json /samples/pypi/manifest.json /LICENSE /README.md
materialize_git_source \
  "ecosyste.ms typosquatting-dataset" \
  "$STAGED_SOURCES/typosquats" "$TYPOSQUAT_REF" \
  /typosquats.csv /LICENSE /README.md

# Record the exact upstream revisions that were fetched. A shallow clone's HEAD
# is the resolved commit for the pinned ref above; feeds have no revision, so
# their sha256 is recorded instead.
OSSF_MP_SHA=$(git -C "$STAGED_SOURCES/ossf-mp" rev-parse HEAD)
DD_MP_SHA=$(git -C "$STAGED_SOURCES/dd-mp" rev-parse HEAD)
TYPOSQUAT_SHA=$(git -C "$STAGED_SOURCES/typosquats" rev-parse HEAD)
case "$OSSF_MP_SHA$DD_MP_SHA$TYPOSQUAT_SHA" in
  *[!0-9a-f]*)
    echo "::error::resolved source commit is not lowercase hex: ossf=$OSSF_MP_SHA datadog=$DD_MP_SHA" >&2
    exit 1
    ;;
esac
if [ "$OSSF_MP_SHA" != "$OSSF_MP_REF" ] ||
   [ "$DD_MP_SHA" != "$DD_MP_REF" ] ||
   [ "$TYPOSQUAT_SHA" != "$TYPOSQUAT_REF" ]; then
  echo "::error::source HEAD does not match reviewed revision: ossf=$OSSF_MP_SHA datadog=$DD_MP_SHA typosquats=$TYPOSQUAT_SHA" >&2
  exit 1
fi

for required in \
  "$STAGED_SOURCES/ossf-mp/LICENSE" \
  "$STAGED_SOURCES/dd-mp/LICENSE" \
  "$STAGED_SOURCES/dd-mp/samples/npm/manifest.json" \
  "$STAGED_SOURCES/dd-mp/samples/pypi/manifest.json" \
  "$STAGED_SOURCES/typosquats/LICENSE" \
  "$STAGED_SOURCES/typosquats/typosquats.csv"
do
  if [ ! -s "$required" ]; then
    echo "::error::required sparse source artifact is missing or empty: $required" >&2
    exit 1
  fi
done

read -r OSSF_MAL_COUNT OSSF_FILE_COUNT OSSF_FILE_BYTES < <(
  python3 - "$STAGED_SOURCES/ossf-mp/osv" <<'PY'
import os
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
files = [path for path in root.rglob("*") if path.is_file()]
malicious = [path for path in files if path.name.startswith("MAL-") and path.suffix == ".json"]
print(len(malicious), len(files), sum(os.stat(path).st_size for path in files))
PY
)
if [ "$OSSF_MAL_COUNT" -lt 100 ]; then
  echo "::error::OpenSSF sparse snapshot has only $OSSF_MAL_COUNT MAL records" >&2
  exit 1
fi
if [ "$OSSF_FILE_COUNT" -gt "$OSSF_MAX_FILES" ] ||
   [ "$OSSF_FILE_BYTES" -gt "$OSSF_MAX_BYTES" ]; then
  echo "::error::OpenSSF sparse snapshot exceeds file/byte caps: files=$OSSF_FILE_COUNT bytes=$OSSF_FILE_BYTES" >&2
  exit 1
fi
TYPOSQUAT_COUNT=$(($(wc -l < "$STAGED_SOURCES/typosquats/typosquats.csv") - 1))
if [ "$TYPOSQUAT_COUNT" -lt 100 ]; then
  echo "::error::typosquat snapshot has only $TYPOSQUAT_COUNT data rows" >&2
  exit 1
fi
TYPOSQUAT_BYTES=$(wc -c < "$STAGED_SOURCES/typosquats/typosquats.csv")
if [ "$TYPOSQUAT_BYTES" -gt "$TYPOSQUAT_MAX_BYTES" ]; then
  echo "::error::typosquat snapshot exceeds byte cap: $TYPOSQUAT_BYTES" >&2
  exit 1
fi

# The compiler owns OSV shape classification. It requests registry versions only
# for unique bounded claims and writes one atomic capped snapshot; direct
# introduced:0-without-close claims never trigger a request.
run_bounded "$COMPILER_BIN" fetch-registry-snapshots \
  --ossf "$STAGED_SOURCES/ossf-mp" \
  --ossf-commit "$OSSF_MP_SHA" \
  --output "$STAGED_SOURCES/registry-versions.json"
test -s "$STAGED_SOURCES/registry-versions.json"
python3 - "$STAGED_SOURCES/registry-versions.json" "$OSSF_MP_SHA" <<'PY'
import json
import pathlib
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert document.get("schema_version") == 1
assert document.get("ossf_commit") == sys.argv[2]
packages = document.get("packages")
assert isinstance(packages, list) and len(packages) <= 1000
for package in packages:
    assert package.get("ecosystem") in {"npm", "pypi"}
    assert isinstance(package.get("name"), str) and package["name"]
    assert isinstance(package.get("source_url"), str) and package["source_url"].startswith("https://")
    assert isinstance(package.get("response_sha256"), str) and len(package["response_sha256"]) == 64
    assert package["response_sha256"] != "0" * 64
    assert isinstance(package.get("response_bytes"), int) and 0 < package["response_bytes"] <= 8 * 1024 * 1024
    assert isinstance(package.get("versions"), list) and package["versions"]
    assert len(package["versions"]) <= 20000
PY

FEODO_SHA=$(sha256sum "$STAGED_SOURCES/feodo.txt" | cut -d' ' -f1)
CISA_KEV_SHA=$(sha256sum "$STAGED_SOURCES/cisa-kev.json" | cut -d' ' -f1)
REGISTRY_SNAPSHOT_SHA=$(sha256sum "$STAGED_SOURCES/registry-versions.json" | cut -d' ' -f1)
REGISTRY_SNAPSHOT_BYTES=$(wc -c < "$STAGED_SOURCES/registry-versions.json")
REGISTRY_SNAPSHOT_RETRIEVED_AT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["retrieved_at"])' "$STAGED_SOURCES/registry-versions.json")
REGISTRY_SNAPSHOT_PACKAGES=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["packages"]))' "$STAGED_SOURCES/registry-versions.json")
RETRIEVED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
COMPILER_VERSION=$("$COMPILER_BIN" --version | awk '{print $NF}')
case "$COMPILER_VERSION" in
  ''|*[!0-9A-Za-z.+-]*)
    echo "::error::invalid compiler version metadata: $COMPILER_VERSION" >&2
    exit 1
    ;;
esac
DD_FILE_BYTES=$(wc -c < "$STAGED_SOURCES/dd-mp/samples/npm/manifest.json")
DD_FILE_BYTES=$((DD_FILE_BYTES + $(wc -c < "$STAGED_SOURCES/dd-mp/samples/pypi/manifest.json")))
if [ "$DD_FILE_BYTES" -gt "$DATADOG_MANIFEST_MAX_BYTES" ]; then
  echo "::error::Datadog manifests exceed byte cap: $DD_FILE_BYTES" >&2
  exit 1
fi
OSSF_CONTENT_SHA=$(content_sha256 "$STAGED_SOURCES/ossf-mp" osv)
DD_CONTENT_SHA=$(content_sha256 "$STAGED_SOURCES/dd-mp" \
  samples/npm/manifest.json samples/pypi/manifest.json)
TYPOSQUAT_CONTENT_SHA=$(content_sha256 "$STAGED_SOURCES/typosquats" \
  typosquats.csv)
ANCHOR_ROOT=$(dirname -- "$WEB3_ANCHOR_FILE")
ANCHOR_NAME=$(basename -- "$WEB3_ANCHOR_FILE")
ANCHOR_CONTENT_SHA=$(content_sha256 "$ANCHOR_ROOT" "$ANCHOR_NAME")
ANCHOR_BYTES=$(wc -c < "$WEB3_ANCHOR_FILE")
FEODO_BYTES=$(wc -c < "$STAGED_SOURCES/feodo.txt")
CISA_KEV_BYTES=$(wc -c < "$STAGED_SOURCES/cisa-kev.json")
jq -cS -n \
  --arg retrieved_at "$RETRIEVED_AT" \
  --arg compiler_version "$COMPILER_VERSION" \
  --arg ossf_ref "$OSSF_MP_REF" --arg ossf_commit "$OSSF_MP_SHA" \
  --arg ossf_content_sha "$OSSF_CONTENT_SHA" \
  --argjson ossf_files "$OSSF_FILE_COUNT" --argjson ossf_bytes "$OSSF_FILE_BYTES" \
  --arg dd_ref "$DD_MP_REF" --arg dd_commit "$DD_MP_SHA" --argjson dd_bytes "$DD_FILE_BYTES" \
  --arg dd_content_sha "$DD_CONTENT_SHA" \
  --arg typo_ref "$TYPOSQUAT_REF" --arg typo_commit "$TYPOSQUAT_SHA" \
  --arg typo_content_sha "$TYPOSQUAT_CONTENT_SHA" \
  --argjson typo_rows "$TYPOSQUAT_COUNT" --argjson typo_bytes "$TYPOSQUAT_BYTES" \
  --arg registry_retrieved_at "$REGISTRY_SNAPSHOT_RETRIEVED_AT" \
  --arg registry_sha "$REGISTRY_SNAPSHOT_SHA" \
  --argjson registry_packages "$REGISTRY_SNAPSHOT_PACKAGES" \
  --argjson registry_bytes "$REGISTRY_SNAPSHOT_BYTES" \
  --arg feodo_sha "$FEODO_SHA" --argjson feodo_bytes "$FEODO_BYTES" \
  --arg cisa_sha "$CISA_KEV_SHA" --argjson cisa_bytes "$CISA_KEV_BYTES" \
  --arg anchor_content_sha "$ANCHOR_CONTENT_SHA" --argjson anchor_bytes "$ANCHOR_BYTES" \
  '{
    schema_version: 2,
    retrieved_at: $retrieved_at,
    compiler_version: $compiler_version,
    ossf_malicious_packages: {
      source_url: "https://github.com/ossf/malicious-packages.git",
      ref: $ossf_ref, commit: $ossf_commit, spdx: "CC-BY-4.0",
      files: $ossf_files, bytes: $ossf_bytes, content_sha256: $ossf_content_sha
    },
    datadog_malicious_software_packages: {
      source_url: "https://github.com/DataDog/malicious-software-packages-dataset.git",
      ref: $dd_ref, commit: $dd_commit, spdx: "Apache-2.0",
      files: 2, bytes: $dd_bytes, content_sha256: $dd_content_sha
    },
    ecosystems_typosquatting_dataset: {
      source_url: "https://github.com/ecosyste-ms/typosquatting-dataset.git",
      ref: $typo_ref, commit: $typo_commit, spdx: "CC0-1.0",
      files: 1, rows: $typo_rows, bytes: $typo_bytes,
      content_sha256: $typo_content_sha
    },
    registry_version_snapshot: {
      ossf_commit: $ossf_commit, retrieved_at: $registry_retrieved_at,
      source_urls: ["https://registry.npmjs.org/", "https://pypi.org/pypi/"],
      spdx: "LicenseRef-Registry-Metadata", packages: $registry_packages,
      bytes: $registry_bytes, sha256: $registry_sha
    },
    feodo_tracker_ipblocklist: {
      source_url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
      spdx: "LicenseRef-abuse-ch-terms", files: 1,
      bytes: $feodo_bytes, sha256: $feodo_sha
    },
    cisa_known_exploited_vulnerabilities: {
      source_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
      spdx: "LicenseRef-US-Government-Work", files: 1,
      bytes: $cisa_bytes, sha256: $cisa_sha
    },
    web3_package_anchors: {
      source_url: "repository:crates/tirith/assets/data/web3_package_anchors.csv",
      spdx: "LicenseRef-Package-Name-Facts", files: 1,
      bytes: $anchor_bytes, content_sha256: $anchor_content_sha
    }
  }' > "$PINS_FILE"
echo "Resolved source revisions:"
cat "$PINS_FILE"

# STAGING_DIR was created inside OUTPUT_ROOT, so this publishes the complete set
# atomically on the same filesystem. No compiler-visible path exists beforehand.
mv -- "$STAGED_SOURCES" "$FINAL_DIR"
echo "Sources fetched successfully into $FINAL_DIR"
