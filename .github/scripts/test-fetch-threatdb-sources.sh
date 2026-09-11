#!/usr/bin/env bash

# Deterministic regression for the workflow fetch transaction. One background
# fetch writes partial bytes and fails while all siblings succeed; the wrapper
# must return nonzero, leave no compiler-visible source directory, and prevent
# the simulated compile/publication continuation from running.

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
FETCH_SCRIPT="$SCRIPT_DIR/fetch-threatdb-sources.sh"
# Fake git and registry responses below describe this immutable test snapshot.
# The watcher updates the production manifest before running this test, so using
# that manifest would make every legitimate pin refresh fail the checkout guard.
export THREATDB_SOURCE_PINS_FILE="$SCRIPT_DIR/fixtures/threatdb-source-pins.json"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/tirith-threatdb-fetch-test.XXXXXX")
trap 'rm -rf -- "$TEST_ROOT"' EXIT

FAKE_BIN="$TEST_ROOT/bin"
OUTPUT_ROOT="$TEST_ROOT/output"
mkdir -p -- "$FAKE_BIN" "$OUTPUT_ROOT"

# Guard the calibrated defaults so a reviewed OpenSSF snapshot cannot silently
# become unbuildable again while both resource limits remain bounded.
grep -Fq 'OSSF_MAX_FILES=250000' "$FETCH_SCRIPT"
grep -Fq 'OSSF_MAX_BYTES=$((512 * 1024 * 1024))' "$FETCH_SCRIPT"
grep -Fq 'FETCH_TIMEOUT_SECONDS=${THREATDB_FETCH_TIMEOUT_SECONDS:-300}' "$FETCH_SCRIPT"

cat > "$FAKE_BIN/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
# `git -C <dir> show ...` records the source commit timestamp in provenance.
if [[ "$*" == *" show "* ]] && [[ "$*" == *"--format=%cI"* ]]; then
  case "$2" in
    *ossf-mp) echo "2026-08-31T18:32:57+00:00" ;;
    *dd-mp) echo "2026-08-31T04:05:01+00:00" ;;
    *typosquats) echo "2025-12-17T11:33:09+00:00" ;;
    *) exit 64 ;;
  esac
  exit 0
fi
# `git -C <dir> rev-parse HEAD` records the resolved source revision.
if [[ "$*" == *rev-parse* ]]; then
  case "$2" in
    *ossf-mp) echo "54642f7ee96e780b046660519b028fefb635375a" ;;
    *dd-mp) echo "2d09839012cedc387ce438debeb77884ac2a242c" ;;
    *typosquats) echo "fd0bde98d200efe5c282a07edc4c68fba13252c6" ;;
    *) exit 64 ;;
  esac
  exit 0
fi
if [[ "$*" == *sparse-checkout* ]]; then
  if [[ "$*" == *"${FAKE_SPARSE_HANG:-never-match}"* ]]; then
    if [ -n "${FAKE_SPARSE_STARTED:-}" ]; then
      printf 'started\n' > "$FAKE_SPARSE_STARTED"
    fi
    trap 'if [ -n "${FAKE_SPARSE_TERMINATED:-}" ]; then printf "terminated\n" > "$FAKE_SPARSE_TERMINATED"; fi; exit 143' TERM
    while :; do read -r -t 1 _ || :; done
  fi
  exit 0
fi
if [[ "$*" == *" fetch "* ]] || [[ "$*" == *" checkout "* ]]; then
  exit 0
fi
destination=${!#}
mkdir -p -- "$destination/.git"
case "$*" in
  *ossf/malicious-packages*)
    mkdir -p -- "$destination/osv"
    printf 'fixture license\n' > "$destination/LICENSE"
    printf 'fixture readme\n' > "$destination/README.md"
    # Keep fixture preparation comfortably below the timeout under test, even
    # while CI is compiling: avoid hundreds of command-substitution processes.
    python3 - "$destination/osv" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
for index in range(1, 101):
    record_id = f"MAL-2099-{index:04d}"
    record = {"id": record_id, "affected": [{
        "package": {"ecosystem": "npm", "name": f"bad-{index}"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
    }]}
    (root / f"{record_id}.json").write_text(json.dumps(record) + "\n")
PY
    ln -s MAL-2099-0001.json "$destination/osv/linked-record.json"
    ;;
  *DataDog/malicious-software-packages-dataset*)
    mkdir -p -- "$destination/samples/npm" "$destination/samples/pypi"
    printf 'fixture license\n' > "$destination/LICENSE"
    printf 'fixture readme\n' > "$destination/README.md"
    printf '{"bad-npm":null}\n' > "$destination/samples/npm/manifest.json"
    printf '{"bad-pypi":null}\n' > "$destination/samples/pypi/manifest.json"
    ;;
  *ecosyste-ms/typosquatting-dataset*)
    printf 'fixture license\n' > "$destination/LICENSE"
    printf 'fixture readme\n' > "$destination/README.md"
    printf 'malicious_package,target_package,ecosystem,registry,classification,source\n' > "$destination/typosquats.csv"
    for index in $(seq 1 100); do
      printf 'bad-%d,good-%d,npm,https://npmjs.org,other,fixture\n' "$index" "$index" >> "$destination/typosquats.csv"
    done
    ;;
esac
if [[ "$*" == *"${FAKE_FETCH_FAILURE:-never-match}"* ]]; then
  exit 41
fi
if [[ "$*" == *"${FAKE_FETCH_HANG:-never-match}"* ]]; then
  while :; do read -r -t 1 _ || :; done
fi
EOF

cat > "$FAKE_BIN/tirith-threatdb-compile" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--version" ]; then
  echo "tirith-threatdb-compile 0.3.3"
  exit 0
fi
if [ "${1:-}" != "fetch-registry-snapshots" ]; then
  exit 64
fi
if [ -n "${FAKE_COMPILER_CALLED:-}" ]; then
  printf 'called\n' > "$FAKE_COMPILER_CALLED"
fi
if [ "${FAKE_COMPILER_FAILURE:-}" = "1" ]; then
  exit 43
fi
if [ "${FAKE_COMPILER_HANG:-}" = "1" ]; then
  while :; do read -r -t 1 _ || :; done
fi
shift
output=
while (( $# > 0 )); do
  case "$1" in
    --output) output=$2; shift 2 ;;
    *) shift ;;
  esac
done
test -n "$output"
retrieved_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# Representative entries so the fetch script's per-package validator rules
# (media type per ecosystem/status, resolution consistency) actually execute.
cat > "$output" <<JSON
{"schema_version":2,"ossf_commit":"54642f7ee96e780b046660519b028fefb635375a","retrieved_at":"$retrieved_at","packages":[
{"ecosystem":"npm","name":"fake-live","source_url":"https://registry.npmjs.org/fake-live","media_type":"application/vnd.npm.install-v1+json","http_status":200,"resolution":"registry_versions","response_sha256":"1111111111111111111111111111111111111111111111111111111111111111","response_bytes":64,"versions":["1.0.0","1.0.1"]},
{"ecosystem":"npm","name":"fake-binary-label","source_url":"https://registry.npmjs.org/fake-binary-label","media_type":"application/octet-stream","http_status":200,"resolution":"registry_versions","response_sha256":"3333333333333333333333333333333333333333333333333333333333333333","response_bytes":96,"versions":["0.0.1-security"]},
{"ecosystem":"npm","name":"fake-gone","source_url":"https://registry.npmjs.org/fake-gone","media_type":"application/json","http_status":404,"resolution":"package_not_found","response_sha256":"2222222222222222222222222222222222222222222222222222222222222222","response_bytes":21,"versions":[]}
]}
JSON
EOF

cat > "$FAKE_BIN/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=
url=
connect_timeout=
max_time=
max_filesize=
while (( $# > 0 )); do
  case "$1" in
    -sSfL)
      shift
      ;;
    -o)
      output=$2
      shift 2
      ;;
    --connect-timeout|--max-time|--max-filesize)
      option=$1
      value=${2:-}
      case "$value" in
        ''|*[!0-9]*|0)
          echo "invalid value for $option: $value" >&2
          exit 64
          ;;
      esac
      case "$option" in
        --connect-timeout) connect_timeout=$value ;;
        --max-time) max_time=$value ;;
        --max-filesize) max_filesize=$value ;;
      esac
      shift 2
      ;;
    --connect-timeout=*|--max-time=*|--max-filesize=*)
      echo "curl long-option values must be separate arguments: $1" >&2
      exit 64
      ;;
    http://*|https://*)
      url=$1
      shift
      ;;
    *)
      echo "unexpected curl argument: $1" >&2
      exit 64
      ;;
  esac
done
if [ -z "$output" ] || [ -z "$url" ] ||
   [ "$connect_timeout" != "15" ] || [ "$max_time" != "120" ]; then
  exit 64
fi
case "$url" in
  *ipblocklist*) test "$max_filesize" = "16777216" ;;
  *known_exploited_vulnerabilities*) test "$max_filesize" = "67108864" ;;
  *) exit 64 ;;
esac
printf 'fixture for %s\n' "$url" > "$output"
if [[ "$url" == *"${FAKE_FETCH_FAILURE:-never-match}"* ]]; then
  exit 42
fi
if [[ "$url" == *"${FAKE_FETCH_HANG:-never-match}"* ]]; then
  while :; do read -r -t 1 _ || :; done
fi
EOF

cat > "$FAKE_BIN/timeout" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
while (( $# > 0 )); do
  case "$1" in
    --signal=*|--kill-after=*) shift ;;
    *) break ;;
  esac
done
duration=${1%s}
shift
case "$duration" in
  ''|*[!0-9]*) exit 64 ;;
esac
"$@" &
child=$!
(
  sleeper=
  cleanup_watchdog() {
    if [ -n "$sleeper" ]; then
      kill "$sleeper" 2>/dev/null || true
      sleeper=
    fi
  }
  trap 'cleanup_watchdog; exit 0' TERM INT
  trap cleanup_watchdog EXIT
  sleep "$duration" &
  sleeper=$!
  wait "$sleeper" || exit 0
  sleeper=
  kill -TERM "$child" 2>/dev/null || exit 0
  # Give the fake worker's TERM trap time to record graceful termination even
  # on loaded macOS runners before exercising the hard-kill fallback.
  sleep 1
  kill -KILL "$child" 2>/dev/null || true
) </dev/null >/dev/null 2>&1 &
watchdog=$!
wait "$child"
status=$?
kill "$watchdog" 2>/dev/null || true
wait "$watchdog" 2>/dev/null || true
case "$status" in
  137|143) exit 124 ;;
  *) exit "$status" ;;
esac
EOF

chmod +x "$FAKE_BIN/git" "$FAKE_BIN/curl" "$FAKE_BIN/timeout" \
  "$FAKE_BIN/tirith-threatdb-compile"

compile_reached="$TEST_ROOT/compile-reached"

# The negative cases below deliberately drive the fetch script into its refusal
# paths, and it reports those with GitHub workflow commands (`::error::...`).
# Left alone, Actions renders each expected refusal as a job error annotation,
# so a real assertion failure is buried under annotations describing the cases
# that worked. Suppress command interpretation for the negative section and
# resume it before the positive case; the text still reaches the log verbatim.
STOP_TOKEN="tirith-threatdb-negative-cases"
echo "::stop-commands::${STOP_TOKEN}"

# Preflight validation happens after private staging is created. Invalid
# configuration must still leave neither staging nor a compiler-visible output.
status=0
if PATH="$FAKE_BIN:$PATH" \
   THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
   THREATDB_COMPILER_BIN="$FAKE_BIN/tirith-threatdb-compile" \
   THREATDB_FETCH_TIMEOUT_BIN="$FAKE_BIN/timeout" \
   THREATDB_FETCH_TIMEOUT_SECONDS=invalid \
   bash "$FETCH_SCRIPT"; then
  touch "$compile_reached"
else
  status=$?
fi
if (( status == 0 )); then
  echo "expected an invalid fetch timeout to fail preflight" >&2
  exit 1
fi
if [ -e "$compile_reached" ] || [ -e "$OUTPUT_ROOT/tirith-threatdb-sources" ]; then
  echo "invalid fetch timeout reached compile/publication" >&2
  exit 1
fi
if compgen -G "$OUTPUT_ROOT/.tirith-threatdb-fetch.*" >/dev/null; then
  echo "invalid fetch timeout left private staging state" >&2
  exit 1
fi

status=0
if PATH="$FAKE_BIN:$PATH" \
   THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
   THREATDB_COMPILER_BIN="$FAKE_BIN/tirith-threatdb-compile" \
   THREATDB_FETCH_TIMEOUT_BIN="$FAKE_BIN/timeout" \
   THREATDB_REGISTRY_TIMEOUT_SECONDS=0 \
   bash "$FETCH_SCRIPT"; then
  touch "$compile_reached"
else
  status=$?
fi
if (( status == 0 )); then
  echo "expected an invalid registry timeout to fail preflight" >&2
  exit 1
fi
if [ -e "$compile_reached" ] || [ -e "$OUTPUT_ROOT/tirith-threatdb-sources" ]; then
  echo "invalid registry timeout reached compile/publication" >&2
  exit 1
fi
if compgen -G "$OUTPUT_ROOT/.tirith-threatdb-fetch.*" >/dev/null; then
  echo "invalid registry timeout left private staging state" >&2
  exit 1
fi

status=0
if PATH="$FAKE_BIN:$PATH" \
   THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
   THREATDB_COMPILER_BIN="$FAKE_BIN/tirith-threatdb-compile" \
   THREATDB_FETCH_TIMEOUT_BIN="$FAKE_BIN/timeout" \
   THREATDB_TRANSACTION_TIMEOUT_SECONDS=invalid \
   bash "$FETCH_SCRIPT"; then
  touch "$compile_reached"
else
  status=$?
fi
if (( status == 0 )); then
  echo "expected an invalid transaction timeout to fail preflight" >&2
  exit 1
fi
if [ -e "$compile_reached" ] || [ -e "$OUTPUT_ROOT/tirith-threatdb-sources" ]; then
  echo "invalid transaction timeout reached compile/publication" >&2
  exit 1
fi
if compgen -G "$OUTPUT_ROOT/.tirith-threatdb-fetch.*" >/dev/null; then
  echo "invalid transaction timeout left private staging state" >&2
  exit 1
fi

status=0
if PATH="$FAKE_BIN:$PATH" \
   THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
   THREATDB_COMPILER_BIN="$FAKE_BIN/tirith-threatdb-compile" \
   THREATDB_FETCH_TIMEOUT_BIN="$TEST_ROOT/missing-timeout" \
   bash "$FETCH_SCRIPT"; then
  touch "$compile_reached"
else
  status=$?
fi
if (( status == 0 )); then
  echo "expected a missing timeout binary to fail preflight" >&2
  exit 1
fi
if [ -e "$compile_reached" ] || [ -e "$OUTPUT_ROOT/tirith-threatdb-sources" ]; then
  echo "missing timeout binary reached compile/publication" >&2
  exit 1
fi
if compgen -G "$OUTPUT_ROOT/.tirith-threatdb-fetch.*" >/dev/null; then
  echo "missing timeout binary left private staging state" >&2
  exit 1
fi

for failed_source in \
  ossf/malicious-packages \
  DataDog/malicious-software-packages-dataset \
  ecosyste-ms/typosquatting-dataset \
  ipblocklist \
  known_exploited_vulnerabilities
do
  status=0
  if PATH="$FAKE_BIN:$PATH" \
     THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
     THREATDB_COMPILER_BIN="$FAKE_BIN/tirith-threatdb-compile" \
     THREATDB_FETCH_TIMEOUT_BIN="$FAKE_BIN/timeout" \
     FAKE_FETCH_FAILURE="$failed_source" \
     bash "$FETCH_SCRIPT"; then
    touch "$compile_reached"
  else
    status=$?
  fi

  if (( status == 0 )); then
    echo "expected failed required fetch $failed_source to fail the transaction" >&2
    exit 1
  fi
  if [ -e "$compile_reached" ]; then
    echo "compile/publication continuation ran after $failed_source failed" >&2
    exit 1
  fi
  if [ -e "$OUTPUT_ROOT/tirith-threatdb-sources" ]; then
    echo "a partial source set became visible after $failed_source failed" >&2
    exit 1
  fi
  if compgen -G "$OUTPUT_ROOT/.tirith-threatdb-fetch.*" >/dev/null; then
    echo "failed source-fetch staging state was not cleaned after $failed_source" >&2
    exit 1
  fi
done

# A required source that never returns must be terminated by the wrapper's
# deadline, cleaned from private staging, and block the compile continuation.
status=0
if PATH="$FAKE_BIN:$PATH" \
   THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
   THREATDB_COMPILER_BIN="$FAKE_BIN/tirith-threatdb-compile" \
   THREATDB_FETCH_TIMEOUT_BIN="$FAKE_BIN/timeout" \
   THREATDB_FETCH_TIMEOUT_SECONDS=5 \
   FAKE_FETCH_HANG=ipblocklist \
   bash "$FETCH_SCRIPT"; then
  touch "$compile_reached"
else
  status=$?
fi
if (( status == 0 )); then
  echo "expected a hung required fetch to time out" >&2
  exit 1
fi
if [ -e "$compile_reached" ] || [ -e "$OUTPUT_ROOT/tirith-threatdb-sources" ]; then
  echo "hung fetch reached compile/publication" >&2
  exit 1
fi
if compgen -G "$OUTPUT_ROOT/.tirith-threatdb-fetch.*" >/dev/null; then
  echo "hung source-fetch staging state was not cleaned" >&2
  exit 1
fi

# Blobless clones can lazy-fetch during sparse expansion. The sparse worker is
# therefore subject to the same per-source timeout as an initial clone, and a
# timeout must remove all private state before the compiler can run.
# Allow fixture preparation to finish on loaded runners before the deliberately
# hung sparse step starts. These test ceilings remain far below production.
sparse_started="$TEST_ROOT/sparse-per-source-started"
sparse_terminated="$TEST_ROOT/sparse-per-source-terminated"
sparse_compiler_called="$TEST_ROOT/sparse-per-source-compiler-called"
sparse_log="$TEST_ROOT/sparse-per-source.log"
status=0
if PATH="$FAKE_BIN:$PATH" \
   THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
   THREATDB_COMPILER_BIN="$FAKE_BIN/tirith-threatdb-compile" \
   THREATDB_FETCH_TIMEOUT_BIN="$FAKE_BIN/timeout" \
   THREATDB_FETCH_TIMEOUT_SECONDS=5 \
   THREATDB_TRANSACTION_TIMEOUT_SECONDS=30 \
   FAKE_SPARSE_HANG=ossf-mp \
   FAKE_SPARSE_STARTED="$sparse_started" \
   FAKE_SPARSE_TERMINATED="$sparse_terminated" \
   FAKE_COMPILER_CALLED="$sparse_compiler_called" \
   bash "$FETCH_SCRIPT" >"$sparse_log" 2>&1; then
  touch "$compile_reached"
else
  status=$?
fi
if (( status == 0 )) || [ ! -s "$sparse_started" ] || [ ! -s "$sparse_terminated" ]; then
  printf 'status=%s started=%s terminated=%s\n' "$status" \
    "$([ -s "$sparse_started" ] && echo yes || echo no)" \
    "$([ -s "$sparse_terminated" ] && echo yes || echo no)" >&2
  echo "expected per-source timeout to start and terminate sparse materialization" >&2
  exit 1
fi
if ! grep -q 'OpenSSF malicious-packages: sparse materialization failed or timed out (exit 124)' \
    "$sparse_log"; then
  echo "sparse timeout did not retain the exact source/step label" >&2
  exit 1
fi
if [ -e "$compile_reached" ] || [ -e "$sparse_compiler_called" ] ||
   [ -e "$OUTPUT_ROOT/tirith-threatdb-sources" ]; then
  echo "per-source sparse timeout reached compiler-visible publication state" >&2
  exit 1
fi
if compgen -G "$OUTPUT_ROOT/.tirith-threatdb-fetch.*" >/dev/null; then
  echo "per-source sparse timeout left private staging state" >&2
  exit 1
fi

# The aggregate transaction deadline must also cap sparse materialization even
# when the per-source allowance is much larger.
sparse_started="$TEST_ROOT/sparse-transaction-started"
sparse_terminated="$TEST_ROOT/sparse-transaction-terminated"
sparse_compiler_called="$TEST_ROOT/sparse-transaction-compiler-called"
sparse_log="$TEST_ROOT/sparse-transaction.log"
SECONDS=0
status=0
if PATH="$FAKE_BIN:$PATH" \
   THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
   THREATDB_COMPILER_BIN="$FAKE_BIN/tirith-threatdb-compile" \
   THREATDB_FETCH_TIMEOUT_BIN="$FAKE_BIN/timeout" \
   THREATDB_FETCH_TIMEOUT_SECONDS=30 \
   THREATDB_TRANSACTION_TIMEOUT_SECONDS=8 \
   FAKE_SPARSE_HANG=ossf-mp \
   FAKE_SPARSE_STARTED="$sparse_started" \
   FAKE_SPARSE_TERMINATED="$sparse_terminated" \
   FAKE_COMPILER_CALLED="$sparse_compiler_called" \
   bash "$FETCH_SCRIPT" >"$sparse_log" 2>&1; then
  touch "$compile_reached"
else
  status=$?
fi
elapsed=$SECONDS
if (( status == 0 )) || (( elapsed >= 20 )) ||
   [ ! -s "$sparse_started" ] || [ ! -s "$sparse_terminated" ]; then
  echo "expected aggregate deadline to terminate sparse materialization promptly" >&2
  exit 1
fi
if ! grep -q 'OpenSSF malicious-packages: sparse materialization failed or timed out (exit 124)' \
    "$sparse_log"; then
  echo "aggregate sparse timeout did not retain the exact source/step label" >&2
  exit 1
fi
if [ -e "$compile_reached" ] || [ -e "$sparse_compiler_called" ] ||
   [ -e "$OUTPUT_ROOT/tirith-threatdb-sources" ]; then
  echo "aggregate sparse timeout reached compiler-visible publication state" >&2
  exit 1
fi
if compgen -G "$OUTPUT_ROOT/.tirith-threatdb-fetch.*" >/dev/null; then
  echo "aggregate sparse timeout left private staging state" >&2
  exit 1
fi

# Registry-version snapshot generation is part of the same transaction. Its
# failure must leave neither compiler-visible inputs nor provenance metadata.
status=0
if PATH="$FAKE_BIN:$PATH" \
   THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
   THREATDB_COMPILER_BIN="$FAKE_BIN/tirith-threatdb-compile" \
   THREATDB_FETCH_TIMEOUT_BIN="$FAKE_BIN/timeout" \
   FAKE_COMPILER_FAILURE=1 \
   bash "$FETCH_SCRIPT"; then
  touch "$compile_reached"
else
  status=$?
fi
if (( status == 0 )); then
  echo "expected registry snapshot generation failure" >&2
  exit 1
fi
if [ -e "$compile_reached" ] ||
   [ -e "$OUTPUT_ROOT/tirith-threatdb-sources" ] ||
   [ -e "$OUTPUT_ROOT/tirith-threatdb-sources/source-provenance.json" ]; then
  echo "registry snapshot failure exposed partial publication state" >&2
  exit 1
fi
if compgen -G "$OUTPUT_ROOT/.tirith-threatdb-fetch.*" >/dev/null; then
  echo "registry snapshot failure left private staging state" >&2
  exit 1
fi

# The registry snapshot compiler participates in the same hard transaction
# deadline as network fetches. A hung compiler must be killed and cannot expose
# either source inputs or provenance.
status=0
if PATH="$FAKE_BIN:$PATH" \
   THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
   THREATDB_COMPILER_BIN="$FAKE_BIN/tirith-threatdb-compile" \
   THREATDB_FETCH_TIMEOUT_BIN="$FAKE_BIN/timeout" \
   THREATDB_FETCH_TIMEOUT_SECONDS=5 \
   THREATDB_TRANSACTION_TIMEOUT_SECONDS=8 \
   FAKE_COMPILER_HANG=1 \
   bash "$FETCH_SCRIPT"; then
  touch "$compile_reached"
else
  status=$?
fi
if (( status == 0 )); then
  echo "expected a hung registry snapshot compiler to time out" >&2
  exit 1
fi
if [ -e "$compile_reached" ] || [ -e "$OUTPUT_ROOT/tirith-threatdb-sources" ]; then
  echo "hung registry snapshot compiler exposed publication state" >&2
  exit 1
fi
if compgen -G "$OUTPUT_ROOT/.tirith-threatdb-fetch.*" >/dev/null; then
  echo "hung registry snapshot compiler left private staging state" >&2
  exit 1
fi

# The registry step has its own ceiling. With a generous per-fetch bound and
# transaction deadline, a 1 s registry ceiling must still terminate a hung
# compiler promptly: this proves the registry step is bounded by
# THREATDB_REGISTRY_TIMEOUT_SECONDS rather than by the other two knobs.
status=0
registry_started=$(date +%s)
if PATH="$FAKE_BIN:$PATH" \
   THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
   THREATDB_COMPILER_BIN="$FAKE_BIN/tirith-threatdb-compile" \
   THREATDB_FETCH_TIMEOUT_BIN="$FAKE_BIN/timeout" \
   THREATDB_FETCH_TIMEOUT_SECONDS=60 \
   THREATDB_TRANSACTION_TIMEOUT_SECONDS=120 \
   THREATDB_REGISTRY_TIMEOUT_SECONDS=1 \
   FAKE_COMPILER_HANG=1 \
   bash "$FETCH_SCRIPT"; then
  touch "$compile_reached"
else
  status=$?
fi
registry_elapsed=$(( $(date +%s) - registry_started ))
if (( status == 0 )); then
  echo "expected the registry ceiling to time out a hung compiler" >&2
  exit 1
fi
if (( registry_elapsed >= 30 )); then
  echo "registry ceiling did not bound the hung compiler (took ${registry_elapsed}s)" >&2
  exit 1
fi
if [ -e "$compile_reached" ] || [ -e "$OUTPUT_ROOT/tirith-threatdb-sources" ]; then
  echo "registry ceiling timeout exposed publication state" >&2
  exit 1
fi
if compgen -G "$OUTPUT_ROOT/.tirith-threatdb-fetch.*" >/dev/null; then
  echo "registry ceiling timeout left private staging state" >&2
  exit 1
fi

echo "::${STOP_TOKEN}::"

PATH="$FAKE_BIN:$PATH" \
THREATDB_FETCH_OUTPUT_DIR="$OUTPUT_ROOT" \
THREATDB_FETCH_TIMEOUT_BIN="$FAKE_BIN/timeout" \
THREATDB_COMPILER_BIN="$FAKE_BIN/tirith-threatdb-compile" \
bash "$FETCH_SCRIPT"

published="$OUTPUT_ROOT/tirith-threatdb-sources"
test -d "$published/ossf-mp/.git"
test -d "$published/dd-mp/.git"
test -d "$published/typosquats/.git"
test -s "$published/feodo.txt"
test -s "$published/cisa-kev.json"
test -s "$published/registry-versions.json"
test -s "$published/typosquats/typosquats.csv"

# The resolved upstream revisions must be recorded on the success path only.
test -s "$published/source-provenance.json"
grep -Eq '"commit"[[:space:]]*:[[:space:]]*"54642f7ee96e780b046660519b028fefb635375a"' \
  "$published/source-provenance.json"
grep -Eq '"compiler_version"[[:space:]]*:[[:space:]]*"0.3.3"' \
  "$published/source-provenance.json"
grep -Eq '"schema_version"[[:space:]]*:[[:space:]]*2' \
  "$published/source-provenance.json"
grep -Eq '"spdx"[[:space:]]*:[[:space:]]*"CC-BY-4.0"' \
  "$published/source-provenance.json"
grep -Eq '"spdx"[[:space:]]*:[[:space:]]*"Apache-2.0"' \
  "$published/source-provenance.json"
grep -Eq '"spdx"[[:space:]]*:[[:space:]]*"CC0-1.0"' \
  "$published/source-provenance.json"
grep -Eq '"spdx"[[:space:]]*:[[:space:]]*"LicenseRef-abuse-ch-terms"' \
  "$published/source-provenance.json"
grep -Eq '"spdx"[[:space:]]*:[[:space:]]*"LicenseRef-US-Government-Work"' \
  "$published/source-provenance.json"
grep -Eq '"spdx"[[:space:]]*:[[:space:]]*"LicenseRef-Package-Name-Facts"' \
  "$published/source-provenance.json"
grep -Eq '"content_sha256"[[:space:]]*:[[:space:]]*"[0-9a-f]{64}"' \
  "$published/source-provenance.json"
grep -Eq '"retrieved_at"[[:space:]]*:[[:space:]]*"[0-9]{4}-[0-9]{2}-[0-9]{2}T' \
  "$published/source-provenance.json"
grep -Eq '"commit_timestamp"[[:space:]]*:[[:space:]]*"2026-08-31T18:32:57Z"' \
  "$published/source-provenance.json"
grep -Eq '"pin_selected_at"[[:space:]]*:[[:space:]]*"2026-08-31T19:22:30Z"' \
  "$published/source-provenance.json"

# The single-process tree hasher must remain byte-for-byte compatible with the
# original path-NUL/file-digest-NUL stream format consumed by published source
# provenance. The fixture is intentionally small enough for the legacy oracle.
expected_ossf_digest=$(
  cd -- "$published/ossf-mp"
  find osv -type f -print0 \
    | LC_ALL=C sort -z \
    | while IFS= read -r -d '' file; do
        printf '%s\0' "$file"
        sha256sum "$file" | cut -d' ' -f1 | tr -d '\n'
        printf '\0'
      done \
    | sha256sum \
    | cut -d' ' -f1
)
actual_ossf_digest=$(jq -r '.ossf_malicious_packages.content_sha256' \
  "$published/source-provenance.json")
if [ "$actual_ossf_digest" != "$expected_ossf_digest" ]; then
  echo "single-process content digest is not provenance-compatible: expected $expected_ossf_digest, got $actual_ossf_digest" >&2
  exit 1
fi

# Provenance retention follows the union of retained/protected database
# generations. Generation 20 survives through its protected v1 DB; generation
# 10 loses both formats and therefore loses provenance; orphan generation 5 is
# also pruned.
cat > "$TEST_ROOT/prune-assets.json" <<'EOF'
{"assets":[
  {"name":"tirith-threatdb-30-1.dat"},
  {"name":"tirith-threatdb-v2-30-1.dat"},
  {"name":"threatdb-source-provenance-30-1.json"},
  {"name":"threatdb-source-integrity-30-1.json"},
  {"name":"tirith-threatdb-20-1.dat"},
  {"name":"threatdb-source-provenance-20-1.json"},
  {"name":"threatdb-source-integrity-20-1.json"},
  {"name":"tirith-threatdb-10-1.dat"},
  {"name":"tirith-threatdb-v2-10-1.dat"},
  {"name":"threatdb-source-provenance-10-1.json"},
  {"name":"threatdb-source-integrity-10-1.json"},
  {"name":"threatdb-source-provenance-5-1.json"},
  {"name":"threatdb-source-integrity-5-1.json"}
]}
EOF
actual_prune=$(
  "$SCRIPT_DIR/select-threatdb-prune-assets.sh" \
    "$TEST_ROOT/prune-assets.json" 1 tirith-threatdb-20-1.dat
)
expected_prune=$(printf '%s\n' \
  tirith-threatdb-10-1.dat \
  tirith-threatdb-v2-10-1.dat \
  threatdb-source-provenance-10-1.json \
  threatdb-source-integrity-10-1.json \
  threatdb-source-provenance-5-1.json \
  threatdb-source-integrity-5-1.json)
if [ "$actual_prune" != "$expected_prune" ]; then
  echo "prune selection did not retain/delete provenance in generation lockstep" >&2
  printf 'actual:\n%s\nexpected:\n%s\n' "$actual_prune" "$expected_prune" >&2
  exit 1
fi

# Simulate the workflow's sequential delete loop with a failure on the second
# DB. Because selection is DB-first, no provenance/sidecar may be attempted.
delete_log="$TEST_ROOT/delete-order.log"
status=0
while IFS= read -r asset; do
  printf '%s\n' "$asset" >> "$delete_log"
  if [ "$asset" = "tirith-threatdb-v2-10-1.dat" ]; then
    status=1
    break
  fi
done <<< "$actual_prune"
if (( status == 0 )); then
  echo "expected injected second-DB prune failure" >&2
  exit 1
fi
if grep -q '\.json$' "$delete_log"; then
  echo "provenance deletion was attempted before every DB deletion succeeded" >&2
  exit 1
fi

# Keep the release-provenance merge and its assertion honest: every external
# variable referenced by either jq filter must be bound exactly once by that
# invocation. This catches both a missing --arg and a duplicate --arg before
# GitHub Actions reaches the publication step.
python3 - "$SCRIPT_DIR/../workflows/threatdb.yml" <<'PY'
from collections import Counter
from pathlib import Path
import re
import sys

workflow = Path(sys.argv[1]).read_text(encoding="utf-8")
anchor = workflow.index('SOURCE_INTEGRITY_MANIFEST_SHA=""')
merge_start = workflow.index("          jq -n \\\n", anchor)
validation_start = workflow.index("          jq -e \\\n", merge_start)
validation_end_marker = '            "$SOURCE_PROVENANCE" >/dev/null'
validation_end = workflow.index(validation_end_marker, validation_start) + len(
    validation_end_marker
)


def assert_external_variables_bound_once(label: str, invocation: str) -> None:
    filters = re.findall(r"'([^']*)'", invocation, flags=re.DOTALL)
    if len(filters) != 1:
        raise SystemExit(f"{label}: expected exactly one single-quoted jq filter")
    jq_filter = filters[0]
    referenced = set(re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", jq_filter))
    locally_bound = set(
        re.findall(r"\bas\s+\$([A-Za-z_][A-Za-z0-9_]*)", jq_filter)
    )
    external = referenced - locally_bound - {"ARGS", "ENV", "__loc__"}
    cli_bindings = re.findall(
        r"--(?:arg|argjson|slurpfile|rawfile|argfile)\s+([A-Za-z_][A-Za-z0-9_]*)\b",
        invocation,
    )
    duplicates = sorted(name for name, count in Counter(cli_bindings).items() if count != 1)
    missing = sorted(external - set(cli_bindings))
    if duplicates or missing:
        raise SystemExit(
            f"{label}: invalid jq bindings; missing={missing}, duplicate={duplicates}"
        )


merge = workflow[merge_start:validation_start]
validation = workflow[validation_start:validation_end]
assert_external_variables_bound_once("release provenance merge", merge)
assert_external_variables_bound_once("release provenance validation", validation)

for label, invocation in (("merge", merge), ("validation", validation)):
    if "$integrity_manifest_sha" not in invocation:
        raise SystemExit(f"{label}: source-integrity digest is not covered")
PY

echo "threatdb source-fetch orchestration regression passed"
