#!/usr/bin/env bash

# Print release assets eligible for deletion. V1 and v2 databases retain their
# own newest KEEP generations, discovery-protected databases are never removed,
# and a generation's provenance is removed only when no database from that
# run/attempt remains after the proposed deletion set.

set -euo pipefail

if (( $# < 2 )); then
  echo "usage: $0 <assets.json> <keep> [protected-db-asset ...]" >&2
  exit 64
fi

ASSETS_JSON=$1
KEEP=$2
shift 2
case "$KEEP" in
  ''|*[!0-9]*|0)
    echo "keep must be a positive integer" >&2
    exit 64
    ;;
esac

PROTECTED_JSON=$(printf '%s\n' "$@" | jq -Rsc 'split("\n") | map(select(length > 0))')

jq -r --argjson keep "$KEEP" --argjson protected "$PROTECTED_JSON" '
  def v1: test("^tirith-threatdb-[0-9]+-[0-9]+\\.dat$");
  def v2: test("^tirith-threatdb-v2-[0-9]+-[0-9]+\\.dat$");
  def provenance: test("^threatdb-source-(?:provenance|integrity)-[0-9]+-[0-9]+\\.json$");
  def generation:
    if v1 then capture("^tirith-threatdb-(?<run>[0-9]+)-(?<attempt>[0-9]+)\\.dat$")
    elif v2 then capture("^tirith-threatdb-v2-(?<run>[0-9]+)-(?<attempt>[0-9]+)\\.dat$")
    elif provenance then capture("^threatdb-source-(?:provenance|integrity)-(?<run>[0-9]+)-(?<attempt>[0-9]+)\\.json$")
    else error("asset has no generation: " + .)
    end | .run + "-" + .attempt;
  def newest_first($pattern):
    map(select(test($pattern)))
    | sort_by(capture("^(?:tirith-threatdb(?:-v2)?|threatdb-source-(?:provenance|integrity))-(?<run>[0-9]+)-(?<attempt>[0-9]+)(?:\\.dat|\\.json)$") | [(.run | tonumber), (.attempt | tonumber)])
    | reverse;

  [.assets[].name] as $names
  | ($names | newest_first("^tirith-threatdb-[0-9]+-[0-9]+\\.dat$") | .[$keep:]) as $stale_v1
  | ($names | newest_first("^tirith-threatdb-v2-[0-9]+-[0-9]+\\.dat$") | .[$keep:]) as $stale_v2
  | (($stale_v1 + $stale_v2) | map(select(. as $name | $protected | index($name) | not))) as $delete_dbs
  | ($names | map(select(v1 or v2)) - $delete_dbs | map(generation) | unique) as $retained_generations
  | ($names | map(select(provenance and ((generation as $g | $retained_generations | index($g)) | not)))) as $delete_provenance
  # Phase order is security-significant: every selected DB must be deleted
  # successfully before any provenance/sidecar from its generation disappears.
  | $delete_dbs[], $delete_provenance[]
' "$ASSETS_JSON"
