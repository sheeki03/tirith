#!/bin/sh
# Fail when a benchmark exceeds its absolute ceiling.
#
# Usage: scripts/check-bench-budgets.sh <bencher-output-file> [budgets-file]
#
# Reads Criterion's bencher-format output:
#
#   test tier1_no_match ... bench:         314 ns/iter (+/- 41)
#
# and compares each result to `crates/tirith-core/benches/budgets.txt`. Both
# directions are errors: a budgeted benchmark missing from the run means the
# gate silently stopped covering it, and a benchmark in the run with no budget
# means a hot path arrived unmeasured.
#
# POSIX sh + awk on purpose: this runs on the same runner as `cargo bench` and
# must not need a language runtime the workflow does not already install.
set -eu

output="${1:?usage: check-bench-budgets.sh <bencher-output> [budgets-file]}"
budgets="${2:-crates/tirith-core/benches/budgets.txt}"

[ -r "$output" ] || { echo "bench output not readable: $output" >&2; exit 2; }
[ -r "$budgets" ] || { echo "budgets file not readable: $budgets" >&2; exit 2; }

awk -v budgets="$budgets" '
BEGIN {
    while ((getline line < budgets) > 0) {
        sub(/#.*/, "", line)
        n = split(line, field, /[ \t]+/)
        name = ""; limit = ""
        for (i = 1; i <= n; i++) {
            if (field[i] == "") continue
            if (name == "") { name = field[i]; continue }
            if (limit == "") { limit = field[i]; continue }
        }
        if (name != "" && limit != "") {
            budget[name] = limit + 0
            declared[name] = 1
        }
    }
    close(budgets)
    failures = 0
    checked = 0
}

# test <name> ... bench: <value> ns/iter (+/- <dev>)
/^test .* bench:/ {
    name = $2
    for (i = 1; i <= NF; i++) {
        if ($i == "bench:") { value = $(i + 1) + 0; break }
    }
    seen[name] = 1
    if (!(name in budget)) {
        printf "NO BUDGET  %-34s %12d ns/iter (add it to %s)\n", name, value, budgets
        failures++
        next
    }
    checked++
    if (value > budget[name]) {
        printf "OVER       %-34s %12d ns/iter > budget %d\n", name, value, budget[name]
        failures++
    } else {
        percent = budget[name] > 0 ? (value * 100) / budget[name] : 0
        printf "ok         %-34s %12d ns/iter (%.0f%% of %d)\n", name, value, percent, budget[name]
    }
}

END {
    for (name in declared) {
        if (!(name in seen)) {
            printf "MISSING    %-34s budgeted but absent from this run\n", name
            failures++
        }
    }
    if (checked == 0) {
        print "no benchmark results parsed; refusing to report success"
        exit 2
    }
    if (failures > 0) {
        printf "\n%d benchmark budget failure(s)\n", failures
        exit 1
    }
    printf "\nall %d benchmarks inside their absolute budgets\n", checked
}
' "$output"
