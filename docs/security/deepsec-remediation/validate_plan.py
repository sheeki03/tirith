#!/usr/bin/env python3
"""Validate the public DeepSec remediation plan and sanitized ownership ledger."""

import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parents[2]
LEDGER_PATH = ROOT / "remediation-map.json"
PACKAGE_CATALOG_PATH = ROOT / "package-catalog.json"
LEDGER_MANIFEST_PATH = ROOT / "ledger-manifest.json"
HARDENING_PATH = ROOT / "hardening.json"
HARDENING_MD_PATH = ROOT / "hardening.md"
README_PATH = ROOT / "README.md"
PLAN_PATH = ROOT / "implementation" / "stacked-pr-plan.md"
EXPECTED_MANIFEST_SHA256 = "3af16f8a67b21b889a5050f6e5c907fbbd2d1fb5dc19368a761d9e38a94b9af5"

LEDGER_FIELDS = {
    "id",
    "sourceDisposition",
    "reviewedDisposition",
    "priority",
    "canonicalRoot",
    "ownerTrack",
    "ownerPackage",
    "module",
    "status",
}
SOURCE_COUNTS = {
    "already_fixed": 1,
    "do_not_fix_design_decision": 1,
    "do_not_fix_false_positive": 1,
    "duplicate": 61,
    "fix_reliability": 99,
    "fix_security": 383,
    "needs_more_evidence": 3,
}
REVIEWED_COUNTS = {
    "already_fixed": 1,
    "do_not_fix_design_decision": 1,
    "do_not_fix_false_positive": 1,
    "duplicate": 60,
    "fix_reliability": 99,
    "fix_security": 384,
    "needs_more_evidence": 3,
}
PRIORITY_COUNTS = {
    "CLOSED": 1,
    "HOLD": 3,
    "NO-FIX": 62,
    "P0": 15,
    "P1": 164,
    "P2": 205,
    "P3": 99,
}
STATUS_COUNTS = {"action": 483, "closed": 3, "duplicate": 60, "hold": 3}
ACTION_COUNTS = {"R1": 209, "R2": 186, "R3": 88}
DUPLICATE_COUNTS = {"R1": 41, "R2": 14, "R3": 5}
R1_PREREQUISITES = {
    "repo-0203",
    "repo-0204",
    "repo-0207",
    "repo-0252",
    "repo-0258",
    "repo-0283",
    "repo-0310",
    "repo-0316",
    "repo-0317",
    "repo-0336",
    "repo-0337",
    "repo-0351",
    "repo-0352",
    "repo-0397",
    "repo-0425",
    "repo-0426",
    "repo-0427",
    "repo-0428",
    "repo-0460",
    "repo-0461",
    "repo-0468",
    "repo-0469",
    "repo-0493",
    "repo-0494",
    "pr173-0008",
    "pr173-0012",
    "pr173-0013",
    "pr173-0014",
    "pr173-0028",
    "pr173-0029",
}
REVIEW_OVERRIDES = {
    "repo-0161",
    "repo-0191",
    "repo-0205",
    "repo-0206",
    "repo-0403",
    "repo-0411",
    "repo-0469",
    "repo-0476",
}
TRADEOFF_DIMENSIONS = {
    "security",
    "performance",
    "memory",
    "reliability",
    "operability",
    "migration",
}
EXPECTED_BRANCHES = {
    "codex/deepsec-r1-critical-boundaries",
    "codex/deepsec-r2-security-hardening",
    "codex/deepsec-r3-reliability-convergence",
}
FORBIDDEN_FRAGMENTS = (
    "/" + "Users/",
    "\\\\" + "Users\\\\",
    ".deepsec/" + "disposition-audit",
    "deepsec" + "://",
)
LOCAL_ABSOLUTE_ROOTS = (
    "Users",
    "private",
    "home",
    "root",
    "tmp",
    "var",
    "etc",
    "opt",
    "srv",
    "mnt",
    "Volumes",
    "proc",
    "dev",
)


def fail(message):
    raise AssertionError(message)


def expect(actual, expected, label):
    if actual != expected:
        fail("{}: expected {!r}, got {!r}".format(label, expected, actual))


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail("cannot parse {}: {}".format(path.relative_to(ROOT), exc))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical_json_sha256(value):
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return sha256(encoded)


def resolve_relative(source, target):
    candidate = (source.parent / target).resolve()
    try:
        candidate.relative_to(ROOT.resolve())
    except ValueError:
        fail("path escapes plan directory: {} from {}".format(target, source))
    if not candidate.is_file():
        fail("missing referenced file: {} from {}".format(target, source.relative_to(ROOT)))


def resolve_repo_component(target):
    if not isinstance(target, str) or not target or Path(target).is_absolute():
        fail("invalid repository-relative component {!r}".format(target))
    candidate = (REPO_ROOT / target).resolve()
    try:
        candidate.relative_to(REPO_ROOT.resolve())
    except ValueError:
        fail("component escapes repository: {}".format(target))
    if not candidate.exists():
        fail("missing affected component: {}".format(target))


def validate_ledger_manifest():
    raw_manifest = LEDGER_MANIFEST_PATH.read_bytes()
    expect(sha256(raw_manifest), EXPECTED_MANIFEST_SHA256, "locked ledger manifest")
    manifest = load_json(LEDGER_MANIFEST_PATH)
    expect(manifest.get("schemaVersion"), 1, "ledger manifest schema")

    evidence = manifest.get("sourceEvidence", {})
    expect(
        evidence,
        {
            "targetRevision": "e1ec47ef9f43e32872a550522067a680ff659e6e",
            "collectionSha256": "78b14d301abfb978492b2451fec26b7f748e52e84c15c9eeb0725a57f062490a",
            "reportJsonSha256": "a8fb73905e26755c1fff3143723faa2fd4da25df20f98a4405aebd21c20d0dc5",
            "reportMarkdownSha256": "2b4949f45a0b561b98e1967dad86718060d8a683cc0cf8e33cff585bd4cc9f54",
        },
        "source evidence binding",
    )

    artifact_specs = manifest.get("artifacts", {})
    expect(set(artifact_specs), {"remediation-map.json", "package-catalog.json"}, "manifest artifacts")
    for name, path in (
        ("remediation-map.json", LEDGER_PATH),
        ("package-catalog.json", PACKAGE_CATALOG_PATH),
    ):
        spec = artifact_specs[name]
        raw = path.read_bytes()
        parsed = load_json(path)
        expect(sha256(raw), spec.get("sha256"), "raw-byte hash for {}".format(name))
        expect(
            canonical_json_sha256(parsed),
            spec.get("canonicalJsonSha256"),
            "canonical JSON hash for {}".format(name),
        )

    expect(artifact_specs["remediation-map.json"].get("rowCount"), 549, "manifest row count")
    expect(artifact_specs["package-catalog.json"].get("packageCount"), 15, "manifest package count")
    expect(
        manifest.get("reviewedAccounting"),
        {
            "actionRoots": 483,
            "duplicates": 60,
            "holds": 3,
            "closedNoFixOrAlreadyFixed": 3,
            "trackActions": ACTION_COUNTS,
        },
        "manifest reviewed accounting",
    )


def validate_package_catalog():
    catalog = load_json(PACKAGE_CATALOG_PATH)
    expected_top_fields = {
        "schemaVersion",
        "rowCount",
        "canonicalRootCount",
        "actionRootCount",
        "counts",
        "tracks",
        "packages",
        "explicitR1PrerequisiteCount",
        "unassignedNonActionRows",
    }
    expect(set(catalog), expected_top_fields, "package catalog fields")
    expect(catalog["schemaVersion"], 1, "package catalog schema")
    expect(catalog["rowCount"], 549, "catalog row count")
    expect(catalog["canonicalRootCount"], 489, "catalog canonical roots")
    expect(catalog["actionRootCount"], 483, "catalog action roots")
    expect(catalog["explicitR1PrerequisiteCount"], 30, "catalog R1 prerequisites")
    expect(catalog["unassignedNonActionRows"], 6, "catalog unassigned rows")
    expect(catalog["counts"]["sourceDisposition"], SOURCE_COUNTS, "catalog source counts")
    expect(catalog["counts"]["reviewedDisposition"], REVIEWED_COUNTS, "catalog reviewed counts")
    expect(catalog["counts"]["priority"], PRIORITY_COUNTS, "catalog priority counts")
    expect(catalog["counts"]["status"], STATUS_COUNTS, "catalog status counts")

    tracks = catalog.get("tracks")
    if not isinstance(tracks, list) or len(tracks) != 3:
        fail("package catalog must define exactly three tracks")
    track_by_id = {track.get("id"): track for track in tracks}
    expect(set(track_by_id), set(ACTION_COUNTS), "catalog track IDs")
    expect(track_by_id["R1"].get("dependencies"), [], "R1 track dependencies")
    expect(track_by_id["R2"].get("dependencies"), ["R1"], "R2 track dependencies")
    expect(track_by_id["R3"].get("dependencies"), ["R2"], "R3 track dependencies")
    for track_id, track in track_by_id.items():
        expect(track.get("actionRoots"), ACTION_COUNTS[track_id], "{} catalog actions".format(track_id))
        expect(track.get("duplicateRows"), DUPLICATE_COUNTS[track_id], "{} catalog duplicates".format(track_id))
        expect(
            track.get("totalRows"),
            ACTION_COUNTS[track_id] + DUPLICATE_COUNTS[track_id],
            "{} catalog total".format(track_id),
        )

    packages = catalog.get("packages")
    if not isinstance(packages, list):
        fail("package catalog packages must be an array")
    expect(len(packages), 15, "internal package count")
    package_by_code = {package.get("code"): package for package in packages}
    if len(package_by_code) != len(packages) or None in package_by_code:
        fail("package codes must be present and unique")

    for code, package in package_by_code.items():
        if not re.fullmatch(r"R[123]-[A-Z]+", code):
            fail("invalid package code {}".format(code))
        if package.get("track") not in ACTION_COUNTS:
            fail("{} has invalid track".format(code))
        if not code.startswith(package["track"] + "-"):
            fail("{} does not match its track".format(code))
        if not re.fullmatch(r"[a-z0-9-]+", package.get("label", "")):
            fail("{} has an invalid label".format(code))
        for field in ("actionRoots", "duplicateRows", "totalRows"):
            if not isinstance(package.get(field), int) or package[field] < 0:
                fail("{} has invalid {}".format(code, field))
        expect(
            package["totalRows"],
            package["actionRoots"] + package["duplicateRows"],
            "{} package total".format(code),
        )
        dependencies = package.get("dependencies")
        if not isinstance(dependencies, list) or len(dependencies) != len(set(dependencies)):
            fail("{} dependencies must be a unique array".format(code))
        for dependency in dependencies:
            if dependency not in package_by_code:
                fail("{} references missing dependency {}".format(code, dependency))

    visiting = set()
    visited = set()

    def visit(code):
        if code in visiting:
            fail("package dependency cycle at {}".format(code))
        if code in visited:
            return
        visiting.add(code)
        for dependency in package_by_code[code]["dependencies"]:
            visit(dependency)
        visiting.remove(code)
        visited.add(code)

    for code in package_by_code:
        visit(code)

    expect(sum(package["actionRoots"] for package in packages), 483, "catalog package actions")
    expect(sum(package["duplicateRows"] for package in packages), 60, "catalog package duplicates")
    return package_by_code


def validate_ledger(package_by_code):
    rows = load_json(LEDGER_PATH)
    if not isinstance(rows, list):
        fail("remediation-map.json must contain a JSON array")
    expect(len(rows), 549, "ledger row count")

    expected_ids = (
        ["repo-{:04d}".format(index) for index in range(1, 503)]
        + ["pr173-{:04d}".format(index) for index in range(1, 30)]
        + ["pr172-{:04d}".format(index) for index in range(1, 19)]
    )
    ids = [row.get("id") for row in rows]
    if ids != expected_ids:
        mismatch = next(
            (
                (index, expected, actual)
                for index, (expected, actual) in enumerate(zip(expected_ids, ids), 1)
                if expected != actual
            ),
            (min(len(expected_ids), len(ids)) + 1, "<end>", "<end>"),
        )
        fail(
            "ledger ID order differs at row {}: expected {}, got {}".format(
                mismatch[0], mismatch[1], mismatch[2]
            )
        )

    for row in rows:
        expect(set(row), LEDGER_FIELDS, "field whitelist for {}".format(row.get("id")))
        if not isinstance(row["module"], str) or not re.fullmatch(r"[a-z0-9_]+", row["module"]):
            fail("{} has an invalid coarse module".format(row["id"]))
        for field, value in row.items():
            if isinstance(value, str) and ("://" in value or "\n" in value or "\r" in value):
                fail("{} field {} contains non-ledger content".format(row["id"], field))

    expect(
        dict(Counter(row["sourceDisposition"] for row in rows)),
        SOURCE_COUNTS,
        "source dispositions",
    )
    expect(
        dict(Counter(row["reviewedDisposition"] for row in rows)),
        REVIEWED_COUNTS,
        "reviewed dispositions",
    )
    expect(dict(Counter(row["priority"] for row in rows)), PRIORITY_COUNTS, "priorities")
    expect(dict(Counter(row["status"] for row in rows)), STATUS_COUNTS, "statuses")

    overrides = {
        row["id"]
        for row in rows
        if row["sourceDisposition"] != row["reviewedDisposition"]
    }
    expect(overrides, REVIEW_OVERRIDES, "reviewed disposition overrides")

    by_id = {row["id"]: row for row in rows}
    canonical_roots = {row["canonicalRoot"] for row in rows}
    expect(len(canonical_roots), 489, "canonical root count")

    for row in rows:
        root = by_id.get(row["canonicalRoot"])
        if root is None:
            fail("{} references missing canonical root {}".format(row["id"], row["canonicalRoot"]))

        if row["status"] == "action":
            expect(row["canonicalRoot"], row["id"], "self root for {}".format(row["id"]))
            if row["ownerTrack"] not in ACTION_COUNTS:
                fail("{} lacks an R1/R2/R3 owner".format(row["id"]))
            if row["ownerPackage"] not in package_by_code:
                fail("{} lacks a valid internal package".format(row["id"]))
            expect(
                package_by_code[row["ownerPackage"]]["track"],
                row["ownerTrack"],
                "package track for {}".format(row["id"]),
            )
            if row["reviewedDisposition"] not in {"fix_security", "fix_reliability"}:
                fail("{} is actionable with a no-fix disposition".format(row["id"]))
        elif row["status"] == "duplicate":
            if root["status"] != "action":
                fail("{} does not point directly to an actionable root".format(row["id"]))
            expect(row["ownerTrack"], root["ownerTrack"], "duplicate owner for {}".format(row["id"]))
            expect(row["ownerPackage"], root["ownerPackage"], "duplicate package for {}".format(row["id"]))
        else:
            expect(row["ownerTrack"], None, "non-action owner for {}".format(row["id"]))
            expect(row["ownerPackage"], None, "non-action package for {}".format(row["id"]))

    action_counts = Counter(row["ownerTrack"] for row in rows if row["status"] == "action")
    duplicate_counts = Counter(row["ownerTrack"] for row in rows if row["status"] == "duplicate")
    expect(dict(action_counts), ACTION_COUNTS, "R1/R2/R3 actionable allocation")
    expect(dict(duplicate_counts), DUPLICATE_COUNTS, "R1/R2/R3 duplicate allocation")

    for row in rows:
        if row["status"] != "action":
            continue
        if row["priority"] in {"P0", "P1"}:
            expect(row["ownerTrack"], "R1", "high-priority owner for {}".format(row["id"]))
        elif row["ownerTrack"] == "R2":
            expect(row["priority"], "P2", "R2 priority for {}".format(row["id"]))
        elif row["ownerTrack"] == "R3":
            expect(row["priority"], "P3", "R3 priority for {}".format(row["id"]))

    prerequisites = {
        row["id"]
        for row in rows
        if row["status"] == "action"
        and row["ownerTrack"] == "R1"
        and row["priority"] in {"P2", "P3"}
    }
    expect(prerequisites, R1_PREREQUISITES, "explicit R1 prerequisite roots")

    for code, package in package_by_code.items():
        package_actions = sum(
            row["status"] == "action" and row["ownerPackage"] == code for row in rows
        )
        package_duplicates = sum(
            row["status"] == "duplicate" and row["ownerPackage"] == code for row in rows
        )
        expect(package_actions, package["actionRoots"], "{} ledger actions".format(code))
        expect(package_duplicates, package["duplicateRows"], "{} ledger duplicates".format(code))

    promoted = by_id["repo-0476"]
    expect(promoted["reviewedDisposition"], "fix_reliability", "repo-0476 disposition")
    expect(promoted["priority"], "P3", "repo-0476 priority")
    expect(promoted["canonicalRoot"], "repo-0476", "repo-0476 canonical root")
    expect(promoted["ownerTrack"], "R3", "repo-0476 owner")


def validate_hardening():
    hardening = load_json(HARDENING_PATH)
    opportunities = hardening.get("opportunities")
    if not isinstance(opportunities, list):
        fail("hardening.json opportunities must be an array")
    expect(len(opportunities), 4, "hardening opportunity count")
    resolve_relative(HARDENING_PATH, hardening.get("implementationPlanPath", ""))

    opportunity_ids = set()
    for opportunity in opportunities:
        opportunity_id = opportunity.get("opportunityId")
        if not isinstance(opportunity_id, str) or not opportunity_id:
            fail("hardening opportunity lacks an ID")
        if opportunity_id in opportunity_ids:
            fail("duplicate hardening opportunity {}".format(opportunity_id))
        opportunity_ids.add(opportunity_id)
        resolve_relative(HARDENING_PATH, opportunity.get("proposalPath", ""))

        options = opportunity.get("options")
        if not isinstance(options, list):
            fail("{} options must be an array".format(opportunity_id))
        expect(len(options), 2, "option count for {}".format(opportunity_id))
        option_ids = {option.get("optionId") for option in options}
        if opportunity.get("recommendedOptionId") not in option_ids:
            fail("{} recommendation does not identify an option".format(opportunity_id))

        for option in options:
            option_id = option.get("optionId")
            dimensions = {entry.get("dimension") for entry in option.get("tradeoffs", [])}
            expect(dimensions, TRADEOFF_DIMENSIONS, "tradeoffs for {}".format(option_id))
            for entry in option.get("tradeoffs", []):
                for field in ("direction", "confidence", "basis", "assessment", "validationPlan"):
                    if not entry.get(field):
                        fail("{} tradeoff lacks {}".format(option_id, field))
            diagram_paths = option.get("diagramPaths", {})
            if not isinstance(diagram_paths, dict) or set(diagram_paths) != {"before", "after"}:
                fail("{} must provide before and after diagrams".format(option_id))
            for diagram in diagram_paths.values():
                resolve_relative(HARDENING_PATH, diagram)
            readiness = option.get("implementationReadiness", {})
            for field in ("affectedComponents", "workPackages", "acceptanceCriteria", "rollback"):
                if not readiness.get(field):
                    fail("{} readiness lacks {}".format(option_id, field))
            for component in readiness.get("affectedComponents", []):
                resolve_repo_component(component)


def validate_plan_topology():
    narratives = {
        README_PATH: README_PATH.read_text(encoding="utf-8"),
        HARDENING_MD_PATH: HARDENING_MD_PATH.read_text(encoding="utf-8"),
        PLAN_PATH: PLAN_PATH.read_text(encoding="utf-8"),
    }
    combined = "\n".join(narratives.values())
    branches = set(re.findall(r"codex/deepsec-r[1-9][a-z0-9-]*", combined))
    expect(branches, EXPECTED_BRANCHES, "implementation branch set")

    required_phrases = {
        README_PATH: "exactly three stacked implementation PRs",
        HARDENING_MD_PATH: "exactly three stacked implementation PRs",
        PLAN_PATH: "exactly three implementation PRs",
    }
    for path, phrase in required_phrases.items():
        if phrase not in narratives[path]:
            fail("{} does not state the three-PR constraint".format(path.relative_to(ROOT)))

    hardening = load_json(HARDENING_PATH)
    expect(hardening.get("constraints", {}).get("maxImplementationPrs"), 3, "hardening PR cap")
    if "three-PR remediation stack" not in hardening.get("assessment", {}).get("summary", ""):
        fail("hardening.json assessment does not state the three-PR topology")

    expected_rows = {
        "R1": (209, 41),
        "R2": (186, 14),
        "R3": (88, 5),
    }
    table_row = re.compile(
        r"^\|\s*(R[123])(?:\s+[^|]*)?\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*$",
        re.MULTILINE,
    )
    for path in (README_PATH, PLAN_PATH):
        found = {
            track: (int(actions), int(duplicates))
            for track, actions, duplicates in table_row.findall(narratives[path])
        }
        expect(found, expected_rows, "track table in {}".format(path.relative_to(ROOT)))

    for track, count in ACTION_COUNTS.items():
        marker = "{} actionable roots".format(count)
        if marker not in narratives[PLAN_PATH]:
            fail("implementation plan does not state {} ownership".format(track))


def validate_disclosure_text(path, text):
    label = path.relative_to(ROOT)
    for fragment in FORBIDDEN_FRAGMENTS:
        if fragment in text:
            fail("{} contains forbidden disclosure fragment {!r}".format(label, fragment))
    for root_name in LOCAL_ABSOLUTE_ROOTS:
        prefix = "/" + root_name
        position = text.find(prefix)
        while position != -1:
            end = position + len(prefix)
            following = text[end : end + 1]
            if not following or following in "/\\ \t\r\n`'\"),;]}":
                fail("{} contains a local absolute path rooted at {}".format(label, prefix))
            position = text.find(prefix, position + 1)
    if "file" + "://" in text:
        fail("{} contains a local file URI".format(label))
    if re.search(r"(?i)(?<![A-Za-z0-9])[A-Z]:[\\/]", text):
        fail("{} contains a Windows drive path".format(label))
    if path.suffix.lower() != ".py" and "\\\\" in text:
        fail("{} contains a possible UNC path".format(label))


def validate_links_and_disclosure():
    distributable = sorted(
        path
        for path in ROOT.rglob("*")
        if path.is_file() and path.suffix.lower() in {".json", ".md", ".mmd", ".py"}
    )
    markdown_link = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for path in distributable:
        text = path.read_text(encoding="utf-8")
        validate_disclosure_text(path, text)
        if path.suffix.lower() == ".md":
            for target in markdown_link.findall(text):
                target = target.strip()
                if target.startswith(("http://", "https://", "#")):
                    continue
                target = target.split("#", 1)[0]
                if target:
                    resolve_relative(path, target)


def main():
    validate_ledger_manifest()
    packages = validate_package_catalog()
    validate_ledger(packages)
    validate_hardening()
    validate_plan_topology()
    validate_links_and_disclosure()
    print("PASS: 549 rows, 483 actions, 60 duplicates, exactly three implementation PRs")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, OSError, UnicodeError) as exc:
        print("FAIL: {}".format(exc), file=sys.stderr)
        sys.exit(1)
