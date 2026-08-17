#!/usr/bin/env python3
"""Independent, dependency-free validator and release gate for the remediation ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
SOURCE_INDEX_PATH = HERE / "source-index.json"
FINDINGS_PATH = HERE / "findings.json"
RENDERER = HERE / "render_main.py"

REPORT_ORDER = ["stack", "addendum", "additional", "original"]
REPORT_COUNTS = {"stack": 26, "addendum": 1, "additional": 41, "original": 67}
REPORT_SPECS = {
    "stack": {
        "path": "sources/stack-report.md",
        "origin_sha256": "ec0b8361cad4bca54b60df61cb9b5b93c4de2ff0737b9b1121d6fa1debd09abc",
        "normalized_sha256": "9458454bb20355c2ff4d6239545378e1db99290b05197ca258e1d42d68ec8d5e",
        "line_count": 98,
        "byte_count": 13758,
        "starts": [23, 25, 29, 31, 33, 37, 39, 41, 43, 45, 48, 52, 54, 56, 58, 60, 62, 64, 66, 68, 72, 74, 76, 78, 80, 82],
        "prefix": "STACK",
        "offset": 0,
        "vulnerable_commit": "e9cf7c602b664da195700d8cca0ca5565e4dec4d",
    },
    "addendum": {
        "path": "sources/npm-harness-addendum.md",
        "origin_sha256": "d6c65892df67f0149792ad23f379adfdf8d3f26872436fab90a72b7cf3c876a9",
        "normalized_sha256": "d6c65892df67f0149792ad23f379adfdf8d3f26872436fab90a72b7cf3c876a9",
        "line_count": 1,
        "byte_count": 305,
        "starts": [1],
        "prefix": "ADDENDUM",
        "offset": 26,
        "vulnerable_commit": "e9cf7c602b664da195700d8cca0ca5565e4dec4d",
    },
    "additional": {
        "path": "sources/additional-report.md",
        "origin_sha256": "2c513128cce572167cce567164a9c2c36d6e0e70438abe0e1ed94a93ccde60fb",
        "normalized_sha256": "03421275563636a3fa538c594362afefd9377e11ee316ee211894b8526a8bfd2",
        "line_count": 101,
        "byte_count": 9319,
        "starts": list(range(5, 34, 2)) + list(range(37, 84, 2)) + [87, 89],
        "prefix": "ADDITIONAL",
        "offset": 27,
        "vulnerable_commit": "d7ce6b3689da539e6e7e11cc4f2ac66bc6bba7ad",
    },
    "original": {
        "path": "sources/original-report.md",
        "origin_sha256": "f2da4794ed84586911512ddeba9708b52864dfd972bd326c79a69688a4729b5e",
        "normalized_sha256": "2dcc8c7062243c39fb713915b0a3c081b3ead595b0eb7de00c6d2b4c172f7b95",
        "line_count": 120,
        "byte_count": 16695,
        "starts": [7] + list(range(11, 32, 2)) + list(range(37, 47)) + list(range(50, 56)) + list(range(59, 66)) + list(range(69, 76)) + list(range(79, 90)) + list(range(93, 107)),
        "prefix": "ORIGINAL",
        "offset": 68,
        "vulnerable_commit": "d7ce6b3689da539e6e7e11cc4f2ac66bc6bba7ad",
    },
}
EXACT_DUPLICATES = {
    "ORIGINAL-001": "STACK-001",
    "ORIGINAL-014": "STACK-002",
    "ORIGINAL-042": "ADDITIONAL-011",
    "ORIGINAL-048": "ADDITIONAL-035",
}
EXACT_DUPLICATE_RATIONALES = {
    "ORIGINAL-001": "Same MCP TIRITH=0 enforcement bypass reported at the baseline and cumulative stack revisions",
    "ORIGINAL-014": "Same multiple-command-field inspection and forwarding mismatch reported at the baseline and cumulative stack revisions",
    "ORIGINAL-042": "Same mutable github/codeql-action/upload-sarif@v3 dependency reported by both audits",
    "ORIGINAL-048": "Same concurrent daemon-startup cleanup race reported by both audits",
}
OWNER_FINDINGS = {
    "pr-197": set(range(3, 6)),
    "pr-198": set(range(6, 12)),
    "pr-201": {*range(12, 21), 27},
    "pr-199": set(range(21, 27)),
    "poststack-gateway-runtime": {1, 2, 74, 75, 80, 83, *range(85, 89)},
    "poststack-mcp-identity": {72, 73, 76, 81, 82, 84},
    "poststack-network-license": {*range(58, 62), *range(102, 106), 107, 118, 119, 130},
    "poststack-artifact-analysis": {*range(28, 35), 41, *range(43, 51), 69, *range(89, 92), 93, 94, 120, 122, 131},
    "poststack-state-integrity": {66, 67, *range(95, 102), *range(124, 129)},
    "poststack-user-integrations": {*range(35, 38), *range(51, 56), *range(63, 66), 68, 123},
    "poststack-containment-daemon": {42, 62, 71, 77, *range(108, 118), 129},
    "poststack-release-convergence": {*range(38, 41), 56, 57, 70, 78, 79, 92, 106, 121},
}
OWNERS = set(OWNER_FINDINGS)
LIFECYCLES = [
    "confirmed_open",
    "reproduced",
    "implemented",
    "layer_verified",
    "stack_verified",
    "ready_to_merge",
    "merged_verified",
]
ROUTES = ["local", "upstream_candidate", "upstream_verified"]
SEVERITIES = {"critical", "high", "medium", "low", "untriaged"}
MAPPING_TYPES = {"exact_duplicate", "partial_overlap", "related", "superseded"}
ATTEMPT_KINDS = {
    "baseline",
    "focused",
    "benign",
    "adversarial",
    "platform",
    "performance",
    "ux",
    "packaging",
    "review",
    "release",
}
ATTEMPT_KEYS = {
    "kind",
    "base_sha",
    "head_sha",
    "merge_tree_sha",
    "subject_tree_hash",
    "workflow_sha",
    "os",
    "os_version",
    "arch",
    "toolchain",
    "command",
    "result",
    "log_or_attestation_id",
    "date",
}
BUNDLE_CHECK_KEYS = {
    "kind",
    "os",
    "os_version",
    "arch",
    "toolchain",
    "command",
    "result",
    "log_or_attestation_id",
    "date",
}
HISTORY_EVENTS = {
    "imported",
    "lifecycle_changed",
    "reopened",
    "invalidated",
    "regressed",
    "blocker_added",
    "blocker_cleared",
    "route_changed",
    "evidence_added",
}
RESET_EVENTS = {"reopened", "invalidated", "regressed"}
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
FINDING_RE = re.compile(r"^TIRITH-SEC-\d{4}$")
CLAIM_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
BLOCKER_RE = re.compile(r"^blocked_[a-z0-9_]+$")

SOURCE_TOP_KEYS = {
    "schema_version",
    "normalization",
    "report_order",
    "expected_counts",
    "reports",
    "sources",
}
SOURCE_KEYS = {
    "source_id",
    "ledger_ordinal",
    "report_id",
    "report_ordinal",
    "section",
    "reported_severity",
    "normalized_severity",
    "title",
    "vulnerable_commit",
    "source_locator",
    "block_sha256",
    "evidence",
}
FINDING_KEYS = {
    "finding_id",
    "title",
    "severity",
    "owner",
    "lifecycle",
    "resolution_route",
    "blockers",
    "vulnerable_commits",
    "source_links",
    "preconditions",
    "reproduction",
    "remediation",
    "verification",
    "review",
    "history",
}


class ValidationError(Exception):
    pass


def fail(message: str) -> None:
    raise ValidationError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_canonical(path: Path) -> Any:
    try:
        label = str(path.relative_to(ROOT))
    except ValueError:
        label = str(path)
    try:
        raw = path.read_text(encoding="utf-8")
        value = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"{label}: cannot load canonical JSON: {exc}")
    require(raw == canonical_json(value), f"{label}: JSON is not canonical")
    return value


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    require(actual == expected, f"{label}: keys differ; missing={sorted(expected-actual)}, extra={sorted(actual-expected)}")


def source_block(lines: list[str], start: int) -> tuple[str, int]:
    index = start - 1
    end = index + 1
    while end < len(lines) and lines[end].strip():
        end += 1
    return "\n".join(lines[index:end]).rstrip() + "\n", end


def validate_repo_path(path: Any, label: str) -> None:
    require(isinstance(path, str) and path, f"{label}: path must be nonempty")
    parsed = PurePosixPath(path)
    require(not parsed.is_absolute(), f"{label}: absolute path forbidden")
    require(".." not in parsed.parts and "." not in parsed.parts, f"{label}: escaping path forbidden")
    require("\\" not in path and "\x00" not in path, f"{label}: non-portable path forbidden")
    require(not path.startswith("file:"), f"{label}: URI path forbidden")
    require("/Users/" not in path and "/home/" not in path, f"{label}: local user path forbidden")


def validate_source_index(source_index: dict[str, Any]) -> dict[str, dict[str, Any]]:
    exact_keys(source_index, SOURCE_TOP_KEYS, "source-index")
    require(source_index["schema_version"] == 1, "source-index: unsupported schema_version")
    require(
        source_index["normalization"] == "UTF-8; CRLF and CR converted to LF; exactly one terminal LF",
        "source-index: normalization contract changed",
    )
    require(source_index["report_order"] == REPORT_ORDER, "source-index: report order changed")
    require(
        source_index["expected_counts"] == {"total": 135, "by_report": REPORT_COUNTS},
        "source-index: expected counts must be exactly 26+1+41+67=135",
    )
    require(len(source_index["reports"]) == 4, "source-index: exactly four source artifacts required")
    require(len(source_index["sources"]) == 135, "source-index: exactly 135 rows required")

    expected_ids: list[str] = []
    expected_rows: dict[str, tuple[dict[str, Any], int, int, str, int]] = {}
    for position, report_id in enumerate(REPORT_ORDER):
        spec = REPORT_SPECS[report_id]
        report = source_index["reports"][position]
        expected_report = {
            "report_id": report_id,
            "path": spec["path"],
            "origin_sha256": spec["origin_sha256"],
            "normalized_sha256": spec["normalized_sha256"],
            "line_count": spec["line_count"],
            "byte_count": spec["byte_count"],
            "expected_rows": REPORT_COUNTS[report_id],
            "vulnerable_commit": spec["vulnerable_commit"],
        }
        require(report == expected_report, f"source-index: report metadata changed for {report_id}")
        source_path = HERE / spec["path"]
        raw = source_path.read_bytes()
        require(len(raw) == spec["byte_count"], f"{spec['path']}: byte count changed")
        require(sha256(raw) == spec["normalized_sha256"], f"{spec['path']}: immutable digest changed")
        try:
            text = raw.decode("utf-8")
        except UnicodeError as exc:
            fail(f"{spec['path']}: invalid UTF-8: {exc}")
        require("\r" not in text and text.endswith("\n") and not text.endswith("\n\n"), f"{spec['path']}: normalization changed")
        lines = text.rstrip("\n").split("\n")
        require(len(lines) == spec["line_count"], f"{spec['path']}: line count changed")
        for ordinal, start in enumerate(spec["starts"], 1):
            source_id = f"{spec['prefix']}-{ordinal:03d}"
            if report_id == "original":
                block, end = lines[start - 1].rstrip() + "\n", start
            else:
                block, end = source_block(lines, start)
            ledger_ordinal = spec["offset"] + ordinal
            expected_ids.append(source_id)
            expected_rows[source_id] = (spec, ordinal, start, sha256(block.encode("utf-8")), end)

    seen_ids: set[str] = set()
    for position, row in enumerate(source_index["sources"], 1):
        require(isinstance(row, dict), f"source row {position}: object required")
        exact_keys(row, SOURCE_KEYS, f"source row {position}")
        source_id = row["source_id"]
        require(source_id == expected_ids[position - 1], f"source row {position}: deterministic ID/order changed")
        require(source_id not in seen_ids, f"{source_id}: duplicate source ID")
        seen_ids.add(source_id)
        spec, ordinal, start, block_hash, end = expected_rows[source_id]
        require(row["ledger_ordinal"] == position, f"{source_id}: ledger ordinal changed")
        require(row["report_id"] in REPORT_ORDER, f"{source_id}: invalid report")
        require(row["report_ordinal"] == ordinal, f"{source_id}: report ordinal changed")
        require(row["vulnerable_commit"] == spec["vulnerable_commit"], f"{source_id}: vulnerable commit changed")
        require(COMMIT_RE.fullmatch(row["vulnerable_commit"]) is not None, f"{source_id}: invalid vulnerable commit")
        require(isinstance(row["title"], str) and row["title"].strip(), f"{source_id}: title required")
        require(isinstance(row["section"], str) and row["section"], f"{source_id}: section required")
        require(row["reported_severity"] is None or isinstance(row["reported_severity"], str), f"{source_id}: reported severity invalid")
        require(row["normalized_severity"] in SEVERITIES - {"untriaged"} | {None}, f"{source_id}: normalized severity invalid")
        locator = row["source_locator"]
        require(
            locator == {"path": spec["path"], "line_start": start, "line_end": end},
            f"{source_id}: source locator changed",
        )
        require(row["block_sha256"] == block_hash, f"{source_id}: source block digest changed")
        require(HASH_RE.fullmatch(row["block_sha256"]) is not None, f"{source_id}: invalid block digest")
        require(isinstance(row["evidence"], list), f"{source_id}: evidence must be an array")
        seen_evidence: set[tuple[Any, ...]] = set()
        for evidence in row["evidence"]:
            exact_keys(evidence, {"path", "line_start", "line_end", "commit"}, f"{source_id} evidence")
            validate_repo_path(evidence["path"], f"{source_id} evidence")
            require(COMMIT_RE.fullmatch(evidence["commit"]) is not None, f"{source_id}: invalid evidence commit")
            require(
                isinstance(evidence["line_start"], int)
                and isinstance(evidence["line_end"], int)
                and 1 <= evidence["line_start"] <= evidence["line_end"],
                f"{source_id}: invalid evidence line range",
            )
            key = (evidence["path"], evidence["line_start"], evidence["line_end"], evidence["commit"])
            require(key not in seen_evidence, f"{source_id}: duplicate evidence")
            seen_evidence.add(key)
    return {row["source_id"]: row for row in source_index["sources"]}


def git_is_ancestor(commit: str, head: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, head],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def synthetic_merge_tree(base_sha: str, head_sha: str) -> str:
    result = subprocess.run(
        ["git", "merge-tree", "--write-tree", base_sha, head_sha],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    require(result.returncode == 0, f"{base_sha} + {head_sha}: synthetic merge conflicts or failed")
    tree = result.stdout.splitlines()[0].strip() if result.stdout else ""
    require(COMMIT_RE.fullmatch(tree) is not None, "synthetic merge did not return a tree SHA")
    return tree


def subject_tree_hash(tree_sha: str, closure_bundle_path: str) -> str:
    result = subprocess.run(
        ["git", "ls-tree", "-r", "-z", "--full-tree", tree_sha],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    require(result.returncode == 0, f"{tree_sha}: cannot enumerate subject tree")
    entries: list[str] = []
    for raw_entry in result.stdout.split(b"\0"):
        if not raw_entry:
            continue
        metadata, raw_path = raw_entry.split(b"\t", 1)
        mode, _object_type, object_id = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8", "strict")
        if (
            path == "main.md"
            or path.startswith("docs/security/remediation/")
            or path == closure_bundle_path
        ):
            continue
        entries.append(f"{mode} {object_id} {path}")
    payload = "".join(f"{entry}\n" for entry in sorted(entries)).encode("utf-8")
    return sha256(payload)


def validate_attempt(value: Any, label: str, closure_bundle_path: str) -> None:
    require(isinstance(value, dict), f"{label}: object required")
    exact_keys(value, ATTEMPT_KEYS, label)
    require(value["kind"] in ATTEMPT_KINDS, f"{label}: invalid kind")
    for field in ("base_sha", "head_sha", "merge_tree_sha", "workflow_sha"):
        require(COMMIT_RE.fullmatch(value[field]) is not None, f"{label}: {field} must be a full SHA")
    require(HASH_RE.fullmatch(value["subject_tree_hash"]) is not None, f"{label}: subject tree hash invalid")
    for field in ("os", "os_version", "arch", "toolchain", "command", "log_or_attestation_id"):
        require(isinstance(value[field], str) and value[field].strip(), f"{label}: {field} required")
    require(value["result"] in {"passed", "failed", "blocked_native"}, f"{label}: invalid result")
    require(DATE_RE.fullmatch(value["date"]) is not None, f"{label}: ISO date required")
    require(
        synthetic_merge_tree(value["base_sha"], value["head_sha"]) == value["merge_tree_sha"],
        f"{label}: merge_tree_sha does not bind synthetic base+head merge",
    )
    require(
        git_is_ancestor(value["workflow_sha"], value["base_sha"])
        or git_is_ancestor(value["workflow_sha"], value["head_sha"]),
        f"{label}: workflow SHA is not in base or head history",
    )
    require(
        subject_tree_hash(value["merge_tree_sha"], closure_bundle_path) == value["subject_tree_hash"],
        f"{label}: subject tree hash is stale or includes excluded tracker/evidence paths",
    )


def passed_attempt_kinds(attempts: list[dict[str, Any]], exact_head: str | None) -> set[str]:
    if exact_head is None:
        return set()
    return {
        attempt["kind"]
        for attempt in attempts
        if attempt["head_sha"] == exact_head and attempt["result"] == "passed"
    }


def validate_history(finding: dict[str, Any], label: str) -> None:
    history = finding["history"]
    require(isinstance(history, list) and history, f"{label}: history required")
    previous_lifecycle: str | None = None
    for index, event in enumerate(history):
        exact_keys(event, {"event", "lifecycle", "date", "reason"}, f"{label} history[{index}]")
        require(event["event"] in HISTORY_EVENTS, f"{label}: invalid history event")
        require(event["lifecycle"] in LIFECYCLES, f"{label}: history lifecycle invalid")
        require(DATE_RE.fullmatch(event["date"]) is not None, f"{label}: history date invalid")
        require(isinstance(event["reason"], str) and event["reason"].strip(), f"{label}: history reason required")
        if index == 0:
            require(event["event"] == "imported" and event["lifecycle"] == "confirmed_open", f"{label}: history must start with confirmed_open import")
        elif event["event"] == "lifecycle_changed":
            require(
                LIFECYCLES.index(event["lifecycle"]) == LIFECYCLES.index(previous_lifecycle) + 1,
                f"{label}: lifecycle must advance exactly one stage",
            )
        elif event["event"] in RESET_EVENTS:
            require(
                LIFECYCLES.index(event["lifecycle"]) < LIFECYCLES.index(previous_lifecycle),
                f"{label}: {event['event']} must lower lifecycle",
            )
        else:
            require(event["lifecycle"] == previous_lifecycle, f"{label}: non-lifecycle event changed lifecycle")
        previous_lifecycle = event["lifecycle"]
    require(history[-1]["lifecycle"] == finding["lifecycle"], f"{label}: lifecycle differs from latest history")


def validate_findings(ledger: dict[str, Any], source_rows: dict[str, dict[str, Any]], head: str) -> None:
    exact_keys(
        ledger,
        {
            "schema_version",
            "closure_evidence_bundle_path",
            "source_index_sha256",
            "allowed_lifecycles",
            "allowed_resolution_routes",
            "findings",
        },
        "findings",
    )
    require(ledger["schema_version"] == 2, "findings: unsupported schema_version")
    require(
        ledger["closure_evidence_bundle_path"] == "docs/security/closure-evidence.json",
        "findings: closure evidence bundle path changed",
    )
    validate_repo_path(ledger["closure_evidence_bundle_path"], "findings closure evidence bundle")
    require(ledger["allowed_lifecycles"] == LIFECYCLES, "findings: lifecycle enum changed")
    require(ledger["allowed_resolution_routes"] == ROUTES, "findings: route enum changed")
    source_index = load_canonical(SOURCE_INDEX_PATH)
    require(
        ledger["source_index_sha256"] == sha256(canonical_json(source_index).encode("utf-8")),
        "findings: source-index binding is stale",
    )
    findings = ledger["findings"]
    require(isinstance(findings, list) and len(findings) == 131, "findings: exactly 131 canonical roots required")
    source_coverage: dict[str, list[dict[str, Any]]] = {}
    for position, finding in enumerate(findings, 1):
        label = f"TIRITH-SEC-{position:04d}"
        require(isinstance(finding, dict), f"{label}: object required")
        exact_keys(finding, FINDING_KEYS, label)
        require(finding["finding_id"] == label and FINDING_RE.fullmatch(label) is not None, f"finding {position}: deterministic ID changed")
        require(isinstance(finding["title"], str) and finding["title"].strip(), f"{label}: title required")
        require(finding["severity"] in SEVERITIES, f"{label}: invalid severity")
        expected_owners = [owner for owner, numbers in OWNER_FINDINGS.items() if position in numbers]
        require(len(expected_owners) == 1, f"{label}: validator owner map is not total")
        require(finding["owner"] == expected_owners[0], f"{label}: owner must be {expected_owners[0]}")
        require(finding["lifecycle"] in LIFECYCLES, f"{label}: invalid lifecycle")
        require(finding["resolution_route"] in ROUTES, f"{label}: invalid resolution route")
        require(isinstance(finding["blockers"], list), f"{label}: blockers must be an array")
        blocker_ids: set[str] = set()
        for blocker in finding["blockers"]:
            exact_keys(blocker, {"blocker_id", "reason", "opened_date", "closed_date"}, f"{label} blocker")
            require(BLOCKER_RE.fullmatch(blocker["blocker_id"]) is not None, f"{label}: blocker ID must start blocked_")
            require(blocker["blocker_id"] not in blocker_ids, f"{label}: duplicate blocker")
            blocker_ids.add(blocker["blocker_id"])
            require(isinstance(blocker["reason"], str) and blocker["reason"].strip(), f"{label}: blocker reason required")
            require(DATE_RE.fullmatch(blocker["opened_date"]) is not None, f"{label}: blocker open date invalid")
            require(blocker["closed_date"] is None, f"{label}: closed blockers must be removed after a blocker_cleared history event")
        commits = finding["vulnerable_commits"]
        require(isinstance(commits, list) and commits == sorted(set(commits)) and commits, f"{label}: vulnerable commits must be sorted and unique")
        require(all(COMMIT_RE.fullmatch(value) for value in commits), f"{label}: invalid vulnerable commit")
        links = finding["source_links"]
        require(isinstance(links, list) and links, f"{label}: source links required")
        seen_link_keys: set[tuple[str, tuple[str, ...]]] = set()
        for link in links:
            exact_keys(
                link,
                {
                    "affected_seams",
                    "canonical_root_id",
                    "mapped_claims",
                    "mapping_type",
                    "rationale",
                    "source_id",
                },
                f"{label} source link",
            )
            source_id = link["source_id"]
            require(source_id in source_rows, f"{label}: unknown source {source_id}")
            require(link["canonical_root_id"] == label, f"{label}: bad reverse mapping/canonical root mismatch")
            require(link["mapping_type"] in MAPPING_TYPES, f"{label}: invalid mapping type")
            require(isinstance(link["rationale"], str) and link["rationale"].strip(), f"{label}: mapping rationale required")
            require(isinstance(link["mapped_claims"], list) and link["mapped_claims"], f"{label}: mapped claims required")
            require(
                link["mapped_claims"] == sorted(set(link["mapped_claims"]))
                and all(CLAIM_RE.fullmatch(claim) for claim in link["mapped_claims"]),
                f"{label}: mapped claims must be sorted, unique IDs",
            )
            require(isinstance(link["affected_seams"], list) and link["affected_seams"], f"{label}: affected seams required")
            require(link["affected_seams"] == sorted(set(link["affected_seams"])), f"{label}: affected seams must be sorted and unique")
            expected_seams = sorted({item["path"] for item in source_rows[source_id]["evidence"]})
            expected_seams = expected_seams or [f'report-only:{source_rows[source_id]["section"]}']
            require(link["affected_seams"] == expected_seams, f"{label}: affected seams do not match source evidence")
            key = (source_id, tuple(link["mapped_claims"]))
            require(key not in seen_link_keys, f"{label}: duplicate source claim mapping")
            seen_link_keys.add(key)
            source_coverage.setdefault(source_id, []).append(link)
            require(source_rows[source_id]["vulnerable_commit"] in commits, f"{label}: missing source vulnerable commit")
        require(any(link["mapping_type"] == "related" for link in links), f"{label}: canonical root lacks an owning related mapping")
        require(isinstance(finding["preconditions"], list) and all(isinstance(x, str) for x in finding["preconditions"]), f"{label}: invalid preconditions")
        reproduction = finding["reproduction"]
        exact_keys(reproduction, {"state", "steps"}, f"{label} reproduction")
        require(reproduction["state"] in {"not_recorded", "reproduced", "not_applicable"}, f"{label}: invalid reproduction state")
        require(isinstance(reproduction["steps"], list) and all(isinstance(x, str) for x in reproduction["steps"]), f"{label}: reproduction steps invalid")
        remediation = finding["remediation"]
        exact_keys(remediation, {"summary", "fix_commits", "upstream_reference"}, f"{label} remediation")
        require(remediation["summary"] is None or isinstance(remediation["summary"], str), f"{label}: remediation summary invalid")
        require(isinstance(remediation["fix_commits"], list) and len(remediation["fix_commits"]) == len(set(remediation["fix_commits"])), f"{label}: fix commits invalid")
        require(all(COMMIT_RE.fullmatch(value) for value in remediation["fix_commits"]), f"{label}: full fix commit required")
        require(remediation["upstream_reference"] is None or (isinstance(remediation["upstream_reference"], str) and remediation["upstream_reference"].startswith("https://")), f"{label}: upstream reference must be HTTPS")
        verification = finding["verification"]
        exact_keys(
            verification,
            {
                "attempts",
                "regression_test_locators",
                "migrated_consumers",
                "layer_commit",
                "stack_commit",
                "merge_commit",
            },
            f"{label} verification",
        )
        require(isinstance(verification["attempts"], list), f"{label}: attempts must be an array")
        for index, attempt in enumerate(verification["attempts"]):
            validate_attempt(
                attempt,
                f"{label} attempts[{index}]",
                ledger["closure_evidence_bundle_path"],
            )
        for field in ("regression_test_locators", "migrated_consumers"):
            require(
                isinstance(verification[field], list)
                and verification[field] == sorted(set(verification[field]))
                and all(isinstance(item, str) and item.strip() for item in verification[field]),
                f"{label}: {field} must be sorted, unique, nonempty strings",
            )
        for locator in verification["regression_test_locators"]:
            validate_repo_path(locator.split(":", 1)[0], f"{label} regression test locator")
        for key in ("layer_commit", "stack_commit", "merge_commit"):
            require(verification[key] is None or COMMIT_RE.fullmatch(verification[key]), f"{label}: invalid {key}")
        review = finding["review"]
        exact_keys(review, {"reviewer", "reviewed_commit"}, f"{label} review")
        require(review["reviewer"] is None or isinstance(review["reviewer"], str), f"{label}: reviewer invalid")
        require(review["reviewed_commit"] is None or COMMIT_RE.fullmatch(review["reviewed_commit"]), f"{label}: reviewed commit invalid")
        validate_history(finding, label)

        rank = LIFECYCLES.index(finding["lifecycle"])
        if rank >= LIFECYCLES.index("reproduced"):
            require(reproduction["state"] in {"reproduced", "not_applicable"}, f"{label}: reproduced lifecycle lacks reproduction")
            require(reproduction["steps"] or reproduction["state"] == "not_applicable", f"{label}: reproduction steps required")
        if rank >= LIFECYCLES.index("implemented"):
            require(isinstance(remediation["summary"], str) and remediation["summary"].strip(), f"{label}: implemented lifecycle lacks remediation")
            require(remediation["fix_commits"], f"{label}: implemented lifecycle lacks fix commits")
            require(all(git_is_ancestor(commit, head) for commit in remediation["fix_commits"]), f"{label}: fix commit is not in current history; invalidate after rebase")
            require(verification["regression_test_locators"], f"{label}: implemented lifecycle lacks regression test locators")
        if rank >= LIFECYCLES.index("layer_verified"):
            require(verification["layer_commit"] is not None and git_is_ancestor(verification["layer_commit"], head), f"{label}: layer verification commit stale")
            require(
                passed_attempt_kinds(verification["attempts"], verification["layer_commit"])
                >= {"focused", "benign", "adversarial"},
                f"{label}: layer verification lacks exact-head passed focused/benign/adversarial attempts",
            )
        if rank >= LIFECYCLES.index("stack_verified"):
            require(verification["stack_commit"] is not None and git_is_ancestor(verification["stack_commit"], head), f"{label}: stack verification commit stale after rebase")
            require(
                passed_attempt_kinds(verification["attempts"], verification["stack_commit"])
                >= {"focused", "benign", "adversarial", "platform"},
                f"{label}: stack verification lacks exact-head passed test/platform attempts",
            )
        if rank >= LIFECYCLES.index("ready_to_merge"):
            require(not finding["blockers"], f"{label}: ready_to_merge cannot have blockers")
            require(finding["resolution_route"] != "upstream_candidate", f"{label}: unresolved upstream candidate cannot be ready")
            require(
                passed_attempt_kinds(verification["attempts"], verification["stack_commit"])
                >= ATTEMPT_KINDS - {"baseline"},
                f"{label}: ready_to_merge lacks exact-head passed external verification attempts",
            )
            require(isinstance(review["reviewer"], str) and review["reviewer"].strip(), f"{label}: reviewer required")
            require(review["reviewed_commit"] == verification["stack_commit"], f"{label}: review must bind exact stack commit")
        if rank >= LIFECYCLES.index("merged_verified"):
            require(verification["merge_commit"] is not None and git_is_ancestor(verification["merge_commit"], head), f"{label}: merge verification commit stale")
            require(
                passed_attempt_kinds(verification["attempts"], verification["merge_commit"])
                >= ATTEMPT_KINDS - {"baseline"},
                f"{label}: merged verification lacks exact-main passed external attempts",
            )

    require(set(source_coverage) == set(source_rows), "findings: every one of 135 source rows must be mapped")
    root_by_source: dict[str, str] = {}
    for source_id, mappings in source_coverage.items():
        root_claims = {
            (mapping["canonical_root_id"], tuple(mapping["mapped_claims"]))
            for mapping in mappings
        }
        require(len(root_claims) == len(mappings), f"{source_id}: duplicate canonical claim mapping")
        if source_id in EXACT_DUPLICATES:
            owning = [mapping for mapping in mappings if mapping["mapping_type"] == "exact_duplicate"]
            require(len(owning) == 1, f"{source_id}: exactly one exact_duplicate owner mapping required")
            require(owning[0]["rationale"] == EXACT_DUPLICATE_RATIONALES[source_id], f"{source_id}: duplicate rationale changed")
        else:
            owning = [mapping for mapping in mappings if mapping["mapping_type"] == "related"]
            require(len(owning) == 1, f"{source_id}: exactly one related owner mapping required")
            require(
                owning[0]["rationale"] == "Canonical source row owns this remediation root",
                f"{source_id}: canonical owner rationale changed",
            )
        root_by_source[source_id] = owning[0]["canonical_root_id"]
    for duplicate, primary in EXACT_DUPLICATES.items():
        require(root_by_source[duplicate] == root_by_source[primary], f"{duplicate}: exact duplicate must inherit {primary} root")
    for start in EXACT_DUPLICATES:
        seen: set[str] = set()
        current = start
        while current in EXACT_DUPLICATES:
            require(current not in seen, f"{start}: cyclic exact-duplicate mapping")
            seen.add(current)
            current = EXACT_DUPLICATES[current]


def git_show_json(base_ref: str, relative_path: str) -> Any | None:
    result = subprocess.run(
        ["git", "show", f"{base_ref}:{relative_path}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        return None
    return json.loads(result.stdout)


def validate_append_only(base_ref: str, ledger: dict[str, Any]) -> None:
    relative = str(FINDINGS_PATH.relative_to(ROOT))
    base = git_show_json(base_ref, relative)
    if base is None:
        return
    current_by_id = {item["finding_id"]: item for item in ledger["findings"]}
    for old in base["findings"]:
        finding_id = old["finding_id"]
        require(finding_id in current_by_id, f"{finding_id}: canonical finding deleted")
        new = current_by_id[finding_id]
        require(new["history"][: len(old["history"])] == old["history"], f"{finding_id}: history is not append-only")
        old_sources = {
            (
                x["source_id"],
                x["canonical_root_id"],
                x["mapping_type"],
                tuple(x["mapped_claims"]),
                tuple(x["affected_seams"]),
                x["rationale"],
            )
            for x in old["source_links"]
        }
        new_sources = {
            (
                x["source_id"],
                x["canonical_root_id"],
                x["mapping_type"],
                tuple(x["mapped_claims"]),
                tuple(x["affected_seams"]),
                x["rationale"],
            )
            for x in new["source_links"]
        }
        require(old_sources <= new_sources, f"{finding_id}: source claim mapping removed")
    base_source = git_show_json(base_ref, str(SOURCE_INDEX_PATH.relative_to(ROOT)))
    if base_source is not None:
        require(base_source == load_canonical(SOURCE_INDEX_PATH), "source-index.json is immutable after bootstrap")


def resolve_bundle_path(argument: str, configured_path: str, require_configured: bool) -> Path:
    candidate = Path(argument)
    resolved = candidate.resolve() if candidate.is_absolute() else (ROOT / candidate).resolve()
    if require_configured:
        require(resolved == (ROOT / configured_path).resolve(), "merged-main evidence must use the configured committed closure path")
    require(resolved.is_file(), "evidence bundle file is missing")
    return resolved


def bundle_attempt(bundle: dict[str, Any], check: dict[str, Any]) -> dict[str, Any]:
    return {
        **check,
        "base_sha": bundle["base_sha"],
        "head_sha": bundle["head_sha"],
        "merge_tree_sha": bundle["merge_tree_sha"],
        "subject_tree_hash": bundle["subject_tree_hash"],
        "workflow_sha": bundle["workflow_sha"],
    }


def validate_evidence_bundle(
    argument: str,
    expected_mode: str,
    candidate: str,
    ledger: dict[str, Any],
    owner: str | None = None,
) -> dict[str, Any]:
    path = resolve_bundle_path(
        argument,
        ledger["closure_evidence_bundle_path"],
        require_configured=expected_mode == "merged-main",
    )
    bundle = load_canonical(path)
    exact_keys(
        bundle,
        {
            "schema_version",
            "mode",
            "candidate_sha",
            "base_sha",
            "head_sha",
            "merge_tree_sha",
            "workflow_sha",
            "subject_tree_hash",
            "checks",
            "payload_sha256",
        },
        "evidence bundle",
    )
    require(bundle["schema_version"] == 1, "evidence bundle: unsupported schema")
    require(bundle["mode"] == expected_mode, "evidence bundle: mode mismatch")
    require(bundle["candidate_sha"] == candidate and bundle["head_sha"] == candidate, "evidence bundle: candidate/head mismatch")
    for field in ("candidate_sha", "base_sha", "head_sha", "merge_tree_sha", "workflow_sha"):
        require(COMMIT_RE.fullmatch(bundle[field]) is not None, f"evidence bundle: invalid {field}")
    require(HASH_RE.fullmatch(bundle["subject_tree_hash"]) is not None, "evidence bundle: invalid subject hash")
    require(
        synthetic_merge_tree(bundle["base_sha"], candidate) == bundle["merge_tree_sha"],
        "evidence bundle: merge tree does not bind synthetic base+head merge",
    )
    require(
        git_is_ancestor(bundle["workflow_sha"], bundle["base_sha"])
        or git_is_ancestor(bundle["workflow_sha"], candidate),
        "evidence bundle: workflow is not in base or head history",
    )
    require(
        subject_tree_hash(bundle["merge_tree_sha"], ledger["closure_evidence_bundle_path"]) == bundle["subject_tree_hash"],
        "evidence bundle: subject tree hash mismatch",
    )
    require(isinstance(bundle["checks"], list) and bundle["checks"], "evidence bundle: checks required")
    for index, check in enumerate(bundle["checks"]):
        exact_keys(check, BUNDLE_CHECK_KEYS, f"evidence bundle checks[{index}]")
        validate_attempt(
            bundle_attempt(bundle, check),
            f"evidence bundle checks[{index}]",
            ledger["closure_evidence_bundle_path"],
        )
    unsigned = {key: value for key, value in bundle.items() if key != "payload_sha256"}
    require(
        bundle["payload_sha256"] == sha256(canonical_json(unsigned).encode("utf-8")),
        "evidence bundle: payload digest mismatch",
    )
    bundle_attempts = {
        canonical_json(bundle_attempt(bundle, check))
        for check in bundle["checks"]
    }
    for finding in ledger["findings"]:
        if owner is not None and finding["owner"] != owner:
            continue
        exact_attempts = [
            attempt
            for attempt in finding["verification"]["attempts"]
            if attempt["head_sha"] == candidate and attempt["result"] == "passed"
        ]
        require(exact_attempts, f"{finding['finding_id']}: no exact-candidate passed attempt")
        require(
            all(canonical_json(attempt) in bundle_attempts for attempt in exact_attempts),
            f"{finding['finding_id']}: ledger attempt lacks matching external bundle check",
        )
    return bundle


def current_head() -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True)
    head = result.stdout.strip()
    require(COMMIT_RE.fullmatch(head) is not None, "cannot resolve full current HEAD")
    return head


def run_check(base_ref: str | None, check_render: bool) -> tuple[dict[str, Any], str]:
    source_index = load_canonical(SOURCE_INDEX_PATH)
    source_rows = validate_source_index(source_index)
    ledger = load_canonical(FINDINGS_PATH)
    head = current_head()
    validate_findings(ledger, source_rows, head)
    if base_ref:
        validate_append_only(base_ref, ledger)
    if check_render:
        result = subprocess.run([sys.executable, str(RENDERER), "--check"], cwd=ROOT, check=False)
        require(result.returncode == 0, "generated main.md is stale")
    return ledger, head


def main() -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--structural", action="store_true")
    modes.add_argument("--layer", choices=sorted(OWNERS), metavar="OWNER")
    modes.add_argument("--release-candidate", metavar="COMMIT")
    modes.add_argument("--merged-main", metavar="COMMIT")
    parser.add_argument("--base-ref")
    parser.add_argument("--evidence-bundle")
    parser.add_argument("--skip-render", action="store_true")
    args = parser.parse_args()
    try:
        ledger, head = run_check(args.base_ref, not args.skip_render)
        if args.structural:
            print("structural ledger validation passed: 135 source rows, 131 owned canonical roots")
        elif args.layer:
            require(args.evidence_bundle is not None, "layer gate requires --evidence-bundle")
            owned = [item for item in ledger["findings"] if item["owner"] == args.layer]
            require(owned, f"layer gate: owner {args.layer} has no findings")
            incomplete = [
                item["finding_id"]
                for item in owned
                if LIFECYCLES.index(item["lifecycle"]) < LIFECYCLES.index("layer_verified")
            ]
            require(not incomplete, f"layer gate: {len(incomplete)} owned findings are below layer_verified")
            require(
                all(item["verification"]["layer_commit"] == head for item in owned),
                "layer gate: every owned finding must bind layer_commit to exact HEAD",
            )
            validate_evidence_bundle(args.evidence_bundle, "layer", head, ledger, owner=args.layer)
            print(f"layer ledger gate passed for {args.layer} at exact HEAD")
        elif args.release_candidate:
            require(args.evidence_bundle is not None, "release-candidate gate requires --evidence-bundle")
            candidate = args.release_candidate
            require(COMMIT_RE.fullmatch(candidate) is not None, "release candidate must be a full commit")
            require(candidate == head, "release candidate must equal checked-out HEAD")
            incomplete = [
                item["finding_id"]
                for item in ledger["findings"]
                if LIFECYCLES.index(item["lifecycle"]) < LIFECYCLES.index("ready_to_merge")
            ]
            require(not incomplete, f"release-candidate gate: {len(incomplete)} findings are below ready_to_merge")
            require(
                all(item["verification"]["stack_commit"] == candidate for item in ledger["findings"]),
                "release-candidate gate: every finding must bind stack_commit to the exact candidate",
            )
            require(all(not item["blockers"] for item in ledger["findings"]), "release gate: active blockers remain")
            require(all(item["resolution_route"] != "upstream_candidate" for item in ledger["findings"]), "release gate: unresolved upstream candidates remain")
            validate_evidence_bundle(args.evidence_bundle, "release-candidate", candidate, ledger)
            print("release-candidate ledger gate passed; CI and release workflows remain separate required checks")
        else:
            require(args.evidence_bundle is not None, "merged-main gate requires --evidence-bundle")
            candidate = args.merged_main
            require(COMMIT_RE.fullmatch(candidate) is not None, "merged-main candidate must be a full commit")
            require(candidate == head, "merged-main candidate must equal checked-out HEAD")
            incomplete = [
                item["finding_id"]
                for item in ledger["findings"]
                if item["lifecycle"] != "merged_verified"
            ]
            require(not incomplete, f"merged-main gate: {len(incomplete)} findings are not merged_verified")
            require(
                all(item["verification"]["merge_commit"] == candidate for item in ledger["findings"]),
                "merged-main gate: every finding must bind merge_commit to exact main HEAD",
            )
            require(all(not item["blockers"] for item in ledger["findings"]), "merged-main gate: active blockers remain")
            require(all(item["resolution_route"] != "upstream_candidate" for item in ledger["findings"]), "merged-main gate: unresolved upstream candidates remain")
            validate_evidence_bundle(args.evidence_bundle, "merged-main", candidate, ledger)
            print("merged-main ledger gate passed for exact HEAD; required main/release workflows must also pass")
        return 0
    except (ValidationError, OSError, subprocess.SubprocessError) as exc:
        print(f"ledger validation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
