#!/usr/bin/env python3
"""One-time deterministic importer for the remediation ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SOURCE_INDEX = HERE / "source-index.json"
FINDINGS = HERE / "findings.json"

STACK_STARTS = [23, 25, 29, 31, 33, 37, 39, 41, 43, 45, 48, 52, 54, 56, 58, 60, 62, 64, 66, 68, 72, 74, 76, 78, 80, 82]
ADDITIONAL_STARTS = list(range(5, 34, 2)) + list(range(37, 84, 2)) + [87, 89]
ORIGINAL_STARTS = (
    [7]
    + list(range(11, 32, 2))
    + list(range(37, 47))
    + list(range(50, 56))
    + list(range(59, 66))
    + list(range(69, 76))
    + list(range(79, 90))
    + list(range(93, 107))
)

REPORTS: dict[str, dict[str, Any]] = {
    "stack": {
        "path": "sources/stack-report.md",
        "origin_sha256": "ec0b8361cad4bca54b60df61cb9b5b93c4de2ff0737b9b1121d6fa1debd09abc",
        "normalized_sha256": "9458454bb20355c2ff4d6239545378e1db99290b05197ca258e1d42d68ec8d5e",
        "line_count": 98,
        "byte_count": 13758,
        "starts": STACK_STARTS,
        "prefix": "STACK",
        "ledger_offset": 0,
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
        "ledger_offset": 26,
        "vulnerable_commit": "e9cf7c602b664da195700d8cca0ca5565e4dec4d",
    },
    "additional": {
        "path": "sources/additional-report.md",
        "origin_sha256": "2c513128cce572167cce567164a9c2c36d6e0e70438abe0e1ed94a93ccde60fb",
        "normalized_sha256": "03421275563636a3fa538c594362afefd9377e11ee316ee211894b8526a8bfd2",
        "line_count": 101,
        "byte_count": 9319,
        "starts": ADDITIONAL_STARTS,
        "prefix": "ADDITIONAL",
        "ledger_offset": 27,
        "vulnerable_commit": "d7ce6b3689da539e6e7e11cc4f2ac66bc6bba7ad",
    },
    "original": {
        "path": "sources/original-report.md",
        "origin_sha256": "f2da4794ed84586911512ddeba9708b52864dfd972bd326c79a69688a4729b5e",
        "normalized_sha256": "2dcc8c7062243c39fb713915b0a3c081b3ead595b0eb7de00c6d2b4c172f7b95",
        "line_count": 120,
        "byte_count": 16695,
        "starts": ORIGINAL_STARTS,
        "prefix": "ORIGINAL",
        "ledger_offset": 68,
        "vulnerable_commit": "d7ce6b3689da539e6e7e11cc4f2ac66bc6bba7ad",
    },
}
REPORT_ORDER = ("stack", "addendum", "additional", "original")

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

GH_EVIDENCE = re.compile(
    r"https://github\.com/sheeki03/tirith/blob/"
    r"(?P<commit>[0-9a-f]{40})/(?P<path>[^#)]+)#L(?P<start>\d+)(?:-L(?P<end>\d+))?"
)
LOCAL_EVIDENCE = re.compile(
    r"\]\(/Users/home/security/(?P<path>[^)\n:]+):(?P<start>\d+)(?:-(?P<end>\d+))?\)"
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def read_normalized(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    return text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"


def extract_block(lines: list[str], start: int) -> tuple[str, int]:
    index = start - 1
    end = index + 1
    while end < len(lines) and lines[end].strip():
        end += 1
    block = "\n".join(lines[index:end]).rstrip() + "\n"
    return block, end


def source_section(report: str, ordinal: int) -> str:
    if report == "stack":
        if ordinal <= 2:
            return "critical_and_inherited_blockers"
        if ordinal <= 5:
            return "pr_197_c00_c03"
        if ordinal <= 11:
            return "pr_198_c04_c12"
        if ordinal <= 20:
            return "pr_201_c13_c18"
        return "pr_199_c19_c20"
    if report == "addendum":
        return "pr_201_npm_regression_harness"
    if report == "additional":
        return "high_priority" if ordinal <= 15 else "medium_priority" if ordinal <= 39 else "low_priority"
    if ordinal == 1:
        return "critical"
    if ordinal <= 12:
        return "high_severity"
    if ordinal <= 22:
        return "medium_mcp_and_policy"
    if ordinal <= 28:
        return "medium_artifacts_and_updates"
    if ordinal <= 35:
        return "medium_state_secrets_and_integrity"
    if ordinal <= 42:
        return "medium_network_threatdb_and_licensing"
    if ordinal <= 53:
        return "medium_containment_and_process_lifecycle"
    return "lower_priority_bugs_and_hardening"


def source_severity(report: str, ordinal: int) -> tuple[str | None, str | None]:
    if report == "stack":
        if ordinal == 1:
            return "Critical", "critical"
        if ordinal in {2, 3, 6, 7, 8, 9, 10}:
            return "High", "high"
        if 12 <= ordinal <= 18:
            return "P1", "high"
        if ordinal in {4, 5, 11, 21, 22, 23, 24}:
            return "Medium", "medium"
        if ordinal in {19, 20}:
            return "P2", "medium"
        return "Low", "low"
    if report == "addendum":
        return None, None
    if report == "additional":
        if ordinal <= 15:
            return "High priority", "high"
        if ordinal <= 39:
            return "Medium priority", "medium"
        return "Low priority", "low"
    if ordinal == 1:
        return "Critical", "critical"
    if ordinal <= 12:
        return "High severity", "high"
    if ordinal <= 53:
        return "Medium severity", "medium"
    return "Lower-priority bugs and hardening", None


def source_title(report: str, block: str) -> str:
    if report == "addendum":
        return "npm regression harness conflicts with trusted-child validation"
    bold = re.search(r"\*\*(.+?)\*\*", block, flags=re.DOTALL)
    if bold:
        title = " ".join(bold.group(1).split())
        title = re.sub(r"^(?:Critical|High|Medium|Low|P1|P2)\s+—\s+", "", title)
        return title.rstrip(".")
    first = block.splitlines()[0]
    first = re.sub(r"^(?:\d+\.\s+|-\s+)", "", first)
    first = first.split(" [", 1)[0]
    match = re.match(r"(.+?\.)(?:\s|$)", first)
    return (match.group(1) if match else first).rstrip(".")


def source_evidence(block: str, default_commit: str) -> list[dict[str, Any]]:
    found: set[tuple[str, int, int, str]] = set()
    for match in GH_EVIDENCE.finditer(block):
        start = int(match.group("start"))
        end = int(match.group("end") or start)
        found.add((match.group("path"), start, end, match.group("commit")))
    for match in LOCAL_EVIDENCE.finditer(block):
        start = int(match.group("start"))
        end = int(match.group("end") or start)
        found.add((match.group("path"), start, end, default_commit))
    return [
        {"path": path, "line_start": start, "line_end": end, "commit": commit}
        for path, start, end, commit in sorted(found)
    ]


def build_source_index() -> dict[str, Any]:
    reports: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    for report_id in REPORT_ORDER:
        spec = REPORTS[report_id]
        path = HERE / spec["path"]
        normalized = read_normalized(path)
        lines = normalized.rstrip("\n").split("\n")
        reports.append(
            {
                "report_id": report_id,
                "path": spec["path"],
                "origin_sha256": spec["origin_sha256"],
                "normalized_sha256": spec["normalized_sha256"],
                "line_count": spec["line_count"],
                "byte_count": spec["byte_count"],
                "expected_rows": len(spec["starts"]),
                "vulnerable_commit": spec["vulnerable_commit"],
            }
        )
        for ordinal, start in enumerate(spec["starts"], 1):
            if report_id == "original":
                block, end = lines[start - 1].rstrip() + "\n", start
            else:
                block, end = extract_block(lines, start)
            reported, normalized_severity = source_severity(report_id, ordinal)
            source_id = f'{spec["prefix"]}-{ordinal:03d}'
            rows.append(
                {
                    "source_id": source_id,
                    "ledger_ordinal": spec["ledger_offset"] + ordinal,
                    "report_id": report_id,
                    "report_ordinal": ordinal,
                    "section": source_section(report_id, ordinal),
                    "reported_severity": reported,
                    "normalized_severity": normalized_severity,
                    "title": source_title(report_id, block),
                    "vulnerable_commit": spec["vulnerable_commit"],
                    "source_locator": {
                        "path": spec["path"],
                        "line_start": start,
                        "line_end": end,
                    },
                    "block_sha256": digest(block.encode("utf-8")),
                    "evidence": source_evidence(block, spec["vulnerable_commit"]),
                }
            )
    return {
        "schema_version": 1,
        "normalization": "UTF-8; CRLF and CR converted to LF; exactly one terminal LF",
        "report_order": list(REPORT_ORDER),
        "expected_counts": {
            "total": 135,
            "by_report": {"stack": 26, "addendum": 1, "additional": 41, "original": 67},
        },
        "reports": reports,
        "sources": rows,
    }


def normalized_root_severity(source: dict[str, Any]) -> str:
    return source["normalized_severity"] or "untriaged"


def owner_for(finding_number: int) -> str:
    matches = [owner for owner, numbers in OWNER_FINDINGS.items() if finding_number in numbers]
    assert len(matches) == 1
    return matches[0]


def affected_seams(source: dict[str, Any]) -> list[str]:
    paths = sorted({entry["path"] for entry in source["evidence"]})
    return paths or [f'report-only:{source["section"]}']


def source_mapping(
    source: dict[str, Any],
    canonical_root_id: str,
    mapping_type: str,
    rationale: str,
) -> dict[str, Any]:
    return {
        "affected_seams": affected_seams(source),
        "canonical_root_id": canonical_root_id,
        "mapped_claims": ["main"],
        "mapping_type": mapping_type,
        "rationale": rationale,
        "source_id": source["source_id"],
    }


def build_initial_findings(source_index: dict[str, Any]) -> dict[str, Any]:
    source_to_finding: dict[str, str] = {}
    findings: list[dict[str, Any]] = []
    rows = {row["source_id"]: row for row in source_index["sources"]}
    for row in source_index["sources"]:
        source_id = row["source_id"]
        duplicate_of = EXACT_DUPLICATES.get(source_id)
        if duplicate_of:
            finding_id = source_to_finding[duplicate_of]
            finding = next(item for item in findings if item["finding_id"] == finding_id)
            finding["source_links"].append(
                source_mapping(
                    row,
                    finding_id,
                    "exact_duplicate",
                    EXACT_DUPLICATE_RATIONALES[source_id],
                )
            )
            finding["vulnerable_commits"] = sorted(
                {*finding["vulnerable_commits"], row["vulnerable_commit"]}
            )
            source_to_finding[source_id] = finding_id
            continue
        finding_number = len(findings) + 1
        finding_id = f"TIRITH-SEC-{finding_number:04d}"
        source_to_finding[source_id] = finding_id
        findings.append(
            {
                "finding_id": finding_id,
                "title": row["title"],
                "severity": normalized_root_severity(row),
                "owner": owner_for(finding_number),
                "lifecycle": "confirmed_open",
                "resolution_route": "local",
                "blockers": [],
                "vulnerable_commits": [row["vulnerable_commit"]],
                "source_links": [
                    source_mapping(
                        row,
                        finding_id,
                        "related",
                        "Canonical source row owns this remediation root",
                    )
                ],
                "preconditions": [],
                "reproduction": {"state": "not_recorded", "steps": []},
                "remediation": {
                    "summary": None,
                    "fix_commits": [],
                    "upstream_reference": None,
                },
                "verification": {
                    "attempts": [],
                    "regression_test_locators": [],
                    "migrated_consumers": [],
                    "layer_commit": None,
                    "stack_commit": None,
                    "merge_commit": None,
                },
                "review": {"reviewer": None, "reviewed_commit": None},
                "history": [
                    {
                        "event": "imported",
                        "lifecycle": "confirmed_open",
                        "date": "2026-08-17",
                        "reason": f"Imported from {source_id}",
                    }
                ],
            }
        )
    assert len(findings) == 131
    assert set(source_to_finding) == set(rows)
    return {
        "schema_version": 2,
        "closure_evidence_bundle_path": "docs/security/closure-evidence.json",
        "source_index_sha256": digest(canonical_json(source_index).encode("utf-8")),
        "allowed_lifecycles": [
            "confirmed_open",
            "reproduced",
            "implemented",
            "layer_verified",
            "stack_verified",
            "ready_to_merge",
            "merged_verified",
        ],
        "allowed_resolution_routes": ["local", "upstream_candidate", "upstream_verified"],
        "findings": findings,
    }


def write_if_changed(path: Path, text: str) -> None:
    # Bytes, not text. These artifacts are digest-pinned, and `write_text` opens
    # in text mode, so on a Windows checkout every "\n" is written as "\r\n" and
    # the file stops hashing to its recorded value. `read_text` performs the
    # reverse translation on the way in, so the comparison below would also read
    # a CRLF file as identical to the LF text and skip the rewrite -- hiding the
    # drift instead of correcting it.
    data = text.encode("utf-8")
    if path.exists() and path.read_bytes() == data:
        return
    path.write_bytes(data)


def command_bootstrap(args: argparse.Namespace) -> int:
    if SOURCE_INDEX.exists() or FINDINGS.exists():
        raise SystemExit("bootstrap files already exist; refusing to replace immutable IDs or remediation state")
    source_index = build_source_index()
    ledger = build_initial_findings(source_index)
    write_if_changed(SOURCE_INDEX, canonical_json(source_index))
    write_if_changed(FINDINGS, canonical_json(ledger))
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    bootstrap = commands.add_parser("bootstrap")
    bootstrap.set_defaults(func=command_bootstrap)
    return result


def main() -> int:
    args = parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
