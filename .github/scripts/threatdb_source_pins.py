#!/usr/bin/env python3
"""Validate, resolve, and propose immutable ThreatDB source pins."""

from __future__ import annotations

import argparse
import copy
from collections import Counter
from datetime import datetime, timezone
import json
from email.utils import parsedate_to_datetime
import os
from pathlib import Path
import re
import tempfile
import time
import socket
from typing import Any, Protocol
import urllib.error
import urllib.request


SOURCE_ORDER = (
    "ossf_malicious_packages",
    "datadog_malicious_software_packages",
    "ecosystems_typosquatting_dataset",
)
EXPECTED_REPOSITORIES = {
    "ossf_malicious_packages": "ossf/malicious-packages",
    "datadog_malicious_software_packages": (
        "DataDog/malicious-software-packages-dataset"
    ),
    "ecosystems_typosquatting_dataset": "ecosyste-ms/typosquatting-dataset",
}
ALLOWED_POLICIES = {"default_branch_head", "latest_assign_ids"}
HEX_COMMIT = re.compile(r"^[0-9a-f]{40}$")
UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
COMMITS_PER_PAGE = 100
MAX_COMMIT_PAGES = 10


class PinError(RuntimeError):
    """A fail-closed pin manifest or discovery error."""


class JsonClient(Protocol):
    def commits(self, repository: str, page: int = 1) -> Any: ...

    def compare(self, repository: str, base: str, head: str) -> Any: ...


def parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not UTC_TIMESTAMP.fullmatch(value):
        raise PinError(
            f"{label} must be an RFC3339 UTC timestamp with second precision"
        )
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise PinError(f"{label} is not a valid UTC timestamp") from error


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_manifest(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != {"schema_version", "sources"}:
        raise PinError("pin manifest must contain only schema_version and sources")
    if document["schema_version"] != 1:
        raise PinError("unsupported pin manifest schema_version")
    sources = document["sources"]
    if not isinstance(sources, dict) or set(sources) != set(SOURCE_ORDER):
        raise PinError("pin manifest does not contain the exact required sources")

    expected_fields = {
        "candidate_policy",
        "commit",
        "commit_timestamp",
        "max_lag_hours",
        "repository",
        "selected_at",
    }
    for source_name in SOURCE_ORDER:
        source = sources[source_name]
        if not isinstance(source, dict) or set(source) != expected_fields:
            raise PinError(f"{source_name} has unexpected or missing fields")
        if source["repository"] != EXPECTED_REPOSITORIES[source_name]:
            raise PinError(f"{source_name} repository is not the reviewed upstream")
        if source["candidate_policy"] not in ALLOWED_POLICIES:
            raise PinError(f"{source_name} has an unsupported candidate policy")
        if (
            source_name == "ossf_malicious_packages"
            and source["candidate_policy"] != "latest_assign_ids"
        ):
            raise PinError("OpenSSF must select a completed Assign IDs boundary")
        if (
            source_name != "ossf_malicious_packages"
            and source["candidate_policy"] != "default_branch_head"
        ):
            raise PinError(f"{source_name} must track the default-branch head")
        if not isinstance(source["commit"], str) or not HEX_COMMIT.fullmatch(
            source["commit"]
        ):
            raise PinError(f"{source_name} commit must be lowercase 40-hex")
        commit_time = parse_timestamp(
            source["commit_timestamp"], f"{source_name} commit_timestamp"
        )
        selected_time = parse_timestamp(
            source["selected_at"], f"{source_name} selected_at"
        )
        if commit_time > selected_time:
            raise PinError(f"{source_name} was selected before its commit existed")
        max_lag = source["max_lag_hours"]
        if isinstance(max_lag, bool) or not isinstance(max_lag, int):
            raise PinError(f"{source_name} max_lag_hours must be an integer")
        if not 1 <= max_lag <= 8760:
            raise PinError(f"{source_name} max_lag_hours is outside the safe range")
    return document


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PinError(f"cannot read pin manifest {path}: {error}") from error
    return validate_manifest(document)


def atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, delete=False
    ) as staged:
        staged.write(content)
        staged.flush()
        os.fsync(staged.fileno())
        staged_path = Path(staged.name)
    os.replace(staged_path, path)


def write_json(path: Path, document: Any) -> None:
    atomic_write(path, json.dumps(document, indent=2, sort_keys=True) + "\n")


class GitHubClient:
    def __init__(self, token: str | None) -> None:
        self.token = token
        self.deadline = time.monotonic() + 120

    def _get(self, endpoint: str) -> Any:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "tirith-threatdb-pin-watcher/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(
            f"https://api.github.com{endpoint}", headers=headers
        )
        for attempt in range(3):
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise PinError("GitHub observation transport exceeded overall 120s deadline")
            try:
                with urllib.request.urlopen(request, timeout=min(30, remaining)) as response:
                    if response.status != 200:
                        raise PinError(f"GitHub API permanent HTTP {response.status} for {endpoint}")
                    data = response.read(4 * 1024 * 1024 + 1)
                    if len(data) > 4 * 1024 * 1024:
                        raise PinError("GitHub observation exceeded response byte cap")
                    # Parsing is outside transport recovery: invalid HTTP 200 is
                    # a validation failure, never permission to retry bad data.
                    try:
                        return json.loads(data)
                    except (ValueError, UnicodeDecodeError) as error:
                        raise PinError(f"GitHub API schema failure for {endpoint}") from error
            except urllib.error.HTTPError as error:
                retryable = error.code in {408, 429, 500, 502, 503, 504}
                category = "rate_limit" if error.code == 429 else "transport"
                retry_after = error.headers.get("Retry-After")
                if error.code == 403 and error.headers.get("X-RateLimit-Remaining") == "0":
                    retryable = True
                    category = "rate_limit"
                    try:
                        retry_after = str(max(0, int(error.headers["X-RateLimit-Reset"]) - int(time.time())))
                    except (ValueError, TypeError):
                        retryable = False
                if not retryable:
                    raise PinError(f"GitHub API permanent HTTP {error.code} for {endpoint}") from error
            except (urllib.error.URLError, TimeoutError, ConnectionError) as error:
                reason = getattr(error, "reason", error)
                retryable = isinstance(reason, (TimeoutError, ConnectionError)) or (
                    isinstance(reason, socket.gaierror) and reason.errno == socket.EAI_AGAIN
                )
                if not retryable:
                    raise PinError(f"GitHub API identity or non-transient transport failure for {endpoint}") from error
                category, retry_after = "transport", None
            delay = retry_delay(retry_after, attempt, self.deadline - time.monotonic())
            if delay is None:
                raise PinError(f"GitHub API {category} failure exhausted bounded recovery for {endpoint}")
            time.sleep(delay)
        raise PinError("GitHub observation recovery exhausted")

    def commits(self, repository: str, page: int = 1) -> Any:
        return self._get(
            f"/repos/{repository}/commits?per_page={COMMITS_PER_PAGE}&page={page}"
        )

    def compare(self, repository: str, base: str, head: str) -> Any:
        return self._get(f"/repos/{repository}/compare/{base}...{head}")


def retry_delay(retry_after: str | None, attempt: int, remaining: float) -> float | None:
    if attempt >= 2:
        return None
    if retry_after is None:
        delay = float(2**attempt)
    else:
        try:
            delay = float(int(retry_after))
        except ValueError:
            try:
                parsed = parsedate_to_datetime(retry_after)
                if parsed.tzinfo is None:
                    return None
                delay = max(0.0, parsed.timestamp() - time.time())
            except (ValueError, TypeError, OverflowError):
                return None
    return delay if 0 <= delay < remaining else None


def observation_document(selected_at: str, changes: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "checked_at": selected_at,
        "sources": {
            item["source"]: {
                "pinned_commit": item["old_commit"],
                "candidate_commit": item["candidate"]["commit"],
                "candidate_timestamp": item["candidate"]["commit_timestamp"],
                "ahead_by": item.get("comparison", {}).get("ahead_by", 0),
                "max_lag_hours": item["max_lag_hours"],
                "review_required": item["changed"],
            }
            for item in changes
        },
    }


def command_observe(arguments: argparse.Namespace) -> int:
    manifest = load_manifest(arguments.manifest)
    selected_at = arguments.now or format_timestamp(datetime.now(timezone.utc))
    client = FixtureClient(arguments.api_fixture) if arguments.api_fixture else GitHubClient(os.environ.get("GITHUB_TOKEN"))
    _, changes = update_pins(copy.deepcopy(manifest), client, selected_at)
    write_json(arguments.result, observation_document(selected_at, changes))
    return 0


class FixtureClient:
    def __init__(self, path: Path) -> None:
        try:
            self.document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PinError(f"cannot read API fixture {path}: {error}") from error

    def commits(self, repository: str, page: int = 1) -> Any:
        try:
            fixture = self.document["commits"][repository]
        except (KeyError, TypeError) as error:
            raise PinError(f"API fixture has no commits for {repository}") from error
        if isinstance(fixture, dict):
            return fixture.get(str(page), [])
        return fixture if page == 1 else []

    def compare(self, repository: str, base: str, head: str) -> Any:
        key = f"{repository}:{base}...{head}"
        try:
            return self.document["comparisons"][key]
        except (KeyError, TypeError) as error:
            raise PinError(f"API fixture has no comparison for {key}") from error


def normalized_commit(entry: Any, repository: str) -> dict[str, str]:
    try:
        sha = entry["sha"]
        commit = entry["commit"]
        timestamp = commit["committer"]["date"]
        subject = commit["message"].splitlines()[0]
    except (KeyError, IndexError, TypeError, AttributeError) as error:
        raise PinError(f"{repository} returned malformed commit metadata") from error
    if not isinstance(sha, str) or not HEX_COMMIT.fullmatch(sha):
        raise PinError(f"{repository} returned a non-immutable commit id")
    parsed = parse_timestamp(timestamp, f"{repository} candidate timestamp")
    if not isinstance(subject, str) or not subject.strip():
        raise PinError(f"{repository} returned an empty commit subject")
    return {
        "commit": sha,
        "commit_timestamp": format_timestamp(parsed),
        "subject": subject.strip(),
    }


def discover_candidate(source: dict[str, Any], client: JsonClient) -> dict[str, str]:
    repository = source["repository"]
    if source["candidate_policy"] == "default_branch_head":
        entries = client.commits(repository, 1)
        if not isinstance(entries, list) or not entries:
            raise PinError(f"{repository} returned no default-branch commits")
        return normalized_commit(entries[0], repository)

    for page in range(1, MAX_COMMIT_PAGES + 1):
        entries = client.commits(repository, page)
        if not isinstance(entries, list):
            raise PinError(f"{repository} returned malformed commit page {page}")
        if not entries:
            break
        for entry in entries:
            candidate = normalized_commit(entry, repository)
            if candidate["subject"] == "Assign IDs":
                return candidate
        if len(entries) < COMMITS_PER_PAGE:
            break
    raise PinError(f"{repository} returned no completed Assign IDs boundary")


def summarize_comparison(
    repository: str, base: str, head: str, document: Any
) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("status") != "ahead":
        raise PinError(
            f"{repository} candidate is not strictly ahead of the pinned commit"
        )
    ahead_by = document.get("ahead_by")
    total_commits = document.get("total_commits")
    files = document.get("files")
    if (
        isinstance(ahead_by, bool)
        or not isinstance(ahead_by, int)
        or ahead_by < 1
        or isinstance(total_commits, bool)
        or not isinstance(total_commits, int)
        or total_commits < 1
        or not isinstance(files, list)
    ):
        raise PinError(f"{repository} returned malformed comparison metadata")
    statuses: Counter[str] = Counter()
    prefixes: Counter[str] = Counter()
    for file in files:
        if not isinstance(file, dict):
            raise PinError(f"{repository} returned a malformed changed file")
        status = file.get("status")
        filename = file.get("filename")
        if not isinstance(status, str) or not isinstance(filename, str) or not filename:
            raise PinError(f"{repository} returned incomplete changed-file metadata")
        statuses[status] += 1
        prefixes[filename.split("/", 1)[0]] += 1
    return {
        "ahead_by": ahead_by,
        "compare_url": f"https://github.com/{repository}/compare/{base}...{head}",
        "files_returned": len(files),
        "files_truncated": len(files) >= 300,
        "path_prefixes": dict(sorted(prefixes.items())),
        "status_counts": dict(sorted(statuses.items())),
        "total_commits": total_commits,
    }


def update_pins(
    manifest: dict[str, Any], client: JsonClient, selected_at: str
) -> tuple[bool, list[dict[str, Any]]]:
    selected_time = parse_timestamp(selected_at, "selection time")
    changes: list[dict[str, Any]] = []
    changed = False
    for source_name in SOURCE_ORDER:
        source = manifest["sources"][source_name]
        candidate = discover_candidate(source, client)
        candidate_time = parse_timestamp(
            candidate["commit_timestamp"], f"{source_name} candidate timestamp"
        )
        if candidate_time > selected_time:
            raise PinError(f"{source_name} candidate is newer than the selection time")
        pinned_time = parse_timestamp(
            source["commit_timestamp"], f"{source_name} pinned timestamp"
        )
        lag_hours = max(0.0, (candidate_time - pinned_time).total_seconds() / 3600)
        item: dict[str, Any] = {
            "candidate": candidate,
            "changed": candidate["commit"] != source["commit"],
            "lag_hours": lag_hours,
            "max_lag_hours": source["max_lag_hours"],
            "old_commit": source["commit"],
            "old_commit_timestamp": source["commit_timestamp"],
            "policy": source["candidate_policy"],
            "repository": source["repository"],
            "source": source_name,
            "stale": lag_hours > source["max_lag_hours"],
        }
        if item["changed"]:
            comparison = client.compare(
                source["repository"], source["commit"], candidate["commit"]
            )
            item["comparison"] = summarize_comparison(
                source["repository"],
                source["commit"],
                candidate["commit"],
                comparison,
            )
            source["commit"] = candidate["commit"]
            source["commit_timestamp"] = candidate["commit_timestamp"]
            source["selected_at"] = selected_at
            changed = True
        elif candidate["commit_timestamp"] != source["commit_timestamp"]:
            raise PinError(
                f"{source_name} pinned commit timestamp disagrees with GitHub"
            )
        changes.append(item)
    validate_manifest(manifest)
    return changed, changes


def markdown_code(value: str) -> str:
    return value.replace("`", "'").replace("\r", " ").replace("\n", " ")


def render_report(selected_at: str, changes: list[dict[str, Any]]) -> str:
    lines = [
        "## ThreatDB source-pin refresh",
        "",
        f"Generated at `{selected_at}` by the read-only source watcher.",
        "The watcher has no ThreatDB signing key, release permission, or auto-merge step.",
        "",
        "| Source | State | Pinned | Candidate | Lag | Policy |",
        "|---|---:|---|---|---:|---|",
    ]
    for item in changes:
        state = (
            "stale" if item["stale"] else ("update" if item["changed"] else "current")
        )
        candidate = item["candidate"]
        lines.append(
            "| {source} | {state} | `{old}` | `{new}` | {lag:.1f}h / {limit}h | `{policy}` |".format(
                source=item["source"],
                state=state,
                old=item["old_commit"][:12],
                new=candidate["commit"][:12],
                lag=item["lag_hours"],
                limit=item["max_lag_hours"],
                policy=item["policy"],
            )
        )
    lines.extend(["", "### Review evidence", ""])
    for item in changes:
        candidate = item["candidate"]
        lines.extend(
            [
                f"#### `{item['source']}`",
                "",
                f"- repository: `{item['repository']}`",
                f"- candidate: `{candidate['commit']}` at `{candidate['commit_timestamp']}`",
                f"- subject: `{markdown_code(candidate['subject'])}`",
            ]
        )
        comparison = item.get("comparison")
        if comparison:
            lines.extend(
                [
                    f"- compare: {comparison['compare_url']}",
                    f"- commits: {comparison['ahead_by']} ahead ({comparison['total_commits']} in comparison)",
                    f"- file statuses returned: `{json.dumps(comparison['status_counts'], sort_keys=True)}`",
                    f"- changed path prefixes: `{json.dumps(comparison['path_prefixes'], sort_keys=True)}`",
                    f"- GitHub file list truncated: `{str(comparison['files_truncated']).lower()}`",
                ]
            )
        else:
            lines.append("- no change")
        lines.append("")
    lines.extend(
        [
            "### Required review",
            "",
            "Do not auto-merge this PR. Review the upstream comparisons and require the normal Tirith CI checks. The watcher already ran the fail-closed fixture suite and a real source fetch against these exact immutable revisions before publishing this branch.",
            "",
        ]
    )
    return "\n".join(lines)


def command_validate(arguments: argparse.Namespace) -> int:
    load_manifest(arguments.manifest)
    return 0


def command_resolve(arguments: argparse.Namespace) -> int:
    manifest = load_manifest(arguments.manifest)
    fields: list[str] = []
    for source_name in SOURCE_ORDER:
        source = manifest["sources"][source_name]
        fields.extend(
            [source["commit"], source["commit_timestamp"], source["selected_at"]]
        )
    print("\t".join(fields))
    return 0


def command_update(arguments: argparse.Namespace) -> int:
    manifest = load_manifest(arguments.manifest)
    selected_at = arguments.now or format_timestamp(datetime.now(timezone.utc))
    client: JsonClient
    if arguments.api_fixture:
        client = FixtureClient(arguments.api_fixture)
    else:
        client = GitHubClient(os.environ.get("GITHUB_TOKEN"))
    changed, changes = update_pins(manifest, client, selected_at)
    if changed:
        write_json(arguments.manifest, manifest)
    report = render_report(selected_at, changes)
    atomic_write(arguments.report, report)
    result = {
        "changed": changed,
        "changed_sources": [item["source"] for item in changes if item["changed"]],
        "selected_at": selected_at,
        "stale_sources": [item["source"] for item in changes if item["stale"]],
        "upstream_observations": observation_document(selected_at, changes),
    }
    write_json(arguments.result, result)
    print(json.dumps(result, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("manifest", type=Path)
    validate.set_defaults(handler=command_validate)

    resolve = subparsers.add_parser("resolve")
    resolve.add_argument("manifest", type=Path)
    resolve.set_defaults(handler=command_resolve)

    update = subparsers.add_parser("update")
    update.add_argument("manifest", type=Path)
    update.add_argument("--api-fixture", type=Path)
    update.add_argument("--now")
    update.add_argument("--report", type=Path, required=True)
    update.add_argument("--result", type=Path, required=True)
    update.set_defaults(handler=command_update)

    observe = subparsers.add_parser("observe", help="report upstream lag without adopting any pins")
    observe.add_argument("manifest", type=Path)
    observe.add_argument("--api-fixture", type=Path)
    observe.add_argument("--now")
    observe.add_argument("--result", type=Path, required=True)
    observe.set_defaults(handler=command_observe)
    return parser


def main() -> int:
    parser = build_parser()
    arguments = parser.parse_args()
    try:
        return arguments.handler(arguments)
    except PinError as error:
        parser.error(str(error))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
