#!/usr/bin/env python3
"""Emit one bounded, actionable ThreatDB run record without posting incidents."""

import argparse
import hashlib
import json
from pathlib import Path


PUBLICATION_PHASES = {"publish_legacy", "commit_legacy", "retire_index", "retire_main_index",
                      "publish_v2", "publish_baseline", "publish_index", "commit_index", "prune"}


def build_report(steps, previous, provenance, run_id, run_attempt=1, job_status=None):
    failed = [name for name, result in steps.items() if result.get("outcome") in {"failure", "cancelled"}]
    if job_status in {"failure", "cancelled"} and not failed:
        failed.append("workflow")
    # A release action can upload a subset before failing or being cancelled.
    # Only skipped/not-started publication supports the retained-generation claim.
    published = any(steps.get(name, {}).get("outcome") in {"success", "failure", "cancelled"}
                    for name in PUBLICATION_PHASES)
    verified = steps.get("cold_verify", {}).get("outcome") == "success"
    status = "failed" if failed else ("verified" if verified else "incomplete")
    incident = hashlib.sha256(("threatdb:" + ",".join(sorted(failed or [status]))).encode()).hexdigest()[:16] if status != "verified" else None
    old_runs = [run for run in previous.get("workflow_runs", []) if str(run.get("id")) != str(run_id)]
    old = old_runs[0].get("conclusion") if old_runs else None
    prior_attempt = previous.get("previous_attempt", {})
    if (run_attempt > 1 and str(prior_attempt.get("id")) == str(run_id) and
            prior_attempt.get("run_attempt") == run_attempt - 1):
        old = prior_attempt.get("conclusion")
    recovery = "recovered" if status == "verified" and old in {"failure", "cancelled", "timed_out"} else ("healthy" if status == "verified" else "required")
    sources = {}
    for source, counts in provenance.get("compiler_parse", {}).get("sources", {}).items():
        accepted, rejected = counts.get("accepted"), counts.get("rejected")
        if isinstance(accepted, int) and isinstance(rejected, int) and accepted >= 0 and rejected >= 0:
            sources[source] = {"accepted": accepted, "rejected": rejected,
                "accepted_fraction": accepted / (accepted + rejected) if accepted + rejected else None}
    return {"schema_version": 1, "run_id": str(run_id), "run_attempt": run_attempt, "status": status,
        "incident_key": incident, "failed_phases": failed, "recovery": recovery,
        "previous_run_conclusion": old,
        "publication_state": "verified" if verified else ("partial_or_unverified" if published else "previous_generation_retained"),
        "next_action": "No publication recovery required." if status == "verified" else (
            "Discovery and cold-client verification passed; inspect the failed later phases before declaring recovery."
            if verified else
            "Inspect the failed phases and verify both discovery surfaces before retrying publication or pruning."
            if published else "Inspect the failed phases; retain current signed pointers and retry after the cause is fixed."),
        "sources": sources,
        "upstream_observations": provenance.get("compiler_parse", {}).get("upstream_observations"),
        "anomaly_policy": {"source_section_drop_percent": 50,
            "accepted_fraction_gate": "observation_only_pending_feed_calibration"}}


def load_optional(path):
    try:
        if path.stat().st_size > 1024 * 1024:
            return {}
        value = json.loads(path.read_text())
        return value if type(value) is dict else {}
    except (OSError, ValueError):
        return {}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["steps", "previous", "provenance", "output", "summary"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", type=int, default=1)
    parser.add_argument("--job-status", choices=["success", "failure", "cancelled"])
    parser.add_argument("--previous-attempt", type=Path)
    args = parser.parse_args()
    previous = load_optional(args.previous)
    if args.previous_attempt is not None:
        previous["previous_attempt"] = load_optional(args.previous_attempt)
    report = build_report(load_optional(args.steps), previous, load_optional(args.provenance), args.run_id,
                          args.run_attempt, args.job_status)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    with args.summary.open("a") as summary:
        summary.write(f"## ThreatDB run: {report['status']}\n\n")
        summary.write(f"Publication: `{report['publication_state']}`. Recovery: `{report['recovery']}`.\n\n")
        if report["incident_key"]:
            summary.write(f"Incident key: `{report['incident_key']}` (stable across repeated failures in the same phases).\n\n")
        summary.write(report["next_action"] + "\n\n")
        summary.write("| Source | Accepted | Rejected | Parse coverage |\n|---|---:|---:|---:|\n")
        for source, counts in report["sources"].items():
            fraction = counts["accepted_fraction"]
            coverage = f"{fraction:.2%}" if fraction is not None else "unknown"
            summary.write(f"| {source} | {counts['accepted']} | {counts['rejected']} | {coverage} |\n")
        summary.write("\nParse coverage is observed; additional rejection-rate gates require feed-specific calibration. Existing signed baseline source/section drop gates remain enforced.\n")
