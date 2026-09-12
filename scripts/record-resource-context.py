#!/usr/bin/env python3
"""Record the current native runner and exact resource-report/source identities.

Run immediately after measurements in the same release-build CI job. This local
manifest is provenance, not cryptographic attestation of a compiler or host.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys

spec = importlib.util.spec_from_file_location("resource_budgets", Path(__file__).with_name("check-resource-budgets.py"))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def cpu_model(explicit):
    if explicit:
        return explicit
    if sys.platform == "linux":
        with Path("/proc/cpuinfo").open("r") as source:
            data = source.read(65536)
        for line in data.splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip() == "model name" and value.strip():
                return value.strip()
    raise check.Invalid("supply an explicit --cpu-model on this platform")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("local-report", "allocation-report", "local-source", "allocation-source", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("source-revision", "run-id", "runner-label", "runner-image", "runner-image-version"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--build-profile", choices=("release",), required=True)
    parser.add_argument("--cpu-model")
    args = parser.parse_args()
    try:
        local, allocation, hashes, _ = check.reports(args.local_report, args.allocation_report)
        host = {"system": platform.system(), "release": platform.release(), "machine": platform.machine()}
        check.require(host == local["host"], "context must be recorded on the measurement host")
        value = {"schema_version": 1, "source_revision": args.source_revision, "build_profile": args.build_profile,
                 "run_id": args.run_id, "host": host,
                 "runner": {"label": args.runner_label, "image": args.runner_image, "image_version": args.runner_image_version,
                            "cpu_model": cpu_model(args.cpu_model), "logical_cpus": os.cpu_count()},
                 "producer_sha256": {"local": hashlib.sha256(args.local_source.read_bytes()).hexdigest(),
                                     "allocation": hashlib.sha256(args.allocation_source.read_bytes()).hexdigest()},
                 "report_sha256": hashes,
                 "executable_sha256": {"local": local["binary_sha256"], "allocation": allocation["instrumented_harness_sha256"]}}
        check.context_check(value, local, allocation, hashes)
        with args.output.open("x") as output:
            output.write(json.dumps(value, indent=2, allow_nan=False) + "\n")
        print("Recorded resource context; this does not establish a performance budget.")
        return 0
    except (check.Invalid, OSError, TypeError, ValueError, KeyError, AttributeError, OverflowError) as error:
        print("resource context refused: " + str(error)[:2048], file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
