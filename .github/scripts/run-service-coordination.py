#!/usr/bin/env python3
"""Run the native pending-job update coordination check against the CLI test binary.

Usage: run-service-coordination.py <evidence-dir>

<evidence-dir>/cargo.jsonl must hold the JSON messages of
`cargo test --locked -p tirith --bin tirith --no-run --message-format=json`
run from the repository root. Writes <evidence-dir>/selected-test.json and the
native evidence under <evidence-dir>/native.
"""
import hashlib
import json
import pathlib
import subprocess
import sys


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    output = pathlib.Path(sys.argv[1])
    source = pathlib.Path.cwd().resolve()
    records = [json.loads(line) for line in (output / "cargo.jsonl").read_text().splitlines()]
    selected = [r for r in records if r.get("reason") == "compiler-artifact"
                and r.get("executable") and r.get("profile", {}).get("test") is True
                and r.get("target", {}).get("name") == "tirith"
                and pathlib.Path(r["manifest_path"]).resolve() == source / "crates/tirith/Cargo.toml"]
    if len(selected) != 1:
        raise SystemExit("expected one current Tirith CLI test executable")
    binary = pathlib.Path(selected[0]["executable"]).resolve(strict=True)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    (output / "selected-test.json").write_text(json.dumps({
        "cargo_artifact": selected[0], "sha256": digest,
        "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "scope": "instrumented test fixture, not signed replacement or release qualification",
    }, indent=2) + "\n")
    subprocess.run([sys.executable, "-B", "tools/qualification/service_coordination_native.py",
                    "--test-executable", str(binary), "--sha256", digest,
                    "--output", str(output / "native")], check=True)


if __name__ == "__main__":
    main()
