#!/usr/bin/env python3
"""Static checks that keep the CI workflows small, honest and runnable.

Plain text parsing only (no PyYAML), so it runs on any hosted runner.
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github/workflows").glob("*.yml"))
BENCH = ROOT / ".github/workflows/bench.yml"
RESOURCE_BENCH = ROOT / "crates/tirith-core/benches/resource_counts.rs"
CEILINGS = "crates/tirith-core/benches/resource_ceilings.json"
DASHBOARD_TESTS = ROOT / "crates/tirith/tests/control_dashboard.rs"
WINDOWS_COMMON = ROOT / ".github/scripts/windows-test-common.ps1"
WINDOWS_SELF_TEST = ROOT / ".github/scripts/test-windows-test-runner.ps1"
NATIVE_ARM = ROOT / ".github/workflows/native-arm-containment.yml"
NATIVE_ARM_STEP = "Native ARM syscall and breakpoint contracts"
CRATE_SOURCES = {
    "tirith-core": ("crates/tirith-core/src", "lib.rs"),
    "tirith": ("crates/tirith/src", "main.rs"),
}
# The clone flag table (checked as compiled BPF for both architectures) and the
# installed production filter, which only a native aarch64 kernel can exercise.
CLONE_POLICY_TESTS = (
    ("tirith-core", "capsule::linux::clone_policy::tests"),
    ("tirith-core", "capsule::linux::tests::production_policy_restricts_clone_flags_on_every_architecture"),
)


def text(path):
    return path.read_text(encoding="utf-8")


def native_arm_contract_tests():
    """The native ARM contracts step and its (package, test filter) pairs."""
    match = re.search(
        r"- name: " + re.escape(NATIVE_ARM_STEP) + r"\n(.*?)(?=\n      - name:|\Z)",
        text(NATIVE_ARM),
        re.S,
    )
    if match is None:
        raise AssertionError("native ARM contracts step not found")
    step = match.group(1)
    tests = re.findall(
        r"cargo test -p ([a-z-]+) (?:--lib|--bin [a-z-]+) --locked -j \d+ ([A-Za-z0-9_:]+) --",
        step,
    )
    return step, tests


def item_pattern(kind, name):
    visibility = r"(?:pub(?:\([^)]*\))?[ \t]+)?"
    return re.compile(r"^[ \t]*" + visibility + kind + r"[ \t]+" + re.escape(name) + r"\b[ \t]*([;{(<])", re.M)


def native_arm_attribute_problems(scope, start, label):
    """Attributes on the item at `start` that keep it from running on aarch64-unknown-linux-gnu."""
    problems = []
    for line in reversed(scope[:start].splitlines()):
        line = line.strip()
        if line.startswith("//"):
            continue
        if not line.startswith("#["):
            if line.endswith(")]"):
                problems.append(f"{label}: multi-line attribute not understood: {line}")
            break
        if line.startswith("#[ignore"):
            problems.append(f"{label}: ignored")
        if line.startswith("#[path"):
            problems.append(f"{label}: #[path] module not understood")
        if not line.startswith("#[cfg("):
            continue
        negated = re.findall(r"not\(([^()]*)\)", line)
        if any(re.search(r'"(?:aarch64|linux|gnu)"|\bunix\b', group) for group in negated):
            problems.append(f"{label}: {line} excludes native ARM Linux")
        rest = re.sub(r"not\([^()]*\)", "", line)
        if (
            ("target_arch" in rest and '"aarch64"' not in rest)
            or ("target_os" in rest and '"linux"' not in rest)
            or ("target_env" in rest and '"gnu"' not in rest)
            or re.search(r"\bwindows\b", rest)
        ):
            problems.append(f"{label}: {line} excludes native ARM Linux")
    return problems


def native_arm_filter_problems(package, test_filter):
    """Why `test_filter` would run no test on native aarch64-unknown-linux-gnu ([] when it resolves)."""
    source, root = CRATE_SOURCES[package]
    directory = ROOT / source
    segments = test_filter.split("::")
    if len(segments) == 1:
        # A bare name: a test function of that name somewhere in the crate.
        pattern = item_pattern("fn", test_filter)
        for path in sorted(directory.rglob("*.rs")):
            body = text(path)
            match = pattern.search(body)
            if match is not None:
                return native_arm_attribute_problems(body, match.start(), test_filter)
        return [f"{test_filter}: no fn {test_filter} in {source}"]
    scope = text(directory / root)
    for index, name in enumerate(segments):
        label = "::".join(segments[: index + 1])
        last = index == len(segments) - 1
        match = item_pattern("mod", name).search(scope)
        if match is None and last:
            match = item_pattern("fn", name).search(scope)
            if match is not None:
                return native_arm_attribute_problems(scope, match.start(), label)
        if match is None:
            return [f"{label}: not found"]
        problems = native_arm_attribute_problems(scope, match.start(), label)
        if problems:
            return problems
        if match.group(1) == ";":
            files = [directory / f"{name}.rs", directory / name / "mod.rs"]
            found = [path for path in files if path.is_file()]
            if not found:
                return [f"{label}: module file not found"]
            scope = text(found[0])
        else:
            # Inline module: search from its opening brace to the end of the
            # file. That also covers items after the module closes, which is
            # acceptable for a name check.
            scope = scope[match.end():]
        directory = directory / name
    return []


def without_action_pins(body):
    return "\n".join(line for line in body.splitlines() if "uses:" not in line)


def powershell_list(body, variable):
    match = re.search(r"\$" + variable + r" = @\((.*?)\n\s*\)", body, re.S)
    if match is None:
        raise AssertionError(f"${variable} list not found")
    return re.findall(r"'([A-Za-z0-9_]+)'", match.group(1))


class WorkflowHygiene(unittest.TestCase):
    def test_workflows_run_no_inline_python(self):
        # Workflow logic lives in reviewed, testable script files.
        pattern = re.compile(r"python3?\s+(-[A-Za-z]+\s+)*(-\s|-c\s|-$)|shell:\s*python", re.M)
        for path in WORKFLOWS:
            with self.subTest(workflow=path.name):
                self.assertIsNone(pattern.search(text(path)), "inline Python in workflow")

    def test_resource_ci_has_no_hash_runner_or_toolchain_pins(self):
        # Bug 10: a version bump or runner image refresh must not fail CI.
        body = without_action_pins(text(BENCH))
        self.assertIsNone(re.search(r"\b[0-9a-f]{40,64}\b", body), "hash pin in bench.yml")
        for pinned in ("ImageVersion ==", "expected_rustc", "admission", "cohort", "macos-"):
            self.assertNotIn(pinned, body)

    def test_resource_ceilings_cover_every_measured_workload(self):
        measured = re.findall(r'measure\(\s*"([a-z0-9_]+)"', text(RESOURCE_BENCH))
        self.assertTrue(measured, "no resource workloads found")
        self.assertEqual(len(measured), len(set(measured)))
        ceilings = json.loads(text(ROOT / CEILINGS))
        workloads = ceilings["workloads"]
        self.assertEqual(sorted(workloads), sorted(measured))
        for name, limits in workloads.items():
            with self.subTest(workload=name):
                self.assertEqual(sorted(limits), ["first_sample", "steady"])
                for phase in limits.values():
                    self.assertEqual(sorted(phase), ["allocation_requests", "requested_bytes"])
                    for value in phase.values():
                        self.assertIsInstance(value, int)
                        self.assertGreater(value, 0)
        bench = text(BENCH)
        self.assertIn("--bench resource_counts", bench)
        self.assertRegex(bench, r'--ceilings "?(\$GITHUB_WORKSPACE/)?' + re.escape(CEILINGS))

    def test_each_self_test_runs_once_per_pull_request(self):
        # Scheduled gates (for example the ThreatDB pin watcher) may re-run a
        # self-test before they publish; pull-request CI runs each one once.
        seen = {}
        pattern = re.compile(r"python3?\s+(?:-B\s+)?((?:\.github/scripts|scripts|tools/[a-z_]+)/test[-_][A-Za-z0-9_.-]+\.py)")
        for path in WORKFLOWS:
            if not re.search(r"^  pull_request(_target)?:", text(path), re.M):
                continue
            for script in pattern.findall(text(path)):
                seen.setdefault(script, []).append(path.name)
        repeated = {script: where for script, where in seen.items() if len(where) > 1}
        self.assertEqual(repeated, {}, "self-test runs more than once")

    def test_referenced_repository_scripts_exist(self):
        pattern = re.compile(r"(?<![\w/.-])((?:\.github/scripts|scripts|tools|tests)/[A-Za-z0-9_./-]+\.(?:py|sh|ps1|mjs|json))")
        for path in WORKFLOWS:
            for referenced in sorted(set(pattern.findall(text(path)))):
                with self.subTest(workflow=path.name, path=referenced):
                    self.assertTrue((ROOT / referenced).is_file(), "missing referenced file")

    def test_android_target_is_compiled_in_ci(self):
        # Issue #261: Android/Termux code (the arboard gate, the Bionic errno
        # accessor, the cfg(target_os = "android") clipboard test) only builds
        # for an Android target, so CI must compile both crates and the
        # tirith-core test binary for one, or a regression goes unnoticed.
        ci = text(ROOT / ".github/workflows/ci.yml")
        for command in (
            "cargo check --locked -p tirith-core -p tirith --target aarch64-linux-android",
            "cargo test --no-run --locked -p tirith-core --target aarch64-linux-android",
        ):
            self.assertIn(command, ci)
        for variable in (
            "CC_aarch64_linux_android",
            "AR_aarch64_linux_android",
            "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER",
        ):
            self.assertRegex(ci, r"\b" + variable + r"[:=]")
        self.assertIn("targets: aarch64-linux-android", ci)
        clipboard = text(ROOT / "crates/tirith-core/src/clipboard.rs")
        self.assertIn('#[cfg(target_os = "android")]', clipboard)

    def test_native_arm_runs_the_clone_policy_tests(self):
        # R4.11: the clone flag table and the installed production filter are
        # exercised on a native aarch64 kernel, not only on x86_64 hosts.
        body = text(NATIVE_ARM)
        self.assertIn("runs-on: ubuntu-24.04-arm", body)
        self.assertIn('test "$(uname -m)" = aarch64', body)
        step, tests = native_arm_contract_tests()
        self.assertIn("if: matrix.target == 'aarch64-unknown-linux-gnu'", step)
        for required in CLONE_POLICY_TESTS:
            self.assertIn(required, tests)

    def test_native_arm_test_filters_name_tests_built_for_native_arm(self):
        # A cargo test filter that matches nothing still passes ("0 passed"),
        # so a renamed, moved, ignored or cfg-excluded test would silently stop
        # running in the native ARM job.
        step, tests = native_arm_contract_tests()
        self.assertEqual(step.count("cargo test "), len(tests), "unparsed cargo test line")
        self.assertGreaterEqual(len(tests), len(CLONE_POLICY_TESTS))
        for package, test_filter in tests:
            with self.subTest(package=package, test_filter=test_filter):
                self.assertEqual(native_arm_filter_problems(package, test_filter), [])

    def test_windows_required_dashboard_tests_exist(self):
        defined = set(re.findall(r"^fn ([a-z0-9_]+)\(", text(DASHBOARD_TESTS), re.M))
        required = powershell_list(text(WINDOWS_COMMON), "required")
        self_test = powershell_list(text(WINDOWS_SELF_TEST), "names")
        self.assertEqual(required, self_test, "runner and its self-test disagree")
        self.assertEqual(sorted(set(required) - defined), [], "required test was removed")


if __name__ == "__main__":
    unittest.main()
