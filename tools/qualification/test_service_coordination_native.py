#!/usr/bin/env python3
"""Pure failure-injection controls; these never spawn a process or claim cleanup."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location(
    "service_coordination_under_test", Path(__file__).with_name("service_coordination_native.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CloseProbe:
    def __init__(self, events, name, fail=False):
        self.events, self.name, self.fail = events, name, fail

    def close(self):
        self.events.append(self.name)
        if self.fail:
            raise OSError(self.name + " injected failure")


class JobProbe:
    def __init__(self, events, failures=()):
        self.events, self.failures = events, failures
        self.process = SimpleNamespace(
            stdout=CloseProbe(events, "stdout_close", "stdout_close" in failures),
            stderr=CloseProbe(events, "stderr_close", "stderr_close" in failures))

    def kill(self):
        self.events.append("owned_cleanup")
        if "owned_cleanup" in self.failures:
            raise OSError("injected cleanup failure")

    def result(self):
        self.events.append("owned_result")
        if "owned_result" in self.failures:
            raise OSError("injected result failure")
        return {"scope": "synthetic control", "cleanup": {"output_eof": False}}


class FinishOwnedTests(unittest.TestCase):
    def run_case(self, failures=(), finish_error=None):
        events, report = [], {}
        job = JobProbe(events, failures)

        def finish(jobs):
            self.assertEqual(jobs, [job])
            events.append("finish")
            if finish_error is not None:
                raise finish_error
            return [{"scope": "synthetic finish result"}]

        def call():
            return runner.finish_owned(SimpleNamespace(finish=finish), job, report)

        return events, report, call

    def assert_attempts(self, events):
        self.assertEqual(events, ["finish", "owned_cleanup", "stdout_close", "stderr_close", "owned_result"])

    def test_success_still_records_actual_result_without_inventing_eof(self):
        events, report, call = self.run_case()
        self.assertEqual(call(), {"scope": "synthetic finish result"})
        self.assert_attempts(events)
        self.assertFalse(report["owned_process"]["cleanup"]["output_eof"])
        self.assertEqual(report["cleanup_errors"], [])

    def test_finish_constructor_failure_still_cleans_and_records(self):
        error = OSError("selector constructor")
        events, report, call = self.run_case(finish_error=error)
        with self.assertRaises(OSError) as caught:
            call()
        self.assertIs(caught.exception, error)
        self.assert_attempts(events)
        self.assertEqual(report["finish_error"], "selector constructor")
        self.assertIn("owned_process", report)

    def test_first_close_failure_still_attempts_second_and_result(self):
        events, report, call = self.run_case(("stdout_close",))
        with self.assertRaises(RuntimeError):
            call()
        self.assert_attempts(events)
        self.assertEqual(report["cleanup_errors"][0]["operation"], "stdout_close")
        self.assertIn("owned_process", report)

    def test_second_close_failure_retains_result(self):
        events, report, call = self.run_case(("stderr_close",))
        with self.assertRaises(RuntimeError):
            call()
        self.assert_attempts(events)
        self.assertEqual(report["cleanup_errors"][0]["operation"], "stderr_close")
        self.assertIn("owned_process", report)

    def test_all_cleanup_failures_are_independently_recorded(self):
        failures = ("owned_cleanup", "stdout_close", "stderr_close", "owned_result")
        events, report, call = self.run_case(failures)
        with self.assertRaises(RuntimeError):
            call()
        self.assert_attempts(events)
        self.assertEqual([item["operation"] for item in report["cleanup_errors"]], list(failures))
        self.assertNotIn("owned_process", report)

    def test_original_finish_error_survives_cleanup_error(self):
        error = ValueError("original finish refusal")
        events, report, call = self.run_case(("stdout_close",), error)
        with self.assertRaises(ValueError) as caught:
            call()
        self.assertIs(caught.exception, error)
        self.assert_attempts(events)
        self.assertEqual(report["finish_error"], "original finish refusal")
        self.assertEqual(report["cleanup_errors"][0]["operation"], "stdout_close")


if __name__ == "__main__":
    unittest.main()
