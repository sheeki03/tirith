#!/usr/bin/env python3
"""Check native process accounting formats and fixture identity refusal."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("measure_local_control", Path(__file__).with_name("measure-local-control.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProcessAccounting(unittest.TestCase):
    def test_native_cpu_formats_and_rss_units(self):
        for clock, expected in [("0:00.02", 20), ("01:02:03", 3723000), ("2-01:02:03", 176523000)]:
            with self.subTest(clock=clock):
                value = module.parse_process_sample(f"42 Sat Sep 12 17:36:09 2026 1234 {clock}", 42)
                self.assertEqual(value["cpu_ms"], expected)
                self.assertEqual(value["rss_bytes"], 1234 * 1024)

    def test_invalid_pid_accounting_and_nonfinite_cpu_are_refused(self):
        for pid, rss, clock in [(41, 1234, "0:00.02"), (42, -1, "0:00.02"), (42, 1234, "0:nan"),
                                (42, 1234, "0:inf"), (42, 1234, "0:60"), (42, 1234, "-1:00")]:
            with self.subTest(pid=pid, rss=rss, clock=clock), self.assertRaises(ValueError):
                module.parse_process_sample(f"{pid} Sat Sep 12 17:36:09 2026 {rss} {clock}", 42)

    def test_record_mismatch_refuses_before_process_sampling(self):
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / "service.json"
            record.write_text(json.dumps({"service_id":"other", "binary_sha256":"other", "pid":42}))
            sampler = object.__new__(module.ServiceSampler)
            sampler.record_path, sampler.service_id, sampler.binary_sha256 = record, "expected", "expected"
            with self.assertRaisesRegex(ValueError, "identity changed"):
                sampler.sample()
            record.write_bytes(b"x" * 16385)
            with self.assertRaisesRegex(ValueError, "exceeds bound"):
                sampler.sample()


if __name__ == "__main__":
    unittest.main()
