#!/usr/bin/env python3
import copy
import json
import unittest

import compatibility_capture as capture


class ContractValidation(unittest.TestCase):
    def row(self, value, exit_code=0):
        return {"failure": None, "cleanup": {"leader_reaped": True, "group_signaled_or_absent": True,
                                              "group_members_exited": True, "output_eof": True}, "exit": exit_code, "stdout": json.dumps(value)}

    def test_rejects_duplicate_and_nonfinite_machine_data(self):
        for text in ('{"action":"allow","action":"block"}', '{"a":{"b":1,"b":2}}',
                     '{"timing":NaN}', '[Infinity]', '[-Infinity]', '[1e999]'):
            with self.subTest(text=text), self.assertRaises((ValueError, AssertionError)):
                capture.json_value(text)

    def test_exit_action_and_cleanup_are_required_together(self):
        case = capture.definitions()[1]
        row = self.row({"schema_version": 3, "action": "block"}, 1)
        capture.validate(case, "baseline", row)
        for field, value in (("failure", "timeout"), ("exit", 0)):
            bad = copy.deepcopy(row)
            bad[field] = value
            with self.assertRaises(AssertionError):
                capture.validate(case, "baseline", bad)
        for field in row["cleanup"]:
            bad = copy.deepcopy(row)
            bad["cleanup"][field] = False
            with self.assertRaises(AssertionError):
                capture.validate(case, "baseline", bad)
            del bad["cleanup"][field]
            with self.assertRaises(AssertionError):
                capture.validate(case, "baseline", bad)
        with self.assertRaises(AssertionError):
            capture.validate(case, "candidate", self.row({"schema_version": 3, "action": "allow"}, 1))

    def test_inherited_mode_cannot_qualify_blocking(self):
        case = next(case for case in capture.definitions() if case["name"] == "reported-shell-blocks")
        for evidence in ({}, {"protection_evidence": {}},
                         {"protection_evidence": {"verified_blocking": True}},
                         {"protection_evidence": {"verified_blocking": 0}}):
            with self.subTest(evidence=evidence), self.assertRaises(AssertionError):
                capture.validate(case, "candidate", self.row(evidence))
        good = {"schema_version": 1, "protection_mode": "guarded", "hook_configured": False,
                "policy_path_used": None, "protection_evidence": {"verified_blocking": False,
                                                                  "fresh": False, "observed_at": None}}
        capture.validate(case, "candidate", self.row(good))
        for who in ("baseline", "candidate"):
            for value in ({}, {**good, "protection_mode": "off"}, {**good, "schema_version": 2},
                          {**good, "hook_configured": True}):
                with self.subTest(who=who, value=value), self.assertRaises(AssertionError):
                    capture.validate(case, who, self.row(value))

    def test_policy_value_scope_and_neutralization_are_checked(self):
        cases = {case["name"]: case for case in capture.definitions()}
        for value in ({"scope": "repo", "policy": {"paranoia": 3}},
                      {"scope": "user", "policy": {"paranoia": 2}}):
            with self.assertRaises(AssertionError):
                capture.validate(cases["personal-policy"], "baseline", self.row(value))
        good = {"scope": "repo", "policy": {"allowlist": []}, "neutralized_fields": ["allowlist"]}
        capture.validate(cases["repository-policy"], "candidate", self.row(good))
        for value in ({**good, "policy": {"allowlist": ["fixture.example"]}},
                      {**good, "neutralized_fields": []}):
            with self.assertRaises(AssertionError):
                capture.validate(cases["repository-policy"], "candidate", self.row(value))

    def test_receipt_mismatch_cannot_pass_with_success_shaped_json(self):
        case = next(case for case in capture.definitions() if case["name"] == "download-receipt-cache-changed")
        good = {"sha256": capture.CONTENT_ID, "url": capture.receipt()["url"], "valid": False}
        capture.validate(case, "candidate", self.row(good, 1))
        for value in ({**good, "valid": True}, {**good, "sha256": "a" * 64}, {**good, "cwd": "/private"}):
            with self.assertRaises(AssertionError):
                capture.validate(case, "candidate", self.row(value, 1))

    def test_receipt_shape_cardinality_and_all_fields_are_preserved(self):
        cases = {case["name"]: case for case in capture.definitions()}
        public = capture.receipt()
        del public["cwd"]
        for who in ("baseline", "candidate"):
            capture.validate(cases["download-receipt-list"], who, self.row([public]))
            capture.validate(cases["download-receipt-last"], who, self.row(public))
            for value in (public, [], [public, public], [public, {**public, "cwd": "/private"}]):
                with self.assertRaises(AssertionError):
                    capture.validate(cases["download-receipt-list"], who, self.row(value))
            for value in ([public], {**public, "url": "https://changed.example"}, {**public, "size": 0}):
                with self.assertRaises(AssertionError):
                    capture.validate(cases["download-receipt-last"], who, self.row(value))


if __name__ == "__main__":
    unittest.main(verbosity=2)
