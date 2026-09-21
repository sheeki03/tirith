#!/usr/bin/env python3
"""Exercise publication, interrupted-publish and incident evidence without network."""

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


VERIFY = module("verify-threatdb-publication")
REPORT = module("threatdb-run-report")


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private = self.root / "private.der"
        self.private.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + bytes([42]) * 32)
        public = subprocess.check_output(["openssl", "pkey", "-in", str(self.private), "-inform", "DER", "-pubout", "-outform", "DER"])
        self.key = public[-32:]
        self.assets = []
        self.documents = {}
        for format_version in [1, 2]:
            header = bytearray(172)
            header[:8] = b"TIRITHDB"
            header[8:12] = format_version.to_bytes(4, "little")
            header[20:28] = (7).to_bytes(8, "little")
            header[76:108] = hashlib.sha256(self.key).digest()
            header[108:172] = self.sign(header[:108])
            filename = f"tirith-threatdb-{'v2-' if format_version == 2 else ''}123-1.dat"
            url = VERIFY.FALLBACK + filename
            self.documents[url] = bytes(header)
            self.assets.append({"format": format_version, "filename": filename, "url": url,
                "sha256": hashlib.sha256(header).hexdigest(), "size": len(header)})
        source = {"schema_version": 2, "retrieved_at": "2026-01-01T00:00:00Z"}
        compiler = {"schema_version": 1, "sources": {}}
        integrity = {"manifest_version": 1, "sequence": 7,
            "source_transaction_sha256": hashlib.sha256(VERIFY.canonical(source) + b"\n").hexdigest(),
            "compiler_metadata_sha256": hashlib.sha256(VERIFY.canonical(compiler)).hexdigest(),
            "registry_snapshot_sha256": "a" * 64,
            "v1_filename": self.assets[0]["filename"], "v2_filename": self.assets[1]["filename"],
            "v1_sha256": self.assets[0]["sha256"], "v2_sha256": self.assets[1]["sha256"]}
        self.documents[VERIFY.FALLBACK + "threatdb-source-integrity-123-1.json"] = self.signed(integrity)
        self.documents[VERIFY.FALLBACK + "threatdb-source-provenance-123-1.json"] = VERIFY.canonical({**source, "compiler_parse": compiler, "integrity_bindings": {}})
        for prefix in [VERIFY.PRIMARY, VERIFY.FALLBACK]:
            self.documents[prefix + "threatdb-manifest.json"] = self.signed({k: v for k, v in self.assets[0].items() if k in {"sha256", "size", "url"}} | {"version": 7})
            self.documents[prefix + "threatdb-index-v2.json"] = self.signed({"assets": self.assets, "sequence": 7, "manifest_version": 2})

    def tearDown(self):
        self.temporary.cleanup()

    def sign(self, payload):
        path = self.root / "payload"
        path.write_bytes(payload)
        return subprocess.check_output(["openssl", "pkeyutl", "-sign", "-inkey", str(self.private), "-keyform", "DER", "-rawin", "-in", str(path)])

    def signed(self, document):
        return VERIFY.canonical({**document, "signature": base64.b64encode(self.sign(VERIFY.canonical(document))).decode()})

    def verify(self):
        return VERIFY.verify_publication(7, True, self.key, lambda url, limit: self.documents[url])

    def replace_signed(self, name, transform, prefix=VERIFY.PRIMARY):
        path = prefix + name
        value = json.loads(self.documents[path])
        value.pop("signature")
        transform(value)
        self.documents[path] = self.signed(value)

    def no_validation_retry(self):
        sleeps, requested = [], []
        def download(url, limit):
            requested.append(url)
            return self.documents[url]
        with self.assertRaises(ValueError) as error:
            VERIFY.verify_with_propagation_retry(7, True, self.key, download, sleeps.append)
        self.assertNotIsInstance(error.exception, VERIFY.PublicationLag)
        self.assertEqual(sleeps, [])
        self.assertLessEqual(requested.count(VERIFY.PRIMARY + "threatdb-manifest.json"), 1)
        return str(error.exception)

    def test_both_discovery_surfaces_and_signed_provenance_verify(self):
        report = self.verify()
        self.assertEqual(report["status"], "verified")
        self.assertEqual({item["surface"] for item in report["checked"]}, {"primary", "fallback"})

    def test_v1_only_publication_requires_both_signed_surfaces_without_inventing_v2_evidence(self):
        requested = []
        def download(url, limit):
            requested.append(url)
            return self.documents[url]
        report = VERIFY.verify_publication(7, False, self.key, download)
        self.assertEqual(len(report["checked"]), 2)
        self.assertTrue(all(row["format"] == 1 for row in report["checked"]))
        self.assertFalse(any("index-v2" in url or "source-integrity" in url for url in requested))

    def test_partial_upload_wrong_signature_and_replayed_pointer_refuse(self):
        original = copy.deepcopy(self.documents)
        del self.documents[self.assets[1]["url"]]
        with self.assertRaises(KeyError):
            self.verify()
        self.documents = copy.deepcopy(original)
        self.documents[VERIFY.PRIMARY + "threatdb-index-v2.json"] = self.signed({"assets": self.assets, "sequence": 6, "manifest_version": 2})
        with self.assertRaisesRegex(ValueError, "generation"):
            self.verify()
        self.documents = copy.deepcopy(original)
        manifest = json.loads(self.documents[VERIFY.FALLBACK + "threatdb-manifest.json"])
        manifest["signature"] = base64.b64encode(bytes(64)).decode()
        self.documents[VERIFY.FALLBACK + "threatdb-manifest.json"] = VERIFY.canonical(manifest)
        with self.assertRaisesRegex(ValueError, "signature"):
            self.verify()

    def test_provenance_tampering_never_counts_as_successful_publication(self):
        path = VERIFY.FALLBACK + "threatdb-source-provenance-123-1.json"
        provenance = json.loads(self.documents[path])
        provenance["compiler_parse"]["sources"] = {"injected": {"accepted": 100}}
        self.documents[path] = VERIFY.canonical(provenance)
        with self.assertRaisesRegex(ValueError, "provenance integrity"):
            self.verify()

    def test_invalid_successful_response_and_duplicate_keys_never_retry(self):
        path = VERIFY.PRIMARY + "threatdb-manifest.json"
        original = self.documents[path]
        for malformed in (b"<html>HTTP 200</html>", b"[]", b'{"version": NaN}',
                          original.replace(b'"version":7', b'"version":6,"version":7')):
            with self.subTest(response=malformed[:40]):
                self.documents[path] = malformed
                self.no_validation_retry()
        self.documents[path] = original

    def test_signed_wrong_schema_and_identity_do_not_become_retryable_lag(self):
        original = copy.deepcopy(self.documents)
        mutations = [
            ("threatdb-manifest.json", {"version": 6, "url": "https://example.invalid/other.dat"}),
            ("threatdb-manifest.json", {"version": 7.0}),
            ("threatdb-manifest.json", {"version": True}),
            ("threatdb-index-v2.json", {"sequence": 6, "assets": []}),
            ("threatdb-index-v2.json", {"sequence": 7.0}),
            ("threatdb-index-v2.json", {"manifest_version": 2.0}),
            ("threatdb-index-v2.json", {"assets": [{**self.assets[0], "format": True}, self.assets[1]]}),
        ]
        for name, fields in mutations:
            with self.subTest(name=name, fields=fields):
                self.documents = copy.deepcopy(original)
                self.replace_signed(name, lambda value: value.update(fields))
                self.no_validation_retry()

    def test_old_primary_cannot_hide_an_invalid_fallback(self):
        self.replace_signed("threatdb-manifest.json", lambda value: value.update(version=6))
        path = VERIFY.FALLBACK + "threatdb-manifest.json"
        value = json.loads(self.documents[path]); value["signature"] = base64.b64encode(bytes(64)).decode()
        self.documents[path] = VERIFY.canonical(value)
        self.assertIn("signature", self.no_validation_retry())

    def test_verified_propagation_lag_has_bounded_retries_and_can_recover(self):
        path = VERIFY.PRIMARY + "threatdb-manifest.json"
        current = self.documents[path]
        self.replace_signed("threatdb-manifest.json", lambda value: value.update(version=6))
        sleeps = []
        def advance(delay):
            sleeps.append(delay)
            self.documents[path] = current
        report = VERIFY.verify_with_propagation_retry(7, True, self.key, lambda url, limit: self.documents[url], advance)
        self.assertEqual(report["status"], "verified")
        self.assertEqual(sleeps, [10])
        self.replace_signed("threatdb-manifest.json", lambda value: value.update(version=6))
        sleeps.clear()
        with self.assertRaises(VERIFY.PublicationLag):
            VERIFY.verify_with_propagation_retry(7, True, self.key, lambda url, limit: self.documents[url], sleeps.append)
        self.assertEqual(sleeps, [10, 20])

    def test_same_sequence_equivocation_and_mixed_run_assets_are_refused(self):
        original = copy.deepcopy(self.documents)
        self.replace_signed("threatdb-index-v2.json", lambda value: value["assets"][0].update(sha256="b" * 64))
        self.assertIn("disagree", self.no_validation_retry())
        self.documents = copy.deepcopy(original)
        # Optional signed metadata differs while the referenced DBs agree.
        self.replace_signed("threatdb-index-v2.json", lambda value: value["assets"][1].update(min_tirith_version="0.4.2"), VERIFY.FALLBACK)
        self.assertIn("equivocate", self.no_validation_retry())
        self.documents = copy.deepcopy(original)
        self.replace_signed("threatdb-index-v2.json", lambda value: value["assets"][1].update(
            filename="tirith-threatdb-v2-124-1.dat", url=VERIFY.FALLBACK + "tirith-threatdb-v2-124-1.dat"))
        self.assertIn("mixes", self.no_validation_retry())

    def test_signed_database_identity_mismatch_refuses(self):
        original = copy.deepcopy(self.documents)
        for field, replacement in ((slice(0, 8), b"OTHERDB!"), (slice(20, 28), (6).to_bytes(8, "little")),
                                   (slice(76, 108), bytes(32))):
            with self.subTest(field=field):
                self.documents = copy.deepcopy(original)
                data = bytearray(self.documents[self.assets[1]["url"]]); data[field] = replacement
                data[108:172] = self.sign(data[:108] + data[172:])
                self.documents[self.assets[1]["url"]] = bytes(data)
                digest = hashlib.sha256(data).hexdigest()
                for prefix in (VERIFY.PRIMARY, VERIFY.FALLBACK):
                    self.replace_signed("threatdb-index-v2.json", lambda value: value["assets"][1].update(sha256=digest), prefix)
                self.no_validation_retry()

    def test_source_schema_and_filename_bindings_are_checked(self):
        self.replace_signed("threatdb-source-integrity-123-1.json", lambda value: value.update(v2_filename="different.dat"), VERIFY.FALLBACK)
        self.assertIn("does not bind", self.no_validation_retry())

    def test_verifier_failure_is_retained_as_failed_evidence_and_nonzero_exit(self):
        key = self.root / "key.pub"; key.write_bytes(self.key)
        output = self.root / "verification.json"
        argv = ["--sequence", "7", "--v2", "true", "--verify-key", str(key), "--output", str(output)]
        for error, category in ((ValueError("invalid successful response"), "invalid_publication"),
                                (VERIFY.PublicationLag("still old"), "propagation_timeout"),
                                (subprocess.TimeoutExpired("fixture-fetch", 1), "transport_or_verifier_failure")):
            with self.subTest(category=category), patch.object(VERIFY, "verify_with_propagation_retry", side_effect=error):
                self.assertEqual(VERIFY.main(argv), 1)
                result = json.loads(output.read_text())
                self.assertEqual(result["status"], "refused")
                self.assertEqual(result["failure_class"], category)

    def test_repeated_failure_key_is_stable_and_recovery_is_explicit(self):
        steps = {"fetch": {"outcome": "failure"}}
        one = REPORT.build_report(steps, {}, {}, 1)
        two = REPORT.build_report(steps, {}, {}, 2)
        self.assertEqual(one["incident_key"], two["incident_key"])
        self.assertEqual(one["publication_state"], "previous_generation_retained")
        partial = REPORT.build_report({**steps, "publish_legacy": {"outcome": "success"}}, {}, {}, 3)
        self.assertEqual(partial["publication_state"], "partial_or_unverified")
        recovered = REPORT.build_report({"cold_verify": {"outcome": "success"}}, {"workflow_runs": [{"id": 2, "conclusion": "failure"}]}, {}, 3)
        self.assertEqual(recovered["recovery"], "recovered")
        self.assertIsNone(recovered["incident_key"])

    def test_failed_or_cancelled_upload_is_partial_even_without_a_successful_step(self):
        for name in REPORT.PUBLICATION_PHASES:
            for outcome in ("failure", "cancelled"):
                with self.subTest(name=name, outcome=outcome):
                    result = REPORT.build_report({name: {"outcome": outcome}}, {}, {}, 1)
                    self.assertEqual(result["publication_state"], "partial_or_unverified")
                    self.assertEqual(result["status"], "failed")
                    self.assertEqual(result["recovery"], "required")
        result = REPORT.build_report({"publish_legacy": {"outcome": "skipped"}, "compile": {"outcome": "failure"}}, {}, {}, 1)
        self.assertEqual(result["publication_state"], "previous_generation_retained")

    def test_late_failure_never_claims_recovery_and_same_run_retry_is_bound_to_attempt(self):
        previous = {"workflow_runs": [{"id": 2, "conclusion": "success"}],
                    "previous_attempt": {"id": 3, "run_attempt": 1, "conclusion": "failure"}}
        result = REPORT.build_report({"cold_verify": {"outcome": "success"}, "prune": {"outcome": "failure"}}, previous, {}, 3, 2)
        self.assertEqual(result["publication_state"], "verified")
        self.assertEqual(result["recovery"], "required")
        self.assertNotEqual(result["next_action"], "No publication recovery required.")
        healthy = {"cold_verify": {"outcome": "success"}}
        result = REPORT.build_report(healthy, previous, {}, 3, 2)
        self.assertEqual(result["recovery"], "recovered")
        previous["previous_attempt"]["run_attempt"] = 5
        self.assertEqual(REPORT.build_report(healthy, previous, {}, 3, 2)["recovery"], "healthy")
        untracked = REPORT.build_report(healthy, {}, {}, 3, job_status="failure")
        self.assertEqual(untracked["status"], "failed")
        self.assertEqual(untracked["failed_phases"], ["workflow"])


if __name__ == "__main__":
    unittest.main()
