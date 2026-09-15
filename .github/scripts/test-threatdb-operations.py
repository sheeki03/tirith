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

    def test_both_discovery_surfaces_and_signed_provenance_verify(self):
        report = self.verify()
        self.assertEqual(report["status"], "verified")
        self.assertEqual({item["surface"] for item in report["checked"]}, {"primary", "fallback"})

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


if __name__ == "__main__":
    unittest.main()
