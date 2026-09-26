#!/usr/bin/env python3
"""Package identity and harmless native process controls; no candidate execution."""
import copy
import hashlib
import importlib.util
import io
import json
import os
import sys
from pathlib import Path
import stat
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
from unittest import mock
import zipfile

SPEC = importlib.util.spec_from_file_location("certificate", Path(__file__).with_name("certify-shell-package.py"))
CERTIFICATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CERTIFICATE)


class NativeProcessOwnership(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.env = {"PATH": os.defpath, "HOME": str(self.root)}

    def fixture(self, code, timeout=5):
        return CERTIFICATE.run([sys.executable, "-I", "-c", code], self.env, timeout)

    def assert_clean(self, evidence):
        self.assertTrue(all(evidence["cleanup"].values()), evidence)
        self.assertTrue(evidence["group_observation"]["leader_retained_waitable"])

    def test_quick_exit_preserves_merged_output_and_nonzero_status(self):
        result = self.fixture("import os; os.write(1, b'out\\n'); os.write(2, b'err\\n'); raise SystemExit(17)")
        self.assertEqual(result.returncode, 17)
        self.assertEqual(result.stdout, "out\nerr\n")
        self.assert_clean(result.qualification)

    def test_original_group_is_signaled_only_while_its_leader_is_owned(self):
        owned = CERTIFICATE.owner_runtime()
        constructor, original_killpg = owned.OwnedProcess, os.killpg
        children, signaled = [], []

        def create(*args, **kwargs):
            process = constructor(*args, **kwargs)
            children.append(process)
            return process

        def signal_original_group(pgid, sig):
            self.assertEqual(pgid, children[0].pid)
            self.assertFalse(children[0].reaped)
            self.assertFalse(children[0].ownership_lost)
            signaled.append(pgid)
            return original_killpg(pgid, sig)

        with mock.patch.object(owned, "OwnedProcess", side_effect=create), \
                mock.patch.object(owned.os, "killpg", side_effect=signal_original_group):
            result = self.fixture("print('completed')")
        self.assertTrue(signaled)
        self.assertTrue(children[0].reaped)
        self.assert_clean(result.qualification)
        with self.assertRaises(ChildProcessError):
            os.waitpid(children[0].pid, os.WNOHANG)

    @unittest.skipUnless(hasattr(os, "fork"), "native fork control")
    def test_exited_leader_descendant_holding_output_pipe_is_cleaned(self):
        marker = self.root / "descendant-marker"
        result = self.fixture(
            "import os,pathlib,time; child=os.fork(); os._exit(0) if child else None; "
            f"time.sleep(.7); pathlib.Path({str(marker)!r}).write_text('ran')")
        self.assertEqual(result.returncode, 0)
        self.assert_clean(result.qualification)
        time.sleep(.8)
        self.assertFalse(marker.exists())

    @unittest.skipUnless(hasattr(os, "fork"), "native fork control")
    def test_exited_leader_descendant_without_output_pipe_is_cleaned(self):
        marker = self.root / "closed-pipe-marker"
        result = self.fixture(
            "import os,pathlib,time; child=os.fork(); os._exit(0) if child else None; "
            "os.close(1); os.close(2); "
            f"time.sleep(.7); pathlib.Path({str(marker)!r}).write_text('ran')")
        self.assertEqual(result.returncode, 0)
        self.assert_clean(result.qualification)
        time.sleep(.8)
        self.assertFalse(marker.exists())

    def test_deadline_retains_cleanup_evidence(self):
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            self.fixture("import time; time.sleep(30)", timeout=.1)
        self.assertLess(time.monotonic() - started, 8)
        self.assertEqual(raised.exception.qualification["failure"], "timeout")
        self.assert_clean(raised.exception.qualification)

    def test_fast_oversized_output_is_refused_even_after_exit(self):
        with mock.patch.object(CERTIFICATE, "MAX_PROCESS_OUTPUT_BYTES", 4096):
            with self.assertRaisesRegex(ValueError, "output-limit") as raised:
                self.fixture("import os; os.write(1, b'x' * 65536)")
        self.assertEqual(raised.exception.qualification["merged_output_bytes"], 4096)
        self.assert_clean(raised.exception.qualification)

    def test_unavailable_group_observation_cannot_produce_success(self):
        owned = CERTIFICATE.owner_runtime()
        with mock.patch.object(owned, "group_members", side_effect=RuntimeError("fixture observation unavailable")):
            with self.assertRaisesRegex(ValueError, "cleanup is incomplete") as raised:
                self.fixture("print('completed')")
        evidence = raised.exception.qualification
        self.assertFalse(evidence["cleanup"]["group_members_exited"])
        self.assertTrue(evidence["cleanup"]["leader_reaped"])
        self.assertEqual(evidence["group_observation"]["error"], "fixture observation unavailable")

    def test_failed_run_appends_its_actual_cleanup_observation(self):
        observations = []
        with self.assertRaises(subprocess.TimeoutExpired):
            CERTIFICATE.run([sys.executable, "-I", "-c", "import time; time.sleep(30)"],
                            self.env, timeout=.1, observations=observations)
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0]["failure"], "timeout")
        self.assert_clean(observations[0])

    def test_selector_creation_failure_cannot_spawn_a_child(self):
        with mock.patch.object(CERTIFICATE.selectors, "DefaultSelector", side_effect=OSError("selector unavailable")), \
                mock.patch.object(CERTIFICATE, "merged_job") as spawn:
            with self.assertRaisesRegex(OSError, "selector unavailable"):
                self.fixture("print('must not run')")
        spawn.assert_not_called()

    def test_failed_cleanup_with_live_leader_and_closed_pipe_is_bounded(self):
        original_start = CERTIFICATE.merged_job
        retained = []

        def start(*args, **kwargs):
            job = original_start(*args, **kwargs)
            # Keep the actual native cleanup method and owned child separately
            # from the deliberately unproved cleanup response under test.
            retained.append((job, job.kill))

            def unproved_cleanup():
                job.failure = "fixture cleanup unavailable"
                if job.pipe_deadline is None:
                    job.pipe_deadline = time.monotonic() + .1

            job.kill = unproved_cleanup
            return job

        started = time.monotonic()
        try:
            with mock.patch.object(CERTIFICATE, "merged_job", side_effect=start):
                with self.assertRaisesRegex(ValueError, "cleanup is incomplete") as raised:
                    # The finite child exits on its own even if the driver
                    # regresses. No extra watcher or sampled signal target.
                    self.fixture("import os,time; os.close(1); os.close(2); time.sleep(2)", timeout=.1)
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertTrue(raised.exception.qualification["cleanup"]["output_eof"])
            self.assertFalse(raised.exception.qualification["cleanup"]["leader_reaped"])
            self.assertIsNone(retained[0][0].process.poll())
        finally:
            for job, native_cleanup in retained:
                native_cleanup()  # Original helper retains/reaps only our child.
                self.assertTrue(job.cleanup["leader_reaped"])
                self.assertTrue(job.cleanup["group_members_exited"])

    def test_postspawn_selector_failure_cleans_owned_child_without_inventing_eof(self):
        selector = mock.Mock()
        selector.register.side_effect = OSError("registration unavailable")
        observations = []
        with mock.patch.object(CERTIFICATE.selectors, "DefaultSelector", return_value=selector):
            with self.assertRaisesRegex(OSError, "registration unavailable"):
                CERTIFICATE.run([sys.executable, "-I", "-c", "import time; time.sleep(30)"],
                                self.env, observations=observations)
        self.assertEqual(len(observations), 1)
        facts = observations[0]["cleanup"]
        self.assertTrue(facts["leader_reaped"])
        self.assertTrue(facts["group_members_exited"])
        self.assertFalse(facts["output_eof"])
        selector.close.assert_called_once()

    def test_main_retains_fixture_and_observations_when_cleanup_is_incomplete(self):
        binary, harness, package = (self.root / name for name in ("tirith", "harness", "package.tar"))
        binary.write_bytes(b"inert fixture")
        harness.write_bytes(b"not executed")
        with tarfile.open(package, "w") as archive:
            entry = tarfile.TarInfo("tirith")
            entry.size = len(binary.read_bytes())
            archive.addfile(entry, io.BytesIO(binary.read_bytes()))
        report_path = self.root / "result.json"
        # Mock only the product-run boundary: this control must never execute
        # its inert package/harness. Native cleanup itself has separate tests.
        def refuse(*args, observations, **kwargs):
            observations.append({"failure": "fixture observation unavailable", "cleanup": {
                "leader_reaped": True, "group_signaled_or_absent": False,
                "group_members_exited": False, "output_eof": False}})
            raise ValueError("fixture cleanup is incomplete")

        argv = ["certify-shell-package.py", "--package", str(package), "--binary", str(binary),
                "--harness", str(harness), "--report", str(report_path), "--shells", "zsh"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(CERTIFICATE, "run", side_effect=refuse):
            self.assertEqual(CERTIFICATE.main(), 1)
        report = json.loads(report_path.read_text())
        retained = Path(report["fixture_root"])
        self.addCleanup(shutil.rmtree, retained)
        self.assertTrue(retained.is_dir())
        self.assertFalse(report["fixture_removed"])
        self.assertEqual(report["state"], "failed")
        self.assertEqual(len(report["processes"]), 1)
        self.assertFalse(report["processes"][0]["cleanup"]["group_members_exited"])


class PackageIdentity(unittest.TestCase):
    def test_native_child_does_not_inherit_ambient_bypass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.dict(os.environ, {"TIRITH": "0", "_TIRITH_RECEIPT_INSTANCE": "inert-placeholder"}):
                env = CERTIFICATE.isolated_env(root, root / "bin/tirith")
                result = CERTIFICATE.run(
                    [sys.executable, "-c", "import os; assert 'TIRITH' not in os.environ; assert '_TIRITH_RECEIPT_INSTANCE' not in os.environ; assert os.environ['TIRITH_OFFLINE'] == '1'"],
                    env,
                )
            self.assertEqual(result.returncode, 0, result.stdout)

    def test_tar_regular_member_is_hashed_without_extracting_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "candidate.tar.gz"
            with tarfile.open(package, "w:gz") as archive:
                info = tarfile.TarInfo("../../never-extracted/tirith")
                info.size = 9
                archive.addfile(info, io.BytesIO(b"candidate"))
            self.assertEqual(CERTIFICATE.packaged_binary_digest(package), hashlib.sha256(b"candidate").hexdigest())
            self.assertEqual(list(Path(temporary).iterdir()), [package])

    def test_duplicate_binaries_and_symlink_only_packages_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "candidate.tar.gz"
            with tarfile.open(package, "w:gz") as archive:
                info = tarfile.TarInfo("tirith")
                info.type = tarfile.SYMTYPE
                info.linkname = "/usr/bin/true"
                archive.addfile(info)
            with self.assertRaises(ValueError):
                CERTIFICATE.packaged_binary_digest(package)
            package = Path(temporary) / "candidate.zip"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("a/tirith.exe", b"one")
                archive.writestr("b/tirith.exe", b"two")
            with self.assertRaises(ValueError):
                CERTIFICATE.packaged_binary_digest(package)

    def test_zip_hash_is_tied_to_exact_shipped_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "candidate.zip"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("tirith.exe", b"candidate")
            actual = CERTIFICATE.packaged_binary_digest(package)
            self.assertEqual(actual, hashlib.sha256(b"candidate").hexdigest())
            self.assertNotEqual(actual, hashlib.sha256(b"other build").hexdigest())

    def test_archive_link_cannot_shadow_regular_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "candidate.tar"
            with tarfile.open(package, "w") as archive:
                info = tarfile.TarInfo("tirith")
                info.size = 9
                archive.addfile(info, io.BytesIO(b"candidate"))
                link = tarfile.TarInfo("tirith")
                link.type = tarfile.SYMTYPE
                link.linkname = "/other/tirith"
                archive.addfile(link)
            with self.assertRaises(ValueError):
                CERTIFICATE.packaged_binary_digest(package)

            package = Path(temporary) / "candidate.zip"
            with zipfile.ZipFile(package, "w") as archive:
                link = zipfile.ZipInfo("tirith")
                link.create_system = 3
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(link, b"candidate")
            with self.assertRaises(ValueError):
                CERTIFICATE.packaged_binary_digest(package)


START={'schema_version':1,'scope':'original_owned_pty_session','id':'fixture-owned-id','pid':42}
END=dict(START,passed=True,native_eof=True,reader_joined=True,private_pty_handles_released=True,errors=[],native={'leader_reaped':True,'original_group_exited':True,'original_session_exited':True,'reaped_after_native_observation':True,'errors':[]})
def output(start=START,end=END):
 return 'test owned ... TIRITH_PTY_OWNED_BEGIN '+json.dumps(start)+'\nTIRITH_PTY_OWNED_CLEANUP '+json.dumps(end)+'\n'
class NativePtyEvidence(unittest.TestCase):
 def test_separate_matching_native_scope_is_required(self):
  self.assertEqual(len(CERTIFICATE.pty_cleanup_evidence(output())['sessions']),1)
  for text in ('','test result: ok. 32 passed; 0 failed; 0 ignored',output().splitlines()[0]):
   with self.assertRaises(ValueError):CERTIFICATE.pty_cleanup_evidence(text)
 def test_any_unknown_cleanup_fact_refuses(self):
  for key in ('passed','native_eof','reader_joined','private_pty_handles_released'):
   end=copy.deepcopy(END);end[key]=False
   with self.assertRaises(ValueError):CERTIFICATE.pty_cleanup_evidence(output(end=end))
  for key in ('leader_reaped','original_group_exited','original_session_exited','reaped_after_native_observation'):
   end=copy.deepcopy(END);end['native'][key]=False
   with self.assertRaises(ValueError):CERTIFICATE.pty_cleanup_evidence(output(end=end))
 def test_duplicate_mismatched_or_missing_owner_refuses(self):
  end=copy.deepcopy(END);end['pid']=43
  with self.assertRaises(ValueError):CERTIFICATE.pty_cleanup_evidence(output(end=end))
  with self.assertRaises(ValueError):CERTIFICATE.pty_cleanup_evidence(output()+output())
  with self.assertRaises(ValueError):CERTIFICATE.pty_cleanup_evidence(output().splitlines()[1])
 def test_native_or_reader_error_refuses_even_with_true_facts(self):
  for native in (False,True):
   end=copy.deepcopy(END);target=end['native'] if native else end;target['errors']=['unknown']
   with self.assertRaises(ValueError):CERTIFICATE.pty_cleanup_evidence(output(end=end))


if __name__ == "__main__":
    unittest.main()
