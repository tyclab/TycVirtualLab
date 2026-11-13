import fcntl
import os
from pathlib import Path
import sys
import signal
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from vfl.model import LabError, digest, load_json, validate_capture, write_json
from vfl.runner import load_completed_capture, resource_lock, run_capture, run_process
from vfl.stimuli import generate_trace


FIXTURE = Path(__file__).with_name("external_fixture.py").resolve()


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.trace = generate_trace(3, 1000, channels=1, maximum=255)
        self.trace_path = self.directory / "trace.json"
        write_json(self.trace_path, self.trace)

    def profile(self, mode="valid", auxiliary=None):
        command = [sys.executable, str(FIXTURE), "--mode", mode,
                   "--request", "{request}", "--capture", "{capture}"]
        if auxiliary is not None:
            command += ["--auxiliary", str(auxiliary)]
        return {"schema": "vfl.profile.v1", "id": "authored-external", "input": {
            "kind": "bands", "channels": 1, "minimum": 0, "maximum": 255, "units": "adc-counts"},
            "buses": [{"id": "main", "pixels": 4, "order": "RGB"}],
            "backend": {"kind": "external", "command": command,
                        "execution_kind": "synthetic", "timeout_s": 3},
            "firmware": [], "geometry": {"kind": "strips"}}

    def run_fixture(self, mode="valid", suffix=None, auxiliary=None, profile=None):
        p = self.profile(mode, auxiliary) if profile is None else profile
        path = self.directory / f"{suffix or mode}.profile.json"
        write_json(path, p)
        return run_capture(path, self.trace_path, self.directory / f"run-{suffix or mode}")

    def test_external_subprocess_success_and_identity_echo(self):
        path = self.run_fixture()
        result = load_json(path)
        request = load_json(path.parent / "request.json")
        validate_capture(result)
        self.assertEqual(result["manifest"]["execution_kind"], "synthetic")
        self.assertEqual(result["manifest"]["input_sha256"], digest(self.trace))
        self.assertEqual(result["manifest"]["request_id"], request["request_id"])
        for name, value in request["identities"].items():
            self.assertEqual(result["manifest"][name], value)
        self.assertEqual(load_json(path.parent / "status.json")["status"], "complete")

    def test_external_failures_leave_failed_status_without_final_capture(self):
        for mode in ("missing", "truncated", "wrong-frames", "wrong-time", "wrong-kind",
                     "wrong-hash", "missing-hash", "wrong-run"):
            with self.subTest(mode=mode), self.assertRaises(LabError):
                self.run_fixture(mode)
            output = self.directory / f"run-{mode}"
            self.assertFalse((output / "capture.json").exists())
            self.assertEqual(load_json(output / "status.json")["status"], "failed")

    def test_stale_output_rejected_even_with_same_input_schedule(self):
        old = self.run_fixture(suffix="old")
        with self.assertRaisesRegex(LabError, "request_id"):
            self.run_fixture("stale", auxiliary=old)
        self.assertFalse((self.directory / "run-stale" / "capture.json").exists())

    def test_existing_directory_and_unit_mismatch_fail_before_start(self):
        output = self.directory / "run-existing"
        output.mkdir()
        marker = output / "keep"
        marker.write_text("preserve")
        with self.assertRaisesRegex(LabError, "already exists"):
            self.run_fixture(suffix="existing")
        self.assertEqual(marker.read_text(), "preserve")
        wrong = self.profile()
        wrong["input"]["units"] = "volts"
        with self.assertRaisesRegex(LabError, "units"):
            self.run_fixture(suffix="units", profile=wrong)
        self.assertFalse((self.directory / "run-units").exists())

    def test_original_kind_needs_assets_and_asset_hash_must_match(self):
        original = self.profile()
        original["backend"]["execution_kind"] = "original-firmware"
        with self.assertRaisesRegex(LabError, "assets"):
            self.run_fixture(suffix="no-assets", profile=original)
        asset = self.directory / "synthetic-fixture.bin"
        asset.write_bytes(b"authored test bytes, not firmware")
        wrong = self.profile()
        wrong["firmware"] = [{"role": "test-data", "path": str(asset), "sha256": "0" * 64}]
        with self.assertRaisesRegex(LabError, "hash mismatch"):
            self.run_fixture(suffix="bad-asset", profile=wrong)

    def test_timeout_terminates_descendant_processes(self):
        marker = self.directory / "child-survived"
        command = [sys.executable, str(FIXTURE), "--mode", "timeout-child", "--auxiliary", str(marker)]
        with self.assertRaisesRegex(LabError, "timeout"):
            run_process(command, self.directory, self.directory / "out", self.directory / "err", 0.2)
        pid_path = Path(str(marker) + ".pid")
        self.assertTrue(pid_path.exists(), "fixture child was started before timeout")
        child_pid = int(pid_path.read_text())
        # A reparented zombie is already terminated, even if the init process
        # has not reaped it yet. A live descendant would be a cleanup failure.
        proc = Path(f"/proc/{child_pid}/stat")
        deadline = time.monotonic() + 0.5
        while True:
            try:
                state = proc.read_text().split(") ", 1)[1][0]
            except FileNotFoundError:
                break
            if state == "Z":
                break
            if time.monotonic() >= deadline:
                self.fail(f"descendant remained alive after process-group cleanup: {state}")
            time.sleep(0.01)  # Allow pending SIGKILL delivery to the descendant.
        self.assertFalse(marker.exists())
        time.sleep(0.9)
        self.assertFalse(marker.exists(), "child survived long enough to write its marker")

    def test_completed_run_verification_rejects_raw_failed_and_modified_captures(self):
        path = self.run_fixture()
        self.assertEqual(load_completed_capture(path), load_completed_capture(path.parent))
        with self.assertRaisesRegex(LabError, "regular capture.json"):
            load_completed_capture(path.parent / "adapter.capture.json")
        edited = load_json(path)
        edited["manifest"]["limitations"].append("edited")
        write_json(path, edited)
        with self.assertRaisesRegex(LabError, "hash mismatch"):
            load_completed_capture(path)
        with self.assertRaises(LabError):
            self.run_fixture("wrong-kind")
        failed = self.directory / "run-wrong-kind"
        (failed / "capture.json").write_bytes((failed / "adapter.capture.json").read_bytes())
        with self.assertRaisesRegex(LabError, "not complete"):
            load_completed_capture(failed)

    def test_signal_handlers_restored_after_success(self):
        before = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGHUP)}
        run_process([sys.executable, "-c", "pass"], self.directory,
                    self.directory / "signals.out", self.directory / "signals.err", 2)
        self.assertEqual(before, {sig: signal.getsignal(sig) for sig in before})

    def test_changed_runner_source_and_oversized_rgb_payload_fail_closed(self):
        with patch("vfl.runner._source_fingerprint", side_effect=["a" * 64, "b" * 64]):
            with self.assertRaisesRegex(LabError, "source changed"):
                self.run_fixture(suffix="changed-source")
        self.assertFalse((self.directory / "run-changed-source" / "capture.json").exists())
        large = self.profile()
        large["buses"][0]["pixels"] = 65536
        write_json(self.trace_path, generate_trace(1000, 1000, channels=1, maximum=255))
        with self.assertRaisesRegex(LabError, "RGB payload"):
            self.run_fixture(suffix="oversized", profile=large)
        self.assertFalse((self.directory / "run-oversized").exists())

    def _start_runner_with_child(self, label):
        marker = self.directory / (label + "-survived")
        profile = self.profile("timeout-child", marker)
        lock = self.directory / (label + ".lock")
        profile["backend"].update(resource_lock=str(lock), timeout_s=10)
        profile_path = self.directory / (label + ".json")
        write_json(profile_path, profile)
        out = self.directory / (label + "-run")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(FIXTURE.parent.parent)
        process = subprocess.Popen([sys.executable, "-m", "vfl.cli", "run", str(profile_path),
                                    str(self.trace_path), "--out", str(out)],
                                   cwd=self.directory, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        backend_pid_path = Path(str(marker) + ".backend.pid")
        while not backend_pid_path.exists():
            if time.monotonic() > deadline or process.poll() is not None:
                process.kill()
                self.fail("runner did not start fixture backend")
            time.sleep(0.01)
        return process, marker, lock, out, int(backend_pid_path.read_text())

    def test_termination_signals_cleanup_child_and_release_lock(self):
        for sig in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=sig):
                process, marker, lock, out, backend_pid = self._start_runner_with_child(sig.name)
                try:
                    process.send_signal(sig)
                    _, error = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 2, error)
                    self.assertIn(sig.name.encode(), error)
                    self.assertEqual(load_json(out / "status.json")["status"], "failed")
                    time.sleep(0.9)  # Beyond the ignored-TERM child's marker deadline.
                    self.assertFalse(marker.exists())
                    with lock.open("a+b") as fd:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
                    try:
                        os.killpg(backend_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_sigkill_keeps_inherited_lock_until_backend_is_killed(self):
        process, marker, lock, _, backend_pid = self._start_runner_with_child("KILL")
        try:
            process.kill()
            process.communicate(timeout=5)
            with lock.open("a+b") as fd:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            try:
                os.killpg(backend_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_log_limit_for_running_and_fast_exiting_process(self):
        for mode in ("log-limit", "log-exit"):
            command = [sys.executable, str(FIXTURE), "--mode", mode]
            with self.subTest(mode=mode), self.assertRaisesRegex(LabError, "log size"):
                run_process(command, self.directory, self.directory / f"{mode}.out",
                            self.directory / f"{mode}.err", 3, output_limit=4096)

    def test_hold_and_busy_lock_prevent_execution(self):
        hold = self.directory / "HOLD"
        hold.write_text("live recording")
        p = self.profile()
        p["backend"]["hold_file"] = str(hold)
        with self.assertRaisesRegex(LabError, "HOLD"):
            self.run_fixture(suffix="hold", profile=p)
        self.assertFalse((self.directory / "run-hold" / "stdout.log").exists())
        hold.unlink()
        lock = self.directory / "resource.lock"
        backend = {"resource_lock": str(lock), "queue_timeout_s": 0}
        with lock.open("a+b") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(LabError, "queue timeout"):
                with resource_lock(backend, self.directory, self.directory):
                    self.fail("locked resource was entered")
        with resource_lock(backend, self.directory, self.directory):
            pass

    def test_hold_is_rechecked_while_waiting_for_resource(self):
        hold = self.directory / "HOLD"
        lock = self.directory / "resource.lock"
        backend = {"resource_lock": str(lock), "queue_timeout_s": 2, "hold_file": str(hold)}
        with lock.open("a+b") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            timer = threading.Timer(0.05, lambda: hold.write_text("stop queue"))
            timer.start()
            try:
                with self.assertRaisesRegex(LabError, "HOLD"):
                    with resource_lock(backend, self.directory, self.directory):
                        self.fail("HOLD was ignored while waiting")
            finally:
                timer.join()


if __name__ == "__main__":
    unittest.main()
