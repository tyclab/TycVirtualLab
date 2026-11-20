import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import wave
from unittest.mock import patch
import contextlib
import io

from vfl.model import load_json, validate_trace, write_json


SOURCE_ROOT = Path(__file__).resolve().parent.parent


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def cli(self, *arguments, expected=0):
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(SOURCE_ROOT)
        result = subprocess.run([sys.executable, "-m", "vfl.cli", *map(str, arguments)],
                                cwd=self.directory, env=environment, capture_output=True, text=True,
                                timeout=15)
        self.assertEqual(result.returncode, expected, result.stderr + result.stdout)
        self.assertNotIn("Traceback", result.stderr)
        return result

    def test_generate_run_repeat_compare_difference_and_offline_viewer(self):
        trace = self.directory / "input.json"
        self.cli("generate", "--frames", 5, "--out", trace)
        self.cli("validate", trace)
        for name in ("one", "two"):
            self.cli("run", "hypercube-demo", trace, "--out", self.directory / name)
        first = self.directory / "one" / "capture.json"
        second = self.directory / "two" / "capture.json"
        equal = self.cli("compare", first, second, "--events", "--repeat")
        self.assertEqual(json.loads(equal.stdout)["verdict"], "equal")
        self.assertEqual(json.loads(equal.stdout)["verification"], "completed-run")
        # the same two runs without the declaration: no difference, but nothing shown about a second implementation
        undeclared = self.cli("compare", first, second, "--events", expected=3)
        self.assertEqual(json.loads(undeclared.stdout)["verdict"], "inconclusive")
        self.assertIn(json.loads(undeclared.stdout)["inconclusive_reasons"][0], ("same-capture", "same-implementation"))
        once = self.cli("compare", first, first, "--repeat", expected=2)
        self.assertIn("two capture files", once.stderr + once.stdout)
        self.cli("verify-run", first.parent)
        changed = load_json(second)
        bus = changed["buses"][0]["id"]
        raw = bytearray.fromhex(changed["frames"][2]["buses"][bus])
        raw[0] ^= 1
        changed["frames"][2]["buses"][bus] = raw.hex()
        changed_path = self.directory / "changed.json"
        write_json(changed_path, changed)
        self.cli("compare", first, changed_path, expected=2)
        different = self.cli("compare", first, changed_path, "--unverified", expected=1)
        self.assertEqual(json.loads(different.stdout)["verification"], "unverified")
        self.assertEqual(json.loads(different.stdout)["first_difference"]["frame"], 2)
        viewer = self.directory / "viewer.html"
        self.cli("view", first, "--out", viewer)
        html = viewer.read_text()
        self.assertIn("connect-src 'none'", html)
        self.assertIn("vfl.capture.v1", html)
        self.assertNotIn('src="http', html)

    def test_all_bundled_demos_accept_default_generated_trace(self):
        trace = self.directory / "default-input.json"
        self.cli("generate", "--frames", 2, "--out", trace)
        profiles = json.loads(self.cli("profiles").stdout)
        self.assertEqual(len(profiles), 3)
        for profile in profiles:
            result = self.cli("run", profile["id"], trace, "--out", self.directory / profile["id"])
            self.assertEqual(json.loads(result.stdout)["execution_kind"], "synthetic")

    def test_coverage_case_failure_has_nonzero_cli_exit(self):
        from vfl.cli import main
        arguments=['device','coverage','hypercube','--elf','unused','--rom','unused','--out','unused']
        for failed in (0,1):
            output=io.StringIO()
            with patch('vfl.device_cli.execute',return_value={'failed':failed}),contextlib.redirect_stdout(output):
                self.assertEqual(main(arguments),1 if failed else 0)
            self.assertEqual(json.loads(output.getvalue())['failed'],failed)

    def test_device_inventory_and_measured_audio_cli(self):
        devices=json.loads(self.cli("device", "list").stdout)
        self.assertIn("hypercube", [d["id"] for d in devices])
        effects=json.loads(self.cli("device", "effects", "hypercube").stdout)
        self.assertGreater(len(effects), 90)
        self.cli("generate", "--profile", "hypercube-demo", "--frames", 2,
                 "--out", self.directory/"profile-input.json")
        self.cli("generate", "--profile", "hypercube-demo", "--channels", 1,
                 "--out", self.directory/"bad-profile-input.json", expected=2)
        observed=self.directory/"observations.json"
        write_json(observed, {"schema":"vfl.tone-observations.v1","baseline":[100],"input_peak":.25,"observations":[
            {"frequency_hz":100,"values":[600]}, {"frequency_hz":10000,"values":[600]}]})
        calibration=self.directory/"calibration.json"
        self.cli("calibration", "fit", observed, "--out", calibration)
        self.cli("tone", "--calibration", calibration, "--out", self.directory/"missing-scale.json", expected=2)
        self.cli("tone", "--seconds", .05, "--calibration", calibration, "--adc-full-scale-mv", 1000,
                 "--allow-out-of-range", "--out", self.directory/"measured.json")
        trace=load_json(self.directory/"measured.json")
        self.assertEqual(trace["input"]["channels"], 1)
        self.assertEqual(trace["provenance"]["adc"]["full_scale_mv"], 1000)
        self.cli("tone", "--seconds", .03, "--calibration", calibration, "--adc-full-scale-mv", 1000,
                 "--adc-maximum", 4095, "--window-size", 512, "--decay-per-read", 0,
                 "--energy-tolerance", .1, "--calibration-provenance", "embedded",
                 "--out", self.directory/"configured.json")
        configured=load_json(self.directory/"configured.json")
        self.assertEqual(configured["input"]["maximum"],4095)
        self.assertEqual(configured["provenance"]["model"]["window_size"],512)
        self.assertEqual(configured["provenance"]["model"]["decay_per_read"],0)
        self.assertIn("profile",configured["provenance"]["model"])
        self.cli("tone","--window-size",512,"--out",self.directory/"bad-model.json",expected=2)
        self.cli("tone", "--seconds", .048, "--mode", "exoy-adc", "--adc-gain", 2047,
                 "--adc-offset", 2048, "--out", self.directory/"adc.json")
        adc=load_json(self.directory/"adc.json")
        self.assertEqual(adc["input"]["units"], "esp32-adc-chronological-read-counts")
        self.assertEqual([len(f["values"]) for f in adc["frames"]], [64]*3)

    def test_tone_band_selectivity_and_pcm_block_integration(self):
        bands = self.directory / "tone-bands.json"
        self.cli("tone", "--frequency", 1000, "--seconds", 0.08, "--out", bands)
        trace = validate_trace(load_json(bands))
        values = trace["frames"][-1]["values"]
        self.assertEqual(max(range(len(values)), key=values.__getitem__), 3)
        self.cli("run", "hypercube-demo", bands, "--out", self.directory / "tone-run")
        pcm = self.directory / "tone-pcm.json"
        self.cli("tone", "--frequency", 400, "--frequency", 1000, "--amplitude", 0.2,
                 "--seconds", 0.025, "--mode", "pcm", "--block-samples", 480, "--out", pcm)
        source = validate_trace(load_json(pcm))
        self.assertEqual([len(f["values"]) for f in source["frames"]], [480, 480, 240])
        profile = load_json(SOURCE_ROOT / "vfl" / "profiles" / "hypercube-demo.json")
        profile["id"] = "authored-pcm-demo"
        profile["input"] = source["input"]
        profile_path = self.directory / "pcm-profile.json"
        write_json(profile_path, profile)
        self.cli("run", profile_path, pcm, "--out", self.directory / "pcm-run")

    def test_wav_pcm_conversion_and_low_rate_band_rejection(self):
        source = self.directory / "authored.wav"
        with wave.open(str(source), "wb") as output:
            output.setnchannels(2)
            output.setsampwidth(2)
            output.setframerate(8000)
            output.writeframes(b"\x00\x20\x00\xe0" * 32)
        trace = self.directory / "wav-pcm.json"
        self.cli("wav", source, "--channel", 0, "--mode", "pcm", "--out", trace)
        parsed = validate_trace(load_json(trace))
        self.assertEqual(set(parsed["frames"][0]["values"]), {0.25})
        bands = self.directory / "bad-bands.json"
        self.cli("wav", source, "--mode", "bands", "--out", bands, expected=2)
        self.assertFalse(bands.exists())

    def test_malformed_input_and_nonfinite_cli_parameters_exit_two(self):
        source = self.directory / "malformed.json"
        for content in ('{"schema":', '{"schema":[]}', '{"schema":"vfl.trace.v1","input":null}'):
            source.write_text(content)
            self.cli("validate", source, expected=2)
        for seconds in ("inf", "nan", "1e300", "-1"):
            target = self.directory / "bad-tone.json"
            self.cli("tone", "--seconds", seconds, "--out", target, expected=2)
            self.assertFalse(target.exists())

    def test_output_in_source_checkout_rejected_without_creation(self):
        target = SOURCE_ROOT / "must-not-exist.trace.json"
        self.assertFalse(target.exists())
        self.cli("generate", "--frames", 1, "--out", target, expected=2)
        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
