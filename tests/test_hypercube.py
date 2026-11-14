"""Setup metadata and synthetic-image tests; no proprietary fixtures required."""
import copy
import hashlib
import os
import secrets
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from vfl.devices import hypercube as cube
from vfl.ghidra import _asset_paths, compile_commands
from vfl.model import LabError, file_digest
from tests.test_ghidra import tiny_elf


class HyperCubeSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.elf = Path(self.temp.name) / "authored.elf"
        self.elf.write_bytes(tiny_elf())
        self.rom = Path(self.temp.name) / "authored-rom.bin"
        self.rom.write_bytes(bytes(65536))

    def profile(self, **kwargs):
        with patch.object(cube, "_verify_elf", return_value=(self.elf, file_digest(self.elf))), patch.object(cube, "ROM_SHA256", file_digest(self.rom)):
            return cube.build_profile(self.elf, self.rom, **kwargs)

    def trace(self, controls=None):
        return {"schema": "vfl.trace.v1", "input": copy.deepcopy(cube.INPUT), "seed": 7,
                "clock_policy": "frame", "provenance": {"kind": "synthetic"},
                "frames": [{"index": i, "time_us": (i + 1) * 32000, "values": [40, 80, 160, 320, 640, 900, 500],
                            "controls": (controls or {}).get(i, {})} for i in range(3)]}

    def test_inventory_distinguishes_playlists_effects_and_warp(self):
        inventory = cube.effect_inventory()
        self.assertEqual(len(inventory), 99)
        self.assertEqual(len({e["id"] for e in inventory}), 99)
        self.assertEqual(sum(e["kind"] == "effect" for e in inventory), 95)
        self.assertEqual(sum(e["kind"] == "playlist" for e in inventory), 3)
        self.assertEqual(sum(e["kind"] == "command" for e in inventory), 1)
        self.assertEqual({e["table_index"] for e in inventory if e["table_index"] is not None and e["table_index"] >= 0}, set(range(95)))
        self.assertEqual(cube.coverage_plan()[0]["status"], "not-run")

    def test_prepared_backend_launches_from_unrelated_working_directory(self):
        backend = self.profile()["backend"]
        environment = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
        environment.update(backend.get("env", {}))
        result = subprocess.run(backend["command"][:-2],
                                cwd=self.temp.name, env=environment, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stderr.strip(), "tycvl Ghidra: usage: python -m vfl.ghidra REQUEST CAPTURE")

    def test_every_selector_builds_a_concrete_settings_and_startup_recipe(self):
        for case in cube.coverage_plan():
            with self.subTest(case=case["id"]):
                profile = self.profile(settings=case["settings"])
                config = profile["backend"]["options"]["ghidra"]
                self.assertEqual(config["settings_acknowledgements"], profile["settings"])
                calls = [op["address"] for op in config["initialization"] if op["op"] == "call"]
                self.assertEqual(calls[0], 0x40220974)
                self.assertIn(0x402206f8, calls)
                self.assertEqual(calls[-1], 0x402086b4)
                writes = {op["address"]: op["hex"] for op in config["initialization"] if op["op"] == "write"}
                self.assertEqual(writes[0x3fff14b1], bytes([profile["settings"]["fx"]]).hex())
                self.assertEqual(writes.get(0x3fff1460), "01" if case["id"] == "warp" else None)

    def test_image_revisions_and_invalid_settings_fail_closed(self):
        with self.assertRaisesRegex(LabError, "load map"):
            cube.build_profile(self.elf, self.rom)
        for settings in ({"fx": 79}, {"fx": "warp"}, {"palette": 27}, {"symmetry": 3},
                         {"brightness": True}, {"dwell_s": 2}, {"colors": [[1, 2, 3]]},
                         {"boot_stage": "reset-rom"}, {"made_up": 1}):
            with self.subTest(settings=settings), self.assertRaises(LabError):
                self.profile(settings=settings)

    def test_control_changes_compile_into_bound_original_calls(self):
        trace = self.trace({1: {"fx": 124, "ix": 0}, 2: {"warp": True, "palette": 4}})
        profile = self.profile(settings={"boot_stage": "effect"}, trace=trace)
        commands, _, _ = compile_commands(profile, trace, _asset_paths(profile))
        frame1 = commands.split("frame 1 64000", 1)[1].split("frame 2", 1)[0]
        self.assertIn("wbytes 1073681585 7c", frame1)
        self.assertIn(f"callq {0x40207e5c} 1\ncallq {0x402057c8}\ncallq {0x4021c610}", frame1)
        self.assertIn(f"wbytes {0x3fff1460} 01", commands.split("frame 2", 1)[1])
        for change in ("missing", "duplicate", "mismatch", "extra", "out-of-range"):
            wrong = copy.deepcopy(profile)
            recipes = wrong["backend"]["options"]["ghidra"]["frame_operations"]
            if change == "missing": recipes.pop()
            elif change == "duplicate": recipes.append(copy.deepcopy(recipes[0]))
            elif change == "mismatch": recipes[0]["controls"]["ix"] = 1
            elif change == "extra": recipes[0]["index"] = 0
            else: recipes[0]["index"] = 99
            with self.subTest(change=change), self.assertRaises(LabError):
                compile_commands(wrong, trace, _asset_paths(wrong))
        with self.assertRaisesRegex(LabError, "boot-only"):
            self.profile(trace=self.trace({1: {"boot_stage": "effect"}}))

    def test_generated_band_trace_metadata_is_accepted(self):
        from vfl.stimuli import generate_trace
        trace = generate_trace(3, 32000)
        profile = self.profile(trace=trace)
        compile_commands(profile, trace, _asset_paths(profile))

    def test_scan_and_observer_preflight_rejects_ambiguous_configuration(self):
        profile = self.profile()
        trace = self.trace()
        commands = compile_commands(profile, trace, _asset_paths(profile))[0]
        self.assertIn("adc_scan 5 4 7 falling", commands)
        self.assertEqual(commands.count("\nobserve "), 96)
        for change in ("pins", "channels", "observer-hook", "observer-duplicate"):
            bad = copy.deepcopy(profile); config = bad["backend"]["options"]["ghidra"]
            if change == "pins": config["adc_scan"]["reset_pin"] = 4
            elif change == "channels": config["adc_scan"]["channels"] = 6
            elif change == "observer-hook": config["observations"][0]["address"] = config["hooks"][0]["address"]
            else: config["observations"].append(copy.deepcopy(config["observations"][0]))
            with self.subTest(change=change), self.assertRaises(LabError):
                compile_commands(bad, trace, _asset_paths(bad))

    def test_campaign_signal_interruption_stops_before_next_batch(self):
        import sys
        from vfl.model import load_json
        out = Path(self.temp.name) / "campaign"
        with patch.object(cube, "_verify_elf", return_value=(self.elf, file_digest(self.elf))), \
             patch.object(cube, "ROM_SHA256", file_digest(self.rom)), \
             patch("vfl.runner.run_process", side_effect=LabError("runner interrupted by SIGTERM")) as process:
            with self.assertRaisesRegex(LabError, "interrupted"):
                cube.run_coverage(self.elf, self.rom, out, case_ids=["fx-5", "fx-6"], batch_size=1, headless=sys.executable)
        self.assertEqual(process.call_count, 1)
        self.assertEqual(load_json(out / "campaign.json")["status"], "interrupted")
        self.assertFalse((out / "batch-001").exists())
        # Default coverage gives original startup time to elapse; the ordinary
        # trace helper keeps its separate32ms cadence for dense scenarios.
        emitted = load_json(out / "fx-5" / "input.json")
        self.assertEqual([f["time_us"] for f in emitted["frames"]], [n*1000000 for n in range(1,21)])
        self.assertEqual(cube.smoke_trace()["frames"][0]["time_us"],32000)

    def test_hold_appearing_while_launcher_waits_blocks_actual_guest_launch(self):
        import sys
        from tests.test_ghidra import configuration
        from vfl import ghidra
        from vfl.model import digest, experiment_digest, write_json
        from vfl.runner import run_process as real_run_process
        profile, trace = configuration(self.elf)
        hold = Path(self.temp.name) / "HOLD"
        config = profile["backend"]["options"]["ghidra"]
        config.update(headless=sys.executable, launcher_role="wrapper", post_launcher_hold_check=True, hold_files=[str(hold)])
        profile["firmware"].append({"role": "wrapper", "path": str(Path(sys.executable).resolve()), "sha256": file_digest(sys.executable)})
        request = {"schema": "vfl.request.v1", "request_id": secrets.token_hex(16), "profile": profile,
                   "trace": trace, "workdir": self.temp.name, "identities": {"input_sha256": digest(trace),
                   "profile_sha256": digest(profile), "experiment_sha256": experiment_digest(profile, trace)}}
        request_path = Path(self.temp.name) / "request.json"; write_json(request_path, request)
        def after_wait(argv, *args, **kwargs):
            hold.touch()  # Simulate the resource wrapper acquiring its lock after HOLD appeared.
            return real_run_process(argv[1:], *args, **kwargs)
        with patch.object(ghidra, "run_process", side_effect=after_wait), self.assertRaises(LabError):
            ghidra.execute_request(request_path, Path(self.temp.name) / "capture.json")
        self.assertIn("HOLD became active", (Path(self.temp.name) / "ghidra.stderr.log").read_text())
        self.assertFalse((Path(self.temp.name) / "capture.json").exists())

    def test_application_boot_and_effect_boot_are_distinct(self):
        full = self.profile()["backend"]["options"]["ghidra"]
        effect = self.profile(settings={"boot_stage": "effect"})["backend"]["options"]["ghidra"]
        self.assertGreater(len(full["hooks"]), len(effect["hooks"]))
        self.assertNotIn(0x402206f8, [op.get("address") for op in effect["initialization"]])
        self.assertEqual(full["adc_policy"], "strict")
        self.assertNotIn("allow_uninitialized", full)

    def test_image_preparation_preserves_authored_segments_and_rejects_overwrite(self):
        # Five tiny authored byte arrays in the expected five segment positions.
        pieces = [(a, bytes([i + 1]) * 4) for i, (a, _, _) in enumerate(cube.SEGMENTS)]
        data = bytearray(struct.pack("<BBBBI", 0xe9, 5, 3, 0x40, 0x401000b8)); checksum = 0xef
        for address, payload in pieces:
            data.extend(struct.pack("<II", address, len(payload))); data.extend(payload)
            for value in payload: checksum ^= value
        data.extend(bytes((15 - len(data) % 16) % 16)); data.append(checksum)
        source = Path(self.temp.name) / "authored-e9.bin"; source.write_bytes(data)
        target = Path(self.temp.name) / "wrapped.elf"
        metadata = tuple((a, len(b), hashlib.sha256(b).hexdigest()) for a, b in pieces)
        with patch.object(cube, "APP_SHA256", hashlib.sha256(data).hexdigest()), patch.object(cube, "SEGMENTS", metadata):
            result = cube.prepare_image(source, target)
            self.assertFalse(result["redistributable"])
            cube._verify_elf(target)
            with self.assertRaises(FileExistsError): cube.prepare_image(source, target)
            changed = bytearray(target.read_bytes()); changed[220] ^= 1; target.write_bytes(changed)
            with self.assertRaises(LabError): cube._verify_elf(target)


@unittest.skipUnless(os.environ.get("TYCVL_GHIDRA_INTEGRATION") == "1", "set TYCVL_GHIDRA_INTEGRATION=1 for real authored control execution")
class AuthoredControlExecutionTests(unittest.TestCase):
    def test_gpio_selects_adc_band_and_observer_preserves_original_execution(self):
        from tests.test_ghidra import configuration
        from vfl.ghidra import execute_request
        from vfl.model import digest, experiment_digest, load_json, write_json
        # Independently assembled call0 routine: preserve a0, keep output in a3,
        # call ADC three times/store bytes, restore a0 and return. ADC=0x1600.
        authored = bytes.fromhex("12c1f0026103203220455f00224300055f00224301855e00224302083112c1100df0")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); image = root / "authored-scan.elf"; image.write_bytes(tiny_elf(authored))
            for missing_reset in (False, True):
                directory = root / ("missing-reset" if missing_reset else "valid"); directory.mkdir()
                profile, trace = configuration(image)
                spec = {"kind": "bands", "channels": 3, "minimum": 0, "maximum": 255, "units": "count"}
                profile["input"] = spec; trace["input"] = spec
                for frame in trace["frames"]:
                    frame["values"] = [5, 100, 200]
                    frame["controls"] = {"pulse": True}
                config = profile["backend"]["options"]["ghidra"]
                config.update(hooks=[{"address": 0x1600, "kind": "adc"}, {"address": 0x1700, "kind": "gpio"}],
                    adc_scan={"reset_pin": 5, "strobe_pin": 4, "channels": 3, "advance_edge": "falling"},
                    observations=[{"address": 4096, "id": "authored-scan"}],
                    frame_calls=[{"op": "call", "address": 4096, "arguments": [8192]}])
                gpio = lambda pin, value: {"op": "call", "address": 0x1700, "arguments": [pin, value]}
                config["initialization"] = [] if missing_reset else [gpio(5, 1), gpio(5, 0)]
                config["frame_operations"] = [{"index": i, "controls": frame["controls"],
                    "operations": [gpio(4, 1), gpio(4, 0)]} for i, frame in enumerate(trace["frames"])]
                launcher = os.environ.get("TYCVL_GHIDRA_LAUNCHER")
                if launcher:
                    profile["firmware"].append({"role": "launcher", "path": str(Path(launcher).resolve()), "sha256": file_digest(launcher)})
                    config["launcher_role"] = "launcher"
                    config["launcher_environment"] = {"EMU_SLOTS": "1", "EMU_CPUS": "1", "EMU_MEM": "3072M"}
                request = {"schema": "vfl.request.v1", "request_id": secrets.token_hex(16), "profile": profile,
                           "trace": trace, "workdir": str(directory), "identities": {"input_sha256": digest(trace),
                           "profile_sha256": digest(profile), "experiment_sha256": experiment_digest(profile, trace)}}
                write_json(directory / "request.json", request)
                if missing_reset:
                    with self.assertRaises(LabError): execute_request(directory / "request.json", directory / "capture.json")
                    self.assertFalse((directory / "capture.json").exists())
                else:
                    execute_request(directory / "request.json", directory / "capture.json")
                    capture = load_json(directory / "capture.json")
                    self.assertEqual([frame["buses"]["main"] for frame in capture["frames"]], ["050505", "646464"])
                    self.assertEqual([event["channel"] for event in capture["events"] if event["kind"] == "adc"], [0, 0, 0, 1, 1, 1])
                    observers = [event for event in capture["events"] if event.get("operation") == "observe-entry"]
                    self.assertEqual([event["frame"] for event in observers], [0, 1])
                    self.assertTrue(all(event["observer_id"] == "authored-scan" for event in observers))

    def test_control_recipe_changes_captured_guest_memory(self):
        from tests.test_ghidra import configuration
        from vfl.ghidra import execute_request
        from vfl.model import digest, experiment_digest, load_json, write_json
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            image = directory / "authored-ret.elf"
            image.write_bytes(tiny_elf(bytes.fromhex("800000")))
            profile, trace = configuration(image)
            trace["frames"][0]["controls"] = {"color": [1, 2, 3]}
            trace["frames"][1]["controls"] = {"color": [4, 5, 6]}
            config = profile["backend"]["options"]["ghidra"]
            config["frame_calls"] = [{"op": "call", "address": 4096}]
            config["allow_unused_input"] = True
            config["frame_operations"] = [
                {"index": i, "controls": trace["frames"][i]["controls"],
                 "operations": [{"op": "write", "address": 8192, "hex": raw}]}
                for i, raw in enumerate(("010203", "040506"))]
            launcher = os.environ.get("TYCVL_GHIDRA_LAUNCHER")
            if launcher:
                profile["firmware"].append({"role": "launcher", "path": str(Path(launcher).resolve()), "sha256": file_digest(launcher)})
                config["launcher_role"] = "launcher"
                config["launcher_environment"] = {"EMU_SLOTS": "1", "EMU_CPUS": "1", "EMU_MEM": "3072M"}
            request = {"schema": "vfl.request.v1", "request_id": secrets.token_hex(16), "profile": profile,
                       "trace": trace, "workdir": str(directory), "identities": {"input_sha256": digest(trace),
                       "profile_sha256": digest(profile), "experiment_sha256": experiment_digest(profile, trace)}}
            write_json(directory / "request.json", request)
            execute_request(directory / "request.json", directory / "capture.json")
            capture = load_json(directory / "capture.json")
            self.assertEqual([f["buses"]["main"] for f in capture["frames"]], ["010203", "040506"])


if __name__ == "__main__":
    unittest.main()
