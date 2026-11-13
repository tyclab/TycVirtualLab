"""Source-generated, independently authored Xtensa fixture; no vendor images."""

import copy
import json
import os
from pathlib import Path
import secrets
import struct
import tempfile
import unittest

from vfl.ghidra import _asset_paths, compile_commands, execute_request
from vfl.model import LabError, digest, experiment_digest, file_digest


def tiny_elf(text=None):
    """ELF for our five-instruction add/store routine, assembled independently.

    addi a2,a2,1; s8i a2,a3,0; s8i a2,a3,1; s8i a2,a3,2; ret.
    The caller supplies the input and output address; expected bytes are input+1.
    Verified with GNU Xtensa assembler/disassembler. This is not extracted code.
    """
    if text is None:
        text = bytes.fromhex("22c201224300224301224302800000")
    names = b"\0.text\0.shstrtab\0"
    name_offset = 256 + len(text)
    section_offset = (name_offset + len(names) + 3) & ~3
    ident = b"\x7fELF\x01\x01\x01" + bytes(9)
    header = ident + struct.pack("<HHIIIIIHHHHHH", 2, 94, 1, 4096, 52, section_offset,
                                 0x300, 52, 32, 1, 40, 3, 2)
    program = struct.pack("<IIIIIIII", 1, 256, 4096, 4096, len(text), len(text), 5, 256)
    sections = (bytes(40) + struct.pack("<IIIIIIIIII", 1, 1, 6, 4096, 256, len(text), 0, 0, 4, 0)
                + struct.pack("<IIIIIIIIII", 7, 3, 0, 0, name_offset, len(names), 0, 0, 1, 0))
    return (header + program).ljust(256, b"\0") + text + names + bytes(section_offset - name_offset - len(names)) + sections


def configuration(image):
    spec = {"kind": "scalar", "channels": 1, "minimum": 0, "maximum": 255, "units": "count"}
    profile = {"schema": "vfl.profile.v1", "id": "authored-xtensa-add-store", "input": spec,
               "buses": [{"id": "main", "pixels": 1, "order": "RGB", "stage": "logical"}],
               "geometry": {"kind": "strips"}, "settings": {},
               "firmware": [{"role": "program", "path": str(image), "sha256": file_digest(image)}],
               "backend": {"kind": "external", "execution_kind": "original-firmware",
                           "command": ["python3", "-m", "vfl.ghidra", "{request}", "{capture}"],
                           "options": {"ghidra": {
                               "elf_role": "program",
                               "abi": {"kind": "xtensa-call0", "stack_pointer": 12272, "return_sentinel": 16384},
                               "memory_regions": [{"address": 8192, "size": 4096}],
                               "hooks": [], "initialization": [],
                               "frame_calls": [{"op": "call", "address": 4096, "arguments": [{"input": 0}, 8192]}],
                               "outputs": [{"id": "main", "address": 8192, "size": 3}],
                               "state": [{"id": "output-bytes", "address": 8192, "size": 3}],
                               "instruction_limit": 100, "max_frames": 4,
                           }}}}
    trace = {"schema": "vfl.trace.v1", "input": spec, "seed": 9, "clock_policy": "frame",
             "provenance": {"kind": "synthetic", "description": "Independently known add/store values"},
             "frames": [{"index": 0, "time_us": 1000, "values": [0], "controls": {}},
                        {"index": 1, "time_us": 2000, "values": [1], "controls": {}}]}
    return profile, trace


class GhidraScheduleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.image = Path(self.temp.name) / "authored.elf"
        self.image.write_bytes(tiny_elf())
        self.profile, self.trace = configuration(self.image)

    def compile(self, profile=None, trace=None):
        profile = profile or self.profile
        return compile_commands(profile, trace or self.trace, _asset_paths(profile))

    def test_explicit_schedule_has_known_input_calls_and_capture_regions(self):
        commands, outputs, state = self.compile()
        self.assertIn("abi pc a1 a0 a2,a3,a4,a5,a6,a7 a2 12272 16384\n", commands)
        self.assertIn("frame 0 1000 0\ntime 1\ncallq 4096 0 8192\n", commands)
        self.assertIn("frame 1 2000 1\ntime 2\ncallq 4096 1 8192\n", commands)
        self.assertEqual(outputs, {"output0": "main"})
        self.assertEqual(state, {"state0": "output-bytes"})

    def test_no_implicit_windowed_abi_or_stack(self):
        for key, value in (("abi", {"kind": "xtensa-windowed", "stack_pointer": 12272, "return_sentinel": 16384}),
                           ("memory_regions", [])):
            p = copy.deepcopy(self.profile)
            p["backend"]["options"]["ghidra"][key] = value
            with self.assertRaises(LabError):
                self.compile(p)

    def test_unknown_hooks_overlaps_and_wrong_bus_sizes_rejected(self):
        changes = [{"hooks": [{"address": 5000, "kind": "imaginary-peripheral"}]},
                   {"memory_regions": [{"address": 8192, "size": 4096}, {"address": 8200, "size": 16}]},
                   {"outputs": [{"id": "main", "address": 8192, "size": 4}]},
                   {"hooks": [{"address": 16384, "kind": "noop"}]},
                   {"state_encoding": "unspecified"}, {"instruction_limit": 10000001}]
        for change in changes:
            p = copy.deepcopy(self.profile)
            p["backend"]["options"]["ghidra"].update(change)
            with self.subTest(change=change), self.assertRaises(LabError):
                self.compile(p)

    def test_declared_binary_mapping_and_generic_hooks(self):
        p = copy.deepcopy(self.profile)
        c = p["backend"]["options"]["ghidra"]
        c["binary_mappings"] = [{"role": "program", "address": 20000, "offset": 256, "length": 3}]
        c["hooks"] = [{"address": 5000, "kind": "rng", "mode": "bounded"},
                      {"address": 5010, "kind": "write", "target": 8192, "width": 1, "value": 0},
                      {"address": 5020, "kind": "return", "value": 42}]
        commands, _, _ = self.compile(p)
        self.assertIn("wbytes 20000 22c201\n", commands)
        self.assertIn("hook 5000 rng bounded\n", commands)
        self.assertIn("hook 5010 write 8192 1 0\n", commands)

    def test_irregular_millisecond_schedule_allowed_submillisecond_rejected(self):
        trace = copy.deepcopy(self.trace)
        trace["frames"][1]["time_us"] = 17000
        self.assertIn("frame 1 17000 1", self.compile(trace=trace)[0])
        trace["frames"][1]["time_us"] = 17001
        with self.assertRaises(LabError):
            self.compile(trace=trace)

    def test_adc_policy_and_zero_seed_are_explicit(self):
        trace = copy.deepcopy(self.trace)
        trace["seed"] = 0
        commands = self.compile(trace=trace)[0]
        self.assertIn("adc_policy strict\nseed 0\n", commands)
        p = copy.deepcopy(self.profile)
        p["backend"]["options"]["ghidra"]["adc_policy"] = "cycle"
        self.assertIn("adc_policy cycle\n", self.compile(p, trace)[0])
        p["backend"]["options"]["ghidra"]["adc_policy"] = "guess"
        with self.assertRaises(LabError):
            self.compile(p, trace)

    def test_declared_windowed_target_rejected(self):
        p = copy.deepcopy(self.profile)
        p["target"] = {"chip": "example", "isa": "xtensa", "abi": "xtensa-windowed"}
        with self.assertRaisesRegex(LabError, "target ABI"):
            self.compile(p)

    def test_changed_asset_pin_rejected_before_execution(self):
        self.image.write_bytes(b"changed")
        with self.assertRaises(LabError):
            self.compile()

    def test_stale_request_identities_rejected_without_launch(self):
        request = {"schema": "vfl.request.v1", "request_id": secrets.token_hex(16),
                   "profile": self.profile, "trace": self.trace, "workdir": self.temp.name,
                   "identities": {"input_sha256": "0" * 64}}
        path = Path(self.temp.name) / "request.json"
        path.write_text(json.dumps(request))
        with self.assertRaisesRegex(LabError, "identities"):
            execute_request(path, Path(self.temp.name) / "capture.json")


@unittest.skipUnless(os.environ.get("TYCVL_GHIDRA_INTEGRATION") == "1", "set TYCVL_GHIDRA_INTEGRATION=1 with Ghidra configured")
class GhidraOriginalIntegrationTests(unittest.TestCase):
    def run_profile(self, root, profile, trace):
        config = profile["backend"]["options"]["ghidra"]
        config["timeout_s"] = 900
        launcher = os.environ.get("TYCVL_GHIDRA_LAUNCHER")
        if launcher:
            profile["firmware"].append({"role": "limiter", "path": str(Path(launcher).resolve()), "sha256": file_digest(launcher)})
            config.update(launcher_role="limiter", launcher_environment={"EMU_SLOTS": "1", "EMU_CPUS": "1", "EMU_MEM": "3072M", "EMU_NO_LIMIT": "0"})
        request = {"schema": "vfl.request.v1", "request_id": secrets.token_hex(16),
                   "profile": profile, "trace": trace, "workdir": str(root),
                   "identities": {"input_sha256": digest(trace), "profile_sha256": digest(profile),
                                  "experiment_sha256": experiment_digest(profile, trace)}}
        path = root / "request.json"
        path.write_text(json.dumps(request))
        result = root / "capture.json"
        execute_request(path, result)
        capture = json.loads(result.read_text())
        self.assertEqual(capture["manifest"]["request_id"], request["request_id"])
        self.assertEqual(capture["manifest"]["protocol_binding"]["request_id"], request["request_id"])
        return capture

    def test_original_authored_instructions_produce_independently_known_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "authored.elf"
            image.write_bytes(tiny_elf())
            profile, trace = configuration(image)
            capture = self.run_profile(root, profile, trace)
            self.assertEqual([f["buses"]["main"] for f in capture["frames"]], ["010101", "020202"])
            self.assertEqual(capture["manifest"]["execution_kind"], "original-firmware")
            self.assertEqual(capture["manifest"]["adapter_provenance"]["uninitialized_read_warning_count"], 0)

    def test_adc_exhaustion_cycle_zero_seed_and_clock_wrap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "authored.elf"
            image.write_bytes(tiny_elf())
            profile, trace = configuration(image)
            trace["seed"] = 0
            for index, frame in enumerate(trace["frames"]):
                frame["time_us"] = 4294968000 + index * 1000
            config = profile["backend"]["options"]["ghidra"]
            config["hooks"] = [{"address": 5000, "kind": "adc"}, {"address": 5010, "kind": "millis"},
                               {"address": 5020, "kind": "micros"}, {"address": 5030, "kind": "rng"}]
            # Hook entries still need executable bytes for the p-code decoder.
            # Each independently authored placeholder is a three-byte `ret`.
            config["initialization"] = [{"op": "write", "address": address, "hex": "800000"}
                                         for address in (5000, 5010, 5020, 5030)]
            config["frame_calls"] += [{"op": "call", "address": address} for address in (5000, 5000, 5010, 5020, 5030)]
            strict = root / "strict"
            strict.mkdir()
            with self.assertRaises(LabError):
                self.run_profile(strict, copy.deepcopy(profile), trace)
            self.assertIn("ADC input queue exhausted", (strict / "ghidra.output").read_text())
            cycle = root / "cycle"
            cycle.mkdir()
            config["adc_policy"] = "cycle"
            capture = self.run_profile(cycle, profile, trace)
            events = capture["events"]
            self.assertEqual([e["value"] for e in events if e["kind"] == "adc"], [0, 0, 1, 1])
            self.assertEqual([e["value"] for e in events if e["kind"] == "rng"], [270369, 67634689])
            self.assertEqual([e["value"] for e in events if e["kind"] == "clock" and e["units"] == "us"], [704, 1704])
            self.assertEqual([e["value"] for e in events if e["kind"] == "clock" and e["units"] == "ms"], [4294968, 4294969])

    def test_original_unmapped_read_is_rejected_by_default(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "authored-unmapped-read.elf"
            # Independently assembled: l32i a2,a2,0; ret.
            image.write_bytes(tiny_elf(bytes.fromhex("222200800000")))
            profile, trace = configuration(image)
            trace["frames"] = trace["frames"][:1]
            profile["backend"]["options"]["ghidra"]["frame_calls"] = [
                {"op": "call", "address": 4096, "arguments": [24576]}]
            with self.assertRaisesRegex(LabError, "read uninitialized state"):
                self.run_profile(root, profile, trace)
            self.assertFalse((root / "capture.json").exists())
            self.assertIn("read from uninitialized state", (root / "ghidra.stdout.log").read_text())


if __name__ == "__main__":
    unittest.main()
