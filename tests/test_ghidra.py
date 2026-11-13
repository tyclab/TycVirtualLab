"""Source-generated, independently authored Xtensa fixture; no vendor images."""

import copy
import json
import os
from pathlib import Path
import secrets
import struct
import tempfile
import unittest
import sys

from vfl.ghidra import _asset_paths, _inner_timeout, compile_commands, execute_request
from vfl.model import LabError, digest, experiment_digest, file_digest
from vfl.runner import run_capture


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
               "target": {"chip": "authored-xtensa", "isa": "xtensa", "abi": "xtensa-call0"},
               "buses": [{"id": "main", "pixels": 1, "order": "RGB", "stage": "logical"}],
               "geometry": {"kind": "strips"}, "settings": {},
               "firmware": [{"role": "program", "format": "elf", "path": str(image), "sha256": file_digest(image)}],
               "backend": {"kind": "external", "execution_kind": "original-firmware",
                           "command": ["python3", "-m", "vfl.ghidra", "{request}", "{capture}"],
                           "timeout_s": 1000,
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

    def test_preflight_rejects_interlock_types_and_late_snapshot_errors(self):
        for changes in ({"hold_files": "HOLD"}, {"hold_files": ["relative/HOLD"]},
                        {"hold_files": [17]}, {"allow_uninitialized": "false"},
                        {"allow_unused_input": 0},
                        {"state": [{"id": "invalid id", "address": 8192, "size": 3}]},
                        {"state": [{"id": "large", "address": 8192, "size": 8 * 1024 * 1024 + 1}]}):
            p = copy.deepcopy(self.profile)
            p["backend"]["options"]["ghidra"].update(changes)
            with self.subTest(changes=changes), self.assertRaises(LabError):
                self.compile(p)

    def test_settings_require_exact_explicit_acknowledgement(self):
        p = copy.deepcopy(self.profile)
        p["settings"] = {"gain": 4}
        with self.assertRaisesRegex(LabError, "settings_acknowledgements"):
            self.compile(p)
        p["backend"]["options"]["ghidra"]["settings_acknowledgements"] = {"gain": 3}
        with self.assertRaises(LabError):
            self.compile(p)
        p["backend"]["options"]["ghidra"]["settings_acknowledgements"] = {"gain": 4}
        self.compile(p)

    def test_image_format_and_target_declaration_required(self):
        for key in ("target", "format"):
            p = copy.deepcopy(self.profile)
            if key == "target":
                p.pop("target")
            else:
                p["firmware"][0].pop("format")
            with self.subTest(key=key), self.assertRaises(LabError):
                self.compile(p)

    def test_elf_machine_class_and_byte_order_checked_before_forcing_language(self):
        from tests.test_firmware import elf_image
        for bits, endian, machine in ((32, "<", 3), (64, "<", 94), (32, ">", 94)):
            p = copy.deepcopy(self.profile)
            self.image.write_bytes(elf_image(bits=bits, endian=endian, machine=machine))
            p["firmware"][0]["sha256"] = file_digest(self.image)
            with self.subTest(bits=bits, endian=endian, machine=machine), self.assertRaisesRegex(
                    LabError, "32-bit little-endian Xtensa ELF"):
                self.compile(p)

    def test_overwrite_acknowledgement_is_explicit_bytes_and_sar_is_configurable(self):
        p = copy.deepcopy(self.profile)
        cfg = p["backend"]["options"]["ghidra"]
        cfg["memory_regions"].append({"address": 4096, "size": 1, "allow_elf_overlap": True})
        cfg["initialization"].append({"op": "register", "name": "SAR", "value": 31})
        commands = self.compile(p)[0]
        self.assertIn("wbytes 4096 00\n", commands)
        self.assertIn("reg SAR 31\n", commands)

    def test_inner_timeout_is_strictly_below_outer_timeout(self):
        p = copy.deepcopy(self.profile)
        p["backend"]["timeout_s"] = 100
        self.assertEqual(_inner_timeout(p, {}), 90)
        for value in (100, 101, 0, float("nan"), True):
            with self.subTest(value=value), self.assertRaises(LabError):
                _inner_timeout(p, {"timeout_s": value})

    def test_fake_headless_driver_contract_through_outer_runner(self):
        # This executable tests orchestration only. Actual instruction semantics
        # are covered by the separately enabled, pinned Ghidra integration tests.
        root = Path(self.temp.name)
        fake = root / "fake-headless"
        fake.write_text('''#!/usr/bin/env python3
import hashlib,json,sys
from pathlib import Path
i=sys.argv.index('-postScript')
script,commands,out,nonce,policy=sys.argv[i+1:]
raw=Path(commands).read_bytes()
binding={'schema':'tycvl.execution-binding.v1','request_id':nonce,'commands_sha256':hashlib.sha256(raw).hexdigest()}
decl={'schema':'vfl.boundary-log.v1','adc_log':False,'clock_log':False,'rng_log':False,'engine':{'name':'ghidra-pcode','version':'fake-driver-test','language':'Xtensa:LE:32:default','abi':'xtensa-call0'}}
lines=['E binding '+json.dumps(binding),'E instrumentation '+json.dumps(decl)]
frame=-1
for line in raw.decode().splitlines():
 p=line.split()
 if p[0]=='frame':frame=int(p[1])
 if p[0]=='dump':lines.append('D '+p[1]+' '+('%02x'%(frame+1))*int(p[3]))
lines.append('E done stubs=0 ms=1 maxsteps=6')
Path(out).write_text('\\n'.join(lines)+'\\n')
meta={**binding,'schema':'tycvl.ghidra-execution.v1','read_enforcement':'execute-read-fault','uninitialized_policy':policy,'uninitialized_reads':0,'uninitialized_regions':[],'uninitialized_regions_truncated':False}
Path(out+'.execution.json').write_text(json.dumps(meta))
''')
        fake.chmod(0o755)
        p = copy.deepcopy(self.profile)
        p["backend"]["command"][0] = sys.executable
        p["backend"]["env"] = {"PYTHONPATH": str(Path(__file__).resolve().parents[1])}
        p["backend"]["options"]["ghidra"]["headless"] = str(fake)
        # Nix sandboxes do not provide /usr/bin/env. Launch this script through
        # the exact test interpreter instead of relying on its text shebang.
        interpreter = Path(sys.executable).resolve()
        p["firmware"].append({"role": "fake_python", "path": str(interpreter), "sha256": file_digest(interpreter)})
        p["backend"]["options"]["ghidra"]["launcher_role"] = "fake_python"
        profile_path, trace_path = root / "profile.json", root / "trace.json"
        profile_path.write_text(json.dumps(p))
        trace_path.write_text(json.dumps(self.trace))
        capture = json.loads(run_capture(profile_path, trace_path, root / "run").read_text())
        self.assertEqual(capture["manifest"]["adapter_provenance"]["input_argument_values_supplied"], 2)
        self.assertEqual(capture["manifest"]["adapter_provenance"]["read_counts"], {"adc": 0, "clock": 0, "rng": 0})
        self.assertFalse(capture["manifest"]["capabilities"]["adc_log"])


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
            with self.assertRaises(LabError):
                self.run_profile(root, profile, trace)
            self.assertFalse((root / "capture.json").exists())
            self.assertIn("Uninitialized emulation read", (root / "ghidra.output").read_text())

    def test_guest_call_and_tail_jump_reach_hooks_and_return(self):
        # Independently assembled: stack-save a0; call0 ADC hook; increment/store
        # its return; restore a0; ret. A second entry tail-jumps to a return hook.
        code = bytes.fromhex("12c1f002610085010022c20122430022430122430202210012c11080000000008000000006000000800000")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "authored-guest-hooks.elf"
            image.write_bytes(tiny_elf(code))
            profile, trace = configuration(image)
            cfg = profile["backend"]["options"]["ghidra"]
            cfg["hooks"] = [{"address": 4128, "kind": "adc"}, {"address": 4136, "kind": "return", "value": 17}]
            cfg["frame_calls"] = [{"op": "call", "address": 4096, "arguments": [0, 8192]},
                                  {"op": "call", "address": 4132}]
            capture = self.run_profile(root, profile, trace)
            self.assertEqual([frame["buses"]["main"] for frame in capture["frames"]], ["010101", "020202"])
            self.assertEqual([event["value"] for event in capture["events"]], [0, 17, 1, 17])
            self.assertEqual(capture["manifest"]["completion"]["stubs"], 4)
            self.assertFalse(capture["manifest"]["capabilities"]["rng_log"])

    def test_windowed_call_and_loop_fail_before_capture(self):
        # Independently assembled call8 _start and j _start, respectively.
        for name, code, message in (("windowed", "e5ffff", "windowed instruction unsupported"),
                                    ("loop", "06ffff", "per-call instruction/step limit exceeded")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                image = root / (name + ".elf")
                image.write_bytes(tiny_elf(bytes.fromhex(code)))
                profile, trace = configuration(image)
                profile["backend"]["options"]["ghidra"]["instruction_limit"] = 8
                with self.assertRaises(LabError):
                    self.run_profile(root, profile, trace)
                self.assertIn(message, (root / "ghidra.output").read_text())
                self.assertFalse((root / "capture.json").exists())

    def test_zeroing_loaded_elf_requires_explicit_override(self):
        for allowed in (False, True):
            with self.subTest(allowed=allowed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                image = root / "authored-padding.elf"
                image.write_bytes(tiny_elf(bytes.fromhex("22c201224300224301224302800000aa")))
                profile, trace = configuration(image)
                cfg = profile["backend"]["options"]["ghidra"]
                cfg["memory_regions"].append({"address": 4111, "size": 1, "allow_elf_overlap": allowed})
                if allowed:
                    capture = self.run_profile(root, profile, trace)
                    self.assertEqual(capture["frames"][0]["buses"]["main"], "010101")
                else:
                    with self.assertRaises(LabError):
                        self.run_profile(root, profile, trace)
                    self.assertIn("zero region overlaps initialized ELF memory", (root / "ghidra.output").read_text())

    def test_unused_input_requires_explicit_optout(self):
        for allowed in (False, True):
            with self.subTest(allowed=allowed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                image = root / "authored-input-independent.elf"
                image.write_bytes(tiny_elf())
                profile, trace = configuration(image)
                cfg = profile["backend"]["options"]["ghidra"]
                cfg["frame_calls"][0]["arguments"] = [0, 8192]
                cfg["allow_unused_input"] = allowed
                if allowed:
                    capture = self.run_profile(root, profile, trace)
                    self.assertEqual(capture["manifest"]["adapter_provenance"]["input_argument_values_supplied"], 0)
                else:
                    with self.assertRaisesRegex(LabError, "no frame observed ADC input"):
                        self.run_profile(root, profile, trace)


if __name__ == "__main__":
    unittest.main()
