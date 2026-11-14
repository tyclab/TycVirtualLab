"""Exoy setup contracts using authored ELF bytes, never vendor firmware."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests.test_ghidra import tiny_elf
from vfl.devices import exoy
from vfl.ghidra import _asset_paths, compile_commands
from vfl.model import LabError, file_digest


class ExoySetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.image = Path(self.temp.name) / "authored.elf"
        self.image.write_bytes(tiny_elf())
        self.trace = {"schema": "vfl.trace.v1", "input": exoy.INPUT, "seed": 17,
                      "clock_policy": "frame", "provenance": {"kind": "synthetic", "description": "setup test"},
                      "frames": [{"index": 0, "time_us": 0, "values": [0, 255], "controls": {}},
                                 {"index": 1, "time_us": 20000, "values": [80, 120],
                                  "controls": {"effect": 4, "hue": 100}}]}

    def build(self, **kwargs):
        with patch.object(exoy, "_verify_elf", return_value=(self.image, file_digest(self.image))):
            return exoy.build_profile(self.image, **kwargs)

    def test_catalog_preserves_pack_bounds_and_scene_names(self):
        self.assertEqual([len(effects) for _, effects in exoy.PACKS], [7, 11, 6, 5, 6, 9, 11, 8, 7])
        self.assertEqual(len(exoy.effect_inventory()), 70)
        self.assertEqual(exoy.PACKS[8][1][3:5], ("Custom Hue", "Color Carousel"))
        with self.assertRaises(LabError): exoy.settings({"pack": 8, "effect": 7})
        with self.assertRaises(LabError): exoy.settings({"gain": 99})

    def test_null_controls_leave_selection_to_original_fallback(self):
        profile = self.build()
        self.assertIsNone(profile["settings"]["speed"])
        config = profile["backend"]["options"]["ghidra"]
        table = 0x3ffbdbb0 + exoy.DEFAULTS["pack"]*360 + exoy.DEFAULTS["effect"]*12
        writes = {op["address"]:op["hex"] for op in config["initialization"] if op["op"] == "write"}
        self.assertEqual([writes[table+i*4] for i in range(3)], ["ffffffff"]*3)
        with self.assertRaises(LabError): exoy.settings({"speed": -1})

    def test_geometry_requires_a_complete_permutation_and_explicit_reversal(self):
        with self.assertRaises(LabError): exoy.settings({"strip_order": [0] * 30})
        with self.assertRaises(LabError): exoy.settings({"strip_reverse": [False] * 29})
        with self.assertRaises(LabError): exoy.settings({"strip_reverse": [0] * 30})
        valid = exoy.settings({"strip_order": list(reversed(range(30)))})
        self.assertEqual(valid["strip_order"][0], 29)

    def test_unknown_elf_cannot_enter_original_execution(self):
        with self.assertRaises(LabError): exoy.build_profile(self.image)

    def test_null_control_sentinel_is_checked_against_image_initializer(self):
        # Authored uniform initializers exercise the revision assertion without
        # embedding any firmware or palette bytes.
        data=bytearray(8)+bytearray(b"\xff"*(9*30*3*4))
        loaded=[{"virtual_address":0x3ffbdbb0,"file_offset":8,"file_size":len(data)-8}]
        exoy._verify_control_defaults(data,loaded)
        data[-1]=0
        with self.assertRaisesRegex(LabError,"control defaults"):
            exoy._verify_control_defaults(data,loaded)

    def test_windowed_controls_audio_bindings_and_runtime_boundary_are_explicit(self):
        profile = self.build(trace=self.trace)
        commands, _, _ = compile_commands(profile, self.trace, _asset_paths(profile))
        self.assertIn("abi_windowed pc", commands)
        self.assertIn(" f32_div\n", commands)
        self.assertIn(f"w8 {0x3ffd0490} 80\n", commands)
        config = profile["backend"]["options"]["ghidra"]
        self.assertEqual(config["frame_operations"][0]["controls"], self.trace["frames"][1]["controls"])
        self.assertEqual(profile["buses"][0]["stage"], "logical")
        self.assertTrue(any("division" in line for line in profile["metadata"]["limitations"]))
        self.assertEqual(profile["settings"], config["settings_acknowledgements"])

    def test_frame_unknown_setting_and_out_of_range_scene_fail_before_execution(self):
        for controls in ({"typo": 1}, {"pack": 0, "effect": 8}):
            trace = copy.deepcopy(self.trace)
            trace["frames"][1]["controls"] = controls
            with self.assertRaises(LabError): self.build(trace=trace)

    def test_input_binding_rejects_width_overflow_and_bad_channel(self):
        profile = self.build(trace=self.trace)
        cfg = profile["backend"]["options"]["ghidra"]
        cfg["input_writes"][0]["channel"] = 2
        trace = copy.deepcopy(self.trace); trace["frames"] = trace["frames"][:1]
        with self.assertRaises(LabError): compile_commands(profile, trace, _asset_paths(profile))
        cfg["input_writes"][0]["channel"] = 0
        trace["input"] = {**trace["input"], "maximum": 1023}
        trace["frames"][0]["values"][0] = 256
        with self.assertRaises(LabError): compile_commands(profile, trace, _asset_paths(profile))


    def test_adc_packets_execute_original_microphone_code(self):
        trace = exoy.smoke_trace(2)
        profile = self.build(trace=trace)
        config = profile["backend"]["options"]["ghidra"]
        hooks = {hook["address"]: hook["kind"] for hook in config["hooks"]}
        self.assertEqual(hooks[0x400efcf0], "adc")
        self.assertNotIn(0x400ddbe0, hooks)
        self.assertNotIn("input_writes", config)
        self.assertEqual(profile["input"], exoy.ADC_INPUT)
        commands, _, _ = compile_commands(profile, trace, _asset_paths(profile))
        self.assertIn("frame 0 0 2048 2065 2082", commands)
        self.assertIn(f"observe {0x400ddbe0} audio-dsp", commands)
        self.assertEqual([len(frame["values"]) for frame in trace["frames"]], [64, 64])
        self.assertEqual(exoy.device_info()["input"],exoy.ADC_INPUT)
        self.assertTrue(any("Original microphone routine consumes" in line for line in exoy.device_info()["limitations"]))
        self.assertEqual(exoy.device_info()["renderer_input_limitations"],[exoy.RENDERER_INPUT_LIMITATION])
        self.assertIn(exoy.RENDERER_INPUT_LIMITATION,self.build(trace=self.trace)["metadata"]["limitations"])

    def test_rom_must_match_identified_image(self):
        with self.assertRaises(LabError): self.build(rom=self.image)

    def test_modeled_stack_and_heap_do_not_alias_app_or_rom_state(self):
        config=self.build()["backend"]["options"]["ghidra"]
        stack=config["memory_regions"][0];heap=config["heap"]
        self.assertEqual(config["abi"]["stack_pointer"],stack["address"]+stack["size"])
        # Address ranges from the identified image and ROM ELF section headers;
        # reserve ROM data/BSS/PRO/APP stacks, even when they are not imported.
        reserved=[(address,address+size) for address,size,_ in exoy.SEGMENTS]
        reserved += [(0x3ffc5260,0x3ffd6280),(0x3ffae000,0x3ffc0000),
                     (0x3ffe0000,0x3ffe7e30)]
        for region in (stack,heap):
            start,end=region["address"],region["address"]+region["size"]
            self.assertTrue(all(end<=left or right<=start for left,right in reserved))
        self.assertLessEqual(stack["address"]+stack["size"],heap["address"])

    def test_coverage_selection_and_trace_fail_before_output(self):
        output = Path(self.temp.name) / "coverage"
        for ids in (["p99-e0"], ["p0-e0", "p0-e0"], []):
            with self.assertRaises(LabError):
                exoy.run_coverage(self.image, self.image, output, case_ids=ids)
            self.assertFalse(output.exists())
        trace = exoy.smoke_trace(1); trace["frames"][0]["controls"] = {"effect":1}
        with self.assertRaises(LabError):
            exoy.run_coverage(self.image, self.image, output, case_ids=["p0-e0"], trace=trace)
        self.assertFalse(output.exists())
        self.assertEqual(len({case["id"] for case in exoy.coverage_plan()}), 70)

    def test_source_checkout_backend_imports_outside_repository(self):
        import os
        import subprocess
        with patch.object(exoy.shutil, "which", return_value=None): profile = self.build()
        env = {**os.environ, **profile["backend"]["env"]}
        result = subprocess.run(profile["backend"]["command"][:3] + ["--help"],
                                cwd=self.temp.name, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("tycvl Ghidra: usage", result.stderr)
        self.assertNotIn("No module named", result.stderr)


    def test_live_brightness_preserves_geometry_and_unrelated_controls(self):
        trace=copy.deepcopy(self.trace)
        trace["frames"][1]["controls"]={"brightness":80}
        profile=self.build(trace=trace);cfg=profile["backend"]["options"]["ghidra"]
        operations=cfg["frame_operations"][0]["operations"]
        self.assertEqual(operations,[{"op":"write","address":0x3ffc53cc,"hex":"50"}])
        self.assertEqual(sum(op.get("address")==0x400d6874 for op in cfg["initialization"]),1)
        # Apply those writes to an authored state map: all strip/palette/phase
        # bytes retain their sentinel values across the live control change.
        memory={address:(address*7)&255 for address in range(0x3ffc5300,0x3ffc6600)}
        before=memory.copy()
        for op in operations:
            for i,value in enumerate(bytes.fromhex(op["hex"])): memory[op["address"]+i]=value
        self.assertEqual({a:v for a,v in memory.items() if a!=0x3ffc53cc},
                         {a:v for a,v in before.items() if a!=0x3ffc53cc})
        trace["frames"][1]["controls"]={"brightness":255}
        profile=self.build(trace=trace)
        self.assertEqual(profile["backend"]["options"]["ghidra"]["frame_operations"][0]["operations"],[])
        compile_commands(profile,trace,_asset_paths(profile))

    def test_geometry_is_boot_only_and_input_annotations_are_compatible(self):
        for key in ("strip_order","strip_reverse"):
            trace=copy.deepcopy(self.trace);trace["frames"][1]["controls"]={key:None}
            with self.assertRaisesRegex(LabError,"boot-only"): self.build(trace=trace)
        for spec in (exoy.INPUT,exoy.ADC_INPUT):
            trace=copy.deepcopy(self.trace) if spec==exoy.INPUT else exoy.smoke_trace(2)
            trace["input"]={**spec,"description":"extra input annotation"}
            self.assertEqual(self.build(trace=trace)["input"],spec)
            for key,value in (("maximum",65535),("units","wrong")):
                bad=copy.deepcopy(trace);bad["input"][key]=value
                with self.assertRaises(LabError):self.build(trace=bad)
        profile=self.build(hold_files=["relative-HOLD"])
        self.assertTrue(Path(profile["backend"]["options"]["ghidra"]["hold_files"][0]).is_absolute())
        with self.assertRaises(LabError):self.build(hold_files="relative-HOLD")
        hold=Path(self.temp.name)/"HOLD";hold.symlink_to("missing-target")
        self.assertEqual(self.build(hold_files=[hold])["backend"]["options"]["ghidra"]["hold_files"],[str(hold)])

    def test_cli_default_preparation_uses_observed_audio_enabled_scene(self):
        import contextlib,io,json
        from vfl.cli import main
        output=Path(self.temp.name)/"prepared.json"
        with patch.object(exoy,"_verify_elf",return_value=(self.image,file_digest(self.image))),contextlib.redirect_stdout(io.StringIO()):
            code=main(["device","prepare","exoy-one","--elf",str(self.image),"--out",str(output)])
        self.assertEqual(code,0)
        profile=json.loads(output.read_text())
        self.assertEqual((profile["settings"]["pack"],profile["settings"]["effect"]),(1,4))
        self.assertTrue(profile["settings"]["sound_reactive"])
        self.assertEqual(profile["input"],exoy.ADC_INPUT)
        hooks={h["address"]:h["kind"] for h in profile["backend"]["options"]["ghidra"]["hooks"]}
        self.assertEqual(hooks[0x400efcf0],"adc")
        self.assertNotIn(0x400ddbe0,hooks)


if __name__ == "__main__": unittest.main()
