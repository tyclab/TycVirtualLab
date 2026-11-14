"""Authored instruction-edge fixtures; no vendor code or expected device output."""
import copy
import os
from pathlib import Path
import struct
import tempfile
import unittest

from tests.test_ghidra import configuration, tiny_elf
from tests import test_ghidra as fixtures
from tests.test_ghidra_windowed import window_profile
from vfl.ghidra import compile_commands, _asset_paths, _float_bits
from vfl.model import LabError
from vfl.hsemu import _expected, HsemuError

ASSEMBLY = '    .text\n    .align 4\n    .global _start\n_start:\n    entry a1,32\n    .begin no-transform\n    movi a3,0\n    .end no-transform\n    s32i a3,a2,0\n    movi a3,0\n    movi a4,6\n    loop a4,break_end\n    addi a3,a3,1\n    j break_end\nbreak_end:\n    s32i a3,a2,4\n    movi a3,0\n    movi a4,6\n    loop a4,false_end\n    addi a3,a3,1\n    beqz a3,false_end\nfalse_end:\n    s32i a3,a2,8\n    movi a3,0\n    movi a4,0\n    loopnez a4,skip_end\n    addi a3,a3,1\nskip_end:\n    s32i a3,a2,12\n    retw.n\n    .align 4\n    .global tail_main\ntail_main:\n    entry a1,32\n    s32i a2,a1,0\n    call8 entered_tail\n    l32i a2,a1,0\n    s32i a10,a2,0\n    retw.n\n    .align 4\nentered_tail:\n    entry a1,32\n    j hook\n    .align 4\n    .global thunk_main\nthunk_main:\n    entry a1,32\n    s32i a2,a1,0\n    call8 thunk\n    l32i a2,a1,0\n    s32i a10,a2,0\n    retw.n\n    .align 4\nthunk:\n    j hook\n    .align 4\n    .global hook\nhook:\n    entry a1,32\n    retw.n\n    .align 4\n    .global call0_loop\ncall0_loop:\n    movi a3,2\n    loop a3,call0_end\n    addi a2,a2,1\ncall0_end:\n    ret.n\n'
CODE = bytes.fromhex('36410032a00039020c0342a0067684041b33c6ffff39120c030c647684041b3316f3ff39220c030c047694011b3339321df000003641002901a500002801a9021df0000036410046050000003641002901a500002801a9021df00000060000003641001df00000000c237683011b220df0')


def profile_for(image, entry=0x1000):
    profile, trace = window_profile(image)
    cfg = profile["backend"]["options"]["ghidra"]
    cfg["frame_calls"] = [{"op":"call","address":entry,"arguments":[8192]}]
    cfg["allow_unused_input"] = True
    return profile, trace


class ReviewedPreflightTests(unittest.TestCase):
    def test_float32_huge_integer_has_a_bounded_validation_error(self):
        with self.assertRaisesRegex(LabError,"finite float32 range"):
            _float_bits(10**10000)

    def test_tail_policy_is_explicit_per_hook_and_windowed_only(self):
        with tempfile.TemporaryDirectory() as directory:
            image=Path(directory)/"authored.elf"; image.write_bytes(tiny_elf(CODE))
            profile,trace=profile_for(image)
            cfg=profile["backend"]["options"]["ghidra"]
            cfg["hooks"]=[{"address":0x1060,"kind":"return","value":17,"windowed_tail":"entered"}]
            commands,_,_=compile_commands(profile,trace,_asset_paths(profile))
            self.assertIn("hook_tail 4192 entered",commands)
            _expected(commands,"emulator")
            with self.assertRaisesRegex(HsemuError,"tail policy"):
                _expected(commands.replace("hook_tail 4192 entered","hook_tail 4192 guessed"),"emulator")
            cfg["hooks"][0]["windowed_tail"]="guess"
            with self.assertRaisesRegex(LabError,"windowed_tail"):
                compile_commands(profile,trace,_asset_paths(profile))
            cfg["hooks"][0]["windowed_tail"]="entered"
            profile["target"]["abi"]=cfg["abi"]["kind"]="xtensa-call0"
            with self.assertRaisesRegex(LabError,"windowed tail policy"):
                compile_commands(profile,trace,_asset_paths(profile))


@unittest.skipUnless(os.environ.get("TYCVL_GHIDRA_INTEGRATION")=="1", "Ghidra integration opt-in")
class ReviewedExecutionTests(unittest.TestCase):
    run_profile=fixtures.GhidraOriginalIntegrationTests.run_profile

    def test_loop_branch_to_end_untaken_branch_skip_and_sleigh_ps_layout(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/"authored.elf";image.write_bytes(tiny_elf(CODE))
            profile,trace=profile_for(image)
            capture=self.run_profile(root,profile,trace)
            raw=bytes.fromhex(capture["frames"][0]["buses"]["main"])
            # Known zero, taken j executes once, untaken
            # conditional falls through/repeats six times, LOOPNEZ(0) skips.
            self.assertEqual(struct.unpack("<4I",raw[:16]),(0,1,6,0))
            self.assertEqual(capture["manifest"]["engine"]["version"],"12.0.4")
            # Privileged RSR.PS is intentionally unsupported. Verify the actual
            # pinned processor definition instead; successful nested CALLn/ENTRY
            # fixtures independently establish that this layout is operational.
            import shutil
            executable=Path(os.environ.get("GHIDRA_HEADLESS") or shutil.which("ghidra-analyzeHeadless")).resolve()
            definitions=list(executable.parent.parent.rglob("xtensaArch.sinc"))
            self.assertEqual(len(definitions),1)
            self.assertRegex(definitions[0].read_text(),r'PS_CALLINC\s+"PS\[12,2\]"')

    def test_entered_window_tail_hook_requires_explicit_policy(self):
        for allowed in (False,True):
            with self.subTest(allowed=allowed),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);image=root/"authored.elf";image.write_bytes(tiny_elf(CODE))
                profile,trace=profile_for(image,0x1034)
                hook={"address":0x1060,"kind":"return","value":17}
                if allowed:hook["windowed_tail"]="entered"
                profile["backend"]["options"]["ghidra"]["hooks"]=[hook]
                if allowed:
                    capture=self.run_profile(root,profile,trace)
                    self.assertEqual(capture["frames"][0]["buses"]["main"][:8],"11000000")
                else:
                    with self.assertRaises(LabError):self.run_profile(root,profile,trace)
                    self.assertIn("explicit entered-window tail policy",(root/"ghidra.output").read_text())

    def test_no_entry_thunk_is_not_guessed_as_entered_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/"authored.elf";image.write_bytes(tiny_elf(CODE))
            profile,trace=profile_for(image,0x104c)
            profile["backend"]["options"]["ghidra"]["hooks"]=[{"address":0x1060,"kind":"return","value":17}]
            with self.assertRaises(LabError):self.run_profile(root,profile,trace)
            self.assertIn("explicit entered-window tail policy",(root/"ghidra.output").read_text())

    def test_call0_hardware_loop_fails_instead_of_running_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/"authored.elf";image.write_bytes(tiny_elf(CODE))
            profile,trace=configuration(image)
            profile["backend"]["options"]["ghidra"]["frame_calls"]=[{"op":"call","address":0x1068,"arguments":[8192]}]
            with self.assertRaises(LabError):self.run_profile(root,profile,trace)
            self.assertIn("hardware loop instruction unsupported in call0",(root/"ghidra.output").read_text())


if __name__=="__main__":unittest.main()
