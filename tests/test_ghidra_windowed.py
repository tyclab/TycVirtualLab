"""Independently authored window/loop fixtures, assembled with GNU Xtensa tools.

No bytes in this file were extracted from device firmware. Assembly is retained
beside its assembled encoding to make the known register and memory results reviewable.
"""
import copy
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

from tests.test_ghidra import configuration, tiny_elf
from tests import test_ghidra as fixtures
from vfl.ghidra import _asset_paths, compile_commands
from vfl.model import LabError

ASSEMBLY = r"""    .text
    .align 4
    .global _start
_start:
    entry a1,32
    s32i a2,a1,0
    call4 leaf
    l32i a2,a1,0
    s32i a6,a2,0
    s32i a7,a2,4
    s32i a8,a2,8
    s32i a9,a2,12
    call8 leaf
    l32i a2,a1,0
    s32i a10,a2,16
    s32i a11,a2,20
    s32i a12,a2,24
    s32i a13,a2,28
    call12 leaf
    l32i a2,a1,0
    s32i a14,a2,32
    s32i a15,a2,36
    movi a2,99
    retw.n
    .align 4
leaf:
    entry a1,32
    movi a2,11
    movi a3,22
    movi a4,33
    movi a5,44
    retw.n

    .align 4
    .global loop_test
loop_test:
    entry a1,32
    movi a3,0
    movi a4,6
    loop a4,1f
    addi a3,a3,1
    s8i a3,a2,0
    addi a2,a2,1
1:  movi a2,77
    retw.n

    .align 4
    .global indirect
indirect:
    entry a1,32
    s32i a2,a1,0
    movi a8,60
    addmi a8,a8,4096
    callx4 a8
    l32i a2,a1,0
    s32i a6,a2,0
    s32i a7,a2,4
    s32i a8,a2,8
    s32i a9,a2,12
    retw.n
    .align 4
    .global conditional_loop
conditional_loop:
    entry a1,32
    movi a4,0
    loopnez a3,2f
    addi a4,a4,1
    s8i a4,a2,0
    addi a2,a2,1
2:  retw.n
    .align 4
    .global nested
nested:
    entry a1,32
    s32i a2,a1,0
    movi a10,7
    call8 nested2
    l32i a2,a1,0
    s32i a10,a2,0
    retw.n
    .align 4
nested2:
    entry a1,32
    mov a6,a2
    call4 nested3
    mov a2,a6
    addi a2,a2,1
    retw.n
    .align 4
nested3:
    entry a1,32
    addi a2,a2,2
    retw.n
"""
CODE = bytes.fromhex("364100226100550300222100626200726201826202926203250200222100a26204b26205c26206d26207350100222100e26208f2620922a0631df00036410022a00b32a01642a02152a02c1df000000036410032a00042a00676840832c30132420022c20122a04d1df0000036410022610082a03c82d810d008002221006262007262018262029262031df036410042a00076930842c40142420022c2011df0364100226100a2a007a50000222100a262001df0364100206220d5000060262022c2011df000000036410022c2021df0")

ALLOCATOR_ASSEMBLY = '    .text\n    .align 4\n    .global _start\n_start:\n    entry a1,32\n    s32i a2,a1,0\n    movi a10,4\n    call8 allocate\n    mov a3,a10\n    movi a4,77\n    s32i a4,a3,0\n    mov a10,a3\n    movi a11,32\n    call8 resize\n    mov a3,a10\n    l32i a4,a3,0\n    l32i a2,a1,0\n    s32i a4,a2,0\n    mov a10,a3\n    call8 release\n    movi a10,2\n    movi a11,4\n    call8 clearallocate\n    l32i a4,a10,0\n    l32i a5,a10,4\n    l32i a2,a1,0\n    s32i a4,a2,4\n    s32i a5,a2,8\n    retw.n\n    .align 4\nallocate: entry a1,32\n    retw.n\n    .align 4\nresize: entry a1,32\n    retw.n\n    .align 4\nrelease: entry a1,32\n    retw.n\n    .align 4\nclearallocate: entry a1,32\n    retw.n\n    .align 4\nbadwrite:\n    entry a1,32\n    movi a10,4\n    call8 allocate\n    movi a2,99\n    s32i a2,a10,4\n    retw.n\n'
ALLOCATOR_CODE = bytes.fromhex('364100226100a2a004250400a03a2042a04d42630030a320b2a020a50300a03a2042230022210042620030a320e50200a2a002b2a004e50200422a00522a012221004262015262021df000003641001df00000003641001df00000003641001df00000003641001df0000000364100a2a004a5fdff22a063226a011df0')

FMA_ASSEMBLY = '    .text\n    .align 4\n    .global _start\n_start:\n    entry a1,32\n    wfr f0,a2\n    wfr f1,a3\n    wfr f2,a4\n    madd.s f0,f1,f2\n    rfr a2,f0\n    s32i a2,a5,0\n    retw.n\n    .align 4\nsubtract:\n    entry a1,32\n    wfr f0,a2\n    wfr f1,a3\n    wfr f2,a4\n    msub.s f0,f1,f2\n    rfr a2,f0\n    s32i a2,a5,0\n    retw.n\n'
FMA_CODE = bytes.fromhex('3641005002fa5013fa5024fa20014a4020fa2265001df0003641005002fa5013fa5024fa20015a4020fa2265001df0')

LONG_LOOP_ASSEMBLY = '    .text\n    .align 4\n    .global _start\n_start:\n    entry a1,32\n    movi a5,0\n    movi a3,5\n    loop a3,body\n    rsr.lend a4\n    wsr.lbeg a4\n    movi a4,long_end\n    wsr.lend a4\n    isync\n    rsr.lcount a4\n    s32i a4,a2,4\nbody:\n    addi a5,a5,1\n    .rept 150\n    nop.n\n    .endr\nlong_end:\n    rsr.lcount a4\n    s32i a5,a2,0\n    s32i a4,a2,8\n    movi a4,6\n    wsr.lcount a4\n    rsr.lcount a4\n    s32i a4,a2,12\n    movi a4,0\n    wsr.lcount a4\n    retw.n\n    .align 4\n    .global call0_loop_register\ncall0_loop_register:\n    rsr.lend a2\n    ret.n\n'
LONG_LOOP_CODE = (bytes.fromhex('5211000036410052a00032a00576831340010340001341faff40011300200040020349121b55') +
                  bytes.fromhex("3df0") * 150 + bytes.fromhex('400203590249220c6440021340020349320c044002131df000002001030df0'))

def window_profile(image):
    profile, trace = configuration(image)
    profile["target"]["abi"] = "xtensa-windowed"
    cfg = profile["backend"]["options"]["ghidra"]
    cfg["abi"]["kind"] = "xtensa-windowed"
    cfg["instruction_limit"] = 1000
    profile["buses"][0]["pixels"] = 30
    cfg["outputs"][0]["size"] = 90
    cfg["state"][0]["size"] = 90
    cfg["frame_calls"] = [
        {"op":"call", "address":0x1000, "arguments":[8192]},
        {"op":"call", "address":0x1050, "arguments":[8232]},
        {"op":"call", "address":0x106c, "arguments":[8240]},
        {"op":"call", "address":0x10a0, "arguments":[8256]},
        {"op":"call", "address":0x108c, "arguments":[8264, {"input":0}]},
        {"op":"call", "address":0x108c, "arguments":[8272, 0]},
    ]
    trace["frames"] = trace["frames"][:1]
    trace["frames"][0]["values"] = [6]
    return profile, trace

class WindowScheduleTests(unittest.TestCase):
    def test_windowed_abi_is_explicit_and_bound_to_target(self):
        with tempfile.TemporaryDirectory() as directory:
            image=Path(directory)/"authored.elf"; image.write_bytes(tiny_elf(CODE))
            profile,trace=window_profile(image)
            commands,_,_=compile_commands(profile,trace,_asset_paths(profile))
            self.assertIn("abi_windowed pc a1 a0", commands)
            profile["target"]["abi"]="xtensa-call0"
            with self.assertRaisesRegex(LabError,"target ABI"):
                compile_commands(profile,trace,_asset_paths(profile))


    def test_float32_bindings_are_explicit_and_cannot_feed_adc(self):
        with tempfile.TemporaryDirectory() as directory:
            image=Path(directory)/"authored.elf"; image.write_bytes(tiny_elf(CODE))
            profile,trace=window_profile(image)
            cfg=profile["backend"]["options"]["ghidra"]
            cfg["frame_calls"]=[{"op":"call","address":0x1000,"arguments":[8192]}]
            cfg["input_writes"]=[{"channel":0,"address":8200,"width":4,"encoding":"float32-le"}]
            trace["frames"][0]["values"]=[1.5]
            commands,_,_=compile_commands(profile,trace,_asset_paths(profile))
            self.assertIn("w32 8200 1069547520",commands)
            cfg["hooks"]=[{"address":0x1100,"kind":"adc"}]
            with self.assertRaisesRegex(LabError,"no ADC"):
                compile_commands(profile,trace,_asset_paths(profile))
            cfg["hooks"]=[];trace["frames"][0]["values"]=[1e100]
            with self.assertRaisesRegex(LabError,"float32"):
                compile_commands(profile,trace,_asset_paths(profile))

    def test_heap_preflight_rejects_aliases_and_missing_arena(self):
        with tempfile.TemporaryDirectory() as directory:
            image=Path(directory)/"authored.elf"; image.write_bytes(tiny_elf(CODE))
            profile,trace=window_profile(image)
            cfg=profile["backend"]["options"]["ghidra"]
            cfg["hooks"]=[{"address":0x1100,"kind":"malloc"}]
            with self.assertRaisesRegex(LabError,"explicit heap"):
                compile_commands(profile,trace,_asset_paths(profile))
            for address in (0x1000,0x2000):
                cfg["heap"]={"address":address,"size":256}
                with self.assertRaisesRegex(LabError,"overlaps"):
                    compile_commands(profile,trace,_asset_paths(profile))
            cfg["heap"]={"address":0x3000,"size":256}
            commands,_,_=compile_commands(profile,trace,_asset_paths(profile))
            self.assertIn("heap 12288 256",commands)

@unittest.skipUnless(os.environ.get("TYCVL_GHIDRA_INTEGRATION")=="1", "Ghidra integration opt-in")
class WindowExecutionTests(unittest.TestCase):
    run_profile=fixtures.GhidraOriginalIntegrationTests.run_profile

    def test_calls_locals_nested_indirect_and_hardware_loops(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/"authored.elf";image.write_bytes(tiny_elf(CODE))
            profile,trace=window_profile(image)
            capture=self.run_profile(root,profile,trace)
            result=bytes.fromhex(capture["frames"][0]["buses"]["main"])
            expected=bytearray(90)
            expected[:40]=struct.pack("<10I",11,22,33,44,11,22,33,44,11,22)
            expected[40:46]=bytes(range(1,7))
            expected[48:64]=struct.pack("<4I",11,22,33,44)
            expected[64:68]=struct.pack("<I",10)
            expected[72:78]=bytes(range(1,7))
            self.assertEqual(result,bytes(expected))
            self.assertEqual(capture["manifest"]["engine"]["abi"],"xtensa-windowed")

    def test_long_loop_register_relocation_and_count_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/"authored-long-loop.elf"
            image.write_bytes(tiny_elf(LONG_LOOP_CODE))
            profile,trace=window_profile(image);cfg=profile["backend"]["options"]["ghidra"]
            cfg["allow_unused_input"]=True
            cfg["frame_calls"]=[{"op":"call","address":0x1004,"arguments":[8192]}]
            capture=self.run_profile(root,profile,trace)
            raw=bytes.fromhex(capture["frames"][0]["buses"]["main"])
            # Five executions across a body larger than LOOP's immediate range;
            # count reads before/after are4/0, and explicit WSR.LCOUNT reads back6.
            self.assertEqual(raw[:16],struct.pack("<4I",5,4,0,6))
            execution=capture["manifest"]["adapter_provenance"]["execution_metadata"]
            self.assertEqual(execution["loop_register_reads"],4)
            self.assertEqual(execution["loop_register_writes"],4)

    def test_call0_loop_register_access_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/"authored-call0-loop-register.elf"
            image.write_bytes(tiny_elf(LONG_LOOP_CODE))
            profile,trace=window_profile(image);cfg=profile["backend"]["options"]["ghidra"]
            profile["target"]["abi"]="xtensa-call0";cfg["abi"]["kind"]="xtensa-call0"
            cfg["allow_unused_input"]=True
            cfg["frame_calls"]=[{"op":"call","address":0x116c}]
            with self.assertRaises(LabError):self.run_profile(root,profile,trace)
            self.assertIn("loop-register",(root/"ghidra.output").read_text())

    def test_mixed_call0_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/"authored.elf"
            # entry a1,32; call0 to self. The guard must reject before entering it.
            image.write_bytes(tiny_elf(bytes.fromhex("364100c5ffff")))
            profile,trace=window_profile(image)
            cfg=profile["backend"]["options"]["ghidra"]
            cfg["frame_calls"]=cfg["frame_calls"][:1]
            with self.assertRaises(LabError):self.run_profile(root,profile,trace)
            self.assertIn("mixed-call0",(root/"ghidra.output").read_text())

    def test_windowed_f32_helper_boundary_has_known_ieee_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/"authored-f32-caller.elf"
            # entry; move two arguments to call8 registers; call hook;
            # store result through third argument; retw. Hook has entry/retw bytes.
            image.write_bytes(tiny_elf(bytes.fromhex("36410020a22030b320a50000a264001df00000003641001df0")))
            profile,trace=window_profile(image)
            cfg=profile["backend"]["options"]["ghidra"]
            cfg["hooks"]=[{"address":0x1014,"kind":"f32_div"}]
            cfg["frame_calls"]=[{"op":"call","address":0x1000,"arguments":[0x3f800000,0x40400000,8192]}]
            cfg["allow_unused_input"]=True
            capture=self.run_profile(root,profile,trace)
            self.assertEqual(capture["frames"][0]["buses"]["main"][:8],"abaaaa3e")
            event=capture["events"][0]
            self.assertEqual(event["source"],"java-ieee754-f32-division")
            self.assertEqual(event["value"],0x3eaaaaab)
            self.assertEqual(event["right_operand_bits"],0x40400000)

    def test_bounded_allocator_preserves_bytes_calloc_zeroes_and_guards_writes(self):
        for bad in (False,True):
            with self.subTest(bad=bad),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);image=root/"authored-allocator.elf";image.write_bytes(tiny_elf(ALLOCATOR_CODE))
                profile,trace=window_profile(image);cfg=profile["backend"]["options"]["ghidra"]
                cfg["heap"]={"address":0x3000,"size":256};cfg["allow_unused_input"]=True
                cfg["hooks"]=[{"address":address,"kind":kind} for address,kind in ((0x104c,"malloc"),(0x1054,"realloc"),(0x105c,"free"),(0x1064,"calloc"))]
                cfg["frame_calls"]=[{"op":"call","address":0x106c if bad else 0x1000,"arguments":[8192]}]
                if bad:
                    with self.assertRaises(LabError): self.run_profile(root,profile,trace)
                    self.assertIn("heap read/write outside a live allocation",(root/"ghidra.output").read_text())
                else:
                    capture=self.run_profile(root,profile,trace)
                    self.assertEqual(bytes.fromhex(capture["frames"][0]["buses"]["main"])[:12],struct.pack("<3I",77,0,0))
                    self.assertEqual([e["operation"] for e in capture["events"]],["malloc","realloc","free","calloc"])
                    self.assertTrue(all(e["source"]=="bounded-first-fit-runtime-allocator" for e in capture["events"]))

    def test_fused_madd_and_msub_keep_exact_small_residual(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/"authored-fma.elf";image.write_bytes(tiny_elf(FMA_CODE))
            profile,trace=window_profile(image);cfg=profile["backend"]["options"]["ghidra"]
            cfg["allow_unused_input"]=True
            cfg["frame_calls"]=[
                {"op":"call","address":0x1000,"arguments":[0xbf800000,0x3f800001,0x3f7ffffe,8192]},
                {"op":"call","address":0x1018,"arguments":[0x3f800000,0x3f800001,0x3f7ffffe,8196]},
            ]
            capture=self.run_profile(root,profile,trace)
            # (1+2^-23)*(1-2^-23) = 1-2^-46 exactly. One final rounding
            # gives -2^-46 for add(-1) and +2^-46 for subtract-from(+1).
            # Two binary32 rounds would erase this residual and give zero.
            raw=bytes.fromhex(capture["frames"][0]["buses"]["main"])
            self.assertEqual(raw[:8],struct.pack("<2I",0xa8800000,0x28800000))

    def test_fused_nonfinite_operands_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);image=root/"authored-fma-nan.elf";image.write_bytes(tiny_elf(FMA_CODE))
            profile,trace=window_profile(image);cfg=profile["backend"]["options"]["ghidra"]
            cfg["allow_unused_input"]=True
            cfg["frame_calls"]=[{"op":"call","address":0x1000,"arguments":[0,0x7fc00000,0x3f800000,8192]}]
            with self.assertRaises(LabError): self.run_profile(root,profile,trace)
            self.assertIn("non-finite fused float operand",(root/"ghidra.output").read_text())
