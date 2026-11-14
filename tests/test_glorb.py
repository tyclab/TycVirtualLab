import copy
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from vfl.devices import glorb
from vfl.glorb_host import compile_commands, parse_output
from vfl.model import LabError, load_json, write_json
from vfl.runner import run_capture, load_completed_capture


FIXTURE = r'''
#include "wled.h"
static void draw() {
  um_data_t *audio;
  UsermodManager::getUMData(&audio, USERMOD_ID_AUDIOREACTIVE);
  const auto level=uint8_t(*static_cast<float*>(audio->u_data[0]));
  ++SEGENV.step;
  SEGMENT.fill(RGBW32(level,SEGENV.step,0,0));
}
struct Fixture : Usermod {
 void setup() override {
  for (auto name : {"Colorwaves@", "Running@", "Frizzles@", "Black Hole@", "Hiphotic@", "Tartan@"})
    strip.addEffect(0, draw, name);
 }
} glorb_fx;
'''


class GradientTests(unittest.TestCase):
    def test_fixed_point_linear_ramp_and_sparse_slot_boundaries(self):
        self.assertEqual(glorb.expand_gradient([[0,0,0,0],[255,255,255,255]]), [[17*i]*3 for i in range(16)])
        palette=glorb.expand_gradient([[0,255,0,0],[16,0,255,0],[255,0,0,255]])
        self.assertEqual(palette[:3], [[255,0,0],[0,255,0],[0,255,0]])
        self.assertEqual(palette[-1], [0,0,254])
        with self.assertRaises(LabError): glorb.expand_gradient([[0,0,0,0],[254,255,255,255]])


@unittest.skipUnless(shutil.which('c++'), 'C++ compiler required for native boundary checks')
class HostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.root=Path(cls.tmp.name)
        cls.source=cls.root/'fixture.cpp'
        cls.source.write_text(FIXTURE)
        cls.build=glorb.build_host(cls.source,cls.root/'build')
        cls.profile=glorb.build_profile(cls.source,cls.build['executable'],[2,-1,0,3],[[i*17]*3 for i in range(16)],width=2,height=2)
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()

    def trace(self):
        return {'schema':'vfl.trace.v1','input':copy.deepcopy(glorb.INPUT),'seed':1,'clock_policy':'frame',
                'provenance':{'kind':'authored-test'},'frames':[
                  {'index':i,'time_us':i*16000,'values':[10+i],'controls':({'effect':'running'} if i==2 else {})}
                  for i in range(4)]}

    def test_actual_native_mapping_state_reset_audio_binding_and_tampering(self):
        profile=self.root/'profile.json';trace=self.root/'trace.json'
        write_json(profile,self.profile);write_json(trace,self.trace())
        path=run_capture(profile,trace,self.root/'run')
        capture=load_completed_capture(path)
        first=capture['frames'][0]
        self.assertEqual(first['buses']['logical'],'0a01000000000a01000a0100')
        self.assertEqual(first['buses']['mapped'],'0a01000000000a01000a0100')
        self.assertEqual([bytes.fromhex(f['state']['segment'])[0] for f in capture['frames']],[1,2,1,2])
        self.assertEqual(capture['manifest']['adapter_provenance']['processed_audio_reads'],4)
        request=load_json(path.parent/'request.json')
        commands=compile_commands(self.profile,self.trace(),request['request_id'])
        raw=(path.parent/'glorb.output').read_text()
        with self.assertRaisesRegex(LabError,'binding'):
            parse_output(raw,self.profile,self.trace(),'f'*32,hashlib.sha256(commands.encode()).hexdigest())
        with self.assertRaisesRegex(LabError,'audio'):
            parse_output(raw.replace('1092616192','1092616193'),self.profile,self.trace(),request['request_id'],hashlib.sha256(commands.encode()).hexdigest())

    def test_asset_change_and_unbacked_palette_selection_rejected(self):
        other=self.root/'other.cpp';other.write_text(FIXTURE+'\n')
        with self.assertRaisesRegex(LabError,'supplied renderer'):
            glorb.build_profile(other,self.build['executable'],[0],[[0,0,0]]*16,width=1,height=1)
        trace=self.trace();trace['frames'][1]['controls']={'palette_id':99}
        with self.assertRaisesRegex(LabError,'actual table'):
            compile_commands(self.profile,trace,'1'*32)
        trace['frames'][1]['controls']={'palette_id':0}
        with self.assertRaisesRegex(LabError,'actual table'):
            compile_commands(self.profile,trace,'1'*32)
        with self.assertRaisesRegex(LabError,'palette zero'):
            glorb.settings({'palette_id':0})

    def test_host_abi_and_large_mask_are_explicit(self):
        abi=self.build['host_abi']
        self.assertEqual(abi['int_bits'],32)
        self.assertIn(abi['pointer_bits'],(32,64))
        self.assertIn(abi['long_bits'],(32,64))
        self.assertIs(type(abi['char_signed']),bool)
        mapping=list(range(32768));mapping[0]=-1
        profile=glorb.build_profile(self.source,self.build['executable'],mapping,[[0,0,0]]*16,
                                   width=256,height=128,physical_pixels=32768)
        self.assertEqual(len(profile['geometry']['mask']['mapped']),32768)
        self.assertEqual(sum(profile['geometry']['mask']['mapped']),32767)
        self.assertFalse(profile['geometry']['mask']['mapped'][0])

    def test_unmodeled_audio_slot_fails_under_sanitizers(self):
        source=self.root/'bad-audio.cpp'
        source.write_text(FIXTURE.replace('audio->u_data[0]','audio->u_data[2]'))
        build=glorb.build_host(source,self.root/'sanitized-build',sanitize=True)
        self.assertEqual(build['sanitizers'],['address','undefined'])
        commands=self.root/'bad-audio.commands';output=self.root/'bad-audio.output'
        commands.write_text(compile_commands(self.profile,self.trace(),'a'*32))
        result=subprocess.run([build['executable'],str(commands),str(output)],capture_output=True,text=True,timeout=10,
                              env={**os.environ,**build['runtime_environment']})
        self.assertEqual(result.returncode,2,result.stderr)
        self.assertIn('unsupported AudioReactive slot',result.stderr)
        self.assertNotIn('runtime error:',result.stderr)
        self.assertNotIn('AddressSanitizer:',result.stderr)
        self.assertNotIn('\nE ',output.read_text())

    def test_output_create_is_exclusive_and_symlinks_are_rejected(self):
        commands=self.root/'exclusive.commands';output=self.root/'exclusive.output'
        commands.write_text(compile_commands(self.profile,self.trace(),'b'*32))
        output.write_text('keep existing bytes')
        result=subprocess.run([self.build['executable'],str(commands),str(output)],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,2)
        self.assertEqual(output.read_text(),'keep existing bytes')
        link=self.root/'exclusive-link';link.symlink_to(output)
        result=subprocess.run([self.build['executable'],str(commands),str(link)],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,2)
        self.assertEqual(output.read_text(),'keep existing bytes')

    def test_malformed_factory_metadata_and_unsupported_brightness_fail_cleanly(self):
        root=self.root/'factory-fixture';factory=root/'glorb/factory-0.14.4-GLORB.1.3'
        factory.mkdir(parents=True)
        write_json(factory/'presets.json',{'2':{}})
        with self.assertRaises(LabError):glorb.prepare_repository(root,self.root/'unused')
        write_json(factory/'presets.json',{'2':{'bri':120,'seg':[{'start':0,'stop':20,'startY':0,'stopY':6,'fx':193,'pal':1}]}})
        write_json(factory/'palx.json',{'palettes':{'1':[[0,0,0,0],[255,255,255,255]]}})
        write_json(factory/'cfg.json',{'hw':{'led':{'ins':[{'start':0,'len':120}]}},'def':{'bri':255}})
        with self.assertRaisesRegex(LabError,'brightness 255'):glorb.prepare_repository(root,self.root/'unused')

    def test_native_color_holes_and_sha_known_vectors(self):
        source=self.root/'helpers.cpp';binary=self.root/'helpers'
        source.write_text(r'''
#include "wled.h"
#include "sha256.h"
#include <cassert>
int main() {
 assert(tyc_sha256("")=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
 assert(tyc_sha256("abc")=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
 assert(tyc_scale8(255,255)==255 && tyc_scale8(255,0)==0);
 assert(color_add(0xfff000,0x201001,true)==0xffff01);
 assert(color_add(0xfff000,0x201001,false)==0xffe300);
 assert(color_add(0x241420,0x102030)==0x343450);
 tyc_width=2;tyc_height=1;tyc_map={-1,0};tyc_pixels={0,0};
 SEGMENT.setPixelColorXY(0,0,0xffffff);
 assert(SEGMENT.getPixelColorXY(0,0)==0 && tyc_pixels[0]==0);
 SEGMENT.addPixelColorXY(0,0,0xffffff);assert(tyc_pixels[0]==0);
 SEGMENT.setPixelColorXY(1,0,0x102030);assert(SEGMENT.getPixelColorXY(1,0)==0x102030);
}
''')
        native=Path(glorb.__file__).resolve().parents[1]/'native'
        subprocess.run([shutil.which('c++'),'-std=c++17','-I',str(native),str(source),'-o',str(binary)],check=True,capture_output=True,timeout=30)
        subprocess.run([str(binary)],check=True,capture_output=True,timeout=5)
