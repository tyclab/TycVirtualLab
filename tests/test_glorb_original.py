import copy
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from vfl.devices import glorb, glorb_original as original
from vfl.ghidra import compile_commands, _asset_paths
from vfl.model import LabError, digest, experiment_digest, write_json


class OriginalSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.image = self.root / 'authored-image.bin'
        self.image.write_bytes(b'header--CODE--DATA')
        self.info = {'sha256': original.APP_SHA256, 'entry_point': 0x42000020,
                     'segments': [{'load_address': 0x42000020, 'file_offset': 8, 'file_size': 4},
                                  {'load_address': 0x3fc90000, 'file_offset': 14, 'file_size': 4}]}
        self.profile = {'schema':'vfl.profile.v1', 'id':'authored-glorb',
                        'target':{'chip':'esp32-s3', 'isa':'xtensa-lx7', 'abi':'xtensa-windowed'},
                        'input':dict(glorb.INPUT), 'settings':glorb.settings(),
                        'buses':[{'id':name, 'pixels':120, 'order':'RGB', 'stage':'logical'}
                                 for name in ('logical','mapped')], 'firmware':[],
                        'backend':{'kind':'external', 'execution_kind':'recovered-code',
                                   'command':['authored-fixture', '{request}', '{capture}'],
                                   'options':{'glorb':{'width':20, 'height':6, 'physical_pixels':120,
                                       'map':[0,-1,*range(2,120)], 'palette_rgb16':[[i*17]*3 for i in range(16)]}}}}
        self.trace = {'schema':'vfl.trace.v1', 'input':dict(glorb.INPUT), 'seed':1,
                      'clock_policy':'frame', 'provenance':{'kind':'authored-test'},
                      'frames':[{'index':0,'time_us':0,'values':[0],'controls':{}}]}

    def fake_bus(self, output, compiler):
        binary = output/'virtual_bus.bin'
        binary.write_bytes(b'authored-instruction-fixture')
        write_json(output/'build.json', {'kind':'authored-test'})
        return binary, {name:original.BOUNDARY+i*4 for i,name in enumerate(
            ['virtual_length','virtual_get','virtual_set','snapshot','set_frame_time',
             'virtual_audio_id','virtual_audio_data'])}, Path(original.__file__)

    def prepare(self, profile=None, output='setup'):
        with patch.object(original, 'inspect_image', return_value=self.info), \
             patch.object(original, '_build_bus', side_effect=self.fake_bus):
            return original.prepare_original(self.image, profile or self.profile, self.root/output, compiler='unused')

    def test_wrapper_preserves_loaded_bytes_and_addresses(self):
        output = self.root/'fixture.elf'
        with patch.object(original, 'inspect_image', return_value=self.info):
            original._wrap_image(self.image, output)
        data = output.read_bytes()
        header = struct.unpack('<16sHHIIIIIHHHHHH', data[:52])
        self.assertEqual(header[2:5], (94,1,0x42000020))
        for n, expected in enumerate(self.info['segments']):
            p = struct.unpack_from('<IIIIIIII',data,52+32*n)
            self.assertEqual(p[2],expected['load_address'])
            self.assertEqual(data[p[1]:p[1]+p[4]], self.image.read_bytes()[expected['file_offset']:expected['file_offset']+expected['file_size']])
        with patch.object(original, 'inspect_image', return_value=self.info), self.assertRaises(FileExistsError):
            original._wrap_image(self.image, output)

    def test_unknown_image_rejected_before_output_creation(self):
        info = {**self.info, 'sha256':'0'*64}
        with patch.object(original, 'inspect_image', return_value=info), self.assertRaisesRegex(LabError,'unsupported'):
            original.prepare_original(self.image,self.profile,self.root/'bad',compiler='unused')
        self.assertFalse((self.root/'bad').exists())

    def test_original_and_source_share_experiment_and_preserve_source(self):
        before = copy.deepcopy(self.profile)
        result = self.prepare()
        left, right = result['original_profile'],result['source_profile']
        self.assertEqual(self.profile,before)
        self.assertEqual(experiment_digest(left,self.trace),experiment_digest(right,self.trace))
        self.assertNotEqual(digest(left),digest(right))
        self.assertEqual(left['backend']['execution_kind'],'original-firmware')
        self.assertEqual(right['backend']['execution_kind'],'recovered-code')
        self.assertTrue(Path(result['original_profile_path']).is_file())

    def test_commands_keep_original_entry_and_mapping_and_narrow_state(self):
        profile = self.prepare()['original_profile']
        commands, buses, state = compile_commands(profile,self.trace,_asset_paths(profile))
        self.assertIn('callq '+str(original.FUNCTIONS['hiphotic']),commands)
        self.assertIn('observe '+str(original.FUNCTIONS['hiphotic'])+' hiphotic',commands)
        self.assertIn('hook 1107837684 millis',commands)
        self.assertIn('dump state0 '+str(original.SEGMENT+44)+' 12',commands)
        self.assertEqual(set(buses.values()),{'logical','mapped'})
        self.assertEqual(state,{'state0':'segment'})
        mapping = next(op for op in profile['backend']['options']['ghidra']['initialization']
                       if op.get('address')==original.MAPPING)
        self.assertEqual(bytes.fromhex(mapping['hex'])[:6],b'\0\0\xff\xff\x02\0')

    def test_rejects_unmodeled_source_target_layout_and_input(self):
        cases = [('input',lambda p:p['input'].update(units='invented')),
                 ('target',lambda p:p['target'].update(chip='esp32')),
                 ('factory',lambda p:p['backend']['options']['glorb'].update(physical_pixels=83)),
                 ('duplicate',lambda p:p['backend']['options']['glorb']['map'].__setitem__(2,0))]
        for text, mutate in cases:
            with self.subTest(text=text):
                profile = copy.deepcopy(self.profile);mutate(profile)
                with self.assertRaisesRegex(LabError,text):self.prepare(profile)
                self.assertFalse((self.root/'setup').exists())

    def test_unsupported_trace_controls_fail_closed(self):
        profile = self.prepare()['original_profile']
        trace = copy.deepcopy(self.trace)
        trace['frames'][0]['controls']={'speed':9}
        with self.assertRaisesRegex(LabError,'operation recipe'):
            compile_commands(profile,trace,_asset_paths(profile))

    def test_audio_mode_binds_fractional_volume_and_observes_original_load(self):
        source=copy.deepcopy(self.profile)
        source['settings'].update(effect='colorwaves',sound_reactive=True)
        profile=self.prepare(source)['original_profile']
        trace=copy.deepcopy(self.trace)
        trace['frames'][0].update(time_us=16000,values=[1.5])
        commands,_,_=compile_commands(profile,trace,_asset_paths(profile))
        self.assertIn('w32 '+str(original.VOLUME)+' 1069547520',commands)
        self.assertIn('observe '+str(0x42043023)+' audio-value-read',commands)
        config=profile['backend']['options']['ghidra']
        clock=config['frame_calls'][0]
        self.assertEqual(clock['arguments'],[original.STRIP+8,{'time_ms':True}])
        self.assertIn('callq '+str(clock['address'])+' '+str(original.STRIP+8)+' 16',commands)
        check1=next(op for op in config['initialization'] if op.get('address')==original.SEGMENT+31)
        self.assertTrue(int(check1['hex'],16)&32)

    def test_existing_destination_is_not_reused(self):
        self.prepare()
        with self.assertRaisesRegex(LabError,'fresh'):self.prepare()
