import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vfl.board import normalize
from vfl.model import LabError,canonical,digest,write_json
from vfl.runner import load_completed_capture

class BoardCaptureTests(unittest.TestCase):
    def fixture(self):
        request={'schema':'tycvl.board.request.v1','request_id':'1'*32,'tool_version':'0.2.0',
                 'device':'exoy-one-v2-1','workdir':'unused-original-location','assets':[],
                 'settings':{'pack':None,'effect':None},'packets':[[100]*64,[200]*64],
                 'loaded_app_checks':[{'address':0x400d0020,'length':4,'sha256':'b'*64}],
                 'input_provenance':{'kind':'authored'},'seed':3,'boot_mic':1400,'cpu_hz':240000000,'tool_source_sha256':'a'*64}
        observed={'schema':'tycvl.board.observations.v1','request_id':request['request_id'],
                  'request_sha256':hashlib.sha256(canonical(request)+b'\n').hexdigest(),
                  'loaded_app_checks':copy.deepcopy(request['loaded_app_checks']),
                  'core_mapping':'qemu-gdb-thread-global-num-minus-one',
                  'packet_policy':'packet i belongs to scene/output frame i; zero-read frames discard their packet',
                  'boot_frames':80,'wifi_failures':1,'frames':[
                   {'index':i,'ccount':counter,'logical':'010203'*480,'driver':'020103'*480,
                    'state':'00'*80,'selector':'00'*32,'selector_before':'00'*32,'core':0,'adc':list(request['packets'][i])}
                    for i,counter in enumerate((0xfffffff0,2240))]}
        return request,observed

    def test_clock_wrap_observed_adc_and_relocatable_verified_capture(self):
        request,observed=self.fixture();capture=normalize(request,observed)
        self.assertEqual([f['time_us'] for f in capture['frames']],[0,9])
        self.assertEqual(len(capture['events']),128)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name,data in [('request.json',request),('board-observations.json',observed),('capture.json',capture)]:
                write_json(root/name,data)
            status={'schema':'tycvl.board.status.v1','status':'complete','frames':2,
                    'execution_kind':'original-firmware','capture_sha256':digest(capture),'request_sha256':digest(request)}
            write_json(root/'status.json',status)
            self.assertEqual(load_completed_capture(root),capture)
            observed['frames'][1]['adc'][2]=201
            write_json(root/'board-observations.json',observed)
            with self.assertRaisesRegex(LabError,'delivered ADC'):load_completed_capture(root)

    def test_missing_or_stale_completion_and_partial_adc_rejected(self):
        request,observed=self.fixture()
        for mutate in (lambda x:x.update(request_id='2'*32),lambda x:x['frames'].pop(),
                       lambda x:x['frames'][0]['adc'].pop()):
            changed=copy.deepcopy(observed);mutate(changed)
            with self.assertRaises(LabError):normalize(request,changed)
        observed['frames'][0]['adc']=[]
        self.assertEqual(len(normalize(request,observed)['events']),64)

    def test_starting_flash_and_boot_microphone_change_experiment_identity(self):
        request,observed=self.fixture()
        original=normalize(request,observed)['manifest']['experiment_sha256']
        for key,value in [('boot_mic',1800),('assets',[{'role':'flash','sha256':'b'*64}])]:
            changed=copy.deepcopy(request);changed[key]=value
            bound=copy.deepcopy(observed)
            bound['request_sha256']=hashlib.sha256(canonical(changed)+b'\n').hexdigest()
            self.assertNotEqual(normalize(changed,bound)['manifest']['experiment_sha256'],original)

    def test_wrong_loaded_image_core_scene_and_malformed_observations_fail(self):
        request,observed=self.fixture()
        changes=[lambda o:o.update(loaded_app_checks=[]),lambda o:o['frames'][1].update(core=1),
                 lambda o:o['frames'][0].pop('state'),lambda o:o.update(boot_frames=True),
                 lambda o:o['frames'][0].update(selector='ff'*32)]
        for mutate in changes:
            changed=copy.deepcopy(observed);mutate(changed)
            with self.assertRaises(LabError):normalize(request,changed)
        request['cpu_hz']=0
        with self.assertRaises(LabError):normalize(request,observed)


class BoardPrepareTests(unittest.TestCase):
    def setUp(self):
        from test_firmware import esp_image
        from vfl.cli import parser
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        qemu=root/'qemu/bin/qemu-system-xtensa';qemu.parent.mkdir(parents=True);qemu.write_bytes(b'authored emulator')
        rom=root/'qemu/share/qemu';rom.mkdir(parents=True)
        for name in ('esp32-v3-rom.bin','esp32-v3-rom-app.bin'):(rom/name).write_bytes(b'authored ROM')
        gdb=root/'gdb';gdb.write_bytes(b'authored debugger')
        firmware=root/'app.bin';firmware.write_bytes(esp_image())
        flash=root/'flash.bin'
        with flash.open('wb') as stream:
            stream.truncate(8*1024*1024);stream.seek(0x10000);stream.write(firmware.read_bytes())
        self.args=parser().parse_args(['board','exoy-one','--qemu',str(qemu),'--gdb',str(gdb),
            '--firmware',str(firmware),'--flash',str(flash),'--out',str(root/'result')])
        self.pin=patch('vfl.board.APP_SHA256',hashlib.sha256(firmware.read_bytes()).hexdigest())
        self.pin.start();self.addCleanup(self.pin.stop)

    def test_loaded_code_checks_are_derived_from_verified_image(self):
        from vfl.board import prepare
        r=prepare(self.args)
        self.assertEqual(r['app_entrypoint'],0x40001000)
        self.assertEqual(r['loaded_app_checks'],[{'address':0x3f400020,'length':4,
            'sha256':hashlib.sha256(b'\x01\x02\x03\x04').hexdigest()}])
        self.assertEqual(r['packets'],[[1850]*64]*16)
        with patch('vfl.board.APP_SHA256','f'*64):
            with self.assertRaisesRegex(LabError,'unsupported Exoy'):prepare(self.args)

    def test_flash_bounds_mismatch_and_settings_rejected(self):
        from vfl.board import prepare
        self.args.pack=100
        with self.assertRaises(LabError):prepare(self.args)
        self.args.pack=None
        with Path(self.args.flash).open('r+b') as stream:stream.seek(0x10000);stream.write(b'bad')
        with self.assertRaisesRegex(LabError,'differs'):prepare(self.args)
        Path(self.args.flash).write_bytes(b'short')
        with self.assertRaisesRegex(LabError,'8 MiB'):prepare(self.args)

    def test_typed_adc_trace_and_controls(self):
        from vfl.board import prepare
        from vfl.devices.exoy import smoke_trace
        path=Path(self.temp.name)/'trace.json';trace=smoke_trace(2)
        write_json(path,trace);self.args.input=str(path)
        self.assertEqual(prepare(self.args)['packets'],[f['values'] for f in trace['frames']])
        trace['frames'][0]['controls']={'speed':1};write_json(path,trace)
        with self.assertRaisesRegex(LabError,'controls'):prepare(self.args)
