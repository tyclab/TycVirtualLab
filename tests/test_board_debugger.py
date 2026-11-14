"""Scripted debugger stops test bookkeeping and ABI without executing firmware."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import tempfile
import types
import unittest
from unittest.mock import patch

from vfl.model import load_json, write_json

SCRIPT=Path(__file__).resolve().parents[1]/'vfl/native/exoy_board.py'
SELECTOR,THIS,PIXELS=0x3ffc53cc,0x3ffb0000,0x3ffb1000
ENTRY=0x40082ec0
ADDRESSES={'dispatch':0x400d999c,'adc':0x400f39d0,'show':0x40081584,
           'wifi':0x40102c7c,'restart':ENTRY,'handshake':0x40000000}


class DebuggerExit(Exception):pass


class FakeGdb(types.ModuleType):
    BP_WATCHPOINT=1
    BP_HARDWARE_BREAKPOINT=2

    def __init__(self,events):
        super().__init__('gdb')
        self.events=[{'kind':'handshake'},*events]
        self.regs={};self.storage={};self.breakpoints=[];self.commands=[];self.operations=[]
        self.current={};self.thread=1;self.adc_returns=[]
        selector=bytearray(range(32));selector[12:16]=(2).to_bytes(4,'little');selector[16]=3
        self.put(SELECTOR,selector)
        self.put(THIS+28,PIXELS.to_bytes(4,'little'));self.put(THIS+32,(1440).to_bytes(4,'little'))
        self.put(PIXELS,b'\x02\x01\x03'*480)
        self.put(0x3ffc548c,b'\x01\x02\x03'*480);self.put(0x3ffc6530,bytes(80))
        self.checks=[]
        for address,data in [(0x400d0000,bytes(range(256))*270), (0x40080000,b'authored IRAM'),
                             (0x3f400020,b'authored descriptor'), (0x3f410000,b'authored constants')]:
            self.put(address,data)
            self.checks.append({'address':address,'length':len(data),'sha256':hashlib.sha256(data).hexdigest()})

    def put(self,address,data):self.storage.update((address+i,value)for i,value in enumerate(data))

    def read_memory(self,address,size):
        self.operations.append(('read',address,size))
        return bytes(self.storage.get(address+i,0)for i in range(size))

    def write_memory(self,address,data):
        self.operations.append(('write',address,bytes(data)));self.put(address,bytes(data))

    def selected_inferior(self):return self
    def selected_thread(self):return types.SimpleNamespace(global_num=self.thread)
    def parse_and_eval(self,name):return self.regs[name.removeprefix('$')]

    def Breakpoint(self,spec,*,type,internal):
        item=types.SimpleNamespace(spec=spec,type=type,hit_count=0,deleted=False)
        item.delete=lambda:setattr(item,'deleted',True)
        self.breakpoints.append(item)
        return item

    def execute(self,command,to_string=False):
        self.commands.append(command)
        if command=='continue':
            if not self.events:raise RuntimeError('authored stop sequence exhausted')
            self.current=self.events.pop(0)
            event=self.current;kind=event['kind']
            self.thread=event.get('thread',event.get('core',0)+1)
            increment=event.get('call_increment',2)
            self.regs={'pc':ADDRESSES.get(kind,event.get('pc',0xdeadbeef)), 'ps':increment<<16,
                       'a'+str(4*increment):(event.get('return_increment',increment)<<30)|0xd1234,
                       'a'+str(2+4*increment):THIS if kind=='show' else event.get('channel',6),
                       'ccount':event.get('ccount',1234)}
            if kind=='handshake':self.breakpoints[0].hit_count=1
            if 'drift_effect' in event:self.put(SELECTOR+16,bytes([event['drift_effect']]))
            if 'corrupt' in event:self.put(self.checks[event['corrupt']]['address'],b'!')
            if 'driver_size' in event:self.put(THIS+32,event['driver_size'].to_bytes(4,'little'))
        elif command.startswith('set $'):
            words=command.split();name=words[1][1:];value=int(words[-1]);self.regs[name]=value
            if self.current.get('kind')=='adc' and name=='a10':self.adc_returns.append(value)
        elif command=='quit 2':raise DebuggerExit(2)
        return ''


def stops(*kinds):return [{'kind':kind}for kind in kinds]


class BoardDebuggerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.counter=0

    def invoke(self,events,*,packets=None,settings=None,error=None):
        self.counter+=1;work=self.root/str(self.counter);work.mkdir()
        fake=FakeGdb(events);self.fake=fake
        request={'schema':'tycvl.board.request.v1','request_id':'f'*32,'workdir':str(work),
                 'packets':packets or [[100]*64,[200]*64], 'boot_mic':1850,
                 'settings':settings or {'pack':None,'effect':None}, 'app_entrypoint':ENTRY,
                 'loaded_app_checks':fake.checks}
        path=work/'request.json';write_json(path,request)
        log=io.StringIO()
        with patch.dict('sys.modules',{'gdb':fake}), \
             patch.dict(os.environ,{'TYCVL_BOARD_REQUEST':str(path),'TYCVL_BOARD_SOCKET':'authored-no-socket'}), \
             contextlib.redirect_stdout(log):
            if error:
                with self.assertRaises(DebuggerExit):runpy.run_path(str(SCRIPT))
                self.assertIn(error,log.getvalue())
                self.assertFalse((work/'board-observations.json').exists())
                return None
            namespace=runpy.run_path(str(SCRIPT))
        self.assertIn('detach',fake.commands)
        result=load_json(work/'board-observations.json')
        self.assertEqual(result['request_sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
        return result,namespace

    def test_packet_order_zero_read_frame_selector_and_bound_image_checks(self):
        events=stops('adc','show','wifi','dispatch')+stops(*(['adc']*64),'show','dispatch','show','dispatch')+stops(*(['adc']*64),'show')
        packets=[list(range(64)),list(range(1000,1064)),list(range(2000,2064))]
        result,_=self.invoke(events,packets=packets,settings={'pack':4,'effect':1})
        self.assertEqual([f['adc']for f in result['frames']],[packets[0],[],packets[2]])
        self.assertEqual(self.fake.adc_returns,[1850,*packets[0],*packets[2]])
        self.assertEqual([f['core']for f in result['frames']],[0,0,0])
        self.assertEqual((result['boot_frames'],result['wifi_failures']),(1,1))
        self.assertEqual(result['loaded_app_checks'],self.fake.checks)
        self.assertIn('zero-read frames discard',result['packet_policy'])
        for frame in result['frames']:
            selector=bytes.fromhex(frame['selector'])
            self.assertEqual(frame['selector_before'],frame['selector'])
            self.assertEqual(int.from_bytes(selector[12:16],'little'),4)
            self.assertEqual(selector[16],1)
        writes=[op for op in self.fake.operations if op[0]=='write' and op[1]in(SELECTOR+12,SELECTOR+16)]
        self.assertEqual(writes,[('write',SELECTOR+12,b'\x04\0\0\0'),('write',SELECTOR+16,b'\x01')])
        first_control=self.fake.operations.index(writes[0])
        for check in self.fake.checks:
            self.assertIn(('read',check['address'],min(65536,check['length'])),self.fake.operations[:first_control])
        self.assertLessEqual(max(op[2]for op in self.fake.operations if op[0]=='read'),65536)
        self.assertIn('*'+hex(ENTRY),[b.spec for b in self.fake.breakpoints])

    def test_pre_entry_call_window_arguments_and_hardware_returns(self):
        _,namespace=self.invoke(stops('dispatch','show'),packets=[[0]*64])
        for increment in (1,2,3):
            self.fake.regs={'ps':increment<<16,'a'+str(4*increment):(increment<<30)|0xd1234}
            self.assertEqual(namespace['argument'](0),'a'+str(2+4*increment))
            namespace['hardware_return'](0xffffffff)
            self.assertEqual(self.fake.regs['a'+str(2+4*increment)],0xffffffff)
            self.assertEqual(self.fake.regs['pc'],0x400d1234)
        with self.assertRaisesRegex(RuntimeError,'argument'):namespace['argument'](2)
        with self.assertRaisesRegex(RuntimeError,'argument'):namespace['argument'](-1)

    def test_hardware_hooks_reject_call0_and_mismatched_return_window(self):
        for kind in ('adc','wifi','show'):
            for overrides,message in (({'call_increment':0},'CALL0'),
                                      ({'call_increment':2,'return_increment':1},'return address')):
                with self.subTest(kind=kind,overrides=overrides):
                    self.invoke([{'kind':kind,**overrides}],error=message)
                    self.assertFalse(any(command.startswith('set $') for command in self.fake.commands))

    def test_hardware_hooks_accept_consistent_call4_call8_and_call12(self):
        for increment in (1,2,3):
            with self.subTest(increment=increment):
                events=[{'kind':kind,'call_increment':increment} for kind in ('adc','wifi','dispatch','show')]
                result,_=self.invoke(events,packets=[[0]*64])
                self.assertEqual((len(result['frames']),result['wifi_failures']),(1,1))

    def test_loaded_other_application_fails_before_selector_writes(self):
        self.invoke([{'kind':'dispatch','corrupt':2}],settings={'pack':4,'effect':1},error='loaded application differs')
        self.assertFalse(any(op[0]=='write'and op[1]in(SELECTOR+12,SELECTOR+16)for op in self.fake.operations))

    def test_post_start_adc_and_extra_show_fail_instead_of_disappearing(self):
        for kind,message in [('adc','ADC read outside'),('show','LED show outside')]:
            with self.subTest(kind=kind):self.invoke(stops('dispatch','show',kind),error=message)

    def test_duplicate_dispatch_partial_packet_exhaustion_and_wrong_channel(self):
        cases=[(stops('dispatch','dispatch'),'repeated'),
               (stops('dispatch','adc','show'),'incomplete'),
               (stops('dispatch')+stops(*(['adc']*65)),'exhausted'),
               (stops('dispatch')+[{'kind':'adc','channel':5}],'unexpected ADC channel')]
        for events,message in cases:
            with self.subTest(message=message):self.invoke(events,error=message)

    def test_selector_changes_are_observed_and_never_silently_reapplied(self):
        for events in ([*stops('dispatch'),{'kind':'show','drift_effect':2}],
                       [*stops('dispatch','show'),{'kind':'dispatch','drift_effect':2}]):
            self.invoke(events,settings={'pack':4,'effect':1},error='scene selection differs')
            self.assertEqual(sum(op[0]=='write'and op[1]==SELECTOR+16 for op in self.fake.operations),1)

    def test_core_changes_and_application_restart_fail(self):
        cases=[([*stops('dispatch'),{'kind':'adc','core':1}],'ADC acquisition changed CPU'),
               ([*stops('dispatch'),{'kind':'show','core':1}],'LED output changed CPU'),
               ([*stops('dispatch','show'),{'kind':'dispatch','core':1}],'dispatcher changed CPU'),
               ([{'kind':'dispatch','thread':3}],'CPU thread identity'),
               (stops('dispatch','restart'),'application restarted')]
        for events,message in cases:
            with self.subTest(message=message):self.invoke(events,error=message)

    def test_persisted_selector_and_second_core_are_recorded_without_controls(self):
        result,_=self.invoke([{'kind':'dispatch','core':1},{'kind':'show','core':1}],packets=[[0]*64])
        frame=result['frames'][0];selector=bytes.fromhex(frame['selector'])
        self.assertEqual((frame['core'],int.from_bytes(selector[12:16],'little'),selector[16]),(1,2,3))
        self.assertEqual(frame['selector_before'],frame['selector'])

    def test_autonomous_selection_change_retains_dispatch_and_output_values(self):
        result,_=self.invoke([*stops('dispatch'),{'kind':'show','drift_effect':4},
                              *stops('dispatch','show')])
        self.assertEqual([bytes.fromhex(frame['selector_before'])[16]for frame in result['frames']],[3,4])
        self.assertEqual([bytes.fromhex(frame['selector'])[16]for frame in result['frames']],[4,4])
        self.assertFalse(any(op[0]=='write' and op[1]in(SELECTOR+12,SELECTOR+16) for op in self.fake.operations))

    def test_wrong_driver_size_and_unexpected_debugger_stop_fail(self):
        self.invoke([*stops('dispatch'),{'kind':'show','driver_size':3}],error='LED driver size')
        self.invoke([{'kind':'unknown','pc':0x12345678}],error='unexpected debugger stop')
