"""Authored process fixtures for the board supervisor; no vendor images or QEMU."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from vfl.model import file_digest, load_json, write_json


QEMU_FIXTURE = r'''#!/usr/bin/env python3
import json,os,time
from pathlib import Path
request=json.loads(Path(os.environ['TYCVL_BOARD_REQUEST']).read_text())
work=Path(request['workdir'])
(work/'qemu.pid').write_text(str(os.getpid()))
# The fake debugger needs only the worker's readiness marker, never a socket.
Path(os.environ['TYCVL_BOARD_SOCKET']).touch()
while True: time.sleep(.05)
'''

GDB_FIXTURE = r'''#!/usr/bin/env python3
import hashlib,json,os,resource,signal,subprocess,sys,time
from pathlib import Path
request=json.loads(Path(os.environ['TYCVL_BOARD_REQUEST']).read_text())
work=Path(request['workdir'])
(work/'gdb.pid').write_text(str(os.getpid()))
if os.environ.get('TYCVL_TEST_CAPTURE')=='1':
    frames=[{'index':i,'ccount':1000+i*240000,'core':0,'selector':'00'*32,'selector_before':'00'*32,
             'logical':'010203'*480,'driver':'020103'*480,'state':'00'*80,'adc':values}
            for i,values in enumerate(request['packets'])]
    observed={'schema':'tycvl.board.observations.v1','request_id':request['request_id'],
              'request_sha256':hashlib.sha256(Path(os.environ['TYCVL_BOARD_REQUEST']).read_bytes()).hexdigest(),
              'loaded_app_checks':request['loaded_app_checks'],
              'core_mapping':'qemu-gdb-thread-global-num-minus-one',
              'packet_policy':'packet i belongs to scene/output frame i; zero-read frames discard their packet',
              'frames':frames,'boot_frames':80,'wifi_failures':1}
    (work/'board-observations.json').write_text(json.dumps(observed))
    raise SystemExit(0)
if os.environ.get('TYCVL_TEST_BOUND')=='1':
    target=work/'overflow.log'
    failed=False
    try:
        with target.open('wb',buffering=0) as output:
            for _ in range(20): output.write(b'x'*(1024*1024))
    except OSError:
        failed=True
    (work/'bound-result.json').write_text(json.dumps({
        'limit':resource.getrlimit(resource.RLIMIT_FSIZE),
        'bytes':target.stat().st_size,'failed':failed}))
    raise SystemExit(0)
child = subprocess.Popen([sys.executable,'-c',
    'import os,signal,time;from pathlib import Path;'
    'signal.signal(signal.SIGTERM,signal.SIG_IGN);'
    'Path('+repr(str(work/'gdb-child.pid'))+').write_text(str(os.getpid()));'
    'time.sleep(30)'])
while True: time.sleep(.05)
'''


class BoardProcessTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)
        self.work=self.root/'work';self.work.mkdir()
        self.package=Path(__file__).resolve().parents[1]
        assets=[]
        for role, text in [('qemu',QEMU_FIXTURE),('gdb',GDB_FIXTURE),
                           ('esp32-v3-rom.bin','authored ROM placeholder'),
                           ('esp32-v3-rom-app.bin','authored second ROM placeholder')]:
            # These fixtures are generated after Nix's patchShebangs phase;
            # use the running test interpreter even when /usr/bin/env is absent.
            text=text.replace('#!/usr/bin/env python3', '#!'+sys.executable, 1)
            path=self.root/role;path.write_text(text);path.chmod(0o700)
            assets.append({'role':role,'path':str(path),'sha256':file_digest(path)})
        flash=self.root/'authored-zero-flash.bin'
        with flash.open('wb') as output:output.truncate(8*1024*1024)
        assets.append({'role':'flash','path':str(flash),'sha256':file_digest(flash)})
        request={'schema':'tycvl.board.request.v1','request_id':'1'*32,'workdir':str(self.work),
                 'assets':assets,'library_paths':[],'seed':1,'timeout_s':60,'hold_files':[]}
        self.request=self.work/'request.json';write_json(self.request,request)
        self.environment={**os.environ,'PYTHONPATH':str(self.package)}
        self.supervisor=None
        self.addCleanup(self.cleanup_processes)

    def cleanup_processes(self):
        if self.supervisor is not None and self.supervisor.poll() is None:
            self.supervisor.kill();self.supervisor.wait(timeout=5)
        for path in self.work.glob('*.pid'):
            try:
                pid=int(path.read_text())
                if str(self.root).encode() in Path(f'/proc/{pid}/cmdline').read_bytes():
                    os.kill(pid,signal.SIGKILL)
            except (ProcessLookupError,ValueError):pass
            except FileNotFoundError:pass

    def start(self, timeout, *, bound=False):
        code = ('import sys;from pathlib import Path;from vfl.runner import run_process;'
                'root=Path(sys.argv[1]);'
                'run_process([sys.executable,"-m","vfl.board","--worker",str(root/"request.json")],'
                'root,root/"worker.stdout",root/"worker.stderr",float(sys.argv[2]))')
        env={**self.environment}
        if bound:env['TYCVL_TEST_BOUND']='1'
        self.supervisor=subprocess.Popen([sys.executable,'-c',code,str(self.work),str(timeout)],
                                         cwd=self.root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)

    def wait_ready(self):
        until=time.monotonic()+5
        while not (self.work/'gdb-child.pid').exists() or not (self.work/'gdb-child.pid').stat().st_size:
            if self.supervisor.poll() is not None:
                diagnostic=self.work/'worker.stderr'
                self.fail('supervisor stopped before fake debugger was ready: '+self.supervisor.communicate()[1].decode()
                          +(diagnostic.read_text() if diagnostic.exists() else ''))
            if time.monotonic()>until:self.fail('fake debugger startup timed out')
            time.sleep(.02)

    def assert_terminated(self):
        for name in ('qemu.pid','gdb.pid','gdb-child.pid'):
            path=self.work/name
            self.assertTrue(path.exists(),name+' must have started')
            pid=int(path.read_text());until=time.monotonic()+1
            while True:
                try:state=Path(f'/proc/{pid}/stat').read_text().split(') ',1)[1][0]
                except FileNotFoundError:break
                if state=='Z':break
                if time.monotonic()>until:self.fail(f'{name} survived cleanup as {state}')
                time.sleep(.02)
        self.assertFalse((self.work/'capture.json').exists())
        self.assertFalse((self.work/'board-observations.json').exists())

    def test_timeout_kills_qemu_and_detached_debugger_with_stubborn_child(self):
        self.start(2)
        self.wait_ready()
        self.supervisor.communicate(timeout=7)
        self.assertNotEqual(self.supervisor.returncode,0)
        self.assert_terminated()

    def test_sigterm_cleans_both_process_groups(self):
        self.start(20)
        self.wait_ready()
        self.supervisor.send_signal(signal.SIGTERM)
        self.supervisor.communicate(timeout=7)
        self.assertNotEqual(self.supervisor.returncode,0)
        self.assert_terminated()

    def test_file_size_limit_applies_to_debugger_outputs(self):
        self.start(10,bound=True)
        _,stderr=self.supervisor.communicate(timeout=15)
        self.assertEqual(self.supervisor.returncode,0,stderr.decode())
        result=load_json(self.work/'bound-result.json')
        self.assertEqual(result['limit'],[8*1024*1024]*2)
        self.assertEqual(result['bytes'],8*1024*1024)
        self.assertTrue(result['failed'])
        self.assertEqual((self.work/'flash-copy.bin').stat().st_size,8*1024*1024)

    def test_successful_worker_runs_verify_and_compare(self):
        from vfl.board import run_board
        from vfl.runner import load_completed_capture
        from vfl.compare import compare
        request=load_json(self.request)
        request.update(tool_version='0.2.0',device='exoy-one-v2-1',settings={'pack':None,'effect':None},
            packets=[[1400]*64,[1800]*64],input_provenance={'kind':'authored'},boot_mic=1400,cpu_hz=240000000,
            loaded_app_checks=[{'address':0x400d0020,'length':4,'sha256':'a'*64}])
        captures=[]
        with patch.dict(os.environ,{'TYCVL_TEST_CAPTURE':'1'}):
            for name in ('one','two'):
                args=SimpleNamespace(out=str(self.root/name),timeout_s=10)
                with patch('vfl.board.prepare',return_value=dict(request)):
                    path=run_board(args)
                captures.append(load_completed_capture(path))
        result=compare(*captures,include_events=True,repeat=True)
        self.assertEqual(result['verdict'],'equal')
        self.assertEqual(result['events_compared'],128)
        self.assertEqual(result['implementations']['left']['runtime_assets_sha256'],
                         captures[0]['manifest']['runtime_assets_sha256'])
