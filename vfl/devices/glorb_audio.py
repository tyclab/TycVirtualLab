"""Opt-in GLORB audio routine measurement on an Espressif QEMU ESP32-S3."""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time

from ..firmware import inspect_image
from ..model import LabError, file_digest, private_path, require, write_json

APPLICATIONS = {
    'ba2decaae3c39ecb4ae4634c4d361d9f65faff67df4d2d2c87fefa68be4dcc79': 'GLORB.1.3',
    'e73a39c5be534d49d138ae5909f3e12857e013a7640afbb275fdcfd6d7092857': 'fleet 2611200',
    '7305917cd59da0102d7248d836f1d12030d5ab364a5d139504ae32f124fb53d4': 'fleet 2611201',
    '0f5f59f8eda14d41b5194e12e13f240d8ced449e490cb07036ec683ba768b27e': 'fleet 2611202',
}
CASES = [(label + suffix, k, amp, active, 'complete')
         for label, k, amp in [('near-cutoff', 2, 8192), ('soft', 16, 257)]
         for suffix, active in [('', True), ('-bypass', False)]] + [
             ('short-read', 2, 8192, False, 'short'), ('read-error', 2, 8192, False, 'error')]


def flash_image(boot, app):
    require(len(boot) <= 0x8000 and len(app) <= 0x300000, 'image exceeds its virtual partition')
    entry = struct.pack('<HBBII16sI', 0x50aa, 0, 0, 0x10000, 0x300000, b'factory', 0)
    table = entry + b'\xeb\xeb' + b'\xff'*14 + hashlib.md5(entry, usedforsecurity=False).digest()
    flash = bytearray(b'\xff' * 0x800000)
    for address, payload in [(0, boot), (0x8000, table), (0x10000, app)]:
        flash[address:address + len(payload)] = payload
    return flash


def measure(image, boot, qemu, gdb, rom_dir, timeout_s):
    info = inspect_image(image, format='esp32')
    name = APPLICATIONS.get(info['sha256'])
    require(name is not None, 'unsupported GLORB application SHA256')
    app = Path(image).read_bytes()
    require(hashlib.sha256(app).hexdigest() == info['sha256'], 'application changed while reading')
    mapped = []
    for segment in info['segments']:
        addr, pos, size = (segment[k] for k in ('load_address', 'file_offset', 'file_size'))
        if 0x3c000000 <= addr < 0x3e000000 or 0x42000000 <= addr < 0x44000000:
            mapped.append(dict(address=addr, length=size, sha256=hashlib.sha256(app[pos:pos + size]).hexdigest()))
    with tempfile.TemporaryDirectory() as scratch:
        tmp = Path(scratch)
        (tmp/'flash.bin').write_bytes(flash_image(boot, app))
        (tmp/'job.json').write_text(json.dumps(dict(entry=info['entry_point'], application=name,
                                                    cases=CASES, mapped=mapped)))
        shutil.copyfile(Path(__file__).resolve().parents[1]/'native/glorb_pcm.py', tmp/'probe.py')
        options = [qemu, '-M', 'esp32s3', '-nic', 'none', '-display', 'none', '-serial', 'none', '-monitor', 'none',
                   '-S', '-icount', 'shift=3,sleep=off', '-drive', 'file=flash.bin,if=mtd,format=raw,snapshot=on',
                   '-chardev', 'socket,path=debug.sock,server=on,wait=off,id=probe', '-gdb', 'chardev:probe']
        options.extend(['-L', str(rom_dir)])
        with (tmp/'emulator.log').open('w+') as log:
            proc = subprocess.Popen(options, cwd=tmp, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + timeout_s
                while not (tmp/'debug.sock').exists():
                    require(proc.poll() is None, 'ESP32-S3 emulator exited before creating its debug socket')
                    require(time.monotonic() < deadline, 'timed out waiting for the ESP32-S3 emulator')
                    time.sleep(.02)
                result = subprocess.run([gdb, '-nx', '-batch', '-ex', 'source probe.py'], cwd=tmp,
                                        timeout=max(.01, deadline-time.monotonic()), capture_output=True, text=True)
                if result.returncode or not (tmp/'observed.json').exists():
                    raise LabError(f'GLORB routine replay failed: {result.stderr[-1800:]}')
                rows = json.loads((tmp/'observed.json').read_bytes())
                require(len(rows)==18, 'incomplete GLORB measurement')
                return dict(application=name, app_sha256=info['sha256'], blocks=rows)
            except subprocess.TimeoutExpired as exc:
                raise LabError('timed out executing the GLORB audio routines') from exc
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


def compare_to_factory(reports):
    factory = next((r for r in reports if r['application'] == 'GLORB.1.3'), None)
    if factory is None:
        return []
    comparisons = []
    for report in reports:
        if report is factory:
            continue
        cases = {}
        for original, measured in zip(factory['blocks'], report['blocks'], strict=True):
            require(all(original[k] == measured[k] for k in ('case', 'block', 'input_sha256')),
                    'different inputs in paired GLORB measurements')
            counts = cases.setdefault(original['case'], {'blocks': 0, 'same_filtered_buffer': 0, 'same_spectrum': 0})
            counts['blocks'] += 1
            counts['same_filtered_buffer'] += original['filtered_sha256'] == measured['filtered_sha256']
            counts['same_spectrum'] += all(original[k] == measured[k] for k in ('fft_magnitude', 'fft_major_peak_hz'))
        comparisons.append({'compared_application': report['application'], 'cases': cases})
    return comparisons


def execute(args):
    out = private_path(args.out)
    require(not out.exists(), 'choose a fresh private output path')
    require(args.timeout_s > 0, 'timeout must be positive')
    qemu, gdb = (shutil.which(tool) for tool in (args.qemu, args.gdb))
    require(qemu and gdb, 'supply an ESP32-S3 QEMU and Python-enabled Xtensa GDB executable')
    qemu, gdb = Path(qemu).resolve(), Path(gdb).resolve()
    boot_info = inspect_image(args.bootloader, format='esp32')
    boot = Path(args.bootloader).read_bytes()
    require(boot_info['chip_id']==9 and hashlib.sha256(boot).hexdigest()==boot_info['sha256'],
            'expected a standalone ESP32-S3 bootloader image')
    rom_dir = Path(args.rom_dir).resolve()
    rom_digest = file_digest(rom_dir/'esp32s3_rev0_rom.bin')
    reports = [measure(image, boot, qemu, gdb, rom_dir, args.timeout_s) for image in args.firmware]
    require(len({r['app_sha256'] for r in reports}) == len(reports), 'the same GLORB application was supplied twice')
    write_json(out, dict(schema='vfl.glorb-audio.v1', sample_rate=22050, samples_per_block=512,
                         bootloader_sha256=boot_info['sha256'], qemu_sha256=file_digest(qemu),
                         gdb_sha256=file_digest(gdb), rom_sha256=rom_digest, applications=reports,
                         comparison_to_factory=compare_to_factory(reports)))
    return dict(output=str(out), applications=[r['application'] for r in reports])
