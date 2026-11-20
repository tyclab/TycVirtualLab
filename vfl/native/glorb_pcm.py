"""GDB-side GLORB S3 probe. Its application layout and inputs are checked by the host."""
import hashlib
import json
import math
from pathlib import Path
import struct

import gdb


def number(expression):
    return int(gdb.parse_and_eval(expression))


def setreg(name, value):
    gdb.execute(f'set ${name} = {value:#x}')


def write(address, data):
    gdb.selected_inferior().write_memory(address, data)


def memory(address, size):
    return bytes(gdb.selected_inferior().read_memory(address, size))


def stop(address):
    bp = gdb.Breakpoint(f'*{address:#x}', gdb.BP_HARDWARE_BREAKPOINT, internal=True)
    try:
        gdb.execute('continue', to_string=True)
        if number('$pc') != address:
            raise RuntimeError(f'GLORB stopped before expected instruction {address:#x}')
    finally:
        bp.delete()


def word(address, value):
    write(address, struct.pack('<I', value))


def measure(job):
    factory = job['factory']
    if factory:
        call, driver, returned, peak_store, fft_done = 0x4204159c, 0x42040e48, 0x42041112, 0x420411d3, 0x42041214
        vtable, flag, history, low, peak = 0x3c1662e0, 0x3fca1184, 0x3fca00b0, 0x3fca00ac, 0x3fca1180
        real, imag, activity, mag, hz = 0x3fca08d8, 0x3fca00d8, 0x3fca117c, 0x3fca1168, 0x3fc992b8
        fft_object, constructor = 0x3fca00b8, 0x4204773d
    else:
        call, driver, returned, peak_store, fft_done = 0x420030d4, 0x42002a53, 0x42002d2a, 0x42002de3, 0x42002e39
        vtable, flag, history, low, peak = 0x3c0f0910, 0x3fc9ae14, 0x3fc9ad88, 0x3fc9ad84, 0x3fc9ae4c
        real, imag = 0x3fcb9000, 0x3fcba000
        def literal(address):
            return struct.unpack('<I', memory(address, 4))[0]
        activity, mag, hz = (literal(a) for a in (0x420000b4, 0x420000c0, 0x420000c4))
        fft_object, constructor = number('$a1') + 32, 0x42002cf1
        word(literal(0x42000024), real)
        word(literal(0x42000080), imag)
    reader = 0x3fcb8000
    write(reader, struct.pack('<IIIB3xf', vtable, 22050, 128, 1, .25))
    for i, value in enumerate((fft_object, real, imag, 512, 0x46ac4400, 0), 10):
        setreg(f'a{i}', value)
    setreg('pc', constructor)
    stop(constructor + 3)
    word(fft_object + 8, 0x3fcbb000)  # Caller-owned window cache instead of a heap allocation.
    write(activity, struct.pack('<f', 50))
    rows = []
    for name, bin_number, amplitude, filtered, status in job['cases']:
        write(flag, bytes([filtered]))
        write(history, bytes(8))
        word(low, 0)
        pcm = [round(amplitude * math.sin(2*math.pi*bin_number*i/512)) for i in range(512)]
        pcm_bytes = struct.pack('<512h', *pcm)
        expected = struct.pack('<512f', *(x*.25 for x in pcm))
        for block in range(4 if status == 'complete' else 1):
            sentinel = struct.pack('<512f', *((i % 11 - 5)*2.25 + block for i in range(512)))
            write(real, sentinel)
            setreg('a10', reader)
            if factory:
                setreg('a2', real)
            else:
                setreg('a3', literal(0x42000024))
                setreg('a5', literal(0x42000080))
            setreg('pc', call)
            stop(driver)
            if (number('$a10'), number('$a12'), number('$a14') & 0xffffffff) != (0, 1024, 0xffffffff):
                raise RuntimeError('unexpected I2S port, read width, or wait policy')
            write(number('$a11'), pcm_bytes)
            word(number('$a13'), 1022 if status == 'short' else 1024)
            setreg('a10', int(status == 'error'))
            setreg('pc', driver + 3)
            stop(returned)
            scaled = memory(real, 2048)
            if scaled != (expected if status == 'complete' else sentinel):
                raise RuntimeError('incorrect signed PCM conversion or failed-read handling')
            stop(peak_store)
            samples = memory(real, 2048)
            measured_peak = struct.unpack('<f', memory(peak, 4))[0]
            if measured_peak != max(map(abs, struct.unpack('<512f', samples))) or (not filtered and samples != scaled):
                raise RuntimeError('firmware peak or filter bypass disagrees with the sample buffer')
            stop(fft_done)
            magnitude = struct.unpack('<f', memory(mag, 4))[0]
            frequency = struct.unpack('<f', memory(hz, 4))[0]
            if status == 'complete' and (not math.isfinite(magnitude) or magnitude <= 0 or
                                         not abs(frequency-bin_number*22050/512) < 22050/512):
                raise RuntimeError('unexpected FFT magnitude or dominant frequency')
            rows.append(dict(case=name, block=block+1, input_bin=bin_number, amplitude=amplitude, filter_enabled=filtered,
                             driver_status=status, input_sha256=hashlib.sha256(pcm_bytes).hexdigest(),
                             filtered_sha256=hashlib.sha256(samples).hexdigest(), peak=measured_peak,
                             fft_magnitude=magnitude, fft_major_peak_hz=frequency))
    return rows


def run():
    job = json.loads(Path('job.json').read_text())
    gdb.execute('set confirm off')
    gdb.execute('set pagination off')
    gdb.execute('target remote ./debug.sock', to_string=True)
    stop(job['entry'])
    gdb.execute('set scheduler-locking on')
    gdb.execute('thread 1', to_string=True)
    for area in job['mapped']:
        if hashlib.sha256(memory(area['address'], area['length'])).hexdigest() != area['sha256']:
            raise RuntimeError('mapped application differs from the supplied firmware')
    setreg('ps', (number('$ps') & 0xfffffff0) | 15)
    setreg('cpenable', 1)
    setreg('a1', 0x3fcd0000)
    Path('observed.json').write_text(json.dumps(measure(job), allow_nan=False))


run()
