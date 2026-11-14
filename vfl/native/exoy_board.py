"""Executed inside Xtensa GDB; hardware stand-ins never calculate effect pixels."""
import hashlib
import json
import os
from pathlib import Path
import gdb


def register(name):
    return int(gdb.parse_and_eval('$'+name)) & 0xffffffff


def set_register(name, value):
    gdb.execute('set $'+name+' = '+str(value & 0xffffffff), to_string=True)


def memory(address, size):
    return bytes(gdb.selected_inferior().read_memory(address, size))


def write(address, value, width=4):
    gdb.selected_inferior().write_memory(address, int(value).to_bytes(width,'little'))


def call_window():
    # These hooks stop before ENTRY in windowed functions. CALL4/8/12 encode
    # their increment in both PS.CALLINC and the caller's return address.
    increment = (register('ps') >> 16) & 3
    if increment == 0:
        raise RuntimeError('unsupported hardware call window: CALL0')
    ra = register('a'+str(4*increment))
    if ra >> 30 != increment:
        raise RuntimeError('hardware call window does not match return address')
    return increment, ra


def argument(index):
    if type(index) is not int or not 0 <= index <= 5:
        raise RuntimeError('unsupported pre-entry argument register')
    increment, _ = call_window()
    number = 2 + 4*increment + index
    if number >= 16:
        raise RuntimeError('unsupported pre-entry argument register')
    return 'a'+str(number)


def core():
    # A fresh QEMU ESP32 remote session exposes its two CPUs as GDB threads 1/2.
    # This is a debugger CPU identity, not a hardware PRID measurement.
    number = gdb.selected_thread().global_num
    if type(number) is not int or number not in (1, 2):
        raise RuntimeError('unsupported QEMU CPU thread identity')
    return number - 1


def check_loaded_application(checks):
    if not isinstance(checks, list) or not 1 <= len(checks) <= 64:
        raise RuntimeError('loaded application checks are missing')
    observed = []
    for check in checks:
        address, length = check['address'], check['length']
        if type(address) is not int or type(length) is not int or not 0 <= address < 2**32 \
                or not 0 < length <= 8*1024*1024 or address+length > 2**32:
            raise RuntimeError('invalid loaded application region')
        digest = hashlib.sha256()
        for offset in range(0, length, 65536):
            digest.update(memory(address+offset, min(65536, length-offset)))
        result = {'address':address, 'length':length, 'sha256':digest.hexdigest()}
        if result['sha256'] != check['sha256']:
            raise RuntimeError('loaded application differs at '+hex(address))
        observed.append(result)
    return observed


def check_selection(selector, settings):
    if settings['pack'] is not None and (int.from_bytes(selector[12:16], 'little') != settings['pack']
                                        or selector[16] != settings['effect']):
        raise RuntimeError('captured scene selection differs from requested pack/effect')


def hardware_return(value):
    increment, ra = call_window()
    set_register('a'+str(2+4*increment), value)
    set_register('pc', (ra & 0x3fffffff) | 0x40000000)


def run():
    request_path = Path(os.environ['TYCVL_BOARD_REQUEST'])
    raw = request_path.read_bytes()
    request = json.loads(raw)
    work = Path(request['workdir'])
    packets = request['packets']
    gdb.execute('set pagination off')
    gdb.execute('set confirm off')
    gdb.execute('set print thread-events off')
    gdb.execute('maint set target-async off')
    gdb.execute('target remote '+os.environ['TYCVL_BOARD_SOCKET'])
    stall = gdb.Breakpoint('*(unsigned int*)0x3ffd2f7c', type=gdb.BP_WATCHPOINT, internal=True)
    gdb.execute('continue', to_string=True)
    if not stall.hit_count:
        raise RuntimeError('CPU stopped before the expected IPC handshake')
    # Verify the selected application before changing RAM or installing any
    # address-specific stand-in. Recheck at the first scene dispatch below.
    check_loaded_application(request['loaded_app_checks'])
    write(0x3ffd2f7c,0)
    stall.delete()
    show, adc, wifi, dispatch = 0x40081584, 0x400f39d0, 0x40102c7c, 0x400d999c
    entrypoint = request['app_entrypoint']
    if type(entrypoint) is not int or not 0 <= entrypoint < 2**32 or entrypoint in (show,adc,wifi,dispatch):
        raise RuntimeError('invalid application entrypoint')
    for address in (show,adc,wifi,dispatch):
        gdb.Breakpoint('*'+hex(address), type=gdb.BP_HARDWARE_BREAKPOINT, internal=True)
    frames, reads, boot_frames, wifi_failures = [], [], 0, 0
    in_scene, started, selected_core = False, False, None
    selector_before = None
    loaded_checks = None
    while len(frames) < len(packets):
        gdb.execute('continue', to_string=True)
        pc = register('pc')
        if started and pc == entrypoint:
            raise RuntimeError('application restarted after scene capture began')
        if pc == dispatch:
            if in_scene:
                raise RuntimeError('scene dispatcher repeated without an output frame')
            first = not started
            if first:
                loaded_checks = check_loaded_application(request['loaded_app_checks'])
                selected_core = core()
                gdb.Breakpoint('*'+hex(entrypoint), type=gdb.BP_HARDWARE_BREAKPOINT, internal=True)
                started = True
            elif core() != selected_core:
                raise RuntimeError('scene dispatcher changed CPU core')
            in_scene = True
            reads = []
            settings = request['settings']
            # Set an explicit selection once. Later firmware changes must be
            # observed and rejected, rather than hidden by repeated writes.
            if first and settings['pack'] is not None:
                write(0x3ffc53d8, settings['pack'])
                write(0x3ffc53dc, settings['effect'], 1)
            selector_before = memory(0x3ffc53cc,32)
            check_selection(selector_before,settings)
        elif pc == adc:
            if started and not in_scene:
                raise RuntimeError('ADC read outside the scene acquisition window')
            if register(argument(0)) != 6:
                raise RuntimeError('unexpected ADC channel')
            if in_scene:
                if core() != selected_core:
                    raise RuntimeError('ADC acquisition changed CPU core')
                if len(reads) >= 64:
                    raise RuntimeError('ADC packet exhausted')
                value = packets[len(frames)][len(reads)]
                reads.append(value)
            else:
                value = request['boot_mic']
            hardware_return(value)
        elif pc == wifi:
            wifi_failures += 1
            hardware_return(0xffffffff)
        elif pc == show:
            if started and not in_scene:
                raise RuntimeError('LED show outside the scene output window')
            this = register(argument(0))
            pointer = int.from_bytes(memory(this+28,4),'little')
            size = int.from_bytes(memory(this+32,4),'little')
            if size != 1440:
                raise RuntimeError('unexpected LED driver size')
            if in_scene:
                if core() != selected_core:
                    raise RuntimeError('LED output changed CPU core')
                if len(reads) not in (0,64):
                    raise RuntimeError('scene ADC acquisition is incomplete')
                selector = memory(0x3ffc53cc,32)
                check_selection(selector,request['settings'])
                frames.append({'index':len(frames),'ccount':register('ccount'),
                               'logical':memory(0x3ffc548c,1440).hex(),
                               'driver':memory(pointer,size).hex(),
                               'state':memory(0x3ffc6530,80).hex(), 'selector':selector.hex(),
                               'selector_before':selector_before.hex(),
                               'core':selected_core, 'adc':list(reads)})
                in_scene = False
            else:
                boot_frames += 1
                if boot_frames > 2000:
                    raise RuntimeError('no scene output after 2000 boot frames')
            set_register(argument(0),14400)
            set_register('pc',0x40008534)
        else:
            raise RuntimeError('unexpected debugger stop at '+hex(pc))
    result = {'schema':'tycvl.board.observations.v1', 'request_id':request['request_id'],
              'request_sha256':hashlib.sha256(raw).hexdigest(),
              'boot_frames':boot_frames,'wifi_failures':wifi_failures,'frames':frames,
              'loaded_app_checks':loaded_checks,
              'core_mapping':'qemu-gdb-thread-global-num-minus-one',
              'packet_policy':'packet i belongs to scene/output frame i; zero-read frames discard their packet'}
    with (work/'board-observations.json').open('x') as target:
        json.dump(result,target,sort_keys=True,separators=(',',':'))
        target.write('\n')
    print('TycVirtualLab board capture complete:',len(frames),'scene frames;',boot_frames,'boot frames')
    gdb.execute('detach',to_string=True)


try:
    run()
except BaseException as error:
    print('TycVirtualLab board capture failed:',str(error))
    gdb.execute('quit 2')
