"""Original GLORB renderer closure with an authored memory-backed RGB Bus.

Only the identified GLORB.1.3 ESP32-S3 debug image is accepted. Original
instructions are never patched: the virtual Bus is a separate loaded object
with declared vtable methods. Captures stop at logical/mapped RGB.
"""

import copy
from pathlib import Path
import shutil
import struct
import sys

from ..firmware import inspect_image
from ..model import (file_digest, private_path, require, validate_profile,
                     write_json)
from ..runner import run_process
from .glorb import INPUT, settings, palette_rgb16

APP_SHA256 = "888454572bc34beb86e1595e86aef3ff9f477e2f6501201011e91279f29c597a"
FUNCTIONS = {"hiphotic": 0x4204321c, "blackhole": 0x420430c0, "frizzles": 0x42043560,
             "colorwaves": 0x42042e48, "running": 0x420433b4, "tartan": 0x42043b28}
STRIP, SEGMENT, BUS, VTABLE = 0x3fca72a8, 0x3fcb0000, 0x3fcb1000, 0x3fcb1100
PHYSICAL, LOGICAL, MAPPING, BOUNDARY = 0x3fcb2000, 0x3fcb2200, 0x3fcb2400, 0x40390000
AUDIO, AUDIO_VTABLE, AUDIO_DATA, AUDIO_POINTERS, VOLUME = 0x3fcb2600, 0x3fcb2700, 0x3fcb2800, 0x3fcb2820, 0x3fcb2840
LIMITATIONS = [
    "Original effect, palette lookup, blend, fade, blur, ledmap and BusManager execute; virtual Bus only stores/loads RGB.",
    "Direct effect calls with initialized preset state; WLED boot, scheduler, crossfades and network services are outside this boundary.",
    "Palette16 is supplied by the source profile; original palette loading is not executed.",
    "Sound-reactive mode takes supplied float32 volumeSmth through an authored AudioReactive data object; original getUMData and effect reads execute.",
    "Processed volume is an input boundary; microphone PDM, FFT, smoothing and AGC are outside this renderer closure.",
    "Logical/mapped RGB excludes physical bus signaling and brightness/current limiting.",
    "Declared state comparison covers step, call, aux0 and aux1 only.",
]


def _wrap_image(source, output):
    info = inspect_image(source, "esp32")
    require(info["sha256"] == APP_SHA256, "original GLORB requires the identified GLORB.1.3 S3 debug image")
    data = Path(source).read_bytes()
    segments = info["segments"]
    names, sections, programs = b"\0", [], []
    result = bytearray(52 + 32 * len(segments))
    for i, segment in enumerate(segments):
        address, size, offset = segment["load_address"], segment["file_size"], segment["file_offset"]
        result.extend(bytes(-len(result) % 4))
        start = len(result)
        result.extend(data[offset:offset+size])
        executable = 0x40000000 <= address < 0x44000000
        name_offset = len(names)
        names += f".segment{i}".encode() + b"\0"
        programs.append(struct.pack("<IIIIIIII", 1, start, address, address, size, size, 5 if executable else 6, 4))
        sections.append(struct.pack("<IIIIIIIIII", name_offset, 1, 6 if executable else 3,
                                    address, start, size, 0, 0, 4, 0))
    name_offset, start = len(names), len(result)
    names += b".shstrtab\0"
    result.extend(names)
    sections.append(struct.pack("<IIIIIIIIII", name_offset, 3, 0, 0, start, len(names), 0, 0, 1, 0))
    result.extend(bytes(-len(result) % 4))
    section_offset = len(result)
    result += bytes(40) + b"".join(sections)
    result[:52] = struct.pack("<16sHHIIIIIHHHHHH", b"\x7fELF\x01\x01\x01"+bytes(9), 2, 94, 1,
                              info["entry_point"], 52, section_offset, 0x300, 52, 32, len(programs),
                              40, len(sections)+1, len(sections))
    result[52:52+32*len(programs)] = b"".join(programs)
    with output.open("xb") as destination:
        destination.write(result)
    return info


def _build_bus(output, compiler):
    executable = shutil.which(str(compiler))
    require(executable is not None and Path(executable).name.endswith("gcc"), "an Xtensa GCC compiler is required")
    executable = Path(executable)
    prefix = executable.name[:-3]
    objcopy, nm = (executable.with_name(prefix + name) for name in ("objcopy", "nm"))
    require(objcopy.is_file() and nm.is_file(), "matching Xtensa objcopy/nm tools are required")
    native = Path(__file__).resolve().parents[1] / "native"
    source, linker = native / "glorb_bus.c", native / "glorb_bus.ld"
    pins = {str(path): file_digest(path) for path in (executable, objcopy, nm, source, linker)}
    elf, binary = output / "virtual_bus.elf", output / "virtual_bus.bin"
    command = [str(executable), "-Os", "-mabi=windowed", "-mlongcalls", "-ffreestanding", "-fno-builtin",
               "-nostdlib", "-Wl,--build-id=none", "-Wl,-T,"+str(linker), str(source), "-o", str(elf)]
    run_process(command, output, output / "compiler.stdout.log", output / "compiler.stderr.log", 120)
    run_process([str(objcopy), "-O", "binary", "--only-section=.text", str(elf), str(binary)],
                output, output / "objcopy.stdout.log", output / "objcopy.stderr.log", 30)
    run_process([str(nm), "-n", str(elf)], output, output / "symbols.txt", output / "nm.stderr.log", 30)
    symbols = {}
    for line in (output / "symbols.txt").read_text().splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1] in {"t", "T"}:
            symbols[fields[2]] = int(fields[0], 16)
    require({"virtual_length", "virtual_get", "virtual_set", "snapshot", "set_frame_time",
             "virtual_audio_id", "virtual_audio_data"} <= symbols.keys(), "missing boundary symbols")
    require(binary.stat().st_size <= 16384 and all(BOUNDARY <= value < BOUNDARY + binary.stat().st_size
                                                for value in symbols.values()), "boundary exceeds reserved code memory")
    require(pins == {path: file_digest(path) for path in pins}, "boundary compiler/source changed")
    write_json(output / "build.json", {"kind": "authored-memory-bus", "command": command, "inputs": pins,
                                       "elf_sha256": file_digest(elf), "binary_sha256": file_digest(binary), "symbols": symbols})
    return binary, symbols, source


def _write(address, value, width=4):
    return {"op": "write", "address": address, "hex": int(value).to_bytes(width, "little").hex()}


def prepare_original(image, source_profile, output_dir, *, compiler, headless=None, limiter=None,
                     hold_files=None, timeout_s=1200):
    """Write matching original/source profiles for an existing GLORB host setup.

    This compiles only an authored bus fixture and byte-preservingly wraps the
    supplied original app. It never opens hardware or copies captures into source.
    The returned source profile intentionally shares the logical/mapped boundary.
    """
    source_profile = copy.deepcopy(validate_profile(source_profile))
    require(source_profile["backend"].get("execution_kind") == "recovered-code", "GLORB source profile required")
    require(source_profile["input"] == INPUT, "GLORB source input must be processed WLED volume")
    require(source_profile.get("target") == {"chip":"esp32-s3", "isa":"xtensa-lx7", "abi":"xtensa-windowed"},
            "GLORB source target must be ESP32-S3 with the windowed ABI")
    config = source_profile["backend"].get("options", {}).get("glorb")
    require(isinstance(config, dict) and config.get("width") == 20 and config.get("height") == 6
            and config.get("physical_pixels") == 120, "original GLORB boundary requires the factory 20x6 layout and 120 pixel bus")
    selected = settings(source_profile.get("settings"))
    mapping = config.get("map")
    require(isinstance(mapping, list) and len(mapping) == 120
            and all(type(n) is int and -1 <= n < 120 for n in mapping), "invalid 120 cell ledmap")
    require(any(n >= 0 for n in mapping), "ledmap must contain mapped pixels")
    require(len({n for n in mapping if n >= 0}) == sum(n >= 0 for n in mapping), "duplicate ledmap entries")
    palette = palette_rgb16(config.get("palette_rgb16"))
    require(type(timeout_s) in (int, float) and 10 <= timeout_s <= 86400, "invalid timeout")
    require(hold_files is None or isinstance(hold_files, (list, tuple)), "hold_files must be a sequence of paths")
    hold_files = [str(Path(path).expanduser().resolve()) for path in (hold_files or [])]
    image = Path(image).expanduser().resolve(strict=True)
    require(inspect_image(image, "esp32")["sha256"] == APP_SHA256, "unsupported original GLORB firmware image")
    output = private_path(output_dir)
    require(not output.exists(), "original setup directory must be fresh")
    output.mkdir(parents=True, mode=0o700)
    elf = output / "glorb.elf"
    image_info = _wrap_image(image, elf)
    binary, symbols, boundary_source = _build_bus(output, compiler)
    init = [_write(STRIP+1, selected["palette_blend"], 1), _write(STRIP+16, 1, 1),
            _write(STRIP+56, 120, 2), _write(STRIP+60, SEGMENT), _write(STRIP+64, SEGMENT+68),
            _write(STRIP+68, SEGMENT+68), _write(STRIP+74, 120, 2), _write(STRIP+82, 23, 2),
            _write(STRIP+116, MAPPING), _write(STRIP+120, 120, 2), _write(STRIP+128, 0, 1),
            _write(0x3fc9919c, 20, 2), _write(0x3fc9919a, 6, 2), _write(SEGMENT+2, 20, 2),
            _write(SEGMENT+6, selected["speed"], 1), _write(SEGMENT+7, selected["intensity"], 1),
            _write(SEGMENT+8, selected["palette_id"], 1), _write(SEGMENT+10, 5, 2),
            _write(SEGMENT+12, 1, 1), _write(SEGMENT+14, 255, 1), _write(SEGMENT+28, 127, 1),
            _write(SEGMENT+29, selected["custom1"], 1), _write(SEGMENT+30, selected["custom2"], 1),
            _write(SEGMENT+31, selected["custom3"] | (32 if selected["sound_reactive"] else 0), 1),
            _write(SEGMENT+33, 6, 1), _write(SEGMENT+60, 1, 1),
            _write(0x3fca7338, 1, 1), _write(0x3fca733c, BUS), _write(BUS, VTABLE), _write(BUS+8, 120, 2),
            _write(BUS+12, PHYSICAL), _write(VTABLE+20, symbols["virtual_set"]),
            _write(VTABLE+24, symbols["virtual_get"]), _write(VTABLE+40, symbols["virtual_length"]),
            {"op": "write", "address": MAPPING, "hex": b"".join(struct.pack("<H", n if n >= 0 else 65535) for n in mapping).hex()},
            {"op": "write", "address": 0x3fc9fe80, "hex": bytes(v for color in palette for v in color).hex()}]
    init += [_write(0x3fca7220, AUDIO), _write(0x3fca7238, 1, 1), _write(AUDIO, AUDIO_VTABLE),
             _write(AUDIO+4, AUDIO_DATA), _write(AUDIO_VTABLE+72, symbols["virtual_audio_id"]),
             _write(AUDIO_VTABLE+24, symbols["virtual_audio_data"]), _write(AUDIO_DATA+8, AUDIO_POINTERS),
             _write(AUDIO_POINTERS, VOLUME)]
    init += [_write(SEGMENT+16+4*i, (color[0]<<16) | (color[1]<<8) | color[2])
             for i, color in enumerate(selected["colors"])]
    def asset(role, path, format=None):
        record = {"role": role, "path": str(Path(path).resolve()), "sha256": file_digest(path)}
        if format:
            record["format"] = format
        return record
    assets = [asset("elf", elf, "elf"), asset("original-app", image, "esp32"),
              asset("authored-memory-bus", binary), asset("authored-memory-bus-source", boundary_source),
              asset("authored-memory-bus-build", output/"build.json")]
    ghidra = {"elf_role": "elf", "abi": {"kind": "xtensa-windowed", "stack_pointer": 0x3fcdf000,
                                          "return_sentinel": 0x403ff000},
              "memory_regions": [{"address": 0x3fc9fdfc, "size": 0x20204}, {"address": 0x3fcd8000, "size": 0x7000}],
              "binary_mappings": [{"role": "authored-memory-bus", "address": BOUNDARY}],
              "hooks": [{"address": 0x420842f4, "kind": "millis"}], "initialization": init,
              "observations": [{"id": selected["effect"], "address": FUNCTIONS[selected["effect"]]},
                               {"id": "audio-lookup", "address": 0x42150ba4},
                               {"id": "audio-value-read", "address": 0x42043023 if selected["effect"] == "colorwaves" else 0x42043424}],
              "input_writes": [{"channel":0, "address":VOLUME, "width":4, "encoding":"float32-le"}],
              "frame_calls": [{"op": "call", "address": symbols["set_frame_time"], "arguments":[STRIP+8, {"time_ms":True}]},
                              {"op": "call", "address": FUNCTIONS[selected["effect"]]},
                              {"op": "call", "address": symbols["snapshot"],
                               "arguments": [SEGMENT+48, MAPPING, PHYSICAL, LOGICAL, 120]}],
              "outputs": [{"id": "logical", "address": LOGICAL, "size": 360}, {"id": "mapped", "address": PHYSICAL, "size": 360}],
              "state": [{"id": "segment", "address": SEGMENT+44, "size": 12}],
              "instruction_limit": 2000000, "max_frames": 5000, "output_limit": 64*1024*1024,
              "settings_acknowledgements": copy.deepcopy(selected), "input_read_policy": "glorb-volume",
              "timeout_s": float(timeout_s)*.9, "hold_files": hold_files}
    if headless is not None:
        ghidra["headless"] = str(Path(headless).resolve(strict=True))
    if limiter is not None:
        assets.append(asset("limiter", Path(limiter).resolve(strict=True)))
        ghidra.update(launcher_role="limiter", launcher_environment={"EMU_SLOTS":"1", "EMU_CPUS":"1", "EMU_MEM":"3072M", "EMU_NO_LIMIT":"0"})
    source_profile["settings"] = selected
    source_profile.setdefault("geometry", {"kind":"strips"})
    source_profile["buses"] = [{"id": name, "pixels":120, "order":"RGB", "stage":"logical"} for name in ("logical", "mapped")]
    source_profile["geometry"]["mask"] = {k:v for k,v in source_profile["geometry"].get("mask", {}).items() if k in {"logical", "mapped"}}
    source_profile["geometry"]["points"] = [p for p in source_profile["geometry"].get("points", []) if p["bus"] in {"logical", "mapped"}]
    source_profile["backend"]["options"]["glorb"].pop("driver", None)
    original = {"schema":"vfl.profile.v1", "id":source_profile["id"], "input":copy.deepcopy(source_profile["input"]),
                "target":{"chip":"esp32-s3", "isa":"xtensa-lx7", "abi":"xtensa-windowed"},
                "description":"Original GLORB effect and WLED helper closure with virtual RGB memory Bus",
                "settings":selected, "firmware":assets, "buses":copy.deepcopy(source_profile["buses"]),
                "geometry":copy.deepcopy(source_profile["geometry"]),
                "backend":{"kind":"external", "execution_kind":"original-firmware", "timeout_s":timeout_s,
                           "command":[sys.executable,"-m","vfl.ghidra","{request}","{capture}"],
                           "env":{"PYTHONPATH":str(Path(__file__).resolve().parents[2])}, "options":{"ghidra":ghidra}},
                "metadata":{"device":"glorb", "revision":"GLORB.1.3-debug", "limitations":list(LIMITATIONS)}}
    validate_profile(source_profile)
    validate_profile(original)
    write_json(output/"original.profile.json", original)
    write_json(output/"source.profile.json", source_profile)
    write_json(output/"image.json", image_info)
    return {"original_profile":original, "source_profile":source_profile,
            "original_profile_path":str(output/"original.profile.json"), "source_profile_path":str(output/"source.profile.json")}
