"""HyperCube hs-2.2 setup for execution of user-supplied original instructions.

This module contains address metadata and device initialization recipes, never
renderer implementations or firmware bytes. Unknown image revisions fail closed.
"""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import struct
import sys

from .. import device_inputs
from ..firmware import inspect_image
from ..model import LabError, compatible_input, file_digest, integer, private_path, require, validate_profile, validate_trace

REVISION = "hs-2.2"
APP_SHA256 = "b2f8ddabe7139f8f35d02c0716838b13c167ba449def5954d605b716442986dc"
ROM_SOURCES = {
    "761fa92b557e1aa195be4f00faaec776ad1ecae95f71b88da82938e8af3a076a":
        "This run uses the historical, partial ESP8266 ROM reconstruction from a disassembly.",
    "32f199bf10da9a08c6c4e1b556b29c7606656b8a6d04e4f17d5afa74e5d98c68":
        "This run uses the public ESP8266 reference ROM. Its identity with the physical controller remains unverified.",
}
# Load addresses, lengths and content hashes identify this revision independently
# of ELF container metadata or symbols. No segment contents are distributed.
SEGMENTS = (
    (0x40201010, 594388, "79bbf0f07b3acda2d9af210d1df9c063e25417665dbaab1eec1b4f49926078ef"),
    (0x40100000, 380, "76c3c785347c66d6ad262c01d6d73408383b7a3218376c949256da54074f1ad5"),
    (0x4010017c, 28252, "33a77fd8e6630c60a1cd015f7d7c4e5d4856a22abbfcadc537ee837e0668279b"),
    (0x3ffe8000, 1684, "67f5554ce0ac2d8e68c0d2c05177504e3053e13b4c5e433db3997155492bd07e"),
    (0x3ffe86a0, 6320, "4629f856b7cba3e4dd75606b8646cca66628fab90470119cb82cf2b4760ced39"),
)
# selector, pointer-table index, group, group index, original address, display name
_EFFECTS = (
    (5, 55, 'kaleido', 1, 0x4020a5a0, 'Hyper-Rainbow'),
    (6, 56, 'kaleido', 2, 0x4020bd64, 'Supernova'),
    (7, 57, 'kaleido', 3, 0x40215d9c, 'Entropy Engine'),
    (8, 58, 'kaleido', 4, 0x40211734, 'Photonic Accelerator'),
    (9, 59, 'kaleido', 5, 0x4020cc78, 'Grand Prismatic'),
    (10, 60, 'kaleido', 6, 0x4020d1d8, 'Orbital Loop'),
    (11, 61, 'kaleido', 7, 0x402110c4, 'Strange Attractor'),
    (12, 62, 'kaleido', 8, 0x4020dac4, 'Warp Core'),
    (13, 63, 'kaleido', 9, 0x4020a930, 'Chromatic Precession'),
    (14, 64, 'kaleido', 10, 0x40216c10, 'Singularity'),
    (15, 65, 'kaleido', 11, 0x4020d82c, 'Time Warp'),
    (16, 66, 'kaleido', 12, 0x4020b75c, 'Gamma Ray Burst'),
    (17, 67, 'kaleido', 13, 0x4020ba50, 'Gravitational Wave'),
    (18, 68, 'kaleido', 14, 0x40210a58, 'Divergence'),
    (19, 69, 'kaleido', 15, 0x4020dd90, 'Superconductor'),
    (20, 70, 'kaleido', 16, 0x4020b150, 'Achromatic Shift'),
    (21, 71, 'kaleido', 17, 0x4020c694, 'Prismatic Pulse'),
    (22, 72, 'kaleido', 18, 0x4020c254, 'Dazzle Blaster'),
    (23, 73, 'kaleido', 19, 0x4020af88, 'Hyperbolic Manifold'),
    (24, 74, 'kaleido', 20, 0x40210cb4, 'Core Collapse'),
    (25, 75, 'kaleido', 21, 0x4020b950, 'Atomic Generator'),
    (26, 76, 'kaleido', 22, 0x4020bf4c, 'Flux Capacitor'),
    (27, 77, 'kaleido', 23, 0x40215c68, 'Quasar'),
    (28, 78, 'kaleido', 24, 0x40211d2c, 'Stellar Reactor'),
    (29, 79, 'kaleido', 25, 0x4020a760, 'Rainbow Cannon'),
    (30, 80, 'kaleido', 26, 0x4020b3dc, 'Solar Flare'),
    (31, 81, 'kaleido', 27, 0x4020d400, 'Cosmic Rays'),
    (32, 82, 'kaleido', 28, 0x40216558, 'Ionization'),
    (33, 83, 'kaleido', 29, 0x4020b064, 'Fusion Core'),
    (34, 84, 'kaleido', 30, 0x40211a80, 'Hypernova'),
    (35, 85, 'kaleido', 31, 0x4020abe4, 'Superluminal'),
    (36, 86, 'kaleido', 32, 0x40216020, 'Superposition'),
    (37, 87, 'kaleido', 33, 0x4020c980, 'Chromatic Wave'),
    (38, 88, 'kaleido', 34, 0x40217238, 'Pulsar'),
    (39, 89, 'kaleido', 35, 0x40215ac8, 'Quantum Instability'),
    (40, 90, 'kaleido', 36, 0x40210f50, 'Dielectric Breakdown'),
    (41, 91, 'kaleido', 37, 0x40211518, 'Photonic Pulse'),
    (42, 92, 'kaleido', 38, 0x4020cf70, 'Luminous Scatter'),
    (43, 93, 'kaleido', 39, 0x4021138c, 'Magnetar'),
    (44, 94, 'kaleido', 40, 0x40216eac, 'Scintillation'),
    (80, 0, 'calm', 0, 0x4020e53c, 'Breathing'),
    (81, 1, 'calm', 1, 0x40210008, 'Continuum'),
    (82, 2, 'calm', 2, 0x4020e014, 'Dynamo'),
    (83, 3, 'calm', 3, 0x4020ed68, 'Comets'),
    (84, 4, 'calm', 4, 0x4020f308, 'Synchrotron'),
    (85, 5, 'calm', 5, 0x4020ea10, 'Phase Wipe'),
    (86, 6, 'calm', 6, 0x4020f670, 'Nucleus'),
    (87, 7, 'calm', 7, 0x40216214, 'Twinkle'),
    (88, 8, 'calm', 8, 0x4020f864, 'Prismatic Alignment'),
    (89, 9, 'calm', 9, 0x4020f054, 'Stable Isotope'),
    (90, 10, 'calm', 10, 0x40216368, 'Luminous Ether'),
    (91, 11, 'calm', 11, 0x402107d8, 'Photonic Core'),
    (92, 12, 'calm', 12, 0x40210540, 'Equilibration'),
    (93, 13, 'calm', 13, 0x4020fd58, 'Plasma Field'),
    (94, 14, 'calm', 14, 0x4020f124, 'Serenity'),
    (95, 15, 'calm', 15, 0x4020f5b0, 'Chromatic Flux'),
    (96, 16, 'calm', 16, 0x4020faf0, 'Convergence'),
    (97, 17, 'calm', 17, 0x40215ee8, 'Shimmer'),
    (98, 18, 'calm', 18, 0x4020f4e4, 'Celestial'),
    (99, 19, 'calm', 19, 0x402102bc, 'Zenith'),
    (100, 20, 'calm', 20, 0x4021a6b0, 'Ignition'),
    (101, 21, 'calm', 21, 0x40216628, 'Pacifica'),
    (102, 22, 'calm', 22, 0x4020e1cc, 'Spectral Shift'),
    (103, -1, 'none', 0, 0x402155b0, 'Solid'),
    (120, 23, 'sound', 0, 0x402175b0, 'Harmonic Accelerator'),
    (121, 24, 'sound', 1, 0x402146bc, 'Sonic Superposition'),
    (122, 25, 'sound', 2, 0x402140e0, 'Sonic Sparkle'),
    (123, 26, 'sound', 3, 0x402190c8, 'Spectrogram Alpha'),
    (124, 27, 'sound', 4, 0x40212768, 'Resonant Precession'),
    (125, 28, 'sound', 5, 0x40218bc4, 'Aural Dynamo'),
    (126, 29, 'sound', 6, 0x40214f94, 'Hypersonic'),
    (127, 30, 'sound', 7, 0x402149bc, 'Resonance Engine'),
    (128, 31, 'sound', 8, 0x402142fc, 'Rainbow Symphony'),
    (129, 32, 'sound', 9, 0x40218710, 'Melodic Fusion'),
    (130, 33, 'sound', 10, 0x40219a9c, 'Spectrogram Beta'),
    (131, 34, 'sound', 11, 0x40217b30, 'Ultrasonic Arc'),
    (132, 35, 'sound', 12, 0x40212a88, 'Rhythmic Orbital'),
    (133, 36, 'sound', 13, 0x402120ec, 'Tonal Entanglement'),
    (134, 37, 'sound', 14, 0x40212554, 'Synesthesia'),
    (135, 38, 'sound', 15, 0x40218020, 'Spectrogram Delta'),
    (136, 39, 'sound', 16, 0x40213288, 'Chromatic Soundwave'),
    (137, 40, 'sound', 17, 0x40217790, 'Harmonic Ripple'),
    (138, 41, 'sound', 18, 0x40214c98, 'Sonic Superconductor'),
    (139, 42, 'sound', 19, 0x4021955c, 'Spectrogram Gamma'),
    (140, 43, 'sound', 20, 0x40211f0c, 'Dynamic Precession'),
    (141, 44, 'sound', 21, 0x40212fdc, 'Light Sound Dance'),
    (142, 45, 'sound', 22, 0x4021838c, 'Beat Shift'),
    (143, 46, 'sound', 23, 0x402139b4, 'Phase Helix'),
    (144, 47, 'sound', 24, 0x40217408, 'Symphonic Wave'),
    (145, 48, 'sound', 25, 0x40212d34, 'Sound Smash'),
    (146, 49, 'sound', 26, 0x4021528c, 'Hypersonic Orbit'),
    (147, 50, 'sound', 27, 0x40213604, 'Achromatic Harmony'),
    (148, 51, 'sound', 28, 0x4021a44c, 'Acoustic Ignition'),
    (149, 52, 'sound', 29, 0x40219ff0, 'Ultra Sound'),
    (150, 53, 'sound', 30, 0x40213d60, 'Spectral Resonator'),
)

INPUT = {"kind": "bands", "channels": 7, "minimum": 0, "maximum": 1023, "units": "adc-counts"}
DEFAULTS = {
    "fx": 5, "sx": 128, "ix": 128, "palette": 1, "symmetry": 0, "psd": 0,
    "brightness": 200, "colors": [[255, 160, 0], [0, 0, 255], [0, 255, 0]],
    "render_mode": "engine", "dwell_s": 60, "random_order": False,
    "transition_ms": 2000, "transition_delay_ms": 1200, "boot_call": True,
    "boot_stage": "application", "normalize_strings": False, "warp": False,
    "warp_dwell_s": 12,
}

# Each substitution is an explicit hardware/service boundary, not an effect.
BOUNDARIES = (
    (0x4010120c, "return", "UART LED buffer allocation; buffer installed by setup recipe"),
    (0x40209854, "return", "I2S LED bus constructor; count and buffer installed by setup recipe"),
    (0x402259fc, "return", "SDK/service constructor"),
    (0x40226170, "return", "SDK/service constructor"),
    (0x40227dd8, "return", "SDK/service constructor"),
    (0x40228854, "return", "SDK/service constructor"),
    (0x4022dac0, "return", "SDK/service constructor"),
    (0x4022e790, "return", "serial service constructor"),
    (0x402334fc, "return", "runtime/service constructor"),
    (0x401009cc, "millis", "frame-frozen millisecond clock"),
    (0x40100a5c, "micros", "frame-frozen microsecond clock"),
    (0x4022f544, "rng", "bounded random source; seeded xorshift32"),
    (0x40205158, "noop", "UDP synchronization transport"),
    (0x40233644, "guard_acquire", "single-thread static initialization guard"),
    (0x40233660, "guard_release", "single-thread static initialization guard"),
    (0x40100ab4, "gpio", "MSGEQ7 reset/strobe GPIO controls the sampled ADC band"),
    (0x40100a94, "noop", "microsecond settling delay"),
    (0x40230ddc, "noop", "GPIO pin direction"),
    (0x40230d88, "adc", "seven-channel MSGEQ7 scan at ADC return boundary"),
    (0x40202704, "noop", "UART LED transmission after driver buffer capture"),
    (0x4021c054, "noop", "I2S DMA start after driver buffer capture"),
    (0x402306fc, "write", "DMA yield completes by clearing busy flag"),
)
SETUP_BOUNDARIES = (
    (0x40230cec, "noop", "startup millisecond delay"),
    (0x4022e614, "noop", "serial port begin"),
    (0x4022ea58, "noop", "serial startup print"),
    (0x40201064, "return", "FastLED transport registration; stable controller scratch object"),
    (0x40220448, "noop", "network, persisted settings and service setup"),
    (0x40226f78, "noop", "network callback construction"),
    (0x40226e9c, "noop", "network callback construction"),
    (0x4021c024, "noop", "network callback attachment"),
    (0x4023299c, "noop", "network callback temporary destruction"),
    (0x402327e8, "noop", "network callback temporary destruction"),
)


def effect_inventory():
    """98 user selectors plus the distinct, non-selector warp command."""
    playlists = [{"id": n, "name": name, "kind": "playlist", "group": group,
                  "address": None, "table_index": None, "group_index": None}
                 for n, name, group in ((0, "Kaleidoscopic playlist", "kaleido"),
                                       (1, "Calm playlist", "calm"), (2, "Sound playlist", "sound"))]
    effects = [{"id": fx, "name": name, "kind": "effect", "group": group,
                "address": address, "table_index": table, "group_index": index}
               for fx, table, group, index, address, name in _EFFECTS]
    return playlists + effects + [{"id": "warp", "name": "Warp animation", "kind": "command",
                                   "group": "internal", "address": 0x4021ab00,
                                   "table_index": 54, "group_index": 0}]


def device_info():
    return {"id": "hypercube", "revision": REVISION,
            "target": {"chip": "esp8266", "isa": "xtensa-lx106", "abi": "xtensa-call0"},
            "execution": "original-firmware", "execution_scope": "routine-diagnostic", "selectors": 98, "routines": 96,
            "input": copy.deepcopy(INPUT), "effects": effect_inventory(),
            "defaults": copy.deepcopy(DEFAULTS),
            "startup": {"static_initializers": 0x40220974, "application_setup": 0x402206f8,
                        "boot_settings": 0x402086b4, "render_loop": 0x4021c610},
            "boundaries": [{"address": address, "kind": kind, "description": description}
                           for address, kind, description in BOUNDARIES + SETUP_BOUNDARIES],
            "limitations": [
                "Original static constructors, optional application setup, boot settings, audio analysis and renderer execute; reset ROM, WiFi/SDK scheduler and interrupts do not.",
                "Network and persisted-settings setup is replaced by explicit profile settings. Service constructor meanings not fully recovered are identified by exact address.",
                "Microphone and MSGEQ7 analog transfer are upstream models; original GPIO reset/strobe selects the supplied ADC band. GPIO settling has no physical dynamics.",
                "ADC reads are conditional on the selected effect, brightness, frame timer and pause state; an input-independent frame or effect legitimately consumes no audio input.",
                "Captured output is two 144-pixel GRB driver buffers, not electrical UART/I2S waveforms.",
                "Clock is frozen within a frame and random values use a declared seeded surrogate.",
                "Short execution smoke does not prove physical fidelity, effect activity, playlist transitions or all settings combinations."]}


def _settings(settings=None):
    require(settings is None or isinstance(settings, dict), "HyperCube settings must be an object")
    supplied = settings or {}
    require(set(supplied) <= set(DEFAULTS), "unknown HyperCube settings: " + ", ".join(sorted(set(supplied) - set(DEFAULTS))))
    result = copy.deepcopy(DEFAULTS)
    result.update(copy.deepcopy(supplied))
    valid = {row[0] for row in _EFFECTS} | {0, 1, 2}
    integer(result["fx"], "fx", 0, 255)
    require(result["fx"] in valid, "unknown hs-2.2 effect selector; warp is a command, not an fx byte")
    for name in ("sx", "ix", "brightness", "psd"):
        integer(result[name], name, 0, 255)
    integer(result["palette"], "palette", 0, 26)
    integer(result["symmetry"], "symmetry", 0, 2)
    integer(result["dwell_s"], "dwell_s", 3, 255)
    integer(result["warp_dwell_s"], "warp_dwell_s", 1, 255)
    for name in ("transition_ms", "transition_delay_ms"):
        integer(result[name], name, 0, 65535)
    for name in ("random_order", "boot_call", "normalize_strings", "warp"):
        require(type(result[name]) is bool, f"{name} must be boolean")
    require(result["boot_stage"] in {"application", "effect"}, "boot_stage must be application or effect")
    require(result["render_mode"] == "engine", "HyperCube device uses the complete original engine render boundary")
    colors = result["colors"]
    require(isinstance(colors, list) and len(colors) == 3, "colors requires three RGB colors")
    for color in colors:
        require(isinstance(color, list) and len(color) == 3, "colors requires RGB triples")
        for component in color:
            integer(component, "RGB component", 0, 255)
    return result


def _write(address, value, width=1):
    return {"op": "write", "address": address, "hex": value.to_bytes(width, "little").hex()}


def _call(address, *arguments):
    return {"op": "call", "address": address, "arguments": list(arguments)}


def _settings_operations(settings, *, boot=False, changed=None):
    s = settings
    changed = set(s) if boot else set(changed or ())
    operations = []
    mapping = {"dwell_s": (0x3ffe8665, 1), "random_order": (0x3fff14a5, 1),
               "transition_ms": (0x3ffe8580, 2), "transition_delay_ms": (0x3ffe8582, 2),
               "warp_dwell_s": (0x3ffe8630, 1), "brightness": (0x3fff0dcc, 1),
               "fx": (0x3fff14b1, 1), "sx": (0x3fff14af, 1), "ix": (0x3fff14ae, 1),
               "palette": (0x3fff14ad, 1), "psd": (0x3fff14ab, 1), "symmetry": (0x3fff14ac, 1)}
    for key, (address, width) in mapping.items():
        if key in changed:
            operations.append(_write(address, int(s[key]), width))
    if "colors" in changed:
        for address, color in zip((0x3ffe8548, 0x3fff0dee, 0x3fff0de8), s["colors"]):
            operations.append({"op": "write", "address": address, "hex": bytes(color).hex()})
    if boot:
        operations.append(_write(0x3ffe8668, s["brightness"]))
    if "psd" in changed:
        operations.append(_call(0x40226264, 0x3fff14c4, s["psd"]))
    # Boot follows original boot caller. Later settings enter original
    # colorUpdated(JSON mode). Brightness progression runs in the frame recipe.
    if boot:
        operations.append(_call(0x402086b4) if s["boot_call"] else _call(0x40207ca0, 1))
    elif changed - {"warp"}:
        operations.append(_call(0x40207e5c, 1))
    if "warp" in changed and s["warp"]:
        # Same pending flag consumed by original vloop_render as UDP warp input.
        operations.append(_write(0x3fff1460, 1))
    # False clears a queued warp request. It does not interrupt an animation
    # that the original render loop has already started.
    elif changed == {"warp"}:
        operations.append(_write(0x3fff1460, 0))
    return operations


def _verify_elf(path):
    path = Path(path).expanduser().resolve(strict=True)
    image = inspect_image(path, format="elf")
    require(image["machine_id"] == 94 and image["elf_class"] == 32 and image["byte_order"] == "little",
            "HyperCube requires a 32-bit little-endian Xtensa ELF")
    segments = [s for s in image["segments"] if s["type"] == 1 and s["file_size"]]
    require(len(segments) == len(SEGMENTS), "ELF is not the supported hs-2.2 load map")
    raw = path.read_bytes()
    expected = {address: (size, sha) for address, size, sha in SEGMENTS}
    seen = set()
    for segment in segments:
        address, size, offset = segment["virtual_address"], segment["file_size"], segment["file_offset"]
        require(address in expected and address not in seen, "unsupported or duplicate hs-2.2 segment")
        require((size, hashlib.sha256(raw[offset:offset + size]).hexdigest()) == expected[address],
                "firmware revision differs from supported hs-2.2; addresses must not be guessed")
        seen.add(address)
    for section in image["sections"]:
        if not section["flags"] & 2 or not section["has_file_data"] or not section["size"]:
            continue
        address, size, offset = section["address"], section["size"], section["file_offset"]
        containing = [segment for segment in segments if segment["virtual_address"] <= address
                      and address + size <= segment["virtual_address"] + segment["file_size"]]
        require(len(containing) == 1, "ELF has an unexpected allocated section outside the supported image")
        segment = containing[0]
        expected_offset = segment["file_offset"] + address - segment["virtual_address"]
        require(raw[offset:offset + size] == raw[expected_offset:expected_offset + size],
                "ELF section contents differ from the validated load segment")
    return path, image["sha256"]


def prepare_image(app_image, output_elf):
    """Wrap a user-owned standalone E9 hs-2.2 image without changing guest bytes.

    The output is itself proprietary firmware and belongs outside the public
    source tree. Existing files are never overwritten. Full flash dumps are not
    accepted because they may contain device-specific credentials or settings.
    """
    source = Path(app_image).expanduser().resolve(strict=True)
    image = inspect_image(source, format="esp8266")
    require(image["sha256"] == APP_SHA256, "only the identified hs-2.2 standalone app image is supported")
    raw = source.read_bytes()
    segments = sorted(image["segments"], key=lambda s: next((i for i, row in enumerate(SEGMENTS)
                      if row[0] == s["load_address"]), 999))
    require([(s["load_address"], s["file_size"]) for s in segments] == [(a, n) for a, n, _ in SEGMENTS],
            "unexpected application segment layout")
    names = [".irom0.text", ".iram0.vec", ".iram0.text", ".data", ".rodata", ".bss", ".rom", ".shstrtab"]
    strings = b"\0"; name_offsets = {}
    for name in names:
        name_offsets[name] = len(strings); strings += name.encode() + b"\0"
    result = bytearray(52 + 32 * len(segments)); sections = [bytes(40)]; programs = []
    for index, segment in enumerate(segments):
        result.extend(bytes((-len(result)) % 4)); offset = len(result)
        address, size, start = segment["load_address"], segment["file_size"], segment["file_offset"]
        result.extend(raw[start:start + size])
        flags = 6 if index < 3 else 3
        programs.append(struct.pack("<IIIIIIII", 1, offset, address, address, size, size, 5 if index < 3 else 6, 4))
        sections.append(struct.pack("<IIIIIIIIII", name_offsets[names[index]], 1, flags, address, offset, size, 0, 0, 4, 0))
    for name, address, size, flags in ((".bss", 0x3ffe9f50, 0x120b0, 3), (".rom", 0x40000000, 0x10000, 6)):
        sections.append(struct.pack("<IIIIIIIIII", name_offsets[name], 8, flags, address, len(result), size, 0, 0, 4, 0))
    string_offset = len(result); result.extend(strings)
    sections.append(struct.pack("<IIIIIIIIII", name_offsets[".shstrtab"], 3, 0, 0, string_offset, len(strings), 0, 0, 1, 0))
    result.extend(bytes((-len(result)) % 4)); section_offset = len(result)
    result.extend(b"".join(sections))
    result[:52] = struct.pack("<16sHHIIIIIHHHHHH", b"\x7fELF\x01\x01\x01" + bytes(9), 2, 94, 1,
                              image["entry_point"], 52, section_offset, 0x300, 52, 32, len(programs), 40, len(sections), len(sections) - 1)
    result[52:52 + 32 * len(programs)] = b"".join(programs)
    target = private_path(output_elf)
    require(target.parent.is_dir(), "output directory must already exist")
    with target.open("xb") as output:
        output.write(result)
    _verify_elf(target)
    return {"revision": REVISION, "path": str(target.resolve()), "sha256": file_digest(target),
            "source_sha256": image["sha256"], "redistributable": False}


def build_profile(elf, rom, *, settings=None, trace=None, headless=None, limiter=None,
                  hold_files=(), timeout_s=1800, state_encoding="sha256"):
    """Build an executable profile; optional trace binds scheduled setting changes.

    Trace controls are partial settings updates. ``warp: true`` is a one-shot
    event; boot-only keys are rejected. No expected outputs enter the recipe.
    """
    s = _settings(settings)
    program, program_sha = _verify_elf(elf)
    rom_path = Path(rom).expanduser().resolve(strict=True)
    require(rom_path.is_file(), "ESP8266 ROM must be a regular file")
    rom_sha = file_digest(rom_path)
    require(rom_sha in ROM_SOURCES, "unrecognized ESP8266 ROM SHA256")
    limits = [*device_info()["limitations"], ROM_SOURCES[rom_sha]]
    integer(timeout_s, "timeout_s", 30, 86400)
    require(state_encoding in {"bytes", "sha256"}, "unknown state encoding")
    hooks = []
    for address, kind, _ in BOUNDARIES + (SETUP_BOUNDARIES if s["boot_stage"] == "application" else ()):
        hook = {"address": address, "kind": kind}
        if kind == "return": hook["value"] = 0x3fffc000 if address == 0x40201064 else 0
        if kind == "rng": hook["mode"] = "bounded"
        if kind == "write": hook.update(target=0x3fff14e4, width=1, value=0)
        hooks.append(hook)
    initialization = [_call(0x40220974), _write(0x3fff0e90, 1, 4),
                      _write(0x3fff14e0, 144, 2), _write(0x3fff14f4, 0x3fffd200, 4),
                      _write(0x3fff1514, 0x3fffd000, 4)]
    if s["normalize_strings"]:
        initialization.extend({"op": "write", "address": address, "hex": bytes(size).hex()}
                              for address, size in ((0x3ffe855b, 14), (0x3ffe85a9, 11), (0x3ffe85ca, 9)))
    if s["boot_stage"] == "application":
        initialization.append(_call(0x402206f8))
    initialization.extend(_settings_operations(s, boot=True))
    config = {"elf_role": "elf", "abi": {"kind": "xtensa-call0", "stack_pointer": 0x3fffff00, "return_sentinel": 0x40010000},
              "memory_regions": [{"address": 0x3ffe9f50, "size": 0x40000000 - 0x3ffe9f50}],
              "binary_mappings": [{"role": "rom", "address": 0x40000000, "length": 0xe380}],
              "hooks": hooks, "initialization": initialization,
              "adc_scan": {"reset_pin": 5, "strobe_pin": 4, "channels": 7, "advance_edge": "falling"},
              "observations": [{"id": "warp" if effect["id"] == "warp" else f"fx-{effect['id']}", "address": effect["address"]}
                               for effect in effect_inventory() if effect["address"] is not None],
              "frame_calls": [_call(0x4021c610)],
              "outputs": [{"id": "driver-a", "address": 0x3fffd000, "size": 432}, {"id": "driver-b", "address": 0x3fffd200, "size": 432}],
              "state": [{"id": "data", "address": 0x3ffe8000, "size": 1684}, {"id": "bss", "address": 0x3ffefac0, "size": 9024}],
              "state_encoding": state_encoding, "settings_acknowledgements": copy.deepcopy(s),
              "timeout_s": timeout_s - 10, "instruction_limit": 2000000, "max_frames": 5000,
              "output_limit": 256 * 1024 * 1024, "adc_policy": "strict",
              "input_read_policy": "hypercube-adc",
              "hold_files": [str(Path(path).expanduser().absolute()) for path in hold_files]}
    if headless is not None: config["headless"] = str(Path(headless).expanduser().resolve(strict=True))
    assets = [{"role": "elf", "format": "elf", "path": str(program), "sha256": program_sha},
              {"role": "rom", "path": str(rom_path), "sha256": rom_sha}]
    if limiter is not None:
        limit_path = Path(limiter).expanduser().resolve(strict=True)
        require(limit_path.is_file(), "resource limiter must be a regular file")
        assets.append({"role": "resource_limiter", "path": str(limit_path), "sha256": file_digest(limit_path)})
        config.update(launcher_role="resource_limiter", post_launcher_hold_check=True,
                      launcher_environment={"EMU_SLOTS": "1", "EMU_CPUS": "1", "EMU_MEM": "3072M", "EMU_NO_LIMIT": "0"})
    if trace is not None:
        validate_trace(trace)
        compatible_input({"input": INPUT}, trace)
        active = copy.deepcopy(s); recipes = []
        boot_only = {"boot_stage", "boot_call", "render_mode", "normalize_strings"}
        for frame in trace["frames"]:
            controls = frame.get("controls", {})
            if not controls: continue
            require(not set(controls) & boot_only, "boot-only settings cannot change within a trace")
            active["warp"] = False
            active.update(controls)
            active = _settings(active)
            recipes.append({"index": frame["index"], "controls": copy.deepcopy(controls),
                            "operations": _settings_operations(active, changed=controls)})
        if recipes:
            config["frame_operations"] = recipes
            # Original loop calls the brightness-transition step before render.
            # Include it for live setting changes; fixed-setting render campaigns
            # preserve the narrower engine boundary for comparison compatibility.
            config["frame_calls"].insert(0, _call(0x402057c8))
    profile = {"schema": "vfl.profile.v1", "id": "hypercube-hs22", "target": device_info()["target"],
               "metadata": {"limitations": limits},
               "description": "HyperCube hs-2.2 original application/engine with explicit virtual peripheral boundaries",
               "input": copy.deepcopy(INPUT), "geometry": {"kind": "strips"}, "settings": s,
               "buses": [{"id": name, "pixels": 144, "order": "GRB", "stage": "driver"} for name in ("driver-a", "driver-b")],
               "firmware": assets, "backend": {"kind": "external", "execution_kind": "original-firmware",
                   "command": [sys.executable, "-m", "vfl.ghidra", "{request}", "{capture}"], "timeout_s": timeout_s,
                   "env": {"PYTHONPATH": str(Path(__file__).resolve().parents[2])},
                   "options": {"ghidra": config, "device": {"id": "hypercube", "revision": REVISION,
                       "startup_stage": s["boot_stage"], "boundaries": device_info()["boundaries"],
                       "limitations": limits}}}}
    return validate_profile(profile)


def coverage_plan():
    """Independent-reset execution cases; this is a plan, never a pass claim.

    fx121 starts at intensity zero because the original firmware can divide by
    zero at startup with nonzero intensity. A later-intensity case is separate.
    The sound activity campaign needs warmup; fx137 may remain black >340 frames.
    """
    return [{"id": "warp" if effect["id"] == "warp" else f"fx-{effect['id']}",
             "effect": effect, "settings": {"fx": 5 if effect["id"] == "warp" else effect["id"],
                                           "warp": effect["id"] == "warp", "ix": 0 if effect["id"] == 121 else 128},
             "smoke_frames": 20, "smoke_frame_us": 1000000,
             "activity_frames": 500 if effect["group"] == "sound" else 128, "activity_frame_us": 32000,
             "status": "not-run"} for effect in effect_inventory()]


def smoke_trace(frames=4, *, frame_ms=32, seed=7):
    """Authored changing seven-band ADC stimulus, independent of any renderer."""
    integer(frames, "frames", 1, 5000); integer(frame_ms, "frame_ms", 1, 10000)
    return validate_trace({"schema": "vfl.trace.v1", "input": copy.deepcopy(INPUT), "seed": seed,
        "clock_policy": "frame", "provenance": {"kind": "synthetic", "description": "Deterministic seven-band staircase/beat excitation; no expected LED values"},
        "frames": [{"index": i, "time_us": (i + 1) * frame_ms * 1000,
                    "values": [min(1023, 40 + ((i * 113 + channel * 137) % 850)) for channel in range(7)],
                    "controls": {}} for i in range(frames)]})


def _collect_coverage_case(profile, trace, commands, output, output_tags, state_tags, nonce, provenance):
    """Validate real protocol evidence; deliberately not a completed-run import."""
    from ..hsemu import capture_from_output
    from ..model import digest, experiment_digest, load_json, validate_capture
    execution = load_json(str(output) + ".execution.json", maximum_bytes=1024 * 1024)
    require(execution.get("schema") == "tycvl.ghidra-execution.v1"
            and execution.get("request_id") == nonce
            and execution.get("commands_sha256") == hashlib.sha256(commands.encode()).hexdigest(),
            "coverage execution binding differs")
    require(execution.get("uninitialized_policy") == "strict"
            and execution.get("read_enforcement") == "execute-read-fault"
            and integer(execution.get("uninitialized_reads"), "uninitialized read count") == 0,
            "coverage requires strict defined-memory execution")
    config = profile["backend"]["options"]["ghidra"]
    require(output.is_file() and not output.is_symlink()
            and output.stat().st_size <= config["output_limit"], "missing or oversized coverage output")
    capture = capture_from_output(profile, trace, commands, output.read_text(), output_tags,
        state_tag_map=state_tags, request_id=nonce, execution_kind="original-firmware", backend="ghidra-pcode",
        limitations=profile["metadata"]["limitations"] + [
            "Campaign cases have protocol/nonce/asset/source validation, not the outer runner's completed-run status envelope.",
            "Each case starts a fresh emulator, original static initialization and application setup within a shared imported Ghidra Program."])
    engine = capture["manifest"].get("engine", {})
    require(engine.get("name") == "ghidra-pcode" and engine.get("abi") == "xtensa-call0"
            and engine.get("version") and engine.get("language", "").startswith("Xtensa:"), "coverage engine identity differs")
    require(len(capture["events"]) == capture["manifest"]["completion"]["stubs"], "coverage instrumentation is incomplete")
    read_counts = {kind: 0 for kind in ("adc", "clock", "rng")}
    for event in capture["events"]:
        kind = event["kind"]
        if kind in read_counts: read_counts[kind] += 1
        if kind == "adc":
            require(event["frame"] >= 0, "ADC read before frame input")
            values = trace["frames"][event["frame"]]["values"]
            channel = integer(event.get("channel"), "ADC channel", 0, 6)
            require(event["value"] == values[channel], "observed ADC value differs from stimulus")
        if kind == "clock":
            require(event.get("units") in {"ms", "us"}, "unknown clock units")
            expected = event["time_us"] // 1000 if event["units"] == "ms" else event["time_us"]
            require(event["value"] == expected & 0xffffffff, "observed clock differs from frozen schedule")
    require(all(capture["manifest"]["capabilities"].get(key) is True for key in ("adc_log", "clock_log", "rng_log", "state")),
            "coverage instrumentation capabilities incomplete")
    device_inputs.record_input_evidence(profile, trace, capture)
    encoding = config["state_encoding"]
    if encoding == "sha256":
        for frame in capture["frames"]:
            frame["state"] = {tag: hashlib.sha256(bytes.fromhex(raw)).hexdigest() for tag, raw in frame["state"].items()}
    capture["manifest"].update(execution_scope="routine-diagnostic", request_id=nonce, input_sha256=digest(trace), profile_sha256=digest(profile),
        experiment_sha256=experiment_digest(profile, trace), state_encoding=encoding,
        adapter_provenance={**provenance, "execution_metadata": execution, "read_counts": read_counts,
                            "commands_sha256": hashlib.sha256(commands.encode()).hexdigest(), "output_sha256": file_digest(output),
                            "validation_scope": "campaign-protocol-and-assets; no completed-run envelope"})
    validate_capture(capture, profile, trace)
    return capture


def run_coverage(elf, rom, output_dir, *, case_ids=None, trace=None, frames=20, batch_size=8,
                 settings=None, progress=None, script_path=None, **profile_options):
    """Execute independent-reset original cases, with at most eight per JVM.

    The fresh external directory retains requests, exact executed commands, raw
    dumps, execution metadata and normalized captures. A failing case remains a
    failure; later cases are still examined. This campaign is protocol verified,
    not falsely presented as an outer-runner completed-run directory.
    """
    import os
    import json
    import secrets
    import shutil
    import time
    from .. import ghidra, hsemu, model
    from ..ghidra import _asset_paths, compile_commands
    from ..model import digest, experiment_digest, private_path, write_json
    from ..runner import run_process
    integer(batch_size, "batch_size", 1, 8)
    out = private_path(output_dir)
    require(not out.exists(), "coverage output directory must be new")
    cases = coverage_plan()
    if case_ids is not None:
        require(isinstance(case_ids, (list, tuple)) and len(case_ids) == len(set(case_ids)) and case_ids,
                "case_ids must be a nonempty list of unique coverage IDs")
        selected = {case["id"]: case for case in cases}
        require(all(name in selected for name in case_ids), "unknown coverage case ID")
        cases = [selected[name] for name in case_ids]
    trace = validate_trace(copy.deepcopy(trace) if trace is not None else smoke_trace(frames, frame_ms=1000))
    compatible_input({"input": INPUT}, trace)
    # Preflight all cases before allocating the output directory or starting Java.
    compiled = []
    for case in cases:
        options = {**case["settings"], **(settings or {}),
                   "fx": case["settings"]["fx"], "warp": case["settings"]["warp"]}
        profile = build_profile(elf, rom, settings=options, trace=trace, **profile_options)
        assets = _asset_paths(profile)
        commands, output_tags, state_tags = compile_commands(profile, trace, assets)
        compiled.append((case, profile, assets, commands, output_tags, state_tags))
    first_profile = compiled[0][1]
    config = first_profile["backend"]["options"]["ghidra"]
    executable = config.get("headless") or os.environ.get("GHIDRA_HEADLESS") or shutil.which("ghidra-analyzeHeadless")
    require(isinstance(executable, str) and Path(executable).is_file(), "configure Ghidra headless")
    for path in config["hold_files"]:
        require(not os.path.lexists(path), "emulator HOLD is active")
    out.mkdir(parents=True)
    runtime = out / "runtime"; runtime.mkdir()
    script = (Path(script_path).expanduser().resolve(strict=True) if script_path is not None else
              Path(ghidra.__file__).with_name("ghidra") / "TycEmu.java")
    require(script.name == "TycEmu.java" and script.is_file(), "campaign script must be a declared TycEmu.java file")
    for source in (Path(__file__), Path(ghidra.__file__), Path(hsemu.__file__), Path(model.__file__), Path(device_inputs.__file__), script):
        shutil.copyfile(source, runtime / source.name)
    # The limiter can wait before acquiring its lock. Check HOLD again after
    # that wait, immediately before replacing this tiny process with Ghidra.
    guard = runtime / "launch_guard.py"
    guard.write_text("import json, os, sys\n"
                     "assert sys.argv[2] == '--'\n"
                     "if any(os.path.lexists(p) for p in json.loads(sys.argv[1])):\n"
                     "    raise SystemExit('emulator HOLD became active while waiting for the shared slot')\n"
                     "os.execvpe(sys.argv[3], sys.argv[3:], os.environ)\n")
    source_pins = {path.name: file_digest(path) for path in runtime.iterdir()}
    pinned_headless = file_digest(executable)
    summary = {"schema": "tycvl.device-coverage.v1", "device": "hypercube", "revision": REVISION,
               "status": "running", "validation_scope": "original execution with protocol/nonce/asset/source validation",
               "fidelity": "not-evaluated", "completed_run_envelope": False, "input_sha256": digest(trace), "frames_per_case": len(trace["frames"]),
               "runtime_sha256": source_pins, "cases": [], "limitations": first_profile["metadata"]["limitations"]}
    write_json(out / "campaign.json", summary)
    for group_start in range(0, len(compiled), batch_size):
        group = compiled[group_start:group_start + batch_size]
        batch = out / f"batch-{group_start // batch_size:03d}"; batch.mkdir()
        project = batch / "project"; project.mkdir()
        argv = [executable, str(project), "coverage", "-import", str(group[0][2]["elf"]["path"]),
                "-processor", "Xtensa:LE:32:default", "-noanalysis", "-deleteProject", "-scriptPath", str(runtime)]
        prepared = []
        for case, profile, assets, commands, output_tags, state_tags in group:
            directory = out / case["id"]; directory.mkdir()
            nonce = secrets.token_hex(16); command_path = directory / "commands.txt"; output_path = directory / "output.txt"
            command_path.write_text(commands)
            write_json(directory / "profile.json", profile); write_json(directory / "input.json", trace)
            write_json(directory / "request.json", {"schema": "vfl.request.v1", "request_id": nonce,
                "profile": profile, "trace": trace, "workdir": str(directory),
                "identities": {"input_sha256": digest(trace), "profile_sha256": digest(profile), "experiment_sha256": experiment_digest(profile, trace)}})
            argv.extend(["-postScript", script.name, str(command_path), str(output_path), nonce, "strict"])
            prepared.append((case, profile, assets, commands, output_tags, state_tags, directory, nonce))
        env = os.environ.copy(); env.update(config.get("launcher_environment", {}))
        properties = []
        for name in ("settings", "cache", "temp"):
            directory = batch / name; directory.mkdir(); properties.append(f'-Dapplication.{name}dir="{directory}"')
        env["JAVA_TOOL_OPTIONS"] = " ".join([env.get("JAVA_TOOL_OPTIONS", "")] + properties).strip()
        argv = [sys.executable, str(guard), json.dumps(config["hold_files"]), "--", *argv]
        if config.get("launcher_role"):
            argv.insert(0, str(group[0][2][config["launcher_role"]]["path"]))
        for path in config["hold_files"]:
            if os.path.lexists(path):
                summary.update(status="held", interruption="emulator HOLD became active before batch")
                write_json(out / "campaign.json", summary)
                raise LabError(summary["interruption"])
        # Recheck assets before every launch, and after completion before accepting results.
        require(all(assets == _asset_paths(profile) for _, profile, assets, *_ in group), "coverage asset changed")
        started = time.monotonic(); process_error = None
        try:
            run_process(argv, batch, batch / "stdout.log", batch / "stderr.log", config["timeout_s"], env,
                        output_limit=64 * 1024 * 1024, termination_grace_s=0.0)
        except (LabError, OSError) as error:
            if isinstance(error, LabError) and str(error).startswith("runner interrupted by "):
                summary.update(status="interrupted", interruption=str(error))
                write_json(out / "campaign.json", summary)
                raise
            if any(os.path.lexists(path) for path in config["hold_files"]):
                summary.update(status="held", interruption="emulator HOLD became active while waiting for the shared slot")
                write_json(out / "campaign.json", summary)
                raise LabError(summary["interruption"]) from error
            process_error = str(error)
        except KeyboardInterrupt:
            summary.update(status="interrupted", interruption="KeyboardInterrupt")
            write_json(out / "campaign.json", summary)
            raise
        require(file_digest(executable) == pinned_headless and
                all(file_digest(runtime / name) == sha for name, sha in source_pins.items()), "pinned campaign runtime changed")
        require(all(assets == _asset_paths(profile) for _, profile, assets, *_ in group), "coverage asset changed during execution")
        elapsed = time.monotonic() - started
        for case, profile, assets, commands, output_tags, state_tags, directory, nonce in prepared:
            result = {"id": case["id"], "effect": case["effect"], "status": "failed", "fidelity": "not-evaluated", "batch_seconds": round(elapsed, 3)}
            if process_error: result["batch_error"] = process_error
            try:
                capture = _collect_coverage_case(profile, trace, commands, directory / "output.txt", output_tags, state_tags, nonce,
                    {"runtime_sha256": source_pins, "headless_sha256": pinned_headless,
                     "firmware_sha256": {name: value["sha256"] for name, value in assets.items()}})
                # A process timeout/error is never hidden behind a valid partial case.
                require(process_error is None, "batch process did not complete: " + str(process_error))
                write_json(directory / "capture.json", capture)
                rgb = ["".join(frame["buses"].values()) for frame in capture["frames"]]
                result.update(status="executed", frames=len(rgb), nonblack_frames=sum(any(bytes.fromhex(raw)) for raw in rgb),
                              distinct_frames=len(set(rgb)), events=len(capture["events"]),
                              read_counts=capture["manifest"]["adapter_provenance"]["read_counts"],
                              capture_sha256=file_digest(directory / "capture.json"),
                              capture=str(directory / "capture.json"))
                entries = [event["observer_id"] for event in capture["events"]
                           if event.get("operation") == "observe-entry" and event["frame"] >= 0]
                result["observed_effects"] = sorted(set(entries))
                result["effect_entry_count"] = len(entries)
                result["requested_entry_observed"] = (case["id"] in entries
                    if case["effect"]["kind"] != "playlist" else None)
                result["execution_completed"] = True
                playlist_children = []
                if case["effect"]["kind"] == "playlist":
                    child_ids = {f"fx-{effect['id']}" for effect in effect_inventory()
                                 if effect["kind"] == "effect" and effect["group"] == case["effect"]["group"]}
                    playlist_children = sorted(set(entries) & child_ids)
                    result["playlist_children_observed"] = playlist_children
                if (case["effect"]["kind"] == "playlist" and not playlist_children) or result["requested_entry_observed"] is False:
                    result.update(status="failed", failure_kind="entry-not-reached",
                                  error="Original execution completed, but the requested effect entry was not observed; use a longer or differently timed scenario")
            except (LabError, OSError, ValueError, KeyError, TypeError) as error:
                result["error"] = str(error)
            summary["cases"].append(result)
            write_json(out / "campaign.json", summary)
            if progress is not None: progress(copy.deepcopy(result))
        # The optional shared limiter polls at two-second intervals. Yield after
        # every batch so a fresh process cannot repeatedly steal its next slot.
        time.sleep(3)
    summary.update(status="completed", executed=sum(case["status"] == "executed" for case in summary["cases"]),
                   passed=sum(case["status"] == "executed" for case in summary["cases"]),
                   passed_semantics="Compatibility count of executed cases with observed requested entries; fidelity is not evaluated",
                   failed=sum(case["status"] == "failed" for case in summary["cases"]))
    write_json(out / "campaign.json", summary)
    return summary
