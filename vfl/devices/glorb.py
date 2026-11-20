"""Build a host boundary around an externally supplied GLORB effect source."""

import copy
import math
import os
import shutil
import sys
from pathlib import Path

from ..model import (LabError, file_digest, integer, load_json, private_path,
                     require, validate_profile, write_json)
from ..runner import run_process

EFFECTS = {189: "colorwaves", 190: "running", 191: "frizzles",
           192: "blackhole", 193: "hiphotic", 195: "tartan"}
NAMES = list(EFFECTS.values())
INPUT = {"kind": "scalar", "channels": 1, "minimum": 0,
         "maximum": 65535, "units": "wled-volume-smth"}
DEFAULTS = {"effect": "hiphotic", "speed": 128, "intensity": 128,
            "custom1": 128, "custom2": 128, "custom3": 16,
            "sound_reactive": False, "palette_blend": 0, "palette_id": 1,
            "colors": [[0, 0, 255], [0, 0, 0], [0, 0, 0]]}


def device_info():
    return {"id": "glorb", "name": "GLORB", "execution_kind": "recovered-code",
            "effects": [{"factory_id": k, "name": v} for k, v in EFFECTS.items()],
            "input": INPUT, "backend": "external C++ renderer source with WLED compatibility boundary"}


def settings(values=None):
    values = {} if values is None else values
    require(isinstance(values, dict) and set(values) <= set(DEFAULTS), "unknown GLORB setting")
    result = copy.deepcopy(DEFAULTS)
    result.update(values)
    effect = result["effect"]
    if type(effect) is int:
        require(effect in EFFECTS, "unknown GLORB factory effect id")
        effect = EFFECTS[effect]
    require(isinstance(effect, str) and effect in NAMES, "unknown GLORB effect")
    result["effect"] = effect
    for key in ("speed", "intensity", "custom1", "custom2", "palette_id"):
        integer(result[key], key, 0, 255)
    require(result["palette_id"] != 0, "palette zero requires an explicit color-gamma/video-scale model")
    integer(result["custom3"], "custom3", 0, 31)
    integer(result["palette_blend"], "palette_blend", 0, 3)
    require(type(result["sound_reactive"]) is bool, "sound_reactive must be boolean")
    colors = result["colors"]
    require(isinstance(colors, list) and len(colors) == 3, "three RGB colors required")
    for color in colors:
        require(isinstance(color, list) and len(color) == 3, "colors must be RGB triples")
        for value in color:
            integer(value, "RGB channel", 0, 255)
    return result


def expand_gradient(stops):
    """FastLED 16-slot gradient placement and signed fixed-point interpolation."""
    require(isinstance(stops, list) and 2 <= len(stops) <= 256, "need 2..256 gradient stops")
    previous = -1
    for stop in stops:
        require(isinstance(stop, list) and len(stop) == 4, "gradient stops are index,R,G,B")
        for value in stop:
            integer(value, "gradient byte", 0, 255)
        require(stop[0] > previous, "gradient indexes must increase")
        previous = stop[0]
    require(stops[0][0] == 0 and stops[-1][0] == 255, "gradient must span 0..255")
    palette = [[0, 0, 0] for _ in range(16)]
    used = -1
    for first, last in zip(stops, stops[1:]):
        begin, end = first[0] // 16, last[0] // 16
        if len(stops) < 16:
            if begin <= used < 15:
                begin = used + 1
                end = max(end, begin)
            used = end
        distance = max(1, end - begin)
        delta = [math.trunc((last[c + 1] - first[c + 1]) * 128 / distance) * 2 for c in range(3)]
        for slot in range(begin, end + 1):
            palette[slot] = [((first[c + 1] * 256 + (slot - begin) * delta[c]) & 0xffff) >> 8 for c in range(3)]
    return palette


def palette_rgb16(value):
    require(isinstance(value, list) and len(value) == 16, "palette must contain 16 RGB entries")
    for color in value:
        require(isinstance(color, list) and len(color) == 3, "palette entry must be RGB")
        for component in color:
            integer(component, "palette channel", 0, 255)
    return value


def build_host(source, output, *, compiler=None, sanitize=False):
    source = Path(source).expanduser().resolve()
    require(source.is_file(), "renderer source is missing")
    require(not any(c in str(source) for c in '\"\\\n\r'), "unsupported renderer source path")
    directory = private_path(output)
    require(not directory.exists(), "host build directory already exists")
    executable = shutil.which(compiler or "c++")
    require(executable is not None, "C++ compiler missing; use the Nix development shell")
    require(type(sanitize) is bool, "sanitize must be boolean")
    native = Path(__file__).resolve().parents[1] / "native"
    inputs = [source, *(native / name for name in ("glorb_host.cpp", "wled.h", "sha256.h"))]
    checksums = {str(path): file_digest(path) for path in inputs}
    directory.mkdir(parents=True, mode=0o700)
    binary = directory / "TycGlorbHost"
    command = [executable, "-std=c++17", "-O2", "-fwrapv", "-fno-fast-math", "-ffp-contract=off",
               "-Wall", "-Wextra", "-I", str(native),
               '-DTYCVL_EFFECT_SOURCE="' + str(source) + '"', str(native / "glorb_host.cpp"), "-o", str(binary)]
    if sanitize:
        command[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    run_process(command, directory, directory / "compiler.stdout.log", directory / "compiler.stderr.log", 120)
    sanitizer_environment = {"ASAN_OPTIONS":"detect_leaks=0"} if sanitize else {}
    run_process([str(binary), "--abi"], directory, directory / "abi.json", directory / "abi.stderr.log", 10,
                {**os.environ, **sanitizer_environment})
    abi = load_json(directory / "abi.json")
    require(isinstance(abi, dict) and abi.get("schema") == "tycvl.native-abi.v1"
            and abi.get("int_bits") == 32 and abi.get("char_bits") == 8, "unsupported native integer ABI")
    require(checksums == {str(path): file_digest(path) for path in inputs}, "source changed during host build")
    report = {"schema": "tycvl.native-build.v1", "executable": str(binary), "sha256": file_digest(binary),
              "compiler": str(Path(executable).resolve()), "compiler_sha256": file_digest(executable),
              "host_abi": abi, "sanitizers": ["address", "undefined"] if sanitize else [],
              "runtime_environment": sanitizer_environment,
              "sources": checksums, "flags": command[1:-3],
              "scope": "Compiles the supplied renderer; does not certify equivalence to a vendor binary"}
    write_json(directory / "build.json", report)
    return report


def _asset(role, path):
    path = Path(path).expanduser().resolve()
    require(path.is_file(), f"missing GLORB asset: {role}")
    return {"role": role, "path": str(path), "sha256": file_digest(path)}


def build_profile(source, executable, ledmap, palette, *, values=None, width=20, height=6,
                  physical_pixels=None, extra_assets=(), driver=None):
    width = integer(width, "width", 1, 256)
    height = integer(height, "height", 1, 256)
    mapping = load_json(ledmap).get("map") if isinstance(ledmap, (str, Path)) else ledmap
    require(isinstance(mapping, list) and len(mapping) == width * height, "GLORB ledmap dimensions differ")
    require(all(type(n) is int and -1 <= n < 65536 for n in mapping), "invalid ledmap index")
    present = [n for n in mapping if n >= 0]
    present_set = set(present)
    require(present and len(present_set) == len(present), "GLORB ledmap must have unique mapped pixels")
    count = max(present) + 1 if physical_pixels is None else integer(physical_pixels, "physical pixels", 1, 65536)
    require(max(present) < count, "ledmap references missing physical pixel")
    config = settings(values)
    colors = palette_rgb16(palette)
    assets = [_asset("renderer-source", source), _asset("host-renderer", executable)]
    build = Path(executable).parent / "build.json"
    require(build.is_file(), "GLORB host build provenance is missing")
    report = load_json(build)
    require(report.get("schema") == "tycvl.native-build.v1" and report.get("sha256") == file_digest(executable)
            and report.get("sources", {}).get(str(Path(source).expanduser().resolve())) == file_digest(source),
            "GLORB executable was not built from the supplied renderer")
    assets.append(_asset("host-build", build))
    if isinstance(ledmap, (str, Path)):
        assets.append(_asset("ledmap", ledmap))
    assets.extend(_asset(role, path) for role, path in extra_assets)
    command = ["tycvl-glorb-host", "{request}", "{capture}"]
    if shutil.which(command[0]) is None:
        command = [sys.executable, "-m", "vfl.glorb_host", "{request}", "{capture}"]
    backend = {"kind": "external", "execution_kind": "recovered-code", "command": command,
               "timeout_s": 300, "options": {"glorb": {"width": width, "height": height,
                    "physical_pixels": count, "map": mapping, "palette_rgb16": colors}}}
    if command[1:3] == ["-m", "vfl.glorb_host"]:
        backend["env"] = {"PYTHONPATH": str(Path(__file__).resolve().parents[2])}
    if report.get("sanitizers") == ["address", "undefined"]:
        backend.setdefault("env", {})["ASAN_OPTIONS"] = "detect_leaks=0"
    points = [{"bus": "logical", "index": y * width + x, "x": x, "y": -y, "z": 0}
              for y in range(height) for x in range(width)]
    profile = {"schema": "vfl.profile.v1", "id": "glorb-source-v1", "description": "GLORB supplied renderer on host",
               "target": {"chip": "esp32-s3", "isa": "xtensa-lx7", "abi": "xtensa-windowed"},
               "input": dict(INPUT), "settings": config, "firmware": assets, "backend": backend,
               "buses": [{"id": "logical", "pixels": width * height, "order": "RGB", "stage": "logical"},
                         {"id": "mapped", "pixels": count, "order": "RGB", "stage": "logical"}],
               "geometry": {"kind": "points", "points": points,
                            "mask": {"logical": [n >= 0 for n in mapping], "mapped": [i in present_set for i in range(count)]}}}
    if driver is not None:
        from ..output import glorb_driver
        glorb_driver(bytes(count * 3), driver)
        backend["options"]["glorb"]["driver"] = driver
        profile["buses"].append({"id": "driver", "pixels": count, "order": "RGB", "stage": "driver"})
        profile["geometry"]["mask"]["driver"] = [i in present_set for i in range(count)]
    return validate_profile(profile)


def prepare_repository(source_root, build_dir, *, preset=2, compiler=None, executable=None,
                       driver_model="wled14", driver_brightness=255):
    try:
        return _prepare_repository(source_root, build_dir, preset=preset, compiler=compiler, executable=executable,
                                   driver_model=driver_model, driver_brightness=driver_brightness)
    except (KeyError, IndexError, TypeError) as error:
        raise LabError("malformed GLORB factory metadata: " + str(error)) from error


def _prepare_repository(source_root, build_dir, *, preset=2, compiler=None, executable=None,
                       driver_model="wled14", driver_brightness=255):
    root = Path(source_root).expanduser().resolve()
    source = root / "glorb/usermod/glorb_fx/glorb_fx.cpp"
    factory = root / "glorb/factory-0.14.4-GLORB.1.3"
    presets = load_json(factory / "presets.json")
    selected = presets.get(str(preset))
    require(isinstance(selected, dict), "factory preset is absent")
    active = [s for s in selected.get("seg", []) if s.get("stop", 0)]
    require(len(active) == 1, "host boundary requires one active segment")
    segment = active[0]
    for key, expected in {"start": 0, "startY": 0, "grp": 1, "spc": 0, "of": 0, "m12": 0,
                          "rev": False, "mi": False, "rY": False, "mY": False, "tp": False,
                          "frz": False, "on": True, "bri": 255}.items():
        require(segment.get(key, expected) == expected, f"preset {key} requires unsupported segment transformation")
    palette_id = segment["pal"]
    palx = load_json(factory / "palx.json")
    config = load_json(factory / "cfg.json")
    require(selected.get("bri", config["def"]["bri"]) == 255 and config["def"]["bri"] == 255
            and config.get("light", {}).get("scale-bri", 100) == 100,
            "factory host requires preset/default brightness 255 and brightness scale 100")
    buses = config["hw"]["led"]["ins"]
    require(len(buses) == 1 and buses[0].get("start", 0) == 0, "factory host supports a single bus starting at zero")
    require(str(palette_id) in palx["palettes"], "factory palette is absent")
    colors = segment.get("col", DEFAULTS["colors"])
    require(all(len(c) in (3, 4) and (len(c) == 3 or c[3] == 0) for c in colors), "RGBW preset unsupported")
    values = {"effect": segment["fx"], "speed": segment.get("sx", 128), "intensity": segment.get("ix", 128),
              "custom1": segment.get("c1", 128), "custom2": segment.get("c2", 128), "custom3": segment.get("c3", 16),
              "sound_reactive": segment.get("o1", False), "palette_id": palette_id,
              "palette_blend": config.get("light", {}).get("pal-mode", 0),
              "colors": [color[:3] for color in colors]}
    require(driver_model in ("wled14", "wled16"), "unknown RGB driver model")
    integer(driver_brightness, "driver brightness", 0, 255)
    led = config["hw"]["led"]
    driver = {"brightness": driver_brightness, "limit_ma": led["maxpwr"]}
    if driver_model == "wled16":
        bus = buses[0]
        require(bus.get("type", 22) == 22 and not bus.get("rev") and not bus.get("skip"),
                "WLED 16 model requires a forward WS2812 RGB bus without skipped pixels")
        require(led["maxpwr"] or not bus.get("maxpwr"), "per-bus WLED 16 limiting is unsupported")
        driver.update(model=driver_model, led_ma=bus.get("ledma", 55))
    else:
        driver["led_ma"] = led["ledma"]
    if executable is None:
        executable = build_host(source, build_dir, compiler=compiler)["executable"]
    return build_profile(source, executable, factory / "ledmap.json",
                         expand_gradient(palx["palettes"][str(palette_id)]), values=values,
                         width=segment["stop"], height=segment["stopY"],
                         physical_pixels=buses[0]["len"],
                         driver=driver,
                         extra_assets=(("factory-presets", factory / "presets.json"), ("factory-palettes", factory / "palx.json"),
                                       ("factory-config", factory / "cfg.json")))
