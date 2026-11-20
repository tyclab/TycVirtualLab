"""Run supplied GLORB C++ effects and normalize actual host output."""

import copy
import hashlib
import re
import struct
import sys
from pathlib import Path

from .devices.glorb import INPUT, NAMES, palette_rgb16, settings
from .model import (LabError, canonical, compatible_input, digest, experiment_digest, file_digest, integer,
                    load_json, private_path, require, validate_capture, validate_profile, validate_trace)
from .output import glorb_driver
from .runner import run_process


def compile_commands(profile, trace, nonce):
    require(re.fullmatch(r"[0-9a-f]{32}", nonce) is not None, "invalid request nonce")
    require(profile["input"] == INPUT, "GLORB host expects processed WLED volume input")
    require(trace["clock_policy"] == "frame", "GLORB host requires frame clock")
    options = profile["backend"].get("options", {})
    require(set(options) == {"glorb"}, "unknown GLORB backend options")
    config = options["glorb"]
    required = {"width", "height", "physical_pixels", "map", "palette_rgb16"}
    require(isinstance(config, dict) and required <= set(config) <= required | {"driver"},
            "invalid GLORB host configuration")
    width, height, count = config["width"], config["height"], config["physical_pixels"]
    require(all(type(v) is int and 1 <= v <= 65536 for v in (width, height, count))
            and width <= 256 and height <= 256 and width * height <= 65536, "invalid GLORB dimensions")
    mapping = config["map"]
    require(isinstance(mapping, list) and len(mapping) == width * height
            and all(type(v) is int and -1 <= v < count for v in mapping), "invalid GLORB mapping")
    mapped = [v for v in mapping if v >= 0]
    require(mapped and len(set(mapped)) == len(mapped), "duplicate or empty GLORB mapping")
    expected_buses = [{"id": "logical", "pixels": width * height, "order": "RGB", "stage": "logical"},
                      {"id": "mapped", "pixels": count, "order": "RGB", "stage": "logical"}]
    if "driver" in config:
        expected_buses.append({"id": "driver", "pixels": count, "order": "RGB", "stage": "driver"})
        glorb_driver(bytes(count * 3), config["driver"])
    require(profile["buses"] == expected_buses, "GLORB bus layout differs from renderer")
    palette = palette_rgb16(config["palette_rgb16"])
    values = settings(profile["settings"])
    lines = ["TycGlorb1 " + nonce,
             "layout " + " ".join(map(str, [width, height, count, *mapping])),
             "palette " + " ".join(str(v) for color in palette for v in color)]
    for frame in trace["frames"]:
        controls = dict(frame.get("controls", {}))
        clock_command = ""
        if "effect_time_ms" in controls:
            effect_time = integer(controls.pop("effect_time_ms"), "effect_time_ms", 0, 2**31 - 1)
            clock_command = f" {effect_time}"
        require(set(controls) <= set(values), "unsupported GLORB control")
        require("palette_id" not in controls or controls["palette_id"] == profile["settings"]["palette_id"],
                "palette selection requires its actual table; prepare a profile for that palette")
        values = settings({**values, **controls})
        packed = [(color[0] << 16) | (color[1] << 8) | color[2] for color in values["colors"]]
        args = [NAMES.index(values["effect"]), *(values[k] for k in ("speed", "intensity", "custom1", "custom2", "custom3")),
                int(values["sound_reactive"]), values["palette_blend"], values["palette_id"], *packed]
        lines.append("settings " + " ".join(map(str, args)))
        lines.append(f"frame {frame['index']} {frame['time_us']} {frame['values'][0]:.17g}{clock_command}")
    encoded = "\n".join(lines) + "\n"
    require(len(encoded.encode()) <= 8 * 1024 * 1024, "GLORB command limit exceeded")
    require(len(trace["frames"]) * ((width * height + count) * 6 + 160) < 128 * 1024 * 1024,
            "GLORB capture would exceed the native output limit")
    return encoded


def parse_output(text, profile, trace, nonce, command_hash):
    rows = text.splitlines()
    require(len(rows) == len(trace["frames"]) + 2, "GLORB output frame count differs")
    require(rows[0].split() == ["B", nonce, command_hash], "GLORB execution binding differs")
    require(rows[-1].split() == ["E", str(len(trace["frames"]))], "GLORB completion is absent")
    frames, events = [], []
    driver = profile["backend"]["options"]["glorb"].get("driver")
    for raw, source in zip(rows[1:-1], trace["frames"]):
        words = raw.split()
        require(len(words) == 8 and words[0] == "F", "malformed GLORB frame")
        require(words[1:3] == [str(source["index"]), str(source["time_us"])], "GLORB frame schedule differs")
        bits = struct.unpack("<I", struct.pack("<f", source["values"][0]))[0]
        require(words[3] == str(bits), "GLORB delivered audio input differs")
        require(words[4].isdigit() and 0 <= int(words[4]) <= 1, "invalid GLORB audio read count")
        frames.append({"index": source["index"], "time_us": source["time_us"],
                       "buses": {"logical": words[5], "mapped": words[6]}, "state": {"segment": words[7]}})
        if driver is not None:
            pixels, state = glorb_driver(bytes.fromhex(words[6]), driver)
            frames[-1]["buses"]["driver"] = pixels.hex()
            frames[-1]["state"]["output"] = struct.pack("<BBII", state["brightness"], state["limited_brightness"],
                                                       state["estimated_ma"], state["limit_ma"]).hex()
        require(len(words[7]) == 24, "GLORB segment state is incomplete")
        if int(words[4]):
            events.append({"kind": "stub", "frame": source["index"], "time_us": source["time_us"],
                           "boundary": "processed-audio", "value": struct.unpack("<f", struct.pack("<I", bits))[0],
                           "call_site": "UsermodManager.getUMData"})
        if source.get("controls"):
            events.append({"kind": "control", "frame": source["index"], "time_us": source["time_us"], "values": source["controls"]})
    result = {"schema": "vfl.capture.v1", "manifest": {"profile_id": profile["id"],
              "execution_kind": "recovered-code", "execution_scope": "host-renderer", "backend": "glorb-host-v1", "request_id": nonce,
              "engine": {"name": "native-cpp", "renderer": "externally-supplied-glorb-source", "version": "1"},
              "capabilities": {"adc_log": False, "clock_log": False, "rng_log": False, "state": True},
              "protocol_binding": {"request_id": nonce, "commands_sha256": command_hash},
              "limitations": ["Runs the supplied recovered renderer source with a WLED/FastLED compatibility boundary.",
                              "Logical and mapped RGB preserve renderer history. Optional driver bytes use the profile's RGB current/brightness model. Whole-frame color gamma is outside this adapter.",
                              "Driver brightness is the internal bus value, not a user slider. Each frame writes the complete mapped RGB bus once. Electrical wire timing is not captured.",
                              "Input is processed WLED volumeSmth at the AudioReactive boundary; PDM decimation and AGC require their own input adapter.",
                              "Changing effects resets segment state and pixel history; timed WLED effect crossfades are not part of this host boundary.",
                              "Native host integer widths and the standard math library can differ from ESP32-S3; the pinned host-build report records the actual ABI.",
                              "Color helper arithmetic follows WLED 0.14.4/FastLED fixed-scale semantics; whole-device equivalence requires original-code comparison."]},
              "buses": profile["buses"], "geometry": profile.get("geometry", {"kind": "strips"}),
              "frames": frames, "events": events}
    return validate_capture(result, profile, trace)


def execute_request(request_path, capture_path):
    request = load_json(request_path)
    require(isinstance(request, dict) and request.get("schema") == "vfl.request.v1", "invalid GLORB request")
    profile, trace = validate_profile(request["profile"]), validate_trace(request["trace"])
    compatible_input(profile, trace)
    require(profile["backend"].get("execution_kind") == "recovered-code", "GLORB host requires recovered-code classification")
    identities = {"input_sha256": digest(trace), "profile_sha256": digest(profile), "experiment_sha256": experiment_digest(profile, trace)}
    require(request.get("identities") == identities, "GLORB request identities differ")
    work = private_path(request["workdir"])
    target = private_path(capture_path)
    require(work.is_dir() and not target.exists(), "fresh GLORB output required")
    declared = {entry["role"]: entry for entry in profile["firmware"]}
    require("host-renderer" in declared and "renderer-source" in declared, "GLORB renderer assets missing")
    checksums = {}
    for role, entry in declared.items():
        path = Path(entry["path"])
        require(path.is_absolute() and path.is_file() and not path.is_symlink(), "assets must be resolved files")
        checksums[role] = file_digest(path)
        require(entry.get("sha256") == checksums[role], "GLORB asset hash mismatch")
    commands = compile_commands(profile, trace, request["request_id"])
    command_hash = hashlib.sha256(commands.encode()).hexdigest()
    command_path, output_path = work / "glorb.commands", work / "glorb.output"
    with command_path.open("x") as output:
        output.write(commands)
    run_process([declared["host-renderer"]["path"], str(command_path), str(output_path)], work,
                work / "glorb.stdout.log", work / "glorb.stderr.log", min(120, profile["backend"].get("timeout_s", 300) * .9),
                termination_grace_s=0)
    require(output_path.is_file() and not output_path.is_symlink() and output_path.stat().st_size <= 128 * 1024 * 1024,
            "invalid GLORB native output")
    result = parse_output(output_path.read_text(), profile, trace, request["request_id"], command_hash)
    result["manifest"].update(identities)
    result["manifest"]["adapter_provenance"] = {"driver_sha256": file_digest(__file__), "assets": checksums,
          "processed_audio_reads": sum(e.get("boundary") == "processed-audio" for e in result["events"]),
          "commands_sha256": command_hash, "output_sha256": file_digest(output_path)}
    if "driver" in profile["backend"]["options"]["glorb"]:
        result["manifest"]["adapter_provenance"]["output_model_sha256"] = file_digest(Path(__file__).with_name("output.py"))
    require(checksums == {role: file_digest(entry["path"]) for role, entry in declared.items()}, "GLORB assets changed during execution")
    require(file_digest(command_path) == command_hash, "GLORB command file changed during execution")
    with target.open("x") as output:
        output.write(canonical(result).decode() + "\n")
    return target


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        require(len(args) == 2, "usage: tycvl-glorb-host REQUEST CAPTURE")
        execute_request(*args)
        return 0
    except (LabError, OSError, ValueError) as error:
        print(f"tycvl-glorb-host: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
