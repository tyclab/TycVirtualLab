"""Generic, explicit Xtensa routine execution through Ghidra's p-code emulator.

All target addresses, images, hooks and calls are supplied by external profiles.
This is an isolated routine boundary, with explicit call0 or logical windowed ABI.
Invoke as an external backend: ``python -m vfl.ghidra REQUEST CAPTURE``.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import struct

from . import device_inputs
from .hsemu import capture_from_output
from .firmware import inspect_image
from .model import (LabError, compatible_input, digest, experiment_digest, file_digest,
                    identifier, integer, load_json, private_path, require, validate_capture,
                    validate_profile, validate_trace, write_json)
from .runner import run_process

U32 = 0xffffffff
MAX_MEMORY = 32 * 1024 * 1024
MAX_TRANSFER = 16 * 1024 * 1024
MAX_COMMANDS = 64 * 1024 * 1024
REG = re.compile(r"(?:a(?:[0-9]|1[0-5])|PS|SAR)")


def _u32(value, name):
    return integer(value, name, 0, U32)


def _region(address, size):
    address = _u32(address, "region.address")
    size = integer(size, "region.size", 1, MAX_MEMORY)
    require(address + size <= U32 + 1, "region crosses the 32-bit address space")
    return address, size


def _keys(item, required, optional=()):
    require(isinstance(item, dict) and set(required) <= set(item)
            and set(item) <= set(required) | set(optional), "invalid or unknown configuration fields")


def _argument(value, frame=None):
    if isinstance(value, dict):
        require(frame is not None, "dynamic arguments are only valid in frame calls")
        if set(value) == {"input"}:
            index = integer(value["input"], "argument input index", 0, len(frame["values"]) - 1)
            value = frame["values"][index]
        elif set(value) == {"time_ms"} and value["time_ms"] is True:
            value = frame["time_us"] // 1000
        else:
            raise LabError("unknown dynamic call argument")
    return str(_u32(value, "call argument"))


def _operation(operation, frame=None):
    require(isinstance(operation, dict), "initialization operation must be an object")
    kind = operation.get("op")
    if kind == "call":
        _keys(operation, {"op", "address"}, {"arguments"})
        args = operation.get("arguments", [])
        require(isinstance(args, list) and len(args) <= 6, "call accepts at most six arguments")
        return "callq " + str(_u32(operation["address"], "call address")) + "".join(
            " " + _argument(value, frame) for value in args)
    if kind == "write":
        _keys(operation, {"op", "address", "hex"})
        raw = operation["hex"]
        require(isinstance(raw, str) and re.fullmatch(r"(?:[0-9a-fA-F]{2})+", raw), "write requires hexadecimal bytes")
        address, _ = _region(operation["address"], len(raw) // 2)
        require(len(raw) // 2 <= MAX_TRANSFER, "single initialization write exceeds transfer limit")
        return f"wbytes {address} {raw.lower()}"
    if kind == "register":
        _keys(operation, {"op", "name", "value"})
        require(isinstance(operation["name"], str) and REG.fullmatch(operation["name"]), "unsupported register")
        if operation["name"] == "SAR":
            integer(operation["value"], "SAR value", 0, 63)
        return f"reg {operation['name']} {_u32(operation['value'], 'register value')}"
    raise LabError("unsupported initialization operation")


def _asset_paths(profile):
    result = {}
    for entry in profile.get("firmware", []):
        require(entry["role"] not in result, "duplicate asset role")
        path = Path(entry["path"]).expanduser()
        require(path.is_absolute() and path.is_file() and not path.is_symlink(), "assets must be resolved regular files")
        actual = file_digest(path)
        require(not entry.get("sha256") or entry["sha256"] == actual, "asset hash mismatch")
        result[entry["role"]] = {"path": path, "sha256": actual, "format": entry.get("format")}
    return result


def compile_commands(profile, trace, assets):
    """Validate external configuration and compile a deterministic command schedule.

    No target instructions run here. The result depends only on configuration,
    the trace and explicitly declared binary mappings, never expected outputs.
    """
    options = profile["backend"].get("options", {})
    config = options.get("ghidra")
    _keys(config, {"elf_role", "abi", "memory_regions", "hooks", "initialization", "frame_calls", "outputs"},
          {"binary_mappings", "state", "state_encoding", "instruction_limit", "output_limit",
           "max_frames", "headless", "launcher_role", "launcher_environment", "timeout_s",
           "allow_uninitialized", "hold_files", "adc_policy", "settings_acknowledgements", "allow_unused_input",
           "frame_operations", "input_writes", "input_read_policy", "observations", "adc_scan", "post_launcher_hold_check", "heap"})
    if "input_read_policy" in config:
        require(isinstance(config["input_read_policy"], str) and config["input_read_policy"] in device_inputs.POLICIES, "unknown device input read policy")
    for key in ("allow_uninitialized", "allow_unused_input", "post_launcher_hold_check"):
        require(type(config.get(key, False)) is bool, f"{key} must be boolean")
    require(not config.get("post_launcher_hold_check") or config.get("launcher_role"),
            "post_launcher_hold_check requires a resource-wrapper launcher")
    device_limits = profile.get("metadata", {}).get("limitations", [])
    require(isinstance(device_limits, list) and len(device_limits) <= 256
            and all(isinstance(value, str) and len(value) <= 4096 for value in device_limits),
            "device limitations must be a bounded list of strings")
    holds = config.get("hold_files", [])
    require(isinstance(holds, list) and len(holds) <= 128
            and all(isinstance(path, str) and path and "\0" not in path and Path(path).is_absolute() for path in holds),
            "hold_files must be a list of absolute path strings")
    settings = profile.get("settings", {})
    acknowledged = config.get("settings_acknowledgements", {})
    require(isinstance(acknowledged, dict) and digest(acknowledged) == digest(settings),
            "every setting key and value requires explicit settings_acknowledgements")
    abi = config["abi"]
    _keys(abi, {"kind", "stack_pointer", "return_sentinel"}, {"registers"})
    require(abi["kind"] in {"xtensa-call0", "xtensa-windowed"}, "unsupported Xtensa ABI")
    target_abi = profile.get("target", {}).get("abi", "unspecified")
    require(target_abi == abi["kind"], "declare matching target ABI for this execution boundary")
    expected_regs = {"pc": "pc", "sp": "a1", "return_address": "a0",
                     "arguments": ["a2", "a3", "a4", "a5", "a6", "a7"], "result": "a2"}
    require(abi.get("registers", expected_regs) == expected_regs, "unsupported Xtensa register layout")
    stack = _u32(abi["stack_pointer"], "stack pointer")
    sentinel = _u32(abi["return_sentinel"], "return sentinel")
    require(stack % 16 == 0, "stack pointer must be aligned to 16 bytes")
    require(config["elf_role"] in assets, "ELF asset role is absent")
    require(assets[config["elf_role"]].get("format") == "elf", "the program asset must explicitly declare format elf")
    image = inspect_image(assets[config["elf_role"]]["path"], format="elf")
    require(image["sha256"] == assets[config["elf_role"]]["sha256"], "ELF asset changed during preflight")
    require(image["machine_id"] == 94 and image["elf_class"] == 32 and image["byte_order"] == "little",
            "Ghidra backend requires a 32-bit little-endian Xtensa ELF")
    require(trace["clock_policy"] == "frame", "this backend requires a frozen clock per frame")
    require(trace["input"]["kind"] in {"bands", "scalar"}, "this backend accepts integer scalar/band inputs")
    limit = integer(config.get("instruction_limit", 500000), "instruction limit", 1, 10000000)
    output_limit = integer(config.get("output_limit", 64 * 1024 * 1024), "output limit", 1024, 512 * 1024 * 1024)
    max_frames = integer(config.get("max_frames", 1000), "max_frames", 1, 5000)
    require(1 <= len(trace["frames"]) <= max_frames, "frame count exceeds backend limit")
    state_encoding = config.get("state_encoding", "bytes")
    require(state_encoding in {"bytes", "sha256"}, "unknown state encoding")
    regions = config["memory_regions"]
    require(isinstance(regions, list) and len(regions) <= 128, "invalid memory region list")
    lines = [f"limit {limit}", f"output_limit {output_limit}",
             f"{'abi_windowed' if abi['kind'] == 'xtensa-windowed' else 'abi'} pc a1 a0 a2,a3,a4,a5,a6,a7 a2 {stack} {sentinel}"]
    total_memory, spans = 0, []
    for item in regions:
        _keys(item, {"address", "size"}, {"allow_elf_overlap"})
        require(type(item.get("allow_elf_overlap", False)) is bool, "allow_elf_overlap must be boolean")
        address, size = _region(item["address"], item["size"])
        require(all(address + size <= lo or address >= hi for lo, hi in spans), "zero regions overlap")
        spans.append((address, address + size))
        total_memory += size
        if item.get("allow_elf_overlap", False):
            # An acknowledged overwrite becomes an explicit byte-write recipe.
            # Ordinary zero commands are guarded against ELF overlap by Java.
            for start in range(0, size, 1024):
                lines.append(f"wbytes {address + start} {'00' * min(1024, size - start)}")
        else:
            for start in range(0, size, MAX_TRANSFER):
                lines.append(f"zero {address + start} {min(MAX_TRANSFER, size - start)}")
    require(any(lo <= stack - 1 < hi for lo, hi in spans), "stack must have an explicitly initialized memory region")
    mapped_spans = []
    mappings = config.get("binary_mappings", [])
    require(isinstance(mappings, list) and len(mappings) <= 128, "invalid binary mappings")
    for item in mappings:
        _keys(item, {"role", "address"}, {"offset", "length"})
        require(item["role"] in assets, "mapping asset role is absent")
        path = assets[item["role"]]["path"]
        offset = integer(item.get("offset", 0), "mapping offset", 0, path.stat().st_size)
        size = item.get("length", path.stat().st_size - offset)
        address, size = _region(item["address"], size)
        require(offset + size <= path.stat().st_size, "mapping exceeds asset length")
        mapped_spans.append((address,address+size))
        total_memory += size
        require(total_memory <= MAX_MEMORY, "memory initialization limit exceeded")
        with path.open("rb") as source:
            source.seek(offset)
            for start in range(0, size, 1024):
                raw = source.read(min(1024, size - start))
                lines.append(f"wbytes {address + start} {raw.hex()}")
    require(total_memory <= MAX_MEMORY, "memory initialization limit exceeded")
    heap = config.get("heap")
    if heap is not None:
        _keys(heap, {"address", "size"})
        address,size = _region(heap["address"], heap["size"])
        require(address != 0 and address % 16 == 0 and size % 16 == 0 and size <= 1024*1024, "heap must be nonzero, 16-byte aligned and at most1MiB")
        imported = [(section["address"],section["address"]+section["size"]) for section in image["sections"] if section["flags"]&2]
        imported += [(segment["virtual_address"],segment["virtual_address"]+segment["memory_size"]) for segment in image["segments"] if segment["type"]==1]
        require(all(address+size <= lo or address >= hi for lo,hi in spans+mapped_spans+imported), "heap overlaps initialized, imported or mapped memory")
        lines.append(f"heap {address} {size}")
    hooks = config["hooks"]
    require(isinstance(hooks, list) and len(hooks) <= 256, "invalid hook list")
    used_hooks = set()
    for hook in hooks:
        require(isinstance(hook, dict), "hook must be an object")
        kind = hook.get("kind")
        extras = {"value"} if kind == "return" else {"target", "width", "value"} if kind == "write" else set()
        _keys(hook, {"address", "kind"} | extras, {"windowed_tail"} | ({"mode"} if kind == "rng" else set()))
        tail = hook.get("windowed_tail", "reject")
        require(tail in {"reject", "entered"}, "windowed_tail must be reject or entered")
        require(tail == "reject" or abi["kind"] == "xtensa-windowed", "windowed tail policy requires windowed ABI")
        require(kind in {"millis", "micros", "adc", "rng", "noop", "return", "write", "guard_acquire", "guard_release", "f32_div", "gpio", "malloc", "free", "calloc", "realloc"}, "unsupported hook")
        require(kind not in {"malloc","free","calloc","realloc"} or heap is not None, "allocator hooks require an explicit heap")
        address = _u32(hook["address"], "hook address")
        require(address not in used_hooks and address != sentinel, "duplicate hook or sentinel collision")
        used_hooks.add(address)
        suffix = ""
        if kind == "return":
            suffix = f" {_u32(hook['value'], 'hook return value')}"
        elif kind == "rng":
            require(hook.get("mode", "raw") in {"raw", "bounded"}, "RNG mode must be raw or bounded")
            suffix = " bounded" if hook.get("mode") == "bounded" else ""
        elif kind == "write":
            require(hook["width"] in {1, 2, 4} and type(hook["width"]) is int, "invalid hook write width")
            target, _ = _region(hook["target"], hook["width"])
            value = integer(hook["value"], "hook write value", 0, (1 << (8 * hook["width"])) - 1)
            suffix = f" {target} {hook['width']} {value}"
        lines.append(f"hook {address} {kind}{suffix}")
        if tail == "entered":
            lines.append(f"hook_tail {address} entered")
    observations = config.get("observations", [])
    require(isinstance(observations, list) and len(observations) <= 256, "invalid instruction observers")
    observer_ids, observer_addresses = set(), set()
    for observer in observations:
        _keys(observer, {"address", "id"})
        identifier(observer["id"], "observer id")
        address = _u32(observer["address"], "observer address")
        require(observer["id"] not in observer_ids and address not in observer_addresses
                and address not in used_hooks and address != sentinel, "duplicate or conflicting instruction observer")
        observer_ids.add(observer["id"]); observer_addresses.add(address)
        lines.append(f"observe {address} {observer['id']}")
    scan = config.get("adc_scan")
    if scan is not None:
        _keys(scan, {"reset_pin", "strobe_pin", "channels", "advance_edge"})
        reset = integer(scan["reset_pin"], "ADC reset pin", 0, 255)
        strobe = integer(scan["strobe_pin"], "ADC strobe pin", 0, 255)
        channels = integer(scan["channels"], "ADC scan channels", 1, 4096)
        require(reset != strobe and scan["advance_edge"] in {"falling", "rising"}, "invalid ADC scan pins or edge")
        require(trace["input"]["channels"] == channels and any(h["kind"] == "gpio" for h in hooks)
                and any(h["kind"] == "adc" for h in hooks), "ADC scan requires matching inputs and ADC/GPIO hooks")
        lines.append(f"adc_scan {reset} {strobe} {channels} {scan['advance_edge']}")
    else:
        require(not any(h["kind"] == "gpio" for h in hooks), "GPIO scan hook requires adc_scan configuration")
    seed = _u32(trace["seed"], "xorshift32 seed")
    adc_policy = config.get("adc_policy", "strict")
    require(adc_policy in {"strict", "cycle"}, "ADC policy must be strict or cycle")
    lines.extend([f"adc_policy {adc_policy}", f"seed {seed}", "frame -1 0", "time 0"])
    initialization = config["initialization"]
    require(isinstance(initialization, list) and len(initialization) <= 4096, "invalid initialization list")
    lines.extend(_operation(operation) for operation in initialization)
    calls = config["frame_calls"]
    require(isinstance(calls, list) and 1 <= len(calls) <= 64, "need one to 64 frame calls")
    require(all(isinstance(call, dict) and call.get("op") == "call" for call in calls), "frame_calls must contain calls")
    output_tags, state_tags, dump_lines = {}, {}, []
    for category, entries, mapping in (("output", config["outputs"], output_tags), ("state", config.get("state", []), state_tags)):
        require(isinstance(entries, list) and len(entries) <= 128, "invalid capture regions")
        for n, item in enumerate(entries):
            _keys(item, {"id", "address", "size"})
            identifier(item["id"], "capture region id")
            require(item["id"] not in mapping.values(), "duplicate region id")
            address, size = _region(item["address"], item["size"])
            require(size <= MAX_TRANSFER, "capture region exceeds transfer limit")
            if category == "state":
                require(size <= 8 * 1024 * 1024, "state region exceeds normalized snapshot limit")
            tag = f"{category}{n}"
            mapping[tag] = item["id"]
            dump_lines.append(f"dump {tag} {address} {size}")
    require(set(output_tags.values()) == {bus["id"] for bus in profile["buses"]}, "output regions must cover every bus exactly")
    for item in config["outputs"]:
        bus = next(bus for bus in profile["buses"] if bus["id"] == item["id"])
        require(item["size"] == bus["pixels"] * len(bus["order"]), "output region size disagrees with bus")
    minimum_output = len(trace["frames"]) * sum(2 * item["size"] + 16 for item in config["outputs"] + config.get("state", []))
    require(minimum_output <= output_limit, "requested snapshots exceed the protocol output limit")
    input_writes = config.get("input_writes", [])
    require(isinstance(input_writes, list) and len(input_writes) <= 256, "invalid input write bindings")
    float_channels = set()
    for item in input_writes:
        _keys(item, {"channel", "address", "width"}, {"encoding"})
        integer(item["channel"], "input write channel", 0, trace["input"]["channels"] - 1)
        require(type(item["width"]) is int and item["width"] in {1, 2, 4}, "input write width must be 1, 2 or 4")
        _region(item["address"], item["width"])
        encoding = item.get("encoding", "uint-le")
        require(encoding in {"uint-le", "float32-le"}, "unknown input write encoding")
        if encoding == "float32-le":
            require(item["width"] == 4 and not any(hook["kind"] == "adc" for hook in hooks), "float32 input writes require width4 and no ADC hooks")
            float_channels.add(item["channel"])
    recipes = config.get("frame_operations", [])
    require(isinstance(recipes, list) and len(recipes) <= len(trace["frames"]), "invalid frame operation recipes")
    by_frame = {}
    for recipe in recipes:
        _keys(recipe, {"index", "controls", "operations"})
        index = integer(recipe["index"], "frame operation index", 0, len(trace["frames"]) - 1)
        require(index not in by_frame, "duplicate frame operation recipe")
        controls = recipe["controls"]
        require(isinstance(controls, dict) and controls
                and digest(controls) == digest(trace["frames"][index].get("controls", {})),
                "frame operation recipe must acknowledge exact nonempty frame controls")
        operations = recipe["operations"]
        require(isinstance(operations, list) and len(operations) <= 4096, "invalid frame operations")
        by_frame[index] = operations
    for frame in trace["frames"]:
        t = integer(frame["time_us"], "frame clock", 0, U32 * 1000)
        require(t % 1000 == 0, "backend v1 requires millisecond-aligned frame times")
        require(not frame.get("controls") or frame["index"] in by_frame,
                "per-frame controls require an exact frame operation recipe")
        values = " ".join(str(_float_bits(value) if channel in float_channels else _u32(value, "ADC value")) for channel,value in enumerate(frame["values"]))
        lines.extend([f"frame {frame['index']} {t} {values}", f"time {t // 1000}"])
        for item in input_writes:
            raw_value = frame["values"][item["channel"]]
            value = _float_bits(raw_value) if item.get("encoding") == "float32-le" else integer(raw_value, "input write value", 0, (1 << (8 * item["width"])) - 1)
            lines.append(f"w{item['width'] * 8} {item['address']} {value}")
        lines.extend(_operation(operation, frame) for operation in by_frame.get(frame["index"], []))
        lines.extend(_operation(call, frame) for call in calls)
        lines.extend(dump_lines)
    commands = "\n".join(lines) + "\n"
    require(len(commands.encode()) <= MAX_COMMANDS, "command schedule exceeds size limit")
    return commands, output_tags, state_tags


def _float_bits(value):
    import math
    try:
        require(type(value) in (int,float) and math.isfinite(value), "float32 input must be finite")
        encoded = struct.pack("<f", value)
    except (OverflowError,struct.error) as error:
        raise LabError("input exceeds finite float32 range") from error
    require(math.isfinite(struct.unpack("<f",encoded)[0]), "input exceeds finite float32 range")
    return int.from_bytes(encoded,"little")


def _inner_timeout(profile, config):
    outer = profile["backend"].get("timeout_s", 300)
    timeout = config.get("timeout_s", min(300, 0.9 * outer))
    require(type(timeout) in (int, float) and 0 < timeout < outer and timeout <= 86400,
            "Ghidra timeout must be positive and shorter than the outer backend timeout")
    return timeout


def execute_request(request_path, capture_path):
    request = load_json(request_path)
    require(request.get("schema") == "vfl.request.v1", "unsupported request schema")
    require(isinstance(request.get("request_id"), str) and re.fullmatch(r"[0-9a-f]{32}", request["request_id"]), "fresh request_id is required")
    profile = validate_profile(request["profile"])
    trace = validate_trace(request["trace"])
    compatible_input(profile, trace)
    require(profile["backend"].get("execution_kind") == "original-firmware", "Ghidra backend executes original firmware")
    identities = {"input_sha256": digest(trace), "profile_sha256": digest(profile),
                  "experiment_sha256": experiment_digest(profile, trace)}
    require(request.get("identities") == identities, "request identities differ from supplied profile/trace")
    workdir = private_path(request["workdir"])
    target = private_path(capture_path)
    require(workdir.is_dir() and not target.exists(), "fresh workdir and output required")
    assets = _asset_paths(profile)
    commands, output_tags, state_tags = compile_commands(profile, trace, assets)
    config = profile["backend"]["options"]["ghidra"]
    timeout = _inner_timeout(profile, config)
    for path in config.get("hold_files", []):
        require(not os.path.lexists(path), "emulator HOLD is active")
    executable = config.get("headless") or os.environ.get("GHIDRA_HEADLESS") or shutil.which("ghidra-analyzeHeadless")
    require(isinstance(executable, str) and Path(executable).is_file(), "configure a Ghidra headless executable")
    script = Path(__file__).with_name("ghidra") / "TycEmu.java"
    require(script.is_file(), "packaged Ghidra script missing")
    fingerprints = {"driver": file_digest(__file__), "device_inputs": file_digest(device_inputs.__file__), "script": file_digest(script), "headless": file_digest(executable)}
    command_path, output_path = workdir / "ghidra.commands", workdir / "ghidra.output"
    execution_path = Path(str(output_path) + ".execution.json")
    require(not command_path.exists() and not output_path.exists() and not execution_path.exists(), "stale Ghidra artifacts rejected")
    with command_path.open("x") as dest:
        dest.write(commands)
    project = workdir / "ghidra-project"
    project.mkdir()
    argv = [executable, str(project), "experiment", "-import", str(assets[config["elf_role"]]["path"]),
            "-processor", "Xtensa:LE:32:default", "-noanalysis", "-deleteProject",
            "-scriptPath", str(script.parent), "-postScript", script.name, str(command_path), str(output_path), request["request_id"],
            "allow" if config.get("allow_uninitialized", False) else "strict"]
    if config.get("post_launcher_hold_check"):
        guard = workdir / "ghidra.launch-guard.py"
        require(not guard.exists(), "stale launch guard rejected")
        guard.write_text("import json, os, sys\n"
                         "assert sys.argv[2] == '--'\n"
                         "if any(os.path.lexists(p) for p in json.loads(sys.argv[1])):\n"
                         "    raise SystemExit('emulator HOLD became active while waiting for the shared slot')\n"
                         "os.execvpe(sys.argv[3], sys.argv[3:], os.environ)\n")
        argv = [sys.executable, str(guard), json.dumps(config.get("hold_files", [])), "--", *argv]
    if config.get("launcher_role"):
        require(config["launcher_role"] in assets, "launcher asset is absent")
        argv.insert(0, str(assets[config["launcher_role"]]["path"]))
    env = os.environ.copy()
    extra = config.get("launcher_environment", {})
    require(isinstance(extra, dict) and all(isinstance(k, str) and isinstance(v, str) and "=" not in k and "\0" not in k + v for k, v in extra.items()), "invalid launcher environment")
    env.update(extra)
    isolated = {}
    for name in ("settings", "cache", "temp"):
        directory = workdir / f"ghidra-{name}"
        directory.mkdir()
        isolated[name] = directory
    # JAVA_TOOL_OPTIONS uses its own argument quoting, not a shell. Reject
    # embedded quote characters rather than producing an ambiguous JVM option.
    require(all('"' not in str(path) and "\\" not in str(path) for path in isolated.values()),
            "Ghidra cache paths may not contain quote or backslash characters")
    properties = " ".join(f'-Dapplication.{name}dir="{path}"' for name, path in isolated.items())
    env["JAVA_TOOL_OPTIONS"] = (env.get("JAVA_TOOL_OPTIONS", "") + " " + properties).strip()
    for path in config.get("hold_files", []):
        require(not os.path.lexists(path), "emulator HOLD became active before launch")
    run_process(argv, workdir, workdir / "ghidra.stdout.log", workdir / "ghidra.stderr.log", timeout, env,
                output_limit=64 * 1024 * 1024, termination_grace_s=0.0)
    require(output_path.is_file() and not output_path.is_symlink(), "Ghidra produced no regular output")
    require(output_path.stat().st_size <= config.get("output_limit", 64 * 1024 * 1024), "Ghidra output limit exceeded")
    log = (workdir / "ghidra.stdout.log").read_text() + (workdir / "ghidra.stderr.log").read_text()
    warnings = [line.strip() for line in log.splitlines() if "read from uninitialized state" in line]
    require("SCRIPT ERROR" not in log, "Ghidra script reported an error")
    require(execution_path.is_file() and not execution_path.is_symlink(), "Ghidra execution metadata missing")
    execution = load_json(execution_path, maximum_bytes=1024 * 1024)
    require(execution.get("schema") == "tycvl.ghidra-execution.v1"
            and execution.get("request_id") == request["request_id"]
            and execution.get("commands_sha256") == file_digest(command_path), "execution metadata binding differs")
    policy = "allow" if config.get("allow_uninitialized", False) else "strict"
    require(execution.get("uninitialized_policy") == policy
            and execution.get("read_enforcement") == "execute-read-fault", "uninitialized read enforcement was not active")
    undefined_count = integer(execution.get("uninitialized_reads"), "uninitialized read count")
    require(policy == "allow" or undefined_count == 0, "Ghidra executed an uninitialized read under strict policy")
    limitations = ["Original instructions execute at configured routine boundaries; no full SoC, board boot, interrupts or physical LED wire timing are modeled.",
                   ("Windowed CALL4/8/12 use bounded logical register windows; physical window spills, exceptions, window-register manipulation and mixed call0 routines are unsupported." if config["abi"]["kind"] == "xtensa-windowed" else "Only Xtensa call0 is enabled; windowed calls fail execution."),
                   "Clock is frozen per frame. ADC and RNG hooks return the declared schedule and seeded xorshift32 surrogate; other hooks have only their explicit configured behavior."]
    limitations.append("ADC channel is selected by configured GPIO reset/strobe edges; that channel's declared value is held throughout the frame. Missing reset/strobe or invalid sample phase fails. Analog settling is not modeled."
                       if config.get("adc_scan") else
                       "ADC consumes each frame's input queue once and fails on exhaustion. Unconsumed input values are permitted."
                       if config.get("adc_policy", "strict") == "strict" else
                       "ADC explicitly cycles the held input queue within each frame; repeated reads revisit supplied channel values.")
    if policy == "allow":
        limitations.append("Profile explicitly permits uninitialized reads; results depend on the pinned Ghidra runtime's handling. Direct executor fault counts and regions are recorded.")
    if config.get("settings_acknowledgements"):
        limitations.append("Settings are explicitly acknowledged by the profile's initialization recipe; the generic backend does not automatically apply or prove their device semantics.")
    limitations.extend(profile.get("metadata", {}).get("limitations", []))
    limitations.append("Ghidra12.0.4 is required. Windowed loops repeat only on instruction fallthrough; call0 hardware-loop opcodes fail. Finite MADD.S/MSUB.S use single-round Java Math.fma with default nearest-even FCR; non-finite operands/results and floating-point status reads fail.")
    if any(hook.get("windowed_tail") == "entered" for hook in config["hooks"]):
        limitations.append("Selected hooks explicitly allow entered-window tail returns; the profile asserts their callers executed ENTRY before the tail jump. Unacknowledged tail hooks fail.")
    if any(hook["kind"] == "f32_div" for hook in config["hooks"]):
        limitations.append("The configured f32_div runtime hook substitutes Java finite IEEE-754 single-precision division; this is a declared numeric boundary, not original runtime instructions.")
    if config.get("heap"):
        limitations.append("Allocator hooks implement a bounded deterministic first-fit arena with16-byte alignment, live-allocation read/write and free/realloc guards. This substitutes allocation semantics, not the device SDK heap algorithm; malloc contents are not zero-initialized and reused blocks retain unspecified bytes.")
    if any(item.get("encoding") == "float32-le" for item in config.get("input_writes", [])):
        limitations.append("Explicit float32 input bindings round finite scalar inputs to binary32. Their unused frame tape contains the same bits; ADC hooks are prohibited in this mode.")
    capture = capture_from_output(profile, trace, commands, output_path.read_text(), output_tags,
                                  state_tag_map=state_tags, execution_kind="original-firmware",
                                  backend="ghidra-pcode", limitations=limitations, request_id=request["request_id"])
    engine = capture["manifest"].get("engine", {})
    require(engine.get("name") == "ghidra-pcode" and engine.get("abi") == config["abi"]["kind"]
            and engine.get("version") == "12.0.4"
            and isinstance(engine.get("language"), str) and engine["language"].startswith("Xtensa:"),
            "missing or incompatible emulator engine identity")
    require(len(capture["events"]) == capture["manifest"]["completion"]["stubs"], "boundary log is incomplete")
    hook_kinds = {hook["kind"] for hook in config["hooks"]}
    expected_caps = {"adc_log": "adc" in hook_kinds,
                     "clock_log": bool(hook_kinds & {"millis", "micros"}), "rng_log": "rng" in hook_kinds}
    require(all(capture["manifest"]["capabilities"][key] == value for key, value in expected_caps.items()), "Ghidra instrumentation differs from configured hooks")
    observer_addresses = {item["id"]: item["address"] for item in config.get("observations", [])}
    for event in capture["events"]:
        if event.get("operation") == "observe-entry":
            address = observer_addresses.get(event.get("observer_id"))
            require(event["kind"] == "control" and address is not None
                    and event.get("value") == address and event.get("entrypoint") == hex(address)
                    and event.get("source") == "executed-instruction-observer",
                    "instruction observer differs from configured address")
        if event["kind"] == "adc":
            require(event["frame"] >= 0, "ADC read before a frame input was supplied")
            values = trace["frames"][event["frame"]]["values"]
            channel = integer(event.get("channel"), "observed ADC channel", 0, len(values) - 1)
            require(event["value"] == values[channel], "observed ADC return differs from scheduled input")
        elif event["kind"] == "clock":
            require(event.get("units") in {"ms", "us"}, "clock event has unknown units")
            value = event["time_us"] // 1000 if event["units"] == "ms" else event["time_us"]
            require(event["value"] == value & U32, "observed clock return differs from frame clock")
    read_counts = {kind: sum(event["kind"] == kind for event in capture["events"]) for kind in ("adc", "clock", "rng")}
    frame_adc_reads = sum(event["kind"] == "adc" and event["frame"] >= 0 for event in capture["events"])
    arguments_per_frame = sum(isinstance(arg, dict) and set(arg) == {"input"}
                              for call in config["frame_calls"] for arg in call.get("arguments", []))
    argument_values = arguments_per_frame * len(trace["frames"])
    argument_values += sum(isinstance(arg, dict) and set(arg) == {"input"}
                           for recipe in config.get("frame_operations", [])
                           for operation in recipe["operations"] if operation["op"] == "call"
                           for arg in operation.get("arguments", []))
    device_inputs.record_input_evidence(profile, trace, capture)
    require(device_inputs.policy_for(profile) is not None or config.get("allow_unused_input", False) or frame_adc_reads + argument_values + len(config.get("input_writes", [])) * len(trace["frames"]) > 0,
            "no frame observed ADC input or received an input argument; explicitly allow_unused_input for an input-independent routine")
    if config.get("allow_unused_input", False) and device_inputs.policy_for(profile) is None:
        capture["manifest"]["limitations"].append("Profile explicitly permits execution without delivering trace input to any frame boundary.")
    encoding = config.get("state_encoding", "bytes")
    if encoding == "sha256":
        for frame in capture["frames"]:
            frame["state"] = {tag: hashlib.sha256(bytes.fromhex(raw)).hexdigest() for tag, raw in frame.get("state", {}).items()}
        capture["manifest"]["limitations"].append("State contains SHA256 hashes per region; raw snapshots remain in the private protocol output.")
    capture["manifest"].update({"request_id": request["request_id"], **identities, "state_encoding": encoding,
                               "adapter_provenance": {"implementation_sha256": fingerprints,
                                   "commands_sha256": file_digest(command_path), "output_sha256": file_digest(output_path),
                                   "adc_policy": config.get("adc_policy", "strict"),
                                   "adc_scan": config.get("adc_scan"),
                                   "observations": config.get("observations", []),
                                   "settings_acknowledgements": config.get("settings_acknowledgements", {}),
                                   "read_counts": read_counts, "frame_adc_reads": frame_adc_reads,
                                   "input_argument_values_supplied": argument_values,
                                  "input_memory_values_supplied": len(config.get("input_writes", [])) * len(trace["frames"]),
                                   "argument_observation_scope": "Supplied to completed routine calls; instruction-level use is not tracked.",
                                   "allow_unused_input": config.get("allow_unused_input", False),
                                   "execution_metadata": execution,
                                   "headless_path": str(Path(executable).resolve()),
                                   "runtime_isolation": "fresh per-run settings, compiled-script cache and temporary directories",
                                   "post_launcher_hold_check": config.get("post_launcher_hold_check", False),
                                   "rng_seed_requested": trace["seed"], "rng_initial_state": trace["seed"] or 1,
                                   "uninitialized_read_warning_count": len(warnings),
                                   "unique_uninitialized_read_warnings": sorted(set(warnings))}})
    require(fingerprints == {"driver": file_digest(__file__), "device_inputs": file_digest(device_inputs.__file__), "script": file_digest(script), "headless": file_digest(executable)}, "backend implementation changed during execution")
    require(assets == _asset_paths(profile), "assets changed during execution")
    validate_capture(capture, profile, trace)
    # CREATE_NEW preserves freshness even if the caller races with this process.
    with target.open("x") as dest:
        from .model import canonical
        dest.write(canonical(capture).decode() + "\n")
    return target


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        require(len(args) == 2, "usage: python -m vfl.ghidra REQUEST CAPTURE")
        execute_request(*args)
        return 0
    except (LabError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"tycvl Ghidra: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
