"""Full-boot Exoy QEMU capture with an observed clock and explicit hardware hooks."""

import json
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import resource

from . import __version__
from .devices.exoy import ADC_INPUT, APP_SHA256, PACKS
from .model import (LabError, canonical, digest, file_digest, integer, load_json,
                    private_path, require, validate_capture, validate_trace, write_json)
from .runner import _source_fingerprint, inherited_resource_lock_fds, run_process
from .firmware import inspect_image


def add_parser(sub):
    p = sub.add_parser("board", help="boot an Exoy flash copy in QEMU and capture actual driver frames")
    p.add_argument("device", choices=["exoy-one"])
    for name in ("qemu", "gdb", "flash", "firmware", "out"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--library-path", default="", help="shared-library search path from the pinned board Nix shell")
    p.add_argument("--input", help="64-value ADC trace; packets are applied in scene-dispatch order")
    p.add_argument("--frames", type=int, default=16)
    p.add_argument("--mic", type=int, default=1850)
    p.add_argument("--seed", type=int, help="QEMU seed; otherwise use input-trace seed, or 1")
    p.add_argument("--pack", type=int)
    p.add_argument("--effect", type=int)
    p.add_argument("--cpu-hz", type=int, default=240000000, help="declared CCOUNT-to-display-time conversion")
    p.add_argument("--timeout-s", type=int, default=900)
    p.add_argument("--limiter")
    p.add_argument("--hold-file", action="append", default=[])


def _asset(role, path):
    path = Path(path).expanduser().resolve(strict=True)
    require(path.is_file(), f"missing board asset {role}")
    return {"role": role, "path": str(path), "sha256": file_digest(path)}


def _check_assets(request):
    for asset in request["assets"]:
        require(file_digest(asset["path"]) == asset["sha256"], "board asset changed: " + asset["role"])


def prepare(args):
    integer(args.frames, "frames", 1, 500)
    integer(args.mic, "mic", 0, 4095)
    if args.seed is not None:
        integer(args.seed, "seed", 0, 2**32-1)
    integer(args.cpu_hz, "cpu_hz", 1, 1000000000)
    integer(args.timeout_s, "timeout_s", 30, 86400)
    if args.pack is not None or args.effect is not None:
        integer(args.pack, "pack", 0, len(PACKS)-1)
        integer(args.effect, "effect", 0, len(PACKS[args.pack][1])-1)
    assets = [_asset(k, getattr(args, k)) for k in ("qemu", "gdb", "flash", "firmware")]
    paths = {a["role"]: Path(a["path"]) for a in assets}
    require(file_digest(paths["firmware"]) == APP_SHA256, "unsupported Exoy application revision")
    image = inspect_image(paths["firmware"], format="esp32")
    data = paths["firmware"].read_bytes()
    require(image["sha256"] == hashlib.sha256(data).hexdigest() == APP_SHA256,
            "application changed during board preparation")
    loaded_checks = []
    for segment in image["segments"]:
        address, length = segment["load_address"], segment["file_size"]
        if ((0x3f400000 <= address < address+length <= 0x3f800000)
                or (0x40080000 <= address < address+length <= 0x40400000)):
            start = segment["file_offset"]
            loaded_checks.append({"address":address,"length":length,
                                  "sha256":hashlib.sha256(data[start:start+length]).hexdigest()})
    require(loaded_checks, "application has no verifiable loaded code/constants")
    require(paths["flash"].stat().st_size == 8*1024*1024, "board runner requires an 8 MiB raw flash image")
    with paths["flash"].open("rb") as source:
        source.seek(0x10000)
        require(source.read(paths["firmware"].stat().st_size) == paths["firmware"].read_bytes(), "flash application differs from supplied firmware")
    for name in ("esp32-v3-rom.bin", "esp32-v3-rom-app.bin"):
        assets.append(_asset(name, paths["qemu"].parents[1] / "share/qemu" / name))
    if args.limiter:
        assets.append(_asset("limiter", args.limiter))
    libraries = []
    for value in filter(None, args.library_path.split(os.pathsep)):
        directory = Path(value).expanduser().resolve(strict=True)
        require(directory.is_dir(), "library search entry must be a directory")
        libraries.append(str(directory))
        for path in sorted(directory.glob("*.so*")):
            if path.is_file():
                resolved = str(path.resolve())
                if resolved not in {a["path"] for a in assets}:
                    assets.append(_asset("library-" + str(len(assets)), path))
    if args.input:
        trace = validate_trace(load_json(args.input))
        require(trace["input"] == ADC_INPUT, "board microphone input requires 64 chronological ESP32 ADC counts")
        require(all(not f.get("controls") for f in trace["frames"]), "board trace controls are unsupported; use pack/effect options")
        packets = [f["values"] for f in trace["frames"]]
        require(len(packets) <= 500, "board input exceeds 500 frames")
        provenance = {"source_trace_sha256": digest(trace), "source_timestamps_us": [f["time_us"] for f in trace["frames"]]}
    else:
        packets = [[args.mic] * 64 for _ in range(args.frames)]
        provenance = {"kind": "constant-adc", "value": args.mic}
    for packet in packets:
        for value in packet:
            integer(value, "ADC sample", 0, 4095)
    seed = args.seed if args.seed is not None else (trace["seed"] if args.input else 1)
    return {"schema": "tycvl.board.request.v1", "request_id": secrets.token_hex(16), "tool_version": __version__,
            "device": "exoy-one-v2-1", "assets": assets, "library_paths": libraries,
            "app_entrypoint": image["entry_point"], "loaded_app_checks": loaded_checks,
            "packets": packets, "input_provenance": provenance, "seed": seed,
            "settings": {"pack": args.pack, "effect": args.effect}, "boot_mic": args.mic,
            "cpu_hz": args.cpu_hz, "timeout_s": args.timeout_s,
            "hold_files": [str(Path(p).expanduser().resolve()) for p in args.hold_file]}


def run_board(args):
    request = prepare(args)
    output = private_path(args.out)
    require(not output.exists(), "board output directory already exists")
    output.mkdir(parents=True, mode=0o700)
    request["workdir"] = str(output)
    request["tool_source_sha256"] = _source_fingerprint()
    write_json(output / "request.json", request)
    command = [sys.executable, "-m", "vfl.board", "--worker", str(output / "request.json")]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
    limiter = next((a["path"] for a in request["assets"] if a["role"] == "limiter"), None)
    if limiter:
        command.insert(0, limiter)
        env.update(EMU_SLOTS="1", EMU_CPUS="1", EMU_MEM="3072M", EMU_NO_LIMIT="0")
    try:
        run_process(command, output, output/"stdout.log", output/"stderr.log", args.timeout_s, env)
        _check_assets(request)
        require(_source_fingerprint() == request["tool_source_sha256"], "board runner source changed")
        capture = normalize(request, load_json(output / "board-observations.json"))
        write_json(output / "capture.json", capture)
        write_json(output / "status.json", {"status": "complete", "schema": "tycvl.board.status.v1",
                   "capture_sha256": digest(capture), "request_sha256": digest(request),
                   "execution_kind": "original-firmware", "frames": len(capture["frames"])})
        return output / "capture.json"
    except BaseException as exc:
        write_json(output / "status.json", {"status": "failed", "error": str(exc), "error_type": type(exc).__name__})
        raise


def worker(request_path):
    request_path = Path(request_path).expanduser().absolute()
    require(request_path.is_file() and not request_path.is_symlink(), "board request must be a regular file")
    request = load_json(request_path)
    require(request.get("schema") == "tycvl.board.request.v1", "invalid board worker request")
    work = private_path(request["workdir"])
    require(request_path.resolve().parent == work and request_path.name == "request.json",
            "board request must be inside its private work directory")
    _check_assets(request)
    require(not any(Path(p).exists() for p in request["hold_files"]), "board execution held")
    paths = {a["role"]: Path(a["path"]) for a in request["assets"]}
    flash = work / "flash-copy.bin"
    with flash.open("xb") as target, paths["flash"].open("rb") as source:
        shutil.copyfileobj(source, target)
    rom = work / "roms"
    rom.mkdir()
    for name in ("esp32-v3-rom.bin", "esp32-v3-rom-app.bin"):
        shutil.copyfile(paths[name], rom / name)
    script = Path(__file__).with_name("native") / "exoy_board.py"
    # The worker is isolated from the parent CLI. Bound every file written by
    # QEMU/GDB, including UART logs that do not pass through run_process.
    # The mutable flash copy is exactly this size and is never extended.
    resource.setrlimit(resource.RLIMIT_FSIZE, (8*1024*1024, 8*1024*1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    env = os.environ.copy()
    env["LD_LIBRARY_PATH"] = os.pathsep.join(request["library_paths"])
    env["TYCVL_BOARD_REQUEST"] = str(Path(request_path).resolve())
    with tempfile.TemporaryDirectory(prefix="tycvl-qemu-") as runtime:
        sock = Path(runtime) / "gdb.sock"
        env["TYCVL_BOARD_SOCKET"] = str(sock)
        command = [str(paths["qemu"]), "-machine", "esp32", "-L", str(rom),
                   "-drive", f"file={flash},if=mtd,format=raw", "-serial", f"file:{work/'uart.log'}",
                   "-monitor", "none", "-display", "none", "-net", "none",
                   "-global", "driver=timer.esp32.timg,property=wdt_disable,value=true",
                   "-accel", "tcg,thread=single", "-icount", "shift=3,align=off,sleep=off", "-seed", str(request["seed"]),
                   "-gdb", f"unix:{sock},server=on,wait=off", "-S"]
        write_json(work / "emulator-command.json", command)
        with (work/"qemu.stdout.log").open("xb") as stdout, (work/"qemu.stderr.log").open("xb") as stderr:
            process = subprocess.Popen(command, cwd=work, env=env, stdout=stdout, stderr=stderr,
                                       pass_fds=inherited_resource_lock_fds())
            try:
                deadline = time.monotonic()+10
                while not sock.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.05)
                require(sock.exists() and process.poll() is None, "QEMU failed before debugger connection")
                run_process([str(paths["gdb"]), "-q", "-nx", "-nh", "-batch", "-ex", "source " + str(script)],
                            work, work/"gdb.stdout.log", work/"gdb.stderr.log", request["timeout_s"]*.9, env,
                            termination_grace_s=0)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill(); process.wait()


def normalize(request, observations):
    try:
        return _normalize(request, observations)
    except (KeyError, TypeError, OverflowError) as error:
        raise LabError("malformed board request or observations; required execution fields are missing or invalid") from error


def _normalize(request, observations):
    integer(request["cpu_hz"], "cpu_hz", 1, 1000000000)
    require(isinstance(observations, dict), "board observations must be an object")
    require(observations.get("schema") == "tycvl.board.observations.v1"
            and observations.get("request_sha256") == hashlib.sha256(canonical(request)+b"\n").hexdigest()
            and observations.get("request_id") == request["request_id"], "board execution binding differs")
    require(observations.get("loaded_app_checks") == request["loaded_app_checks"],
            "loaded application code/constants differ from verified firmware")
    boot_frames = integer(observations.get("boot_frames"), "startup frames", 0, 2000)
    wifi_failures = integer(observations.get("wifi_failures"), "WiFi failures", 0, 1000000)
    require(observations.get("core_mapping") == "qemu-gdb-thread-global-num-minus-one",
            "unknown board CPU core mapping")
    packet_policy = "packet i belongs to scene/output frame i; zero-read frames discard their packet"
    require(observations.get("packet_policy") == packet_policy, "unknown board input packet policy")
    frames = observations.get("frames")
    require(isinstance(frames, list) and len(frames) == len(request["packets"]), "incomplete board capture")
    result, events, elapsed, previous, capture_core = [], [], 0, None, None
    for i, frame in enumerate(frames):
        require(isinstance(frame, dict), "board frame must be an object")
        require(frame.get("index") == i, "board frame order differs")
        counter = integer(frame.get("ccount"), "CCOUNT", 0, 2**32-1)
        core = integer(frame.get("core"), "CPU core", 0, 1)
        require(capture_core is None or capture_core == core, "board capture changed CPU core")
        capture_core = core
        for name, size in (("logical",1440),("driver",1440),("state",80),("selector",32),("selector_before",32)):
            value = frame.get(name)
            require(isinstance(value,str) and len(value)==size*2
                    and all(c in "0123456789abcdef" for c in value), "invalid board " + name + " bytes")
        selector = bytes.fromhex(frame["selector"])
        pack, effect = int.from_bytes(selector[12:16],"little"), selector[16]
        require(0 <= pack < len(PACKS) and effect < len(PACKS[pack][1]), "invalid observed scene selection")
        require(request["settings"]["pack"] is None or (pack == request["settings"]["pack"]
                and effect == request["settings"]["effect"]), "observed scene differs from requested selection")
        before = bytes.fromhex(frame["selector_before"])
        require(request["settings"]["pack"] is None or
                (int.from_bytes(before[12:16],"little")==request["settings"]["pack"]
                 and before[16]==request["settings"]["effect"]), "scene entry differs from requested selection")
        if previous is not None: elapsed += (counter-previous) & 0xffffffff
        previous = counter
        reads = frame.get("adc")
        require(isinstance(reads, list) and len(reads) in (0,64), "board ADC acquisition is incomplete")
        for value in reads: integer(value, "observed ADC value", 0, 4095)
        require(reads == request["packets"][i][:len(reads)], "board delivered ADC input differs")
        result.append({"index": i, "time_us": elapsed*1000000//request["cpu_hz"],
                       "buses": {"logical": frame["logical"], "driver": frame["driver"]},
                       "state": {"scene": frame["state"], "selector": frame["selector"],
                                 "selector_before": frame["selector_before"],
                                 "core": bytes([core]).hex(), "ccount": counter.to_bytes(4,"little").hex()}})
        events.extend({"kind":"adc", "frame":i, "channel":6, "sample_index":j, "value":v,
                       "call_site":"adc1_get_raw"} for j,v in enumerate(reads))
    profile_id = "exoy-one-qemu-v2-1"
    initial_assets = {a["role"]:a["sha256"] for a in request["assets"]
                      if a["role"] in {"flash", "firmware", "esp32-v3-rom.bin", "esp32-v3-rom-app.bin"}}
    identities = {"input_sha256": digest({"packets":request["packets"],"provenance":request["input_provenance"]}),
                  "profile_sha256": digest({"assets":request["assets"],"settings":request["settings"],"cpu_hz":request["cpu_hz"]}),
                  "experiment_sha256": digest({"device":request["device"],"packets":request["packets"],
                      "settings":request["settings"],"seed":request["seed"],"cpu_hz":request["cpu_hz"],
                      "boot_mic":request["boot_mic"],"initial_assets":initial_assets})}
    return validate_capture({"schema":"vfl.capture.v1", "manifest": {
        "tool":"TycVirtualLab", "tool_version":request.get("tool_version", "0.2.0"), "tool_source_sha256":request["tool_source_sha256"],
        "profile_id":profile_id, "backend":"qemu-esp32-board", "execution_kind":"original-firmware", "execution_scope":"board-diagnostic",
        "request_id":request["request_id"], **identities,
        "runtime_assets_sha256": {a["role"]:a["sha256"] for a in request["assets"]
                                  if a["role"] in {"qemu","gdb","esp32-v3-rom.bin","esp32-v3-rom-app.bin"}},
        "loaded_app_checks": observations["loaded_app_checks"],
        "input_packet_policy": packet_policy,
        "capabilities":{"adc_log":True,"clock_log":False,"rng_log":False,"state":True},
        "clock":{"source":"observed-32bit-CCOUNT", "conversion_hz":request["cpu_hz"],
                 "origin":"first captured scene frame", "core_mapping":observations["core_mapping"]},
        "boot":{"skipped_show_frames":boot_frames,"wifi_failures":wifi_failures},
        "limitations":["Boots a private copy of supplied flash, including its SDK bootloader and persisted settings; these need not be the physical lamp's boot assets.",
         "IPC stall handshake, ADC channel6, offline WiFi failure and RMT send are explicit debugger hardware stand-ins.",
         "The timer-group watchdogs are switched off in QEMU (timer.esp32.timg wdt_disable): a stall that resets a lamp does not reset this run.",
         "Packet i belongs to scene/output frame i; zero-read frames discard their packet. Source PCM timestamps do not drive QEMU's clock or establish physical ADC acquisition spacing.",
         "Display timestamps convert observed CCOUNT using the declared frequency; this is a QEMU observation, not measured silicon timing.",
         "ADC and WiFi stand-ins consume no simulated conversion/attempt time; only the RMT stand-in invokes the declared ROM delay.",
         "QEMU seed/icount do not certify repeatability. Repeat captures and compare their timestamps, state and bytes."]},
        "buses":[{"id":"logical","pixels":480,"order":"RGB","stage":"logical"},
                 {"id":"driver","pixels":480,"order":"GRB","stage":"driver"}],
        "geometry":{"kind":"strips"}, "frames":result, "events":events})


def verify_completed(directory, request, status, capture):
    require(status.get("schema") == "tycvl.board.status.v1" and status.get("request_sha256") == digest(request), "board request changed")
    require(status.get("frames") == len(capture["frames"]) and status.get("execution_kind") == "original-firmware", "board completion differs")
    expected = normalize(request, load_json(Path(directory)/"board-observations.json"))
    require(digest(expected) == digest(capture), "board capture differs from bound observations")
    return capture


if __name__ == "__main__":
    try:
        require(len(sys.argv)==3 and sys.argv[1]=="--worker", "board worker arguments required")
        worker(sys.argv[2])
    except (LabError, OSError, ValueError) as error:
        print(f"tycvl-board: {error}", file=sys.stderr)
        raise SystemExit(2)
