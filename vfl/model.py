"""Strict, bounded JSON contracts shared by all execution adapters."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import tempfile
import tomllib
from pathlib import Path

MAX_JSON_BYTES = 128 * 1024 * 1024
MAX_FRAMES = 100_000
MAX_PIXELS = 65_536
MAX_PROJECT_METADATA_BYTES = 128 * 1024
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
HEX = re.compile(r"^(?:[0-9a-fA-F]{2})*$")
EXECUTIONS = {"synthetic", "original-firmware", "recovered-code", "replay"}


class LabError(ValueError):
    """Invalid experiment, unavailable capability, or failed execution."""


def require(condition, message):
    if not condition:
        raise LabError(message)


def integer(value, name, minimum=0, maximum=2**63 - 1):
    require(type(value) is int and minimum <= value <= maximum,
            f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def number(value, name):
    try:
        finite = type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        finite = False
    require(finite, f"{name} must be finite")
    return value


def mapping(value, name):
    require(isinstance(value, dict), f"{name} must be an object")
    return value


def identifier(value, name):
    require(isinstance(value, str) and ID.fullmatch(value), f"invalid {name}")
    return value


def choice(value, allowed, message):
    require(isinstance(value, str) and value in allowed, message)
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value):
    raise LabError(f"non-finite JSON constant: {value}")


def load_json(path, maximum_bytes=MAX_JSON_BYTES):
    p = Path(path)
    require(p.is_file(), f"missing JSON file: {p}")
    require(p.stat().st_size <= maximum_bytes, f"JSON exceeds {maximum_bytes} bytes")
    try:
        with p.open("rb") as f:
            raw = f.read(maximum_bytes + 1)
        require(len(raw) <= maximum_bytes, "JSON exceeded size limit while reading")
        result = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
        canonical(result)  # Also rejects non-JSON and excessive nesting.
        return result
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise LabError(f"invalid JSON: {exc}") from exc


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError) as exc:
        raise LabError(f"invalid JSON value: {exc}") from exc


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def source_root():
    root = Path(__file__).resolve().parent.parent
    return root if (root / "pyproject.toml").is_file() else None


def _is_lab_project(directory):
    """Inspect project identity without importing or executing build tooling."""
    metadata = directory / "pyproject.toml"
    try:
        # Nonblocking open also prevents a substituted FIFO from hanging the
        # path guard. Check the opened descriptor, not a racy preliminary stat.
        fd = os.open(metadata, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except (FileNotFoundError, NotADirectoryError):
        return False
    except OSError as exc:
        raise LabError(f"cannot inspect ancestor project metadata: {metadata}: {exc}") from exc
    try:
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            require(stat.S_ISREG(info.st_mode), f"ancestor project metadata is not a regular file: {metadata}")
            require(info.st_size <= MAX_PROJECT_METADATA_BYTES, f"ancestor project metadata exceeds inspection limit: {metadata}")
            raw = source.read(MAX_PROJECT_METADATA_BYTES + 1)
            require(len(raw) <= MAX_PROJECT_METADATA_BYTES, f"ancestor project metadata exceeded inspection limit: {metadata}")
        data = tomllib.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, RecursionError) as exc:
        raise LabError(f"cannot parse ancestor project metadata: {metadata}: {exc}") from exc
    project = data.get("project", {})
    name = project.get("name") if isinstance(project, dict) else None
    return isinstance(name, str) and name.casefold() == "tycvirtuallab"


def private_path(path):
    """Results may not be written into the shareable source checkout."""
    p = Path(path).expanduser().resolve()
    root = source_root()
    require(root is None or not p.is_relative_to(root),
            "write experiments outside the source checkout; use a separate private directory")
    # Installed wheels/Nix packages have no checkout next to __file__. Identify
    # any destination checkout independently, after resolving symlink aliases.
    for ancestor in (p, *p.parents):
        require(not _is_lab_project(ancestor),
                "write experiments outside a TycVirtualLab source checkout; use a separate private directory")
    return p


def write_json(path, value):
    p = Path(path)
    data = canonical(value) + b"\n"
    require(len(data) <= MAX_JSON_BYTES, "JSON output exceeds the supported size limit")
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tycvl-", dir=p.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def validate_input(spec):
    mapping(spec, "input")
    choice(spec.get("kind"), {"bands", "pcm", "scalar"}, "unsupported input kind")
    integer(spec.get("channels"), "input.channels", 1, 256)
    lo = number(spec.get("minimum"), "input.minimum")
    hi = number(spec.get("maximum"), "input.maximum")
    require(lo < hi, "input range must be increasing")
    require(isinstance(spec.get("units"), str) and spec["units"], "input.units is required")
    if spec["kind"] == "pcm":
        require(spec["channels"] == 1, "PCM v1 requires explicit mono conversion")
        integer(spec.get("sample_rate_hz"), "sample_rate_hz", 1, 768000)
        integer(spec.get("block_samples"), "block_samples", 1, 65536)
    return spec


def validate_buses(buses):
    require(isinstance(buses, list) and 1 <= len(buses) <= 64, "one to 64 buses required")
    names = set()
    total = 0
    for bus in buses:
        mapping(bus, "bus")
        name = identifier(bus.get("id"), "bus.id")
        require(name not in names, "duplicate bus id")
        names.add(name)
        total += integer(bus.get("pixels"), "bus.pixels", 1, MAX_PIXELS)
        choice(bus.get("order"), {"RGB", "RBG", "GRB", "GBR", "BRG", "BGR"}, "invalid channel order")
        choice(bus.get("stage", "driver"), {"logical", "driver"}, "invalid bus stage")
    require(total <= MAX_PIXELS, "total pixel limit exceeded")
    return buses


def validate_geometry(geometry, buses):
    mapping(geometry, "geometry")
    choice(geometry.get("kind", "strips"), {"strips", "points"}, "invalid geometry kind")
    counts = {b["id"]: b["pixels"] for b in buses}
    masks = geometry.get("mask", {})
    mapping(masks, "geometry.mask")
    for name, mask in masks.items():
        require(name in counts and isinstance(mask, list) and len(mask) == counts[name], "mask length or bus mismatch")
        require(all(type(x) is bool for x in mask), "mask values must be boolean")
    points = geometry.get("points", [])
    require(isinstance(points, list) and len(points) <= MAX_PIXELS, "invalid geometry points")
    seen = set()
    for point in points:
        mapping(point, "point")
        name = point.get("bus")
        require(isinstance(name, str) and name in counts, "unknown point bus")
        idx = integer(point.get("index"), "point.index", 0, counts[name] - 1)
        require((name, idx) not in seen, "duplicate point mapping")
        seen.add((name, idx))
        for axis in ("x", "y", "z"):
            number(point.get(axis), f"point.{axis}")
    return geometry


def validate_profile(profile):
    from .identity import validate_target
    mapping(profile, "profile")
    profile_keys = {"schema", "id", "description", "input", "buses", "backend", "settings",
                    "geometry", "firmware", "target", "metadata"}
    require(set(profile) <= profile_keys, "unknown profile keys: " + ", ".join(sorted(set(profile) - profile_keys)))
    if "description" in profile:
        require(isinstance(profile["description"], str), "profile.description must be a string")
    if "metadata" in profile:
        mapping(profile["metadata"], "profile.metadata")
    require(profile.get("schema") == "vfl.profile.v1", "unsupported profile schema")
    identifier(profile.get("id"), "profile.id")
    validate_target(profile.get("target"))
    validate_input(profile.get("input"))
    validate_buses(profile.get("buses"))
    validate_geometry(profile.get("geometry", {"kind": "strips"}), profile["buses"])
    mapping(profile.get("settings", {}), "settings")
    backend = mapping(profile.get("backend"), "backend")
    choice(backend.get("kind"), {"demo", "external"}, "unsupported backend")
    common_keys = {"kind", "execution_kind", "hold_file", "resource_lock", "queue_timeout_s"}
    external_keys = {"command", "timeout_s", "cwd", "env", "options"} if backend["kind"] == "external" else set()
    require(set(backend) <= common_keys | external_keys,
            "unknown backend keys: " + ", ".join(sorted(set(backend) - common_keys - external_keys)))
    for key in ("hold_file", "resource_lock", "cwd"):
        if key in backend:
            require(isinstance(backend[key], str) and backend[key] and "\x00" not in backend[key],
                    f"backend.{key} must be a nonempty path string")
    if "queue_timeout_s" in backend:
        number(backend["queue_timeout_s"], "backend.queue_timeout_s")
        require(0 <= backend["queue_timeout_s"] <= 86400, "queue timeout must be in [0, 86400]")
        require("resource_lock" in backend, "queue_timeout_s requires resource_lock")
    if "env" in backend:
        env = mapping(backend["env"], "backend.env")
        require(len(env) <= 256 and all(isinstance(k, str) and k and isinstance(v, str)
                and "\x00" not in k + v and "=" not in k and len(v) <= 65536 for k, v in env.items()),
                "backend.env must contain bounded string names and values")
    if "options" in backend:
        mapping(backend["options"], "backend.options")
    if backend["kind"] == "demo":
        require(backend.get("execution_kind", "synthetic") == "synthetic", "demo execution_kind must be synthetic")
    if backend["kind"] == "external":
        command = backend.get("command")
        require(isinstance(command, list) and command and all(isinstance(x, str) and x and "\x00" not in x for x in command), "external command must be a nonempty argument list")
        choice(backend.get("execution_kind"), EXECUTIONS, "declare external execution_kind")
        number(backend.get("timeout_s", 300), "backend.timeout_s")
        require(0 < backend.get("timeout_s", 300) <= 86400, "timeout must be in (0, 86400]")
    assets = profile.get("firmware", [])
    require(isinstance(assets, list), "firmware must be a list")
    roles = set()
    for asset in assets:
        mapping(asset, "firmware asset")
        asset_keys = {"role", "path", "sha256", "format", "description", "metadata"}
        require(set(asset) <= asset_keys, "unknown firmware asset keys: " + ", ".join(sorted(set(asset) - asset_keys)))
        require(isinstance(asset.get("path"), str) and asset["path"], "asset.path required")
        identifier(asset.get("role"), "asset.role")
        require(asset["role"] not in roles, "duplicate firmware asset role")
        roles.add(asset["role"])
        if "description" in asset:
            require(isinstance(asset["description"], str), "asset.description must be a string")
        if "metadata" in asset:
            mapping(asset["metadata"], "asset.metadata")
        if "format" in asset:
            choice(asset["format"], {"esp32", "esp8266", "elf"}, "invalid asset.format")
        if "sha256" in asset:
            require(isinstance(asset["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", asset["sha256"]), "invalid asset SHA256")
    canonical(profile)
    return profile


def validate_trace(trace):
    mapping(trace, "trace")
    require(trace.get("schema") == "vfl.trace.v1", "unsupported trace schema")
    spec = validate_input(trace.get("input"))
    integer(trace.get("seed"), "seed", 0, 2**32 - 1)
    choice(trace.get("clock_policy"), {"frame"}, "v1 supports frame clock_policy only")
    mapping(trace.get("provenance"), "provenance")
    frames = trace.get("frames")
    require(isinstance(frames, list) and 1 <= len(frames) <= MAX_FRAMES, "invalid frame count")
    previous = -1
    sample_start = 0
    for i, frame in enumerate(frames):
        mapping(frame, "frame")
        require(frame.get("index") == i and type(frame.get("index")) is int, "frame indexes must be contiguous from zero")
        t = integer(frame.get("time_us"), "time_us")
        require(t > previous, "frame timestamps must strictly increase")
        previous = t
        values = frame.get("values")
        require(isinstance(values, list), "frame.values must be a list")
        if spec["kind"] == "pcm":
            require(1 <= len(values) <= spec["block_samples"], "invalid PCM block size")
            if i < len(frames) - 1:
                require(len(values) == spec["block_samples"], "only the final PCM block may be short")
            require(t == sample_start * 1_000_000 // spec["sample_rate_hz"], "PCM timestamp disagrees with sample index")
            sample_start += len(values)
        else:
            require(len(values) == spec["channels"], "wrong input channel count")
        for value in values:
            number(value, "input value")
            require(spec["minimum"] <= value <= spec["maximum"], "input value outside declared range")
            if spec["kind"] == "bands":
                require(type(value) is int, "band ADC values must be integers")
        mapping(frame.get("controls", {}), "frame.controls")
    canonical(trace)
    return trace


def compatible_input(profile, trace):
    keys = ("kind", "channels", "minimum", "maximum", "units")
    require(all(profile["input"].get(k) == trace["input"].get(k) for k in keys),
            "trace input units, range, kind or channels do not match profile")
    for key in ("sample_rate_hz", "block_samples"):
        if key in profile["input"]:
            require(profile["input"][key] == trace["input"].get(key), f"input {key} mismatch")


def validate_capture(capture, profile=None, trace=None):
    mapping(capture, "capture")
    require(capture.get("schema") == "vfl.capture.v1", "unsupported capture schema")
    manifest = mapping(capture.get("manifest"), "manifest")
    identifier(manifest.get("profile_id"), "manifest.profile_id")
    choice(manifest.get("execution_kind"), EXECUTIONS, "invalid execution kind")
    require(isinstance(manifest.get("backend"), str) and manifest["backend"], "backend provenance required")
    for key in ("input_sha256", "profile_sha256", "experiment_sha256", "tool_source_sha256"):
        if key in manifest:
            require(isinstance(manifest[key], str) and re.fullmatch(r"[0-9a-f]{64}", manifest[key]),
                    f"invalid manifest {key}")
    if "request_id" in manifest:
        require(isinstance(manifest["request_id"], str) and re.fullmatch(r"[0-9a-f]{32}", manifest["request_id"]),
                "invalid manifest request_id")
    require(isinstance(manifest.get("limitations"), list) and all(isinstance(x, str) for x in manifest["limitations"]), "limitations must be a list of strings")
    caps = mapping(manifest.get("capabilities"), "capabilities")
    choice(manifest.get("state_encoding", "bytes"), {"bytes", "sha256"}, "state encoding")
    for key in ("adc_log", "clock_log", "rng_log", "state"):
        require(type(caps.get(key)) is bool, f"capability {key} must be explicit boolean")
    buses = validate_buses(capture.get("buses"))
    lengths = {b["id"]: b["pixels"] * 6 for b in buses}
    geometry = capture.get("geometry", {"kind": "strips"})
    validate_geometry(geometry, buses)
    frames = capture.get("frames")
    require(isinstance(frames, list) and 1 <= len(frames) <= MAX_FRAMES, "invalid capture frame count")
    if profile is not None:
        require(manifest["profile_id"] == profile["id"], "adapter returned wrong profile")
        require(buses == profile["buses"], "adapter returned wrong bus layout")
        require(geometry == profile.get("geometry", {"kind": "strips"}), "adapter changed geometry")
    if trace is not None:
        require(len(frames) == len(trace["frames"]), "adapter returned wrong frame count")
    previous = -1
    for i, frame in enumerate(frames):
        mapping(frame, "capture frame")
        require(type(frame.get("index")) is int and frame["index"] == i, "capture indexes must be contiguous")
        t = integer(frame.get("time_us"), "capture time_us")
        require(t > previous, "capture timestamps must strictly increase")
        previous = t
        if trace is not None:
            require(t == trace["frames"][i]["time_us"], "capture timestamp disagrees with input")
        streams = mapping(frame.get("buses"), "frame.buses")
        require(set(streams) == set(lengths), "missing or extra bus")
        for name, size in lengths.items():
            value = streams[name]
            require(isinstance(value, str) and len(value) == size and HEX.fullmatch(value), f"bad RGB bytes for bus {name}")
        state = mapping(frame.get("state", {}), "frame.state")
        if caps["state"]:
            require(bool(state), "state capability declared but state is missing")
        for name, value in state.items():
            identifier(name, "state tag")
            require(isinstance(value, str) and len(value) <= 16 * 1024 * 1024 and HEX.fullmatch(value), "state must contain bounded hex bytes")
            if manifest.get("state_encoding", "bytes") == "sha256":
                require(len(value) == 64, "state SHA256 must be 32 bytes")
    events = capture.get("events")
    require(isinstance(events, list) and len(events) <= 5_000_000, "invalid event log")
    kinds = set()
    for event in events:
        mapping(event, "event")
        choice(event.get("kind"), {"adc", "clock", "rng", "stub", "control"}, "unsupported event kind")
        kinds.add(event["kind"])
        frame_index = integer(event.get("frame"), "event.frame", -1, len(frames) - 1)
        if frame_index == -1:
            require(event.get("phase") == "initialization", "frame -1 events require initialization phase")
        if "time_us" in event:
            integer(event["time_us"], "event.time_us")
        if "phase" in event:
            require(event["phase"] == ("initialization" if frame_index == -1 else "frame"), "event phase disagrees with frame")
        if event["kind"] in {"adc", "clock", "rng"}:
            number(event.get("value"), "event.value")
        if "channel" in event:
            require((type(event["channel"]) is int and event["channel"] >= 0)
                    or (isinstance(event["channel"], str) and event["channel"]), "invalid event channel")
    for cap, kind in (("adc_log", "adc"), ("clock_log", "clock"), ("rng_log", "rng")):
        require(caps[cap] or kind not in kinds, f"{kind} log present but capability disabled")
    canonical(capture)
    return capture


def experiment_digest(profile, trace):
    from .identity import validate_target
    return digest({"profile_id": profile["id"], "input": profile["input"],
                   "target": validate_target(profile.get("target")),
                   "buses": profile["buses"], "geometry": profile.get("geometry", {"kind": "strips"}),
                   "settings": profile.get("settings", {}), "trace": trace})
