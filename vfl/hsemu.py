"""Strict adapter for an external D/R/E/X memory-dump subprocess protocol.

No firmware, addresses, device defaults or recovered routines belong here.
Execution is performed by a separately configured, trusted local adapter.
"""

from dataclasses import dataclass
import hashlib
import json
import re


class HsemuError(ValueError):
    """A command contract or subprocess capture is incomplete or malformed."""


@dataclass(frozen=True)
class Dump:
    tag: str
    address: int
    size: int
    time_us: int | None
    data: str


@dataclass(frozen=True)
class ParsedOutput:
    dumps: tuple[Dump, ...]
    returns: tuple[tuple[int, int], ...]
    completion: dict
    events: tuple[dict, ...] = ()
    instrumentation: dict | None = None
    binding: dict | None = None


_HEX = re.compile(r"(?:[0-9a-fA-F]{2})+")
_REGISTER = re.compile(r"[0-9a-fA-F]{1,8}")
_DONE = re.compile(r"E done stubs=(\d+) ms=(\d+)(?: maxsteps=(\d+))?")


def _event_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise HsemuError("duplicate event JSON key")
            result[key] = value
        return result
    try:
        result = json.loads(text, object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(HsemuError("nonfinite event JSON")))
    except (ValueError, TypeError) as exc:
        raise HsemuError("invalid instrumentation JSON") from exc
    if not isinstance(result, dict):
        raise HsemuError("instrumentation JSON must be an object")
    return result


def _validate_event(event, sequence):
    if event.get("kind") not in {"adc", "clock", "rng", "stub", "control"}:
        raise HsemuError("unsupported instrumentation event kind")
    if type(event.get("sequence")) is not int or event["sequence"] != sequence:
        raise HsemuError("event sequence is missing or discontinuous")
    frame = event.get("frame")
    if type(frame) is not int or frame < -1:
        raise HsemuError("invalid instrumentation frame")
    if event.get("phase") != ("initialization" if frame == -1 else "frame"):
        raise HsemuError("event frame and phase disagree")
    if type(event.get("time_us")) is not int or event["time_us"] < 0:
        raise HsemuError("invalid instrumentation time")
    if not isinstance(event.get("call_site"), str) or not event["call_site"]:
        raise HsemuError("instrumented event has no call site")
    if event["kind"] in {"adc", "clock", "rng", "stub"}:
        if type(event.get("value")) is not int or not 0 <= event["value"] <= 0xffffffff:
            raise HsemuError("instrumented return value must be an unsigned register value")


def _number(value):
    try:
        digits = value[1:] if value.startswith("-") else value
        return int(value, 16 if digits.lower().startswith("0x") else 10)
    except ValueError as exc:
        raise HsemuError(f"invalid command integer: {value!r}") from exc


def _expected(commands_text, dialect):
    events = []
    time_us = None
    called = False
    for line_no, line in enumerate(commands_text.splitlines(), 1):
        parts = line.split("#", 1)[0].split()
        if not parts:
            continue
        op = parts[0]
        if op == "time":
            if len(parts) != 2:
                raise HsemuError(f"invalid time command at line {line_no}")
            milliseconds = _number(parts[1])
            if not 0 <= milliseconds <= 0xffffffff:
                raise HsemuError("time must fit an unsigned 32-bit millisecond clock")
            time_us = milliseconds * 1000
            called = False
        elif op == "dump":
            if len(parts) != 4:
                raise HsemuError(f"invalid dump command at line {line_no}")
            address, size = _number(parts[2]), _number(parts[3])
            if address < 0 or size <= 0:
                raise HsemuError("dump address must be nonnegative and length positive")
            if not called:
                raise HsemuError("each captured frame requires a preceding call after its time command")
            events.append(("D", parts[1], address, size, time_us))
        elif op in {"call", "callq"}:
            if not 2 <= len(parts) <= 8:
                raise HsemuError(f"invalid call command at line {line_no}")
            for value in parts[1:]:
                _number(value)
            called = True
            if op == "call" and dialect == "emulator":
                events.append(("R",))
        elif op == "echo":
            if dialect == "emulator":
                events.append(("E", line.split("#", 1)[0].strip()[4:].strip()))
        elif op in {"seed", "limit", "output_limit"}:
            if len(parts) != 2 or _number(parts[1]) < 0:
                raise HsemuError(f"invalid {op} command")
        elif op == "adc_policy":
            if len(parts) != 2 or parts[1] not in {"strict", "cycle"}:
                raise HsemuError("invalid ADC policy command")
        elif op in {"w8", "w16", "w32", "stub", "zero"}:
            if len(parts) != 3:
                raise HsemuError(f"invalid {op} command")
            for value in parts[1:]:
                _number(value)
        elif op == "wf":
            if len(parts) != 3:
                raise HsemuError("invalid floating-point write command")
            _number(parts[1])
            try:
                import math
                if not math.isfinite(float(parts[2])):
                    raise ValueError()
            except ValueError as exc:
                raise HsemuError("invalid floating-point write value") from exc
        elif op == "wbytes":
            if len(parts) != 3 or not _HEX.fullmatch(parts[2]):
                raise HsemuError("invalid byte-write command")
            _number(parts[1])
        elif op in {"frame", "bands"}:
            if len(parts) < 2:
                raise HsemuError(f"invalid {op} command")
            for value in parts[1:]:
                _number(value)
        elif op == "reg":
            if len(parts) != 3 or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", parts[1]):
                raise HsemuError("invalid register command")
            _number(parts[2])
        elif op == "abi":
            if len(parts) != 8:
                raise HsemuError("invalid ABI command")
            for value in parts[-2:]:
                _number(value)
        elif op == "hook":
            if len(parts) < 3:
                raise HsemuError("invalid hook command")
            _number(parts[1])
            kind, args = parts[2], parts[3:]
            if kind in {"millis", "micros", "adc", "noop", "guard_acquire", "guard_release"}:
                valid = not args
            elif kind == "rng":
                valid = not args or args in (["raw"], ["bounded"])
            elif kind in {"return", "write"}:
                valid = len(args) == (1 if kind == "return" else 3)
                for value in args:
                    _number(value)
            else:
                valid = False
            if not valid:
                raise HsemuError("unsupported hook command")
        else:
            raise HsemuError(f"unknown command at line {line_no}: {op}")
    if not any(event[0] == "D" for event in events):
        raise HsemuError("command contract contains no dumps")
    return events


def parse_output(commands_text, output_text, *, dialect="emulator", request_id=None):
    """Check output against every requested dump and call, in execution order.

    ``dialect='port'`` accepts only D lines. Its process exit status must be
    checked by the caller; no emulator completion marker is fabricated.
    """
    if dialect not in {"emulator", "port"}:
        raise HsemuError("unknown dump protocol dialect")
    expected = _expected(commands_text, dialect)
    actual = []
    completion = None
    events = []
    instrumentation = None
    binding = None
    for line_no, line in enumerate(output_text.splitlines(), 1):
        if completion is not None:
            raise HsemuError("content follows the completion marker")
        if not line.strip():
            raise HsemuError(f"blank output line {line_no}")
        parts = line.split()
        if parts[0] == "X":
            raise HsemuError(f"emulator stopped at output line {line_no}")
        if parts[0] == "D":
            if len(parts) != 3 or not _HEX.fullmatch(parts[2]):
                raise HsemuError(f"invalid dump at output line {line_no}")
            actual.append(("D", parts[1], parts[2].lower()))
        elif dialect == "emulator" and parts[0] == "R":
            if len(parts) != 3 or any(not _REGISTER.fullmatch(v) for v in parts[1:]):
                raise HsemuError(f"invalid register return at output line {line_no}")
            actual.append(("R", int(parts[1], 16), int(parts[2], 16)))
        elif dialect == "emulator" and parts[0] == "E":
            if len(parts) >= 2 and parts[1] == "binding":
                if binding is not None or instrumentation is not None or events or actual:
                    raise HsemuError("execution binding must precede every other record")
                binding = _event_json(line.split(maxsplit=2)[2] if len(parts) > 2 else "")
                if (binding.get("schema") != "tycvl.execution-binding.v1"
                        or not isinstance(binding.get("request_id"), str)
                        or not re.fullmatch(r"[0-9a-f]{32}", binding["request_id"])
                        or binding.get("commands_sha256") != hashlib.sha256(commands_text.encode()).hexdigest()):
                    raise HsemuError("execution binding differs from actual command schedule")
                if request_id is not None and binding["request_id"] != request_id:
                    raise HsemuError("execution binding request nonce differs")
            elif len(parts) >= 2 and parts[1] == "instrumentation":
                if instrumentation is not None or events or actual:
                    raise HsemuError("instrumentation declaration must precede records")
                instrumentation = _event_json(line.split(maxsplit=2)[2] if len(parts) > 2 else "")
                if instrumentation.get("schema") != "vfl.boundary-log.v1":
                    raise HsemuError("unsupported instrumentation schema")
                if any(type(instrumentation.get(cap)) is not bool for cap in ("adc_log", "clock_log", "rng_log")):
                    raise HsemuError("instrumentation capabilities must be explicit booleans")
            elif len(parts) >= 2 and parts[1] == "event":
                if instrumentation is None:
                    raise HsemuError("event appears without an instrumentation declaration")
                event = _event_json(line.split(maxsplit=2)[2] if len(parts) > 2 else "")
                _validate_event(event, len(events))
                if events and (event["frame"], event["time_us"]) < (events[-1]["frame"], events[-1]["time_us"]):
                    raise HsemuError("instrumentation events are out of order")
                events.append(event)
            elif len(parts) >= 2 and parts[1] == "done":
                match = _DONE.fullmatch(line)
                if not match:
                    raise HsemuError("invalid completion marker")
                completion = {"stubs": int(match[1]), "wall_ms": int(match[2])}
                if match[3] is not None:
                    completion["maxsteps"] = int(match[3])
            else:
                info = line[1:].strip()
                if not info or ("E", info) not in expected:
                    raise HsemuError(f"unknown informational output record at line {line_no}")
                actual.append(("E", info))
        else:
            raise HsemuError(f"unrecognized output line {line_no}")
    if dialect == "emulator" and completion is None:
        raise HsemuError("missing emulator completion marker")
    if request_id is not None and binding is None:
        raise HsemuError("missing execution binding")
    if len(actual) != len(expected):
        raise HsemuError(f"received {len(actual)} records; expected {len(expected)}")
    dumps, returns = [], []
    for index, (want, got) in enumerate(zip(expected, actual)):
        if got[0] != want[0]:
            raise HsemuError(f"record {index} is out of order")
        if want[0] == "R":
            returns.append((got[1], got[2]))
        elif want[0] == "E":
            if want != got:
                raise HsemuError("echo record differs from command contract")
        else:
            if got[1] != want[1] or len(got[2]) != want[3] * 2:
                raise HsemuError(f"dump {index} has wrong tag or byte length")
            dumps.append(Dump(want[1], want[2], want[3], want[4], got[2]))
    return ParsedOutput(tuple(dumps), tuple(returns), completion or {}, tuple(events), instrumentation, binding)


def capture_from_output(profile, trace, commands_text, output_text, output_tag_map,
                        *, execution_kind, backend="hsemu", state_tag_map=None,
                        dialect="emulator", limitations=None, request_id=None):
    """Map externally configured dump tags to a complete vfl.capture.v1.

    Frame timestamps come from the command schedule and must match the trace;
    this never assigns missing timestamps by merely counting output lines.
    """
    if execution_kind not in {"original-firmware", "recovered-code", "synthetic", "replay"}:
        raise HsemuError("unknown execution kind")
    if dialect == "port" and execution_kind == "original-firmware":
        raise HsemuError("port dumps cannot establish original firmware execution")
    parsed = parse_output(commands_text, output_text, dialect=dialect, request_id=request_id)
    state_tag_map = state_tag_map or {}
    if set(output_tag_map) & set(state_tag_map):
        raise HsemuError("a dump tag cannot map to both a bus and state")
    buses = profile["buses"]
    bus_specs = {bus["id"]: bus for bus in buses}
    if len(bus_specs) != len(buses):
        raise HsemuError("duplicate bus identifiers")
    if (set(output_tag_map.values()) != set(bus_specs)
            or len(output_tag_map) != len(bus_specs)):
        raise HsemuError("output tags must map one-to-one onto every profile bus")
    if len(set(state_tag_map.values())) != len(state_tag_map):
        raise HsemuError("state tags must map to distinct state names")
    frames, by_time = [], {}
    for expected_index, source in enumerate(trace["frames"]):
        if source["index"] != expected_index or source["time_us"] in by_time:
            raise HsemuError("trace needs sequential indices and unique timestamps")
        frame = {"index": source["index"], "time_us": source["time_us"], "buses": {}}
        frames.append(frame)
        by_time[source["time_us"]] = frame
    if not frames:
        raise HsemuError("trace contains no frames")
    last_index = -1
    for dump in parsed.dumps:
        frame = by_time.get(dump.time_us)
        if frame is None:
            raise HsemuError("dump command time is absent from the trace")
        if frame["index"] < last_index:
            raise HsemuError("dump frames are out of chronological order")
        last_index = frame["index"]
        if dump.tag in output_tag_map:
            bus_id = output_tag_map[dump.tag]
            bus = bus_specs[bus_id]
            expected_size = bus["pixels"] * len(bus["order"])
            if dump.size != expected_size or bus_id in frame["buses"]:
                raise HsemuError("duplicate or incorrectly sized bus frame")
            frame["buses"][bus_id] = dump.data
        elif dump.tag in state_tag_map:
            state_name = state_tag_map[dump.tag]
            state = frame.setdefault("state", {})
            if state_name in state:
                raise HsemuError("duplicate state snapshot in one frame")
            state[state_name] = dump.data
        else:
            raise HsemuError(f"unmapped dump tag: {dump.tag}")
    for frame in frames:
        if set(frame["buses"]) != set(bus_specs):
            raise HsemuError("incomplete bus frame")
        if set(frame.get("state", {})) != set(state_tag_map.values()):
            raise HsemuError("incomplete state snapshot in a captured frame")
    event_caps = {"adc_log": False, "clock_log": False, "rng_log": False}
    if parsed.instrumentation is not None:
        event_caps.update({key: parsed.instrumentation[key] for key in event_caps})
    for event in parsed.events:
        if event["frame"] >= len(frames):
            raise HsemuError("event references an absent frame")
        if event["frame"] >= 0 and event["time_us"] != frames[event["frame"]]["time_us"]:
            raise HsemuError("event time disagrees with frozen frame clock")
        if event["frame"] == -1 and event["time_us"] > frames[0]["time_us"]:
            raise HsemuError("initialization event occurs after the first frame")
        cap = {"adc": "adc_log", "clock": "clock_log", "rng": "rng_log"}.get(event["kind"])
        if cap is not None and not event_caps[cap]:
            raise HsemuError("event kind conflicts with declared instrumentation")
    return {
        "schema": "vfl.capture.v1",
        "manifest": {
            "profile_id": profile["id"], "execution_kind": execution_kind,
            "backend": backend,
            "capabilities": {**event_caps, "state": any("state" in frame for frame in frames)},
            "limitations": list(limitations or [
                ("Boundary reads are logged at declared hooks; unmodelled peripheral behavior remains outside scope."
                 if parsed.instrumentation else "Inputs and clocks are scheduled; actual ADC, clock and RNG reads are not logged."),
                "The dump protocol validates completeness, not firmware or peripheral fidelity."]),
            "completion": parsed.completion,
            "protocol_binding": parsed.binding,
            **({"engine": parsed.instrumentation["engine"]}
               if parsed.instrumentation and "engine" in parsed.instrumentation else {}),
        },
        "buses": buses, "frames": frames, "events": list(parsed.events),
        "geometry": profile.get("geometry", {"kind": "strips"}),
    }
