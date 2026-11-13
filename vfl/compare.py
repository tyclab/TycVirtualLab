"""Compare matching experiments and stop at the first observable divergence."""

from .model import LabError, choice, digest, integer, require, validate_capture


def _normalized_events(capture, kinds):
    result = []
    for event in capture["events"]:
        if event["kind"] not in kinds:
            continue
        normalized = {"kind": event["kind"], "frame": event["frame"], "value": event["value"],
                      "phase": event.get("phase", "initialization" if event["frame"] == -1 else "frame")}
        if "time_us" in event:
            normalized["time_us"] = event["time_us"]
        if event["kind"] == "adc":
            require("channel" in event, "ADC event comparison requires a declared channel")
            normalized["channel"] = event["channel"]
        elif event["kind"] == "clock":
            require(isinstance(event.get("units"), str) and event["units"], "clock event comparison requires declared units")
            normalized["units"] = event["units"]
        else:
            mode = choice(event.get("mode"), {"raw", "bounded"}, "RNG event comparison requires raw or bounded mode")
            normalized["mode"] = mode
            integer(event["value"], "RNG event value", 0, 0xffffffff)
            if mode == "bounded":
                normalized["bound"] = integer(event.get("bound"), "RNG event bound", 0, 0xffffffff)
        result.append(normalized)
    return result


def compare(left, right, *, include_state=True, include_events=False):
    validate_capture(left)
    validate_capture(right)
    lm, rm = left["manifest"], right["manifest"]
    for key in ("profile_id", "input_sha256", "experiment_sha256"):
        require(key in lm and key in rm and lm[key] == rm[key], f"incomparable captures: {key} missing or differs")
    require(left["buses"] == right["buses"], "incomparable bus layouts")
    require(left.get("geometry", {}) == right.get("geometry", {}), "incomparable geometry")
    if include_state:
        require(lm["capabilities"]["state"] and rm["capabilities"]["state"], "state comparison requested but unavailable; explicitly select RGB-only")
        require(lm.get("state_encoding", "bytes") == rm.get("state_encoding", "bytes"), "incomparable state encodings")
    event_kinds = []
    left_events, right_events = [], []
    if include_events:
        event_kinds = [kind for kind in ("adc", "clock", "rng")
                       if lm["capabilities"][kind + "_log"] and rm["capabilities"][kind + "_log"]]
        require(event_kinds, "event comparison requested but no common log capabilities")
        left_events, right_events = _normalized_events(left, event_kinds), _normalized_events(right, event_kinds)
        require(left_events and right_events, "event comparison requested but a common event log is empty")
    base = {"schema": "vfl.comparison.v1", "left_execution": lm["execution_kind"],
            "right_execution": rm["execution_kind"], "input_sha256": lm["input_sha256"],
            "left_capture_sha256": digest(left), "right_capture_sha256": digest(right),
            "scope": {"rgb": True, "state": include_state, "events": include_events, "event_kinds": event_kinds},
            "verification": "unverified", "frames_compared": 0, "events_compared": 0}

    def different(reason, **detail):
        return dict(base, verdict="different", first_difference=dict(reason=reason, **detail))

    if len(left["frames"]) != len(right["frames"]):
        return different("frame-count", left=len(left["frames"]), right=len(right["frames"]))
    for a, b in zip(left["frames"], right["frames"]):
        i = a["index"]
        if a["time_us"] != b["time_us"]:
            return different("timestamp", frame=i, left=a["time_us"], right=b["time_us"])
        for bus in left["buses"]:
            name = bus["id"]
            x, y = bytes.fromhex(a["buses"][name]), bytes.fromhex(b["buses"][name])
            if x != y:
                offset = next(j for j, (p, q) in enumerate(zip(x, y)) if p != q)
                return different("rgb", frame=i, time_us=a["time_us"], bus=name, pixel=offset//3,
                                 channel=bus["order"][offset%3], byte_offset=offset,
                                 left=x[offset], right=y[offset])
        if include_state and a.get("state", {}) != b.get("state", {}):
            sa, sb = a.get("state", {}), b.get("state", {})
            for key in sorted(set(sa) | set(sb)):
                if key not in sa or key not in sb:
                    return different("state-tag", frame=i, tag=key)
                x, y = bytes.fromhex(sa[key]), bytes.fromhex(sb[key])
                if x != y:
                    if lm.get("state_encoding", "bytes") == "sha256":
                        return different("state-hash", frame=i, tag=key, left=sa[key], right=sb[key])
                    offset = next((j for j,(p,q) in enumerate(zip(x,y)) if p != q), min(len(x),len(y)))
                    return different("state", frame=i, tag=key, byte_offset=offset,
                                     left=x[offset] if offset < len(x) else None,
                                     right=y[offset] if offset < len(y) else None)
        base["frames_compared"] += 1
    if include_events:
        for index, (a, b) in enumerate(zip(left_events, right_events)):
            if a != b:
                return different("event", event_index=index)
            base["events_compared"] += 1
        if len(left_events) != len(right_events):
            return different("event", event_index=base["events_compared"])
    return dict(base, verdict="equal", first_difference=None,
                interpretation="Equal for these declared inputs, snapshots and comparison scope; not a proof of physical equivalence.")
