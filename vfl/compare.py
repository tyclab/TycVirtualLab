"""Compare matching experiments and stop at the first observable divergence."""

from .model import LabError, choice, digest, execution_scope, integer, require, validate_capture


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


def _information(left, right, implementations):
    """What an equal result would rest on, and the reasons it would carry no information.

    An equal comparison shows something only if there were frames with light in them, the two sides are two
    implementations (or the caller declares a repeat of one), and no side used an input the other never read.
    """
    buses = [bus["id"] for bus in left["buses"]]
    contents = [tuple(frame["buses"][name] for name in buses) for frame in left["frames"]]
    lit = sum(1 for content in contents if any(value.strip("0") for value in content))
    input_use = {}
    for kind in ("adc", "clock", "rng"):
        if left["manifest"]["capabilities"][kind + "_log"] and right["manifest"]["capabilities"][kind + "_log"]:
            input_use[kind] = {side: sum(1 for event in capture["events"] if event["kind"] == kind)
                               for side, capture in (("left", left), ("right", right))}
    audio_evidence = {side: data["manifest"].get("input_evidence") for side, data in (("left", left), ("right", right))}
    same_capture = digest(left) == digest(right)
    same_implementation = implementations["left"] == implementations["right"]
    reasons = []
    if not contents:
        reasons.append("no-frames")
    elif not lit:
        reasons.append("all-black")
    if same_capture:
        reasons.append("same-capture")
    elif same_implementation:
        reasons.append("same-implementation")
    for kind, counts in input_use.items():
        if bool(counts["left"]) != bool(counts["right"]):
            reasons.append("input-use-" + kind)
    if any(e and e.get("sound_requested_frames") and not e.get("observed_frames") for e in audio_evidence.values()):
        reasons.append("sound-requested-no-read")
    return {"audio_evidence": audio_evidence, "frames": len(contents), "lit_frames": lit, "distinct_frames": len(set(contents)),
            "same_capture": same_capture, "same_implementation": same_implementation, "input_use": input_use}, reasons


def compare(left, right, *, include_state=True, include_events=False, repeat=False):
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
    omitted_empty_kinds = []
    event_counts = {"left": {}, "right": {}}
    left_events, right_events = [], []
    if include_events:
        common = [kind for kind in ("adc", "clock", "rng")
                  if lm["capabilities"][kind + "_log"] and rm["capabilities"][kind + "_log"]]
        require(common, "event comparison requested but no common log capabilities")
        for side, capture in (("left", left), ("right", right)):
            event_counts[side] = {kind: 0 for kind in ("adc", "clock", "rng")}
            for event in capture["events"]:
                if event["kind"] in event_counts[side]:
                    event_counts[side][event["kind"]] += 1
        for kind in common:
            a, b = event_counts["left"][kind], event_counts["right"][kind]
            if a == b == 0:
                omitted_empty_kinds.append(kind)
                continue
            require(a and b, f"cannot compare {kind} events: one common log is empty")
            event_kinds.append(kind)
        require(event_kinds, "event comparison requested but common event logs are empty")
        left_events, right_events = _normalized_events(left, event_kinds), _normalized_events(right, event_kinds)
        require(left_events and right_events, "event comparison requested but a common event log is empty")
    base = {"schema": "vfl.comparison.v1", "left_execution": lm["execution_kind"],
            "left_execution_scope": execution_scope(lm), "right_execution_scope": execution_scope(rm),
            "right_execution": rm["execution_kind"], "input_sha256": lm["input_sha256"],
            "left_capture_sha256": digest(left), "right_capture_sha256": digest(right),
            "implementations": {side: {key: manifest[key] for key in
                ("backend","tool_version","tool_source_sha256","runtime_assets_sha256") if key in manifest}
                for side, manifest in (("left",lm),("right",rm))},
            "scope": {"rgb": True, "state": include_state, "events": include_events, "event_kinds": event_kinds,
                      "omitted_empty_event_kinds": omitted_empty_kinds},
            "verification": "unverified", "frames_compared": 0, "events_compared": 0,
            "event_counts": event_counts, "events_compared_by_kind": {kind: 0 for kind in event_kinds}}

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
            base["events_compared_by_kind"][a["kind"]] += 1
        if len(left_events) != len(right_events):
            return different("event", event_index=base["events_compared"])
    information, reasons = _information(left, right, base["implementations"])
    if repeat:
        # A declared repeat of one implementation: equal means it repeats, nothing about a second implementation.
        require(information["same_implementation"], "repeat comparison requested but the implementations differ")
        # Two runs of a deterministic implementation give the same capture: that is the expected result here.
        reasons = [reason for reason in reasons if reason not in ("same-capture", "same-implementation")]
    base = dict(base, information=information, relation="repeat" if repeat else "two-implementations")
    if reasons:
        return dict(base, verdict="inconclusive", first_difference=None, inconclusive_reasons=reasons,
                    interpretation="No difference found, but the comparison carries no information: " + ", ".join(reasons) + ".")
    return dict(base, verdict="equal", first_difference=None,
                interpretation=("The implementation repeats itself for these declared inputs and comparison scope."
                                if repeat else
                                "Equal for these declared inputs, snapshots and comparison scope; not a proof of physical equivalence."))
