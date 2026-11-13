"""An authored synthetic state machine for testing adapters and visualizations.

This deliberately does not implement any vendor's animation algorithm.
"""

import math
import struct


def capture(profile, trace):
    from .model import LabError
    if trace["clock_policy"] != "frame":
        raise LabError("demo implements frame clock policy only")
    buses = profile["buses"]
    history = {b["id"]: bytearray(b["pixels"] * 3) for b in buses}
    rng = trace["seed"] or 1
    phase = 0
    frames, events = [], []
    masks = profile.get("geometry", {}).get("mask", {})
    masked = profile.get("settings", {}).get("pixel_access") == "masked-black"
    for f in trace["frames"]:
        rng ^= (rng << 13) & 0xffffffff
        rng ^= rng >> 17
        rng ^= (rng << 5) & 0xffffffff
        rng &= 0xffffffff
        values = f["values"]
        if trace["input"]["kind"] == "pcm":
            level = min(255, int(255 * math.sqrt(sum(x*x for x in values) / len(values))))
        else:
            spec = trace["input"]
            level = round(255 * (sum(values) / len(values) - spec["minimum"]) /
                          (spec["maximum"] - spec["minimum"]))
        phase = (phase + 1 + level // 16) & 0xffffffff
        events.extend([
            {"kind": "clock", "frame": f["index"], "time_us": f["time_us"], "call_site": "demo.frame", "units": "us", "value": f["time_us"]},
            {"kind": "rng", "frame": f["index"], "time_us": f["time_us"], "call_site": "demo.frame", "mode": "raw", "value": rng},
        ])
        if trace["input"]["kind"] != "pcm":
            events.extend({"kind": "adc", "frame": f["index"], "time_us": f["time_us"], "call_site": "demo.input", "channel": k, "value": value} for k, value in enumerate(values))
        outputs = {}
        for bus in buses:
            name, n = bus["id"], bus["pixels"]
            old = history[name]
            mask = masks.get(name, [True] * n)
            data = bytearray(len(old))
            for p in range(n):
                if masked and not mask[p]:
                    continue
                src = (p - 1) % n
                for c in range(3):
                    trail = old[3*src+c] if not masked or mask[src] else 0
                    data[3*p+c] = trail * 7 // 8
                if p == phase % n:
                    rgb = [level, (level * (64 + (rng & 127))) // 255, 255 - level]
                    for c, channel in enumerate(bus["order"]):
                        data[3*p+c] = rgb["RGB".index(channel)]
            history[name] = data
            outputs[name] = data.hex()
        frames.append({"index": f["index"], "time_us": f["time_us"], "buses": outputs,
                       "state": {"machine": struct.pack("<II", phase, rng).hex()}})
    limitations = ["Synthetic test algorithm authored for TycVirtualLab; not vendor firmware or recovered effects.",
                   "Geometry is a display/test configuration, not a measured device wiring map."]
    if masked:
        limitations.append("Synthetic masked-black reads and writes; not proof of a vendor's hole semantics.")
    if any(f.get("controls") for f in trace["frames"]):
        raise LabError("demo does not implement control events")
    return {"schema": "vfl.capture.v1", "manifest": {
        "profile_id": profile["id"], "execution_kind": "synthetic", "backend": "demo-v1",
        "capabilities": {"adc_log": trace["input"]["kind"] != "pcm", "clock_log": True, "rng_log": True, "state": True},
        "limitations": limitations}, "buses": buses, "geometry": profile.get("geometry", {"kind": "strips"}),
        "frames": frames, "events": events}
