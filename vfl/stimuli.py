"""Synthetic ADC-boundary inputs; no device measurements or vendor content."""

import math
import random

from .audio import CENTERS_HZ, MAX_TRACE_FRAMES, _integer


def generate_trace(frames, frame_us, *, channels=7, maximum=1023,
                   kind="music-noise", seed=1):
    """Generate a deterministic vfl.trace.v1 sequence of integer ADC values.

    music-noise is synthetic band activity, not a PCM or MSGEQ7 simulation.
    Its 120 bpm kick and hi-hat schedule follow timestamps, not frame counts.
    """
    _integer(frames, "frames", 1, MAX_TRACE_FRAMES)
    _integer(frame_us, "frame_us", 1)
    _integer(channels, "channels", 1, 64)
    _integer(maximum, "maximum", 1, 65535)
    _integer(seed, "seed", 0, 2**32 - 1)
    _integer((frames - 1) * frame_us, "last timestamp", 0)
    if not isinstance(kind, str) or kind not in {"music-noise", "silence", "steps", "ramp", "impulses"}:
        raise ValueError("unknown band stimulus kind")
    rng = random.Random(seed)
    output = []
    for f in range(frames):
        t = f * frame_us / 1_000_000
        if kind == "silence":
            values = [0] * channels
        elif kind == "steps":
            active = (f // 16) % channels
            values = [maximum if c == active else 0 for c in range(channels)]
        elif kind == "ramp":
            values = [maximum * f // max(1, frames - 1)] * channels
        elif kind == "impulses":
            active = (f // 31) % channels
            values = [maximum if f % 31 == 0 and c == active else 0 for c in range(channels)]
        else:
            kick = math.exp(-(t % 0.5) / 0.080)
            snare = math.exp(-((t + 0.25) % 0.5) / 0.045)
            hat = math.exp(-(t % 0.125) / 0.012)
            pad = 0.5 + 0.5 * math.sin(2 * math.pi * t / 4)
            activity = (0.8 * kick, 0.6 * kick, 0.4 * snare + 0.15 * pad,
                        0.35 * snare + 0.2 * pad, 0.2 * snare, 0.5 * hat, 0.4 * hat)
            values = [min(maximum, int(maximum * (0.02 + 0.05 * rng.random()
                      + activity[c % len(activity)]))) for c in range(channels)]
        output.append({"index": f, "time_us": f * frame_us, "values": values, "controls": {}})
    return {
        "schema": "vfl.trace.v1",
        "input": {"kind": "bands", "channels": channels, "minimum": 0,
                  "maximum": maximum, "units": "adc-counts",
                  **({"centers_hz": list(CENTERS_HZ)} if channels == 7 else {})},
        "seed": seed, "clock_policy": "frame",
        "provenance": {"kind": "synthetic", "generator": f"vfl.{kind}.v1",
                       "description": "Synthetic ADC inputs; no device measurements or calibrated analog model",
                       "seed": seed, "frame_us": frame_us},
        "frames": output,
    }
