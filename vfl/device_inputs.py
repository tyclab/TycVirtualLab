"""Observed audio and clock boundaries in the built-in Ghidra device profiles."""

from .model import require


POLICIES = {"hypercube-adc", "exoy-adc", "exoy-renderer", "glorb-volume"}


def policy_for(profile):
    config = profile["backend"]["options"]["ghidra"]
    if "input_read_policy" in config:
        return config["input_read_policy"]
    # Previously generated device profiles predate the policy field. Preserve
    # their filenames, trace identities and execution recipes when replayed.
    device = profile.get("metadata", {}).get("device")
    if profile["id"] == "hypercube-hs22":
        return "hypercube-adc"
    if device == "exoy-one" and profile["id"] == "exoy-one-v2-1":
        return "exoy-renderer" if config.get("input_writes") else "exoy-adc"
    if device == "glorb" and profile.get("metadata", {}).get("revision") == "GLORB.1.3-debug":
        return "glorb-volume"
    return None


def record_input_evidence(profile, trace, capture):
    config = profile["backend"]["options"]["ghidra"]
    events = [e for e in capture["events"] if e["frame"] >= 0]
    capture["manifest"]["clock"] = {"source": "scheduled-frame-time", "frame_clock_reads":
                                      sum(e["kind"] == "clock" for e in events)}
    policy = policy_for(profile)
    if policy is None:
        return
    require(policy in POLICIES, "unknown device input read policy")
    if policy == "exoy-renderer":
        sound = profile["settings"]["sound_reactive"]
        requested = 0
        for frame in trace["frames"]:
            sound = frame.get("controls", {}).get("sound_reactive", sound)
            requested += sound
        capture["manifest"]["input_evidence"] = {
            "boundary": "injected-renderer-values", "supplied_values": len(config["input_writes"]) * len(trace["frames"]),
            "consumption": "unobserved", "sound_requested_frames": requested}
        return
    if policy == "glorb-volume":
        read_frames = {e["frame"] for e in events if e.get("operation") == "observe-entry"
                       and e.get("observer_id") == "audio-value-read"}
        boundary = "processed-volume-load"
    else:
        read_frames = {e["frame"] for e in events if e["kind"] == "adc"}
        boundary = "adc-read"
    settings = dict(profile["settings"])
    required_frames = []
    requested_count = 0
    forced_off_count = 0
    for frame in trace["frames"]:
        settings.update(frame.get("controls", {}))
        if policy == "hypercube-adc":
            active = (settings["fx"] == 2 or 120 <= settings["fx"] <= 150) and settings["brightness"] and not settings["psd"]
        else:
            active = settings["sound_reactive"]
        requested_count += bool(active)
        if policy == "exoy-adc":
            # The v2.1 selector stores force_music and effective music at
            # 0x3ffc653c/3d in the raw scene-state snapshot at 0x3ffc6530.
            state = bytes.fromhex(capture["frames"][frame["index"]]["state"]["scene-state"])
            require(len(state) == 80, "Exoy input policy requires the raw scene state")
            if state[12]:
                forced_off_count += bool(active and not state[13])
                active = bool(state[13])
        if active:
            required_frames.append(frame["index"])
    # Frames where a timer is not due can legitimately skip audio. Each separately
    # enabled window still needs a real read; a read in another window cannot count.
    start = None
    for pos, index in enumerate(required_frames):
        if start is None:
            start = index
        if pos + 1 == len(required_frames) or required_frames[pos + 1] != index + 1:
            require(not read_frames.isdisjoint(range(start, index + 1)),
                    f"no {boundary} observed in requested sound frames {start}..{index}")
            start = None
    capture["manifest"]["input_evidence"] = {
        "boundary": boundary, "sound_requested_frames": requested_count, "required_frames": len(required_frames),
        "guest_forced_off_frames": forced_off_count, "observed_frames": len(read_frames),
        "observed_in_required_frames": len(read_frames.intersection(required_frames)),
        "consumption": "observed" if read_frames else "no-reads"}
