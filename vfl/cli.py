"""TycVirtualLab command-line interface. Experiment writes require explicit paths."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .model import (LabError, load_json, number, private_path, validate_capture,
                    validate_profile, validate_trace, write_json)


def parser():
    p = argparse.ArgumentParser(prog="tycvl", description="TycVirtualLab — virtual firmware capture, comparison and offline visualization")
    p.add_argument("--version", action="version", version=f"TycVirtualLab {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("profiles", help="list bundled synthetic device demonstrations")
    d = sub.add_parser("doctor", help="check a local profile and its declared assets")
    d.add_argument("profile")
    g = sub.add_parser("generate", help="generate a deterministic seven-band input trace")
    g.add_argument("--kind", choices=["silence", "steps", "ramp", "impulses", "music-noise"], default="music-noise")
    g.add_argument("--frames", type=int, default=300)
    g.add_argument("--frame-us", type=int, default=16000)
    g.add_argument("--channels", type=int, default=7)
    g.add_argument("--maximum", type=int, default=1023)
    g.add_argument("--seed", type=int, default=1)
    g.add_argument("--out", required=True)
    for name in ("wav", "tone"):
        a = sub.add_parser(name, help="convert PCM to input blocks or approximate MSGEQ7 bands")
        if name == "wav":
            a.add_argument("input")
            a.add_argument("--channel", default="mean", help="mean or zero-based channel number")
        else:
            a.add_argument("--frequency", type=float, action="append", default=None)
            a.add_argument("--seconds", type=float, default=1.0)
            a.add_argument("--sample-rate", type=int, default=48000)
            a.add_argument("--amplitude", type=float, default=0.5)
        a.add_argument("--mode", choices=["bands", "pcm"], default="bands")
        a.add_argument("--frame-us", type=int, default=16000)
        a.add_argument("--block-samples", type=int, default=480)
        a.add_argument("--seed", type=int, default=1)
        a.add_argument("--out", required=True)
    v = sub.add_parser("validate", help="validate a profile, trace or capture")
    v.add_argument("path")
    r = sub.add_parser("run", help="run a complete scenario into a fresh private directory")
    r.add_argument("profile")
    r.add_argument("input")
    r.add_argument("--out", required=True)
    c = sub.add_parser("compare", help="compare experiment identity, RGB, state and optional read logs")
    c.add_argument("left")
    c.add_argument("right")
    c.add_argument("--rgb-only", action="store_true")
    c.add_argument("--events", action="store_true")
    c.add_argument("--unverified", action="store_true", help="explicitly compare standalone imports without completed-run verification")
    c.add_argument("--out")
    vr = sub.add_parser("verify-run", help="verify a completed run and its capture hash")
    vr.add_argument("path")
    v = sub.add_parser("view", help="export a private, standalone offline HTML viewer")
    v.add_argument("capture", nargs="?", help="omit to create an empty local-file viewer")
    v.add_argument("--out", required=True)
    a = sub.add_parser("audit-source", help="check the source-only sharing boundary")
    a.add_argument("root", nargs="?", default=str(Path(__file__).resolve().parent.parent))
    vs = sub.add_parser("verify-source", help="verify an exported source manifest and all source hashes")
    vs.add_argument("root", nargs="?", default=str(Path(__file__).resolve().parent.parent))
    e = sub.add_parser("export-source", help="make a deterministic source-only archive")
    e.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    e.add_argument("--out", required=True)
    i = sub.add_parser("inspect-image", help="inspect an image without executing or flashing it")
    i.add_argument("path")
    i.add_argument("--format", choices=["auto", "esp32", "esp8266", "elf"], default="auto")
    i.add_argument("--out")
    return p


def _emit(value, output=None):
    if output:
        write_json(private_path(output), value)
    print(json.dumps(value, indent=2, allow_nan=False))


def _trace_output(trace, path):
    validate_trace(trace)
    target = private_path(path)
    if target.exists():
        raise LabError("input output already exists; choose a fresh path")
    write_json(target, trace)
    _emit({"trace": str(target), "frames": len(trace["frames"]), "input": trace["input"], "provenance": trace["provenance"]})


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "profiles":
            rows = []
            for path in sorted(Path(__file__).with_name("profiles").glob("*.json")):
                profile = validate_profile(load_json(path))
                rows.append({"id": profile["id"], "description": profile.get("description", ""),
                             "execution_kind": profile["backend"].get("execution_kind", "synthetic")})
            _emit(rows)
        elif args.command == "doctor":
            from .runner import doctor
            result = doctor(args.profile)
            _emit(result)
            return 0 if result["ready"] else 2
        elif args.command == "generate":
            from .stimuli import generate_trace
            _trace_output(generate_trace(args.frames, args.frame_us, channels=args.channels,
                                        maximum=args.maximum, kind=args.kind, seed=args.seed), args.out)
        elif args.command in {"wav", "tone"}:
            from .audio import MAX_PCM_SAMPLES, read_wav, synthesize, pcm_to_trace, to_bands_trace
            if args.command == "wav":
                channel = args.channel if args.channel == "mean" else int(args.channel)
                pcm = read_wav(args.input, channel=channel)
            else:
                frequencies = args.frequency or [1000]
                number(args.seconds, "seconds")
                if not 0 < args.seconds <= MAX_PCM_SAMPLES / max(1, args.sample_rate):
                    raise LabError("seconds must be positive and within the PCM sample limit")
                pcm = synthesize("mix" if len(frequencies) > 1 else "sine", duration_us=int(args.seconds*1_000_000),
                                 sample_rate_hz=args.sample_rate, frequencies_hz=frequencies,
                                 amplitude=args.amplitude, seed=args.seed)
            if args.mode == "pcm":
                trace = pcm_to_trace(pcm, args.block_samples, seed=args.seed)
            else:
                if args.frame_us <= 0:
                    raise LabError("frame-us must be positive")
                duration = len(pcm.samples) * 1_000_000 // pcm.sample_rate_hz
                times = range(0, duration + 1, args.frame_us)
                trace = to_bands_trace(pcm, times, seed=args.seed)
            _trace_output(trace, args.out)
        elif args.command == "validate":
            data = load_json(args.path)
            schema = data.get("schema") if isinstance(data, dict) else None
            validate = {"vfl.trace.v1": validate_trace, "vfl.profile.v1": validate_profile,
                        "vfl.capture.v1": validate_capture}.get(schema) if isinstance(schema, str) else None
            if not validate:
                raise LabError("unsupported schema")
            validate(data)
            _emit({"valid": True, "schema": data["schema"]})
        elif args.command == "run":
            from .runner import run_capture
            output = run_capture(args.profile, args.input, args.out)
            result = load_json(output)
            _emit({"capture": str(output), "frames": len(result["frames"]),
                   "execution_kind": result["manifest"]["execution_kind"],
                   "limitations": result["manifest"]["limitations"]})
        elif args.command == "compare":
            from .compare import compare
            from .runner import load_completed_capture
            loader = load_json if args.unverified else load_completed_capture
            result = compare(loader(args.left), loader(args.right),
                             include_state=not args.rgb_only, include_events=args.events)
            result["verification"] = "unverified" if args.unverified else "completed-run"
            _emit(result, args.out)
            return 0 if result["verdict"] == "equal" else 1
        elif args.command == "verify-run":
            from .runner import load_completed_capture
            from .model import digest
            capture = load_completed_capture(args.path)
            _emit({"schema": "vfl.run-verification.v1", "verified": True,
                   "capture_sha256": digest(capture), "frames": len(capture["frames"]),
                   "scope": "Local completed-run status, hash and request consistency; not signed attestation"})
        elif args.command == "view":
            from .viewer import export_html
            data = validate_capture(load_json(args.capture)) if args.capture else None
            target = private_path(args.out)
            if target.exists():
                raise LabError("viewer output already exists")
            target.parent.mkdir(parents=True, exist_ok=True)
            export_html(data, target)
            _emit({"viewer": str(target), "network": "disabled", "contains_private_capture": bool(data)})
        elif args.command == "audit-source":
            from .release import audit
            result = audit(args.root)
            _emit(result)
            return 0 if result["clean"] else 2
        elif args.command == "verify-source":
            from .release import verify_source
            result = verify_source(args.root)
            _emit(result)
            return 0 if result["clean"] else 2
        elif args.command == "export-source":
            from .release import export_source
            result = export_source(args.root, args.out)
            _emit({"archive": str(Path(args.out).resolve()), "source_files": len(result["files"])})
        elif args.command == "inspect-image":
            from .firmware import inspect_image
            _emit(inspect_image(args.path, format=args.format), args.out)
        return 0
    except (LabError, ValueError, OSError) as exc:
        print(f"tycvl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
