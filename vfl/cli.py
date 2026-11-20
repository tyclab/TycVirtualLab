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
    from .device_cli import add_parser
    add_parser(sub)
    from .board import add_parser as add_board_parser
    add_board_parser(sub)
    sub.add_parser("profiles", help="list bundled synthetic device demonstrations")
    calibration = sub.add_parser("calibration", help="fit and validate a measured tone-response model")
    cal = calibration.add_subparsers(dest="calibration_action", required=True)
    fit = cal.add_parser("fit", help="fit JSON containing observations, baseline and input_peak")
    fit.add_argument("observations")
    fit.add_argument("--out", required=True)
    evaluate = cal.add_parser("evaluate", help="evaluate against independent tone observations")
    evaluate.add_argument("profile")
    evaluate.add_argument("observations", help="JSON array of held-out observations")
    evaluate.add_argument("--out")
    d = sub.add_parser("doctor", help="check a local profile and its declared assets")
    d.add_argument("profile")
    g = sub.add_parser("generate", help="generate a deterministic seven-band input trace")
    g.add_argument("--kind", choices=["silence", "steps", "ramp", "impulses", "music-noise"], default="music-noise")
    g.add_argument("--frames", type=int, default=300)
    g.add_argument("--frame-us", type=int, default=16000)
    g.add_argument("--channels", type=int)
    g.add_argument("--maximum", type=int)
    g.add_argument("--profile", help="derive scalar/band channel count, range and units from a device profile")
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
        a.add_argument("--mode", choices=["bands", "pcm", "exoy-adc"], default="bands")
        a.add_argument("--frame-us", type=int, default=16000)
        a.add_argument("--block-samples", type=int, default=480)
        a.add_argument("--seed", type=int, default=1)
        a.add_argument("--calibration", help="measured tone-response profile for band conversion")
        a.add_argument("--adc-full-scale-mv", type=float, help="explicit firmware ADC full-scale voltage")
        a.add_argument("--adc-maximum", type=int, help="calibrated ADC maximum count (default 1023)")
        a.add_argument("--window-size", type=int, help="calibrated Hann window samples (default 8192)")
        a.add_argument("--decay-per-read", type=float, help="explicit calibrated hold decay (default 0.10, unmeasured)")
        a.add_argument("--energy-tolerance", type=float, help="calibrated spectral guard threshold (default 0.01)")
        a.add_argument("--calibration-provenance", choices=["digest", "embedded"], help="digest by default; embedded includes private fitted coefficients")
        a.add_argument("--allow-censored", action="store_true")
        a.add_argument("--allow-out-of-range", action="store_true")
        a.add_argument("--adc-gain", type=float, help="ADC counts per normalized PCM sample")
        a.add_argument("--adc-offset", type=float, help="ADC count at zero PCM input")
        a.add_argument("--adc-tail", choices=["reject", "pad-silence"], default="reject")
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
    c.add_argument("--repeat", action="store_true",
                   help="both captures come from one implementation: a repeatability check, not a comparison of two")
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
        if args.command == "device":
            from .device_cli import execute
            result = execute(args)
            _emit(result)
            if args.device_action == "coverage" and result.get("failed", 0):
                return 1
        elif args.command == "board":
            from .board import run_board
            path = run_board(args)
            _emit({"capture": str(path), "execution_kind": "original-firmware", "boot": "qemu-esp32"})
        elif args.command == "calibration":
            from .calibration import evaluate_tones, fit_tone_profile
            observations = load_json(args.observations)
            if args.calibration_action == "fit":
                if (not isinstance(observations, dict) or observations.get("schema") != "vfl.tone-observations.v1"
                        or not {"observations", "baseline", "input_peak"} <= set(observations)):
                    raise LabError("fit input requires schema vfl.tone-observations.v1, observations, baseline and input_peak")
                target = private_path(args.out)
                if target.exists():
                    raise LabError("calibration output already exists")
                result = fit_tone_profile(observations["observations"], baseline=observations["baseline"],
                            input_peak=observations["input_peak"], units=observations.get("units", "millivolts"),
                            provenance=observations.get("provenance"))
                write_json(target, result)
                _emit({"profile": str(target), "channels": result["channels"], "units": result["units"]})
            else:
                _emit(evaluate_tones(load_json(args.profile), observations), args.out)
        elif args.command == "profiles":
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
            contract = None
            if args.profile:
                from .runner import resolve_profile
                contract = resolve_profile(args.profile)[1]["input"]
                if contract["kind"] not in {"bands", "scalar"} or contract["minimum"] != 0 or type(contract["maximum"]) is not int:
                    raise LabError("generated device input requires scalar/bands with an integer range starting at zero")
                if (args.channels is not None and args.channels != contract["channels"]) or (args.maximum is not None and args.maximum != contract["maximum"]):
                    raise LabError("channel/range override differs from profile")
            trace = generate_trace(args.frames, args.frame_us,
                    channels=contract["channels"] if contract else (args.channels if args.channels is not None else 7),
                    maximum=contract["maximum"] if contract else (args.maximum if args.maximum is not None else 1023),
                    kind=args.kind, seed=args.seed)
            if contract:
                trace["input"] = contract
                trace["provenance"]["contract_source"] = "supplied-device-profile"
            _trace_output(trace, args.out)
        elif args.command in {"wav", "tone"}:
            from .audio import MAX_PCM_SAMPLES, read_wav_stream, synthesize, pcm_to_trace, to_bands_trace
            if args.calibration:
                if args.mode != "bands" or args.adc_full_scale_mv is None:
                    raise LabError("--calibration requires --mode bands and explicit --adc-full-scale-mv")
            elif (any(value is not None for value in (args.adc_full_scale_mv, args.adc_maximum,
                  args.window_size, args.decay_per_read, args.energy_tolerance, args.calibration_provenance))
                  or args.allow_censored or args.allow_out_of_range):
                raise LabError("calibration options require --calibration")
            if args.command == "wav":
                channel = args.channel if args.channel == "mean" else int(args.channel)
                pcm = read_wav_stream(args.input, channel=channel)
            else:
                frequencies = args.frequency or [1000]
                number(args.seconds, "seconds")
                if not 0 < args.seconds <= MAX_PCM_SAMPLES / max(1, args.sample_rate):
                    raise LabError("seconds must be positive and within the PCM sample limit")
                pcm = synthesize("mix" if len(frequencies) > 1 else "sine", duration_us=int(args.seconds*1_000_000),
                                 sample_rate_hz=args.sample_rate, frequencies_hz=frequencies,
                                 amplitude=args.amplitude, seed=args.seed)
            if args.mode == "exoy-adc":
                if args.adc_gain is None or args.adc_offset is None:
                    raise LabError("exoy-adc requires explicit --adc-gain and --adc-offset")
                from .audio import pcm_to_adc_trace
                from .devices.exoy import ADC_INPUT
                trace = pcm_to_adc_trace(pcm, gain=args.adc_gain, offset=args.adc_offset,
                        samples_per_frame=ADC_INPUT["channels"], maximum=ADC_INPUT["maximum"],
                        units=ADC_INPUT["units"], frame_us=args.frame_us, seed=args.seed, tail=args.adc_tail)
            elif args.adc_gain is not None or args.adc_offset is not None or args.adc_tail != "reject":
                raise LabError("ADC window options require --mode exoy-adc")
            elif args.mode == "pcm":
                trace = pcm_to_trace(pcm, args.block_samples, seed=args.seed)
            else:
                if args.frame_us <= 0:
                    raise LabError("frame-us must be positive")
                duration = len(pcm.samples) * 1_000_000 // pcm.sample_rate_hz
                times = range(0, duration + 1, args.frame_us)
                if args.calibration:
                    from .calibration import to_calibrated_trace
                    trace = to_calibrated_trace(pcm, times, load_json(args.calibration), seed=args.seed,
                            adc_full_scale_mv=args.adc_full_scale_mv, allow_censored=args.allow_censored,
                            allow_out_of_range=args.allow_out_of_range,
                            adc_maximum=args.adc_maximum if args.adc_maximum is not None else 1023,
                            window_size=args.window_size if args.window_size is not None else 8192,
                            decay_per_read=args.decay_per_read if args.decay_per_read is not None else .10,
                            energy_tolerance=args.energy_tolerance if args.energy_tolerance is not None else .01,
                            provenance_mode=args.calibration_provenance or "digest")
                else:
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
            if args.repeat:
                if Path(args.left).resolve() == Path(args.right).resolve():
                    raise LabError("repeat comparison needs two capture files, not one file twice")
            result = compare(loader(args.left), loader(args.right),
                             include_state=not args.rgb_only, include_events=args.events, repeat=args.repeat)
            result["verification"] = "unverified" if args.unverified else "completed-run"
            _emit(result, args.out)
            return {"equal": 0, "different": 1}.get(result["verdict"], 3)
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
