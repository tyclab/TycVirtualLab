"""Concrete device setup commands; local firmware and results remain external."""

from pathlib import Path
import sys

from .model import LabError, load_json, private_path, require, write_json


def add_parser(sub):
    parser = sub.add_parser("device", help="prepare and exercise supported real device adapters")
    actions = parser.add_subparsers(dest="device_action", required=True)
    actions.add_parser("list", help="list real execution adapters and their boundaries")
    effects = actions.add_parser("effects", help="list supported selectors")
    effects.add_argument("device", choices=["hypercube", "exoy-one", "glorb"])
    prepare = actions.add_parser("prepare", help="create a profile from local device assets")
    targets = prepare.add_subparsers(dest="device", required=True)
    hyper = targets.add_parser("hypercube")
    _hypercube_assets(hyper)
    hyper.add_argument("--out", required=True)
    exoy = targets.add_parser("exoy-one")
    _hypercube_assets(exoy, rom=False)
    exoy.add_argument("--rom", help="optional compatible ESP32 ROM ELF for original ROM arithmetic")
    exoy.add_argument("--out", required=True)
    glorb = targets.add_parser("glorb")
    glorb.add_argument("--source-root", required=True, help="repository containing glorb/usermod and factory assets")
    glorb.add_argument("--build-dir", required=True)
    glorb.add_argument("--preset", type=int, default=2)
    glorb.add_argument("--driver-model", choices=["wled14", "wled16"], default="wled14",
                       help="RGB output model for source execution (default: wled14)")
    glorb.add_argument("--driver-brightness", type=int, default=255,
                       help="internal RGB bus brightness for source execution (0–255)")
    glorb.add_argument("--compiler")
    glorb.add_argument("--original-image", help="execute original GLORB machine code using this supported S3 image")
    glorb.add_argument("--original-compiler", help="Xtensa ESP32-S3 GCC used to build the authored memory bus")
    glorb.add_argument("--headless")
    glorb.add_argument("--limiter")
    glorb.add_argument("--hold-file", action="append", default=[])
    glorb.add_argument("--timeout-s", type=int, default=1200)
    glorb.add_argument("--out", required=True)
    audio = actions.add_parser("glorb-audio", help="measure signed PCM, filter and spectrum in supported GLORB S3 applications")
    audio.add_argument("--firmware", nargs="+", required=True, help="identified standalone application images")
    audio.add_argument("--bootloader", required=True, help="compatible ESP32-S3 bootloader binary")
    audio.add_argument("--qemu", required=True, help="Espressif qemu-system-xtensa")
    audio.add_argument("--gdb", required=True, help="Python-enabled Xtensa GDB")
    audio.add_argument("--rom-dir", required=True, help="QEMU directory containing the ESP32-S3 ROM")
    audio.add_argument("--timeout-s", type=int, default=120, help="timeout per application")
    audio.add_argument("--out", required=True, help="fresh private result JSON")
    coverage = actions.add_parser("coverage", help="run original selector cases with fresh state")
    coverage.add_argument("device", choices=["hypercube", "exoy-one"])
    _hypercube_assets(coverage)
    coverage.add_argument("--case", action="append", dest="case_ids")
    coverage.add_argument("--frames", type=int, help="frames per case (default: HyperCube20, Exoy4)")
    coverage.add_argument("--batch-size", type=int, default=8)
    coverage.add_argument("--out", required=True)


def _hypercube_assets(parser, *, rom=True):
    image = parser.add_mutually_exclusive_group(required=True)
    image.add_argument("--elf")
    image.add_argument("--firmware", help="supported original application image")
    parser.add_argument("--build-dir", help="fresh external directory for generated ELF")
    if rom:
        parser.add_argument("--rom", required=True)
    parser.add_argument("--settings", help="JSON object of device settings")
    parser.add_argument("--input", help="trace whose scheduled controls must be compiled into the profile")
    parser.add_argument("--headless")
    parser.add_argument("--limiter")
    parser.add_argument("--hold-file", action="append", default=[])
    parser.add_argument("--timeout-s", type=int, default=1800)
    parser.add_argument("--state-encoding", choices=["bytes", "sha256"], default="sha256")


def execute(args):
    if args.device_action == "glorb-audio":
        from .devices import glorb_audio
        return glorb_audio.execute(args)
    from .devices import glorb, hypercube
    from .devices import exoy
    modules = {"hypercube": hypercube, "glorb": glorb, "exoy-one":exoy}
    if args.device_action == "list":
        rows = []
        for module in modules.values():
            row = dict(module.device_info())
            if "effects" in row:
                row["effect_count"] = len(row.pop("effects"))
            row.pop("boundaries", None)
            rows.append(row)
        return rows
    require(args.device in modules, "device adapter is not installed")
    module = modules[args.device]
    if args.device_action == "effects":
        return module.effect_inventory() if hasattr(module, "effect_inventory") else module.device_info()["effects"]
    target = private_path(args.out)
    require(not target.exists(), "device output already exists; choose a fresh path")
    if args.device == "glorb":
        require(bool(args.original_image) == bool(args.original_compiler), "original GLORB execution requires both --original-image and --original-compiler")
        require(not args.original_image or (args.driver_model == "wled14" and args.driver_brightness == 255),
                "original GLORB routine execution has no driver output stage")
        profile = glorb.prepare_repository(args.source_root, args.build_dir, preset=args.preset, compiler=args.compiler,
                                           driver_model=args.driver_model, driver_brightness=args.driver_brightness)
        if args.original_image:
            from .devices.glorb_original import prepare_original
            prepared = prepare_original(args.original_image, profile, Path(args.build_dir)/"original",
                        compiler=args.original_compiler, headless=args.headless, limiter=args.limiter,
                        hold_files=args.hold_file, timeout_s=args.timeout_s)
            profile = prepared["original_profile"]
    else:
        elf = args.elf
        if args.firmware:
            require(args.build_dir is not None, "--firmware requires --build-dir")
            directory = private_path(args.build_dir)
            require(not directory.exists(), "device build directory already exists")
            directory.mkdir(parents=True, mode=0o700)
            elf = directory / "application.elf"
            module.prepare_image(args.firmware, elf)
        options = dict(settings=load_json(args.settings) if args.settings else None,
                       trace=load_json(args.input) if args.input else None,
                       headless=args.headless, limiter=args.limiter, hold_files=args.hold_file,
                       timeout_s=args.timeout_s, state_encoding=args.state_encoding)
        if args.device_action == "coverage":
            def progress(result):
                print(f"{result.get('id', 'case')}: {result.get('status', 'processed')}", file=sys.stderr, flush=True)
            return module.run_coverage(elf, args.rom, target, case_ids=args.case_ids,
                                      frames=args.frames if args.frames is not None else (20 if args.device=="hypercube" else 4),
                                      batch_size=args.batch_size, progress=progress, **options)
        if args.device == "hypercube":
            profile = hypercube.build_profile(elf, args.rom, **options)
        else:
            profile = module.build_profile(elf, rom=args.rom, **options)
    write_json(target, profile)
    return {"profile": str(target), "id": profile["id"],
            "execution_kind": profile["backend"]["execution_kind"],
            "execution_scope": "routine-diagnostic" if "ghidra" in profile["backend"]["options"] else "host-renderer"}
