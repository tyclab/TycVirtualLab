# Original GLORB renderer closure

`vfl.devices.glorb_original.prepare_original` creates matching original-firmware
and recovered-source profiles from an existing GLORB source profile. It accepts
the identified GLORB.1.3 ESP32-S3 debug application only, checks its SHA256, and
wraps its loadable segments in an ELF without changing their bytes. Supply the
firmware yourself; the source package contains neither that image nor effect
bodies, palettes or captured results.

```python
from vfl.devices.glorb import prepare_repository
from vfl.devices.glorb_original import prepare_original

source = prepare_repository(
    "/path/to/supplied/source", "/path/to/private/host-build", preset=2)
pair = prepare_original(
    "/path/to/supplied/original-app.bin", source,
    "/path/to/private/original-setup",
    compiler="/path/to/xtensa-esp32s3-elf-gcc",
    headless="/path/to/analyzeHeadless",
    limiter="/path/to/shared-emulator-limiter",
    hold_files=["/path/to/private/HOLD"])
print(pair["original_profile_path"], pair["source_profile_path"])
```

The compiler's matching `objcopy` and `nm` must be beside it. Preparation builds
only the authored memory-I/O fixture; it does not execute the original image.
Use a fresh private destination. Profiles pin local asset paths and are intended
for that machine. Build and execution reports remain private.

```sh
tycvl generate --profile /path/to/private/original-setup/original.profile.json --kind silence --frames 60 --out /path/to/private/input.json
tycvl run /path/to/private/original-setup/original.profile.json /path/to/private/input.json --out /path/to/private/original-run
tycvl run /path/to/private/original-setup/source.profile.json /path/to/private/input.json --out /path/to/private/source-run
tycvl compare /path/to/private/original-run/capture.json /path/to/private/source-run/capture.json
```

The original profile supports all six identified effect entrypoints. Original
effect instructions, palette lookup, color arithmetic, fade, blur, segment
geometry, ledmap access and BusManager dispatch execute in Ghidra. An authored
virtual Bus stores and returns RGB bytes. Original mapping therefore handles
holes during every pixel access, before feedback or blur. A non-substituting
observer records each requested effect entry.

The normal scheduler boundary supplies the declared frame time to `strip.now`,
increments the segment call count after rendering, and supplies `millis()` from
the same frame clock. Captures contain 120 logical and 120 mapped pixels plus
the 12-byte step/call/auxiliary state. The source counterpart uses this same
scope; the optional modeled `driver` bus is removed from the comparison pair.

For Colorwaves and Running, set `source["settings"]["sound_reactive"] = True`
before preparation. Trace values are processed `volumeSmth`, rounded explicitly
to binary32. Original `UsermodManager::getUMData` and the original floating-point
load execute against an authored AudioReactive data object. Separate observers
record the lookup and load. A supplied value alone does not prove a read. This
boundary permits arbitrary finite nonnegative scalar inputs within the profile
range, including fractional levels. It does not implement microphone PDM, FFT,
smoothing or AGC.

Preparation initializes a single 20-by-6 segment and the supplied 16-entry
palette. Boot, original palette loading, effect transitions, network services,
the physical bus driver and wire timing are outside this closure. Per-frame
controls are rejected by this profile; prepare another profile for a changed
setting. Rendering equality applies only to the particular input, schedule,
initialization, output buses and declared state that were compared. Running the
original functions is not evidence that the recovered source is already equal.
