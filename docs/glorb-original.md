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

## Signed microphone samples and FFT on the virtual ESP32-S3

`tycvl device glorb-audio` measures the deployed GLORB.1.3 application (`ba2decaa…`)
and WLED fleet builds 2611200 (`e73a39c5…`), 2611201 (`7305917c…`) and
2611202 (`0f5f59f8…`). The renderer above uses a different debug build. Supply
one or more standalone application images, an ESP32-S3 bootloader compatible with the 8 MiB flash layout, Espressif
QEMU with `esp32s3` machine support, its ROM directory, and Python-enabled
Xtensa GDB. The command checks the full application identity before execution.

```sh
tycvl device glorb-audio --firmware factory.bin fleet-2611200.bin fleet-2611201.bin fleet-2611202.bin \
  --bootloader bootloader-s3.bin --qemu /path/to/qemu-system-xtensa \
  --gdb /path/to/xtensa-esp32s3-elf-gdb --rom-dir /path/to/share/qemu \
  --out /path/to/private/pcm-spectrum.json
```

A local QEMU with networking disabled boots an ephemeral single-partition flash.
At application entry, GDB checks the mapped code and constants, sets up the
reader and FFT working memory, and invokes the real receiver and FFT instructions.
The driver boundary supplies signed 16-bit PCM at 22,050 Hz. Four consecutive
512-sample blocks retain filter history. The loud 86.13 Hz tone probes the filter
cutoff. A softer 689.06 Hz tone exercises signed values near zero. Both inputs
also run with the filter bypassed. A short read and a failed read must each
preserve a patterned, nonzero buffer.

The private JSON gives input and filtered-buffer hashes, measured time-domain
peaks, FFT magnitudes and dominant frequencies for every block. With a factory
image in the run, it also counts exact buffer and spectrum matches per case.
The old filter in 2611200 is a negative control. At 86.13 Hz its fourth-block
peak is about 1,389.69. The factory, 2611201 and 2611202 produce about 1,484.73, and all
four produce 2,048 in bypass. The factory and WLED ports use different FFT
window functions, so matching the filtered samples can yield different spectra.
The electrical PDM stream, driver decimation, application scheduling, AGC,
acoustic sensitivity and LED output are beyond this measurement.
