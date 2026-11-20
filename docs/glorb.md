# GLORB renderer setup

`tycvl device prepare glorb` builds the supplied recovered C++ renderer against
TycVirtualLab's small WLED compatibility boundary. It reads factory presets,
palettes, mapping and bus length from the supplied source repository. The public
package contains the host machinery and no recovered renderer body or palette.
A C++17 compiler is available in the pinned Nix development shell.

```sh
tycvl device prepare glorb --source-root /path/to/source --preset 2 --build-dir /path/to/experiments/host --out /path/to/experiments/profile.json
tycvl generate --profile /path/to/experiments/profile.json --kind silence --frames 600 --out /path/to/experiments/input.json
tycvl run /path/to/experiments/profile.json /path/to/experiments/input.json --out /path/to/experiments/run
tycvl view /path/to/experiments/run/capture.json --out /path/to/experiments/viewer.html
```

The expected repository layout is:

- `glorb/usermod/glorb_fx/glorb_fx.cpp`: supplied six-effect renderer.
- `glorb/factory-0.14.4-GLORB.1.3/presets.json`: preset settings.
- `glorb/factory-0.14.4-GLORB.1.3/palx.json`: gradient stops.
- `glorb/factory-0.14.4-GLORB.1.3/ledmap.json`: logical-to-bus mapping.
- `glorb/factory-0.14.4-GLORB.1.3/cfg.json`: bus dimensions and current settings.

The Python `build_host` and `build_profile` APIs also accept independent source,
map and palette inputs. `prepare_repository(..., executable=...)` reuses a prior
build across presets after checking its source and binary hashes. The compile
report records compiler identity, flags, source hashes and output hash. A changed
source cannot silently reuse its old binary.
The report also records the actual host pointer, long, size_t and floating-point
widths, character signedness, byte order and C library. The host ABI and math
runtime can differ from Xtensa; output equality requires independent comparison.
`build_host(..., sanitize=True)` enables address and undefined-behavior checks.
Leak detection is explicitly disabled in that mode so it also works under a
ptrace-based sandbox; this environment setting is recorded in the build report.

## Boundaries

The host preserves fixed-point palette expansion and lookup, per-pixel feedback,
segment step/call/auxiliary state, and masks during rendering. Reads from a hole
return black and writes to it are dropped. The native process checks its command
nonce and hashes the bytes it executed. Captures retain that binding, actual
processed-audio accesses and exact frame schedule.

Input is one scalar channel in `wled-volume-smth` units. Each frame supplies the
processed AudioReactive value. `sound_reactive` controls whether a renderer asks
for it. A value present in the trace is not claimed as consumed unless the actual
renderer calls the audio-data boundary. This is downstream of microphone sampling,
PDM decimation, FFT and AGC; a raw WAV is not interchangeable with this contract.

Frame controls accept partial updates to effect, speed, intensity, custom1/2/3,
colors, palette blend and sound-reactive toggle. Effect changes reset segment
history. A different palette requires its actual table in a new profile. There is
no implicit random palette lookup or synthetic microphone fallback.
The source adapter derives device uptime (`millis()`) from trace timestamps.
The `effect_time_ms` frame control sets WLED's effect clock (`strip.now`) to
the given millisecond value at that frame, as the WLED JSON `tb` command does.
Subsequent frames retain this offset while uptime continues. A value of zero
replays the clock reset on power-on. On/off transitions and fades still need
their own measurements.
Palette 0 is rejected because its color-gamma and video-scaling path is not
modeled. Only audio slot 0 is available; accessing another AudioReactive slot
raises an error instead of reading adjacent memory.

## Output stages

`logical` captures the renderer's raster, `mapped` captures its permutation into
the complete configured bus, and optional `driver` captures an explicit output
model. Factory preparation defaults to WLED 0.14 at internal brightness 255.
For a source renderer running on a WLED 16 port, choose the driver and bus
brightness when preparing the profile:

```sh
tycvl device prepare glorb --source-root "$SOURCE" --build-dir "$BUILD" --preset 11 \
  --driver-model wled16 --driver-brightness 45 --out "$PROFILE"
```

The WLED 16.0.1 model covers one ESP32-S3 RGB bus. Each frame writes all pixels
once after mapping. The digital driver scales each color with the video form of
`color_fade`. Global automatic brightness limiting estimates current from those
scaled bytes and can apply another video fade. A zero limit represents disabled
limiting. Per-bus limiting, WS2815 current estimation and RGBW require other
models. The capture's `output` state packs requested and effective brightness
(two uint8 values), estimated current and the configured limit (two little-endian
uint32 values). The controller allowance in the WLED 16 estimate is 120 mA.
[WLED 16 color arithmetic](https://github.com/wled/WLED/blob/v16.0.1/wled00/colors.cpp)
and [digital bus](https://github.com/wled/WLED/blob/v16.0.1/wled00/bus_manager.cpp).

For both versions, color gamma and conversion from user to internal brightness
happen upstream. A chip recording used for comparison must have matching gamma
or supply equivalently corrected RGB. The supplied factory metadata still
requires preset/default brightness 255 and brightness scale 100. An explicit
`--driver-brightness` changes the output stage for the run. Feedback uses the
renderer buffer. Lossy bus readback, timed crossfades and electrical transport
are outside this model. [WLED 0.14 output](https://github.com/wled/WLED/blob/v0.14.4/wled00/FX_fcn.cpp)
and [bus wrapper](https://github.com/wled/WLED/blob/v0.14.4/wled00/bus_wrapper.h).

Original-machine-code comparison remains distinct from the host's
`recovered-code` classification. Running every factory preset proves those source
paths execute under the declared host boundary; only a comparison against an
independent original runner can establish equal output for a particular scenario.
The [original GLORB setup](glorb-original.md) supplies that independent runner for
the identified S3 application, including observed processed-audio reads.
