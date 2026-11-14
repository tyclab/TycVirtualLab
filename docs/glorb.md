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
Palette 0 is rejected because its color-gamma and video-scaling path is not
modeled. Only audio slot 0 is available; accessing another AudioReactive slot
raises an error instead of reading adjacent memory.

## Output stages

`logical` captures the renderer's raster, `mapped` captures its permutation into
the complete configured bus, and optional `driver` captures an explicit output
model. Factory preparation enables the WLED 0.14 RGB current-limit/brightness
model at internal brightness 255. The captured `output` state records requested
and limited brightness, estimated current and configured limit. This model keeps
renderer feedback separate from output scaling and does not claim to execute the
original bus driver or electrical transport.
Factory preparation requires preset/default brightness 255 and brightness scale
100; other factory brightness settings fail instead of being silently ignored.

No whole-frame gamma is applied in that WLED 0.14 stage. Palette/color gamma and
user-slider conversion are upstream operations; the driver's brightness parameter
is already the internal bus value. The [WLED 0.14 output implementation](https://github.com/wled/WLED/blob/v0.14.4/wled00/FX_fcn.cpp)
and [bus wrapper](https://github.com/wled/WLED/blob/v0.14.4/wled00/bus_wrapper.h)
identify the current-estimation and luminance boundaries. Frame output at lowered
brightness is a model and does not include lossy bus-buffer readback or timed
crossfades.

Original-machine-code comparison remains distinct from the host's
`recovered-code` classification. Running every factory preset proves those source
paths execute under the declared host boundary; only a comparison against an
independent original runner can establish equal output for a particular scenario.
The [original GLORB setup](glorb-original.md) supplies that independent runner for
the identified S3 application, including observed processed-audio reads.
