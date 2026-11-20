# TycVirtualLab

TycVirtualLab runs reproducible firmware experiments, captures LED buffers and
internal state, compares independent implementations, and displays captures in an
offline viewer. Its command is `tycvl`.

The shareable project includes device setup for HyperCube, Exoy ONE and GLORB,
version-pinned address maps, input adapters, execution engines and validation tools.
Firmware blobs, externally supplied renderer source, recordings, fitted calibration
coefficients and experiment results remain outside this repository. The MIT license
covers this project's original setup code, not those external inputs.

Use `tycvl device list` to inspect real execution adapters and `tycvl device effects
hypercube` to list selectors. The `*-demo` profiles are separate synthetic fixtures.

## Device setup

Supply local assets; generated profiles refer to them by path and SHA256. HyperCube
accepts its supported application image and ROM:

```sh
tycvl device prepare hypercube --firmware /path/to/application.bin --rom /path/to/rom.bin --build-dir ../TycVirtualLab-private/hypercube-image --out ../TycVirtualLab-private/hypercube.json
tycvl generate --frames 300 --kind music-noise --out ../TycVirtualLab-private/input.json
tycvl run ../TycVirtualLab-private/hypercube.json ../TycVirtualLab-private/input.json --out ../TycVirtualLab-private/hypercube-run
```

`--settings` accepts a JSON settings object; `--input` compiles scheduled controls
into the original-code profile. `--headless`, `--limiter` and repeated `--hold-file`
configure the local emulator and resource coordination. `device coverage hypercube`
executes selector cases with independent initialization and retains each failure.

GLORB builds a native host around the supplied recovered C++ renderer, with the
factory palettes and LED map loaded from the same source repository:

```sh
tycvl device prepare glorb --source-root /path/to/renderer-repository --preset 2 --build-dir ../TycVirtualLab-private/glorb-build --out ../TycVirtualLab-private/glorb.json
tycvl generate --profile ../TycVirtualLab-private/glorb.json --kind silence --frames 600 --out ../TycVirtualLab-private/glorb-input.json
tycvl run ../TycVirtualLab-private/glorb.json ../TycVirtualLab-private/glorb-input.json --out ../TycVirtualLab-private/glorb-run
```

This profile takes one scalar `wled-volume-smth` channel, whose units and range
must match its profile. It records actual renderer output and segment state, plus a separately labeled
model of WLED 0.14 current limiting and bus brightness. The
public host boundary preserves masked-cell reads and writes, integer palette
arithmetic and frame history. Exoy uses `device prepare exoy-one` with its own
application image; inspect its selector inventory and declared execution boundary.
Use `generate --profile` for each device to retain its input units and channel count.

GLORB also has an [original ESP32-S3 firmware backend](docs/glorb-original.md),
paired with the source host for byte/state comparisons. Exoy has a separate
[full-board QEMU backend](docs/board.md) that boots a supplied flash copy and
captures original scene and driver buffers. These paths declare their hardware
stand-ins and clock models explicitly.

See [device details](docs/devices.md) and the [measured audio workflow](docs/calibration.md).
All commands can also be invoked as `python3 -m vfl` from a checkout.

## Framework quick start

Linux (including WSL2) and Python 3.11 or newer are required; the core has no
third-party Python dependencies. Process groups and resource locks use Unix APIs;
native Windows execution is not supported. From this checkout:

```sh
python3 -m vfl profiles
python3 -m vfl generate --kind music-noise --frames 300 --out ../TycVirtualLab-private/input.json
python3 -m vfl run hypercube-demo ../TycVirtualLab-private/input.json --out ../TycVirtualLab-private/run-a
python3 -m vfl run hypercube-demo ../TycVirtualLab-private/input.json --out ../TycVirtualLab-private/run-b
python3 -m vfl compare ../TycVirtualLab-private/run-a/capture.json ../TycVirtualLab-private/run-b/capture.json --events --repeat
python3 -m vfl view ../TycVirtualLab-private/run-a/capture.json --out ../TycVirtualLab-private/viewer.html
```

Open the resulting HTML locally. It embeds its data and assets, makes no network
requests, and needs no account or server. The capture may also be loaded with its
file picker. An exported viewer contains the capture, so it remains private.

The `hypercube-demo`, `exoy-one-demo`, and `glorb-demo` profiles run an authored
synthetic state machine. They demonstrate different geometry and masking needs;
they are **not vendor firmware emulators**. Device details and the boundaries of
these demonstrations are in [docs/devices.md](docs/devices.md).

On Nix:

```sh
nix develop --command python -m unittest discover -s tests -v
mkdir -p ../TycVirtualLab-private
nix build --out-link ../TycVirtualLab-private/nix-result
nix run . -- profiles
nix develop .#emulation --command ghidra-analyzeHeadless
```

Keep the Nix output link outside this checkout: source auditing rejects symlinks.
The flake pins its toolchain. The optional emulation shell supplies Ghidra; the
framework itself does not need it. No system package installation is required.
Installing this Python package into a virtual environment also provides `tycvl`.

## Inputs and execution

An experiment has a versioned profile, an input trace, an execution adapter, and a
fresh private output directory. All frame timestamps use microseconds. Input kind,
units, range, channel count, random seed and clock policy are explicit.

- **Bands:** integer ADC values. The firmware's own filtering and gain processing
  can execute after this boundary.
- **PCM:** normalized mono sample blocks with an explicit sample rate and block
  size. A device adapter must identify the correct firmware sample-input boundary.
- **WAV to bands:** a separate approximate seven-filter/peak-envelope model. It
  includes read-dependent decay and declares its parameters and omissions. A fitted
  measured-path model is selected with `--calibration` and explicit ADC scaling.

```sh
python3 -m vfl tone --frequency 160 --frequency 1000 --seconds 2 --out ../TycVirtualLab-private/tones.json
python3 -m vfl wav input.wav --mode bands --out ../TycVirtualLab-private/bands.json
python3 -m vfl wav input.wav --mode pcm --out ../TycVirtualLab-private/pcm.json
python3 -m vfl doctor /path/to/private/device-profile.json
python3 -m vfl run /path/to/private/device-profile.json /path/to/private/input.json --out /path/to/private/new-run
```

For WAV input, integer PCM 8/16/24/32-bit is supported. Choose a channel explicitly
or use the documented mean downmix. The seven-band model requires a sample rate
above 32 kHz. Existing captures can inform a private calibration configuration;
they are never bundled into the source distribution.

The public external-process interface can host Ghidra, QEMU, a recovered native
renderer, or another execution engine without pretending those engines already
model a particular device. The included `tycvl-ghidra` adapter executes configured
Xtensa call0 and register-window routines, with images supplied externally;
see [docs/ghidra.md](docs/ghidra.md). The included Exoy board adapter uses QEMU and
Xtensa GDB; additional devices need their own board integration.
Reusable device adapters provide loading, memory maps, initialization, entry
points, peripheral hooks and output conversion. Local profiles select their assets
and settings. The included
strict `vfl.hsemu` parser supports an existing D/R/E/X dump protocol without
embedding firmware addresses. See [docs/adapters.md](docs/adapters.md).

## What a comparison proves

New captures also identify the execution boundary with `execution_scope`. `routine-diagnostic` runs selected original instructions with declared hooks. `board-diagnostic` runs the QEMU board with the debugger and watchdog settings recorded in its manifest. `host-renderer` executes compiled renderer source. A scheduled Ghidra frame time and the board's observed CCOUNT are distinct clock sources. Ghidra records actual frame clock reads and the audio boundary observed. The recorded scope describes execution only. Historical captures retain their original bytes and hashes.

Capture manifests distinguish `original-firmware`, `recovered-code`, `synthetic`,
and `replay`. Execution kind is an explicit adapter declaration checked against
its profile, not certification that arbitrary external code tells the truth.

Before comparing, TycVirtualLab checks experiment identity: inputs, profile ID,
settings, geometry and bus layout. It compares every RGB byte and, by default,
the captured state; `--events` additionally compares recorded reads. `--rgb-only`
explicitly narrows the comparison when state is unavailable. The report identifies
the first differing frame, pixel, channel, state byte or event.

By default, `compare` requires completed run evidence and verifies the capture
hash recorded by the runner. Either a run directory or its `capture.json` may be
supplied. `verify-run` performs that integrity check separately. Standalone
captures and raw imports require `compare --unverified`; that result is labeled
unverified and cannot establish that a run completed successfully.

The verdict is `different`, `equal` or `inconclusive` (exit codes 1, 0, 3). `equal` is
given only when the comparison carries information: at least one frame has light in
it, the two captures come from two implementations (backend, tool version, tool
source or runtime assets differ), and no side logged reads of an input (`adc`,
`clock`, `rng`) that the other, able to log them, never read. Otherwise the verdict
is `inconclusive` with its reasons (`no-frames`, `all-black`, `same-capture`,
`same-implementation`, `input-use-adc`, ...). Two runs of one implementation are a
repeatability check and must be declared with `--repeat`; `equal` then says only
that the implementation repeats itself. Every report carries the counts it rests on
(`information`: frames, frames with light, distinct frames, reads per side).

A match is conditional on the supplied inputs and initialization. It does not
establish a real microphone response, electrical integrity, wall-clock scheduling,
or accurate physical LED pulses. Substituted RNG/time sources and omitted hardware
must be listed in a capture's limitations. A backend without real read logging
must report that capability as false.

## Local execution and privacy

Profiles contain executable argument lists and are trusted local code. Review a
profile before running it. TycVirtualLab does not sandbox an emulator or a hostile
firmware image; use an OS/container boundary when needed. Commands run without a
shell, with a bounded timeout, process-group cleanup, log limits, optional shared
resource locks, and an optional HOLD file. HOLD is checked before execution and
while waiting for a lock; it is not a live cancellation switch.

TERM and HUP trigger process-group cleanup, and child processes inherit the
resource lock. The external runner API must be called from the main Python
thread so it can install temporary signal handlers. SIGKILL cannot trigger
cleanup; a surviving backend retains its inherited lock until it exits.
Descendants that start their own sessions escape process-group cleanup. Use an
external supervisor or cgroup when forced termination must stop every process.
Backend configuration keys and types are validated; unknown options are rejected.

Each external request carries a fresh nonce and input/configuration hashes. The
adapter must echo them, preventing a stale capture from silently becoming a fresh
result. Declared assets are hashed before and after execution. A failed run keeps
its diagnostic files and failed status, but does not produce a final accepted
capture. Choose a new directory for each run.

The CLI refuses experiment writes inside the source checkout. Source sharing uses
an allowlist and rejects private artifact names, firmware blobs, result schemas,
symlinks and recognizable private paths/keys. This is a release check, not a
universal secret detector; review the archive before publication.

```sh
python3 -m vfl audit-source
python3 -m vfl export-source --out ../TycVirtualLab-releases/TycVirtualLab-source.tar.gz
python3 -m vfl verify-source /path/to/extracted/TycVirtualLab
```

The archive contains source and exactly one source checksum manifest. Auditing
an extracted archive also checks its manifest; `verify-source` requires the
manifest and verifies the exact file inventory and every payload hash. Re-export
of an unchanged extracted tree produces the same archive bytes. These checks
establish source integrity, not publisher authenticity, and do not inspect Git
history. Nothing is uploaded or published by these commands.

## Development

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q vfl
nix flake check
```

`nix flake check` runs the package tests, including Node-based viewer checks, and
the pinned Ghidra integration check (`checks.<system>.ghidra`) with independently
authored instruction fixtures. No vendor firmware is needed. Plain Python test
discovery skips real Ghidra execution unless explicitly enabled; see
[docs/ghidra.md](docs/ghidra.md). The default Nix development shell includes Node
so viewer checks also run there.

Tests use authored synthetic inputs, WAV data and tiny subprocess fixtures. They
exercise spectral behavior, strict parsing, stateful execution, mismatches,
timeouts, stale output, resource coordination, source export, and viewer escaping.
Optional tests with local vendor firmware belong in a separate private workspace.

The [JSON contract](docs/contract.json) and [adapter guide](docs/adapters.md)
describe the extension points. Preserve explicit capability boundaries when adding
a device; a runnable demonstration is not evidence of original firmware support.
The [input semantics](docs/input-semantics.md) define frame clocks, ADC queues,
random substitution and the limits of read-log comparison.
