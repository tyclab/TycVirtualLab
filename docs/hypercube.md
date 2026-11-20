# HyperCube hs-2.2

The HyperCube adapter executes the supplied ESP8266 application's original Xtensa instructions. Its public setup contains the versioned address map, effect catalog, initialization sequence and peripheral boundary configuration. It contains no firmware payload, recovered renderer, private capture or expected LED output.

The supported revision is identified by all five loaded segment hashes. An ELF may have different container metadata, but its loaded guest bytes must match. The separately supplied ESP8266 ROM is also pinned. Unsupported revisions fail before execution; selecting a similar version does not authorize reusing these addresses.

The profile records which ROM supplied the runtime routines. Both supported files are 65,536 bytes. Earlier runs used a partial reconstruction from a disassembly (`761fa92b557e1aa195be4f00faaec776ad1ecae95f71b88da82938e8af3a076a`). The public reference image has SHA256 `32f199bf10da9a08c6c4e1b556b29c7606656b8a6d04e4f17d5afa74e5d98c68`. Its match to a particular controller's mask ROM remains unverified. [Reference image at the pinned revision](https://github.com/gschorcht/qemu-xtensa/blob/afdb2baa7a0779a07186a93f8e95f5be2d6c86d0/pc-bios/esp8266.rom)

## Prepare and run

Keep images, profiles and runs outside this source checkout. Supply either an ELF or the standalone E9 application image. A merged flash dump is deliberately not accepted by the image preparation command.

```sh
mkdir -p ../hypercube-private
printf '%s\n' '{"fx":124,"sx":128,"ix":128,"palette":1,"brightness":200}' > ../hypercube-private/settings.json

tycvl device prepare hypercube \
  --firmware /absolute/path/to/app-image.bin \
  --rom /absolute/path/to/esp8266-rom.bin \
  --build-dir ../hypercube-private/image \
  --settings ../hypercube-private/settings.json \
  --out ../hypercube-private/profile.json

tycvl generate --kind music-noise --frames 192 --frame-us 32000 \
  --out ../hypercube-private/input.json

tycvl run ../hypercube-private/profile.json ../hypercube-private/input.json \
  --out ../hypercube-private/run-001

tycvl view ../hypercube-private/run-001/capture.json \
  --out ../hypercube-private/run-001.html
```

Use `--headless` when Ghidra is not on `PATH`, and `--limiter`/`--hold-file` for a shared emulator rig. The generated ELF still contains the user's proprietary firmware and must stay private.

## Initialization and execution

The default `boot_stage: "application"` performs these stages:

1. Load and verify the original initialized code/data sections and external ROM. Explicitly zero the BSS, reserved heap and stack region.
2. Execute original static initialization at `0x40220974`, including original palette and timer setup. Exact service and LED allocation boundaries are listed by `device_info()`.
3. Install two reserved virtual driver buffers and execute original application `setup` at `0x402206f8`. This includes the original MSGEQ7 GPIO initialization. Serial, transport registration, network/persisted-settings setup and callback service boundaries are explicit substitutions.
4. Write the selected settings and call the original boot-settings function at `0x402086b4`.
5. Invoke original `vloop_render` at each scheduled frame. Audio analysis, AGC, effect selection, rendering, blending and brightness-to-driver conversion remain original instructions.

`boot_stage: "effect"` omits application `setup` and preserves the narrower historical renderer comparison boundary. `boot_call: false` uses the original state-application entry instead of its boot caller. These options change the experiment identity. `normalize_strings` defaults to false; its explicit true value zeros three irrelevant default strings for compatibility with older state comparisons.

This is application startup with declared service boundaries, not a claim that the ESP reset ROM, WiFi scheduler, filesystem, interrupts or network loop have booted. Captures contain the two final 144-pixel **GRB driver buffers**, before electrical UART/I2S transmission. State can be raw bytes or SHA256 per region; hashes are of the raw bytes.

## Effects and controls

`tycvl device effects hypercube` lists 98 user selectors: three playlists, 40 Kaleidoscopic effects, 23 Calm effects, 31 Sound effects and Solid. Warp is a separate command and the 96th rendering routine; it is not a valid effect byte.

Settings include `fx`, `sx`, `ix`, `palette` (0–26), `symmetry` (0–2), `brightness`, three RGB `colors`, `psd`, playlist `dwell_s`, `random_order`, `transition_ms`, `transition_delay_ms`, and `warp_dwell_s`. The source module defines defaults and validates ranges.

A trace frame may contain a partial settings object in `controls`, for example `{"fx":124,"ix":0}`, `{"brightness":80}`, or `{"warp":true}`. Prepare the profile with `--input` pointing to that trace. The adapter compiles exact indexed control recipes, writing only changed settings and entering the original `colorUpdated` request path. Original brightness-transition stepping runs before rendering when a control timeline is configured. Warp uses the pending flag handled by the original render loop. `warp: false` clears a queued request but does not interrupt an animation that has already started. Boot-only settings cannot change mid-trace. Changing the trace controls without regenerating the profile is rejected.

## Input and time

The input boundary is seven ADC counts in the range 0–1023, corresponding to the MSGEQ7 scan. Original GPIO5 reset and GPIO4 falling-edge strobe writes select the band; ADC reads use that selected channel rather than advancing an unrelated input queue. The virtual scan requires a reset, a channel-selection pulse and low reset/strobe at the sample. Repeated ADC reads without a new strobe return the same held band. Channels advance only on actual GPIO writes, and an invalid scan phase fails. The original code decides whether to sample: visual effects, zero brightness, pause state or an unexpired frame timer may consume no audio input. Captures report actual ADC/clock/RNG reads; supplying a trace does not establish that it was consumed.

The analog microphone and MSGEQ7 frequency response are upstream of this boundary. WAV conversion produces a modelled or explicitly calibrated trace; it does not turn an analog approximation into measured device behavior. GPIO delays have no physical settling dynamics. RNG is a documented seeded substitute, and time is frozen within each frame.

Frame cadence is part of the experiment. A 32 ms smoke trace is cheap but differs from calling the original render boundary every millisecond; the firmware's 20 ms timers and palette updates respond to that cadence. Use 1 ms calls when investigating loop cadence, and durations beyond ten seconds for long AGC/palette/playlist behavior. A black short capture is not proof that an effect is inactive: Harmonic Ripple can require hundreds of beat frames. Sonic Superposition is initially exercised with intensity zero because a nonzero startup intensity can reach an original division-by-zero path.

## Coverage campaigns

```sh
tycvl device coverage hypercube \
  --elf ../hypercube-private/image/application.elf \
  --rom /absolute/path/to/esp8266-rom.bin \
  --frames 20 --batch-size 6 \
  --out ../hypercube-private/selector-smoke-001
```

Coverage defaults to twenty calls spaced one second apart, allowing startup Warp
and delayed selection to progress. This is a sparse selector smoke, not a model
of the device's normal loop cadence. Supply `--input` for a dense or longer
scenario; the standalone Python `smoke_trace` helper retains its32ms default.

Use repeated `--case` options such as `fx-124` or `warp` for a subset. A campaign runs each selected case from fresh emulated state, batching at most eight scripts in a single Ghidra import. It preserves the actual commands, nonce, source and asset hashes, strict undefined-read metadata, boundary logs and normalized capture per case. It yields between batches and checks HOLD again after obtaining the shared limiter slot.

`campaign.json` uses `status: "executed"` and `fidelity: "not-evaluated"` for cases whose original execution and requested entry checks completed. Its legacy `passed` aggregate is explicitly a compatibility count of those executions, not a fidelity result. It distinguishes failures, completed frames, nonblack frames, distinct outputs and actual read counts. Passive instruction-entry observers identify which original effect routines actually executed; they do not replace those instructions or change the program counter. A case whose requested effect was never reached fails with `entry-not-reached`, even when all scheduled frames completed. Playlists must reach at least one child effect from their own group; Warp alone does not satisfy this check. Nonblack/distinct-output counts remain separate: entering a routine can legitimately produce black output. This establishes bounded original routine execution, not physical equivalence or a complete settings matrix. Use a trace with longer elapsed time when startup fades or delayed transitions prevent a short case from reaching its selected effect. Campaign captures have their own protocol/source/asset validation; they are not falsely stamped with the single-run runner's completed-run envelope. Use `tycvl run` when that envelope is required.
