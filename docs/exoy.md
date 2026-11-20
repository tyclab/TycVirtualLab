# Exoy ONE original application boundary

`tycvl device prepare exoy-one` accepts the identified public v2.1 application
image or its validated ELF wrapper. The adapter checks every loaded segment
against the known revision. Firmware bytes and generated images stay outside the
source tree. The public adapter distributes address metadata and initialization
recipes only. The image comes from the vendor-linked
[Exoy binary repository](https://github.com/the-skips/Exoy-bin-files/tree/91c28be5cbb90765e97cba3ae7f135d5cc1ad237).

```sh
tycvl device prepare exoy-one --firmware /path/to/firmware.bin --rom /path/to/esp32_rev0_rom.elf --build-dir ../TycVirtualLab-private/exoy-build --out ../TycVirtualLab-private/exoy.json
```

Use `tycvl device effects exoy-one` for the 70 selection names and pack/index bounds.
Inventory presence is not a claim that every scene and setting combination has
completed execution. Failures remain errors; unsupported instructions never
silently become synthetic pixel output.

The default scene is Party / Jubulo (pack 1, effect 4), with sound enabled. This
was observed in a supplied fresh-flash QEMU boot; it is not a physical factory
configuration measurement.

The original central scene routine reads the selected pack/effect and its control
table, calls the original selector, then executes its renderer and pixel helpers.
Settings include `pack`, `effect`, `brightness`, `speed`, `hue`, `saturation` and
`sound_reactive`. Speed, hue and saturation default to null: the original
selector chooses its own fallback, using the firmware's −1 control-table sentinel.
The adapter verifies that the identified image initializes every control-table
slot to −1 before permitting those null defaults.
Explicit values in 0..255 override those controls. The same keys can appear in frame controls when preparing the
profile with that input trace. Only changed controls are written; changing a
scene also writes its current speed/hue/saturation overrides into that scene's
control table. Unchanged controls produce an explicitly acknowledged empty recipe.
Strip objects and the original mapping constructor run only during initialization;
`strip_order` and `strip_reverse` are boot-only and rejected in frame controls.
The adapter builds exact per-frame write recipes;
unknown or out-of-range settings fail before execution. Original selectors can
constrain or override a control, as they do on the device.

Two input boundaries are available. A trace matching `ADC_INPUT` supplies 64
integer values in 0..4095, in chronological read order, with units
`esp32-adc-chronological-read-counts`. The adapter substitutes `analogRead(34)` at
its function boundary. The original microphone routine performs all 64 reads,
retains their unsigned maximum, and executes its original baseline, threshold,
envelope and renderer-level calculations. These are scalar sample queues, not
frequency bands. Frame time is explicit; the hardware acquisition spacing,
analog microphone response, ADC peripheral behavior and sound pressure
calibration are not modeled. Some original selectors disable sound and consume
no samples; observed ADC-read counts distinguish this from a processed input.

The alternative two-channel `exoy-renderer-audio-counts` trace replaces the
microphone-processing routine and writes two internal byte-valued renderer
globals. This narrower boundary excludes original DSP and remains useful for
isolated renderer comparisons. Its supplied-value count establishes delivery,
not proof that every value was read by the original code.

`--rom /path/to/esp32_rev0_rom.elf` maps original Espressif ROM instructions and
constants required by scenes using ROM arithmetic. Only the pinned compatible
ROM image is accepted. Without it, scenes that enter unmapped ROM fail closed.
This is an explicitly selected ROM revision, not a claim that the physical
lamp's silicon revision was measured. Firmware and ROM bytes stay external.

```sh
tycvl device coverage exoy-one --elf ../TycVirtualLab-private/exoy-build/application.elf --rom /path/to/esp32_rev0_rom.elf --case p8-e0 --frames 4 --out ../TycVirtualLab-private/exoy-smoke
```

Omit `--case` for the 70-selection campaign. Each case starts fresh state; the
campaign records original pack-selector instruction entry, RGB snapshots,
actual ADC/clock/RNG boundary events, and strict undefined-read enforcement.
A case receives `executed` after the requested pack selector was reached and its input checks completed. The `executed` aggregate counts these cases. The legacy `passed` aggregate carries the same count for existing readers. Physical fidelity stays `not-evaluated`. A short smoke does not prove later behavior or every setting. Cases
are bound to command, asset and source hashes and a fresh request nonce. They
are campaign evidence, not the outer runner's completed-run envelope; standalone
capture comparison therefore requires `--unverified`.

The captured stream contains 480 logical RGB pixels before the final hardware
show operation. Thirty strip objects each reference sixteen pixels. The default
`strip_order` and `strip_reverse` are null: the original mapping initializer
loads its own order and reversal lists from the supplied image. Optional
`strip_order` overrides the logical-to-physical permutation; `strip_reverse`
overrides reversal by physical strip. The setup does not supply a measured
three-dimensional optical placement. Physical
wire timing, output-driver brightness/current limiting and dithering are excluded.

The scene boundary explicitly zeroes the BSS range named by the original
entrypoint and installs strip objects and control values. It does not run a complete ESP32 boot or restore
a captured device session. Scene state persists between frames; preparing a new
run creates fresh state. Captured state contains the declared selector, scene
scratch and audio regions; it is not a dump of all firmware RAM or heap objects.
The original image supplies constants and palettes.

Ghidra 12.0.4 cannot decode the ESP32 floating division helper's `div0.s` family.
Its complete instruction sequence matches GCC’s [Xtensa `__divsf3` implementation](https://github.com/gcc-mirror/gcc/blob/master/libgcc/config/xtensa/ieee754-sf.S).
The adapter replaces that helper with logged, finite IEEE754 binary32 division
and replaces the final hardware-show operation with a logged no-op. It also
provides declared frozen-clock, seeded RNG and C++ guard boundaries when reached.
SDK `malloc`, `realloc` and `free` use an explicit 64 KiB deterministic first-fit
arena with 16-byte alignment. The original C++ vector and scene logic execute;
heap allocation addresses and exhaustion behavior are a declared runtime model.
Reads/writes must stay within a live allocation, and invalid/double frees fail.
The allocator does not emulate ESP-IDF heap locks, region choices or RTOS behavior.
The modeled stack occupies `0x3ffd8000..0x3ffdf000` (exclusive end), after the
application BSS `0x3ffc5260..0x3ffd6280`. The heap occupies
`0x3fff0000..0x40000000`. Both avoid the supplied ROM ELF's data, BSS and
reserved stack ranges; unused ROM RAM remains undefined. These addresses are
execution setup, not reconstructed physical allocation addresses.
The engine also applies the documented fused-arithmetic correction for
`MADD.S`/`MSUB.S`, with finite operands/results and nearest-even rounding.
All other encountered instructions must execute successfully. The division
replacement rejects nonfinite inputs, a zero denominator and overflow; no FPU
exception flags are modeled. It has an independently known one-third fixture,
but is not a blanket instruction-equivalence proof of the device FP unit.

Separate bounded renderer tests can execute the original integer mapping, HSV
conversion and pixel replication without that division substitution. A result
from that narrower boundary must not be described as full application execution.
See [the generic Ghidra contract](ghidra.md) for logical register-window limits,
undefined-read enforcement and the exact boundary event records.
