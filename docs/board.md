# Exoy full-board capture

`tycvl board exoy-one` boots a private 8 MiB flash copy in Espressif's ESP32 QEMU
machine. The original application performs startup, scene dispatch, audio DSP,
rendering and driver-buffer conversion. GDB provides explicit hardware stand-ins
and records the actual logical RGB buffer, driver GRB buffer and scene state.

Supply the supported Exoy v2.1 application, a raw flash image containing that
application at offset `0x10000`, an Espressif QEMU build with the ESP32 machine
and its two ROM files, and Xtensa GDB with Python support. No firmware is bundled
or downloaded by this command. The source flash stays unchanged. A flash image
assembled from an SDK bootloader, partition table and filesystem represents those
specific boot assets and settings; it is not evidence that they match a physical
lamp's flash.

```sh
nix develop .#board
tycvl board exoy-one --qemu /path/to/qemu/bin/qemu-system-xtensa --gdb /path/to/xtensa-esp32-elf-gdb --flash /path/to/flash.bin --firmware /path/to/application.bin --library-path "$LD_LIBRARY_PATH" --frames 16 --mic 1850 --out ../TycVirtualLab-private/exoy-board
tycvl verify-run ../TycVirtualLab-private/exoy-board
tycvl view ../TycVirtualLab-private/exoy-board/capture.json --out ../TycVirtualLab-private/exoy-board.html
```

The board Nix shell supplies shared libraries for the external QEMU executable.
`--limiter` and repeated `--hold-file` coordinate use with other emulators and
physical captures. The limiter is invoked with one CPU and one emulator slot.
The debugger uses a private Unix socket; QEMU networking is disabled. Runtime
assets are hashed before and after execution. Timeouts clean up QEMU and the
debugger; each worker output file has an 8 MiB operating-system size limit.
Core dumps are disabled. Before the first hardware stand-in and again at the
first scene dispatch, every loaded application
code and read-only-data segment is hashed through the debugger and compared with
the supplied image. This checks the application actually selected by the
bootloader, including OTA selection, rather than relying only on bytes at one
flash offset. An application restart or scene CPU-core change fails the capture.
An external limiter should export inherited lock descriptors through
`TYCVL_RESOURCE_LOCK_FDS` (comma-separated integers) to keep them held by nested
processes. A limiter that only keeps its lock in the supervisor needs a cgroup
or equivalent whole-job supervisor for abrupt SIGKILL cleanup. Normal TERM/HUP
and timeout cleanup are handled by the runner.

`--pack` and `--effect` select an original scene at the dispatcher entry. Without
them, persisted settings determine the scene. `--input` accepts the device's
64-count ADC input trace. Packet *i* belongs to captured scene frame *i*, with
chronological reads inside that frame. Zero or 64 reads are accepted according to
whether the scene reads audio; an unused packet is discarded, never carried to
the next frame. After the first scene begins, an ADC read or extra show outside
the dispatch-to-show interval fails the run. Trace controls are rejected. `--mic` supplies
startup ADC reads and, when no trace is supplied, the scene samples too. These
are raw ADC counts, not normalized loudness. The image's initialized DSP baseline
is 1400 counts, so an offset of 2048 can produce a nonzero level even for zero PCM.
The actual selector bytes are captured at dispatch and output for every frame,
preserving both values if the firmware changes selection during a scene.
Explicit pack/effect options
are written once at the first dispatcher entry, then checked at each dispatch and
output; later selector drift fails the run. Without these options, the recorded selector identifies
the persisted or firmware-selected scene.

The observed clock differs from the routine backend. Capture timestamps derive
from the actual 32-bit CCOUNT register, with wrap handling and an explicit
`--cpu-hz` conversion (default 240 MHz). Input trace timestamps are retained as
provenance and do not drive QEMU time. The conversion is a declared interpretation
of the emulator counter, not a measured silicon frequency or microphone cadence.
Runs longer than one counter wrap between consecutive outputs cannot resolve the
number of wraps; keep captures dense and inspect observed timing.

The fixed hardware boundaries are the IPC stall handshake, GPIO34/ADC channel 6,
an offline WiFi-initialization failure, and RMT transmission. The timer-group
watchdogs are switched off in QEMU (`timer.esp32.timg` `wdt_disable`), so a stall
that would reset a lamp does not reset the run; every capture says so in its
limitations. At RMT output the
adapter captures bytes, then invokes the original ROM delay for the modeled
14400 microsecond transfer. It does not synthesize effect pixels. Startup output
frames before the first scene are counted separately. ADC and WiFi stand-ins
consume no simulated conversion/attempt time. The capture reports no clock
or RNG read-log capability because those calls are not intercepted.

`--seed` defaults to the input trace's seed, or 1. QEMU seed and instruction-count
mode do not guarantee repeatability of this multicore firmware. Repeat the same
request into a fresh directory and use `tycvl compare` to check bytes, state and
timing. The experiment identity binds initial flash, ROM and application hashes,
startup microphone value, selected scene, packets, seed and clock conversion.
Comparison reports show each implementation's source and runtime-asset hashes;
different implementations may intentionally be compared under the same experiment.
Completion means the requested execution finished with bound observations;
agreement with a physical lamp requires separate evidence.
