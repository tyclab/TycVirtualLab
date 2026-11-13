# Original instruction execution with Ghidra

The public backend runs an externally supplied ELF in Ghidra's p-code emulator.
It supports explicitly configured **Xtensa call0 routines**, including repeated
engine calls. It does not boot a complete ESP board. ESP32/ESP32-S3 windowed calls,
interrupts, networking and unconfigured peripheral behavior are unsupported.
Encountered windowed instructions and unknown p-code operations fail the run.
This backend and its direct memory-read checks are tested with **Ghidra 12.0.4**.
Other Ghidra versions are not validated by this release; the running version and
language remain recorded with each capture.

Keep images, ROMs, addresses, initialization recipes and results outside the
source checkout. No device profile or vendor instruction bytes are bundled.
`tests/test_ghidra.py` generates a newly authored five-instruction ELF whose
independently known outputs test the execution pipeline.

## Configure the external backend

For an installed package, use `backend.command`:

```json
["tycvl-ghidra", "{request}", "{capture}"]
```

`["python3", "-m", "vfl.ghidra", "{request}", "{capture}"]` is equivalent when
the package is importable from the private run directory. Running from a source
checkout alone does not add that checkout to a child process's module path.

Set `backend.kind` to `external`, `backend.execution_kind` to
`original-firmware`, and put the following configuration under
`backend.options.ghidra`. This example uses arbitrary addresses from the authored
test routine, not a device's memory map:

```json
{
  "elf_role": "program",
  "abi": {
    "kind": "xtensa-call0",
    "stack_pointer": 12272,
    "return_sentinel": 16384
  },
  "memory_regions": [{"address": 8192, "size": 4096}],
  "hooks": [],
  "initialization": [],
  "frame_calls": [
    {"op": "call", "address": 4096, "arguments": [{"input": 0}, 8192]}
  ],
  "outputs": [{"id": "main", "address": 8192, "size": 3}],
  "state": [{"id": "output-bytes", "address": 8192, "size": 3}],
  "instruction_limit": 100,
  "max_frames": 4
}
```

Declare the ELF in `profile.firmware` with `role: "program"`, `format: "elf"`,
its local path, and preferably a pinned `sha256`. The runner resolves asset paths
relative to the private profile. Additional ROM/helper binaries use separate
roles. The backend verifies a 32-bit little-endian Xtensa ELF before selecting
the processor. `profile.target.abi` must explicitly be `xtensa-call0`; declare the
appropriate `chip` and `isa` alongside it. ELF metadata alone does not establish
the Xtensa core or ABI.

If `profile.settings` is nonempty, `settings_acknowledgements` must be an object
containing exactly the same keys and values. This records a deliberate private
initialization assumption and is included in provenance. It does not generate
memory writes or implement the settings: the private initialization/call recipe
must do that, and independent evidence must establish the mapping. A changed
setting with an unchanged acknowledgement fails before launch.

Provide `GHIDRA_HEADLESS`, an absolute `headless` path in this configuration, or
`ghidra-analyzeHeadless` on PATH. The script reports the running application's
version and language ID in `manifest.engine`. Script, driver and launcher hashes
are recorded separately from image hashes. An explicit configuration `headless`
path takes precedence over `GHIDRA_HEADLESS`, which takes precedence over PATH.
Each run gets fresh Ghidra settings, compiled-script cache and temporary
directories, avoiding reuse of a compiled script from an earlier source tree.

`tycvl run PROFILE INPUT --out PRIVATE_RUN` creates a fresh request and validates
the result. `tycvl compare PRIVATE_RUN_A PRIVATE_RUN_B` compares completed runs.

## Memory and calls

- Initialized, loaded ELF blocks are copied. Non-loaded ELF metadata is skipped;
  loaded overlays fail. `memory_regions` are explicitly zeroed after loading.
  Use them for BSS, stack and scratch memory. They must not overlap one another.
  A zero region intersecting initialized ELF bytes fails unless that region
  explicitly declares `allow_elf_overlap: true`. This override is a private
  initialization decision, not an automatically inferred BSS range.
- Optional `binary_mappings` entries contain `role`, `address`, and optional
  `offset`/`length`. They copy bytes from declared assets after zeroing.
- The ABI uses PC, a1 stack, a0 return address, a2–a7 arguments and a2 result.
  a0–a15 and PS start at zero. Each call sets the configured stack and return
  sentinel; other register/memory state carries between calls.
- `initialization` is an ordered list of `{"op":"call","address":...,"arguments":[...]}`,
  `{"op":"write","address":...,"hex":"..."}` and
  `{"op":"register","name":"a2","value":...}` operations.
- `frame_calls` contains ordered calls. An argument is an unsigned integer,
  `{"input": channel_index}`, or `{"time_ms": true}`. Bus IDs in `outputs`
  must cover every profile bus exactly. Region sizes must match bus byte counts.
- Every configured `state` region is captured on every frame. Optional
  `state_encoding: "sha256"` stores a hash per region in normalized JSON; the
  original bytes remain in the private protocol output. Hash differences identify
  regions, not memory byte offsets. The digest is SHA256 of the raw bytes in
  ascending memory-address order, not of their hexadecimal or JSON encoding.

Uninitialized reads fail directly in the emulator state implementation by default,
including explicit snapshot reads. Enforcement does not depend on parsing host
log messages. Fix the declared initialization first. `allow_uninitialized: true`
is an explicit exception: the read count, bounded region diagnostics and resulting
runtime dependency appear in provenance and limitations. Decoder lookahead keeps
Ghidra's normal semantics; unavailable instruction bytes still fail decoding.
This is not a peripheral emulator: guest writes have ordinary
emulator memory semantics. Configure the required peripheral boundaries as
hooks; no physical meaning is inferred for MMIO addresses.

## Hook and input semantics

Each hook has an external `address` and a `kind`:

| Kind | Configured behavior |
| --- | --- |
| `millis`, `micros` | Return the current frame clock, truncated to 32 bits. |
| `adc` | Return successive channel values; restart at channel zero each frame. |
| `rng` | Return the next xorshift32 value; optional `mode: "bounded"` uses a2 as modulus. |
| `return` | Return the configured unsigned `value` in a2. |
| `noop` | Return with a2 unchanged. |
| `write` | Write `value` to `target`, with `width` of 1, 2 or 4 bytes; preserve a2. |
| `guard_acquire` | Return whether the byte at the a2 argument address is zero. |
| `guard_release` | Write one to that byte and preserve a2. |

Only integer scalar/band traces and `clock_policy: "frame"` are supported.
Timestamps must align to whole milliseconds, but intervals may vary. Time stays
frozen throughout each frame's calls. Delays advance time only if explicitly
modeled by another backend. Per-frame controls are rejected.

The default `adc_policy: "strict"` fails if reads exhaust the frame's input
queue; unconsumed values are allowed. Explicit `adc_policy: "cycle"` revisits
channel zero after the last supplied value. Events and provenance record this
policy. It models held channel values, not a device scan rate.

By default, a completed run must contain at least one observed frame ADC read or
one trace value supplied through an `{"input": channel}` call argument. The
check spans the whole run; it does not require every channel or every frame to
be consumed. Input-independent routines require explicit `allow_unused_input:
true`, recorded as a limitation. Provenance distinguishes observed ADC reads from
argument values supplied to completed calls: instruction-level use of an argument
is not tracked. ADC, clock and RNG capabilities derive from configured hooks,
and observed read counts are reported separately.

The RNG seed fits 32 bits; zero is mapped to one. Starting from unsigned state `x`,
each draw applies `x ^= x << 13`, `x ^= x >> 17`, `x ^= x << 5`, masking left
shifts and the result to 32 bits. Bounded mode returns `draw % a2`; a zero bound
returns zero without advancing state. This models a boundary RNG, not an
unobserved hardware generator or an internal firmware PRNG.

Read events record actual intercepted calls, not the planned number of samples.
Initialization calls have `frame: -1` and `phase: "initialization"`. A frame can
have zero, seven or many ADC calls depending on guest execution. Call-site
metadata records the return address, which is not necessarily the call
instruction address. Event counts must match the emulator's stub counter.

## Freshness, resource limits and verification

Java reads the command file once, hashes the same bytes it executes, and emits
`E binding` with that SHA256 and the fresh request nonce. Python requires both;
cached output from another seed or request fails even when frame sizes match.
The JSON manifest also echoes the runner's input/profile/experiment identities.
Legacy D/R/E/X import supports unbound captures, but cannot make this freshness
claim; the public Ghidra backend always requires binding.

Command binding establishes which scheduled bytes the script executed. It does
not establish that a private memory address implements a named setting, that all
supplied inputs were consumed, or that a peripheral substitute matches hardware.
Those claims need the configured mapping, actual consumption records and
independent reference evidence.

Commands, hooks and informational records use explicit allowlists. Requested
echo messages are the only arbitrary informational text accepted. A call must
precede each frame's dumps, every mapped state region must be present, and a
completion marker is required. Unknown instructions, traps, malformed records,
missing logs and stale files fail the run.

The default per-call limit is 500,000 steps (maximum 10,000,000), default raw
protocol limit 64 MiB (maximum 512 MiB), and maximum 5,000 frames. The default
Ghidra timeout is the smaller of 300 seconds and 90% of the outer backend timeout
(270 seconds with the default outer timeout). An explicit inner timeout must
remain shorter than the outer timeout. `instruction_limit`, `output_limit`, `max_frames` and
`timeout_s` configure these limits. Output/state sizes are checked before launch.
There is also a one-million-event limit. Large snapshots still consume memory
and disk even with hashed normalized state.

Use the runner's `resource_lock`/`hold_file` for coordination. An optional
`launcher_role` names a declared executable asset prepended to the Ghidra command;
`launcher_environment` supplies its string environment variables. This can reuse
a host's existing CPU/memory/concurrency limiter. `hold_files` must be a list of
absolute paths and adds private adapter-specific checks before launching. The backend does not invent a host's
resource policy. Account for any queue wait in the timeout.
The nested process inherits resource-lock descriptors. On termination or timeout
the adapter kills the Ghidra process group without an additional grace period,
so it does not compete with the outer runner's cleanup deadline.

Fast tests run with `python3 -m unittest tests.test_ghidra tests.test_hsemu`.
For the real, independently authored ELF test, set `TYCVL_GHIDRA_INTEGRATION=1`
and `GHIDRA_HEADLESS`; optionally set `TYCVL_GHIDRA_LAUNCHER` to the host limiter.
All generated images and captures are temporary/private artifacts.
`nix flake check` includes the pinned Ghidra integration check as well as the
package tests; ordinary Python test discovery leaves real Ghidra tests opt-in.
