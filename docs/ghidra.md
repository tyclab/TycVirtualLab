# Original instruction execution with Ghidra

The public backend runs an externally supplied ELF in Ghidra's p-code emulator.
It supports explicitly configured **Xtensa call0 or logical windowed routines**,
including repeated engine calls. It does not boot a complete ESP board.
Interrupts, networking and unconfigured peripheral behavior are unsupported.
Physical register-window spilling, window-management instructions and mixing
call0 routines into a windowed invocation fail explicitly.
This backend and its direct memory-read checks are tested with **Ghidra 12.0.4**.
Other Ghidra versions are rejected; the running version and language remain recorded with each capture.

Keep images, ROMs, private state and results outside the source checkout.
Reusable device address metadata and setup recipes are bundled; vendor
instruction bytes and palettes are not.
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
the processor. `profile.target.abi` must match the configured `xtensa-call0` or
`xtensa-windowed` ABI; declare the
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
- Call0 uses PC, a1 stack, a0 return address, a2–a7 arguments and a2 result.
  Windowed entry presents the same callee registers by establishing a CALL8
  boundary: arguments begin in caller a10 and the encoded link in a8. Entry
  and sentinel must share a 1 GiB address region. Nested CALL4/8/12 and CALLX
  calls use bounded logical register snapshots, including overlapping CALL4
  return values. Maximum logical depth is 256; physical spill exceptions are
  excluded. a0–a15 and PS start at zero. Each top-level call sets the configured
  stack and return sentinel; other register/memory state carries between calls.
- Windowed mode explicitly handles LOOP/LOOPNEZ/LOOPGTZ at LEND. This avoids
  relying on Ghidra 12.0.4's static disassembly loop context during dynamic
  execution. Authored tests exercise six iterations and a skipped zero loop.
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
| `f32_div` | Interpret two argument bit patterns as finite IEEE754 binary32 operands and return Java float division bits. Reject zero denominator, nonfinite inputs and overflow. No floating-point exception flags are modeled. |

Windowed hooks normalize the caller argument/result registers and encoded return
link before the callee ENTRY executes. Each substituted call is logged. The
`f32_div` hook is a declared runtime replacement; its use does not establish
instruction-by-instruction equivalence of an unsupported firmware FP helper.
Java's operation is specified in the [Java language specification](https://docs.oracle.com/javase/specs/jls/se21/html/jls-15.html#jls-15.17.2).

Only integer scalar/band traces and `clock_policy: "frame"` are supported.
Timestamps must align to whole milliseconds, but intervals may vary. Time stays
frozen throughout each frame's calls. Delays advance time only if explicitly
modeled by another backend. Per-frame controls require a matching
`frame_operations` recipe: each entry has `index`, the exact nonempty `controls`
object, and ordered initialization-format `operations`. The device adapter owns
the setting-to-memory mapping; the generic engine rejects unacknowledged controls.

Optional `input_writes` bindings contain `channel`, `address`, and byte `width`
(1, 2 or 4). After setting the frame clock, the driver writes that trace value to
the declared address before calling the firmware. This supports traced internal
DSP boundaries; it does not claim the firmware read the supplied value. Values
that exceed the write width fail preflight.

The default `adc_policy: "strict"` fails if reads exhaust the frame's input
queue; unconsumed values are allowed. Explicit `adc_policy: "cycle"` revisits
channel zero after the last supplied value. Events and provenance record this
policy. It models held channel values, not a device scan rate.

By default, a completed run must contain at least one observed frame ADC read or
one trace value supplied through an `{"input": channel}` call argument or
`input_writes` binding. The
check spans the whole run; it does not require every channel or every frame to
be consumed. Input-independent routines require explicit `allow_unused_input:
true`, recorded as a limitation. Provenance distinguishes observed ADC reads from
argument values and memory values supplied: instruction-level use of an input
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

The windowed calling convention follows Espressif's
[Xtensa ISA overview](https://dl.espressif.com/github_assets/espressif/xtensa-isa-doc/releases/download/latest/Xtensa.pdf).
The authored fixtures found and cover Ghidra 12.0.4's overlapping CALL4 register
copy and missing dynamic LOOP repetition; the adapter supplies explicit handling.

Fast tests run with `python3 -m unittest tests.test_ghidra tests.test_ghidra_windowed tests.test_ghidra_reviewed tests.test_hsemu`.
For the real, independently authored ELF test, set `TYCVL_GHIDRA_INTEGRATION=1`
and `GHIDRA_HEADLESS`; optionally set `TYCVL_GHIDRA_LAUNCHER` to the host limiter.
All generated images and captures are temporary/private artifacts.
`nix flake check` includes the pinned Ghidra integration check as well as the
package tests; ordinary Python test discovery leaves real Ghidra tests opt-in.


An optional `heap: {"address": ..., "size": ...}` declares an isolated runtime
allocation arena, at most 1 MiB and aligned to 16 bytes. It must not overlap ELF,
zero-initialized regions or binary mappings. Explicit `malloc`, `calloc`,
`realloc` and `free` hooks implement deterministic first-fit allocation and
coalescing. Zero-size allocation returns null; failed realloc preserves the old
allocation. Calloc clears its result and checks product overflow. Guest reads
and writes that overlap the arena must fit one live allocation's requested size;
invalid/double frees fail. Fresh malloc bytes remain uninitialized under the
existing strict-read policy; reused blocks retain unspecified prior bytes. This
is a named runtime substitute, not the original SDK allocation algorithm.

`input_writes` may declare `"encoding": "float32-le"` with `"width": 4` for
finite scalar input. Values round to binary32 and are stored as little-endian
bits. Their unused frame tape carries the same bits; ADC hooks are prohibited
for these profiles so the bits cannot masquerade as ADC measurements. Ordinary
input writes retain the default `uint-le` encoding. Dynamic call arguments
remain unsigned integers. Exact control-acknowledgement recipes may contain an
empty operations list when a supplied control repeats the existing value.

## Instruction edge semantics

Windowed hardware loops repeat only after an instruction falls through to LEND
with nonzero LCOUNT. A taken branch to LEND does not repeat; an untaken branch
does. Loop registers persist as architectural state, without an invented active
flag. Windowed RSR/WSR are implemented only for LBEG/LEND/LCOUNT, including compiler-generated long-loop relocation; other special-register accesses fail. Their actual read/write counts are recorded in execution metadata. The authored edge fixtures check branch-to-end, conditional fallthrough
and LOOPNEZ zero-trip behavior. Call0 hardware-loop instructions are explicitly
rejected; the supported LX106 device does not implement them. This behavior follows
the [QEMU Xtensa loop and conditional-branch implementation](https://github.com/qemu/qemu/blob/master/target/xtensa/translate.c).

Ghidra12.0.4 defines PS_CALLINC at PS bits12–13 in xtensaArch.sinc, unlike the
hardware PS bits16–17. The harness uses a named constant for the SLEIGH layout;
a test checks the installed SLEIGH definition, and executed windowed calls verify it operationally. Privileged RSR.PS remains unsupported. This register model is not
a claim to emulate arbitrary privileged PS manipulation.

A normal CALL4/8/12 to a hook uses its call-site register window. A hook reached
without CALLn fails by default. An inspected entered-frame tail jump can opt in
per hook with `"windowed_tail": "entered"`; that profile asserts ENTRY already
ran and the hook returns by restoring that frame. A no-ENTRY thunk must not use
this policy. The authored tests cover both an opted-in entered tail and rejection
of an unacknowledged no-ENTRY thunk.

MADD.S/MSUB.S are fused operations, but the pinned SLEIGH emits two rounded
p-code operations. The adapter corrects their destination with Java `Math.fma`
for finite operands and results under default nearest-even FCR. Non-finite values,
other FCR modes and floating-point status reads fail. Execution metadata counts
corrected instructions; no floating-point exception flags are claimed. Authored
fixtures distinguish fused ±2^-46 residuals from the incorrect unfused zero.


The pinned Ghidra engine corrects `MADD.S`/`MSUB.S` to one final binary32 rounding
using Java's fused operation. The [Cadence Xtensa ISA summary](https://www.cadence.com/content/dam/cadence-www/global/en_US/documents/tools/silicon-solutions/compute-ip/isa-summary.pdf)
specifies no intermediate product rounding; the installed SLEIGH definition
otherwise emits separate multiply and add/subtract operations. Only finite
operands/results and default nearest-even FCR mode are supported; other cases
fail. Floating-point exception/status flags are not modeled. Execution metadata
records the policy and number of corrected fused instructions. An authored
fixture distinguishes the exact ±2⁻⁴⁶ residual from the incorrect zero produced
by two binary32 rounds.
