# Execution adapters

An external adapter is a local program that accepts a request filename and an
output filename. It reads the request, executes one complete stateful scenario,
writes a `vfl.capture.v1` object, then exits zero. A partial run must fail. There is
no network protocol, remote service or dependency on a particular emulator.

## Profile

Profiles use `vfl.profile.v1` with `id`, `input`, `buses`, `backend`, optional
`settings`, `geometry` and `firmware`. The backend argument list can include
`{request}`, `{capture}` and `{workdir}`. Relative script and firmware paths resolve
against the profile directory. The default process working directory is a fresh
private run directory; `backend.cwd` can select another location explicitly.

An external backend declares `execution_kind`, `timeout_s`, optional `env`,
`hold_file`, `resource_lock` and `queue_timeout_s`. Environment additions are local
configuration and remain private. Firmware assets have `role`, `path` and an
optional expected `sha256`; an original-firmware claim requires declared assets.
List ROM, relevant initialization files and executable helpers as assets when
they affect reproducibility, not just the main application image.

Keep effect selection, palette, brightness, speed and other experiment settings in
`profile.settings`. Backend-specific implementation options belong in `backend`.
The experiment hash deliberately omits the latter so two implementations can be
compared under the same settings. An adapter must reject unsupported settings or
controls rather than silently ignore them.

An input bus declares a kind, units and range. Output buses declare an ID, number
of pixels, byte order, and `stage` (`logical` or `driver`). RGB data is a hex string
of exactly `pixels * 3` bytes in that declared order. Use different buses for
pre-conversion and final output if both are captured.

## Request identity

The request has:

- `schema: vfl.request.v1`
- `profile` and `trace`: validated full objects
- `workdir`: the fresh private run directory
- `request_id`: a fresh 32-character hexadecimal nonce
- `identities`: `input_sha256`, `profile_sha256`, and `experiment_sha256`

Copy `request_id` and the three identity fields into the returned capture's
`manifest` **from this request**. The runner rejects missing or conflicting values.
This freshness handshake is not a security boundary against a malicious adapter.

`python -m vfl.demo_adapter REQUEST CAPTURE` is a complete synthetic external
adapter example. Install the package or provide an explicit Python module path
when running it from a different directory.

## Capture and read logs

The capture contains `manifest`, `buses`, `geometry`, `frames` and `events`.
Its frames must match the input indexes and timestamps exactly. Each frame has a
`buses` dictionary and optional `state` dictionary of named hex byte sequences.
State should include all relevant persistent memory, including pixel history and
heap objects where needed; list any exclusions explicitly.

The manifest declares `profile_id`, `execution_kind`, `backend`, `limitations` and
boolean capabilities `adc_log`, `clock_log`, `rng_log`, `state`. These describe
actual instrumentation. Do not synthesize a read log from input values and claim
the firmware consumed those values.

Events have `kind` (`adc`, `clock`, `rng`, `stub`, `control`), `frame`, and may
include `time_us`, `call_site`, `value`, `channel` or other backend details.
Initialization events use `frame: -1` and `phase: initialization`; normal events
refer to an existing frame. For deterministic replay, record the read result and
call site, including the order in which time and random values were consumed.

## Ghidra dump bridge

`vfl.hsemu.parse_output(commands, output, dialect="emulator")` checks every
requested dump and returned register record in order, validates byte lengths,
rejects trap/error records, and requires exactly one final completion marker.
`dialect="port"` accepts the recovered-program dump syntax without fabricating
an emulator completion marker; process success must be checked separately.

`capture_from_output` maps configured dump tags into generic bus/state records.
The private adapter supplies the command file, tag mapping and firmware knowledge.
The public parser neither loads firmware nor contains a device memory map.

## Geometry and holes

`geometry.points` contains objects `{bus,index,x,y,z}`. `geometry.mask` maps bus
IDs to boolean arrays. The viewer uses those fields for display only. If an effect
reads previous pixels, holes may need special semantics during computation; hiding
them in the viewer is insufficient. Model that behavior in the execution adapter
and identify whether a stream is logical or physical. Do not treat an estimated
mesh as a calibrated LED wiring map.

## Failure and comparison

Abort on unsupported instructions, missing assets, exhausted strict input traces,
unexpected peripheral calls, malformed output, or inability to honor the declared
clock policy. Preserve raw diagnostics privately. A backend's zero exit code is
necessary but insufficient: the runner also validates freshness, the complete
capture, timestamps, bus sizes, capabilities and asset hashes.

Use the same trace and semantic profile settings for original and recovered code.
Neither should obtain expected outputs or evolved internal state from the other.
Shared initialization and peripheral assumptions still need independent checks.
