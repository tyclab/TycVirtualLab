# Input and observation semantics

Version 1 uses a **frozen frame clock**. A trace supplies frame indexes,
monotonically increasing microsecond timestamps, values, and a deterministic seed.
It does not claim that every supplied channel was read, nor that the firmware
executed once per physical display refresh. Read logs record actual consumption.
An advancing clock, asynchronous interrupt schedule and arbitrary read tape need a
different explicit model; the v1 `events` clock policy is unsupported.

## Boundary values

For `bands`, `values` contains integer values in the declared ADC units and range.
The public Ghidra backend supplies channels in order when its configured ADC hook
is reached. It resets the channel cursor at each frame and fails when a routine
reads beyond that frame's supplied values. A frame may consume none or fewer than
all values. This is a bounded input model, not a claim about a device's scan rate.
An adapter that cycles inputs or models a multiplexer must declare that difference.

For `scalar`, values can describe explicitly identified function inputs. The
public Ghidra call adapter supports unsigned integer arguments. A profile that
needs floating-point conversion must provide that conversion explicitly.

For `pcm`, blocks contain normalized mono samples in sample order, and their
timestamps derive from the sample rate. Only the final block may be shorter than
the declared block size. The included Ghidra routine backend does not accept PCM
directly; an appropriate device adapter must implement its sample-input boundary.

## Clock and randomness

Trace timestamps are microseconds. The public Ghidra adapter currently requires
millisecond-aligned timestamps; it rejects a 16,667-microsecond interval rather
than rounding it. `millis` and `micros` hooks return the current frame time in their
named units, truncated to unsigned 32-bit clock values. This preserves clock-wrap
semantics within the backend's accepted range; it does not provide cycle timing.

The public Ghidra RNG substitution uses xorshift32. A zero seed is replaced by one.
Each draw applies, in order, `x ^= x << 13`, `x ^= x >> 17`, `x ^= x << 5` with
unsigned 32-bit arithmetic. The raw hook returns this word. The bounded hook
returns the word modulo its unsigned argument; a zero bound returns zero without
consuming a draw. Logs expose the result, source policy and draw order.

This substitutes a reproducible stream for hardware entropy. It does not identify
the vendor's actual hardware-RNG stream or every Arduino/core version's random
algorithm. Other adapters must declare their RNG policy. A matching seed alone is
insufficient if two adapters consume different numbers of draws.

## Observed events

ADC, clock and RNG events describe intercepted firmware calls. They include kind,
frame, phase and returned value; ADC includes channel and clock includes units.
Initialization is distinguished from frame execution. Instrumentation-only
locations, sequence counters and host call sites are useful diagnostics but do not
by themselves define semantic equivalence between machine code and a port.

Event comparison must state which common read kinds were compared and how many
observations existed. An empty log is not successful evidence that two input paths
agree. Strict state/RGB comparison remains useful when only one implementation has
read instrumentation, but it must not claim read-log coverage.

## Audio model boundary

The seven-band model approximates filters, peak history, read-triggered decay,
gain, offset and clipping. Its transfer function and timing are not calibrated to
a particular microphone board. Firmware AGC and beat processing remain downstream
of ADC injection; duplicating them in the input model would test the wrong system.
Physical calibration data belongs in a private model configuration and provenance.

## Future extensions

A future typed read tape should specify clock, ADC and RNG observations in one
ordered stream, including initialization and callback scheduling, with explicit
exhaustion and leftover-input rules. Heterogeneous input channels and replay/time
alignment also need versioned contracts. They are not implied by the existing
`replay` execution label or the current frame trace schema.
