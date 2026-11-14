# Measured audio front ends

`vfl.calibration` turns measured tone responses into a reusable PCM-to-ADC
adapter. The model can include a speaker, room, microphone, preamplifier, and
filter chip as one measured path. Its scope belongs in the profile's provenance:
different playback settings or microphone positions require separate profiles.
Firmware smoothing, gain control, and beat detection still run in the firmware.

## Fit and validate a profile

Supply a quiet baseline and observations at one known normalized PCM peak
amplitude. Each observation has `frequency_hz`, one measured `values` entry per
channel, and optional `censored` booleans. Units are `millivolts` or `adc-counts`.
Use medians from trustworthy steady windows, retaining the original sample
counts, alignment uncertainty, and recording hashes in your private audit.

```python
from vfl.calibration import fit_tone_profile, evaluate_tones, predict_tone

# Synthetic example only; real observations and fitted profiles stay private.
observations = [
    {"frequency_hz": 100, "values": [110, 400]},
    {"frequency_hz": 1000, "values": [600, 160]},
    {"frequency_hz": 10000, "values": [120, 200]},
]
profile = fit_tone_profile(
    observations, baseline=[100, 150], input_peak=0.25,
    provenance={"scope": "synthetic example, fixed playback setting"},
)
prediction = predict_tone(profile, 1000)
```

For the CLI, wrap those fields in an object with
`"schema": "vfl.tone-observations.v1"`, `observations`, `baseline`, and
`input_peak`. Run `tycvl calibration fit observations.json --out profile.json`.
`tycvl calibration evaluate profile.json held-out.json` accepts an array of one
or more independent observations and reports any overlap with fitting frequencies.
An independent repeat may use the same frequency; a frequency match alone does
not establish or invalidate independence.

The fit interpolates nonnegative gain linearly on a logarithmic frequency axis.
Training-point error is therefore not evidence of predictive accuracy. Hold out
interior frequencies before fitting and pass them to `evaluate_tones`; also use
independent recordings of known tones. The report includes MAE, RMSE, bias,
sample counts, and a quiet-baseline comparison. It excludes a channel pair when
either its measurement or the neighboring fitted knots are censored.
Below-baseline responses are clamped to zero gain. This can bias noisy weak
responses upward; retain signed differences and baseline uncertainty in the
private measurement audit. The current boolean censor flag does not encode
which clipping endpoint supplied the bound. Keep that direction in the original
observations rather than treating a censored prediction as an estimate.

An ADC endpoint is a bound, not a recovered voltage. `piecewise_convert` applies
an explicitly supplied monotonic sensor calibration, clamping outside its
anchors. The caller must preserve the corresponding censor flags. A calibrated
measurement ADC and the firmware's own ADC are separate transfers.

## Feed a complete WAV into firmware

```python
from vfl.audio import read_wav_stream
from vfl.calibration import to_calibrated_trace

pcm = read_wav_stream("input.wav")
last_us = len(pcm.samples) * 1_000_000 // pcm.sample_rate_hz
trace = to_calibrated_trace(
    pcm, range(0, last_us + 1, 16_000), profile,
    adc_full_scale_mv=3300,  # Example assumption; supply your measured transfer.
)
```

The resulting `vfl.trace.v1` contains one ADC vector per requested firmware
frame. It is consumed by the same backend input mechanism as generated band
traces. Output channel count must match the target profile. A calibrated
millivolt profile requires an explicit `adc_full_scale_mv`; quantization is
nearest-half-up after clamping. This conversion does not model ADC caching or
pin/strobe timing.

`read_wav_stream` validates the entire integer-PCM WAV and keeps its encoded bytes
as an immutable snapshot, with a 128 MiB file limit. Sample slices decode on demand;
the full recording does not become millions of Python floats. The existing
five-million-sample limit still applies to `read_wav` and synthetic in-memory
`PCM`, while a streamed WAV may be longer for spectral conversion. Exporting raw
PCM or ADC-window traces also enforces the five-million-value output limit, so
streaming input cannot create an unbounded JSON trace. There is no truncation, resampling,
gain normalization, or file reread during conversion. A trace is limited to
100,000 frames. Adapters consume at most 65,536 decoded samples per batch even
when requested scans are far apart.

## What the PCM adapter approximates

`CalibratedFrontend` uses a trailing periodic-Hann window and a standard-library
radix-two FFT. It weights the one-sided spectrum with the measured response,
combines energy, and applies an optional hold with read-triggered decay. The
default 8192 samples at 48 kHz span 170.7 ms, resolve 5.86 Hz bins, and smear a transition
by roughly 85 ms. The default 0.10 decay fraction per scan is an assumption, not a
parameter recovered from steady tones; pass `decay_per_read` explicitly when a
separate temporal experiment supports another value.
The CLI exposes `--window-size`, `--decay-per-read`, `--energy-tolerance`, and
`--adc-maximum`. These require `--calibration`. Changing them changes the model;
the trace records every setting and its approximate analysis delay.

Steady sine amplitude is calibrated. Mixture phase, instantaneous peak behavior,
amplitude linearity, acoustic delay, microphone overload, and individual-read
noise are not identified by that experiment. In particular, a lower error on
steady tones does not establish event-exact beat timing or LED equality. Use
recorded ADC traces when isolating firmware behavior from front-end uncertainty.

After one complete analysis window, the adapter refuses frames with more than
1% of spectral energy outside its supported range or intersecting a censored
region. A margin of two FFT bins at either frequency endpoint uses the nearest
measured gain to accommodate the Hann main lobe; it is an explicit extension
assumption, not extra measured bandwidth. Warmup frames are retained and marked
`warmup: true` with `spectral_guard_enforced: false`, because zero-prefill itself
causes leakage. `allow_out_of_range=True` and `allow_censored=True` explicitly
permit exploratory conversion after warmup. Each frame records the outside,
censored and endpoint-extension energy shares, plus amplitude extrapolation
relative to the fitting level. These annotations expose uncertainty and do not
validate the result. Evaluate steady response after warmup and transient
response separately.

Runtime scales with requested scans and FFT window size. On each scan the
adapter computes one FFT; longer audio is supported but this Python reference
implementation is intended for offline experiments. Preserve timings alongside
your experiment rather than assuming real-time throughput.

Traces carry a normalized profile SHA256, window settings, energy-boundary
observations and ADC mapping. Profile provenance and coefficients remain in the
separate private profile by default. `provenance_mode="embedded"` or CLI
`--calibration-provenance embedded` includes them explicitly. Public source and tests contain only
synthetic fixtures. Store physical captures, observations, fitted coefficients,
and validation results outside the source checkout.
