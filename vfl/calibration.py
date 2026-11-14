"""Measured tone-response calibration and a deterministic PCM front end.

This fits the complete playback/acoustic/electronic path described by provenance.
It does not identify individual microphone, room, or MSGEQ7 components. Steady
tone interpolation is empirical; spectral mixture addition and temporal behavior
are approximations which require separate validation.
"""

from bisect import bisect_left
from collections import deque
from functools import lru_cache
import cmath
import hashlib
import json
import math
import statistics

from .audio import PCM, WAVStream, MAX_TRACE_FRAMES, _integer, _metadata, _number, _trace

SCHEMA = "vfl.tone-calibration.v1"
MAX_KNOTS = 4096


def piecewise_convert(value, input_points, output_points):
    """Clamped, monotonic sensor conversion; endpoints remain censored values."""
    x = _number(value, "sensor value")
    if not isinstance(input_points, (list, tuple)) or not isinstance(output_points, (list, tuple)):
        raise ValueError("sensor points must be lists")
    if not 2 <= len(input_points) == len(output_points) <= 256:
        raise ValueError("sensor conversion needs 2..256 paired points")
    xs = [_number(v, "input point") for v in input_points]
    ys = [_number(v, "output point") for v in output_points]
    if any(b <= a for a, b in zip(xs, xs[1:])) or any(b <= a for a, b in zip(ys, ys[1:])):
        raise ValueError("sensor calibration points must increase strictly")
    if x <= xs[0]:
        return ys[0]
    if x >= xs[-1]:
        return ys[-1]
    right = bisect_left(xs, x)
    fraction = (x - xs[right - 1]) / (xs[right] - xs[right - 1])
    return ys[right - 1] + fraction * (ys[right] - ys[right - 1])


def _rows(observations, channels, *, minimum=2):
    if not isinstance(observations, (list, tuple)) or not minimum <= len(observations) <= MAX_KNOTS:
        raise ValueError(f"observations must contain {minimum}..{MAX_KNOTS} tones")
    rows = []
    for observation in observations:
        if not isinstance(observation, dict):
            raise ValueError("each observation must be an object")
        frequency = _number(observation.get("frequency_hz"), "frequency_hz", 1e-9, 192000)
        values = observation.get("values")
        censored = observation.get("censored", [False] * channels)
        if not isinstance(values, list) or len(values) != channels:
            raise ValueError("observation values must match channel count")
        if not isinstance(censored, list) or len(censored) != channels or any(type(v) is not bool for v in censored):
            raise ValueError("censored must contain one boolean per channel")
        rows.append({"frequency_hz": frequency,
                     "values": [_number(v, "observed value", 0) for v in values],
                     "censored": list(censored)})
    rows.sort(key=lambda row: row["frequency_hz"])
    if any(a["frequency_hz"] == b["frequency_hz"] for a, b in zip(rows, rows[1:])):
        raise ValueError("duplicate tone frequencies must be aggregated explicitly")
    return rows


def fit_tone_profile(observations, *, baseline, input_peak, units="millivolts", provenance=None):
    """Fit nonnegative piecewise-linear gain on a log-frequency axis.

    Each observation contains frequency_hz, channel values, and optional censor
    booleans. All tones must have the same normalized digital input_peak. A
    censored value is retained as a bound, never silently reconstructed. Quiet
    baseline must be measured separately. No volume-level interpolation occurs.
    """
    if not isinstance(baseline, (list, tuple)) or not 1 <= len(baseline) <= 64:
        raise ValueError("baseline must contain 1..64 channels")
    baseline = [_number(v, "baseline", 0) for v in baseline]
    peak = _number(input_peak, "input_peak", 1e-12, 1)
    if units not in {"millivolts", "adc-counts"}:
        raise ValueError("calibration units must be millivolts or adc-counts")
    rows = _rows(observations, len(baseline))
    return {"schema": SCHEMA, "channels": len(baseline), "units": units,
            "baseline": baseline, "input_peak": peak,
            "interpolation": "linear-gain-on-log-frequency",
            "knots": [{"frequency_hz": r["frequency_hz"],
                       "gain": [_number(max(0.0, v - b) / peak, "fitted gain", 0, 1e12)
                                for v, b in zip(r["values"], baseline)],
                       "censored": r["censored"]} for r in rows],
            "provenance": _metadata({} if provenance is None else provenance),
            "limitations": ["Measured complete path at one playback setting and tone amplitude",
                            "Amplitude linearity, mixtures, and transient response are not fitted",
                            "Endpoint clipping supplies bounds, not recovered voltages",
                            "Quiet baseline drift and individual-read noise are not simulated"]}


def validate_profile(profile):
    if not isinstance(profile, dict) or profile.get("schema") != SCHEMA:
        raise ValueError("unsupported tone calibration schema")
    channels = _integer(profile.get("channels"), "channels", 1, 64)
    if profile.get("interpolation") != "linear-gain-on-log-frequency":
        raise ValueError("unsupported calibration interpolation")
    baseline = profile.get("baseline")
    if not isinstance(baseline, list) or len(baseline) != channels:
        raise ValueError("invalid calibration baseline")
    baseline = [_number(v, "baseline", 0) for v in baseline]
    peak = _number(profile.get("input_peak"), "input_peak", 1e-12, 1)
    knots = profile.get("knots")
    if not isinstance(knots, list) or not 2 <= len(knots) <= MAX_KNOTS:
        raise ValueError("invalid calibration knots")
    observations = []
    for knot in knots:
        if not isinstance(knot, dict) or not isinstance(knot.get("gain"), list) or len(knot["gain"]) != channels:
            raise ValueError("invalid calibration gain")
        gain = [_number(v, "gain", 0, 1e12) for v in knot["gain"]]
        observations.append({"frequency_hz": knot.get("frequency_hz"),
                             "values": [b + peak * g for b, g in zip(baseline, gain)],
                             "censored": knot.get("censored")})
    result = fit_tone_profile(observations, baseline=baseline, input_peak=peak,
                             units=profile.get("units"), provenance=profile.get("provenance", {}))
    # Preserve serialized gains exactly: reconstructing value-minus-baseline can
    # round a small coefficient away and make a profile's digest non-idempotent.
    result["knots"] = [{"frequency_hz": _number(k["frequency_hz"], "frequency_hz"),
                        "gain": [float(v) for v in k["gain"]], "censored": list(k["censored"])}
                       for k in sorted(knots, key=lambda k: k["frequency_hz"])]
    return result


def profile_digest(profile):
    valid = validate_profile(profile)
    return hashlib.sha256(json.dumps(valid, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


def _response(profile, frequency):
    knots = profile["knots"]
    frequencies = [k["frequency_hz"] for k in knots]
    if frequency < frequencies[0] or frequency > frequencies[-1]:
        raise ValueError("frequency lies outside calibrated range")
    right = bisect_left(frequencies, frequency)
    if right == 0 or frequencies[right] == frequency:
        return knots[right]["gain"], knots[right]["censored"]
    left = right - 1
    fraction = math.log(frequency / frequencies[left]) / math.log(frequencies[right] / frequencies[left])
    return ([a + fraction * (b - a) for a, b in zip(knots[left]["gain"], knots[right]["gain"])],
            [a or b for a, b in zip(knots[left]["censored"], knots[right]["censored"])])


def predict_tone(profile, frequency_hz, *, input_peak=None, allow_censored=False):
    valid = validate_profile(profile)
    frequency = _number(frequency_hz, "frequency_hz", 1e-9)
    peak = valid["input_peak"] if input_peak is None else _number(input_peak, "input_peak", 0, 1)
    if type(allow_censored) is not bool:
        raise ValueError("allow_censored must be boolean")
    gains, censored = _response(valid, frequency)
    if any(censored) and not allow_censored:
        raise ValueError("tone intersects censored calibration; only a bound is available")
    return {"values": [b + peak * g for b, g in zip(valid["baseline"], gains)],
            "censored": list(censored), "units": valid["units"],
            "amplitude_extrapolated": peak != valid["input_peak"]}


def evaluate_tones(profile, observations):
    """Report actual errors, omitting individually censored channel pairs."""
    valid = validate_profile(profile)
    rows = _rows(observations, valid["channels"], minimum=1)
    errors = [[] for _ in range(valid["channels"])]
    baselines = [[] for _ in errors]
    excluded = [0] * len(errors)
    for row in rows:
        gains, model_censored = _response(valid, row["frequency_hz"])
        for channel, (gain, actual) in enumerate(zip(gains, row["values"])):
            if row["censored"][channel] or model_censored[channel]:
                excluded[channel] += 1
                continue
            base = valid["baseline"][channel]
            errors[channel].append(base + valid["input_peak"] * gain - actual)
            baselines[channel].append(base - actual)
    def metrics(values, baseline_errors):
        if not values:
            return {"count": 0, "mae": None, "rmse": None, "bias": None, "baseline_mae": None}
        return {"count": len(values), "mae": statistics.fmean(abs(x) for x in values),
                "rmse": math.sqrt(statistics.fmean(x*x for x in values)),
                "bias": statistics.fmean(values),
                "baseline_mae": statistics.fmean(abs(x) for x in baseline_errors)}
    return {"units": valid["units"],
            "fit_frequency_overlap_hz": [r["frequency_hz"] for r in rows
                if r["frequency_hz"] in {k["frequency_hz"] for k in valid["knots"]}],
            "independence": "Frequency overlap alone does not establish whether observations are independent repeats.",
            "overall": metrics(sum(errors, []), sum(baselines, [])),
            "channels": [{**metrics(e, b), "excluded_censored": x}
                         for e, b, x in zip(errors, baselines, excluded)],
            "excluded_censored": sum(excluded)}


@lru_cache(maxsize=4)
def _fft_plan(n):
    swaps = []
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            swaps.append((i, j))
    stages = []
    width = 2
    while width <= n:
        step = cmath.exp(-2j * math.pi / width)
        rotations = []
        rotation = 1 + 0j
        for _ in range(width // 2):
            rotations.append(rotation)
            rotation *= step
        stages.append((width, tuple(rotations)))
        width *= 2
    return tuple(swaps), tuple(stages)


def _fft(values):
    """In-place radix-two DFT with cached, identically rounded twiddle recurrence."""
    n = len(values)
    swaps, stages = _fft_plan(n)
    for i, j in swaps:
        values[i], values[j] = values[j], values[i]
    for width, rotations in stages:
        for start in range(0, n, width):
            for k, rotation in enumerate(rotations):
                i = start + k
                even = values[i]
                odd = rotation * values[i + width // 2]
                values[i], values[i + width // 2] = even + odd, even - odd


class CalibratedFrontend:
    """Causal Hann-window spectral-energy model of a measured physical path.

    Steady sinusoids use the fitted peak response. Mixtures combine as energy,
    not true instantaneous peak: no phase response was measured. A trailing
    window delays transients by roughly half its duration. Read-triggered hold
    decay is an explicit assumption, not inferred from the steady-tone fit.
    """

    def __init__(self, profile, sample_rate_hz, *, window_size=8192,
                 decay_per_read=.10, allow_censored=False, allow_out_of_range=False,
                 energy_tolerance=.01, provenance_mode="digest"):
        self.profile = validate_profile(profile)
        self.sample_rate_hz = _integer(sample_rate_hz, "sample_rate_hz", 1, 384000)
        self.window_size = _integer(window_size, "window_size", 256, 32768)
        if window_size & (window_size - 1):
            raise ValueError("window_size must be a power of two")
        if self.profile["knots"][-1]["frequency_hz"] >= sample_rate_hz / 2:
            raise ValueError("calibrated frequencies must be below PCM Nyquist")
        if type(allow_censored) is not bool or type(allow_out_of_range) is not bool:
            raise ValueError("calibration overrides must be boolean")
        self.decay = _number(decay_per_read, "decay_per_read", 0, 1)
        self.tolerance = _number(energy_tolerance, "energy_tolerance", 0, 1)
        self.allow_censored = allow_censored
        self.allow_out_of_range = allow_out_of_range
        if provenance_mode not in {"digest", "embedded"}:
            raise ValueError("provenance_mode must be digest or embedded")
        self.provenance_mode = provenance_mode
        self._samples = deque([0.0] * window_size, maxlen=window_size)
        self._window = [.5 - .5 * math.cos(2 * math.pi * i / window_size) for i in range(window_size)]
        self._normalizer = window_size * sum(x*x for x in self._window)
        self._weights = []
        low = self.profile["knots"][0]["frequency_hz"]
        high = self.profile["knots"][-1]["frequency_hz"]
        padding = 2 * sample_rate_hz / window_size
        for i in range(window_size // 2 + 1):
            frequency = i * sample_rate_hz / window_size
            extended = False
            try:
                if low - padding <= frequency <= high + padding:
                    extended = not low <= frequency <= high
                    gains, censored = _response(self.profile, min(high, max(low, frequency)))
                else:
                    gains, censored = None, None
            except ValueError:
                gains, censored = None, None
            self._weights.append((gains, censored, extended))
        self._holds = [0.0] * self.profile["channels"]
        self.reads = self.samples_processed = self.censored_reads = self.out_of_range_reads = 0
        self.max_out_of_range_energy_share = self.max_censored_energy_share = 0.0
        self.max_endpoint_extension_share = self.max_amplitude_ratio = 0.0
        self.warmup_reads = self.amplitude_extrapolated_reads = 0
        self.last_read = {}

    def feed(self, samples):
        for sample in samples:
            self._samples.append(_number(sample, "PCM sample", -1, 1))
            self.samples_processed += 1

    def read(self):
        values = [complex(x*w) for x, w in zip(self._samples, self._window)]
        _fft(values)
        energy = [0.0] * self.profile["channels"]
        total = outside = censored_energy = extended_energy = 0.0
        for i, (gains, censored, extended) in enumerate(self._weights):
            power = abs(values[i]) ** 2 / self._normalizer
            if i not in (0, self.window_size // 2):
                power *= 2
            total += power
            if gains is None:
                outside += power
                continue
            if any(censored):
                censored_energy += power
            if extended:
                extended_energy += power
            for channel, gain in enumerate(gains):
                energy[channel] += 2 * power * gain * gain
        outside_share = outside / total if total > 1e-24 else 0.0
        censored_share = censored_energy / total if total > 1e-24 else 0.0
        extended_share = extended_energy / total if total > 1e-24 else 0.0
        amplitude_ratio = math.sqrt(2 * total) / self.profile["input_peak"]
        extrapolated = abs(amplitude_ratio - 1) > .01
        warmup = self.samples_processed < self.window_size
        self.last_read = {"out_of_range_energy_share": outside_share, "censored_energy_share": censored_share,
                          "endpoint_extension_energy_share": extended_share, "warmup": warmup,
                          "spectral_guard_enforced": not warmup,
                          "energy_equivalent_peak_relative_to_fit": amplitude_ratio,
                          "amplitude_extrapolated": extrapolated}
        self.warmup_reads += warmup
        self.amplitude_extrapolated_reads += extrapolated
        self.max_endpoint_extension_share = max(self.max_endpoint_extension_share, extended_share)
        self.max_amplitude_ratio = max(self.max_amplitude_ratio, amplitude_ratio)
        self.max_out_of_range_energy_share = max(self.max_out_of_range_energy_share, outside_share)
        self.max_censored_energy_share = max(self.max_censored_energy_share, censored_share)
        if outside_share > self.tolerance:
            if not warmup and not self.allow_out_of_range:
                raise ValueError("PCM energy lies outside calibrated frequency range")
            self.out_of_range_reads += 1
        if censored_share > self.tolerance:
            if not warmup and not self.allow_censored:
                raise ValueError("PCM energy intersects censored calibration")
            self.censored_reads += 1
        self._holds = [max(math.sqrt(e), held) for e, held in zip(energy, self._holds)]
        result = tuple(base + held for base, held in zip(self.profile["baseline"], self._holds))
        self._holds = [held * (1 - self.decay) for held in self._holds]
        self.reads += 1
        return result

    def metadata(self):
        result = {"name": "vfl.calibrated-spectral-frontend.v2", "profile_sha256": profile_digest(self.profile),
                "provenance_mode": self.provenance_mode, "sample_rate_hz": self.sample_rate_hz,
                "window_size": self.window_size, "window_duration_us": self.window_size * 1e6 / self.sample_rate_hz,
                "analysis_delay_us": self.window_size * 5e5 / self.sample_rate_hz,
                "endpoint_extension_hz": 2 * self.sample_rate_hz / self.window_size,
                "endpoint_extension_rule": "Hann main-lobe margin uses the closest measured endpoint gain",
                "frequency_bin_hz": self.sample_rate_hz / self.window_size,
                "window": "trailing-periodic-Hann-with-zero-prefill", "mixture_rule": "root-sum-squared-energy",
                "decay_per_read": self.decay, "decay_status": "assumed-not-fitted",
                "energy_tolerance": self.tolerance, "allow_censored": self.allow_censored,
                "allow_out_of_range": self.allow_out_of_range, "reads": self.reads,
                "samples_processed": self.samples_processed, "censored_reads": self.censored_reads,
                "out_of_range_reads": self.out_of_range_reads,
                "max_out_of_range_energy_share": self.max_out_of_range_energy_share,
                "max_censored_energy_share": self.max_censored_energy_share,
                "max_endpoint_extension_energy_share": self.max_endpoint_extension_share,
                "warmup_reads": self.warmup_reads, "amplitude_extrapolated_reads": self.amplitude_extrapolated_reads,
                "max_energy_equivalent_peak_relative_to_fit": self.max_amplitude_ratio}
        if self.provenance_mode == "embedded":
            result["profile"] = self.profile
        return result


def to_calibrated_trace(pcm, frame_times_us, profile, *, adc_full_scale_mv,
                        adc_maximum=1023, seed=1, **model_options):
    """Convert measured-path voltages to firmware ADC counts on explicit scans.

    adc_full_scale_mv must be supplied: sensor calibration is not a measurement
    of the firmware ADC's divider/reference. Conversion uses nearest-half-up.
    """
    if not isinstance(pcm, (PCM, WAVStream)):
        raise ValueError("pcm must be a PCM or WAVStream object")
    full_scale = _number(adc_full_scale_mv, "adc_full_scale_mv", 1e-9, 1e9)
    maximum = _integer(adc_maximum, "adc_maximum", 1, 65535)
    _integer(seed, "seed", 0, 2**32 - 1)
    model = CalibratedFrontend(profile, pcm.sample_rate_hz, **model_options)
    if model.profile["units"] != "millivolts":
        raise ValueError("ADC conversion requires a millivolt calibration")
    times = []
    duration = len(pcm.samples) * 1_000_000 // pcm.sample_rate_hz
    try:
        iterator = iter(frame_times_us)
    except TypeError as exc:
        raise ValueError("scan times must be iterable") from exc
    for time in iterator:
        _integer(time, "time_us", 0, duration)
        if len(times) >= MAX_TRACE_FRAMES or (times and time <= times[-1]):
            raise ValueError("scan times must increase and stay within frame limit")
        times.append(time)
    if not times:
        raise ValueError("at least one scan is required")
    position = clipped = 0
    frames = []
    for i, time in enumerate(times):
        end = time * pcm.sample_rate_hz // 1_000_000
        for start in range(position, end, 65_536):
            model.feed(pcm.samples[start:min(end, start + 65_536)])
        position = end
        raw = [v * maximum / full_scale for v in model.read()]
        clipped += sum(v > maximum or v < 0 for v in raw)
        frames.append({"index": i, "time_us": time,
                       "values": [int(math.floor(max(0, min(maximum, v)) + .5)) for v in raw], "controls": {},
                       "calibration": dict(model.last_read)})
    return _trace({"kind": "bands", "channels": model.profile["channels"], "minimum": 0,
                   "maximum": maximum, "units": "adc-counts"}, seed,
                  {"kind": "calibrated-pcm", "source": _metadata(pcm.provenance), "model": model.metadata(),
                   "adc": {"full_scale_mv": full_scale, "maximum": maximum,
                           "mapping_status": "caller-supplied-transfer-not-identified-by-tone-fit",
                           "quantization": "nearest-half-up-after-clamping", "clipped_values": clipped},
                   "timestamp_semantics": "scan after floor(time_us * sample_rate_hz / 1000000) completed samples"}, frames)
