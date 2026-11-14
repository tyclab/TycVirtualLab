"""Deterministic PCM inputs and an explicitly approximate MSGEQ7 adapter.

The adapter is a filter bank followed by peak holds and read-triggered decay.
It is not a microphone circuit, ADC peripheral, or calibrated MSGEQ7 emulator.
Firmware gain, smoothing, and beat detection belong in the firmware under test.
"""

from dataclasses import dataclass, field
import hashlib
import io
import json
import math
from pathlib import Path
import random
import wave


CENTERS_HZ = (63, 160, 400, 1000, 2500, 6250, 16000)
MAX_PCM_SAMPLES = 5_000_000
MAX_TRACE_FRAMES = 100_000
MAX_WAV_BYTES = 128 * 1024 * 1024
FILTER_SOURCE = "https://www.w3.org/TR/audio-eq-cookbook/"
CHIP_SOURCE = "https://www.electronicsdatasheets.com/download/52e77fe8e34e24e37610de1f.pdf?format=pdf"


def _integer(value, name, minimum=0, maximum=2**63 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def _number(value, name, minimum=-math.inf, maximum=math.inf):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number")
    try:
        result = float(value)
    except OverflowError as exc:
        raise ValueError(f"{name} must be a finite number") from exc
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError(f"{name} must be finite and in [{minimum}, {maximum}]")
    return result


def _metadata(value):
    if not isinstance(value, dict):
        raise ValueError("provenance must be a JSON object")
    try:
        return json.loads(json.dumps(value, allow_nan=False))
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("provenance must contain finite JSON values") from exc


def _check_wav_layout(data):
    """Validate chunk bounds and integer PCM alignment before wave decodes it."""
    position = 12
    seen = set()
    while position < len(data):
        if len(data) - position < 8:
            raise ValueError("truncated WAV chunk header")
        tag = data[position:position + 4]
        size = int.from_bytes(data[position + 4:position + 8], "little")
        start = position + 8
        end = start + size
        if end > len(data):
            raise ValueError("truncated WAV chunk payload")
        if tag in (b"fmt ", b"data"):
            if tag in seen:
                raise ValueError("duplicate WAV format or data chunk")
            seen.add(tag)
        if tag == b"fmt ":
            if size < 16:
                raise ValueError("truncated WAV format")
            encoding = int.from_bytes(data[start:start + 2], "little")
            channels = int.from_bytes(data[start + 2:start + 4], "little")
            rate = int.from_bytes(data[start + 4:start + 8], "little")
            byte_rate = int.from_bytes(data[start + 8:start + 12], "little")
            alignment = int.from_bytes(data[start + 12:start + 14], "little")
            bits = int.from_bytes(data[start + 14:start + 16], "little")
            if encoding != 1 or bits not in (8, 16, 24, 32):
                raise ValueError("only format-1 integer PCM WAV at 8/16/24/32 bits is supported")
            if alignment != channels * (bits // 8) or byte_rate != rate * alignment:
                raise ValueError("inconsistent WAV frame alignment or byte rate")
        position = end
        # Accept the unpadded final odd data chunk emitted by Python's wave
        # writer; intervening odd chunks still require their alignment byte.
        if size % 2 and position < len(data):
            position += 1
    if not {b"fmt ", b"data"} <= seen:
        raise ValueError("WAV requires format and data chunks")


@dataclass(frozen=True)
class PCM:
    """Mono samples in [-1, 1], with a sample clock independent of firmware time."""

    sample_rate_hz: int
    samples: tuple[float, ...]
    provenance: dict = field(default_factory=dict)

    def __post_init__(self):
        _integer(self.sample_rate_hz, "sample_rate_hz", 1, 384_000)
        if not isinstance(self.samples, (list, tuple)):
            raise ValueError("samples must be a list or tuple")
        if not 1 <= len(self.samples) <= MAX_PCM_SAMPLES:
            raise ValueError(f"PCM must contain 1..{MAX_PCM_SAMPLES} samples")
        values = tuple(_number(x, "PCM sample", -1, 1) for x in self.samples)
        object.__setattr__(self, "samples", values)
        object.__setattr__(self, "provenance", _metadata(self.provenance))


class _WAVSamples:
    """Immutable encoded samples with bounded decoding at slice boundaries."""

    def __init__(self, raw, width, channels, channel, count):
        self._raw, self._width, self._channels = raw, width, channels
        self._channel, self._count = channel, count

    def __len__(self):
        return self._count

    def __getitem__(self, item):
        if isinstance(item, slice):
            start, end, step = item.indices(self._count)
            if step != 1:
                raise ValueError("WAV samples support contiguous slices only")
            return tuple(self._sample(i) for i in range(start, end))
        _integer(item, "sample index", 0, self._count - 1)
        return self._sample(item)

    def _sample(self, index):
        width = self._width
        start = index * self._channels * width
        selected = range(self._channels) if self._channel == "mean" else (self._channel,)
        total = count = 0
        for channel in selected:
            offset = start + channel * width
            word = self._raw[offset:offset + width]
            total += word[0] - 128 if width == 1 else int.from_bytes(word, "little", signed=True)
            count += 1
        return total / (count * float(1 << (8 * width - 1)))


@dataclass(frozen=True)
class WAVStream:
    """Validated WAV bytes decoded as requested, without an entire float array.

    The encoded file is retained as an immutable snapshot (at most 128 MiB).
    This avoids source changes during a long run and supports full recordings
    exceeding the in-memory PCM sample limit, without truncation or resampling.
    """

    sample_rate_hz: int
    samples: _WAVSamples
    provenance: dict

    def __post_init__(self):
        _integer(self.sample_rate_hz, "sample_rate_hz", 1, 384000)
        if not isinstance(self.samples, _WAVSamples):
            raise ValueError("WAVStream requires validated encoded samples")
        object.__setattr__(self, "provenance", _metadata(self.provenance))


def read_wav(path, channel="mean"):
    """Read integer PCM WAV (8/16/24/32-bit), selecting or averaging channels.

    Integer full scale is normalized by 2**(bits-1); 8-bit WAV is unsigned.
    No resampling, automatic gain, or normalization to the loudest sample occurs.
    """
    return _read_wav(path, channel, stream=False)


def read_wav_stream(path, channel="mean"):
    """Read a full bounded WAV into an encoded snapshot with lazy sample slices."""
    return _read_wav(path, channel, stream=True)


def _read_wav(path, channel, *, stream):
    source = Path(path)
    if source.stat().st_size > MAX_WAV_BYTES:
        raise ValueError("WAV exceeds size limit")
    data = source.read_bytes()
    if len(data) > MAX_WAV_BYTES:
        raise ValueError("WAV exceeds size limit")
    if (len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WAVE"
            or int.from_bytes(data[4:8], "little") + 8 != len(data)):
        raise ValueError("invalid or truncated RIFF/WAVE length")
    _check_wav_layout(data)
    try:
        with wave.open(io.BytesIO(data), "rb") as wav:
            channels = wav.getnchannels()
            width = wav.getsampwidth()
            rate = wav.getframerate()
            count = wav.getnframes()
            if wav.getcomptype() != "NONE" or width not in (1, 2, 3, 4):
                raise ValueError("only 8/16/24/32-bit integer PCM WAV is supported")
            sample_limit = MAX_WAV_BYTES if stream else MAX_PCM_SAMPLES
            if not 1 <= channels <= 64 or not 1 <= count <= sample_limit:
                raise ValueError("unsupported WAV channel or sample count")
            if channel != "mean":
                _integer(channel, "channel", 0, channels - 1)
            raw = wav.readframes(count + 1)
            if len(raw) != count * channels * width:
                raise ValueError("truncated or misaligned WAV sample data")
    except (wave.Error, EOFError) as exc:
        raise ValueError(f"unsupported or malformed WAV: {exc}") from exc
    provenance = {
        "kind": "wav", "sha256": hashlib.sha256(data).hexdigest(),
        "encoding": f"pcm_{'u' if width == 1 else 's'}{width * 8}le",
        "source_channels": channels, "channel_policy": channel,
        "source_frames": count, "normalization": "integer-full-scale",
    }
    samples = _WAVSamples(raw, width, channels, channel, count)
    if stream:
        provenance["decoding"] = "immutable-encoded-snapshot-with-lazy-sample-slices"
        return WAVStream(rate, samples, provenance)
    return PCM(rate, samples[:], provenance)


def synthesize(kind="sine", *, duration_us=1_000_000, sample_rate_hz=48_000,
               frequencies_hz=None, amplitude=0.5, seed=1, phase_rad=0.0,
               end_frequency_hz=None, clip=False):
    """Generate mono sine/mix/chirp/impulse/noise/silence with explicit clipping.

    In a mix, amplitude applies to each tone. Over-range mixtures fail unless
    clip=True; the provenance records the number of clipped samples.
    """
    if not isinstance(kind, str) or kind not in {"sine", "mix", "chirp", "impulse", "noise", "silence"}:
        raise ValueError("unknown PCM stimulus kind")
    _integer(sample_rate_hz, "sample_rate_hz", 1, 384_000)
    _integer(duration_us, "duration_us", 1)
    _integer(seed, "seed", 0, 2**32 - 1)
    if type(clip) is not bool:
        raise ValueError("clip must be boolean")
    amp = _number(amplitude, "amplitude", 0, 1)
    phase = _number(phase_rad, "phase_rad")
    count = duration_us * sample_rate_hz // 1_000_000
    if not 1 <= count <= MAX_PCM_SAMPLES:
        raise ValueError("duration produces an unsupported sample count")
    tones = []
    if kind in {"sine", "mix", "chirp"}:
        requested = [1000] if frequencies_hz is None else frequencies_hz
        if not isinstance(requested, (list, tuple)) or not 1 <= len(requested) <= 64:
            raise ValueError("frequencies_hz must contain 1..64 frequencies")
        tones = [_number(f, "frequency_hz", 0) for f in requested]
        if any(f <= 0 or f >= sample_rate_hz / 2 for f in tones):
            raise ValueError("frequencies must be strictly between zero and Nyquist")
        if kind != "mix" and len(tones) != 1:
            raise ValueError("sine and chirp require exactly one frequency")
    elif frequencies_hz is not None:
        raise ValueError("frequencies_hz only applies to sine/mix/chirp")
    end = None
    if kind == "chirp":
        end = _number(tones[0] if end_frequency_hz is None else end_frequency_hz,
                      "end_frequency_hz", 0)
        if not 0 < end < sample_rate_hz / 2:
            raise ValueError("chirp end frequency must be below Nyquist")
    elif end_frequency_hz is not None:
        raise ValueError("end_frequency_hz only applies to chirp")
    rng = random.Random(seed)
    samples = []
    clipped = 0
    for i in range(count):
        t = i / sample_rate_hz
        if kind == "silence":
            value = 0.0
        elif kind == "noise":
            value = amp * (2 * rng.random() - 1)
        elif kind == "impulse":
            value = amp if i == 0 else 0.0
        elif kind == "chirp":
            slope = (end - tones[0]) / (duration_us / 1_000_000)
            value = amp * math.sin(phase + 2 * math.pi * (tones[0] * t + slope * t * t / 2))
        else:
            value = amp * sum(math.sin(phase + 2 * math.pi * f * t) for f in tones)
        if abs(value) > 1:
            if not clip:
                raise ValueError("mixture exceeds normalized full scale; choose clip=True or lower amplitude")
            value = max(-1.0, min(1.0, value))
            clipped += 1
        samples.append(value)
    return PCM(sample_rate_hz, tuple(samples), {
        "kind": "synthetic-pcm", "generator": kind, "seed": seed,
        "requested_duration_us": duration_us, "frequencies_hz": tones,
        "end_frequency_hz": end, "amplitude_per_tone": amp,
        "phase_rad": phase, "clipping_enabled": clip, "clipped_samples": clipped,
    })


class MSGEQ7Approx:
    """Seven constant-peak-gain biquads, peak holds, and read-triggered decay.

    read_adc captures the held envelope, quantizes, then decays every channel.
    feed only advances filters and peak holds. Channels are read simultaneously;
    reset/strobe pins, their timing, analog leakage, and ADC caching are omitted.
    """

    def __init__(self, sample_rate_hz, *, q=6.0, decay_per_read=0.10,
                 adc_scale=1023.0, adc_offset=0.0, adc_maximum=1023):
        _integer(sample_rate_hz, "sample_rate_hz", 1, 384_000)
        if sample_rate_hz <= 2 * max(CENTERS_HZ):
            raise ValueError("MSGEQ7 approximation requires sample_rate_hz > 32000")
        self.sample_rate_hz = sample_rate_hz
        self.q = _number(q, "q", 0.01, 1000)
        self.decay_per_read = _number(decay_per_read, "decay_per_read", 0, 1)
        self.adc_scale = _number(adc_scale, "adc_scale", 0, 1e9)
        self.adc_offset = _number(adc_offset, "adc_offset", -1e9, 1e9)
        self.adc_maximum = _integer(adc_maximum, "adc_maximum", 1, 65535)
        self._coefficients = []
        for frequency in CENTERS_HZ:
            omega = 2 * math.pi * frequency / sample_rate_hz
            alpha = math.sin(omega) / (2 * self.q)
            a0 = 1 + alpha
            self._coefficients.append((alpha / a0, -alpha / a0,
                                       -2 * math.cos(omega) / a0, (1 - alpha) / a0))
        self._states = [[0.0, 0.0] for _ in CENTERS_HZ]
        self._peaks = [0.0] * 7
        self.samples_processed = 0
        self.reads = 0
        self.clipped_low = 0
        self.clipped_high = 0

    @property
    def envelopes(self):
        return tuple(self._peaks)

    def feed(self, samples):
        for sample in samples:
            x = _number(sample, "PCM sample", -1, 1)
            for k, (b0, b2, a1, a2) in enumerate(self._coefficients):
                z1, z2 = self._states[k]
                y = b0 * x + z1
                self._states[k] = [-a1 * y + z2, b2 * x - a2 * y]
                self._peaks[k] = max(self._peaks[k], abs(y))
            self.samples_processed += 1

    def read_adc(self):
        result = []
        for k, peak in enumerate(self._peaks):
            raw = self.adc_offset + self.adc_scale * peak
            self.clipped_low += raw < 0
            self.clipped_high += raw > self.adc_maximum
            result.append(int(math.floor(max(0.0, min(float(self.adc_maximum), raw)) + 0.5)))
            self._peaks[k] *= 1 - self.decay_per_read
        self.reads += 1
        return tuple(result)

    def metadata(self):
        return {
            "name": "vfl.msgeq7-approx.v1", "fidelity": "uncalibrated-approximation",
            "centers_hz": list(CENTERS_HZ), "q": self.q,
            "filter": "constant-0dB-peak-biquad", "filter_source": FILTER_SOURCE,
            "chip_source": CHIP_SOURCE, "sample_rate_hz": self.sample_rate_hz,
            "decay_per_read": self.decay_per_read,
            "adc_scale_counts_per_normalized_peak": self.adc_scale,
            "adc_offset_counts": self.adc_offset, "adc_maximum": self.adc_maximum,
            "quantization": "nearest-half-up-after-clamping",
            "samples_processed": self.samples_processed, "reads": self.reads,
            "clipped_low": self.clipped_low, "clipped_high": self.clipped_high,
            "limitations": ["No microphone/preamp calibration", "No strobe or reset timing",
                            "Simultaneous channel reads", "No ADC/Wi-Fi hardware behavior",
                            "Peak hold has no continuous leakage"],
        }


def _trace(input_spec, seed, provenance, frames):
    _integer(seed, "seed", 0, 2**32 - 1)
    return {"schema": "vfl.trace.v1", "input": input_spec, "seed": seed,
            "clock_policy": "frame", "provenance": provenance, "frames": frames}


def pcm_to_trace(pcm, block_samples=480, *, seed=1):
    """Produce mono PCM blocks; each timestamp marks the block's first sample.

    channels is the audio channel count (one), not the number of block samples.
    The final block may be shorter. Sample clock offsets use integer floor.
    """
    if not isinstance(pcm, (PCM, WAVStream)):
        raise ValueError("pcm must be a PCM or WAVStream object")
    _integer(seed, "seed", 0, 2**32 - 1)
    _integer(block_samples, "block_samples", 1, 65_536)
    if len(pcm.samples) > MAX_PCM_SAMPLES:
        raise ValueError("PCM trace exceeds total sample limit; use a shorter window or band conversion")
    count = (len(pcm.samples) + block_samples - 1) // block_samples
    if count > MAX_TRACE_FRAMES:
        raise ValueError("PCM trace exceeds frame limit")
    frames = [{"index": i, "time_us": start * 1_000_000 // pcm.sample_rate_hz,
               "values": list(pcm.samples[start:start + block_samples]), "controls": {}}
              for i, start in enumerate(range(0, len(pcm.samples), block_samples))]
    return _trace({"kind": "pcm", "channels": 1, "minimum": -1, "maximum": 1,
                   "units": "normalized", "sample_rate_hz": pcm.sample_rate_hz,
                   "block_samples": block_samples}, seed,
                  {"kind": "pcm-blocks", "source": _metadata(pcm.provenance),
                   "timestamp_semantics": "first sample in block; floor(sample_index * 1000000 / sample_rate_hz)"}, frames)


def pcm_to_adc_trace(pcm, *, gain, offset, samples_per_frame=64, maximum=4095,
                     units="adc-counts", frame_us=None, seed=1, tail="reject"):
    """Select chronological PCM windows and explicitly quantize them to ADC reads.

    Frames start at the supplied cadence, or at consecutive window boundaries.
    Intra-window spacing is the source PCM spacing, not measured hardware timing.
    """
    if not isinstance(pcm, (PCM, WAVStream)):
        raise ValueError("pcm must be a PCM or WAVStream object")
    gain = _number(gain, "gain", 0, 1e9)
    offset = _number(offset, "offset", -1e9, 1e9)
    _integer(samples_per_frame, "samples_per_frame", 1, 256)
    _integer(maximum, "maximum", 1, 65535)
    if not isinstance(units, str) or not units or len(units) > 128:
        raise ValueError("ADC units must be a nonempty string of at most 128 characters")
    if tail not in {"reject", "pad-silence"}:
        raise ValueError("tail must be reject or pad-silence")
    if frame_us is not None:
        _integer(frame_us, "frame_us", 1, 2**32)
        if frame_us * pcm.sample_rate_hz < samples_per_frame * 1_000_000:
            raise ValueError("ADC frame windows must not overlap")
        count = (len(pcm.samples) * 1_000_000 + frame_us * pcm.sample_rate_hz - 1) // (frame_us * pcm.sample_rate_hz)
    else:
        count = (len(pcm.samples) + samples_per_frame - 1) // samples_per_frame
    if not 1 <= count <= MAX_TRACE_FRAMES:
        raise ValueError("ADC trace exceeds frame limit or has no samples")
    if count * samples_per_frame > MAX_PCM_SAMPLES:
        raise ValueError("ADC trace exceeds total value limit")
    frames, clipped, padded = [], 0, 0
    for i in range(count):
        time = i * frame_us if frame_us is not None else i * samples_per_frame * 1_000_000 // pcm.sample_rate_hz
        start = time * pcm.sample_rate_hz // 1_000_000 if frame_us is not None else i * samples_per_frame
        samples = list(pcm.samples[start:start + samples_per_frame])
        missing = samples_per_frame - len(samples)
        if missing:
            if tail == "reject":
                raise ValueError("incomplete ADC window; explicitly select pad-silence or trim the input")
            samples.extend([0.0] * missing)
            padded += missing
        raw = [offset + gain * value for value in samples]
        clipped += sum(value < 0 or value > maximum for value in raw)
        frames.append({"index": i, "time_us": time, "controls": {},
                       "values": [int(math.floor(max(0, min(maximum, value)) + .5)) for value in raw]})
    return _trace({"kind": "scalar", "channels": samples_per_frame, "minimum": 0,
                   "maximum": maximum, "units": units}, seed,
                  {"kind": "pcm-adc-windows", "source": _metadata(pcm.provenance),
                   "gain_counts_per_normalized_sample": gain, "offset_counts": offset,
                   "sample_rate_hz": pcm.sample_rate_hz, "frame_us": frame_us,
                   "selection": "consecutive source samples at each frame start; gaps between windows are omitted",
                   "quantization": "nearest-half-up-after-clamping", "clipped_values": clipped,
                   "tail_policy": tail, "padded_samples": padded,
                   "fidelity": "caller-supplied ADC transfer and PCM spacing; not measured acquisition timing"}, frames)


def to_bands_trace(pcm, frame_times_us, *, seed=1, **model_options):
    """Read approximate band peaks at strictly increasing integer timestamps.

    At time t, floor(t * sample_rate_hz / 1e6) source samples have completed.
    Time starts at zero; input beyond the supplied PCM is rejected, not padded.
    Each timestamp represents a real scan; skipped scans must be omitted.
    """
    if not isinstance(pcm, (PCM, WAVStream)):
        raise ValueError("pcm must be a PCM or WAVStream object")
    _integer(seed, "seed", 0, 2**32 - 1)
    try:
        frame_times_us = iter(frame_times_us)
    except TypeError as exc:
        raise ValueError("frame_times_us must be an iterable of scan times") from exc
    model = MSGEQ7Approx(pcm.sample_rate_hz, **model_options)
    times = []
    previous = -1
    duration_ceiling = (len(pcm.samples) * 1_000_000 + pcm.sample_rate_hz - 1) // pcm.sample_rate_hz
    for t in frame_times_us:
        _integer(t, "time_us", 0, duration_ceiling)
        if t <= previous:
            raise ValueError("frame timestamps must be strictly increasing")
        if len(times) >= MAX_TRACE_FRAMES:
            raise ValueError("band trace exceeds frame limit")
        times.append(t)
        previous = t
    if not times:
        raise ValueError("at least one scan timestamp is required")
    frames = []
    position = 0
    for i, t in enumerate(times):
        end = min(len(pcm.samples), t * pcm.sample_rate_hz // 1_000_000)
        for start in range(position, end, 65_536):
            model.feed(pcm.samples[start:min(end, start + 65_536)])
        position = end
        frames.append({"index": i, "time_us": t, "values": list(model.read_adc()), "controls": {}})
    return _trace({"kind": "bands", "channels": 7, "minimum": 0,
                   "maximum": model.adc_maximum, "units": "adc-counts",
                   "centers_hz": list(CENTERS_HZ)}, seed,
                  {"kind": "modeled-pcm", "source": _metadata(pcm.provenance),
                   "timestamp_semantics": "scan after floor(time_us * sample_rate_hz / 1000000) completed samples",
                   "model": model.metadata()}, frames)
