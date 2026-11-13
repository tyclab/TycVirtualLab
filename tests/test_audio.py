import math
from pathlib import Path
import tempfile
import unittest
import wave

from vfl.audio import (CENTERS_HZ, MSGEQ7Approx, PCM, pcm_to_trace, read_wav,
                       synthesize, to_bands_trace)


class AudioTests(unittest.TestCase):
    def test_each_center_selects_its_own_channel(self):
        # Check measured filter output, not coefficients or a mirrored formula.
        for selected, frequency in enumerate(CENTERS_HZ):
            pcm = synthesize(duration_us=200_000, frequencies_hz=[frequency], amplitude=0.5)
            model = MSGEQ7Approx(pcm.sample_rate_hz)
            model.feed(pcm.samples)
            values = model.read_adc()
            others = [value for k, value in enumerate(values) if k != selected]
            with self.subTest(frequency=frequency):
                self.assertGreater(values[selected], 350)
                self.assertGreater(values[selected], 4 * max(others))

    def test_decay_occurs_on_reads_and_chunking_preserves_state(self):
        pcm = synthesize(duration_us=30_000, frequencies_hz=[1000])
        whole = MSGEQ7Approx(pcm.sample_rate_hz)
        chunks = MSGEQ7Approx(pcm.sample_rate_hz)
        whole.feed(pcm.samples)
        for start in range(0, len(pcm.samples), 47):
            chunks.feed(pcm.samples[start:start + 47])
        self.assertEqual(whole.envelopes, chunks.envelopes)
        held = whole.envelopes
        whole.feed([])
        self.assertEqual(held, whole.envelopes)
        whole.read_adc()
        for before, after in zip(held, whole.envelopes):
            self.assertAlmostEqual(after, before * 0.9)
        whole.read_adc()
        for before, after in zip(held, whole.envelopes):
            self.assertAlmostEqual(after, before * 0.81)
        self.assertEqual(whole.reads, 2)

    def test_adc_clipping_and_scale_are_explicit(self):
        pcm = synthesize(duration_us=50_000, amplitude=0.8)
        model = MSGEQ7Approx(48_000, adc_scale=10_000)
        model.feed(pcm.samples)
        values = model.read_adc()
        self.assertEqual(values[3], 1023)
        self.assertGreater(model.clipped_high, 0)
        negative_offset = MSGEQ7Approx(48_000, adc_offset=-10)
        self.assertEqual(negative_offset.read_adc(), (0,) * 7)
        self.assertEqual(negative_offset.clipped_low, 7)

    def test_synthesis_determinism_mixture_and_clipping(self):
        a = synthesize("noise", duration_us=10_000, seed=23)
        self.assertEqual(a, synthesize("noise", duration_us=10_000, seed=23))
        self.assertNotEqual(a.samples, synthesize("noise", duration_us=10_000, seed=24).samples)
        arguments = {"kind": "mix", "duration_us": 10_000,
                     "frequencies_hz": [1000, 1000], "amplitude": 0.8}
        with self.assertRaises(ValueError):
            synthesize(**arguments)
        clipped = synthesize(**arguments, clip=True)
        self.assertGreater(clipped.provenance["clipped_samples"], 0)
        self.assertEqual(max(clipped.samples), 1)
        low = synthesize("sine", duration_us=10_000, frequencies_hz=[1000], amplitude=0.1)
        summed = synthesize("mix", duration_us=10_000, frequencies_hz=[1000, 1000], amplitude=0.1)
        for single, double in zip(low.samples, summed.samples):
            self.assertAlmostEqual(double, 2 * single)

    def test_other_generators(self):
        silence = synthesize("silence", duration_us=1000)
        self.assertEqual(set(silence.samples), {0.0})
        impulse = synthesize("impulse", duration_us=1000, amplitude=0.7)
        self.assertEqual(impulse.samples[0], 0.7)
        self.assertEqual(set(impulse.samples[1:]), {0.0})
        chirp = synthesize("chirp", duration_us=20_000, frequencies_hz=[100], end_frequency_hz=2000)
        self.assertEqual(len(chirp.samples), 960)
        self.assertTrue(all(abs(value) <= 0.5 for value in chirp.samples))

    def test_wav_bit_depths_channel_selection_and_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            for width in (1, 2, 3, 4):
                midpoint = 1 << (8 * width - 1)
                # Two stereo frames: [-1, 0] and [0, maximum positive].
                integers = [0, 128, 128, 255] if width == 1 else [-midpoint, 0, 0, midpoint - 1]
                raw = bytes(integers) if width == 1 else b"".join(
                    n.to_bytes(width, "little", signed=True) for n in integers)
                path = Path(directory) / f"depth{width}.wav"
                with wave.open(str(path), "wb") as output:
                    output.setnchannels(2)
                    output.setsampwidth(width)
                    output.setframerate(48_000)
                    output.writeframes(raw)
                selected = read_wav(path, channel=0)
                averaged = read_wav(path)
                self.assertEqual(selected.samples, (-1.0, 0.0))
                self.assertEqual(averaged.samples[0], -0.5)
                self.assertAlmostEqual(averaged.samples[1], (midpoint - 1) / midpoint / 2)
                self.assertEqual(len(averaged.provenance["sha256"]), 64)
                with self.assertRaises(ValueError):
                    read_wav(path, channel=2)
                with self.assertRaises(ValueError):
                    read_wav(path, channel=True)

    def test_wav_truncation_and_malformed_header(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.wav"
            with wave.open(str(path), "wb") as output:
                output.setnchannels(1)
                output.setsampwidth(2)
                output.setframerate(48_000)
                output.writeframes(b"\x00\x00" * 10)
            valid = path.read_bytes()
            for invalid in (b"not a wave", valid[:-1], valid + b"trailing"):
                path.write_bytes(invalid)
                with self.assertRaises(ValueError):
                    read_wav(path)
            # Still reject a truncated data chunk when RIFF length was repaired.
            truncated = valid[:-1]
            truncated = truncated[:4] + (len(truncated) - 8).to_bytes(4, "little") + truncated[8:]
            path.write_bytes(truncated)
            with self.assertRaises(ValueError):
                read_wav(path)
            # wave itself rounds unusual bit depths to a byte width and ignores
            # a wrong byte rate. The input contract rejects both explicitly.
            for offset, replacement in ((34, (12).to_bytes(2, "little")),
                                        (28, (1).to_bytes(4, "little")),
                                        (20, (3).to_bytes(2, "little"))):
                malformed = valid[:offset] + replacement + valid[offset + len(replacement):]
                path.write_bytes(malformed)
                with self.assertRaises(ValueError):
                    read_wav(path)

    def test_trace_timestamps_and_scan_semantics(self):
        pcm = synthesize(duration_us=20_000)
        trace = to_bands_trace(pcm, [0, 10_000, 20_000], seed=3)
        self.assertEqual(trace["frames"][0]["values"], [0] * 7)
        self.assertGreater(trace["frames"][1]["values"][3], 100)
        self.assertEqual(trace["provenance"]["model"]["reads"], 3)
        self.assertEqual(trace["provenance"]["model"]["samples_processed"], 960)
        self.assertEqual(trace, to_bands_trace(pcm, [0, 10_000, 20_000], seed=3))
        blocks = pcm_to_trace(pcm, block_samples=400)
        self.assertEqual([f["time_us"] for f in blocks["frames"]], [0, 8333, 16666])
        self.assertEqual([len(f["values"]) for f in blocks["frames"]], [400, 400, 160])
        self.assertEqual(blocks["input"]["channels"], 1)
        self.assertEqual(tuple(x for f in blocks["frames"] for x in f["values"]), pcm.samples)

    def test_malformed_values_and_model_parameters(self):
        for value in (math.nan, math.inf, -math.inf, True, 1.1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                PCM(48_000, (value,))
        for rate in (True, 0, 48_000.0):
            with self.assertRaises(ValueError):
                PCM(rate, (0.0,))
        with self.assertRaises(ValueError):
            PCM(48_000, ())
        with self.assertRaises(ValueError):
            PCM(48_000, (0,), {"bad": math.nan})
        for kwargs in ({"q": 0}, {"q": math.nan}, {"decay_per_read": 1.1}, {"adc_scale": -1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                MSGEQ7Approx(48_000, **kwargs)
        with self.assertRaises(ValueError):
            MSGEQ7Approx(32_000)
        with self.assertRaises(ValueError):
            synthesize(frequencies_hz=[24_000])
        with self.assertRaises(ValueError):
            synthesize(seed=-1)
        pcm = synthesize(duration_us=1000)
        for times in (None, [], [0, 0], [100, 99], [-1], [1001], [True], [0.5]):
            with self.subTest(times=times), self.assertRaises(ValueError):
                to_bands_trace(pcm, times)
        with self.assertRaises(ValueError):
            pcm_to_trace(pcm, block_samples=0)
        with self.assertRaises(ValueError):
            pcm_to_trace(pcm, block_samples=65_537)


if __name__ == "__main__":
    unittest.main()
