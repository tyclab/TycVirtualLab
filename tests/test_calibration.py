import copy
import math
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import wave

from vfl.audio import synthesize, read_wav, read_wav_stream, pcm_to_trace
from vfl.calibration import (CalibratedFrontend, evaluate_tones, fit_tone_profile,
                             piecewise_convert, predict_tone, profile_digest,
                             to_calibrated_trace, validate_profile)
from vfl.model import validate_trace


def fixture():
    # Entirely synthetic two-channel response with a flat pass band around 1kHz.
    return fit_tone_profile([
        {"frequency_hz": f, "values": [100 + .25*g, 150 + .25*h]}
        for f, g, h in [(100, 0, 2000), (500, 0, 100), (900, 2000, 0),
                        (1100, 2000, 0), (2000, 0, 100), (10000, 0, 100)]
    ], baseline=[100, 150], input_peak=.25, provenance={"kind": "synthetic-test"})


class CalibrationTests(unittest.TestCase):
    def test_log_interpolation_and_quiet_baseline(self):
        profile = fit_tone_profile([
            {"frequency_hz": 100, "values": [200]},
            {"frequency_hz": 400, "values": [600]}], baseline=[100], input_peak=.5)
        self.assertAlmostEqual(predict_tone(profile, 200)["values"][0], 400)
        self.assertEqual(predict_tone(profile, 200, input_peak=0)["values"], [100])
        self.assertTrue(predict_tone(profile, 200, input_peak=.1)["amplitude_extrapolated"])
        self.assertEqual(profile_digest(profile), profile_digest(copy.deepcopy(profile)))

    def test_sensor_conversion_and_censor_refusal(self):
        self.assertEqual(piecewise_convert(15, [0, 10, 20], [100, 300, 400]), 350)
        self.assertEqual(piecewise_convert(-4, [0, 10], [100, 200]), 100)
        with self.assertRaises(ValueError):
            piecewise_convert(4, [0, 0], [100, 200])
        profile = fixture()
        profile["knots"][2]["censored"][0] = True
        with self.assertRaisesRegex(ValueError, "censored"):
            predict_tone(profile, 1000)
        self.assertEqual(predict_tone(profile, 1000, allow_censored=True)["censored"], [True, False])
        with self.assertRaisesRegex(ValueError, "outside"):
            predict_tone(profile, 20)

    def test_error_reporting_never_counts_censored_pairs(self):
        profile = fixture()
        result = evaluate_tones(profile, [
            {"frequency_hz": 900, "values": [610, 150], "censored": [False, True]},
            {"frequency_hz": 1100, "values": [590, 150]}])
        self.assertEqual(result["overall"]["count"], 3)
        self.assertAlmostEqual(result["overall"]["mae"], 20/3)
        self.assertEqual(result["excluded_censored"], 1)
        self.assertEqual(result["channels"][0]["bias"], 0)

    def test_pcm_prediction_matches_known_tone_and_rejects_other_band(self):
        pcm = synthesize(duration_us=220000, frequencies_hz=[1000], amplitude=.25)
        model = CalibratedFrontend(fixture(), 48000)
        model.feed(pcm.samples)
        values = model.read()
        self.assertAlmostEqual(values[0], 600, delta=1)
        self.assertAlmostEqual(values[1], 150, delta=.1)

    def test_mixture_energy_and_amplitude_scaling_are_explicit(self):
        profile = fit_tone_profile([
            {"frequency_hz": 100, "values": [600]},
            {"frequency_hz": 10000, "values": [600]}], baseline=[100], input_peak=.25)
        pcm = synthesize("mix", duration_us=220000, frequencies_hz=[1000, 2000], amplitude=.125)
        model = CalibratedFrontend(profile, 48000)
        model.feed(pcm.samples)
        self.assertAlmostEqual(model.read()[0], 100 + math.sqrt(2)*250, delta=1)
        self.assertEqual(model.metadata()["mixture_rule"], "root-sum-squared-energy")
        self.assertEqual(model.metadata()["decay_status"], "assumed-not-fitted")

    def test_chunking_determinism_and_decay_after_silence(self):
        pcm = synthesize(duration_us=220000, amplitude=.25)
        whole = CalibratedFrontend(fixture(), 48000)
        chunks = CalibratedFrontend(fixture(), 48000)
        whole.feed(pcm.samples)
        for start in range(0, len(pcm.samples), 17):
            chunks.feed(pcm.samples[start:start+17])
        first = whole.read()
        self.assertEqual(first, chunks.read())
        whole.feed([0] * 8192)
        second = whole.read()
        self.assertAlmostEqual(second[0] - 100, (first[0] - 100)*.9)

    def test_runtime_refuses_unmeasured_and_censored_energy(self):
        profile = fixture()
        profile["knots"][2]["censored"][0] = True
        model = CalibratedFrontend(profile, 48000)
        model.feed(synthesize(duration_us=220000).samples)
        with self.assertRaisesRegex(ValueError, "censored"):
            model.read()
        model = CalibratedFrontend(fixture(), 48000)
        model.feed(synthesize(duration_us=220000, frequencies_hz=[15000]).samples)
        with self.assertRaisesRegex(ValueError, "outside"):
            model.read()

    def test_adc_conversion_trace_and_explicit_clipping(self):
        pcm = synthesize(duration_us=220000, amplitude=.25)
        trace = to_calibrated_trace(pcm, [200000, 220000], fixture(), adc_full_scale_mv=1000)
        validate_trace(trace)
        self.assertEqual(trace["frames"][0]["values"], [614, 153])
        clipped = to_calibrated_trace(pcm, [220000], fixture(), adc_full_scale_mv=500)
        self.assertEqual(clipped["frames"][0]["values"][0], 1023)
        self.assertEqual(clipped["provenance"]["adc"]["clipped_values"], 1)
        profile = fixture()
        profile["units"] = "adc-counts"
        with self.assertRaisesRegex(ValueError, "millivolt"):
            to_calibrated_trace(pcm, [220000], profile, adc_full_scale_mv=1000)

    def test_malformed_profiles_and_scan_times_fail_closed(self):
        for mutate in [lambda p: p.update(channels=True), lambda p: p.update(baseline=[1]),
                       lambda p: p["knots"][0].update(gain=[float("nan"), 1]),
                       lambda p: p["knots"][0].update(censored=[1, False]),
                       lambda p: p["knots"][1].update(frequency_hz=100)]:
            profile = fixture()
            mutate(profile)
            with self.assertRaises(ValueError):
                validate_profile(profile)
        with self.assertRaises(ValueError):
            CalibratedFrontend(fixture(), 48000, window_size=1000)
        pcm = synthesize(duration_us=220000)
        for times in [[], [2, 1], [1, 1], [220001], [True], [float("nan")]]:
            with self.assertRaises(ValueError):
                to_calibrated_trace(pcm, times, fixture(), adc_full_scale_mv=3300)

    def test_encoded_stream_decodes_identically_without_pcm_sample_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic.wav'
            with wave.open(str(path), 'wb') as wav:
                wav.setnchannels(2)
                wav.setsampwidth(2)
                wav.setframerate(48000)
                wav.writeframes(b''.join(n.to_bytes(2, 'little', signed=True)
                                         for n in [-32768, 0, 1234, 30000, -4, 4, 32767, 32767]))
            expected = read_wav(path)
            with mock.patch('vfl.audio.MAX_PCM_SAMPLES', 2):
                with self.assertRaises(ValueError):
                    read_wav(path)
                stream = read_wav_stream(path)
            self.assertEqual(stream.samples[:], expected.samples)
            self.assertEqual(stream.samples[1:3], expected.samples[1:3])
            self.assertEqual(pcm_to_trace(stream, 2)['frames'], pcm_to_trace(expected, 2)['frames'])
            # A run consumes immutable validated source bytes, not a changed path.
            path.write_bytes(b'changed')
            self.assertEqual(stream.samples[:], expected.samples)

    def test_profile_digest_is_stable_after_validation(self):
        profile = fixture()
        profile['knots'][0]['gain'][0] = 1e-20
        self.assertEqual(profile_digest(profile), profile_digest(validate_profile(profile)))

    def test_endpoint_main_lobe_has_no_silent_low_bias(self):
        profile = fit_tone_profile([
            {"frequency_hz":187.5,"values":[600]}, {"frequency_hz":3000,"values":[600]}],
            baseline=[100], input_peak=.25)
        for frequency in (187.5,3000):
            model=CalibratedFrontend(profile,48000)
            model.feed(synthesize(duration_us=220000,frequencies_hz=[frequency],amplitude=.25).samples)
            self.assertAlmostEqual(model.read()[0],600,delta=.05)
            self.assertGreater(model.last_read['endpoint_extension_energy_share'],.15)
            self.assertFalse(model.last_read['warmup'])
            self.assertFalse(model.last_read['amplitude_extrapolated'])

    def test_warmup_read_diagnostics_delay_and_private_profile_digest(self):
        profile=fit_tone_profile([
            {"frequency_hz":900,"values":[600]}, {"frequency_hz":1100,"values":[600]}],
            baseline=[100],input_peak=.25)
        pcm=synthesize(duration_us=220000,frequencies_hz=[1000],amplitude=.125)
        trace=to_calibrated_trace(pcm,[10000,220000],profile,adc_full_scale_mv=1000)
        self.assertEqual([f['calibration']['warmup'] for f in trace['frames']],[True,False])
        self.assertFalse(trace['frames'][0]['calibration']['spectral_guard_enforced'])
        self.assertTrue(trace['frames'][1]['calibration']['amplitude_extrapolated'])
        self.assertAlmostEqual(trace['frames'][1]['calibration']['energy_equivalent_peak_relative_to_fit'],.5,delta=.001)
        model=trace['provenance']['model']
        self.assertNotIn('profile',model)
        self.assertAlmostEqual(model['analysis_delay_us'],8192/48000*500000)
        self.assertIn('profile',CalibratedFrontend(profile,48000,provenance_mode='embedded').metadata())
        self.assertEqual(evaluate_tones(profile,[{'frequency_hz':900,'values':[601]}])['overall']['count'],1)

    def test_streamed_pcm_trace_retains_total_sample_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'bounded.wav'
            with wave.open(str(path),'wb') as wav:
                wav.setnchannels(1);wav.setsampwidth(2);wav.setframerate(48000)
                wav.writeframes(b'\0\0'*10)
            stream=read_wav_stream(path)
            with mock.patch('vfl.audio.MAX_PCM_SAMPLES',9):
                with self.assertRaisesRegex(ValueError,'total sample limit'):
                    pcm_to_trace(stream,2)


if __name__ == "__main__":
    unittest.main()
