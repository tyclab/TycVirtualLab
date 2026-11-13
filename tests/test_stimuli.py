import unittest

from vfl.stimuli import generate_trace


class StimuliTests(unittest.TestCase):
    def test_all_generators_have_valid_clocks_and_ranges(self):
        for kind in ("music-noise", "silence", "steps", "ramp", "impulses"):
            trace = generate_trace(80, 16_000, kind=kind, maximum=255, channels=4)
            self.assertEqual(trace["schema"], "vfl.trace.v1")
            self.assertEqual(trace["input"]["units"], "adc-counts")
            for i, frame in enumerate(trace["frames"]):
                self.assertEqual(frame["index"], i)
                self.assertEqual(frame["time_us"], i * 16_000)
                self.assertEqual(len(frame["values"]), 4)
                self.assertTrue(all(type(v) is int and 0 <= v <= 255 for v in frame["values"]))

    def test_silence_ramp_and_isolated_band_steps(self):
        silence = generate_trace(2, 1, kind="silence")
        self.assertTrue(all(frame["values"] == [0] * 7 for frame in silence["frames"]))
        ramp = generate_trace(5, 1, kind="ramp", maximum=100)
        self.assertEqual([f["values"][0] for f in ramp["frames"]], [0, 25, 50, 75, 100])
        steps = generate_trace(48, 1, kind="steps", channels=3)
        self.assertEqual(steps["frames"][0]["values"], [1023, 0, 0])
        self.assertEqual(steps["frames"][16]["values"], [0, 1023, 0])
        self.assertEqual(steps["frames"][32]["values"], [0, 0, 1023])
        impulses = generate_trace(32, 1, kind="impulses", channels=2)
        self.assertEqual(impulses["frames"][0]["values"], [1023, 0])
        self.assertEqual(impulses["frames"][1]["values"], [0, 0])
        self.assertEqual(impulses["frames"][31]["values"], [0, 1023])

    def test_seed_repeats_music_but_changes_noise(self):
        one = generate_trace(100, 16_000, seed=7)
        self.assertEqual(one, generate_trace(100, 16_000, seed=7))
        self.assertNotEqual(one["frames"], generate_trace(100, 16_000, seed=8)["frames"])

    def test_malformed_settings(self):
        for kwargs in ({"frames": 0}, {"frames": True}, {"frames": 100_001},
                       {"frame_us": 0}, {"frame_us": 1.5}, {"channels": 0},
                       {"channels": 65}, {"maximum": 0}, {"maximum": 65536},
                       {"seed": -1}, {"seed": 2**32}, {"kind": "unknown"}):
            settings = {"frames": 2, "frame_us": 16_000, **kwargs}
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                generate_trace(**settings)


if __name__ == "__main__":
    unittest.main()
