import copy
import unittest

from vfl.compare import compare
from vfl.demo import capture
from vfl.model import LabError, digest, experiment_digest, validate_capture
from vfl.stimuli import generate_trace


class StateHashTests(unittest.TestCase):
    def setUp(self):
        self.profile = {
            "schema": "vfl.profile.v1", "id": "hash-test",
            "input": {"kind": "bands", "channels": 7, "minimum": 0, "maximum": 1023, "units": "adc-counts"},
            "backend": {"kind": "demo"}, "buses": [{"id": "main", "pixels": 2, "order": "RGB"}],
        }
        trace = generate_trace(2, 16000)
        self.original = capture(self.profile, trace)
        self.original["manifest"].update(input_sha256=digest(trace), experiment_sha256=experiment_digest(self.profile, trace))
        self.hashed = copy.deepcopy(self.original)
        self.hashed["manifest"]["state_encoding"] = "sha256"
        for frame in self.hashed["frames"]:
            frame["state"] = {name: digest(value) for name, value in frame["state"].items()}

    def test_hash_difference_does_not_claim_raw_byte_offset(self):
        altered = copy.deepcopy(self.hashed)
        altered["frames"][1]["state"]["machine"] = "ab" * 32
        result = compare(self.hashed, altered)
        self.assertEqual(result["first_difference"]["reason"], "state-hash")
        self.assertEqual(result["first_difference"]["frame"], 1)
        self.assertNotIn("byte_offset", result["first_difference"])
        self.assertEqual(compare(self.hashed, altered, include_state=False)["verdict"], "equal")

    def test_mixed_encoding_and_wrong_size_fail(self):
        with self.assertRaises(LabError):
            compare(self.original, self.hashed)
        self.hashed["frames"][0]["state"]["machine"] = "00"
        with self.assertRaises(LabError):
            validate_capture(self.hashed)
