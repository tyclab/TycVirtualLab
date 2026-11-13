"""The published contract contains valid, mutually consistent synthetic objects."""

from pathlib import Path
import unittest

from vfl.model import (digest, experiment_digest, load_json, validate_capture,
                       validate_profile, validate_trace)


class ContractExamplesTests(unittest.TestCase):
    def setUp(self):
        self.document = load_json(Path(__file__).resolve().parents[1] / "docs" / "contract.json")

    def test_primary_examples_validate_together_and_have_real_identity_hashes(self):
        profile = validate_profile(self.document["profile"])
        trace = validate_trace(self.document["trace"])
        capture = validate_capture(self.document["capture"], profile, trace)
        self.assertEqual(capture["manifest"]["input_sha256"], digest(trace))
        self.assertEqual(capture["manifest"]["profile_sha256"], digest(profile))
        self.assertEqual(capture["manifest"]["experiment_sha256"], experiment_digest(profile, trace))
        self.assertEqual(len(capture["frames"][0]["buses"]["main"]), 16 * 3 * 2)

    def test_external_request_and_response_contain_valid_objects_and_echoes(self):
        external = self.document["external_backend"]
        request = external["request"]
        self.assertEqual(request["schema"], "vfl.request.v1")
        profile = validate_profile(request["profile"])
        trace = validate_trace(request["trace"])
        self.assertEqual(profile["backend"], external["profile_backend"])
        self.assertEqual(profile["backend"]["kind"], "external")
        self.assertEqual(request["identities"], {
            "input_sha256": digest(trace), "profile_sha256": digest(profile),
            "experiment_sha256": experiment_digest(profile, trace),
        })
        self.assertRegex(request["request_id"], r"^[0-9a-f]{32}$")
        self.assertTrue(Path(request["workdir"]).is_absolute())
        capture = validate_capture(external["response_example"], profile, trace)
        self.assertEqual(capture["manifest"]["request_id"], request["request_id"])
        for key, value in request["identities"].items():
            self.assertEqual(capture["manifest"][key], value)
        self.assertEqual(capture["manifest"]["execution_kind"], profile["backend"]["execution_kind"])

    def test_every_nested_profile_trace_and_capture_is_valid(self):
        validators = {"vfl.profile.v1": validate_profile, "vfl.trace.v1": validate_trace,
                      "vfl.capture.v1": validate_capture}
        validated = []

        def visit(value):
            if isinstance(value, dict):
                schema = value.get("schema")
                if schema in validators:
                    validators[schema](value)
                    validated.append(schema)
                for nested in value.values():
                    visit(nested)
            elif isinstance(value, list):
                for nested in value:
                    visit(nested)

        visit(self.document)
        self.assertEqual(len(validated), 6)
        self.assertTrue(self.document["field_notes"]["state_encoding"])
        self.assertTrue(self.document["field_notes"]["experiment_sha256"])


if __name__ == "__main__":
    unittest.main()
