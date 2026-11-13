import copy
import math
from pathlib import Path
import tempfile
import unittest

from vfl.audio import PCM, pcm_to_trace
from vfl.compare import compare
from vfl.demo import capture
from vfl.model import (LabError, compatible_input, digest, experiment_digest, load_json,
                       number, validate_capture, validate_profile, validate_trace)
from vfl.stimuli import generate_trace


def profile():
    return {"schema": "vfl.profile.v1", "id": "authored-test", "input": {
        "kind": "bands", "channels": 1, "minimum": 0, "maximum": 255, "units": "adc-counts"},
        "buses": [{"id": "main", "pixels": 4, "order": "GRB"}],
        "backend": {"kind": "demo"}, "firmware": [], "geometry": {"kind": "strips"}}


def identified_capture(p=None, t=None):
    p = profile() if p is None else p
    t = generate_trace(4, 1000, channels=1, maximum=255) if t is None else t
    result = capture(p, t)
    result["manifest"].update(input_sha256=digest(t), experiment_sha256=experiment_digest(p, t))
    return result


class CoreTests(unittest.TestCase):
    def test_json_rejects_duplicate_nonfinite_and_truncated(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "data.json"
            for data in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":'):
                p.write_text(data)
                with self.subTest(data=data), self.assertRaises(LabError):
                    load_json(p)

    def test_trace_rejects_clock_shape_units_and_nonfinite_errors(self):
        good = generate_trace(3, 1000, channels=1, maximum=255)
        for mutate in (
            lambda t: t["frames"][1].update(time_us=0),
            lambda t: t["frames"][1].update(index=4),
            lambda t: t["frames"][0].update(values=[0, 0]),
            lambda t: t["frames"][0].update(values=[math.nan]),
            lambda t: t["frames"][0].update(values=[256]),
            lambda t: t["frames"][0].update(values=[1.5]),
            lambda t: t["input"].update(units=""),
        ):
            bad = copy.deepcopy(good)
            mutate(bad)
            with self.assertRaises(LabError):
                validate_trace(bad)
        changed = copy.deepcopy(good)
        changed["input"]["units"] = "volts"
        validate_trace(changed)
        with self.assertRaisesRegex(LabError, "units"):
            compatible_input(profile(), changed)

    def test_pcm_block_clock_matches_samples(self):
        trace = pcm_to_trace(PCM(48_000, (0.1,) * 1000), block_samples=480)
        validate_trace(trace)
        trace["frames"][1]["time_us"] += 1
        with self.assertRaisesRegex(LabError, "sample index"):
            validate_trace(trace)

    def test_capture_requires_complete_rgb_schedule_and_state(self):
        p = profile()
        t = generate_trace(3, 1000, channels=1, maximum=255)
        for mutate in (
            lambda c: c["frames"].pop(),
            lambda c: c["frames"][1].update(time_us=1001),
            lambda c: c["frames"][0]["buses"].update(main="00"),
            lambda c: c["frames"][0].update(state={}),
            lambda c: c["manifest"].update(profile_id="different"),
        ):
            bad = capture(p, t)
            mutate(bad)
            with self.assertRaises(LabError):
                validate_capture(bad, p, t)

    def test_demo_deterministic_and_mask_blocks_feedback(self):
        p = profile()
        p["settings"] = {"pixel_access": "masked-black"}
        p["geometry"]["mask"] = {"main": [True, True, False, True]}
        t = generate_trace(5, 1000, channels=1, maximum=255, kind="silence")
        for frame in t["frames"]:
            frame["values"] = [48]  # phase advances four pixels, repeatedly writing pixel zero
        result = capture(p, t)
        self.assertEqual(result, capture(p, t))
        for frame in result["frames"]:
            raw = bytes.fromhex(frame["buses"]["main"])
            self.assertEqual(raw[6:9], b"\x00" * 3)
            self.assertEqual(raw[9:12], b"\x00" * 3)
        visible = copy.deepcopy(p)
        visible["settings"] = {}
        propagated = bytes.fromhex(capture(visible, t)["frames"][3]["buses"]["main"])
        self.assertNotEqual(propagated[9:12], b"\x00" * 3)

    def test_demo_rejects_unimplemented_controls(self):
        t = generate_trace(1, 1000, channels=1, maximum=255)
        t["frames"][0]["controls"] = {"effect": 1}
        with self.assertRaisesRegex(LabError, "control"):
            capture(profile(), t)
        t["frames"][0]["controls"] = {}
        t["clock_policy"] = "events"
        with self.assertRaisesRegex(LabError, "clock"):
            capture(profile(), t)

    def test_initialization_events_require_explicit_phase(self):
        result = identified_capture()
        event = {"kind": "clock", "frame": -1, "phase": "initialization", "time_us": 0, "value": 0}
        result["events"].insert(0, event)
        validate_capture(result)
        for phase in (None, "execution", ""):
            event["phase"] = phase
            with self.subTest(phase=phase), self.assertRaisesRegex(LabError, "initialization"):
                validate_capture(result)

    def test_compare_exact_first_rgb_difference_and_channel_order(self):
        left = identified_capture()
        self.assertEqual(compare(left, copy.deepcopy(left))["verdict"], "equal")
        right = copy.deepcopy(left)
        raw = bytearray.fromhex(right["frames"][2]["buses"]["main"])
        raw[4] ^= 1
        raw[7] ^= 1
        right["frames"][2]["buses"]["main"] = raw.hex()
        report = compare(left, right)
        self.assertEqual(report["frames_compared"], 2)
        self.assertEqual(report["first_difference"]["frame"], 2)
        self.assertEqual(report["first_difference"]["pixel"], 1)
        self.assertEqual(report["first_difference"]["channel"], "R")
        self.assertEqual(report["first_difference"]["byte_offset"], 4)

    def test_compare_state_length_tags_and_unavailable_scope(self):
        left = identified_capture()
        right = copy.deepcopy(left)
        right["frames"][1]["state"]["machine"] += "00"
        difference = compare(left, right)["first_difference"]
        self.assertEqual((difference["reason"], difference["frame"], difference["byte_offset"]), ("state", 1, 8))
        right["manifest"]["capabilities"]["state"] = False
        with self.assertRaisesRegex(LabError, "unavailable"):
            compare(left, right)
        self.assertEqual(compare(left, right, include_state=False)["verdict"], "equal")
        right = copy.deepcopy(left)
        right["frames"][0]["state"] = {"other": "00"}
        self.assertEqual(compare(left, right)["first_difference"]["reason"], "state-tag")

    def test_compare_state_hashes_and_encoding_scope(self):
        import hashlib
        left = identified_capture()
        right = copy.deepcopy(left)
        for capture in (left, right):
            capture["manifest"]["state_encoding"] = "sha256"
            for frame in capture["frames"]:
                frame["state"] = {name: hashlib.sha256(bytes.fromhex(value)).hexdigest()
                                  for name, value in frame["state"].items()}
        self.assertEqual(compare(left, right)["verdict"], "equal")
        right["frames"][1]["state"]["machine"] = "0" * 64
        self.assertEqual(compare(left, right)["first_difference"]["reason"], "state-hash")
        with self.assertRaisesRegex(LabError, "encodings"):
            compare(left, identified_capture())

    def test_compare_identity_missing_mismatch_or_invalid(self):
        left = identified_capture()
        for value in ("0" * 64, None, "", "not-a-hash"):
            right = copy.deepcopy(left)
            right["manifest"]["input_sha256"] = value
            with self.subTest(value=value), self.assertRaises(LabError):
                compare(left, right)
        missing = copy.deepcopy(left)
        del missing["manifest"]["input_sha256"]
        with self.assertRaises(LabError):
            compare(left, missing)
        # Two equally malformed identities must not establish comparability.
        left["manifest"]["input_sha256"] = None
        with self.assertRaises(LabError):
            compare(left, copy.deepcopy(left))

    def test_compare_events_scope_and_first_event(self):
        left = identified_capture()
        right = copy.deepcopy(left)
        right["events"][1]["value"] ^= 1
        self.assertEqual(compare(left, right)["verdict"], "equal")
        difference = compare(left, right, include_events=True)["first_difference"]
        self.assertEqual(difference, {"reason": "event", "event_index": 1})

    def test_events_normalize_locations_preserve_semantics_and_reject_empty_scope(self):
        left = identified_capture()
        right = copy.deepcopy(left)
        for event in right["events"]:
            event["call_site"] = "different-engine-address"
            event["sequence"] = 123
            event["entrypoint"] = "engine-specific-entry"
            event["return_address"] = "engine-specific-return"
            event["source"] = "different implementation"
            event["operation"] = "different operation name"
            event["argument_a2"] = 999
            event["state_before"] = 42
            event["state_after"] = 87
            event["phase"] = "frame"
        result = compare(left, right, include_events=True)
        self.assertEqual(result["verdict"], "equal")
        self.assertEqual(result["events_compared"], len(left["events"]))
        self.assertEqual(result["verification"], "unverified")
        right["events"][0]["units"] = "milliseconds"
        self.assertEqual(compare(left, right, include_events=True)["verdict"], "different")
        right["events"][0].pop("units")
        with self.assertRaisesRegex(LabError, "units"):
            compare(left, right, include_events=True)
        right = copy.deepcopy(left)
        right["events"][2]["channel"] = 7
        self.assertEqual(compare(left, right, include_events=True)["verdict"], "different")
        right["events"][2].pop("channel")
        with self.assertRaisesRegex(LabError, "channel"):
            compare(left, right, include_events=True)
        right = copy.deepcopy(left)
        for item in (left, right):
            item["events"][1].update(mode="bounded", bound=10, value=3)
        right["events"][1]["bound"] = 11
        self.assertEqual(compare(left, right, include_events=True)["verdict"], "different")
        right["events"][1].pop("bound")
        with self.assertRaisesRegex(LabError, "bound"):
            compare(left, right, include_events=True)
        right = copy.deepcopy(left)
        right["events"] = []
        with self.assertRaisesRegex(LabError, "empty"):
            compare(left, right, include_events=True)
        for capture in (left, right):
            capture["events"] = []
            capture["manifest"]["capabilities"].update(adc_log=False, clock_log=False, rng_log=False)
        with self.assertRaisesRegex(LabError, "no common"):
            compare(left, right, include_events=True)

    def test_backend_options_are_closed_and_typed(self):
        for settings in ({"hold_fiel": "HOLD"}, {"resource_lok": "lock"}, {"hold_file": 7},
                         {"resource_lock": []}, {"execution_kind": "original-firmware"}):
            bad = profile()
            bad["backend"].update(settings)
            with self.subTest(settings=settings), self.assertRaises(LabError):
                validate_profile(bad)
        for settings in ({"env": []}, {"env": {"A": 2}}, {"cwd": 7}, {"timeout_s": float("nan")},
                         {"queue_timeout_s": -1}, {"options": []}):
            bad = profile()
            bad["backend"] = {"kind": "external", "command": ["python3"], "execution_kind": "synthetic", **settings}
            with self.subTest(settings=settings), self.assertRaises(LabError):
                validate_profile(bad)

    def test_profile_and_asset_keys_are_closed_with_annotation_metadata(self):
        bad = profile()
        bad["setings"] = {}
        with self.assertRaisesRegex(LabError, "unknown profile"):
            validate_profile(bad)
        bad = profile()
        bad["firmware"] = [{"role": "fixture", "path": "fixture.bin", "sha265": "0" * 64}]
        with self.assertRaisesRegex(LabError, "unknown firmware asset"):
            validate_profile(bad)
        good = profile()
        good["metadata"] = {"note": "authored metadata is not execution settings"}
        good["firmware"] = [{"role": "fixture", "path": "fixture.bin", "metadata": {"note": "test only"}}]
        validate_profile(good)

    def test_empty_common_event_kind_is_omitted_and_counts_are_per_kind(self):
        left = identified_capture()
        right = copy.deepcopy(left)
        for item in (left, right):
            item["events"] = [event for event in item["events"] if event["kind"] != "adc"]
        result = compare(left, right, include_events=True)
        self.assertEqual(result["verdict"], "equal")
        self.assertEqual(result["scope"]["event_kinds"], ["clock", "rng"])
        self.assertEqual(result["scope"]["omitted_empty_event_kinds"], ["adc"])
        self.assertEqual(result["events_compared_by_kind"], {"clock": 4, "rng": 4})
        self.assertEqual(result["event_counts"]["left"]["adc"], 0)
        self.assertEqual(result["events_compared"], 8)
        right["events"].insert(0, {"kind": "adc", "frame": 0, "channel": 0, "value": 1})
        with self.assertRaisesRegex(LabError, "adc.*empty"):
            compare(left, right, include_events=True)

    def test_huge_numbers_fail_with_contract_error(self):
        with self.assertRaises(LabError):
            number(10**400, "large input")

    def test_object_or_array_enum_values_fail_with_contract_error(self):
        for mutate in (
            lambda p: p["input"].update(kind=[]),
            lambda p: p["backend"].update(kind={}),
            lambda p: p["buses"][0].update(order=[]),
            lambda p: p["buses"][0].update(stage={}),
            lambda p: p["geometry"].update(kind=[]),
        ):
            malformed = profile()
            mutate(malformed)
            with self.assertRaises(LabError):
                validate_profile(malformed)
        bad_trace = generate_trace(1, 1000)
        bad_trace["clock_policy"] = []
        with self.assertRaises(LabError):
            validate_trace(bad_trace)
        bad_capture = identified_capture()
        bad_capture["events"][0]["kind"] = {}
        with self.assertRaises(LabError):
            validate_capture(bad_capture)

    def test_geometry_requires_boolean_masks_and_unique_points(self):
        p = profile()
        p["geometry"]["mask"] = {"main": [True, True, 0, False]}
        with self.assertRaises(LabError):
            validate_profile(p)
        p = profile()
        point = {"bus": "main", "index": 0, "x": 0, "y": 0, "z": 0}
        p["geometry"] = {"kind": "points", "points": [point, point]}
        with self.assertRaises(LabError):
            validate_profile(p)


if __name__ == "__main__":
    unittest.main()
