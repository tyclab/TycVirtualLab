import unittest

from vfl.device_inputs import record_input_evidence
from vfl.model import LabError, execution_scope


def record(policy, settings, controls, events, scene=None):
    profile = {"id": "test", "settings": settings, "backend": {"options": {"ghidra": {"input_read_policy": policy}}}}
    trace = {"frames": [{"index": i, "controls": edit} for i, edit in enumerate(controls)]}
    capture = {"manifest": {}, "events": events, "frames": [{"state": {"scene-state": (scene or bytes(80)).hex()}} for _ in controls]}
    record_input_evidence(profile, trace, capture)
    return capture["manifest"]


class DeviceEvidenceTests(unittest.TestCase):
    def test_clock_and_reads_outside_sound_window_do_not_satisfy_cube_guard(self):
        options = {"fx": 90, "brightness": 255, "psd": 0}
        changes = [{}, {"fx": 122}, {"psd": 1}, {"psd": 0}]
        events = [{"kind": "adc", "frame": 0}, {"kind": "clock", "frame": 1}, {"kind": "adc", "frame": 3}]
        with self.assertRaisesRegex(LabError, "sound frames 1..1"):
            record("hypercube-adc", options, changes, events)
        checked = record("hypercube-adc", options, changes, events + [{"kind": "adc", "frame": 1}])
        self.assertEqual(checked["input_evidence"]["observed_in_required_frames"], 2)
        self.assertEqual(checked["clock"], {"source": "scheduled-frame-time", "frame_clock_reads": 1})

    def test_glorb_requires_a_frame_volume_load_not_lookup_or_setup(self):
        settings = {"sound_reactive": True}
        events = [{"kind": "control", "operation": "observe-entry", "observer_id": "audio-value-read", "frame": -1},
                  {"kind": "control", "operation": "observe-entry", "observer_id": "audio-lookup", "frame": 0}]
        with self.assertRaisesRegex(LabError, "processed-volume-load"):
            record("glorb-volume", settings, [{}], events)
        events.append({"kind": "control", "operation": "observe-entry", "observer_id": "audio-value-read", "frame": 0})
        self.assertEqual(record("glorb-volume", settings, [{}], events)["input_evidence"]["observed_frames"], 1)

    def test_exoy_selector_can_force_sound_off_or_on(self):
        scene = bytearray(80); scene[12] = 1
        result = record("exoy-adc", {"sound_reactive": True}, [{}], [], scene)["input_evidence"]
        self.assertEqual((result["guest_forced_off_frames"], result["observed_frames"]), (1, 0))
        scene[13] = 1
        with self.assertRaisesRegex(LabError, "adc-read"):
            record("exoy-adc", {"sound_reactive": False}, [{}], [], scene)

    def test_execution_scope_retains_legacy_kind_and_unknown_external_backend(self):
        for backend, kind, expected in (("ghidra-pcode", "original-firmware", "routine-diagnostic"),
                ("qemu-esp32-board", "original-firmware", "board-diagnostic"),
                ("glorb-host-v1", "recovered-code", "host-renderer"), ("other", "original-firmware", "unspecified")):
            self.assertEqual(execution_scope({"backend": backend, "execution_kind": kind}), expected)
