import hashlib
from pathlib import Path
import tempfile
import unittest

from test_firmware import elf_image, esp_image
from vfl.identity import validate_asset_targets, validate_target
from vfl.model import LabError


class TargetIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def inspect(self, data, image_format, target):
        path = Path(self.tmp.name) / "authored-image"
        path.write_bytes(data)
        profile = {"target": target, "firmware": [{"role": "application", "path": str(path), "format": image_format}]}
        record = {"role": "application", "path": str(path), "sha256": hashlib.sha256(data).hexdigest()}
        return validate_asset_targets(profile, [record])

    def test_unknown_remains_explicit_and_target_fields_are_typed(self):
        self.assertEqual(validate_target()["abi"], "unspecified")
        for bad in ([], {}, {"chip": "esp32", "isa": [], "abi": "unknown"}):
            with self.subTest(bad=bad), self.assertRaises(LabError):
                validate_target(bad)

    def test_esp32_and_s3_mismatch_cannot_pass_on_same_xtensa_family(self):
        target = {"chip": "esp32", "isa": "xtensa-lx6", "abi": "xtensa-windowed"}
        result = self.inspect(esp_image(0), "esp32", target)
        self.assertEqual(result[0]["checked"], ["chip", "isa"])
        self.assertIn("abi", result[0]["unverified"])
        with self.assertRaisesRegex(LabError, "target.chip"):
            self.inspect(esp_image(9), "esp32", target)

    def test_elf_does_not_certify_xtensa_chip_or_abi(self):
        target = {"chip": "esp32-s3", "isa": "xtensa-lx7", "abi": "xtensa-windowed"}
        result = self.inspect(elf_image(machine=94), "elf", target)
        self.assertEqual(result[0]["checked"], ["isa-family"])
        self.assertIn("chip", result[0]["unverified"])
        self.assertIn("abi", result[0]["unverified"])
        with self.assertRaisesRegex(LabError, "ISA family"):
            self.inspect(elf_image(machine=40), "elf", target)

    def test_esp8266_explicit_format_is_not_a_chip_id(self):
        target = {"chip": "esp8266", "isa": "xtensa-lx106", "abi": "xtensa-call0"}
        result = self.inspect(esp_image(extended=False, appended=False), "esp8266", target)
        self.assertEqual(result[0]["checked"], [])
        self.assertIn("chip", result[0]["unverified"])
