import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from tests.test_firmware import esp_image
from vfl.devices.glorb_audio import compare_to_factory, flash_image, measure
from vfl.model import LabError


class GlorbAudioTests(unittest.TestCase):
    def test_unknown_esp32s3_application_is_rejected_before_launch(self):
        with tempfile.TemporaryDirectory() as base:
            image = Path(base) / 'unknown.bin'
            image.write_bytes(esp_image(chip_id=9))
            with self.assertRaisesRegex(LabError, 'unsupported GLORB application SHA256'):
                measure(image, b'', 'unused-qemu', 'unused-gdb', base, 1)

    def test_single_factory_partition_without_saved_device_settings(self):
        flash = flash_image(b'boot', b'app')
        self.assertEqual(len(flash), 8 * 1024 * 1024)
        self.assertEqual(flash[:5], b'boot\xff')
        self.assertEqual(flash[0x10000:0x10004], b'app\xff')
        entry = flash[0x8000:0x8020]
        self.assertEqual(struct.unpack('<HBBII', entry[:12]), (0x50aa, 0, 0, 0x10000, 0x300000))
        self.assertEqual(flash[0x8030:0x8040], hashlib.md5(entry, usedforsecurity=False).digest())
        self.assertEqual(set(flash[0x8040:0x10000]), {255})

    def test_compares_spectrum_and_buffer_independently_on_matching_input(self):
        original = dict(case='soft', block=1, input_sha256='a', filtered_sha256='b',
                        fft_magnitude=200, fft_major_peak_hz=689)
        factory = dict(application='GLORB.1.3', blocks=[original])
        measured = dict(application='fleet', blocks=[dict(original, fft_magnitude=300)])
        case = compare_to_factory([factory, measured])[0]['cases']['soft']
        self.assertEqual(case, dict(blocks=1, same_filtered_buffer=1, same_spectrum=0))
        measured['blocks'][0]['input_sha256'] = 'c'
        with self.assertRaisesRegex(LabError, 'different inputs'):
            compare_to_factory([factory, measured])
