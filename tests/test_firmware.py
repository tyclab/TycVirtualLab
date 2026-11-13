"""Synthetic image fixtures only; no vendor firmware or extracted payloads."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

from vfl.firmware import inspect_image, MAX_IMAGE_BYTES
from vfl.model import LabError


def esp_image(chip_id=0, appended=True, extended=True):
    data = bytearray(struct.pack("<BBBBI", 0xE9, 2, 2, 0x20, 0x40001000))
    if extended:
        extra = bytearray(16)
        extra[0] = 0xEE
        struct.pack_into("<H", extra, 4, chip_id)
        extra[15] = int(appended)
        data.extend(extra)
    checksum = 0xEF
    for address, payload in ((0x3F400020, b"\x01\x02\x03\x04"), (0x40001000, b"\xa5\x5a\x00\xff")):
        data.extend(struct.pack("<II", address, len(payload)))
        data.extend(payload)
        for byte in payload:
            checksum ^= byte
    while len(data) % 16 != 15:
        data.append(0)
    data.append(checksum)
    if extended and appended:
        data.extend(hashlib.sha256(data).digest())
    return data


def elf_image(bits=32, endian="<", machine=94):
    """One load segment with four bytes of data and four bytes of BSS."""
    ident = b"\x7fELF" + bytes((1 if bits == 32 else 2, 1 if endian == "<" else 2, 1)) + bytes(9)
    if bits == 32:
        header = struct.pack(endian + "HHIIIIIHHHHHH", 2, machine, 1, 0x40000080, 52, 0, 0, 52, 32, 1, 0, 0, 0)
        program = struct.pack(endian + "IIIIIIII", 1, 128, 0x40000080, 0x40000080, 4, 8, 5, 16)
    else:
        header = struct.pack(endian + "HHIQQQIHHHHHH", 2, machine, 1, 0x40000080, 64, 0, 0, 64, 56, 1, 0, 0, 0)
        program = struct.pack(endian + "IIQQQQQQ", 1, 5, 128, 0x40000080, 0x40000080, 4, 8, 16)
    data = bytearray(ident + header + program)
    data.extend(bytes(128 - len(data)))
    data.extend(b"\x11\x22\x33\x44")
    return data


def elf_with_sections(extended=False):
    data = elf_image()
    data.extend(bytes(160 - len(data)))
    # NULL, PROGBITS, NOBITS; BSS occupies memory but has no file payload.
    data.extend(struct.pack("<IIIIIIIIII", 0, 0, 0, 0, 0, 3 if extended else 0, 0, 1 if extended else 0, 0, 0))
    data.extend(struct.pack("<IIIIIIIIII", 0, 1, 6, 0x40000080, 128, 4, 0, 0, 4, 0))
    data.extend(struct.pack("<IIIIIIIIII", 0, 8, 3, 0x40000084, 4096, 4, 0, 0, 4, 0))
    struct.pack_into("<I", data, 32, 160)
    struct.pack_into("<HH", data, 46, 40, 0 if extended else 3)
    if extended:
        struct.pack_into("<H", data, 44, 0xFFFF)
    return data


class FirmwareTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "synthetic.bin"

    def inspect(self, data, format="auto"):
        self.path.write_bytes(data)
        return inspect_image(self.path, format=format)

    def reject(self, data, message=None, format="auto"):
        if message:
            with self.assertRaisesRegex(LabError, message):
                self.inspect(data, format)
        else:
            with self.assertRaises(LabError):
                self.inspect(data, format)

    def test_esp_chip_id_distinguishes_lx6_and_lx7(self):
        for chip_id, chip, architecture in ((0, "ESP32", "Xtensa LX6"), (9, "ESP32-S3", "Xtensa LX7")):
            with self.subTest(chip=chip):
                data = esp_image(chip_id)
                result = self.inspect(data)
                self.assertEqual(result["schema"], "vfl.image.v1")
                self.assertTrue(result["valid"])
                self.assertEqual((result["chip_id"], result["chip"], result["architecture"]), (chip_id, chip, architecture))
                self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
                self.assertEqual(result["entry_point"], 0x40001000)
                self.assertEqual(result["segments"][0], {"index": 0, "load_address": 0x3F400020, "file_offset": 32, "file_size": 4})
                self.assertTrue(result["verification"]["checksum_valid"])
                self.assertTrue(result["verification"]["appended_sha256_valid"])
                self.assertFalse(result["verification"]["signature_verified"])

    def test_esp_checksum_only_and_unknown_chip_are_explicit(self):
        result = self.inspect(esp_image(chip_id=65535, appended=False))
        self.assertEqual(result["architecture"], "unknown")
        self.assertEqual(result["chip_id"], 65535)
        self.assertIsNone(result["verification"]["appended_sha256_valid"])
        self.assertIn("Unrecognized chip ID", " ".join(result["limitations"]))

    def test_esp8266_requires_explicit_selection(self):
        data = esp_image(extended=False)
        self.reject(data, "explicit esp8266")
        result = self.inspect(data, "esp8266")
        self.assertEqual(result["architecture"], "Xtensa L106")
        self.assertEqual(result["header_size"], 8)
        self.assertIsNone(result["chip_id"])

    def test_auto_rejects_image_valid_under_both_e9_layouts(self):
        # In the short header, bytes 12..15 mean a 16-byte segment. In
        # the extended header, they mean an unknown chip ID of 16. Both
        # interpretations have zero-valued payload XOR and the same footer.
        data = bytearray(struct.pack("<BBBBI", 0xE9, 1, 2, 0, 4))
        data.extend(bytes(16))
        struct.pack_into("<H", data, 12, 16)
        data.extend(struct.pack("<II", 4, 4))
        data.extend(bytes(15))
        data.append(0xEF)
        self.assertTrue(self.inspect(data, "esp32")["valid"])
        self.assertTrue(self.inspect(data, "esp8266")["valid"])
        self.reject(data, "matches both")

    def test_esp_detects_payload_checksum_corruption(self):
        data = esp_image()
        data[32] ^= 1
        self.reject(data, "checksum mismatch")

    def test_esp_hash_catches_xor_preserving_corruption(self):
        data = esp_image()
        data[32] ^= 1
        data[33] ^= 1
        self.reject(data, "SHA256 mismatch")

    def test_esp_hash_also_covers_header(self):
        data = esp_image()
        data[4] ^= 1
        self.reject(data, "SHA256 mismatch")

    def test_esp_rejects_bad_headers_segment_bounds_and_wrap(self):
        for offset, replacement, message in ((1, b"\x00", "segment count"), (19, b"\x01", "reserved"),
                                              (23, b"\x02", "hash flag"), (28, struct.pack("<I", 2**32 - 1), "bounds"),
                                              (24, struct.pack("<I", 2**32 - 2), "wraps")):
            with self.subTest(offset=offset):
                data = esp_image()
                data[offset:offset + len(replacement)] = replacement
                self.reject(data, message)

    def test_esp_rejects_truncation_nonzero_padding_and_trailers(self):
        data = esp_image()
        for size in (1, 23, 31, 35, 47, 63, len(data) - 1):
            with self.subTest(size=size):
                self.reject(data[:size])
        padding_corrupt = bytearray(data)
        padding_corrupt[48] = 1
        self.reject(padding_corrupt, "padding")
        self.reject(data + bytes(16), "trailing bytes")

    def test_elf_class_and_byte_order(self):
        for bits, endian, machine, architecture in ((32, "<", 94, "Xtensa (core/ABI unspecified)"),
                                                    (64, ">", 243, "RISC-V")):
            with self.subTest(bits=bits, endian=endian):
                result = self.inspect(elf_image(bits, endian, machine))
                self.assertEqual(result["elf_class"], bits)
                self.assertEqual(result["byte_order"], "little" if endian == "<" else "big")
                self.assertEqual(result["architecture"], architecture)
                self.assertEqual(result["segments"][0]["memory_size"], 8)
                self.assertIsNone(result["verification"]["embedded_checksum"])
                self.assertNotIn("chip_id", result)

    def test_elf_section_data_and_nobits_bounds_are_distinct(self):
        result = self.inspect(elf_with_sections())
        self.assertEqual(len(result["sections"]), 3)
        self.assertTrue(result["sections"][1]["has_file_data"])
        self.assertFalse(result["sections"][2]["has_file_data"])
        data = elf_with_sections()
        struct.pack_into("<I", data, 244, 1)  # Same oversized offset, now PROGBITS.
        self.reject(data, "section 2.*bounds")

    def test_elf_extended_counts_use_section_zero(self):
        result = self.inspect(elf_with_sections(extended=True))
        self.assertEqual(len(result["sections"]), 3)
        self.assertEqual(len(result["segments"]), 1)
        data = elf_image()
        struct.pack_into("<H", data, 44, 0xFFFF)
        self.reject(data, "extended counts")

    def test_elf_rejects_bad_identification_and_header(self):
        for offset, replacement in ((4, b"\x00"), (5, b"\x03"), (6, b"\x00"), (20, bytes(4)),
                                     (40, struct.pack("<H", 51)), (42, struct.pack("<H", 31)),
                                     (28, struct.pack("<I", 2**32 - 1))):
            with self.subTest(offset=offset):
                data = elf_image()
                data[offset:offset + len(replacement)] = replacement
                self.reject(data)

    def test_elf_rejects_load_bounds_size_alignment_and_overflow(self):
        for offset, value, message in ((56, 130, "bounds"), (68, 9, "file size larger"),
                                       (80, 3, "alignment"), (60, 0x40000081, "alignment mismatch"),
                                       (64, 2**32 - 4, "wraps")):
            with self.subTest(offset=offset):
                data = elf_image()
                struct.pack_into("<I", data, offset, value)
                # The oversized file-size case must stay within the file, so
                # its failure specifically exercises filesz <= memsz.
                if offset == 68:
                    data.extend(bytes(8))
                self.reject(data, message)

    def test_elf_rejects_bad_section_table_and_name_index(self):
        for offset, replacement, message in ((48, struct.pack("<H", 4), "section table.*bounds"),
                                              (50, struct.pack("<H", 3), "index out of range"),
                                              (50, struct.pack("<H", 1), "not a string table"),
                                              (164, struct.pack("<I", 1), "SHT_NULL"),
                                              (232, struct.pack("<I", 3), "alignment")):
            with self.subTest(offset=offset):
                data = elf_with_sections()
                data[offset:offset + len(replacement)] = replacement
                self.reject(data, message)

    def test_elf_truncation_and_unknown_machine(self):
        data = elf_image()
        for size in (4, 15, 51, 83, 131):
            with self.subTest(size=size):
                self.reject(data[:size])
        struct.pack_into("<H", data, 18, 65535)
        self.assertEqual(self.inspect(data)["architecture"], "unknown")

    def test_output_contains_metadata_only(self):
        result = self.inspect(elf_image())
        rendered = json.dumps(result)
        self.assertNotIn("11223344", rendered)
        self.assertNotIn(str(self.path), rendered)
        self.assertNotIn("payload", result)

    def test_rejects_unknown_magic_wrong_format_and_empty_file(self):
        self.reject(b"\xea" + bytes(100), "Unknown image magic")
        self.reject(elf_image(), "E9 magic", "esp32")
        self.reject(esp_image(), "ELF magic", "elf")
        self.reject(b"", "empty")
        self.reject(esp_image(), "Unknown image format", "guess")

    def test_rejects_missing_directory_and_oversized_files(self):
        with self.assertRaises(LabError):
            inspect_image(self.path)
        with self.assertRaises(LabError):
            inspect_image(self.path.parent)
        with self.path.open("wb") as handle:
            handle.truncate(MAX_IMAGE_BYTES + 1)
        with self.assertRaisesRegex(LabError, "exceeds 256 MiB"):
            inspect_image(self.path)

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "POSIX FIFO check")
    def test_nonregular_file_rejected_without_waiting_for_a_writer(self):
        os.mkfifo(self.path)
        with self.assertRaisesRegex(LabError, "regular file"):
            inspect_image(self.path)


if __name__ == "__main__":
    unittest.main()
