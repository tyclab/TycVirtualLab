"""Read-only image metadata, with structural and available integrity checks.

Formats: Espressif's documented E9 images and the System V ELF gABI.
No instructions, firmware strings, section payloads or device code are emitted.
"""

from __future__ import annotations

from functools import reduce
import hashlib
import operator
import os
import stat
import struct

from .model import LabError


MAX_IMAGE_BYTES = 256 * 1024 * 1024
MAX_TABLE_ENTRIES = 100000
ESP_CHIPS = {0: ("ESP32", "Xtensa LX6"), 9: ("ESP32-S3", "Xtensa LX7")}
ELF_MACHINES = {3: "Intel 80386", 40: "ARM", 62: "AMD x86-64", 94: "Xtensa (core/ABI unspecified)", 183: "AArch64", 243: "RISC-V"}
FORMAT_SOURCES = {
    "esp32": "https://docs.espressif.com/projects/esptool/en/latest/esp32/advanced-topics/firmware-image-format.html",
    "esp8266": "https://docs.espressif.com/projects/esptool/en/latest/esp8266/advanced-topics/firmware-image-format.html",
    "elf": "https://gabi.xinuos.com/elf/02-eheader.html",
}


def _require(condition, message):
    if not condition:
        raise LabError(message)


def _bounds(data, offset, size, label):
    _require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset, f"{label} exceeds image bounds")


def _esp(data, image_format):
    extended = image_format == "esp32"
    header_size = 24 if extended else 8
    _bounds(data, 0, header_size, "Espressif header")
    magic, count, mode, flash, entry = struct.unpack_from("<BBBBI", data)
    _require(magic == 0xE9, "Expected Espressif E9 magic")
    _require(1 <= count <= 16, "Espressif segment count must be 1..16")
    chip_id, appended = None, False
    if extended:
        _require(data[19:23] == bytes(4), "Unsupported nonzero reserved ESP32 header fields")
        _require(data[23] in (0, 1), "Invalid ESP32 appended-hash flag")
        chip_id = struct.unpack_from("<H", data, 12)[0]
        appended = bool(data[23])
    segments, offset, checksum = [], header_size, 0xEF
    for index in range(count):
        _bounds(data, offset, 8, f"Segment {index} header")
        address, size = struct.unpack_from("<II", data, offset)
        offset += 8
        _bounds(data, offset, size, f"Segment {index} data")
        _require(address + size <= 1 << 32, f"Segment {index} wraps its address space")
        checksum = reduce(operator.xor, memoryview(data)[offset:offset + size], checksum)
        segments.append({"index": index, "load_address": address, "file_offset": offset, "file_size": size})
        offset += size
    checksum_offset = (offset // 16) * 16 + 15
    _bounds(data, offset, checksum_offset + 1 - offset, "Espressif footer")
    _require(not any(data[offset:checksum_offset]), "Nonzero Espressif footer padding")
    _require(data[checksum_offset] == checksum, "Espressif segment checksum mismatch")
    end = checksum_offset + 1
    digest = None
    if appended:
        _bounds(data, end, 32, "Appended SHA256")
        digest = hashlib.sha256(data[:end]).digest()
        _require(data[end:end + 32] == digest, "Espressif appended SHA256 mismatch")
        end += 32
    _require(end == len(data), "Unparsed trailing bytes: signed images, merged flash and extra trailers are unsupported")
    chip, architecture = ESP_CHIPS.get(chip_id, ("Unknown ESP32-family chip", "unknown")) if extended else ("ESP8266", "Xtensa L106")
    result = {
        "format": image_format, "header_size": header_size, "architecture": architecture,
        "chip": chip, "chip_id": chip_id, "entry_point": entry, "segments": segments,
        "flash_header": {"mode_code": mode, "size_code": flash >> 4, "frequency_code": flash & 15},
        "verification": {"segment_bounds": True, "checksum_valid": True, "checksum_offset": checksum_offset,
                         "checksum": checksum, "appended_sha256_present": appended,
                         "appended_sha256_valid": True if appended else None,
                         "appended_sha256": digest.hex() if digest else None, "signature_verified": False},
        "limitations": ["Supported standalone image layout and available integrity checks only; not execution or board compatibility.",
                        "Checksum and simple SHA256 do not authenticate a vendor or prove secure-boot validity.",
                        "No partition table, device state, peripheral support or instruction execution is verified."],
    }
    if not extended:
        result["limitations"].append("ESP8266 classification was explicitly requested; this header contains no chip ID.")
    elif chip_id not in ESP_CHIPS:
        result["limitations"].append("Unrecognized chip ID; no CPU family or emulator compatibility inferred.")
    return result


def _elf(data):
    _bounds(data, 0, 16, "ELF identification")
    _require(data[:4] == b"\x7fELF", "Expected ELF magic")
    elf_class, encoding, version = data[4:7]
    _require(elf_class in (1, 2), "Unsupported ELF class")
    _require(encoding in (1, 2), "Unsupported ELF byte order")
    _require(version == 1, "Unsupported ELF identification version")
    endian = "<" if encoding == 1 else ">"
    bits = 32 if elf_class == 1 else 64
    header_format = endian + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH")
    header_size = 16 + struct.calcsize(header_format)
    _bounds(data, 0, header_size, "ELF header")
    (elf_type, machine, version, entry, phoff, shoff, flags, ehsize, phentsize,
     phnum, shentsize, shnum, shstrndx) = struct.unpack_from(header_format, data, 16)
    _require(version == 1 and ehsize == header_size, "Unsupported ELF version or header size")
    sh_format = endian + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ")
    ph_format = endian + ("IIIIIIII" if bits == 32 else "IIQQQQQQ")
    section_zero = None
    if shoff:
        _require(shoff >= header_size and shentsize == struct.calcsize(sh_format), "Invalid or unsupported ELF section table layout")
        _bounds(data, shoff, shentsize, "ELF section zero")
        section_zero = struct.unpack_from(sh_format, data, shoff)
        _require(section_zero[1] == 0, "ELF section zero must have SHT_NULL type")
        if shnum == 0:
            shnum = section_zero[5]
        if phnum == 0xFFFF:
            phnum = section_zero[7]
        if shstrndx == 0xFFFF:
            shstrndx = section_zero[6]
        _require(1 <= shnum <= MAX_TABLE_ENTRIES, "Invalid ELF section count")
        _bounds(data, shoff, shnum * shentsize, "ELF section table")
    else:
        _require(shnum == 0 and shstrndx == 0 and phnum != 0xFFFF, "ELF extended counts require section zero")
    _require(shstrndx == 0 or shstrndx < shnum, "ELF section-name table index out of range")
    sections = []
    for index in range(shnum):
        name, kind, sflags, address, offset, size, link, info, align, entsize = struct.unpack_from(sh_format, data, shoff + index * shentsize)
        if kind != 0:
            if kind != 8:
                _bounds(data, offset, size, f"ELF section {index}")
            _require(address + size <= 1 << bits, f"ELF section {index} wraps its address space")
            _require(align in (0, 1) or align & (align - 1) == 0, f"Invalid ELF section {index} alignment")
        if index == shstrndx and index != 0:
            _require(kind == 3, "ELF section-name table is not a string table")
        sections.append({"index": index, "type": kind, "address": address, "file_offset": offset,
                         "size": size, "has_file_data": kind not in (0, 8), "flags": sflags})
    _require(0 <= phnum <= MAX_TABLE_ENTRIES, "Invalid ELF program-header count")
    if phnum:
        _require(phoff >= header_size and phentsize == struct.calcsize(ph_format), "Invalid or unsupported ELF program table layout")
        _bounds(data, phoff, phnum * phentsize, "ELF program table")
    else:
        _require(phoff == 0, "ELF program table offset set with no entries")
    segments = []
    for index in range(phnum):
        values = struct.unpack_from(ph_format, data, phoff + index * phentsize)
        if bits == 32:
            kind, offset, virtual, physical, filesz, memsz, pflags, align = values
        else:
            kind, pflags, offset, virtual, physical, filesz, memsz, align = values
        if kind != 0:
            _bounds(data, offset, filesz, f"ELF segment {index}")
            _require(virtual + memsz <= 1 << bits and physical + memsz <= 1 << bits, f"ELF segment {index} wraps its address space")
        if kind == 1:
            _require(filesz <= memsz, f"ELF load segment {index} has file size larger than memory size")
            _require(align in (0, 1) or align & (align - 1) == 0, f"Invalid ELF segment {index} alignment")
            _require(align <= 1 or virtual % align == offset % align, f"ELF segment {index} address/offset alignment mismatch")
        segments.append({"index": index, "type": kind, "file_offset": offset, "file_size": filesz,
                         "virtual_address": virtual, "physical_address": physical,
                         "memory_size": memsz, "flags": pflags, "alignment": align})
    return {
        "format": "elf", "elf_class": bits, "byte_order": "little" if encoding == 1 else "big",
        "architecture": ELF_MACHINES.get(machine, "unknown"), "machine_id": machine,
        "elf_type": elf_type, "flags": flags, "entry_point": entry, "segments": segments, "sections": sections,
        "verification": {"header_bounds": True, "segment_bounds": True, "section_bounds": True,
                         "embedded_checksum": None, "signature_verified": False},
        "limitations": ["ELF structure and file/address bounds checked; instructions, relocations and runtime dependencies are not executed or validated.",
                        "ELF machine ID alone does not identify an Espressif chip or establish ABI/emulator compatibility.",
                        "The whole-file SHA256 identifies bytes; no embedded authenticity or integrity checksum is asserted."],
    }


def inspect_image(path, format="auto"):
    """Return metadata only; reject malformed or unsupported layouts with LabError."""
    _require(isinstance(format, str) and format in {"auto", "esp32", "esp8266", "elf"}, "Unknown image format")
    try:
        # Nonblocking open prevents a FIFO masquerading as an image from hanging
        # the process before its descriptor can be checked. It has no effect on
        # reads from regular files.
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            _require(stat.S_ISREG(info.st_mode), "Firmware input must be a regular file")
            _require(0 < info.st_size <= MAX_IMAGE_BYTES, "Firmware input is empty or exceeds 256 MiB")
            data = handle.read(MAX_IMAGE_BYTES + 1)
    except OSError as error:
        raise LabError(f"Cannot read firmware input: {error.strerror}") from error
    _require(len(data) == info.st_size, "Firmware input changed size while being read")
    if format == "auto":
        if data.startswith(b"\x7fELF"):
            result = _elf(data)
        elif data[0] == 0xE9:
            try:
                result = _esp(data, "esp32")
            except LabError as error:
                raise LabError(f"No validated ESP32-family image: {error}. E9 alone is ambiguous; use explicit esp8266 format for a known ESP8266 image") from error
            try:
                _esp(data, "esp8266")
            except LabError:
                pass
            else:
                raise LabError("E9 image matches both supported layouts; select an explicit image format")
        else:
            raise LabError("Unknown image magic; merged flash, encrypted images and ESP8266 EA containers are unsupported")
    else:
        result = _elf(data) if format == "elf" else _esp(data, format)
    return {"schema": "vfl.image.v1", "valid": True, "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), **result,
            "format_source": FORMAT_SOURCES[result["format"]]}
