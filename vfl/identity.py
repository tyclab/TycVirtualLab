"""Declared target identity and bounded checks against image metadata.

ELF's machine ID cannot identify an Xtensa core or its ABI. Unknown facts remain
explicitly unverified rather than being inferred from an application filename.
"""

import re

from .model import LabError, require

UNSPECIFIED = {"chip": "unspecified", "isa": "unspecified", "abi": "unspecified"}
NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


def validate_target(target=None):
    if target is None:
        return dict(UNSPECIFIED)
    require(isinstance(target, dict) and set(target) == set(UNSPECIFIED),
            "target must declare chip, isa and abi")
    require(all(isinstance(value, str) and NAME.fullmatch(value) for value in target.values()),
            "target identities must be lowercase identifiers")
    return dict(target)


def _family(isa):
    for prefix in ("xtensa", "aarch64", "arm", "riscv", "x86"):
        if isa.startswith(prefix):
            return prefix
    return None


def validate_asset_targets(profile, asset_records):
    """Inspect only explicitly typed images; never interpret ROM/helper bytes.

    Returns local provenance describing both checked and unverified properties.
    Matching does not imply emulator support or runtime compatibility.
    """
    from .firmware import inspect_image

    target = validate_target(profile.get("target"))
    records = {record["role"]: record for record in asset_records}
    inspected = []
    for asset in profile.get("firmware", []):
        if "format" not in asset:
            continue
        image_format = asset["format"]
        require(isinstance(image_format, str) and image_format in {"elf", "esp32", "esp8266"},
                "asset.format must be elf, esp32 or esp8266")
        record = records.get(asset["role"])
        require(record is not None, "declared asset record is missing")
        info = inspect_image(record["path"], format=image_format)
        require(info["sha256"] == record["sha256"], "asset changed during target inspection")
        checked, unverified = [], ["abi"]
        if image_format == "esp32":
            known = {0: ("esp32", "xtensa-lx6"), 9: ("esp32-s3", "xtensa-lx7")}.get(info["chip_id"])
            if known:
                for key, actual in zip(("chip", "isa"), known):
                    if target[key] != "unspecified":
                        require(target[key] == actual, f"asset {asset['role']} disagrees with target.{key}: image identifies {actual}")
                        checked.append(key)
                    else:
                        unverified.append(key)
            else:
                unverified.extend(["chip", "isa"])
        elif image_format == "elf":
            family = {3: "x86", 62: "x86", 40: "arm", 183: "aarch64", 94: "xtensa", 243: "riscv"}.get(info["machine_id"])
            declared_family = _family(target["isa"])
            if family and declared_family:
                require(family == declared_family, f"asset {asset['role']} ELF machine disagrees with target ISA family")
                checked.append("isa-family")
            unverified.extend(["chip", "isa-core"])
        else:
            # This eight-byte header has no chip identifier. Format choice is
            # configuration, not independent proof of hardware identity.
            require(target["chip"] in {"unspecified", "esp8266"}, "ESP8266-format asset conflicts with declared target chip")
            unverified.extend(["chip", "isa"])
        inspected.append({"role": asset["role"], "format": image_format, "sha256": info["sha256"],
                          "image_architecture": info["architecture"], "checked": checked,
                          "unverified": unverified, "scope": "Image metadata compatibility only; no execution or board compatibility claim"})
    return inspected
