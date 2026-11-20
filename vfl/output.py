"""Explicit RGB output stages, kept separate from renderer pixel history."""

import struct

from .model import integer, require


def wled14_rgb(rgb, *, brightness=255, limit_ma=0, led_ma=55):
    """Model WLED 0.14 RGB ABL and NeoPixelBus brightness; no frame gamma.

    brightness is the already converted internal bus brightness. The caller owns
    user-brightness gamma and palette/color gamma upstream. Output is RGB order.
    """
    require(isinstance(rgb, bytes) and len(rgb) % 3 == 0, "RGB bytes required")
    integer(brightness, "driver brightness", 0, 255)
    integer(limit_ma, "limit_ma", 0, 1000000)
    integer(led_ma, "led_ma", 0, 254)
    pixels = len(rgb) // 3
    current, effective = 0, brightness
    if limit_ma >= 150 and led_ma:
        budget = max(0, limit_ma - 100 - pixels)
        full = sum(rgb) * led_ma // 765
        if full * brightness // 255 > budget:
            f32 = lambda n: struct.unpack("<f", struct.pack("<f", n))[0]
            ratio = f32(f32(budget * 255) / f32(full * brightness))
            factor = min(255, int(f32(ratio * 255)))
            effective = (brightness * (factor + 1) >> 8) + 1
        current = full * effective // 255 + 100 + pixels
    result = bytes(value * (effective + 1) >> 8 for value in rgb)
    return result, {"brightness": brightness, "limited_brightness": effective,
                    "estimated_ma": current, "limit_ma": limit_ma}


def _video_scale(rgb, amount):
    if amount == 255:
        return rgb
    if amount == 0:
        return bytes(len(rgb))
    scaled = bytearray(len(rgb))
    for i in range(0, len(rgb), 3):
        pixel = rgb[i:i+3]
        threshold = (max(pixel) >> 2) + 1
        for j, value in enumerate(pixel):
            scaled[i+j] = ((value * amount + 127) >> 8) | int(value > threshold)
    return bytes(scaled)


def wled16_rgb(rgb, *, brightness, limit_ma, led_ma):
    """WLED 16.0.1, one ESP32-S3 RGB bus written once per pixel each show.

    Input is mapped RGB after color gamma. A positive limit enables global ABL.
    A zero limit represents disabled ABL. Per-bus and WS2815 modes are separate.
    """
    require(isinstance(rgb, bytes) and len(rgb) % 3 == 0, "RGB bytes required")
    integer(brightness, "driver brightness", 0, 255)
    integer(limit_ma, "limit_ma", 0, 65535)
    integer(led_ma, "led_ma", 0, 254)
    scaled = _video_scale(rgb, brightness)
    factor, used = 255, 0
    if limit_ma and led_ma:
        pixels = len(rgb) // 3
        used = (sum(scaled) * led_ma // 765 + pixels) & 0xffff
        budget = max(1, limit_ma - 120)  # Default ESP32 controller allowance.
        if budget <= pixels:
            factor, used = 1, pixels
        elif used > budget:
            factor, used = budget * 255 // used + 1, budget
        scaled = _video_scale(scaled, factor)
    return scaled, {"brightness": brightness, "limited_brightness": brightness * factor // 255,
                    "estimated_ma": (used + 120) & 0xffff, "limit_ma": limit_ma}


def glorb_driver(rgb, config):
    required = {"brightness", "limit_ma", "led_ma"}
    require(isinstance(config, dict) and required <= config.keys() <= required | {"model"},
            "invalid driver configuration")
    model = config.get("model", "wled14")
    require(model in ("wled14", "wled16"), "unknown RGB driver model")
    apply = wled16_rgb if model == "wled16" else wled14_rgb
    return apply(rgb, brightness=config["brightness"], limit_ma=config["limit_ma"], led_ma=config["led_ma"])
