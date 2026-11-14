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
