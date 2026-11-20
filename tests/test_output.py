import unittest
from vfl.output import glorb_driver, wled14_rgb, wled16_rgb
from vfl.model import LabError

class OutputTests(unittest.TestCase):
    def test_endpoint_brightness_and_disabled_limit(self):
        values=bytes(range(255))+b'\xff'
        values+=b'\x00\x00'
        self.assertEqual(wled14_rgb(values)[0], values)
        self.assertEqual(wled14_rgb(values,brightness=0)[0], bytes(len(values)))
        self.assertEqual(wled14_rgb(bytes([255,128,1]),brightness=127)[0], bytes([127,64,0]))

    def test_rgb_white_budget_limits_and_black_standby(self):
        data,state=wled14_rgb(bytes([255])*360,limit_ma=2800)
        self.assertEqual(state,{'brightness':255,'limited_brightness':100,'estimated_ma':2808,'limit_ma':2800})
        self.assertEqual(set(data),{100})
        _,black=wled14_rgb(bytes(360),limit_ma=2800)
        self.assertEqual(black['estimated_ma'],220)
        self.assertEqual(black['limited_brightness'],255)
        with self.assertRaises(LabError):wled14_rgb(b'xx')
        with self.assertRaises(LabError):wled14_rgb(b'xxx',led_ma=255)

    def test_wled16_video_scale_and_endpoints(self):
        # Known answers from WLED v16.0.1 color_fade(pixel, amount, true).
        rgb = bytes.fromhex("804120 ff4001 3f100f 212223")
        options = {"limit_ma": 0, "led_ma": 55}
        self.assertEqual(wled16_rgb(rgb, brightness=45, **options)[0],
                         bytes.fromhex("170b06 2d0b00 0b0303 070707"))
        self.assertEqual(wled16_rgb(rgb, brightness=0, **options)[0], bytes(len(rgb)))
        self.assertEqual(wled16_rgb(rgb, brightness=255, **options)[0], rgb)
        with self.assertRaisesRegex(LabError, "unknown RGB driver"):
            glorb_driver(rgb, {**options, "brightness": 45, "model": "other"})

    def test_wled16_global_abl_second_video_fade(self):
        white = bytes([255]) * 360
        out, state = wled16_rgb(white, brightness=255, led_ma=55, limit_ma=2800)
        # Bus current is 6720 mA. ESP32 reserves 120 mA for itself from the limit.
        self.assertEqual(state, {"brightness": 255, "limited_brightness": 102,
                                 "estimated_ma": 2800, "limit_ma": 2800})
        self.assertEqual(out, bytes([103]) * 360)
        out, state = wled16_rgb(white, brightness=255, led_ma=55, limit_ma=240)
        self.assertEqual(state["limited_brightness"], 1)
        self.assertEqual(state["estimated_ma"], 240)
        self.assertEqual(out, bytes([1]) * 360)
        out, state = wled16_rgb(white, brightness=255, led_ma=0, limit_ma=240)
        self.assertEqual(out, white)
        self.assertEqual(state["estimated_ma"], 120)
