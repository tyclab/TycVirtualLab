import unittest
from vfl.output import wled14_rgb
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
