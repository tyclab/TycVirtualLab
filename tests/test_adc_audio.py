import unittest
from vfl.audio import PCM,pcm_to_adc_trace
from vfl.model import validate_trace

class ADCWindowTests(unittest.TestCase):
    def test_quantization_clipping_and_chronological_order(self):
        pcm=PCM(48000,(-1,-.5,0,.5,1,0),{'kind':'authored'})
        trace=pcm_to_adc_trace(pcm,gain=4,offset=2,samples_per_frame=3,maximum=4)
        validate_trace(trace)
        self.assertEqual([f['values'] for f in trace['frames']],[[0,0,2],[4,4,2]])
        self.assertEqual(trace['provenance']['clipped_values'],2)
        self.assertEqual([f['time_us'] for f in trace['frames']],[0,62])

    def test_cadence_selects_window_and_explicit_tail(self):
        pcm=PCM(8000,tuple(i/100 for i in range(18)),{'kind':'authored'})
        trace=pcm_to_adc_trace(pcm,gain=100,offset=0,samples_per_frame=2,frame_us=1000)
        self.assertEqual([f['values'] for f in trace['frames']],[[0,1],[8,9],[16,17]])
        with self.assertRaisesRegex(ValueError,'incomplete'):
            pcm_to_adc_trace(pcm,gain=100,offset=0,samples_per_frame=4)
        padded=pcm_to_adc_trace(pcm,gain=100,offset=5,samples_per_frame=4,tail='pad-silence')
        self.assertEqual(padded['frames'][-1]['values'],[21,22,5,5])
        self.assertEqual(padded['provenance']['padded_samples'],2)
        with self.assertRaisesRegex(ValueError,'overlap'):
            pcm_to_adc_trace(pcm,gain=100,offset=0,samples_per_frame=64,frame_us=1000)
        with self.assertRaises(ValueError):pcm_to_adc_trace(pcm,gain=float('nan'),offset=0)
