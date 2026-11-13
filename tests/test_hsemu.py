import json
import hashlib
import unittest

from vfl.hsemu import HsemuError, capture_from_output, parse_output
from vfl.model import validate_capture


COMMANDS = """seed 9
time 2
call 4096 4 5
dump strip 8192 3
dump ram 9000 2
time 3
callq 4096
dump strip 8192 3
dump ram 9000 2
"""
OUTPUT = "R 9 5\nD strip 010203\nD ram abcd\nD strip 040506\nD ram ff00\nE done stubs=0 ms=2 maxsteps=7\n"
PROFILE = {"id": "test", "buses": [{"id": "main", "pixels": 1, "order": "RGB"}]}
TRACE = {"frames": [{"index": 0, "time_us": 2000}, {"index": 1, "time_us": 3000}]}
DECLARATION = 'E instrumentation {"schema":"vfl.boundary-log.v1","adc_log":true,"clock_log":true,"rng_log":true}\n'


def event_line(sequence, frame, time_us, kind="clock", **extra):
    value = {"sequence": sequence, "frame": frame, "time_us": time_us, "kind": kind,
             "phase": "initialization" if frame == -1 else "frame", "call_site": "fixture.call", "value": 7}
    value.update(extra)
    return "E event " + json.dumps(value) + "\n"


class HsemuTests(unittest.TestCase):
    def test_ordered_returns_dumps_and_times(self):
        parsed = parse_output(COMMANDS, OUTPUT)
        self.assertEqual(parsed.returns, ((9, 5),))
        self.assertEqual([d.time_us for d in parsed.dumps], [2000, 2000, 3000, 3000])
        self.assertEqual(parsed.completion["maxsteps"], 7)

    def test_negative_hex_call_argument(self):
        parsed = parse_output(COMMANDS.replace("call 4096 4 5", "call 4096 -0x1 5"), OUTPUT)
        self.assertEqual(parsed.returns, ((9, 5),))

    def test_complete_capture_with_explicit_state_mapping(self):
        capture = capture_from_output(PROFILE, TRACE, COMMANDS, OUTPUT,
                                      {"strip": "main"}, state_tag_map={"ram": "memory"},
                                      execution_kind="synthetic")
        self.assertEqual(capture["frames"][0]["state"], {"memory": "abcd"})
        self.assertEqual(capture["frames"][1]["buses"], {"main": "040506"})
        self.assertFalse(capture["manifest"]["capabilities"]["adc_log"])
        validate_capture(capture)

    def test_broken_captures_rejected(self):
        broken = ["", OUTPUT.replace("D ram abcd\n", ""),
                  OUTPUT.replace("010203", "01020"), OUTPUT.replace("010203", "01020z"),
                  OUTPUT.replace("D strip", "D other", 1),
                  OUTPUT.replace("R 9 5", "R garbage 5"),
                  OUTPUT.replace("R 9 5\nD strip 010203", "D strip 010203\nR 9 5"),
                  OUTPUT.split("E done")[0], OUTPUT + "D strip 010203\n",
                  OUTPUT + "E done stubs=0 ms=2\n", OUTPUT + "\n",
                  "X line 1: trap\n" + OUTPUT, OUTPUT.replace("ms=2", "ms=x")]
        for output in broken:
            with self.subTest(output=output), self.assertRaises(HsemuError):
                parse_output(COMMANDS, output)

    def test_invalid_command_contracts(self):
        for commands in ("", "time 1\n", "dump x 1 0", "dump x -1 2",
                         "dump x 1", "time -1\ndump x 1 2", "call\ndump x 1 2"):
            with self.subTest(commands=commands), self.assertRaises(HsemuError):
                parse_output(commands, OUTPUT)

    def test_port_dialect_requires_exact_dumps_without_emulator_claim(self):
        port_output = "D strip 010203\nD ram abcd\nD strip 040506\nD ram ff00\n"
        self.assertEqual(len(parse_output(COMMANDS, port_output, dialect="port").dumps), 4)
        with self.assertRaises(HsemuError):
            parse_output(COMMANDS, OUTPUT, dialect="port")
        with self.assertRaises(HsemuError):
            capture_from_output(PROFILE, TRACE, COMMANDS, port_output,
                                {"strip": "main"}, execution_kind="original-firmware", dialect="port")

    def test_missing_time_is_not_inferred_from_output_order(self):
        with self.assertRaises(HsemuError):
            capture_from_output(PROFILE, TRACE, COMMANDS.replace("time 2\n", ""), OUTPUT,
                                {"strip": "main"}, state_tag_map={"ram": "memory"},
                                execution_kind="synthetic")

    def test_unknown_and_duplicate_mapping_rejected(self):
        for mapping in ({}, {"strip": "other"}, {"strip": "main", "other": "main"}):
            with self.subTest(mapping=mapping), self.assertRaises(HsemuError):
                capture_from_output(PROFILE, TRACE, COMMANDS, OUTPUT, mapping,
                                    execution_kind="synthetic")
        with self.assertRaises(HsemuError):
            capture_from_output(PROFILE, TRACE, COMMANDS, OUTPUT, {"strip": "main"},
                                execution_kind="synthetic")

    def test_duplicate_frame_dump_rejected(self):
        commands = "time 2\ndump strip 8192 3\ndump strip 8192 3\n"
        output = "D strip 010203\nD strip 040506\nE done stubs=0 ms=1\n"
        with self.assertRaises(HsemuError):
            capture_from_output(PROFILE, TRACE, commands, output, {"strip": "main"},
                                execution_kind="synthetic")

    def test_changing_clock_to_different_trace_time_rejected(self):
        with self.assertRaises(HsemuError):
            capture_from_output(PROFILE, TRACE, COMMANDS.replace("time 3", "time 4"), OUTPUT,
                                {"strip": "main"}, state_tag_map={"ram": "memory"},
                                execution_kind="synthetic")

    def test_actual_event_log_preserves_initialization_and_read_values(self):
        output = DECLARATION + event_line(0, -1, 0) + event_line(1, 0, 2000, "adc", channel=2, value=19) + OUTPUT
        capture = capture_from_output(PROFILE, TRACE, COMMANDS, output, {"strip": "main"},
                                      state_tag_map={"ram": "memory"}, execution_kind="synthetic")
        self.assertEqual(capture["events"][0]["frame"], -1)
        self.assertEqual(capture["events"][1]["value"], 19)
        self.assertTrue(capture["manifest"]["capabilities"]["rng_log"])

    def test_malformed_event_logs_fail_closed(self):
        cases = [event_line(0, 0, 2000) + OUTPUT,
                 DECLARATION + event_line(1, 0, 2000) + OUTPUT,
                 DECLARATION + event_line(0, -1, 0, phase="frame") + OUTPUT,
                 DECLARATION + event_line(0, 0, 2000, value=-1) + OUTPUT,
                 DECLARATION + event_line(0, 0, 2000) + event_line(1, -1, 0) + OUTPUT,
                 DECLARATION + 'E event {"sequence":0,"sequence":0}\n' + OUTPUT,
                 DECLARATION + 'E event null\n' + OUTPUT,
                 DECLARATION + DECLARATION + OUTPUT]
        for output in cases:
            with self.subTest(output=output), self.assertRaises(HsemuError):
                parse_output(COMMANDS, output)

    def test_events_must_match_capture_clock_and_capabilities(self):
        cases = [DECLARATION + event_line(0, 0, 2001) + OUTPUT,
                 DECLARATION + event_line(0, 3, 2000) + OUTPUT,
                 DECLARATION + event_line(0, -1, 3000) + OUTPUT,
                 DECLARATION.replace('"adc_log":true', '"adc_log":false') + event_line(0, 0, 2000, "adc") + OUTPUT]
        for output in cases:
            with self.subTest(output=output), self.assertRaises(HsemuError):
                capture_from_output(PROFILE, TRACE, COMMANDS, output, {"strip": "main"},
                                    state_tag_map={"ram": "memory"}, execution_kind="synthetic")

    def test_unknown_informational_records_and_commands_rejected(self):
        for prefix in ("E error unmapped read\n", "E\n", "E mystery\n"):
            with self.subTest(prefix=prefix), self.assertRaises(HsemuError):
                parse_output(COMMANDS, prefix + OUTPUT)
        with self.assertRaises(HsemuError):
            parse_output("sead 3\n" + COMMANDS, OUTPUT)
        commands = COMMANDS + "echo finished\n"
        output = OUTPUT.replace("E done", "E finished\nE done")
        self.assertEqual(len(parse_output(commands, output).dumps), 4)

    def test_every_state_tag_required_in_every_frame(self):
        commands = COMMANDS.rsplit("dump ram 9000 2\n", 1)[0]
        output = OUTPUT.replace("D ram ff00\n", "")
        with self.assertRaisesRegex(HsemuError, "incomplete state"):
            capture_from_output(PROFILE, TRACE, commands, output, {"strip": "main"},
                                state_tag_map={"ram": "memory"}, execution_kind="synthetic")

    def test_each_frame_requires_an_executed_call(self):
        with self.assertRaisesRegex(HsemuError, "preceding call"):
            parse_output(COMMANDS.replace("callq 4096\n", ""), OUTPUT)

    def test_execution_binding_rejects_cached_different_input_or_nonce(self):
        nonce = "12" * 16
        binding = {"schema": "tycvl.execution-binding.v1", "request_id": nonce,
                   "commands_sha256": hashlib.sha256(COMMANDS.encode()).hexdigest()}
        output = "E binding " + json.dumps(binding) + "\n" + OUTPUT
        self.assertEqual(parse_output(COMMANDS, output, request_id=nonce).binding, binding)
        for commands, result, request_id in ((COMMANDS.replace("seed 9", "seed 10"), output, nonce),
                                             (COMMANDS, output, "34" * 16),
                                             (COMMANDS, OUTPUT, nonce)):
            with self.subTest(commands=commands, request_id=request_id), self.assertRaises(HsemuError):
                parse_output(commands, result, request_id=request_id)


if __name__ == "__main__":
    unittest.main()
