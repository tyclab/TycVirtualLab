from __future__ import annotations

import copy
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

from vfl.viewer import export_html, render_html, viewer_path


def capture_fixture():
    return {
        "schema": "vfl.capture.v1",
        "manifest": {
            "profile_id": "demo", "execution_kind": "synthetic", "backend": "demo",
            "capabilities": {"state": False, "adc_log": False, "clock_log": False, "rng_log": False},
            "limitations": ["Synthetic output; not vendor firmware"],
        },
        "buses": [{"id": "main", "pixels": 2, "order": "GRB", "stage": "logical"}],
        "frames": [
            {"index": 0, "time_us": 10, "buses": {"main": "20ff00000000"}, "state": {}},
            {"index": 1, "time_us": 30, "buses": {"main": "0020ff000000"}, "state": {}},
        ],
        "events": [],
        "geometry": {
            "kind": "points", "points": [{"bus": "main", "index": 0, "x": 0, "y": 1, "z": 2}],
            "mask": {"main": [True, False]},
        },
    }


class PageParser(HTMLParser):
    def __init__(self, page):
        super().__init__()
        self.scripts = []
        self.links = []
        self.meta = []
        self.embedded = ""
        self.reading_capture = False
        self.feed(page)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script":
            self.scripts.append(attrs)
            self.reading_capture = attrs.get("id") == "vfl-capture"
        if tag == "link":
            self.links.append(attrs)
        if tag == "meta":
            self.meta.append(attrs)

    def handle_endtag(self, tag):
        if tag == "script":
            self.reading_capture = False

    def handle_data(self, data):
        if self.reading_capture:
            self.embedded += data


class ViewerExportTests(unittest.TestCase):
    def test_capture_cannot_break_out_of_embedded_json(self):
        capture = capture_fixture()
        payload = '</script><script>alert("bad")</script>&\u2028\u2029'
        capture["manifest"]["profile_id"] = payload
        capture["manifest"]["limitations"].append(payload)
        parsed = PageParser(render_html(capture))
        self.assertEqual(json.loads(parsed.embedded), capture)
        self.assertEqual(len(parsed.scripts), 2)
        self.assertNotIn("</script", parsed.embedded.lower())
        self.assertNotIn("<", parsed.embedded)

    def test_export_inlines_every_asset_and_disallows_connections(self):
        page = render_html(capture_fixture())
        parsed = PageParser(page)
        self.assertFalse(parsed.links)
        self.assertTrue(all("src" not in script for script in parsed.scripts))
        policy = next(meta["content"] for meta in parsed.meta if meta.get("http-equiv") == "Content-Security-Policy")
        self.assertIn("connect-src 'none'", policy)
        self.assertIn("object-src 'none'", policy)
        self.assertIn("TycVirtualLab", page)

    def test_empty_viewer_is_usable_without_a_capture(self):
        parsed = PageParser(render_html())
        self.assertIsNone(json.loads(parsed.embedded))
        self.assertTrue(viewer_path().is_file())

    def test_export_replaces_with_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.html"
            path.write_text("old")
            path.chmod(0o644)
            self.assertEqual(export_html(capture_fixture(), path), path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(PageParser(path.read_text()).embedded), capture_fixture())
            self.assertEqual([p.name for p in Path(directory).iterdir()], ["capture.html"])

    def test_non_json_numbers_are_rejected(self):
        capture = capture_fixture()
        capture["frames"][0]["state"] = {"bad": float("nan")}
        with self.assertRaises(ValueError):
            render_html(capture)


@unittest.skipUnless(shutil.which("node"), "Node is needed to test browser decoding")
class ViewerDataTests(unittest.TestCase):
    def run_js(self, capture, expression):
        script = "const v=require(process.argv[1]);const c=JSON.parse(process.argv[2]);" + expression
        result = subprocess.run(
            [shutil.which("node"), "-e", script, str(viewer_path().with_name("viewer.js")), json.dumps(capture)],
            capture_output=True, text=True, timeout=10, check=False,
        )
        return result

    def test_accepts_masked_geometry_and_decodes_wire_order(self):
        result = self.run_js(capture_fixture(), "v.validateCapture(c);console.log(JSON.stringify(v.decodePixel(c.frames[0].buses.main,'GRB',0)));")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [255, 32, 0])

    def test_incomplete_frame_and_invalid_geometry_fail(self):
        variants = []
        incomplete = capture_fixture(); incomplete["frames"][1]["buses"]["main"] = "00"; variants.append(incomplete)
        extra = capture_fixture(); extra["frames"][0]["buses"]["unknown"] = "000000"; variants.append(extra)
        bad_point = capture_fixture(); bad_point["geometry"]["points"][0]["index"] = 2; variants.append(bad_point)
        bad_mask = capture_fixture(); bad_mask["geometry"]["mask"]["main"] = [True]; variants.append(bad_mask)
        empty = capture_fixture(); empty["frames"] = []; variants.append(empty)
        backward = capture_fixture(); backward["frames"][1]["time_us"] = 0; variants.append(backward)
        duplicate_time = capture_fixture(); duplicate_time["frames"][1]["time_us"] = 10; variants.append(duplicate_time)
        missing_capability = capture_fixture(); del missing_capability["manifest"]["capabilities"]["rng_log"]; variants.append(missing_capability)
        unknown_execution = capture_fixture(); unknown_execution["manifest"]["execution_kind"] = "verified"; variants.append(unknown_execution)
        duplicate_point = capture_fixture(); duplicate_point["geometry"]["points"] *= 2; variants.append(duplicate_point)
        for capture in variants:
            with self.subTest(capture=capture):
                result = self.run_js(capture, "try{v.validateCapture(c);process.exit(1)}catch(e){process.exit(0)}")
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_nonzero_masked_bytes_are_detected_without_ignoring_them(self):
        capture = capture_fixture()
        capture["frames"][1]["buses"]["main"] = "000000ff0000"
        result = self.run_js(capture, "v.validateCapture(c);console.log(JSON.stringify(c.frames.map(f=>v.maskedNonzeroCount(c,f))));")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [0, 1])

    def test_timeline_uses_actual_timestamps(self):
        result = self.run_js(capture_fixture(), "console.log(JSON.stringify([0,10,29,30,100].map(t=>v.frameAtTime(c.frames,t))));")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [0, 0, 0, 1, 1])

    def test_bundled_demo_geometry_matches_its_logical_buses(self):
        for profile_path in sorted(viewer_path().parent.parent.joinpath("profiles").glob("*.json")):
            profile = json.loads(profile_path.read_text())
            capture = copy.deepcopy(capture_fixture())
            capture["buses"] = profile["buses"]
            capture["geometry"] = profile["geometry"]
            capture["frames"] = [{"index": 0, "time_us": 0, "state": {}, "buses": {bus["id"]: "000000" * bus["pixels"] for bus in profile["buses"]}}]
            with self.subTest(profile=profile["id"]):
                result = self.run_js(capture, "v.validateCapture(c)")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(profile["backend"]["kind"], "demo")
                self.assertFalse(profile["firmware"])


if __name__ == "__main__":
    unittest.main()
