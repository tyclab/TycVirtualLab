import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from vfl.model import LabError
from vfl.release import audit, export_source, verify_source


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.root = self.directory / "source"
        self.root.mkdir()
        self.put("pyproject.toml", '[project]\nname = "authored-fixture"\nversion = "0.0.0"\n')
        self.put("README.md", "Authored source-only test fixture.\n")
        self.put("vfl/__init__.py", 'NAME = "fixture"\n')
        self.put("docs/guide.md", "Only generated source belongs here.\n")

    def put(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data)
        return path

    def test_archive_is_deterministic_and_manifest_hashes_payloads(self):
        first = self.directory / "first.tar.gz"
        second = self.directory / "second.tar.gz"
        manifest = export_source(self.root, first)
        source = self.root / "docs" / "guide.md"
        os.utime(source, (1_700_000_000, 1_700_000_000))
        source.chmod(0o600)
        self.assertEqual(manifest, export_source(self.root, second))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with tarfile.open(first, "r:gz") as archive:
            names = archive.getnames()
            self.assertEqual(len(names), 5)
            archived_manifest = json.load(archive.extractfile("TycVirtualLab/source-manifest.json"))
            self.assertEqual(manifest, archived_manifest)
            for relative, expected_hash in manifest["files"].items():
                member = archive.getmember("TycVirtualLab/" + relative)
                self.assertTrue(member.isfile())
                self.assertEqual((member.mtime, member.uid, member.gid, member.mode), (0, 0, 0, 0o644))
                self.assertEqual(hashlib.sha256(archive.extractfile(member).read()).hexdigest(), expected_hash)

    def test_extracted_archive_audits_verifies_and_reexports_byte_identically(self):
        first = self.directory / "first.tar.gz"
        second = self.directory / "second.tar.gz"
        expected_manifest = export_source(self.root, first)
        extracted = self.directory / "extracted"
        with tarfile.open(first, "r:gz") as archive:
            archive.extractall(extracted, filter="data")
        source = extracted / "TycVirtualLab"
        report = audit(source)
        self.assertTrue(report["clean"], report)
        self.assertEqual(report["manifest"], {"present": True, "verified": True})
        self.assertTrue(verify_source(source)["clean"])
        self.assertEqual(expected_manifest, export_source(source, second))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(hashlib.sha256(first.read_bytes()).hexdigest(), hashlib.sha256(second.read_bytes()).hexdigest())
        with tarfile.open(second, "r:gz") as archive:
            names = archive.getnames()
            self.assertEqual(len(names), len(set(names)))
            self.assertEqual(names.count("TycVirtualLab/source-manifest.json"), 1)

    def install_manifest(self):
        manifest = export_source(self.root, self.directory / "seed.tar.gz")
        self.put("source-manifest.json", json.dumps(manifest))
        return manifest

    def test_verify_requires_manifest_but_checkout_audit_does_not(self):
        self.assertTrue(audit(self.root)["clean"])
        report = verify_source(self.root)
        self.assertFalse(report["clean"])
        self.assertFalse(report["manifest"]["present"])

    def test_manifest_detects_changed_missing_and_unlisted_sources(self):
        self.install_manifest()
        path = self.root / "README.md"
        original = path.read_text()
        path.write_text("Changed source.\n")
        self.assertFalse(verify_source(self.root)["clean"])
        self.assertFalse(audit(self.root)["clean"])
        with self.assertRaisesRegex(LabError, "hash mismatch"):
            export_source(self.root, self.directory / "changed.tar.gz")
        path.unlink()
        self.assertFalse(verify_source(self.root)["clean"])
        path.write_text(original)
        extra = self.put("docs/unlisted.md", "Extra source.\n")
        self.assertFalse(verify_source(self.root)["clean"])
        extra.unlink()
        self.assertTrue(verify_source(self.root)["clean"])

    def test_manifest_rejects_bad_schema_paths_hashes_and_self_reference(self):
        original = self.install_manifest()
        mutations = [
            {"schema": "unknown", "files": original["files"]},
            {**original, "unexpected": True},
            {"schema": original["schema"], "files": {"../outside.py": "0" * 64}},
            {"schema": original["schema"], "files": {"README.md": "not a checksum"}},
            {"schema": original["schema"], "files": {"source-manifest.json": "0" * 64}},
        ]
        for data in mutations:
            with self.subTest(data=data):
                self.put("source-manifest.json", json.dumps(data))
                self.assertFalse(verify_source(self.root)["clean"])
                self.assertFalse(audit(self.root)["clean"])

    def test_manifest_symlink_is_never_followed_for_verification(self):
        outside = self.directory / "outside.json"
        outside.write_text("{}")
        (self.root / "source-manifest.json").symlink_to(outside)
        self.assertFalse(verify_source(self.root)["clean"])

    def test_actual_source_checkout_passes_release_audit(self):
        report = audit(Path(__file__).resolve().parents[1])
        self.assertTrue(report["clean"], report["errors"])

    def test_caches_are_excluded_from_source_archive(self):
        self.put(".git/private-note", "ignored metadata")
        self.put("vfl/__pycache__/module.pyc", "ignored bytecode")
        self.put("fixture.egg-info/metadata.txt", "ignored build metadata")
        report = audit(self.root)
        self.assertTrue(report["clean"])
        manifest = export_source(self.root, self.directory / "archive.tar.gz")
        self.assertEqual(len(manifest["files"]), 4)

    def test_experiment_schemas_and_private_names_rejected(self):
        for name, content in (
            ("docs/innocent.json", '{"schema":"vfl.capture.v1"}'),
            ("docs/innocent.json", '{"schema":"vfl.trace.v1"}'),
            ("docs/innocent.json", '{"schema":"vfl.request.v1"}'),
            ("docs/innocent.json", '{"schema":"vfl.comparison.v1"}'),
            ("docs/result.capture.json", "{}"),
            ("private/note.md", "private content"),
            ("firmware/image.bin", "not actual firmware"),
        ):
            path = self.put(name, content)
            try:
                self.assertFalse(audit(self.root)["clean"], name)
                with self.assertRaises(LabError):
                    export_source(self.root, self.directory / "blocked.tar.gz")
                self.assertFalse((self.directory / "blocked.tar.gz").exists())
            finally:
                path.unlink()

    def test_private_paths_keys_and_tokens_rejected(self):
        # Construct examples at runtime so the source itself contains no key or
        # user-specific absolute path matching the release scanner.
        examples = ["/" + "home/" + "fixture-user/secret", "/mnt/" + "c/Users/" + "Fixture/file",
                    "/" + "Users/" + "Fixture/file", "C:" + chr(92) + "Users" + chr(92) + "Fixture" + chr(92) + "file",
                    "-" * 5 + "BEGIN OPENSSH PRIVATE KEY" + "-" * 5, "ghp_" + "A" * 30]
        for text in examples:
            path = self.put("docs/injected.md", text)
            try:
                self.assertFalse(audit(self.root)["clean"])
            finally:
                path.unlink()

    def test_symlinks_and_special_files_rejected(self):
        outside = self.directory / "outside.md"
        outside.write_text("outside source root")
        link = self.root / "docs" / "linked.md"
        link.symlink_to(outside)
        self.assertFalse(audit(self.root)["clean"])
        link.unlink()
        fifo = self.root / "vfl" / "stream.py"
        os.mkfifo(fifo)
        try:
            self.assertFalse(audit(self.root)["clean"])
        finally:
            fifo.unlink()

    def test_export_rejects_output_inside_selected_source_root_and_overwrite(self):
        with self.assertRaisesRegex(LabError, "source"):
            export_source(self.root, self.root / "docs" / "release.tar.gz")
        self.assertFalse((self.root / "docs" / "release.tar.gz").exists())
        target = self.directory / "existing.tar.gz"
        target.write_bytes(b"preserve")
        with self.assertRaises(LabError):
            export_source(self.root, target)
        self.assertEqual(target.read_bytes(), b"preserve")

    def test_competing_output_creation_is_not_removed(self):
        target = self.directory / "racing.tar.gz"
        original_open = Path.open

        def racing_open(path, *args, **kwargs):
            if path == target and args and args[0] == "xb":
                with original_open(path, "wb") as handle:
                    handle.write(b"created by another writer")
                raise FileExistsError("output appeared concurrently")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", racing_open):
            with self.assertRaises(FileExistsError):
                export_source(self.root, target)
        self.assertEqual(target.read_bytes(), b"created by another writer")

    def test_only_valid_firmware_free_demo_profiles_may_be_bundled(self):
        for data in ([], {"backend": {"kind": "external"}},
                     {"backend": {"kind": "demo"}, "firmware": [{"path": "local.bin"}]}):
            path = self.put("vfl/profiles/test.json", json.dumps(data))
            try:
                self.assertFalse(audit(self.root)["clean"])
            finally:
                path.unlink()

    def test_malformed_json_reported_as_unclean_source(self):
        self.put("docs/broken.json", '{"unfinished":')
        report = audit(self.root)
        self.assertFalse(report["clean"])
        self.assertTrue(report["errors"])


if __name__ == "__main__":
    unittest.main()
