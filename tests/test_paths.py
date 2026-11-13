import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vfl.model import LabError, MAX_PROJECT_METADATA_BYTES, private_path


class InstalledOutputPathTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)
        self.checkout = self.workspace / "TycVirtualLab"
        self.checkout.mkdir()
        (self.checkout / "pyproject.toml").write_text('[project]\nname = "tycvirtuallab"\n')
        self.private = self.workspace / "TycVirtualLab-private"
        self.private.mkdir()
        installed = patch("vfl.model.source_root", return_value=None)
        installed.start()
        self.addCleanup(installed.stop)

    def test_installed_package_rejects_checkout_and_nested_new_outputs(self):
        for destination in (self.checkout, self.checkout / "capture.json",
                            self.checkout / "new" / "deep" / "run"):
            with self.subTest(destination=destination), self.assertRaisesRegex(LabError, "source checkout"):
                private_path(destination)

    def test_sibling_private_directory_and_unrelated_git_project_are_allowed(self):
        (self.workspace / ".git").mkdir()  # A workspace-wide Git marker is irrelevant.
        self.assertEqual(private_path(self.private / "capture.json"), self.private / "capture.json")
        other = self.workspace / "other-project"
        other.mkdir()
        (other / ".git").mkdir()
        (other / "pyproject.toml").write_text('[project]\nname = "unrelated-tool"\n')
        self.assertEqual(private_path(other / "output.json"), other / "output.json")

    def test_symlink_alias_into_checkout_is_rejected(self):
        alias = self.private / "source-alias"
        alias.symlink_to(self.checkout, target_is_directory=True)
        with self.assertRaisesRegex(LabError, "source checkout"):
            private_path(alias / "new" / "result.json")
        existing = self.checkout / "existing.json"
        existing.write_text("{}")
        file_alias = self.private / "file-alias.json"
        file_alias.symlink_to(existing)
        with self.assertRaisesRegex(LabError, "source checkout"):
            private_path(file_alias)

    def test_project_metadata_is_parsed_without_executing_backend(self):
        other = self.workspace / "metadata-only"
        other.mkdir()
        marker = other / "backend-was-executed"
        (other / "dangerous.py").write_text("from pathlib import Path\nPath(__file__).with_name('backend-was-executed').write_text('bad')\n")
        (other / "pyproject.toml").write_text(
            '[project]\nname = "unrelated-tool"\n'
            '[build-system]\nrequires = []\nbuild-backend = "dangerous"\nbackend-path = ["."]\n')
        self.assertEqual(private_path(other / "output.json"), other / "output.json")
        self.assertFalse(marker.exists())

    def test_uninspectable_metadata_fails_closed(self):
        metadata = self.checkout / "pyproject.toml"
        for content in ('[project\n', '[project]\nname="tycvirtuallab"\n#' + 'x' * MAX_PROJECT_METADATA_BYTES):
            metadata.write_text(content)
            with self.assertRaises(LabError):
                private_path(self.checkout / "output.json")
        metadata.unlink()
        os.mkfifo(metadata)
        with self.assertRaisesRegex(LabError, "regular file"):
            private_path(self.checkout / "output.json")


if __name__ == "__main__":
    unittest.main()
