"""Successful runs remove only the disposable tools they installed."""

import json
from pathlib import Path
import tempfile
import unittest

import run


CASES = json.loads(Path(__file__).with_name("CptaCleanupTestCases.def").read_text())


class CleanupTests(unittest.TestCase):
    def test_cleanup_preserves_guests_inputs_reports_and_supplied_models(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = CASES["payload"].encode()
            for name in CASES["preserved"]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            for key in ("model_archive", "model_installer"):
                (root / run.CONFIG[key]).write_bytes(data)
            model = root / run.CONFIG["model_install_directory"] / run.CONFIG["model_binary"]
            model.parent.mkdir(parents=True)
            model.write_bytes(data)
            run.remove_model_tools(root)
            for key in ("model_archive", "model_installer", "model_install_directory"):
                self.assertFalse((root / run.CONFIG[key]).exists())
            for name in CASES["preserved"]:
                self.assertEqual((root / name).read_bytes(), data)

    def test_an_installation_symlink_does_not_delete_its_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            external = root / CASES["preserved"][-1]
            external.parent.mkdir(parents=True)
            external.write_text(CASES["payload"])
            (root / run.CONFIG["model_install_directory"]).symlink_to(
                external.parent, target_is_directory=True)
            run.remove_model_tools(root)
            self.assertEqual(external.read_text(), CASES["payload"])


if __name__ == "__main__":
    unittest.main()
