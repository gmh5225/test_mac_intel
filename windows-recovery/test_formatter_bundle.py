"""Authored negative controls for the downloaded tool's file boundary."""
from pathlib import Path
import json
import tempfile
import unittest

from formatter_bundle import OWNER_TESTS, PARSER_PROFILE, SOURCE_COMMIT, sha, verify


class BundleBoundary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ["neverd-web-source-recovery.exe", "owner-tests.xml"]:
            (self.root / name).write_bytes(b"authored fixture, never executed")
        self.receipt = {"source_commit": SOURCE_COMMIT, "parser_profile": PARSER_PROFILE,
            "owner_tests": sorted(OWNER_TESTS), "tool": "neverd-web-source-recovery.exe",
            "files": [{"file": p.name, "bytes": p.stat().st_size, "sha256": sha(p)}
                      for p in sorted(self.root.iterdir())]}

    def seal(self):
        path = self.root / "manifest.json"
        path.write_text(json.dumps(self.receipt))
        return sha(path)

    def test_exact_files_accepted(self):
        verify(self.root, self.seal())

    def test_manifest_pin_required(self):
        self.seal()
        with self.assertRaises(AssertionError):
            verify(self.root, "0" * 64)

    def test_modified_tool_refused(self):
        digest = self.seal()
        (self.root / "neverd-web-source-recovery.exe").write_bytes(b"changed")
        with self.assertRaises(AssertionError):
            verify(self.root, digest)

    def test_unlisted_runtime_library_refused(self):
        digest = self.seal()
        (self.root / "unexpected.dll").write_bytes(b"unlisted")
        with self.assertRaises(AssertionError):
            verify(self.root, digest)

    def test_duplicate_file_refused(self):
        self.receipt["files"].append(dict(self.receipt["files"][0]))
        with self.assertRaises(AssertionError):
            verify(self.root, self.seal())

    def test_escaping_or_noncanonical_paths_refused(self):
        for name in ["../outside", "/absolute", "C:/drive", "a\\b", "a//b", "./a"]:
            with self.subTest(name=name):
                self.receipt["files"][0]["file"] = name
                with self.assertRaises(AssertionError):
                    verify(self.root, self.seal())

    def test_owner_drift_refused(self):
        self.receipt["source_commit"] = "0" * 40
        with self.assertRaises(AssertionError):
            verify(self.root, self.seal())

    def test_missing_qualification_refused(self):
        self.receipt["owner_tests"].pop()
        with self.assertRaises(AssertionError):
            verify(self.root, self.seal())


if __name__ == "__main__":
    unittest.main()
