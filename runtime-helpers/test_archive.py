import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from build import unpack

class ArchiveControls(unittest.TestCase):
    def extract(self, entries, verify=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); archive = root / "source.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                for name, target in entries:
                    item = tarfile.TarInfo(name)
                    if target is None:
                        item.size = 7; tar.addfile(item, io.BytesIO(b"source\n"))
                    else:
                        item.type = tarfile.SYMTYPE; item.linkname = target; tar.addfile(item)
            unpack(archive, root / "source", "component/")
            if verify: verify(root / "source")

    def test_regular_source_and_contained_packaging_link(self):
        self.extract([("component/pkg/brew/file", None), ("component/HomebrewFormula", "pkg/brew")],
                     lambda root: self.assertEqual((root / "HomebrewFormula/file").read_bytes(), b"source\n"))

    def test_directory_link_can_precede_its_target(self):
        self.extract([("component/HomebrewFormula", "pkg/brew"), ("component/pkg/brew/file", None)],
                     lambda root: self.assertEqual((root / "HomebrewFormula/file").read_bytes(), b"source\n"))

    def test_escaping_member_is_refused(self):
        with self.assertRaises(AssertionError): self.extract([("component/../../outside", None)])

    def test_escaping_link_is_refused(self):
        with self.assertRaises(AssertionError): self.extract([("component/link", "../../outside")])

    def test_wrong_component_prefix_is_refused(self):
        with self.assertRaises(AssertionError): self.extract([("unexpected/file", None)])

if __name__ == "__main__": unittest.main()
