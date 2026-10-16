from pathlib import Path
import io
import tarfile
import tempfile
import unittest
from build_linux import unpack_source


class ReleaseMetadata(unittest.TestCase):
    def test_generated_file_dates_survive_reverse_archive_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "release.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                for name, date, data in [("aclocal.m4", 200, b"generated"), ("configure.ac", 100, b"input")]:
                    row = tarfile.TarInfo("release/" + name)
                    row.size = len(data); row.mtime = date
                    tar.addfile(row, io.BytesIO(data))
            unpack_source(archive, root / "source", "release/")
            self.assertEqual((root / "source/aclocal.m4").read_bytes(), b"generated")
            self.assertEqual((root / "source/configure.ac").read_bytes(), b"input")
            self.assertEqual((root / "source/aclocal.m4").stat().st_mtime, 200)
            self.assertEqual((root / "source/configure.ac").stat().st_mtime, 100)


if __name__ == "__main__":
    unittest.main()
