"""Owned data checks real file creation, confidentiality and admission."""
from pathlib import Path
import base64
import tempfile
import unittest
from receive_private_input import receive


class PrivateTransport(unittest.TestCase):
    def test_exact_private_files_and_no_overwrite(self):
        values = [base64.b64encode(('owned data ' + str(i)).encode()).decode() for i in range(8)]
        environment = {'NDC_NATIVE_X64_V12_' + format(i, '03'): value for i, value in enumerate(values)}
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / 'chunks'
            receive(folder, 0, 8, environment)
            self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
            for index, value in enumerate(values):
                path = folder / format(index, '03')
                self.assertEqual(path.read_text(), value)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                receive(folder, 0, 8, environment)

    def test_malformed_payload_never_creates_a_chunk(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary) / 'chunks'
            with self.assertRaises(AssertionError):
                receive(folder, 0, 1, {'NDC_NATIVE_X64_V12_000': 'not base64!'})
            self.assertEqual(list(folder.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
