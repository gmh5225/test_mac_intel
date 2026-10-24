"""Owned payloads exercise the real secret-to-private-file boundary."""
from pathlib import Path
import base64
import tempfile
import unittest
from receive_private_input import receive


class PrivateTransport(unittest.TestCase):
    def test_complete_batch_is_private_exact_and_cannot_overwrite(self):
        values = [base64.b64encode(('owned fixture ' + str(i)).encode()).decode() for i in range(13)]
        environment = {'NDC_AUDIO_X64_V10_' + format(i, '03'): value for i, value in enumerate(values)}
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / 'chunks'
            receive(destination, 0, 13, environment)
            self.assertEqual(len(list(destination.iterdir())), 13)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            for index, value in enumerate(values):
                path = destination / format(index, '03')
                self.assertEqual(path.read_text(), value)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                receive(destination, 0, 13, environment)
            self.assertEqual((destination / '000').read_text(), values[0])

    def test_malformed_payload_is_rejected_before_a_file_is_created(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / 'chunks'
            with self.assertRaises(AssertionError):
                receive(destination, 0, 1, {'NDC_AUDIO_X64_V10_000': 'not base64!'})
            self.assertEqual(list(destination.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
