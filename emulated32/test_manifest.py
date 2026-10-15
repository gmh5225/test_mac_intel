#!/usr/bin/env python3
"""Reject malformed qualification manifests even when an attacker rehashes them."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from run_apple import load_images

class ManifestAdmission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / 'images'
        shutil.copytree(Path(__file__).parent / 'apple/macos-i386', self.directory)
        self.path = self.directory / 'manifest.json'
        self.manifest = json.loads(self.path.read_text())

    def write(self):
        self.path.write_text(json.dumps(self.manifest))

    def reject(self):
        self.write()
        with self.assertRaises(AssertionError):
            load_images(self.directory, 'macos-i386')

    def test_real_baseline(self):
        load_images(self.directory, 'macos-i386')

    def test_corrupt_image(self):
        p = self.directory / self.manifest['images'][0]['path']
        p.write_bytes(p.read_bytes() + b'x')
        self.reject()

    def test_wrong_cpu_with_matching_hash(self):
        row = self.manifest['images'][0]
        p = self.directory / row['path']
        data = bytearray(p.read_bytes())
        struct.pack_into('<I', data, 4, 12)
        p.write_bytes(data)
        row['sha256'] = hashlib.sha256(data).hexdigest()
        self.manifest['cpu'] = 12
        self.reject()

    def test_duplicate_case(self):
        self.manifest['images'][1] = copy.deepcopy(self.manifest['images'][0])
        self.reject()

    def test_forged_expected_exit(self):
        self.manifest['images'][1]['expected'] = 0
        self.reject()

    def test_receipt_mapping_mismatch_with_matching_hash(self):
        row = self.manifest['images'][1]
        p = self.directory / row['receipt']
        receipt = json.loads(p.read_text())
        receipt['requested'][0]['original_va'] += 4
        p.write_text(json.dumps(receipt))
        row['receipt_sha256'] = hashlib.sha256(p.read_bytes()).hexdigest()
        self.reject()

if __name__ == '__main__':
    unittest.main()
