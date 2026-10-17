import copy
from pathlib import Path
import hashlib,json,tempfile
import unittest
from original_acceptance import admit_package,differences

class ExactComparisonTests(unittest.TestCase):
    def test_complete_streams_and_expected_status_are_required(self):
        value=dict(exit_code=0,stdout=b'owned output\n',stderr=b'')
        self.assertEqual(differences(value,dict(value),0),[])
        for field,replacement in [('stdout',b'owned output'),('stdout',b'owned output\nextra'),('stderr',b'warning\n'),('exit_code',1)]:
            changed=dict(value);changed[field]=replacement
            self.assertTrue(differences(value,changed,0),field)
        wrong=dict(value,exit_code=2)
        self.assertEqual(differences(wrong,dict(wrong),0),['exit status'])

    def test_package_admission_refuses_tampering_extra_files_and_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'package';root.mkdir();payload=root/'bfs';payload.write_bytes(b'owned artifact')
            manifest=root/'MANIFEST.json';manifest.write_text(json.dumps(dict(files=[dict(file='bfs',bytes=payload.stat().st_size,sha256=hashlib.sha256(payload.read_bytes()).hexdigest())])))
            expected=hashlib.sha256(manifest.read_bytes()).hexdigest();admit_package(root,expected)
            payload.write_bytes(b'tampered bytes')
            with self.assertRaises(AssertionError):admit_package(root,expected)
            payload.write_bytes(b'owned artifact');extra=root/'unqualified';extra.write_bytes(b'extra')
            with self.assertRaises(AssertionError):admit_package(root,expected)
            extra.unlink();outside=Path(temporary)/'outside';outside.write_bytes(payload.read_bytes());payload.unlink();payload.symlink_to(outside)
            with self.assertRaises(AssertionError):admit_package(root,expected)
