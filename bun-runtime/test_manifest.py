from pathlib import Path
import json,tempfile,unittest
from native_libraries import check_manifest,sha

class ArtifactOwnershipTests(unittest.TestCase):
    def test_complete_regular_package_is_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'entry').write_bytes(b'owned')
            manifest=root/'MANIFEST.json'
            manifest.write_text(json.dumps({'files':[dict(file='entry',bytes=5,sha256=sha(root/'entry'))]}))
            digest=sha(manifest);check_manifest(root,digest)
            (root/'entry').write_bytes(b'other')
            with self.assertRaises(AssertionError):check_manifest(root,digest)
            (root/'entry').write_bytes(b'owned');(root/'extra').write_bytes(b'extra')
            with self.assertRaises(AssertionError):check_manifest(root,digest)
            (root/'extra').unlink();(root/'alias').symlink_to(root/'entry')
            with self.assertRaises(AssertionError):check_manifest(root,digest)

    def test_manifest_cannot_escape_or_alias_file_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'entry').write_bytes(b'owned')
            row=dict(file='entry',bytes=5,sha256=sha(root/'entry'));manifest=root/'MANIFEST.json'
            for records in [[dict(row,file='../entry')],[dict(row,file='/entry')],
                            [dict(row,file='./entry')],[row,row]]:
                manifest.write_text(json.dumps({'files':records}))
                with self.assertRaises(AssertionError):check_manifest(root,sha(manifest))
