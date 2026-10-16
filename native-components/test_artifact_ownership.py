from pathlib import Path
import json,tempfile,unittest
from select_artifacts import select

class CargoArtifactOwnership(unittest.TestCase):
    def record(self,path,fresh=False):
        return dict(reason='compiler-artifact',filenames=[str(path)],fresh=fresh,package_id='authored-fixture',target=dict(name='recovered_ripgrep',crate_types=['rlib']))

    def test_reported_alternative_intermediate_path_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'separate-build/aarch64-unknown-linux-gnu/librecovered_ripgrep.rlib';source.parent.mkdir(parents=True);source.write_bytes(b'!<arch>\nowned fixture')
            log=root/'cargo.jsonl';log.write_text(json.dumps(self.record(source))+'\n')
            output=root/'selected';select(log,root,'aarch64-unknown-linux-gnu',output)
            self.assertEqual((output/source.name).read_bytes(),source.read_bytes())

    def test_unowned_and_cached_artifacts_refuse_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);owned=root/'owned';owned.mkdir();source=root/'aarch64-unknown-linux-gnu/librecovered_ripgrep.rlib';source.parent.mkdir();source.write_bytes(b'!<arch>\nfixture')
            log=root/'cargo.jsonl';output=root/'output'
            for record,boundary in [(self.record(source),owned),(self.record(source,True),root)]:
                log.write_text(json.dumps(record)+'\n')
                with self.assertRaises(AssertionError):select(log,boundary,'aarch64-unknown-linux-gnu',output)
                self.assertFalse(output.exists())

if __name__=='__main__':unittest.main()
