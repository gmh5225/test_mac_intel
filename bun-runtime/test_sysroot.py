from pathlib import Path
import io,tarfile,tempfile,unittest
from prepare_sysroot import Projection
def archive(rows):
    wire=io.BytesIO()
    with tarfile.open(fileobj=wire,mode='w') as stream:
        for name,value,kind in rows:
            m=tarfile.TarInfo(name)
            if kind=='file':m.size=len(value);m.mode=0o644;stream.addfile(m,io.BytesIO(value))
            else:m.type=tarfile.SYMTYPE;m.linkname=value;stream.addfile(m)
    wire.seek(0);return tarfile.open(fileobj=wire)
class SysrootBoundaries(unittest.TestCase):
    def test_absolute_links_are_relocated_without_host_access(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);p=Projection(root)
            with archive([('lib/owned',b'fixture','file'),('lib/alias','/lib/owned','link')]) as stream:p.extract(stream)
            p.finish();self.assertEqual((root/'lib/alias').read_bytes(),b'fixture');self.assertEqual((root/'lib/alias').readlink(),Path('owned'))
    def test_traversal_and_link_parent_collision_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for rows in [[('../outside',b'no','file')],[('lib/alias','../../outside','link')]]:
                with archive(rows) as stream,self.assertRaises(AssertionError):Projection(root).extract(stream)
            p=Projection(root)
            with archive([('alias','/owned','link'),('alias/file',b'data','file')]) as stream:p.extract(stream)
            with self.assertRaises(AssertionError):p.finish()
if __name__=='__main__':unittest.main()
