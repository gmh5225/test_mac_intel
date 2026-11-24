from pathlib import Path
import hashlib,os,shutil,subprocess as sp

class FixedImage:
    """Run each image at a single pathname, inode and ELF load address."""
    def __init__(self, dest, paths):
        image={k:p.read_bytes()for k,p in paths.items()}
        size=max(map(len,image.values()))
        self.data={k:v.ljust(size,b'\0') for k,v in image.items()}
        self.path=dest
        shutil.copy2(paths['base'],dest)
        dest.write_bytes(self.data['base'])
        self.size=size
        self.inode=dest.stat().st_ino
        self.offsets=[i for i in range(0,size,4096) if len({v[i:i+4096] for v in self.data.values()})>1]
        assert self.offsets and 'EXEC' in sp.check_output(['readelf','-h',dest],text=True)
        self.checked={}
    def run(self,label,*args):
        with self.path.open('r+b',buffering=0) as f:
            for offset in self.offsets:
                part=self.data[label][offset:offset+4096]
                f.seek(offset)
                assert f.write(part)==len(part)
        assert self.path.stat().st_ino==self.inode and self.path.stat().st_size==self.size
        if label not in self.checked:
            self.checked[label]=hashlib.sha256(self.path.read_bytes()).hexdigest()
            assert self.checked[label]==hashlib.sha256(self.data[label]).hexdigest()
        return list(map(int,sp.check_output(['setarch',os.uname().machine,'-R',self.path,*args]).split()))
