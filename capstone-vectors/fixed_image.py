import hashlib,os

class FixedImage:
    """Switch only differing pages at one inode, path and load address."""
    def __init__(self,path,blobs,executable=False):
        self.path=path
        self.size=max(map(len,blobs.values()))
        self.images={k:b.ljust(self.size,b'\0')for k,b in blobs.items()}
        self.images['copy']=self.images['base']
        self.images['repeat']=self.images['candidate']
        self.current='base';self.verified={}
        path.write_bytes(self.images['base'])
        if executable:os.chmod(path,0o755)
        self.inode=path.stat().st_ino
        self.spans=[]
        for start in range(0,self.size,4096):
            end=min(start+4096,self.size)
            if len({image[start:end] for image in self.images.values()})==1:continue
            if self.spans and self.spans[-1][1]==start:self.spans[-1][1]=end
            else:self.spans.append([start,end])
        self.select('base')
    def select(self,stage):
        if self.current!=stage:
            with self.path.open('r+b',buffering=0) as f:
                for a,b in self.spans:
                    f.seek(a);assert f.write(memoryview(self.images[stage])[a:b])==b-a
            self.current=stage
        assert self.path.stat().st_ino==self.inode
        if stage not in self.verified:
            self.verified[stage]=hashlib.sha256(self.path.read_bytes()).hexdigest()
            assert self.verified[stage]==hashlib.sha256(self.images[stage]).hexdigest()
    def receipt(self):
        return dict(inode=self.inode,bytes=self.size,verified=self.verified,spans=self.spans)
