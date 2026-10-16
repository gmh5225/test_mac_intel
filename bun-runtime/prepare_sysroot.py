"""Project the upstream focal/GCC-13 sysroot from exact public inputs."""
from pathlib import Path,PurePosixPath
import hashlib,json,os,posixpath,subprocess,tarfile,urllib.request
ROOT=Path(__file__).resolve().parent
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def relative(name):
    path=PurePosixPath(name);assert not path.is_absolute() and '..' not in path.parts
    parts=[part for part in path.parts if part!='.']
    return PurePosixPath(*parts) if parts else None
class Projection:
    def __init__(self,root):self.root=root.resolve();self.links={};self.files=0;self.bytes=0
    def extract(self,stream):
        for member in stream:
            rel=relative(member.name)
            if rel is None:continue
            self.files+=1;assert self.files<=100000
            path=self.root/rel;assert not path.is_symlink()
            assert all(not p.is_symlink() for p in path.parents if p.is_relative_to(self.root))
            if member.isdir():path.mkdir(parents=True,exist_ok=True)
            elif member.isfile():
                assert member.size<=256*1024*1024
                self.bytes+=member.size;assert self.bytes<=3*1024*1024*1024
                data=stream.extractfile(member).read();assert len(data)==member.size
                path.parent.mkdir(parents=True,exist_ok=True)
                if path.exists():assert path.is_file() and path.read_bytes()==data,'Nonidentical package file collision'
                else:path.write_bytes(data);path.chmod(member.mode&0o755)
            elif member.issym() or member.islnk():
                if member.linkname.startswith('/'):target=posixpath.normpath(member.linkname).lstrip('/')
                elif member.islnk():target=posixpath.normpath(member.linkname)
                else:target=posixpath.normpath(str(rel.parent)+'/'+member.linkname)
                target=relative(target);assert target is not None
                record=(str(target),member.islnk())
                assert str(rel) not in self.links or self.links[str(rel)]==record
                self.links[str(rel)]=record
            else:raise AssertionError('Unsupported sysroot archive member')
    def finish(self):
        for name,(target,hard) in self.links.items():
            path=self.root/name
            assert all(not p.is_symlink() for p in path.parents if p.is_relative_to(self.root))
            path.parent.mkdir(parents=True,exist_ok=True)
            assert not path.exists() and not path.is_symlink(),'Package link collides with materialized data'
            if hard:
                source=self.root/target;assert source.is_file() and not source.is_symlink();os.link(source,path)
            else:path.symlink_to(os.path.relpath(self.root/target,path.parent))
def prepare(arch,out,logs,*,cache=None):
    pins=ROOT/'glibc-sysroot-pins.json';profile=json.loads(pins.read_bytes())['profiles'][arch]
    archives=out/'sysroot-inputs';archives.mkdir();root=out/'sysroot';root.mkdir()
    receipt=dict(status='started',arch=arch,pins_sha256=sha(pins),sources=[],extracts=[])
    def download(label,record):
        path=archives/label;size=0;digest=hashlib.sha256()
        cached=cache/Path(record['url']).name if cache is not None else None
        if cached is not None:assert cached.is_file() and not cached.is_symlink()
        source=cached.open('rb') if cached is not None else urllib.request.urlopen(record['url'],timeout=90)
        with source,path.open('xb') as target:
            while block:=source.read(1048576):
                size+=len(block);assert size<=record['bytes'];digest.update(block);target.write(block)
        assert size==record['bytes'] and digest.hexdigest()==record['sha256']
        receipt['sources'].append(dict(file=label,**record));return path
    projection=Projection(root)
    def deb(path):
        with (logs/(path.name+'.dpkg.stderr')).open('xb') as error:
            process=subprocess.Popen(['dpkg-deb','--fsys-tarfile',path],stdout=subprocess.PIPE,stderr=error)
            try:
                with tarfile.open(fileobj=process.stdout,mode='r|') as stream:projection.extract(stream)
                assert process.wait(timeout=60)==0
            finally:
                if process.poll() is None:process.kill();process.wait(timeout=5)
                process.stdout.close()
        receipt['extracts'].append(dict(file=path.name,sha256=sha(path),bytes=path.stat().st_size))
    try:
        for row in profile['debs']:deb(download(row['name']+'.deb',row))
        gcc=download('gcc-13-focal.tar.gz',profile['gcc']);gcc_debs=archives/'gcc-debs';gcc_debs.mkdir();count=0
        excluded=[]
        with tarfile.open(gcc,'r:gz') as stream:
            for member in stream:
                rel=relative(member.name)
                if rel is None or member.isdir():continue
                assert member.isfile() and member.size<=256*1024*1024
                if not rel.name.endswith('.deb'):continue
                # Bun uses its pinned Clang. Keep every GCC runtime/header
                # package, while omitting the three unrelated compiler drivers.
                if rel.name.split('_')[0] in ['cpp-13','g++-13','gcc-13']:
                    excluded.append(dict(file=rel.name,bytes=member.size));continue
                target=gcc_debs/rel.name;assert not target.exists()
                target.write_bytes(stream.extractfile(member).read());assert target.stat().st_size==member.size
                count+=1;assert count<=128;deb(target)
        assert count>0;projection.finish()
        assert (root/'usr/include/c++/13').is_dir()
        triple={'x64':'x86_64-linux-gnu','arm64':'aarch64-linux-gnu'}[arch]
        assert (root/'lib'/triple/'libc.so.6').is_file()
        rows=[]
        for path in sorted(root.rglob('*')):
            if path.is_symlink():rows.append(dict(file=path.relative_to(root).as_posix(),symlink=os.readlink(path)))
            elif path.is_file():rows.append(dict(file=path.relative_to(root).as_posix(),bytes=path.stat().st_size,sha256=sha(path)))
        inventory=logs/'sysroot-files.json';inventory.write_text(json.dumps(dict(files=rows),indent=2)+'\n')
        receipt.update(status='pinned_upstream_focal_gcc13_sysroot_prepared',inventory_sha256=sha(inventory),files=len(rows),bytes=projection.bytes,
            absolute_links_projected_inside_root=True,upstream_base_image_omitted=True,excluded_compiler_executables=excluded,
            scope='Five exact libc/header packages and all GCC runtime/header packages. The three unused GCC compiler driver packages are omitted; Bun uses pinned Clang. Host configuration is unchanged.')
        return root
    except Exception as error:receipt.update(status='failed',error=str(error));raise
    finally:(logs/'sysroot-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
