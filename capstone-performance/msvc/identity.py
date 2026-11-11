"""Verify that the Windows-specific implementations leave other runtime binaries identical."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess,tempfile,sys
os.environ['ZERO_AR_DATE'] = '1'
root=Path.cwd()
src=root/'capstone-performance'
out=root/'capstone-evidence'
out.mkdir()
work=Path(tempfile.mkdtemp(dir=os.environ['RUNNER_TEMP'],prefix='capstone-identity-'))
def run(args,name,cwd=None):
    with (out/(name+'.log')).open('w') as f:
        subprocess.run(list(map(str,args)),cwd=cwd,stdout=f,stderr=subprocess.STDOUT,check=True)
def digest(path):
    with path.open('rb') as f: return hashlib.sha256(f.read()).hexdigest()
def archive_without_dates(path):
    data=bytearray(path.read_bytes())
    assert data[:8] == b"!<arch>\n"
    offset=8
    members=0
    while offset < len(data):
        header=data[offset:offset+60]
        assert len(header)==60 and header[58:60]==bytes((96,10))
        size=int(header[48:58]); assert size>=0
        data[offset+16:offset+28]=b' '*12
        offset += 60 + size + size%2
        members+=1
    assert offset==len(data) and members>100
    return hashlib.sha256(data).hexdigest()

def write(name,value):
    (out/name).write_text(json.dumps(value,indent=2)+'\n')
try:
    source=work/'capstone'
    run(['git','init',source],'init')
    rev=json.loads((src/'manifest.json').read_text())['capstone_revision']
    run(['git','fetch','--depth=1','https://github.com/NeverSight/capstone.git',rev],'fetch',source)
    run(['git','checkout','--detach','FETCH_HEAD'],'checkout',source)
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()==rev
    run([os.environ['CC'],'--version'],'compiler')
    run(['cmake','-S',source,'-B',work/'build','-G','Ninja','-DCMAKE_BUILD_TYPE=Release',
         '-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON',
         '-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
         '-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
    build=work/'build'
    reference=None
    for label,patch in [('base',None),('formatter','msvc-hook-only.patch'),('printer','windows-formatter.patch'),('alias','msvc-alias.patch')]:
        run(['git','restore','.'],'reset-'+label,source)
        if patch: run(['git','apply',src/patch],label+'-apply',source)
        run(['cmake','--build',build,'--parallel','4','--target','capstone_static','capstone_shared'],label+'-build')
        products=sorted((build/'CMakeFiles/capstone.dir').rglob('*.o'))+[build/'libcapstone.a']
        shared=[x for x in build.glob('libcapstone*') if x.is_file() and not x.is_symlink() and x.suffix!='.a']
        assert len(shared)==1 and len(products)>100
        hashes={str(p.relative_to(build)):digest(p) for p in products+shared}
        hashes['archive-without-member-dates']=archive_without_dates(build/'libcapstone.a')
        write(label+'.json',hashes)
        if reference is None:
            reference=hashes
        else:
            changed=[k for k in hashes.keys()|reference.keys() if hashes.get(k)!=reference.get(k)]
            write(label+'-changed.json',changed)
            assert set(changed) <= {'libcapstone.a'}, changed
finally:
    before=sum(p.stat().st_size for p in work.rglob('*') if p.is_file() and not p.is_symlink())
    shutil.rmtree(work)
    write('cleanup.json',dict(logical_bytes=before,removed=not work.exists()))
