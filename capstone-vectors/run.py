from pathlib import Path
from elftools.elf.elffile import ELFFile
import hashlib,json,shutil,subprocess as sp,tempfile
from firmware import inputs
from fixtures import fixtures
r=Path(__file__).resolve().parent;p=r.parent;e=p/'evidence';e.mkdir(exist_ok=True);s=p/'source';nd=p/'neverd-config'
rd=lambda f:json.loads(f.read_bytes())
def save(name,v):(e/(name+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def get(*a):return sp.check_output(a,text=True).strip()
def run(*a):sp.run(a,check=True)
q=rd(r/'source.json');m=rd(r/'experiment.json');w=Path(tempfile.mkdtemp());pr=w/'project';b=w/'build'
try:
    assert get('git','-C',s,'rev-parse','HEAD')==q['base']['commit'] and get('git','-C',nd,'rev-parse','HEAD')==q['dev']
    (pr/'third_party').mkdir(parents=True);(pr/'third_party/capstone').symlink_to(s);(pr/'cmake').mkdir();cm='cmake/NeverDCapstoneCompilerOptions.inc';shutil.copyfile(nd/cm,pr/cm)
    text=(nd/'CMakeLists.txt').read_text();(pr/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Records LANGUAGES C CXX)\n'+text[text.index('# --- Capstone (our fork'):text.index('# --- NeverD CMake helpers')])
    run('cmake','-S',pr,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release');run('cmake','--build',b,'--target','capstone_static','--parallel','4')
    lib,=b.rglob('libcapstone.a');run('clang++','-std=c++17','-O2','-I',s/'include',r/'profile.cpp',lib,'-o',w/'profile')
    rom,tsv,bios=inputs(w);assert bios['extents']==q['bios_extents'] and all(bios[k]==v for k,v in q['bios'].items())
    source=rd(r/'input-sources.json');run('clang',*source['compile'],r/'scalar.c','-o',w/'scalar.o')
    with (w/'scalar.o').open('rb')as f:raw=ELFFile(f).get_section_by_name('.text').data()
    assert hashlib.sha256(raw).hexdigest()==q['scalar']
    scalar=w/'scalar.bin';scalar.write_bytes(raw);spans=w/'scalar.tsv';spans.write_text(f'0 {len(raw)} 1048576\n')
    samples=[('seabios16',16,rom,tsv),('scalar16',16,scalar,spans),*fixtures(r,w,m)]
    assert len(samples)==8;counts={}
    for name,bits,file,ext in samples:
        rows=[x.split('\t') for x in get(w/'profile',str(bits),file,ext).splitlines()]
        freq={k:int(n)for n,k in rows};assert len(freq)==len(rows) and all(x>0 for x in freq.values());counts[name]=dict(bits=bits,total=sum(freq.values()),shapes=freq)
    save('complete',dict(complete=True,source=q,bios=bios,programs=counts))
finally:
    used=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=used))
