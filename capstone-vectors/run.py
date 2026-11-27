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
    run('cmake','-S',pr,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release');rom,tsv,bios=inputs(w);assert bios['extents']==q['bios_extents'] and all(bios[k]==v for k,v in q['bios'].items())
    source=rd(r/'input-sources.json');run('clang',*source['compile'],r/'scalar.c','-o',w/'scalar.o')
    with (w/'scalar.o').open('rb')as f:raw=ELFFile(f).get_section_by_name('.text').data()
    assert hashlib.sha256(raw).hexdigest()==q['scalar']
    scalar=w/'scalar.bin';scalar.write_bytes(raw);spans=w/'scalar.tsv';spans.write_text(f'0 {len(raw)} 1048576\n')
    samples=[('seabios16',16,rom,tsv),('scalar16',16,scalar,spans),*fixtures(r,w,m)]
    assert len(samples)==8;counts={}
    reports={}
    def instrument(file,marker,counter,body=False):
        path=s/file
        text=path.read_text()
        assert text.count(marker)==1,(file,marker)
        i=text.index(marker)
        if body:i=text.index('{',i)+1
        text=text[:i]+'\n\textern uint64_t '+counter+'; ++'+counter+';\n\t'+text[i:]
        path.write_text(text)
    for stage in ('base','candidate'):
        if stage=='candidate':
            run('git','-C',s,'restore','--worktree','--source=HEAD','--','.')
            patch=r/'candidate.patch';assert hashlib.sha256(patch.read_bytes()).hexdigest()==q[stage]['sha256']
            run('git','-C',s,'apply','--index',patch)
        assert get('git','-C',s,'write-tree')==q[stage]['tree']
        instrument('cs.c','MCInst_InitX86(&mci);','profile_full_decodes')
        instrument('arch/X86/X86Disassembler.c','const int ret = decodeInstruction(insn, decode_code, decode_size, mode);','profile_decodes')
        instrument('arch/X86/X86IntelInstPrinter.c','void X86_Intel_printInst(MCInst *MI, SStream *O, void *Info)','profile_prints',True)
        run('cmake','--build',b,'--target','capstone_static','--parallel','4')
        lib,=b.rglob('libcapstone.a')
        run('clang++','-O2','-std=c++17','-I',s,'-I',s/'include',r/'profile.cpp',lib,'-o',w/'profile')
        counts={};reports[stage]=counts
        for name,bits,file,ext in samples:
            lines=get(w/'profile',file,ext,str(bits)).splitlines()
            header=lines.pop(0).split('\t');assert header[0]=='total'
            head=list(map(int,header[1:]));assert len(head)==12 and head[:2]==q['events'][name],(name,head,q['events'][name])
            families={}
            for line in lines:
                z=line.split('\t');assert len(z) in (15,17)
                k='/'.join(z[:2]);v=list(map(int,z[2:15]));assert k not in families and all(0<=x<=v[0] for x in v[1:])
                families[k]=dict(count=v[0],full=v[1:5],canonical=v[5:9],printer=v[9:13],example=z[15:])
            assert sum(v['count'] for v in families.values())==head[0]
            counts[name]=dict(header=head,families=families)
            if stage=='candidate':
                prev=reports['base'][name]
                assert head[:4]==prev['header'][:4] and {k:v['count']for k,v in families.items()}=={k:v['count']for k,v in prev['families'].items()}
            save('counts',reports)
    save('complete',dict(complete=True,source=q,bios=bios,programs=reports))

finally:
    used=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=used))
