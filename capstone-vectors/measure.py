from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,tempfile
from training import fetch
from foreign_time import measure
r=Path(__file__).resolve().parent;p=r.parent;out=p/'evidence';out.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text())
def save(n,data):(out/(n+'.json')).write_text(json.dumps(data,indent=2)+'\n')
def run(*x):sp.run(x,check=True)
def get(*x):return sp.check_output(x,text=True)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
q=rd(r/'source.json');m=rd(r/'experiment.json');cap=p/'source';nd=p/'neverd-config'
assert get('git','-C',cap,'rev-parse','HEAD').strip()==q['base']['commit'] and get('git','-C',nd,'rev-parse','HEAD').strip()==m['neverd']
w=Path(tempfile.mkdtemp())
try:
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    proj=w/'project';b=w/'build';(proj/'third_party').mkdir(parents=True);(proj/'third_party/capstone').symlink_to(cap)
    (proj/'cmake').mkdir();cm='cmake/NeverDCapstoneCompilerOptions.inc';shutil.copy2(nd/cm,proj/cm)
    code=(nd/'CMakeLists.txt').read_text()
    (proj/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(ReaderWork LANGUAGES C CXX)\n'+code[code.index('# --- Capstone (our fork'):code.index('# --- NeverD CMake helpers')])
    rows=fetch(r,w);expected=rd(r/'corpus-receipt.json');assert rows==expected
    save('corpus',rows)
    run('cmake','-S',proj,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    cpp=(r/'foreign.cpp').read_text();old='CS_MODE_RISCV_C | CS_MODE_RISCV_A';assert cpp.count(old)==1;cpp=cpp.replace(old,old+' | CS_MODE_RISCV_FD')
    (w/'native.cpp').write_text(cpp);mark='  for (unsigned rep = 0; rep < repeats; ++rep)';end='  const uint64_t cpu_ns'
    assert cpp.count(mark)==cpp.count(end)==1
    (w/'counted.cpp').write_text('#include <valgrind/callgrind.h>\n'+cpp.replace(mark,'  CALLGRIND_START_INSTRUMENTATION; CALLGRIND_ZERO_STATS;\n'+mark).replace(end,'  CALLGRIND_DUMP_STATS_AT("measure"); CALLGRIND_STOP_INSTRUMENTATION;\n'+end))
    for obj in ('native','counted'):run('clang++','-O3','-std=c++17','-I',cap/'include','-c',w/(obj+'.cpp'),'-o',w/(obj+'.o'))
    images={};obj_changes={};data={}
    for tag,src in [('base','base'),('candidate','prefix'),('outlined','outlined')]:
        run('git','-C',cap,'restore','--staged','--worktree','--source','HEAD','--','.')
        if tag!='base':
            patch=r/(tag+'.patch');assert sha(patch)==q[src]['sha256'];run('git','-C',cap,'apply','--index',patch)
        assert get('git','-C',cap,'write-tree').strip()==q[src]['tree']
        run('cmake','--build',b,'--target','capstone_static','--parallel','4')
        commands=rd(b/'compile_commands.json');assert ('CAPSTONE_STATIC_X86_READERS' in next(x['command']for x in commands if Path(x['file']).name=='cs.c'))==(tag!='base')
        ids={str(f.relative_to(b)):sha(f) for f in b.rglob('*.c.o')}
        if tag=='base':base_ids=ids
        else:assert set(ids)==set(base_ids)
        obj_changes[tag]=[Path(f).name for f,v in ids.items() if base_ids[f]!=v]
        if tag!='base':assert set(obj_changes[tag])=={'cs.c.o','X86DisassemblerDecoder.c.o','X86Sse64Output.c.o','X86Vex32Output.c.o'}
        lib,=b.rglob('libcapstone.a')
        for obj,img in [('native','foreign-'),('counted','count-')]:run('clang++',w/(obj+'.o'),lib,'-no-pie','-o',w/(img+tag))
        images[tag]=[sha(w/(a+tag)) for a in ['foreign-','count-']]
        for fun in ('cs_disasm_iter','cs_decode_full_insn',*(['decode_non_x86_record']if tag=='outlined' else [])):
            asm=get('objdump','-d','--disassemble='+fun,w/('foreign-'+tag));assert '<'+fun+'>:' in asm
            (out/(tag+'-'+fun+'.txt')).write_text(asm)
        for row in rows:
            arch=row['arch'];name=row['name'];text=w/(name+'.text');assert sha(text)==row['text_sha256']
            if arch not in ('arm','riscv64','ppc64el'):continue
            for mode in (0,1,2):
                args=[arch,text,str(mode),'1'];truth=list(map(int,get(w/('foreign-'+tag),*args).split()))[2:]
                assert truth[0]>0
                if arch=='riscv64':assert truth[1]==0
                key=name+'/'+str(mode);slot=data.setdefault(key,{})
                if tag!='base':assert truth==slot['base']['result']
                path=w/'counts';prefix='--callgrind-out-file='+str(path)
                res=list(map(int,get('valgrind','--tool=callgrind','--instr-atstart=no','--branch-sim=yes',prefix,'--log-file='+str(w/'log'),w/('count-'+tag),*args).split()))[2:];assert res==truth
                dumps=[f for f in w.glob('counts.*') if 'Client Request: measure' in f.read_text(errors='replace')];assert len(dumps)==1
                lines=dumps[0].read_text().splitlines()
                names=next(x.split()[1:]for x in lines if x.startswith('events:'));counts=list(map(int,next(x.split()[1:]for x in lines if x.startswith('summary:'))));assert names==['Ir','Bc','Bcm','Bi','Bim'] and counts[0]>truth[0]
                (out/(tag+'-'+name+'-'+str(mode)+'-owners.txt')).write_text(get('callgrind_annotate','--show=Ir,Bc,Bcm,Bi,Bim','--sort=Ir','--threshold=100','--auto=no',dumps[0]))
                slot[tag]=dict(result=truth,events=dict(zip(names,counts)));save('work',data)
                path.unlink();dumps[0].unlink()
    measure(rows,w,save)
    save('complete',dict(complete=True,source=q,neverd=m['neverd'],images=images,changed_objects=obj_changes,host=os.uname().machine,cpu=get('lscpu'),compiler=get('clang','--version').splitlines()[0],rows=len(data)))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
