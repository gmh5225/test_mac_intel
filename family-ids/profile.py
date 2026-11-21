from pathlib import Path
import gzip, hashlib, json, os, platform, shutil, statistics, subprocess as sp, tempfile
import corpus
import parse_cost
r=Path(__file__).resolve().parent;root=r.parent;s=root/'source';out=root/'evidence';out.mkdir(exist_ok=True)
def save(n,x):(out/(n+'.json')).write_text(json.dumps(x,indent=2)+'\n')
def read(f):return json.loads(f.read_text())
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def run(args,n,cwd=None):
    with (out/(n+'.log')).open('w') as f:sp.run(args,cwd=cwd,stdout=f,stderr=sp.STDOUT,check=True)
def git(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
m=read(r/'source.json');cc=os.environ['CC'];labels=('base','projection','owner')
assert git('rev-parse','HEAD')==m['base']
interesting={'cs_disasm_iter','cs_decode_full_insn','ARM_getInstruction','AArch64_getInstruction','X86_get_op_access','X86_postprinter','X86_get_insn_id','printSSEAVXCC','X86_Intel_printInst','X86_scanBatch','PPC_getInstruction'}
with tempfile.TemporaryDirectory() as td:
    t=Path(td);b=t/'build';fix=t/'fixed';fix.mkdir(); libs={};objects={};symbols={};size=0
    try:
        opts=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers')]
        opts+=['-DCAPSTONE_'+k+'_SUPPORT=ON' for k in ('X86','AARCH64','ARM','MIPS','PPC','RISCV')]
        run(['cmake','-S',s,'-B',b,*opts],'configure')
        for k in labels:
            if k!='base':
                patch=r/(k+'.patch');assert sha(patch)==m[k]['sha256']
                git('apply','--index',str(patch));assert git('write-tree')==m[k]['tree']
            run(['cmake','--build',b,'--target','capstone_shared','--parallel','4'],'build-'+k)
            path=next(z for z in b.glob('libcapstone.so.*') if not z.is_symlink())
            dest=t/(k+'.so');shutil.copyfile(path,dest);libs[k]=dest
            sections={}
            for f in sorted((b/'CMakeFiles/capstone.dir').rglob('*.o')):
                stem=str(f.relative_to(b/'CMakeFiles/capstone.dir'));tmp=t/'text'
                sp.run(['objcopy','-O','binary','--only-section=.text',f,tmp],check=True)
                sections[stem]=dict(object=sha(f),text=sha(tmp),text_bytes=tmp.stat().st_size)
            objects[k]=sections
            sy={}
            for line in sp.check_output(['nm','-Sn','--defined-only',dest],text=True).splitlines():
                a=line.split()
                if len(a)==4 and a[3] in interesting:sy[a[3]]=dict(address=int(a[0],16),size=int(a[1],16))
            symbols[k]=sy
            git('restore','--source=HEAD','--staged','--worktree','.');assert not git('status','--porcelain')
        save('objects',objects);save('symbols',symbols)
        all_cases=corpus.prepare(r,t,out,run);cases={c['name']:Path(c['path'])for c in all_cases}
        for n in ('libmvec.py','libmvec.json'):shutil.copyfile(r/n,t/n)
        run(['python3','-B',t/'libmvec.py'],'libmvec')
        glib=read(t/'libmvec.json');cases['libmvec']=t/'libmvec.text'
        panels=[('putty-32-0.85',32,1,0x401000),('putty-32-0.85',32,2,0x401000),('libmvec',64,2,glib['address']),('arm64-ls',102,0,0x100000)]
        target=fix/'libcapstone.so.6';target.write_bytes(libs['base'].read_bytes());(fix/'libcapstone.so').symlink_to(target.name)
        src=(r/'time.cpp').read_text()
        assert src.count('uint64_t warm=go()')==1 and src.count('for(int n=0;n<reps;++n)total+=go();')==1
        src='#include <valgrind/callgrind.h>\n'+src.replace('uint64_t warm=go()', 'CALLGRIND_START_INSTRUMENTATION; uint64_t warm=go()').replace('for(int n=0;n<reps;++n)total+=go();','CALLGRIND_ZERO_STATS; for(int n=0;n<reps;++n)total+=go(); CALLGRIND_STOP_INSTRUMENTATION;')
        (t/'app.cpp').write_text(src)
        run(['c++','-O3','-std=c++17','-I',s/'include',t/'app.cpp','-L',fix,'-Wl,-rpath,'+str(fix),'-lcapstone','-o',t/'app'],'driver')
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
        bind=['setarch',platform.machine(),'-R'];sp.run([*bind,'/bin/true'],check=True)
        imgs={k:f.read_bytes()for k,f in libs.items()};imgs['copy']=imgs['base']
        cap=max(map(len,imgs.values()));imgs={k:v+bytes(cap-len(v))for k,v in imgs.items()};inode=target.stat().st_ino
        data=[];cores=[]
        for name,bits,mode,ip in panels:
            cmd=[str(t/'app'),str(bits),str(mode),str(cases[name]),str(ip)]
            def select(k):
                with target.open('r+b') as handle:handle.write(imgs[k])
                assert target.stat().st_ino==inode and target.stat().st_size==cap
            select('base');first=list(map(int,sp.check_output([*bind,*cmd,'1'],text=True).split()));reps=max(1,round(55e6/first[0]))
            times=[];variants=['base','copy','projection','owner']
            for it in range(9):
                order=variants[it%4:]+variants[:it%4];obs={k:[]for k in order}
                for k in order+order[::-1]:
                    select(k);vals=list(map(int,sp.check_output([*bind,*cmd,str(reps)],text=True).split()))
                    assert vals[2]==first[2];obs[k].append(vals[0])
                times.append(obs)
            sig=first[2];data.append(dict(panel=name,mode=mode,source_sha256=sha(cases[name]),reps=reps,signature=sig,cycles=times))
            save('times',data)
            for k in labels:
                select(k);trace=t/'trace';tag=f'{name}-{mode}-{k}'
                vg=[*bind,'valgrind','--tool=callgrind','--instr-atstart=no','--cache-sim=yes','--branch-sim=yes','--callgrind-out-file='+str(trace),*cmd,'1']
                run(vg,'cost-'+tag)
                parsed=parse_cost.parse(trace)
                ok=any(v.strip().split()[-1:]==[str(sig)] and len(v.split())==3 for v in (out/('cost-'+tag+'.log')).read_text().splitlines())
                assert ok and parsed['totals'][0]>1_000_000
                save('cost-'+tag,parsed)
                cores.append(dict(name=name,mode=mode,variant=k,events=parsed['events'],totals=parsed['totals'],trace_sha256=parsed['trace_sha256']))
                trace.unlink()
        save('complete',dict(source=m,compiler=sp.check_output([cc,'--version'],text=True).splitlines()[0],profiles=cores,labels=labels,rows=len(data),shared_images={k:sha(f)for k,f in libs.items()}))
    finally:size=sum(f.stat().st_size for f in t.rglob('*') if f.is_file() and not f.is_symlink())
save('cleanup',dict(removed=not t.exists(),bytes=size))
