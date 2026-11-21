from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
import corpus
r=Path(__file__).resolve().parent;root=r.parent;s=root/'source';out=root/'evidence';out.mkdir(exist_ok=True)
def save(n,x):(out/(n+'.json')).write_text(json.dumps(x,indent=2)+'\n')
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def run(a,n):
    with (out/(n+'.log')).open('w') as stream:sp.run(a,stdout=stream,stderr=sp.STDOUT,check=True)
def git(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
meta=json.loads((r/'lineage.json').read_text());cc=os.environ['CC'];assert git('rev-parse','HEAD')==meta['base']['commit']
t=Path(tempfile.mkdtemp())
try:
    b=t/'build';labels=['base','batch','worker','leaf']
    opts=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SCAN_ADAPTER=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers')]
    opts.extend('-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('X86','ARM','AARCH64','MIPS','PPC','RISCV'))
    run(['cmake','-S',s,'-B',b,*opts],'configure')
    flags=['-O3','-DNDEBUG','-DCAPSTONE_X86_SCAN_ADAPTER','-I',s,'-I',s/'include'];exe={};objs={};sym={}
    for source in ('batch','dump','time'):
        run(['c++','-std=c++17',*flags,'-c',r/(source+'.cpp'),'-o',t/(source+'.o')],'compile-'+source)
    for label in labels:
        git('restore','--source=HEAD','--staged','--worktree','.')
        if label!='base':
            patch=r/(label+'.patch');assert sha(patch)==meta[label]['sha256']
            git('apply','--index',str(patch))
        assert git('write-tree')==meta[label]['tree']
        run(['cmake','--build',b,'--parallel','4','--target','capstone_static','x86_scan_batch','x86_scan_adapter'],'build-'+label)
        run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_x86_scan_(batch|adapter)$'],'units-'+label)
        library=b/'libcapstone.a'
        for source in ('batch','dump','time'):
            dest=t/(source+'-'+label)
            run(['c++',t/(source+'.o'),library,'-lm','-o',dest],'link-'+source+'-'+label);exe[source,label]=dest
        run([cc,'-std=c11',*flags,r/'adapter.c',library,'-lm','-o',t/'adapter'],'link-adapter-'+label);run([t/'adapter'],'mode-switch-'+label)
        objs[label]={str(v.relative_to(b)):sha(v) for v in b.rglob('*.o')if 'CMakeFiles/capstone.dir' in str(v)};assert len(objs[label])>45
        if label!='base':assert [Path(k).name for k in objs[label]if objs[label][k]!=objs['base'][k]]==['X86DisassemblerDecoder.c.o']
        sym[label]=[line.strip() for line in sp.check_output(['nm','-Sn',exe['batch',label]],text=True).splitlines() if any(x in line for x in (' X86_scanBatch',' scanBatch32',' scanBatchOtherModes',' cs_disasm_iter'))]
        run(['objdump','-d','--disassemble=X86_scanBatch',exe['batch',label]],'disassembly-'+label)
    save('objects',objs);save('symbols',sym);cases=corpus.prepare(r,t,out,lambda a,n,cwd=None:run(a,n))
    samples={x['name']:x for x in cases}
    wanted={'putty-32-0.85':(32,0x401000),'putty-64-0.85':(64,0x140001000),'libssl3t64-i386':(32,0x100000),'libjpeg62-turbo-i386':(32,0x100000)}
    shutil.copy(r/'libmvec.py',t);shutil.copy(r/'libmvec.json',t)
    run(['python3','-B',t/'libmvec.py'],'libmvec');libm=json.loads((t/'libmvec.json').read_text())
    wanted['libmvec']=(64,libm['address']);samples['libmvec']=dict(path=str(t/'libmvec.text'))
    traces={}
    for name,(bits,ip) in wanted.items():
        for cap in (0,1,7,64,128):
            for label in labels:
                trace=t/'seq'
                val=list(map(int,sp.check_output([exe['dump',label],str(bits),str(cap),samples[name]['path'],str(ip),'-','1'],env={**os.environ,'RECORD_FILE':str(trace)},text=True).split()))
                obs=dict(count=trace.stat().st_size//4,sha256=sha(trace),signature=val[2:]);trace.unlink()
                traces.setdefault(name,obs);assert traces[name]==obs
    save('trace',traces)
    cases=[('batch',name,cap,[bits,cap,samples[name]['path'],ip,'-']) for name,(bits,ip) in wanted.items() for cap in (0,1,64)]
    for name,bits in [('arm-cp',101),('arm64-ls',102),('mips64el-ls',103),('ppc64el-ls',104),('riscv64-ls',105)]:
        for mode in range(3):cases.append(('time',name,mode,[bits,mode,samples[name]['path'],0x100000]))
    bind=['setarch',platform.machine(),'-R'];sp.run([*bind,'/bin/true'],check=True)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    blobs={k:v.read_bytes() for k,v in exe.items()if k[0]!='dump'};timings=[]
    for tool in ('time','batch'):
        blobs[tool,'copy']=blobs[tool,'base'];maximum=max(len(v)for (n,k),v in blobs.items() if n==tool)
        for k in [*labels,'copy']:blobs[tool,k]=blobs[tool,k].ljust(maximum,b'\0')
    fixed=t/'runner';fixed.touch(mode=0o755);inode=fixed.stat().st_ino
    def call(tool,label,args,reps):
        fixed.write_bytes(blobs[tool,label]);assert fixed.stat().st_ino==inode
        return list(map(int,sp.check_output([*bind,fixed,*map(str,args),str(reps)],text=True).split()))
    ordered=['base','copy','batch','worker','leaf']
    for tool,name,mode,args in cases:
        v=call(tool,'base',args,1);n=max(1,round(32e6/v[0]));sig=v[2:];cycles=[]
        for i in range(7):
            j=i%len(ordered);plan=ordered[j:]+ordered[:j];record={k:[]for k in plan}
            for label in plan+plan[::-1]:
                value=call(tool,label,args,n);assert value[2:]==sig
                record[label].append(value[:2])
            cycles.append(record)
        timings.append(dict(tool=tool,case=name,mode=mode,signature=sig,cycles=cycles));save('timings',timings)
    save('complete',dict(rows=len(timings),source=meta,compiler=sp.check_output([cc,'--version'],text=True).splitlines()[0],source_traces=len(traces),fixed_inode=True))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=n))
