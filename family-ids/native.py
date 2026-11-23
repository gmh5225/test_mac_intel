from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;s=r.parent/'source';out=r.parent/'evidence';out.mkdir(exist_ok=True);t=Path(tempfile.mkdtemp())
meta=json.loads((r/'metadata.json').read_text())
def save(name,v):(out/(name+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def cmd(*args,**kw):return sp.check_output(args,text=True,**kw)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def once(s,a,b):
    assert s.count(a)==1,a
    return s.replace(a,b)
try:
    assert cmd('git','-C',s,'rev-parse','HEAD').strip()==meta['checkout']
    assert sha(s/'arch/X86/X86Mapping.c')==meta['owner'] and sha(r/'instrumentation.patch')==meta['patch']
    cmd('git','-C',s,'apply','--check',r/'instrumentation.patch');cmd('git','-C',s,'apply',r/'instrumentation.patch')
    project=t/'project';(project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(s,target_is_directory=True);(project/'cmake').mkdir()
    for f in ('CMakeLists.txt','cmake/NeverDCapstoneCompilerOptions.inc'):
        shutil.copy2(r/Path(f).name,project/f)
    cmd('cmake','-S',project,'-B',t/'build','-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++')
    cmd('cmake','--build',t/'build','--target','capstone_static','--parallel','4')
    lib,=(t/'build').rglob('libcapstone.a');args=['clang++','-O3','-std=c++17','-I',s,'-I',s/'include']
    cmd(*args,r/'time.cpp',lib,'-o',t/'time')
    prof=(r/'time.cpp').read_text();prof='#include <valgrind/callgrind.h>\n'+once(prof,'if(argc!=6)','if(argc!=7)')
    a=prof.index('    uint64_t a=now(')
    prof=prof[:a]+'''    bench_select_prefix(std::atoi(argv[6]));
    const auto expected=go(h,insn,bytes,addr,mode);
    CALLGRIND_ZERO_STATS; CALLGRIND_TOGGLE_COLLECT;
    const auto measured=go(h,insn,bytes,addr,mode);
    CALLGRIND_TOGGLE_COLLECT;
    if(measured!=expected)return 7;
    std::printf("%llu\\n",(unsigned long long)measured);
    cs_free(insn,1);cs_close(&h);
}
'''
    (t/'profile.cpp').write_text(prof);cmd(*args,t/'profile.cpp',lib,'-o',t/'profile')
    for f in ('fetch.py','libmvec.py','libmvec.json'):shutil.copy2(r/f,t/f)
    for f in ('fetch.py','libmvec.py'):cmd('python3','-B',t/f)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});images={f:sha(t/f)for f in ('time','profile')}
    rows={};events={};counts={};stats_path=t/'callgrind.out'
    for name,info in meta['inputs'].items():
        bits=info['bits'];f=t/('libmvec.text'if 'libmvec' in name else 'putty-0.85-'+str(bits)+'.text')
        assert sha(f)==info['sha256']
        for mode in (0,1,2):
            for private in (0,1):
                label=f'{name}/{mode}/{private}';work=[f,str(bits),str(mode),str(private),str(info['address'])]
                rows[label]=json.loads(cmd('setarch','x86_64','-R',t/'time',*work));save('timings',rows)
                if name=='putty64' or mode!=1:continue
                counts[label]={}
                for merged in (0,1):
                    checks=cmd('setarch','x86_64','-R','valgrind','--tool=callgrind','--collect-atstart=no','--branch-sim=yes','--callgrind-out-file='+str(stats_path),t/'profile',*work,str(merged)).strip()
                    assert int(checks)==rows[label]['sum']
                    lines=stats_path.read_text().splitlines();names=next(x.split()[1:]for x in lines if x.startswith('events:'));tot=next(x.split()[1:]for x in lines if x.startswith('totals:'));counts[label][merged]=dict(zip(names,map(int,tot)))
                    assert counts[label][merged]['Ir']>1000 and counts[label][merged]['Bc']>100;stats_path.unlink()
                save('events',counts)
    save('complete',dict(metadata=meta,images=images,platform=platform.platform(),cpu=cmd('lscpu'),compiler=cmd('clang','--version'),panels=len(rows)))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=size))
