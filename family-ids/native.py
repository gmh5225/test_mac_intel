from pathlib import Path
import hashlib,json,os,random,shutil,subprocess as sp,tempfile
from compose import compose
d = Path(__file__).resolve().parent
s = d.parent/'source'
out = d.parent/'evidence'
out.mkdir(exist_ok=True)
def read(p):return json.loads(p.read_text())
def save(name,data):(out/(name+'.json')).write_text(json.dumps(data,indent=2)+'\n')
def cmd(name,argv):
    with (out/(name+'.log')).open('wb') as log:
        status=sp.run(argv,stdout=log,stderr=sp.STDOUT)
    if status.returncode:
        print((out/(name+'.log')).read_text(errors='replace')[-3500:],flush=True)
        status.check_returncode()
def git(*args):return sp.check_output(['git','-C',s,*args],text=True).strip()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def stream(argv,name):
    digest=hashlib.sha256();n=0
    with (out/(name+'.log')).open('wb')as log,sp.Popen(argv,stdout=sp.PIPE,stderr=log)as p:
        for chunk in iter(lambda:p.stdout.read(1<<20),b''):
            digest.update(chunk);n+=len(chunk)
        assert p.wait()==0
    assert n>400_000_000
    return dict(bytes=n,sha256=digest.hexdigest())
m=read(d/'revisions.json');parent=git('rev-parse','HEAD');assert m['fixed']['parent']==parent
t=Path(tempfile.mkdtemp());b=t/'build'
try:
    configure=['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers']
    cmd('configure',configure+['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('X86','ARM','AARCH64','MIPS','RISCV','PPC')])
    source=s/'arch/X86/X86Mapping.c';base=source.read_text();counts=(source.parent/'X86GenMappingCounts.inc').read_text()
    refs={}
    mapper_opts=['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-I',s,'-I',s/'include']
    def build_static(name,src):
        cmd('static-'+name,['cmake','--build',b,'--target','capstone_static','--parallel','4'])
        cmd('oracle-link-'+name,[*mapper_opts,src,b/'libcapstone.a','-lm','-o',t/'mapper'])
    for name in ('base','fixed'):
        if name=='fixed':
            assert sha(d/'fixed.patch')==m['fixed']['sha256']
            git('apply','--index',str(d/'fixed.patch'));assert git('write-tree')==m['fixed']['tree']
        build_static(name,d/'mapper.c')
        refs[name]=stream([t/'mapper'],'reference-'+name)
    assert refs['base']['bytes']==refs['fixed']['bytes'] and refs['base']!=refs['fixed']
    both=compose(source.read_text(),base,counts);source.write_text(both)
    new=(d/'mapper.c').read_text().replace('int main(void) {','void cs_bench_select_mapping(unsigned);\nint main(int argc,char **argv) {\n    if(argc!=2)return 2;\n    cs_bench_select_mapping(argv[1][0]-\'0\');')
    (t/'selected.c').write_text(new);build_static('same',t/'selected.c')
    tested={k:stream([t/'mapper',str(i)],'selected-'+k) for i,k in enumerate(('base','fixed'))}
    assert refs==tested
    save('records',dict(reference=refs,selected=tested))
    cmd('shared',['cmake','--build',b,'--target','capstone_shared','--parallel','4'])
    so,=[v for v in b.glob('libcapstone.so.*') if not v.is_symlink()]
    slot=t/'slot';slot.mkdir();lib=slot/so.name;shutil.copy2(so,lib)
    for p in b.glob('libcapstone.so*'):
        if p.is_symlink():(slot/p.name).symlink_to(os.readlink(p))
    main=(d/'time.cpp').read_text().replace('int main(int argc','extern "C" void cs_bench_select_mapping(unsigned);\nextern "C" unsigned long long cs_bench_mapping_calls();\nint main(int argc').replace('if(argc!=6)return 2;', "if(argc!=7)return 2;\n cs_bench_select_mapping(argv[6][0]-'0');").replace('cs_free(i,1);','std::printf("%llu\\n",cs_bench_mapping_calls());\n cs_free(i,1);')
    assert 'cs_bench_select_mapping(argv' in main
    (t/'time.cpp').write_text(main)
    cmd('time',['c++','-std=c++17','-O3','-I',s/'include',t/'time.cpp','-L',slot,'-Wl,-rpath,'+str(slot),'-lcapstone','-o',t/'time'])
    timed_hash=sha(lib);exe_hash=sha(t/'time')
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    save('host',dict(cpu=sp.check_output(['lscpu'],text=True),cc=sp.check_output(['clang','--version'],text=True),library=timed_hash,executable=exe_hash,source=m))
    shutil.copy2(d/'fetch.py',t/'fetch.py');cmd('pe',['python3','-B',t/'fetch.py'])
    import corpus
    extra=corpus.prepare(d,t,out,lambda argv,name:cmd(name,argv))
    panels=[('putty32',32,t/'putty-0.85-32.text',0x401000,(0,1,2,3)),('putty64',64,t/'putty-0.85-64.text',0x140001000,(1,2))]
    for item in extra:
        name=item['name']
        if name in ('riscv64-sort','mips64el-ls'):
            panels.append((name,105 if name=='riscv64-sort' else 103,Path(item['path']),0x100000,(0,1,2)))
    assert len(panels)==4
    def invoke(sel,bits,mode,path,ip,n):
        return list(map(int,sp.check_output(['setarch','x86_64','-R',t/'time',str(bits),str(mode),path,str(ip),str(n),str(sel)]).split()))
    rng=random.Random(2204);rows=[]
    for name,bits,path,ip,modes in panels:
        for mode in modes:
            one=invoke(0,bits,mode,path,ip,1);assert len(one)==4 and one[3]==0
            n=max(1,round(60e6/one[0]));cycles=[]
            for i in range(19):
                order=['base','copy','fixed'];rng.shuffle(order);pair={k:[] for k in order}
                for k in order+order[::-1]:
                    v=invoke(int(k=='fixed'),bits,mode,path,ip,n)
                    delta=read(d/'reference.json')['pe32-score'] if k=='fixed' and (name,mode)==('putty32',3) else 0
                    assert v[2]==one[2]-delta and v[3]==0,(name,mode,k,v,one)
                    pair[k].append(v[:2])
                cycles.append(pair)
            rows.append(dict(case=name,mode=mode,reps=n,cycles=cycles,checksum=one[2],input_sha=sha(path)))
    assert sha(lib)==timed_hash and sha(t/'time')==exe_hash
    save('timings',rows)
    mark='    selected_mapper(h, insn, id);';assert both.count(mark)==1
    source.write_text(both.replace(mark,'    ++mapping_calls;\n'+mark))
    cmd('counted',['cmake','--build',b,'--target','capstone_shared','--parallel','4'])
    shutil.copyfile(so,lib);assert sha(lib)!=timed_hash
    for name,bits,path,ip,modes in panels:
        for mode in modes:
            row=next(v for v in rows if (v['case'],v['mode'])==(name,mode))
            v=[invoke(i,bits,mode,path,ip,1) for i in (0,1)]
            assert v[0][3]==v[1][3] and v[0][3]%2==0 and v[0][2]==row['checksum']
            assert v[1][2]==v[0][2]-(read(d/'reference.json')['pe32-score'] if (name,mode)==('putty32',3) else 0)
            if bits>100:assert v[0][3]==0
            row['mapping_calls_per_pass']=v[0][3]//2
    assert len(rows)==12
    save('timings',rows);save('complete',dict(panels=len(rows),counted_library=sha(lib),timed_library=timed_hash,exe=exe_hash,records=refs))
finally:
    removed=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=removed))
