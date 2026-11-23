from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;s=r.parent/'source';out=r.parent/'evidence';out.mkdir(exist_ok=True);t=Path(tempfile.mkdtemp());m=json.loads((r/'metadata.json').read_text())
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def cmd(*a):return sp.check_output(a,text=True)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
try:
    assert cmd('git','-C',s,'rev-parse','HEAD').strip()==m['checkout'] and sha(r/'status.patch')==m['source']['sha256']
    cmd('git','-C',s,'apply','--index',r/'status.patch');assert cmd('git','-C',s,'write-tree').strip()==m['source']['tree']
    for bits,file in ((32,'X86Vex32Output.c'),(64,'X86Sse64Output.c')):
        f=s/'arch/X86'/file;addition=r/('count'+str(bits)+'.inc');assert sha(addition)==m['extra']['family-ids/'+addition.name]
        src=f.read_text();i=src.rindex('\n#endif');f.write_text(src[:i]+'\n'+addition.read_text()+'\n'+src[i:])
    project=t/'project';(project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(s,target_is_directory=True);(project/'cmake').mkdir()
    for f in ('CMakeLists.txt','cmake/NeverDCapstoneCompilerOptions.inc'):shutil.copy2(r/Path(f).name,project/f)
    cmd('cmake','-S',project,'-B',t/'build','-G','Ninja','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++')
    cmd('cmake','--build',t/'build','--target','capstone_static','--parallel','4');lib,=(t/'build').rglob('libcapstone.a')
    cmd('clang++','-O3','-std=c++17','-I',s,'-I',s/'include',r/'at-address.cpp',lib,'-o',t/'time');darwin=platform.system()=='Darwin'
    syms=cmd('nm','-n',t/'time').splitlines()
    methods=['X86_disasmIterText','X86_disasmOneText','X86_decodeOneText'];positions={}
    for name in methods:
        row,=[l.split() for l in syms if len(l.split())==3 and l.split()[1]in('t','T') and l.split()[2]==('_' if darwin else '')+name];positions[name]=int(row[0],16)
    for f in ('fetch.py','libmvec.py','libmvec.json'):shutil.copy2(r/f,t/f)
    for f in ('fetch.py','libmvec.py'):cmd('python3','-B',t/f)
    if not darwin:os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    launch=[] if darwin else ['setarch','x86_64','-R'];panels={}
    for name,info in m['inputs'].items():
        bits=info['bits'];f=t/('libmvec.text' if 'libmvec' in name else 'putty-0.85-'+str(bits)+'.text')
        assert sha(f)==info['sha256']
        for mode in (1,2):
            lab=f'{name}/{mode}';panels[lab]=json.loads(cmd(*launch,t/'time',f,str(bits),str(mode),str(info['address'])));save('timings',panels)
    save('complete',dict(source=m,compiler=cmd('clang','--version'),cpu=cmd('sysctl','-n','machdep.cpu.brand_string')if darwin else cmd('lscpu'),panels=len(panels),image=sha(t/'time'),methods=positions))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=size))
