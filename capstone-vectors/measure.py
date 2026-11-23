from pathlib import Path
from itertools import product
import hashlib,json,math,os,platform,random,shutil,subprocess as sp,tempfile
import corpus
from placement import layout,script
d=Path(__file__).resolve().parent;s=d.parent/'source';nd=d.parent/'neverd-config';out=d.parent/'evidence';out.mkdir(exist_ok=True);m=json.loads((d/'alias-inputs.json').read_text())
def save(k,z):(out/(k+'.json')).write_text(json.dumps(z,indent=2)+'\n')
def go(k,cmd):
    with (out/(k+'.log')).open('w')as f:p=sp.run(cmd,stdout=f,stderr=sp.STDOUT)
    if p.returncode:print((out/(k+'.log')).read_text()[-1600:],flush=True);p.check_returncode()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def git(p,*args):return sp.check_output(['git','-C',p,*args],text=True).strip()
assert git(s,'rev-parse','HEAD')==m['capstone'] and git(nd,'rev-parse','HEAD')==m['neverd']
t=Path(tempfile.mkdtemp())
try:
    project=t/'project';(project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(s,target_is_directory=True);(project/'cmake').mkdir()
    flow=(nd/'CMakeLists.txt').read_text();i=flow.index('# --- Capstone (our fork');j=flow.index('# --- NeverD CMake helpers',i);shutil.copy2(nd/'cmake/NeverDCapstoneCompilerOptions.inc',project/'cmake')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Profile LANGUAGES C CXX)\n'+flow[i:j])
    build=t/'b';go('configure',['cmake','-S',project,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++','-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers'])
    go('build',['cmake','--build',build,'--target','capstone_static','--parallel','4'])
    lib,=build.rglob('libcapstone.a');assert len(sp.check_output(['ar','t',lib],text=True).splitlines())==49
    go('driver',['clang++','-O3','-std=c++17','-I',s/'include','-c',d/'time.cpp','-o',t/'time.o'])
    exe=t/'current';ld=t/'offsets.ld';bins={};layouts={};base_symbols=None
    for c,b in product(range(2),repeat=2):
        k=f'c{c}d{b}';ld.write_text(script(m['sections'],c,b));go('link-'+k,['clang++',t/'time.o',lib,'-Wl,-T,'+str(ld),'-lm','-o',exe])
        sec,syms=layout(exe);assert len(syms)==7
        if base_symbols is None:base_symbols=syms;all_positions={n:v[:2]for n,v in sec.items()}
        assert {n:v[:2]for n,v in sec.items() if n not in ('.strtab','.symtab','.shstrtab')}=={n:v for n,v in all_positions.items() if n not in ('.strtab','.symtab','.shstrtab')}
        for n,(va,nb) in syms.items():
            shift=m['sections']['.cs_alias_pattern_lookup'][2]*c if n.startswith('match')else m['sections']['.cs_alias_pattern_rows'][2]*b if n.endswith('_blocks')else 0
            assert (va,nb)==(base_symbols[n][0]+shift,base_symbols[n][1]),(k,n,va,nb,base_symbols[n],shift)
        payload=exe.read_bytes();views={}
        for n,(start,size,delta) in m['sections'].items():
            va,length,offset=sec[n];active=(c if n.endswith('lookup')else b)*delta
            assert va%4096==start%4096 and length==size+delta,(k,n,va,length,start,size,delta)
            views[n]=[va+active,size,hashlib.sha256(payload[offset+active:offset+active+size]).hexdigest()]
        layouts[k]=dict(symbols=syms,windows=views);bins[k]=payload
    assert len({z['windows']['.cs_alias_pattern_rows'][2]for z in layouts.values()})==1
    save('layouts',layouts);save('host',dict(cpu=sp.check_output(['lscpu'],text=True),compiler=sp.check_output(['clang','--version'],text=True)))
    bins['copy']=bins['c0d0'];os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});rows=[]
    for sm in m['samples']:
        pkg=t/'archive.deb';go('download-'+sm['name'],['curl','-fsSL','--retry','3',sm['url'],'-o',pkg]);assert sha(pkg)==sm['package_sha256'];data=corpus.deb_binary(pkg,sm['command']);text=t/'sample.text';text.write_bytes(corpus.elf_text(data));assert sha(text)==sm['text_sha256'];pkg.unlink()
        for mode in range(3):
            def call(key,reps):
                exe.write_bytes(bins[key]);return list(map(int,sp.check_output(['setarch',platform.machine(),'-R',exe,'102' if sm['selector']==0 else '103',str(mode),text,'1048576',str(reps)]).split()))
            reps=max(1,math.ceil(90e6/call('c0d0',1)[0]));rows0=[];order=random.Random(str((sm['name'],mode,'alias-address-controls')))
            for _ in range(21):
                keys=list(bins);order.shuffle(keys);obs=[(key,call(key,reps))for key in keys+keys[::-1]]
                assert len({v[2]for _,v in obs})==1
                rows0.append(obs)
            rows.append(dict(case=sm['name'],mode=mode,reps=reps,sha256=sha(text),observations=rows0));save('timings',rows)
    save('complete',dict(source=m,panels=len(rows)))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(bytes=size,removed=not t.exists()))
