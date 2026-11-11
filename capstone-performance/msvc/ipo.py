"""Compare whole-library optimization with one physical Windows consumer."""
import json,math,os,shutil,statistics,subprocess as sp
from pathlib import Path
import run as tool
s,w=tool.source,tool.work
def main():
    c=tool.fetch('base','capstone',tool.manifest['capstone_revision'])
    tool.fetch('iced','iced',tool.manifest['iced_revision'])
    tool.write('sources.json',{k:tool.manifest[k] for k in ('capstone_revision','iced_revision')})
    adapter=w/'adapter';adapter.mkdir()
    for f in ('Cargo.lock','iced.rs'):shutil.copy2(s/f,adapter/f)
    cargo='''[package]
name="iced_compare"
version="0.1.0"
edition="2021"
[lib]
crate-type=["staticlib"]
path="iced.rs"
[dependencies]
iced-x86={path="../iced/src/rust/iced-x86",default-features=false,features=["std","decoder","intel","instr_info"]}
[profile.release]
panic="abort"
opt-level=3
'''
    rs={}
    for name,opts in [('regular',''),('ipo','lto="fat"\ncodegen-units=1\n')]:
        (adapter/'Cargo.toml').write_text(cargo+opts)
        dest=w/('cargo-'+name)
        tool.run(['cargo','build','--release','--locked','--target-dir',dest,'--manifest-path',adapter/'Cargo.toml'],'rust-'+name)
        rs[name]=dest/'release/iced_compare.lib'
    cpp={}
    opts=['-G','Visual Studio 17 2022','-A','x64','-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL']
    for name,on in [('regular','OFF'),('ipo','ON')]:
        b=w/('capstone-'+name)
        tool.run(['cmake','-S',c,'-B',b,*opts,'-DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE='+on,'-DCMAKE_C_FLAGS=/MP4','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+k+'_SUPPORT=ON' for k in ('X86','ARM','AARCH64','MIPS')],'-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=OFF'],'configure-'+name)
        tool.run(['cmake','--build',b,'--config','Release','--parallel','4','--target','capstone_static'],'build-'+name)
        flags=[q.read_text(encoding='utf-16',errors='replace') for q in b.rglob('CL.command.1.tlog') if q.parent.name.lower().startswith('capstone.')]
        assert flags and any('/GL ' in t.upper() or '/GL\n' in t.upper() for t in flags)==(on=='ON')
        tool.write(name+'-compiler.json',[t.splitlines()[1][:5000] for t in flags])
        cpp[name]=b/'Release/capstone.lib'
    d=w/'driver';d.mkdir()
    defs=['cmake_minimum_required(VERSION 3.20)','project(driver CXX)',f'add_library(consumer OBJECT "{(s/"msvc/compare.cpp").as_posix()}")','target_compile_features(consumer PRIVATE cxx_std_17)',f'target_include_directories(consumer PRIVATE "{(c/"include").as_posix()}")']
    for name,cl,rust in [('base','regular','regular'),('optimized','ipo','regular'),('rustopt','regular','ipo')]:
        defs+=[f'add_executable({name} $<TARGET_OBJECTS:consumer>)',f'target_link_libraries({name} PRIVATE "{cpp[cl].as_posix()}" "{rs[rust].as_posix()}" advapi32 bcrypt ntdll userenv ws2_32)']
        if cl=='ipo':defs.append('target_link_options(optimized PRIVATE /LTCG)')
    (d/'CMakeLists.txt').write_text('\n'.join(defs)+'\n');b=w/'driver-build'
    tool.run(['cmake','-S',d,'-B',b,*opts],'driver-config');tool.run(['cmake','--build',b,'--config','Release','--parallel','3'],'driver-build')
    obj,=b.rglob('compare.obj');tool.write('products.json',dict(consumer=tool.digest(obj.read_bytes()),libraries={n:{k:tool.digest(f.read_bytes()) for k,f in a.items()} for n,a in [('capstone',cpp),('iced',rs)]}))
    labels=['base','optimized','iced','iced_opt'];exes=['base','optimized','base','rustopt'];programs={k:b/'Release'/(v+'.exe') for k,v in zip(labels,exes)}
    results=[]
    for case in tool.get_cases():
        for mode in ('scan','format','detail'):
            def sample(k,n):
                label='iced' if k.startswith('iced') else 'capstone'
                return json.loads(sp.check_output([programs[k],label,mode,str(case['bits']),str(n),case['path']]))
            n=1
            while (probe:=sample('base',n))['wall_ns']<10000000:n*=3
            n=max(1,math.ceil(n*120000000/probe['wall_ns']))
            cycles=[]
            for i in range(6):
                order=labels[i%4:]+labels[:i%4]
                if i%2:order.reverse()
                raw=[(k,sample(k,n)) for k in order+order[::-1]]
                def signature(row,values):
                    return tuple(row[key] for key in (('instructions','rejected','boundary_hash','value_hash') if values else ('instructions','rejected','boundary_hash')))
                for group in (labels[:2],labels[2:]):
                    assert len({signature(t,True) for k,t in raw if k in group})==1
                same=len({signature(t,False) for k,t in raw})==1
                times={k:[t['thread_cycles'] for lab,t in raw if lab==k] for k in labels}
                avg={k:statistics.mean(v) for k,v in times.items()}
                cycles.append(dict(raw=raw,same_boundaries=same,capstone=avg['base']/avg['optimized'],iced=avg['iced']/avg['iced_opt'],relative=avg['iced_opt']/avg['optimized'] if same else None,aa={k:a[0]/a[1] for k,a in times.items()}))
            results.append(dict(case=case['name'],mode=mode,cycles=cycles))
            tool.write('measurements.json',results)
    tool.write('complete.json',dict(complete=True))
try:main()
finally:
    size=sum(a.stat().st_size for a in w.rglob('*') if a.is_file())
    def writable(func,path,exc):os.chmod(path,0o700);func(path)
    shutil.rmtree(w,onerror=writable);tool.write('cleanup.json',dict(bytes=size,removed=not w.exists()))
