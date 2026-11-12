"""Compare whole-library optimization with one physical Windows consumer."""
import struct,hashlib,json,math,os,shutil,statistics,subprocess as sp
from pathlib import Path
import run as tool
from inspect_release import inspect
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
    for name,opts in [('regular','')]:
        (adapter/'Cargo.toml').write_text(cargo+opts)
        dest=w/('cargo-'+name)
        tool.run(['cargo','build','--release','--locked','--target-dir',dest,'--manifest-path',adapter/'Cargo.toml'],'rust-'+name)
        rs[name]=dest/'release/iced_compare.lib'
    cpp={}
    opts=['-A','x64','-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded'+('DLL' if tool.crt=='MD' else '')]
    def apply(name, reverse=False):
        path=s/name
        assert hashlib.sha256(path.read_bytes()).hexdigest()==tool.manifest['source_lineage'][name]['sha256']
        args=['git','-C',c,'apply']+(['-R'] if reverse else [])
        sp.run([*args,'--check',path],check=True);sp.run([*args,path],check=True)
    tool.write('processor.json',json.loads(sp.check_output(['powershell','-NoProfile','-Command','Get-CimInstance Win32_Processor | Select-Object Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors | ConvertTo-Json -Compress'],text=True)))
    decoder='arch/X86/X86DisassemblerDecoder.c'
    variants=[('regular','OFF',''),('regular_new','OFF',decoder),('ipo','ON',decoder if tool.crt=='MT' else ''),('ipo_new','ON',decoder if tool.crt=='MT' else '')]
    for name,on,ordinary in variants:
        if name in ('regular_new','ipo_new'):apply('profiles.patch')
        elif name=='ipo':apply('profiles.patch',reverse=True)
        b=w/('regular-build' if on=='OFF' else 'mixed-build')
        args=['-DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE='+on,'-DCMAKE_C_FLAGS=/MP4','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+k+'_SUPPORT=ON' for k in ('X86','ARM','AARCH64','MIPS')],'-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if tool.crt=='MT' else 'OFF')]
        tool.run(['cmake','-S',c,'-B',b,*opts,*args],'configure-'+name)
        tool.run(['cmake','--build',b,'--config','Release','--parallel','4','--target','capstone_static'],'build-'+name)
        flags={}
        for tlog in (b/'capstone.dir'/'Release').rglob('CL.command.1.tlog'):
            for unit,cmd in zip(*[iter(tlog.read_text(encoding='utf-16',errors='replace').splitlines())]*2):
                units=unit.lstrip('^').split('|')
                for path in units: flags[Path(path).name.lower()]=cmd
        chosen={k:flags[k] for k in ('cs.c','x86disassemblerdecoder.c','x86disassembler.c')}
        def gl(cmd):
            switches=[v for v in cmd.upper().split() if v in ('/GL','/GL-')]
            return bool(switches and switches[-1]=='/GL')
        assert all(gl(v)==(on=='ON' and k!=Path(ordinary).name.lower()) for k,v in chosen.items()),chosen
        tool.write(name+'-compiler.json',chosen)
        assert all(('/'+tool.crt+' ') in (v.upper()+' ') for v in chosen.values());cpp[name]=w/(name+'.lib');shutil.copyfile(b/'Release/capstone.lib',cpp[name])
    d=w/'driver';d.mkdir()
    defs=['cmake_minimum_required(VERSION 3.20)','project(driver CXX)',f'add_library(consumer OBJECT "{(s/"msvc/compare.cpp").as_posix()}")','target_compile_features(consumer PRIVATE cxx_std_17)',f'target_include_directories(consumer PRIVATE "{(c/"include").as_posix()}")']
    for name,on,ordinary in variants:
        defs.extend([f'add_executable({name} $<TARGET_OBJECTS:consumer>)',f'target_link_libraries({name} PRIVATE "{cpp[name].as_posix()}" "{rs["regular"].as_posix()}" advapi32 bcrypt ntdll userenv ws2_32)',f'target_link_options({name} PRIVATE /MAP:{name}.map'+(' /LTCG)' if on=='ON' else ')')])
    (d/'CMakeLists.txt').write_text('\n'.join(defs)+'\n');b=w/'driver-build'
    tool.run(['cmake','-S',d,'-B',b,*opts],'driver-config');tool.run(['cmake','--build',b,'--config','Release','--parallel','2'],'driver-build')
    obj,=b.rglob('compare.obj');tool.write('products.json',dict(consumer=tool.digest(obj.read_bytes()),libraries={n:tool.digest(f.read_bytes()) for n,f in cpp.items()}))
    labels=[*cpp,'iced']
    programs={name:b/'Release'/(name+'.exe') for name in cpp}
    assembly={}
    for name,exe in programs.items():
        linker_map,=b.rglob(name+'.map')
        assembly[name]=inspect(exe,linker_map,tool.evidence);tool.write('linked-functions.json',assembly)
    def code_digest(exe):
        data=exe.read_bytes();pe=struct.unpack_from('<I',data,60)[0]
        count=struct.unpack_from('<H',data,pe+6)[0];offs=pe+24+struct.unpack_from('<H',data,pe+20)[0]
        for i in range(count):
            off=offs+40*i
            if data[off:off+8].rstrip(b'\x00')==b'.text':
                size,raw=struct.unpack_from('<II',data,off+16)
                return hashlib.sha256(data[raw:raw+size]).hexdigest()
        raise RuntimeError('missing PE code section')
    tool.write('code-sections.json',{k:code_digest(v)for k,v in programs.items()})
    results=[]
    for case in tool.get_cases():
        for mode in ('scan','format','detail'):
            def sample(k,n):
                label='iced' if k.startswith('iced') else 'capstone'
                return json.loads(sp.check_output([programs['regular' if k=='iced' else k],label,mode,str(case['bits']),str(n),case['path']]))
            n=1
            while (probe:=sample('regular',n))['wall_ns']<10000000:n*=3
            n=max(1,math.ceil(n*55000000/probe['wall_ns']))
            cycles=[]
            for i in range(8):
                position=i%len(labels);order=labels[position:]+labels[:position]
                if i%2:order.reverse()
                raw=[(k,sample(k,n)) for k in order+order[::-1]]
                assert len({tuple(t[key] for key in ('instructions','rejected','boundary_hash','value_hash')) for k,t in raw if k!='iced'})==1
                matched=len({tuple(t[key] for key in ('instructions','rejected','boundary_hash')) for _,t in raw})==1
                times={k:[t['thread_cycles'] for lab,t in raw if lab==k] for k in labels}
                avg={k:statistics.mean(v) for k,v in times.items()}
                cycles.append(dict(raw=raw,matched=matched,relative={k:avg['regular']/avg[k] for k in labels},aa={k:a[0]/a[1] for k,a in times.items()}))
            results.append(dict(case=case['name'],mode=mode,cycles=cycles))
            tool.write('measurements.json',results)
    tool.write('complete.json',dict(complete=True))
try:main()
finally:
    size=sum(a.stat().st_size for a in w.rglob('*') if a.is_file())
    def writable(func,path,exc):os.chmod(path,0o700);func(path)
    shutil.rmtree(w,onerror=writable);tool.write('cleanup.json',dict(bytes=size,removed=not w.exists()))
