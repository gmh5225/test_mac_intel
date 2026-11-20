"""Build the published decoder-comparison target with the same four static libraries."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import struct
import subprocess as sp
import tempfile
import sys

root=Path(__file__).resolve().parent
out=root.parent/'evidence'
out.mkdir(exist_ok=True)
spec=json.loads((root/'inputs.json').read_text())
def run(name,args,cwd,expect=0):
    print(name,flush=True)
    with (out/(name+'.log')).open('w',encoding='utf-8') as stream:
        status=sp.run([str(x) for x in args],cwd=cwd,stdout=stream,stderr=sp.STDOUT).returncode
    if (status==0)!=(expect==0):
        raise RuntimeError(name+'\n'+(out/(name+'.log')).read_text(errors='replace')[-3500:])
    return (out/(name+'.log')).read_text(errors='replace')
def lib(build,name):
    result=list(build.rglob(name+'.lib'))
    assert len(result)==1,(build,name,result)
    return result[0]
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def write(name,data):
    (out/(name+'.json')).write_text(json.dumps(data,indent=2)+'\n')
def pe_text(path):
    image=path.read_bytes()
    header=struct.unpack_from('<I',image,60)[0]
    assert image[header:header+4]==b'PE\0\0'
    num=struct.unpack_from('<H',image,header+6)[0]
    opt=struct.unpack_from('<H',image,header+20)[0]
    for i in range(num):
        o=header+24+opt+40*i
        if image[o:o+8].rstrip(b'\0')==b'.text':
            size,start=struct.unpack_from('<II',image,o+16)
            return image[start:start+min(size,65536)]
    raise RuntimeError('no code section')
workspace=tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP'])
with workspace as tmp:
    t=Path(tmp)
    try:
        for key,item in spec['sources'].items():
            path=t/key
            run('init-'+key,['git','init','-q',path],t)
            run('get-'+key,['git','fetch','--depth','1','https://github.com/'+item['repo']+'.git',item['rev']],path)
            run('use-'+key,['git','checkout','--detach','FETCH_HEAD'],path)
            assert sp.check_output(['git','rev-parse','HEAD'],cwd=path,text=True).strip()==item['rev']
        fallback=t/'zydis/dependencies/zycore'
        if fallback.is_dir():
            assert not list(fallback.iterdir());fallback.rmdir()
        (t/'zycore').rename(fallback)
        src=root.parent/'neverd/tools/neverd-bench/decoder-comparison'
        assert hashlib.sha256((src/'CMakeLists.txt').read_text().encode()).hexdigest()==spec['original_cmake']
        adapter=t/'adapter';adapter.mkdir()
        shutil.copyfile(src/'iced.rs',adapter/'iced.rs')
        shutil.copyfile(root/'Cargo.lock',adapter/'Cargo.lock')
        (adapter/'Cargo.toml').write_text('[package]\nname="iced_compare"\nversion="0.1.0"\nedition="2021"\n[lib]\ncrate-type=["staticlib"]\npath="iced.rs"\n[dependencies]\niced-x86={path="../iced/src/rust/iced-x86",default-features=false,features=["std","decoder","intel","instr_info"]}\n[profile.release]\nopt-level=3\npanic="abort"\n')
        run('rust',['cargo','build','--locked','--release'],adapter)
        flags=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL']
        builds={}
        for key,args in [('capstone',['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']),('zydis',['-DZYDIS_BUILD_TOOLS=OFF','-DZYDIS_BUILD_EXAMPLES=OFF','-DZYDIS_BUILD_DOXYGEN=OFF','-DZYDIS_BUILD_TESTS=OFF','-DZYDIS_BUILD_SHARED_LIB=OFF'])]:
            b=t/(key+'-build');builds[key]=b
            run('configure-'+key,['cmake','-S',t/key,'-B',b,*flags,*args],t)
            run('build-'+key,['cmake','--build',b,'--parallel','3','--target','capstone_static' if key=='capstone' else 'Zydis'],t)
        kit=t/'xed-kit'
        run('build-xed',[sys.executable,'mfile.py','--opt=3','--no-encoder','--no-mscrt','--extra-flags=/MD','--install-dir='+str(kit),'--jobs=3','install'],t/'xed')
        libraries={'CAPSTONE_LIBRARY':lib(builds['capstone'],'capstone' if list(builds['capstone'].rglob('capstone.lib')) else 'capstone_static'),'ZYDIS_LIBRARY':lib(builds['zydis'],'Zydis'),'ZYCORE_LIBRARY':lib(builds['zydis'],'Zycore'),'XED_LIBRARY':lib(kit/'lib','xed'),'ICED_LIBRARY':lib(adapter/'target/release','iced_compare')}
        write('libraries',{k:sha(v) for k,v in libraries.items()})
        build=t/'comparison'
        def configure(label):
            args={'CAPSTONE_SOURCE':t/'capstone','ZYDIS_SOURCE':t/'zydis','XED_KIT':kit,**libraries}
            run('configure-'+label,['cmake','-S',src,'-B',build,*flags,*['-D'+k+'='+str(v) for k,v in args.items()]],t)
        configure('baseline')
        message=run('link-baseline',['cmake','--build',build,'--target','decoder-compare'],t,1)
        unresolved=[line for line in message.splitlines() if 'LNK20' in line and 'unresolved external symbol' in line]
        assert unresolved and all(any(name in line for name in ('WaitOnAddress','WakeByAddressSingle','WakeByAddressAll')) for line in unresolved),unresolved
        cmake=src/'CMakeLists.txt'
        s=cmake.read_text()
        assert s.count('ntdll userenv ws2_32)')==1
        cmake.write_bytes(s.replace('ntdll userenv ws2_32)','ntdll synchronization userenv ws2_32)').encode())
        assert sha(cmake)==spec['candidate_cmake']
        configure('candidate')
        run('link-candidate',['cmake','--build',build,'--target','decoder-compare','decoder-snapshot'],t)
        rows=[]
        for bits,folder in [(32,'SysWOW64'),(64,'System32')]:
            source=Path(os.environ['SystemRoot'])/folder/'notepad.exe'
            sample=t/('notepad'+str(bits)+'.text'); sample.write_bytes(pe_text(source))
            for engine in ('capstone','zydis','xed','iced'):
                for mode in ('scan','format','detail'):
                    row=json.loads(sp.check_output([build/'decoder-compare.exe',engine,mode,str(bits),'1',sample],text=True))
                    assert row['instructions']>0
                    rows.append(dict(bits=bits,engine=engine,mode=mode,sample_sha256=sha(sample),record=row))
        write('complete',dict(inputs=spec,raw_baseline_errors=unresolved,smoke=rows))
    finally:
        total=sum(f.stat().st_size for f in t.rglob('*') if f.is_file())
        workspace.cleanup()
        write('cleanup',dict(removed=not t.exists(),bytes=total))
