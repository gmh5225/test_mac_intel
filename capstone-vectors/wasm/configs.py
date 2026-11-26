from pathlib import Path
import hashlib,json,os,subprocess as sp,tempfile
root=Path(os.environ['GITHUB_WORKSPACE']);r=Path(__file__).resolve().parent;e=root/'evidence';e.mkdir(exist_ok=True);s=root/'source';tree=json.loads((r/'tree.json').read_text())
with tempfile.TemporaryDirectory(dir=root)as t:
    w=Path(t);src=w/'src';sp.run(['git','clone','-q','--shared','--no-checkout',s,src],check=True)
    rows={}
    for profile,flags in [('diet',['-DCAPSTONE_BUILD_DIET=ON']),('external',['-DCAPSTONE_USE_DEFAULT_ALLOC=OFF'])]:
        b=w/profile;rows[profile]={}
        for label in ('base','candidate'):
            sp.run(['git','-C',src,'checkout','-q','--detach','--force',tree['parent']],check=True)
            if label=='candidate':sp.run(['git','-C',src,'apply','--index',r/'candidate.patch'],check=True)
            if label=='base':
                sp.run(['cmake','-S',src,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_WASM_SUPPORT=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF',*flags],check=True)
            sp.run(['cmake','--build',b,'--target','capstone_static','--parallel','3'],check=True)
            obj,=b.rglob('WASMInstPrinter.c.o');lib,=b.rglob('libcapstone.a')
            rows[profile][label]={'object':hashlib.sha256(obj.read_bytes()).hexdigest(),'archive':hashlib.sha256(lib.read_bytes()).hexdigest()}
        assert rows[profile]['base']['object']==rows[profile]['candidate']['object'],rows[profile]
    disk=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink())
assert not w.exists()
(e/'configurations.json').write_text(json.dumps(dict(complete=True,variants=rows,cleanup=dict(bytes=disk,removed=True)),indent=2)+'\n')
