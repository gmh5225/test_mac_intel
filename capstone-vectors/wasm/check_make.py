from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
if platform.system()!='Linux' or platform.machine()!='x86_64' or os.environ['CC']!='clang':raise SystemExit(0)
r=Path(__file__).resolve().parent;root=Path(os.environ['GITHUB_WORKSPACE']);e=root/'evidence';t=json.loads((r/'tree.json').read_text())
with tempfile.TemporaryDirectory(dir=root) as tmp:
    w=Path(tmp);s=w/'src';sp.run(['git','clone','-q','--shared','--no-checkout',root/'source',s],check=True)
    sp.run(['git','-C',s,'checkout','-q','--detach',t['parent']],check=True);original=w/'ref.c';original.write_bytes((s/'arch/WASM/WASMInstPrinter.c').read_bytes())
    inc=['-I',s,'-I',s/'include','-I',s/'arch/WASM','-DCAPSTONE_HAS_WASM','-DCAPSTONE_USE_SYS_DYN_MEM']
    sp.run(['clang','-O2',*inc,'-DWASM_printInst=wasm_reference','-c',original,'-o',w/'ref.o'],check=True)
    rows={}
    for tag in ('base','candidate'):
        if tag=='candidate':sp.run(['git','-C',s,'apply','--index',r/'candidate.patch'],check=True)
        b=w/tag
        cmd=['make','-C',s,'-j3','V=1','CC=clang','AR=ar','BUILDDIR='+str(b),'CAPSTONE_BUILD_CORE_ONLY=yes','CAPSTONE_ARCHS=wasm','CAPSTONE_STATIC=yes','CAPSTONE_SHARED=no']
        log=sp.check_output(cmd,text=True);assert ('-DCAPSTONE_WASM_LITERAL_MNEMONICS' in log)==(tag=='candidate')
        lib,=[f for f in b.rglob('libcapstone.a') if not f.is_symlink()]
        obj,=b.rglob('WASMInstPrinter.o')
        sp.run(['clang','-O2',*inc,r/'verify-stream.c',w/'ref.o',lib,'-o',w/'verify'],check=True)
        count=int(sp.check_output([w/'verify'],text=True));assert count==792576
        rows[tag]=dict(states=count,object=hashlib.sha256(obj.read_bytes()).hexdigest(),archive=hashlib.sha256(lib.read_bytes()).hexdigest())
    assert rows['base']['object']!=rows['candidate']['object']
    size=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink())
assert not w.exists()
(e/'make.json').write_text(json.dumps(dict(complete=True,source=t,results=rows,cleanup=dict(bytes=size,removed=True)),indent=2)+'\n')
