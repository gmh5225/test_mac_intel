from pathlib import Path
from binary_identity import identity
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
root=Path(os.environ.get('GITHUB_WORKSPACE',Path(__file__).resolve().parent))
r=Path(__file__).resolve().parent;remote='GITHUB_WORKSPACE' in os.environ
d=lambda n:next(r.parent.glob(f'round{n}-*'));s=root/'source' if remote else d(579)/'source';e=root/'evidence' if remote else r
e.mkdir(exist_ok=True)
t=json.loads(((r if remote else d(3493))/'tree.json').read_text())
def run(*args):sp.run(args,check=True)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
w=Path(tempfile.mkdtemp(dir=root));rows={}
try:
    src=w/'src';b=w/'build'
    run('git','clone','-q','--shared','--no-checkout',s,src)
    run('git','-C',src,'checkout','-q','--detach',t['parent'])
    for label in ('base','candidate'):
        if label=='candidate':
            patch=(r if remote else d(3493))/'candidate.patch';assert sha(patch)==t['sha256']
            run('git','-C',src,'apply','--index',patch);assert sp.check_output(['git','-C',src,'write-tree'],text=True).strip()==t['tree']
        units=['mapping','mcinst','wasm_brtable_size','x86_reg_access','aarch64_scan','arm_reg_access','mips_scan','riscv_reg_access']
        run('cmake','-S',src,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('X86','ARM','AARCH64','PPC','MIPS','RISCV','WASM')])
        run('cmake','--build',b,'--target','capstone_static','capstone_shared',*units,'--parallel','4')
        run('ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$')
        archives=[f for f in b.glob('libcapstone*') if f.is_file() and not f.is_symlink()]
        assert len(archives)==2,archives
        files=sorted(b.rglob('*.c.o')); assert len(files)>50 and any(f.name=='WASMInstPrinter.c.o' for f in files)
        exe=b/'tests/unit/x86_reg_access'
        if not exe.exists():exe,=[f for f in b.rglob('x86_reg_access')if f.is_file()]
        rows[label]=dict(objects={str(f.relative_to(b)):sha(f) for f in files},libraries={f.name:identity(f) for f in archives},linked_x86_test=sha(exe),units=units)
    (e/'mixed-builds.json').write_text(json.dumps(rows,indent=2)+'\n')
    for key in ('objects','linked_x86_test','units'):assert rows['candidate'][key]==rows['base'][key],key
    assert rows['base']['libraries'].keys()==rows['candidate']['libraries'].keys()
    for f,raw in rows['base']['libraries'].items():
        assert raw['content']==rows['candidate']['libraries'][f]['content'],(f,raw,rows['candidate']['libraries'][f])
    (e/'mixed.json').write_text(json.dumps(dict(complete=True,source=t,host=platform.platform(),rows=rows),indent=2)+'\n')

finally:
    size=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);(e/'mixed-cleanup.json').write_text(json.dumps(dict(bytes=size,removed=not w.exists()))+'\n')
