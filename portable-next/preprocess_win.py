"""Compare the code fed to native MSVC for every Capstone object in each build."""
import concurrent.futures,hashlib,json,os,shutil,subprocess as sp,tempfile
from pathlib import Path
def verify(r):
    root=r.parent;src=root/'source';e=root/'evidence';e.mkdir(exist_ok=True);q=json.loads((r/'source.json').read_text());w=Path(tempfile.mkdtemp()).resolve()
    def git(*args):return sp.check_output(['git','-C',src,*args],text=True).strip()
    def save(n,z):(e/(n+'.json')).write_text(json.dumps(z,indent=2)+'\n')
    try:
        b=w/'build';assert git('rev-parse','HEAD')==q['base']['commit']
        flags=['-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON']
        states={}
        for tag in ('base','candidate'):
            if tag=='candidate':
                patch=sp.check_output(['git','-C',root,'cat-file','blob','HEAD:portable-next/candidate.patch']);assert hashlib.sha256(patch).hexdigest()==q[tag]['sha256']
                f=w/'delta.patch';f.write_bytes(patch);git('apply','--index',f)
            assert git('write-tree')==q[tag]['tree']
            sp.run(['cmake','-G','Ninja','-S',src,'-B',b,*flags],check=True)
            jobs=[j for j in json.loads((b/'compile_commands.json').read_text())if Path(j['file']).suffix=='.c']
            def digest(j):
                command=j['command'];assert 'cl.exe' in command.lower() and 'CAPSTONE_HAS_X86' in command
                raw=sp.check_output(command+' /EP',cwd=j['directory'])
                assert len(raw)>5000,(j['file'],len(raw))
                return j['output'],hashlib.sha256(raw).hexdigest()
            with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:states[tag]=dict(pool.map(digest,jobs))
            save('preprocessed',states)
        assert len(states['base'])>20 and states['base']==states['candidate'],[k for k,v in states['base'].items()if v!=states['candidate'].get(k)]
        save('complete',dict(complete=True,source=q,host='Windows',proof='preprocessed',expected='base',objects=len(states['base']),toolchain=os.environ.get('VSCMD_ARG_TGT_ARCH')))
    finally:
        size=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=size))
