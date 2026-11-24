from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,tempfile
p=Path(__file__).resolve().parent;s=p.parent/'source';e=p.parent/'evidence';e.mkdir(exist_ok=True)
q=json.loads((p/'tree.json').read_text());t=Path(tempfile.mkdtemp());compiler=os.environ['SCAN_PROFILE']
def save(name,v):(e/(name+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def git(*args):return sp.check_output(['git','-C',s,*args],text=True).strip()
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def run(label,*args):
    with (e/(label+'.log')).open('wb')as f:z=sp.run(args,stdout=f,stderr=sp.STDOUT)
    if z.returncode:print((e/(label+'.log')).read_text(errors='replace')[-1800:]);z.check_returncode()
try:
    records={};patch=t/'mips.patch';patch.write_bytes(sp.check_output(['git','-C',p.parent,'cat-file','blob','HEAD:portable-next/mips.patch']))
    assert sha(patch)==q['sha256'] and git('rev-parse','HEAD')==q['parent']
    for tag,arches,unit in [('standalone',['X86'],'x86_reg_access'),('mixed',['X86','ARM','AARCH64','MIPS'],'x86_buffer_bounds'),('x86_mips',['X86','MIPS'],'mips_scan'),('arm_mips',['ARM','MIPS'],'mips_scan'),('riscv',['RISCV'],'instruction_bytes')]:
        b=t/tag;rows=records[tag]={}
        for k in ('base','candidate'):
            git('restore','--source','HEAD','--staged','--worktree','--','.')
            if k=='candidate':
                git('apply','--index',patch);assert git('write-tree')==q['tree']
            run(tag+'-'+k+'-configure','cmake','-G','Ninja','-S',s,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+compiler,'-DCMAKE_CXX_COMPILER='+('clang++' if compiler=='clang' else 'g++'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF',*['-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in arches])
            run(tag+'-'+k+'-build','cmake','--build',b,'--parallel','4','--target','capstone_static','capstone_shared',unit)
            run(tag+'-'+k+'-unit','ctest','--test-dir',b,'--output-on-failure','--no-tests=error','-R','^unit_'+unit+'$')
            types=[f for f in b.rglob('*') if f.is_file() and not f.is_symlink() and (f.name=='libcapstone.a' or f.name.startswith('libcapstone.so') or f.name==unit or f.suffix=='.o')]
            rows[k]={str(f.relative_to(b)):sha(f)for f in types}
            assert any(x.endswith('cs.c.o')for x in rows[k]) and sum('libcapstone.'in Path(x).name for x in rows[k])==2
        assert rows['base']==rows['candidate'],(tag,[x for x,v in rows['base'].items()if v!=rows['candidate'].get(x)])
        save('identical',records)
    save('complete',dict(complete=True,source=q,images=records,compiler=compiler))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=n))
