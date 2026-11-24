from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;src=r.parent/'source';nd=r.parent/'neverd';out=r.parent/'evidence';out.mkdir()
q=json.loads((r/'source.json').read_text());sources=q['sources'];profiles={}
def git(repo,*args):return sp.check_output(['git','-C',repo,*args],text=True).strip()
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def save(k,z):(out/(k+'.json')).write_text(json.dumps(z,indent=2)+'\n')
def run(*args):sp.run(args,check=True)
assert git(nd,'rev-parse','HEAD')==q['neverd'] and git(src,'rev-parse','HEAD')==sources['reference']['commit']
work=Path(tempfile.mkdtemp())
try:
    proj=work/'profile';(proj/'cmake').mkdir(parents=True);(proj/'third_party').mkdir();(proj/'third_party/capstone').symlink_to(src)
    cfg='cmake/NeverDCapstoneCompilerOptions.inc';shutil.copy2(nd/cfg,proj/cfg)
    cm=(nd/'CMakeLists.txt').read_text()
    (proj/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Qualification LANGUAGES C CXX)\n'+cm[cm.index('# --- Capstone (our fork'):cm.index('# --- NeverD CMake helpers')])
    for profile,arches in [('neverd',[]),('ppc',['PPC']),('ppc-diet',['PPC']),('x86',['X86']),('mixed',['X86','MIPS','PPC','RISCV','ARM','AARCH64'])]:
        b=work/'build';products={}
        for k,patches in [('reference',()),('selector',('selector',)),('powerpc',('powerpc',)),('both',('powerpc','selector'))]:
            git(src,'restore','--source','HEAD','--worktree','--staged','--','.')
            for patch in patches:
                f=r/(patch+'.patch');assert sha(f)==sources[patch]['sha256']
                git(src,'apply','--index',str(f))
            assert git(src,'write-tree')==sources[k]['tree']
            if k=='reference':
                flags=['-DCMAKE_C_COMPILER=clang','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_DIET='+('ON'if profile=='ppc-diet'else'OFF')]
                if profile!='neverd':flags+=['-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers']
                run('cmake','-G','Ninja','-S',proj if profile=='neverd' else src,'-B',b,*flags,*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in arches])
            run('cmake','--build',b,'--parallel','4','--target','capstone_static')
            archive,=b.rglob('libcapstone.a');products[k]=dict(archive=sha(archive),objects={str(f.relative_to(b)):sha(f) for f in b.rglob('*.c.o')})
        groups=(('reference','selector'),('powerpc','both')) if arches==['PPC'] else (('reference','powerpc'),('selector','both'))
        for a,z in groups:assert products[a]==products[z],(profile,a,z)
        assert products[groups[0][0]]!=products[groups[1][0]],profile
        profiles[profile]=dict(equivalent=groups,products=products)
        save('profiles',profiles);shutil.rmtree(b)
    save('complete',dict(source=q,profiles=list(profiles),host=os.uname().machine))
finally:
    n=sum(f.stat().st_size for f in work.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(work);save('cleanup',dict(bytes=n,removed=not work.exists()))
