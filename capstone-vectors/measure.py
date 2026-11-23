from pathlib import Path
import json,os,subprocess as sp,tempfile,shutil,hashlib,shlex,gzip
d=Path(__file__).resolve().parent;s=d.parent/'source';out=d.parent/'evidence';nd=d.parent/'neverd-config';out.mkdir(exist_ok=True);t=Path(tempfile.mkdtemp());m=json.loads((d/'variants.json').read_text());g=lambda *a:sp.check_output(['git','-C',s,*a],text=True).strip()
def put(n,z):(out/(n+'.json')).write_text(json.dumps(z,indent=2)+'\n')
sha=lambda z:hashlib.sha256(z).hexdigest()
try:
    assert g('rev-parse','HEAD')==m['base']['commit']
    assert sp.check_output(['git','-C',nd,'rev-parse','HEAD'],text=True).strip()==m['neverd']
    flow=(nd/'CMakeLists.txt').read_text();i=flow.index('# --- Capstone (our fork');j=flow.index('# --- NeverD CMake helpers',i)
    project=t/'project';(project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(s,target_is_directory=True);(project/'cmake').mkdir()
    shutil.copy2(nd/'cmake/NeverDCapstoneCompilerOptions.inc',project/'cmake');(project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Profile LANGUAGES C CXX)\n'+flow[i:j])
    result={}
    for name in ('project','dedicated'):
        b=t/name if name!='project' else t/'project-build';cc=os.environ['CC']
        cfg=['cmake','-S',project if name=='project'else s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers')]
        if name=='dedicated':cfg+=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF']
        sp.run(cfg,check=True);db=json.loads((b/'compile_commands.json').read_text())
        ent,=[z for z in db if Path(z['file']).name=='MipsMapping.c'];args=shlex.split(ent['command']);where=Path(ent['directory']);obj=where/args[args.index('-o')+1];obj.parent.mkdir(parents=True,exist_ok=True);allrows={}
        for stage in ('base','measured','assigned','listed'):
            g('restore','--source','HEAD','--staged','--worktree','--','.')
            if stage!='base':
                patch=d/(stage+'.patch');assert sha(patch.read_bytes())==m[stage]['sha256'];g('apply','--index',str(patch))
            assert g('write-tree')==m[stage]['tree']
            sp.run(args,cwd=where,check=True);asm=sp.check_output(['objdump','-dr','--disassemble=Mips_getInstruction',obj]);symbols=sp.check_output(['nm','-nS',obj]);sections={}
            for sect in ('.text','.rodata','.eh_frame'):
                dest=t/'section-data';dest.unlink(missing_ok=True)
                sp.run(['objcopy','--dump-section',sect+'='+str(dest),obj,t/'copy.o'],check=True,stderr=sp.DEVNULL)
                if dest.exists():sections[sect]=[sha(dest.read_bytes()),dest.stat().st_size]
            for key,raw in [('instructions',asm),('symbols',symbols)]:
                compressed=gzip.compress(raw,mtime=0);assert gzip.decompress(compressed)==raw;(out/(name+'-'+stage+'-'+key+'.gz')).write_bytes(compressed)
            allrows[stage]=dict(obj=sha(obj.read_bytes()),sections=sections,assembly=sha(asm))
        result[name]=allrows
    put('complete',dict(complete=True,source=m,profiles=result))
finally:
    n=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);put('cleanup',dict(removed=not t.exists(),bytes=n))
