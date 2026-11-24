from pathlib import Path
import hashlib, json, os, platform, shutil, subprocess, sys
root=Path(__file__).resolve().parent
arch=sys.argv[1]
target={'x86':'i686','x64':'x86_64','arm64':'aarch64'}[arch]+'-pc-windows-msvc'
cl=shutil.which('clang-23') or shutil.which('clang')
link=shutil.which('lld-link-23') or shutil.which('lld-link')
assert cl and link
sources=json.loads((root/'sources.json').read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
for f,expected in sources['files'].items():assert sha(root/f)==expected
out=root/('built-'+arch);out.mkdir(exist_ok=True)
def run(*cmd,wd=out):
    subprocess.run(list(map(str,cmd)),cwd=wd,check=True)
def obj(src,dest,opt):
    run(cl,'--target='+target,'-ffreestanding','-fno-stack-protector','-fno-optimize-sibling-calls','-Werror=incompatible-function-pointer-types','-I'+str(root),opt,'-c',src,'-o',dest)
common=['/nodefaultlib','/timestamp:0']
obj(root/'provider.c','provider.obj','-O2')
run(link,*common,'/dll','/noentry','/out:observer.dll','/implib:observer.lib','provider.obj')
obj(root/'run.c','run.obj','-O1')
symbol='_ExitProcess@4 EXPORTAS ExitProcess' if arch=='x86' else 'ExitProcess'
(out/'system.def').write_text('LIBRARY kernel32.dll\nEXPORTS\n'+symbol+'\n')
run(link,'/lib','/machine:'+arch,'/def:system.def','/out:system.lib')
rows=[]
for route in ['original','highc','llvmc']:
    for opt in ['-O0','-O2']:
        case=out/(route+opt);case.mkdir(exist_ok=True)
        objects=[]
        for api in sources['apis']:
            file=(root/'input'/arch/route/(api+'.c')); dest=case/(api+'.obj')
            obj(file,dest,opt);objects.append(dest)
        run(link,*common,'/dll','/noentry','/out:callers.dll','/implib:callers.lib',
            *['/export:Inspect'+a for a in sources['apis']],*objects,out/'observer.lib',wd=case)
        run(link,*common,'/entry:mainCRTStartup','/subsystem:console','/out:run.exe',
            out/'run.obj','callers.lib',out/'system.lib',wd=case)
        shutil.copy2(out/'observer.dll',case/'observer.dll')
        if 'build' not in sys.argv[2:]:run(case/'run.exe',wd=case)
        rows.append(dict(route=route,opt=opt,executable=sha(case/'run.exe'),dll=sha(case/'callers.dll'),tested='build' not in sys.argv[2:],iterations=32))
receipt=dict(arch=arch,host=platform.machine(),windows=platform.version(),revision=sources['revision'],
             apis=sources['apis'],runs=rows,compiler=subprocess.check_output([cl,'--version'],text=True).splitlines()[0])
(root/('observed-'+arch+'.json')).write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt,indent=2))
