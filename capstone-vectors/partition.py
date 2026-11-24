from collections import Counter
from pathlib import Path
import hashlib,json,re,shlex,shutil,subprocess as sp

def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def preserve(base,build,w):
    commands=json.loads((build/'compile_commands.json').read_text())
    root=w/'original-objects';root.mkdir()
    parts={}
    for c in commands:
        args=shlex.split(c['command'])
        source=Path(c['file']).resolve();name=source.name
        obj=(Path(c['directory'])/args[args.index('-o')+1]).resolve()
        if not obj.is_file() or source.suffix!='.c':continue
        assert obj.name not in parts
        arch=source.parent.parent.name=='arch'
        writer=source.parent.name=='X86' and any(s in name for s in ('Printer','Output','Fallback','Mapping'))
        optimize=arch and (source.parent.name!='X86' or writer)
        dest=root/obj.name;shutil.copyfile(obj,dest)
        parts[obj.name]=(obj,dest,sha(dest),optimize)
    assert 'X86DisassemblerDecoder.c.o' in parts and not parts['X86BatchScan.c.o'][3]
    assert parts['X86Sse64Output.c.o'][3] and parts['PPCMapping.c.o'][3]
    return parts

def report_inlining(build,w,profile,save):
    result={}
    names={'X86Vex32Output.c','X86Sse64Output.c','X86IntelInstPrinter.c','X86BatchScan.c','PPCMapping.c','AArch64Mapping.c','cs.c'}
    def field(block,name):
        m=re.search(r'(?m)^'+name+r':\s*(\S+)',block);return m[1] if m else ''
    for c in json.loads((build/'compile_commands.json').read_text()):
        name=Path(c['file']).name
        if name not in names:continue
        opt=w/'inline.yaml';argv=shlex.split(c['command'])
        argv[argv.index('-o')+1]=str(w/'remarks.o')
        als={}
        for key in ('base','trained'):
            args=[a for a in argv if key=='trained' or not a.startswith('-fprofile-use=')]
            extras=['-gline-tables-only','-fsave-optimization-record','-foptimization-record-passes=inline','-foptimization-record-file='+str(opt)]
            if key=='trained':extras+=['-fdiagnostics-show-hotness']
            sp.run(args+extras,check=True,cwd=c['directory'])
            decisions={}
            for b in opt.read_text().split('--- !')[1:]:
                if field(b,'Pass') not in ('inline','always-inline'):continue
                callee=re.search(r'(?m)^\s*-\s*Callee:\s*(\S+)',b);where=re.search(r'DebugLoc:\s*\{.*?Line:\s*(\d+),\s*Column:\s*(\d+)',b)
                if not callee or not where:continue
                site=(field(b,'Function'),callee[1],where[1],where[2]);hot=field(b,'Hotness')
                decisions[site]=(field(b,'Name'),int(hot) if hot.isdigit()else 0)
            als[key]=decisions
        changes=[]
        for site,after in als['trained'].items():
            before=als['base'].get(site)
            if before and before[0]!=after[0]:
                changes.append(dict(caller=site[0],callee=site[1],line=int(site[2]),column=int(site[3]),original=before[0],trained=after[0],hotness=after[1]))
        result[name]=dict(sites={k:len(v)for k,v in als.items()},changes=sorted(changes,key=lambda x:-x['hotness'])[:32])
    assert set(result)==names and sum(s['sites']['trained'] for s in result.values())>50
    save('inline-decisions',result)

def assemble(parts,build,lib,save):
    import os
    cache=(build/'CMakeCache.txt').read_text()
    def tool(name):return re.search(r'(?m)^CMAKE_'+name+r':FILEPATH=(.+)$',cache)[1]
    ar=tool('AR');ranlib=tool('RANLIB');env=dict(os.environ,ZERO_AR_DATE='1')
    def members(f):return sp.check_output([ar,'t',f],text=True).splitlines()
    ordered=members(lib);assert len(ordered)==len(set(ordered)) and set(ordered)==set(parts),(len(ordered),len(parts))
    trained={k:sha(p)for k,(p,old,h,use)in parts.items()}
    dest=build.parent/'hybrid-capstone.a'
    selected=[(parts[k][0] if parts[k][3] else parts[k][1])for k in ordered]
    sp.run([ar,'qc',dest,*selected],check=True,env=env)
    sp.run([ranlib,dest],check=True,env=env)
    assert members(dest)==ordered
    def contents(archive,k):return hashlib.sha256(sp.check_output([ar,'p',archive,k])).hexdigest()
    digest={k:contents(dest,k)for k in ordered}
    assert all(contents(lib,k)==trained[k] and digest[k]==(trained[k] if use else h)for k,(p,old,h,use)in parts.items()),'archive member provenance'
    assert sha(lib)!=sha(dest) and any(trained[k]!=h and use for k,(p,old,h,use)in parts.items())
    save('partition',dict(full_archive=sha(lib),partial_archive=sha(dest),ordered_members=ordered,objects={k:{'apply':use,'baseline':h,'full':trained[k],'selected':digest[k]} for k,(p,old,h,use)in parts.items()}))
    return dest
