"""Isolate changes to x86 opcode ownership, common completion, and MCInst field layout."""
from pathlib import Path
import collections
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess as sp
import tempfile
import corpus

r=Path(__file__).resolve().parent
root=r.parent
s=root/'source'
out=root/'evidence'
out.mkdir(exist_ok=True)
def save(name,payload):
    (out/(name+'.json')).write_text(json.dumps(payload,indent=2)+'\n')
def run(args,name,cwd=None):
    with (out/(name+'.log')).open('w') as f:
        sp.run(args,cwd=cwd,stdout=f,stderr=sp.STDOUT,check=True)
def sha(f):
    return hashlib.sha256(f.read_bytes()).hexdigest()
def git(*args):
    return sp.check_output(['git','-C',s,*args],text=True).strip()
m=json.loads((r/'controls.json').read_text())
assert git('rev-parse','HEAD')==m['parent']
t=Path(tempfile.mkdtemp());fixed=t/'selected';fixed.mkdir()
cc=os.environ['CC'];b=t/'build'
try:
    opts=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers')]
    opts.extend('-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ('X86','ARM','AARCH64','MIPS','RISCV','PPC'))
    run(['cmake','-S',s,'-B',b,*opts],'configure')
    ordering=['base','owner','exit','aligned','packed','typed']
    libs={};objects={};symbols={};offsets={}
    units=['x86_scan_batch','x86_evex_vpcmp_id','x86_evex_vpcmp_mask_size','x86_evex_detail','x86_buffer_bounds']
    for label in ordering:
        if label!='base':
            patch=r/(label+'.patch');assert sha(patch)==m['variants'][label]['sha256']
            git('apply','--index',str(patch));assert git('write-tree')==m['variants'][label]['tree']
        run(['cmake','--build',b,'--parallel','4','--target','capstone_shared',*units],'build-'+label)
        run(['ctest','--test-dir',b,'--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(units)+')$'],'units-'+label)
        path=next(f for f in b.glob('libcapstone.so.*') if not f.is_symlink());dest=t/(label+'.so');shutil.copyfile(path,dest);libs[label]=dest
        objects[label]={str(f.relative_to(b)):sha(f) for f in b.rglob('*.o') if 'CMakeFiles/capstone.dir' in str(f)}
        assert len(objects[label])>45
        sym=[]
        for line in sp.check_output(['nm','-nS','--defined-only',dest],text=True).splitlines():
            a=line.split()
            if len(a)==4 and re.search(r'^(cs_disasm_iter|cs_decode_full_insn|decode_full_insn_body|ARM_getInstruction|AArch64_getInstruction|Mips_getInstruction|PPC_getInstruction|RISCV_getInstruction|X86_disasmIter|X86_postprinter|X86_scanBatch|PPC_printInst)$',a[3]):
                sym.append(dict(name=a[3],address=int(a[0],16),size=int(a[1],16)))
        symbols[label]=sym
        run([cc,'-I',s,'-I',s/'include',r/'layout.c','-o',t/'layout'],'layout-'+label)
        offsets[label]=json.loads(sp.check_output([t/'layout'],text=True))
        git('restore','--source=HEAD','--staged','--worktree','.')
        assert not git('status','--porcelain')
    assert offsets['base']==offsets['owner']==offsets['exit']==offsets['aligned']
    assert offsets['typed']['assembly']+1==offsets['base']['assembly']
    assert offsets['packed']['assembly']==offsets['base']['assembly'] and offsets['packed']['size']==offsets['base']['size']
    assert all((k=='fillDetailOps' or offsets['base'][k]==v) for k,v in offsets['packed'].items())
    save('source',m);save('objects',objects);save('symbols',symbols);save('offsets',offsets)
    raw=corpus.prepare(r,t,out,run)
    mapping={'arm-cp':101,'arm64-ls':102,'mips64el-ls':103,'ppc64el-ls':104,'riscv64-ls':105,'putty-32-0.85':32,'putty-64-0.85':64}
    cases={c['name']:(mapping[c['name']],Path(c['path']),0x401000 if c['name']=='putty-32-0.85' else 0x140001000 if c['name']=='putty-64-0.85' else 0x100000) for c in raw if c['name'] in mapping}
    assert set(cases)==set(mapping)
    shutil.copyfile(r/'libmvec.py',t/'libmvec.py');shutil.copyfile(r/'libmvec.json',t/'libmvec.json')
    run(['python3','-B',t/'libmvec.py'],'libmvec')
    glibc=json.loads((t/'libmvec.json').read_text());cases['libmvec']=(64,t/'libmvec.text',glibc['address'])
    run(['c++','-O2','-std=c++17','-I',s/'include',r/'records.cpp','-ldl','-o',t/'records'],'compile-records')
    for label in ordering[1:]:
        for name,bits,f,va in [('matrix32',32,'matrix',0),('matrix64',64,'matrix',0),('libmvec',64,t/'libmvec.text',glibc['address'])]:
            run([t/'records',libs['base'],libs[label],str(bits),f,str(va),'0','0'],'records-'+label+'-'+name)
    for arch in ('arm','aarch64','mips','ppc','riscv'):
        run(['c++','-O2','-std=c++17','-I',s,'-I',s/'include',r/(arch+'-states.cpp'),'-ldl','-o',t/(arch+'-states')],'compile-'+arch)
        for label in ('owner','packed'):
            args=[t/(arch+'-states'),libs['base'],libs[label]]
            if arch=='riscv':args.append(t/'corpus')
            run(args,'states-'+label+'-'+arch)
    target=fixed/'libcapstone.so.6';target.write_bytes(libs['base'].read_bytes());(fixed/'libcapstone.so').symlink_to(target.name)
    run(['c++','-O3','-std=c++17','-I',s/'include',r/'time.cpp','-L',fixed,'-Wl,-rpath,'+str(fixed),'-lcapstone','-o',t/'time'],'link-timer')
    bind=['setarch',platform.machine(),'-R'];sp.run([*bind,'/bin/true'],check=True)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    binaries={k:v.read_bytes() for k,v in libs.items()};binaries['copy']=binaries['base']
    maximum=max(map(len,binaries.values()));binaries={k:v+bytes(maximum-len(v)) for k,v in binaries.items()};inode=target.stat().st_ino
    def call(label,args):
        with target.open('wb') as stream:stream.write(binaries[label])
        assert target.stat().st_ino==inode
        ns,wall,check=map(int,sp.check_output([*bind,t/'time',*map(str,args)],text=True).split())
        assert ns>0 and wall>0
        return [ns,wall,check]
    rows=[];labels=['base','copy',*ordering[1:]]
    for name in sorted(cases):
        bits,f,va=cases[name]
        for mode in (0,1,2):
            ns,_,check=call('base',[bits,mode,f,va,1]);reps=max(1,round(26e6/ns));cycles=[]
            for i in range(7):
                order=labels[i:]+labels[:i];observed=collections.defaultdict(list)
                for label in order+order[::-1]:
                    val=call(label,[bits,mode,f,va,reps]);assert val[2]==check
                    observed[label].append(val[:2])
                cycles.append(observed)
            rows.append(dict(case=name,mode=mode,reps=reps,cycles=cycles,check=check))
            save('timings',rows)
    save('complete',dict(rows=len(rows),sources=m,compiler=sp.check_output([cc,'--version'],text=True).splitlines()[0],machine=platform.machine(),same_inode=True,base_aa_identical=binaries['base']==binaries['copy']))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*') if f.is_file());shutil.rmtree(t)
    save('cleanup',dict(removed=not t.exists(),bytes=size))
