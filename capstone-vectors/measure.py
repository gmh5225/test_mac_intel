from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;s=r.parent/'source';e=r.parent/'evidence';e.mkdir(exist_ok=True);t=Path(tempfile.mkdtemp());rd=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def run(*a):return sp.check_output(a,text=True,stderr=sp.STDOUT)
def put(n,j):(e/(n+'.json')).write_text(json.dumps(j,indent=2)+'\n')
def one(v,a,b):assert v.count(a)==1,a;return v.replace(a,b)
try:
    m=rd(r/'experiment.json');q=m['stages']['mixed_bare']
    assert run('git','-C',s,'rev-parse','HEAD').strip()==q['parent'] and sha(r/'bare.patch')==q['sha256']
    run('git','-C',s,'apply','--index',r/'bare.patch');assert run('git','-C',s,'write-tree').strip()==q['tree']
    f=s/'arch/X86/X86EvexPackedScan.c';z=f.read_text();a='#include "X86EvexScanPlan.h"'
    z=one(z,a,a+'\nuint64_t probe_miss[4096], probe_hit[4096], primary_hit[4096];')
    a='unsigned id, length;';z=one(z,a,a+'\n\tunsigned slot = ((code[1] & 15) << 8) | code[4];\n\t++probe_miss[slot];')
    a='instr->Opcode = 0;';f.write_text(one(z,a,'++probe_hit[slot];\n\t\t'+a))
    f=s/'arch/X86/X86BatchScan.c';z=f.read_text();a='if (X86_readEvexScanPlan(code, size, &id, &length))\n\t\t\treturn (id << 8) | length;';f.write_text(one(z,a,'if (X86_readEvexScanPlan(code, size, &id, &length)) {\n\t\t\textern uint64_t primary_hit[4096];\n\t\t\t++primary_hit[((code[1] & 15) << 8) | code[4]];\n\t\t\treturn (id << 8) | length;\n\t\t}'))
    project=t/'project';(project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(s)
    nd=r.parent/'neverd-config';cm='cmake/NeverDCapstoneCompilerOptions.inc';(project/'cmake').mkdir();shutil.copy2(nd/cm,project/cm)
    orig=(nd/'CMakeLists.txt').read_text();(project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Census LANGUAGES C CXX)\n'+orig[orig.index('# --- Capstone (our fork'):orig.index('# --- NeverD CMake helpers')])
    b=t/'b';run('cmake','-S',project,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers')
    run('cmake','--build',b,'--parallel','4','--target','capstone_static');lib,=b.rglob('libcapstone.a')
    for strname in ('census','vectors'):run('clang++','-std=c++17','-O2','-I',s,'-I',s/'include',r/(strname+'.cpp'),lib,'-o',t/strname)
    import sys
    sys.path.insert(0,str(t))
    shutil.copy2(r/'frozen_deb.py',t/'frozen_deb.py')
    import frozen_deb
    for f in ('libmvec.py','libmvec.json','jpeg_archive.py','inputs.json'):shutil.copy2(r/f,t/f)
    inputs=rd(t/'inputs.json');(t/'inputs.json').write_text(json.dumps({'libssl3t64-amd64':inputs['libssl3t64-amd64']}));run('python3','-B',t/'libmvec.py')
    z=rd(t/'libmvec.json');images=[('libmvec-amd64',64,t/'libmvec.text',[(0,z['bytes'],z['address'])],z),*frozen_deb.prepare(t)]
    out={}
    for name,bits,file,extents,_ in images:
        v=m['provenance'][name];assert sha(file)==v['text_sha256'] and len(extents)==v['input_functions']
        skip={tuple(row[:3])for row in v['excluded_incompatible_extents']};chosen=[tuple(row)for row in extents if tuple(row)not in skip]
        ranges=t/(name+'.tsv')
        def emit(z):ranges.write_text(''.join('%d %d %d\n'%tuple(row)for row in z))
        if m['samples'][name]=='simd-functions':
            emit(chosen);sizes=[list(map(int,l.split()))for l in run(t/'vectors',str(bits),file,ranges).splitlines()];assert len(sizes)==len(chosen);chosen=[z for z,(n,k)in zip(chosen,sizes)if k>=8 and k>=.15*n]
        emit(chosen);assert sha(ranges)==v['extent_sha256'] and len(chosen)==v['timed_functions']
        obs={};stage=''
        for line in run(t/'census',file,ranges).splitlines():
            fields=line.split()
            if fields[0]=='path':
                stage=('public','batch')[int(fields[1])];obs[stage]=dict(records=int(fields[2]),bytes=int(fields[3]),digest=int(fields[4]),table={})
            else:
                op,entry,hit,first=map(int,fields);obs[stage]['table'][hex(op)]=[entry,hit,first]
        assert set(obs)=={'public','batch'} and all(obs['public'][k]==obs['batch'][k]for k in ('digest','records','bytes'))
        for z in obs.values():z['totals']=[sum(o[i]for o in z['table'].values())for i in range(3)]
        out[name]=dict(extents=len(chosen),hash=sha(file),range_sha=sha(ranges),readers=obs)
    assert len(out)==2;put('counts',out);put('complete',dict(complete=True,source=q,inputs=list(out),host=platform.machine()))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);put('cleanup',dict(removed=not t.exists(),bytes=size))
