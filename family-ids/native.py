"""Separate a full-decoder call target from executable placement in GCC's public scan."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import os
import platform
import random
import re
import shlex
import shutil
import statistics
import subprocess as sp
import tempfile

here = Path(__file__).resolve().parent
root = here.parent
source = root / 'source'
evidence = root / 'evidence'
evidence.mkdir(exist_ok=True)

def read(path):
    return json.loads(path.read_text())

def save(name, value):
    (evidence / (name+'.json')).write_text(json.dumps(value, indent=2)+'\n')

def output(args, cwd=None):
    return sp.check_output(args, cwd=cwd, text=True).strip()

def run(args, log, cwd=None):
    with (evidence / (log+'.log')).open('w') as stream:
        sp.run(args, cwd=cwd, stdout=stream, stderr=sp.STDOUT, check=True)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def symbols(path):
    rows = []
    for line in output(['nm','-S','--defined-only',path]).splitlines():
        p = line.split()
        if len(p)==4 and re.fullmatch('[0-9a-f]+',p[0]) and re.fullmatch('[0-9a-f]+',p[1]):
            rows.append((p[-1], p[2], int(p[0],16), int(p[1],16)))
    return rows

def sections(path):
    rows = {}
    for line in output(['readelf','-SW',path]).splitlines():
        m = re.match(r'\s*\[\s*\d+\]\s+(\.\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+\S+\s+(\S+)\s+\d+\s+\d+\s+(\d+)',line)
        if m and 'A' in m[5]:
            rows[m[1]] = [int(m[2],16), int(m[3],16), int(m[4],16),m[5],int(m[6])]
    return rows

def scanner(path):
    start,size = [(a,s) for n,t,a,s in symbols(path) if n=='cs_disasm_iter'][0]
    sec = sections(path)['.text']
    blob = path.read_bytes()[sec[1]+start:sec[1]+start+size]
    assert len(blob)==size and size>0
    refs=[]
    for ln in output(['objdump','-r','-j','.text',path]).splitlines():
        p=ln.split()
        if len(p)==3 and re.fullmatch('[0-9a-f]+',p[0]) and start<=int(p[0],16)<start+size:
            refs.append([int(p[0],16)-start,p[1],p[2]])
    return dict(bytes=size, text=hashlib.sha256(blob).hexdigest(), section_align=sec[-1], relocations=refs)

meta=read(here/'tree.json')
reference=read(here/'gcc-reference.json')
assert output(['git','-C',source,'rev-parse','HEAD'])==meta['parent'] and sha(here/'candidate.patch')==meta['sha256']
tmp=Path(tempfile.mkdtemp())
try:
    build=tmp/'build'
    flags=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=gcc','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers']
    flags.extend('-DCAPSTONE_'+n+'_SUPPORT=ON' for n in ('ARM','AARCH64','MIPS','RISCV','PPC'))
    run(['cmake','-S',source,'-B',build,*flags],'configure')
    libs={};objects={};commands={};scan_objects={};checks={}
    for label in ('base','candidate'):
        if label=='candidate':
            run(['git','-C',source,'apply','--index',here/'candidate.patch'],'apply')
            assert output(['git','-C',source,'write-tree'])==meta['tree']
        run(['cmake','--build',build,'--parallel','4','--target','capstone_shared'],'build-'+label)
        original,=[x for x in build.glob('libcapstone.so.*') if not x.is_symlink()]
        libs[label]=tmp/(label+'.so')
        shutil.copy2(original,libs[label])
        link=next(x for x in output(['ninja','-C',build,'-t','commands','capstone_shared']).splitlines() if ' -shared ' in x and ' -o ' in x and 'libcapstone.so' in x)
        args=shlex.split(link)
        while args[0] in (':','&&'):args.pop(0)
        if '&&' in args:args=args[:args.index('&&')]
        obj=[v for v in args if v.endswith('.o')]
        assert obj and '-o' in args
        folder=tmp/(label+'-objects');folder.mkdir()
        objects[label]={}
        for i,v in enumerate(obj):
            saved=folder/(str(i)+'-'+Path(v).name)
            shutil.copy2(build/v,saved)
            objects[label][v]=saved
        commands[label]=args
        key,=[v for v in obj if v.endswith('/X86DisassemblerDecoder.c.o')]
        scan_objects[label]=key
        checks[label]=scanner(objects[label][key])
    extra_writers=[v for v in objects['candidate'] if v not in objects['base']]
    assert {Path(v).name for v in extra_writers}=={'X86Sse64Output.c.o','X86Vex32Output.c.o'}
    assert commands['base']==[v for v in commands['candidate'] if v not in extra_writers] and scan_objects['base']==scan_objects['candidate']
    key=scan_objects['base']
    old_name='cs_decode_full_insn'
    new_name='cs_decode_public_full_insn'
    lib_sha={k:sha(p) for k,p in libs.items()}
    save('originals',dict(expected=reference['libs'],actual=lib_sha,matched=lib_sha==reference['libs'],gcc=output(['gcc','--version']).splitlines()[0],cpu=output(['lscpu']),source=meta))
    save('scanner',checks)
    def link(label,variant,replace=None,before=(),after=(),extra=()):
        args=[]
        for token in commands[label]:
            if token==key:
                args.extend(before)
                args.append(replace or objects[label][key])
                args.extend(after)
            else:
                args.append(objects[label].get(token,token))
        args[args.index('-o')+1]=tmp/(variant+'.so')
        args.extend(extra)
        run(args,'link-'+variant,build)
        libs[variant]=tmp/(variant+'.so')
    for label in ('base','candidate'):
        link(label,label+'-relink')
        assert sha(libs[label+'-relink'])==sha(libs[label])
    normalized=tmp/'normalized-scanner.o'
    run(['objcopy','--redefine-sym',new_name+'='+old_name,objects['candidate'][key],normalized],'canonical-call')
    link('candidate','canonical-call',replace=normalized)
    link('base','candidate-scanner',replace=normalized)
    link('base','writers-only', extra=[objects['candidate'][v] for v in extra_writers])
    def anchors(path):
        wanted={'cs_disasm_iter','X86_scanBatch','cs_decode_full_insn','cs_decode_public_full_insn','X86_disasmIter32','X86_disasmIterText','X86_getInstruction','ARM_getInstruction','AArch64_getInstruction'}
        return {n:[a,s] for n,t,a,s in symbols(path) if n in wanted}
    addrs={k:anchors(v)for k,v in libs.items()}
    offsets={k:addrs[k]['cs_disasm_iter'][0] for k in ('base','candidate')}
    align=max(checks[k]['section_align'] for k in ('base','candidate'))
    span=abs(offsets['candidate']-offsets['base']) or align
    span=((span+align-1)//align)*align
    assert 0<span<1_048_576
    assembly=tmp/'padding.s'
    assembly.write_text('.text\n.fill '+str(span)+',1,0x90\n.section .note.GNU-stack,"",@progbits\n')
    pad=tmp/'padding.o'
    run(['as','--64',assembly,'-o',pad],'padding')
    interventions={}
    for label in ('base','candidate'):
        link(label,label+'-front',before=[pad])
        link(label,label+'-back',after=[pad])
        a=libs[label+'-front'];b=libs[label+'-back']
        sa,sb=symbols(a),symbols(b)
        da=list((Counter(sa)-Counter(sb)).elements())
        db=list((Counter(sb)-Counter(sa)).elements())
        input_names={n for n,t,addr,size in symbols(objects[label][key]) if t.lower()=='t'}
        front=anchors(a);back=anchors(b)
        ac=sections(a);bc=sections(b)
        interventions[label]=dict(front=front,back=back,changed_symbols_front=da,changed_symbols_back=db,unexpected_symbol_names=sorted({v[0] for v in da+db}-input_names),section_changes={s:[ac.get(s),bc.get(s)] for s in ac.keys()|bc.keys() if ac.get(s)!=bc.get(s)},observed_displacement=front['cs_disasm_iter'][0]-back['cs_disasm_iter'][0])
    ren=checks['candidate']['relocations']
    ren=[[p,t,n.replace(new_name,old_name)]for p,t,n in ren]
    save('layout',dict(span=span,align=align,original_addresses=addrs,interventions=interventions,original_scan_same=checks['base']['text']==checks['candidate']['text'],relocations_equal_after_rename=checks['base']['relocations']==ren,hybrid_scan_on_baseline_sha_matches=sha(libs['candidate-scanner'])==sha(libs['base']),originals_relinked_identical=True,normalized=scanner(normalized)))
    # Instrument only the scanner's single output-call relocation, with an enabled-text positive control.
    for label,callee in [('base',old_name),('candidate',new_name)]:
        assert sum(callee in v[2] for v in checks[label]['relocations'])==1
        hook=tmp/(label+'-hook.c')
        hook.write_text('#include <stdint.h>\n#include <stdbool.h>\n#include <stddef.h>\n#include <stdio.h>\nstruct cs_struct; struct cs_insn;\n#define ARGS struct cs_struct *h,const uint8_t *p,size_t n,struct cs_insn *i,uint16_t *z,bool batch\nextern bool '+callee+'(ARGS);\nstatic unsigned long long calls;\n__attribute__((visibility("hidden"))) bool probe_output(ARGS){++calls;return '+callee+'(h,p,n,i,z,batch);}\n__attribute__((destructor)) static void report(void){fprintf(stderr,"output_calls=%llu\\n",calls);}\n')
        wrapper=tmp/(label+'-hook.o')
        run(['gcc','-O2','-fPIC','-c',hook,'-o',wrapper],'hook-'+label)
        renamed=tmp/(label+'-scanner.o')
        run(['objcopy','--redefine-sym',callee+'=probe_output',objects[label][key],renamed],'hook-symbol-'+label)
        link(label,label+'-probe',replace=renamed,extra=[wrapper])
    shutil.copy2(here/'fetch.py',tmp/'fetch.py')
    run(['python3','-B',tmp/'fetch.py'],'putty')
    save('samples',read(tmp/'corpus.json'))
    fixed=tmp/'selected';fixed.mkdir()
    selected=fixed/'libcapstone.so.6'
    selected.write_bytes(libs['base'].read_bytes())
    (fixed/'libcapstone.so').symlink_to(selected.name)
    run(['c++','-O3','-std=c++17','-I',source/'include',here/'time.cpp','-L',fixed,'-Wl,-rpath,'+str(fixed),'-lcapstone','-o',tmp/'time'],'time')
    bind=['setarch',platform.machine(),'-R']
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    payloads={k:v.read_bytes()for k,v in libs.items()}
    payloads['copy']=payloads['base']
    length=max(map(len,payloads.values()))
    payloads={k:v+bytes(length-len(v))for k,v in payloads.items()}
    inode=selected.stat().st_ino
    def invoke(label,bits,mode,reps):
        selected.write_bytes(payloads[label])
        assert selected.stat().st_ino==inode
        z=sp.run([*bind,tmp/'time',str(bits),str(mode),tmp/('putty-0.85-'+str(bits)+'.text'),str(0x401000 if bits==32 else 0x140001000),str(reps)],text=True,capture_output=True,check=True)
        return list(map(int,z.stdout.split())),z.stderr.strip()
    counters=[]
    for bits in (32,64):
        for mode in (0,1):
            base,_=invoke('base',bits,mode,1)
            for label in ('base','candidate'):
                values,msg=invoke(label+'-probe',bits,mode,1)
                assert base[2]==values[2]
                count=int(re.fullmatch('output_calls=([0-9]+)',msg)[1])
                counters.append(dict(bits=bits,mode=mode,variant=label,total_calls_including_warm=count,result=values[2]))
    save('calls',counters)
    panels=[]
    for bits,mode in ((32,0),(64,0),(32,1)):
        variants=['base','copy','candidate','canonical-call','candidate-scanner']
        if mode==0:variants+=['writers-only']+['base-front','base-back','candidate-front','candidate-back']
        one,_=invoke('base',bits,mode,1)
        reps=max(1,round(75e6/one[0]))
        cycles=[];rng=random.Random(100*bits+mode)
        for i in range(15):
            order=variants.copy();rng.shuffle(order)
            ticks={v:[]for v in variants}
            for v in order+order[::-1]:
                result,msg=invoke(v,bits,mode,reps)
                assert not msg and result[2]==one[2]
                ticks[v].append(result[:2])
            cycles.append(ticks)
        panels.append(dict(bits=bits,mode=mode,signature=one[2],reps=reps,cycles=cycles))
        save('panels',panels)
    save('complete',dict(success=True,panels=len(panels),inode=inode,affinity=list(os.sched_getaffinity(0)),original_hashes=lib_sha))
finally:
    size=sum(f.stat().st_size for f in tmp.rglob('*') if f.is_file())
    shutil.rmtree(tmp)
    save('cleanup',dict(bytes=size,removed=not tmp.exists()))
