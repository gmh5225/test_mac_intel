"""Measure exact, common-boundary PE function bodies and three additional ELF text sections."""
from pathlib import Path
import gzip, os, platform, hashlib, importlib.util, json, math, shutil, statistics, subprocess as sp, tempfile
r=Path(__file__).resolve().parent
p=r.parent
base=p/'source'
lab=r; evidence=p/'evidence'; evidence.mkdir()
pe=p/'round118-real-pe'

def save(name,data):
    (evidence/name).write_text(json.dumps(data,indent=2)+'\n')
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(args,label,cwd=None):
    with (evidence/(label+'.log')).open('w') as f:sp.run(args,cwd=cwd,stdout=f,stderr=sp.STDOUT,check=True)
def module(path):
    spec=importlib.util.spec_from_file_location(path.stem,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def main(w):
    reference=json.loads((r/'candidate.json').read_text())['parent']
    assert sp.check_output(['git','-C',base,'rev-parse',reference],text=True).strip()==reference
    iced='8b8d90b13374fbf38e7279749e48c673f4ec243a'
    checkout=w/'iced';checkout.mkdir();tar=w/'iced.tar'
    run(['git','init','--bare',w/'iced-git'],'iced-repo');run(['git','-C',w/'iced-git','fetch','--depth','1','https://github.com/NeverSight/iced.git',iced],'iced-fetch');run(['git','-C',w/'iced-git','archive','--format=tar','-o',tar,iced,'src/rust/iced-x86'],'iced-archive');run(['tar','-xf',tar,'-C',checkout],'iced-extract');tar.unlink()
    ad=w/'adapter';ad.mkdir();src=(lab/'iced.rs').read_text().replace('repeats: u32,\n    output:', 'repeats: u32,\n    ip: u64,\n    output:').replace('bytes, 0x100000,','bytes, ip,').replace('set_ip(0x100000 +','set_ip(ip +')
    src=src.replace('InstructionInfoFactory, IntelFormatter,','InstructionInfoFactory, IntelFormatter, FastFormatter,').replace('    formatter: IntelFormatter,','    formatter: IntelFormatter,\n    fast: FastFormatter,\n    fast_enabled: bool,').replace('        mode,','        mode: mode & 3,\n        fast_enabled: mode & 8 != 0,\n        fast: FastFormatter::new(),')
    old='state.formatter.format(&instruction, &mut state.text);';assert src.count(old)==1;src=src.replace(old,'if state.fast_enabled {state.fast.format(&instruction, &mut state.text);} else {state.formatter.format(&instruction, &mut state.text);}')
    trace=(r/'iced-trace.rs').read_text().replace('iced_trace(input:', 'iced_trace(bits:u32,input:').replace('with_ip(64,','with_ip(bits,');(ad/'iced.rs').write_text(src+trace);shutil.copyfile(lab/'Cargo.lock',ad/'Cargo.lock')
    (ad/'Cargo.toml').write_text('[package]\nname="iced_compare"\nversion="0.1.0"\nedition="2021"\n[lib]\ncrate-type=["staticlib"]\npath="iced.rs"\n[dependencies]\niced-x86={path="../iced/src/rust/iced-x86",default-features=false,features=["std","decoder","intel","instr_info","fast_fmt"]}\n[profile.release]\npanic="abort"\nopt-level=3\n');run(['cargo','build','--locked','--release'],'iced-build',ad)
    save('cpu.json',dict(cpu=Path('/proc/cpuinfo').read_text(),compiler=sp.check_output([os.environ['CC'],'--version'],text=True)))
    save('census-variant.json',dict(variant='integer',round=1298,capstone_revision=reference,iced_revision=iced,purpose='Warm steady-state instruction-address comparison; not native qualification'))
    save('variants.json',dict(integer='Released Capstone next',scan='One direct-index VEX descriptor pool; prior is the exact R1295 shared/extra candidate'))
    save('entrypoints.json',dict(scan='cs_disasm_iter',format='X86_disasmIter',detail='X86_disasmIter',consumer='Physical output entry cost diagnostic; actual NeverD tested separately'))
    inc=(r/'driver.cpp').read_text().replace('size_t iced_trace(const','size_t iced_trace(unsigned, const').replace('if(argc!=6)','if(argc!=7)').replace('  csh handle=0;','  unsigned bits=std::stoul(argv[6]);\n  csh handle=0;').replace('cs_open(CS_ARCH_X86,CS_MODE_64,','cs_open(CS_ARCH_X86,bits==32?CS_MODE_32:CS_MODE_64,').replace('iced_create(64,mode)','iced_create(bits,mode)').replace('iced_trace(ptr,','iced_trace(bits,ptr,')
    inc=inc.replace('iced_create(bits,mode)','iced_create(bits,mode | (engine=="fast" ? 8 : 0))').replace('engine!="capstone" && engine!="iced"','engine!="capstone" && engine!="iced" && engine!="fast"')
    inc=inc.replace('if (mode>2 ||','if (mode>4 ||').replace('mode==2 ? CS_OPT_ON','mode>=2 ? CS_OPT_ON')
    inc=inc.replace('if (mode == 2) {','if (mode == 2 || mode == 4) {\n        if (mode == 2) {').replace('        const auto &x = insn->detail->x86;', '        }\n        const auto &x = insn->detail->x86;')
    assert inc.count('iced_trace(bits,ptr,')==1
    inc=inc.replace('static Result cs_span(', 'extern "C" __attribute__((noinline)) Result cs_span(')
    inc=inc.replace('#include <capstone/capstone.h>', '#include <capstone/capstone.h>\n#include <valgrind/callgrind.h>')
    assert inc.count('Result warm=run(1);')==1 and inc.count('Result timed=run(reps);')==1
    inc=inc.replace('Result warm=run(1);', 'Result warm=run(1);\n    CALLGRIND_ZERO_STATS;')
    inc=inc.replace('Result timed=run(reps);', 'CALLGRIND_TOGGLE_COLLECT;\n    Result timed=run(reps);\n    CALLGRIND_TOGGLE_COLLECT;')
    (w/'functions.cpp').write_text(inc);run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include','-c',w/'functions.cpp','-o',w/'driver.o'],'driver')
    profile=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+os.environ['CC'],'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ['X86','ARM','AARCH64','MIPS']],'-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer '+('-Wno-error=discarded-qualifiers' if os.environ['CC']=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF']
    tree=w/'tree';run(['git','clone','-q','--shared','--no-checkout',base,tree],'capstone-clone');run(['git','checkout','-q','--detach',reference],'capstone-checkout',tree);baseline_tree=sp.check_output(['git','write-tree'],cwd=tree,text=True).strip();assert baseline_tree==json.loads((r/'candidate.json').read_text())['baseline_tree'];save('baseline-tree.json',dict(parent=reference,tree=baseline_tree,published_baseline=True));b=w/'build';run(['cmake','-S',tree,'-B',b,*profile],'configure');evidence={};exe={}
    objects={}
    iterator_shapes={}
    for label in ('integer','prior','scan'):
        if label=='aa':
            exe[label]=w/'baseline-copy';shutil.copy2(exe['integer'],exe[label]);continue
        patches=[] if label=='integer' else [r/({'aligned':'alignment.patch','output':'dispatch.patch','isolated':'isolated.patch','prior':'prior.patch','scan':'scan.patch'}[label])]
        for patch in patches: run(['git','apply',patch],'apply-'+label+'-'+patch.stem,tree)
        if label!='integer':
            metadata=json.loads((r/('prior.json' if label=='prior' else 'candidate.json')).read_text())
            run(['git','add','-A'],'stage-'+label,tree)
            assert sp.check_output(['git','write-tree'],cwd=tree,text=True).strip()==metadata['tree']
            assert sha(r/('prior.patch' if label=='prior' else 'scan.patch'))==metadata['sha256']
            save('tested-'+label+'-source.json',dict(tree=metadata['tree'],patch_sha256=metadata['sha256']))
        run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build-'+label)
        if label != 'integer':
            probe = w/'native-plan-policy.c'
            probe.write_text('#include "arch/X86/X86SimpleOutput.h"\n#if !defined(CAPSTONE_X86_VEX32_OUTPUT) || X86_PLAN_VEX32 != X86_PLAN_VECTOR\n#error Expected active ELF Clang x64 C5/32 vector plan\n#endif\n')
            run([os.environ['CC'], '-E', '-P', '-I', tree, '-I', tree/'include', probe], 'native-plan-policy')
            save(label+'-native-plan-policy.json', dict(active=True, selector='X86_PLAN_VECTOR', policy='Native ELF Clang x64 target macros; no forced feature define'))
        objroot=b/'CMakeFiles/capstone.dir'
        objects[label]={str(path.relative_to(objroot)):sha(path) for path in objroot.rglob('*.o')}
        assert len(objects[label])>30

        if label == 'integer' and os.environ['CC'] == 'clang':
            import shlex
            commands = sp.check_output(['ninja','-C',b,'-t','commands'],text=True).splitlines()
            parsed = [shlex.split(line) for line in commands if ' -c ' in line]
            matching = [args for args in parsed
                        if Path(args[args.index('-c')+1]).name == 'X86OutputIterator.c']
            assert len(matching) == 1, matching
            command = matching[0]
            output = w/'baseline-conditional-plan.o'
            for option, value in [('-o',str(output)),('-MF',str(output)+'.d'),('-MT',str(output))]:
                if option in command: command[command.index(option)+1] = value
            command.append('-fno-jump-tables')
            run(command,'baseline-plan-policy',b)
            identical = sha(output) == sha(objroot/'arch/X86/X86OutputIterator.c.o')
            save('baseline-plan-policy.json',dict(compiler='clang',flag='-fno-jump-tables',
                 baseline_object_identical=identical,source_object_sha256=sha(objroot/'arch/X86/X86OutputIterator.c.o'),
                 conditional_object_sha256=sha(output)))
        if label!='integer':
            changed={n for n in objects['integer']if objects[label].get(n)!=objects['integer'][n]}
            added=set(objects[label])-set(objects['integer'])
            expected={'arch/X86/X86OutputIterator.c.o', 'arch/X86/X86VectorOutput.c.o'}
            expected_added={'arch/X86/X86Vex32Output.c.o'}
            assert changed==expected and added==expected_added,(label,changed,added)
            save('objects-'+label+'.json',dict(changed=sorted(changed),added=sorted(added),total=len(objects[label])))
        if label == 'scan':
            assert set(objects['prior']) == set(objects['scan'])
            delta={name for name,value in objects['prior'].items() if value!=objects['scan'][name]}
            assert delta=={'arch/X86/X86Vex32Output.c.o'},delta
            save('prior-isolation.json',dict(changed=sorted(delta),all_other_runtime_objects_identical=True))
        for component in ('X86Disassembler','X86Mapping','X86OutputIterator','X86DisassemblerDecoder','X86VectorOutput','X86ImmediateOutput'):
            object_file=objroot/'arch/X86'/(component+'.c.o')
            assembly=sp.check_output(['objdump','-dr',object_file])
            with gzip.open(p/'evidence'/(label+'-'+component+'.asm.gz'),'wb') as stream:
                stream.write(assembly)
        if label != 'integer':
            object_file = objroot / 'arch/X86/X86Vex32Output.c.o'
            with gzip.open(p/('evidence/'+label+'-X86Vex32Output.asm.gz'), 'wb') as stream:
                stream.write(sp.check_output(['objdump', '-dr', object_file]))
            (p/('evidence/'+label+'-leaf-sections.txt')).write_bytes(sp.check_output(['readelf', '-WS', object_file]))
        code=inc.replace('#include <capstone/capstone.h>','#include <capstone/capstone.h>\n#include "X86ScanAdapter.h"');old='bool ok = cs_disasm_iter(handle, &cursor, &left, &ip, insn);';assert code.count(old)==1;code=code.replace(old,'bool ok = mode ? X86_disasmIter(handle,&cursor,&left,&ip,insn) : cs_disasm_iter(handle,&cursor,&left,&ip,insn);');(w/'owned.cpp').write_text(code);obj=w/'owned.o';run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include','-I',tree/'arch/X86','-c',w/'owned.cpp','-o',obj],'owned-driver-'+label)
        target=w/('run-'+label);run(['clang++',obj,b/'libcapstone.a',ad/'target/release/libiced_compare.a','-lpthread','-ldl','-lm','-o',target],'link-'+label);exe[label]=target
        import re
        asm=sp.check_output(['objdump','-d','--no-show-raw-insn',target],text=True)
        block=re.search(r'^[0-9a-f]+ <X86_disasmIter>:\n(.*?)(?=^[0-9a-f]+ <|\Z)',asm,re.M|re.S).group(1)
        shape=[]
        for line in block.splitlines():
            match=re.match(r'\s*[0-9a-f]+:\s+(.*)',line)
            if not match:continue
            instruction=match[1].split('#',1)[0].strip()
            instruction=re.sub(r'\b[0-9a-f]+ <([^>]+)>',r'<\1>',instruction)
            instruction=re.sub(r'-?0x[0-9a-f]+(?=\(%rip\))','<relative>',instruction)
            instruction=re.sub(r'\s+',' ',instruction)
            shape.append(instruction)
        iterator_shapes[label]=shape
        save('iterator-shape.json',dict(scope='Linked instruction sequence with external PC-relative addresses normalized; structural comparison, not semantic proof.',counts={k:len(v)for k,v in iterator_shapes.items()},equal_to_baseline={k:v==iterator_shapes['integer']for k,v in iterator_shapes.items()}))
        (p/'evidence'/(label+'-iterator-shape.txt')).write_text('\n'.join(shape)+'\n')
        save('object-digests.json',objects)
        symbols=sp.check_output(['nm','-n','-S','--defined-only',target],text=True)
        (p/'evidence'/(label+'-symbols.txt')).write_text(symbols)
        (p/'evidence'/(label+'-sections.txt')).write_bytes(sp.check_output(['readelf','-WS',target]))
        with gzip.open(p/'evidence'/(label+'-linked-assembly.gz'),'wb')as out:out.write(sp.check_output(['objdump','-dr',target]))

        if label == 'scan':
            iterator_source = tree/'arch/X86/X86OutputIterator.c'
            with iterator_source.open('a') as stream:
                stream.write('\nbool census_output(csh h,const uint8_t*p,size_t n,cs_insn*i){uint16_t len;return X86_trySimpleOutput((cs_struct*)(uintptr_t)h,p,n,i,&len);}\n')
            run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'candidate-census-build')
            run(['clang++','-O2','-std=c++17','-I',tree/'include',r/'census.cpp',b/'libcapstone.a','-o',w/'candidate-census'],'candidate-census-link')
        run(['git','read-tree','--reset','-u',baseline_tree],'restore-'+label,tree)
        run(['git','clean','-fdx'],'remove-generated-'+label,tree)
        assert not sp.check_output(['git','-C',tree,'diff','--name-only',baseline_tree])
        assert sp.check_output(['git','-C',tree,'write-tree'],text=True).strip()==baseline_tree
    with (tree/'arch/X86/X86OutputIterator.c').open('a')as f:f.write('\nbool census_output(csh h,const uint8_t*p,size_t n,cs_insn*i){uint16_t len;return X86_trySimpleOutput((cs_struct*)(uintptr_t)h,p,n,i,&len);}\n')
    run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'census-build')
    run(['clang++','-O2','-std=c++17','-I',tree/'include',r/'census.cpp',b/'libcapstone.a','-o',w/'census'],'census-link')
    import deb
    run(['clang++','-O2','-I',base/'include',r/'vectors.cpp',b/'libcapstone.a','-o',w/'vectors'],'vectors');reported=[];manifest={}
    from hardware import Counters
    counters = Counters(p / "evidence", save)
    costs=[]
    for name,bits,f,spans,source in deb.prepare(w):
        assert bits in (32,64)
        if name not in ('libjpeg62-turbo-amd64','jpeg-avx2-i386','libssl3t64-i386','libssl3t64-amd64'):continue
        intervals=w/(name+'.tsv');intervals.write_text(''.join('%d %d %d\n'%v for v in spans));raw=sp.check_output([exe['integer'],'audit','0','1',f,intervals,str(bits)],text=True);rows=[list(map(int,x.split())) for x in raw.splitlines()];views=[list(map(int,x.split()))for x in sp.check_output([w/'vectors',str(bits),f,intervals],text=True).splitlines()];assert len(views)==len(rows)==len(spans)
        common=[(q[:3],vw)for q,vw in zip(rows,views)if q[1]==q[5]];assert common
        manifest[name]=dict(source,common_functions=len(common),common_bytes=sum(z[0][1]for z in common),host=platform.platform(),iced_revision=iced,selection='all FDE and symbol extents with identical instruction boundaries; SIMD subset has at least 8 explicit vector-register instructions and at least 15% vector instructions')
        for panel in (['simd-functions'] if name in ('libjpeg62-turbo-amd64','jpeg-avx2-i386','libssl3t64-amd64') else ['all-functions']):
            sel=[a for a,v in common if panel=='all-functions' or (v[1]>=8 and v[1]>=0.15*v[0])];manifest[name][panel]=dict(functions=len(sel),bytes=sum(z[1]for z in sel));save('provenance.json',manifest)
            if name=='jpeg-avx2-i386':assert sel,(name,manifest[name])
            if not sel:continue
            intervals.write_text(''.join('%d %d %d\n'%tuple(q) for q in sel))
            rows=sp.check_output([w/'census',f,intervals,str(bits)],text=True).splitlines()
            counts=sorted([(int(x.split(' ',1)[0]),x.split(' ',1)[1]) for x in rows],reverse=True)
            save('baseline-coverage-'+name+'-'+panel+'.json',dict(total=sum(c for c,k in counts),handled=sum(c for c,k in counts if k.startswith('hit ')),forms=counts))
            candidate_rows=sp.check_output([w/'candidate-census',f,intervals,str(bits)],text=True).splitlines()
            candidate_counts=sorted([(int(x.split(' ',1)[0]),x.split(' ',1)[1]) for x in candidate_rows],reverse=True)
            assert sum(c for c,k in candidate_counts)==sum(c for c,k in counts)
            save('candidate-coverage-'+name+'-'+panel+'.json',dict(total=sum(c for c,k in candidate_counts),handled=sum(c for c,k in candidate_counts if k.startswith('hit ')),forms=candidate_counts))

            for profile_mode in (0,1,2):
             reference_record=None
             engines=['capstone','prior','scan']
             for key in engines:
                 args=[str(exe[{'candidate':'output','prior':'prior','scan':'scan'}.get(key,'integer')]),'capstone',str(profile_mode),'1',str(f),str(intervals),str(bits)]
                 observation=list(map(int,sp.check_output(args,text=True).split()))
                 assert len(observation)==6
                 if reference_record is None:reference_record=observation[2:5]
                 assert observation[2:5]==reference_record,(name,profile_mode,key,observation,reference_record)
                 if key=='capstone':baseline_record=observation[2:]
                 if key in ('candidate','prior','scan'):assert observation[2:]==baseline_record,(name,profile_mode,observation,baseline_record)
                 ident=name+'-'+str(profile_mode)+'-'+key
                 counters.measure(ident, args, observation[0])
                 raw=w/(ident+'.callgrind')
                 toggle='timed pass after one full warm-up; client request controlled'
                 run(['valgrind','--tool=callgrind','--cache-sim=yes','--branch-sim=yes','--dump-instr=yes','--collect-jumps=yes','--collect-atstart=no','--callgrind-out-file='+str(raw),*args],'profile-'+ident)
                 payload=raw.read_bytes();lines=payload.decode().splitlines()
                 positions=next(line for line in lines if line.startswith('positions:'))
                 assert 'instr' in positions,positions
                 events=next(line.split()[1:]for line in lines if line.startswith('events:'))
                 totals=next(line.split()[1:]for line in lines if line.startswith('summary:'))
                 counts=dict(zip(events,map(int,totals)));assert counts['Ir']>0
                 costs.append(dict(case=name,panel=panel,mode=profile_mode,variant=key,counts=counts,instructions=observation[2],rejected=observation[3],boundaries=observation[4],scope=toggle,captured_passes=1,cold_initialization_included=False,positions=positions))
                 save('instruction-costs.json',costs)
                 for inclusive in ('yes','no'):
                     (p/'evidence'/(ident+'-'+inclusive+'.txt')).write_bytes(sp.check_output(['callgrind_annotate','--inclusive='+inclusive,'--tree=both','--threshold=99.9','--auto=no',raw]))
                 with gzip.open(p/'evidence'/(ident+'.callgrind.gz'),'wb')as out:out.write(payload)
                 raw.unlink()
            print(name,panel,len(sel),flush=True)
    save('complete.json',dict(traces=len(costs),success=True,native_qualification=False))
w=Path(tempfile.mkdtemp(prefix='capstone-iced-formatters-'))
try:
    if hasattr(os,'sched_setaffinity'): os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    main(w)
finally:
    files=[v for v in w.rglob('*') if v.is_file()];amount=sum(v.stat().st_size for v in files);shutil.rmtree(w);save('cleanup.json',dict(removed=not w.exists(),bytes=amount,files=len(files)))
