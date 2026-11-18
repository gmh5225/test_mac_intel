"""Measure exact, common-boundary PE function bodies and three additional ELF text sections."""
from pathlib import Path
import gzip, os, shlex, platform, hashlib, importlib.util, json, math, shutil, statistics, subprocess as sp, tempfile
from layout import ordinary_text_proof, linked_layout
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
    save('variants.json',dict(control='byte-identical baseline copy',integer='Released four-backend Capstone, revision '+reference,aa='byte-identical reference',plan32='Two existing plan cells select guarded VEX32 output; preserve original iterator text, option ownership and the vector core',iced='NeverSight iced IntelFormatter',fast='NeverSight iced FastFormatter'))
    save('entrypoints.json',dict(scan='cs_disasm_iter',format='X86_disasmIter',detail='X86_disasmIter',consumer='Physical X86_disasmIter output entry; actual NeverD product qualification is separate'))
    inc=(r/'driver.cpp').read_text().replace('size_t iced_trace(const','size_t iced_trace(unsigned, const').replace('if(argc!=6)','if(argc!=7)').replace('  csh handle=0;','  unsigned bits=std::stoul(argv[6]);\n  csh handle=0;').replace('cs_open(CS_ARCH_X86,CS_MODE_64,','cs_open(CS_ARCH_X86,bits==32?CS_MODE_32:CS_MODE_64,').replace('iced_create(64,mode)','iced_create(bits,mode)').replace('iced_trace(ptr,','iced_trace(bits,ptr,')
    inc=inc.replace('iced_create(bits,mode)','iced_create(bits,mode | (engine=="fast" ? 8 : 0))').replace('engine!="capstone" && engine!="iced"','engine!="capstone" && engine!="iced" && engine!="fast"')
    inc=inc.replace('if (mode>2 ||','if (mode>4 ||').replace('mode==2 ? CS_OPT_ON','mode>=2 ? CS_OPT_ON')
    inc=inc.replace('if (mode == 2) {','if (mode == 2 || mode == 4) {\n        if (mode == 2) {').replace('        const auto &x = insn->detail->x86;', '        }\n        const auto &x = insn->detail->x86;')
    old_engine='std::string engine=argv[1];';assert inc.count(old_engine)==1
    inc=inc.replace(old_engine,old_engine+'\n  if(engine=="iced____") engine="iced"; else if(engine=="fast____") engine="fast";')
    assert inc.count('iced_trace(bits,ptr,')==1
    (w/'functions.cpp').write_text(inc);run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include','-c',w/'functions.cpp','-o',w/'driver.o'],'driver')
    profile=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+os.environ['CC'],'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ['X86','ARM','AARCH64','MIPS']],'-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer '+('-Wno-error=discarded-qualifiers' if os.environ['CC']=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON']
    tree=w/'tree';run(['git','clone','-q','--shared','--no-checkout',base,tree],'capstone-clone');run(['git','checkout','-q','--detach',reference],'capstone-checkout',tree);b=w/'build';run(['cmake','-S',tree,'-B',b,*profile],'configure');evidence={};exe={}
    objects = {}
    inputs = json.loads((r/'candidate.json').read_text())
    shim = (r/'owned-shim.txt').read_text()
    for label in ('integer','plan32'):
        if label != 'integer':
            assert sha(r/'candidate.patch') == inputs['sha256']
            run(['git','apply','--index',r/'candidate.patch'],'apply-plan32',tree)
        expected = reference + '^{tree}' if label == 'integer' else inputs['tree']
        expected = sp.check_output(['git','rev-parse',expected],cwd=tree,text=True).strip()
        tested = sp.check_output(['git','write-tree'],cwd=tree,text=True).strip()
        assert tested == expected
        save(label+'-tested-source.json',dict(tree=tested,patch_sha256=None if label=='integer' else inputs['sha256']))
        units=['x86_simple_output','x86_reg_access','x86_buffer_bounds','x86_encoding_accuracy','x86_scan_batch','detail_option','x86_evex_reserved_fields','x86_packed_move_access','x86_memory_scale']
        units=sorted(set(units+['api','text_option','aarch64_scan','arm_post_index','aarch64_postprocess','mips_scan','mapping','register_descriptors','sstream','x86_kmask_access','x86_kmask_width','x86_diet_feature_details','x86_printer_prechecked']) | {f.stem for f in (tree/'tests/unit').glob('x86_*.c') if f.stem.startswith(('x86_apx','x86_amx','x86_evex'))})
        run(['cmake','--build',b,'--target','capstone_static','capstone_shared',*units,'--parallel','4'],'build-'+label)
        run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$'],'units-'+label)
        objroot = b/'CMakeFiles/capstone.dir'
        objects[label] = {str(f.relative_to(objroot)):sha(f) for f in objroot.rglob('*.o')}
        if label=='integer':shutil.copyfile(objroot/'arch/X86/X86OutputIterator.c.o',w/'base-iterator.o')
        if label != 'integer':
            active=os.environ['CC']=='clang'
            proof=ordinary_text_proof(w/'base-iterator.o',objroot/'arch/X86/X86OutputIterator.c.o',active)
            save('ordinary-text-proof.json',proof);assert proof['passed'],proof
            if active:
                dispatch = sp.check_output(['objdump', '-d', '--disassemble=X86_writeVectorOutputDispatch', objroot/'arch/X86/X86Vex32Output.c.o'], text=True)
                (p/'evidence/selector.asm').write_text(dispatch)
                import re
                lines = dispatch.split('<X86_writeVectorOutputDispatch>:', 1)[1].splitlines()
                forbidden = [line for line in lines if re.search(r'\b(?:pushq?|popq?|callq?|retq?|enter|leave)\b', line) or re.search(r'\b(?:sub|add)\s+.*%rsp', line)]
                save('selector-proof.json', dict(no_frame_or_calls=not forbidden, forbidden=forbidden))
                assert not forbidden, forbidden
            changed=[n for n in objects['integer'] if objects['plan32'].get(n)!=objects['integer'][n]]
            assert set(changed) == ({'arch/X86/X86OutputIterator.c.o'} if active else set()),changed
            assert set(objects['plan32'])-set(objects['integer']) == {'arch/X86/X86Vex32Output.c.o'}
            assert set(objects['integer']) <= set(objects['plan32'])
            save('object-isolation.json',dict(changed=changed,added=sorted(set(objects['plan32'])-set(objects['integer'])),unchanged=len(objects['integer'])-len(changed)))
        save('object-digests.json',objects)
        with gzip.open(p/'evidence'/(label+'-vector-object.asm.gz'),'wb') as stream:
            stream.write(sp.check_output(['objdump','-dr',objroot/'arch/X86/X86VectorOutput.c.o']))
        if label=='plan32':
            old=gzip.decompress((p/'evidence/integer-vector-object.asm.gz').read_bytes())
            new=gzip.decompress((p/'evidence/plan32-vector-object.asm.gz').read_bytes())
            normalized=new
            save('vector-core-identity.json',dict(entire_disassembly_identical=old==normalized,before_sha256=hashlib.sha256(old).hexdigest(),after_normalized_sha256=hashlib.sha256(normalized).hexdigest()))
            assert old==normalized, 'The isolated mode prototype changed the existing vector core'
            with gzip.open(p/'evidence/plan32-dispatch-object.asm.gz','wb') as stream:
                stream.write(sp.check_output(['objdump','-dr',objroot/'arch/X86/X86Vex32Output.c.o']))

        code=inc.replace('#include <capstone/capstone.h>','#include <capstone/capstone.h>\n#include "X86ScanAdapter.h"')
        old='bool ok = cs_disasm_iter(handle, &cursor, &left, &ip, insn);'
        assert code.count(old)==1
        code=code.replace(old,'bool ok = mode ? X86_disasmIter(handle,&cursor,&left,&ip,insn) : cs_disasm_iter(handle,&cursor,&left,&ip,insn);')
        (w/'owned.cpp').write_text(code)
        obj=w/'owned.o'
        run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include','-I',tree/'arch/X86','-c',w/'owned.cpp','-o',obj],'consumer-'+label)
        if label=='integer': consumer_hash=sha(obj)
        else: assert sha(obj)==consumer_hash
        save('consumer-object.json',dict(sha256=consumer_hash,all_variants_identical=True,source_unchanged=True))
        target=w/('run-'+label)
        run(['clang++',obj,b/'libcapstone.a',ad/'target/release/libiced_compare.a','-lpthread','-ldl','-lm','-Wl,-Map,'+str(p/'evidence'/(label+'-link.map')),'-o',target],'link-'+label)
        exe[label]=target
        (p/'evidence'/(label+'-symbols.txt')).write_bytes(sp.check_output(['nm','-n','-S','--defined-only',target]))
        (p/'evidence'/(label+'-sections.txt')).write_bytes(sp.check_output(['readelf','-WS',target]))
        if label!='integer':
            save('linked-layout.json',linked_layout(p/'evidence/integer-symbols.txt',p/'evidence/plan32-symbols.txt','output'))
            save('binary-identity.json',dict(active=active,identical=sha(exe['integer'])==sha(target)))
            if not active:assert sha(exe['integer'])==sha(target)
        with gzip.open(p/'evidence'/(label+'-linked-disassembly.gz'),'wb') as stream:
            stream.write(sp.check_output(['objdump','-d',target]))
        iterator=tree/'arch/X86/X86OutputIterator.c'
        original=iterator.read_text()
        iterator.write_text(original+shim)
        run(['cmake','--build',b,'--target','capstone_shared','--parallel','4'],'owned-library-'+label)
        shutil.copyfile(b/'libcapstone.so',w/(label+'.so'))
        iterator.write_text(original)
        run(['git','reset','--hard',reference],'restore-'+label,tree)
        assert not sp.check_output(['git','-C',tree,'status','--porcelain'])
    for name in ('verify','private-guard','public-verify'):
        run(['clang++','-O2','-std=c++17','-DACTIVE_OUTPUT='+('1' if os.environ['CC']=='clang' else '0'),'-I',tree/'include',r/(name+'.cpp'),'-ldl','-o',w/name],name+'-link')
        run([w/name,w/'integer.so',w/'plan32.so'],name)
    import frozen_deb as deb
    run(['clang++','-O2','-I',base/'include',r/'vectors.cpp',b/'libcapstone.a','-o',w/'vectors'],'vectors')
    manifest, costs = {}, []
    for name,bits,f,spans,source in deb.prepare(w):
        if name not in ('libjpeg62-turbo-amd64','jpeg-avx2-i386','libssl3t64-i386','libssl3t64-amd64'):continue
        intervals=w/(name+'.tsv')
        intervals.write_text(''.join('%d %d %d\n'%v for v in spans))
        audit=[list(map(int,x.split()))for x in sp.check_output([exe['integer'],'audit','0','1',f,intervals,str(bits)],text=True).splitlines()]
        views=[list(map(int,x.split()))for x in sp.check_output([w/'vectors',str(bits),f,intervals],text=True).splitlines()]
        assert len(audit)==len(views)==len(spans)
        simd=name!='libssl3t64-i386'
        selected=[a[:3]for a,v in zip(audit,views)if a[1]==a[5] and (not simd or (v[1]>=8 and v[1]>=.15*v[0]))]
        assert selected
        intervals.write_text(''.join('%d %d %d\n'%tuple(v)for v in selected))
        manifest[name]=dict(source,functions=len(selected),bytes=sum(x[1]for x in selected),panel='simd-functions' if simd else 'all-functions')
        save('provenance.json',manifest)
        for mode in (0,1,2):
            signatures={}
            for label in ('integer','plan32'):
                ident=name+'-'+str(mode)+'-'+label
                raw=w/(ident+'.callgrind')
                args=[exe[label],'capstone',str(mode),'1',f,intervals,str(bits)]
                native=list(map(int,sp.check_output(args,text=True).split()))
                assert len(native)==6
                signatures[label]=native[2:]
                if label=='plan32':assert signatures['integer']==signatures['plan32']
                run(['valgrind','--tool=callgrind','--demangle=no','--collect-atstart=no','--toggle-collect=_ZZ4mainENK3$_0clEj','--cache-sim=yes','--branch-sim=yes','--dump-instr=yes','--collect-jumps=yes','--callgrind-out-file='+str(raw),*args],'cost-'+ident)
                log=(p/'evidence'/('cost-'+ident+'.log')).read_text()
                result=next(list(map(int,line.split()))for line in log.splitlines()if len(line.split())==6 and all(x.isdigit()for x in line.split()))
                assert result[2:]==signatures[label]
                text=raw.read_text()
                events=next(line[8:].split()for line in text.splitlines()if line.startswith('events: '))
                counts=list(map(int,next(line[8:].split()for line in text.splitlines()if line.startswith('totals: '))))
                assert len(events)==len(counts) and counts[0]>0
                costs.append(dict(case=name,panel=manifest[name]['panel'],mode=mode,variant=label,events=dict(zip(events,counts)),result=result[2:],collected_traversals=2))
                with gzip.open(p/'evidence'/(ident+'.callgrind.gz'),'wb')as stream:stream.write(raw.read_bytes())
                raw.unlink()
                save('instruction-costs.json',costs)
        print(name,'instruction counts complete',flush=True)
    assert len(costs)==24
    save('complete.json',dict(success=True,traces=24,cases=4,unit_checks_per_variant=len(units),native_qualification=False))
w=Path(tempfile.mkdtemp(prefix='capstone-vector-plan32-cost-'))
try:
    if hasattr(os,'sched_setaffinity'):os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    main(w)
finally:
    files=[v for v in w.rglob('*')if v.is_file()]
    amount=sum(v.stat().st_size for v in files)
    shutil.rmtree(w)
    save('cleanup.json',dict(removed=not w.exists(),bytes=amount,files=len(files)))
