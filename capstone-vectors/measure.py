"""Compare real ELF library functions at common boundaries with current forked iced."""
from pathlib import Path
import gzip, os, shlex, platform, hashlib, importlib.util, json, math, shutil, statistics, subprocess as sp, tempfile
from layout import linked_layout
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
    reference=json.loads((r/'experiment.json').read_text())['baseline_commit']
    assert sp.check_output(['git','-C',base,'rev-parse',reference],text=True).strip()==reference
    iced=json.loads((r/'experiment.json').read_text())['iced_revision']
    checkout=w/'iced';checkout.mkdir();tar=w/'iced.tar'
    run(['git','init','--bare',w/'iced-git'],'iced-repo');run(['git','-C',w/'iced-git','fetch','--depth','1','https://github.com/NeverSight/iced.git',iced],'iced-fetch');run(['git','-C',w/'iced-git','archive','--format=tar','-o',tar,iced,'src/rust/iced-x86'],'iced-archive');run(['tar','-xf',tar,'-C',checkout],'iced-extract');tar.unlink()
    ad=w/'adapter';ad.mkdir();src=(lab/'iced.rs').read_text().replace('repeats: u32,\n    output:', 'repeats: u32,\n    ip: u64,\n    output:').replace('bytes, 0x100000,','bytes, ip,').replace('set_ip(0x100000 +','set_ip(ip +')
    src=src.replace('InstructionInfoFactory, IntelFormatter,','InstructionInfoFactory, IntelFormatter, FastFormatter,').replace('    formatter: IntelFormatter,','    formatter: IntelFormatter,\n    fast: FastFormatter,\n    fast_enabled: bool,').replace('        mode,','        mode: mode & 3,\n        fast_enabled: mode & 8 != 0,\n        fast: FastFormatter::new(),')
    old='state.formatter.format(&instruction, &mut state.text);';assert src.count(old)==1;src=src.replace(old,'if state.fast_enabled {state.fast.format(&instruction, &mut state.text);} else {state.formatter.format(&instruction, &mut state.text);}')
    trace=(r/'iced-trace.rs').read_text().replace('iced_trace(input:', 'iced_trace(bits:u32,input:').replace('with_ip(64,','with_ip(bits,');(ad/'iced.rs').write_text(src+trace);shutil.copyfile(lab/'Cargo.lock',ad/'Cargo.lock')
    (ad/'Cargo.toml').write_text('[package]\nname="iced_compare"\nversion="0.1.0"\nedition="2021"\n[lib]\ncrate-type=["staticlib"]\npath="iced.rs"\n[dependencies]\niced-x86={path="../iced/src/rust/iced-x86",default-features=false,features=["std","decoder","intel","instr_info","fast_fmt"]}\n[profile.release]\npanic="abort"\nopt-level=3\n');run(['cargo','build','--locked','--release'],'iced-build',ad)
    save('cpu.json',dict(cpu=Path('/proc/cpuinfo').read_text(),compiler=sp.check_output([os.environ['CC'],'--version'],text=True)))
    save('variants.json',dict(integer='Four-backend baseline tree '+json.loads((r/'experiment.json').read_text())['baseline_tree'],aa='Byte-identical baseline copy',route='Public path with the GNU/Clang i386 writer',vector='Same public output plus 32-bit VEX scanning at the generic fallback call',iced='NeverSight compatibility branch iced '+iced+' IntelFormatter',fast='NeverSight iced '+iced+' FastFormatter'))
    save('iced-source.json',dict(revision=iced,source='https://github.com/NeverSight/iced.git',built_from_source=True,adapter_source_sha256=sha(ad/'iced.rs'),cargo_lock_sha256=sha(ad/'Cargo.lock')))
    save('entrypoints.json',dict(scan='cs_disasm_iter',format='cs_disasm_iter',detail='cs_disasm_iter',consumer='Common public iterator for every mode; actual NeverD product and private-entry qualification is separate'))
    inc=(r/'driver.cpp').read_text().replace('size_t iced_trace(const','size_t iced_trace(unsigned, const').replace('if(argc!=6)','if(argc!=7)').replace('  csh handle=0;','  unsigned bits=std::stoul(argv[6]);\n  csh handle=0;').replace('cs_open(CS_ARCH_X86,CS_MODE_64,','cs_open(CS_ARCH_X86,bits==32?CS_MODE_32:CS_MODE_64,').replace('iced_create(64,mode)','iced_create(bits,mode)').replace('iced_trace(ptr,','iced_trace(bits,ptr,')
    inc=inc.replace('iced_create(bits,mode)','iced_create(bits,mode | (engine=="fast" ? 8 : 0))').replace('engine!="capstone" && engine!="iced"','engine!="capstone" && engine!="iced" && engine!="fast"')
    inc=inc.replace('if (mode>2 ||','if (mode>4 ||').replace('mode==2 ? CS_OPT_ON','mode>=2 ? CS_OPT_ON')
    inc=inc.replace('if (mode == 2) {','if (mode == 2 || mode == 4) {\n        if (mode == 2) {').replace('        const auto &x = insn->detail->x86;', '        }\n        const auto &x = insn->detail->x86;')
    old_engine='std::string engine=argv[1];';assert inc.count(old_engine)==1
    inc=inc.replace(old_engine,old_engine+'\n  if(engine=="iced____") engine="iced"; else if(engine=="fast____") engine="fast";')
    assert inc.count('iced_trace(bits,ptr,')==1
    assert inc.count('Result timed=run(reps);')==inc.count('Result warm=run(1);')==1
    inc='#include <valgrind/callgrind.h>\n'+inc.replace('Result warm=run(1);','CALLGRIND_START_INSTRUMENTATION; Result warm=run(1);').replace('Result timed=run(reps);','CALLGRIND_ZERO_STATS; Result timed=run(reps); CALLGRIND_STOP_INSTRUMENTATION;')
    (w/'functions.cpp').write_text(inc);run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include','-c',w/'functions.cpp','-o',w/'driver.o'],'driver')
    profile=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+os.environ['CC'],'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ['X86','ARM','AARCH64','MIPS']],'-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer '+('-Wno-error=discarded-qualifiers' if os.environ['CC']=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON']
    tree=w/'tree';run(['git','clone','-q','--shared','--no-checkout',base,tree],'capstone-clone');run(['git','checkout','-q','--detach',reference],'capstone-checkout',tree);b=w/'build';run(['cmake','-S',tree,'-B',b,*profile],'configure');evidence={};exe={}
    objects={}
    inputs=json.loads((r/'experiment.json').read_text())
    for label in ('integer','aa','route','vector'):
        if label=='aa':
            exe[label]=w/'baseline-copy';shutil.copy2(exe['integer'],exe[label]);continue
        if label!='integer':
            patch=r/(label+'.patch')
            assert sha(patch)==inputs['variants'][label]['sha256']
            run(['git','apply',patch],'apply-'+label,tree)
        run(['git','add','-A'],'stage-source-'+label,tree)
        tested=sp.check_output(['git','write-tree'],cwd=tree,text=True).strip()
        expected=inputs['baseline_tree'] if label=='integer' else inputs['variants'][label]['tree']
        assert tested==expected,(label,tested,expected)
        save(label+'-tested-source.json',dict(tree=tested,patch_sha256=None if label=='integer' else sha(patch)))
        run(['cmake','--build',b,'--target','capstone_static','--parallel','4'],'build-'+label)
        objroot=b/'CMakeFiles/capstone.dir'
        members=sp.check_output(['ar','t',b/'libcapstone.a'],text=True).splitlines()
        assert len(set(members))==len(members)
        active={str(path.relative_to(objroot)):path for path in objroot.rglob('*.o') if path.name in members}
        assert len(active)==len(members)
        objects[label]={name:sha(path) for name,path in active.items()}
        assert len(objects[label])>30
        if label=='integer':
            shutil.copyfile(objroot/'arch/X86/X86OutputIterator.c.o',w/'baseline-plan.o')
        else:
            changed={name for name,value in objects['integer'].items() if objects[label].get(name)!=value}
            added=set(objects[label])-set(objects['integer'])
            expected_changed = {'arch/X86/X86OutputIterator.c.o','arch/X86/X86DisassemblerDecoder.c.o'}
            expected_added = {'arch/X86/X86Vex32Output.c.o'}
            assert added == expected_added, (label, added)
            assert expected_changed <= changed <= expected_changed | {'arch/X86/X86VectorOutput.c.o'}, (label, changed)
            if label == 'vector':
                diff=sorted(k for k in objects[label] if objects[label][k]!=objects['route'][k])
                wanted=['arch/X86/X86DisassemblerDecoder.c.o']
                assert diff==wanted,(diff,wanted)
                save('compiler-scope.json',dict(changed=diff, total=len(objects[label])))
                run(['python3','-B',tree/'suite/synctools/x86_operand_specializations.py','--check'],'vex-scan-rows')

                for tool, jobs in [('x86_simple_output', [([], 'X86GenSimpleOutput.inc')]), ('x86_vector_output', [(['--vex32-memory'], 'X86GenVex32MemoryOutput.inc'), (['--vex-pairs32'], 'X86GenVex32PairOutput.inc')])]:
                    run(['clang++','-O2','-std=c++17','-I',tree/'include',tree/'suite/synctools'/(tool+'.cpp'),b/'libcapstone.a','-o',w/tool], 'build-generator-'+tool)
                    for options, name in jobs:
                        with (p/'evidence'/('generate-'+name+'.log')).open('wb') as log:
                            out = sp.check_output([w/tool,*options],stderr=log)
                        assert out == (tree/'arch/X86'/name).read_bytes(), name
                save('generated-tables.json', {name:sha(tree/'arch/X86'/name) for name in ('X86GenSimpleOutput.inc','X86GenVex32MemoryOutput.inc','X86GenVex32PairOutput.inc')})
            save(label+'-object-isolation.json',dict(changed=sorted(changed),added=sorted(added),unchanged=len(objects['integer'])-len(changed)))
        save('object-digests.json',objects)
        obj=w/'driver.o'
        unresolved=sp.check_output(['nm','-u',obj],text=True)
        assert 'cs_disasm_iter' in unresolved and 'X86_disasmIter' not in unresolved
        if label=='integer':consumer_hash=sha(obj)
        else:assert sha(obj)==consumer_hash
        save('consumer-object.json',dict(sha256=consumer_hash,all_variants_identical=True))
        target=w/('run-'+label);run(['clang++',obj,b/'libcapstone.a',ad/'target/release/libiced_compare.a','-lpthread','-ldl','-lm','-o',target],'link-'+label);exe[label]=target
        run(['git','reset','--hard',reference],'restore-'+label,tree)
        run(['git','clean','-fdx'],'remove-generated-'+label,tree)
        assert not sp.check_output(['git','-C',tree,'status','--porcelain'])
    exe['iced']=exe['fast']=exe['integer']
    import frozen_deb as deb
    run(['clang++','-O2','-I',base/'include',r/'vectors.cpp',b/'libcapstone.a','-o',w/'vectors'],'vectors');reported=[];manifest={}
    run(['clang++','-O2','-std=c++17','-I',base/'include',r/'prefixes.cpp',b/'libcapstone.a','-o',w/'prefixes'],'prefixes');prefix_census={}
    import observe, profile_costs
    run(['git','apply',r/'vector.patch'],'apply-observer',tree)
    observe.build(tree,b,w/'observer',base,r/'observer.cpp',run)
    columns=['instructions','scan_fallback','generic_result','generic_decode','feature_slow','evex_fast_success']
    save('observed-fields.json',dict(columns=columns,scope='Single untimed copy of the exact candidate. Counts increment at actual function entry or the compact EVEX success. Last-byte register/memory labels are the encoded ModRM for bare vector forms.'))
    all_costs=[]
    import pe_panels, itertools
    for name,bits,f,spans,source in itertools.chain(deb.prepare(w),pe_panels.prepare(w)):
        if name not in ('libjpeg62-turbo-amd64','libssl3t64-amd64','putty-32-0.85'):continue
        intervals=w/(name+'.tsv');intervals.write_text(''.join('%d %d %d\n'%v for v in spans));raw=sp.check_output([exe['integer'],'audit','0','1',f,intervals,str(bits)],text=True);rows=[list(map(int,x.split())) for x in raw.splitlines()];views=[list(map(int,x.split()))for x in sp.check_output([w/'vectors',str(bits),f,intervals],text=True).splitlines()];assert len(views)==len(rows)==len(spans)
        common=[(q[:3],vw)for q,vw in zip(rows,views)if q[1]==q[5]];assert common
        manifest[name]=dict(source,common_functions=len(common),common_bytes=sum(z[0][1]for z in common),host=platform.platform(),iced_revision=iced,selection='all FDE and symbol extents with identical instruction boundaries; SIMD subset has at least 8 explicit vector-register instructions and at least 15% vector instructions')
        if name.startswith('putty-'):
            assert len(common)==1 and common[0][0][1]==f.stat().st_size if bits==32 else len(common)>150
            manifest[name]['selection']=source['extent_source']+'; require bytewise identical acceptance and boundaries over each retained extent'
        for panel in (['whole-text' if bits==32 else 'runtime-functions'] if name.startswith('putty-') else ['all-functions','simd-functions'] if name in ('libjpeg62-turbo-amd64','libzstd1-amd64') else (['all-functions'] if name=='libssl3t64-i386' else ['simd-functions'])):
            if panel=='all-functions':continue
            sel=[a for a,v in common if panel in ('all-functions','whole-text','runtime-functions') or (v[1]>=8 and v[1]>=0.15*v[0])];manifest[name][panel]=dict(functions=len(sel),bytes=sum(z[1]for z in sel));save('provenance.json',manifest)
            if name=='jpeg-avx2-i386' or name.startswith('putty-'):assert sel,(name,manifest[name])
            if not sel:continue
            intervals.write_text(''.join('%d %d %d\n'%tuple(q) for q in sel))
            prefix_census[name+'/'+panel]=json.loads(sp.check_output([w/'prefixes',str(bits),f,intervals],text=True));save('prefix-census.json',dict(counts=prefix_census,scope='One linear pass over selected benchmark function extents; overlapping extents count as the benchmark does. Bare prefix counts are not packed-reader hit counts or application runtime frequencies.'))
            obs=sp.check_output([w/'observer',str(bits),f,intervals],text=True)
            stages={}
            for line in obs.splitlines():
                fields=line.split('\t')
                assert len(fields)==7 and fields[0] not in stages
                stages[fields[0]]=list(map(int,fields[1:]))
            census=prefix_census[name+'/'+panel]
            assert sum(v[0] for v in stages.values())==census['decoded']+census['invalid_bytes']
            save(name+'-stages.json',dict(columns=columns,mnemonics=stages))
            for mode in (0,1,2):
                results={}
                for label in ['integer','vector','iced']+(['fast'] if mode else []):
                    engine=label+'____' if label in ('fast','iced') else 'capstone'
                    fn=name+'-'+str(mode)+'-'+label
                    trace=w/'tr';args=['valgrind','--tool=callgrind','--instr-atstart=no','--cache-sim=yes','--branch-sim=yes','--callgrind-out-file='+str(trace),str(exe[label]),engine,str(mode),'1',str(f),str(intervals),str(bits)]
                    with (p/'evidence'/(fn+'.log')).open('w') as stream:
                        value=list(map(int,sp.check_output(args,stderr=stream,text=True).split()))
                    assert len(value)==6
                    results[label]=value[2:]
                    profile=profile_costs.parse(trace)
                    assert profile['totals'][0]>0 and value[2]==census['decoded'] and value[3]==census['invalid_bytes']
                    with trace.open('rb') as src, gzip.open(p/'evidence'/(fn+'.callgrind.gz'),'wb',compresslevel=3) as dst:shutil.copyfileobj(src,dst)
                    trace.unlink()
                    save(fn+'-cost.json',profile)
                    all_costs.append(dict(case=name,panel=panel,mode=mode,engine=label,events=profile['events'],totals=profile['totals'],records=value[2:],functions=len(profile['functions']),trace=fn+'.callgrind.gz',top=profile['functions'][:12]))
                assert len({tuple(v[:3]) for v in results.values()})==1 and results['integer']==results['vector']
            print(name,panel,flush=True)
            save('profile-index.json',all_costs)
    assert len(all_costs)==33 and len(manifest)==3
    save('complete.json',dict(cases=len(all_costs),source=inputs,consumer=consumer_hash,method='One warmed traversal under Callgrind zeroed at the timed-loop boundary. Guest work, read/write and simulated cache/branch events; wall times are from the independent native run.'))
w=Path(tempfile.mkdtemp(prefix='capstone-vex32-iced-'))
try:
    if hasattr(os,'sched_setaffinity'): os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    main(w)
finally:
    files=[v for v in w.rglob('*') if v.is_file()];amount=sum(v.stat().st_size for v in files);shutil.rmtree(w);save('cleanup.json',dict(removed=not w.exists(),bytes=amount,files=len(files)))
