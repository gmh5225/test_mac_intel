"""Measure exact, common-boundary PE function bodies and three additional ELF text sections."""
from pathlib import Path
import gzip, os, shlex, platform, hashlib, importlib.util, json, math, shutil, statistics, subprocess as sp, tempfile
from layout import object_proof, linked_layout
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
    reference=json.loads((r/'inputs.json').read_text())['baseline_commit']
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
    save('variants.json',dict(control='byte-identical baseline copy',integer='Released four-backend Capstone, revision '+reference,aa='byte-identical reference',scan='Separate canonical transfer helper',merge='Shared register and transfer plan dispatch',iced='NeverSight iced IntelFormatter',fast='NeverSight iced FastFormatter'))
    save('entrypoints.json',dict(scan='cs_disasm_iter',format='X86_disasmIter',detail='X86_disasmIter',consumer='Physical X86_disasmIter output entry; actual NeverD product qualification is separate'))
    inc=(r/'driver.cpp').read_text().replace('size_t iced_trace(const','size_t iced_trace(unsigned, const').replace('if(argc!=6)','if(argc!=7)').replace('  csh handle=0;','  unsigned bits=std::stoul(argv[6]);\n  csh handle=0;').replace('cs_open(CS_ARCH_X86,CS_MODE_64,','cs_open(CS_ARCH_X86,bits==32?CS_MODE_32:CS_MODE_64,').replace('iced_create(64,mode)','iced_create(bits,mode)').replace('iced_trace(ptr,','iced_trace(bits,ptr,')
    inc=inc.replace('iced_create(bits,mode)','iced_create(bits,mode | (engine=="fast" ? 8 : 0))').replace('engine!="capstone" && engine!="iced"','engine!="capstone" && engine!="iced" && engine!="fast"')
    inc=inc.replace('if (mode>2 ||','if (mode>4 ||').replace('mode==2 ? CS_OPT_ON','mode>=2 ? CS_OPT_ON')
    inc=inc.replace('if (mode == 2) {','if (mode == 2 || mode == 4) {\n        if (mode == 2) {').replace('        const auto &x = insn->detail->x86;', '        }\n        const auto &x = insn->detail->x86;')
    old_engine='std::string engine=argv[1];';assert inc.count(old_engine)==1
    inc=inc.replace(old_engine,old_engine+'\n  if(engine=="iced____") engine="iced"; else if(engine=="fast____") engine="fast";')
    assert inc.count('iced_trace(bits,ptr,')==1
    (w/'functions.cpp').write_text(inc);run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include','-c',w/'functions.cpp','-o',w/'driver.o'],'driver')
    profile=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+os.environ['CC'],'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ['X86','ARM','AARCH64','MIPS']],'-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer '+('-Wno-error=discarded-qualifiers' if os.environ['CC']=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON']
    tree=w/'tree';run(['git','clone','-q','--shared','--no-checkout',base,tree],'capstone-clone');run(['git','checkout','-q','--detach',reference],'capstone-checkout',tree);b=w/'build';run(['cmake','-S',tree,'-B',b,*profile],'configure');evidence={};exe={}
    objects={}
    inputs=json.loads((r/'inputs.json').read_text())
    for label in ('integer','aa','scan','merge'):
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
        units=['x86_simple_output','x86_encoding_accuracy','x86_reg_access','detail_option','text_option','x86_printer_prechecked','x86_buffer_bounds','x86_scan_batch']+[f.stem for f in (tree/'tests/unit').glob('x86_*.c') if f.stem.startswith(('x86_apx','x86_amx','x86_evex'))]
        run(['cmake','--build',b,'--target','capstone_static',*units,'--parallel','4'],'build-'+label)
        run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$'],'units-'+label)
        objroot=b/'CMakeFiles/capstone.dir'
        members=sp.check_output(['ar','t',b/'libcapstone.a'],text=True).splitlines()
        assert len(set(members))==len(members)
        active={str(path.relative_to(objroot)):path for path in objroot.rglob('*.o') if path.name in members}
        assert len(active)==len(members)
        objects[label]={name:sha(path) for name,path in active.items()}
        assert len(objects[label])>30
        if label=='integer':
            shutil.copyfile(objroot/'arch/X86/X86EvexScan.c.o',w/'baseline-plan.o')
        else:
            changed={name for name,value in objects['integer'].items() if objects[label].get(name)!=value}
            added=set(objects[label])-set(objects['integer'])
            assert added==({'arch/X86/X86EvexTransferScan.c.o'} if label=='scan' else set()),added
            assert changed=={'arch/X86/X86EvexScan.c.o'},changed
            proof=object_proof(label,w/'baseline-plan.o',objroot/'arch/X86/X86EvexScan.c.o',objroot/'arch/X86/X86EvexTransferScan.c.o')
            save(label+'-object-isolation.json',dict(changed=sorted(changed),added=sorted(added),unchanged=len(objects['integer'])-len(changed),proof=proof))
        save('object-digests.json',objects)
        for component in ('X86EvexScan',)+(('X86EvexTransferScan',) if label=='scan' else ()):
            with gzip.open(p/'evidence'/(label+'-'+component+'.asm.gz'),'wb') as stream:
                stream.write(sp.check_output(['objdump','-dr',objroot/'arch/X86'/(component+'.c.o')]))
        code=inc.replace('#include <capstone/capstone.h>','#include <capstone/capstone.h>\n#include "X86ScanAdapter.h"');old='bool ok = cs_disasm_iter(handle, &cursor, &left, &ip, insn);';assert code.count(old)==1;code=code.replace(old,'bool ok = mode ? X86_disasmIter(handle,&cursor,&left,&ip,insn) : cs_disasm_iter(handle,&cursor,&left,&ip,insn);');(w/'owned.cpp').write_text(code);obj=w/'owned.o';run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include','-I',tree/'arch/X86','-c',w/'owned.cpp','-o',obj],'owned-driver-'+label)
        if label=='integer':consumer_hash=sha(obj)
        else:assert sha(obj)==consumer_hash
        save('consumer-object.json',dict(sha256=consumer_hash,all_variants_identical=True))
        target=w/('run-'+label);run(['clang++',obj,b/'libcapstone.a',ad/'target/release/libiced_compare.a','-lpthread','-ldl','-lm','-Wl,-Map,'+str(p/'evidence'/(label+'-link.map')),'-o',target],'link-'+label);exe[label]=target
        (p/'evidence'/(label+'-symbols.txt')).write_bytes(sp.check_output(['nm','-n','-S','--defined-only',target]))
        (p/'evidence'/(label+'-sections.txt')).write_bytes(sp.check_output(['readelf','-WS',target]))
        if label!='integer':save(label+'-linked-layout.json',linked_layout(p/'evidence/integer-symbols.txt',p/'evidence'/(label+'-symbols.txt'),label))
        with gzip.open(p/'evidence'/(label+'-linked-disassembly.gz'),'wb')as stream:
            stream.write(sp.check_output(['objdump','-d',target]))
        run(['git','reset','--hard',reference],'restore-'+label,tree)
        run(['git','clean','-fdx'],'remove-generated-'+label,tree)
        assert not sp.check_output(['git','-C',tree,'status','--porcelain'])
    exe['iced']=exe['fast']=exe['integer']
    payloads={key:path.read_bytes()for key,path in exe.items()}
    assert payloads['integer']==payloads['aa']
    maximum=max(map(len,payloads.values()))
    padded={key:value+bytes(maximum-len(value))for key,value in payloads.items()}
    image=w/'same-image';image.write_bytes(padded['integer']);image.chmod(0o755)
    image_inode=image.stat().st_ino
    probe=sp.run(['setarch',platform.machine(),'-R','/bin/true'],capture_output=True,text=True)
    launches=['images']
    if probe.returncode==0:launches.append('same-file-fixed')
    save('launch-controls.json',dict(launches=launches,aslr_disable_returncode=probe.returncode,aslr_disable_stderr=probe.stderr,original_sha256={k:hashlib.sha256(v).hexdigest()for k,v in payloads.items()},padded_sha256={k:hashlib.sha256(v).hexdigest()for k,v in padded.items()},image_inode=image_inode,fixed_size=maximum,equal_length_engine_selectors=True,purpose='Compare both predeclared EVEX transfer implementations, including recorded table relocation, against the same baseline and frozen consumers with original-image and fixed-image controls.'))
    import frozen_deb as deb
    run(['clang++','-O2','-I',base/'include',r/'vectors.cpp',b/'libcapstone.a','-o',w/'vectors'],'vectors');reported=[];manifest={}
    run(['clang++','-O2','-std=c++17','-I',base/'include',r/'prefixes.cpp',b/'libcapstone.a','-o',w/'prefixes'],'prefixes');prefix_census={}
    for name,bits,f,spans,source in deb.prepare(w):
        if name not in ('libjpeg62-turbo-amd64','libzstd1-amd64','libssl3t64-amd64','jpeg-avx2-i386','libssl3t64-i386'): continue
        intervals=w/(name+'.tsv');intervals.write_text(''.join('%d %d %d\n'%v for v in spans));raw=sp.check_output([exe['integer'],'audit','0','1',f,intervals,str(bits)],text=True);rows=[list(map(int,x.split())) for x in raw.splitlines()];views=[list(map(int,x.split()))for x in sp.check_output([w/'vectors',str(bits),f,intervals],text=True).splitlines()];assert len(views)==len(rows)==len(spans)
        common=[(q[:3],vw)for q,vw in zip(rows,views)if q[1]==q[5]];assert common
        manifest[name]=dict(source,common_functions=len(common),common_bytes=sum(z[0][1]for z in common),host=platform.platform(),iced_revision=iced,selection='all FDE and symbol extents with identical instruction boundaries; SIMD subset has at least 8 explicit vector-register instructions and at least 15% vector instructions')
        for panel in (['all-functions','simd-functions'] if name in ('libjpeg62-turbo-amd64','libzstd1-amd64') else (['all-functions'] if name=='libssl3t64-i386' else ['simd-functions'])):
            sel=[a for a,v in common if panel=='all-functions' or (v[1]>=8 and v[1]>=0.15*v[0])];manifest[name][panel]=dict(functions=len(sel),bytes=sum(z[1]for z in sel));save('provenance.json',manifest)
            if name=='jpeg-avx2-i386':assert sel,(name,manifest[name])
            if not sel:continue
            intervals.write_text(''.join('%d %d %d\n'%tuple(q) for q in sel))
            prefix_census[name+'/'+panel]=json.loads(sp.check_output([w/'prefixes',str(bits),f,intervals],text=True));save('prefix-census.json',dict(counts=prefix_census,scope='One linear pass over selected benchmark function extents; overlapping extents count as the benchmark does. Bare prefix counts are not packed-reader hit counts or application runtime frequencies.'))
            for mode in (0,1,2):
                def measure(lib,n,launch):
                    tail=[lib+'____' if lib in ('iced','fast') else 'capstone',str(mode),str(n),str(f),str(intervals),str(bits)]
                    if launch=='images':
                        command=[str(exe[lib]),*tail];executable=None
                    elif launch=='same-argv':
                        command=[str(image),*tail];executable=str(exe[lib])
                    else:
                        with image.open('r+b')as out:
                            assert out.write(padded[lib])==maximum
                        assert image.stat().st_ino==image_inode and image.stat().st_size==maximum
                        command=[str(image),*tail];executable=None
                        if launch=='same-file-fixed':command=['setarch',platform.machine(),'-R',*command]
                    return list(map(int,sp.check_output(command,executable=executable).split()))
                probe=measure('integer',1,'images');rep=max(1,math.ceil(60e6/max(1,probe[0])))
                cycles={launch:[]for launch in launches};labels=['integer','aa','scan','merge','iced']+(['fast'] if mode else [])
                for i in range(21):
                    launch_order=launches[i%len(launches):]+launches[:i%len(launches)]
                    for launch in launch_order:
                        order=labels[i%len(labels):]+labels[:i%len(labels)]
                        obs=[(k,measure(k,rep,launch))for k in order+order[::-1]]
                        assert all(len(v)==6 for k,v in obs)
                        assert len({tuple(v[2:5])for k,v in obs})==1,(name,mode,launch,obs)
                        assert len({tuple(v[2:])for k,v in obs if k not in ('iced','fast')})==1,(name,mode,launch,obs)
                        cycles[launch].append(dict(ns={k:statistics.mean(v[0]/v[2]for who,v in obs if who==k)for k in labels},raw=obs))
                for launch,observations in cycles.items():
                    md=lambda a,b:statistics.median(v['ns'][a]/v['ns'][b]for v in observations)
                    row=dict(case=name,panel=panel,mode=['scan','format','detail'][mode],launch=launch,functions=len(sel),bytes=sum(z[1]for z in sel),repetitions=rep,gain={k:md('integer',k)for k in labels},cycles=observations)
                    row['vs_iced']={k:md('iced',k) for k in ('scan','merge')}
                    row['vs_fast']={k:md('fast',k) for k in ('scan','merge')} if mode else None
                    reported.append(row)
                save('measurements.json',reported)
            print(name,panel,len(sel),flush=True)
    assert len(reported)==21*len(launches)
    # Collect the original consumer lambda by symbol, without inserting client
    # request instructions or changing the original native consumer object.
    costs=[]
    for name,bits,f,spans,source in deb.prepare(w):
        if name!='libssl3t64-amd64': continue
        intervals=w/(name+'-cost.tsv');intervals.write_text(''.join('%d %d %d\n'%v for v in spans))
        audit=[list(map(int,x.split()))for x in sp.check_output([exe['integer'],'audit','0','1',f,intervals,str(bits)],text=True).splitlines()]
        views=[list(map(int,x.split()))for x in sp.check_output([w/'vectors',str(bits),f,intervals],text=True).splitlines()]
        sel=[a[:3]for a,v in zip(audit,views)if a[1]==a[5] and v[1]>=8 and v[1]>=0.15*v[0]]
        assert len(sel)==manifest[name]['simd-functions']['functions']
        intervals.write_text(''.join('%d %d %d\n'%tuple(v) for v in sel))
        native_values={}
        for mode in (0,1,2):
            for label in ('integer','scan','merge'):
                raw=w/(label+'-'+str(mode)+'.callgrind')
                tail=['capstone',str(mode),'1',str(f),str(intervals),str(bits)]
                # -demangle=no makes the symbol selector independent of the
                # installed Valgrind C++ demangler's lambda spelling.
                run(['valgrind','--tool=callgrind','--demangle=no','--collect-atstart=no',
                     '--toggle-collect=_ZZ4mainENK3$_0clEj','--cache-sim=yes','--branch-sim=yes',
                     '--dump-instr=yes','--collect-jumps=yes','--callgrind-out-file='+str(raw),
                     exe[label],*tail],'cost-'+label+'-'+str(mode))
                log=(p/'evidence'/('cost-'+label+'-'+str(mode)+'.log')).read_text()
                result=next(list(map(int,line.split())) for line in log.splitlines() if len(line.split())==6 and all(x.isdigit() for x in line.split()))
                if mode in native_values: assert result[2:]==native_values[mode]
                else:native_values[mode]=result[2:]
                content=raw.read_text();events=next(line[8:].split() for line in content.splitlines() if line.startswith('events: '))
                counts=list(map(int,next(line[8:].split() for line in content.splitlines() if line.startswith('totals: '))))
                assert len(events)==len(counts) and counts[0]>0
                costs.append(dict(case=name,mode=mode,variant=label,events=dict(zip(events,counts)),result=result[2:],collected_traversals=2))
                with gzip.open(p/'evidence'/(label+'-'+str(mode)+'.callgrind.gz'),'wb')as stream:stream.write(raw.read_bytes())
                raw.unlink()
                save('instruction-costs.json',costs)
    assert len(costs)==9
    save('cost-protocol.json',dict(symbol='_ZZ4mainENK3$_0clEj',consumer_unchanged=True,traversals=2,scope='The original benchmark warm traversal and one timed traversal are collected. Simulated cache events do not establish native hardware causes.'))
    save('complete.json',dict(cases=len(reported),success=True,native_qualification=False,controlled_replication=True,launches=launches))
w=Path(tempfile.mkdtemp(prefix='capstone-evex-transfer-comparison-native-'))
try:
    if hasattr(os,'sched_setaffinity'): os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    main(w)
finally:
    files=[v for v in w.rglob('*') if v.is_file()];amount=sum(v.stat().st_size for v in files);shutil.rmtree(w);save('cleanup.json',dict(removed=not w.exists(),bytes=amount,files=len(files)))
