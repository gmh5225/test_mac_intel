"""Measure exact, common-boundary PE function bodies and three additional ELF text sections."""
from pathlib import Path
import gzip, os, shlex, platform, hashlib, importlib.util, json, math, shutil, statistics, subprocess as sp, tempfile
from data_identity import section_proof
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
    save('variants.json',dict(control='byte-identical baseline copy',integer='Released four-backend Capstone, revision '+reference,aa='byte-identical reference',previous='R1360 shared selector filter',data='R1360 with only the constant table in its own ELF section',scan='Small extension entry before the unchanged original decoder body; ordinary selectors unchanged',iced='NeverSight iced IntelFormatter',fast='NeverSight iced FastFormatter'))
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
    for label in ('integer','aa','previous','data','scan'):
        if label=='aa':
            exe[label]=w/'baseline-copy';shutil.copy2(exe['integer'],exe[label]);continue
        patches=[] if label=='integer' else [r/({'previous':'previous.patch','data':'data-control.patch'}.get(label,'scan.patch'))]
        for patch in patches: run(['git','apply',patch],'apply-'+label+'-'+patch.stem,tree)
        if label in ('scan','previous','data'):
            run(['git','add','-A'],'stage-tested-source',tree)
            tested=sp.check_output(['git','write-tree'],cwd=tree,text=True).strip()
            assert tested==json.loads((r/({'previous':'previous.json','data':'data-control.json'}.get(label,'candidate.json'))).read_text())['tree'],tested
            save(({'previous':'previous-source.json','data':'data-source.json'}.get(label,'tested-source.json')),dict(tree=tested,patch_sha256=sha(patches[0])))
        units=['x86_simple_output','x86_encoding_accuracy','x86_reg_access','detail_option','text_option','x86_printer_prechecked','x86_buffer_bounds','x86_scan_batch']+[f.stem for f in (tree/'tests/unit').glob('x86_*.c') if f.stem.startswith(('x86_apx','x86_amx','x86_evex'))]
        run(['cmake','--build',b,'--target','capstone_static',*units,'--parallel','4'],'build-'+label)
        run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$'],'units-'+label)
        objroot=b/'CMakeFiles/capstone.dir'
        objects[label]={str(path.relative_to(objroot)):sha(path) for path in objroot.rglob('*.o')}
        assert len(objects[label])>30
        if label == 'scan':
            changed={name for name,value in objects['integer'].items() if objects['scan'][name]!=value}
            added=set(objects['scan'])-set(objects['integer'])
            assert not added,added
            assert changed=={'arch/X86/X86Mapping.c.o'},changed
            save('object-isolation.json',dict(changed=sorted(changed),added=sorted(added),unchanged=len(objects['integer'])-len(changed)))
        if label=='previous':
            shutil.copyfile(objroot/'arch/X86/X86Mapping.c.o',w/'previous-mapping.o')
        if label=='data':
            save('data-identity.json',section_proof(w/'previous-mapping.o',objroot/'arch/X86/X86Mapping.c.o',objects['previous'],objects['data']))
        save('object-digests.json', objects)
        for component in ('X86IntelInstPrinter','X86IntelInstPrinterPrechecked','X86ATTInstPrinter','X86Mapping','X86ImmediateOutput','X86VectorOutput','X86Disassembler','X86DisassemblerDecoder','X86OutputIterator'):
            object_file=objroot/'arch/X86'/(component+'.c.o')
            assembly=sp.check_output(['objdump','-dr',object_file])
            with gzip.open(p/'evidence'/(label+'-'+component+'.asm.gz'),'wb') as stream:
                stream.write(assembly)
        code=inc.replace('#include <capstone/capstone.h>','#include <capstone/capstone.h>\n#include "X86ScanAdapter.h"');old='bool ok = cs_disasm_iter(handle, &cursor, &left, &ip, insn);';assert code.count(old)==1;code=code.replace(old,'bool ok = mode ? X86_disasmIter(handle,&cursor,&left,&ip,insn) : cs_disasm_iter(handle,&cursor,&left,&ip,insn);');(w/'owned.cpp').write_text(code);obj=w/'owned.o';run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base/'include','-I',tree/'arch/X86','-c',w/'owned.cpp','-o',obj],'owned-driver-'+label)
        if label=='integer':
            consumer_hash=sha(obj)
        else:
            assert sha(obj)==consumer_hash
        save('consumer-object.json',dict(sha256=consumer_hash,all_variants_identical=True))
        target=w/('run-'+label);run(['clang++',obj,b/'libcapstone.a',ad/'target/release/libiced_compare.a','-lpthread','-ldl','-lm','-Wl,-Map,'+str(p/'evidence'/(label+'-link.map')),'-o',target],'link-'+label);exe[label]=target
        (p/'evidence'/(label+'-symbols.txt')).write_bytes(sp.check_output(['nm','-n','-S','--defined-only',target]))
        (p/'evidence'/(label+'-sections.txt')).write_bytes(sp.check_output(['readelf','-WS',target]))
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
    save('launch-controls.json',dict(launches=launches,aslr_disable_returncode=probe.returncode,aslr_disable_stderr=probe.stderr,original_sha256={k:hashlib.sha256(v).hexdigest()for k,v in payloads.items()},padded_sha256={k:hashlib.sha256(v).hexdigest()for k,v in padded.items()},image_inode=image_inode,fixed_size=maximum,equal_length_engine_selectors=True,purpose='Measure compact negative EVEX admission against the published baseline with original-image and same-inode ASLR-disabled controls.'))
    import frozen_deb as deb
    run(['clang++','-O2','-I',base/'include',r/'vectors.cpp',b/'libcapstone.a','-o',w/'vectors'],'vectors');reported=[];manifest={}
    run(['clang++','-O2','-std=c++17','-I',base/'include',r/'prefixes.cpp',b/'libcapstone.a','-o',w/'prefixes'],'prefixes');prefix_census={}
    expected_panels=json.loads((r/'pe32-expected-panels.json').read_text())
    expected_consumers=json.loads((r/'pe32-expected-consumers.json').read_text())
    assert consumer_hash in expected_consumers.values(),consumer_hash
    assert probe.returncode==0
    costs=[]
    for name,bits,f,spans,source in deb.prepare(w):
        if name not in expected_panels:continue
        assert bits==32
        panel=expected_panels[name]['panel']
        intervals=w/(name+'-cost.tsv')
        intervals.write_text(''.join('%d %d %d\n'%v for v in spans))
        audit=[list(map(int,x.split()))for x in sp.check_output([exe['integer'],'audit','0','1',f,intervals,str(bits)],text=True).splitlines()]
        views=[list(map(int,x.split()))for x in sp.check_output([w/'vectors',str(bits),f,intervals],text=True).splitlines()]
        assert len(audit)==len(views)==len(spans)
        sel=[a[:3]for a,v in zip(audit,views)if a[1]==a[5] and (panel=='all-functions' or (v[1]>=8 and v[1]>=0.15*v[0]))]
        assert len(sel)==expected_panels[name]['functions']
        assert sum(x[1]for x in sel)==expected_panels[name]['bytes']
        intervals.write_text(''.join('%d %d %d\n'%tuple(v)for v in sel))
        manifest[name]=dict(source,panel=panel,functions=len(sel),bytes=sum(x[1]for x in sel))
        save('provenance.json',manifest)
        native_result=None
        for label in ('integer','previous','data','scan'):
            with image.open('r+b')as stream:assert stream.write(padded[label])==maximum
            assert image.stat().st_ino==image_inode and image.stat().st_size==maximum
            raw=w/(name+'-'+label+'.callgrind')
            logname='cost-'+name+'-'+label
            run(['setarch',platform.machine(),'-R','valgrind','--tool=callgrind',
                 '--demangle=no','--collect-atstart=no','--toggle-collect=_ZZ4mainENK3$_0clEj',
                 '--cache-sim=yes','--branch-sim=yes','--dump-instr=yes','--collect-jumps=yes',
                 '--callgrind-out-file='+str(raw),str(image),'capstone','1','1',str(f),str(intervals),str(bits)],logname)
            log=(p/'evidence'/(logname+'.log')).read_text()
            result=next(list(map(int,line.split()))for line in log.splitlines()if len(line.split())==6 and all(x.isdigit()for x in line.split()))
            if native_result is None:native_result=result[2:]
            else:assert result[2:]==native_result
            content=raw.read_text()
            events=next(line[8:].split()for line in content.splitlines()if line.startswith('events: '))
            counts=list(map(int,next(line[8:].split()for line in content.splitlines()if line.startswith('totals: '))))
            assert len(events)==len(counts) and counts[0]>0
            costs.append(dict(case=name,panel=panel,mode=1,variant=label,events=dict(zip(events,counts)),result=result[2:],collected_traversals=2))
            with gzip.open(p/'evidence'/(name+'-'+label+'.callgrind.gz'),'wb')as stream:stream.write(raw.read_bytes())
            raw.unlink()
            save('instruction-costs.json',costs)
    assert len(costs)==8
    save('cost-protocol.json',dict(symbol='_ZZ4mainENK3$_0clEj',consumer_unchanged=True,
         original_native_consumer_digest_verified=True,traversals=2,same_inode=True,aslr_disabled=True,
         scope='Original JPEG32 SIMD and SSL32 all-function formatting consumers, identical selected function extents. No native timing sweep.'))
    save('complete.json',dict(cases=len(costs),success=True,cost_only=True))

w=Path(tempfile.mkdtemp(prefix='capstone-evex-extension-small-entry-'))
try:
    if hasattr(os,'sched_setaffinity'): os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    main(w)
finally:
    files=[v for v in w.rglob('*') if v.is_file()];amount=sum(v.stat().st_size for v in files);shutil.rmtree(w);save('cleanup.json',dict(removed=not w.exists(),bytes=amount,files=len(files)))
