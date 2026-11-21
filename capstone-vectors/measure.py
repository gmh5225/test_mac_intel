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
    spec=json.loads((r/'experiment.json').read_text())
    assert sha(r/'bootstrap.patch')==spec['bootstrap_sha256']
    run(['git','-C',base,'apply','--index',r/'bootstrap.patch'],'apply-reference')
    assert sp.check_output(['git','-C',base,'write-tree'],text=True).strip()==spec['baseline_tree']
    checkout=w/'iced';checkout.mkdir();tar=w/'iced.tar'
    run(['git','init','--bare',w/'iced-git'],'iced-repo');run(['git','-C',w/'iced-git','fetch','--depth','1','https://github.com/NeverSight/iced.git',iced],'iced-fetch');run(['git','-C',w/'iced-git','archive','--format=tar','-o',tar,iced,'src/rust/iced-x86'],'iced-archive');run(['tar','-xf',tar,'-C',checkout],'iced-extract');tar.unlink()
    ad=w/'adapter';ad.mkdir();src=(lab/'iced.rs').read_text().replace('repeats: u32,\n    output:', 'repeats: u32,\n    ip: u64,\n    output:').replace('bytes, 0x100000,','bytes, ip,').replace('set_ip(0x100000 +','set_ip(ip +')
    src=src.replace('InstructionInfoFactory, IntelFormatter,','InstructionInfoFactory, IntelFormatter, FastFormatter,').replace('    formatter: IntelFormatter,','    formatter: IntelFormatter,\n    fast: FastFormatter,\n    fast_enabled: bool,').replace('        mode,','        mode: mode & 3,\n        fast_enabled: mode & 8 != 0,\n        fast: FastFormatter::new(),')
    old='state.formatter.format(&instruction, &mut state.text);';assert src.count(old)==1;src=src.replace(old,'if state.fast_enabled {state.fast.format(&instruction, &mut state.text);} else {state.formatter.format(&instruction, &mut state.text);}')
    trace=(r/'iced-trace.rs').read_text().replace('iced_trace(input:', 'iced_trace(bits:u32,input:').replace('with_ip(64,','with_ip(bits,');(ad/'iced.rs').write_text(src+trace);shutil.copyfile(lab/'Cargo.lock',ad/'Cargo.lock')
    (ad/'Cargo.toml').write_text('[package]\nname="iced_compare"\nversion="0.1.0"\nedition="2021"\n[lib]\ncrate-type=["staticlib"]\npath="iced.rs"\n[dependencies]\niced-x86={path="../iced/src/rust/iced-x86",default-features=false,features=["std","decoder","intel","instr_info","fast_fmt"]}\n[profile.release]\npanic="abort"\nopt-level=3\n');run(['cargo','build','--locked','--release'],'iced-build',ad)
    save('cpu.json',dict(cpu=Path('/proc/cpuinfo').read_text(),compiler=sp.check_output([os.environ['CC'],'--version'],text=True)))
    save('iced-source.json',dict(revision=iced,source='https://github.com/NeverSight/iced.git',built_from_source=True,adapter_source_sha256=sha(ad/'iced.rs'),cargo_lock_sha256=sha(ad/'Cargo.lock')))
    save('entrypoints.json',dict(scan='cs_disasm_iter',format='cs_disasm_iter',detail='cs_disasm_iter',consumer='Public iterator benchmark plus the private static-link text entry called by NeverD; both consume the same output fields'))
    inc=(r/'driver.cpp').read_text().replace('size_t iced_trace(const','size_t iced_trace(unsigned, const').replace('if(argc!=6)','if(argc!=7)').replace('  csh handle=0;','  unsigned bits=std::stoul(argv[6]);\n  csh handle=0;').replace('cs_open(CS_ARCH_X86,CS_MODE_64,','cs_open(CS_ARCH_X86,bits==32?CS_MODE_32:CS_MODE_64,').replace('iced_create(64,mode)','iced_create(bits,mode)').replace('iced_trace(ptr,','iced_trace(bits,ptr,')
    inc=inc.replace('iced_create(bits,mode)','iced_create(bits,mode | (engine=="fast" ? 8 : 0))').replace('engine!="capstone" && engine!="iced"','engine!="capstone" && engine!="iced" && engine!="fast"')
    inc=inc.replace('if (mode>2 ||','if (mode>4 ||').replace('mode==2 ? CS_OPT_ON','mode>=2 ? CS_OPT_ON')
    inc=inc.replace('if (mode == 2) {','if (mode == 2 || mode == 4) {\n        if (mode == 2) {').replace('        const auto &x = insn->detail->x86;', '        }\n        const auto &x = insn->detail->x86;')
    old_engine='std::string engine=argv[1];';assert inc.count(old_engine)==1
    inc=inc.replace(old_engine,old_engine+'\n  if(engine=="iced____") engine="iced"; else if(engine=="fast____") engine="fast";')
    inc='#include "arch/X86/X86ScanAdapter.h"\n'+inc
    inc=inc.replace('static Result cs_span(', 'template <auto Next>\nstatic Result cs_span(')
    inc=inc.replace('bool ok = cs_disasm_iter(handle, &cursor, &left, &ip, insn);','bool ok = Next(handle, &cursor, &left, &ip, insn);')
    branch='if(engine=="capstone") row=cs_span(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);'
    assert inc.count(branch)==1
    inc=inc.replace(branch,'if(engine=="capstone") row=cs_span<cs_disasm_iter>(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);\n        else if(engine=="x86_iter") row=cs_span<X86_disasmIter>(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);')
    inc=inc.replace('engine!="capstone" &&','engine!="capstone" && engine!="x86_iter" &&')
    assert inc.count('iced_trace(bits,ptr,')==1
    weak='extern "C" bool X86_disasmIterText(csh, const uint8_t **, size_t *, uint64_t *, cs_insn *) __attribute__((weak));'
    weak+='\n'+weak.replace('X86_disasmIterText','X86_disasmIter32')
    key='else if(engine=="x86_iter") row=cs_span<X86_disasmIter>'
    assert inc.count(key)==1
    inc=inc.replace('#include "arch/X86/X86ScanAdapter.h"', '#include "arch/X86/X86ScanAdapter.h"\n'+weak)
    inc=inc.replace(key,'else if(engine=="x86_iter" && bits==32 && X86_disasmIter32) row=cs_span<X86_disasmIter32>(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);\n        else if(engine=="x86_iter" && X86_disasmIterText) row=cs_span<X86_disasmIterText>(bytes.data()+f.offset,f.size,handle,insn,f.ip,mode);\n        '+key)
    (w/'functions.cpp').write_text(inc);run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'functions.cpp','-o',w/'driver.o'],'driver')
    profile=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+os.environ['CC'],'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ['X86','ARM','AARCH64','MIPS']],'-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer '+('-Wno-error=discarded-qualifiers' if os.environ['CC']=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_SHARED_LIBS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON']
    data=json.loads((r/'experiment.json').read_text())
    profile += ['-DCAPSTONE_MIPS_PRECHECK_PRINTED_ALIAS=ON','-DCAPSTONE_MIPS_FINAL_OUTPUT_TRIM=ON','-DCAPSTONE_X86_NEAR_INDIRECT_OUTPUT=ON','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'];b=w/'build';exe={}
    run(['cmake','-S',base,'-B',b,*profile],'configure')
    obj=w/'driver.o'
    assert 'cs_disasm_iter' in sp.check_output(['nm','-u',obj],text=True)
    save('consumer-object.json',dict(sha256=sha(obj)))
    for label,tree in data['trees'].items():
        if label=='integrated':
            assert sha(r/'integrated.patch')==data['patch_sha256']
            run(['git','-C',base,'apply','--index',r/'integrated.patch'],'apply')
        assert sp.check_output(['git','-C',base,'write-tree'],text=True).strip()==tree
        flags={f:sorted({Path(v['file']).name for v in json.loads((b/'compile_commands.json').read_text())if '-D'+f in v['command'].split() or '-D'+f+'=1' in v['command'].split()}) for f in ('CAPSTONE_MIPS_PRECHECK_PRINTED_ALIAS','CAPSTONE_MIPS_FINAL_OUTPUT_TRIM','CAPSTONE_X86_NEAR_INDIRECT_OUTPUT')}
        assert flags=={'CAPSTONE_MIPS_PRECHECK_PRINTED_ALIAS':['MipsMapping.c'],'CAPSTONE_MIPS_FINAL_OUTPUT_TRIM':['MipsInstPrinter.c'],'CAPSTONE_X86_NEAR_INDIRECT_OUTPUT':['X86Sse64Output.c']}
        save('flags-'+label+'.json',flags)
        run(['cmake','--build',b,'--parallel','4','--target','capstone_static',*data['tests']],'build-'+label)
        run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(data['tests'])+')$'],'units-'+label)
        libs=[b/'libcapstone.a',ad/'target/release/libiced_compare.a','-lpthread','-ldl','-lm']
        target=w/('run-'+label)
        run(['clang++',obj,'-Wl,--undefined=X86_disasmIterText','-Wl,--undefined=X86_disasmIter32',*libs,'-o',target],'link-'+label)
        ordinary=w/('unselected-'+label);run(['clang++',obj,*libs,'-o',ordinary],'link-control-'+label)
        for image,selected in [(ordinary,False),(target,True)]:
            symbols={line.split()[-1] for line in sp.check_output(['nm','--defined-only',image],text=True).splitlines() if line.strip()}
            assert (('X86_disasmIter32' in symbols),('X86_disasmIterText' in symbols))==(selected,selected)
        members={name:hashlib.sha256(sp.check_output(['ar','p',libs[0],name])).hexdigest()for name in sp.check_output(['ar','t',libs[0]],text=True).splitlines()}
        save('members-'+label+'.json',members)
        if label=='baseline':prior=members
        else:
            changed={k for k in prior if members.get(k)!=prior[k]}
            assert prior.keys()==members.keys() and changed=={'X86ImmediateOutput.c.o','X86Sse64Output.c.o','X86Vex32Output.c.o'},changed
            assert sha(ordinary)!=sha(w/'unselected-baseline')
            save('isolation.json',dict(unchanged=len(prior)-len(changed),changed=sorted(changed),baseline=sha(w/'unselected-baseline'),unselected=sha(ordinary)))
        exe[label]=target
        if label=='baseline':
            old_archive=w/'baseline.a';shutil.copyfile(libs[0],old_archive)
        else:
            from factor_layout import locate
            members=['X86ImmediateOutput.c.o','X86Vex32Output.c.o','X86Sse64Output.c.o']
            selected={str(mask):[m for i,m in enumerate(members) if mask&(1<<i)]for mask in range(1,7)}
            for k,which in selected.items():
                ar=w/(k+'.a');shutil.copyfile(old_archive,ar)
                objs=[]
                for member in which:
                    item=w/member;item.write_bytes(sp.check_output(['ar','p',libs[0],member]));objs.append(item)
                run(['ar','r',ar,*objs],'compose-'+k)
                names=sp.check_output(['ar','t',ar],text=True).splitlines()
                assert names==sp.check_output(['ar','t',old_archive],text=True).splitlines()
                altered={name for name in names if hashlib.sha256(sp.check_output(['ar','p',ar,name])).hexdigest()!=prior[name]}
                assert altered==set(which)
                dest=w/(k+'-run')
                run(['clang++',obj,'-Wl,--undefined=X86_disasmIterText','-Wl,--undefined=X86_disasmIter32',ar,*libs[1:],'-o',dest],'link-'+k)
                exe[k]=dest
            save('member-sets.json',selected)
            save('factor-layout.json',{k:locate(exe[k])for k in ('baseline',*selected,'integrated')})

    save('tested-trees.json',data)
    exe['aa']=w/'copy';shutil.copy2(exe['baseline'],exe['aa'])
    exe['private_base']=exe['baseline'];exe['private_integrated']=exe['integrated']
    exe['iced']=exe['fast']=exe['baseline']
    payloads={key:path.read_bytes()for key,path in exe.items()}
    assert payloads['baseline']==payloads['aa']
    maximum=max(map(len,payloads.values()))
    padded={key:value+bytes(maximum-len(value))for key,value in payloads.items()}
    image=w/'same-image';image.write_bytes(padded['baseline']);image.chmod(0o755)
    image_inode=image.stat().st_ino
    probe=sp.run(['setarch',platform.machine(),'-R','/bin/true'],capture_output=True,text=True)
    launches=['images']
    if probe.returncode==0:launches.append('same-file-fixed')
    save('launch-controls.json',dict(launches=launches,aslr_disable_returncode=probe.returncode,aslr_disable_stderr=probe.stderr,original_sha256={k:hashlib.sha256(v).hexdigest()for k,v in payloads.items()},padded_sha256={k:hashlib.sha256(v).hexdigest()for k,v in padded.items()},image_inode=image_inode,fixed_size=maximum,equal_length_engine_selectors=True,purpose='Compare the public iterator against its bounds-corrected baseline and the current NeverSight iced fork in both launch controls.'))
    import frozen_deb as deb
    run(['clang++','-O2','-I',base/'include',r/'vectors.cpp',b/'libcapstone.a','-o',w/'vectors'],'vectors');reported=[];manifest={}
    assert set(launches)=={'images','same-file-fixed'}
    import pe_panels,itertools
    shutil.copyfile(r/'libmvec.py',w/'libmvec.py');shutil.copyfile(r/'libmvec.json',w/'libmvec.json')
    run(['python3','-B',w/'libmvec.py'],'glibc')
    glibc=json.loads((w/'libmvec.json').read_text())
    extra=[('libmvec-amd64',64,w/'libmvec.text',[(0,glibc['bytes'],glibc['address'])],glibc)]
    for name,bits,f,spans,source in itertools.chain(deb.prepare(w),pe_panels.prepare(w),extra):
        if name not in data['samples']:continue
        panel=data['samples'][name]
        intervals=w/(name+'.tsv')
        intervals.write_text(''.join('%d %d %d\n'%v for v in spans))
        audit=[sp.check_output([exe[k],'audit','0','1',f,intervals,str(bits)],text=True) for k in ('baseline','integrated')]
        assert audit[0]==audit[1]
        trace=[list(map(int,x.split())) for x in audit[0].splitlines()]
        views=[list(map(int,x.split())) for x in sp.check_output([w/'vectors',str(bits),f,intervals],text=True).splitlines()]
        assert len(views)==len(spans)==len(trace)
        common=[(a[:3],v) for a,v in zip(trace,views) if a[1]==a[5]]
        selected=[a for a,v in common if panel!='simd-functions' or (v[1]>=8 and v[1]>=.15*v[0])]
        if panel=='whole-text':assert len(selected)==1 and selected[0][1]==f.stat().st_size,(name,trace[:1])
        assert selected
        intervals.write_text(''.join('%d %d %d\n'%tuple(a) for a in selected))
        sel=selected
        manifest[name]=dict(source=source,input_functions=len(spans),common_functions=len(common),timed_functions=len(sel),bytes=sum(v[1] for v in sel),selection=panel,extent_sha256=sha(intervals),text_sha256=sha(f),excluded_incompatible_extents=[a for a in trace if a[1]!=a[5]])
        save('provenance.json',manifest)
        from factor_layout import paired
        for mode in (1,2):
            reported.append(paired(w,image,padded,name,bits,f,intervals,mode))
            save('factor-times.json',reported)
    assert len(reported)==2*len(data['samples'])
    save('complete.json',dict(cases=len(reported),success=True))

w=Path(tempfile.mkdtemp(prefix='capstone-vex32-iced-'))
try:
    if hasattr(os,'sched_setaffinity'): os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    main(w)
finally:
    files=[v for v in w.rglob('*') if v.is_file()];amount=sum(v.stat().st_size for v in files);shutil.rmtree(w);save('cleanup.json',dict(removed=not w.exists(),bytes=amount,files=len(files)))
